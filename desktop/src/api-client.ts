import type { CertificateRecord, MyCertConfig } from './secure-store';

export interface AuthorizationResult {
  status: number;
  message?: string;
  content?: boolean;
}

export interface AuthorizationRecord {
  identifierCA: string;
  serialNumber?: string;
  expirationDate?: string;
}

export interface SessionToken {
  access_token: string;
  expires_in?: number;
}

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

function joinUrl(base: string, suffix: string): string {
  return `${base.replace(/\/$/, '')}/${suffix.replace(/^\//, '')}`;
}

async function requestJsonWithMeta<T>(url: string, init: RequestInit = {}): Promise<{ status: number; body: T }> {
  const response = await fetch(url, {
    ...init,
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(init.headers ?? {}),
    },
  });
  const text = await response.text();
  let body: unknown = undefined;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = text;
  }
  if (!response.ok) {
    const message = typeof body === 'object' && body !== null && 'message' in body
      ? String((body as { message: unknown }).message)
      : `API respondeu HTTP ${response.status}`;
    throw new ApiError(message, response.status, body);
  }
  return { status: response.status, body: body as T };
}

async function requestJson<T>(url: string, init: RequestInit = {}): Promise<T> {
  const result = await requestJsonWithMeta<T>(url, init);
  return result.body;
}

export async function authorizeCA(config: MyCertConfig, document: string): Promise<AuthorizationResult & { _diagnostics?: Record<string, unknown> }> {
  const endpoint = joinUrl(config.oauthBaseUrl, 'authorize-ca');
  // O redirect_uri PRECISA estar cadastrado no SafeWeb para o client_id em uso
  // (ver DIAGNOSTICO-CALLBACK-SAFEID.md). A URL da demonstração pública nunca
  // vai funcionar de verdade — ela entrega o resultado para o backend deles,
  // não para o MyCert. Se `redirectUri` não foi preenchido manualmente na
  // tela, montamos a URL do callback-server próprio (que precisa estar
  // cadastrada no SafeWeb antes de funcionar).
  const redirectUri = config.redirectUri.trim()
    || (config.callbackServerUrl.trim() && config.callbackToken.trim()
      ? joinUrl(config.callbackServerUrl, `ca/callback/${config.callbackToken.trim()}`)
      : '');
  const result = await requestJsonWithMeta<AuthorizationResult>(endpoint, {
    method: 'POST',
    body: JSON.stringify({
      client_id: config.clientId,
      login_hint: document,
      // Só manda redirect_uri se tiver um valor de verdade: mandar string
      // vazia não é a mesma coisa que omitir o campo. Omitido, a doc do PSC
      // diz que ele usa "a primeira URI cadastrada para a aplicação".
      ...(redirectUri ? { redirect_uri: redirectUri } : {}),
      state: document,
      lifetime: config.lifetime,
    }),
  });
  const body = result.body && typeof result.body === 'object' ? result.body : { body: result.body };
  return {
    ...(body as AuthorizationResult),
    _diagnostics: {
      httpStatus: result.status,
      endpoint,
      redirectUri,
      request: 'POST /authorize-ca',
    },
  };
}

export async function pollAuthorization(config: MyCertConfig, document: string): Promise<AuthorizationRecord> {
  // NÃO usa mais config.demoApiBaseUrl: aquela rota é interna da demonstração
  // pública do SafeWeb e nunca vai ter o resultado de uma autorização feita
  // com o client_id do MyCert (ver DIAGNOSTICO-CALLBACK-SAFEID.md). Consulta
  // o mycert-callback-server próprio, que recebeu o callback via POST.
  if (!config.callbackServerUrl.trim() || !config.callbackToken.trim()) {
    throw new ApiError(
      'Configure "Servidor de callback do MyCert" e o token antes de autorizar (ver callback-server/README.md).',
      0,
      undefined,
    );
  }
  const record = await requestJson<{
    status: 'approved' | 'denied';
    state: string;
    identifierCA?: string;
    expirationDate?: string;
    serialNumber?: string;
    error?: string;
  }>(joinUrl(config.callbackServerUrl, `ca/status/${config.callbackToken.trim()}/${encodeURIComponent(document)}`));
  if (record.status === 'denied') {
    throw new ApiError(`Autorização negada pelo titular (${record.error ?? 'user_denied'}).`, 409, record);
  }
  return {
    identifierCA: record.identifierCA ?? '',
    serialNumber: record.serialNumber,
    expirationDate: record.expirationDate,
  };
}

export async function exchangeIdentifierCA(config: MyCertConfig, identifierCA: string): Promise<SessionToken> {
  // Troca o identifierCA por um token de sessão diretamente no endpoint OAuth
  // real (/pwd_authorize), usando o client_id/client_secret DA PRÓPRIA
  // aplicação. Antes, isso passava pelo backend da demonstração pública da
  // SafeWeb, que troca o identifierCA usando o client_id/client_secret DELE
  // — como o identifierCA foi emitido para o client_id da nossa própria
  // aplicação, essa troca cruzada é rejeitada pelo servidor OAuth (esse era
  // o motivo do login/assinatura falhar mesmo com a autorização CA correta).
  // Ver PSC.Business.IntegracaoBusiness.TrocarJWTCA no código-fonte oficial.
  //
  // O campo `password` deste endpoint NÃO é só o identifierCA — pela
  // documentação oficial ("Autorização com credenciais do titular"), é a
  // concatenação de dois fatores: identifierCA + senha/PIN do certificado
  // digital do titular, sem separador nenhum entre os dois. Sem o PIN
  // concatenado, o SafeWeb recusa com "Verifique o segundo fator de
  // autenticação concatenado com a senha".
  return requestJson<SessionToken>(joinUrl(config.oauthBaseUrl, 'pwd_authorize'), {
    method: 'POST',
    body: JSON.stringify({
      grant_type: 'password',
      client_id: config.clientId,
      client_secret: config.clientSecret,
      // Deliberadamente MENOR que config.lifetime: a autorização CA já consumiu
      // parte da própria validade entre o authorize-ca e esta troca, e o SafeWeb
      // recusa ("O valor de lifetime é maior do que a data de validade da
      // autorização") se pedirmos o período cheio.
      lifetime: 300,
      username: config.username || config.document,
      password: identifierCA + (config.certificatePin ?? ''),
      scope: 'signature_session',
      // Indica explicitamente o slot (número de série do certificado) em que a
      // autorização foi criada. Sem isso o PSC escolhe sozinho e pode procurar no
      // slot errado, respondendo "Esta solicitação não está ativa ou foi revogada".
      ...(config.certificateSerialNumber ? { slot_alias: config.certificateSerialNumber } : {}),
    }),
  });
}

export async function listCertificates(config: MyCertConfig, accessToken: string): Promise<CertificateRecord[]> {
  if (config.certificates.length > 0) {
    return config.certificates;
  }
  const payload = await requestJson<unknown>(joinUrl(config.apiBaseUrl, 'certificates'), {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return normalizeCertificates(payload);
}

export async function signHash(
  config: MyCertConfig,
  accessToken: string,
  request: { certificate_alias: string; hashes: Array<Record<string, string>> },
): Promise<unknown> {
  return requestJson(joinUrl(config.apiBaseUrl, 'signature'), {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
    body: JSON.stringify(request),
  });
}

function normalizeCertificates(payload: unknown): CertificateRecord[] {
  const records = Array.isArray(payload)
    ? payload
    : typeof payload === 'object' && payload !== null && Array.isArray((payload as { certificates?: unknown }).certificates)
      ? (payload as { certificates: unknown[] }).certificates
      : [];
  return records.flatMap((item) => {
    if (typeof item !== 'object' || item === null) return [];
    const value = item as Record<string, unknown>;
    const der = value.der_b64 ?? value.certificate_der_b64 ?? value.certificateDerB64 ?? value.der ?? value.certificate;
    const publicKey = value.public_key_der_b64 ?? value.publicKeyDerB64 ?? value.public_key_der ?? value.publicKey;
    const id = value.id ?? value.identifier ?? value.serialNumber;
    if (typeof id !== 'string' || typeof der !== 'string') return [];
    return [{
      id,
      alias: typeof value.alias === 'string' ? value.alias : undefined,
      label: typeof value.label === 'string' ? value.label : undefined,
      der_b64: der,
      public_key_der_b64: typeof publicKey === 'string' ? publicKey : undefined,
      algorithm: String(value.algorithm ?? 'RSA').toUpperCase() === 'EC' ? 'EC' : 'RSA',
    } satisfies CertificateRecord];
  });
}

export { joinUrl, requestJson, requestJsonWithMeta };
