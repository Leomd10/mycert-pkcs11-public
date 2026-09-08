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
  // Quando o callback-server recebeu este callback. É o que permite distinguir a
  // autorização em curso de uma anterior ainda em cache — ver `pollAuthorization`.
  receivedAt?: string;
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

// O SafeWeb é uma stack .NET: dependendo do ponto onde a requisição é recusada, a
// mensagem vem em `message`, `Message` (padrão do ASP.NET), `error_description`
// (padrão OAuth) ou `title`/`detail` (RFC 7807). Só olhávamos `message` minúsculo —
// nos outros casos a causa real era descartada e sobrava o genérico "API respondeu
// HTTP 400", que não diz nada sobre o motivo da recusa.
const CHAVES_DE_MENSAGEM = ['message', 'Message', 'error_description', 'error', 'title', 'detail'];

function extractMessage(body: unknown, status: number): string {
  if (typeof body === 'string' && body.trim()) return body.trim();
  if (typeof body === 'object' && body !== null) {
    const registro = body as Record<string, unknown>;
    for (const chave of CHAVES_DE_MENSAGEM) {
      const valor = registro[chave];
      if (typeof valor === 'string' && valor.trim()) return valor.trim();
    }
    // Último recurso: nenhuma chave conhecida, mas há corpo. Devolve o JSON inteiro em
    // vez de engolir — é justamente esse corpo que identifica a causa da recusa.
    return `API respondeu HTTP ${status}: ${JSON.stringify(body)}`;
  }
  return `API respondeu HTTP ${status}`;
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
    throw new ApiError(extractMessage(body, response.status), response.status, body);
  }
  return { status: response.status, body: body as T };
}

async function requestJson<T>(url: string, init: RequestInit = {}): Promise<T> {
  const result = await requestJsonWithMeta<T>(url, init);
  return result.body;
}

export interface CallbackServerCheck {
  ok: boolean;
  tentativas: number;
  ms: number;
  detalhe?: string;
}

/**
 * Acorda e confirma o servidor de callback ANTES de iniciar a autorização.
 *
 * Por que isso importa: o fluxo não tem polling do lado da SafeWeb — a entrega do
 * `identifierCA` é um POST único, sem retentativa conhecida. Se o servidor de callback
 * estiver hibernando quando esse POST chegar (hospedagens gratuitas derrubam o serviço
 * após alguns minutos ociosos e levam 30-60s para subir), a entrega se perde em
 * silêncio — e a autorização, que já consumiu um push no celular do titular e já existe
 * do lado do provedor, vira lixo. O usuário só descobre minutos depois, quando o
 * polling estoura as 60 tentativas, ou pior: mais tarde, na hora de assinar.
 *
 * Uma requisição ao /health antes do `authorize-ca` resolve: ela mesma tira o serviço da
 * hibernação, e o polling subsequente (a cada 3s) o mantém acordado durante toda a
 * janela em que o callback pode chegar.
 */
export async function ensureCallbackServerAwake(config: MyCertConfig): Promise<CallbackServerCheck> {
  const base = config.callbackServerUrl.trim();
  const inicio = Date.now();
  if (!base) {
    return { ok: false, tentativas: 0, ms: 0, detalhe: 'Servidor de callback não configurado.' };
  }
  const url = joinUrl(base, 'health');
  // Janela generosa: um cold start de hospedagem gratuita leva de 30 a 60 segundos.
  const LIMITE_MS = 90_000;
  const ESPERA_ENTRE_TENTATIVAS_MS = 5_000;
  let tentativas = 0;
  let detalhe = '';
  while (Date.now() - inicio < LIMITE_MS) {
    tentativas += 1;
    try {
      const resposta = await fetch(url, { signal: AbortSignal.timeout(15_000) });
      if (resposta.ok) {
        return { ok: true, tentativas, ms: Date.now() - inicio };
      }
      detalhe = `HTTP ${resposta.status}`;
    } catch (error) {
      detalhe = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, ESPERA_ENTRE_TENTATIVAS_MS));
  }
  return { ok: false, tentativas, ms: Date.now() - inicio, detalhe };
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
    receivedAt?: string;
    error?: string;
  }>(joinUrl(config.callbackServerUrl, `ca/status/${config.callbackToken.trim()}/${encodeURIComponent(document)}`));
  if (record.status === 'denied') {
    throw new ApiError(`Autorização negada pelo titular (${record.error ?? 'user_denied'}).`, 409, record);
  }
  // O callback-server indexa os registros pelo `state`, que é o CPF, e os mantém por 24h.
  // Uma consulta feita antes de o callback novo chegar devolve o registro da autorização
  // ANTERIOR — mesmo CPF, identifierCA velho. Aceitá-lo parecia sucesso aqui e só
  // estourava lá na frente, no pwd_authorize, como "Esta solicitação não está ativa ou
  // foi revogada". Então: só vale registro recebido depois do início desta autorização.
  const iniciadaEm = Date.parse(config.authorizationStartedAt);
  const recebidoEm = Date.parse(record.receivedAt ?? '');
  if (Number.isFinite(iniciadaEm)) {
    // Tolerância para diferença de relógio entre esta máquina e o callback-server, que
    // são hosts distintos. Folga pequena: o caso que isto pega são registros de horas
    // atrás, não de segundos.
    const TOLERANCIA_RELOGIO_MS = 2 * 60 * 1000;
    if (!Number.isFinite(recebidoEm) || recebidoEm < iniciadaEm - TOLERANCIA_RELOGIO_MS) {
      throw new ApiError(
        `O callback disponível é de uma autorização anterior (recebido em ${record.receivedAt ?? 'data desconhecida'}). `
          + 'Aguardando o push desta autorização ser aprovado no celular.',
        409,
        record,
      );
    }
  }
  return {
    identifierCA: record.identifierCA ?? '',
    serialNumber: record.serialNumber,
    expirationDate: record.expirationDate,
    receivedAt: record.receivedAt,
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
