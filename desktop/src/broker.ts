import http from 'node:http';
import { ApiError, exchangeIdentifierCA, listCertificates, signHash } from './api-client';
import { SecureStore, type CertificateRecord, type MyCertConfig } from './secure-store';

interface ActiveSession {
  accessToken: string;
  expiresAt: number;
  config: MyCertConfig;
}

interface SignPayload {
  certificate_alias?: string;
  hashes?: Array<Record<string, string>>;
}

export class LocalBroker {
  private readonly store: SecureStore;
  private readonly sessions = new Map<string, ActiveSession>();
  private server?: http.Server;
  private port = 47891;

  constructor(store: SecureStore) {
    this.store = store;
  }

  async start(): Promise<number> {
    if (this.server) return this.port;
    this.port = Number(process.env.MYCERT_BROKER_PORT ?? 47891);
    this.server = http.createServer((request, response) => {
      void this.handle(request, response);
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(this.port, '127.0.0.1', () => resolve());
    });
    return this.port;
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    this.server = undefined;
  }

  private async handle(request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {
    response.setHeader('Access-Control-Allow-Origin', 'http://localhost');
    response.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    response.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (request.method === 'OPTIONS') {
      response.writeHead(204);
      response.end();
      return;
    }

    try {
      const url = new URL(request.url ?? '/', 'http://127.0.0.1');
      if (url.pathname === '/v1/health' && request.method === 'GET') {
        json(response, 200, { ok: true, broker: 'mycert', port: this.port });
        return;
      }
      if (url.pathname === '/v1/session/login' && request.method === 'POST') {
        await this.login(request, response);
        return;
      }
      if (url.pathname === '/v1/session/logout' && request.method === 'POST') {
        this.logout(request, response);
        return;
      }
      if (url.pathname === '/v1/certificates' && request.method === 'GET') {
        await this.certificates(request, response);
        return;
      }
      if (url.pathname === '/v1/sign' && request.method === 'POST') {
        await this.sign(request, response);
        return;
      }
      json(response, 404, { message: 'Rota não encontrada' });
    } catch (error) {
      console.error('Broker error:', error);
      json(response, 500, { message: error instanceof Error ? error.message : 'Erro interno' });
    }
  }

  private async login(request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {
    const body = await readJson<{ pin?: string }>(request);
    const config = this.store.get();
    const identifierCA = body.pin?.trim() || config.identifierCA.trim();
    if (!identifierCA) {
      json(response, 401, { message: 'Nenhuma autorização CA está disponível. Autorize o certificado no app.' });
      return;
    }
    // Mesmo motivo do try/catch em sign(): sem isto, um ApiError subia até o catch
    // genérico de handle() e virava "HTTP 500" seco. O módulo PKCS#11 registrava só
    // "broker login failed: status code 500", e a causa real — tipicamente
    // "Esta solicitação não está ativa ou foi revogada", ou seja, a autorização CA
    // expirou e precisa de um novo push — ficava visível apenas no console do Electron.
    let token: Awaited<ReturnType<typeof exchangeIdentifierCA>>;
    try {
      token = await exchangeIdentifierCA(config, identifierCA);
    } catch (error) {
      if (!(error instanceof ApiError)) throw error;
      console.error('Troca do identifierCA recusada pelo provedor:', {
        status: error.status,
        body: error.body,
      });
      json(response, 401, {
        message: error.message,
        upstream_status: error.status,
        upstream_body: error.body,
        hint: 'Refaça a autorização do certificado no app MyCert (push no celular) para obter um identifierCA novo.',
      });
      return;
    }
    // Registra o que o SafeWeb devolveu de fato: se o escopo vier como
    // "single_signature", o token é invalidado logo após um único uso — o que se
    // manifesta como "Sessão PKCS#11 expirada" (HTTP 401) na hora de assinar.
    console.log('Token de sessão obtido:', {
      scope: (token as { scope?: string }).scope ?? '(não informado)',
      expires_in: token.expires_in,
      token_type: (token as { token_type?: string }).token_type,
    });
    // A demonstração Safeweb 2 não fornece um endpoint de descoberta de certificados.
    // O app usa os certificados públicos informados na tela, mas o login não depende deles.
    const expiresIn = Math.max(60, Number(token.expires_in ?? 900));
    this.sessions.set(token.access_token, {
      accessToken: token.access_token,
      expiresAt: Date.now() + expiresIn * 1000,
      config: this.store.get(),
    });
    json(response, 200, { access_token: token.access_token, expires_in: expiresIn });
  }

  private logout(request: http.IncomingMessage, response: http.ServerResponse): void {
    const token = bearer(request);
    if (token) this.sessions.delete(token);
    json(response, 200, { ok: true });
  }

  private async certificates(request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {
    const token = bearer(request);
    const config = this.store.get();
    if (config.certificates.length > 0) {
      json(response, 200, { certificates: config.certificates });
      return;
    }
    const session = token ? this.validSession(token) : undefined;
    if (!session) {
      json(response, 200, { certificates: [] });
      return;
    }
    try {
      const certificates = await listCertificates(session.config, token!);
      this.store.save({ certificates });
      json(response, 200, { certificates });
    } catch (error) {
      console.warn('A API não expôs descoberta de certificados; usando a configuração local.', error);
      json(response, 200, { certificates: [] });
    }
  }

  private async sign(request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {
    const token = bearer(request);
    if (!token) {
      json(response, 401, { message: 'Bearer token ausente' });
      return;
    }
    const session = this.validSession(token);
    if (!session) {
      json(response, 401, { message: 'Sessão PKCS#11 expirada' });
      return;
    }
    const body = await readJson<SignPayload>(request);
    if (!body.certificate_alias || !Array.isArray(body.hashes) || body.hashes.length === 0) {
      json(response, 400, { message: 'certificate_alias e hashes são obrigatórios' });
      return;
    }
    // Sem este try/catch, um ApiError subia até o catch genérico de handle(), que o
    // reescrevia como HTTP 500 { message } — apagando o status real e, principalmente,
    // o CORPO devolvido pela SafeWeb. O módulo PKCS#11 registrava só
    // "HTTP 500 corpo={"message":"API respondeu HTTP 400"}", que não identifica a causa
    // da recusa. O corpo do provedor é a única evidência do motivo real: preserve-o.
    try {
      const result = await signHash(session.config, token, {
        certificate_alias: body.certificate_alias,
        hashes: body.hashes,
      });
      json(response, 200, result);
    } catch (error) {
      if (!(error instanceof ApiError)) throw error;
      console.error('Assinatura recusada pelo provedor:', {
        status: error.status,
        body: error.body,
        hash_algorithm: body.hashes.map((h) => h.hash_algorithm),
        signature_format: body.hashes.map((h) => h.signature_format),
      });
      // 502: o erro é do provedor upstream, não do broker. `upstream_*` chega intacto
      // ao log do MYCERT_PKCS11_LOG, que é onde o diagnóstico acontece de verdade.
      json(response, 502, {
        message: error.message,
        upstream_status: error.status,
        upstream_body: error.body,
      });
    }
  }

  private validSession(token: string): ActiveSession | undefined {
    const session = this.sessions.get(token);
    if (!session) return undefined;
    if (session.expiresAt <= Date.now()) {
      this.sessions.delete(token);
      return undefined;
    }
    return session;
  }
}

function bearer(request: http.IncomingMessage): string | undefined {
  const value = request.headers.authorization;
  if (!value?.startsWith('Bearer ')) return undefined;
  return value.slice('Bearer '.length).trim();
}

async function readJson<T>(request: http.IncomingMessage): Promise<T> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > 2 * 1024 * 1024) throw new Error('Payload excede o limite de 2 MB');
    chunks.push(buffer);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  return (text ? JSON.parse(text) : {}) as T;
}

function json(response: http.ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body);
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(data);
}
