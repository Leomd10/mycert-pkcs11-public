import http from 'node:http';
import path from 'node:path';
import { AuthorizationStore, type AuthorizationRecord } from './store';

// Token que precisa aparecer na URL cadastrada como redirect_uri no SafeWeb e
// que o desktop também usa para consultar o status. Funciona como um segredo
// compartilhado simples: quem não souber o token não consegue nem entregar
// callbacks falsos nem ler o resultado de outra pessoa.
// Definir via variável de ambiente CALLBACK_TOKEN — não tem valor padrão de
// propósito, pra obrigar quem for hospedar a escolher um valor próprio.
const TOKEN = process.env.CALLBACK_TOKEN;
const PORT = Number(process.env.PORT ?? 8787);
const DATA_FILE = process.env.DATA_FILE ?? path.join(process.cwd(), 'data', 'authorizations.json');

if (!TOKEN) {
  console.error('Defina a variável de ambiente CALLBACK_TOKEN antes de iniciar o servidor.');
  process.exit(1);
}

const store = new AuthorizationStore(DATA_FILE);

interface CallbackBody {
  identifierCA?: string;
  state?: string;
  expirationDate?: string;
  serialNumber?: string;
  error?: string;
}

const server = http.createServer((request, response) => {
  void handle(request, response).catch((error) => {
    console.error('Erro não tratado:', error);
    json(response, 500, { message: 'Erro interno' });
  });
});

async function handle(request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {
  const url = new URL(request.url ?? '/', 'http://localhost');
  const segments = url.pathname.split('/').filter(Boolean);

  if (segments[0] === 'health' && request.method === 'GET') {
    json(response, 200, { ok: true, service: 'mycert-callback-server' });
    return;
  }

  // POST /ca/callback/:token
  if (segments[0] === 'ca' && segments[1] === 'callback' && request.method === 'POST') {
    const token = segments[2];
    if (token !== TOKEN) {
      // Não revela se o token existe ou não; só responde 404 igual a uma rota inexistente.
      json(response, 404, { message: 'Não encontrado' });
      return;
    }
    const body = await readJson<CallbackBody>(request);
    if (!body.state) {
      json(response, 400, { message: 'state é obrigatório' });
      return;
    }
    const receivedAt = new Date().toISOString();
    const record: AuthorizationRecord = body.error
      ? { status: 'denied', state: body.state, error: body.error, receivedAt }
      : {
          status: 'approved',
          state: body.state,
          identifierCA: body.identifierCA ?? '',
          expirationDate: body.expirationDate,
          serialNumber: body.serialNumber,
          receivedAt,
        };
    if (record.status === 'approved' && !record.identifierCA) {
      json(response, 400, { message: 'identifierCA é obrigatório quando não há error' });
      return;
    }
    store.save(record);
    console.log(`[callback] state=${body.state} status=${record.status}`);
    // O corpo da resposta aqui não importa para o SafeID; 200 já confirma o recebimento.
    json(response, 200, { ok: true });
    return;
  }

  // GET /ca/status/:token/:state
  if (segments[0] === 'ca' && segments[1] === 'status' && request.method === 'GET') {
    const token = segments[2];
    const state = segments[3];
    if (token !== TOKEN) {
      json(response, 404, { message: 'Não encontrado' });
      return;
    }
    if (!state) {
      json(response, 400, { message: 'state é obrigatório na URL' });
      return;
    }
    const record = store.get(decodeURIComponent(state));
    if (!record) {
      json(response, 404, { message: 'Ainda não há callback registrado para este state' });
      return;
    }
    json(response, 200, record);
    return;
  }

  json(response, 404, { message: 'Rota não encontrada' });
}

async function readJson<T>(request: http.IncomingMessage): Promise<T> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > 256 * 1024) throw new Error('Payload excede o limite de 256 KB');
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

server.listen(PORT, () => {
  console.log(`mycert-callback-server ouvindo na porta ${PORT}`);
  console.log(`Cadastre no SafeWeb o redirect_uri: https://SEU_DOMINIO/ca/callback/${TOKEN}`);
});
