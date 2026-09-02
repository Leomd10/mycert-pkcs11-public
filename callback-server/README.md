# mycert-callback-server

Servidor mínimo (só Node.js, sem dependências externas além de `typescript`
para build) que resolve o problema descrito em
`../DIAGNOSTICO-CALLBACK-SAFEID.md`: recebe o **callback real** que o
SafeID/PSC faz via POST quando o usuário aprova a autorização no celular, e
expõe um GET simples para o app desktop MyCert consultar o resultado.

Ele substitui o uso da API de demonstração pública do SafeWeb
(`ca/buscarautorizacao`), que nunca vai devolver resultados de autorizações
feitas com o client_id do MyCert.

## Como funciona

- `POST /ca/callback/:token` — é a URL que você cadastra como `redirect_uri`
  autorizada para o client_id do MyCert no painel do SafeWeb/PSC. O SafeID
  chama essa URL sozinho, sem você precisar fazer nada, assim que o usuário
  aprova (ou nega) a autorização no celular. Grava o resultado indexado pelo
  `state` (hoje o app desktop usa o CPF/CNPJ como `state`).
- `GET /ca/status/:token/:state` — é o que o app desktop MyCert passa a
  consultar (no lugar do polling na demonstração pública) até receber o
  resultado.
- `:token` é um segredo simples (definido por você via `CALLBACK_TOKEN`) que
  entra na própria URL — como o SafeID não manda nenhum header de
  autenticação no POST (pela documentação, é só um POST simples no
  `redirect_uri`), colocar o segredo no caminho é a forma de garantir que só
  quem conhece o token consegue entregar ou ler resultados.
- Os registros ficam num arquivo JSON local (`data/authorizations.json` por
  padrão) e são descartados automaticamente depois de 24h — é só para o
  desktop ter tempo de consultar, não é um banco de autorizações
  permanente.

## Rodando localmente (teste)

```bash
cd callback-server
npm install
CALLBACK_TOKEN=um-token-bem-aleatorio-aqui npm run dev
```

Isso sobe o servidor em `http://localhost:8787`. Para testar sem esperar o
SafeID de verdade:

```bash
# Simula o POST que o SafeID faria
curl -X POST http://localhost:8787/ca/callback/um-token-bem-aleatorio-aqui \
  -H "Content-Type: application/json" \
  -d '{"identifierCA":"abc123","state":"12345678900","expirationDate":"2026-08-24T00:00:00Z","serialNumber":"999"}'

# Simula o desktop consultando o resultado
curl http://localhost:8787/ca/status/um-token-bem-aleatorio-aqui/12345678900
```

## Colocando no ar (produção/homologação)

Este servidor **precisa estar acessível pela internet em HTTPS**, porque
quem chama o `/ca/callback/:token` é o servidor do SafeWeb, não o navegador
do usuário. Passos:

1. Suba este servidor em qualquer host que rode Node (VPS, Railway, Render,
   Fly.io, uma instância própria etc.). Ele escuta HTTP puro na porta
   `PORT` (padrão 8787) — o TLS/HTTPS deve ser feito por um proxy reverso
   na frente (nginx, Caddy, ou o HTTPS já embutido da plataforma escolhida).
2. Escolha um `CALLBACK_TOKEN` aleatório e forte (ex.: `openssl rand -hex 24`)
   e defina como variável de ambiente do processo.
3. Anote a URL pública final, por exemplo:
   `https://callback.seudominio.com.br/ca/callback/<TOKEN>`
4. Peça ao suporte do SafeWeb/PSC para cadastrar essa URL como
   `redirect_uri` autorizada para o client_id de vocês (ver as perguntas
   no `DIAGNOSTICO-CALLBACK-SAFEID.md`, seção 4).
5. No app desktop MyCert, configure a nova opção "Servidor de callback do
   MyCert" com a base pública (`https://callback.seudominio.com.br`) e o
   mesmo `<TOKEN>`. Isso faz o desktop enviar esse `redirect_uri` no
   `authorize-ca` e consultar `GET /ca/status/:token/:state` no lugar da API
   de demonstração.

## Variáveis de ambiente

| Nome | Obrigatório | Padrão | Descrição |
|---|---|---|---|
| `CALLBACK_TOKEN` | Sim | — | Segredo usado na URL do callback e da consulta de status |
| `PORT` | Não | `8787` | Porta HTTP local (o HTTPS é feito pelo proxy reverso) |
| `DATA_FILE` | Não | `./data/authorizations.json` | Onde os resultados recebidos ficam guardados |

## Rodando como serviço (exemplo systemd)

```ini
[Unit]
Description=mycert-callback-server
After=network.target

[Service]
Environment=CALLBACK_TOKEN=um-token-bem-aleatorio-aqui
Environment=PORT=8787
WorkingDirectory=/opt/mycert-callback-server
ExecStart=/usr/bin/node dist/server.js
Restart=on-failure
User=mycert

[Install]
WantedBy=multi-user.target
```

(compile com `npm run build` antes, e coloque o proxy reverso — nginx/Caddy
— na frente apontando para `127.0.0.1:8787` com TLS.)
