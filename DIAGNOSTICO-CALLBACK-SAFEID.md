# Diagnóstico — callback de autorização CA do SafeID/PSC não chega ao MyCert

> **✅ RESOLVIDO.** Este documento registra a investigação original do
> problema de callback (a autorização não chegava de volta ao MyCert). A
> causa raiz e a correção completa estão nas seções abaixo; esse fluxo
> funciona desde então — incluindo autorização, troca de token e assinatura
> de documentos (validado de ponta a ponta no SERPRO). Mantido como registro
> histórico do processo de diagnóstico.
>
> Uma limitação diferente e definitiva foi identificada depois desse
> diagnóstico: o login por certificado no **PJeOffice Pro** especificamente
> não funciona, porque esse assinador usa MD5withRSA e a **SafeWeb
> confirmou oficialmente** (suporte, chamado #1266615) que a API só aceita
> SHA-1 e SHA-256, sem alternativa para MD5. Ver a seção "Limitação
> conhecida" do `README.md` na raiz do projeto.

> Leia este arquivo antes de mexer em qualquer coisa. Ele resume tudo que já foi
> investigado sobre o problema "aprova no SafeID do celular, mas a API não recebe
> a resposta", pra não repetir passos já descartados.

## 1. Sintoma original

No app desktop do MyCert (Electron), ao iniciar a autorização de um certificado
via SafeID (fluxo "Certificado de Atributo" do PSC SafeWeb):

1. O app chama `POST {oauthBaseUrl}/authorize-ca`.
2. O push de autorização chega no celular normalmente.
3. O usuário aprova no app do SafeID.
4. O MyCert fica em "Aguardando confirmação no dispositivo" fazendo polling em
   `GET {demoApiBaseUrl}/ca/buscarautorizacao/{documento}`.
5. Depois de 60 tentativas (3s cada = 180s), aparece "Tempo limite de
   autorização excedido" — o `identifierCA` nunca chega.

## 2. Causa raiz confirmada

**Não é bug de código.** É arquitetura: o MyCert está reaproveitando a
infraestrutura da **demonstração pública** do SafeWeb, que só funciona para a
aplicação de demonstração deles — não para o `client_id` de homologação do
MyCert (`aplicacao-teste-safeweb-irhpbaai`).

A documentação oficial do PSC (prints enviados pelo usuário) confirma:

- `redirect_uri` (enviado no `authorize-ca`) **precisa estar na lista de URIs
  autorizadas cadastradas para a aplicação** (o `client_id`). Se não for
  informado, o serviço usa **a primeira URI cadastrada para a aplicação**.
- A resposta da autorização (`identifierCA`, `state`, `expirationDate`,
  `serialNumber`) **é entregue via POST no corpo da requisição para essa URI
  de redirecionamento** — ou seja, é um **callback/webhook real** que o SafeID
  chama, e não um endpoint de consulta (GET) genérico que qualquer aplicação
  possa usar.

Isso explica os dois testes feitos:

| Teste | `redirect_uri` usado | Resultado | Por quê |
|---|---|---|---|
| 1 | `.../DemonstracaoIntegracao/api/CA/CallbackCA` (URL da demo pública) | Push chega, aprovação funciona, polling nunca acha nada | A URI passa na validação (é a cadastrada para o app de demo), então o SafeID faz o POST — mas para o servidor da demonstração pública, não para um servidor do MyCert. O `GET .../ca/buscarautorizacao` é a rota que o **frontend da própria demonstração** usa para ler o que **o backend da demonstração** recebeu. Nunca vai ter o resultado de uma autorização feita com o client_id do MyCert. |
| 2 | URL de teste em webhook.site | Push nem chega | webhook.site não está na lista de URIs autorizadas cadastradas para o client_id do MyCert, então o pedido é rejeitado antes de disparar o push. |

**Conclusão:** o `GET .../ca/buscarautorizacao/{documento}` que o código do
MyCert consulta hoje é um endpoint interno da demonstração pública do
SafeWeb (foi descoberto via engenharia reversa do bundle JS público, ver
`work/live-demo-callback-findings.md`), **não faz parte do contrato oficial
da API** e nunca vai funcionar para o client_id do MyCert.

## 3. O que falta fazer

O MyCert precisa da própria infraestrutura de callback, porque o modelo
real é push/webhook, não polling:

1. **Subir um servidor com URL pública em HTTPS** que o MyCert controla,
   capaz de receber `POST` do SafeID com o corpo:
   ```json
   {
     "identifierCA": "...",
     "state": "...",
     "expirationDate": "2020-03-27T17:17:12.663Z",
     "serialNumber": "..."
   }
   ```
   (e também o caso de negação: `{"error": "user_denied", "state": "..."}`).
   O servidor deve gravar o resultado indexado por `state` (hoje o app usa o
   `document`/CPF-CNPJ como `state`).

2. **Cadastrar essa URL pública como URI de redirecionamento autorizada**
   para o `client_id` do MyCert. Isso é feito no painel de "Cadastro de
   Aplicação" do PSC/SafeWeb — ainda não sabemos exatamente onde fica esse
   painel para o ambiente de homologação usado
   (`pscsafeweb-homologacao.safewebpss.com.br`, client_id
   `aplicacao-teste-safeweb-irhpbaai`). **Perguntar ao suporte do
   SafeWeb/PSC.**

3. **Trocar o polling do app desktop**: em vez de consultar
   `{demoApiBaseUrl}/ca/buscarautorizacao/{documento}` (backend da
   demonstração pública, nunca vai funcionar), o desktop passa a consultar o
   **servidor próprio do MyCert** criado no passo 1.

4. O `LocalBroker` que já existe em `desktop/src/broker.ts` **não serve para
   isso** — ele só escuta em `127.0.0.1`, e o SafeID precisa alcançar a URL
   pela internet. É um componente novo, hospedado (nuvem/VPS/etc.), separado
   do broker local do desktop.

## 4. Perguntas para levar ao suporte do SafeWeb/PSC

- Qual é a URI de redirecionamento cadastrada hoje para o client_id
  `aplicacao-teste-safeweb-irhpbaai` (ambiente homologação)? Como
  cadastramos/alteramos essa URI?
- Existe algum endpoint de consulta (GET) oficial e documentado para o
  status da autorização CA, como alternativa ao callback POST, para clients
  de terceiros (não só a demonstração pública)? (Suspeita: não existe — o
  modelo oficial é só push/webhook — mas vale confirmar.)
- O ambiente de homologação (`pscsafeweb-homologacao...`) tem as mesmas
  regras de cadastro de URI que a produção (`pscsafeweb...`, sem
  "-homologacao")?

## 5. Arquivos relevantes no projeto

- `desktop/src/api-client.ts` — `authorizeCA`, `pollAuthorization`,
  `exchangeIdentifierCA`. É aqui que a nova chamada ao servidor próprio do
  MyCert vai substituir `pollAuthorization`.
- `desktop/src/main.ts` — handlers IPC `authorization:start` e
  `authorization:poll` (este último já foi ajustado para devolver
  diagnóstico estruturado em vez de engolir erro — ver `_pollError` no
  retorno).
- `desktop/renderer/renderer.js` — `pollUntilAuthorized()`, tela de
  autorização.
- `desktop/src/broker.ts` — broker local (`127.0.0.1`), não é o lugar do
  novo servidor de callback.
- `work/live-demo-callback-findings.md` — histórico completo da
  investigação anterior (engenharia reversa do bundle JS da demonstração
  pública, testes de case-sensitivity no path, etc.).
- `README.md` (raiz do projeto) — já tem uma ressalva própria dizendo que a
  API de produção ainda precisa ser validada com o fornecedor.

## 6. Estado da conversa

O item 3 ("subir um servidor próprio de callback") **já foi implementado**
neste pacote, na pasta `callback-server/` — ver `callback-server/README.md`
para instruções de deploy. O app desktop também já foi ajustado para usar
esse servidor:

- `desktop/src/secure-store.ts` — novos campos de config `callbackServerUrl`
  e `callbackToken`.
- `desktop/src/api-client.ts` — `authorizeCA` agora monta o `redirect_uri` a
  partir de `callbackServerUrl`/`callbackToken` (em vez da URL da
  demonstração pública) quando o campo "Redirect URI" manual está vazio; e
  omite o campo `redirect_uri` do body inteiramente quando não há nada
  configurado (a doc do PSC diz que nesse caso o servidor usa "a primeira
  URI cadastrada para a aplicação"). `pollAuthorization` agora consulta
  `GET {callbackServerUrl}/ca/status/{token}/{document}` em vez de
  `demoApiBaseUrl` — inclusive tratando o caso de autorização negada
  (`status: 'denied'`) como erro explícito, não mais como timeout genérico.
- `desktop/renderer/index.html` e `renderer.js` — dois campos novos na tela
  de configuração: "Servidor de callback do MyCert" e "Token do callback".
- Tudo replicado também no build compilado (`desktop/dist/*.js`), que é o
  que o Electron roda de fato.

**O que ainda falta para funcionar de ponta a ponta** (nenhuma dessas
depende mais de código, são passos operacionais):

1. Hospedar o `callback-server/` em algum lugar com HTTPS público (ver
   seção "Colocando no ar" do README dele) e definir um `CALLBACK_TOKEN`.
2. Pedir ao suporte do SafeWeb/PSC para cadastrar
   `https://SEU_DOMINIO/ca/callback/<TOKEN>` como `redirect_uri` autorizada
   para o client_id `aplicacao-teste-safeweb-irhpbaai` (homologação) — as
   perguntas da seção 4 continuam valendo.
3. Preencher na tela do desktop os campos "Servidor de callback do MyCert"
   (a base pública, ex. `https://SEU_DOMINIO`) e "Token do callback" (o
   mesmo `CALLBACK_TOKEN`), deixando "Redirect URI" vazio para o app montar
   sozinho.
4. Refazer o teste de autorização. Se o SafeWeb aceitar o `redirect_uri`, o
   `callback-server` vai logar `[callback] state=... status=approved` no
   console assim que o POST chegar, e o polling do desktop deve achar o
   resultado na hora seguinte (em vez de dar 404 até o timeout).

Ainda não foi possível testar de ponta a ponta neste ambiente porque não há
acesso à internet nem ao painel de cadastro de aplicação do SafeWeb — os
passos 1–2 dependem do usuário/fornecedor.

---

## Atualização final — fechamento

Todos os passos acima foram concluídos com sucesso: o `callback-server` foi
hospedado, o `redirect_uri` foi cadastrado pela SafeWeb para um client_id
próprio, e a autorização CA passou a funcionar de ponta a ponta.

Na sequência, uma investigação separada (assinatura/login) revelou e
corrigiu, nessa ordem: a troca do `identifierCA` pelo endpoint OAuth
correto (`pwd_authorize`, não o backend da demonstração), a necessidade de
concatenar a senha do titular ao `identifierCA`, o envio do `slot_alias`
(número de série do certificado) para identificar corretamente a
autorização, a separação do hash puro do DigestInfo enviado pelo Java, e a
correção do `signature_format` de `CMS` para `RAW` (um módulo PKCS#11 deve
devolver a assinatura crua, não um envelope completo).

O resultado final: assinatura validada com sucesso no assinador do SERPRO.
O único cenário que permanece bloqueado é o login via PJeOffice Pro, por
uma limitação confirmada do lado da SafeWeb (não aceitam o OID de MD5) —
ver `README.md`.
