# MyCert — assinatura digital remota via PKCS#11

MyCert conecta certificados digitais em nuvem (SafeID / SafeWeb) a qualquer
aplicação Java que use o padrão **PKCS#11** — incluindo assinadores como o do
SERPRO e o PJeOffice Pro (CNJ) — sem exigir token físico nem instalar a chave
privada na máquina do usuário. A chave nunca sai do provedor: o módulo
nativo faz o papel de "token PKCS#11 virtual", encaminhando cada operação de
assinatura para a API do provedor via um serviço local.

## Arquitetura

| Componente | Responsabilidade | Tecnologia |
|---|---|---|
| `desktop/` | App Electron: autorização do titular (push), armazenamento seguro da configuração, geração do `.cfg` do SunPKCS11 | Electron + TypeScript |
| `desktop/src/broker.ts` | Servidor HTTP local (`127.0.0.1:47891`), único ponto que fala com a internet — troca `identifierCA` por token de sessão e encaminha assinaturas para a API OAuth real do provedor | Node.js |
| `pkcs11/` | Biblioteca nativa (`.dll` / `.dylib` / `.so`) que implementa a interface PKCS#11 (Cryptoki): sessões, listagem de certificados, atributos de chave RSA, assinatura | Rust + [`native-pkcs11`](https://github.com/google/native-pkcs11) |
| `callback-server/` | Serviço HTTP mínimo, hospedado publicamente, que recebe o callback assíncrono do provedor após o titular aprovar a autorização no celular | Node.js (sem dependências) |
| `.github/workflows/` | Pipeline que compila e testa o módulo `pkcs11` num runner macOS real | GitHub Actions |

### Fluxo de ponta a ponta

1. **Autorização** — o app pede ao provedor um *push* de autorização (`authorize-ca`); o titular aprova no app do celular.
2. **Callback** — o provedor entrega o resultado (`identifierCA`) via webhook, recebido pelo `callback-server` próprio (não existe endpoint de consulta/polling oficial — é sempre push).
3. **Sessão** — quando um assinador (PJe, SERPRO, etc.) carrega a biblioteca PKCS#11 e tenta usar a chave, o módulo nativo pede um login ao broker local; o broker troca o `identifierCA` (concatenado com a senha do titular, conforme exigido pelo provedor) por um token de sessão OAuth.
4. **Assinatura** — o assinador chama `C_Sign`; o módulo nativo repassa o hash ao broker, que chama a API de assinatura do provedor e devolve a assinatura RSA crua.

Validado de ponta a ponta com um assinador real (SERPRO), usando SHA-256 e
assinatura RAW.

<!--
  Print da tela de configuração/autorização do MyCert Desktop.
  Basta arrastar a imagem pra essa pasta (ex.: docs/screenshot.png) e trocar
  o caminho abaixo — o comentário HTML acima não aparece renderizado.
-->
![Tela do MyCert Desktop](docs/screenshot.png)

## Requisitos

- **App desktop:** Node.js 22+ e npm.
- **Módulo nativo:** Rust 1.85+. No Windows, Visual Studio Build Tools com o
  workload de C++. No macOS, Xcode Command Line Tools.
- **Servidor de callback:** qualquer host com Node.js e HTTPS público (ver
  `callback-server/README.md`).

## Desenvolvimento do app desktop

```bash
cd desktop
npm install
npm start   # builda e abre o Electron
```

A configuração fica protegida pelo armazenamento seguro nativo do sistema
operacional (Electron `safeStorage`). Nenhum segredo é incluído no
código-fonte — preencha `client_id`, `client_secret`, o servidor de callback
e a senha do titular direto na tela do app.

## Compilação do módulo PKCS#11

```bash
cd pkcs11
cargo build --release
```

Gera `target/release/mycert_pkcs11.dll` (Windows), `libmycert_pkcs11.dylib`
(macOS) ou `libmycert_pkcs11.so` (Linux), conforme a plataforma.

Para testar a biblioteca fora de um assinador de verdade, veja
`pkcs11/test/mock_broker.py` e o workflow em
`.github/workflows/test-pkcs11-macos.yml` (compila, roda os testes unitários
do módulo e testa a `.dylib` com `keytool` num runner macOS real, sem
precisar de hardware Apple).

## Servidor de callback

Veja `callback-server/README.md` — inclui instruções de deploy e as
variáveis de ambiente necessárias (nenhuma tem valor padrão de propósito,
para forçar quem for hospedar a escolher segredos próprios).

## Diagnóstico e histórico técnico

- `DIAGNOSTICO-CALLBACK-SAFEID.md` — investigação completa do fluxo de
  callback/autorização, incluindo os erros reais encontrados e como foram
  resolvidos.
- `work/live-demo-callback-findings.md` — engenharia reversa inicial da
  demonstração pública do provedor, que motivou a arquitetura de callback
  próprio.

## Limitação conhecida (causa ainda em investigação)

O login por certificado em alguns assinadores (ex.: **PJeOffice Pro**) assina o
desafio de autenticação com **MD5withRSA**. O algoritmo é definido pelo
próprio assinador — o MyCert não tem como alterá-lo. Esse fluxo hoje falha.

**A hipótese principal**, informada pela SafeWeb (suporte, chamado #1266615):
a API SafeID só aceita os OIDs de **SHA-1** e **SHA-256**; MD5 não é
suportado e não existe fluxo alternativo. É a explicação mais provável — mas
ainda **não foi confirmada por um erro observado**, pelos dois motivos
abaixo.

**1. A evidência estava sendo destruída pelo próprio código.** Quando a
assinatura MD5 falha, a API devolve HTTP 400. O broker convertia isso em
`HTTP 500 {"message":"API respondeu HTTP 400"}` — o corpo da resposta do
provedor, única evidência do motivo real da recusa, era descartado antes de
chegar ao log. Corrigido em `desktop/src/broker.ts` (agora propaga
`upstream_status`/`upstream_body`) e `desktop/src/api-client.ts` (agora lê
`Message`, `error_description` e outras chaves além de `message`), mas o
fluxo ainda **não foi reexecutado** com a instrumentação nova.

**2. Os testes bem-sucedidos não passam pelo mesmo caminho de código.** A
biblioteca anuncia `CKM_SHA256_RSA_PKCS` e `CKM_SHA1_RSA_PKCS`, então o
SunPKCS11 usa esses mecanismos diretamente e `prepare_hash` calcula o hash nos
branches `RsaPkcs1v15Sha256`/`Sha1`. Não existe `CKM_MD5_RSA_PKCS` na lista,
então MD5withRSA cai no fallback `CKM_RSA_PKCS`, em que o Java entrega um
`DigestInfo` pronto e o código passa por `RsaPkcs1v15Raw` →
`split_digest_info` — um branch que **nunca teve sucesso confirmado contra a
API real**. Ou seja: "SHA-256 funciona e MD5 não" compara dois caminhos
distintos, e não isola o algoritmo como causa.

**Experimento que decide a questão:** remover temporariamente
`CKM_SHA256_RSA_PKCS` da lista de mecanismos anunciados força o SHA-256 pelo
mesmo caminho raw do MD5. Se a API aceitar, o caminho raw está correto e a
recusa é mesmo do MD5 — limitação externa, nada a corrigir aqui. Se recusar
igual, o problema está no payload do caminho raw, e é corrigível neste
projeto.

**O que está validado de fato.** Em *Teste de Dispositivos* do PJeOffice Pro,
a biblioteca foi carregada, o certificado lido e a assinatura concluída com
**SHA256withRSA** e **SHA1withRSA**. A assinatura de documentos foi validada
de ponta a ponta num assinador real (SERPRO), com SHA-256 e formato RAW. O
cenário de uso mais comum de um certificado digital, portanto, funciona
normalmente.

## Segurança

- Nenhuma chave privada é armazenada localmente — a assinatura acontece
  inteiramente no provedor.
- O `client_secret` e a senha do titular ficam apenas na configuração
  criptografada local do desktop, nunca no módulo nativo (que roda dentro de
  processos de terceiros).
- Nunca commite segredos reais neste repositório — veja `.gitignore`.
