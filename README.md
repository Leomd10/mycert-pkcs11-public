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
| `ksp/` | Key Storage Provider do Windows (CNG): põe o certificado no repositório do Windows, para Edge, Chrome e demais programas que não carregam PKCS#11 | Rust + `windows-sys` |
| `broker-client/` | Cliente do broker local compartilhado por `pkcs11/` e `ksp/`: login, renovação da sessão e envio do hash | Rust |
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

## Repositório do Windows (KSP)

No Windows, Edge e Chrome não carregam módulos PKCS#11: só enxergam
certificados do repositório do Windows. O `ksp/` resolve isso do mesmo jeito
que o SafeID Desktop: registra um *Key Storage Provider* ("MyCert Key Storage
Provider") e vincula o certificado a ele (`CERT_KEY_PROV_INFO`, chave
`mycert-<thumbprint>`). Quando um programa assina, o Windows carrega
`System32\mycert_ksp.dll`, que encaminha o hash ao broker local, igual ao
`C_Sign` do módulo PKCS#11.

```bash
cd ksp
cargo build --release
```

Com o app MyCert aberto:

```bash
# uma vez, num terminal de administrador
target/release/mycert-ksp-tool instalar
# como usuário comum
target/release/mycert-ksp-tool importar
target/release/mycert-ksp-tool testar
```

`testar` passa pelo mesmo caminho de um navegador (NCrypt → DLL registrada →
broker) e confere a assinatura com a chave pública do certificado. `remover`
desfaz o vínculo e `desinstalar` tira o provedor do sistema.

Só PKCS#1: a API do provedor recusa `signature_format: "PSS"` ("O
signature_format do hash é inválido"), então o KSP responde
`NTE_NOT_SUPPORTED` a pedidos PSS sem ir à rede.

**Mesmo certificado no SafeID:** o repositório guarda um único provedor por
certificado. Se o SafeID Desktop já vinculou o certificado, `importar` avisa e
não mexe. `importar --substituir` troca o vínculo e guarda o anterior em
`%LOCALAPPDATA%\MyCert\ksp-vinculos-anteriores`; `remover` o restaura. Com o
SafeID Desktop aberto, ele pode refazer o próprio vínculo.

O log é o mesmo `MYCERT_PKCS11_LOG` do módulo PKCS#11, com as linhas do
provedor marcadas `KSP <programa>#<pid>`.

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

## Login do PJe por certificado (MD5withRSA)

O login por certificado no **PJeOffice Pro** assina o desafio com
**MD5withRSA**, e a **API OAuth de integração** da SafeWeb, usada pelo MyCert,
recusa o OID de MD5. Por isso o MyCert, sozinho, não conclui esse login.

**Existe solução oficial.** O SafeID Desktop 1.4.2 instala uma biblioteca
PKCS#11 própria (`safeid-p11.dll` no Windows e `libsafeid-p11.dylib` no macOS),
que o PJeOffice detecta sozinho. Validado em 02/10/2026 nos dois sistemas: o
PJeOffice pede `MD5WITHRSA`, o SafeID Desktop recebe `hashAlgorithm: md5`, o
serviço da SafeWeb responde 200 OK e o login no PJe conclui. Para esse login,
use o SafeID Desktop 1.4.2 ou posterior.

O MyCert continua indicado para o que essa biblioteca não cobre: assinatura
por API com `client_id`, sem o app SafeID aberto.

**A origem do MD5 não é o PJeOffice nem o provedor do certificado: é a
aplicação servidora do PJe.** O que segue documenta como isso foi verificado.

### A cadeia, verificada

O PJeOffice executa a tarefa `sso.autenticador`, cujo contrato
(`ITarefaAutenticador`) expõe o campo `algoritmoAssinatura`. O cliente
JavaScript de referência distribuído com o próprio assinador
(`welcome/pjeoffice-pro.js`) define:

```js
"ALGORITMO_AUTENTICACAO" : "SHA256withRSA",
```

Ou seja, **o padrão oficial do PJeOffice para autenticação é SHA-256**. O
`MD5withRSA` aparece apenas como fallback legado da `PjeAuthenticatorTask`
quando o campo não é enviado. No fluxo real, porém, o log registra
`Algoritmo: 'MD5WITHRSA'` — porque o backend do PJe pede MD5 explicitamente.

Confirmado pela **Equipe PJeOffice Pro** (suporte):

> "O PJeOffice Pro já possui suporte a algoritmos criptográficos mais
> modernos, incluindo o SHA256withRSA. Entretanto, o algoritmo utilizado no
> fluxo de autenticação não é definido ou negociado pelo assinador. [...]
> Atualmente, nesse fluxo, o backend solicita a assinatura utilizando
> MD5withRSA."

E pela **SafeWeb** (chamado #1266615), cuja recusa aparece literalmente na
resposta da API, capturada com `MYCERT_PKCS11_LOG`:

```
O OID do hash é inválido.
  at PSC.Business.SignatureBusiness.Sign(...) in ...\SignatureBusiness.cs:line 108
```

### Por que o MyCert, pela API OAuth, não tem o que corrigir

O PJeOffice usa um provider JCA próprio (`ANYwithRSASignature`), que calcula o
digest em Java e faz o RSA cru via `Cipher`/`P11RSACipher`. Isso força
`CKM_RSA_PKCS` em **todos** os algoritmos — SHA-256 e MD5 percorrem aqui
exatamente o mesmo caminho: `prepare_hash` → `RsaPkcs1v15Raw` →
`split_digest_info`. Comparando as duas execuções, só o OID difere:

| Algoritmo | `hash_algorithm` enviado | Resposta da API |
|---|---|---|
| SHA256withRSA | `2.16.840.1.101.3.4.2.1` | ✅ assinatura devolvida |
| MD5withRSA | `1.2.840.113549.2.5` | ❌ "O OID do hash é inválido" |

Com o restante do payload idêntico, a recusa isola o OID como causa — e
confirma que o caminho raw está correto, já que produziu uma requisição que a
API aceitou. **Se o PJe passar a pedir SHA256withRSA, o login funciona sem
nenhuma alteração neste projeto.**

### Não há contorno pelo lado do cliente, só pela biblioteca oficial

Trocar o algoritmo apenas na chamada do cliente não resolve: a aplicação
servidora também precisa verificar a assinatura com o novo algoritmo. Nas
palavras do suporte do PJeOffice, a adequação "não se resume à substituição do
algoritmo na requisição, pois os componentes responsáveis pelo processamento e
pela validação também precisam estar preparados". Converter hash também é
impossível — MD5 e SHA-256 são funções distintas, e o PJe verifica
matematicamente a assinatura sobre aquele hash MD5 específico.

**Situação:** as tratativas para migrar o fluxo para SHA-256 já estão em
andamento no CNJ. Acompanhamento pelo canal oficial
(https://suporteti.cnj.jus.br/), registrando que **não** se trata de demanda
para o assinador PJeOffice Pro.

### O que funciona normalmente

*Teste de Dispositivos* do PJeOffice Pro com **SHA256withRSA** e
**SHA1withRSA**: biblioteca carregada, certificado lido, assinatura concluída.
Assinatura de documentos validada de ponta a ponta num assinador real (SERPRO),
com SHA-256 e formato RAW.

**Login por certificado no navegador** (gov.br): validado no Firefox com o
módulo PKCS#11. Quem assina é o próprio navegador, no handshake TLS, com
SHA-256 — o PJeOffice não participa. No Edge e no Chrome, o mesmo login passa
pelo KSP (ver "Repositório do Windows").

**Login no PJe com MD5:** não pelo MyCert, e sim pela biblioteca oficial do
SafeID Desktop 1.4.2 (ver o início desta seção). Duas observações de Windows
que explicam por que o repositório do Windows nem sempre serve:

- Com o SafeID Desktop 1.4.3 (provedor CNG), o login falha dentro do Java do
  PJeOffice, antes de chegar à SafeWeb: o `SunMSCAPI` não pede MD5 a chaves
  CNG (`java.security.SignatureException: Unrecognised hash algorithm`).
- Com o SafeID Desktop 1.2.3 (CSP legado), o login funcionava pelo repositório
  do Windows.

Para o MyCert, o caminho de uso é entrar no PJe por senha/CPF ou gov.br e usar
o certificado para **assinar** dentro do processo, que funciona com SHA-256.

## Segurança

- Nenhuma chave privada é armazenada localmente — a assinatura acontece
  inteiramente no provedor.
- O `client_secret` e a senha do titular ficam apenas na configuração
  criptografada local do desktop, nunca no módulo nativo (que roda dentro de
  processos de terceiros).
- Nunca commite segredos reais neste repositório — veja `.gitignore`.
