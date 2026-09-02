# Fluxo da demonstração pública Safeweb

Fonte consultada: https://pscsafeweb.safewebpss.com.br/demonstracao/ca
Bundle público consultado: https://pscsafeweb.safewebpss.com.br/demonstracao/assets/js/CertificadoAtributoView.c14d03ad.js

A demonstração pública monta a autorização CA com:

- Client ID de demonstração: `aplicacao-teste-safeweb-cfnqpiuo` (não usar na aplicação do usuário)
- `redirect_uri`: `https://pscsafeweb.safewebpss.com.br/Service/Microservice/DemonstracaoIntegracao/api/CA/CallbackCA`
- `state`: o mesmo documento informado
- chamada de autorização pelo cliente HTTP configurado para a API OAuth

Depois de chamar `authorize-ca`, a demonstração faz polling a cada 5 segundos para:

`/ca/buscarautorizacao/{documento}`

O endpoint é relativo ao cliente HTTP configurado para o serviço da demonstração; no bundle, o caminho aparece em minúsculas como `/ca/buscarautorizacao`. Quando a resposta contém `identifierCA`, a demonstração encerra o polling e avança para a etapa seguinte.

O código atual do MyCert usa `GET {demoApiBaseUrl}/CA/BuscarAutorizacao/{documento}`. Como a API demonstrativa pode ser sensível ao caminho/ambiente, a diferença de capitalização e principalmente o host configurado precisam ser verificados. O callback da demonstração pública confirma que o servidor Safeweb recebe o POST e a própria demonstração usa a base pública `https://pscsafeweb.safewebpss.com.br/Service/Microservice/DemonstracaoIntegracao/api` para esse fluxo.

Conclusão: como a notificação chegou ao usuário, `authorize-ca` está funcionando. A falha restante está no callback/polling: callback não foi armazenado no mesmo backend consultado, a aplicação usa outra Redirect URI, ou a rota de polling do MyCert precisa acompanhar o caminho usado pela demonstração (`/ca/buscarautorizacao/{documento}`).

## Atualização — "aprova no SafeID do celular, mas a API não recebe a resposta"

Este pacote (`-fixed`) já corrige a capitalização (`ca/buscarautorizacao` minúsculo) tanto em `desktop/src/api-client.ts` quanto no build compilado `desktop/dist/api-client.js`. Mesmo assim o sintoma persiste, então a causa mais provável não é mais o path — é o `redirect_uri` enviado em `authorize-ca`.

Onde olhar:
- `desktop/src/main.ts` (`authorization:start`) e `desktop/src/api-client.ts` (`authorizeCA`): quando o campo `redirectUri` da configuração está vazio (é o padrão em `secure-store.ts`), o app monta `redirect_uri` sozinho como `{demoApiBaseUrl}/CA/CallbackCA`. Isso só funciona se o backend do SafeID aceitar qualquer `redirect_uri` que aponte para o próprio host da demonstração — muitos provedores OAuth/CA só aceitam um `redirect_uri` pré-cadastrado para o `client_id`. Se o `redirect_uri` construído não bate com o que está cadastrado para `aplicacao-teste-safeweb-irhpbaai`, o push é disparado e o usuário consegue aprovar no celular normalmente (a aprovação em si não depende do redirect_uri estar certo), mas o servidor do SafeID nunca terá para onde entregar o `identifierCA` — então `GET .../ca/buscarautorizacao/{documento}` nunca vai ter o que retornar.
- `secure-store.ts` (`DEFAULT_CONFIG`): a base usada por padrão é a de **homologação** (`pscsafeweb-homologacao.safewebpss.com.br`), enquanto a demonstração pública original (que gerou os achados acima) roda em **produção** (`pscsafeweb.safewebpss.com.br`, sem "-homologacao"). Vale confirmar com o fornecedor se o `client_id` configurado e o `redirect_uri` estão de fato cadastrados para o ambiente de homologação, e não só para produção.
- `desktop/renderer/renderer.js` (`pollUntilAuthorized`): antes deste patch, qualquer erro do polling (404, 401, 500, erro de rede) era silenciosamente ignorado e tratado como "ainda não chegou", então a tela ficava presa em "Aguardando confirmação no dispositivo" por até 180s sem nunca revelar o motivo real. Isso foi corrigido: `main.ts`/`dist/main.js` agora devolvem `{ _pollError, status, message, endpoint, body }` em vez de lançar a exceção, e o renderer só continua tentando quando o status é 404 (callback genuinamente ainda não existe); qualquer outro status interrompe o polling na hora e mostra o erro real na tela.

Próximo passo prático: rodar o fluxo de novo com este patch. Se a tela passar a mostrar um erro (ex.: 401/403 em `authorize-ca` ou no polling), isso confirma problema de `redirect_uri`/credencial cadastrada. Se continuar mostrando só 404 até o timeout, o `identifierCA` realmente nunca chega nesse backend — nesse caso é preciso confirmar com o fornecedor SafeID/PSC qual `redirect_uri` está de fato cadastrado para o `client_id` em uso, e apontar a configuração da tela para bater exatamente com isso.
