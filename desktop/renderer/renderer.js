(() => {
  const $ = (id) => document.getElementById(id);
  let pendingAuthorization = null;
  let pendingDocument = '';

  const fields = ['apiBaseUrl', 'oauthBaseUrl', 'demoApiBaseUrl', 'redirectUri', 'callbackServerUrl', 'callbackToken', 'clientId', 'clientSecret', 'document', 'username', 'certificatePin', 'lifetime', 'certificateAlias', 'certificateId', 'modulePath'];

  function setValue(id, value) {
    const element = $(id);
    if (element) element.value = value ?? '';
  }

  function getValue(id) {
    return $(id)?.value?.trim() ?? '';
  }

  function redact(value, key = '') {
    if (/(client[_-]?secret|password|access[_-]?token|refresh[_-]?token|callback[_-]?token|certificate[_-]?pin)/i.test(key)) return '<redigido>';
    if (Array.isArray(value)) return value.map((item) => redact(item));
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([entryKey, entryValue]) => [entryKey, redact(entryValue, entryKey)]));
    }
    return value;
  }

  function showAuthorizationResponse(result) {
    const output = $('authorization-response');
    if (!output) return;
    output.textContent = JSON.stringify(redact(result), null, 2);
  }

  function setStatus(title, message, state = '') {
    $('authorization-title').textContent = title;
    $('authorization-message').textContent = message;
    $('authorization-box').className = `progress-box ${state}`;
  }

  function notify(message, isError = false) {
    const header = $('header-status');
    header.textContent = message;
    header.style.background = isError ? '#fae8e8' : '';
    header.style.color = isError ? '#9b3d3d' : '';
  }

  function readPatch() {
    return {
      apiBaseUrl: getValue('apiBaseUrl'),
      oauthBaseUrl: getValue('oauthBaseUrl'),
      demoApiBaseUrl: getValue('demoApiBaseUrl'),
      redirectUri: getValue('redirectUri'),
      callbackServerUrl: getValue('callbackServerUrl'),
      callbackToken: getValue('callbackToken'),
      clientId: getValue('clientId'),
      clientSecret: getValue('clientSecret'),
      document: getValue('document'),
      username: getValue('username'),
      certificatePin: getValue('certificatePin'),
      lifetime: Number(getValue('lifetime')) || 3600,
      certificateAlias: getValue('certificateAlias'),
      certificateId: getValue('certificateId'),
      modulePath: getValue('modulePath'),
    };
  }

  async function loadConfig() {
    const config = await window.mycert.getConfig();
    fields.forEach((id) => setValue(id, config[id]));
    setValue('authorization-document', config.document);
    $('identifierCA-display').textContent = config.identifierCA || 'Não autorizado';
    if (config.certificates?.length) $('certificates').value = JSON.stringify(config.certificates, null, 2);
    const status = await window.mycert.brokerStatus();
    notify(`Broker ativo · porta ${status.port}`);
    if (config.modulePath) $('module-status').textContent = config.modulePath;
  }

  $('config-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      await window.mycert.saveConfig(readPatch());
      notify('Configuração salva');
    } catch (error) {
      notify(error.message, true);
    }
  });

  $('reset-config').addEventListener('click', async () => {
    if (!confirm('Restaurar a configuração padrão?')) return;
    const config = await window.mycert.resetConfig();
    fields.forEach((id) => setValue(id, config[id]));
    setValue('authorization-document', config.document);
    $('certificates').value = '';
    $('identifierCA-display').textContent = 'Não autorizado';
    notify('Configuração restaurada');
  });

  $('authorization-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    pendingDocument = getValue('authorization-document');
    if (!pendingDocument) return;
    try {
      await window.mycert.saveConfig({ ...readPatch(), document: pendingDocument });
      // O início agora acorda e confere o servidor de callback antes de disparar o push,
      // o que pode levar até 90s se ele estiver hibernando. Sem avisar aqui, a tela
      // ficaria muda esse tempo todo e pareceria travada.
      setStatus('Verificando o servidor de callback', 'Confirmando que o receptor do callback está no ar antes de gastar o push do titular. Pode levar até 90s se ele estiver hibernando.', 'active');
      const started = await window.mycert.startAuthorization(pendingDocument);
      showAuthorizationResponse(started);
      if (started && started.content === false) {
        throw Object.assign(new Error(started.message || 'A API recusou o início da autorização.'), {
          status: started.status,
          body: started._diagnostics,
        });
      }
      pendingAuthorization = null;
      $('save-identifier').disabled = true;
      setStatus('Aguardando confirmação no dispositivo', 'A autorização foi iniciada. Confirme no aplicativo ou dispositivo solicitado.', 'active');
      notify('Aguardando autorização');
      await pollUntilAuthorized();
    } catch (error) {
      if (error && typeof error === 'object' && (error.status || error.body)) {
        showAuthorizationResponse({ error: error.message, status: error.status, body: error.body });
      }
      setStatus('Falha na autorização', error.message || 'Não foi possível iniciar a autorização.', 'error');
      notify('Falha na autorização', true);
    }
  });

  async function pollUntilAuthorized() {
    for (let attempt = 0; attempt < 60; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 3000));
      const record = await window.mycert.pollAuthorization(pendingDocument);
      if (record && record._pollError) {
        // 404 é esperado enquanto o callback ainda não chegou: continua o polling.
        // Qualquer outro status (401/403/500/erro de rede) é um problema real de
        // configuração (host errado, credencial errada etc.) e não vai se resolver
        // sozinho — parar de tentar e mostrar o erro em vez de ficar "aguardando" 180s.
        // 409 = há registro, mas de uma autorização ANTERIOR (o callback-server indexa
        // pelo CPF e guarda 24h). Também é estado de espera, não falha: o callback desta
        // autorização ainda não chegou. Tratar como erro fatal aqui abortaria o polling
        // justamente no caso em que basta esperar mais alguns segundos.
        if (record.status === 404 || record.status === 409) {
          setStatus('Aguardando confirmação no dispositivo', `Consultando o callback… tentativa ${attempt + 1}/60.`, 'active');
          continue;
        }
        showAuthorizationResponse(record);
        setStatus('Falha ao consultar o callback', `HTTP ${record.status || '—'} em ${record.endpoint}: ${record.message}`, 'error');
        notify('Falha ao consultar o callback', true);
        return;
      }
      const identifier = record.identifierCA || record.IdentifierCA;
      if (identifier) {
        pendingAuthorization = record;
        $('identifierCA-display').textContent = identifier;
        $('serial-display').textContent = record.serialNumber || record.SerialNumber || '—';
        $('save-identifier').disabled = false;
        setStatus('Autorização recebida', 'O identificador CA foi recebido. Salve-o para habilitar o token PKCS#11.', 'success');
        notify('Autorização concluída');
        return;
      }
      setStatus('Aguardando confirmação no dispositivo', `Consultando o callback… tentativa ${attempt + 1}/60.`, 'active');
    }
    throw new Error('Tempo limite de autorização excedido.');
  }

  $('save-identifier').addEventListener('click', async () => {
    if (!pendingAuthorization) return;
    const identifier = pendingAuthorization.identifierCA || pendingAuthorization.IdentifierCA;
    // Salva também o número de série: ele vira o slot_alias na troca por token, dizendo
    // ao PSC exatamente em qual certificado procurar esta autorização.
    const serial = pendingAuthorization.serialNumber || pendingAuthorization.SerialNumber || '';
    await window.mycert.saveConfig({ identifierCA: identifier, certificateSerialNumber: serial });
    $('save-identifier').disabled = true;
    notify('Autorização salva com proteção do sistema');
    setStatus('Pronto para o PKCS#11', 'O aplicativo consumidor poderá solicitar o login do token.', 'success');
  });

  $('save-certificate').addEventListener('click', async () => {
    try {
      const text = $('certificates').value.trim();
      const certificates = text ? JSON.parse(text) : [];
      if (!Array.isArray(certificates)) throw new Error('O campo de certificados deve ser um array JSON.');
      await window.mycert.saveConfig({ ...readPatch(), certificates });
      notify(`${certificates.length} certificado(s) salvo(s)`);
    } catch (error) {
      notify(error.message || 'JSON inválido', true);
    }
  });

  $('install-config').addEventListener('click', async () => {
    try {
      const result = await window.mycert.installPkcs11Config();
      $('module-status').textContent = `${result.modulePath} · ${result.exists ? 'biblioteca encontrada' : 'biblioteca ainda não compilada'}`;
      notify(result.exists ? 'Configuração PKCS#11 pronta' : 'Arquivo gerado; compile o módulo nativo');
      $('diagnostics').textContent = JSON.stringify(result, null, 2);
    } catch (error) {
      notify(error.message, true);
    }
  });

  $('run-diagnostics').addEventListener('click', async () => {
    try {
      const result = await window.mycert.diagnostics();
      $('diagnostics').textContent = JSON.stringify(result, null, 2);
      notify(result.moduleExists ? 'Diagnóstico concluído' : 'Diagnóstico: módulo ausente');
    } catch (error) {
      $('diagnostics').textContent = error.stack || error.message;
      notify('Diagnóstico falhou', true);
    }
  });

  loadConfig().catch((error) => notify(error.message || 'Falha ao carregar a configuração', true));
})();
