import { app, safeStorage } from 'electron';
import fs from 'node:fs';
import path from 'node:path';

export interface CertificateRecord {
  id: string;
  alias?: string;
  label?: string;
  der_b64: string;
  public_key_der_b64?: string;
  algorithm?: 'RSA' | 'EC';
}

export interface MyCertConfig {
  brokerUrl: string;
  apiBaseUrl: string;
  oauthBaseUrl: string;
  demoApiBaseUrl: string;
  redirectUri: string;
  callbackServerUrl: string;
  callbackToken: string;
  clientId: string;
  clientSecret: string;
  document: string;
  username: string;
  lifetime: number;
  identifierCA: string;
  // Número de série do certificado usado na autorização (vem no callback como
  // serialNumber). Enviado como slot_alias no pwd_authorize para dizer ao PSC em qual
  // slot procurar a autorização — sem ele, o PSC "decide sozinho" e pode olhar o slot
  // errado quando o titular tem mais de um certificado.
  certificateSerialNumber: string;
  // Senha/PIN do certificado digital do titular. Precisa ser concatenada logo após o
  // identifierCA na troca por token (pwd_authorize) — ver DIAGNOSTICO-CALLBACK-SAFEID.md.
  certificatePin: string;
  certificateAlias: string;
  certificateId: string;
  modulePath: string;
  certificates: CertificateRecord[];
}

const DEFAULT_CONFIG: MyCertConfig = {
  brokerUrl: 'http://127.0.0.1:47891',
  apiBaseUrl: 'https://pscsafeweb-homologacao.safewebpss.com.br/Service/Microservice/OAuth/api/v0/oauth',
  oauthBaseUrl: 'https://pscsafeweb-homologacao.safewebpss.com.br/Service/Microservice/OAuth/api/v0/oauth',
  demoApiBaseUrl: 'https://pscsafeweb-homologacao.safewebpss.com.br/Service/Microservice/DemonstracaoIntegracao/api',
  redirectUri: '',
  // Base pública do mycert-callback-server (ver pasta callback-server/) e o
  // token combinado com ele. Preenchidos depois que o servidor estiver no ar
  // e a URI estiver cadastrada no SafeWeb — ver DIAGNOSTICO-CALLBACK-SAFEID.md.
  callbackServerUrl: '',
  callbackToken: '',
  clientId: 'aplicacao-teste-safeweb-irhpbaai',
  clientSecret: '',
  document: '',
  username: '',
  lifetime: 3600,
  identifierCA: '',
  certificateSerialNumber: '',
  certificatePin: '',
  certificateAlias: '',
  certificateId: '',
  modulePath: '',
  certificates: [],
};

interface EncryptedFile {
  version: 1;
  encrypted: true;
  payload: string;
}

export class SecureStore {
  private readonly filePath: string;
  private config: MyCertConfig;

  constructor() {
    this.filePath = path.join(app.getPath('userData'), 'mycert-config.enc');
    this.config = this.readConfig();
  }

  get(): MyCertConfig {
    return structuredClone(this.config);
  }

  save(patch: Partial<MyCertConfig>): MyCertConfig {
    this.config = { ...this.config, ...patch };
    this.persist();
    return this.get();
  }

  reset(): MyCertConfig {
    this.config = structuredClone(DEFAULT_CONFIG);
    this.persist();
    return this.get();
  }

  private readConfig(): MyCertConfig {
    if (!fs.existsSync(this.filePath)) {
      return structuredClone(DEFAULT_CONFIG);
    }
    try {
      const file = JSON.parse(fs.readFileSync(this.filePath, 'utf8')) as EncryptedFile;
      const plaintext = safeStorage.decryptString(Buffer.from(file.payload, 'base64'));
      return { ...DEFAULT_CONFIG, ...JSON.parse(plaintext) };
    } catch (error) {
      console.warn('Não foi possível abrir a configuração segura; iniciando configuração vazia.', error);
      return structuredClone(DEFAULT_CONFIG);
    }
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    if (!safeStorage.isEncryptionAvailable()) {
      throw new Error('O armazenamento seguro do sistema operacional não está disponível.');
    }
    const payload = safeStorage.encryptString(JSON.stringify(this.config));
    const file: EncryptedFile = {
      version: 1,
      encrypted: true,
      payload: payload.toString('base64'),
    };
    fs.writeFileSync(this.filePath, JSON.stringify(file, null, 2), { mode: 0o600 });
  }
}

export { DEFAULT_CONFIG };
