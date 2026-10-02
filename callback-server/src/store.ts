import fs from 'node:fs';
import path from 'node:path';

export type AuthorizationRecord =
  | {
      status: 'approved';
      identifierCA: string;
      state: string;
      expirationDate?: string;
      serialNumber?: string;
      receivedAt: string;
    }
  | {
      status: 'denied';
      state: string;
      error: string;
      receivedAt: string;
    };

interface StoreFile {
  version: 1;
  records: Record<string, AuthorizationRecord>;
}

// Quanto tempo um registro fica disponível para consulta depois de recebido.
// O desktop já teria consultado bem antes disso; isso é só limpeza de lixo.
const RETENTION_MS = 24 * 60 * 60 * 1000;

export class AuthorizationStore {
  private readonly filePath: string;
  private records: Record<string, AuthorizationRecord> = {};

  constructor(filePath: string) {
    this.filePath = filePath;
    this.load();
  }

  private load(): void {
    if (!fs.existsSync(this.filePath)) {
      this.records = {};
      return;
    }
    try {
      const file = JSON.parse(fs.readFileSync(this.filePath, 'utf8')) as StoreFile;
      this.records = file.records ?? {};
    } catch (error) {
      console.warn('Não foi possível ler o arquivo de dados; iniciando vazio.', error);
      this.records = {};
    }
    this.purgeExpired();
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const file: StoreFile = { version: 1, records: this.records };
    const tmpPath = `${this.filePath}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(file, null, 2), { mode: 0o600 });
    fs.renameSync(tmpPath, this.filePath);
  }

  private purgeExpired(): void {
    const now = Date.now();
    let changed = false;
    for (const [state, record] of Object.entries(this.records)) {
      if (now - new Date(record.receivedAt).getTime() > RETENTION_MS) {
        delete this.records[state];
        changed = true;
      }
    }
    if (changed) this.persist();
  }

  save(record: AuthorizationRecord): void {
    this.records[record.state] = record;
    this.persist();
  }

  get(state: string): AuthorizationRecord | undefined {
    this.purgeExpired();
    return this.records[state];
  }

  /// Quantos registros o servidor conhece agora. Serve só para o log: um store vazio
  /// logo após um 'callback GRAVADO' é a assinatura de disco efêmero (o processo
  /// reiniciou e o arquivo se perdeu), enquanto um store com outros registros aponta
  /// para `state` divergente entre quem gravou e quem consulta.
  states(): string[] {
    return Object.keys(this.records);
  }
}
