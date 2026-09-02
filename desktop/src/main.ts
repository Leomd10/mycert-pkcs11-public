import { app, BrowserWindow, ipcMain, shell } from 'electron';
import fs from 'node:fs';
import path from 'node:path';
import { ApiError, authorizeCA, joinUrl, pollAuthorization } from './api-client';
import { LocalBroker } from './broker';
import { SecureStore, type MyCertConfig } from './secure-store';

let mainWindow: BrowserWindow | undefined;
let store: SecureStore;
let broker: LocalBroker;

if (process.env.MYCERT_DISABLE_GPU === '1') app.commandLine.appendSwitch('disable-gpu');

function defaultNativeModulePath(): string {
  const file = process.platform === 'win32'
    ? 'mycert_pkcs11.dll'
    : process.platform === 'darwin'
      ? 'libmycert_pkcs11.dylib'
      : 'libmycert_pkcs11.so';
  if (app.isPackaged) return path.join(process.resourcesPath, 'native', file);
  return path.resolve(app.getAppPath(), '..', 'pkcs11', 'target', 'release', file);
}

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 820,
    minWidth: 960,
    minHeight: 680,
    title: 'MyCert',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  mainWindow.loadFile(path.join(app.getAppPath(), 'renderer', 'index.html'));
  if (!app.isPackaged && process.env.MYCERT_OPEN_DEVTOOLS === '1') mainWindow.webContents.openDevTools({ mode: 'detach' });
}

function registerIpc(): void {
  ipcMain.handle('config:get', () => store.get());
  ipcMain.handle('config:save', (_event, patch: Partial<MyCertConfig>) => store.save(patch));
  ipcMain.handle('config:reset', () => store.reset());
  ipcMain.handle('authorization:start', async (_event, document: string) => {
    const config = store.save({ document });
    const endpoint = joinUrl(config.oauthBaseUrl, 'authorize-ca');
    const redirectUri = config.redirectUri.trim() || joinUrl(config.demoApiBaseUrl, 'CA/CallbackCA');
    try {
      return await authorizeCA(config, document);
    } catch (error) {
      if (error instanceof ApiError) {
        return {
          content: false,
          status: error.status,
          message: error.message,
          _diagnostics: {
            httpStatus: error.status,
            endpoint,
            redirectUri,
            request: 'POST /authorize-ca',
            response: error.body,
          },
        };
      }
      throw error;
    }
  });
  ipcMain.handle('authorization:poll', async (_event, document: string) => {
    const config = store.get();
    const endpoint = joinUrl(config.demoApiBaseUrl, `ca/buscarautorizacao/${encodeURIComponent(document)}`);
    try {
      return await pollAuthorization(config, document);
    } catch (error) {
      if (error instanceof ApiError) {
        return {
          _pollError: true,
          status: error.status,
          message: error.message,
          endpoint,
          body: error.body,
        };
      }
      return {
        _pollError: true,
        status: 0,
        message: error instanceof Error ? error.message : 'Falha de rede ao consultar o callback',
        endpoint,
      };
    }
  });
  ipcMain.handle('broker:status', async () => {
    const response = await fetch(`http://127.0.0.1:${await broker.start()}/v1/health`);
    return response.json();
  });
  ipcMain.handle('pkcs11:install-config', () => installPkcs11Config());
  ipcMain.handle('diagnostics:run', () => runDiagnostics());
  ipcMain.handle('shell:open-path', (_event, target: string) => shell.openPath(target));
}

function installPkcs11Config(): { configPath: string; modulePath: string; exists: boolean } {
  const config = store.get();
  const modulePath = config.modulePath || defaultNativeModulePath();
  const folder = path.join(app.getPath('documents'), 'MyCert');
  fs.mkdirSync(folder, { recursive: true });
  const configPath = path.join(folder, 'mycert-sunpkcs11.cfg');
  const javaPath = modulePath.replaceAll('\\', '/');
  const contents = [
    'name = MyCert',
    `library = ${javaPath}`,
    'slotListIndex = 0',
    'showInfo = false',
    '',
  ].join('\n');
  fs.writeFileSync(configPath, contents, { encoding: 'utf8', mode: 0o600 });
  store.save({ modulePath });
  return { configPath, modulePath, exists: fs.existsSync(modulePath) };
}

async function runDiagnostics(): Promise<Record<string, unknown>> {
  const config = store.get();
  const brokerPort = await broker.start();
  let brokerOk = false;
  try {
    const response = await fetch(`http://127.0.0.1:${brokerPort}/v1/health`);
    brokerOk = response.ok;
  } catch {
    brokerOk = false;
  }
  const modulePath = config.modulePath || defaultNativeModulePath();
  return {
    platform: process.platform,
    arch: process.arch,
    broker: brokerOk,
    brokerPort,
    modulePath,
    moduleExists: fs.existsSync(modulePath),
    configPath: path.join(app.getPath('documents'), 'MyCert', 'mycert-sunpkcs11.cfg'),
    certificateCount: config.certificates.length,
    hasClientId: Boolean(config.clientId),
    hasClientSecret: Boolean(config.clientSecret),
    hasIdentifierCA: Boolean(config.identifierCA),
  };
}

app.whenReady().then(async () => {
  store = new SecureStore();
  broker = new LocalBroker(store);
  await broker.start();
  registerIpc();
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  void broker?.stop();
});
