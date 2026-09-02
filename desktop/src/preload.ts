import { contextBridge, ipcRenderer } from 'electron';
import type { MyCertConfig } from './secure-store';

const api = {
  getConfig: (): Promise<MyCertConfig> => ipcRenderer.invoke('config:get'),
  saveConfig: (patch: Partial<MyCertConfig>): Promise<MyCertConfig> => ipcRenderer.invoke('config:save', patch),
  resetConfig: (): Promise<MyCertConfig> => ipcRenderer.invoke('config:reset'),
  startAuthorization: (document: string): Promise<unknown> => ipcRenderer.invoke('authorization:start', document),
  pollAuthorization: (document: string): Promise<unknown> => ipcRenderer.invoke('authorization:poll', document),
  brokerStatus: (): Promise<unknown> => ipcRenderer.invoke('broker:status'),
  installPkcs11Config: (): Promise<unknown> => ipcRenderer.invoke('pkcs11:install-config'),
  diagnostics: (): Promise<unknown> => ipcRenderer.invoke('diagnostics:run'),
  openPath: (target: string): Promise<string> => ipcRenderer.invoke('shell:open-path', target),
};

contextBridge.exposeInMainWorld('mycert', api);
