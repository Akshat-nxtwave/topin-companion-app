const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('companion', {
  getNotificationStatus: () => ipcRenderer.invoke('app:getNotificationStatus'),
  openNotificationSettings: () => ipcRenderer.invoke('app:openNotificationSettings'),
  openGuide: (kind) => ipcRenderer.invoke('app:openGuide', kind),
  scan: () => ipcRenderer.invoke('app:scan'),
  auditNotifications: () => ipcRenderer.invoke('app:auditNotifications'),
  startAutoScan: (intervalMs) => ipcRenderer.invoke('app:autoScanStart', intervalMs),
  stopAutoScan: () => ipcRenderer.invoke('app:autoScanStop'),
  onAutoScanResult: (handler) => {
    const listener = (_evt, payload) => handler(payload);
    ipcRenderer.on('app:autoScanResult', listener);
    return () => { ipcRenderer.removeListener('app:autoScanResult', listener); };
  }
}); 