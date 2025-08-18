const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('companion', {
  getNotificationStatus: () => ipcRenderer.invoke('app:getNotificationStatus'),
  openNotificationSettings: () => ipcRenderer.invoke('app:openNotificationSettings'),
  openGuide: (kind) => ipcRenderer.invoke('app:openGuide', kind),
  scan: () => ipcRenderer.invoke('app:scan'),
  auditNotifications: () => ipcRenderer.invoke('app:auditNotifications'),
  completeSystemCheck: () => ipcRenderer.invoke('app:completeSystemCheck'),
  
  // Stepped scanning functions
  startSteppedScan: () => ipcRenderer.invoke('app:startSteppedScan'),
  retryStep1: () => ipcRenderer.invoke('app:retryStep1'),
  retryStep2: () => ipcRenderer.invoke('app:retryStep2'),
  getScanStatus: () => ipcRenderer.invoke('app:getScanStatus'),
  cancelScan: () => ipcRenderer.invoke('app:cancelScan'),
  resetScan: () => ipcRenderer.invoke('app:resetScan'),
  startAutoScan: (intervalMs) => ipcRenderer.invoke('app:autoScanStart', intervalMs),
  stopAutoScan: () => ipcRenderer.invoke('app:autoScanStop'),
  onAutoScanResult: (handler) => {
    const listener = (_evt, payload) => handler(payload);
    ipcRenderer.on('app:autoScanResult', listener);
    return () => { ipcRenderer.removeListener('app:autoScanResult', listener); };
  },
  
  // WebSocket communication functions
  sendToClients: (data) => ipcRenderer.invoke('app:sendToClients', data),
  getServerStatus: () => ipcRenderer.invoke('app:getServerStatus'),
  onWebSocketMessage: (handler) => {
    const listener = (_evt, message) => handler(message);
    ipcRenderer.on('websocket:message', listener);
    return () => { ipcRenderer.removeListener('websocket:message', listener); };
  }
}); 