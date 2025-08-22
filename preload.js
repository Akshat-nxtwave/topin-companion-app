const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('companion', {
  getNotificationStatus: () => ipcRenderer.invoke('app:getNotificationStatus'),
  openNotificationSettings: () => ipcRenderer.invoke('app:openNotificationSettings'),
  openGuide: (kind) => ipcRenderer.invoke('app:openGuide', kind),
  // Accept optional scanId to pair events across calls
  scan: (scanId) => ipcRenderer.invoke('app:scan', scanId),
  auditNotifications: (scanId) => ipcRenderer.invoke('app:auditNotifications', scanId),
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
  // Threat application listing
  listThreatApps: () => ipcRenderer.invoke('app:listThreatApps'),
  
  // WebSocket communication functions
  sendToClients: (data) => ipcRenderer.invoke('app:sendToClients', data),
  getServerStatus: () => ipcRenderer.invoke('app:getServerStatus'),
  checkBrowserTabPermissions: () => ipcRenderer.invoke('app:checkBrowserTabPermissions'),
  testTabDetection: (browserName) => ipcRenderer.invoke('app:testTabDetection', browserName),
  setLogging: (enabled) => ipcRenderer.invoke('app:setLogging', enabled),
  getLoggingStatus: () => ipcRenderer.invoke('app:getLoggingStatus'),
  getRAMInfo: () => ipcRenderer.invoke('app:getRAMInfo'),
  onWebSocketMessage: (handler) => {
    const listener = (_evt, message) => handler(message);
    ipcRenderer.on('websocket:message', listener);
    return () => { ipcRenderer.removeListener('websocket:message', listener); };
  }
}); 