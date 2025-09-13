const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('companion', {
  getNotificationStatus: () => ipcRenderer.invoke('app:getNotificationStatus'),
  getFocusStatus: () => ipcRenderer.invoke('app:getFocusStatus'),
  setNotificationLogging: (enabled) => ipcRenderer.invoke('app:setNotificationLogging', enabled),
  getNotificationLoggingStatus: () => ipcRenderer.invoke('app:getNotificationLoggingStatus'),
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
  // Auto-scan is started by main automatically; expose stop if needed
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
  getActiveSharingTabs: () => ipcRenderer.invoke('app:listActiveSharingTabs'),
  runExamModeCheck: (options) => ipcRenderer.invoke('app:runExamModeCheck', options),
  onWebSocketMessage: (handler) => {
    const listener = (_evt, message) => handler(message);
    ipcRenderer.on('websocket:message', listener);
    return () => { ipcRenderer.removeListener('websocket:message', listener); };
  },
  
  // Auto-update functions
  downloadUpdate: () => ipcRenderer.invoke('update:download'),
  installUpdate: () => ipcRenderer.invoke('update:install'),
  skipUpdate: () => ipcRenderer.invoke('update:skip'),
  
  // Update event listeners
  onUpdateChecking: (handler) => {
    const listener = (_evt) => handler();
    ipcRenderer.on('update:checking', listener);
    return () => { ipcRenderer.removeListener('update:checking', listener); };
  },
  onUpdateAvailable: (handler) => {
    const listener = (_evt, data) => handler(data);
    ipcRenderer.on('update:available', listener);
    return () => { ipcRenderer.removeListener('update:available', listener); };
  },
  onUpdateNotAvailable: (handler) => {
    const listener = (_evt) => handler();
    ipcRenderer.on('update:not-available', listener);
    return () => { ipcRenderer.removeListener('update:not-available', listener); };
  },
  onUpdateDownloadProgress: (handler) => {
    const listener = (_evt, data) => handler(data);
    ipcRenderer.on('update:download-progress', listener);
    return () => { ipcRenderer.removeListener('update:download-progress', listener); };
  },
  onUpdateDownloaded: (handler) => {
    const listener = (_evt, data) => handler(data);
    ipcRenderer.on('update:downloaded', listener);
    return () => { ipcRenderer.removeListener('update:downloaded', listener); };
  },
  onUpdateError: (handler) => {
    const listener = (_evt, data) => handler(data);
    ipcRenderer.on('update:error', listener);
    return () => { ipcRenderer.removeListener('update:error', listener); };
  },
  onUpdateSkip: (handler) => {
    const listener = (_evt) => handler();
    ipcRenderer.on('update:skip', listener);
    return () => { ipcRenderer.removeListener('update:skip', listener); };
  }
}); 