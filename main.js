const { app, BrowserWindow, ipcMain } = require('electron');
app.disableHardwareAcceleration();
app.commandLine.appendSwitch('disable-gpu-vsync');
app.commandLine.appendSwitch('log-level', '3');
app.commandLine.appendSwitch('no-sandbox');
app.commandLine.appendSwitch('disable-dev-shm-usage');
app.commandLine.appendSwitch('disable-gpu-sandbox');
const path = require('path');
const os = require('os');
const si = require('systeminformation');
const fs = require('fs');
const { exec } = require('child_process');
const SecurityService = require('./security/SecurityService');
const ExamModeService = require('./security/ExamModeService');
const NotificationService = require('./security/NotificationService');
const { EventBus } = require('./comm/EventBus');
const { LocalServer } = require('./comm/LocalServer');

// WebSocket Event Enums for TOPIN Website Communication
const TopinEvents = Object.freeze({
  CONNECTED_WITH_TOPIN_WEBSITE: 'CONNECTED_WITH_TOPIN_WEBSITE',
  SCANNING_STARTED: 'SCANNING_STARTED',
  SUSPICIOUS_APPLICATION_DETECTED: 'SUSPICIOUS_APPLICATION_DETECTED',
  SUSPICIOUS_CHECK_COMPLETE: 'SUSPICIOUS_CHECK_COMPLETE',
  NOTIFICATION_APPLICATION_DETECTED: 'NOTIFICATION_APPLICATION_DETECTED',
  NOTIFICATION_CHECK_COMPLETE: 'NOTIFICATION_CHECK_COMPLETE',
  SYSTEM_CHECK_SUCCESSFUL: 'SYSTEM_CHECK_SUCCESSFUL'
});
const securityService = new SecurityService();
const examModeService = new ExamModeService();
const notificationService = new NotificationService();

// Initialize EventBus and WebSocket server for communication
const eventBus = new EventBus();

// Store connected WebSocket clients for TOPIN event broadcasting
let connectedClients = new Set();

// Helper function to debug client status
function debugClientStatus() {
  console.log('\n🔍🔍🔍 CLIENT STATUS DEBUG 🔍🔍🔍');
  console.log(`Total connectedClients: ${connectedClients.size}`);
  
  if (connectedClients.size > 0) {
    let index = 1;
    connectedClients.forEach(client => {
      console.log(`   Client ${index}: readyState=${client.readyState}, url=${client.url || 'unknown'}`);
      index++;
    });
  } else {
    console.log('   No clients connected');
  }
  console.log('🔍🔍🔍 END CLIENT STATUS 🔍🔍🔍\n');
}

// Function to analyze notification threats from audit result (similar to stepped scan)
function analyzeNotificationThreatsFromAudit(auditResult) {
  const threats = [];
  // Linux: Only enforce Do Not Disturb (DND/Focus) requirement. Do not inspect apps/browsers further.
  if (process.platform === 'linux') {
    const sys = auditResult.system || {};
    const status = String(sys.status || '').toLowerCase();
    const dndOn = (status === 'disabled'); // our convention: notifications disabled => DND ON
    if (!dndOn) {
      threats.push({
        type: 'linux_dnd_required',
        severity: 'high',
        message: 'Turn on Do Not Disturb (DND) in system settings',
        action: 'Open notification settings and enable DND',
        userActionRequired: true,
        settingsRequired: true,
        details: { platform: 'linux', system: sys }
      });
    }
    return threats;
  }
  
  // EXCLUDE system notifications from threat analysis as per user requirement
  // System notifications are not considered threats
  const systemProcessNameExclusions = new Set(['win32', 'darwin']);
  const isProcessNameExcluded = (name) => {
    const n = String(name || '').toLowerCase();
    if (!n) return false;
    if (systemProcessNameExclusions.has(n)) return true;
    if (n.includes('crashpad')) return true;
    return false;
  };
  const runningProcessNames = new Set(
    (auditResult.processes || [])
      .map(p => String(p.name || '').toLowerCase())
      .filter(n => n && !isProcessNameExcluded(n))
  );
  const hasRunningBrowser = (browserKey) => {
    // Map logical browser key to process name patterns
    const patterns = {
      chrome: ['chrome'],
      chromium: ['chromium'],
      msedge: ['msedge', 'microsoft edge'],
      brave: ['brave'],
      firefox: ['firefox']
    }[browserKey] || [];
    // Exclude webview/updater helpers
    const excludedSubstrings = ['webview', 'edgewebview', 'updater', 'update'];
    for (const name of runningProcessNames) {
      if (excludedSubstrings.some(x => name.includes(x))) continue;
      if (patterns.some(p => name.includes(p))) return true;
    }
    return false;
  };
  
  // Check for browser notifications enabled
  // Only consider browsers with status 'enabled' as threats, regardless of URL counts
  if (auditResult.browsers && auditResult.browsers.length > 0) {
    const enabledBrowsers = [];
    
    auditResult.browsers.forEach(browser => {
      if (browser.profiles && browser.profiles.length > 0) {
        // Only profiles with status 'enabled' are threats - ignore allowed/blocked URL counts
        const enabledProfiles = browser.profiles.filter(profile => profile.status === 'enabled');
        const bname = String(browser.browser || '').toLowerCase();
        const key = bname.includes('chromium') ? 'chromium'
          : bname.includes('edge') ? 'msedge'
          : bname.includes('brave') ? 'brave'
          : bname.includes('firefox') ? 'firefox'
          : 'chrome';
        // Only report as threat if corresponding browser process is actually running
        if (enabledProfiles.length > 0 && hasRunningBrowser(key)) {
          enabledBrowsers.push({
            browser: browser.browser,
            enabledProfiles: enabledProfiles.length,
            totalProfiles: browser.profiles.length
          });
        }
      }
    });
    
    if (enabledBrowsers.length > 0) {
      threats.push({
        type: 'browser_notifications_enabled',
        severity: 'high',
        browsers: enabledBrowsers,
        count: enabledBrowsers.length,
        message: `${enabledBrowsers.length} browser(s) have notifications enabled: ${enabledBrowsers.map(b => b.browser).join(', ')}`,
        action: 'User must manually disable notifications in these browsers',
        userActionRequired: true,
        settingsRequired: true
      });
    }
  }
  
  // Check for notification-enabled applications/processes
  if (auditResult.processes && auditResult.processes.length > 0) {
    const enabledApps = auditResult.processes.filter(proc => proc.notifEnabled && !isProcessNameExcluded(proc.name));
    
    if (enabledApps.length > 0) {
      threats.push({
        type: 'notification_apps_enabled',
        severity: 'medium',
        apps: enabledApps,
        count: enabledApps.length,
        message: `${enabledApps.length} notification app(s) are running: ${enabledApps.map(app => app.name).join(', ')}`,
        action: 'Consider disabling notifications in these applications',
        userActionRequired: true,
        settingsRequired: true
      });
    }
  }
  
  return threats;
}

// Function to send TOPIN events to all connected WebSocket clients
function sendTopinEvent(eventType, data = {}) {
  console.log(`\n🔥🔥🔥 ===== SENDING TOPIN EVENT ===== 🔥🔥🔥`);
  console.log(`🔥 Event Type: ${eventType}`);
  console.log(`🔥 Call from:`, new Error().stack.split('\n')[2].trim());
  console.log(`🔥 Current timestamp: ${new Date().toISOString()}`);
  
  const message = {
    type: 'topin_event',
    event: eventType,
    data: data,
    timestamp: Date.now(),
    source: 'electron_companion_app'
  };

  console.log(`📡 Message to send:`, JSON.stringify(message, null, 2));
  console.log(`📊 Total connected clients in Set: ${connectedClients.size}`);
  
  // Log all client details
  if (connectedClients.size > 0) {
    let clientIndex = 1;
    connectedClients.forEach(client => {
      console.log(`   Client ${clientIndex}: readyState=${client.readyState}, url=${client.url || 'unknown'}`);
      clientIndex++;
    });
  } else {
    console.log('⚠️⚠️⚠️ NO CONNECTED CLIENTS FOUND! ⚠️⚠️⚠️');
    return message;
  }

  let sentCount = 0;
  let clientIndex = 1;
  
  connectedClients.forEach(client => {
    console.log(`\n🚀 Attempting to send to Client ${clientIndex}:`);
    console.log(`   ReadyState: ${client.readyState} (1=OPEN, 0=CONNECTING, 2=CLOSING, 3=CLOSED)`);
    
    try {
      if (client.readyState === 1) { // WebSocket.OPEN
        console.log(`   📤 Sending message to Client ${clientIndex}...`);
        client.send(JSON.stringify(message));
        sentCount++;
        console.log(`   ✅ SUCCESS: Message sent to Client ${clientIndex}`);
      } else {
        console.log(`   ❌ FAILED: Client ${clientIndex} not ready (readyState: ${client.readyState})`);
      }
    } catch (error) {
      console.error(`   💥 EXCEPTION sending to Client ${clientIndex}:`, error.message);
      console.error(`   💥 Full error:`, error);
      connectedClients.delete(client);
      console.log(`   🗑️ Removed dead client ${clientIndex} from connectedClients`);
    }
    clientIndex++;
  });

  console.log(`\n📊 FINAL RESULT: Event "${eventType}" sent to ${sentCount}/${connectedClients.size} clients`);
  console.log(`🔥🔥🔥 ===== END TOPIN EVENT ===== 🔥🔥🔥\n`);
  return message;
}

// Enhanced LocalServer with message logging
class LoggingLocalServer extends LocalServer {
  start() {
    if (this.server) return this.port;
    this.server = require('http').createServer((req, res) => {
      if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      if (req.method === 'POST' && req.url === '/emit') {
        let body = '';
        req.on('data', chunk => { body += chunk; if (body.length > 1024 * 1024) req.destroy(); });
        req.on('end', () => {
          try {
            const json = JSON.parse(body || '{}');
            const kind = json.kind === 'stage' ? 'stage' : 'event';
            if (kind === 'stage') this.eventBus.emitStage(json.name, json.payload || null);
            else this.eventBus.emitEvent(json.name, json.payload || null);
            res.writeHead(202, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ accepted: true }));
          } catch (e) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: String(e) }));
          }
        });
        return;
      }
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    });

    this.wss = new (require('ws')).WebSocketServer({ noServer: true });
    const clients = new Set();

    this.server.on('upgrade', (req, socket, head) => {
      if (!req.url || !req.url.startsWith('/ws')) {
        socket.destroy();
        return;
      }
      this.wss.handleUpgrade(req, socket, head, (ws) => {
        this.wss.emit('connection', ws, req);
      });
    });

    // Enhanced connection handler with TOPIN events
    this.wss.on('connection', (ws) => {
      console.log('\n🔗🔗🔗 NEW WEBSOCKET CLIENT CONNECTED 🔗🔗🔗');
      console.log(`   Client readyState: ${ws.readyState}`);
      console.log(`   Client URL: ${ws.url || 'unknown'}`);
      console.log(`   Client origin: ${ws.headers?.origin || 'unknown'}`);
      
      // Add to both local clients and global connected clients
      clients.add(ws);
      connectedClients.add(ws);
      
      console.log(`   ✅ Added to clients set (size: ${clients.size})`);
      console.log(`   ✅ Added to connectedClients set (size: ${connectedClients.size})`);
      
      // Test immediate send to verify connection
      console.log('   🧪 Testing immediate send to new client...');
      try {
        const testMessage = JSON.stringify({
          type: 'connection_test',
          message: 'Connection test from server',
          timestamp: Date.now()
        });
        ws.send(testMessage);
        console.log('   ✅ Immediate test message sent successfully');
      } catch (error) {
        console.error('   ❌ Failed to send immediate test message:', error);
      }
      
      // Send CONNECTED_WITH_TOPIN_WEBSITE event
      setTimeout(() => {
        sendTopinEvent(TopinEvents.CONNECTED_WITH_TOPIN_WEBSITE, {
          message: 'Successfully connected to TOPIN companion app',
          clientCount: connectedClients.size,
          appVersion: require('./package.json').version
        });
      }, 100);
      
      // Add detailed message logging and command handling
        ws.on('message', async (data) => {
          try {
            const message = JSON.parse(data.toString());
            console.log('📥 RECEIVED MESSAGE:');
            console.log('   Raw Data:', data.toString());
            console.log('   Parsed JSON:', JSON.stringify(message, null, 2));
            console.log('   Message Type:', message.kind || message.type || 'unknown');
            console.log('   Timestamp:', new Date().toISOString());
            console.log('-----------------------------------');
            
            // Handle scan commands
            if (message.type === 'command') {
              let response = null;
              
              switch (message.action) {
                case 'start_stepped_scan':
                  console.log('🎯 WebSocket command: Starting stepped scan');
                  debugClientStatus();
                  console.log('🎯 About to call steppedScanManager.startSteppedScan()');
                  response = await steppedScanManager.startSteppedScan();
                  console.log('🎯 Scan response:', JSON.stringify(response, null, 2));
                  break;
                  
                case 'retry_step1':
                  console.log('🎯 WebSocket command: Retrying Step 1');
                  response = await steppedScanManager.retryStep1();
                  break;
                  
                case 'retry_step2':
                  console.log('🎯 WebSocket command: Retrying Step 2');
                  response = await steppedScanManager.retryStep2();
                  break;
                  
                case 'get_scan_status':
                  console.log('🎯 WebSocket command: Getting scan status');
                  response = steppedScanManager.getScanStatus();
                  break;
                  
                case 'cancel_scan':
                  console.log('🎯 WebSocket command: Cancelling scan');
                  response = steppedScanManager.cancelScan();
                  break;
                  
                case 'reset_scan':
                  console.log('🎯 WebSocket command: Resetting scan state');
                  response = steppedScanManager.resetScan();
                  break;
                  
                case 'test_event':
                  console.log('🎯 WebSocket command: Testing event sending');
                  debugClientStatus();
                  sendTopinEvent('TEST_EVENT', {
                    message: 'This is a test event',
                    clientCount: connectedClients.size,
                    timestamp: Date.now()
                  });
                  response = { ok: true, message: 'Test event sent', clientCount: connectedClients.size };
                  break;
                  
                case 'debug_clients':
                  console.log('🎯 WebSocket command: Debug client status');
                  debugClientStatus();
                  response = { 
                    ok: true, 
                    message: 'Client status logged to console', 
                    clientCount: connectedClients.size 
                  };
                  break;
                  
                default:
                  response = { ok: false, error: `Unknown command: ${message.action}` };
              }
              
              // Send response back to WebSocket client
              if (response) {
                const responseMessage = {
                  type: 'command_response',
                  originalCommand: message.action,
                  result: response,
                  timestamp: Date.now()
                };
                
                ws.send(JSON.stringify(responseMessage));
                console.log('📤 SENT COMMAND RESPONSE:', JSON.stringify(responseMessage, null, 2));
              }
            }
            
            // Forward to renderer if window exists
            if (mainWindow && !mainWindow.isDestroyed()) {
              mainWindow.webContents.send('websocket:message', message);
            }
          } catch (e) {
            console.log('📥 RECEIVED RAW MESSAGE (not JSON):');
            console.log('   Data:', data.toString());
            console.log('   Parse Error:', e.message);
            console.log('-----------------------------------');
          }
        });
        
      ws.on('close', () => {
        console.log('\n❌❌❌ WEBSOCKET CLIENT DISCONNECTED ❌❌❌');
        console.log(`   connectedClients before removal: ${connectedClients.size}`);
        console.log(`   clients before removal: ${clients.size}`);
        
        const removedFromConnected = connectedClients.delete(ws);
        const removedFromClients = clients.delete(ws);
        
        console.log(`   ✅ Removed from connectedClients: ${removedFromConnected}`);
        console.log(`   ✅ Removed from clients: ${removedFromClients}`);
        console.log(`   connectedClients after removal: ${connectedClients.size}`);
        console.log(`   clients after removal: ${clients.size}`);
      });
      
      ws.on('error', (error) => {
        console.log('⚠️ WebSocket error:', error.message);
        connectedClients.delete(ws);
      });
      
      // Send welcome message
      setTimeout(() => {
        const welcomeMessage = {
          type: 'welcome',
          message: 'Connected to Electron app successfully!',
          timestamp: Date.now(),
          server: 'electron-companion-app'
        };
        
        try {
          ws.send(JSON.stringify(welcomeMessage));
          console.log('📤 SENT WELCOME MESSAGE:', JSON.stringify(welcomeMessage, null, 2));
        } catch (e) {
          console.log('⚠️ Failed to send welcome message:', e.message);
        }
      }, 200);
    });

    // Set up EventBus subscription for broadcasting
    this.unsubscribe = this.eventBus.subscribe((message) => {
      const json = JSON.stringify(message);
      for (const ws of clients) {
        try {
          if (ws.readyState === 1) ws.send(json);
        } catch {}
      }
    });

    this.server.listen(this.port, this.host);
    return this.port;
  }
}

// Initialize enhanced LocalServer with logging
const localServer = new LoggingLocalServer(eventBus, {
  port: 8080,  // WebSocket server on port 8080
  host: '127.0.0.1'
});

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 960,
    height: 600,
    minWidth: 860,
    minHeight: 540,
    backgroundColor: '#0b1221',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      webSecurity: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // Debug helper: open DevTools automatically if env var set
  if (process.env.TOPIN_OPEN_DEVTOOLS === '1') {
    try { mainWindow.webContents.openDevTools({ mode: 'detach' }); } catch {}
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  // Route Chromium logs to macOS Console when needed
  if (process.env.TOPIN_ENABLE_LOGGING === '1') {
    try { app.commandLine.appendSwitch('enable-logging'); } catch {}
  }
  // Add a small delay to prevent race conditions on macOS
  setTimeout(() => {
    createWindow();
  }, 100);

  // Start WebSocket server to accept incoming connections
  try {
    const serverPort = localServer.start();
    if (serverPort) {
      console.log(`✅ WebSocket server started on ws://localhost:${serverPort}/ws`);
      console.log(`   Connect from Postman to: ws://localhost:${serverPort}/ws`);
      console.log(`   Waiting for incoming WebSocket connections...`);
    } else {
      console.error('❌ Failed to start WebSocket server');
    }
  } catch (error) {
    console.error('❌ Error starting WebSocket server:', error);
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    // Clean up WebSocket server
    localServer.stop();
    app.quit();
  }
});

app.on('before-quit', () => {
  // Ensure WebSocket server is closed
  localServer.stop();
});

// Load malicious signatures
let maliciousSignatures = { processNames: [], ports: [], domains: [], packages: [] };
const signaturesPath = app.isPackaged
  ? path.join(process.resourcesPath, 'data', 'malicious.json')
  : path.join(__dirname, 'data', 'malicious.json');
function loadSignatures() {
  try {
    const raw = fs.readFileSync(signaturesPath, 'utf8');
    const parsed = JSON.parse(raw);
    maliciousSignatures = {
      processNames: (parsed.processNames || []).map(s => String(s).toLowerCase()),
      ports: (parsed.ports || []).map(p => String(p)),
      domains: (parsed.domains || []).map(d => String(d).toLowerCase()),
      packages: parsed.packages || []
    };
  } catch (e) {
    maliciousSignatures = { processNames: [], ports: [], domains: [], packages: [] };
  }
}
loadSignatures();
try { fs.watch(signaturesPath, { persistent: false }, () => loadSignatures()); } catch {}

async function getFallbackProcessesPOSIX() {
  return new Promise(resolve => {
    exec('ps axo pid,ppid,pcpu,pmem,comm,command --no-headers', { timeout: 3000 }, (err, stdout) => {
      if (err || !stdout) return resolve([]);
      const rows = stdout.trim().split('\n');
      const procs = [];
      for (const line of rows) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 6) continue;
        const [pid, ppid, pcpu, pmem, comm, ...cmdParts] = parts;
        const command = cmdParts.join(' ');
        procs.push({ pid: parseInt(pid) || 0, ppid: parseInt(ppid) || 0, pcpu: parseFloat(pcpu) || 0, pmem: parseFloat(pmem) || 0, name: comm || 'unknown', command });
      }
      resolve(procs);
    });
  });
}

async function scanSystem() {
  try {
    const [processes, currentLoad] = await Promise.all([
      si.processes().catch(err => {
        console.warn('systeminformation.processes() failed:', err);
        return { list: [] };
      }), 
      si.currentLoad().catch(err => {
        console.warn('systeminformation.currentLoad() failed:', err);
        return { currentLoad: 0 };
      })
    ]);
    let running = (processes.list || []).map(p => ({ pid: p.pid, name: p.name || 'unknown', path: p.path, user: p.user, cpu: Number.isFinite(p.pcpu) ? p.pcpu : 0, mem: Number.isFinite(p.pmem) ? p.pmem : 0, command: p.command || '' }));
    if (running.length === 0) {
      try {
        const fb = await getFallbackProcessesPOSIX();
        if (fb.length) running = fb.map(p => ({ pid: p.pid, name: p.name, path: '', user: '', cpu: Number.isFinite(p.pcpu) ? p.pcpu : 0, mem: Number.isFinite(p.pmem) ? p.pmem : 0, command: p.command }));
      } catch {}
    }
    running.sort((a,b) => (b.cpu || 0) - (a.cpu || 0));
    const runningLimited = running.slice(0, 500);
    return { platform: os.platform(), arch: os.arch(), load: Number.isFinite(currentLoad.currentLoad) ? currentLoad.currentLoad : 0, processes: runningLimited };
  } catch (error) {
    console.warn('scanSystem() failed with error:', error);
    return { platform: os.platform(), arch: os.arch(), load: 0, processes: [] };
  }
}

ipcMain.handle('app:getNotificationStatus', async () => notificationService.getNotificationStatus());
ipcMain.handle('app:getFocusStatus', async () => notificationService.getFocusStatus());
ipcMain.handle('app:openNotificationSettings', async () => notificationService.openNotificationSettings());
ipcMain.handle('app:auditNotifications', async (_evt, _providedScanId) => {
  try {
    // Send SCANNING_STARTED event to TOPIN website
    const scanId = Date.now();
    sendTopinEvent(TopinEvents.SCANNING_STARTED, {
      scanId: scanId,
      scanType: 'notification_audit',
      steps: ['notification_audit'],
      currentStep: 1,
      stepName: 'notification_audit'
    });
    
    const audit = await notificationService.auditNotifications();
    
    // Analyze notification threats similar to stepped scan
    const notificationThreats = analyzeNotificationThreatsFromAudit(audit);
    
    if (notificationThreats.length > 0) {
      // Send NOTIFICATION_APPLICATION_DETECTED event for each detection
      notificationThreats.forEach(threat => {
        sendTopinEvent(TopinEvents.NOTIFICATION_APPLICATION_DETECTED, {
          scanId: scanId,
          scanType: 'notification_audit',
          threat: threat,
          type: threat.type,
          severity: threat.severity,
          message: threat.message,
          action: threat.action,
          browsers: threat.browsers || [],
          apps: threat.apps || []
        });
      });
    } else {
      // Send NOTIFICATION_CHECK_COMPLETE event when no threats found
      sendTopinEvent(TopinEvents.NOTIFICATION_CHECK_COMPLETE, {
        scanId: scanId,
        scanType: 'notification_audit',
        message: 'Notification check completed successfully - no threats found',
        auditResult: {
          systemStatus: audit.system?.status || 'unknown',
          browserCount: audit.browsers?.length || 0,
          processCount: audit.processes?.length || 0
        }
      });
      // Pair with suspicious completion (from app:scan) in a time window
      sequentialCompletion.notifComplete = true;
      if (sequentialCompletion.notifComplete && sequentialCompletion.suspiciousComplete) {
        sendTopinEvent(TopinEvents.SYSTEM_CHECK_SUCCESSFUL, {
          scanId: Date.now(),
          scanType: 'sequential_checks',
          message: 'All system checks completed successfully - no threats detected'
        });
        clearSequentialCompletion();
      } else {
        armSequentialCompletionExpiry();
      }
    }
    
    // Include threats in return payload for renderer consumption
    return { ok: true, threats: notificationThreats, ...audit };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

ipcMain.handle('app:openGuide', async (_evt, kind) => {
  const { shell } = require('electron');
  const guides = {
    general: 'https://support.google.com/chrome/answer/3220216?hl=en',
    firefox: 'https://support.mozilla.org/kb/push-notifications-firefox',
    edge: 'https://support.microsoft.com/microsoft-edge/block-pop-ups-and-notifications-in-microsoft-edge-0cdb1634-74f4-fa23-c8be-d17c73f38dd2'
  };
  const url = guides[kind] || guides.general;
  try { await shell.openExternal(url); return true; } catch { return false; }
});

// Stepped scanning system with user intervention
class SteppedScanManager {
  constructor() {
    this.currentScan = null;
    this.scanState = 'idle'; // 'idle', 'step1_notification', 'step1_blocked', 'step2_security', 'step2_blocked', 'completed'
    this.detections = { notifications: [], security: [] };
  }

  async startSteppedScan() {
    console.log('🚀 startSteppedScan() method called');
    console.log(`🚀 Current scan state: ${this.scanState}`);
    console.log(`🚀 Current scan:`, this.currentScan);
    
    // Allow restarting if scan is blocked or completed
    if (this.currentScan && this.scanState !== 'step1_blocked' && this.scanState !== 'step2_blocked' && this.scanState !== 'completed') {
      console.log('❌ Scan already in progress, returning error');
      return { ok: false, error: 'Scan already in progress' };
    }

    // Reset any previous scan state
    this.currentScan = {
      id: Date.now(),
      startTime: Date.now(),
      currentStep: 1,
      status: 'running'
    };

    this.scanState = 'step1_notification';
    this.detections = { notifications: [], security: [] };

    console.log('🔍 Starting new stepped scan - Step 1: Notification Audit');
    console.log(`🔍 Scan ID: ${this.currentScan.id}`);
    
    // Send SCANNING_STARTED event to TOPIN website
    sendTopinEvent(TopinEvents.SCANNING_STARTED, {
      scanId: this.currentScan.id,
      scanType: 'stepped_scan',
      steps: ['notification_audit', 'security_scan'],
      currentStep: 1,
      stepName: 'notification_audit'
    });
    
    // Emit scan started event for internal use
    eventBus.emitStage('STEPPED_SCAN_STARTED', {
      scanId: this.currentScan.id,
      step: 1,
      stepName: 'notification_audit'
    });

    return this.executeStep1();
  }

  async executeStep1() {
    try {
      console.log('📱 Auditing notification settings...');
      
      const auditResult = await notificationService.auditNotifications();
      
      // Check for notification-related detections
      const notificationThreats = analyzeNotificationThreatsFromAudit(auditResult);
      this.detections.notifications = notificationThreats;

      if (notificationThreats.length > 0) {
        console.log(`⚠️ Found ${notificationThreats.length} notification-related issues - SCAN BLOCKED`);
        console.log('🛑 Scan will NOT proceed to Step 2 until these issues are resolved');
        this.scanState = 'step1_blocked';
        
        // Send NOTIFICATION_APPLICATION_DETECTED event for each detection
        notificationThreats.forEach(threat => {
          sendTopinEvent(TopinEvents.NOTIFICATION_APPLICATION_DETECTED, {
            scanId: this.currentScan.id,
            threat: threat,
            type: threat.type,
            severity: threat.severity,
            message: threat.message,
            action: threat.action,
            browsers: threat.browsers || [],
            apps: threat.apps || []
          });
        });
        
        eventBus.emitStage('SCAN_STEP1_BLOCKED', {
          scanId: this.currentScan.id,
          detections: notificationThreats,
          message: 'SCAN BLOCKED: User must resolve notification issues before proceeding',
          blocked: true,
          waitingForUser: true
        });

        return {
          ok: true,
          status: 'blocked',
          step: 1,
          stepName: 'notification_audit',
          detections: notificationThreats,
          message: 'SCAN BLOCKED: Please resolve the notification issues and run the scan again',
          nextAction: 'user_must_resolve_notifications_and_rescan',
          blocked: true,
          canProceed: false
        };
      } else {
        console.log('✅ No notification threats detected, proceeding to Step 2');
        
        // Send NOTIFICATION_CHECK_COMPLETE event
        sendTopinEvent(TopinEvents.NOTIFICATION_CHECK_COMPLETE, {
          scanId: this.currentScan.id,
          message: 'Notification check completed successfully - no threats found',
          step: 1,
          nextStep: 2
        });
        
        eventBus.emitStage('SCAN_STEP1_COMPLETED', {
          scanId: this.currentScan.id,
          step: 1,
          message: 'Step 1 completed successfully - proceeding to security scan'
        });
        return this.executeStep2();
      }
    } catch (e) {
      this.scanState = 'idle';
      this.currentScan = null;
      return { ok: false, error: `Step 1 failed: ${String(e)}` };
    }
  }

  async executeStep2() {
    try {
      this.scanState = 'step2_security';
      this.currentScan.currentStep = 2;

      console.log('🔍 Starting Step 2: Security and Threat Scan');
      
      eventBus.emitStage('SCAN_STEP2_STARTED', {
        scanId: this.currentScan.id,
        step: 2,
        stepName: 'security_scan'
      });

      const systemReport = await scanSystem();
      const securityThreats = await securityService.runAllChecks({ 
        processNames: maliciousSignatures.processNames, 
        ports: maliciousSignatures.ports.map(p => Number(p)), 
        domains: maliciousSignatures.domains 
      });

      // runAllChecks returns array directly, not object with threats property
      this.detections.security = Array.isArray(securityThreats) ? securityThreats : [];

      if (securityThreats && securityThreats.length > 0) {
        console.log(`⚠️ Found ${securityThreats.length} security threats`);
        this.scanState = 'step2_blocked';
        
        // Send SUSPICIOUS_APPLICATION_DETECTED event for each security threat
        securityThreats.forEach(threat => {
          sendTopinEvent(TopinEvents.SUSPICIOUS_APPLICATION_DETECTED, {
            scanId: this.currentScan.id,
            threat: threat,
            type: threat.type,
            severity: threat.severity,
            message: threat.message,
            details: threat.details || {},
            processInfo: {
              name: threat.details?.name || threat.name,
              pid: threat.details?.pid || threat.pid,
              port: threat.details?.port || threat.port
            }
          });
        });
        
        eventBus.emitStage('SCAN_STEP2_BLOCKED', {
          scanId: this.currentScan.id,
          detections: securityThreats,
          message: 'Security threats detected - user intervention required'
        });

        return {
          ok: true,
          status: 'blocked',
          step: 2,
          stepName: 'security_scan',
          detections: securityThreats,
          systemReport,
          message: 'Security threats detected. Please resolve these issues before completing the scan',
          nextAction: 'user_must_resolve_security_threats'
        };
      } else {
        console.log('✅ No security threats detected');
        
        // Send SUSPICIOUS_CHECK_COMPLETE event
        sendTopinEvent(TopinEvents.SUSPICIOUS_CHECK_COMPLETE, {
          scanId: this.currentScan.id,
          message: 'Security check completed successfully - no threats found',
          step: 2,
          systemReport: {
            platform: systemReport.platform,
            processCount: systemReport.processes?.length || 0,
            cpuLoad: systemReport.load
          }
        });
        
        return this.completeScan(systemReport);
      }
    } catch (e) {
      this.scanState = 'idle';
      this.currentScan = null;
      return { ok: false, error: `Step 2 failed: ${String(e)}` };
    }
  }

  async retryStep1() {
    if (this.scanState !== 'step1_blocked') {
      return { ok: false, error: 'Cannot retry step 1 - not in blocked state' };
    }
    
    console.log('🔄 User initiated retry of Step 1: Notification Audit');
    console.log('⚠️ Verifying if notification issues have been resolved...');
    
    // Reset current scan step but keep the scan ID
    this.currentScan.currentStep = 1;
    this.scanState = 'step1_notification';
    
    return this.executeStep1();
  }

  async retryStep2() {
    if (this.scanState !== 'step2_blocked') {
      return { ok: false, error: 'Cannot retry step 2 - not in blocked state' };
    }
    
    console.log('🔄 Retrying Step 2: Security Scan');
    return this.executeStep2();
  }

  async completeScan(systemReport = null) {
    this.scanState = 'completed';
    const endTime = Date.now();
    
    const finalReport = {
      scanId: this.currentScan.id,
      startTime: this.currentScan.startTime,
      endTime,
      duration: endTime - this.currentScan.startTime,
      status: 'completed',
      allDetections: this.detections,
      systemReport: systemReport || await scanSystem(),
      summary: {
        notificationIssues: this.detections.notifications.length,
        securityThreats: this.detections.security.length,
        totalIssues: this.detections.notifications.length + this.detections.security.length
      }
    };

    // Send SYSTEM_CHECK_SUCCESSFUL event
    sendTopinEvent(TopinEvents.SYSTEM_CHECK_SUCCESSFUL, {
      scanId: finalReport.scanId,
      message: 'All system checks completed successfully - no threats detected',
      duration: finalReport.duration,
      summary: finalReport.summary,
      systemReport: {
        platform: finalReport.systemReport?.platform,
        processCount: finalReport.systemReport?.processes?.length || 0,
        cpuLoad: finalReport.systemReport?.load
      },
      completedSteps: ['notification_audit', 'security_scan']
    });
    
    eventBus.emitStage('STEPPED_SCAN_COMPLETED', finalReport);
    
    console.log('✅ Stepped scan completed successfully');
    this.currentScan = null;
    
    return {
      ok: true,
      status: 'completed',
      report: finalReport
    };
  }



  getScanStatus() {
    return {
      scanActive: this.currentScan !== null,
      scanId: this.currentScan?.id || null,
      state: this.scanState,
      currentStep: this.currentScan?.currentStep || 0,
      detections: this.detections,
      canStartNewScan: this.scanState === 'idle' || this.scanState === 'step1_blocked' || this.scanState === 'step2_blocked' || this.scanState === 'completed',
      isBlocked: this.scanState === 'step1_blocked' || this.scanState === 'step2_blocked',
      isCompleted: this.scanState === 'completed'
    };
  }

  resetScan() {
    console.log('🔄 Resetting scan state');
    this.currentScan = null;
    this.scanState = 'idle';
    this.detections = { notifications: [], security: [] };
    
    eventBus.emitStage('SCAN_RESET', {
      message: 'Scan state has been reset',
      timestamp: Date.now()
    });
    
    return { ok: true, message: 'Scan state reset successfully' };
  }

  cancelScan() {
    if (this.currentScan) {
      eventBus.emitStage('STEPPED_SCAN_CANCELLED', {
        scanId: this.currentScan.id,
        reason: 'user_cancelled'
      });
    }
    
    this.currentScan = null;
    this.scanState = 'idle';
    this.detections = { notifications: [], security: [] };
    
    return { ok: true, message: 'Scan cancelled' };
  }
}

// IPC to list categorized threat applications (installed, running, services, browser extensions)
ipcMain.handle('app:listThreatApps', async () => {
  try {
    const res = await securityService.listThreatApplications();
    return { ok: true, ...res };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

const steppedScanManager = new SteppedScanManager();

// Legacy scan function for compatibility with renderer.js
async function legacyScan(options = {}) {
  try {
    const { skipEvents = false, scanId = Date.now(), scanType = 'legacy_scan' } = options;
    
    console.log('🔍 Running legacy scan (for UI compatibility)');
    
    // Send SCANNING_STARTED event only if not skipping events
    if (!skipEvents) {
      sendTopinEvent(TopinEvents.SCANNING_STARTED, {
        scanId: scanId,
        scanType: scanType,
        steps: ['system_scan', 'security_scan'],
        currentStep: 1,
        stepName: 'system_scan'
      });
    }
    
    const systemReport = await scanSystem();
    const threats = await securityService.runAllChecks({ 
      processNames: maliciousSignatures.processNames, 
      ports: maliciousSignatures.ports.map(p => Number(p)), 
      domains: maliciousSignatures.domains 
    });
    
    // Ensure threats is always an array
    systemReport.threats = Array.isArray(threats) ? threats : [];
    
    // Send appropriate events based on threat detection results (only if not skipping events)
    if (!skipEvents) {
      if (systemReport.threats.length > 0) {
        // Send SUSPICIOUS_APPLICATION_DETECTED event for each threat
        systemReport.threats.forEach(threat => {
          sendTopinEvent(TopinEvents.SUSPICIOUS_APPLICATION_DETECTED, {
            scanId: scanId,
            scanType: scanType,
            threat: threat,
            type: threat.type,
            severity: threat.severity,
            message: threat.message,
            details: threat.details || {},
            processInfo: {
              name: threat.details?.name || threat.name,
              pid: threat.details?.pid || threat.pid,
              port: threat.details?.port || threat.port
            }
          });
        });
      } else {
        // Send SUSPICIOUS_CHECK_COMPLETE event when no threats found
        sendTopinEvent(TopinEvents.SUSPICIOUS_CHECK_COMPLETE, {
          scanId: scanId,
          scanType: scanType,
          message: 'Security check completed successfully - no threats found',
          systemReport: {
            platform: systemReport.platform,
            processCount: systemReport.processes?.length || 0,
            cpuLoad: systemReport.load
          }
        });
      }
    }
    
    console.log(`✅ Legacy scan completed. Found ${systemReport.threats.length} threats`);
    return { ok: true, report: systemReport };
  } catch (e) {
    console.error('❌ Legacy scan failed:', e);
    return { ok: false, error: String(e) };
  }
}

// Function to perform complete system check (legacy scan + notification audit)
async function completeSystemCheck() {
  try {
    const scanId = Date.now();
    
    // Send SCANNING_STARTED event (notifications first)
    sendTopinEvent(TopinEvents.SCANNING_STARTED, {
      scanId: scanId,
      scanType: 'complete_system_check',
      steps: ['notification_audit', 'security_scan'],
      currentStep: 1,
      stepName: 'notification_audit'
    });
    
    // Step 1: Notification audit
    const notificationResult = await notificationService.auditNotifications();
    const notificationThreats = analyzeNotificationThreatsFromAudit(notificationResult);
    const hasNotificationThreats = notificationThreats.length > 0;
    
    // Send notification events
    if (hasNotificationThreats) {
      notificationThreats.forEach(threat => {
        sendTopinEvent(TopinEvents.NOTIFICATION_APPLICATION_DETECTED, {
          scanId: scanId,
          scanType: 'complete_system_check',
          threat: threat,
          type: threat.type,
          severity: threat.severity,
          message: threat.message,
          action: threat.action,
          browsers: threat.browsers || [],
          apps: threat.apps || []
        });
      });
    } else {
      sendTopinEvent(TopinEvents.NOTIFICATION_CHECK_COMPLETE, {
        scanId: scanId,
        scanType: 'complete_system_check',
        message: 'Notification check completed successfully - no threats found',
        auditResult: {
          systemStatus: notificationResult.system?.status || 'unknown',
          browserCount: notificationResult.browsers?.length || 0,
          processCount: notificationResult.processes?.length || 0
        }
      });
    }
    
    // Step 2: Security scan (skip events - we'll send them ourselves)
    const securityResult = await legacyScan({ 
      skipEvents: true, 
      scanId: scanId, 
      scanType: 'complete_system_check' 
    });
    const securityOk = !!(securityResult && securityResult.ok);
    const hasSecurityThreats = securityOk && securityResult.report.threats && securityResult.report.threats.length > 0;
    
    // Send security events
    if (hasSecurityThreats) {
      securityResult.report.threats.forEach(threat => {
        sendTopinEvent(TopinEvents.SUSPICIOUS_APPLICATION_DETECTED, {
          scanId: scanId,
          scanType: 'complete_system_check',
          threat: threat,
          type: threat.type,
          severity: threat.severity,
          message: threat.message,
          details: threat.details || {},
          processInfo: {
            name: threat.details?.name || threat.name,
            pid: threat.details?.pid || threat.pid,
            port: threat.details?.port || threat.port
          }
        });
      });
    } else if (securityOk) {
      sendTopinEvent(TopinEvents.SUSPICIOUS_CHECK_COMPLETE, {
        scanId: scanId,
        scanType: 'complete_system_check',
        message: 'Security check completed successfully - no threats found',
        systemReport: {
          platform: securityResult.report.platform,
          processCount: securityResult.report.processes?.length || 0,
          cpuLoad: securityResult.report.load
        }
      });
    }
    
    // Send SYSTEM_CHECK_SUCCESSFUL only if both completion events were sent
    const sentNotificationComplete = !hasNotificationThreats;
    const sentSuspiciousComplete = securityOk && !hasSecurityThreats;
    if (sentNotificationComplete && sentSuspiciousComplete) {
      sendTopinEvent(TopinEvents.SYSTEM_CHECK_SUCCESSFUL, {
        scanId: scanId,
        scanType: 'complete_system_check',
        message: 'All system checks completed successfully - no threats detected',
        completedChecks: ['notification_audit', 'security_scan'],
        systemReport: securityOk ? {
          platform: securityResult.report.platform,
          processCount: securityResult.report.processes?.length || 0,
          cpuLoad: securityResult.report.load
        } : undefined,
        auditResult: {
          systemStatus: notificationResult.system?.status || 'unknown',
          browserCount: notificationResult.browsers?.length || 0,
          processCount: notificationResult.processes?.length || 0
        }
      });
    }
    
    // Return combined results
    return {
      ok: true,
      security: securityOk ? securityResult.report : { threats: [], platform: process.platform, processes: [], load: 0 },
      notifications: {
        ...notificationResult,
        threats: notificationThreats
      },
      hasThreats: hasSecurityThreats || hasNotificationThreats,
      completionEvents: {
        notificationComplete: sentNotificationComplete,
        suspiciousComplete: sentSuspiciousComplete,
        systemSuccess: sentNotificationComplete && sentSuspiciousComplete
      }
    };
    
  } catch (e) {
    console.error('❌ Complete system check failed:', e);
    return { ok: false, error: String(e) };
  }
}

// Updated IPC handlers for stepped scanning
// Track completion state for sequential UI flow (no strict single-session requirement)
const sequentialCompletion = { notifComplete: false, suspiciousComplete: false, timer: null };
function clearSequentialCompletion() {
  sequentialCompletion.notifComplete = false;
  sequentialCompletion.suspiciousComplete = false;
  if (sequentialCompletion.timer) {
    try { clearTimeout(sequentialCompletion.timer); } catch {}
    sequentialCompletion.timer = null;
  }
}
function armSequentialCompletionExpiry() {
  if (sequentialCompletion.timer) {
    try { clearTimeout(sequentialCompletion.timer); } catch {}
  }
  sequentialCompletion.timer = setTimeout(() => {
    clearSequentialCompletion();
  }, 20000); // auto-expire after 20s if the other half doesn't arrive
}

ipcMain.handle('app:scan', async (_evt, _providedScanId) => {
  // Use legacy scan for compatibility with existing UI
  const res = await legacyScan({});
  try {
    if (res && res.ok && res.report && Array.isArray(res.report.threats)) {
      const hasThreats = res.report.threats.length > 0;
      if (!hasThreats) {
        sequentialCompletion.suspiciousComplete = true;
        if (sequentialCompletion.notifComplete && sequentialCompletion.suspiciousComplete) {
          sendTopinEvent(TopinEvents.SYSTEM_CHECK_SUCCESSFUL, {
            scanId: Date.now(),
            scanType: 'sequential_checks',
            message: 'All system checks completed successfully - no threats detected'
          });
          clearSequentialCompletion();
        } else {
          armSequentialCompletionExpiry();
        }
      } else {
        clearSequentialCompletion();
      }
    }
  } catch {}
  return res;
});

ipcMain.handle('app:completeSystemCheck', async () => {
  // New comprehensive check that coordinates both security and notifications
  return completeSystemCheck();
});

ipcMain.handle('app:startSteppedScan', async () => {
  return steppedScanManager.startSteppedScan();
});

ipcMain.handle('app:retryStep1', async () => {
  return steppedScanManager.retryStep1();
});

ipcMain.handle('app:retryStep2', async () => {
  return steppedScanManager.retryStep2();
});

ipcMain.handle('app:getScanStatus', async () => {
  return steppedScanManager.getScanStatus();
});

ipcMain.handle('app:cancelScan', async () => {
  return steppedScanManager.cancelScan();
});

ipcMain.handle('app:resetScan', async () => {
  return steppedScanManager.resetScan();
});

// Auto-scan worker (Node worker thread) to keep main thread responsive
const { Worker } = require('worker_threads');
let autoScanWorker = null;

function startAutoScanWorker(intervalMs = 30000) {
  if (autoScanWorker) return true;
  const workerPath = app.isPackaged
    ? path.join(process.resourcesPath, 'app.asar.unpacked', 'workers', 'autoScanWorker.js')
    : path.join(__dirname, 'workers', 'autoScanWorker.js');
  autoScanWorker = new Worker(workerPath, {
    workerData: null
  });
  autoScanWorker.on('message', (msg) => {
    if (!msg) return;
    if (msg.type === 'result') {
      // Handle scan results and send appropriate threat detection events
      if (msg.payload && msg.payload.ok && msg.payload.report) {
        const threats = msg.payload.report.threats || [];
        
        if (threats.length > 0) {
          // Send SUSPICIOUS_APPLICATION_DETECTED event for each threat
          threats.forEach(threat => {
            sendTopinEvent(TopinEvents.SUSPICIOUS_APPLICATION_DETECTED, {
              scanId: Date.now(),
              scanType: 'auto_scan',
              threat: threat,
              type: threat.type,
              severity: threat.severity,
              message: threat.message,
              details: threat.details || {},
              processInfo: {
                name: threat.details?.name || threat.name,
                pid: threat.details?.pid || threat.pid,
                port: threat.details?.port || threat.port
              }
            });
          });
        } else {
          // Send SUSPICIOUS_CHECK_COMPLETE event when no threats found
          sendTopinEvent(TopinEvents.SUSPICIOUS_CHECK_COMPLETE, {
            scanId: Date.now(),
            scanType: 'auto_scan',
            message: 'Security check completed successfully - no threats found',
            systemReport: {
              platform: msg.payload.report.platform,
              processCount: msg.payload.report.processes?.length || 0,
              cpuLoad: msg.payload.report.load
            }
          });
        }
      }
      
      // Send result to renderer process
      if (mainWindow && !mainWindow.isDestroyed()) {
        try { mainWindow.webContents.send('app:autoScanResult', msg.payload); } catch {}
      }
    }
  });
  autoScanWorker.on('error', () => { /* noop: keep app running */ });
  autoScanWorker.on('exit', () => { autoScanWorker = null; });
  autoScanWorker.postMessage({ type: 'start', intervalMs, signatures: {
    processNames: maliciousSignatures.processNames,
    ports: maliciousSignatures.ports.map(p => Number(p)),
    domains: maliciousSignatures.domains
  }});
  return true;
}

function stopAutoScanWorker() {
  if (!autoScanWorker) return true;
  try { autoScanWorker.postMessage({ type: 'stop' }); } catch {}
  try { autoScanWorker.terminate(); } catch {}
  autoScanWorker = null;
  return true;
}

ipcMain.handle('app:autoScanStart', async (_evt, intervalMs) => {
  try { return startAutoScanWorker(Number(intervalMs) || 30000); } catch { return false; }
});

ipcMain.handle('app:autoScanStop', async () => {
  try { return stopAutoScanWorker(); } catch { return false; }
});

// IPC handlers for WebSocket communication
ipcMain.handle('app:sendToClients', async (_evt, data) => {
  try {
    eventBus.emitEvent('FROM_APP', data);
    console.log('📤 SENT TO CLIENTS:', JSON.stringify(data, null, 2));
    return { ok: true };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

ipcMain.handle('app:getServerStatus', async () => {
  return {
    running: localServer.server && localServer.server.listening,
    port: localServer.port,
    endpoint: `ws://localhost:${localServer.port}/ws`
  };
}); 

// Permission preflight for browser tab access
ipcMain.handle('app:checkBrowserTabPermissions', async () => {
  try {
    const res = await securityService.checkBrowserTabAccessPermissions();
    return { ok: true, ...res };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// Debug: Test tab detection
ipcMain.handle('app:testTabDetection', async (_evt, browserName) => {
  try {
    const res = await securityService.testTabDetection(browserName);
    return { ok: true, ...res };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// Logging control
ipcMain.handle('app:setLogging', async (_evt, enabled) => {
  try {
    securityService.setLogging(enabled);
    try { notificationService.setLogging(enabled); } catch {}
    return { ok: true, enabled };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

ipcMain.handle('app:getLoggingStatus', async () => {
  try {
    const enabled = securityService.getLoggingStatus();
    try { if (enabled) notificationService.setLogging(true); } catch {}
    return { ok: true, enabled };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// NotificationService-only logging controls
ipcMain.handle('app:setNotificationLogging', async (_evt, enabled) => {
  try {
    notificationService.setLogging(!!enabled);
    return { ok: true, enabled: !!enabled };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

ipcMain.handle('app:getNotificationLoggingStatus', async () => {
  try {
    const enabled = !!notificationService.getLoggingStatus();
    return { ok: true, enabled };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// List only actively sharing tabs in currently open browsers
ipcMain.handle('app:listActiveSharingTabs', async () => {
  try {
    const tabs = await securityService.getActiveScreenSharingTabs();
    return { ok: true, tabs };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// Exam mode: allow only one browser family and the companion app; flag the rest
ipcMain.handle('app:runExamModeCheck', async (_evt, options) => {
  try {
    const pkg = require('./package.json');
    const appName = String(pkg.name || '').toLowerCase();
    const exeBase = (process.execPath || '').split(/[\\/]/).pop().toLowerCase();
    const defaults = {
      allowedCompanionMatches: [appName, 'electron', 'companion', 'topin', exeBase].filter(Boolean),
      preferredBrowserFamily: null
    };
    const opts = Object.assign({}, defaults, options || {});
    // On Linux, route to SecurityService for threat/malicious detection instead of ExamModeService
    if (process.platform === 'linux') {
      const [systemReport, threats] = await Promise.all([
        scanSystem().catch(() => ({ processes: [], platform: 'linux', load: 0 })),
        securityService.runAllChecks({
          processNames: maliciousSignatures.processNames,
          ports: maliciousSignatures.ports.map(p => Number(p)),
          domains: maliciousSignatures.domains
        }).catch(() => [])
      ]);
      const byPid = new Map((systemReport.processes || []).map(p => [p.pid, p]));
      const flagged = [];
      for (const t of (threats || [])) {
        const pid = (t && t.details && t.details.pid) ? Number(t.details.pid) : (t && t.pid ? Number(t.pid) : 0);
        const proc = pid && byPid.get(pid);
        const name = (t && t.details && t.details.name) || t.name || (proc && proc.name) || 'unknown';
        const cpu = proc ? (Number(proc.cpu) || 0) : 0;
        const mem = proc ? (Number(proc.mem) || 0) : 0;
        const command = proc ? (proc.command || '') : '';
        flagged.push({ pid: pid || 0, name, cpu, mem, command });
      }
      return {
        ok: true,
        summary: {
          totalProcesses: (systemReport.processes || []).length,
          nonSystemProcesses: 0,
          flaggedCount: flagged.length,
          activeBrowsers: [],
          allowedBrowserFamily: null,
          multipleBrowsersActive: false
        },
        flagged,
        allowed: {
          browserFamily: null,
          companionMatches: opts.allowedCompanionMatches
        },
        linuxActiveWindows: []
      };
    }
    const res = await examModeService.runExamModeChecks(opts);
    return res;
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});