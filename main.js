const { app, BrowserWindow, ipcMain } = require('electron');
app.disableHardwareAcceleration();
app.commandLine.appendSwitch('disable-gpu-vsync');
app.commandLine.appendSwitch('log-level', '3');
const path = require('path');
const os = require('os');
const si = require('systeminformation');
const fs = require('fs');
const { exec } = require('child_process');
const SecurityService = require('./security/SecurityService');
const NotificationService = require('./security/NotificationService');
const securityService = new SecurityService();
const notificationService = new NotificationService();

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
      sandbox: true
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// Load malicious signatures
let maliciousSignatures = { processNames: [], ports: [], domains: [], packages: [] };
const signaturesPath = path.join(__dirname, 'data', 'malicious.json');
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
  const [processes, currentLoad] = await Promise.all([si.processes(), si.currentLoad()]);
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
}

ipcMain.handle('app:getNotificationStatus', async () => notificationService.getNotificationStatus());
ipcMain.handle('app:openNotificationSettings', async () => notificationService.openNotificationSettings());
ipcMain.handle('app:auditNotifications', async () => {
  try {
    const audit = await notificationService.auditNotifications();
    return { ok: true, ...audit };
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

ipcMain.handle('app:scan', async () => {
  try {
    const report = await scanSystem();
    const threats = await securityService.runAllChecks({ processNames: maliciousSignatures.processNames, ports: maliciousSignatures.ports.map(p => Number(p)), domains: maliciousSignatures.domains });
    report.threats = threats;
    return { ok: true, report };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}); 