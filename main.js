const { app, BrowserWindow, ipcMain } = require("electron");
const { autoUpdater } = require("electron-updater");
const UpdateSecurity = require("./update-security");
app.disableHardwareAcceleration();
app.commandLine.appendSwitch("disable-gpu-vsync");
app.commandLine.appendSwitch("log-level", "3");
app.commandLine.appendSwitch("no-sandbox");
app.commandLine.appendSwitch("disable-dev-shm-usage");
app.commandLine.appendSwitch("disable-gpu-sandbox");
const path = require("path");
const os = require("os");
const si = require("systeminformation");
const fs = require("fs");
const { exec } = require("child_process");
const SecurityService = require("./security/SecurityService");
const ExamModeService = require("./security/ExamModeService");
const NotificationService = require("./security/NotificationService");
const { EventBus, AppEvent } = require("./comm/EventBus");
const { LocalServer } = require("./comm/LocalServer");

const securityService = new SecurityService();
const examModeService = new ExamModeService();
const notificationService = new NotificationService();

// Initialize EventBus and WebSocket server for communication
const eventBus = new EventBus();

// Initialize update security
const updateSecurity = new UpdateSecurity();

// Configure auto-updater with security settings
autoUpdater.autoDownload = false; // This will handle downloads manually for better UX
autoUpdater.autoInstallOnAppQuit = false; // This will handle manual installation for better control

// TEMPORARY BYPASS: Disable auto-updater completely for testing
const DISABLE_AUTO_UPDATER = false; // Set to false to re-enable

// Disable code signature verification for testing (since we're not code signing)
// Note: verifySignature property may not be available in newer versions
try {
  autoUpdater.verifySignature = false;
} catch (e) {
  console.log('verifySignature property not available:', e.message);
}
autoUpdater.requireCodeSigning = false;

// Store update info globally for IPC handlers
let currentUpdateInfo = null;

// Set the update feed URL for GitHub releases
autoUpdater.setFeedURL({
  provider: 'github',
  owner: 'Akshat-nxtwave',
  repo: 'topin-companion-app',
  private: false
});

// Configure timeouts to prevent hanging
autoUpdater.requestHeaders = {
  'User-Agent': 'TOPIN-Companion-Updater'
};

// Set longer timeouts for download operations
autoUpdater.downloadTimeout = 300000; // 5 minutes
autoUpdater.requestTimeout = 60000; // 1 minute

// Log the configured feed URL
console.log('🔗 Auto-updater feed URL:', autoUpdater.getFeedURL());
console.log('⏱️ Download timeout:', autoUpdater.downloadTimeout);
console.log('⏱️ Request timeout:', autoUpdater.requestTimeout);

// Security: Only check for updates in production
if (process.env.NODE_ENV !== 'development' && !DISABLE_AUTO_UPDATER) {
  // Check for updates on startup (but don't notify automatically)
  setTimeout(() => {
    autoUpdater.checkForUpdates().catch(err => {
      // Only log in development if it's not the expected "not packed" error
      if (!err.message.includes('not packed') && !err.message.includes('dev update config')) {
        console.log('Update check failed:', err.message);
      }
    });
  }, 5000); // Wait 5 seconds after app start
} else if (DISABLE_AUTO_UPDATER) {
  console.log('🚫 Auto-updater disabled for testing - skipping update checks');
} else {
  console.log('🔧 Development mode: Update checks disabled');
}

// Auto-updater event handlers
autoUpdater.on('checking-for-update', () => {
  console.log('🔍 Checking for update...');
  console.log('📡 Feed URL:', autoUpdater.getFeedURL());
  console.log('📦 Current version:', app.getVersion());
});

autoUpdater.on('update-available', (info) => {
  console.log('✅ Update available!');
  console.log('📋 Update info:', JSON.stringify(info, null, 2));
  
  // Store update info globally for IPC handlers
  currentUpdateInfo = info;
  console.log('💾 Stored update info globally:', currentUpdateInfo);
  
  // Log the complete download URLs
  if (info.files && info.files.length > 0) {
    console.log('🌐 Download URLs:');
    info.files.forEach((file, index) => {
      console.log(`  File ${index + 1}:`);
      console.log(`    - URL: ${file.url}`);
      console.log(`    - Size: ${file.size} bytes`);
      console.log(`    - SHA512: ${file.sha512}`);
    });
  }
  
  // Security validation
  if (!updateSecurity.validateUpdateInfo(info)) {
    console.error('Update info failed security validation');
    updateSecurity.logSecurityEvent('update_validation_failed', { info });
    return;
  }
  
  // Check if version is actually newer
  const pkg = require("./package.json");
  const currentVersion = pkg.version;
  if (!updateSecurity.isNewerVersion(currentVersion, info.version)) {
    console.log('Update version is not newer than current version');
    return;
  }
  
  updateSecurity.logSecurityEvent('update_available', { 
    currentVersion, 
    newVersion: info.version 
  });
  
  // Send update available event to renderer
  if (mainWindow) {
    mainWindow.webContents.send('update-available', info);
  }
});

autoUpdater.on('update-not-available', (info) => {
  console.log('❌ Update not available');
  console.log('📋 Info:', JSON.stringify(info, null, 2));
  
  // Send update not available event to renderer
  if (mainWindow) {
    mainWindow.webContents.send('update-not-available', info);
  }
});

autoUpdater.on('error', (err) => {
  console.error('❌ Auto-updater error:', err.message);
  console.error('📋 Error details:', JSON.stringify(err, null, 2));
  console.error('📋 Error properties:', {
    message: err.message,
    stack: err.stack,
    code: err.code,
    errno: err.errno,
    syscall: err.syscall,
    hostname: err.hostname,
    port: err.port,
    path: err.path,
    timeout: err.timeout
  });
  
  // Categorize errors for better user experience
  let errorMessage = err.message;
  let errorType = 'unknown';
  
  if (err.message.includes('ENOTFOUND') || err.message.includes('network')) {
    errorType = 'network';
    errorMessage = 'Network error: Unable to check for updates. Please check your internet connection.';
  } else if (err.message.includes('404') || err.message.includes('not found')) {
    errorType = 'not_found';
    errorMessage = 'Update server not found. Please contact support.';
  } else if (err.message.includes('permission') || err.message.includes('access')) {
    errorType = 'permission';
    errorMessage = 'Permission error: Unable to download update. Please run as administrator.';
  } else if (err.message.includes('signature') || err.message.includes('verification') || err.message.includes('Code signature')) {
    errorType = 'security';
    errorMessage = 'Code signature verification failed. This is expected for unsigned apps. You can continue using the current version.';
    
    // For signature errors, we'll treat this as a non-critical error and allow the user to continue
    console.log('🔒 Code signature error - treating as non-critical, allowing user to continue');
  } else if (err.message.includes('timeout') || err.message.includes('ETIMEDOUT')) {
    errorType = 'timeout';
    errorMessage = 'Request timeout: The update server is taking too long to respond. Please try again.';
  }
  
  // Send error event to renderer with categorized information
  if (mainWindow) {
    mainWindow.webContents.send('update-error', {
      message: errorMessage,
      type: errorType,
      originalError: err.message
    });
  }
});

autoUpdater.on('download-progress', (progressObj) => {
  let log_message = "Download speed: " + progressObj.bytesPerSecond;
  log_message = log_message + ' - Downloaded ' + progressObj.percent + '%';
  log_message = log_message + ' (' + progressObj.transferred + "/" + progressObj.total + ')';
  console.log('📥 Download progress:', log_message);
  console.log('📥 Progress details:', {
    bytesPerSecond: progressObj.bytesPerSecond,
    percent: progressObj.percent,
    transferred: progressObj.transferred,
    total: progressObj.total,
    speed: progressObj.speed
  });
  
  // Send progress to renderer
  if (mainWindow) {
    mainWindow.webContents.send('download-progress', progressObj);
  }
});

autoUpdater.on('update-downloaded', (info) => {
  console.log('📥 Update downloaded event received!');
  console.log('📥 Downloaded info:', info);
  console.log('📥 Downloaded info details:');
  console.log('  - Version:', info.version);
  console.log('  - Release name:', info.releaseName);
  console.log('  - Release date:', info.releaseDate);
  console.log('  - Path:', info.path);
  console.log('  - SHA512:', info.sha512);
  
  // Check auto-updater state after download
  console.log('📥 Auto-updater state after download:');
  console.log('  - updateDownloaded:', autoUpdater.updateDownloaded);
  console.log('  - isUpdateDownloaded:', autoUpdater.isUpdateDownloaded);
  console.log('  - updateInfo:', autoUpdater.updateInfo);
  
  // Send update downloaded event to renderer
  if (mainWindow) {
    console.log('📥 Sending update-downloaded event to renderer...');
    mainWindow.webContents.send('update-downloaded', info);
  }
});

// Note: Outbound events are now emitted via EventBus with AppEvent only.

// Function to analyze notification threats from audit result (similar to stepped scan)
function analyzeNotificationThreatsFromAudit(auditResult) {
  const threats = [];
  // Linux: Only enforce Do Not Disturb (DND/Focus) requirement. Do not inspect apps/browsers further.
  if (process.platform === "linux") {
    const sys = auditResult.system || {};
    const status = String(sys.status || "").toLowerCase();
    const dndOn = status === "disabled"; // our convention: notifications disabled => DND ON
    if (!dndOn) {
      threats.push({
        type: "linux_dnd_required",
        severity: "high",
        message: "Turn on Do Not Disturb (DND) in system settings",
        action: "Open notification settings and enable DND",
        userActionRequired: true,
        settingsRequired: true,
        details: { platform: "linux", system: sys },
      });
    }
    return threats;
  }
  
  // macOS-only replacement flow: require Full Disk Access and DND (Focus) ON
  try {
    const isMac =
      (auditResult &&
        auditResult.system &&
        auditResult.system.platform === "darwin") ||
      process.platform === "darwin" ||
      !!auditResult.mac;
    if (isMac) {
      const mac = auditResult.mac || {};
      const permissionGranted = !!mac.permissionGranted;
      const focusOn = !!mac.focusOn; // true only when Do Not Disturb (default) is ON
      
      if (!permissionGranted) {
        threats.push({
          type: "mac_full_disk_access_required",
          severity: "high",
          message:
            "Grant Full Disk Access to the companion app to verify Focus (DND) state",
          action:
            "Open System Settings > Privacy & Security > Full Disk Access, add and enable this app",
          userActionRequired: true,
          settingsRequired: true,
          details: mac.details || "Assertions.json not readable",
        });
      } else if (!focusOn) {
        threats.push({
          type: "mac_focus_mode_disabled",
          severity: "high",
          message: "Enable Do Not Disturb (Focus) mode to proceed",
          action:
            "Enable Do Not Disturb from Control Center or System Settings > Focus",
          userActionRequired: true,
          settingsRequired: true,
          details: mac.details || "Focus=OFF",
        });
      }
      return threats;
    }
  } catch {}

  // Windows: treat system DND (Focus Assist) OFF as a violation
  try {
    const sys = auditResult.system || {};
    const platform = String(sys.platform || process.platform);
    if (platform === "win32") {
      const status = String(sys.status || "").toLowerCase();
      const dndOn = status === "disabled"; // notifications disabled => DND ON
      if (!dndOn) {
        threats.push({
          type: "windows_dnd_off",
          severity: "high",
          message: "Enable Focus Assist (Do Not Disturb) to proceed",
          action:
            "Open Windows Settings > System > Notifications (or Focus Assist) and enable Do Not Disturb",
          userActionRequired: true,
          settingsRequired: true,
          details: sys.details || "Focus Assist OFF",
        });
      }
    }
  } catch {}
  
  // EXCLUDE system notifications from threat analysis as per user requirement
  // System notifications are not considered threats
  const systemProcessNameExclusions = new Set(["win32", "darwin"]);
  const isProcessNameExcluded = (name) => {
    const n = String(name || "").toLowerCase();
    if (!n) return false;
    if (systemProcessNameExclusions.has(n)) return true;
    if (n.includes("crashpad")) return true;
    return false;
  };
  const runningProcessNames = new Set(
    (auditResult.processes || [])
      .map((p) => String(p.name || "").toLowerCase())
      .filter((n) => n && !isProcessNameExcluded(n))
  );
  const hasRunningBrowser = (browserKey) => {
    // Map logical browser key to process name patterns
    const patterns =
      {
        chrome: ["chrome"],
        chromium: ["chromium"],
        msedge: ["msedge", "microsoft edge"],
        brave: ["brave"],
        firefox: ["firefox"],
    }[browserKey] || [];
    // Exclude webview/updater helpers
    const excludedSubstrings = ["webview", "edgewebview", "updater", "update"];
    for (const name of runningProcessNames) {
      if (excludedSubstrings.some((x) => name.includes(x))) continue;
      if (patterns.some((p) => name.includes(p))) return true;
    }
    return false;
  };
  
  // Check for browser notifications enabled
  // Only consider browsers with status 'enabled' as threats, regardless of URL counts
  if (auditResult.browsers && auditResult.browsers.length > 0) {
    const enabledBrowsers = [];
    
    auditResult.browsers.forEach((browser) => {
      if (browser.profiles && browser.profiles.length > 0) {
        // Only profiles with status 'enabled' are threats - ignore allowed/blocked URL counts
        const enabledProfiles = browser.profiles.filter(
          (profile) => profile.status === "enabled"
        );
        const bname = String(browser.browser || "").toLowerCase();
        const key = bname.includes("chromium")
          ? "chromium"
          : bname.includes("edge")
          ? "msedge"
          : bname.includes("brave")
          ? "brave"
          : bname.includes("firefox")
          ? "firefox"
          : "chrome";
        // Only report as threat if corresponding browser process is actually running
        if (enabledProfiles.length > 0 && hasRunningBrowser(key)) {
          enabledBrowsers.push({
            browser: browser.browser,
            enabledProfiles: enabledProfiles.length,
            totalProfiles: browser.profiles.length,
          });
        }
      }
    });
    
    if (enabledBrowsers.length > 0) {
      threats.push({
        type: "browser_notifications_enabled",
        severity: "high",
        browsers: enabledBrowsers,
        count: enabledBrowsers.length,
        message: `${
          enabledBrowsers.length
        } browser(s) have notifications enabled: ${enabledBrowsers
          .map((b) => b.browser)
          .join(", ")}`,
        action: "User must manually disable notifications in these browsers",
        userActionRequired: true,
        settingsRequired: true,
      });
    }
  }
  
  // Check for notification-enabled applications/processes
  if (auditResult.processes && auditResult.processes.length > 0) {
    const enabledApps = auditResult.processes.filter(
      (proc) => proc.notifEnabled && !isProcessNameExcluded(proc.name)
    );
    
    if (enabledApps.length > 0) {
      threats.push({
        type: "notification_apps_enabled",
        severity: "medium",
        apps: enabledApps,
        count: enabledApps.length,
        message: `${
          enabledApps.length
        } notification app(s) are running: ${enabledApps
          .map((app) => app.name)
          .join(", ")}`,
        action: "Consider disabling notifications in these applications",
        userActionRequired: true,
        settingsRequired: true,
      });
    }
  }
  
  return threats;
}

// Deprecated direct WebSocket broadcasting removed. Use EventBus with AppEvent.

// Enhanced LocalServer with message logging
class LoggingLocalServer extends LocalServer {
  start() {
    const port = super.start();
    // Optionally handle inbound WS command messages without emitting outbound events here
    if (this.wss) {
      this.wss.on("connection", (ws) => {
        ws.on("message", async (data) => {
          try {
            const message = JSON.parse(String(data || ""));
            if (message && message.type === "command") {
              let response = null;
              switch (message.action) {
                case "start_stepped_scan":
                  response = await steppedScanManager.startSteppedScan();
                  break;
                case "retry_step1":
                  response = await steppedScanManager.retryStep1();
                  break;
                case "retry_step2":
                  response = await steppedScanManager.retryStep2();
                  break;
                case "get_scan_status":
                  response = steppedScanManager.getScanStatus();
                  break;
                case "cancel_scan":
                  response = steppedScanManager.cancelScan();
                  break;
                case "reset_scan":
                  response = steppedScanManager.resetScan();
                  break;
                default:
                  response = { 
                    ok: false,
                    error: `Unknown command: ${message.action}`,
                  };
              }
              if (response) {
                ws.send(
                  JSON.stringify({
                    type: "command_response",
                  originalCommand: message.action,
                  result: response,
                    timestamp: Date.now(),
                  })
                );
              }
            }
          } catch {}
        });
      });
    }
    return port;
  }
}

// Initialize enhanced LocalServer with logging
const localServer = new LoggingLocalServer(eventBus, {
  port: 8080, // WebSocket server on port 8080
  host: "127.0.0.1",
});

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 960,
    height: 600,
    minWidth: 860,
    minHeight: 540,
    backgroundColor: "#0b1221",
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      webSecurity: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, "renderer", "update.html"));

  // Debug helper: open DevTools automatically if env var set
  if (process.env.TOPIN_OPEN_DEVTOOLS === "1") {
    try {
      mainWindow.webContents.openDevTools({ mode: "detach" });
    } catch {}
  }
  
  // Add keyboard shortcut to open DevTools (Cmd+Option+I)
  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (input.meta && input.alt && input.key.toLowerCase() === 'i') {
      mainWindow.webContents.openDevTools({ mode: "detach" });
    }
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  // Route Chromium logs to macOS Console when needed
  if (process.env.TOPIN_ENABLE_LOGGING === "1") {
    try {
      app.commandLine.appendSwitch("enable-logging");
    } catch {}
  }
  // Add a small delay to prevent race conditions on macOS
  setTimeout(() => {
    createWindow();
  }, 100);

  // Start WebSocket server to accept incoming connections
  try {
    const serverPort = localServer.start();
    if (serverPort) {
      console.log(
        `✅ WebSocket server started on ws://localhost:${serverPort}/ws`
      );
      console.log(
        `   Connect from Postman to: ws://localhost:${serverPort}/ws`
      );
      console.log(`   Waiting for incoming WebSocket connections...`);
    } else {
      console.error("❌ Failed to start WebSocket server");
    }
  } catch (error) {
    console.error("❌ Error starting WebSocket server:", error);
  }

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });

  // Auto-start background scan 5 seconds after app is ready
  try {
    setTimeout(() => {
      try { startAutoScanWorker(30000); } catch {}
    }, 5000);
  } catch {}
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    // Clean up WebSocket server
    localServer.stop();
    app.quit();
  }
});

app.on("before-quit", () => {
  // Ensure WebSocket server is closed
  localServer.stop();
});

// Load malicious signatures
let maliciousSignatures = {
  processNames: [],
  ports: [],
  domains: [],
  packages: [],
};
const signaturesPath = app.isPackaged
  ? path.join(process.resourcesPath, "data", "malicious.json")
  : path.join(__dirname, "data", "malicious.json");
function loadSignatures() {
  try {
    const raw = fs.readFileSync(signaturesPath, "utf8");
    const parsed = JSON.parse(raw);
    maliciousSignatures = {
      processNames: (parsed.processNames || []).map((s) =>
        String(s).toLowerCase()
      ),
      ports: (parsed.ports || []).map((p) => String(p)),
      domains: (parsed.domains || []).map((d) => String(d).toLowerCase()),
      packages: parsed.packages || [],
    };
  } catch (e) {
    maliciousSignatures = {
      processNames: [],
      ports: [],
      domains: [],
      packages: [],
    };
  }
}
loadSignatures();
try {
  fs.watch(signaturesPath, { persistent: false }, () => loadSignatures());
} catch {}

async function getFallbackProcessesPOSIX() {
  return new Promise((resolve) => {
    exec(
      "ps axo pid,ppid,pcpu,pmem,comm,command --no-headers",
      { timeout: 3000 },
      (err, stdout) => {
      if (err || !stdout) return resolve([]);
        const rows = stdout.trim().split("\n");
      const procs = [];
      for (const line of rows) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 6) continue;
        const [pid, ppid, pcpu, pmem, comm, ...cmdParts] = parts;
          const command = cmdParts.join(" ");
          procs.push({
            pid: parseInt(pid) || 0,
            ppid: parseInt(ppid) || 0,
            pcpu: parseFloat(pcpu) || 0,
            pmem: parseFloat(pmem) || 0,
            name: comm || "unknown",
            command,
          });
      }
      resolve(procs);
      }
    );
  });
}

// Windows-specific active process filtering is handled inside ExamModeService; no filtering here

async function scanSystem() {
  try {
    const [processes, currentLoad] = await Promise.all([
      si.processes().catch((err) => {
        console.warn("systeminformation.processes() failed:", err);
        return { list: [] };
      }), 
      si.currentLoad().catch((err) => {
        console.warn("systeminformation.currentLoad() failed:", err);
        return { currentLoad: 0 };
      }),
    ]);
    let running = (processes.list || []).map((p) => ({
      pid: p.pid,
      name: p.name || "unknown",
      path: p.path,
      user: p.user,
      cpu: Number.isFinite(p.pcpu) ? p.pcpu : 0,
      mem: Number.isFinite(p.pmem) ? p.pmem : 0,
      command: p.command || "",
    }));
    if (running.length === 0) {
      try {
        const fb = await getFallbackProcessesPOSIX();
        if (fb.length)
          running = fb.map((p) => ({
            pid: p.pid,
            name: p.name,
            path: "",
            user: "",
            cpu: Number.isFinite(p.pcpu) ? p.pcpu : 0,
            mem: Number.isFinite(p.pmem) ? p.pmem : 0,
            command: p.command,
          }));
      } catch {}
    }
    running.sort((a, b) => (b.cpu || 0) - (a.cpu || 0));
    const runningLimited = running.slice(0, 500);
    return {
      platform: os.platform(),
      arch: os.arch(),
      load: Number.isFinite(currentLoad.currentLoad)
        ? currentLoad.currentLoad
        : 0,
      processes: runningLimited,
    };
  } catch (error) {
    console.warn("scanSystem() failed with error:", error);
    return { platform: os.platform(), arch: os.arch(), load: 0, processes: [] };
  }
}

ipcMain.handle("app:getNotificationStatus", async () =>
  notificationService.getNotificationStatus()
);
ipcMain.handle("app:getFocusStatus", async () =>
  notificationService.getFocusStatus()
);
ipcMain.handle("app:openNotificationSettings", async () =>
  notificationService.openNotificationSettings()
);
ipcMain.handle("app:auditNotifications", async (_evt, _providedScanId) => {
  try {
    const scanId = Date.now();
    const audit = await notificationService.auditNotifications();
    const notificationThreats = analyzeNotificationThreatsFromAudit(audit);
    
    // Rule 1: If DND is not active on any OS → emit ACTIVE_NOTIFICATION_SERVICE
    const sys = audit.system || {};
    const dndOn = String(sys.status || "").toLowerCase() === "disabled"; // disabled => DND ON

    // Rule 2: Additionally for Windows, if any background apps detected → emit ACTIVE_NOTIFICATION_SERVICE
    const bgApps = Array.isArray(audit.backgroundAppsWindows)
      ? audit.backgroundAppsWindows
      : [];
    const windowsBgDetected = process.platform === "win32" && bgApps.length > 0;

    if (!dndOn || windowsBgDetected) {
      try {
        eventBus.emitEvent(AppEvent.ACTIVE_NOTIFICATION_SERVICE, {
          scanId,
          reason: !dndOn ? "dnd_off" : "windows_background_apps",
          backgroundAppsWindows: windowsBgDetected ? bgApps : [],
          system: sys,
        });
      } catch {}
    } else {
      // Both conditions passed → no notification event
      // Pair with suspicious completion (from app:scan) in a time window
      sequentialCompletion.notifComplete = true;
      if (
        sequentialCompletion.notifComplete &&
        sequentialCompletion.suspiciousComplete
      ) {
        try {
          eventBus.emitEvent(AppEvent.NO_ISSUES_DETECTED, {
          scanId: Date.now(),
            flow: "sequential_checks",
        });
        } catch {}
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

ipcMain.handle("app:openGuide", async (_evt, kind) => {
  const { shell } = require("electron");
  const guides = {
    general: "https://support.google.com/chrome/answer/3220216?hl=en",
    firefox: "https://support.mozilla.org/kb/push-notifications-firefox",
    edge: "https://support.microsoft.com/microsoft-edge/block-pop-ups-and-notifications-in-microsoft-edge-0cdb1634-74f4-fa23-c8be-d17c73f38dd2",
  };
  const url = guides[kind] || guides.general;
  try {
    await shell.openExternal(url);
    return true;
  } catch {
    return false;
  }
});

// Stepped scanning system with user intervention
class SteppedScanManager {
  constructor() {
    this.currentScan = null;
    this.scanState = "idle"; // 'idle', 'step1_notification', 'step1_blocked', 'step2_security', 'step2_blocked', 'completed'
    this.detections = { notifications: [], security: [] };
  }

  async startSteppedScan() {
    console.log("🚀 startSteppedScan() method called");
    console.log(`🚀 Current scan state: ${this.scanState}`);
    console.log(`🚀 Current scan:`, this.currentScan);
    
    // Allow restarting if scan is blocked or completed
    if (
      this.currentScan &&
      this.scanState !== "step1_blocked" &&
      this.scanState !== "step2_blocked" &&
      this.scanState !== "completed"
    ) {
      console.log("❌ Scan already in progress, returning error");
      return { ok: false, error: "Scan already in progress" };
    }

    // Reset any previous scan state
    this.currentScan = {
      id: Date.now(),
      startTime: Date.now(),
      currentStep: 1,
      status: "running",
    };

    this.scanState = "step1_notification";
    this.detections = { notifications: [], security: [] };

    console.log("🔍 Starting new stepped scan - Step 1: Notification Audit");
    console.log(`🔍 Scan ID: ${this.currentScan.id}`);
    
    // Emit scan started event for internal use
    eventBus.emitStage("STEPPED_SCAN_STARTED", {
      scanId: this.currentScan.id,
      step: 1,
      stepName: "notification_audit",
    });

    return this.executeStep1();
  }

  async executeStep1() {
    try {
      console.log("📱 Auditing notification settings...");
      
      const auditResult = await notificationService.auditNotifications();
      const notificationThreats = analyzeNotificationThreatsFromAudit(auditResult);
      this.detections.notifications = Array.isArray(notificationThreats)
        ? notificationThreats
        : [];

      // Step rule application:
      const sys = auditResult.system || {};
      const dndOn = String(sys.status || "").toLowerCase() === "disabled";
      const bgApps = Array.isArray(auditResult.backgroundAppsWindows)
        ? auditResult.backgroundAppsWindows
        : [];
      const windowsBgDetected = process.platform === "win32" && bgApps.length > 0;

      if (!dndOn || windowsBgDetected) {
        console.log(
          `⚠️ Notification gating: dndOn=${dndOn}, windowsBgDetected=${windowsBgDetected} - SCAN BLOCKED`
        );
        this.scanState = "step1_blocked";
        try {
          eventBus.emitEvent(AppEvent.ACTIVE_NOTIFICATION_SERVICE, {
            scanId: this.currentScan.id,
            reason: !dndOn ? "dnd_off" : "windows_background_apps",
            backgroundAppsWindows: windowsBgDetected ? bgApps : [],
            system: sys,
          });
        } catch {}

        eventBus.emitStage("SCAN_STEP1_BLOCKED", {
          scanId: this.currentScan.id,
          detections: [],
          message:
            "SCAN BLOCKED: User must resolve notification issues before proceeding",
          blocked: true,
          waitingForUser: true,
        });

        return {
          ok: true,
          status: "blocked",
          step: 1,
          stepName: "notification_audit",
          detections: notificationThreats,
          message:
            "SCAN BLOCKED: Please resolve the notification issues and run the scan again",
          nextAction: "user_must_resolve_notifications_and_rescan",
          blocked: true,
          canProceed: false,
        };
      } else {
        console.log("✅ Notification gate passed, proceeding to Step 2");

        // No outbound event; proceed internally

        eventBus.emitStage("SCAN_STEP1_COMPLETED", {
          scanId: this.currentScan.id,
          step: 1,
          message:
            "Step 1 completed successfully - proceeding to security scan",
        });
        return this.executeStep2();
      }
    } catch (e) {
      this.scanState = "idle";
      this.currentScan = null;
      return { ok: false, error: `Step 1 failed: ${String(e)}` };
    }
  }

  async executeStep2() {
    try {
      this.scanState = "step2_security";
      this.currentScan.currentStep = 2;

      console.log("🔍 Starting Step 2: Security and Threat Scan");
      
      eventBus.emitStage("SCAN_STEP2_STARTED", {
        scanId: this.currentScan.id,
        step: 2,
        stepName: "security_scan",
      });

      const systemReport = await scanSystem();
      const securityThreats = await securityService.runAllChecks({ 
        processNames: maliciousSignatures.processNames, 
        ports: maliciousSignatures.ports.map((p) => Number(p)),
        domains: maliciousSignatures.domains,
      });

      // runAllChecks returns array directly, not object with threats property
      this.detections.security = Array.isArray(securityThreats)
        ? securityThreats
        : [];

      if (securityThreats && securityThreats.length > 0) {
        console.log(`⚠️ Found ${securityThreats.length} security threats`);
        this.scanState = "step2_blocked";

        eventBus.emitStage("SCAN_STEP2_BLOCKED", {
          scanId: this.currentScan.id,
          detections: securityThreats,
          message: "Security threats detected - user intervention required",
        });

        return {
          ok: true,
          status: "blocked",
          step: 2,
          stepName: "security_scan",
          detections: securityThreats,
          systemReport,
          message:
            "Security threats detected. Please resolve these issues before completing the scan",
          nextAction: "user_must_resolve_security_threats",
        };
      } else {
        console.log("✅ No security threats detected");
        
        return this.completeScan(systemReport);
      }
    } catch (e) {
      this.scanState = "idle";
      this.currentScan = null;
      return { ok: false, error: `Step 2 failed: ${String(e)}` };
    }
  }

  async retryStep1() {
    if (this.scanState !== "step1_blocked") {
      return { ok: false, error: "Cannot retry step 1 - not in blocked state" };
    }
    
    console.log("🔄 User initiated retry of Step 1: Notification Audit");
    console.log("⚠️ Verifying if notification issues have been resolved...");
    
    // Reset current scan step but keep the scan ID
    this.currentScan.currentStep = 1;
    this.scanState = "step1_notification";
    
    return this.executeStep1();
  }

  async retryStep2() {
    if (this.scanState !== "step2_blocked") {
      return { ok: false, error: "Cannot retry step 2 - not in blocked state" };
    }
    
    console.log("🔄 Retrying Step 2: Security Scan");
    return this.executeStep2();
  }

  async completeScan(systemReport = null) {
    this.scanState = "completed";
    const endTime = Date.now();
    
    const finalReport = {
      scanId: this.currentScan.id,
      startTime: this.currentScan.startTime,
      endTime,
      duration: endTime - this.currentScan.startTime,
      status: "completed",
      allDetections: this.detections,
      systemReport: systemReport || (await scanSystem()),
      summary: {
        notificationIssues: this.detections.notifications.length,
        securityThreats: this.detections.security.length,
        totalIssues:
          this.detections.notifications.length +
          this.detections.security.length,
      },
    };

    try {
      eventBus.emitEvent(AppEvent.NO_ISSUES_DETECTED, {
      scanId: finalReport.scanId,
      duration: finalReport.duration,
      summary: finalReport.summary,
      });
    } catch {}

    eventBus.emitStage("STEPPED_SCAN_COMPLETED", finalReport);

    console.log("✅ Stepped scan completed successfully");
    this.currentScan = null;
    
    return {
      ok: true,
      status: "completed",
      report: finalReport,
    };
  }

  getScanStatus() {
    return {
      scanActive: this.currentScan !== null,
      scanId: this.currentScan?.id || null,
      state: this.scanState,
      currentStep: this.currentScan?.currentStep || 0,
      detections: this.detections,
      canStartNewScan:
        this.scanState === "idle" ||
        this.scanState === "step1_blocked" ||
        this.scanState === "step2_blocked" ||
        this.scanState === "completed",
      isBlocked:
        this.scanState === "step1_blocked" ||
        this.scanState === "step2_blocked",
      isCompleted: this.scanState === "completed",
    };
  }

  resetScan() {
    console.log("🔄 Resetting scan state");
    this.currentScan = null;
    this.scanState = "idle";
    this.detections = { notifications: [], security: [] };
    
    eventBus.emitStage("SCAN_RESET", {
      message: "Scan state has been reset",
      timestamp: Date.now(),
    });

    return { ok: true, message: "Scan state reset successfully" };
  }

  cancelScan() {
    if (this.currentScan) {
      eventBus.emitStage("STEPPED_SCAN_CANCELLED", {
        scanId: this.currentScan.id,
        reason: "user_cancelled",
      });
    }
    
    this.currentScan = null;
    this.scanState = "idle";
    this.detections = { notifications: [], security: [] };
    
    return { ok: true, message: "Scan cancelled" };
  }
}

// IPC to list categorized threat applications (installed, running, services, browser extensions)
ipcMain.handle("app:listThreatApps", async () => {
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
    const {
      skipEvents = false,
      scanId = Date.now(),
      scanType = "legacy_scan",
    } = options;

    console.log("🔍 Running legacy scan (for UI compatibility)");

    // No outbound events here; EventBus-only policy
    
    const systemReport = await scanSystem();
    const threats = await securityService.runAllChecks({ 
      processNames: maliciousSignatures.processNames, 
      ports: maliciousSignatures.ports.map((p) => Number(p)),
      domains: maliciousSignatures.domains,
    });
    
    // Ensure threats is always an array
    systemReport.threats = Array.isArray(threats) ? threats : [];
    
    // No outbound events here; EventBus-only policy

    console.log(
      `✅ Legacy scan completed. Found ${systemReport.threats.length} threats`
    );
    return { ok: true, report: systemReport };
  } catch (e) {
    console.error("❌ Legacy scan failed:", e);
    return { ok: false, error: String(e) };
  }
}

// Function to perform complete system check (legacy scan + notification audit)
async function completeSystemCheck() {
  try {
    const scanId = Date.now();
    
    // No outbound events at start
    
    // Step 1: Notification audit
    const notificationResult = await notificationService.auditNotifications();
    const notificationThreats =
      analyzeNotificationThreatsFromAudit(notificationResult);
    const hasNotificationThreats = notificationThreats.length > 0;
    
    // Emit ACTIVE_NOTIFICATION_SERVICE only when threats present
    if (hasNotificationThreats) {
      try {
        eventBus.emitEvent(AppEvent.ACTIVE_NOTIFICATION_SERVICE, {
          scanId,
          threats: notificationThreats,
        });
      } catch {}
    }
    
    // Step 2: Security scan (skip events - we'll send them ourselves)
    const securityResult = await legacyScan({ 
      skipEvents: true, 
      scanId: scanId, 
      scanType: "complete_system_check",
    });
    const securityOk = !!(securityResult && securityResult.ok);
    const hasSecurityThreats =
      securityOk &&
      securityResult.report.threats &&
      securityResult.report.threats.length > 0;

    // No outbound events for security threats in this flow per allowed policy
    
    // Send SYSTEM_CHECK_SUCCESSFUL only if both completion events were sent
    const sentNotificationComplete = !hasNotificationThreats;
    const sentSuspiciousComplete = securityOk && !hasSecurityThreats;
    if (sentNotificationComplete && sentSuspiciousComplete) {
      try {
        eventBus.emitEvent(AppEvent.NO_ISSUES_DETECTED, {
          scanId,
          flow: "complete_system_check",
        });
      } catch {}
    }
    
    // Return combined results
    return {
      ok: true,
      security: securityOk
        ? securityResult.report
        : { threats: [], platform: process.platform, processes: [], load: 0 },
      notifications: {
        ...notificationResult,
        threats: notificationThreats,
      },
      hasThreats: hasSecurityThreats || hasNotificationThreats,
      completionEvents: {
        notificationComplete: sentNotificationComplete,
        suspiciousComplete: sentSuspiciousComplete,
        systemSuccess: sentNotificationComplete && sentSuspiciousComplete,
      },
    };
  } catch (e) {
    console.error("❌ Complete system check failed:", e);
    return { ok: false, error: String(e) };
  }
}

// Updated IPC handlers for stepped scanning
// Track completion state for sequential UI flow (no strict single-session requirement)
const sequentialCompletion = {
  notifComplete: false,
  suspiciousComplete: false,
  timer: null,
};
function clearSequentialCompletion() {
  sequentialCompletion.notifComplete = false;
  sequentialCompletion.suspiciousComplete = false;
  if (sequentialCompletion.timer) {
    try {
      clearTimeout(sequentialCompletion.timer);
    } catch {}
    sequentialCompletion.timer = null;
  }
}
function armSequentialCompletionExpiry() {
  if (sequentialCompletion.timer) {
    try {
      clearTimeout(sequentialCompletion.timer);
    } catch {}
  }
  sequentialCompletion.timer = setTimeout(() => {
    clearSequentialCompletion();
  }, 20000); // auto-expire after 20s if the other half doesn't arrive
}

ipcMain.handle("app:scan", async (_evt, _providedScanId) => {

  console.log('app:scan    =========================>  ')
  // Use legacy scan for compatibility with existing UI
  const res = await legacyScan({});
  try {
    if (res && res.ok && res.report && Array.isArray(res.report.threats)) {
      const hasThreats = res.report.threats.length > 0;
      if (!hasThreats) {
        sequentialCompletion.suspiciousComplete = true;
        if (
          sequentialCompletion.notifComplete &&
          sequentialCompletion.suspiciousComplete
        ) {
          try {
            eventBus.emitEvent(AppEvent.NO_ISSUES_DETECTED, {
            scanId: Date.now(),
              flow: "sequential_checks",
          });
          } catch {}
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

ipcMain.handle("app:completeSystemCheck", async () => {
  console.log('app:completeSystemCheck ======================>  ')
  // New comprehensive check that coordinates both security and notifications
  return completeSystemCheck();
});

ipcMain.handle("app:startSteppedScan", async () => {
  return steppedScanManager.startSteppedScan();
});

ipcMain.handle("app:retryStep1", async () => {
  return steppedScanManager.retryStep1();
});

ipcMain.handle("app:retryStep2", async () => {
  return steppedScanManager.retryStep2();
});

ipcMain.handle("app:getScanStatus", async () => {
  return steppedScanManager.getScanStatus();
});

ipcMain.handle("app:cancelScan", async () => {
  return steppedScanManager.cancelScan();
});

ipcMain.handle("app:resetScan", async () => {
  return steppedScanManager.resetScan();
});

// Auto-scan worker (Node worker thread) to keep main thread responsive
const { Worker } = require("worker_threads");
let autoScanWorker = null;

function startAutoScanWorker(intervalMs = 30000) {
  if (autoScanWorker) return true;
  const workerPath = app.isPackaged
    ? path.join(
        process.resourcesPath,
        "app.asar.unpacked",
        "workers",
        "autoScanWorker.js"
      )
    : path.join(__dirname, "workers", "autoScanWorker.js");
  autoScanWorker = new Worker(workerPath, {
    workerData: null,
  });
  autoScanWorker.on("message", (msg) => {
    if (!msg) return;
    if (msg.type === "result") {
      // Handle scan results; no outbound events from here per allowed policy
      if (msg.payload && msg.payload.ok && msg.payload.report) {
        // Intentionally no-op for outbound events here
      }
      
      // Send result to renderer process
      if (mainWindow && !mainWindow.isDestroyed()) {
        try {
          mainWindow.webContents.send("app:autoScanResult", msg.payload);
        } catch {}
      }
    }
  });
  autoScanWorker.on("error", () => {
    /* noop: keep app running */
  });
  autoScanWorker.on("exit", () => {
    autoScanWorker = null;
  });
  autoScanWorker.postMessage({
    type: "start",
    intervalMs,
    signatures: {
    processNames: maliciousSignatures.processNames,
      ports: maliciousSignatures.ports.map((p) => Number(p)),
      domains: maliciousSignatures.domains,
    },
  });
  return true;
}

function stopAutoScanWorker() {
  if (!autoScanWorker) return true;
  try {
    autoScanWorker.postMessage({ type: "stop" });
  } catch {}
  try {
    autoScanWorker.terminate();
  } catch {}
  autoScanWorker = null;
  return true;
}

ipcMain.handle("app:autoScanStart", async (_evt, intervalMs) => {
  try {
    return startAutoScanWorker(Number(intervalMs) || 30000);
  } catch {
    return false;
  }
});

ipcMain.handle("app:autoScanStop", async () => {
  try {
    return stopAutoScanWorker();
  } catch {
    return false;
  }
});

// IPC handlers for WebSocket communication
ipcMain.handle("app:sendToClients", async (_evt, data) => {
  try {
    eventBus.emitEvent("FROM_APP", data);
    console.log("📤 SENT TO CLIENTS:", JSON.stringify(data, null, 2));
    return { ok: true };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

ipcMain.handle("app:getServerStatus", async () => {
  return {
    running: localServer.server && localServer.server.listening,
    port: localServer.port,
    endpoint: `ws://localhost:${localServer.port}/ws`,
  };
}); 

// Permission preflight for browser tab access
ipcMain.handle("app:checkBrowserTabPermissions", async () => {
  try {
    const res = await securityService.checkBrowserTabAccessPermissions();
    return { ok: true, ...res };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// Debug: Test tab detection
ipcMain.handle("app:testTabDetection", async (_evt, browserName) => {
  try {
    const res = await securityService.testTabDetection(browserName);
    return { ok: true, ...res };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// Logging control
ipcMain.handle("app:setLogging", async (_evt, enabled) => {
  try {
    securityService.setLogging(enabled);
    try {
      notificationService.setLogging(enabled);
    } catch {}
    return { ok: true, enabled };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

ipcMain.handle("app:getLoggingStatus", async () => {
  try {
    const enabled = securityService.getLoggingStatus();
    try {
      if (enabled) notificationService.setLogging(true);
    } catch {}
    return { ok: true, enabled };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// NotificationService-only logging controls
ipcMain.handle("app:setNotificationLogging", async (_evt, enabled) => {
  try {
    notificationService.setLogging(!!enabled);
    return { ok: true, enabled: !!enabled };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

ipcMain.handle("app:getNotificationLoggingStatus", async () => {
  try {
    const enabled = !!notificationService.getLoggingStatus();
    return { ok: true, enabled };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// List only actively sharing tabs in currently open browsers
ipcMain.handle("app:listActiveSharingTabs", async () => {
  try {
    const tabs = await securityService.getActiveScreenSharingTabs();
    return { ok: true, tabs };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// Auto-updater IPC handlers
ipcMain.handle("app:checkForUpdates", async () => {
  try {
    // Security check: Only allow in production or when explicitly requested
    if (process.env.NODE_ENV === 'development' || DISABLE_AUTO_UPDATER) {
      console.log('Update check skipped - auto-updater disabled');
      return { success: false, error: 'Update checks disabled' };
    }
    
    console.log('🔍 IPC: Starting update check...');
    const result = await autoUpdater.checkForUpdates();
    console.log('📋 IPC: Update check result:', result);
    
    // Check if update is available and send event manually if needed
    if (result && result.isUpdateAvailable) {
      console.log('✅ IPC: Update available, sending event to renderer');
      
      // Store update info globally for download/install handlers
      currentUpdateInfo = result.updateInfo;
      console.log('💾 IPC: Stored update info globally from result:', currentUpdateInfo);
      
      if (mainWindow) {
        mainWindow.webContents.send('update-available', result.updateInfo);
      }
    } else {
      console.log('ℹ️ IPC: No update available, sending event to renderer');
      if (mainWindow) {
        mainWindow.webContents.send('update-not-available', result);
      }
    }
    
    return { success: true, result };
  } catch (error) {
    console.error('❌ IPC: Error checking for updates:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle("app:downloadUpdate", async () => {
  try {
    console.log('🚀 IPC: Starting download...');
    
    // Use the globally stored update info
    const updateInfo = currentUpdateInfo || autoUpdater.updateInfo;
    console.log('📋 IPC: Update info for download:', updateInfo);
    console.log('📋 IPC: Current update info (global):', currentUpdateInfo);
    console.log('📋 IPC: Auto-updater update info:', autoUpdater.updateInfo);
    
    if (!updateInfo) {
      console.log('❌ IPC: No update info available');
      return { success: false, error: 'No update available to download' };
    }
    
    // Security: Validate update info
    if (!updateInfo.version || !updateInfo.files || updateInfo.files.length === 0) {
      console.log('❌ IPC: Invalid update info');
      return { success: false, error: 'Invalid update information' };
    }
    
    console.log('📡 IPC: Calling autoUpdater.downloadUpdate()...');
    await autoUpdater.downloadUpdate();
    console.log('✅ IPC: Download initiated successfully');
    
    return { success: true };
  } catch (error) {
    console.error('❌ IPC: Error downloading update:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle("app:installUpdate", async () => {
  try {
    console.log('🚀 IPC: Starting installation...');
    
    // Check all auto-updater properties
    console.log('📋 IPC: Auto-updater state check:');
    console.log('  - updateDownloaded:', autoUpdater.updateDownloaded);
    console.log('  - updateInfo:', autoUpdater.updateInfo);
    console.log('  - isUpdaterActive:', autoUpdater.isUpdaterActive);
    console.log('  - isUpdateAvailable:', autoUpdater.isUpdateAvailable);
    console.log('  - isUpdateDownloaded:', autoUpdater.isUpdateDownloaded);
    
    // Validate that update is downloaded before installing
    if (!autoUpdater.updateDownloaded) {
      console.log('❌ IPC: No update downloaded - autoUpdater.updateDownloaded is false');
      console.log('❌ IPC: Checking alternative properties...');
      console.log('  - isUpdateDownloaded:', autoUpdater.isUpdateDownloaded);
      
      // Try alternative check
      if (!autoUpdater.isUpdateDownloaded) {
        return { success: false, error: 'No update downloaded to install' };
      }
    }
    
    // Security: Final validation before installation
    const updateInfo = currentUpdateInfo || autoUpdater.updateInfo;
    console.log('📋 IPC: Update info for installation:', updateInfo);
    console.log('📋 IPC: Current update info (global):', currentUpdateInfo);
    console.log('📋 IPC: Auto-updater update info:', autoUpdater.updateInfo);
    
    if (!updateInfo || !updateInfo.version) {
      console.log('❌ IPC: Invalid update info for installation');
      return { success: false, error: 'Invalid update information for installation' };
    }
    
    // Log installation attempt for security audit
    console.log(`✅ IPC: Installing update to version ${updateInfo.version}`);
    console.log('📋 IPC: About to call autoUpdater.quitAndInstall()...');
    
    // Add a small delay to ensure all logs are written
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    console.log('🚀 IPC: Calling autoUpdater.quitAndInstall() now...');
    autoUpdater.quitAndInstall();
    
    console.log('✅ IPC: quitAndInstall() called successfully');
    return { success: true };
  } catch (error) {
    console.error('❌ IPC: Error installing update:', error);
    console.error('❌ IPC: Error details:', {
      message: error.message,
      stack: error.stack,
      code: error.code,
      errno: error.errno
    });
    return { success: false, error: error.message };
  }
});

ipcMain.handle("app:getAppVersion", async () => {
  try {
    const pkg = require("./package.json");
    return { 
      version: pkg.version,
      name: pkg.name,
      description: pkg.description
    };
  } catch (error) {
    console.error('Error getting app version:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle("app:isDevelopment", async () => {
  return process.env.NODE_ENV === 'development' || !app.isPackaged;
});

// Exam mode: allow only one browser family and the companion app; flag the rest
ipcMain.handle("app:runExamModeCheck", async (_evt, options) => {
  try {
    const pkg = require("./package.json");
    const appName = String(pkg.name || "").toLowerCase();
    const exeBase = (process.execPath || "").split(/[\\/]/).pop().toLowerCase();
    const defaults = {
      allowedCompanionMatches: [
        appName,
        "electron",
        "companion",
        "topin",
        exeBase,
      ].filter(Boolean),
      preferredBrowserFamily: null,
    };
    const opts = Object.assign({}, defaults, options || {});
    // On Linux, route to SecurityService for threat/malicious detection instead of ExamModeService
    if (process.platform === "linux") {
      const [systemReport, threats] = await Promise.all([
        scanSystem().catch(() => ({
          processes: [],
          platform: "linux",
          load: 0,
        })),
        securityService
          .runAllChecks({
          processNames: maliciousSignatures.processNames,
            ports: maliciousSignatures.ports.map((p) => Number(p)),
            domains: maliciousSignatures.domains,
          })
          .catch(() => []),
      ]);
      const byPid = new Map(
        (systemReport.processes || []).map((p) => [p.pid, p])
      );
      const flagged = [];
      for (const t of threats || []) {
        const pid =
          t && t.details && t.details.pid
            ? Number(t.details.pid)
            : t && t.pid
            ? Number(t.pid)
            : 0;
        const proc = pid && byPid.get(pid);
        const name =
          (t && t.details && t.details.name) ||
          t.name ||
          (proc && proc.name) ||
          "unknown";
        const cpu = proc ? Number(proc.cpu) || 0 : 0;
        const mem = proc ? Number(proc.mem) || 0 : 0;
        const command = proc ? proc.command || "" : "";
        flagged.push({ pid: pid || 0, name, cpu, mem, command });
      }
      
      if (flagged.length > 0) {
        eventBus.emitEvent(AppEvent.DETECTED_UNWANTED_APPS, {
          items: flagged,
          summary: { totalProcesses: (systemReport.processes || []).length },
        });
        // Security/exam half not clean → reset pairing
        clearSequentialCompletion();
      } else {
        // Security/exam half clean → mark complete; emit NO_ISSUES_DETECTED only if notifications already clean
        sequentialCompletion.suspiciousComplete = true;
        if (sequentialCompletion.notifComplete && sequentialCompletion.suspiciousComplete) {
          try { eventBus.emitEvent(AppEvent.NO_ISSUES_DETECTED, { scanId: Date.now(), flow: 'sequential_checks' }); } catch {}
          clearSequentialCompletion();
        } else {
          armSequentialCompletionExpiry();
        }
      }

      return {
        ok: true,
        summary: {
          totalProcesses: (systemReport.processes || []).length,
          nonSystemProcesses: 0,
          flaggedCount: flagged.length,
          activeBrowsers: [],
          allowedBrowserFamily: null,
          multipleBrowsersActive: false,
        },
        flagged,
        allowed: {
          browserFamily: null,
          companionMatches: opts.allowedCompanionMatches,
        },
        linuxActiveWindows: [],
      };
    }

    const res = await examModeService.runExamModeChecks(opts);
    try {
      const hasUnwanted = res && res.ok && Array.isArray(res.flagged) && res.flagged.length > 0;
      if (hasUnwanted) {
        eventBus.emitEvent(AppEvent.DETECTED_UNWANTED_APPS, { items: res.flagged, summary: res.summary || {} });
        clearSequentialCompletion();
      } else if (res && res.ok) {
        // Security/exam half clean → mark complete; emit NO_ISSUES_DETECTED only if notifications already clean
        sequentialCompletion.suspiciousComplete = true;
        if (sequentialCompletion.notifComplete && sequentialCompletion.suspiciousComplete) {
          try { eventBus.emitEvent(AppEvent.NO_ISSUES_DETECTED, { scanId: Date.now(), flow: 'sequential_checks' }); } catch {}
          clearSequentialCompletion();
        } else {
          armSequentialCompletionExpiry();
        }
      }
    } catch {}
    return res;
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});
