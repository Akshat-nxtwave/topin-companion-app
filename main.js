// ============================================================================
// ELECTRON MAIN PROCESS - COMPANION APP SECURITY MONITORING
// ============================================================================
// This is the main entry point for the Electron application that provides
// real-time security monitoring for exam environments. It coordinates between
// security services, communication layers, and the UI renderer process.

const { app, BrowserWindow, ipcMain } = require("electron");

const { autoUpdater, AppUpdater } = require("electron-updater");


autoUpdater.autoDownload = false;
autoUpdater.autoInstallOnAppQuit = true;
// ============================================================================
// ELECTRON APP CONFIGURATION & PERFORMANCE OPTIMIZATION
// ============================================================================
// Disable hardware acceleration to prevent GPU-related crashes and ensure
// consistent behavior across different systems during exam monitoring
app.disableHardwareAcceleration();
app.commandLine.appendSwitch("disable-gpu-vsync");        // Disable vertical sync for better performance
app.commandLine.appendSwitch("log-level", "3");           // Reduce Chromium logging verbosity
app.commandLine.appendSwitch("no-sandbox");               // Disable sandbox for system access
app.commandLine.appendSwitch("disable-dev-shm-usage");    // Prevent shared memory issues
app.commandLine.appendSwitch("disable-gpu-sandbox");      // Disable GPU sandbox for stability

// ============================================================================
// CORE DEPENDENCIES
// ============================================================================
const path = require("path");                              // File system path utilities
const os = require("os");                                  // Operating system information
const si = require("systeminformation");                   // System information gathering
const fs = require("fs");                                  // File system operations
const { exec } = require("child_process");                 // Execute system commands

// ============================================================================
// SECURITY SERVICES
// ============================================================================
const SecurityService = require("./security/SecurityService");     // Core security scanning
const ExamModeService = require("./security/ExamModeService");     // Exam-specific security checks
const NotificationService = require("./security/NotificationService"); // DND/notification monitoring

// ============================================================================
// COMMUNICATION LAYER
// ============================================================================
const { EventBus, AppEvent } = require("./comm/EventBus");         // Event-driven communication
const { LocalServer } = require("./comm/LocalServer");             // WebSocket server for external communication

// ============================================================================
// SERVICE INSTANCES INITIALIZATION
// ============================================================================
// Create singleton instances of all security services for the application lifecycle
const securityService = new SecurityService();           // Main security scanning service
const examModeService = new ExamModeService();           // Exam-specific security checks
const notificationService = new NotificationService();   // DND/notification monitoring

// ============================================================================
// EVENT-DRIVEN COMMUNICATION SETUP
// ============================================================================
// Initialize EventBus for inter-component communication and external event broadcasting
const eventBus = new EventBus();

// Note: All outbound events are now emitted via EventBus with AppEvent only.
// This ensures consistent event handling and filtering for external communication.

// ============================================================================
// NOTIFICATION THREAT ANALYSIS FUNCTION
// ============================================================================
/**
 * Analyzes notification audit results and converts them into standardized threat objects
 * This function processes platform-specific notification settings and identifies violations
 * that could compromise exam security (e.g., DND not enabled, notifications active)
 * 
 * @param {Object} auditResult - Result from NotificationService.auditNotifications()
 * @returns {Array} Array of threat objects with standardized format
 */
function analyzeNotificationThreatsFromAudit(auditResult) {
  const threats = [];
  
  // ============================================================================
  // LINUX PLATFORM: DND-ONLY ENFORCEMENT
  // ============================================================================
  // Linux implementation focuses solely on Do Not Disturb requirement
  // No browser/app inspection - only system-level DND enforcement
  if (process.platform === "linux") {
    const sys = auditResult.system || {};
    const status = String(sys.status || "").toLowerCase();
    const dndOn = status === "disabled"; // Convention: notifications disabled = DND ON
    
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

  // ============================================================================
  // MACOS PLATFORM: FOCUS MODE & PERMISSION ENFORCEMENT
  // ============================================================================
  // macOS requires Full Disk Access permission to read Focus state from Assertions.json
  // and enforces Focus mode (macOS equivalent of DND) to be active
  try {
    const isMac =
      (auditResult &&
        auditResult.system &&
        auditResult.system.platform === "darwin") ||
      process.platform === "darwin" ||
      !!auditResult.mac;
      
    if (isMac) {
      const mac = auditResult.mac || {};
      const permissionGranted = !!mac.permissionGranted;  // Full Disk Access granted
      const focusOn = !!mac.focusOn;                      // Focus mode active (DND equivalent)

      // First check: Full Disk Access permission required
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
      } 
      // Second check: Focus mode must be enabled
      else if (!focusOn) {
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

  // ============================================================================
  // WINDOWS PLATFORM: FOCUS ASSIST ENFORCEMENT
  // ============================================================================
  // Windows enforces Focus Assist (Windows equivalent of DND) to be active
  // This prevents notifications from interrupting the exam environment
  try {
    const sys = auditResult.system || {};
    const platform = String(sys.platform || process.platform);
    
    if (platform === "win32") {
      const status = String(sys.status || "").toLowerCase();
      const dndOn = status === "disabled"; // Convention: notifications disabled = DND ON
      
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

  // ============================================================================
  // BROWSER & APPLICATION NOTIFICATION THREAT DETECTION
  // ============================================================================
  // Analyze running processes and browser notification settings to identify
  // applications that could send notifications during exam (security risk)
  
  // System process exclusions - these are not considered security threats
  const systemProcessNameExclusions = new Set(["win32", "darwin"]);
  const isProcessNameExcluded = (name) => {
    const n = String(name || "").toLowerCase();
    if (!n) return false;
    if (systemProcessNameExclusions.has(n)) return true;
    if (n.includes("crashpad")) return true;  // Exclude crash reporting processes
    return false;
  };
  
  // Build set of running process names (excluding system processes)
  const runningProcessNames = new Set(
    (auditResult.processes || [])
      .map((p) => String(p.name || "").toLowerCase())
      .filter((n) => n && !isProcessNameExcluded(n))
  );
  
  /**
   * Checks if a specific browser is currently running
   * @param {string} browserKey - Browser identifier (chrome, firefox, etc.)
   * @returns {boolean} True if browser is running
   */
  const hasRunningBrowser = (browserKey) => {
    // Map logical browser keys to actual process name patterns
    const patterns =
      {
        chrome: ["chrome"],
        chromium: ["chromium"],
        msedge: ["msedge", "microsoft edge"],
        brave: ["brave"],
        firefox: ["firefox"],
    }[browserKey] || [];
      
    // Exclude browser helper processes (webviews, updaters)
    const excludedSubstrings = ["webview", "edgewebview", "updater", "update"];
    
    for (const name of runningProcessNames) {
      if (excludedSubstrings.some((x) => name.includes(x))) continue;
      if (patterns.some((p) => name.includes(p))) return true;
    }
    return false;
  };
  
  // ============================================================================
  // BROWSER NOTIFICATION THREAT DETECTION
  // ============================================================================
  // Check for browsers with notifications enabled - these are security threats
  // Only consider browsers with status 'enabled' as threats, regardless of URL counts
  if (auditResult.browsers && auditResult.browsers.length > 0) {
    const enabledBrowsers = [];
    
    auditResult.browsers.forEach((browser) => {
      if (browser.profiles && browser.profiles.length > 0) {
        // Only profiles with status 'enabled' are threats - ignore allowed/blocked URL counts
        const enabledProfiles = browser.profiles.filter(
          (profile) => profile.status === "enabled"
        );
        
        // Map browser name to standardized key for process detection
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
    
    // Create threat if any browsers have notifications enabled
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
  
  // ============================================================================
  // APPLICATION NOTIFICATION THREAT DETECTION
  // ============================================================================
  // Check for non-browser applications that have notifications enabled
  // These could potentially send notifications during exam (medium severity)
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

// ============================================================================
// ENHANCED WEBSOCKET SERVER WITH COMMAND HANDLING
// ============================================================================
// Extended LocalServer that handles incoming WebSocket commands from external clients
// (like TOPIN website) to control the companion app's scanning operations

/**
 * Enhanced LocalServer that extends the base LocalServer with command handling capabilities
 * Allows external clients to send commands via WebSocket to control scanning operations
 */
class LoggingLocalServer extends LocalServer {
  start() {
    const port = super.start();
    
    // Handle incoming WebSocket command messages from external clients
    if (this.wss) {
      this.wss.on("connection", (ws) => {
        ws.on("message", async (data) => {
          try {
            const message = JSON.parse(String(data || ""));
            
            // Process command messages from external clients
            if (message && message.type === "command") {
              let response = null;
              
              // Route commands to appropriate stepped scan manager methods
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
              
              // Send response back to the client
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

// ============================================================================
// WEBSOCKET SERVER INITIALIZATION
// ============================================================================
// Initialize enhanced LocalServer with command handling capabilities
// This server accepts connections from TOPIN website and other external clients
const localServer = new LoggingLocalServer(eventBus, {
  port: 8080, // WebSocket server on port 8080
  host: "127.0.0.1",  // Localhost only for security
});

// ============================================================================
// MAIN WINDOW MANAGEMENT
// ============================================================================
let mainWindow;

/**
 * Creates the main Electron window with security-optimized settings
 * Configures the window for exam monitoring with appropriate security restrictions
 */
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 960,
    height: 600,
    minWidth: 860,
    minHeight: 540,
    backgroundColor: "#0b1221",  // Dark theme for exam environment
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),  // Secure IPC bridge
      contextIsolation: true,    // Isolate renderer context for security
      nodeIntegration: false,    // Disable Node.js in renderer for security
      sandbox: false,           // Allow preload script access
      webSecurity: false,       // Disable web security for local file access
    },
  });

  // Load the main UI from renderer process
  mainWindow.loadFile(path.join(__dirname, "renderer", "index.html"));

  // Debug helper: open DevTools automatically if environment variable is set
  if (process.env.TOPIN_OPEN_DEVTOOLS === "1") {
    try {
      mainWindow.webContents.openDevTools({ mode: "detach" });
    } catch {}
  }

  // Clean up window reference when closed
  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

// ============================================================================
// APPLICATION STARTUP SEQUENCE
// ============================================================================
/**
 * Main application startup sequence that initializes all components
 * Sets up logging, creates main window, starts WebSocket server, and begins monitoring
 */
app.whenReady().then(() => {
  // ============================================================================
  // LOGGING CONFIGURATION
  // ============================================================================
  // Route Chromium logs to macOS Console when debugging is enabled
  if (process.env.TOPIN_ENABLE_LOGGING === "1") {
    try {
      app.commandLine.appendSwitch("enable-logging");
    } catch {}
  }
  
  // ============================================================================
  // WINDOW CREATION
  // ============================================================================
  // Add a small delay to prevent race conditions on macOS
  setTimeout(() => {
  createWindow();
  }, 100);

  // ============================================================================
  // WEBSOCKET SERVER STARTUP
  // ============================================================================
  // Start WebSocket server to accept incoming connections from TOPIN website
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

  // ============================================================================
  // APPLICATION EVENT HANDLERS
  // ============================================================================
  // Handle macOS app activation (when dock icon is clicked)
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });

  // ============================================================================
  // BACKGROUND MONITORING STARTUP
  // ============================================================================
  // Auto-start background security scan worker 5 seconds after app is ready
  // This provides continuous monitoring for security threats
  try {
    setTimeout(() => {
      try { startAutoScanWorker(30000); } catch {}  // 30-second intervals
    }, 5000);
  } catch { }
  
  autoUpdater.checkForUpdates();
});

// ============================================================================
// APPLICATION LIFECYCLE MANAGEMENT
// ============================================================================
// Handle application shutdown and cleanup

/**
 * Handle application shutdown when all windows are closed
 * On macOS, apps typically stay active even when all windows are closed
 */
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    // Clean up WebSocket server before quitting
    localServer.stop();
    app.quit();
  }
});

/**
 * Handle application shutdown cleanup
 * Ensures WebSocket server is properly closed before app termination
 */
app.on("before-quit", () => {
  // Ensure WebSocket server is closed
  localServer.stop();
});

// ============================================================================
// MALICIOUS SIGNATURES MANAGEMENT
// ============================================================================
// Load and manage security threat signatures for process, port, and domain detection

/**
 * Global malicious signatures store for security threat detection
 * Contains patterns for processes, ports, domains, and packages that are considered threats
 */
let maliciousSignatures = {
  processNames: [],  // Malicious process names to detect
  ports: [],         // Suspicious network ports to monitor
  domains: [],       // Malicious domains to block
  packages: [],      // Malicious software packages
};

// Determine path to malicious signatures file (development vs production)
const signaturesPath = app.isPackaged
  ? path.join(process.resourcesPath, "data", "malicious.json")
  : path.join(__dirname, "data", "malicious.json");

/**
 * Loads malicious signatures from JSON file
 * Normalizes data formats and handles loading errors gracefully
 */
function loadSignatures() {
  try {
    const raw = fs.readFileSync(signaturesPath, "utf8");
    const parsed = JSON.parse(raw);
    maliciousSignatures = {
      processNames: (parsed.processNames || []).map((s) =>
        String(s).toLowerCase()  // Normalize to lowercase for case-insensitive matching
      ),
      ports: (parsed.ports || []).map((p) => String(p)),
      domains: (parsed.domains || []).map((d) => String(d).toLowerCase()),
      packages: parsed.packages || [],
    };
  } catch (e) {
    // Fallback to empty signatures if loading fails
    maliciousSignatures = {
      processNames: [],
      ports: [],
      domains: [],
      packages: [],
    };
  }
}

// Load signatures on startup
loadSignatures();

// Watch for signature file changes and reload automatically
try {
  fs.watch(signaturesPath, { persistent: false }, () => loadSignatures());
} catch {}

// ============================================================================
// SYSTEM PROCESS DETECTION UTILITIES
// ============================================================================

/**
 * Fallback process detection for POSIX systems (Linux/macOS)
 * Uses native 'ps' command when systeminformation library fails
 * Provides basic process information for security scanning
 * 
 * @returns {Promise<Array>} Array of process objects with pid, name, cpu, memory, command
 */
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

// Note: Windows-specific active process filtering is handled inside ExamModeService

/**
 * Comprehensive system scanning function
 * Gathers running processes, system load, and platform information
 * Uses systeminformation library with fallback to native commands
 * 
 * @returns {Promise<Object>} System report with processes, load, platform info
 */
async function scanSystem() {
  try {
    // Parallel execution of system information gathering
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
    
    // Normalize process data format
    let running = (processes.list || []).map((p) => ({
      pid: p.pid,
      name: p.name || "unknown",
      path: p.path,
      user: p.user,
      cpu: Number.isFinite(p.pcpu) ? p.pcpu : 0,
      mem: Number.isFinite(p.pmem) ? p.pmem : 0,
      command: p.command || "",
    }));
    
    // Fallback to native 'ps' command if systeminformation fails
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
    
    // Sort processes by CPU usage (highest first) and limit to 500 processes
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

// ============================================================================
// IPC HANDLERS - NOTIFICATION SERVICE
// ============================================================================
// IPC handlers for notification and DND status management

/**
 * Get current notification status from NotificationService
 * Returns system notification settings and DND state
 */
ipcMain.handle("app:getNotificationStatus", async () =>
  notificationService.getNotificationStatus()
);

/**
 * Get current focus/DND status from NotificationService
 * Returns whether focus mode is active
 */
ipcMain.handle("app:getFocusStatus", async () =>
  notificationService.getFocusStatus()
);

/**
 * Open system notification settings
 * Launches OS-specific notification settings dialog
 */
ipcMain.handle("app:openNotificationSettings", async () =>
  notificationService.openNotificationSettings()
);
/**
 * Comprehensive notification audit handler
 * Performs notification/DND audit and emits appropriate security events
 * Coordinates with security scanning for complete system check
 */
ipcMain.handle("app:auditNotifications", async (_evt, _providedScanId) => {
  try {
    const scanId = Date.now();
    const audit = await notificationService.auditNotifications();
    const notificationThreats = analyzeNotificationThreatsFromAudit(audit);
    
    // ============================================================================
    // NOTIFICATION SECURITY RULE ENFORCEMENT
    // ============================================================================
    // Rule 1: If DND is not active on any OS → emit ACTIVE_NOTIFICATION_SERVICE
    const sys = audit.system || {};
    const dndOn = String(sys.status || "").toLowerCase() === "disabled"; // disabled => DND ON

    // Rule 2: Additionally for Windows, if any background apps detected → emit ACTIVE_NOTIFICATION_SERVICE
    const bgApps = Array.isArray(audit.backgroundAppsWindows)
      ? audit.backgroundAppsWindows
      : [];
    const windowsBgDetected = process.platform === "win32" && bgApps.length > 0;

    // ============================================================================
    // EVENT EMISSION LOGIC
    // ============================================================================
    if (!dndOn || windowsBgDetected) {
      // Security violation detected - emit threat event
      try {
        eventBus.emitEvent(AppEvent.ACTIVE_NOTIFICATION_SERVICE, {
          scanId,
          reason: !dndOn ? "dnd_off" : "windows_background_apps",
          backgroundAppsWindows: windowsBgDetected ? bgApps : [],
          system: sys,
        });
      } catch {}
    } else {
      // Notification check passed - coordinate with security scan completion
      sequentialCompletion.notifComplete = true;
      if (
        sequentialCompletion.notifComplete &&
        sequentialCompletion.suspiciousComplete
      ) {
        // Both notification and security checks passed
        try {
          eventBus.emitEvent(AppEvent.NO_ISSUES_DETECTED, {
          scanId: Date.now(),
            flow: "sequential_checks",
        });
        } catch {}
        clearSequentialCompletion();
      } else {
        // Wait for security scan to complete
        armSequentialCompletionExpiry();
      }
    }
    
    // Include threats in return payload for renderer consumption
    return { ok: true, threats: notificationThreats, ...audit };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

/**
 * Open browser-specific notification guide
 * Launches external browser help pages for notification settings
 */
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

// ============================================================================
// STEPPED SCAN MANAGER - USER-GUIDED SECURITY SCANNING
// ============================================================================
/**
 * Manages stepped security scanning with user intervention capabilities
 * Provides a two-step scanning process: notification audit → security scan
 * Allows users to resolve issues between steps and retry failed steps
 */
class SteppedScanManager {
  constructor() {
    this.currentScan = null;
    // Scan states: 'idle', 'step1_notification', 'step1_blocked', 'step2_security', 'step2_blocked', 'completed'
    this.scanState = "idle";
    this.detections = { notifications: [], security: [] };
  }

  /**
   * Initiates a new stepped security scan
   * Validates scan state and begins with notification audit (Step 1)
   * @returns {Promise<Object>} Scan result or error
   */
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

    // Initialize new scan session
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

  /**
   * Executes Step 1: Notification Audit
   * Checks DND status and Windows background apps
   * Blocks scan if violations are detected, otherwise proceeds to Step 2
   * @returns {Promise<Object>} Step 1 result or proceeds to Step 2
   */
  async executeStep1() {
    try {
      console.log("📱 Auditing notification settings...");

      // Perform comprehensive notification audit
      const auditResult = await notificationService.auditNotifications();
      const notificationThreats = analyzeNotificationThreatsFromAudit(auditResult);
      this.detections.notifications = Array.isArray(notificationThreats)
        ? notificationThreats
        : [];

      // ============================================================================
      // NOTIFICATION SECURITY GATE EVALUATION
      // ============================================================================
      const sys = auditResult.system || {};
      const dndOn = String(sys.status || "").toLowerCase() === "disabled";
      const bgApps = Array.isArray(auditResult.backgroundAppsWindows)
        ? auditResult.backgroundAppsWindows
        : [];
      const windowsBgDetected = process.platform === "win32" && bgApps.length > 0;

      if (!dndOn || windowsBgDetected) {
        // ============================================================================
        // NOTIFICATION VIOLATIONS DETECTED - BLOCK SCAN
        // ============================================================================
        console.log(
          `⚠️ Notification gating: dndOn=${dndOn}, windowsBgDetected=${windowsBgDetected} - SCAN BLOCKED`
        );
        this.scanState = "step1_blocked";
        
        // Emit security threat event
        try {
          eventBus.emitEvent(AppEvent.ACTIVE_NOTIFICATION_SERVICE, {
            scanId: this.currentScan.id,
            reason: !dndOn ? "dnd_off" : "windows_background_apps",
            backgroundAppsWindows: windowsBgDetected ? bgApps : [],
            system: sys,
          });
        } catch {}

        // Emit internal stage event
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
        // ============================================================================
        // NOTIFICATION CHECK PASSED - PROCEED TO STEP 2
        // ============================================================================
        console.log("✅ Notification gate passed, proceeding to Step 2");

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

  /**
   * Executes Step 2: Security and Threat Scan
   * Performs comprehensive security scanning for malicious processes, ports, and domains
   * Blocks scan if threats are detected, otherwise completes the scan
   * @returns {Promise<Object>} Step 2 result or scan completion
   */
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

      // ============================================================================
      // PARALLEL SECURITY SCANNING
      // ============================================================================
      const systemReport = await scanSystem();
      const securityThreats = await securityService.runAllChecks({
        processNames: maliciousSignatures.processNames,
        ports: maliciousSignatures.ports.map((p) => Number(p)),
        domains: maliciousSignatures.domains,
      });

      // Store security detection results
      this.detections.security = Array.isArray(securityThreats)
        ? securityThreats
        : [];

      if (securityThreats && securityThreats.length > 0) {
        // ============================================================================
        // SECURITY THREATS DETECTED - BLOCK SCAN
        // ============================================================================
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
        // ============================================================================
        // NO SECURITY THREATS - COMPLETE SCAN
        // ============================================================================
        console.log("✅ No security threats detected");
        return this.completeScan(systemReport);
      }
    } catch (e) {
      this.scanState = "idle";
      this.currentScan = null;
      return { ok: false, error: `Step 2 failed: ${String(e)}` };
    }
  }

  /**
   * Retry Step 1: Notification Audit
   * Allows user to retry notification check after resolving issues
   * @returns {Promise<Object>} Retry result
   */
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

  /**
   * Retry Step 2: Security Scan
   * Allows user to retry security scan after resolving threats
   * @returns {Promise<Object>} Retry result
   */
  async retryStep2() {
    if (this.scanState !== "step2_blocked") {
      return { ok: false, error: "Cannot retry step 2 - not in blocked state" };
    }

    console.log("🔄 Retrying Step 2: Security Scan");
    return this.executeStep2();
  }

  /**
   * Completes the stepped scan and generates final report
   * Emits completion events and cleans up scan state
   * @param {Object} systemReport - Optional system report from Step 2
   * @returns {Promise<Object>} Final scan completion result
   */
  async completeScan(systemReport = null) {
    this.scanState = "completed";
    const endTime = Date.now();

    // ============================================================================
    // FINAL REPORT GENERATION
    // ============================================================================
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

    // ============================================================================
    // COMPLETION EVENT EMISSION
    // ============================================================================
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

  /**
   * Get current scan status and state information
   * @returns {Object} Current scan status with state, detections, and capabilities
   */
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

  /**
   * Reset scan state to idle
   * Clears all scan data and returns to initial state
   * @returns {Object} Reset confirmation
   */
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

  /**
   * Cancel current scan
   * Stops scan execution and cleans up state
   * @returns {Object} Cancellation confirmation
   */
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

// ============================================================================
// IPC HANDLERS - THREAT APPLICATION LISTING
// ============================================================================

/**
 * List categorized threat applications across all platforms
 * Returns installed apps, running processes, services, and browser extensions
 * that match threat patterns (messaging, remote control, virtualization, screen capture)
 */
ipcMain.handle("app:listThreatApps", async () => {
  try {
    const res = await securityService.listThreatApplications();
    return { ok: true, ...res };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// ============================================================================
// STEPPED SCAN MANAGER INSTANCE
// ============================================================================
const steppedScanManager = new SteppedScanManager();

// ============================================================================
// LEGACY SCAN FUNCTIONS
// ============================================================================

/**
 * Legacy scan function for compatibility with existing UI
 * Performs basic security scanning without stepped scan complexity
 * Used by renderer.js for simple security checks
 * 
 * @param {Object} options - Scan options (skipEvents, scanId, scanType)
 * @returns {Promise<Object>} Scan result with system report and threats
 */
async function legacyScan(options = {}) {
  try {
    const {
      skipEvents = false,
      scanId = Date.now(),
      scanType = "legacy_scan",
    } = options;

    console.log("🔍 Running legacy scan (for UI compatibility)");

    // ============================================================================
    // PARALLEL SECURITY SCANNING
    // ============================================================================
    const systemReport = await scanSystem();
    const threats = await securityService.runAllChecks({
      processNames: maliciousSignatures.processNames,
      ports: maliciousSignatures.ports.map((p) => Number(p)),
      domains: maliciousSignatures.domains,
    });

    // Ensure threats is always an array
    systemReport.threats = Array.isArray(threats) ? threats : [];

    console.log(
      `✅ Legacy scan completed. Found ${systemReport.threats.length} threats`
    );
    return { ok: true, report: systemReport };
  } catch (e) {
    console.error("❌ Legacy scan failed:", e);
    return { ok: false, error: String(e) };
  }
}

/**
 * Performs complete system check combining notification audit and security scan
 * Coordinates both checks and emits appropriate events based on results
 * Used for comprehensive system validation
 * 
 * @returns {Promise<Object>} Combined results from both notification and security checks
 */
async function completeSystemCheck() {
  try {
    const scanId = Date.now();

    // ============================================================================
    // STEP 1: NOTIFICATION AUDIT
    // ============================================================================
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

    // ============================================================================
    // STEP 2: SECURITY SCAN
    // ============================================================================
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

    // ============================================================================
    // COMPLETION EVENT COORDINATION
    // ============================================================================
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

    // ============================================================================
    // COMBINED RESULTS
    // ============================================================================
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

// ============================================================================
// SEQUENTIAL COMPLETION TRACKING
// ============================================================================
// Track completion state for sequential UI flow coordination
// Allows notification and security checks to be performed independently
// but coordinates their completion for final event emission

const sequentialCompletion = {
  notifComplete: false,      // Notification audit completion status
  suspiciousComplete: false, // Security scan completion status
  timer: null,              // Auto-expiry timer
};

/**
 * Clear sequential completion state
 * Resets both completion flags and clears any pending timer
 */
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

/**
 * Arm sequential completion expiry timer
 * Sets a 20-second timer to auto-expire completion state
 * Prevents indefinite waiting if one check never completes
 */
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

// ============================================================================
// IPC HANDLERS - SCANNING OPERATIONS
// ============================================================================

/**
 * Legacy scan handler for UI compatibility
 * Performs basic security scan and coordinates with notification completion
 */
ipcMain.handle("app:scan", async (_evt, _providedScanId) => {
  console.log('app:scan    =========================>  ')
  
  // Use legacy scan for compatibility with existing UI
  const res = await legacyScan({});
  
  try {
    if (res && res.ok && res.report && Array.isArray(res.report.threats)) {
      const hasThreats = res.report.threats.length > 0;
      
      if (!hasThreats) {
        // No security threats - coordinate with notification completion
        sequentialCompletion.suspiciousComplete = true;
        if (
          sequentialCompletion.notifComplete &&
          sequentialCompletion.suspiciousComplete
        ) {
          // Both checks completed successfully
          try {
            eventBus.emitEvent(AppEvent.NO_ISSUES_DETECTED, {
              scanId: Date.now(),
              flow: "sequential_checks",
            });
          } catch {}
          clearSequentialCompletion();
        } else {
          // Wait for notification check to complete
          armSequentialCompletionExpiry();
        }
      } else {
        // Security threats detected - clear completion state
        clearSequentialCompletion();
      }
    }
  } catch {}
  return res;
});

/**
 * Complete system check handler
 * Performs comprehensive security and notification validation
 */
ipcMain.handle("app:completeSystemCheck", async () => {
  console.log('app:completeSystemCheck ======================>  ')
  // New comprehensive check that coordinates both security and notifications
  return completeSystemCheck();
});

/**
 * Start stepped scan handler
 * Initiates user-guided two-step security scanning process
 */
ipcMain.handle("app:startSteppedScan", async () => {
  return steppedScanManager.startSteppedScan();
});

/**
 * Retry Step 1 handler
 * Allows user to retry notification audit after resolving issues
 */
ipcMain.handle("app:retryStep1", async () => {
  return steppedScanManager.retryStep1();
});

/**
 * Retry Step 2 handler
 * Allows user to retry security scan after resolving threats
 */
ipcMain.handle("app:retryStep2", async () => {
  return steppedScanManager.retryStep2();
});

/**
 * Get scan status handler
 * Returns current scan state and progress information
 */
ipcMain.handle("app:getScanStatus", async () => {
  return steppedScanManager.getScanStatus();
});

/**
 * Cancel scan handler
 * Stops current scan and cleans up state
 */
ipcMain.handle("app:cancelScan", async () => {
  return steppedScanManager.cancelScan();
});

/**
 * Reset scan handler
 * Resets scan state to idle
 */
ipcMain.handle("app:resetScan", async () => {
  return steppedScanManager.resetScan();
});

// ============================================================================
// AUTO-SCAN WORKER MANAGEMENT
// ============================================================================
// Background worker thread for continuous security monitoring
// Keeps main thread responsive while performing periodic security scans

const { Worker } = require("worker_threads");
let autoScanWorker = null;

/**
 * Start auto-scan worker for continuous background monitoring
 * Creates a worker thread that performs periodic security scans
 * 
 * @param {number} intervalMs - Scan interval in milliseconds (default: 30000)
 * @returns {boolean} Success status
 */
function startAutoScanWorker(intervalMs = 30000) {
  if (autoScanWorker) return true;
  
  // Determine worker path based on packaging status
  const workerPath = app.isPackaged
    ? path.join(
        process.resourcesPath,
        "app.asar.unpacked",
        "workers",
        "autoScanWorker.js"
      )
    : path.join(__dirname, "workers", "autoScanWorker.js");
    
  // Create worker thread
  autoScanWorker = new Worker(workerPath, {
    workerData: null,
  });
  
  // Handle worker messages
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
  
  // Handle worker errors and cleanup
  autoScanWorker.on("error", () => {
    /* noop: keep app running */
  });
  autoScanWorker.on("exit", () => {
    autoScanWorker = null;
  });
  
  // Start worker with configuration
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

/**
 * Stop auto-scan worker
 * Terminates the background worker thread and cleans up resources
 * @returns {boolean} Success status
 */
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

/**
 * Start auto-scan worker IPC handler
 * Allows renderer to start background monitoring
 */
ipcMain.handle("app:autoScanStart", async (_evt, intervalMs) => {
  try {
    return startAutoScanWorker(Number(intervalMs) || 30000);
  } catch {
    return false;
  }
});

/**
 * Stop auto-scan worker IPC handler
 * Allows renderer to stop background monitoring
 */
ipcMain.handle("app:autoScanStop", async () => {
  try {
    return stopAutoScanWorker();
  } catch {
    return false;
  }
});

// ============================================================================
// IPC HANDLERS - WEBSOCKET COMMUNICATION
// ============================================================================

/**
 * Send data to WebSocket clients
 * Broadcasts data to all connected WebSocket clients via EventBus
 */
ipcMain.handle("app:sendToClients", async (_evt, data) => {
  try {
    eventBus.emitEvent("FROM_APP", data);
    console.log("📤 SENT TO CLIENTS:", JSON.stringify(data, null, 2));
    return { ok: true };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

/**
 * Get WebSocket server status
 * Returns server status, port, and endpoint information
 */
ipcMain.handle("app:getServerStatus", async () => {
  return {
    running: localServer.server && localServer.server.listening,
    port: localServer.port,
    endpoint: `ws://localhost:${localServer.port}/ws`,
  };
}); 

// ============================================================================
// IPC HANDLERS - BROWSER TAB ACCESS & TESTING
// ============================================================================

/**
 * Check browser tab access permissions
 * Verifies if the app has permission to access browser tabs for monitoring
 */
ipcMain.handle("app:checkBrowserTabPermissions", async () => {
  try {
    const res = await securityService.checkBrowserTabAccessPermissions();
    return { ok: true, ...res };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

/**
 * Test tab detection for specific browser
 * Debug function to test tab detection capabilities
 */
ipcMain.handle("app:testTabDetection", async (_evt, browserName) => {
  try {
    const res = await securityService.testTabDetection(browserName);
    return { ok: true, ...res };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// ============================================================================
// IPC HANDLERS - LOGGING CONTROL
// ============================================================================

/**
 * Set logging for all services
 * Enables/disables logging for SecurityService and NotificationService
 */
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

/**
 * Get current logging status
 * Returns logging status from SecurityService
 */
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

/**
 * Set NotificationService-only logging
 * Controls logging specifically for NotificationService
 */
ipcMain.handle("app:setNotificationLogging", async (_evt, enabled) => {
  try {
    notificationService.setLogging(!!enabled);
    return { ok: true, enabled: !!enabled };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

/**
 * Get NotificationService logging status
 * Returns logging status specifically from NotificationService
 */
ipcMain.handle("app:getNotificationLoggingStatus", async () => {
  try {
    const enabled = !!notificationService.getLoggingStatus();
    return { ok: true, enabled };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// ============================================================================
// IPC HANDLERS - SCREEN SHARING DETECTION
// ============================================================================

/**
 * List actively sharing tabs in currently open browsers
 * Detects browser tabs that are currently sharing screen content
 */
ipcMain.handle("app:listActiveSharingTabs", async () => {
  try {
    const tabs = await securityService.getActiveScreenSharingTabs();
    return { ok: true, tabs };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
});

// ============================================================================
// IPC HANDLERS - EXAM MODE CHECK
// ============================================================================

/**
 * Exam mode security check
 * Allows only one browser family and the companion app; flags all other processes
 * Uses different detection logic for Linux vs Windows/macOS
 */
ipcMain.handle("app:runExamModeCheck", async (_evt, options) => {
  try {
    // ============================================================================
    // COMPANION APP IDENTIFICATION
    // ============================================================================
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
    
    // ============================================================================
    // LINUX PLATFORM: SECURITY SERVICE ROUTING
    // ============================================================================
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
