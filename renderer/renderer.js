// ============================================================================
// RENDERER PROCESS - COMPANION APP UI CONTROLLER
// ============================================================================
// This is the main UI controller for the companion app's renderer process.
// It handles user interactions, displays scan results, and manages the UI state
// for exam security monitoring.

// ============================================================================
// DOM ELEMENT REFERENCES
// ============================================================================
// Cache DOM elements for efficient access throughout the application lifecycle
const notifStatusEl = document.getElementById('notifStatus');        // Notification status indicator
const focusStatusEl = document.getElementById('focusStatus');        // Focus/DND status indicator  
const scanBtn = document.getElementById('scanBtn');                  // Main scan button
const globalStatusEl = document.getElementById('globalStatus');      // Global status display
const globalHintEl = document.getElementById('globalHint');          // Status hint/instruction text
const suspiciousListEl = document.getElementById('suspiciousList');  // Container for threat results
const notifAuditEl = document.getElementById('notifAudit');          // Container for notification audit results
const scanBtnDefaultText = scanBtn.textContent;                     // Store original button text

// Update modal elements
const updateModal = document.getElementById('updateModal');          // Update modal container
const updateTitle = document.getElementById('updateTitle');          // Update modal title
const updateMessage = document.getElementById('updateMessage');      // Update status message
const updateStatus = document.getElementById('updateStatus');        // Update status container
const updateActions = document.getElementById('updateActions');      // Update action buttons
const updateDownloadBtn = document.getElementById('updateDownloadBtn'); // Download button
const updateInstallBtn = document.getElementById('updateInstallBtn');   // Install button
const updateLaterBtn = document.getElementById('updateLaterBtn');    // Later button
const mainContent = document.getElementById('mainContent');          // Main app content
const versionDisplayEl = document.getElementById('versionDisplay');  // Version display element

// ============================================================================
// VERSION DISPLAY FUNCTIONS
// ============================================================================

/**
 * Loads and displays the application version in the UI
 * Fetches version from main process and updates the version display element
 */
async function loadAppVersion() {
  try {
    if (!versionDisplayEl) {
      console.warn('Version display element not found');
      return;
    }
    
    // Check if companion API is available
    if (!window.companion || !window.companion.getVersion) {
      console.warn('Companion API not available, using fallback version');
      versionDisplayEl.textContent = 'v1.0.0';
      return;
    }
    
    const result = await window.companion.getVersion();
    if (result && result.ok && result.version) {
      versionDisplayEl.textContent = `v${result.version}`;
      console.log('App version loaded:', result.version);
    } else {
      // Fallback to default version if API fails
      console.warn('Version API returned invalid result:', result);
      versionDisplayEl.textContent = 'v1.0.0';
    }
  } catch (error) {
    console.warn('Failed to load app version:', error);
    // Fallback to default version on error
    if (versionDisplayEl) {
      versionDisplayEl.textContent = 'v1.0.0';
    }
  }
}

// ============================================================================
// UI STATUS DISPLAY FUNCTIONS
// ============================================================================

/**
 * Updates the notification status indicator in the UI
 * Displays whether system notifications are enabled or disabled
 * Uses color coding: green for OFF (good), red for ON (bad for exams)
 * 
 * @param {Object} status - Notification status object from main process
 * @param {boolean} status.supported - Whether notification detection is supported
 * @param {boolean} status.enabledLikely - Whether notifications are likely enabled
 */
function setNotifStatus(status){
  if (!status.supported) {
    // Platform doesn't support notification detection
    notifStatusEl.textContent = 'Not supported';
    notifStatusEl.style.background = '#4b2738';  // Gray for unsupported
    return;
  }
  
  // Display notification status with color coding
  notifStatusEl.textContent = status.enabledLikely ? 'ON' : 'OFF';
  notifStatusEl.style.background = status.enabledLikely ? '#284047' : '#2b3a20';  // Red for ON, Green for OFF
}

/**
 * Updates the Focus/DND status indicator in the UI
 * Displays whether Focus mode (macOS) or Do Not Disturb is active
 * Essential for exam security - DND must be ON to prevent distractions
 * 
 * @returns {Promise<void>}
 */
async function setFocusStatus(){
  try {
    // Get focus status from main process via IPC
    const res = await window.companion.getFocusStatus();
    if (!focusStatusEl) return;
    
    if (!res || res.supported === false) {
      // Focus detection not supported on this platform
      focusStatusEl.textContent = 'Focus: Unsupported';
      focusStatusEl.style.background = '#4b2738';  // Gray for unsupported
      return;
    }
    
    // Determine if focus/DND is active
    const on = String(res.focus || '').toLowerCase() === 'on';
    
    // Add mode information if available (e.g., "Do Not Disturb", "Work", etc.)
    let modeSuffix = '';
    if (Array.isArray(res.modes) && res.modes.length) {
      modeSuffix = ` (${res.modes[0]})`;
    }
    
    // Update UI with status and color coding
    focusStatusEl.textContent = `Focus: ${on ? 'ON' : 'OFF'}${modeSuffix}`;
    focusStatusEl.style.background = on ? '#284047' : '#2b3a20';  // Green for ON, Red for OFF
    focusStatusEl.title = res.details || '';  // Tooltip with additional details
    
  } catch (e) {
    // Handle errors gracefully
    if (focusStatusEl) {
      focusStatusEl.textContent = 'Focus: Unknown';
      focusStatusEl.style.background = '#4b2738';  // Gray for error state
      focusStatusEl.title = String(e.message || e);  // Show error in tooltip
    }
  }
}

// ============================================================================
// GLOBAL STATE VARIABLES
// ============================================================================
let isChecking = false;              // Prevents multiple simultaneous scans
let unsubscribeAutoScan = null;      // Auto-scan subscription cleanup function
let updateState = 'checking';        // Current update state: checking, available, downloading, downloaded, error, complete

// ============================================================================
// THREAT DISPLAY UTILITY FUNCTIONS
// ============================================================================

/**
 * Determines the best display label for a threat's target application
 * Attempts to resolve threat information from multiple sources to provide
 * meaningful names for security threats in the UI
 * 
 * @param {Object} threat - Threat object from security scan
 * @param {Array} processes - Array of running processes for PID lookup
 * @returns {string} Human-readable target name for the threat
 */
function resolveThreatTarget(threat, processes){
  try {
    if (!threat) return '';
    
    // Try to get name directly from threat object
    const nameFromThreat = (threat.details && threat.details.name) || threat.name;
    if (nameFromThreat) return String(nameFromThreat);

    // Try to resolve by PID from process list
    const pid = (threat.details && threat.details.pid) || threat.pid;
    if (pid && Array.isArray(processes)) {
      const proc = processes.find(p => p && p.pid === pid);
      if (proc && proc.name) return `${proc.name}`;
    }

    // Try to get port information
    const port = (threat.details && threat.details.port) || threat.port;
    if (port) return `port ${port}`;

    // Try to extract name from threat message
    const message = String(threat.message || '');
    if (message.includes(':')) {
      const part = message.split(':').pop().trim();
      if (part) return part;
    }
  } catch {}
  return '';
}

/**
 * Normalizes application names for consistent display in the UI
 * Maps common application names to their proper display names
 * Handles variations in naming (e.g., "teams" -> "Microsoft Teams")
 * 
 * @param {string} name - Raw application name from process detection
 * @returns {string} Normalized display name for the application
 */
function normalizeAppDisplay(name){
  const n = String(name || '').trim();
  if (!n) return '';
  const lower = n.toLowerCase();
  
  // Map of common application name variations to proper display names
  const map = new Map([
    // Communication apps
    ['microsoft teams', 'Microsoft Teams'], ['teams', 'Microsoft Teams'], ['ms teams', 'Microsoft Teams'],
    ['discord', 'Discord'], ['slack', 'Slack'], ['zoom', 'Zoom'], ['skype', 'Skype'], ['webex', 'Webex'],
    // Browsers
    ['google chrome', 'Chrome'], ['chrome', 'Chrome'], ['chromium', 'Chromium'], ['brave', 'Brave'], 
    ['msedge', 'Edge'], ['edge', 'Edge'], ['firefox', 'Firefox']
  ]);
  
  // Check for exact matches in the mapping
  for (const [k, v] of map.entries()) if (lower.includes(k)) return v;
  
  // Default: capitalize first letter
  return n.charAt(0).toUpperCase() + n.slice(1);
}

/**
 * Converts threat severity strings to numeric ranks for sorting
 * Used to prioritize threats by severity level in the UI
 * 
 * @param {string} s - Severity string (critical, high, medium, low)
 * @returns {number} Numeric rank (4=critical, 3=high, 2=medium, 1=low, 0=unknown)
 */
function severityRank(s){
  const m = { critical: 4, high: 3, medium: 2, low: 1 };
  return m[String(s || '').toLowerCase()] || 0;
}

// ============================================================================
// UPDATE MODAL MANAGEMENT FUNCTIONS
// ============================================================================

/**
 * Show the update modal and hide main content
 */
function showUpdateModal() {
  updateModal.style.display = 'flex';
  mainContent.style.display = 'none';
}

/**
 * Hide the update modal and show main content
 */
function hideUpdateModal() {
  updateModal.style.display = 'none';
  mainContent.style.display = 'block';
}

/**
 * Update the modal UI based on current state
 * @param {string} state - Current update state
 * @param {Object} data - Additional data for the state
 */
function updateModalUI(state, data = {}) {
  updateState = state;
  
  switch (state) {
    case 'checking':
      updateTitle.textContent = 'Checking for Updates';
      updateMessage.textContent = 'Checking for updates...';
      updateStatus.style.display = 'block';
      updateActions.style.display = 'none';
      break;
      
    case 'available':
      updateTitle.textContent = 'Update Available';
      updateMessage.textContent = `Version ${data.version || 'latest'} is available. Would you like to download it?`;
      updateStatus.style.display = 'block';
      updateActions.style.display = 'flex';
      updateDownloadBtn.style.display = 'inline-block';
      updateInstallBtn.style.display = 'none';
      updateLaterBtn.style.display = 'inline-block';
      break;
      
    case 'downloading':
      updateTitle.textContent = 'Downloading Update';
      updateMessage.textContent = `Downloading update... ${Math.round(data.percent || 0)}%`;
      updateStatus.style.display = 'block';
      updateActions.style.display = 'none';
      break;
      
    case 'downloaded':
      updateTitle.textContent = 'Update Ready';
      updateMessage.textContent = 'Update downloaded successfully. The app will restart to install the update.';
      updateStatus.style.display = 'block';
      updateActions.style.display = 'flex';
      updateDownloadBtn.style.display = 'none';
      updateInstallBtn.style.display = 'inline-block';
      updateLaterBtn.style.display = 'inline-block';
      break;
      
    case 'error':
      updateTitle.textContent = 'Update Error';
      updateMessage.textContent = data.message || 'An error occurred while checking for updates.';
      updateStatus.style.display = 'block';
      updateActions.style.display = 'flex';
      updateDownloadBtn.style.display = 'none';
      updateInstallBtn.style.display = 'none';
      updateLaterBtn.style.display = 'inline-block';
      break;
      
    case 'complete':
      hideUpdateModal();
      break;
  }
}

/**
 * Handle download update button click
 */
async function handleDownloadUpdate() {
  try {
    updateModalUI('downloading');
    const result = await window.companion.downloadUpdate();
    if (!result.ok) {
      updateModalUI('error', { message: result.error || 'Download failed' });
    }
  } catch (error) {
    updateModalUI('error', { message: error.message || 'Download failed' });
  }
}

/**
 * Handle install update button click
 */
async function handleInstallUpdate() {
  try {
    const result = await window.companion.installUpdate();
    if (!result.ok) {
      updateModalUI('error', { message: result.error || 'Installation failed' });
    }
  } catch (error) {
    updateModalUI('error', { message: error.message || 'Installation failed' });
  }
}

/**
 * Handle skip update button click
 */
async function handleSkipUpdate() {
  try {
    await window.companion.skipUpdate();
    updateModalUI('complete');
  } catch (error) {
    console.error('Error skipping update:', error);
    updateModalUI('complete'); // Show main content anyway
  }
}

// ============================================================================
// MAIN SYSTEM CHECK FUNCTION
// ============================================================================

/**
 * Main system check function that performs comprehensive exam security validation
 * Executes a two-phase check: exam mode validation followed by notification audit
 * Updates UI with results and provides actionable feedback to users
 * 
 * @returns {Promise<void>}
 */
async function runSystemCheck(){
  // Prevent multiple simultaneous scans
  if (isChecking) return;
  isChecking = true;
  
  // ============================================================================
  // UI STATE PREPARATION
  // ============================================================================
  scanBtn.disabled = true;
  scanBtn.classList.add('loading');
  scanBtn.setAttribute('aria-busy', 'true');
  scanBtn.textContent = 'Scanning…';
  globalStatusEl.textContent = 'Exam check: Validating running applications…';
  globalHintEl.textContent = 'Only one browser and the companion app may be running';
  suspiciousListEl.innerHTML = '';
  
  try {
    // Refresh focus badge at scan start
    try { await setFocusStatus(); } catch {}
    
    // ============================================================================
    // PHASE 1: EXAM MODE CHECK
    // ============================================================================
    // Exam mode check first: allow only 1 browser + companion app
    try {
      const exam = await window.companion.runExamModeCheck();
      if (exam && exam.ok) {
        const flagged = Array.isArray(exam.flagged) ? exam.flagged : [];
        const multi = !!exam.summary?.multipleBrowsersActive;
        
        if (multi || flagged.length > 0) {
          // ============================================================================
          // EXAM MODE VIOLATIONS DETECTED
          // ============================================================================
          const browserWarning = multi ? `<div class="muted" style="margin:6px 0 10px">Multiple browsers active: ${
            Array.isArray(exam.summary.activeBrowsers) ? exam.summary.activeBrowsers.join(', ') : ''
          }. Primary Browser : ${exam.summary.allowedBrowserFamily || 'auto-selected'}. Please keep only one browser open.</div>` : '';
          
          // Generate table of flagged applications
          const rows = flagged.slice(0, 100).map(p => {
            const cpu = (Number(p.cpu) || 0).toFixed(1);
            const mem = (Number(p.mem) || 0).toFixed(1);
            return `<tr><td>${p.name}</td><td>${p.pid}</td><td>${cpu}%</td><td>${mem}%</td></tr>`;
          }).join('');
          
          const table = `
<table class="table">
  <thead><tr><th>Application</th><th>PID</th><th>CPU</th><th>MEM</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="4" class="muted">No additional apps flagged</td></tr>'}</tbody>
</table>`;
          
          // Update UI with exam mode violations
          suspiciousListEl.innerHTML = table;
          notifAuditEl.innerHTML = browserWarning;
          globalStatusEl.textContent = 'Action required: Close disallowed applications';
          globalHintEl.textContent = 'During the exam, only one browser and this companion app may run.';
          return;
        }
      }
    } catch {}
    // ============================================================================
    // PHASE 2: NOTIFICATION AUDIT
    // ============================================================================
    // Continue with Notification audit only if exam check passes
    globalStatusEl.textContent = 'Checking notifications…';
    globalHintEl.textContent = 'Verifying system/browser notification settings';
    const audit = await window.companion.auditNotifications();
    
    if (audit) {
      const sys = audit.system;
      const threats = Array.isArray(audit.threats) ? audit.threats : [];
      const browsers = audit.browsers || [];
      const procs = audit.processes || [];

      // ============================================================================
      // NOTIFICATION THREAT ANALYSIS
      // ============================================================================
      // Detect DND violation threats explicitly
      const dndThreat = threats.find(t => t && (
        t.type === 'mac_focus_mode_disabled' ||
        t.type === 'linux_dnd_required' ||
        t.type === 'windows_dnd_off'
      ));

      // Check for browsers that need notification disabling
      const anyNeedsDisable = (browsers || []).some(b => (b.profiles || []).some(p => p.status !== 'disabled'));
      const anyProc = procs.length > 0;
      const showTables = anyNeedsDisable || anyProc || !!dndThreat;

      if (showTables) {
        // ============================================================================
        // NOTIFICATION VIOLATIONS DETECTED - GENERATE DETAILED TABLES
        // ============================================================================
        
        // System status table
        const sysTable = `
<table class="table">
  <thead><tr><th>System</th><th>Status</th><th>Details</th></tr></thead>
  <tbody>
    <tr><td>${sys.platform}</td><td>${sys.status}</td><td>${sys.details || ''}</td></tr>
  </tbody>
</table>`;

        // DND violation banner
        const dndBanner = dndThreat ? `<div class="muted" style="margin:6px 0 10px">Do Not Disturb is OFF. Please enable it to proceed.</div>` : '';

        // Browser notification status table
        const browserRows = browsers.map(b => {
          const activeProfiles = (b.profiles || []).filter(p => p.status !== 'disabled');
          const rows = activeProfiles.map(p => {
            const needsDisable = p.status !== 'disabled';
            const cls = needsDisable ? ' class="row-enabled"' : '';
            const hint = needsDisable ? ' <span class="badge-enabled">disable to continue</span>' : '';
            return `<tr${cls}><td>${b.browser}</td><td>${p.profile}</td><td>${p.status}${hint}</td><td>${p.allowedSites ?? ''}</td><td>${p.blockedSites ?? ''}</td></tr>`;
          }).join('');
          return rows;
        }).join('');
        
        const browserTable = `
<table class="table">
  <thead><tr><th>Browser</th><th>Profile</th><th>Status</th><th>Allowed</th><th>Blocked</th></tr></thead>
  <tbody>${browserRows || '<tr><td colspan="5" class="muted">No active browsers detected</td></tr>'}</tbody>
</table>`;

        // Process notification status table
        const procRows = (audit.processes || []).map(p => {
          const cls = p.notifEnabled ? ' class="row-enabled"' : '';
          return `<tr${cls}><td>${p.name}${p.notifEnabled ? ' <span class=\"badge-enabled\">enabled</span>' : ''}</td><td>${p.pid}</td><td>${p.state || ''}</td><td>${(p.cpu ?? 0).toFixed(1)}%</td><td>${(p.mem ?? 0).toFixed(1)}%</td></tr>`;
        }).join('');
        
        const procTable = `
<table class="table">
  <thead><tr><th>Active app (notifications ON)</th><th>PID</th><th>State</th><th>CPU</th><th>MEM</th></tr></thead>
  <tbody>${procRows || '<tr><td colspan=\"5\" class=\"muted\">None</td></tr>'}</tbody>
</table>`;

        // User instruction
        const instruction = anyNeedsDisable ? `<div class="muted" style="margin:6px 0 10px">You are required to disable notification settings for the browser.</div>` : '';
        notifAuditEl.innerHTML = sysTable + dndBanner + instruction + browserTable + procTable;
        
        // Note: Notification settings button binding is commented out
        // This could be enabled to provide direct access to system notification settings
        // try {
        //   const btn = document.getElementById('openNotifSettingsBtn');
        //   if (btn) {
        //     btn.addEventListener('click', async () => {
        //       try { await window.companion.openNotificationSettings(); } catch {}
        //     });
        //   }
        // } catch {}
      } else {
        // No notification violations detected - clear audit display
        notifAuditEl.innerHTML = '';
      }

      // ============================================================================
      // FINAL STATUS DETERMINATION
      // ============================================================================
      if ((threats.length > 0) || anyNeedsDisable || anyProc) {
        // Notification violations detected
        if (dndThreat) {
          globalStatusEl.textContent = 'Action required: Do Not Disturb is OFF';
          globalHintEl.innerHTML = 'Enable Do Not Disturb in system settings, then re-run the check.';
        } else {
          globalStatusEl.textContent = 'Action required: Notifications are ON';
          globalHintEl.innerHTML = 'Please disable notifications in your browser/apps, then re-run the check.';
        }
        return;
      }
    }

    // ============================================================================
    // SUCCESS STATE
    // ============================================================================
    notifAuditEl.innerHTML = '';
    globalStatusEl.textContent = 'All clear';
    globalHintEl.textContent = 'No threats detected and notifications look off.';
    
  } catch (e) {
    // ============================================================================
    // ERROR HANDLING
    // ============================================================================
    globalStatusEl.textContent = 'Scan error';
    globalHintEl.textContent = e.message;
  } finally {
    // ============================================================================
    // UI CLEANUP AND REFRESH
    // ============================================================================
    scanBtn.classList.remove('loading');
    scanBtn.removeAttribute('aria-busy');
    scanBtn.textContent = scanBtnDefaultText;
    scanBtn.disabled = false;
    isChecking = false;
    
    // Refresh focus and notification badges after scan
    try {
      const notif = await window.companion.getNotificationStatus();
      setNotifStatus(notif);
    } catch {}
    try { await setFocusStatus(); } catch {}
  }
}

// ============================================================================
// EVENT LISTENERS AND INITIALIZATION
// ============================================================================

// Bind scan button click event
scanBtn.addEventListener('click', runSystemCheck);

// Bind update modal button events
updateDownloadBtn.addEventListener('click', handleDownloadUpdate);
updateInstallBtn.addEventListener('click', handleInstallUpdate);
updateLaterBtn.addEventListener('click', handleSkipUpdate);

/**
 * Application initialization function
 * Sets up initial UI state, checks permissions, and subscribes to auto-scan events
 * Runs immediately when the renderer loads
 */
(async function init(){
  // ============================================================================
  // INITIAL UI STATE - SHOW UPDATE MODAL FIRST
  // ============================================================================
  showUpdateModal();
  updateModalUI('checking');
  
  // ============================================================================
  // UPDATE EVENT LISTENERS
  // ============================================================================
  // Listen for update events from main process
  window.companion.onUpdateChecking(() => {
    updateModalUI('checking');
  });
  
  window.companion.onUpdateAvailable((data) => {
    updateModalUI('available', data);
  });
  
  window.companion.onUpdateNotAvailable(() => {
    updateModalUI('complete');
  });
  
  window.companion.onUpdateDownloadProgress((data) => {
    updateModalUI('downloading', data);
  });
  
  window.companion.onUpdateDownloaded((data) => {
    updateModalUI('downloaded', data);
  });
  
  window.companion.onUpdateError((data) => {
    updateModalUI('error', data);
  });
  
  window.companion.onUpdateSkip(() => {
    updateModalUI('complete');
  });
  
  // ============================================================================
  // INITIAL UI STATE (AFTER UPDATE CHECK)
  // ============================================================================
  globalStatusEl.textContent = 'Idle';
  globalHintEl.textContent = 'Click Scan Now to run notifications check and system scan.';
  
  // ============================================================================
  // LOAD APPLICATION VERSION
  // ============================================================================
  // Load and display the current application version after DOM is ready
  setTimeout(async () => {
    try { await loadAppVersion(); } catch {}
  }, 100);
  
  // ============================================================================
  // PERMISSION CHECKS
  // ============================================================================
  try {
    const perm = await window.companion.checkBrowserTabPermissions();
    if (perm && perm.ok === false) {
      console.warn('Browser tab permission check failed', perm);
    }
  } catch {}
  
  // ============================================================================
  // INITIAL STATUS LOADING
  // ============================================================================
  // Load initial focus status (macOS)
  try { await setFocusStatus(); } catch {}
  
  // ============================================================================
  // AUTO-SCAN SUBSCRIPTION
  // ============================================================================
  if (unsubscribeAutoScan) { try { unsubscribeAutoScan(); } catch {} }
  
  // Subscribe to auto-scan results only; auto-scan is started by main process
  unsubscribeAutoScan = window.companion.onAutoScanResult(() => {
    // Trigger system check if not already running
    if (!isChecking) runSystemCheck();
    
    // Animate auto-scan badge to show activity
    try {
      const badge = document.getElementById('autoScanBadge');
      if (badge) {
        badge.classList.remove('pulse');
        // trigger reflow to restart animation
        void badge.offsetWidth;
        badge.classList.add('pulse');
      }
    } catch {}
  });
})();

// ============================================================================
// CLEANUP ON PAGE UNLOAD
// ============================================================================
/**
 * Cleanup function that runs when the page is about to unload
 * Ensures proper cleanup of auto-scan subscriptions and resources
 */
window.addEventListener('beforeunload', () => {
  try { if (unsubscribeAutoScan) unsubscribeAutoScan(); } catch {}
  try { window.companion.stopAutoScan(); } catch {}
  unsubscribeAutoScan = null;
}); 