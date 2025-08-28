const notifStatusEl = document.getElementById('notifStatus');
const focusStatusEl = document.getElementById('focusStatus');
const scanBtn = document.getElementById('scanBtn');
const globalStatusEl = document.getElementById('globalStatus');
const globalHintEl = document.getElementById('globalHint');
const suspiciousListEl = document.getElementById('suspiciousList');
const notifAuditEl = document.getElementById('notifAudit');
const scanBtnDefaultText = scanBtn.textContent;

function setNotifStatus(status){
  if (!status.supported) {
    notifStatusEl.textContent = 'Not supported';
    notifStatusEl.style.background = '#4b2738';
    return;
  }
  notifStatusEl.textContent = status.enabledLikely ? 'ON' : 'OFF';
  notifStatusEl.style.background = status.enabledLikely ? '#284047' : '#2b3a20';
}

async function setFocusStatus(){
  try {
    const res = await window.companion.getFocusStatus();
    if (!focusStatusEl) return;
    if (!res || res.supported === false) {
      focusStatusEl.textContent = 'Focus: Unsupported';
      focusStatusEl.style.background = '#4b2738';
      return;
    }
    const on = String(res.focus || '').toLowerCase() === 'on';
    let modeSuffix = '';
    if (Array.isArray(res.modes) && res.modes.length) {
      modeSuffix = ` (${res.modes[0]})`;
    }
    focusStatusEl.textContent = `Focus: ${on ? 'ON' : 'OFF'}${modeSuffix}`;
    focusStatusEl.style.background = on ? '#284047' : '#2b3a20';
    focusStatusEl.title = res.details || '';
  } catch (e) {
    if (focusStatusEl) {
      focusStatusEl.textContent = 'Focus: Unknown';
      focusStatusEl.style.background = '#4b2738';
      focusStatusEl.title = String(e.message || e);
    }
  }
}

let isChecking = false;
let unsubscribeAutoScan = null;

// Determine the best label to display for a threat's target application
function resolveThreatTarget(threat, processes){
  try {
    if (!threat) return '';
    const nameFromThreat = (threat.details && threat.details.name) || threat.name;
    if (nameFromThreat) return String(nameFromThreat);

    const pid = (threat.details && threat.details.pid) || threat.pid;
    if (pid && Array.isArray(processes)) {
      const proc = processes.find(p => p && p.pid === pid);
      if (proc && proc.name) return `${proc.name}`;
    }

    const port = (threat.details && threat.details.port) || threat.port;
    if (port) return `port ${port}`;

    const message = String(threat.message || '');
    if (message.includes(':')) {
      const part = message.split(':').pop().trim();
      if (part) return part;
    }
  } catch {}
  return '';
}

function normalizeAppDisplay(name){
  const n = String(name || '').trim();
  if (!n) return '';
  const lower = n.toLowerCase();
  const map = new Map([
    ['microsoft teams', 'Microsoft Teams'], ['teams', 'Microsoft Teams'], ['ms teams', 'Microsoft Teams'],
    ['discord', 'Discord'], ['slack', 'Slack'], ['zoom', 'Zoom'], ['skype', 'Skype'], ['webex', 'Webex'],
    ['google chrome', 'Chrome'], ['chrome', 'Chrome'], ['chromium', 'Chromium'], ['brave', 'Brave'], ['msedge', 'Edge'], ['edge', 'Edge'], ['firefox', 'Firefox']
  ]);
  for (const [k, v] of map.entries()) if (lower.includes(k)) return v;
  return n.charAt(0).toUpperCase() + n.slice(1);
}

function severityRank(s){
  const m = { critical: 4, high: 3, medium: 2, low: 1 };
  return m[String(s || '').toLowerCase()] || 0;
}

async function runSystemCheck(){
  if (isChecking) return;
  isChecking = true;
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
    // Exam mode check first: allow only 1 browser + companion app
    try {
      const exam = await window.companion.runExamModeCheck();
      if (exam && exam.ok) {
        const flagged = Array.isArray(exam.flagged) ? exam.flagged : [];
        const multi = !!exam.summary?.multipleBrowsersActive;
        if (multi || flagged.length > 0) {
          const browserWarning = multi ? `<div class="muted" style="margin:6px 0 10px">Multiple browsers active: ${
            Array.isArray(exam.summary.activeBrowsers) ? exam.summary.activeBrowsers.join(', ') : ''
          }. Primary Browser : ${exam.summary.allowedBrowserFamily || 'auto-selected'}. Please keep only one browser open.</div>` : '';
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
          suspiciousListEl.innerHTML = table;
          notifAuditEl.innerHTML = browserWarning;
          globalStatusEl.textContent = 'Action required: Close disallowed applications';
          globalHintEl.textContent = 'During the exam, only one browser and this companion app may run.';
          return;
        }
      }
    } catch {}
    // Continue with Notification audit only if exam check passes
    globalStatusEl.textContent = 'Checking notifications…';
    globalHintEl.textContent = 'Verifying system/browser notification settings';
    const audit = await window.companion.auditNotifications();
    if (audit) {
      const sys = audit.system;
      const threats = Array.isArray(audit.threats) ? audit.threats : [];
      const browsers = audit.browsers || [];
      const procs = audit.processes || [];

      // Detect DND violation threats explicitly
      const dndThreat = threats.find(t => t && (
        t.type === 'mac_focus_mode_disabled' ||
        t.type === 'linux_dnd_required' ||
        t.type === 'windows_dnd_off'
      ));

      const anyNeedsDisable = (browsers || []).some(b => (b.profiles || []).some(p => p.status !== 'disabled'));
      const anyProc = procs.length > 0;
      const showTables = anyNeedsDisable || anyProc || !!dndThreat;

      if (showTables) {
        const sysTable = `
<table class="table">
  <thead><tr><th>System</th><th>Status</th><th>Details</th></tr></thead>
  <tbody>
    <tr><td>${sys.platform}</td><td>${sys.status}</td><td>${sys.details || ''}</td></tr>
  </tbody>
</table>`;

        const dndBanner = dndThreat ? `<div class="muted" style="margin:6px 0 10px">Do Not Disturb is OFF. Please enable it to proceed.</div>` : '';

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

        const procRows = (audit.processes || []).map(p => {
          const cls = p.notifEnabled ? ' class="row-enabled"' : '';
          return `<tr${cls}><td>${p.name}${p.notifEnabled ? ' <span class=\"badge-enabled\">enabled</span>' : ''}</td><td>${p.pid}</td><td>${p.state || ''}</td><td>${(p.cpu ?? 0).toFixed(1)}%</td><td>${(p.mem ?? 0).toFixed(1)}%</td></tr>`;
        }).join('');
        const procTable = `
<table class="table">
  <thead><tr><th>Active app (notifications ON)</th><th>PID</th><th>State</th><th>CPU</th><th>MEM</th></tr></thead>
  <tbody>${procRows || '<tr><td colspan=\"5\" class=\"muted\">None</td></tr>'}</tbody>
</table>`;

        const instruction = anyNeedsDisable ? `<div class="muted" style="margin:6px 0 10px">You are required to disable notification settings for the browser.</div>` : '';
        notifAuditEl.innerHTML = sysTable + dndBanner + instruction + browserTable + procTable;
        // Bind button if present
        // try {
        //   const btn = document.getElementById('openNotifSettingsBtn');
        //   if (btn) {
        //     btn.addEventListener('click', async () => {
        //       try { await window.companion.openNotificationSettings(); } catch {}
        //     });
        //   }
        // } catch {}
      } else {
        notifAuditEl.innerHTML = '';
      }

      if ((threats.length > 0) || anyNeedsDisable || anyProc) {
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

    notifAuditEl.innerHTML = '';
    globalStatusEl.textContent = 'All clear';
    globalHintEl.textContent = 'No threats detected and notifications look off.';
  } catch (e) {
    globalStatusEl.textContent = 'Scan error';
    globalHintEl.textContent = e.message;
  } finally {
    scanBtn.classList.remove('loading');
    scanBtn.removeAttribute('aria-busy');
    scanBtn.textContent = scanBtnDefaultText;
    scanBtn.disabled = false;
    isChecking = false;
    // Refresh focus and notif badges after scan
    try {
      const notif = await window.companion.getNotificationStatus();
      setNotifStatus(notif);
    } catch {}
    try { await setFocusStatus(); } catch {}
  }
}

scanBtn.addEventListener('click', runSystemCheck);

(async function init(){
  globalStatusEl.textContent = 'Idle';
  globalHintEl.textContent = 'Click Scan Now to run notifications check and system scan.';
  try {
    const perm = await window.companion.checkBrowserTabPermissions();
    if (perm && perm.ok === false) {
      console.warn('Browser tab permission check failed', perm);
    }
  } catch {}
  // Load initial focus status (macOS)
  try { await setFocusStatus(); } catch {}
  if (unsubscribeAutoScan) { try { unsubscribeAutoScan(); } catch {} }
  unsubscribeAutoScan = window.companion.onAutoScanResult(() => {
    if (!isChecking) runSystemCheck();
  });
  try { await window.companion.startAutoScan(30000); } catch {}
})();

window.addEventListener('beforeunload', () => {
  try { if (unsubscribeAutoScan) unsubscribeAutoScan(); } catch {}
  try { window.companion.stopAutoScan(); } catch {}
  unsubscribeAutoScan = null;
}); 