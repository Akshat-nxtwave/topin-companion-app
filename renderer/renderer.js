const notifStatusEl = document.getElementById('notifStatus');
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
  globalStatusEl.textContent = 'Step 1/2: Scanning for threats…';
  globalHintEl.textContent = 'Running security checks for malicious software and activity';
  suspiciousListEl.innerHTML = '';
  try {
    // Run both checks together in main for consistent results
    const res = await window.companion.completeSystemCheck();
    if (!res.ok) throw new Error(res.error || 'Scan failed');

    // Step 1: Security scan (threats & malicious)
    const report = res.security;
    if (Array.isArray(report?.threats) && report.threats.length > 0) {
      // Aggregate by application so we show one row per app
      const processes = report.processes || [];
      const agg = new Map();
      for (const t of report.threats) {
        const targetRaw = resolveThreatTarget(t, processes);
        const target = String(targetRaw || '').trim();
        if (!target) continue;
        const key = target.toLowerCase();
        const display = normalizeAppDisplay(target);
        const rank = severityRank(t.severity);
        const cur = agg.get(key) || { app: display, type: t.type, message: t.message || '', severity: t.severity, rank: rank, reasons: new Set() };
        cur.reasons.add(t.message || t.type || '');
        if (rank > (cur.rank || 0)) {
          cur.type = t.type;
          cur.message = t.message || cur.message;
          cur.severity = t.severity;
          cur.rank = rank;
        }
        agg.set(key, cur);
      }
      const rows = Array.from(agg.values()).slice(0, 50).map(item => {
        const reasons = Array.from(item.reasons).filter(Boolean);
        const reasonText = reasons.length > 1 ? `${item.message} (+${reasons.length - 1} more)` : (item.message || '');
        return `<tr><td>${item.type}</td><td>${reasonText}</td><td>${item.app}</td></tr>`;
      }).join('');
      const table = `
<table class="table">
  <thead><tr><th>Type</th><th>Message</th><th>Application</th></tr></thead>
  <tbody>${rows}</tbody>
</table>`;
      suspiciousListEl.innerHTML = table;
      globalStatusEl.textContent = 'Action required: Threats detected';
      globalHintEl.textContent = 'Please stop/terminate the listed processes or close apps, then re-run the check.';
      return;
    }

    // Step 2: Notifications
    globalStatusEl.textContent = 'Step 2/2: Checking notifications…';
    globalHintEl.textContent = 'Verifying system/browser notification settings';

    const audit = res.notifications;
    if (audit) {
      const sys = audit.system;
      const browsers = audit.browsers || [];
      const procs = audit.threats?.length ? (audit.processes || []) : (audit.processes || []); // keep as-is

      const anyNeedsDisable = (browsers || []).some(b => (b.profiles || []).some(p => p.status !== 'disabled'));
      const anyProc = procs.length > 0;
      const showTables = anyNeedsDisable || anyProc;

      if (showTables) {
        const sysTable = `
<table class="table">
  <thead><tr><th>System</th><th>Status</th><th>Details</th></tr></thead>
  <tbody>
    <tr><td>${sys.platform}</td><td>${sys.status}</td><td>${sys.details || ''}</td></tr>
  </tbody>
</table>`;

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
        notifAuditEl.innerHTML = sysTable + instruction + browserTable + procTable;
      } else {
        notifAuditEl.innerHTML = '';
      }

      if (anyNeedsDisable || anyProc) {
        globalStatusEl.textContent = 'Action required: Notifications are ON';
        globalHintEl.innerHTML = 'Please disable notifications in your browser/apps, then re-run the check.';
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