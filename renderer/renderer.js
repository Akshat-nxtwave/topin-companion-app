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
    // Step 1: Security scan (threats & malicious)
    const res = await window.companion.scan();
    if (!res.ok) throw new Error(res.error || 'Scan failed');
    const { report } = res;

    if (Array.isArray(report.threats) && report.threats.length > 0) {
      const rows = report.threats.slice(0, 50).map(t => `<tr><td>${t.type}</td><td>${t.message || ''}</td><td>${t.name || t.port || ''}</td></tr>`).join('');
      const table = `
<table class="table">
  <thead><tr><th>Type</th><th>Message</th><th>Target</th></tr></thead>
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

    const notif = await window.companion.getNotificationStatus();
    // setNotifStatus(notif);

    try {
      const audit = await window.companion.auditNotifications();
      if (audit.ok) {
        const sys = audit.system;
        const browsers = audit.browsers || [];
        const procs = audit.processes || [];

        const anyNeedsDisable = (browsers || []).some(b => (b.profiles || []).some(p => p.status !== 'disabled'));
        const anyProc = procs.length > 0;
        // Exclude system notification status from action/table decisions
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
            // Only include profiles that are NOT disabled in the table
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

          const procRows = procs.map(p => {
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
      } else {
        notifAuditEl.textContent = 'Audit failed: ' + audit.error;
      }
    } catch (e) {
      notifAuditEl.textContent = 'Audit error: ' + e.message;
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