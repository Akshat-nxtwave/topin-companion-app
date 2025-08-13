const notifStatusEl = document.getElementById('notifStatus');
const scanBtn = document.getElementById('scanBtn');
const globalStatusEl = document.getElementById('globalStatus');
const globalHintEl = document.getElementById('globalHint');
const suspiciousListEl = document.getElementById('suspiciousList');
const notifAuditEl = document.getElementById('notifAudit');

function setNotifStatus(status){
  if (!status.supported) {
    notifStatusEl.textContent = 'Not supported';
    notifStatusEl.style.background = '#4b2738';
    return;
  }
  notifStatusEl.textContent = status.enabledLikely ? 'ON' : 'OFF';
  notifStatusEl.style.background = status.enabledLikely ? '#284047' : '#2b3a20';
}

async function runSystemCheck(){
  scanBtn.disabled = true;
  globalStatusEl.textContent = 'Step 1/2: Checking notifications…';
  globalHintEl.textContent = 'Verifying system/browser notification settings';
  suspiciousListEl.innerHTML = '';
  try {
    // Step 1: notifications
    const notif = await window.companion.getNotificationStatus();
    setNotifStatus(notif);

    // Detailed audit
    try {
      const audit = await window.companion.auditNotifications();
      if (audit.ok) {
        const sys = audit.system;
        const browsers = audit.browsers || [];
        const procs = audit.processes || [];

        const sysTable = `
<table class="table">
  <thead><tr><th>System</th><th>Status</th><th>Details</th></tr></thead>
  <tbody>
    <tr><td>${sys.platform}</td><td>${sys.status}</td><td>${sys.details || ''}</td></tr>
  </tbody>
</table>`;

        const browserRows = browsers.map(b => {
          const rows = (b.profiles || []).map(p => {
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

        const anyNeedsDisable = (browsers || []).some(b => (b.profiles || []).some(p => p.status !== 'disabled'));
        const instruction = anyNeedsDisable ? `<div class="muted" style="margin:6px 0 10px">You are required to disable notification settings for the browser.</div>` : '';

        // Build set of browsers with notifications enabled in any active profile
        const enabledBrowsers = new Set();
        for (const b of browsers) if ((b.profiles || []).some(p => p.status === 'enabled')) {
          const name = String(b.browser || '').toLowerCase();
          if (name.includes('chrome')) enabledBrowsers.add('chrome');
          if (name.includes('chromium')) enabledBrowsers.add('chromium');
          if (name.includes('edge')) enabledBrowsers.add('msedge');
          if (name.includes('brave')) enabledBrowsers.add('brave');
          if (name.includes('firefox')) enabledBrowsers.add('firefox');
        }

        const filteredProcs = procs.filter(p => {
          const n = String(p.name || '').toLowerCase();
          return (
            (enabledBrowsers.has('chrome') && n.includes('chrome') && !n.includes('chromium')) ||
            (enabledBrowsers.has('chromium') && n.includes('chromium')) ||
            (enabledBrowsers.has('msedge') && (n.includes('msedge') || n.includes('microsoft edge'))) ||
            (enabledBrowsers.has('brave') && n.includes('brave')) ||
            (enabledBrowsers.has('firefox') && n.includes('firefox'))
          );
        });

        const procRows = filteredProcs.map(p => {
          const cls = p.notifEnabled ? ' class="row-enabled"' : '';
          return `<tr${cls}><td>${p.name}${p.notifEnabled ? ' <span class="badge-enabled">enabled</span>' : ''}</td><td>${p.pid}</td><td>${p.state || ''}</td><td>${(p.cpu ?? 0).toFixed(1)}%</td><td>${(p.mem ?? 0).toFixed(1)}%</td></tr>`;
        }).join('');
        const procTable = `
<table class="table">
  <thead><tr><th>Active app (notifications ON)</th><th>PID</th><th>State</th><th>CPU</th><th>MEM</th></tr></thead>
  <tbody>${procRows || '<tr><td colspan="5" class="muted">None</td></tr>'}</tbody>
</table>`;

        notifAuditEl.innerHTML = sysTable + instruction + browserTable + procTable;
      } else {
        notifAuditEl.textContent = 'Audit failed: ' + audit.error;
      }
    } catch (e) {
      notifAuditEl.textContent = 'Audit error: ' + e.message;
    }

    if (notif.enabledLikely) {
      globalStatusEl.textContent = 'Action required: Notifications are ON';
      globalHintEl.innerHTML = 'Please turn off notifications in system settings or your browser, then re-run the check.';
      return;
    }

    // Step 2: scan
    globalStatusEl.textContent = 'Step 2/2: Scanning system…';
    globalHintEl.textContent = 'Looking for malicious processes and connections';

    const res = await window.companion.scan();
    if (!res.ok) throw new Error(res.error || 'Scan failed');
    const { report } = res;

    if (Array.isArray(report.threats) && report.threats.length > 0) {
      suspiciousListEl.innerHTML = '';
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

    globalStatusEl.textContent = 'All clear';
    globalHintEl.textContent = 'Notifications look off, and no threats detected.';
  } catch (e) {
    globalStatusEl.textContent = 'Scan error';
    globalHintEl.textContent = e.message;
  } finally {
    scanBtn.disabled = false;
  }
}

scanBtn.addEventListener('click', runSystemCheck);

(async function init(){
  globalStatusEl.textContent = 'Idle';
  globalHintEl.textContent = 'Click Scan Now to run notifications check and system scan.';
})(); 