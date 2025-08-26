const si = require('systeminformation');
const path = require('path');
const os = require('os');
const { exec } = require('child_process');

class ExamModeService {
  constructor() {
    this.enableLog = true;
  }

  log(message, ...args) {
    if (this.enableLog) {
      // console.log(message, ...args);
    }
  }

  setLogging(enabled) {
    this.enableLog = !!enabled;
  }

  async safe(checkName, fn, timeoutMs = 3000) {
    try {
      const result = await Promise.race([
        fn(),
        new Promise((_, reject) => setTimeout(() => reject(new Error(`${checkName} timeout`)), timeoutMs))
      ]);
      return result || [];
    } catch {
      return [];
    }
  }

  execCmd(command, timeoutMs = 1500) {
    return new Promise((resolve) => {
      try {
        const child = exec(command, { timeout: timeoutMs }, (err, stdout, stderr) => {
          if (err) return resolve({ ok: false, stdout: '', stderr: String(stderr || err.message || '') });
          resolve({ ok: true, stdout: String(stdout || ''), stderr: String(stderr || '') });
        });
        // Prevent hanging
        child.on('error', () => resolve({ ok: false, stdout: '', stderr: 'spawn error' }));
      } catch (e) {
        resolve({ ok: false, stdout: '', stderr: String(e) });
      }
    });
  }

  isSystemHelper(processName, command) {
    const name = String(processName || '').toLowerCase();
    const cmd = String(command || '').toLowerCase();
    if (!name && !cmd) return false;
    if (name.includes('airplayxpchelper') || cmd.includes('airplayxpchelper')) return true;
    if (name.includes('airplay') || cmd.includes('airplay')) return true;
    if (
      name === 'teamviewerd' ||
      cmd.includes('/teamviewerd') ||
      cmd.includes('\\teamviewerd') ||
      cmd.includes('tv_bin/teamviewerd')
    ) return true;
    if (name.includes('.driver') || cmd.includes('.driver')) return true;
    if (name.includes('kext') || cmd.includes('kext')) return true;
    if (name.includes('coreaudio') || cmd.includes('coreaudio')) return true;
    if (cmd.includes('/library/audio/plug-ins/hal')) return true;
    return false;
  }

  isBackgroundService(processName, command) {
    const name = (processName || '').toLowerCase();
    const cmd = (command || '').toLowerCase();
    const svcList = [
      'teamviewerd','tv_bin/teamviewerd','ad_service','vncserver-x11-core','sshd','rdp-server','chrome --type=gpu-process','chrome --type=utility'
    ];
    for (const svc of svcList) {
      const s = svc.toLowerCase();
      if (name.includes(s) || cmd.includes(s)) return true;
    }
    if (name.includes('.driver') || cmd.includes('.driver') || name.includes('kext') || cmd.includes('kext')) return true;
    if (name.includes('coreaudio') || cmd.includes('coreaudio') || cmd.includes('/library/audio/plug-ins/hal')) return true;
    if (name.includes('airplayxpchelper') || cmd.includes('airplayxpchelper') || name.includes('airplay') || cmd.includes('airplay')) return true;
    if ((name.endsWith('d') && (name.includes('teamviewer') || name.includes('anydesk'))) ||
        cmd.includes('--service') || cmd.includes('--daemon') || cmd.includes('-d ') ||
        (cmd.includes('chrome') && (cmd.includes('--type=') && !cmd.includes('--type=renderer')))) return true;
    return false;
  }

  isKernelStyleNameLinux(name) {
    if (process.platform !== 'linux') return false;
    const n = String(name || '').toLowerCase();
    if (!n) return false;
    if (n.startsWith('[')) return true; // kernel threads
    const patterns = [
      /^kworker/, /^ksoftirqd/, /^rcu_/, /^rcu-/, /^rcu\b/, /^cpuhp/, /^migration/, /^idle_inject/, /^oom_reaper/, /^kauditd/, /^kdevtmpfs/, /^writeback/, /^netns/, /^slub_flushwq/, /^mm_percpu_wq/, /^pool_workqueue_release/
    ];
    return patterns.some(r => r.test(n));
  }

  async collectLinuxGuiPids() {
    const gui = new Set();
    try {
      // X11 windows via wmctrl (if available)
      const wm = await this.execCmd('wmctrl -lp 2>/dev/null || true', 800);
      if (wm.ok && wm.stdout) {
        const lines = wm.stdout.split(/\r?\n/).filter(Boolean);
        for (const line of lines) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 4) {
            const pid = Number(parts[2]) || Number(parts[3]) || 0; // different wmctrl versions
            if (pid) gui.add(pid);
          }
        }
      }
      // Wayland/X11 sockets via lsof
      const way = process.env.XDG_RUNTIME_DIR ? await this.execCmd(`lsof -t ${process.env.XDG_RUNTIME_DIR}/wayland-* 2>/dev/null || true`, 800) : { ok: false, stdout: '' };
      if (way.ok && way.stdout) {
        for (const p of way.stdout.split(/\s+/)) { const pid = Number(p) || 0; if (pid) gui.add(pid); }
      }
      const x11 = await this.execCmd('lsof -t -U /tmp/.X11-unix/* 2>/dev/null || true', 800);
      if (x11.ok && x11.stdout) {
        for (const p of x11.stdout.split(/\s+/)) { const pid = Number(p) || 0; if (pid) gui.add(pid); }
      }
    } catch {}
    return gui;
  }

  async readProcCgroup(pid) {
    try {
      const fs = require('fs');
      const data = fs.readFileSync(`/proc/${pid}/cgroup`, 'utf8');
      const lines = data.split(/\r?\n/).filter(Boolean);
      const joined = lines.join('\n');
      const userSlice = /user\.slice/.test(joined);
      const systemSlice = /system\.slice/.test(joined);
      const isFlatpak = /flatpak/.test(joined);
      const isSnap = /snap\./.test(joined);
      const inAppScope = /app-.*\.scope/.test(joined);
      return { userSlice, systemSlice, isFlatpak, isSnap, inAppScope };
    } catch { return null; }
  }

  readProcStat(pid) {
    try {
      const fs = require('fs');
      const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
      // https://man7.org/linux/man-pages/man5/proc.5.html
      // Field 7 is tty_nr (1-based), index 6 in split array
      const parts = stat.split(' ');
      const ttyNr = Number(parts[6] || 0);
      return { ttyNr };
    } catch { return null; }
  }

  async isLikelyUserStartedLinux(p) {
    const u = String(p.user || '').trim();
    const current = (os.userInfo && os.userInfo().username) ? String(os.userInfo().username) : '';
    if (!u || !current || u !== current) return false;
    const stat = this.readProcStat(p.pid);
    const hasTty = !!(stat && stat.ttyNr && stat.ttyNr !== 0);
    const cg = await this.readProcCgroup(p.pid);
    const inAppScope = !!(cg && cg.inAppScope);
    const inUserSlice = !!(cg && cg.userSlice);
    // Consider user-started if it has a TTY, or lives in a user app scope/slice (GNOME/KDE app launch)
    return hasTty || inAppScope || inUserSlice;
  }

  async collectWindowsMainAppPids() {
    // Use PowerShell to enumerate processes with visible main windows in current session
    try {
      const ps = [
        "$cs=(Get-Process -Id $PID).SessionId",
        "$sys=@('explorer','svchost','winlogon','dwm','SearchUI','ShellExperienceHost','System','Idle','taskhostw','RuntimeBroker')",
        "$all=Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $_.SessionId -eq $cs }",
        "$user=$all | Where-Object { $_.MainWindowTitle -ne '' -and $_.Path -and $_.Path -notlike 'C:\\Windows\\*' -and $sys -notcontains $_.ProcessName }",
        "$user | Select-Object -ExpandProperty Id"
      ].join('; ');
      const cmd = `powershell -NoProfile -ExecutionPolicy Bypass -Command "${ps.replace(/"/g, '\\"')}"`;
      const res = await this.execCmd(cmd, 2000);
      const set = new Set();
      if (res.ok && res.stdout) {
        for (const line of res.stdout.split(/\r?\n/)) {
          const pid = Number(String(line).trim());
          if (pid) set.add(pid);
        }
      }
      return set;
    } catch {
      return new Set();
    }
  }

  async collectMacActiveAppNames() {
    // Prefer visible or frontmost application processes that are not background-only
    const scripts = [
      `osascript -e 'tell application "System Events" to get name of (application processes where background only is false and (visible is true or frontmost is true))'`,
      `osascript -e 'tell application "System Events" to get name of (application processes where background only is false)'`
    ];
    for (const cmd of scripts) {
      const res = await this.execCmd(cmd, 1500);
      if (res.ok && res.stdout && res.stdout.trim()) {
        const out = res.stdout.trim();
        // AppleScript returns comma-separated list or a single token
        const parts = out.split(/\s*,\s*/).map(s => s.trim()).filter(Boolean);
        if (parts.length) return new Set(parts.map(s => s.toLowerCase()));
      }
    }
    return new Set();
  }

  isChromiumMainProcess(command) {
    const c = String(command || '').toLowerCase();
    if (!c.includes('--type=')) return true; // main process usually has no --type
    return c.includes('--type=browser');
  }

  async runExamModeChecks(options = {}) {
    const opts = {
      allowedCompanionMatches: Array.isArray(options.allowedCompanionMatches) ? options.allowedCompanionMatches.map(s => String(s || '').toLowerCase()).filter(Boolean) : [],
      preferredBrowserFamily: String(options.preferredBrowserFamily || '').toLowerCase() || null
    };
    try {
      const processesRes = await this.safe('processes', () => si.processes(), 6000);
      const list = (processesRes && processesRes.list) ? processesRes.list : [];

      const simplify = (p) => ({
        pid: p.pid,
        name: p.name || 'unknown',
        command: p.command || '',
        cpu: Number.isFinite(p.pcpu) ? p.pcpu : 0,
        mem: Number.isFinite(p.pmem) ? p.pmem : 0,
        user: p.user || ''
      });

      const all = list.map(simplify);

      // Current user name (Linux filtering)
      const currentUser = os.userInfo && os.userInfo().username ? String(os.userInfo().username) : '';
      const isLinux = process.platform === 'linux';
      const isWindows = process.platform === 'win32';
      const isMac = process.platform === 'darwin';
      let guiPidSet = new Set();
      if (isLinux) {
        guiPidSet = await this.collectLinuxGuiPids();
      }
      let winMainPidSet = new Set();
      if (isWindows) {
        winMainPidSet = await this.collectWindowsMainAppPids();
      }
      let macActiveNames = new Set();
      if (isMac) {
        macActiveNames = await this.collectMacActiveAppNames();
      }

      const getExeBase = (cmd) => {
        const first = String(cmd || '').split(/\s+/)[0] || '';
        return path.basename(first).toLowerCase();
      };
      const isBrowserProcess = (name, cmd) => {
        const n = String(name || '').toLowerCase();
        const c = String(cmd || '').toLowerCase();
        return /(chrome|chromium|firefox|brave|opera|edge|msedge|safari)/.test(n) || /(chrome|chromium|firefox|brave|opera|edge|msedge|safari)/.test(getExeBase(c)) || /(chrome|chromium|firefox|brave|opera|edge|msedge|safari)/.test(c);
      };
      const browserFamily = (name, cmd) => {
        const text = `${String(name || '').toLowerCase()} ${String(cmd || '').toLowerCase()}`;
        if (/(msedge|edge)/.test(text)) return 'edge';
        if (/brave/.test(text)) return 'brave';
        if (/opera/.test(text)) return 'opera';
        if (/chromium/.test(text)) return 'chromium';
        if (/chrome/.test(text)) return 'chrome';
        if (/safari/.test(text)) return 'safari';
        if (/firefox/.test(text)) return 'firefox';
        return null;
      };
      const isKernelThreadLinux = (name) => this.isKernelStyleNameLinux(name);
      const isSystemPath = (cmd) => {
        const c = String(cmd || '').toLowerCase();
        return (
          c.startsWith('/usr/lib/') || c.startsWith('/usr/libexec/') || c.startsWith('/lib/') || c.startsWith('/sbin/') || c.startsWith('/usr/sbin/') ||
          c.startsWith('/system/') || c.startsWith('/bin/') ||
          c.includes('c:\\windows') || c.includes('\\windows\\system32') || c.includes('\\windows\\syswow64')
        );
      };
      const isSystemName = (name) => {
        const n = String(name || '').toLowerCase();
        const sysNames = [
          'systemd','init','launchd','windowserver','loginwindow','kernel_task','kthreadd','rcu_sched','xorg','xwayland','wayland','dbus-daemon',
          'pipewire','pulseaudio','xdg-desktop-portal','gnome-shell','kwin_x11','kwin_wayland','plasmashell','finder','coreaudiod','notifyd','cron','cupsd','avahi-daemon'
        ];
        return sysNames.some(s => n === s || n.includes(s));
      };
      const isCompanion = (name, cmd) => {
        const n = String(name || '').toLowerCase();
        const c = String(cmd || '').toLowerCase();
        if (!opts.allowedCompanionMatches.length) return false;
        const exe = getExeBase(c);
        return opts.allowedCompanionMatches.some(tok => n.includes(tok) || c.includes(tok) || exe.includes(tok));
      };

      const nonSystem = [];
      for (const p of all) {
        const n = String(p.name || '').toLowerCase();
        const c = String(p.command || '').toLowerCase();
        // Linux: Only consider likely user-started processes (same user and has TTY or app scope)
        if (isLinux) {
          const likelyUser = await this.isLikelyUserStartedLinux(p);
          if (!likelyUser) continue;
        }
        // Windows: Only consider processes with visible main window in current session
        if (isWindows && winMainPidSet.size && !winMainPidSet.has(p.pid)) continue;
        // macOS: Only consider application processes reported as active (not background-only)
        if (isMac && macActiveNames.size) {
          const pname = String(p.name || '').toLowerCase();
          if (!macActiveNames.has(pname)) continue;
        }
        if (this.isSystemHelper(n, c)) continue;
        if (this.isBackgroundService(n, c)) continue;
        if (isKernelThreadLinux(n)) continue;
        if (isSystemName(n)) continue;
        // cgroup: exclude system.slice, prefer user.slice; keep flatpak/snap as user apps
        if (isLinux) {
          const cg = await this.readProcCgroup(p.pid);
          if (cg && cg.systemSlice && !(cg.isFlatpak || cg.isSnap)) continue;
        }
        const fam = browserFamily(p.name, p.command);
        const isBrowserMain = fam ? (fam === 'firefox' ? true : this.isChromiumMainProcess(p.command)) : false;
        const isGui = isLinux ? guiPidSet.has(p.pid) : true;
        const isUserAppPath = c.includes('/opt/') || c.includes('/home/') || c.includes('/snap/') || c.includes('appimage');
        // Allow override: browsers and companion are considered user apps
        if (fam || isCompanion(n, c) || isGui || isUserAppPath) {
          nonSystem.push(p);
          continue;
        }
        // Finally, drop processes clearly under system paths
        if (isSystemPath(c)) continue;
        nonSystem.push(p);
      }

      const familyCpu = new Map();
      for (const p of nonSystem) {
        const fam = browserFamily(p.name, p.command);
        if (!fam) continue;
        // Only count main browser processes to avoid double-counting helpers
        const isMain = fam === 'firefox' ? true : this.isChromiumMainProcess(p.command);
        if (!isMain) continue;
        familyCpu.set(fam, (familyCpu.get(fam) || 0) + (Number(p.cpu) || 0));
      }
      const activeBrowsers = Array.from(familyCpu.keys());
      const multipleBrowsersActive = activeBrowsers.length > 1;

      let allowedBrowserFamily = opts.preferredBrowserFamily && activeBrowsers.includes(opts.preferredBrowserFamily)
        ? opts.preferredBrowserFamily
        : null;
      if (!allowedBrowserFamily && activeBrowsers.length >= 1) {
        allowedBrowserFamily = activeBrowsers.sort((a, b) => (familyCpu.get(b) || 0) - (familyCpu.get(a) || 0))[0];
      }

      const flagged = [];
      for (const p of nonSystem) {
        const fam = browserFamily(p.name, p.command);
        const isMain = fam ? (fam === 'firefox' ? true : this.isChromiumMainProcess(p.command)) : false;
        const allowAsBrowser = allowedBrowserFamily && fam === allowedBrowserFamily && isMain;
        const allowAsCompanion = isCompanion(p.name, p.command);
        if (allowAsBrowser || allowAsCompanion) continue;
        flagged.push({ pid: p.pid, name: p.name, cpu: p.cpu, mem: p.mem, command: p.command });
      }

      flagged.sort((a, b) => (b.cpu || 0) - (a.cpu || 0));

      return {
        ok: true,
        summary: {
          totalProcesses: all.length,
          nonSystemProcesses: nonSystem.length,
          flaggedCount: flagged.length,
          activeBrowsers,
          allowedBrowserFamily,
          multipleBrowsersActive
        },
        flagged,
        allowed: {
          browserFamily: allowedBrowserFamily,
          companionMatches: opts.allowedCompanionMatches
        }
      };
    } catch (e) {
      return { ok: false, error: String(e) };
    }
  }
}

module.exports = ExamModeService;


