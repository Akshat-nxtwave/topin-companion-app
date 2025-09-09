const si = require('systeminformation');
const path = require('path');
const os = require('os');
const { exec } = require('child_process');

class ExamModeService {
  constructor() {
    this.enableLog = true;
    // Domains used to detect screen-sharing related tabs
    this.screenSharingDomains = [
      'meet.google.com','teams.microsoft.com','zoom.us','webex.com','gotomeeting.com','discord.com','slack.com','whereby.com','jitsi.org','appear.in','skype.com','teamviewer.com'
    ];
    
    // Blacklisted processes for enhanced security detection
    this.blacklistedProcesses = [
     'remote_assistance_host'
    ];
  }

  log(message, ...args) {
    if (this.enableLog) {
      console.log(message, ...args);
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

  isBlacklistedProcess(name, command) {
    const n = String(name || '').toLowerCase();
    const c = String(command || '').toLowerCase();
    
    // Check if process name or command starts with any blacklisted process
    for (const blacklisted of this.blacklistedProcesses) {
      const blacklistedLower = blacklisted.toLowerCase();
      if (n.startsWith(blacklistedLower) || c.startsWith(blacklistedLower)) {
        return true;
      }
    }
    
    return false;
  }

  async getActiveLinuxWindowApplications() {
    if (process.platform !== 'linux') return [];
    try {
      // Require wmctrl for reliable window enumeration
      const which = await this.execCmd('command -v wmctrl || true', 800);
      if (!which.stdout || !which.stdout.trim()) return [];

      // Use both PID (-p) and WM_CLASS (-x)
      const res = await this.execCmd('wmctrl -lp -x 2>/dev/null || true', 2000);
      const lines = (res.stdout || '').split(/\r?\n/).filter(Boolean);
      if (!lines.length) return [];

      // Parse wmctrl lines: winId desktop pid host wm_class title...
      const byPid = new Map();
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 5) continue;
        // Some wmctrl builds shift columns; try robust PID extraction
        let pid = 0;
        // Common: [0]=winId [1]=desk [2]=pid [3]=host [4]=wm_class [5..]=title
        pid = Number(parts[2]) || Number(parts[3]) || 0;
        if (!pid) continue;
        const wmClass = String(parts[4] || '').toLowerCase();
        const title = parts.slice(5).join(' ').trim();
        if (!byPid.has(pid)) {
          byPid.set(pid, { pid, wmClass, titles: new Set() });
        }
        const rec = byPid.get(pid);
        if (wmClass && !rec.wmClass) rec.wmClass = wmClass;
        if (title) rec.titles.add(title);
      }

      if (byPid.size === 0) return [];

      // Join with process list to enrich with name/command
      const processesRes = await this.safe('processes', () => si.processes(), 3000);
      const list = (processesRes && processesRes.list) ? processesRes.list : [];
      const procByPid = new Map();
      for (const p of list) procByPid.set(p.pid, p);

      const result = [];
      for (const [pid, rec] of byPid) {
        const proc = procByPid.get(pid);
        const name = proc && proc.name ? String(proc.name) : '';
        const command = proc && proc.command ? String(proc.command) : '';
        result.push({
          pid,
          name,
          command,
          wmClass: rec.wmClass || '',
          titles: Array.from(rec.titles).slice(0, 5)
        });
      }

      // Sort by process name then title for stability
      result.sort((a, b) => {
        const an = String(a.name || '').toLowerCase();
        const bn = String(b.name || '').toLowerCase();
        if (an < bn) return -1; if (an > bn) return 1; return a.pid - b.pid;
      });
      return result;
    } catch {
      return [];
    }
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
      // Fallback via xprop: enumerate windows and map to _NET_WM_PID
      if (gui.size === 0) {
        const haveXprop = await this.execCmd('command -v xprop || true', 600);
        if (haveXprop.ok && haveXprop.stdout && haveXprop.stdout.trim()) {
          const root = await this.execCmd('xprop -root _NET_CLIENT_LIST 2>/dev/null || true', 1200);
          if (root.ok && root.stdout) {
            const ids = (root.stdout.match(/0x[0-9a-fA-F]+/g) || []).slice(0, 100);
            for (const id of ids) {
              const pr = await this.execCmd(`xprop -id ${id} _NET_WM_PID -notype 2>/dev/null || true`, 400);
              if (pr.ok && pr.stdout) {
                const m = pr.stdout.match(/\b(\d+)\b/);
                const pid = m ? Number(m[1]) : 0;
                if (pid) gui.add(pid);
              }
              if (gui.size >= 200) break;
            }
          }
        }
      }
      // Enrich with environment-based GUI detection for current-user processes
      const processesRes = await this.safe('processes', () => si.processes(), 2500);
      const list = (processesRes && processesRes.list) ? processesRes.list : [];
      const current = (os.userInfo && os.userInfo().username) ? String(os.userInfo().username) : '';
      for (const p of list) {
        const sameUser = current && String(p.user || '') === current;
        if (!sameUser) continue;
        if (this.hasGuiEnvForPid(p.pid)) gui.add(p.pid);
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
      // Proper parsing to extract ppid and tty_nr even when comm contains spaces
      const lp = stat.indexOf('(');
      const rp = stat.lastIndexOf(')');
      let after = '';
      if (lp !== -1 && rp !== -1 && rp > lp) {
        after = stat.slice(rp + 1).trim();
      } else {
        after = stat.trim();
      }
      const fields = after.split(/\s+/);
      // fields: state ppid pgrp session tty_nr ...
      const ppid = Number(fields[1] || 0);
      const ttyNr = Number(fields[4] || 0);
      return { ppid, ttyNr };
    } catch { return null; }
  }

  readProcCmdline(pid) {
    try {
      const fs = require('fs');
      const buf = fs.readFileSync(`/proc/${pid}/cmdline`);
      const raw = buf.toString('utf8');
      return raw.split('\0').filter(Boolean).join(' ').trim();
    } catch { return ''; }
  }

  readProcEnviron(pid) {
    try {
      const fs = require('fs');
      const buf = fs.readFileSync(`/proc/${pid}/environ`);
      const raw = buf.toString('utf8');
      const env = {};
      for (const kv of raw.split('\0')) {
        if (!kv) continue;
        const idx = kv.indexOf('=');
        if (idx > 0) {
          const key = kv.slice(0, idx);
          const val = kv.slice(idx + 1);
          env[key] = val;
        }
      }
      return env;
    } catch { return null; }
  }

  hasGuiEnvForPid(pid) {
    if (process.platform !== 'linux') return false;
    try {
      const env = this.readProcEnviron(pid);
      if (!env) return false;
      const display = String(env.DISPLAY || '').trim();
      const waylandDisplay = String(env.WAYLAND_DISPLAY || '').trim();
      const sessionType = String(env.XDG_SESSION_TYPE || '').trim().toLowerCase();
      const desktopSession = String(env.DESKTOP_SESSION || env.GDMSESSION || '').trim();
      const kde = String(env.KDE_FULL_SESSION || '').trim();
      const gnome = String(env.GNOME_DESKTOP_SESSION_ID || '').trim();
      if (display) return true; // X11
      if (waylandDisplay) return true; // Wayland
      if (sessionType === 'wayland' || sessionType === 'x11') return true;
      if (desktopSession || kde || gnome) return true; // inside a desktop session
      return false;
    } catch { return false; }
  }

  readProcStatusUid(pid) {
    try {
      const fs = require('fs');
      const data = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
      const lines = data.split(/\r?\n/);
      for (const line of lines) {
        if (line.startsWith('Uid:')) {
          const parts = line.split(/\s+/).filter(Boolean);
          const real = Number(parts[1] || 0);
          return Number.isFinite(real) ? real : null;
        }
      }
      return null;
    } catch { return null; }
  }

  readProcExePath(pid) {
    try {
      const fs = require('fs');
      const exe = fs.readlinkSync(`/proc/${pid}/exe`);
      return String(exe || '');
    } catch { return ''; }
  }

  getExecutablePathForPidLinux(p) {
    try {
      const firstToken = String(p.command || '').split(/\s+/)[0] || '';
      if (firstToken.startsWith('/')) return firstToken;
      const exe = this.readProcExePath(p.pid);
      return exe || firstToken || '';
    } catch { return ''; }
  }

  getPathBase(p) {
    try { return path.basename(String(p || '')); } catch { return String(p || ''); }
  }

  isChromiumHelperProcess(command) {
    const c = String(command || '').toLowerCase();
    if (!/--type=/.test(c)) return false;
    return !/--type=browser/.test(c);
  }

  isCrashpadProcess(name, command) {
    const n = String(name || '').toLowerCase();
    const c = String(command || '').toLowerCase();
    return n.includes('crashpad') || c.includes('crashpad_handler') || c.includes('crashpad');
  }

  isLinuxDevToolProcess(name, command, execPath) {
    const n = String(name || '').toLowerCase();
    const c = String(command || '').toLowerCase();
    const e = String(execPath || '').toLowerCase();
    const base = this.getPathBase(e || this.getPathBase(String(c).split(/\s+/)[0] || ''));
    const deny = [
      'node','nodejs','npm','npx','pnpm','yarn','tsserver','pyright-langserver','gopls','java','jdtls','watchman','webpack','vite','parcel','eslint','prettier','bash','sh','zsh','fish','tmux'
    ];
    if (deny.includes(n) || deny.includes(base)) return true;
    if (/\b(tsserver|node|npm|npx|pnpm|yarn|watchman|webpack|vite|parcel|eslint|prettier)\b/.test(c)) return true;
    // Common language servers/tooling
    if (/langserver|language-server|lsp-/.test(c)) return true;
    return false;
  }

  async isLikelyUserStartedLinux(p) {
    const u = String(p.user || '').trim();
    const current = (os.userInfo && os.userInfo().username) ? String(os.userInfo().username) : '';
    let sameUser = (!!u && !!current && u === current);
    if (!sameUser) {
      const currUid = (process.getuid && typeof process.getuid === 'function') ? process.getuid() : null;
      const pidUid = this.readProcStatusUid(p.pid);
      if (currUid !== null && pidUid !== null && currUid === pidUid) sameUser = true;
    }
    if (!sameUser) return false;
    const stat = this.readProcStat(p.pid);
    const hasTty = !!(stat && stat.ttyNr && stat.ttyNr !== 0);
    const parentNotSystemd = !!(stat && stat.ppid && stat.ppid !== 1);
    const cg = await this.readProcCgroup(p.pid);
    const inAppScope = !!(cg && cg.inAppScope);
    const inUserSlice = !!(cg && cg.userSlice);
    const hasGuiEnv = this.hasGuiEnvForPid(p.pid);
    // Consider user-started if it has a TTY, or was not spawned by systemd (PPID != 1),
    // or lives in a user app scope/slice (GNOME/KDE app launch), or GUI env detected.
    return hasTty || parentNotSystemd || inAppScope || inUserSlice || hasGuiEnv;
  }

  async collectWindowsMainAppPids() {
    // Use PowerShell to enumerate processes with visible main windows in current session
    // Primary signal: visible window title in current session; plus known name + handle for Edge/Copilot
    try {
      const ps = [
        "$cs=(Get-Process -Id $PID).SessionId",
        // Title-visible windows in current session
        "$title=Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $cs -and $_.MainWindowTitle -ne '' } | Select-Object -ExpandProperty Id",
        // Known user apps (Edge/Copilot) when they have a window handle even if title is empty
        "$known=Get-Process -Name msedge,msedgewebview2,microsoftedge,Copilot,CopilotApp -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $cs -and $_.MainWindowHandle -ne 0 } | Select-Object -ExpandProperty Id",
        "$title + $known"
      ].join('; ');
      const cmd = `powershell -NoProfile -ExecutionPolicy Bypass -Command "${ps.replace(/"/g, '\\"')}"`;
      const res = await this.execCmd(cmd, 6000);
      const set = new Set();
      if (res.ok && res.stdout) {
        for (const line of res.stdout.split(/\r?\n/)) {
          const pid = Number(String(line).trim());
          if (pid) set.add(pid);
        }
      }
      // Targeted fallback for Edge if nothing found
      if (set.size === 0) {
        const edgePs = "Get-Process -Name msedge,msedgewebview2 -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -ExpandProperty Id";
        const edgeCmd = `powershell -NoProfile -ExecutionPolicy Bypass -Command "${edgePs.replace(/"/g, '\\"')}"`;
        const edgeRes = await this.execCmd(edgeCmd, 4000);
        if (edgeRes.ok && edgeRes.stdout) {
          for (const line of edgeRes.stdout.split(/\r?\n/)) {
            const pid = Number(String(line).trim());
            if (pid) set.add(pid);
          }
        }
      }
      return set;
    } catch {
      return new Set();
    }
  }

  expandWindowsUserAppPidsFromProcesses(list) {
    try {
      const set = new Set();
      for (const p of Array.isArray(list) ? list : []) {
        const n = String(p.name || '').toLowerCase();
        const c = String(p.command || '').toLowerCase();
        const pathLower = String(p.path || '').toLowerCase();
        // Edge main browser process (Chromium main process has no --type or --type=browser)
        if ((n.includes('msedge') || n === 'edge' || /\\msedge\.exe$/.test(pathLower)) && this.isChromiumMainProcess(c)) {
          set.add(p.pid);
          continue;
        }
        // Copilot app hosted via SystemApps or WebView2; keep it precise to avoid false positives
        const isCopilotName = /\bcopilot\b/.test(n) || /\bcopilot\b/.test(c);
        const isCopilotPath = pathLower.includes('windows\\systemapps') && pathLower.includes('copilot');
        const isWebView2Copilot = (n.includes('msedgewebview2') || /msedgewebview2\.exe$/.test(pathLower)) && /\bcopilot\b/.test(c);
        if (isCopilotName || isCopilotPath || isWebView2Copilot) {
          set.add(p.pid);
          continue;
        }
        // Electron-based desktop apps (safe heuristic): executable not under Windows dir AND
        // command/path indicates app resources (app.asar or app-<version>) and is a top-level process
        const underWindows = pathLower.includes('\\windows\\');
        const looksElectron = /electron\.exe$/.test(pathLower) || c.includes('electron') || pathLower.includes('resources\\app.asar') || /\\app-\d/i.test(pathLower);
        const isHelper = /--type=/.test(c) || /renderer|gpu|utility/.test(c);
        if (!underWindows && looksElectron && !isHelper) {
          set.add(p.pid);
          continue;
        }
      }
      return set;
    } catch {
      return new Set();
    }
  }

  async collectWindowsVisiblePidsViaTasklist() {
    // Fallback using tasklist verbose output to discover visible windows (Window Title column)
    try {
      const res = await this.execCmd('tasklist /v /fo csv', 3000);
      // Allow a slightly higher timeout to improve detection when the system is under load
      if (!res.ok || !res.stdout) {
        const retry = await this.execCmd('tasklist /v /fo csv', 5500);
        if (retry.ok && retry.stdout) {
          res.ok = true; res.stdout = retry.stdout; res.stderr = retry.stderr;
        }
      }
      const set = new Set();
      if (!res.ok || !res.stdout) return set;
      const lines = res.stdout.split(/\r?\n/).filter(Boolean);
      // CSV columns: "Image Name","PID",...,"Window Title"
      // Skip header
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        const cols = [];
        let curr = '';
        let inQ = false;
        for (let j = 0; j < line.length; j++) {
          const ch = line[j];
          if (ch === '"') { inQ = !inQ; continue; }
          if (ch === ',' && !inQ) { cols.push(curr); curr = ''; continue; }
          curr += ch;
        }
        cols.push(curr);
        if (cols.length < 9) continue;
        const image = String(cols[0] || '').toLowerCase();
        const pid = Number(String(cols[1] || '').trim()) || 0;
        const title = String(cols[cols.length - 1] || '').trim();
        if (!pid) continue;
        // Visible window: non-empty and not N/A
        const hasWindow = title && title.toLowerCase() !== 'n/a';
        if (!hasWindow) continue;
        // Exclude common system images to reduce false positives
        const sys = ['svchost.exe','winlogon.exe','dwm.exe','runtimebroker.exe','searchui.exe','shellexperiencehost.exe','applicationframehost.exe'];
        if (sys.includes(image)) continue;
        set.add(pid);
      }
      return set;
    } catch {
      return new Set();
    }
  }

  async getActiveWindowsUIProcessesPS() {
    try {
      const ps = "$systemUIProcesses = @('explorer','ApplicationFrameHost','SystemSettings','Taskmgr','ShellExperienceHost','SearchApp','SearchUI','StartMenuExperienceHost','RuntimeBroker','TextInputHost'); Get-Process | Where-Object { $_.MainWindowTitle -ne '' -and $systemUIProcesses -notcontains $_.Name } | Select-Object -ExpandProperty Id";
      const cmd = `powershell -NoProfile -ExecutionPolicy Bypass -Command "${ps.replace(/"/g, '\\"')}"`;
      const res = await this.execCmd(cmd, 5000);
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
      const processesRes = await this.safe('processes', () => si.processes(), process.platform === 'win32' ? 10000 : 6000);
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

      // Linux: application detection is handled by SecurityService.js. Do not detect here.
      if (isLinux) {
        return {
          ok: true,
          summary: {
            totalProcesses: list.length,
            nonSystemProcesses: 0,
            flaggedCount: 0,
            activeBrowsers: [],
            allowedBrowserFamily: null,
            multipleBrowsersActive: false
          },
          flagged: [],
          allowed: {
            browserFamily: null,
            companionMatches: opts.allowedCompanionMatches
          },
          linuxActiveWindows: []
        };
      }
      let guiPidSet = new Set();
      if (isLinux) {
        guiPidSet = await this.collectLinuxGuiPids();
      }
      let winMainPidSet = new Set();
      if (isWindows) {
        // Use strict PowerShell-based active UI process filter
        winMainPidSet = await this.getActiveWindowsUIProcessesPS();
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
        // Exclude WebView2 host explicitly to avoid false positives
        if (n.includes('msedgewebview2') || c.includes('msedgewebview2')) return false;
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
        // Windows: Only consider processes with visible main window in current session
        // Apply gating only when we have a non-empty set; otherwise avoid over-filtering
        if (isWindows) {
          const gateOk = winMainPidSet.size >= 2; // small sets are unreliable; skip gating when too small
          if (gateOk && !winMainPidSet.has(p.pid)) continue;
        }
        // Windows-specific: exclude shell host that causes false positives
        if (isWindows) {
          const exeBase = (() => { const first = String(c || '').split(/\s+/)[0] || ''; return path.basename(first).toLowerCase(); })();
          if (n === 'applicationframehost.exe' || n === 'applicationframehost' || exeBase === 'applicationframehost.exe') continue;
        }
        // macOS: Only consider application processes reported as active (not background-only)
        if (isMac && macActiveNames.size) {
          const pname = String(p.name || '').toLowerCase();
          if (!macActiveNames.has(pname)) continue;
        }
        if (this.isSystemHelper(n, c)) continue;
        if (this.isBackgroundService(n, c)) continue;
        if (isKernelThreadLinux(n)) continue;
        if (isSystemName(n)) continue;
        
        if (isLinux) {
          // Require presence + session + acceptable location
          const likelyUser = await this.isLikelyUserStartedLinux(p);
          if (!likelyUser) continue;
          const isGui = guiPidSet.has(p.pid) || this.hasGuiEnvForPid(p.pid);
          const hasTty = (() => { const st = this.readProcStat(p.pid); return !!(st && st.ttyNr && st.ttyNr !== 0); })();
          if (!(isGui || hasTty)) continue;
          const execPath = this.getExecutablePathForPidLinux(p).toLowerCase();
          const cg = await this.readProcCgroup(p.pid);
          const isUserAppPath = execPath.includes('/opt/') || execPath.includes('/home/') || execPath.includes('/snap/') || execPath.includes('appimage') || execPath.includes('/.var/app/') || execPath.includes('/usr/bin/');
          const isExecOk = isUserAppPath || (cg && (cg.isFlatpak || cg.isSnap));
          if (!isExecOk) continue;
          // Exclude developer tools and terminals/shells
          if (this.isLinuxDevToolProcess(p.name, p.command, execPath)) continue;
          // Exclude Chromium/Electron helpers and crashpad
          if (this.isChromiumHelperProcess(p.command)) continue;
          if (this.isCrashpadProcess(p.name, p.command)) continue;
          nonSystem.push({ ...p, command: execPath || p.command });
          continue;
        }

        // Non-Linux platforms keep prior heuristics
        const fam = browserFamily(p.name, p.command);
        const isBrowserMain = fam ? (fam === 'firefox' ? true : this.isChromiumMainProcess(p.command)) : false;
        const isGui = true;
        const isUserAppPath = c.includes('/opt/') || c.includes('/home/') || c.includes('/snap/') || c.includes('appimage');
        if (fam || isCompanion(n, c) || isGui || isUserAppPath) {
          nonSystem.push(p);
          continue;
        }
        if (isSystemPath(c)) continue;
        nonSystem.push(p);
      }

      const familyCpu = new Map();
      for (const p of nonSystem) {
        const fam = browserFamily(p.name, p.command);
        if (!fam) continue;
        // Only count main browser processes to avoid double-counting helpers
        const isMainForCpu = fam ? (
          fam === 'firefox' ? true : (
            fam === 'edge' ? (this.isChromiumMainProcess(p.command) || (!p.command && /msedge/i.test(String(p.name || '')))) : this.isChromiumMainProcess(p.command)
          )
        ) : false;
        if (!isMainForCpu) continue;
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
      const blacklistedProcesses = [];
      
      // First pass: collect blacklisted processes from all processes (active + background)
      for (const p of all) {
        if (this.isBlacklistedProcess(p.name, p.command)) {
          blacklistedProcesses.push({ 
            pid: p.pid, 
            name: p.name, 
            cpu: p.cpu, 
            mem: p.mem, 
            command: p.command,
            isBlacklisted: true 
          });
        }
      }
      
      // Second pass: flag non-system processes (existing logic)
      for (const p of nonSystem) {
        const fam = browserFamily(p.name, p.command);
        const isMain = fam ? (
          fam === 'firefox' ? true : (
            fam === 'edge' ? (this.isChromiumMainProcess(p.command) || (!p.command && /msedge/i.test(String(p.name || '')))) : this.isChromiumMainProcess(p.command)
          )
        ) : false;
        const allowAsBrowser = allowedBrowserFamily && fam === allowedBrowserFamily && isMain;
        const allowAsCompanion = isCompanion(p.name, p.command);
        const whiteListedProcesses = ['Cursor.exe', 'Cursor', 'cursor.exe', 'cursor']
        const isWhiteListedProcess = whiteListedProcesses.includes(p.name);
        if (allowAsBrowser || allowAsCompanion || isWhiteListedProcess) continue;
        flagged.push({ pid: p.pid, name: p.name, cpu: p.cpu, mem: p.mem, command: p.command });
      }
      
      // Add blacklisted processes to flagged list (they should always be flagged)
      for (const blacklisted of blacklistedProcesses) {
        // Avoid duplicates if blacklisted process is already in flagged
        const alreadyFlagged = flagged.some(f => f.pid === blacklisted.pid);
        if (!alreadyFlagged) {
          flagged.push(blacklisted);
        }
      }

      flagged.sort((a, b) => (b.cpu || 0) - (a.cpu || 0));

      // Linux: include active window applications (by wmctrl) for visibility
      let linuxActiveWindows = [];
      if (isLinux) {
        linuxActiveWindows = await this.getActiveLinuxWindowApplications();
      }

      return {
        ok: true,
        summary: {
          totalProcesses: all.length,
          nonSystemProcesses: nonSystem.length,
          flaggedCount: flagged.length,
          blacklistedCount: blacklistedProcesses.length,
          activeBrowsers,
          allowedBrowserFamily,
          multipleBrowsersActive
        },
        flagged,
        blacklistedProcesses,
        allowed: {
          browserFamily: allowedBrowserFamily,
          companionMatches: opts.allowedCompanionMatches
        },
        linuxActiveWindows
      };
    } catch (e) {
      return { ok: false, error: String(e) };
    }
  }

  async getAllTabsForBrowser(browserName) {
    const allTabs = [];
    const keywords = ['meet','zoom','teams','webex','discord','present','is presenting','sharing','share this tab','screen share','screenshare','sharing screen','sharing your screen','you are sharing','screen sharing','screen-sharing','jitsi','whereby','appear.in','hang','call','video call','conference'];
    const domains = this.screenSharingDomains || [];
    const matches = (text) => {
      const t = String(text || '').toLowerCase();
      return domains.some(d => t.includes(d)) || keywords.some(k => t.includes(k));
    };

    try {
      if (process.platform === 'darwin') {
        if (browserName.includes('firefox')) {
          try {
            const script = `
              tell application "Firefox"
                set tabList to {}
                repeat with w from 1 to count of windows
                  repeat with t from 1 to count of tabs of window w
                    set tabURL to URL of tab t of window w
                    set tabName to name of tab t of window w
                    set end of tabList to {tabURL, tabName, w, t}
                  end repeat
                end repeat
                return tabList
              end tell
            `;
            const { stdout } = await this.execCmd(`osascript -e '${script}'`, 3000);
            if (stdout && stdout.trim()) {
              const tabMatches = stdout.trim().match(/\{([^}]+)\}/g) || [];
              for (const match of tabMatches) {
                const parts = match.slice(1, -1).split(', ');
                if (parts.length >= 2) {
                  const url = parts[0];
                  const title = parts[1];
                  if (matches(url) || matches(title)) {
                    allTabs.push({ url, title, windowIndex: parts[2] || 1, tabIndex: parts[3] || 1, isSharing: true });
                  }
                }
              }
            }
          } catch {}
        }
        if (browserName.includes('safari')) {
          try {
            const script = `
              tell application "Safari"
                set tabList to {}
                repeat with w from 1 to count of windows
                  repeat with t from 1 to count of tabs of window w
                    set tabURL to URL of tab t of window w
                    set tabName to name of tab t of window w
                    set end of tabList to tabURL & "|||" & tabName & "|||" & w & "|||" & t
                  end repeat
                end repeat
                return tabList
              end tell
            `;
            const { stdout } = await this.execCmd(`osascript -e '${script}'`, 3000);
            if (stdout && stdout.trim()) {
              const lines = stdout.trim().split('\n');
              for (const line of lines) {
                if (line.includes('|||')) {
                  const [url, title, windowIndex, tabIndex] = line.split('|||');
                  if (matches(url) || matches(title)) {
                    allTabs.push({ url, title, windowIndex: Number(windowIndex) || 1, tabIndex: Number(tabIndex) || 1, isSharing: true });
                  }
                }
              }
            }
          } catch {}
        }
        if (browserName.includes('chrome') || browserName.includes('chromium') || browserName.includes('edge') || browserName.includes('brave') || browserName.includes('opera')) {
          try {
            const appName = browserName.includes('edge') ? 'Microsoft Edge' : browserName.includes('brave') ? 'Brave Browser' : browserName.includes('opera') ? 'Opera' : 'Google Chrome';
            const script = `
              tell application "${appName}"
                set tabList to {}
                repeat with w from 1 to count of windows
                  repeat with t from 1 to count of tabs of window w
                    set tabURL to URL of tab t of window w
                    set tabTitle to title of tab t of window w
                    set end of tabList to tabURL & "|||" & tabTitle & "|||" & w & "|||" & t
                  end repeat
                end repeat
                return tabList
              end tell
            `;
            const { stdout } = await this.execCmd(`osascript -e '${script}'`, 3000);
            if (stdout && stdout.trim()) {
              const lines = stdout.trim().split('\n');
              for (const line of lines) {
                if (line.includes('|||')) {
                  const [url, title, windowIndex, tabIndex] = line.split('|||');
                  if (matches(url) || matches(title)) {
                    allTabs.push({ url, title, windowIndex: Number(windowIndex) || 1, tabIndex: Number(tabIndex) || 1, isSharing: true });
                  }
                }
              }
            }
          } catch {}
        }
      } else if (process.platform === 'win32') {
        // Firefox
        if (browserName.includes('firefox')) {
          try {
            const cmd = `powershell -NoProfile -Command "(Get-Process -Name firefox -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -ne '' -and $_.MainWindowHandle -ne 0 } | ForEach-Object { $_.MainWindowTitle + '|||' + $_.Id })"`;
            const { stdout } = await this.execCmd(cmd, 3000);
            if (stdout && stdout.trim()) {
              const lines = stdout.trim().split('\n');
              for (const line of lines) {
                if (line.includes('|||')) {
                  const [title, pid] = line.split('|||');
                  if (matches(title)) allTabs.push({ title, pid: Number(pid) || 0, isSharing: true });
                }
              }
            }
          } catch {}
        }
        // Chrome/Chromium/Edge/Brave/Opera (by process name)
        const winMap = [
          { key: 'chrome', pn: 'chrome' },
          { key: 'chromium', pn: 'chrome' },
          { key: 'edge', pn: 'msedge' },
          { key: 'brave', pn: 'brave' },
          { key: 'opera', pn: 'opera' }
        ];
        for (const m of winMap) {
          if (!browserName.includes(m.key)) continue;
          try {
            const cmd = `powershell -NoProfile -Command "(Get-Process -Name ${m.pn} -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -ne '' -and $_.MainWindowHandle -ne 0 } | ForEach-Object { $_.MainWindowTitle + '|||' + $_.Id })"`;
            const { stdout } = await this.execCmd(cmd, 3500);
            if (stdout && stdout.trim()) {
              const lines = stdout.trim().split('\n');
              for (const line of lines) {
                if (line.includes('|||')) {
                  const [title, pid] = line.split('|||');
                  if (matches(title)) allTabs.push({ title, pid: Number(pid) || 0, isSharing: true });
                }
              }
            }
          } catch {}
        }
      } else {
        try {
          const { stdout } = await this.execCmd('wmctrl -lx 2>/dev/null || true', 2000);
          const lines = (stdout || '').split(/\r?\n/);
          for (const line of lines) {
            if (!line) continue;
            const lower = line.toLowerCase();
            if (browserName.includes('firefox') && lower.includes('firefox')) {
              const parts = line.trim().split(/\s+/);
              const title = parts.slice(4).join(' ');
              if (matches(title)) allTabs.push({ title, isSharing: true });
            } else if ((browserName.includes('chrome') || browserName.includes('chromium')) && (lower.includes('chrome') || lower.includes('chromium'))) {
              const parts = line.trim().split(/\s+/);
              const title = parts.slice(4).join(' ');
              if (matches(title)) allTabs.push({ title, isSharing: true });
            }
          }
        } catch {}
      }
    } catch {}
    return allTabs;
  }

  async resolveSharingTabInfoForBrowser(browserName) {
    const keywords = ['meet','zoom','teams','webex','discord','present','is presenting','sharing','share this tab','screen share','screenshare','sharing screen','sharing your screen','you are sharing','screen sharing','screen-sharing','jitsi','whereby','appear.in','hang','call','video call','conference'];
    const domains = this.screenSharingDomains || [];
    const matches = (text) => {
      const t = String(text || '').toLowerCase();
      return domains.some(d => t.includes(d)) || keywords.some(k => t.includes(k));
    };
    try {
      if (process.platform === 'darwin') {
        const map = [
          { key: 'chrome', app: 'Google Chrome' },
          { key: 'edge', app: 'Microsoft Edge' },
          { key: 'brave', app: 'Brave Browser' },
          { key: 'opera', app: 'Opera' },
        ];
        for (const b of map) {
          if (!browserName.includes(b.key)) continue;
          try {
            const script = `tell application "${b.app}" to set _t to {URL, title} of active tab of front window\nreturn (item 1 of _t) & '|||' & (item 2 of _t)`;
            const { stdout } = await this.execCmd(`osascript -e '${script}'`, 2000);
            const out = (stdout || '').trim();
            if (out && out.includes('|||')) {
              const [u, t] = out.split('|||');
              if (matches(u) || matches(t)) return { url: u, title: t };
            }
          } catch {}
        }
        if (browserName.includes('safari')) {
          try {
            const script = 'tell application "Safari" to set _t to {URL, name} of current tab of front window\nreturn (item 1 of _t) & "|||" & (item 2 of _t)';
            const { stdout } = await this.execCmd(`osascript -e '${script}'`, 2000);
            const out = (stdout || '').trim();
            if (out && out.includes('|||')) {
              const [u, t] = out.split('|||');
              if (matches(u) || matches(t)) return { url: u, title: t };
            }
          } catch {}
        }
        if (browserName.includes('firefox')) {
          try {
            const script = 'tell application "Firefox" to set _t to {URL of active tab of front window, name of active tab of front window}\nreturn (item 1 of _t) & "|||" & (item 2 of _t)';
            const { stdout } = await this.execCmd(`osascript -e '${script}'`, 2000);
            const out = (stdout || '').trim();
            if (out && out.includes('|||')) {
              const [u, t] = out.split('|||');
              if (matches(u) || matches(t)) return { url: u, title: t };
            }
          } catch {}
        }
        return null;
      } else if (process.platform === 'win32') {
        const procNames = [];
        if (browserName.includes('chrome')) procNames.push('chrome');
        if (browserName.includes('edge')) procNames.push('msedge');
        if (browserName.includes('firefox')) procNames.push('firefox');
        if (browserName.includes('brave')) procNames.push('brave');
        if (browserName.includes('opera')) procNames.push('opera');
        for (const pn of procNames) {
          try {
            const cmd = `powershell -NoProfile -Command "(Get-Process -Name ${pn} -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -ne '' -and $_.MainWindowHandle -ne 0 } | Sort-Object CPU -Descending | Select-Object -First 1 -ExpandProperty MainWindowTitle)"`;
            const { stdout } = await this.execCmd(cmd, 2000);
            const title = (stdout || '').trim();
            if (title && matches(title)) return { title };
          } catch {}
        }
        return null;
      } else {
        try {
          const { stdout } = await this.execCmd('wmctrl -lx 2>/dev/null || true', 2000);
          const lines = (stdout || '').split(/\r?\n/);
          for (const line of lines) {
            if (!line) continue;
            const lower = line.toLowerCase();
            if (!(lower.includes('chrome') || lower.includes('chromium') || lower.includes('firefox') || lower.includes('edge') || lower.includes('brave') || lower.includes('opera'))) continue;
            const parts = line.trim().split(/\s+/);
            const title = parts.slice(4).join(' ');
            if (matches(title)) return { title };
          }
        } catch {}
        return null;
      }
    } catch { return null; }
  }

  async getActiveScreenSharingTabs() {
    const result = [];
    try {
      // Build families from running processes to limit checks
      const processesRes = await this.safe('processes', () => si.processes(), process.platform === 'win32' ? 8000 : 4000);
      const list = (processesRes && processesRes.list) ? processesRes.list : [];
      const families = new Set();
      for (const p of (list || [])) {
        const n = String(p.name || '').toLowerCase();
        if (/chrome|chromium|firefox|edge|msedge|brave|opera|safari/.test(n)) {
          if (n.includes('chromium')) families.add('chromium');
          else if (n.includes('edge') || n.includes('msedge')) families.add('edge');
          else if (n.includes('brave')) families.add('brave');
          else if (n.includes('opera')) families.add('opera');
          else if (n.includes('safari')) families.add('safari');
          else if (n.includes('firefox')) families.add('firefox');
          else families.add('chrome');
        }
      }
      for (const fam of families) {
        const tabs = await this.getAllTabsForBrowser(fam);
        if (Array.isArray(tabs) && tabs.length) {
          result.push({ browser: fam, tabs });
          continue;
        }
        const info = await this.resolveSharingTabInfoForBrowser(fam);
        if (info && (info.title || info.url)) {
          result.push({ browser: fam, tabs: [info] });
        }
      }
    } catch {}
    return result;
  }

  async checkBrowserAccess(browserKey) {
    try {
      if (process.platform === 'darwin') {
        const appMap = new Map([
          ['chrome', 'Google Chrome'],
          ['edge', 'Microsoft Edge'],
          ['brave', 'Brave Browser'],
          ['opera', 'Opera'],
          ['safari', 'Safari'],
          ['firefox', 'Firefox']
        ]);
        const app = appMap.get(browserKey) || null;
        if (!app) return false;
        // Attempt to read active tab title/URL to infer permission
        const script = browserKey === 'safari'
          ? 'tell application "Safari" to set _t to {URL, name} of current tab of front window\nreturn (item 1 of _t) & "||" & (item 2 of _t)'
          : `tell application "${app}" to set _t to {URL, title} of active tab of front window\nreturn (item 1 of _t) & "||" & (item 2 of _t)`;
        const res = await this.execCmd(`osascript -e '${script}'`, 2000);
        return Boolean(res.ok && res.stdout && res.stdout.trim());
      } else if (process.platform === 'win32') {
        // Consider access granted if we can read a non-empty MainWindowTitle for the browser
        const pn = browserKey === 'edge' ? 'msedge' : browserKey;
        const cmd = `powershell -NoProfile -Command "(Get-Process -Name ${pn} -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -ne '' -and $_.MainWindowHandle -ne 0 } | Select-Object -First 1 -ExpandProperty MainWindowTitle)"`;
        const { stdout } = await this.execCmd(cmd, 2500);
        return Boolean((stdout || '').trim());
      } else {
        // Linux: require wmctrl present and a browser window to be visible
        const tools = await this.execCmd('command -v wmctrl || true', 1000);
        if (!tools.stdout || !tools.stdout.trim()) return false;
        const { stdout } = await this.execCmd('wmctrl -lx 2>/dev/null || true', 2000);
        if (!stdout) return false;
        const lower = stdout.toLowerCase();
        if (browserKey === 'edge') return lower.includes('edge') || lower.includes('microsoft-edge');
        return lower.includes(browserKey);
      }
    } catch { return false; }
  }

  async runBrowserTabPermissionFlow() {
    const outcome = { platform: process.platform, browsers: [], flagged: [], sharing: [] };
    try {
      // Identify running browsers
      const processesRes = await this.safe('processes', () => si.processes(), process.platform === 'win32' ? 8000 : 4000);
      const list = (processesRes && processesRes.list) ? processesRes.list : [];
      const families = new Set();
      for (const p of (list || [])) {
        const n = String(p.name || '').toLowerCase();
        if (/chrome|chromium|firefox|edge|msedge|brave|opera|safari/.test(n)) {
          if (n.includes('chromium')) families.add('chromium');
          else if (n.includes('edge') || n.includes('msedge')) families.add('edge');
          else if (n.includes('brave')) families.add('brave');
          else if (n.includes('opera')) families.add('opera');
          else if (n.includes('safari')) families.add('safari');
          else if (n.includes('firefox')) families.add('firefox');
          else families.add('chrome');
        }
      }
      // Evaluate permission per browser
      for (const browser of families) {
        const granted = await this.checkBrowserAccess(browser);
        outcome.browsers.push({ browser, granted });
        if (!granted) {
          // Flag denied browser as malicious per requirement
          outcome.flagged.push({ type: 'malicious_browser_permission_denied', severity: 'high', browser });
          continue;
        }
        // Access granted → collect tabs and mark sharing
        const tabs = await this.getAllTabsForBrowser(browser);
        const info = tabs && tabs.length ? tabs : [];
        const sharingTabs = (info || []).filter(t => (t.isSharing === true) || (t.title && typeof t.title === 'string'));
        outcome.sharing.push({ browser, tabs: info, tabCount: info.length, sharingCount: sharingTabs.length });
      }
    } catch {}
    return outcome;
  }
}

module.exports = ExamModeService;


