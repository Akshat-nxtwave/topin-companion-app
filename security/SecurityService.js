const { EventEmitter } = require('events');
const si = require('systeminformation');
const os = require('os');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

class SecurityService extends EventEmitter {
  constructor() {
    super();
    this.isMonitoring = false;
    this.monitoringInterval = null;
    this.securityLog = [];
    this.knownThreats = new Map();
    this.networkBaseline = null;

    this.checkInterval = 20000;

    this.remoteControlApps = [
      'teamviewer','tv_w32','tv_x64',
      'anydesk','anydesk.exe',
      'chrome_remote','remotedesktop','chrome_remote_desktop',
      'vnc','vncserver','vncviewer','realvnc','tightvnc','ultravnc','winvnc','vnc4server','x11vnc',
      'mstsc','rdp','remote desktop','terminal services','rdpclip','rdpinput','rdpsnd','rdpdr',
      'logmein','gotomypc','pchelper','remotepc','splashtop','dameware','radmin','ammyy','screenconnect','bomgar',
      'remoteutilities','supremo','showmypc','chrome.exe --remote-debugging',
      'vmware','virtualbox','vbox','qemu','kvm','hyperv',
      'obs','camtasia','bandicam','fraps','screencast',
      'zoom','skype','discord','slack','teams','webex','gotomeeting',
      'chrome --remote-debugging','firefox --marionette','edge --remote-debugging'
    ];

    this.backgroundServices = [
      'teamviewerd','tv_bin/teamviewerd',
      'ad_service',
      'vncserver-x11-core',
      'sshd',
      'rdp-server',
      'chrome --type=gpu-process','chrome --type=utility'
    ];

    this.screenSharingDomains = [
      'meet.google.com','teams.microsoft.com','zoom.us','webex.com','gotomeeting.com','discord.com','slack.com','whereby.com','jitsi.org','appear.in','skype.com','teamviewer.com'
    ];

    this.suspiciousProcesses = [
      'calculator','calc','gnome-calculator','kcalc','galculator','qalculate','mate-calc','xcalc','notepad','wordpad','gedit','kate','sublime','vscode','atom','brackets','intellij','eclipse',
      'pycharm','webstorm','visual studio','dev-cpp','codeblocks','android studio','xcode','matlab','mathematica','maple',
      'wolfram','octave','rstudio','spyder','anaconda'
    ];

    this.suspiciousPorts = [5900,5901,5902,5903,5904,3389,22,23,5938,7070,4899,5500,6129];
  }

  async safe(checkName, fn, timeoutMs = 3000) {
    try {
      const result = await Promise.race([
        fn(),
        new Promise((_, reject) => setTimeout(() => reject(new Error(`${checkName} timeout`)), timeoutMs))
      ]);
    return result || [];
    } catch (e) {
      return [];
    }
  }

  isBackgroundService(processName, command) {
    const name = (processName || '').toLowerCase();
    const cmd = (command || '').toLowerCase();
    for (const svc of this.backgroundServices) {
      const s = svc.toLowerCase();
      if (name.includes(s) || cmd.includes(s)) return true;
    }
    if ((name.endsWith('d') && (name.includes('teamviewer') || name.includes('anydesk'))) ||
        cmd.includes('--service') || cmd.includes('--daemon') || cmd.includes('-d ') ||
        (cmd.includes('chrome') && (cmd.includes('--type=') && !cmd.includes('--type=renderer')))) {
      return true;
    }
    return false;
  }

  isInstallerContext(command) {
    const cmd = (command || '').toLowerCase();
    if (/\.(deb|rpm|pkg|msi|dmg)(\s|$)/i.test(cmd)) return true;
    // Consider installer context only when the executable itself is an installer tool
    const firstToken = (cmd.split(/\s+/)[0] || '');
    const exeBase = path.basename(firstToken);
    const installerTools = [ 'apt', 'apt-get', 'dpkg', 'rpm', 'dnf', 'pacman', 'brew', 'msiexec', 'winget', 'choco' ];
    return installerTools.includes(exeBase);
  }

  isProcessActive(p) {
    const state = String(p.state || '').toLowerCase();
    const cpu = Number(p.pcpu) || 0;
    const mem = Number(p.pmem) || 0;
    return cpu >= 0.2 || mem >= 0.5 || state === 'running' || state === 'r' || state === '';
  }

  isActiveUserApplication(processName, command) {
    const name = (processName || '').toLowerCase();
    const cmd = (command || '').toLowerCase();
    if (this.isBackgroundService(name, cmd)) return false;
    if ((name.includes('teamviewer') && !name.includes('teamviewerd') && !cmd.includes('-d')) ||
        (name.includes('anydesk') && !name.includes('service')) ||
        cmd.includes('--display') || cmd.includes('--x11') ||
        (cmd.includes('chrome') && cmd.includes('remote') && !cmd.includes('--type='))) {
      return true;
    }
    return false;
  }

  async checkRemoteControlApplications(processes = null) {
    const threats = [];
    try {
      if (!processes) {
        processes = await this.safe('processes', () => si.processes(), 4000);
      }
      if (!processes?.list) return threats;

      const detectedApps = new Map();

      for (const p of processes.list) {
        if (!p.name && !p.command) continue;
        const name = (p.name || '').toLowerCase();
        const cmd = (p.command || '').toLowerCase();
        if (this.isBackgroundService(name, cmd)) continue;
        if (this.isInstallerContext(cmd)) continue;

        // Compare against executable basename when possible
        const firstToken = (p.command || '').split(/\s+/)[0] || '';
        const exeBase = path.basename(firstToken).toLowerCase();

        const matchedApp = this.remoteControlApps.find(app => {
          const a = app.toLowerCase();
          return name.includes(a) || exeBase.includes(a) || (cmd.includes(a) && !/\.(deb|rpm|msi|dmg)/.test(cmd));
        });
        if (!matchedApp) continue;

        const isActiveUser = this.isActiveUserApplication(name, cmd);
        const isActiveProc = this.isProcessActive(p);

        let appKey = matchedApp.toLowerCase();
        if (appKey.includes('teamviewer')) appKey = 'teamviewer';
        else if (appKey.includes('anydesk')) appKey = 'anydesk';
        else if (appKey.includes('vnc')) appKey = 'vnc';
        else if (appKey.includes('chrome') && appKey.includes('remote')) appKey = 'chrome_remote';

        if (isActiveUser && isActiveProc) {
          const prev = detectedApps.get(appKey);
          const entry = {
            applicationName: this.getDisplayName(appKey),
            appKey,
            process: p,
            cpu: p.pcpu || 0,
            mem: p.pmem || 0
          };
          if (!prev || entry.cpu > prev.cpu) detectedApps.set(appKey, entry);
        } else {
          // Report as suspicious if matched but not active user app
          threats.push({
            type: 'suspicious_process',
            severity: 'medium',
            message: `Suspicious application detected: ${p.name}`,
            details: { pid: p.pid, reason: 'matches remote-control list but not active UI app' }
          });
        }
      }

      for (const [, e] of detectedApps) {
        threats.push({
          type: 'remote_control_application',
          severity: 'critical',
          message: `Remote control application detected: ${e.applicationName}`,
          details: { pid: e.process.pid, cpu: e.cpu, mem: e.mem }
        });
      }
    } catch {}
    return threats;
  }

  async checkSuspiciousProcesses(processes = null) {
    const threats = [];
    try {
      if (!processes) processes = await this.safe('processes', () => si.processes(), 4000);
      if (!processes?.list) return threats;
      for (const p of processes.list) {
        if (!p.name && !p.command) continue;
        const name = (p.name || '').toLowerCase();
        const cmd = (p.command || '').toLowerCase();
        // Do not skip based on activity; even idle apps are relevant
        if (this.isInstallerContext(cmd)) continue;
        const match = this.suspiciousProcesses.find(s => name.includes(s.toLowerCase()) || cmd.includes(s.toLowerCase()));
        if (match) {
          threats.push({
            type: 'suspicious_process',
            severity: 'high',
            message: `Suspicious process detected: ${p.name}`,
            details: { pid: p.pid, name: p.name || 'unknown', command: p.command || 'unknown', suspiciousPattern: match }
          });
        }
      }
    } catch {}
    return threats;
  }

  async checkSuspiciousNetworkConnections() {
    const threats = [];
    try {
      const connections = await this.safe('net', () => si.networkConnections(), 3000);
      for (const conn of connections) {
        const lp = Number(conn.localport);
        const pp = Number(conn.peerport);
        if (this.suspiciousPorts.includes(lp) || this.suspiciousPorts.includes(pp)) {
          threats.push({
            type: 'suspicious_network_connection',
            severity: 'high',
            message: `Suspicious network connection on port ${lp || pp}`,
            details: { protocol: conn.protocol, state: conn.state, localPort: lp, peerPort: pp, pid: conn.pid }
          });
        }
      }
    } catch {}
    return threats;
  }

  async checkScreenSharingIndicators() {
    let threats = [];
    try {
      const processes = await this.safe('processes', () => si.processes(), 4000);
      const browsers = ['chrome','chromium','firefox','edge','brave','opera'];
      const videoApps = ['zoom','teams','skype','webex','discord','slack'];
      const browserProcs = [];
      const videoProcs = [];
      const livePidSet = new Set((processes.list || []).map(p => p.pid));
      for (const p of (processes.list || [])) {
        if (!p || (!p.name && !p.command)) continue;
        const name = (p.name || '').toLowerCase();
        const cmd = (p.command || '').toLowerCase();
        if (!this.isProcessActive(p)) continue;
        if (browsers.some(b => name.includes(b))) browserProcs.push(p);
        if (videoApps.some(a => name.includes(a))) videoProcs.push(p);
        for (const app of videoApps) if (name.includes(app)) {
          threats.push({ type: 'video_conferencing_detected', severity: 'high', message: `Video conferencing app detected: ${p.name}`, details: { pid: p.pid } });
        }
        if (browsers.some(b => name.includes(b))) {
          const flags = ['--enable-usermedia-screen-capturing','--auto-select-desktop-capture-source','--use-fake-ui-for-media-stream','--disable-web-security','--allow-running-insecure-content'];
          const hasFlags = flags.some(f => cmd.includes(f));
          if (hasFlags) {
            threats.push({ type: 'browser_screen_sharing_detected', severity: 'critical', message: `Browser screen sharing indicators in ${p.name}`, details: { pid: p.pid } });
          }
          if ((p.pcpu || 0) > 15) {
            threats.push({ type: 'browser_high_cpu_usage', severity: 'medium', message: `Browser high CPU: ${p.name} (${p.pcpu}%)`, details: { pid: p.pid } });
          }
        }
        // Dedicated screen capture tools
        if (/\bobs\b/.test(name) || /\bffmpeg\b/.test(name)) {
          const captureHints = ['x11grab','gdigrab','avfoundation','dshow','screen-capture','pipewire','xcbgrab'];
          if (captureHints.some(h => cmd.includes(h))) {
            threats.push({ type: 'screen_capture_tool_detected', severity: 'critical', message: `Screen capture tool active: ${p.name}`, details: { pid: p.pid } });
          }
        }
      }

      if (browserProcs.length > 0) threats.push(...await this.detectChromeScreenSharing(browserProcs));
      if (videoProcs.length > 0) threats.push(...await this.detectChromeScreenSharing(videoProcs));

      let activeScreencastPids = new Set();
      if (process.platform === 'linux') {
        // PipeWire screencast detection (Wayland/modern X11)
        try {
          const pipewire = await this.detectPipeWireScreencast();
          threats.push(...pipewire);
          for (const t of pipewire) if (t.details && t.details.pid) activeScreencastPids.add(t.details.pid);
        } catch {}

        try {
          const { stdout } = await execAsync('lsof /tmp/.X11-unix/* 2>/dev/null | grep -v COMMAND || true');
          if (stdout && stdout.trim()) {
            for (const line of stdout.trim().split('\n')) {
              if (/(chrome|chromium|firefox)/i.test(line)) {
                threats.push({ type: 'x11_display_access_detected', severity: 'low', message: 'Browser accessing X11 display', details: { line } });
              }
            }
          }
        } catch {}
        try {
          const { stdout } = await execAsync('pactl list short sources 2>/dev/null || true');
          if (stdout.includes('monitor') && stdout.includes('running')) {
            threats.push({ type: 'audio_monitor_detected', severity: 'medium', message: 'Audio monitoring active', details: {} });
          }
        } catch {}
        try {
          const { stdout } = await execAsync('pactl list source-outputs 2>/dev/null || true');
          if (stdout && /(State:\s*RUNNING)/i.test(stdout) && /(chrome|chromium|firefox|zoom|teams|obs)/i.test(stdout)) {
            threats.push({ type: 'desktop_audio_capture_detected', severity: 'medium', message: 'Active recording stream from desktop audio', details: {} });
          }
        } catch {}

        // Filter: Only keep WebRTC-only browser hints if there is an active screencast for that PID (Linux-only)
        if (activeScreencastPids.size > 0) {
          const browserPidSet = new Set(browserProcs.map(p => p.pid));
          threats = threats.filter(t => {
            if (t.type !== 'screen_sharing_process_webrtc') return true;
            const pid = t.details && t.details.pid;
            if (!pid) return true;
            if (browserPidSet.has(pid) && !activeScreencastPids.has(pid)) return false;
            return true;
          });
        }
      }

      // Final de-stale filter: drop threats whose PID no longer exists
      threats = threats.filter(t => {
        const pid = t.details && t.details.pid;
        if (!pid) return true;
        return livePidSet.has(pid);
      });

      // Platform-specific additions
      if (process.platform === 'win32') {
        try { threats.push(...await this.detectWindowsRemoteDesktop()); } catch {}
      } else if (process.platform === 'darwin') {
        try { threats.push(...await this.detectMacOSScreenSharingSession()); } catch {}
      }

    } catch {}
    return threats;
  }

  async detectChromeScreenSharing(chromeProcesses) {
    const threats = [];
    try {
      const connections = await this.safe('net', () => si.networkConnections(), 3000);
      const procByPid = new Map((chromeProcesses || []).map(p => [p.pid, p]));
      if (chromeProcesses.length > 12) {
        threats.push({ type: 'browser_multiple_processes', severity: 'low', message: `Multiple browser processes detected (${chromeProcesses.length})` });
      }
      const totalMem = chromeProcesses.reduce((s, p) => s + (p.pmem || 0), 0);
      if (totalMem > 30) {
        threats.push({ type: 'browser_high_memory_usage', severity: 'medium', message: `Browser using high memory (${totalMem.toFixed(1)}%)` });
      }
      for (const p of chromeProcesses) if ((p.pcpu || 0) > 20) {
        threats.push({ type: 'browser_process_high_cpu', severity: 'medium', message: `${p.name} high CPU (${p.pcpu}%)`, details: { pid: p.pid } });
      }
      const byPid = new Map();
      for (const c of (connections || [])) {
        if (c.protocol !== 'udp') continue;
        const pid = c.pid;
        if (!procByPid.has(pid)) continue;
        const highPort = (c.localport > 30000 && c.localport < 65535) || (c.peerport > 30000 && c.peerport < 65535);
        if (!highPort) continue;
        byPid.set(pid, (byPid.get(pid) || 0) + 1);
      }
      for (const [pid, count] of byPid) {
        const p = procByPid.get(pid);
        const name = p?.name || 'browser';
        threats.push({
          type: 'screen_sharing_process_webrtc',
          severity: 'medium',
          message: `${name} possible screen sharing via WebRTC`,
          details: { pid, connections: count }
        });
      }
    } catch {}
    return threats;
  }

  async detectPipeWireScreencast() {
    const threats = [];
    try {
      const { stdout } = await execAsync('pw-dump 2>/dev/null || true');
      if (!stdout || !stdout.trim()) return threats;
      let data;
      try { data = JSON.parse(stdout); } catch { data = []; }
      if (!Array.isArray(data)) return threats;

      // Map clients for fallback PID/app resolution
      const clientById = new Map();
      for (const obj of data) {
        if (!obj || obj.type !== 'PipeWire:Interface:Client') continue;
        const id = obj.id;
        const props = (obj.info && obj.info.props) || {};
        const pid = Number(props['application.process.id']) || 0;
        const appName = String(props['application.name'] || '').toLowerCase();
        const bin = String(props['application.process.binary'] || '').toLowerCase();
        clientById.set(id, { pid, appName, bin, rawName: String(props['application.name'] || '') });
      }

      const seenPid = new Set();
      for (const obj of data) {
        if (!obj || obj.type !== 'PipeWire:Interface:Node') continue;
        const info = obj.info || {};
        const props = info.props || {};
        const stateStr = String(info.state || props['node.state'] || '').toLowerCase();
        const hasState = Boolean(stateStr);
        const isActive = hasState ? /running|active|streaming/.test(stateStr) : true; // if state unknown, assume active
        const mediaClass = String(props['media.class'] || '').toLowerCase();
        const nodeName = String(props['node.name'] || '').toLowerCase();
        const nodeDesc = String(props['node.description'] || '').toLowerCase();
        const role = String(props['node.role'] || '').toLowerCase();
        let appName = String(props['application.name'] || '').toLowerCase();
        let procBin = String(props['application.process.binary'] || '').toLowerCase();
        let pid = Number(props['application.process.id']) || 0;

        // Fallback to client if missing
        const clientId = info.clientId || info['client.id'] || info['clientId'] || null;
        if ((!pid || !appName) && clientId && clientById.has(clientId)) {
          const c = clientById.get(clientId);
          pid = pid || c.pid;
          appName = appName || c.appName;
          procBin = procBin || c.bin;
        }

        const isBrowser = /(chrome|chromium|firefox|brave|opera|edge)/.test(appName) || /(chrome|chromium|firefox|brave|opera|edge)/.test(procBin);
        const isVideoApp = /(zoom|teams|webex|discord)/.test(appName);
        const looksLikeScreencast = mediaClass.includes('video') || mediaClass.includes('stream') || role.includes('screen') || nodeName.includes('xdpw') || nodeDesc.includes('screencast') || nodeDesc.includes('screen') || nodeDesc.includes('portal') || appName.includes('xdg-desktop-portal');
        if (!isActive) continue;
        if (looksLikeScreencast && (isBrowser || isVideoApp || appName.includes('xdg-desktop-portal'))) {
          if (pid && seenPid.has(pid)) continue;
          if (pid) seenPid.add(pid);
          threats.push({
            type: 'screen_sharing_process_pipewire',
            severity: 'critical',
            message: `${props['application.name'] || clientById.get(clientId)?.rawName || 'Unknown app'} screencast active`,
            details: { pid: pid || undefined, appName: props['application.name'] || clientById.get(clientId)?.rawName || '', node: props['node.description'] || props['node.name'] || '' }
          });
        }
      }
    } catch {}
    return threats;
  }

  async analyzeNetworkTrafficPatterns() {
    const threats = [];
    try {
      const connections = await this.safe('net', () => si.networkConnections(), 1500);
      if (!Array.isArray(connections)) return threats;
      const count = connections.length;
      if (!this.networkBaseline) {
        this.networkBaseline = { totalConnections: count, highPortConnections: connections.filter(c => c.localport && c.localport > 30000).length, timestamp: Date.now() };
        return threats;
      }
      const suspicious = connections.filter(c => c.protocol === 'udp' && ((c.localport > 50000 && c.localport < 65535) || (c.peerport > 50000 && c.peerport < 65535)));
      if (suspicious.length > 20) threats.push({ type: 'high_udp_traffic', severity: 'medium', message: `High UDP traffic (${suspicious.length})` });
      this.networkBaseline = { totalConnections: count, highPortConnections: connections.filter(c => c.localport && c.localport > 30000).length, timestamp: Date.now() };
    } catch {}
    return threats;
  }

  async detectActiveScreenCapture() {
    const threats = [];
    try {
      const gpu = await this.detectGPUScreenEncoding();
      threats.push(...gpu);
    } catch {}
    return threats;
  }

  async detectGPUScreenEncoding() {
    const threats = [];
    try {
      const [graphicsRes, processesRes] = await Promise.allSettled([
        this.safe('graphics', () => si.graphics(), 2000),
        this.safe('processes', () => si.processes(), 2000)
      ]);
      const processes = (processesRes.value && processesRes.value.list) ? processesRes.value.list : [];
      const gpuIntensive = processes.filter(p => {
        const name = (p.name || '').toLowerCase();
        const isScreenApp = /(chrome|chromium|firefox|obs|zoom|teams|discord)/.test(name);
        return isScreenApp && (p.pmem || 0) > 5;
      });
      if (gpuIntensive.length > 0) {
        const total = gpuIntensive.reduce((s, p) => s + (p.pmem || 0), 0);
        if (total > 15) threats.push({ type: 'high_gpu_memory_usage', severity: 'high', message: `High GPU memory usage (${total.toFixed(1)}%)` });
      }
    } catch {}
    return threats;
  }

  async detectMacOSScreenRecording() {
    const threats = [];
    if (process.platform !== 'darwin') return threats;
    try {
      const { stdout } = await this.safe('tcc', () => execAsync('sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT client FROM access WHERE service=\'kTCCServiceScreenCapture\' AND allowed=1;" 2>/dev/null || true'), 2000);
      if (stdout && stdout.trim()) {
        const apps = stdout.trim().split('\n').filter(Boolean);
        if (apps.length) threats.push({ type: 'screen_recording_permissions', severity: 'critical', message: `Apps with screen recording permissions (${apps.length})` });
      }
    } catch {}
    return threats;
  }

  async detectClipboardSynchronization() {
    const threats = [];
    try {
      const processes = await this.safe('processes', () => si.processes(), 2000);
      const list = (processes.list || []).filter(p => {
        const cmd = (p.command || '').toLowerCase();
        return cmd.includes('clipboard') || cmd.includes('xclip') || cmd.includes('pbcopy') || cmd.includes('pbpaste') ||
               (cmd.includes('teamviewer') && cmd.includes('clipboard')) || (cmd.includes('anydesk') && cmd.includes('clipboard'));
      });
      if (list.length) threats.push({ type: 'clipboard_synchronization', severity: 'medium', message: 'Clipboard synchronization processes detected' });
    } catch {}
    return threats;
  }

  getDisplayName(appKey) {
    const names = { teamviewer: 'TeamViewer', anydesk: 'AnyDesk', vnc: 'VNC', 'chrome-remote': 'Chrome Remote Desktop', chrome_remote: 'Chrome Remote Desktop' };
    return names[appKey] || (appKey.charAt(0).toUpperCase() + appKey.slice(1));
  }

  async checkVirtualMachine() {
    const threats = [];
    try {
      const [system, processes] = await Promise.all([si.system(), si.processes()]);
      const manufacturer = (system.manufacturer || '').toLowerCase();
      const model = (system.model || '').toLowerCase();
      const vmIndicators = ['vmware','virtualbox','qemu','kvm','hyper-v','xen','parallels'];
      for (const ind of vmIndicators) if (manufacturer.includes(ind) || model.includes(ind)) threats.push({ type: 'virtual_machine_detected', severity: 'critical', message: `VM detected: ${manufacturer} ${model}` });
      for (const p of (processes.list || [])) {
        const name = (p.name || '').toLowerCase();
        if (vmIndicators.some(ind => name.includes(ind))) threats.push({ type: 'vm_process_detected', severity: 'high', message: `VM process detected: ${p.name}` });
      }
    } catch {}
    return threats;
  }

  async checkMaliciousSignatures(signatures) {
    const threats = [];
    try {
      const [proc, conns] = await Promise.all([si.processes(), si.networkConnections()]);
      const sig = signatures || { processNames: [], ports: [], domains: [] };
      const processNames = (sig.processNames || []).map(s => String(s).toLowerCase());
      const ports = (sig.ports || []).map(p => Number(p));
      const domains = (sig.domains || []).map(d => String(d).toLowerCase());

      for (const p of (proc.list || [])) {
        if (!this.isProcessActive(p)) continue;
        const name = String(p.name || '').toLowerCase();
        if (processNames.includes(name)) {
          threats.push({ type: 'signature_process', severity: 'high', message: `Malicious process detected: ${p.name}`, details: { pid: p.pid } });
        }
      }

      for (const c of (conns || [])) {
        const lp = Number(c.localport);
        const pp = Number(c.peerport);
        if (ports.includes(lp) || ports.includes(pp)) {
          threats.push({ type: 'signature_port', severity: 'high', message: `Malicious port in use (${lp || pp})`, details: { protocol: c.protocol, state: c.state } });
        }
        const peer = String(c.peeraddress || '').toLowerCase();
        if (peer && domains.some(d => peer.includes(d))) {
          threats.push({ type: 'signature_domain', severity: 'high', message: `Connection to malicious host: ${c.peeraddress}`, details: { protocol: c.protocol, state: c.state } });
        }
      }
    } catch {}
    return threats;
  }

  async detectWindowsRemoteDesktop() {
    const threats = [];
    if (process.platform !== 'win32') return threats;
    try {
      // Check for active RDP sessions via query user
      let out = '';
      try {
        const r = await execAsync('query user');
        out = r.stdout || '';
      } catch {
        try {
          const r2 = await execAsync('qwinsta');
          out = r2.stdout || '';
        } catch {}
      }
      if (out) {
        const lines = out.trim().split(/\r?\n/);
        for (const line of lines) {
          if (/rdp\-tcp|RDP\-Tcp|console/i.test(line)) {
            const isRdp = /rdp\-tcp/i.test(line);
            if (isRdp && /Active/i.test(line)) {
              threats.push({ type: 'windows_rdp_session_active', severity: 'critical', message: 'Active Windows RDP session detected', details: { line: line.trim() } });
            }
          }
        }
      }
      // Detect RDP clipboard/audio helpers if present
      try {
        const proc = await this.safe('processes', () => si.processes(), 2000);
        for (const p of (proc.list || [])) {
          const n = String(p.name || '').toLowerCase();
          if (n === 'rdpclip.exe' || n.includes('rdpclip')) {
            threats.push({ type: 'windows_rdp_clipboard', severity: 'medium', message: 'RDP clipboard synchronization running', details: { pid: p.pid } });
          }
        }
      } catch {}
    } catch {}
    return threats;
  }

  async detectMacOSScreenSharingSession() {
    const threats = [];
    if (process.platform !== 'darwin') return threats;
    try {
      // macOS Screen Sharing / ARD
      let out = '';
      try {
        const r = await execAsync('pgrep -x screensharingd || true');
        out = r.stdout || '';
      } catch {}
      if (out && out.trim()) {
        threats.push({ type: 'mac_screensharing_session_active', severity: 'critical', message: 'macOS Screen Sharing session active', details: {} });
      }
      // ARD Agent
      try {
        const r2 = await execAsync('pgrep -x ARDAgent || true');
        if (r2.stdout && r2.stdout.trim()) {
          threats.push({ type: 'mac_ard_agent_running', severity: 'high', message: 'Apple Remote Desktop agent running', details: {} });
        }
      } catch {}
    } catch {}
    return threats;
  }

  async runAllChecks(signatures) {
    const results = await Promise.allSettled([
      this.checkRemoteControlApplications(),
      this.checkSuspiciousProcesses(),
      this.checkSuspiciousNetworkConnections(),
      this.checkScreenSharingIndicators(),
      this.analyzeNetworkTrafficPatterns(),
      this.detectActiveScreenCapture(),
      this.detectMacOSScreenRecording(),
      this.detectClipboardSynchronization(),
      this.checkVirtualMachine(),
      this.checkMaliciousSignatures(signatures),
      // Platform-specific add-ons
      this.detectWindowsRemoteDesktop(),
      this.detectMacOSScreenSharingSession()
    ]);
    const threats = [];
    for (const r of results) if (r.status === 'fulfilled' && Array.isArray(r.value)) threats.push(...r.value);
    const seen = new Set();
    const unique = [];
    for (const t of threats) {
      const k = `${t.type}|${t.message}`;
      if (seen.has(k)) continue;
      seen.add(k);
      unique.push(t);
    }
    return unique;
  }
}

module.exports = SecurityService; 