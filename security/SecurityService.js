const { EventEmitter } = require('events');
const si = require('systeminformation');
const os = require('os');
const path = require('path');
const fs = require('fs');
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
    this.recentSharingByPid = new Map();
    this.sharingStickyMs = 60000;

    this.checkInterval = 20000;

    // Only remote control / RDP-style tools here to avoid false positives
    this.remoteControlApps = [
      'teamviewer','tv_w32','tv_x64',
      'anydesk','anydesk.exe',
      'chrome_remote','remotedesktop','chrome_remote_desktop',
      'vnc','vncserver','vncviewer','realvnc','tightvnc','ultravnc','winvnc','vnc4server','x11vnc',
      'mstsc','rdp','remote desktop','terminal services','rdpclip','rdpinput','rdpsnd','rdpdr',
      'logmein','gotomypc','remotepc','splashtop','dameware','radmin','ammyy','screenconnect','bomgar',
      'remoteutilities','supremo','showmypc','zoho assist',
      'chrome.exe --remote-debugging'
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

  async testTabDetection(browserName = 'firefox') {
    console.log(`🧪 Testing tab detection for ${browserName}...`);
    try {
      const allTabs = await this.getAllTabsForBrowser(browserName);
      console.log(`🧪 Found ${allTabs.length} sharing tabs:`, allTabs);
      
      const tabInfo = await this.resolveSharingTabInfoForBrowser(browserName);
      console.log(`🧪 Single tab info:`, tabInfo);
      
      return { allTabs, tabInfo };
    } catch (e) {
      console.error(`🧪 Test failed:`, e);
      return { error: String(e) };
    }
  }

  async checkBrowserTabAccessPermissions() {
    const result = { platform: process.platform, browsers: [], tools: {}, ok: true };
    try {
      // First, get currently running processes to check which browsers are active
      const processes = await si.processes();
      const runningBrowsers = new Set();
      
      // Map process names to browser keys
      const browserProcessMap = {
        'chrome': ['chrome', 'google chrome'],
        'safari': ['safari'],
        'edge': ['msedge', 'microsoft edge'],
        'brave': ['brave', 'brave browser'],
        'opera': ['opera'],
        'firefox': ['firefox'],
        'chromium': ['chromium']
      };
      
      // Check which browsers are actually running
      for (const proc of processes) {
        const procName = String(proc.name || '').toLowerCase();
        for (const [browserKey, processNames] of Object.entries(browserProcessMap)) {
          if (processNames.some(name => procName.includes(name))) {
            runningBrowsers.add(browserKey);
            break;
          }
        }
      }
      
      if (process.platform === 'darwin') {
        const macBrowsers = [
          { key: 'chrome', app: 'Google Chrome', script: 'tell application "Google Chrome" to set _t to {URL, title} of active tab of front window' },
          { key: 'safari', app: 'Safari', script: 'tell application "Safari" to set _t to {URL, name} of current tab of front window' },
          { key: 'edge', app: 'Microsoft Edge', script: 'tell application "Microsoft Edge" to set _t to {URL, title} of active tab of front window' },
          { key: 'brave', app: 'Brave Browser', script: 'tell application "Brave Browser" to set _t to {URL, title} of active tab of front window' },
          { key: 'opera', app: 'Opera', script: 'tell application "Opera" to set _t to {URL, title} of active tab of front window' },
          { key: 'firefox', app: 'Firefox', script: 'tell application "Firefox" to set _t to {URL of active tab of front window, name of active tab of front window}' }
        ];
        
        for (const b of macBrowsers) {
          // Only check browsers that are actually running
          if (!runningBrowsers.has(b.key)) {
            continue;
          }
          
          try {
            // First check if the application is running
            const runningCheck = await execAsync(`osascript -e 'tell application "System Events" to (name of processes) contains "${b.app}"'`);
            if (!String(runningCheck.stdout || '').toLowerCase().includes('true')) {
              continue;
            }
            
            // Test tab access permission
            const { stdout } = await execAsync(`osascript -e '${b.script}\nreturn "ok"'`, { timeout: 5000 });
            const ok = String(stdout || '').toLowerCase().includes('ok');
            result.browsers.push({ browser: b.key, ok, running: true });
            if (!ok) result.ok = false;
          } catch (e) {
            const errorMsg = String(e);
            result.browsers.push({ browser: b.key, ok: false, running: true, error: errorMsg });
            // Don't fail overall check if it's just a permission issue
            if (!errorMsg.includes('User canceled') && !errorMsg.includes('not allowed assistive access')) {
              result.ok = false;
            }
          }
        }
      } else if (process.platform === 'win32') {
        const winBrowsers = [
          { key: 'chrome', processName: 'chrome' },
          { key: 'edge', processName: 'msedge' },
          { key: 'firefox', processName: 'firefox' },
          { key: 'brave', processName: 'brave' },
          { key: 'opera', processName: 'opera' }
        ];
        
        for (const b of winBrowsers) {
          // Only check browsers that are actually running
          if (!runningBrowsers.has(b.key)) {
            continue;
          }
          
          try {
            // Check if browser has accessible windows
            const cmd = `powershell -NoProfile -Command "(Get-Process -Name ${b.processName} -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowHandle -ne 0} | Select-Object -First 1 | ForEach-Object { $_.MainWindowTitle })"`;
            const { stdout } = await execAsync(cmd, { timeout: 5000 });
            const hasWindow = Boolean((stdout || '').trim());
            result.browsers.push({ browser: b.key, ok: hasWindow, running: true });
            if (!hasWindow) result.ok = false;
          } catch (e) {
            result.browsers.push({ browser: b.key, ok: false, running: true, error: String(e) });
            result.ok = false;
          }
        }
      } else {
        // Linux
        try {
          const { stdout } = await execAsync('command -v wmctrl || true');
          result.tools.wmctrl = Boolean((stdout || '').trim());
        } catch { result.tools.wmctrl = false; }
        
        try {
          const { stdout } = await execAsync('command -v xdotool || true');
          result.tools.xdotool = Boolean((stdout || '').trim());
        } catch { result.tools.xdotool = false; }
        
        const hasTools = result.tools.wmctrl || result.tools.xdotool;
        if (!hasTools) result.ok = false;
        
        // Only report running browsers on Linux
        const linuxBrowsers = ['chrome', 'chromium', 'firefox', 'edge', 'brave', 'opera'];
        for (const browserKey of linuxBrowsers) {
          if (runningBrowsers.has(browserKey)) {
            result.browsers.push({ browser: browserKey, ok: hasTools, running: true });
          }
        }
      }
    } catch (e) {
      result.ok = false;
      result.error = String(e);
    }
    return result;
  }

  // Identify system helper processes we should exclude from threat reporting
  isSystemHelper(processName, command) {
    const name = String(processName || '').toLowerCase();
    const cmd = String(command || '').toLowerCase();
    if (!name && !cmd) return false;
    
    // Check for AirPlay helpers first (more specific)
    if (name.includes('airplayxpchelper') || cmd.includes('airplayxpchelper')) {
      console.log(`🔧 Excluding AirPlayXPCHelper: ${processName}`);
      return true;
    }
    if (name.includes('airplay') || cmd.includes('airplay')) {
      console.log(`🔧 Excluding AirPlay process: ${processName}`);
      return true;
    }
    
    // CoreAudio / Drivers / Kexts / HAL plugins
    if (name.includes('.driver') || cmd.includes('.driver')) return true;
    if (name.includes('kext') || cmd.includes('kext')) return true;
    if (name.includes('coreaudio') || cmd.includes('coreaudio')) return true;
    if (cmd.includes('/library/audio/plug-ins/hal')) return true;
    
    return false;
  }

  getThreatPatterns() {
    // Keyword patterns for matching app/process/service/extension names
    return {
      messaging: [
        'whatsapp', 'telegram', 'discord', 'microsoft teams', 'teams', 'slack', 'zoom', 'signal', 'messenger', 'skype'
      ],
      remote_control: [
        'teamviewer', 'anydesk', 'chrome remote desktop', 'chrome_remote_desktop', 'remote desktop', 'zoho assist', 'ultraviewer', 'remote utilities', 'remotepc', 'splashtop', 'vnc', 'realvnc', 'tightvnc', 'ultravnc', 'rdp', 'radmin', 'screenconnect', 'bomgar'
      ],
      virtualization: [
        'virtualbox', 'vmware', 'parallels', 'qemu', 'kvm', 'hyper-v', 'hyperv', 'xen'
      ],
      screen_capture: [
        'snagit', 'sharex', 'obs', 'obs studio', 'gyazo', 'camtasia', 'bandicam', 'fraps', 'screencast'
      ]
    };
  }

  normalizeName(name) {
    return String(name || '').toLowerCase();
  }

  matchCategoryForName(name) {
    const n = this.normalizeName(name);
    const patterns = this.getThreatPatterns();
    for (const category of Object.keys(patterns)) {
      const match = patterns[category].find(p => n.includes(p));
      if (match) return { category, match };
    }
    return null;
  }

  async listInstalledApplications() {
    const platform = process.platform;
    let names = new Set();
    try {
      if (platform === 'win32') {
        try {
          const ps = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "'
            + '$paths = @(\"HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\", \"HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\", \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\");'
            + '$paths | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } | Where-Object { $_.DisplayName } | Select-Object -ExpandProperty DisplayName | ForEach-Object { $_ }' + '"';
          const r = await execAsync(ps);
          const lines = (r.stdout || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
          for (const line of lines) names.add(line);
        } catch {}
        try {
          const r2 = await execAsync('wmic product get name 2>NUL | findstr /R /V "Name"');
          const lines = (r2.stdout || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
          for (const line of lines) names.add(line);
        } catch {}
      } else if (platform === 'darwin') {
        try {
          const r = await execAsync('ls -1 /Applications 2>/dev/null || true');
          const lines = (r.stdout || '').split(/\n/).map(s => s.trim()).filter(Boolean);
          for (const l of lines) names.add(l.replace(/\.app$/i, ''));
        } catch {}
        try {
          const r2 = await execAsync('ls -1 "$HOME"/Applications 2>/dev/null || true');
          const lines = (r2.stdout || '').split(/\n/).map(s => s.trim()).filter(Boolean);
          for (const l of lines) names.add(l.replace(/\.app$/i, ''));
        } catch {}
        try {
          const r3 = await execAsync('system_profiler SPApplicationsDataType -json 2>/dev/null || true');
          const json = JSON.parse(r3.stdout || '{}');
          const items = (json.SPApplicationsDataType || []).map(x => x._name).filter(Boolean);
          for (const n of items) names.add(n);
        } catch {}
      } else {
        // linux
        try {
          const r = await execAsync('dpkg -l 2>/dev/null | awk "NR>5 {print $2}" || true');
          const lines = (r.stdout || '').split(/\n/).map(s => s.trim()).filter(Boolean);
          for (const l of lines) names.add(l);
        } catch {}
        try {
          const r2 = await execAsync('rpm -qa 2>/dev/null || true');
          const lines = (r2.stdout || '').split(/\n/).map(s => s.trim()).filter(Boolean);
          for (const l of lines) names.add(l);
        } catch {}
        try {
          const r3 = await execAsync('flatpak list --app --columns=application 2>/dev/null || true');
          const lines = (r3.stdout || '').split(/\n/).map(s => s.trim()).filter(Boolean);
          for (const l of lines) names.add(l);
        } catch {}
        try {
          const r4 = await execAsync('snap list 2>/dev/null | awk "NR>1 {print $1}" || true');
          const lines = (r4.stdout || '').split(/\n/).map(s => s.trim()).filter(Boolean);
          for (const l of lines) names.add(l);
        } catch {}
      }
    } catch {}
    return Array.from(names);
  }

  async listRunningServices() {
    const platform = process.platform;
    const services = new Set();
    try {
      if (platform === 'linux') {
        try {
          const r = await execAsync('systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null || true');
          const lines = (r.stdout || '').split(/\n/).map(s => s.trim()).filter(Boolean);
          for (const line of lines) {
            const name = line.split(/\s+/)[0] || '';
            if (name) services.add(name.replace(/\.service$/i, ''));
          }
        } catch {}
      } else if (platform === 'win32') {
        try {
          const r = await execAsync('sc query type= service state= all');
          const lines = (r.stdout || '').split(/\r?\n/);
          for (const line of lines) {
            const m = line.match(/SERVICE_NAME:\s*(.+)$/i);
            if (m && m[1]) services.add(m[1].trim());
          }
        } catch {}
      } else if (platform === 'darwin') {
        try {
          const r = await execAsync('launchctl list 2>/dev/null || true');
          const lines = (r.stdout || '').split(/\n/).map(s => s.trim()).filter(Boolean);
          for (const line of lines.slice(1)) {
            const parts = line.split(/\s+/);
            if (parts.length >= 3) services.add(parts[2]);
          }
        } catch {}
      }
    } catch {}
    return Array.from(services);
  }

  async scanBrowserExtensions() {
    const results = [];
    const addChromiumExtensions = (baseDir, browser) => {
      try {
        const profileDirs = [];
        if (fs.existsSync(baseDir)) {
          const entries = fs.readdirSync(baseDir, { withFileTypes: true });
          for (const e of entries) if (e.isDirectory()) profileDirs.push(path.join(baseDir, e.name));
        }
        for (const profile of profileDirs) {
          const extDir = path.join(profile, 'Extensions');
          if (!fs.existsSync(extDir)) continue;
          const extIds = fs.readdirSync(extDir, { withFileTypes: true }).filter(d => d.isDirectory());
          for (const idDir of extIds) {
            const idPath = path.join(extDir, idDir.name);
            const versionDirs = fs.readdirSync(idPath, { withFileTypes: true }).filter(d => d.isDirectory());
            for (const v of versionDirs) {
              const manifestPath = path.join(idPath, v.name, 'manifest.json');
              try {
                if (!fs.existsSync(manifestPath)) continue;
                const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
                const extName = manifest.name || '';
                const extDesc = manifest.description || '';
                const text = this.normalizeName(`${extName} ${extDesc}`);
                const m = this.matchCategoryForName(text);
                if (m) {
                  results.push({ browser, name: manifest.name, category: m.category, match: m.match, id: idDir.name });
                }
              } catch {}
            }
          }
        }
      } catch {}
    };

    const home = os.homedir();
    if (process.platform === 'win32') {
      const localAppData = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
      addChromiumExtensions(path.join(localAppData, 'Google', 'Chrome', 'User Data'), 'chrome');
      addChromiumExtensions(path.join(localAppData, 'Microsoft', 'Edge', 'User Data'), 'edge');
      addChromiumExtensions(path.join(localAppData, 'BraveSoftware', 'Brave-Browser', 'User Data'), 'brave');
      addChromiumExtensions(path.join(localAppData, 'Chromium', 'User Data'), 'chromium');
    } else if (process.platform === 'darwin') {
      addChromiumExtensions(path.join(home, 'Library', 'Application Support', 'Google', 'Chrome'), 'chrome');
      addChromiumExtensions(path.join(home, 'Library', 'Application Support', 'Microsoft Edge'), 'edge');
      addChromiumExtensions(path.join(home, 'Library', 'Application Support', 'BraveSoftware', 'Brave-Browser'), 'brave');
      addChromiumExtensions(path.join(home, 'Library', 'Application Support', 'Chromium'), 'chromium');
    } else {
      addChromiumExtensions(path.join(home, '.config', 'google-chrome'), 'chrome');
      addChromiumExtensions(path.join(home, '.config', 'microsoft-edge'), 'edge');
      addChromiumExtensions(path.join(home, '.config', 'BraveSoftware', 'Brave-Browser'), 'brave');
      addChromiumExtensions(path.join(home, '.config', 'chromium'), 'chromium');
    }

    // Firefox
    try {
      const ffBase = process.platform === 'win32'
        ? path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Mozilla', 'Firefox', 'Profiles')
        : process.platform === 'darwin'
          ? path.join(home, 'Library', 'Application Support', 'Firefox', 'Profiles')
          : path.join(home, '.mozilla', 'firefox');
      if (fs.existsSync(ffBase)) {
        const profiles = fs.readdirSync(ffBase, { withFileTypes: true }).filter(d => d.isDirectory());
        for (const p of profiles) {
          const extJson = path.join(ffBase, p.name, 'extensions.json');
          if (!fs.existsSync(extJson)) continue;
          try {
            const data = JSON.parse(fs.readFileSync(extJson, 'utf8'));
            const addons = (data.addons || []).filter(a => a.name);
            for (const a of addons) {
              const text = this.normalizeName(`${a.name} ${a.description || ''}`);
              const m = this.matchCategoryForName(text);
              if (m) results.push({ browser: 'firefox', name: a.name, category: m.category, match: m.match, id: a.id || '' });
            }
          } catch {}
        }
      }
    } catch {}

    return results;
  }

  async listThreatApplications() {
    try {
      const [installed, processesRes, services, extensions] = await Promise.all([
        this.listInstalledApplications(),
        this.safe('processes', () => si.processes(), 3000),
        this.listRunningServices(),
        this.scanBrowserExtensions()
      ]);
      const processes = (processesRes && processesRes.list) ? processesRes.list : [];

      const categories = {
        messaging: { installed: [], running: [], services: [], extensions: [] },
        remote_control: { installed: [], running: [], services: [], extensions: [] },
        virtualization: { installed: [], running: [], services: [], extensions: [] },
        screen_capture: { installed: [], running: [], services: [], extensions: [] }
      };

      // Installed apps
      for (const appName of installed) {
        const m = this.matchCategoryForName(appName);
        if (m) categories[m.category].installed.push({ name: appName, match: m.match });
      }

      // Running processes
      for (const p of processes) {
        const candidate = this.normalizeName(`${p.name || ''} ${p.command || ''}`);
        const m = this.matchCategoryForName(candidate);
        if (m) {
          categories[m.category].running.push({ name: p.name || 'unknown', pid: p.pid, match: m.match });
        }
      }

      // Services
      for (const s of services) {
        const m = this.matchCategoryForName(s);
        if (m) categories[m.category].services.push({ name: s, match: m.match });
      }

      // Browser extensions
      for (const ext of extensions) {
        if (ext.category && categories[ext.category]) {
          categories[ext.category].extensions.push(ext);
        }
      }

      const summary = {};
      for (const [k, v] of Object.entries(categories)) {
        summary[k] = {
          installed: v.installed.length,
          running: v.running.length,
          services: v.services.length,
          extensions: v.extensions.length
        };
      }

      return { categories, summary, platform: process.platform };
    } catch (e) {
      return { error: String(e), platform: process.platform };
    }
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
    // Treat drivers/kext/coreaudio helpers as background/system services
    if (name.includes('.driver') || cmd.includes('.driver') || name.includes('kext') || cmd.includes('kext')) return true;
    if (name.includes('coreaudio') || cmd.includes('coreaudio') || cmd.includes('/library/audio/plug-ins/hal')) return true;
    // Exclude macOS AirPlay system helpers broadly
    if (name.includes('airplayxpchelper') || cmd.includes('airplayxpchelper') || name.includes('airplay') || cmd.includes('airplay')) return true;
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
        if (this.isInstallerContext(cmd)) continue;
        
        // Skip system helpers like AirPlayXPCHelper
        if (this.isSystemHelper(name, cmd)) {
          console.log(`🔧 Skipping system helper in remote control check: ${p.name}`);
          continue;
        }

        // Compare against executable basename when possible
        const firstToken = (p.command || '').split(/\s+/)[0] || '';
        const exeBase = path.basename(firstToken).toLowerCase();

        // Match against known remote-control and screen-sharing software
        const matchedApp = this.remoteControlApps.find(app => {
          const a = String(app || '').toLowerCase();
          if (!a) return false;
          const matches = name.includes(a) || exeBase.includes(a) || (cmd.includes(a) && !/\.(deb|rpm|msi|dmg)/.test(cmd));
          if (matches && name.includes('airplay')) {
            console.log(`🔧 AirPlay process ${p.name} matched remote control pattern "${app}" but should be excluded`);
          }
          return matches;
        });
        if (!matchedApp) continue;

        let appKey = matchedApp.toLowerCase();
        if (appKey.includes('teamviewer')) appKey = 'teamviewer';
        else if (appKey.includes('anydesk')) appKey = 'anydesk';
        else if (appKey.includes('vnc')) appKey = 'vnc';
        else if (appKey.includes('chrome') && appKey.includes('remote')) appKey = 'chrome_remote';

        // If it's a known remote-control app running as a service/daemon, still flag it
        if (this.isBackgroundService(name, cmd)) {
          threats.push({
            type: 'remote_control_service',
            severity: 'medium',
            message: `Remote control service detected: ${this.getDisplayName(appKey)}`,
            details: { pid: p.pid }
          });
          continue;
        }

        // Record even when minimized/background (still a security risk), excluding services/drivers above
        const isActiveUser = this.isActiveUserApplication(name, cmd) || true; // allow minimized apps
        const isActiveProc = this.isProcessActive(p) || true; // include background CPU/mem-low
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
        if (this.isSystemHelper(name, cmd)) continue;
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
      const [connections, proc] = await Promise.all([
        this.safe('net', () => si.networkConnections(), 3000),
        this.safe('processes', () => si.processes(), 20000)
      ]);
      const byPid = new Map((proc.list || []).map(p => [p.pid, p]));
      for (const conn of connections) {
        const lp = Number(conn.localport);
        const pp = Number(conn.peerport);
        if (this.suspiciousPorts.includes(lp) || this.suspiciousPorts.includes(pp)) {
          // Skip if owned by a known system helper process
          const owner = byPid.get(conn.pid);
          if (owner && this.isSystemHelper(owner.name, owner.command)) continue;
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
      const browsers = ['chrome','chromium','firefox','edge','brave','opera','safari'];
      const videoApps = ['zoom','teams','microsoft teams','skype','webex','discord','slack'];
      const browserProcs = [];
      const videoProcs = [];
      const livePidSet = new Set((processes.list || []).map(p => p.pid));
      console.log(`🔍 Screen sharing check - found ${processes.list?.length || 0} processes`);
      for (const p of (processes.list || [])) {
        if (!p || (!p.name && !p.command)) continue;
        const name = (p.name || '').toLowerCase();
        const cmd = (p.command || '').toLowerCase();
        if (this.isSystemHelper(name, cmd)) continue;
        // Consider browsers/video apps even if minimized/idle
        const isActiveEnough = this.isProcessActive(p) || browsers.some(b => name.includes(b)) || videoApps.some(a => name.includes(a));
        if (!isActiveEnough) continue;
        if (browsers.some(b => name.includes(b))) {
          // Check system helper first
          if (this.isSystemHelper(name, cmd)) {
            console.log(`🔧 Skipping system helper that matches browser pattern: ${p.name} (PID: ${p.pid})`);
            continue;
          }
          
          // Filter out helper processes and agents - only keep main browser processes
          const isMainBrowser = !name.includes('helper') && !name.includes('agent') && 
                                !name.includes('crashpad') && !name.includes('spotlight') &&
                                !name.includes('knowledge') && !name.includes('sync') &&
                                !name.includes('notification') && !name.includes('search');
          if (isMainBrowser) {
            console.log(`🌐 Found main browser: ${p.name} (PID: ${p.pid})`);
            browserProcs.push(p);
          } else {
            console.log(`🔧 Skipping browser helper: ${p.name} (PID: ${p.pid})`);
          }
        }
        if (videoApps.some(a => name.includes(a))) {
          console.log(`📹 Found video app: ${p.name} (PID: ${p.pid})`);
          videoProcs.push(p);
        }
        if (browsers.some(b => name.includes(b))) {
          const flags = ['--enable-usermedia-screen-capturing','--auto-select-desktop-capture-source','--use-fake-ui-for-media-stream','--disable-web-security','--allow-running-insecure-content'];
          const hasFlags = flags.some(f => cmd.includes(f));
          if (hasFlags) {
            threats.push({ type: 'browser_screen_sharing_detected', severity: 'critical', message: `Browser screen sharing indicators in ${p.name}`, details: { pid: p.pid, name: p.name } });
          }
          if ((p.pcpu || 0) > 15) {
            threats.push({ type: 'browser_high_cpu_usage', severity: 'medium', message: `Browser high CPU: ${p.name} (${p.pcpu}%)`, details: { pid: p.pid, name: p.name } });
          }
        }
        // Dedicated screen capture tools
        if (/\bobs\b/.test(name) || /\bffmpeg\b/.test(name)) {
          const captureHints = ['x11grab','gdigrab','avfoundation','dshow','screen-capture','pipewire','xcbgrab'];
          if (captureHints.some(h => cmd.includes(h))) {
            threats.push({ type: 'screen_capture_tool_detected', severity: 'critical', message: `Screen capture tool active: ${p.name}`, details: { pid: p.pid, name: p.name } });
          }
        }
      }

      console.log(`🔍 Processing ${browserProcs.length} browser processes and ${videoProcs.length} video app processes`);
      if (browserProcs.length > 0) {
        const browserThreats = await this.detectChromeScreenSharing(browserProcs);
        console.log(`🔍 Browser WebRTC detection returned ${browserThreats.length} threats`);
        threats.push(...browserThreats);
      }
      if (videoProcs.length > 0) {
        const videoThreats = await this.detectChromeScreenSharing(videoProcs);
        console.log(`🔍 Video app WebRTC detection returned ${videoThreats.length} threats`);
        threats.push(...videoThreats);
      }
      
      // Even without WebRTC activity, check for sharing tabs directly
      console.log(`🔍 Checking for sharing tabs directly without WebRTC requirement...`);
      for (const p of browserProcs) {
        try {
          const name = (p.name || '').toLowerCase();
          const allSharingTabs = await this.getAllTabsForBrowser(name);
          if (allSharingTabs.length > 0) {
            console.log(`🎯 Found ${allSharingTabs.length} sharing tabs in ${p.name} without WebRTC`);
            threats.push({
              type: 'screen_sharing_tabs_detected',
              severity: allSharingTabs.length > 1 ? 'high' : 'medium',
              message: `${p.name} has ${allSharingTabs.length} tab${allSharingTabs.length > 1 ? 's' : ''} with screen sharing content`,
              details: { 
                pid: p.pid, 
                name: p.name,
                sharingTabs: allSharingTabs,
                tabCount: allSharingTabs.length,
                detectionMethod: 'direct_tab_scan'
              }
            });
          }
        } catch (e) {
          console.error(`❌ Direct tab check failed for ${p.name}:`, e);
        }
      }

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
      const [connections, proc] = await Promise.all([
        this.safe('net', () => si.networkConnections(), 3000),
        this.safe('processes', () => si.processes(), 20000)
      ]);
      const byPidProc = new Map((proc.list || []).map(p => [p.pid, p]));
      const procByPid = new Map((chromeProcesses || []).map(p => [p.pid, p]));
      // Remove generic browser health signals; only report active sharing indicators
      const byPid = new Map();
      const stunPorts = new Set([3478, 5349, 19302]);
      for (const c of (connections || [])) {
        if (c.protocol !== 'udp') continue;
        const pid = c.pid;
        if (!procByPid.has(pid)) continue;
        const owner = byPidProc.get(pid);
        if (owner && this.isSystemHelper(owner.name, owner.command)) continue;
        const isStunTurn = stunPorts.has(Number(c.localport)) || stunPorts.has(Number(c.peerport));
        const highPort = (c.localport > 30000 && c.localport < 65535) || (c.peerport > 30000 && c.peerport < 65535);
        if (!(highPort || isStunTurn)) continue;
        byPid.set(pid, (byPid.get(pid) || 0) + 1);
      }

      // Always try fallback methods as systeminformation UDP detection is unreliable
      console.log(`🔍 Trying fallback UDP detection methods...`);
      if (byPid.size === 0 || true) {
        if (process.platform === 'win32') {
          try {
            const { stdout } = await execAsync('netstat -ano -p udp');
            if (stdout && stdout.trim()) {
              const lines = stdout.split(/\r?\n/).slice(1);
              for (const line of lines) {
                const parts = line.trim().split(/\s+/);
                if (parts.length < 4) continue;
                const local = parts[1] || '';
                const pidStr = parts[parts.length - 1] || '';
                const pid = Number(pidStr) || 0;
                if (!procByPid.has(pid)) continue;
                const localPortStr = local.split(':')[1] || '0';
                const port = Number(localPortStr) || 0;
                const owner = byPidProc.get(pid);
                if (owner && this.isSystemHelper(owner.name, owner.command)) continue;
                if (port > 30000 || stunPorts.has(port)) {
                  byPid.set(pid, (byPid.get(pid) || 0) + 1);
                }
              }
            }
          } catch {}
        } else {
          // macOS/Linux - use lsof for UDP connections
          try {
            const { stdout } = await execAsync('lsof -nP -i UDP 2>/dev/null || true');
            console.log(`🔍 lsof UDP output lines: ${stdout ? stdout.split('\n').length : 0}`);
            if (stdout && stdout.trim()) {
              const lines = stdout.split(/\r?\n/).slice(1);
              let foundConnections = 0;
              for (const line of lines) {
                const cols = line.trim().split(/\s+/);
                if (cols.length < 9) continue;
                const pid = Number(cols[1]) || 0;
                const command = cols[0] || '';
                const nameCol = cols.slice(8).join(' ');
                
                // Extract port from the address column (usually like *:port or ip:port)
                let port = 0;
                const m = nameCol.match(/:(\d+)(?:->|$|\s)/);
                if (m) port = Number(m[1]);
                
                console.log(`🔍 UDP connection: ${command} (PID: ${pid}) port: ${port}`);
                
                // Check if this PID matches any of our browser processes
                if (procByPid.has(pid)) {
                  const owner = byPidProc.get(pid);
                  if (owner && this.isSystemHelper(owner.name, owner.command)) continue;
                  
                  // Count high ports and STUN/TURN ports
                  if (port > 30000 || stunPorts.has(port)) {
                    byPid.set(pid, (byPid.get(pid) || 0) + 1);
                    foundConnections++;
                    console.log(`✅ Counted UDP for PID ${pid} (${command}) port ${port} - total: ${byPid.get(pid)}`);
                  }
                }
              }
              console.log(`🔍 Found ${foundConnections} relevant UDP connections`);
            }
          } catch (e) {
            console.error(`❌ lsof UDP detection failed:`, e);
          }
        }
      }
      const now = Date.now();
      const sticky = this.sharingStickyMs || 0;
      console.log(`🔍 WebRTC detection found ${byPid.size} processes with UDP activity`);
      for (const [pid, count] of byPid) {
        const p = procByPid.get(pid);
        const name = p?.name || 'browser';
        const owner = byPidProc.get(pid);
        const cpu = Number(owner?.pcpu || 0);
        const lowerName = String(name || '').toLowerCase();
        console.log(`🔍 Checking PID ${pid}: ${name} (${count} UDP connections, ${cpu}% CPU)`);
        const isNativeMeetingApp = /zoom|teams|microsoft teams|webex|discord/.test(lowerName);
        // Heuristic:
        // - Browsers: substantial UDP traffic or UDP+CPU (likely a sharing tab)
        // - Native meeting apps: lower threshold since they multiplex fewer sockets
        const likelySharingBrowser = (count >= 10) || (count >= 4 && cpu >= 8);
        const likelySharingNative = (count >= 3) || (count >= 1 && cpu >= 5);
        let likelySharing = isNativeMeetingApp ? likelySharingNative : likelySharingBrowser;
        // Sticky: if recently detected for this PID, keep reporting for a short window
        const recent = this.recentSharingByPid.get(pid);
        if (!likelySharing && recent && (now - recent.timestamp < sticky)) {
          likelySharing = true;
        }
        let tabInfo = null;
        let allSharingTabs = [];
        try { 
          // Get comprehensive tab list for all browsers
          allSharingTabs = await this.getAllTabsForBrowser(lowerName);
          // Fallback to single tab detection if comprehensive method fails
          if (allSharingTabs.length === 0) {
            tabInfo = await this.resolveSharingTabInfoForBrowser(lowerName);
          }
        } catch {}
        
        // For browsers, require either comprehensive tab list or single tab info or substantial WebRTC activity
        const isChromiumBased = /(chrome|chromium|edge|brave|opera)/.test(lowerName);
        const hasTabEvidence = allSharingTabs.length > 0 || (tabInfo && tabInfo.title);
        console.log(`🔍 PID ${pid} (${name}): isNativeMeetingApp=${isNativeMeetingApp}, hasTabEvidence=${hasTabEvidence}, likelySharing=${likelySharing}, allSharingTabs=${allSharingTabs.length}, tabInfo=${!!tabInfo}`);
        if (!isNativeMeetingApp && !hasTabEvidence && !likelySharing) {
          console.log(`❌ PID ${pid} (${name}): Skipping - no evidence of sharing`);
          continue;
        }
        
        // Build comprehensive message with all sharing tabs
        let message = `${name} possible screen sharing via WebRTC`;
        let details = { pid, name, connections: count };
        
        if (allSharingTabs.length > 0) {
          // List all sharing tabs for non-Chromium browsers
          const tabTitles = allSharingTabs.map(tab => tab.title || tab.url || 'Unknown tab').slice(0, 3);
          message += ` (${allSharingTabs.length} sharing tab${allSharingTabs.length > 1 ? 's' : ''}: ${tabTitles.join(', ')})`;
          if (allSharingTabs.length > 3) message += ` +${allSharingTabs.length - 3} more`;
          details.sharingTabs = allSharingTabs;
          details.tabCount = allSharingTabs.length;
        } else if (tabInfo && tabInfo.title) {
          // Single tab info for Chromium browsers
          message += ` (tab: ${tabInfo.title})`;
          details.tabTitle = tabInfo.title;
          details.tabUrl = tabInfo.url;
        }
        
        threats.push({
          type: 'screen_sharing_process_webrtc',
          severity: allSharingTabs.length > 1 ? 'high' : 'medium',
          message,
          details
        });
        this.recentSharingByPid.set(pid, { timestamp: now });
      }
    } catch {}
    return threats;
  }

  async getAllTabsForBrowser(browserName) {
    const allTabs = [];
    const keywords = ['meet','zoom','teams','webex','discord','present','is presenting','sharing','share this tab','screen share','screenshare','sharing screen','sharing your screen','you are sharing','screen sharing','screen-sharing','jitsi','whereby','appear.in','hang','call','video call','conference'];
    const domains = this.screenSharingDomains || [];
    const matches = (text) => {
      const t = String(text || '').toLowerCase();
      return domains.some(d => t.includes(d)) || keywords.some(k => t.includes(k));
    };

    console.log(`🔍 getAllTabsForBrowser called for: ${browserName} on ${process.platform}`);

    try {
      if (process.platform === 'darwin') {
        if (browserName.includes('firefox')) {
          try {
            // Get all Firefox windows and tabs
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
            const { stdout } = await execAsync(`osascript -e '${script}'`);
            console.log(`🦊 Firefox AppleScript output:`, stdout);
            if (stdout && stdout.trim()) {
              // Parse AppleScript list format
              const tabData = stdout.trim();
              // Simple parsing for Firefox tabs - this is a basic implementation
              const tabMatches = tabData.match(/\{([^}]+)\}/g) || [];
              console.log(`🦊 Firefox tab matches found: ${tabMatches.length}`);
              for (const match of tabMatches) {
                const parts = match.slice(1, -1).split(', ');
                if (parts.length >= 2) {
                  const url = parts[0];
                  const title = parts[1];
                  const isSharing = matches(url) || matches(title);
                  console.log(`🦊 Firefox tab: ${title} | ${url} | sharing: ${isSharing}`);
                  if (isSharing) {
                    allTabs.push({ url, title, windowIndex: parts[2] || 1, tabIndex: parts[3] || 1, isSharing: true });
                  }
                }
              }
            }
          } catch {}
        }

        if (browserName.includes('safari')) {
          try {
            // Get all Safari tabs across all windows
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
            const { stdout } = await execAsync(`osascript -e '${script}'`);
            if (stdout && stdout.trim()) {
              const lines = stdout.trim().split('\n');
              for (const line of lines) {
                if (line.includes('|||')) {
                  const [url, title, windowIndex, tabIndex] = line.split('|||');
                  const isSharing = matches(url) || matches(title);
                  if (isSharing) {
                    allTabs.push({ url, title, windowIndex: Number(windowIndex) || 1, tabIndex: Number(tabIndex) || 1, isSharing: true });
                  }
                }
              }
            }
          } catch {}
        }

        // For Chromium browsers, get all tabs across all windows
        if (browserName.includes('chrome') || browserName.includes('chromium')) {
          try {
            const script = `
              tell application "Google Chrome"
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
            const { stdout } = await execAsync(`osascript -e '${script}'`);
            if (stdout && stdout.trim()) {
              const lines = stdout.trim().split('\n');
              for (const line of lines) {
                if (line.includes('|||')) {
                  const [url, title, windowIndex, tabIndex] = line.split('|||');
                  const isSharing = matches(url) || matches(title);
                  if (isSharing) {
                    allTabs.push({ url, title, windowIndex: Number(windowIndex) || 1, tabIndex: Number(tabIndex) || 1, isSharing: true });
                  }
                }
              }
            }
          } catch {}
        }

        if (browserName.includes('edge')) {
          try {
            const script = `
              tell application "Microsoft Edge"
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
            const { stdout } = await execAsync(`osascript -e '${script}'`);
            if (stdout && stdout.trim()) {
              const lines = stdout.trim().split('\n');
              for (const line of lines) {
                if (line.includes('|||')) {
                  const [url, title, windowIndex, tabIndex] = line.split('|||');
                  const isSharing = matches(url) || matches(title);
                  if (isSharing) {
                    allTabs.push({ url, title, windowIndex: Number(windowIndex) || 1, tabIndex: Number(tabIndex) || 1, isSharing: true });
                  }
                }
              }
            }
          } catch {}
        }
      } else if (process.platform === 'win32') {
        // Windows: Use PowerShell to enumerate browser windows and attempt to get tab info
        if (browserName.includes('firefox')) {
          try {
            // Get all Firefox windows
            const cmd = `powershell -NoProfile -Command "(Get-Process -Name firefox -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowTitle -ne '' -and $_.MainWindowHandle -ne 0} | ForEach-Object { $_.MainWindowTitle + '|||' + $_.Id })"`;
            const { stdout } = await execAsync(cmd);
            if (stdout && stdout.trim()) {
              const lines = stdout.trim().split('\n');
              for (const line of lines) {
                if (line.includes('|||')) {
                  const [title, pid] = line.split('|||');
                  const isSharing = matches(title);
                  if (isSharing) {
                    allTabs.push({ title, pid: Number(pid) || 0, isSharing: true });
                  }
                }
              }
            }
          } catch {}
        }
      } else {
        // Linux: Use wmctrl to get window information
        try {
          const { stdout } = await execAsync('wmctrl -lx 2>/dev/null || true');
          const lines = (stdout || '').split(/\r?\n/);
          for (const line of lines) {
            if (!line) continue;
            const lower = line.toLowerCase();
            if (browserName.includes('firefox') && lower.includes('firefox')) {
              const parts = line.trim().split(/\s+/);
              const title = parts.slice(4).join(' ');
              const windowId = parts[0];
              const isSharing = matches(title);
              if (isSharing) {
                allTabs.push({ title, windowId, isSharing: true });
              }
            } else if (browserName.includes('chrome') && (lower.includes('chrome') || lower.includes('chromium'))) {
              const parts = line.trim().split(/\s+/);
              const title = parts.slice(4).join(' ');
              const windowId = parts[0];
              const isSharing = matches(title);
              if (isSharing) {
                allTabs.push({ title, windowId, isSharing: true });
              }
            }
          }
        } catch {}
      }
    } catch (e) {
      console.error(`❌ getAllTabsForBrowser error for ${browserName}:`, e);
    }
    
    console.log(`📊 getAllTabsForBrowser returning ${allTabs.length} tabs for ${browserName}`);
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
        if (browserName.includes('chrome')) {
          try {
            const script = 'tell application "Google Chrome" to set _t to {URL, title} of active tab of front window\nreturn (item 1 of _t) & "|||" & (item 2 of _t)';
            const { stdout } = await execAsync(`osascript -e '${script}'`);
            const out = (stdout || '').trim();
            if (out && out.includes('|||')) {
              const [u, t] = out.split('|||');
              if (matches(u) || matches(t)) return { url: u, title: t };
            }
          } catch {}
        }
        if (browserName.includes('edge')) {
          try {
            const script = 'tell application "Microsoft Edge" to set _t to {URL, title} of active tab of front window\nreturn (item 1 of _t) & "|||" & (item 2 of _t)';
            const { stdout } = await execAsync(`osascript -e '${script}'`);
            const out = (stdout || '').trim();
            if (out && out.includes('|||')) {
              const [u, t] = out.split('|||');
              if (matches(u) || matches(t)) return { url: u, title: t };
            }
          } catch {}
        }
        if (browserName.includes('brave')) {
          try {
            const script = 'tell application "Brave Browser" to set _t to {URL, title} of active tab of front window\nreturn (item 1 of _t) & "|||" & (item 2 of _t)';
            const { stdout } = await execAsync(`osascript -e '${script}'`);
            const out = (stdout || '').trim();
            if (out && out.includes('|||')) {
              const [u, t] = out.split('|||');
              if (matches(u) || matches(t)) return { url: u, title: t };
            }
          } catch {}
        }
        if (browserName.includes('opera')) {
          try {
            const script = 'tell application "Opera" to set _t to {URL, title} of active tab of front window\nreturn (item 1 of _t) & "|||" & (item 2 of _t)';
            const { stdout } = await execAsync(`osascript -e '${script}'`);
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
            const { stdout } = await execAsync(`osascript -e '${script}'`);
            const out = (stdout || '').trim();
            if (out && out.includes('|||')) {
              const [u, t] = out.split('|||');
              if (matches(u) || matches(t)) return { url: u, title: t };
            }
          } catch {}
        }
        if (browserName.includes('firefox')) {
          try {
            // Try direct Firefox AppleScript first
            const script = 'tell application "Firefox" to set _t to {URL of active tab of front window, name of active tab of front window}\nreturn (item 1 of _t) & "|||" & (item 2 of _t)';
            const { stdout } = await execAsync(`osascript -e '${script}'`);
            const out = (stdout || '').trim();
            if (out && out.includes('|||')) {
              const [u, t] = out.split('|||');
              if (matches(u) || matches(t)) return { url: u, title: t };
            }
          } catch {
            // Fallback via System Events: get front window title of Firefox
            try {
              const script = 'tell application "System Events" to tell process "Firefox" to get name of front window';
              const { stdout } = await execAsync(`osascript -e '${script}'`);
              const title = (stdout || '').trim();
              if (title && matches(title)) return { title };
            } catch {}
          }
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
            // Try to get the active window title for the browser
            const cmd = `powershell -NoProfile -Command "(Get-Process -Name ${pn} -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowTitle -ne '' -and $_.MainWindowHandle -ne 0} | Sort-Object CPU -Descending | Select-Object -First 1 -ExpandProperty MainWindowTitle)"`;
            const { stdout } = await execAsync(cmd);
            const title = (stdout || '').trim();
            if (title && matches(title)) return { title };
            
            // For Firefox, try alternative approach using window enumeration
            if (pn === 'firefox') {
              try {
                const altCmd = `powershell -NoProfile -Command "Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; using System.Text; public class Win32 { [DllImport(\\"user32.dll\\")] public static extern IntPtr GetForegroundWindow(); [DllImport(\\"user32.dll\\")] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count); [DllImport(\\"user32.dll\\")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId); }'; $hwnd = [Win32]::GetForegroundWindow(); $pid = 0; [Win32]::GetWindowThreadProcessId($hwnd, [ref]$pid); $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue; if ($proc -and $proc.ProcessName -eq 'firefox') { $title = New-Object System.Text.StringBuilder 256; [Win32]::GetWindowText($hwnd, $title, $title.Capacity); $title.ToString() }"`;
                const { stdout: altOut } = await execAsync(altCmd);
                const altTitle = (altOut || '').trim();
                if (altTitle && matches(altTitle)) return { title: altTitle };
              } catch {}
            }
          } catch {}
        }
        return null;
      } else {
        // linux
        try {
          const { stdout } = await execAsync('wmctrl -lx 2>/dev/null || true');
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
        
        // Try browser-specific approaches for Firefox and others
        if (browserName.includes('firefox')) {
          try {
            // Get Firefox window titles specifically
            const { stdout } = await execAsync('wmctrl -l | grep -i firefox | head -1 | cut -d\' \' -f4- || true');
            const title = (stdout || '').trim();
            if (title && matches(title)) return { title };
          } catch {}
        }
        
        // Fallback to xdotool for active window title
        try {
          const { stdout } = await execAsync('xdotool getactivewindow getwindowname 2>/dev/null || true');
          const title = (stdout || '').trim();
          if (title && matches(title)) {
            // Double-check this is from a browser by checking the active window class
            try {
              const { stdout: windowClass } = await execAsync('xdotool getactivewindow getwindowclassname 2>/dev/null || true');
              const className = (windowClass || '').toLowerCase();
              if (className.includes('firefox') || className.includes('chrome') || className.includes('edge') || className.includes('brave') || className.includes('opera')) {
                return { title };
              }
            } catch {}
          }
        } catch {}
        return null;
      }
    } catch { return null; }
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
          const appDisplay = props['application.name'] || clientById.get(clientId)?.rawName || '';
          threats.push({
            type: 'screen_sharing_process_pipewire',
            severity: 'critical',
            message: `${appDisplay || 'Unknown app'} screencast active`,
            details: { pid: pid || undefined, name: appDisplay, appName: appDisplay, node: props['node.description'] || props['node.name'] || '' }
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
        this.safe('graphics', () => si.graphics(), 20000),
        this.safe('processes', () => si.processes(), 20000)
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
      const { stdout } = await this.safe('tcc', () => execAsync('sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT client FROM access WHERE service=\'kTCCServiceScreenCapture\' AND allowed=1;" 2>/dev/null || true'), 20000);
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
      const processes = await this.safe('processes', () => si.processes(), 20000);
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
        const proc = await this.safe('processes', () => si.processes(), 20000);
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

  // New: enumerate applications actively sharing screen (cross-OS best-effort)
  async checkScreenSharingApplicationsActive() {
    const threats = [];
    try {
      const proc = await this.safe('processes', () => si.processes(), 4000);
      const list = (proc.list || []);
      const candidates = ['chrome','chromium','msedge','edge','brave','firefox','safari','zoom','teams','microsoft teams','webex','meet','discord','slack','obs'];
      const seen = new Set();
      for (const p of list) {
        const name = (p.name || '').toLowerCase();
        const cmd = (p.command || '').toLowerCase();
        if (!name && !cmd) continue;
        if (this.isSystemHelper(name, cmd) || this.isInstallerContext(cmd)) continue;
        const match = candidates.find(c => name.includes(c) || cmd.includes(c));
        if (!match) continue;
        const key = match.includes('microsoft teams') ? 'teams' : match;
        if (seen.has(key)) continue;
        seen.add(key);
        const display = this.getDisplayNameForApp(match, p.name);
        threats.push({ type: 'screen_sharing_app_candidate', severity: 'low', message: `App capable of screen sharing detected: ${display}`, details: { pid: p.pid, name: p.name } });
      }

      // Linux PipeWire active screencast already handled; this consolidates per-app listing based on processes present
    } catch {}
    return threats;
  }

  // New: enumerate apps which have screen sharing permission (OS-specific)
  async checkScreenSharingPermissions() {
    const threats = [];
    try {
      if (process.platform === 'darwin') {
        // macOS TCC database for screen capture permission
        try {
          const { stdout } = await this.safe('tcc', () => execAsync('sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT client FROM access WHERE service=\'kTCCServiceScreenCapture\' AND allowed=1;" 2>/dev/null || true'), 3000);
          if (stdout && stdout.trim()) {
            const apps = stdout.trim().split('\n').filter(Boolean);
            for (const a of apps) threats.push({ type: 'screen_sharing_permission', severity: 'low', message: `App has screen recording permission: ${a}`, details: { name: a } });
          }
        } catch {}
      } else if (process.platform === 'win32') {
        // Windows: no single central permission; note capabilities based on running apps
        try {
          const proc = await this.safe('processes', () => si.processes(), 2000);
          const list = (proc.list || []);
          const apps = ['teams','msteams','microsoft teams','zoom','webex','chrome','edge','firefox','brave','obs','discord','slack'];
          const seen = new Set();
          for (const p of list) {
            const n = (p.name || '').toLowerCase();
            const c = (p.command || '').toLowerCase();
            const m = apps.find(x => n.includes(x) || c.includes(x));
            if (!m) continue; const key = m.includes('microsoft teams') ? 'teams' : m; if (seen.has(key)) continue; seen.add(key);
            threats.push({ type: 'screen_sharing_permission_inferred', severity: 'low', message: `Likely has screen sharing permission: ${p.name}`, details: { name: p.name } });
          }
        } catch {}
      } else {
        // Linux: permissions are session-portal scoped; list portal usage via PipeWire if present
        try {
          const pipe = await this.detectPipeWireScreencast();
          for (const t of pipe) threats.push({ type: 'screen_sharing_permission_inferred', severity: 'low', message: `Portal access detected: ${t.details?.name || 'Unknown'}`, details: { name: t.details?.name || '' } });
        } catch {}
      }
    } catch {}
    return threats;
  }

  getDisplayNameForApp(match, fallback) {
    const map = new Map([
      ['teams','Microsoft Teams'], ['microsoft teams','Microsoft Teams'], ['ms teams','Microsoft Teams'], ['msteams','Microsoft Teams'],
      ['zoom','Zoom'], ['skype','Skype'], ['webex','Webex'], ['discord','Discord'], ['slack','Slack'],
      ['chrome','Chrome'], ['chromium','Chromium'], ['edge','Edge'], ['msedge','Edge'], ['brave','Brave'], ['firefox','Firefox'], ['safari','Safari'], ['meet','Google Meet']
    ]);
    const key = String(match || '').toLowerCase();
    return map.get(key) || fallback || match || '';
  }
  async checkMessagingApplications() {
    const threats = [];
    try {
      const proc = await this.safe('processes', () => si.processes(), 4000);
      const apps = ['teams','microsoft teams','discord','slack','zoom','skype','webex'];
      for (const p of (proc.list || [])) {
        const name = (p.name || '').toLowerCase();
        const cmd = (p.command || '').toLowerCase();
        if (this.isSystemHelper(name, cmd) || this.isInstallerContext(cmd)) continue;
        const matched = apps.find(a => name.includes(a) || cmd.includes(a));
        if (!matched) continue;
        threats.push({
          type: 'messaging_app_detected',
          severity: 'medium',
          message: `Messaging/meeting app detected: ${p.name}`,
          details: { pid: p.pid }
        });
      }
    } catch {}
    return threats;
  }

  async runAllChecks(signatures) {
    console.log(`🔍 Starting runAllChecks...`);
    const results = await Promise.allSettled([
      this.checkRemoteControlApplications(),
      this.checkSuspiciousProcesses(),
      this.checkSuspiciousNetworkConnections(),
      this.checkScreenSharingIndicators(),
      this.analyzeNetworkTrafficPatterns(),
      this.detectActiveScreenCapture(),
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
      // Debug: Log all threats to identify AirPlayXPCHelper source
      if (t.message && t.message.toLowerCase().includes('airplay')) {
        console.log(`🚨 AirPlay threat detected:`, t);
      }
      const k = `${t.type}|${t.message}`;
      if (seen.has(k)) continue;
      seen.add(k);
      unique.push(t);
    }
    return unique;
  }
}

module.exports = SecurityService; 