const path = require('path');
const os = require('os');
const fs = require('fs');
const { exec } = require('child_process');
const si = require('systeminformation');

class NotificationService {
  async getNotificationStatus() {
    try {
      const supported = require('electron').Notification.isSupported();
      return { supported, enabledLikely: false, state: 'unknown' };
    } catch (e) {
      return { supported: false, enabledLikely: false, state: 'unknown', error: String(e) };
    }
  }

  async openNotificationSettings() {
    const platform = process.platform;
    try {
      const { shell } = require('electron');
      if (platform === 'darwin') { await shell.openExternal('x-apple.systempreferences:com.apple.preference.notifications'); return true; }
      if (platform === 'win32') { await shell.openExternal('ms-settings:notifications'); return true; }
      const envDesktop = (process.env.XDG_CURRENT_DESKTOP || '').toLowerCase();
      if (envDesktop.includes('gnome')) { await shell.openExternal('gnome-control-center notifications'); return true; }
      await shell.openExternal('https://wiki.archlinux.org/title/Desktop_notifications');
      return true;
    } catch (e) { return false; }
  }

  async auditNotifications() {
    const [system, browsers, processes] = await Promise.all([
      this.#detectSystemNotificationSetting(),
      this.#detectBrowserNotificationSettings(),
      this.#getNotifierProcesses()
    ]);

    // Only consider active (non-background) processes across all OSes
    const activeProcesses = (processes || []).filter(p => !p.backgroundLikely);

    // Build set of browsers with notifications enabled in any active profile
    const enabledBrowsers = new Set();
    for (const b of browsers || []) {
      if ((b.profiles || []).some(p => p.status === 'enabled')) {
        const name = String(b.browser || '').toLowerCase();
        if (name.includes('chrome')) enabledBrowsers.add('chrome');
        if (name.includes('chromium')) enabledBrowsers.add('chromium');
        if (name.includes('edge')) enabledBrowsers.add('msedge');
        if (name.includes('brave')) enabledBrowsers.add('brave');
        if (name.includes('firefox')) enabledBrowsers.add('firefox');
      }
    }

    // Detect non-browser app notification settings (best-effort)
    const enabledApps = await this.#detectAppNotificationsEnabled(activeProcesses);

    // Only keep non-system processes whose app has notifications enabled
    const systemUsers = new Set(['ROOT', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE']);
    const nameExcluded = (n) => {
      const x = String(n || '').toLowerCase();
      if (!x) return false;
      return x === 'win32' || x === 'darwin' || x.includes('crashpad');
    };
    const filteredProcesses = (activeProcesses || [])
      .filter(p => p && !systemUsers.has(String(p.user || '').toUpperCase()))
      .filter(p => !nameExcluded(p.name))
      .filter(p => {
        const n = String(p.name || '').toLowerCase();
        const isBrowserEnabled = (
          (enabledBrowsers.has('chrome') && n.includes('chrome') && !n.includes('chromium')) ||
          (enabledBrowsers.has('chromium') && n.includes('chromium')) ||
          (enabledBrowsers.has('msedge') && (n.includes('msedge') || n.includes('microsoft edge'))) ||
          (enabledBrowsers.has('brave') && n.includes('brave')) ||
          (enabledBrowsers.has('firefox') && n.includes('firefox'))
        );
        const isKnownAppEnabled = Array.from(enabledApps).some(a => n.includes(a));
        return isBrowserEnabled || isKnownAppEnabled;
      })
      .map(p => ({ ...p, notifEnabled: true }));

    return { system, browsers, processes: filteredProcesses };
  }

  async #detectSystemNotificationSetting() {
    const platform = process.platform;
    const result = { platform, status: 'unknown', details: '' };
    if (platform === 'win32') {
      return new Promise(resolve => {
        exec('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" /v ToastEnabled', (err, stdout) => {
          if (err || !stdout) { result.details = 'Registry query failed'; return resolve(result); }
          const m = stdout.match(/ToastEnabled\s+REG_DWORD\s+0x([0-9a-f]+)/i);
          if (m) { const val = parseInt(m[1], 16); result.status = val === 1 ? 'enabled' : 'disabled'; result.details = `ToastEnabled=${val}`; }
          else { result.details = 'ToastEnabled not found'; }
          resolve(result);
        });
      });
    }
    if (platform === 'darwin') {
      return new Promise(resolve => {
        exec('/usr/bin/defaults -currentHost read com.apple.notificationcenterui doNotDisturb', (err, stdout) => {
          if (err) { result.details = 'defaults read failed (Focus modes on newer macOS)'; return resolve(result); }
          const val = (stdout || '').trim();
          if (val === '1') { result.status = 'disabled'; result.details = 'DoNotDisturb=1'; }
          else if (val === '0') { result.status = 'enabled'; result.details = 'DoNotDisturb=0'; }
          else { result.details = `DoNotDisturb=${val}`; }
          resolve(result);
        });
      });
    }
    return new Promise(resolve => {
      exec('gsettings get org.gnome.desktop.notifications show-banners', (err, stdout) => {
        if (err || !stdout) { result.details = 'gsettings not available or schema not found'; return resolve(result); }
        const val = (stdout || '').trim();
        if (val === 'true') { result.status = 'enabled'; result.details = 'show-banners=true'; }
        else if (val === 'false') { result.status = 'disabled'; result.details = 'show-banners=false'; }
        else { result.details = `show-banners=${val}`; }
        resolve(result);
      });
    });
  }

  async #detectBrowserNotificationSettings() {
    const hints = await this.#buildActiveBrowserHints();
    const chromium = this.#detectChromiumBasedBrowsersActive(hints);
    const firefox = await this.#detectFirefoxBrowsersActive(hints);
    const safari = await this.#detectSafariActive(hints);
    return [...chromium, ...firefox, ...safari];
  }

  async #buildActiveBrowserHints() {
    const proc = await si.processes();
    const excludeCmdPatterns = ['--type=renderer','--type=gpu-process','--type=utility','--type=zygote','--type=broker','crashpad','crashpad_handler','zygote','utility','broker','extension','devtools','headless'];
    const list = (proc.list || []).map(p => ({ name: String(p.name || ''), cmd: String(p.command || ''), nameLower: String(p.name || '').toLowerCase(), cmdLower: String(p.command || '').toLowerCase(), cpu: Number(p.pcpu) || 0, mem: Number(p.pmem) || 0, state: String(p.state || '').toLowerCase() }));
    const isActive = (p) => (p.cpu >= 1) || (p.mem >= 1.5) || ['running','r'].includes(p.state);
    const notHelper = (p) => !excludeCmdPatterns.some(x => p.cmdLower.includes(x) || p.nameLower.includes(x));
    const notWebViewOrUpdater = (p) => !(p.nameLower.includes('webview') || p.cmdLower.includes('webview') || p.nameLower.includes('updater') || p.cmdLower.includes('updater') || p.nameLower.includes('update') || p.cmdLower.includes('update'));
    const hints = { chrome: [], msedge: [], brave: [], chromium: [], firefox: [], safari: false };
    for (const p of list) {
      if (!isActive(p) || !notHelper(p) || !notWebViewOrUpdater(p)) continue;
      const isChrome = p.nameLower.includes('chrome') && !p.nameLower.includes('chromium');
      const isChromium = p.nameLower.includes('chromium');
      const isEdge = p.nameLower.includes('msedge') || p.nameLower.includes('microsoft-edge');
      const isBrave = p.nameLower.includes('brave');
      const isFirefox = p.nameLower.includes('firefox');
      const isSafari = process.platform === 'darwin' && p.name.includes('Safari');
      if (isSafari) hints.safari = true;
      const userDataDir = this.#parseArgValue(p.cmdLower, '--user-data-dir') || this.#parseArgValue(p.cmdLower, '-user-data-dir');
      const profileDir = this.#parseArgValue(p.cmdLower, '--profile-directory') || this.#parseArgValue(p.cmdLower, '-profile-directory');
      const pushHint = (key) => { const entry = { userDataDir, profileDir }; const arr = hints[key]; if (!arr.find(e => e.userDataDir === entry.userDataDir && e.profileDir === entry.profileDir)) arr.push(entry); };
      if (isChrome) pushHint('chrome'); if (isChromium) pushHint('chromium'); if (isEdge) pushHint('msedge'); if (isBrave) pushHint('brave');
      if (isFirefox) { const profName = this.#parseArgValue(p.cmd, '-P') || this.#parseArgValue(p.cmdLower, '-p'); const profPath = this.#parseArgValue(p.cmd, '-profile') || this.#parseArgValue(p.cmdLower, '-profile'); const entry = { profileName: profName, profilePath: profPath }; const arr = hints.firefox; if (!arr.find(e => e.profileName === entry.profileName && e.profilePath === entry.profilePath)) arr.push(entry); }
    }
    return hints;
  }

  #parseArgValue(cmd, key) {
    const regex = new RegExp(`${key}=([^\s"']+)|${key}="([^"]+)"|${key}='([^']+)'|${key}\s+([^\s"']+)`, 'i');
    const m = cmd.match(regex);
    if (!m) return null;
    return (m[1] || m[2] || m[3] || m[4] || '').trim();
  }

  #readJsonSafe(filePath) {
    try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch { return null; }
  }

  #pathExists(p) { try { return fs.existsSync(p); } catch { return false; } }

  #readLocalStateProfiles(baseDir) {
    try {
      const fp = path.join(baseDir, 'Local State');
      const json = this.#readJsonSafe(fp) || {};
      const profiles = (((json.profile || {}).last_active_profiles) || []);
      if (Array.isArray(profiles) && profiles.length) return profiles;
      const single = (json.profile || {}).last_active_profile;
      return single ? [single] : [];
    } catch { return []; }
  }

  #resolveChromiumProfilePaths(browserKey, baseDir, hints) {
    const resolved = new Set();
    const add = (p) => { if (p) resolved.add(p); };
    const items = (hints[browserKey] || []);
    for (const h of items) {
      if (h.userDataDir && h.profileDir) add(path.join(h.userDataDir, h.profileDir));
      else if (h.profileDir) add(path.join(baseDir, h.profileDir));
      else if (h.userDataDir) add(path.join(h.userDataDir, 'Default'));
    }
    if (resolved.size === 0) for (const prof of this.#readLocalStateProfiles(baseDir)) add(path.join(baseDir, prof));
    return Array.from(resolved);
  }

  #detectChromiumBasedBrowsersActive(hints) {
    const home = process.env.HOME || process.env.USERPROFILE || os.homedir();
    const candidates = [];
    if (process.platform === 'win32') {
      const base = process.env.LOCALAPPDATA || '';
      candidates.push({ name: 'Chrome', key: 'chrome', base: path.join(base, 'Google', 'Chrome', 'User Data') });
      candidates.push({ name: 'Edge', key: 'msedge', base: path.join(base, 'Microsoft', 'Edge', 'User Data') });
      candidates.push({ name: 'Brave', key: 'brave', base: path.join(base, 'BraveSoftware', 'Brave-Browser', 'User Data') });
      candidates.push({ name: 'Chromium', key: 'chromium', base: path.join(base, 'Chromium', 'User Data') });
    } else if (process.platform === 'darwin') {
      const as = path.join(home, 'Library', 'Application Support');
      candidates.push({ name: 'Chrome', key: 'chrome', base: path.join(as, 'Google', 'Chrome') });
      candidates.push({ name: 'Edge', key: 'msedge', base: path.join(as, 'Microsoft Edge') });
      candidates.push({ name: 'Brave', key: 'brave', base: path.join(as, 'BraveSoftware', 'Brave-Browser') });
      candidates.push({ name: 'Chromium', key: 'chromium', base: path.join(as, 'Chromium') });
    } else {
      candidates.push({ name: 'Chrome', key: 'chrome', base: path.join(home, '.config', 'google-chrome') });
      candidates.push({ name: 'Chromium', key: 'chromium', base: path.join(home, '.config', 'chromium') });
      candidates.push({ name: 'Edge', key: 'msedge', base: path.join(home, '.config', 'microsoft-edge') });
      candidates.push({ name: 'Brave', key: 'brave', base: path.join(home, '.config', 'BraveSoftware', 'Brave-Browser') });
    }

    const results = [];
    for (const c of candidates) {
      if (!this.#pathExists(c.base)) continue;
      const profilePaths = this.#resolveChromiumProfilePaths(c.key, c.base, hints);
      if (profilePaths.length === 0) continue;
      const perProfiles = [];
      for (const pPath of profilePaths) {
        const prefPath = path.join(pPath, 'Preferences');
        const prefs = this.#readJsonSafe(prefPath) || {};
        const profileNode = prefs.profile || {};
        const defaultVals = (profileNode.default_content_setting_values || {});
        const managedDefaults = (profileNode.managed_default_content_settings || {});
        const exceptions = (((prefs.profile || {}).content_settings || {}).exceptions || {}).notifications
          || (((prefs || {}).profile || {}).content_setting_exceptions || {}).notifications
          || {};
        const globalDefault = Number(defaultVals.notifications);
        const managedDefault = Number(managedDefaults.notifications);
        const global = Number.isFinite(managedDefault) ? managedDefault : (Number.isFinite(globalDefault) ? globalDefault : undefined);
        let allowedSites = 0; let blockedSites = 0;
        try { for (const k of Object.keys(exceptions)) { const entry = exceptions[k]; const setting = Number(entry.setting); if (setting === 1) allowedSites++; else if (setting === 2) blockedSites++; } } catch {}
        let status = 'unknown';
        if (global === 2) status = 'disabled';
        else if (global === 1) status = 'enabled';
        else if (allowedSites > 0) status = 'enabled';
        else if (global === 0 || typeof global === 'undefined') status = 'ask';
        // Treat all 'ask' as enabled
        if (status === 'ask') status = 'enabled';
        perProfiles.push({ profile: path.basename(pPath), status, global: Number.isFinite(global) ? global : null, allowedSites, blockedSites });
      }
      if (perProfiles.length) results.push({ browser: c.name, profiles: perProfiles });
    }
    return results;
  }

  async #querySqlite(filePath, sql) {
    return new Promise(resolve => {
      const cmd = `sqlite3 -readonly "${filePath}" "${sql.replace(/"/g, '"')}"`;
      exec(cmd, { timeout: 1500 }, (err, stdout) => { if (err) return resolve(null); resolve(stdout || ''); });
    });
  }

  #getFirefoxProfilesIniPath() {
    const home = process.env.HOME || process.env.USERPROFILE || os.homedir();
    if (process.platform === 'win32') return path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Mozilla', 'Firefox', 'profiles.ini');
    if (process.platform === 'darwin') return path.join(home, 'Library', 'Application Support', 'Firefox', 'profiles.ini');
    return path.join(home, '.mozilla', 'firefox', 'profiles.ini');
  }

  #findFirefoxProfiles() {
    const profilesIni = this.#getFirefoxProfilesIniPath();
    if (!fs.existsSync(profilesIni)) return [];
    try { const ini = fs.readFileSync(profilesIni, 'utf8'); const dirs = []; for (const line of ini.split(/\r?\n/)) if (line.startsWith('Path=')) dirs.push(line.split('=')[1].trim()); const base = path.dirname(profilesIni); return dirs.map(rel => path.join(base, rel)); } catch { return []; }
  }

  #firefoxProfileLocked(profileDir) { try { return fs.existsSync(path.join(profileDir, 'parent.lock')); } catch { return false; } }

  #parseFirefoxPrefs(content) { const m = content.match(/permissions\.default\.desktop-notification"\s*,\s*(\d)\s*\)/); if (!m) return { status: 'ask', global: 0 }; const v = parseInt(m[1], 10); if (v === 2) return { status: 'disabled', global: 2 }; if (v === 1) return { status: 'enabled', global: 1 }; return { status: 'ask', global: 0 }; }

  async #detectFirefoxBrowsersActive(hints) {
    const explicit = []; for (const h of (hints.firefox || [])) if (h.profilePath) explicit.push(h.profilePath);
    const all = this.#findFirefoxProfiles();
    const locked = all.filter(p => this.#firefoxProfileLocked(p));
    const activeDirs = new Set([ ...explicit, ...locked ]);
    const perProfiles = [];
    for (const dir of activeDirs) {
      const permDb = path.join(dir, 'permissions.sqlite');
      let status = 'ask'; let allowedSites = 0; let blockedSites = 0; let global = null;
      if (fs.existsSync(permDb)) {
        try {
          const out = await this.#querySqlite(permDb, "SELECT type, permission FROM moz_perms WHERE type LIKE '%notification%';");
          if (out) {
            const lines = out.trim().split(/\r?\n/);
            for (const line of lines) {
              const parts = line.split('|');
              const perm = Number(parts[1]);
              if (perm === 1) allowedSites++; else if (perm === 2) blockedSites++;
            }
            if (allowedSites > 0) status = 'enabled'; else if (blockedSites > 0) status = 'ask';
          }
        } catch {}
      }
      if (status === 'ask') { const prefsPath = path.join(dir, 'prefs.js'); if (fs.existsSync(prefsPath)) { try { const text = fs.readFileSync(prefsPath, 'utf8'); const parsed = this.#parseFirefoxPrefs(text); status = parsed.status; global = parsed.global; } catch {} } }
      // Treat all 'ask' as enabled
      if (status === 'ask') status = 'enabled';
      perProfiles.push({ profile: path.basename(dir), status, global, allowedSites, blockedSites });
    }
    return perProfiles.length ? [{ browser: 'Firefox', profiles: perProfiles }] : [];
  }

  async #detectSafariActive(hints) { if (process.platform !== 'darwin') return []; if (!hints.safari) return []; return [{ browser: 'Safari', profiles: [{ profile: 'Default', status: 'unknown' }] }]; }

  async #getNotifierProcesses() {
    const proc = await si.processes();
    const browserCandidates = ['chrome','chromium','msedge','brave','firefox','opera'];
    const appCandidates = ['slack','discord','teams','skype','zoom','whatsapp','telegram','signal','thunderbird','outlook','spotify'];
    const excludeCmdPatterns = ['--type=renderer','--type=gpu-process','--type=utility','--type=zygote','--type=broker','crashpad','crashpad_handler','zygote','utility','broker','extension','devtools','headless'];

    const list = (proc.list || []).map(p => ({ pid: p.pid, ppid: p.parentPid || p.ppid, name: String(p.name || ''), nameLower: String(p.name || '').toLowerCase(), path: p.path, user: p.user, cpu: Number.isFinite(p.pcpu) ? p.pcpu : 0, mem: Number.isFinite(p.pmem) ? p.pmem : 0, state: (p.state || '').toLowerCase(), command: String(p.command || '').toLowerCase() }));

    const candidates = list.filter(p => {
      // Exclude obvious system placeholders/names
      const sysName = p.nameLower === 'win32' || p.nameLower === 'darwin';
      if (sysName) return false;
      // Exclude crashpad helpers from candidate list; will only be considered if not system and explicitly matched later
      if (p.nameLower.includes('crashpad') || p.command.includes('crashpad')) return false;
      const isBrowser = browserCandidates.some(c => p.nameLower.includes(c) || p.command.includes(c));
      const isApp = appCandidates.some(c => p.nameLower.includes(c) || p.command.includes(c));
      if (!isBrowser && !isApp) return false;
      if (excludeCmdPatterns.some(x => p.command.includes(x) || p.nameLower.includes(x))) return false;
      // Exclude webview/updater/update helpers
      if (p.nameLower.includes('webview') || p.command.includes('webview') || p.nameLower.includes('updater') || p.command.includes('updater') || p.nameLower.includes('update') || p.command.includes('update')) return false;
      const isActive = (p.cpu >= 0.5) || (p.mem >= 1) || ['running','r'].includes(p.state) || p.state === '';
      return isActive;
    });

    const groups = new Map();
    for (const p of candidates) {
      let key = 'other:' + p.nameLower;
      for (const b of browserCandidates) if (p.nameLower.includes(b) || p.command.includes(b)) { key = 'browser:' + b; break; }
      for (const a of appCandidates) if (p.nameLower.includes(a) || p.command.includes(a)) { key = 'app:' + a; }
      const prev = groups.get(key);
      if (!prev || p.cpu > prev.cpu) groups.set(key, p);
    }

    return Array.from(groups.values()).map(p => ({ pid: p.pid, name: p.name || 'unknown', path: p.path, cpu: p.cpu, mem: p.mem, state: p.state, backgroundLikely: p.state.includes('sleep') && (p.cpu || 0) < 1 }));
  }

  async #detectAppNotificationsEnabled(processes) {
    const present = new Set();
    for (const p of processes || []) {
      const n = String(p.name || '').toLowerCase();
      if (n.includes('slack')) present.add('slack');
      if (n.includes('teams') || n.includes('microsoft teams')) present.add('teams');
      if (n.includes('discord')) present.add('discord');
      if (n.includes('skype')) present.add('skype');
      if (n.includes('zoom')) present.add('zoom');
      if (n.includes('whatsapp')) present.add('whatsapp');
      if (n.includes('telegram')) present.add('telegram');
      if (n.includes('signal')) present.add('signal');
      if (n.includes('thunderbird')) present.add('thunderbird');
      if (n.includes('outlook')) present.add('outlook');
      if (n.includes('spotify')) present.add('spotify');
    }

    const enabled = new Set();

    // Best-effort checks for specific apps
    if (present.has('teams')) {
      try {
        const teamsEnabled = await this.#checkTeamsNotificationsEnabled();
        if (teamsEnabled) enabled.add('teams');
      } catch {}
    }

    if (present.has('slack')) {
      // Slack generally enables notifications by default; settings are stored in Local Storage which is not trivially accessible.
      // Treat as enabled when running.
      enabled.add('slack');
    }

    // Mark other present apps as enabled by default (heuristic) since most allow notifications by default
    for (const app of present) {
      if (!enabled.has(app)) enabled.add(app);
    }

    return enabled;
  }

  async #checkTeamsNotificationsEnabled() {
    try {
      const home = process.env.HOME || process.env.USERPROFILE || os.homedir();
      let base = '';
      if (process.platform === 'win32') base = path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Microsoft', 'Teams');
      else if (process.platform === 'darwin') base = path.join(home, 'Library', 'Application Support', 'Microsoft', 'Teams');
      else base = path.join(home, '.config', 'Microsoft', 'Teams');

      const candidates = [
        path.join(base, 'desktop-config.json'),
        path.join(base, 'settings.json')
      ];
      for (const fp of candidates) {
        if (!fs.existsSync(fp)) continue;
        try {
          const text = fs.readFileSync(fp, 'utf8');
          const json = JSON.parse(text);
          // Look for obvious disable flags
          const flattened = JSON.stringify(json).toLowerCase();
          if (flattened.includes('disablenotifications":true') || flattened.includes('muted":true') || flattened.includes('donotdisturb":true')) {
            return false;
          }
          return true;
        } catch {}
      }
    } catch {}
    // If unknown, assume enabled
    return true;
  }
}

module.exports = NotificationService; 