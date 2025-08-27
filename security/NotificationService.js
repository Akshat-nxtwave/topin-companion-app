const path = require('path');
const os = require('os');
const fs = require('fs');
const { exec } = require('child_process');
const si = require('systeminformation');

// macOS 12+ (Monterey and later): system-wide Focus state database
const FOCUS_STATE_DB_PATH = '/private/var/db/DoNotDisturb/DB.json';

class NotificationService {
  constructor() {
    this.logging = true;
  }

  setLogging(enabled) {
    this.logging = !!enabled;
  }

  getLoggingStatus() {
    return !!this.logging;
  }

  #log(...args) {
    if (this.logging || true) {
      try { console.log('[NotificationService]', ...args); } catch {}
    }
  }

  async getNotificationStatus() {
    try {
      const supported = require('electron').Notification.isSupported();
      const sys = await this.#detectSystemNotificationSetting();
      this.#log('getNotificationStatus()', { supported, sys });
      const enabledLikely = String(sys.status || '').toLowerCase() === 'enabled';
      return { supported, enabledLikely, state: sys.status || 'unknown', details: sys.details || '' };
    } catch (e) {
      this.#log('getNotificationStatus() error', String(e));
      return { supported: false, enabledLikely: false, state: 'unknown', error: String(e) };
    }
  }

  async getFocusStatus() {
    try {
      const platform = process.platform;
      if (platform !== 'darwin') {
        // Windows Focus Assist detection
        if (platform === 'win32') {
          const windows = await this.#detectWindowsFocusStatus();
          if (windows) {
            this.#log('getFocusStatus windows', windows);
            return { platform: 'win32', supported: true, focus: windows.focusOn ? 'on' : 'off', details: windows.details, modes: windows.modes || [] };
          }
          return { platform: 'win32', supported: false, focus: 'unknown', details: 'Focus Assist detection not available' };
        }
        // Linux best-effort detection for common desktops (GNOME, KDE/Plasma, XFCE)
        if (platform === 'linux') {
          const linux = await this.#detectLinuxFocusStatus();
          if (linux) {
            this.#log('getFocusStatus linux', linux);
            return { platform: 'linux', supported: true, focus: linux.focusOn ? 'on' : 'off', details: linux.details, modes: linux.modes || [] };
          }
          return { platform: 'linux', supported: false, focus: 'unknown', details: 'Focus/DND detection not available for this desktop' };
        }
        return { platform, supported: false, focus: 'unknown', details: 'Focus mode detection only on macOS/Linux/Windows' };
      }
      // Prefer Assertions.json, then fallback to DB.json
      const viaAssertions = await this.#detectMacFocusViaAssertions();
      if (viaAssertions) { this.#log('getFocusStatus via Assertions', viaAssertions); return { platform: 'darwin', supported: true, focus: viaAssertions.focusOn ? 'on' : 'off', details: viaAssertions.details, modes: viaAssertions.modes || [] }; }
      const viaDb = await this.#detectMacFocusViaDb();
      if (viaDb) { this.#log('getFocusStatus via DB.json', viaDb); return { platform: 'darwin', supported: true, focus: viaDb.focusOn ? 'on' : 'off', details: viaDb.details, modes: viaDb.modes || (viaDb.mode ? [viaDb.mode] : []) }; }
      // Fallback: legacy defaults key; interpret DoNotDisturb=1 as Focus ON
      return await new Promise(resolve => {
        exec('/usr/bin/defaults -currentHost read com.apple.notificationcenterui doNotDisturb', (err, stdout) => {
          if (err) return resolve({ platform: 'darwin', supported: true, focus: 'unknown', details: 'defaults read failed' });
          const val = (stdout || '').trim();
          if (val === '1') return resolve({ platform: 'darwin', supported: true, focus: 'on', details: 'DoNotDisturb=1' });
          if (val === '0') return resolve({ platform: 'darwin', supported: true, focus: 'off', details: 'DoNotDisturb=0' });
          resolve({ platform: 'darwin', supported: true, focus: 'unknown', details: `DoNotDisturb=${val}` });
        });
      });
    } catch (e) {
      this.#log('getFocusStatus() error', String(e));
      return { platform: process.platform, supported: false, focus: 'unknown', details: String(e) };
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

    // Linux flow override: only enforce DND; do not report apps/browsers
    if (process.platform === 'linux') {
      return { system, browsers: [], processes: [] };
    }
    return { system, browsers, processes: filteredProcesses };
  }

  async #detectSystemNotificationSetting() {
    const platform = process.platform;
    const result = { platform, status: 'unknown', details: '' };
    // Prefer modern macOS Focus detection via Assertions.json when on darwin
    if (platform === 'darwin') {
      try {
        // Try Assertions.json first (matches shell logic), then DB.json
        const focus = await this.#detectMacFocusViaAssertions();
        if (focus) { this.#log('#detectSystemNotificationSetting darwin via Assertions', focus); return { platform: 'darwin', status: focus.focusOn ? 'disabled' : 'enabled', details: focus.details }; }
        const viaDb = await this.#detectMacFocusViaDb();
        if (viaDb) { this.#log('#detectSystemNotificationSetting darwin via DB.json', viaDb); return { platform: 'darwin', status: viaDb.focusOn ? 'disabled' : 'enabled', details: viaDb.details }; }
      } catch {}
    }
    if (platform === 'win32') {
      return new Promise(async (resolve) => {
        try {
          // First check if Focus Assist is enabled (which disables notifications)
          const focusStatus = await this.#detectWindowsFocusStatus();
          if (focusStatus && focusStatus.focusOn) {
            result.status = 'disabled';
            result.details = `Focus Assist: ${focusStatus.details}`;
            this.#log('#detectSystemNotificationSetting win32 focus', result);
            return resolve(result);
          }

          // Check basic notification settings
          exec('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" /v ToastEnabled', (err, stdout) => {
            if (err || !stdout) { 
              result.details = 'Registry query failed'; 
              return resolve(result); 
            }
            const m = stdout.match(/ToastEnabled\s+REG_DWORD\s+0x([0-9a-f]+)/i);
            if (m) { 
              const val = parseInt(m[1], 16); 
              result.status = val === 1 ? 'enabled' : 'disabled'; 
              result.details = `ToastEnabled=${val}`; 
            } else { 
              result.details = 'ToastEnabled not found'; 
            }
            this.#log('#detectSystemNotificationSetting win32', result);
            resolve(result);
          });
        } catch (e) {
          result.details = `Error: ${String(e)}`;
          resolve(result);
        }
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
          this.#log('#detectSystemNotificationSetting darwin fallback defaults', result);
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
        this.#log('#detectSystemNotificationSetting linux', result);
        resolve(result);
      });
    });
  }

  async #detectMacFocusViaAssertions() {
    try {
      const home = process.env.HOME || process.env.USERPROFILE || os.homedir();
      const assertionsPath = path.join(home, 'Library', 'DoNotDisturb', 'DB', 'Assertions.json');
      if (!fs.existsSync(assertionsPath)) return null;
      return await new Promise(resolve => {
        const cmd = `/usr/bin/plutil -convert json -o - ${assertionsPath}`;
        exec(cmd, { timeout: 1500 }, (err, stdout) => {
          if (err || !stdout) { this.#log('#detectMacFocusViaAssertions plutil error', String(err)); return resolve(null); }
          try {
            const data = JSON.parse(stdout);
            const entries = Array.isArray(data?.data) ? data.data : [];
            const first = entries.length ? entries[0] : null;
            const records = Array.isArray(first?.storeAssertionRecords) ? first.storeAssertionRecords : [];
            const last = records.length ? records[records.length - 1] : null;
            const modeIdentifier = last?.assertionDetails?.assertionDetailsModeIdentifier;
            // Only treat Do Not Disturb default as ON per requirement
            const isDndDefault = modeIdentifier === 'com.apple.donotdisturb.mode.default';
            // Map to friendly name (for display), but ON only if DND default
            const idLower = String(modeIdentifier || '').toLowerCase();
            let mode = '';
            if (idLower.includes('donotdisturb')) mode = 'Do Not Disturb';
            else if (idLower.includes('work')) mode = 'Work';
            else if (idLower.includes('personal')) mode = 'Personal';
            else if (idLower.includes('sleep')) mode = 'Sleep';
            if (!modeIdentifier) {
              const details = 'Focus=OFF (Assertions.json)';
              this.#log('#detectMacFocusViaAssertions OFF', { dataEntries: entries.length, records: records.length });
              return resolve({ platform: 'darwin', status: 'enabled', details, focusOn: false, modes: [] });
            }
            const details = `Focus=${isDndDefault ? 'ON' : 'OFF'} (Assertions.json) mode=${modeIdentifier}`;
            this.#log('#detectMacFocusViaAssertions MODE', { modeIdentifier, mapped: mode || modeIdentifier, isDndDefault });
            resolve({ platform: 'darwin', status: isDndDefault ? 'disabled' : 'enabled', details, focusOn: isDndDefault, modes: mode ? [mode] : [modeIdentifier] });
          } catch {
            this.#log('#detectMacFocusViaAssertions parse error');
            resolve(null);
          }
        });
      });
    } catch {
      this.#log('#detectMacFocusViaAssertions exception');
      return null;
    }
  }

  async #detectMacFocusViaDb() {
    try {
      if (!fs.existsSync(FOCUS_STATE_DB_PATH)) return null;
      const raw = fs.readFileSync(FOCUS_STATE_DB_PATH, 'utf8');
      const json = JSON.parse(raw);
      const entries = Array.isArray(json?.data) ? json.data : [];
      if (!entries.length) return { focusOn: false, details: 'DB.json: no data' };
      const latest = entries[0];
      const records = Array.isArray(latest.storeAssertionRecords) ? latest.storeAssertionRecords : [];
      if (!records.length) return { focusOn: false, details: 'DB.json: no active assertions' };
      const current = records[0];
      const modeIdentifier = current?.assertionDetails?.assertionDetailsModeIdentifier || '';
      let mode = 'Unknown';
      const idLower = String(modeIdentifier || '').toLowerCase();
      if (idLower.includes('donotdisturb')) mode = 'Do Not Disturb';
      else if (idLower.includes('work')) mode = 'Work Focus';
      else if (idLower.includes('personal')) mode = 'Personal';
      else if (idLower.includes('sleep')) mode = 'Sleep';
      const details = `Focus=ON (DB.json) mode=${mode} start=${current?.assertionStartDateTimestamp ?? ''}`;
      this.#log('#detectMacFocusViaDb', { modeIdentifier, mapped: mode });
      return { focusOn: true, mode, details };
    } catch {
      this.#log('#detectMacFocusViaDb exception');
      return null;
    }
  }

  async #detectLinuxFocusStatus() {
    try {
      const envDesktop = (process.env.XDG_CURRENT_DESKTOP || process.env.DESKTOP_SESSION || '').toLowerCase();
      const isGNOME = envDesktop.includes('gnome') || envDesktop.includes('unity') || envDesktop.includes('cinnamon');
      const isXFCE = envDesktop.includes('xfce');
      const isKDE = envDesktop.includes('kde') || envDesktop.includes('plasma');

      // GNOME/Cinnamon: gsettings show-banners=false => DND ON
      if (isGNOME) {
        return await new Promise(resolve => {
          exec('gsettings get org.gnome.desktop.notifications show-banners', (err, stdout) => {
            if (err || !stdout) return resolve(null);
            const val = (stdout || '').trim();
            const focusOn = (val === 'false');
            const details = `GNOME show-banners=${val}`;
            resolve({ focusOn, details, modes: ['Do Not Disturb'] });
          });
        });
      }

      // KDE/Plasma: kreadconfig5 kdeglobals Notifications DoNotDisturb=true => DND ON
      if (isKDE) {
        return await new Promise(resolve => {
          exec('kreadconfig5 --file kdeglobals --group Notifications --key DoNotDisturb 2>/dev/null', (err, stdout) => {
            if (err) return resolve(null);
            const val = (stdout || '').trim().toLowerCase();
            if (!val) return resolve(null);
            const focusOn = (val === 'true' || val === '1');
            const details = `KDE DoNotDisturb=${val}`;
            resolve({ focusOn, details, modes: ['Do Not Disturb'] });
          });
        });
      }

      // XFCE: xfconf-query -c xfce4-notifyd -p /do-not-disturb => true/false
      if (isXFCE) {
        return await new Promise(resolve => {
          exec('xfconf-query -c xfce4-notifyd -p /do-not-disturb 2>/dev/null', (err, stdout) => {
            if (err || !stdout) return resolve(null);
            const val = (stdout || '').trim().toLowerCase();
            const focusOn = (val === 'true' || val === '1');
            const details = `XFCE do-not-disturb=${val}`;
            resolve({ focusOn, details, modes: ['Do Not Disturb'] });
          });
        });
      }

      // Fallback: try GNOME schema even if desktop unknown
      return await new Promise(resolve => {
        exec('gsettings get org.gnome.desktop.notifications show-banners', (err, stdout) => {
          if (err || !stdout) return resolve(null);
          const val = (stdout || '').trim();
          const focusOn = (val === 'false');
          const details = `GNOME(show-banners)=${val}`;
          resolve({ focusOn, details, modes: ['Do Not Disturb'] });
        });
      });
    } catch {
      return null;
    }
  }

  async #detectWindowsFocusStatus() {
    try {
      // Method 1: Check Windows Focus Assist via WNF state data (most reliable)
      const wnfResult = await new Promise(resolve => {
        const wnfScript = `$source = @"
using System;
using System.Runtime.InteropServices;

public static class FocusAssistQuery {
    [StructLayout(LayoutKind.Sequential)]
    public struct WNF_STATE_NAME {
        public uint Data1;
        public uint Data2;
        public WNF_STATE_NAME(uint d1, uint d2) { Data1 = d1; Data2 = d2; }
    }

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtQueryWnfStateData(
        ref WNF_STATE_NAME StateName,
        IntPtr TypeId,
        IntPtr ExplicitScope,
        out uint ChangeStamp,
        out uint Buffer,
        ref uint BufferSize
    );

    public static int GetFocusAssistState() {
        var stateName = new WNF_STATE_NAME(0xA3BF1C75, 0x0D83063E); 
        uint changeStamp, buffer = 0, size = 4;
        int result = NtQueryWnfStateData(ref stateName, IntPtr.Zero, IntPtr.Zero, out changeStamp, out buffer, ref size);
        return result == 0 ? (int)buffer : -1;
    }
}
"@

Add-Type $source
$state = [FocusAssistQuery]::GetFocusAssistState()
Write-Output $state`;
        
        // Use a temporary file to avoid PowerShell escaping issues
        const tempScriptPath = path.join(os.tmpdir(), 'focus-assist-test.ps1');
        try {
          fs.writeFileSync(tempScriptPath, wnfScript, 'utf8');
          
          exec(`powershell -ExecutionPolicy Bypass -File "${tempScriptPath}"`, (err, stdout) => {
            // Clean up temp file
            try { fs.unlinkSync(tempScriptPath); } catch {}
            
            if (err) {
              this.#log('#detectWindowsFocusStatus WNF PowerShell error', String(err));
              return resolve(null);
            }
            
            if (!stdout) {
              this.#log('#detectWindowsFocusStatus WNF no output');
              return resolve(null);
            }
            
            try {
              const state = parseInt(stdout.trim(), 10);
              if (isNaN(state)) {
                this.#log('#detectWindowsFocusStatus WNF invalid output', stdout.trim());
                return resolve(null);
              }
              
              let focusOn = false;
              let details = '';
              let modes = [];
              
              switch (state) {
                case 0:
                  focusOn = false;
                  details = 'Windows Focus Assist: OFF (WNF)';
                  modes = ['Focus Assist'];
                  break;
                case 1:
                  focusOn = true;
                  details = 'Windows Focus Assist: ON - Priority only (WNF)';
                  modes = ['Focus Assist - Priority'];
                  break;
                case 2:
                  focusOn = true;
                  details = 'Windows Focus Assist: ON - Alarms only (WNF)';
                  modes = ['Focus Assist - Alarms'];
                  break;
                case -1:
                  // WNF query failed, fall through to other methods
                  this.#log('#detectWindowsFocusStatus WNF query failed');
                  return resolve(null);
                default:
                  focusOn = true;
                  details = `Windows Focus Assist: ON - Unknown state ${state} (WNF)`;
                  modes = ['Focus Assist'];
                  break;
              }
              
              this.#log('#detectWindowsFocusStatus WNF success', { state, focusOn, details });
              resolve({ focusOn, details, modes });
            } catch (e) {
              this.#log('#detectWindowsFocusStatus WNF parse error', String(e));
              resolve(null);
            }
          });
        } catch (e) {
          // Clean up temp file on error
          try { fs.unlinkSync(tempScriptPath); } catch {}
          this.#log('#detectWindowsFocusStatus WNF file write error', String(e));
          resolve(null);
        }
      });

      if (wnfResult) {
        return wnfResult;
      }

      // Method 2: Check registry for Focus Assist settings (fallback)
      const registryResult = await new Promise(resolve => {
        exec('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\CloudStore\\Store\\Cache\\DefaultAccount\\$$windows.data.notifications$$$$windows.data.notifications\\Current" /v Data', (err, stdout) => {
          if (err || !stdout) return resolve(null);
          // Focus Assist registry exists, check if enabled
          exec('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\CloudStore\\Store\\Cache\\DefaultAccount\\$$windows.data.notifications$$$$windows.data.notifications\\Current" /v Data', (err2, stdout2) => {
            if (err2 || !stdout2) return resolve(null);
            // Try to determine if Focus Assist is enabled by checking for specific patterns
            const data = stdout2.toLowerCase();
            if (data.includes('focusassist') || data.includes('donotdisturb')) {
              // Focus Assist is configured, assume it's enabled if we can't determine exact status
              const details = 'Windows Focus Assist: ON (Registry detected)';
              resolve({ focusOn: true, details, modes: ['Focus Assist'] });
            } else {
              resolve(null);
            }
          });
        });
      });

      if (registryResult) {
        return registryResult;
      }

      // Method 3: Check for Quiet Hours (older Windows versions)
      const quietHoursResult = await new Promise(resolve => {
        exec('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings" /v NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND', (err, stdout) => {
          if (err || !stdout) return resolve(null);
          const match = stdout.match(/NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND\s+REG_DWORD\s+0x([0-9a-f]+)/i);
          if (match) {
            const val = parseInt(match[1], 16);
            const focusOn = (val === 0); // 0 = notifications disabled (Quiet Hours ON)
            const details = `Windows Quiet Hours: ${focusOn ? 'ON' : 'OFF'} (0x${match[1]})`;
            resolve({ focusOn, details, modes: ['Quiet Hours'] });
          } else {
            resolve(null);
          }
        });
      });

      if (quietHoursResult) {
        return quietHoursResult;
      }

      // Method 4: Check notification center settings (final fallback)
      const notificationResult = await new Promise(resolve => {
        exec('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" /v ToastEnabled', (err, stdout) => {
          if (err || !stdout) return resolve(null);
          const match = stdout.match(/ToastEnabled\s+REG_DWORD\s+0x([0-9a-f]+)/i);
          if (match) {
            const val = parseInt(match[1], 16);
            const focusOn = (val === 0); // 0 = notifications disabled (Focus ON)
            const details = `Windows Notifications: ${focusOn ? 'DISABLED' : 'ENABLED'} (ToastEnabled=0x${match[1]})`;
            resolve({ focusOn, details, modes: ['Do Not Disturb'] });
          } else {
            resolve(null);
          }
        });
      });

      if (notificationResult) {
        return notificationResult;
      }

      // No Focus Assist or DND detected
      return null;
    } catch (e) {
      this.#log('#detectWindowsFocusStatus exception', String(e));
      return null;
    }
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
    const excludeDrivers = (p) => {
      const n = p.nameLower || '';
      const c = p.command || '';
      if (n.includes('.driver') || c.includes('.driver') || n.includes('kext') || c.includes('kext') || c.includes('/library/audio/plug-ins/hal') || n.includes('coreaudio') || c.includes('coreaudio')) return true;
      // Exclude macOS AirPlay system helpers broadly
      if (n.includes('airplayxpchelper') || c.includes('airplayxpchelper') || n.includes('airplay') || c.includes('airplay')) return true;
      return false;
    };
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
    const appCandidates = [
      // Common communication/productivity apps
      'slack','discord','teams','ms-teams','msteams','microsoft teams','skype','zoom','whatsapp','telegram','signal','thunderbird','outlook','spotify','clickup'
    ];
    const excludeCmdPatterns = ['--type=renderer','--type=gpu-process','--type=utility','--type=zygote','--type=broker','crashpad','crashpad_handler','zygote','utility','broker','extension','devtools','headless'];
    const excludeDrivers = (p) => {
      const n = p.nameLower || '';
      const c = p.command || '';
      return n.includes('.driver') || c.includes('.driver') || n.includes('kext') || c.includes('kext') || c.includes('/library/audio/plug-ins/hal') || n.includes('coreaudio') || c.includes('coreaudio');
    };

    const list = (proc.list || []).map(p => ({ pid: p.pid, ppid: p.parentPid || p.ppid, name: String(p.name || ''), nameLower: String(p.name || '').toLowerCase(), path: p.path, user: p.user, cpu: Number.isFinite(p.pcpu) ? p.pcpu : 0, mem: Number.isFinite(p.pmem) ? p.pmem : 0, state: (p.state || '').toLowerCase(), command: String(p.command || '').toLowerCase() }));

    const candidates = list.filter(p => {
      // Exclude obvious system placeholders/names
      const sysName = p.nameLower === 'win32' || p.nameLower === 'darwin';
      if (sysName) return false;
      // Exclude crashpad helpers from candidate list; will only be considered if not system and explicitly matched later
      if (p.nameLower.includes('crashpad') || p.command.includes('crashpad')) return false;
      const isBrowser = browserCandidates.some(c => p.nameLower.includes(c) || p.command.includes(c));
      const matchedApp = appCandidates.find(c => p.nameLower.includes(c) || p.command.includes(c));
      const isApp = Boolean(matchedApp);
      if (!isBrowser && !isApp) return false;
      // Always include recognized UI apps (WhatsApp/Telegram/etc.) even if helper processes have renderer/gpu flags
      if (isApp) return true;
      // For browsers and others, exclude known helper/utility processes
      if (excludeCmdPatterns.some(x => p.command.includes(x) || p.nameLower.includes(x))) return false;
      // Exclude webview helpers always
      if (p.nameLower.includes('webview') || p.command.includes('webview')) return false;
      // Exclude CoreAudio/driver/kext processes to avoid false positives
      if (excludeDrivers(p)) return false;
      // Updater/Update helpers: keep only if they clearly launch a known app (e.g., Update.exe --processStart "Teams.exe")
      const isUpdaterProc = p.nameLower.includes('updater') || p.command.includes('updater') || p.nameLower.includes('update.exe') || (/\\update\.exe/.test(p.command));
      if ((p.nameLower.includes('update') || isUpdaterProc)) {
        if (matchedApp) {
          // Tag normalized app for downstream grouping/name
          p._normalizedApp = matchedApp;
        } else {
          return false;
        }
      }
      // For browsers, keep only meaningfully active ones
      const isActiveBrowser = (p.cpu >= 0.5) || (p.mem >= 1) || ['running','r'].includes(p.state) || p.state === '';
      return isActiveBrowser;
    });

    const groups = new Map();
    for (const p of candidates) {
      let key = 'other:' + p.nameLower;
      for (const b of browserCandidates) if (p.nameLower.includes(b) || p.command.includes(b)) { key = 'browser:' + b; break; }
      // Prefer normalized app tag if assigned (e.g., Update.exe launching Teams)
      if (p._normalizedApp) {
        key = 'app:' + p._normalizedApp;
      } else {
        for (const a of appCandidates) if (p.nameLower.includes(a) || p.command.includes(a)) { key = 'app:' + a; }
      }
      const prev = groups.get(key);
      if (!prev || p.cpu > prev.cpu) groups.set(key, p);
    }

    const normalizeDisplayName = (p) => {
      const map = new Map([
        ['ms-teams','Microsoft Teams'], ['msteams','Microsoft Teams'], ['microsoft teams','Microsoft Teams'], ['teams','Microsoft Teams'],
        ['slack','Slack'], ['discord','Discord'], ['skype','Skype'], ['zoom','Zoom'], ['whatsapp','WhatsApp'], ['telegram','Telegram'], ['signal','Signal'], ['thunderbird','Thunderbird'], ['outlook','Outlook'], ['spotify','Spotify'], ['clickup','ClickUp']
      ]);
      const fromTag = p._normalizedApp && map.get(p._normalizedApp);
      if (fromTag) return fromTag;
      for (const [k, v] of map.entries()) if ((p.nameLower || '').includes(k) || (p.command || '').includes(k)) return v;
      return p.name || 'unknown';
    };
    return Array.from(groups.values()).map(p => ({
      pid: p.pid,
      name: normalizeDisplayName(p),
      path: p.path,
      cpu: p.cpu,
      mem: p.mem,
      state: p.state,
      backgroundLikely: (p.state.includes('sleep') && (p.cpu || 0) < 1) && !appCandidates.some(a => (p.nameLower || '').includes(a) || (p.command || '').includes(a))
    }));
  }

  async #detectAppNotificationsEnabled(processes) {
    const present = new Set();
    for (const p of processes || []) {
      const n = String(p.name || '').toLowerCase();
      if (n.includes('slack')) present.add('slack');
      if (n.includes('teams') || n.includes('microsoft teams') || n.includes('ms-teams') || n.includes('msteams')) present.add('teams');
      if (n.includes('discord')) present.add('discord');
      if (n.includes('skype')) present.add('skype');
      if (n.includes('zoom')) present.add('zoom');
      if (n.includes('whatsapp')) present.add('whatsapp');
      if (n.includes('telegram')) present.add('telegram');
      if (n.includes('signal')) present.add('signal');
      if (n.includes('thunderbird')) present.add('thunderbird');
      if (n.includes('outlook')) present.add('outlook');
      if (n.includes('spotify')) present.add('spotify');
      if (n.includes('clickup')) present.add('clickup');
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