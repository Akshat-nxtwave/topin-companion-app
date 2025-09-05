# Debug Logs Guide

## How to View Logs from Installed App

### Method 1: Developer Tools (Recommended)

1. **Open the installed app**
2. **Press `Cmd + Option + I`** (keyboard shortcut)
3. **Go to Console tab** to see all logs
4. **Look for update-related messages** with emojis:
   - 🔍 Checking for update...
   - ✅ Update available!
   - ❌ Update not available
   - ❌ Auto-updater error

### Method 2: Terminal Logs

Run the app from terminal to see console output:

```bash
# Navigate to the app
cd /Applications/TOPIN-Companion.app/Contents/MacOS

# Run with console output
./TOPIN-Companion
```

### Method 3: System Console

1. **Open Console.app** (Applications > Utilities > Console)
2. **Search for "TOPIN-Companion"** or "Electron"
3. **Look for update-related messages**

### Method 4: Environment Variable

Set environment variable to auto-open DevTools:

```bash
export TOPIN_OPEN_DEVTOOLS=1
open /Applications/TOPIN-Companion.app
```

## What to Look For

### Successful Update Detection:
```
🔍 Checking for update...
📡 Feed URL: https://github.com/Akshat-nxtwave/topin-companion-app/releases/latest/download/latest-mac.yml
📦 Current version: 1.0.3
✅ Update available!
📋 Update info: {
  "version": "1.0.6",
  "files": [...],
  "path": "TOPIN-Companion-1.0.6-mac-arm64.zip"
}
```

### No Update Available:
```
🔍 Checking for update...
📡 Feed URL: https://github.com/Akshat-nxtwave/topin-companion-app/releases/latest/download/latest-mac.yml
📦 Current version: 1.0.6
❌ Update not available
```

### Update Error:
```
🔍 Checking for update...
❌ Auto-updater error: [error message]
📋 Error details: {...}
```

## Troubleshooting

### If DevTools don't open:
1. Try `Cmd + Option + I` keyboard shortcut
2. Use environment variable method
3. Check if app is properly built

### If no logs appear:
1. Make sure you're running the installed app (not development)
2. Check if update checks are enabled in production mode
3. Verify the app is properly packaged

### Common Issues:
- **"not packed" error**: App is running in development mode
- **Network errors**: Check internet connection
- **URL errors**: Verify GitHub repository configuration
- **Version errors**: Check version numbers match
