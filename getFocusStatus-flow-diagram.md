# getFocusStatus Flow Diagram

## Electron IPC Communication Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RENDERER PROCESS                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    renderer.js                                     │   │
│  │                                                                     │   │
│  │  async function setFocusStatus() {                                 │   │
│  │    const res = await window.companion.getFocusStatus();            │   │
│  │    // Update UI with focus status                                   │   │
│  │  }                                                                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 1. Call API
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PRELOAD SCRIPT                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      preload.js                                    │   │
│  │                                                                     │   │
│  │  contextBridge.exposeInMainWorld('companion', {                    │   │
│  │    getFocusStatus: () => ipcRenderer.invoke('app:getFocusStatus')  │   │
│  │  });                                                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 2. IPC Message
                                    │    Channel: 'app:getFocusStatus'
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            MAIN PROCESS                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        main.js                                     │   │
│  │                                                                     │   │
│  │  ipcMain.handle("app:getFocusStatus", async () =>                  │   │
│  │    notificationService.getFocusStatus()                            │   │
│  │  );                                                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 3. Call Service
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        NOTIFICATION SERVICE                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │              security/NotificationService.js                       │   │
│  │                                                                     │   │
│  │  async getFocusStatus() {                                          │   │
│                                                                   │   │
│  |                                                                    |    |
│  │  }                                                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 4. Return Result
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            MAIN PROCESS                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        main.js                                     │   │
│  │                                                                     │   │
│  │  // Returns the result from NotificationService                     │   │
│  │  // via IPC response                                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 5. IPC Response
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PRELOAD SCRIPT                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      preload.js                                    │   │
│  │                                                                     │   │
│  │  // Resolves the Promise with the result                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 6. Promise Resolution
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RENDERER PROCESS                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    renderer.js                                     │   │
│  │                                                                     │   │
│  │  // Receives the result and updates UI                              │   │
│  │  // Further execution continues                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Summary

1. **Renderer** calls `window.companion.getFocusStatus()`
2. **Preload** sends IPC message via `ipcRenderer.invoke('app:getFocusStatus')`
3. **Main Process** receives message via `ipcMain.handle('app:getFocusStatus')`
4. **NotificationService** detects platform-specific focus status
5. **Main Process** returns result via IPC response
6. **Preload** resolves Promise with result
7. **Renderer** receives result and updates UI

## Return Data Structure

```javascript
{
  platform: 'darwin' | 'win32' | 'linux',
  supported: boolean,
  focus: 'on' | 'off' | 'unknown',
  details: string,
  modes: string[]
}
```

## Key Technologies

- **IPC Communication**: `ipcRenderer.invoke()` ↔ `ipcMain.handle()`
- **Context Bridge**: Secure API exposure from preload to renderer
- **Platform Detection**: Cross-platform focus/DND status detection
- **Async/Await**: Promise-based communication pattern

