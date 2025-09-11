# TOPIN Companion App - Architecture Diagram

## High-Level Application Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                    TOPIN COMPANION APP                                  │
│                                   (Electron v31)                                       │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                    MAIN PROCESS                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │                              main.js (1,362 lines)                             │   │
│  │  • Application lifecycle management                                             │   │
│  │  • IPC handlers (ipcMain.handle)                                               │   │
│  │  • Service orchestration                                                       │   │
│  │  • Window management                                                            │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                SECURITY SERVICES                                       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐                        │
│  │ SecurityService │  │NotificationService│  │  ExamModeService│                        │
│  │   (2,126 lines) │  │  (1,067 lines)  │  │  (1,339 lines) │                        │
│  │                 │  │                 │  │                 │                        │
│  │ • Threat detect │  │ • Focus mode    │  │ • Exam mode     │                        │
│  │ • Process scan  │  │ • Notifications │  │ • Environment   │                        │
│  │ • Network scan  │  │ • Cross-platform│  │ • Detection     │                        │
│  │ • Malicious DB  │  │ • macOS/Windows │  │ • Monitoring    │                        │
│  │                 │  │   /Linux        │  │                 │                        │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘                        │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              COMMUNICATION LAYER                                       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐                        │
│  │   EventBus.js   │  │  LocalServer.js │  │ RemoteClient.js │                        │
│  │                 │  │  (114 lines)    │  │  (94 lines)     │                        │
│  │ • Event routing │  │ • WebSocket     │  │ • Remote        │                        │
│  │ • IPC bridge    │  │   server        │  │   connections   │                        │
│  │ • Message bus   │  │ • Client comm   │  │ • External      │                        │
│  │                 │  │                 │  │   integration   │                        │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘                        │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                WORKER THREADS                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │                        autoScanWorker.js (49 lines)                            │   │
│  │  • Background scanning                                                          │   │
│  │  • Non-blocking operations                                                      │   │
│  │  • Continuous monitoring                                                        │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                PRELOAD SCRIPT                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │                           preload.js (46 lines)                               │   │
│  │  • Secure API bridge                                                           │   │
│  │  • Context isolation                                                           │   │
│  │  • IPC communication                                                           │   │
│  │  • Exposed methods:                                                            │   │
│  │    - getFocusStatus()                                                          │   │
│  │    - scan()                                                                    │   │
│  │    - auditNotifications()                                                      │   │
│  │    - runExamModeCheck()                                                        │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                RENDERER PROCESS                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │                              renderer.js (272 lines)                           │   │
│  │  • UI logic and interactions                                                   │   │
│  │  • API calls to main process                                                   │   │
│  │  • Real-time updates                                                           │   │
│  │  • Status display                                                              │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │                              index.html                                        │   │
│  │  • HTML structure                                                               │   │
│  │  • UI components                                                                │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │                              styles.css                                        │   │
│  │  • Application styling                                                          │   │
│  │  • Responsive design                                                            │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                    DATA FLOW                                           │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐    IPC Call    ┌─────────────┐    Service Call    ┌─────────────┐
│  Renderer   │ ──────────────► │    Main     │ ─────────────────► │  Security   │
│             │                │   Process   │                    │  Services   │
│ • UI Logic  │                │             │                    │             │
│ • User      │                │ • IPC       │                    │ • Threat    │
│   Actions   │                │   Handlers  │                    │   Detection │
│ • Status    │                │ • Service   │                    │ • System    │
│   Display   │                │   Manager   │                    │   Scanning  │
└─────────────┘                └─────────────┘                    └─────────────┘
       ▲                              │                                    │
       │                              │                                    │
       │        IPC Response          │                                    │
       │ ◄────────────────────────────┼────────────────────────────────────┘
       │                              │
       │                              ▼
       │                    ┌─────────────┐
       │                    │    Data     │
       │                    │             │
       │                    │ • malicious │
       │                    │   .json     │
       │                    │ • System    │
       │                    │   Info      │
       │                    │ • Config    │
       │                    └─────────────┘
       │
       └─────────────────────────────────────────────────────────────────────────────┐
                                                                                     │
┌─────────────┐    WebSocket    ┌─────────────┐    Background    ┌─────────────┐    │
│  External   │ ◄──────────────► │   Local     │ ◄──────────────► │   Worker    │    │
│  Clients    │                 │   Server    │                  │   Threads   │    │
│             │                 │             │                  │             │    │
│ • Browser   │                 │ • Real-time │                  │ • Auto      │    │
│   Extensions│                 │   Comm      │                  │   Scanning  │    │
│ • Remote    │                 │ • Message   │                  │ • Continuous│    │
│   Tools     │                 │   Routing   │                  │   Monitor   │    │
└─────────────┘                 └─────────────┘                  └─────────────┘    │
                                                                                     │
                                                                                     │
┌─────────────┐    File System    ┌─────────────┐    System APIs    ┌─────────────┐  │
│   Config    │ ◄────────────────► │   System    │ ◄────────────────► │   OS       │  │
│   Files     │                   │   Monitor   │                    │             │  │
│             │                   │             │                    │ • macOS     │  │
│ • malicious │                   │ • Process   │                    │   Focus     │  │
│   .json     │                   │   Scanning  │                    │ • Windows   │  │
│ • Settings  │                   │ • Network   │                    │   Focus     │  │
│             │                   │   Analysis  │                    │   Assist    │  │
└─────────────┘                   └─────────────┘                    │ • Linux     │  │
                                                                     │   DND       │  │
                                                                     └─────────────┘  │
                                                                                     │
                                                                                     └─┘
```

## Platform Support & Build Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                BUILD & DISTRIBUTION                                    │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐    electron-builder    ┌─────────────┐    Cross-Platform    ┌─────────────┐
│   Source    │ ─────────────────────► │    Build    │ ───────────────────► │  Packages   │
│   Code      │                        │   Process   │                      │             │
│             │                        │             │                      │ • Linux     │
│ • main.js   │                        │ • ASAR      │                      │   AppImage  │
│ • preload.js│                        │   Packing   │                      │   .deb      │
│ • renderer/ │                        │ • Resource  │                      │ • Windows   │
│ • security/ │                        │   Bundling  │                      │   .exe      │
│ • comm/     │                        │ • Platform  │                      │   .zip      │
│ • workers/  │                        │   Specific  │                      │ • macOS     │
│ • data/     │                        │   Builds    │                      │   .dmg      │
└─────────────┘                        └─────────────┘                      │   .zip      │
                                                                             └─────────────┘
```

## Key Features & Capabilities

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                CORE FEATURES                                           │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Security   │  │Notification │  │   Exam      │  │  Real-time  │  │  Cross-     │
│  Monitoring │  │  Detection  │  │   Mode      │  │  Scanning   │  │  Platform   │
│             │  │             │  │  Detection  │  │             │  │  Support    │
│ • Process   │  │ • Focus     │  │ • Environment│  │ • Background│  │ • Linux     │
│   Scanning  │  │   Mode      │  │   Analysis  │  │   Workers   │  │ • Windows   │
│ • Network   │  │ • DND       │  │ • Proctoring│  │ • Auto      │  │ • macOS     │
│   Analysis  │  │   Status    │  │   Detection │  │   Scanning  │  │             │
│ • Threat    │  │ • Cross-    │  │ • Monitoring│  │ • Continuous│  │ • Native    │
│   Detection │  │   Platform  │  │             │  │   Updates   │  │   Builds    │
│ • Malicious │  │             │  │             │  │             │  │             │
│   Patterns  │  │             │  │             │  │             │  │             │
└─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘
```

## Dependencies & Technologies

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              TECHNOLOGY STACK                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│   Electron  │  │System Info  │  │ WebSocket   │  │   Yarn      │  │   Git       │
│             │  │             │  │             │  │             │  │             │
│ • v31       │  │ • Process   │  │ • Real-time │  │ • Package   │  │ • Version   │
│ • IPC       │  │   Info      │  │   Comm      │  │   Manager   │  │   Control   │
│ • Context   │  │ • Network   │  │ • Client    │  │ • Lock      │  │ • History   │
│   Bridge    │  │   Info      │  │   Server    │  │   Files     │  │ • CI/CD     │
│ • Security  │  │ • Hardware  │  │ • Message   │  │ • Build     │  │             │
│   Model     │  │   Info      │  │   Routing   │  │   Scripts   │  │             │
└─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘
```

