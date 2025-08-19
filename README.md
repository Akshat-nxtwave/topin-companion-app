## Companion App (Electron v28)

Minimal cross-platform desktop companion to monitor notifications status and scan for suspicious processes and connections.

### Run

```bash
yarn install
yarn start
```

### Features
- Check desktop notifications status and open OS settings
- System scan: processes and network connections via `systeminformation`
- Suspicious matching using `data/malicious.json` (editable)

### Malicious list
Edit `data/malicious.json` with arrays:
```json
{
  "processNames": ["anydesk", "teamviewer"],
  "ports": ["5938"],
  "domains": ["webrtc.example.com"],
  "packages": ["com.remote.control"]
}
```

### Build

Packaging is configured with `electron-builder`.

Steps:

```bash
# 1) Install deps
yarn install

# 2) Build distributables (all targets supported on your OS)
yarn dist

# Or target specific platforms
yarn build:linux      # AppImage, deb
yarn build:win        # nsis, zip (requires Wine/Mono on Linux)
yarn build:win:zip    # zip only (no Wine required, cross-platform)
yarn build:mac        # dmg, zip (requires macOS)
```

Outputs are written to `dist/`.

Notes:
- The app loads signatures from `data/malicious.json`. This file is bundled as an extra resource when packaged.
- Worker threads are unpacked to ensure they execute correctly when using ASAR.
- Windows builds on Linux:
  - For full installers (NSIS), install Wine/Mono first, e.g. on Ubuntu:
    - `sudo apt-get update && sudo apt-get install -y wine64 mono-devel`
  - Alternatively, produce a portable zip (no Wine needed): `yarn build:win:zip`