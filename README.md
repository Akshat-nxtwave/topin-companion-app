## Companion App (Electron v28)

Minimal cross-platform desktop companion to monitor notifications status and scan for suspicious processes and connections.

### Run

```bash
npm install
npm start
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
Use `npm start` for development. Packaging can be added later (e.g. electron-builder) as needed for Windows, macOS, Linux. 