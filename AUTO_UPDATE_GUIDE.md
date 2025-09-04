# Auto-Update Implementation Guide

## Overview

This document provides a comprehensive guide to the auto-update feature implemented in the TOPIN Companion application. The auto-update system allows users to receive and install application updates automatically through GitHub Releases.

## Architecture

### Components

1. **Main Process (`main.js`)**
   - `electron-updater` integration
   - Security validation
   - IPC handlers for update operations
   - Event handling and logging

2. **Renderer Process (`renderer.js`)**
   - Update UI components
   - User interaction handling
   - Progress tracking
   - Error display

3. **Security Module (`update-security.js`)**
   - URL validation
   - File integrity verification
   - Version comparison
   - Security event logging

4. **Configuration (`package.json`)**
   - GitHub Releases configuration
   - Build settings for all platforms
   - Update server settings

## Features

### ✅ Implemented Features

- **Automatic Update Checking**: Checks for updates on app startup and periodically
- **Manual Update Control**: Users can manually check for updates
- **Download Progress**: Real-time download progress with speed and percentage
- **Security Validation**: URL validation, file integrity checks, version verification
- **Error Handling**: Categorized error messages with user-friendly descriptions
- **Cross-Platform Support**: Works on Windows, macOS, and Linux
- **GitHub Integration**: Uses GitHub Releases as update server
- **User-Friendly UI**: Modal dialog with update information and controls

### 🔒 Security Features

- **HTTPS Enforcement**: All update downloads must use HTTPS
- **Domain Whitelisting**: Only allows downloads from trusted domains
- **File Extension Validation**: Ensures platform-appropriate file types
- **Version Verification**: Prevents downgrades and invalid versions
- **Integrity Checking**: SHA512 hash verification for downloaded files
- **Audit Logging**: Security events are logged for monitoring

## Usage

### For Users

1. **Automatic Updates**: The app automatically checks for updates when started
2. **Update Notification**: When an update is available, a green badge appears in the header
3. **Update Modal**: Click the badge or the app will show an update modal
4. **Download & Install**: Users can download and install updates with progress tracking
5. **Error Handling**: Clear error messages help users understand and resolve issues

### For Developers

#### Building and Releasing

1. **Update Version**: Increment version in `package.json`
2. **Create Release**: Use GitHub Actions or manual release process
3. **Test Updates**: Verify update flow works correctly

#### Testing Updates

```bash
# Build current version
yarn build:all

# Test update detection (requires higher version in GitHub Releases)
yarn start
```

## Configuration

### GitHub Repository Setup

The auto-update system is configured to use your GitHub repository:

```json
{
  "build": {
    "publish": {
      "provider": "github",
      "owner": "Akshat-nxtwave",
      "repo": "topin-companion-app"
    }
  }
}
```

### Environment Variables

Create a `.env` file with:

```env
# GitHub Personal Access Token
GH_TOKEN=your_github_token_here

# For macOS builds (optional)
APPLE_ID=your_apple_id
APPLE_PASSWORD=your_app_specific_password
APPLE_TEAM_ID=your_team_id
```

### Build Scripts

```bash
# Build for all platforms (local)
yarn build:all

# Publish to GitHub Releases
yarn publish:all

# Platform-specific builds
yarn publish:linux
yarn publish:win
yarn publish:mac
```

## Testing

### Local Testing

1. **Build Test Version**:
   ```bash
   # Update version in package.json to 0.1.1
   yarn build:all
   ```

2. **Create Test Release**:
   - Create a GitHub release with version 0.1.1
   - Upload the built files

3. **Test Update Flow**:
   - Install version 0.1.0
   - Start the app
   - Verify update detection and installation

### Automated Testing

The GitHub Actions workflow automatically:
- Builds for all platforms on tag push
- Creates GitHub releases
- Uploads artifacts

## Troubleshooting

### Common Issues

1. **Updates Not Detected**
   - Check GitHub repository configuration
   - Verify GitHub token permissions
   - Ensure release has correct version number

2. **Download Failures**
   - Check internet connection
   - Verify GitHub token has `repo` scope
   - Check file permissions

3. **Installation Failures**
   - Run as administrator (Windows)
   - Check code signing certificates
   - Verify file integrity

4. **Security Errors**
   - Check domain whitelist in `update-security.js`
   - Verify HTTPS URLs
   - Check file extension validation

### Debug Mode

Enable debug logging:

```bash
# Set environment variable
export ELECTRON_ENABLE_LOGGING=1

# Start app
yarn start
```

### Log Files

Security events are logged to console. In production, consider:
- Writing to secure log files
- Sending to monitoring service
- Implementing log rotation

## Security Considerations

### Best Practices

1. **Code Signing**: Sign all releases for trust verification
2. **HTTPS Only**: Never allow HTTP downloads
3. **Domain Validation**: Whitelist only trusted domains
4. **Version Verification**: Prevent downgrades and invalid versions
5. **Audit Logging**: Log all security events
6. **User Consent**: Always ask before downloading/installing

### Threat Mitigation

- **Man-in-the-Middle**: HTTPS enforcement
- **Malicious Updates**: Domain whitelisting and integrity checks
- **Version Rollback**: Version comparison validation
- **Unauthorized Access**: Token-based authentication

## API Reference

### Main Process IPC Handlers

- `app:checkForUpdates()` - Check for available updates
- `app:downloadUpdate()` - Download the latest update
- `app:installUpdate()` - Install downloaded update
- `app:getAppVersion()` - Get current app version

### Renderer Events

- `update-available` - New update is available
- `update-downloaded` - Update download completed
- `download-progress` - Download progress update
- `update-error` - Update error occurred

### Security Module Methods

- `validateUpdateUrl(url)` - Validate update URL
- `validateUpdateInfo(info)` - Validate update information
- `verifyFileIntegrity(filePath, hash)` - Verify file integrity
- `isNewerVersion(current, newer)` - Compare versions

## Future Enhancements

### Planned Features

- [ ] **Rollback Support**: Automatic rollback on startup failure
- [ ] **Delta Updates**: Download only changed files
- [ ] **Background Updates**: Download updates in background
- [ ] **Update Channels**: Beta/stable release channels
- [ ] **User Preferences**: Update frequency and notification settings

### Security Improvements

- [ ] **Certificate Pinning**: Pin GitHub certificates
- [ ] **Update Signing**: Sign update metadata
- [ ] **Rate Limiting**: Limit update check frequency
- [ ] **Network Validation**: Validate network security

## Support

For issues or questions:

1. Check this documentation
2. Review console logs for errors
3. Test with different network conditions
4. Verify GitHub repository settings
5. Contact development team

## Changelog

### v1.0.0 (Initial Implementation)
- Basic auto-update functionality
- GitHub Releases integration
- Security validation
- Cross-platform support
- User-friendly UI
- Error handling and logging
