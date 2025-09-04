# Release Instructions

## Prerequisites

1. **GitHub Personal Access Token**
   - Go to https://github.com/settings/tokens
   - Create a new token with scopes: `repo`, `write:packages`
   - Add it to your `.env` file as `GH_TOKEN=your_token_here`

2. **Code Signing (Optional but Recommended)**
   - **macOS**: Apple Developer account for code signing and notarization
   - **Windows**: Code signing certificate
   - **Linux**: No code signing required

## Creating a Release

### Method 1: Using GitHub Actions (Recommended)

1. Update version in `package.json`
2. Commit your changes
3. Create and push a tag:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
4. GitHub Actions will automatically build and create a release

### Method 2: Manual Release

1. Build for all platforms:
   ```bash
   yarn publish:all
   ```

2. Or build for specific platforms:
   ```bash
   yarn publish:linux    # Linux only
   yarn publish:win      # Windows only
   yarn publish:mac      # macOS only
   ```

3. Upload the files from `dist/` folder to GitHub Releases

## Testing Updates

1. **Local Testing**:
   - Build a version with a higher version number
   - Install the older version
   - The app should detect and offer the update

2. **Production Testing**:
   - Create a beta release with a higher version
   - Test with a small group of users
   - Monitor update success rates

## Update Flow

1. App checks for updates on startup and periodically
2. When update is available, user sees notification
3. User can download and install the update
4. App restarts with new version

## Troubleshooting

- **Updates not detected**: Check GitHub repository configuration
- **Download fails**: Verify GitHub token permissions
- **Install fails**: Check code signing certificates
- **App doesn't restart**: Ensure proper permissions

## Security Notes

- Always verify update signatures
- Use HTTPS for update downloads
- Consider implementing update rollback
- Monitor for suspicious update activity
