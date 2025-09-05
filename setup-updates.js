#!/usr/bin/env node

/**
 * Setup script for configuring auto-updates
 * This script helps configure the GitHub repository settings for auto-updates
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

console.log('🚀 Setting up auto-updates for TOPIN Companion...\n');

// Read current package.json
const packagePath = path.join(__dirname, 'package.json');
const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));

// Get GitHub repository info
let githubOwner = '';
let githubRepo = '';

try {
  // Try to get from git remote
  const gitRemote = execSync('git remote get-url origin', { encoding: 'utf8' }).trim();
  const match = gitRemote.match(/github\.com[:/]([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (match) {
    githubOwner = match[1];
    githubRepo = match[2];
  }
} catch (error) {
  console.log('⚠️  Could not detect GitHub repository from git remote');
}

// Prompt for GitHub repository info if not detected
if (!githubOwner || !githubRepo) {
  console.log('Please provide your GitHub repository information:');
  githubOwner = process.argv[2] || 'your-github-username';
  githubRepo = process.argv[3] || 'companion-app-topin';
  
  if (githubOwner === 'your-github-username') {
    console.log('\n❌ Please update the GitHub repository information in package.json:');
    console.log(`   - Change "your-github-username" to your actual GitHub username`);
    console.log(`   - Change "companion-app-topin" to your actual repository name`);
    console.log('\nOr run this script with: node setup-updates.js <username> <repo-name>');
    process.exit(1);
  }
}

console.log(`📦 Repository: ${githubOwner}/${githubRepo}`);

// Update package.json with correct GitHub info
packageJson.build.publish.owner = githubOwner;
packageJson.build.publish.repo = githubRepo;
packageJson.build.updater.url = `https://github.com/${githubOwner}/${githubRepo}/releases/`;

// Write updated package.json
fs.writeFileSync(packagePath, JSON.stringify(packageJson, null, 2));

console.log('✅ Updated package.json with GitHub repository information');

// Create .env.example for GitHub token
const envExample = `# GitHub Personal Access Token for publishing releases
# Create one at: https://github.com/settings/tokens
# Required scopes: repo, write:packages
GH_TOKEN=your_github_token_here

# For macOS builds (if building on macOS)
# APPLE_ID=your_apple_id
# APPLE_PASSWORD=your_app_specific_password
# APPLE_TEAM_ID=your_team_id
`;

fs.writeFileSync(path.join(__dirname, '.env.example'), envExample);
console.log('✅ Created .env.example file');

// Create release instructions
const releaseInstructions = `# Release Instructions

## Prerequisites

1. **GitHub Personal Access Token**
   - Go to https://github.com/settings/tokens
   - Create a new token with scopes: \`repo\`, \`write:packages\`
   - Add it to your \`.env\` file as \`GH_TOKEN=your_token_here\`

2. **Code Signing (Optional but Recommended)**
   - **macOS**: Apple Developer account for code signing and notarization
   - **Windows**: Code signing certificate
   - **Linux**: No code signing required

## Creating a Release

### Method 1: Using GitHub Actions (Recommended)

1. Update version in \`package.json\`
2. Commit your changes
3. Create and push a tag:
   \`\`\`bash
   git tag v1.0.0
   git push origin v1.0.0
   \`\`\`
4. GitHub Actions will automatically build and create a release

### Method 2: Manual Release

1. Build for all platforms:
   \`\`\`bash
   yarn publish:all
   \`\`\`

2. Or build for specific platforms:
   \`\`\`bash
   yarn publish:linux    # Linux only
   yarn publish:win      # Windows only
   yarn publish:mac      # macOS only
   \`\`\`

3. Upload the files from \`dist/\` folder to GitHub Releases

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
`;

fs.writeFileSync(path.join(__dirname, 'RELEASE_INSTRUCTIONS.md'), releaseInstructions);
console.log('✅ Created RELEASE_INSTRUCTIONS.md');

console.log('\n🎉 Auto-update setup complete!');
console.log('\nNext steps:');
console.log('1. Update your GitHub repository information in package.json');
console.log('2. Create a GitHub Personal Access Token');
console.log('3. Add the token to your .env file');
console.log('4. Test the release process');
console.log('\nSee RELEASE_INSTRUCTIONS.md for detailed instructions.');
