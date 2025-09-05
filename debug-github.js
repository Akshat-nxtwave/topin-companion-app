#!/usr/bin/env node

/**
 * Debug script to check GitHub releases and update files
 */

const https = require('https');

console.log('🔍 Debugging GitHub releases and update files...\n');

// Test the actual URL that should be checked
const testUrl = 'https://github.com/Akshat-nxtwave/topin-companion-app/releases/latest/download/latest-mac.yml';
console.log('🔗 Testing URL:', testUrl);

// Try to fetch the latest-mac.yml file directly
console.log('\n🌐 Fetching latest-mac.yml...');

https.get(testUrl, (res) => {
  console.log('📊 Status Code:', res.statusCode);
  console.log('📋 Headers:', JSON.stringify(res.headers, null, 2));
  
  let data = '';
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    console.log('\n📄 Response body:');
    console.log('---');
    console.log(data);
    console.log('---');
    
    if (res.statusCode === 200) {
      console.log('\n✅ latest-mac.yml found on GitHub');
      
      // Parse the YAML content
      try {
        const lines = data.split('\n');
        const versionLine = lines.find(line => line.startsWith('version:'));
        if (versionLine) {
          const version = versionLine.split(':')[1].trim();
          console.log('📦 Latest version on GitHub:', version);
          console.log('📦 Current app version: 1.0.3');
          
          if (version !== '1.0.3') {
            console.log('✅ Update should be available!');
            console.log('🔍 The update mechanism should detect this version difference');
          } else {
            console.log('❌ No update available (same version)');
          }
        }
      } catch (error) {
        console.log('❌ Error parsing YAML:', error.message);
      }
    } else {
      console.log('❌ latest-mac.yml not found on GitHub');
      console.log('This means the GitHub release v1.0.6 is missing the update files');
      console.log('🔧 Solution: Upload the latest-mac.yml file to the GitHub release');
    }
  });
}).on('error', (error) => {
  console.log('❌ Error fetching URL:', error.message);
});

// Also test the GitHub API to see what releases exist
console.log('\n🔍 Checking GitHub releases via API...');

const apiUrl = 'https://api.github.com/repos/Akshat-nxtwave/topin-companion-app/releases';
https.get(apiUrl, (res) => {
  let data = '';
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    try {
      const releases = JSON.parse(data);
      console.log('\n📋 Available releases:');
      releases.forEach((release, index) => {
        console.log(`${index + 1}. ${release.tag_name} - ${release.name || 'No name'}`);
        console.log(`   Published: ${release.published_at}`);
        console.log(`   Assets: ${release.assets.length} files`);
        
        // List all assets
        if (release.assets.length > 0) {
          console.log('   Files:');
          release.assets.forEach(asset => {
            console.log(`     - ${asset.name} (${asset.size} bytes)`);
          });
        }
        
        // Check if latest-mac.yml exists in assets
        const hasLatestMac = release.assets.some(asset => asset.name === 'latest-mac.yml');
        console.log(`   Has latest-mac.yml: ${hasLatestMac ? '✅' : '❌'}`);
        
        if (index === 0) {
          console.log('   (This is the latest release)');
        }
        console.log('');
      });
    } catch (error) {
      console.log('❌ Error parsing GitHub API response:', error.message);
    }
  });
}).on('error', (error) => {
  console.log('❌ Error fetching GitHub API:', error.message);
});
