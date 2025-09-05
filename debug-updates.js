#!/usr/bin/env node

/**
 * Debug script to test update mechanism
 * This script helps debug why updates aren't being detected
 */

const { autoUpdater } = require('electron-updater');
const https = require('https');
const fs = require('fs');

console.log('🔍 Debugging update mechanism...\n');

// Set the same feed URL as in main.js
autoUpdater.setFeedURL({
  provider: 'github',
  owner: 'Akshat-nxtwave',
  repo: 'topin-companion-app'
});

console.log('📡 Update feed URL configured');
console.log('🔗 Checking GitHub releases...\n');

// Check what URL the updater is actually using
const feedUrl = autoUpdater.getFeedURL();
console.log('Feed URL:', feedUrl);

// Test the actual URL that should be checked
const testUrl = 'https://github.com/Akshat-nxtwave/topin-companion-app/releases/latest/download/latest-mac.yml';
console.log('Expected URL:', testUrl);

// Try to fetch the latest-mac.yml file directly
console.log('\n🌐 Testing direct URL fetch...');

https.get(testUrl, (res) => {
  console.log('Status Code:', res.statusCode);
  console.log('Headers:', res.headers);
  
  let data = '';
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    console.log('\n📄 Response body:');
    console.log(data);
    
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
