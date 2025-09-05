#!/usr/bin/env node

/**
 * Test script to verify update detection
 * Run this with the built app to test update mechanism
 */

const { app, autoUpdater } = require('electron');

console.log('🧪 Testing update detection...\n');

// Set the same feed URL as in main.js
autoUpdater.setFeedURL({
  provider: 'github',
  owner: 'Akshat-nxtwave',
  repo: 'topin-companion-app',
  private: false
});

console.log('📡 Feed URL configured');
console.log('📦 Current app version:', app.getVersion());

// Set up event listeners
autoUpdater.on('checking-for-update', () => {
  console.log('🔍 Checking for update...');
});

autoUpdater.on('update-available', (info) => {
  console.log('✅ Update available!');
  console.log('📋 Update info:', JSON.stringify(info, null, 2));
});

autoUpdater.on('update-not-available', (info) => {
  console.log('❌ No update available');
  console.log('📋 Info:', JSON.stringify(info, null, 2));
});

autoUpdater.on('error', (error) => {
  console.log('❌ Update error:', error.message);
});

// Check for updates
console.log('\n🚀 Starting update check...');
autoUpdater.checkForUpdates().then(() => {
  console.log('✅ Update check initiated');
}).catch((error) => {
  console.log('❌ Update check failed:', error.message);
});

// Keep the process alive for a few seconds
setTimeout(() => {
  console.log('\n🏁 Test completed');
  process.exit(0);
}, 10000);
