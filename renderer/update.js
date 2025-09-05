// Update Page JavaScript - Handles all update-related functionality

let currentAppVersion = '';
let updateInfo = null;
let updateEventListeners = [];
let isCheckingForUpdates = false;

// Initialize update system
async function initUpdateSystem() {
  try {
    // Get current app version
    const versionInfo = await window.companion.getAppVersion();
    currentAppVersion = versionInfo.version;
    
    // Update UI with current version
    const currentVersionEl = document.getElementById('currentVersion');
    const currentVersionModalEl = document.getElementById('currentVersionModal');
    if (currentVersionEl) currentVersionEl.textContent = `v${currentAppVersion}`;
    if (currentVersionModalEl) currentVersionModalEl.textContent = currentAppVersion;
    
    // Set up update event listeners
    setupUpdateEventListeners();
    
    // Set up modal event listeners
    setupUpdateModalEvents();
    
    // Start checking for updates
    await checkForUpdates();
    
  } catch (error) {
    console.error('Failed to initialize update system:', error);
    showError('Failed to initialize update system: ' + error.message);
  }
}

function setupUpdateEventListeners() {
  updateEventListeners.push(
    window.companion.onUpdateAvailable((info) => {
      updateInfo = info;
      showUpdateAvailable();
    })
  );
  
  updateEventListeners.push(
    window.companion.onUpdateDownloaded((info) => {
      showUpdateDownloaded();
    })
  );
  
  updateEventListeners.push(
    window.companion.onDownloadProgress((progressObj) => {
      updateDownloadProgress(progressObj);
    })
  );
  
  updateEventListeners.push(
    window.companion.onUpdateError((error) => {
      showUpdateError(error);
    })
  );
  
  updateEventListeners.push(
    window.companion.onUpdateNotAvailable(() => {
      showUpdateNotAvailable();
    })
  );
}

function setupUpdateModalEvents() {
  const modal = document.getElementById('updateModal');
  const closeBtn = document.getElementById('closeUpdateModal');
  const downloadBtn = document.getElementById('downloadUpdateBtnModal');
  const installBtn = document.getElementById('installUpdateBtnModal');
  const skipBtn = document.getElementById('skipUpdateBtnModal');
  
  // Close modal
  closeBtn?.addEventListener('click', hideUpdateModal);
  
  // Download update
  downloadBtn?.addEventListener('click', async () => {
    try {
      downloadBtn.disabled = true;
      downloadBtn.textContent = 'Downloading...';
      document.getElementById('downloadProgressModal').style.display = 'block';
      
      const result = await window.companion.downloadUpdate();
      if (!result.success) {
        throw new Error(result.error);
      }
    } catch (error) {
      showUpdateError(error.message);
      downloadBtn.disabled = false;
      downloadBtn.textContent = 'Download Update';
      document.getElementById('downloadProgressModal').style.display = 'none';
    }
  });
  
  // Install update
  installBtn?.addEventListener('click', async () => {
    try {
      installBtn.disabled = true;
      installBtn.textContent = 'Installing...';
      
      const result = await window.companion.installUpdate();
      if (!result.success) {
        throw new Error(result.error);
      }
      
      showRestartMessage();
    } catch (error) {
      showUpdateError(error.message);
      installBtn.disabled = false;
      installBtn.textContent = 'Install & Restart';
    }
  });
  
  // Skip update
  skipBtn?.addEventListener('click', () => {
    hideUpdateModal();
    proceedToMainApp();
  });
  
  // Close modal when clicking outside
  modal?.addEventListener('click', (e) => {
    if (e.target === modal) {
      hideUpdateModal();
    }
  });
}

async function checkForUpdates() {
  if (isCheckingForUpdates) return;
  
  // Check if we're in development mode
  try {
    const isDev = await window.companion.isDevelopment();
    if (isDev) {
      console.log('🔧 Development mode: Skipping update check');
      updateStatus('Development Mode', 'Update checks are disabled in development.');
      
      // Auto-proceed to main app after 2 seconds in dev mode
      setTimeout(() => {
        proceedToMainApp();
      }, 2000);
      return;
    }
  } catch (error) {
    console.warn('Could not determine development mode:', error);
  }
  
  isCheckingForUpdates = true;
  updateStatus('Checking for updates...', 'Please wait while we check for the latest version.');
  
  try {
    const result = await window.companion.checkForUpdates();
    
    if (!result.success) {
      throw new Error(result.error);
    }
  } catch (error) {
    console.error('Update check failed:', error);
    showUpdateError(error.message);
  }
}

function updateStatus(title, message) {
  const statusEl = document.getElementById('updateStatus');
  const messageEl = document.getElementById('updateMessage');
  
  if (statusEl) statusEl.textContent = title;
  if (messageEl) messageEl.textContent = message;
}

function showUpdateAvailable() {
  isCheckingForUpdates = false;
  
  // Update status
  updateStatus('Update Available', 'A new version is available for download.');
  
  // Show update details
  const updateDetails = document.getElementById('updateDetails');
  const updateActions = document.getElementById('updateActions');
  const latestVersionEl = document.getElementById('latestVersion');
  const releaseNotesEl = document.getElementById('releaseNotes');
  const releaseNotesContent = document.getElementById('releaseNotesContent');
  
  if (updateDetails) updateDetails.style.display = 'block';
  if (updateActions) updateActions.style.display = 'block';
  
  if (latestVersionEl) latestVersionEl.textContent = `v${updateInfo?.version || 'Unknown'}`;
  
  if (updateInfo?.releaseNotes && releaseNotesEl && releaseNotesContent) {
    releaseNotesEl.style.display = 'block';
    releaseNotesContent.textContent = updateInfo.releaseNotes;
  }
  
  // Show download button
  const downloadBtn = document.getElementById('downloadUpdateBtn');
  if (downloadBtn) {
    downloadBtn.style.display = 'inline-block';
    downloadBtn.addEventListener('click', async () => {
      try {
        downloadBtn.disabled = true;
        downloadBtn.textContent = 'Downloading...';
        document.getElementById('downloadProgress').style.display = 'block';
        
        const result = await window.companion.downloadUpdate();
        if (!result.success) {
          throw new Error(result.error);
        }
      } catch (error) {
        showUpdateError(error.message);
        downloadBtn.disabled = false;
        downloadBtn.textContent = 'Download Update';
        document.getElementById('downloadProgress').style.display = 'none';
      }
    });
  }
  
  // Show skip button
  const skipBtn = document.getElementById('skipUpdateBtn');
  if (skipBtn) {
    skipBtn.style.display = 'inline-block';
    skipBtn.addEventListener('click', () => {
      proceedToMainApp();
    });
  }
  
  // Show modal
  const modal = document.getElementById('updateModal');
  const newVersionModalEl = document.getElementById('newVersionModal');
  const releaseNotesModalEl = document.getElementById('releaseNotesModal');
  
  if (newVersionModalEl) newVersionModalEl.textContent = updateInfo?.version || 'Unknown';
  if (releaseNotesModalEl) {
    releaseNotesModalEl.textContent = updateInfo?.releaseNotes || 'No release notes available.';
  }
  
  if (modal) modal.style.display = 'flex';
}

function showUpdateDownloaded() {
  const downloadBtn = document.getElementById('downloadUpdateBtn');
  const installBtn = document.getElementById('installUpdateBtn');
  const downloadProgress = document.getElementById('downloadProgress');
  
  // Hide download progress
  if (downloadProgress) downloadProgress.style.display = 'none';
  
  // Show install button
  if (downloadBtn) downloadBtn.style.display = 'none';
  if (installBtn) {
    installBtn.style.display = 'inline-block';
    installBtn.addEventListener('click', async () => {
      try {
        installBtn.disabled = true;
        installBtn.textContent = 'Installing...';
        
        const result = await window.companion.installUpdate();
        if (!result.success) {
          throw new Error(result.error);
        }
        
        showRestartMessage();
      } catch (error) {
        showUpdateError(error.message);
        installBtn.disabled = false;
        installBtn.textContent = 'Install & Restart';
      }
    });
  }
  
  // Update modal
  const downloadBtnModal = document.getElementById('downloadUpdateBtnModal');
  const installBtnModal = document.getElementById('installUpdateBtnModal');
  const downloadProgressModal = document.getElementById('downloadProgressModal');
  
  if (downloadProgressModal) downloadProgressModal.style.display = 'none';
  if (downloadBtnModal) downloadBtnModal.style.display = 'none';
  if (installBtnModal) installBtnModal.style.display = 'inline-block';
}

function updateDownloadProgress(progressObj) {
  const progressFill = document.getElementById('progressFill');
  const progressText = document.getElementById('progressText');
  const progressFillModal = document.getElementById('progressFillModal');
  const progressTextModal = document.getElementById('progressTextModal');
  
  if (progressFill) {
    progressFill.style.width = `${progressObj.percent}%`;
  }
  
  if (progressText) {
    const speed = formatBytes(progressObj.bytesPerSecond);
    const downloaded = formatBytes(progressObj.transferred);
    const total = formatBytes(progressObj.total);
    progressText.textContent = `Downloading... ${downloaded} / ${total} (${speed}/s)`;
  }
  
  if (progressFillModal) {
    progressFillModal.style.width = `${progressObj.percent}%`;
  }
  
  if (progressTextModal) {
    const speed = formatBytes(progressObj.bytesPerSecond);
    const downloaded = formatBytes(progressObj.transferred);
    const total = formatBytes(progressObj.total);
    progressTextModal.textContent = `Downloading... ${downloaded} / ${total} (${speed}/s)`;
  }
}

function showUpdateNotAvailable() {
  isCheckingForUpdates = false;
  
  updateStatus('Up to Date', 'You are running the latest version.');
  
  // Show continue button
  const continueBtn = document.getElementById('continueBtn');
  if (continueBtn) {
    continueBtn.style.display = 'inline-block';
    continueBtn.addEventListener('click', () => {
      proceedToMainApp();
    });
  }
  
  // Auto-proceed after 2 seconds
  setTimeout(() => {
    proceedToMainApp();
  }, 2000);
}

function showUpdateError(error) {
  isCheckingForUpdates = false;
  
  let errorMessage = error;
  if (typeof error === 'object' && error.message) {
    errorMessage = error.message;
  }
  
  updateStatus('Update Check Failed', 'An error occurred while checking for updates.');
  
  // Show error modal
  const errorModal = document.getElementById('errorModal');
  const errorMessageEl = document.getElementById('errorMessage');
  const continueErrorBtn = document.getElementById('continueErrorBtn');
  
  if (errorMessageEl) errorMessageEl.textContent = `Update Check Failed: ${errorMessage}`;
  if (errorModal) errorModal.style.display = 'flex';
  
  if (continueErrorBtn) {
    continueErrorBtn.addEventListener('click', () => {
      hideErrorModal();
      proceedToMainApp();
    });
  }
  
  // Auto-proceed after 5 seconds
  setTimeout(() => {
    hideErrorModal();
    proceedToMainApp();
  }, 5000);
}

function showRestartMessage() {
  // Hide all modals
  hideUpdateModal();
  hideErrorModal();
  
  // Show restart modal
  const restartModal = document.getElementById('restartModal');
  const quitAppBtn = document.getElementById('quitAppBtn');
  
  if (restartModal) restartModal.style.display = 'flex';
  
  if (quitAppBtn) {
    quitAppBtn.addEventListener('click', () => {
      window.close();
    });
  }
}

function hideUpdateModal() {
  const modal = document.getElementById('updateModal');
  if (modal) modal.style.display = 'none';
}

function hideErrorModal() {
  const modal = document.getElementById('errorModal');
  if (modal) modal.style.display = 'none';
}

function showError(message) {
  console.error(message);
  showUpdateError(message);
}

function proceedToMainApp() {
  // Navigate to main app (scan page)
  window.location.href = 'index.html';
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Initialize update system when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  initUpdateSystem();
});

// Clean up event listeners on page unload
window.addEventListener('beforeunload', () => {
  updateEventListeners.forEach(cleanup => {
    try { cleanup(); } catch {}
  });
  updateEventListeners = [];
});
