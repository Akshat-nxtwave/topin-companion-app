/**
 * Update Security Configuration
 * This module provides security validation for auto-updates
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class UpdateSecurity {
  constructor() {
    this.allowedDomains = [
      'github.com',
      'github-releases.githubusercontent.com',
      'api.github.com'
    ];
    
    this.requiredFileExtensions = {
      'win32': ['.exe', '.zip'],
      'darwin': ['.dmg', '.zip'],
      'linux': ['.AppImage', '.deb', '.rpm']
    };
  }

  /**
   * Validate update URL security
   * @param {string} url - The update URL to validate
   * @returns {boolean} - Whether the URL is safe
   */
  validateUpdateUrl(url) {
    try {
      const urlObj = new URL(url);
      
      // Check if domain is allowed
      if (!this.allowedDomains.includes(urlObj.hostname)) {
        console.warn(`Update URL domain not allowed: ${urlObj.hostname}`);
        return false;
      }
      
      // Ensure HTTPS
      if (urlObj.protocol !== 'https:') {
        console.warn('Update URL must use HTTPS');
        return false;
      }
      
      return true;
    } catch (error) {
      console.error('Invalid update URL:', error);
      return false;
    }
  }

  /**
   * Validate file extension for current platform
   * @param {string} filename - The filename to validate
   * @returns {boolean} - Whether the file extension is valid
   */
  validateFileExtension(filename) {
    const platform = process.platform;
    const allowedExtensions = this.requiredFileExtensions[platform] || [];
    
    const extension = path.extname(filename).toLowerCase();
    return allowedExtensions.includes(extension);
  }

  /**
   * Validate file extension for specific platform
   * @param {string} filename - The filename to validate
   * @param {string} platform - The platform to validate against
   * @returns {boolean} - Whether the file extension is valid
   */
  validateFileExtensionForPlatform(filename, platform) {
    const allowedExtensions = this.requiredFileExtensions[platform] || [];
    const extension = path.extname(filename).toLowerCase();
    return allowedExtensions.includes(extension);
  }

  /**
   * Validate update information structure
   * @param {Object} updateInfo - The update information object
   * @returns {boolean} - Whether the update info is valid
   */
  validateUpdateInfo(updateInfo) {
    if (!updateInfo || typeof updateInfo !== 'object') {
      return false;
    }

    // Required fields
    const requiredFields = ['version', 'files'];
    for (const field of requiredFields) {
      if (!updateInfo[field]) {
        console.warn(`Missing required field in update info: ${field}`);
        return false;
      }
    }

    // Validate version format (semantic versioning)
    const versionRegex = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$/;
    if (!versionRegex.test(updateInfo.version)) {
      console.warn(`Invalid version format: ${updateInfo.version}`);
      return false;
    }

    // Validate files array
    if (!Array.isArray(updateInfo.files) || updateInfo.files.length === 0) {
      console.warn('Update info must contain at least one file');
      return false;
    }

    // Validate each file
    for (const file of updateInfo.files) {
      if (!file.url || !file.sha512) {
        console.warn('Each file must have url and sha512');
        return false;
      }

      if (!this.validateUpdateUrl(file.url)) {
        return false;
      }

      // Extract filename from URL and validate extension
      const filename = path.basename(file.url);
      const hasValidExtension = this.validateFileExtensionForPlatform(filename, 'win32') ||
                               this.validateFileExtensionForPlatform(filename, 'darwin') ||
                               this.validateFileExtensionForPlatform(filename, 'linux');
      
      if (!hasValidExtension) {
        console.warn(`Invalid file extension for any platform: ${filename}`);
        return false;
      }
    }

    return true;
  }

  /**
   * Calculate file hash for verification
   * @param {string} filePath - Path to the file
   * @param {string} algorithm - Hash algorithm (default: sha512)
   * @returns {Promise<string>} - The file hash
   */
  async calculateFileHash(filePath, algorithm = 'sha512') {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash(algorithm);
      const stream = fs.createReadStream(filePath);
      
      stream.on('data', (data) => hash.update(data));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }

  /**
   * Verify file integrity
   * @param {string} filePath - Path to the downloaded file
   * @param {string} expectedHash - Expected SHA512 hash
   * @returns {Promise<boolean>} - Whether the file is valid
   */
  async verifyFileIntegrity(filePath, expectedHash) {
    try {
      if (!fs.existsSync(filePath)) {
        return false;
      }

      const actualHash = await this.calculateFileHash(filePath);
      return actualHash.toLowerCase() === expectedHash.toLowerCase();
    } catch (error) {
      console.error('Error verifying file integrity:', error);
      return false;
    }
  }

  /**
   * Check if update is newer than current version
   * @param {string} currentVersion - Current app version
   * @param {string} newVersion - New version to check
   * @returns {boolean} - Whether the new version is newer
   */
  isNewerVersion(currentVersion, newVersion) {
    try {
      const current = this.parseVersion(currentVersion);
      const newer = this.parseVersion(newVersion);
      
      for (let i = 0; i < 3; i++) {
        if (newer[i] > current[i]) return true;
        if (newer[i] < current[i]) return false;
      }
      
      return false; // Same version
    } catch (error) {
      console.error('Error comparing versions:', error);
      return false;
    }
  }

  /**
   * Parse version string to array of numbers
   * @param {string} version - Version string (e.g., "1.2.3")
   * @returns {Array<number>} - Array of version numbers
   */
  parseVersion(version) {
    return version.split('.').map(num => parseInt(num, 10) || 0);
  }

  /**
   * Log security event for audit trail
   * @param {string} event - Event type
   * @param {Object} data - Event data
   */
  logSecurityEvent(event, data) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      event,
      data,
      platform: process.platform,
      version: process.env.npm_package_version || 'unknown'
    };
    
    console.log(`[SECURITY] ${event}:`, logEntry);
    
    // In production, you might want to send this to a security monitoring service
    // or write to a secure log file
  }
}

module.exports = UpdateSecurity;
