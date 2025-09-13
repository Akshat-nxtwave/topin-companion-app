#!/bin/bash

# Build script for Mac with code signing
# This script sets up the environment to avoid repeated password prompts

echo "🔐 Setting up code signing environment..."

# Set the certificate identity
export CSC_IDENTITY="topin-certificate"

# Disable notarization for local testing
export CSC_NOTARIZE=false

# Additional environment variables to prevent password prompts
export CSC_LINK=""
export CSC_KEY_PASSWORD=""

# Enable signing for all distribution formats
export CSC_DMG_SIGN=true
export CSC_ZIP_SIGN=true

# Set the keychain to use (optional, uses default if not set)
# export CSC_KEYCHAIN="login.keychain"

# Build the app
echo "🏗️  Building Mac app with code signing..."
yarn build:mac

echo "✅ Build complete!"
