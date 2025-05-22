#!/bin/bash

# Red Team MCP - Sudo Setup Script
# This script helps configure sudo access for masscan

set -e

echo "Red Team MCP - Sudo Setup for masscan"
echo "======================================"
echo

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "Error: This script should not be run as root"
   echo "Please run as a regular user with sudo privileges"
   exit 1
fi

# Check if user has sudo access
if ! sudo -n true 2>/dev/null; then
    echo "Error: This script requires sudo privileges"
    echo "Please ensure your user has sudo access"
    exit 1
fi

# Detect masscan path
MASSCAN_PATH=""
if command -v masscan >/dev/null 2>&1; then
    MASSCAN_PATH=$(which masscan)
    echo "Found masscan at: $MASSCAN_PATH"
else
    echo "Error: masscan not found in PATH"
    echo "Please install masscan first:"
    echo "  macOS: brew install masscan"
    echo "  Ubuntu/Debian: sudo apt-get install masscan"
    echo "  CentOS/RHEL: sudo yum install masscan"
    exit 1
fi

# Get current username
USERNAME=$(whoami)

# Create sudoers entry
SUDOERS_ENTRY="$USERNAME ALL=(ALL) NOPASSWD: $MASSCAN_PATH"

echo
echo "This script will add the following line to sudoers:"
echo "  $SUDOERS_ENTRY"
echo
echo "This allows your user to run masscan with sudo without a password prompt."
echo

read -p "Do you want to continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Setup cancelled."
    exit 0
fi

# Check if entry already exists
if sudo grep -q "$SUDOERS_ENTRY" /etc/sudoers 2>/dev/null; then
    echo "Sudoers entry already exists. No changes needed."
    exit 0
fi

# Create temporary sudoers file
TEMP_SUDOERS=$(mktemp)
trap "rm -f $TEMP_SUDOERS" EXIT

# Copy current sudoers and add our entry
sudo cp /etc/sudoers "$TEMP_SUDOERS"
echo "$SUDOERS_ENTRY" >> "$TEMP_SUDOERS"

# Validate the sudoers file
if sudo visudo -c -f "$TEMP_SUDOERS" >/dev/null 2>&1; then
    # Copy the validated file back
    sudo cp "$TEMP_SUDOERS" /etc/sudoers
    echo "✓ Sudoers configuration updated successfully"
    echo
    echo "You can now run masscan with sudo without a password:"
    echo "  sudo $MASSCAN_PATH --version"
    echo
    echo "Test the Red Team MCP setup with:"
    echo "  red-team-mcp validate"
else
    echo "✗ Error: Invalid sudoers configuration"
    echo "The sudoers file was not modified for safety"
    exit 1
fi

echo
echo "Setup complete! You can now use Red Team MCP with masscan."
