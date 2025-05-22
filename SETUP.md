# Red Team MCP Setup Guide

This guide will help you set up the Red Team MCP server with proper permissions for masscan.

## Prerequisites

1. **Python 3.8+** installed
2. **masscan** installed
3. **sudo access** (for masscan raw socket operations)

## Installation

### 1. Install masscan

#### macOS (using Homebrew)
```bash
brew install masscan
```

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install masscan
```

#### CentOS/RHEL
```bash
sudo yum install masscan
# or
sudo dnf install masscan
```

### 2. Install Red Team MCP

```bash
# Clone or navigate to the project directory
cd ai/red-team-mcp

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install the package
pip install -e .
```

### 3. Configure sudo for masscan (Recommended)

For security scanning, masscan needs raw socket access, which requires root privileges. The recommended approach is to configure sudo to allow masscan without a password prompt.

#### Option A: NOPASSWD sudo for masscan (Recommended for development)

1. Edit the sudoers file:
```bash
sudo visudo
```

2. Add this line (replace `username` with your actual username):
```
username ALL=(ALL) NOPASSWD: /opt/homebrew/bin/masscan
```

For Linux systems, the path might be different:
```
username ALL=(ALL) NOPASSWD: /usr/bin/masscan
```

3. Save and exit the editor.

#### Option B: Use capabilities (Linux only)

On Linux systems, you can set capabilities instead of using sudo:

```bash
sudo setcap cap_net_raw+ep /usr/bin/masscan
```

Then configure the server to not use sudo:
```json
{
  "scanner": {
    "use_sudo": false,
    "masscan_path": "/usr/bin/masscan"
  }
}
```

#### Option C: Run server as root (NOT recommended for production)

```bash
sudo .venv/bin/red-team-mcp serve
```

## Configuration

### 1. Create a configuration file

```bash
red-team-mcp config-template -o config.json
```

### 2. Edit the configuration

Key settings to configure:

```json
{
  "scanner": {
    "masscan_path": "/opt/homebrew/bin/masscan",  // Path to masscan
    "use_sudo": true,                             // Use sudo for masscan
    "max_rate": 1000,                            // Max scan rate (packets/sec)
    "max_targets": 1000,                         // Max targets per scan
    "blocked_networks": [                        // Networks to block
      "127.0.0.0/8",
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ]
  },
  "security": {
    "log_level": "INFO",
    "require_auth": false
  }
}
```

### 3. Validate the setup

```bash
red-team-mcp --config config.json validate
```

## Testing

### 1. Test with localhost (requires allowing localhost in config)

Create a test config that allows localhost:

```json
{
  "scanner": {
    "masscan_path": "/opt/homebrew/bin/masscan",
    "use_sudo": true,
    "blocked_networks": [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ]
  }
}
```

### 2. Run a test scan

```bash
red-team-mcp --config test_config.json scan --target 127.0.0.1 --ports 22,80,443 --wait
```

### 3. Start the MCP server

```bash
red-team-mcp --config config.json serve
```

## Security Considerations

1. **Principle of Least Privilege**: Only grant sudo access to masscan, not all commands
2. **Network Restrictions**: Configure `blocked_networks` to prevent scanning internal networks
3. **Rate Limiting**: Set appropriate `max_rate` and `max_targets` to prevent network abuse
4. **Logging**: Enable logging to monitor scan activities
5. **Authentication**: Consider enabling `require_auth` for production deployments

## Troubleshooting

### Common Issues

1. **Permission denied errors**
   - Ensure sudo is configured correctly for masscan
   - Check that masscan path is correct
   - Verify user has sudo privileges

2. **Masscan not found**
   - Install masscan using your package manager
   - Update `masscan_path` in configuration
   - Ensure masscan is in PATH

3. **Network interface errors**
   - Masscan may need specific network interface configuration
   - Try running with `--interface` parameter in scan options

4. **Timeout errors**
   - Increase `timeout` value in scanner configuration
   - Reduce `max_rate` for slower networks
   - Check network connectivity

### Getting Help

1. Check logs for detailed error messages
2. Run validation: `red-team-mcp validate`
3. Test masscan directly: `sudo masscan --version`
4. Verify network connectivity to targets

## Production Deployment

For production deployments:

1. Use a dedicated service account
2. Enable authentication (`require_auth: true`)
3. Configure proper logging and monitoring
4. Set up network segmentation
5. Regular security audits of scan activities
6. Consider using capabilities instead of sudo on Linux
