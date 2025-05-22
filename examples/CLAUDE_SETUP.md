# Claude Desktop Integration

This guide shows how to integrate the Red Team MCP server with Claude Desktop.

## Setup Instructions

1. **Copy the configuration file:**
   ```bash
   cp examples/claude_config.json ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```
   
   **Platform-specific paths:**
   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   - **Linux**: `~/.config/Claude/claude_desktop_config.json`

2. **Update the config path:**
   Edit the configuration file and update the path to your actual config file:
   ```json
   {
     "mcpServers": {
       "red-team-mcp": {
         "command": "red-team-mcp",
         "args": ["--config", "/full/path/to/your/config.json", "serve"],
         "env": {
           "REDTEAM_LOG_LEVEL": "INFO"
         }
       }
     }
   }
   ```

3. **Restart Claude Desktop**

4. **Verify integration:**
   Claude will now have access to these tools:
   - `port_scan`: Scan networks and hosts for open ports
   - `scan_status`: Check the status of running scans
   - `list_scans`: List all scan operations
   - `cancel_scan`: Cancel running scans
   - `validate_masscan`: Validate masscan installation

## Example Prompts

Once configured, you can use these prompts with Claude:

- "Can you scan 8.8.8.8 for common ports and tell me what services are running?"
- "Please perform a network scan of 192.168.1.0/24 to discover active hosts"
- "Scan the target 203.0.113.0/28 for web services (ports 80, 443, 8080, 8443)"
- "Check if there are any SSH servers running on 10.0.0.0/24"
- "Validate that masscan is properly configured"
- "List all previous scans and their results"

## Troubleshooting

- **Tools not appearing**: Check that the config file path is correct and Claude Desktop was restarted
- **Permission errors**: Ensure masscan sudo access is configured (see main SETUP.md)
- **Path issues**: Use absolute paths in the configuration file
