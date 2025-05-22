# Red Team MCP Examples

This directory contains examples showing how to integrate the Red Team MCP server with various LLMs and AI agents.

## Overview

The Red Team MCP server exposes the following tools to LLMs:

1. **`port_scan`** - Perform port scanning using masscan
2. **`scan_status`** - Get the status of a running or completed scan
3. **`list_scans`** - List all scan operations
4. **`cancel_scan`** - Cancel a running scan operation
5. **`validate_masscan`** - Validate that masscan is properly configured

## Examples

### 1. **Main Demo** (`clean_mcp_demo.py`) ⭐ **START HERE**
Comprehensive demonstration of MCP tool discovery concepts. This is the best example to understand how LLMs discover and use tools dynamically.

### 2. **Claude Desktop Integration** (`claude_config.json` + `CLAUDE_SETUP.md`)
Complete setup guide and configuration for using the Red Team MCP server with Claude Desktop.

### 3. **Example Configuration** (`config.json`)
Sample configuration file showing all available options.

## Quick Start

1. **Run the main demo:**
```bash
cd ai/red-team-mcp
source .venv/bin/activate
python examples/clean_mcp_demo.py
```

2. **Or start the MCP server manually:**
```bash
red-team-mcp --config test_config.json serve
```

## Tool Schemas

The LLM sees these tool definitions:

```json
{
  "name": "port_scan",
  "description": "Perform port scanning using masscan",
  "inputSchema": {
    "type": "object",
    "properties": {
      "target": {
        "type": "string",
        "description": "IP address or CIDR range to scan"
      },
      "ports": {
        "type": "string",
        "description": "Ports to scan (e.g., '80,443' or '1-1000')"
      },
      "scan_type": {
        "type": "string",
        "enum": ["tcp_syn", "tcp_connect", "udp", "tcp_ack", "tcp_window"]
      }
    },
    "required": ["target"]
  }
}
```

This allows the LLM to understand what tools are available and how to call them properly.
