# Red Team Agno Agent

An AI-powered red team agent built with Agno that uses local Ollama with Qwen3 model and connects to the Red Team MCP server for intelligent red team operations through natural language interaction.

## Features

- 🤖 **Local AI** - Uses local Ollama with Qwen3 model (no API keys required)
- 🛡️ **Red Team Operations** - Intelligent network scanning and reconnaissance
- 🔌 **MCP Integration** - Connects to Red Team MCP server using Agno's built-in MCP client
- 🧠 **Reasoning** - Thinks through problems and provides analysis
- 💾 **Memory** - Remembers conversation history and context
- 🎨 **Rich Output** - Beautiful formatted output with colors and tables
- 🔍 **Natural Language** - Interact using plain English commands
- 🏠 **Privacy** - Everything runs locally, no data sent to external APIs

## Prerequisites

- Ollama installed and running locally
- Qwen3 model downloaded (`ollama pull qwen2.5:7b`)
- Red Team MCP server available

## Installation

```bash
# Install dependencies
pip install agno sqlalchemy

# Install the red-team-mcp package
pip install -e .
```

## Usage

### Start the Agent

```bash
# Run with default settings (qwen3, inline MCP server)
cd agent && python redteam_agent.py

# Use a different model
cd agent && python redteam_agent.py --model qwen2.5:7b

# Use custom Ollama host
cd agent && python redteam_agent.py --host http://192.168.1.100:11434

# With debug mode
cd agent && python redteam_agent.py --debug
```

### Natural Language Commands

The agent understands natural language requests. Here are some examples:

| Request | What it does |
|---------|-------------|
| "Scan 192.168.1.1 for common ports" | Performs a port scan on the target |
| "Check the status of my last scan" | Gets status of recent scans |
| "List all completed scans" | Shows all finished scan operations |
| "Validate that masscan is working" | Checks masscan installation |
| "Perform a TCP SYN scan on 10.0.0.0/24" | Advanced scanning with specific parameters |
| "Analyze the results from scan abc123" | Gets and analyzes specific scan results |
| "Cancel the running scan" | Stops active scan operations |

### Built-in Commands

| Command | Description |
|---------|-------------|
| `help` | Show help information |
| `exit/quit/bye` | Exit the agent |

### Example Session

```
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  Red Team Agno Agent                   ║
║                                                              ║
║  AI-Powered Red Team Operations with MCP Integration        ║
║  Type your requests in natural language                     ║
╚══════════════════════════════════════════════════════════════╝

🔌 Initializing Red Team Agent with MCP server...
✅ Agent initialized successfully!
💡 You can now ask the agent to perform red team operations
   Examples:
   • 'Scan 127.0.0.1 for common ports'
   • 'Check the status of my last scan'
   • 'List all completed scans'
   • 'Validate that masscan is working'

red-team> Scan 192.168.1.1 for common web ports

🤖 Processing: Scan 192.168.1.1 for common web ports

🧠 Reasoning: I need to perform a port scan on 192.168.1.1 targeting common web ports.
Common web ports include 80 (HTTP), 443 (HTTPS), 8080 (HTTP alternate), and 8443 (HTTPS alternate).

🔧 Using tool: port_scan
   Target: 192.168.1.1
   Ports: 80,443,8080,8443
   Scan Type: tcp_syn

✅ Port scan initiated successfully!
📋 Scan ID: f7e8d9c0-1234-5678-9abc-def012345678

The scan has been started and will check for common web services on the target host.

red-team> What did my scan find?

🤖 Processing: What did my scan find?

🧠 Reasoning: The user is asking about scan results. I should check the status of the most recent scan
to see if it has completed and what results were found.

🔧 Using tool: scan_status
   Scan ID: f7e8d9c0-1234-5678-9abc-def012345678

📊 Scan Results Analysis:
- Status: COMPLETED
- Target: 192.168.1.1
- Duration: 3.2 seconds
- Open Ports Found: 2

| Port | Service | Status |
|------|---------|--------|
| 80   | HTTP    | Open   |
| 443  | HTTPS   | Open   |

🔍 Security Assessment:
The target host is running standard web services on both HTTP and HTTPS ports.
This suggests it's likely a web server. Consider further enumeration of web applications.

red-team> exit
👋 Goodbye!
```

## Features in Detail

### AI-Powered Intelligence
- **Reasoning**: The agent thinks through problems step by step
- **Context Awareness**: Remembers previous conversations and scan results
- **Natural Language**: Understands complex requests in plain English
- **Analysis**: Provides security insights and recommendations

### MCP Integration
- **Dynamic Tool Discovery**: Automatically finds available MCP tools
- **Seamless Communication**: Uses Agno's built-in MCP client
- **Real-time Results**: Streams results as they become available
- **Error Handling**: Graceful handling of MCP server issues

### Rich Output
- **Formatted Results**: Beautiful tables and structured output
- **Progress Tracking**: Shows reasoning and tool usage
- **Color Coding**: Status indicators and syntax highlighting
- **Streaming**: Real-time output as the agent works

## Architecture

The agent is built using:
- **Agno Framework**: Lightweight, high-performance agent framework
- **MCP Protocol**: Model Context Protocol for tool integration
- **Reasoning Tools**: Built-in reasoning capabilities
- **Storage**: SQLite-based conversation history
- **Rich UI**: Beautiful terminal output

## Requirements

- Python 3.8+
- Agno framework
- OpenAI or Anthropic API key
- Red Team MCP server
- SQLAlchemy for storage

## Troubleshooting

### API Key Issues
```bash
# Set your API key
export OPENAI_API_KEY="your-key-here"
# or
export ANTHROPIC_API_KEY="your-key-here"
```

### MCP Server Issues
```bash
# Make sure the MCP server is working
python examples/fastmcp_server.py

# Test with a different server command
python agent/redteam_agent.py --server "python examples/fastmcp_server.py"
```

### Missing Dependencies
```bash
# Install all required packages
pip install agno openai anthropic sqlalchemy
```

### Debug Mode
```bash
# Run with debug output
python agent/redteam_agent.py --debug
```
