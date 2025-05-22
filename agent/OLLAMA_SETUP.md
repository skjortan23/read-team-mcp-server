# Red Team Agno Agent with Local Ollama

This document provides setup instructions for running the Red Team Agno Agent with local Ollama and Qwen3 model.

## Quick Start

The agent is now configured to use local Ollama with Qwen3 model and loads the MCP server inline. No API keys or separate processes required!

### 1. Start the Agent

```bash
# Run with default settings (qwen3)
cd agent && python redteam_agent.py

# Use a different model
cd agent && python redteam_agent.py --model qwen2.5:7b

# Use custom Ollama host
cd agent && python redteam_agent.py --host http://192.168.1.100:11434
```

### 2. Example Usage

```
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  Red Team Agno Agent                   ║
║                                                              ║
║  AI-Powered Red Team Operations with Local Ollama          ║
║  Model: qwen3                                               ║
║  Type your requests in natural language                     ║
╚══════════════════════════════════════════════════════════════╝

🔌 Initializing Red Team Agent with MCP server...
🤖 Using local Ollama model: qwen3
🔗 Connecting to Ollama at: http://localhost:11434
✅ Agent initialized successfully!

red-team> Scan 192.168.1.1 for web services

🤖 Processing: Scan 192.168.1.1 for web services

🧠 Reasoning: I need to perform a port scan targeting common web service ports...

🔧 Using tool: port_scan
   Target: 192.168.1.1
   Ports: 80,443,8080,8443
   Scan Type: tcp_syn

✅ Scan initiated successfully!
```

## Configuration Options

### Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--model` | `qwen3` | Ollama model to use |
| `--host` | `http://localhost:11434` | Ollama server URL |
| `--debug` | `False` | Enable debug mode |

### Supported Models

The agent works with any Ollama model that supports tool use. Recommended models:

- `qwen3` (default) - Latest Qwen model with excellent tool use
- `qwen2.5:7b` - Good balance of performance and resource usage
- `qwen2.5:14b` - Better performance, more resource intensive
- `qwen2.5:32b` - Best performance, requires significant resources
- `llama3.1:8b` - Alternative option
- `mistral:7b` - Another alternative

### Model Selection

```bash
# Use different Qwen models
cd agent && python redteam_agent.py --model qwen2.5:14b
cd agent && python redteam_agent.py --model qwen2.5:32b

# Use other models
cd agent && python redteam_agent.py --model llama3.1:8b
cd agent && python redteam_agent.py --model mistral:7b
```

## Architecture

The agent uses:

- **Agno Framework**: Lightweight agent framework with built-in MCP support
- **Local Ollama**: No external API calls, complete privacy
- **Qwen3 Model**: Excellent tool use capabilities
- **Inline MCP Server**: FastMCP server loaded directly, no separate process
- **Reasoning Tools**: Built-in step-by-step reasoning
- **SQLite Storage**: Local conversation history

## Benefits of Local Ollama

✅ **Privacy**: All processing happens locally
✅ **No API Costs**: No usage fees or rate limits
✅ **Offline Capable**: Works without internet connection
✅ **Customizable**: Use any compatible model
✅ **Fast**: Direct local inference
✅ **Secure**: No data sent to external services
✅ **Inline MCP**: No separate process management required

## Testing

Run the test suite to verify everything is working:

```bash
python agent/test_agent.py
```

Expected output:
```
🚀 Starting Red Team Agno Agent Tests
🧪 Testing imports...
✅ All Agno imports successful
🎉 All imports test passed!

🧪 Testing Red Team Agno Agent initialization...
✅ Default model: qwen2.5:7b
🎉 Agent initialization test passed!

🧪 Testing banner display...
✅ Banner display successful
🎉 Banner display test passed!

📊 Test Results: 3/3 tests passed
🎉 All tests passed! The agent is ready to use.
```

## Troubleshooting

### Ollama Connection Issues

```bash
# Check if Ollama is running
curl http://localhost:11434/api/version

# Start Ollama if not running
ollama serve

# Check available models
ollama list
```

### Model Not Found

```bash
# Pull the required model
ollama pull qwen2.5:7b

# Or use a different model you have
python agent/redteam_agent.py --model llama3.1:8b
```

### Performance Issues

- Use smaller models for faster response: `qwen2.5:7b`
- Use larger models for better quality: `qwen2.5:14b` or `qwen2.5:32b`
- Adjust Ollama's `OLLAMA_NUM_PARALLEL` environment variable
- Monitor system resources (RAM, CPU)

## Next Steps

1. Start the agent: `python agent/redteam_agent.py`
2. Try natural language commands
3. Explore different models and configurations
4. Integrate with your red team workflows

The agent is now ready for local, private red team operations!
