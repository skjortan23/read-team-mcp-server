#!/usr/bin/env python3
"""
Test Agno MCP integration with FastMCP server.
"""

import asyncio
import sys
from pathlib import Path

from agno.agent import Agent
from agno.models.ollama import Ollama
from agno.tools.mcp import MCPTools


async def test_agno_mcp():
    """Test Agno MCP integration."""
    
    print("🧪 Testing Agno MCP with FastMCP server")
    print("=" * 40)
    
    try:
        # Get the path to the FastMCP server script
        server_script = Path(__file__).parent / "examples" / "fastmcp_server.py"
        mcp_command = f"python {server_script}"
        
        print(f"1. Connecting to FastMCP server: {mcp_command}")
        
        # Try to create MCPTools
        async with MCPTools(command=mcp_command) as mcp_tools:
            print("   ✅ MCPTools created successfully!")
            
            # Create a simple agent
            print("2. Creating Agno agent...")
            agent = Agent(
                model=Ollama(id="qwen3", host="http://localhost:11434"),
                tools=[mcp_tools],
                instructions="You are a test agent with MCP tools.",
                markdown=True,
                show_tool_calls=True,
            )
            print("   ✅ Agent created successfully!")
            
            # Test a simple query
            print("3. Testing agent with MCP tools...")
            response = await agent.arun("Validate that masscan is working")
            print(f"   ✅ Agent response: {response[:100]}...")
            
            return True
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Main test function."""
    success = await test_agno_mcp()
    
    if success:
        print("\n🎉 Agno MCP integration working!")
    else:
        print("\n❌ Agno MCP integration failed")
    
    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
