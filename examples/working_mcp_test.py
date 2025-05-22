#!/usr/bin/env python3
"""
Working MCP Test - Actually starts and tests the Red Team MCP Server

This demonstrates real MCP tool discovery by starting the server and communicating with it.
"""

import asyncio
import json
import sys


async def test_mcp_server():
    """Test the actual MCP server functionality."""
    
    print("🚀 Testing Red Team MCP Server")
    print("=" * 30)
    print()
    
    server_process = None
    
    try:
        # Start the MCP server
        print("Starting MCP server...")
        server_process = await asyncio.create_subprocess_exec(
            "red-team-mcp", "--config", "test_config.json", "serve",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        await asyncio.sleep(2)  # Give server time to start
        
        # Test 1: Initialize connection
        print("1. Initializing MCP connection...")
        init_msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"}
            }
        }
        
        server_process.stdin.write((json.dumps(init_msg) + "\n").encode())
        await server_process.stdin.drain()
        
        response = await asyncio.wait_for(server_process.stdout.readline(), timeout=5)
        init_response = json.loads(response.decode())
        
        if "result" in init_response:
            print("   ✅ Connection established")
        else:
            print("   ❌ Connection failed")
            return False
        
        # Test 2: Discover tools
        print("2. Discovering available tools...")
        tools_msg = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        
        server_process.stdin.write((json.dumps(tools_msg) + "\n").encode())
        await server_process.stdin.drain()
        
        tools_response = await asyncio.wait_for(server_process.stdout.readline(), timeout=5)
        tools_data = json.loads(tools_response.decode())
        
        if "result" in tools_data and "tools" in tools_data["result"]:
            tools = tools_data["result"]["tools"]
            print(f"   ✅ Found {len(tools)} tools:")
            for tool in tools:
                print(f"      • {tool['name']}: {tool['description']}")
        else:
            print("   ❌ Tool discovery failed")
            return False
        
        # Test 3: Call a tool
        print("3. Testing tool call (validate_masscan)...")
        call_msg = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "validate_masscan",
                "arguments": {}
            }
        }
        
        server_process.stdin.write((json.dumps(call_msg) + "\n").encode())
        await server_process.stdin.drain()
        
        call_response = await asyncio.wait_for(server_process.stdout.readline(), timeout=10)
        call_data = json.loads(call_response.decode())
        
        if "result" in call_data:
            result_text = call_data["result"]["content"][0]["text"]
            result_json = json.loads(result_text)
            masscan_available = result_json.get("masscan_available", False)
            print(f"   ✅ Tool call successful - Masscan available: {masscan_available}")
        else:
            print("   ❌ Tool call failed")
            return False
        
        print()
        print("🎉 All tests passed! MCP server is working correctly.")
        print()
        print("This demonstrates:")
        print("• LLMs can discover tools dynamically")
        print("• No hardcoded tool definitions needed")
        print("• Standard MCP protocol works")
        print("• Ready for AI agent integration!")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
        
    finally:
        # Clean up
        if server_process:
            server_process.terminate()
            await server_process.wait()


async def main():
    """Main function."""
    success = await test_mcp_server()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
