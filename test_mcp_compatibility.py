#!/usr/bin/env python3
"""
Test MCP compatibility between FastMCP server and official MCP client.
"""

import asyncio
import sys
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters


async def test_fastmcp_with_official_client():
    """Test FastMCP server with official MCP client."""
    
    print("🧪 Testing FastMCP server with official MCP client")
    print("=" * 55)
    
    try:
        # Connect to FastMCP server using official MCP client
        server_params = StdioServerParameters(
            command="python",
            args=["examples/fastmcp_server.py"]
        )
        
        print("1. Connecting to FastMCP server...")
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                print("   ✅ Connected successfully!")
                
                # Initialize the session
                print("2. Initializing MCP session...")
                await session.initialize()
                print("   ✅ Session initialized!")
                
                # List tools
                print("3. Listing available tools...")
                tools = await session.list_tools()
                print(f"   ✅ Found {len(tools.tools)} tools:")
                for tool in tools.tools:
                    print(f"      • {tool.name}: {tool.description}")
                
                # Test a tool call
                print("4. Testing validate_masscan tool...")
                result = await session.call_tool("validate_masscan", {})
                print(f"   ✅ Tool call successful!")
                print(f"   Result: {result.content[0].text[:100]}...")
                
                return True
                
    except Exception as e:
        print(f"   ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Main test function."""
    success = await test_fastmcp_with_official_client()
    
    if success:
        print("\n🎉 FastMCP is compatible with official MCP client!")
        print("✅ This means it should work with any MCP client including Agno")
    else:
        print("\n❌ Compatibility issue found")
        print("This suggests FastMCP may not be fully MCP compliant")
    
    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
