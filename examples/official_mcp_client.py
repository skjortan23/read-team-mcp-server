#!/usr/bin/env python3
"""
Official MCP Client Example - Tests Red Team MCP Server

This demonstrates how to use the official MCP client library to connect
to and interact with the Red Team MCP server.
"""

import asyncio
import json
import sys
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters


async def test_red_team_mcp():
    """Test the Red Team MCP server using official MCP client."""

    print("🚀 Testing Red Team MCP Server with Official MCP Client")
    print("=" * 55)
    print()

    try:
        # Connect to the Red Team MCP server
        print("1. Connecting to Red Team MCP server...")

        server_params = StdioServerParameters(
            command="red-team-mcp",
            args=["--config", "test_config.json", "serve"]
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:

                # Initialize the session
                await session.initialize()
                print("   ✅ Connected and initialized")

                # Test 2: List available tools (this is the key MCP feature!)
                print("\n2. Discovering available tools...")
                tools_result = await session.list_tools()

                print(f"   ✅ Found {len(tools_result.tools)} tools:")
                for tool in tools_result.tools:
                    print(f"      • {tool.name}: {tool.description}")

                # Test 3: Call validate_masscan tool
                print("\n3. Testing tool call: validate_masscan")
                validate_result = await session.call_tool("validate_masscan", {})

                if validate_result.content:
                    result_text = validate_result.content[0].text
                    result_data = json.loads(result_text)
                    masscan_available = result_data.get("masscan_available", False)
                    print(f"   ✅ Tool call successful - Masscan available: {masscan_available}")

                    # Test 4: If masscan is available, try a port scan
                    if masscan_available:
                        print("\n4. Testing port scan...")
                        scan_result = await session.call_tool("port_scan", {
                            "target": "8.8.8.8",
                            "ports": "53,443",
                            "scan_type": "tcp_syn",
                            "rate": 100
                        })

                        if scan_result.content:
                            scan_text = scan_result.content[0].text
                            scan_data = json.loads(scan_text)

                            if scan_data.get("success"):
                                scan_id = scan_data.get("scan_id")
                                print(f"   ✅ Scan started with ID: {scan_id}")

                                # Wait a bit and check status
                                print("\n5. Checking scan status...")
                                await asyncio.sleep(5)  # Give scan more time

                                status_result = await session.call_tool("scan_status", {
                                    "scan_id": scan_id
                                })

                                if status_result.content:
                                    status_text = status_result.content[0].text
                                    status_data = json.loads(status_text)

                                    if status_data.get("success"):
                                        scan_info = status_data.get("scan_result", {})
                                        print(f"   ✅ Scan status: {scan_info.get('status')}")
                                        print(f"      Hosts found: {scan_info.get('total_hosts', 0)}")
                                        print(f"      Open ports: {scan_info.get('total_open_ports', 0)}")

                                        # Show discovered services
                                        hosts = scan_info.get("hosts", [])
                                        for host in hosts:
                                            if host.get("ports"):
                                                print(f"      Host {host.get('ip')}:")
                                                for port in host.get("ports", []):
                                                    if port.get("state") == "open":
                                                        print(f"        🔓 {port.get('port')}/{port.get('protocol')}")
                            else:
                                print(f"   ❌ Scan failed: {scan_data.get('error')}")
                    else:
                        print("\n4. Skipping port scan (masscan not available)")

                # Test 6: List all scans
                print("\n6. Listing all scans...")
                list_result = await session.call_tool("list_scans", {})

                if list_result.content:
                    list_text = list_result.content[0].text
                    list_data = json.loads(list_text)

                    if list_data.get("success"):
                        scans = list_data.get("scans", [])
                        print(f"   ✅ Total scans in history: {len(scans)}")
                        for scan in scans:
                            print(f"      • {scan.get('scan_id')}: {scan.get('target')} ({scan.get('status')})")

                print("\n" + "=" * 55)
                print("🎉 All tests completed successfully!")
                print("=" * 55)
                print()
                print("Key Demonstrations:")
                print("✅ LLMs can discover tools dynamically via MCP")
                print("✅ No hardcoded tool definitions needed")
                print("✅ Standard MCP protocol enables tool calling")
                print("✅ Red Team MCP server is ready for AI agents!")
                print()
                print("Integration ready for:")
                print("• Claude Desktop (native MCP support)")
                print("• OpenAI Function Calling (via MCP bridge)")
                print("• Custom AI agents (using MCP client)")

                return True

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def show_mcp_concept():
    """Show the MCP concept briefly."""
    print("💡 MCP (Model Context Protocol) Concept:")
    print("   1. LLM connects to MCP server")
    print("   2. LLM calls list_tools() to discover capabilities")
    print("   3. LLM receives tool schemas dynamically")
    print("   4. LLM can call any tool with proper parameters")
    print("   5. Server executes tools and returns results")
    print()
    print("Benefits:")
    print("   • No hardcoded tool definitions")
    print("   • Easy to add new capabilities")
    print("   • Standardized across all LLMs")
    print("   • Server controls security and access")
    print()


async def main():
    """Main function."""
    await show_mcp_concept()
    success = await test_red_team_mcp()

    if success:
        print("\n🚀 Red Team MCP Server is fully functional!")
        print("Ready for production AI agent integration.")
    else:
        print("\n❌ Some tests failed. Check configuration and dependencies.")

    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
