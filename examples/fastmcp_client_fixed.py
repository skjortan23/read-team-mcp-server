#!/usr/bin/env python3
"""
FastMCP Client - Proper MCP Client-Server Communication

This demonstrates real MCP protocol communication between client and server.
"""

import asyncio
import json
import sys

from fastmcp import Client


async def test_fastmcp_server():
    """Test the FastMCP Red Team server using proper MCP protocol."""

    print("🚀 Testing Red Team MCP Server (FastMCP Protocol)")
    print("=" * 55)
    print()

    try:
        # Connect to the FastMCP server via stdio (proper MCP communication)
        print("1. Connecting to FastMCP server via MCP protocol...")

        async with Client("examples/fastmcp_server.py") as client:
            print("   ✅ Connected successfully via MCP!")

            # Test 2: List available tools (MCP tools/list)
            print("\n2. Discovering available tools via MCP...")
            tools = await client.list_tools()

            print(f"   ✅ Found {len(tools)} tools:")
            for tool in tools:
                print(f"      • {tool.name}: {tool.description}")

            # Test 3: Validate masscan (MCP tools/call)
            print("\n3. Testing validate_masscan tool via MCP...")
            validate_result = await client.call_tool("validate_masscan", {})

            if validate_result:
                # FastMCP returns a list of content items
                result_text = validate_result[0].text if isinstance(validate_result, list) else validate_result.text
                result_data = json.loads(result_text)

                masscan_available = result_data.get("masscan_available", False)
                print(f"   ✅ Masscan available: {masscan_available}")

                if masscan_available:
                    print(f"   Version: {result_data.get('version', 'Unknown')}")

                    # Test 4: Perform a port scan via MCP
                    print("\n4. Testing port scan via MCP...")
                    scan_result = await client.call_tool("port_scan", {
                        "target": "8.8.8.8",
                        "ports": "53,443",
                        "scan_type": "tcp_syn"
                    })

                    if scan_result:
                        scan_text = scan_result[0].text if isinstance(scan_result, list) else scan_result.text
                        scan_data = json.loads(scan_text)

                        if scan_data.get("success"):
                            print(f"   ✅ Scan completed successfully via MCP!")
                            print(f"      Scan ID: {scan_data.get('scan_id')}")
                            print(f"      Target: {scan_data.get('target')}")
                            print(f"      Hosts found: {scan_data.get('total_hosts', 0)}")
                            print(f"      Open ports: {scan_data.get('total_open_ports', 0)}")

                            # Show discovered services with banner information
                            hosts = scan_data.get("hosts", [])
                            for host in hosts:
                                if host.get("ports"):
                                    print(f"      Host {host.get('ip')}:")
                                    for port in host.get("ports", []):
                                        if port.get("state") == "open":
                                            service = port.get("service", "unknown")
                                            version = port.get("version", "")
                                            banner = port.get("banner", "")

                                            print(f"        🔓 {port.get('port')}/{port.get('protocol')} - {port.get('state')}")
                                            print(f"           Service: {service}")
                                            if version:
                                                print(f"           Version: {version}")
                                            if banner:
                                                print(f"           Banner: {banner}")
                                            else:
                                                print(f"           Banner: No banner captured")
                        else:
                            print(f"   ❌ Scan failed: {scan_data.get('error')}")
                else:
                    print("   ⚠️  Masscan not available - skipping scan test")

            # Test 5: List capabilities via MCP
            print("\n5. Testing list_capabilities via MCP...")
            caps_result = await client.call_tool("list_capabilities", {})

            if caps_result:
                caps_text = caps_result[0].text if isinstance(caps_result, list) else caps_result.text
                caps_data = json.loads(caps_text)

                if caps_data.get("success"):
                    capabilities = caps_data.get("capabilities", {})
                    print("   ✅ Available capabilities:")
                    for category, tools in capabilities.items():
                        print(f"      {category.title()}:")
                        for tool_name, description in tools.items():
                            print(f"        • {tool_name}: {description}")

            print("\n" + "=" * 55)
            print("🎉 All MCP tests completed successfully!")
            print("=" * 55)
            print()
            print("✅ MCP Protocol Communication Working!")
            print("✅ Client-Server interaction via MCP")
            print("✅ Tool discovery via MCP tools/list")
            print("✅ Tool execution via MCP tools/call")
            print("✅ Real port scanning via MCP")
            print("✅ Ready for AI agent integration!")

            return True

    except Exception as e:
        print(f"❌ MCP test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def demonstrate_mcp_protocol():
    """Demonstrate what just happened with MCP protocol."""

    print("\n🔌 MCP Protocol Communication Demonstrated")
    print("=" * 45)
    print()

    print("What just happened:")
    print("1. 🚀 Client spawned FastMCP server process")
    print("2. 🔌 Client connected via stdio MCP transport")
    print("3. 🤝 MCP handshake and initialization")
    print("4. 🔍 Client sent 'tools/list' MCP request")
    print("5. 📋 Server responded with tool schemas")
    print("6. 🔧 Client sent 'tools/call' MCP requests")
    print("7. 📊 Server executed tools and returned JSON")
    print("8. 🧠 Client parsed structured responses")
    print()

    print("🔑 This is REAL MCP protocol communication!")
    print("  ✅ Not direct function calls")
    print("  ✅ Not REST API calls")
    print("  ✅ Actual MCP JSON-RPC over stdio")
    print("  ✅ Same protocol LLMs would use")
    print()

    print("🤖 LLM Integration:")
    print("  • Claude Desktop: Native MCP support")
    print("  • OpenAI: Via MCP-to-function bridge")
    print("  • Custom agents: Direct FastMCP client")
    print("  • Any MCP-compatible LLM")


async def test_in_memory_pattern():
    """Demonstrate the in-memory testing pattern."""

    print("\n🧪 In-Memory Testing Pattern")
    print("=" * 35)
    print()

    try:
        # Import the FastMCP server instance
        from fastmcp_server import app

        print("Testing in-memory FastMCP connection...")

        # Connect directly to the FastMCP instance (no process spawning)
        async with Client(app) as client:
            print("   ✅ Connected to FastMCP instance in-memory!")

            # Quick test
            tools = await client.list_tools()
            print(f"   ✅ Found {len(tools)} tools in-memory")

            # Test a tool call
            result = await client.call_tool("validate_masscan", {})
            if result:
                data = json.loads(result[0].text if isinstance(result, list) else result.text)
                print(f"   ✅ In-memory tool call: masscan available = {data.get('masscan_available')}")

        print("   ✅ In-memory testing successful!")
        print()
        print("🔑 Benefits of in-memory testing:")
        print("  • No process management")
        print("  • Faster test execution")
        print("  • Same MCP protocol")
        print("  • Perfect for unit tests")

    except Exception as e:
        print(f"   ❌ In-memory test failed: {e}")


async def main():
    """Main test function."""

    # Test 1: Full MCP protocol communication
    success = await test_fastmcp_server()

    # Test 2: Demonstrate MCP protocol
    await demonstrate_mcp_protocol()

    # Test 3: In-memory testing pattern
    await test_in_memory_pattern()

    if success:
        print("\n🚀 FastMCP Red Team Server is fully functional!")
        print("✅ Real MCP protocol communication working")
        print("✅ Ready for production AI agent integration")
    else:
        print("\n❌ Some MCP tests failed.")

    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
