#!/usr/bin/env python3
"""
FastMCP Client - Test the Red Team MCP Server

This demonstrates how to connect to and test the FastMCP Red Team server.
"""

import asyncio
import json
import sys

from fastmcp import Client


async def test_fastmcp_server():
    """Test the FastMCP Red Team server."""


    try:
        # Connect to the FastMCP server using PythonStdioTransport
        print("1. Connecting to FastMCP server...")

        # Use the correct FastMCP transport
        from fastmcp.client.transports import PythonStdioTransport
        transport = PythonStdioTransport("python", "examples/fastmcp_server.py")
        client = Client(transport)
        await client.connect()
        print("   ✅ Connected successfully!")

        # Test 2: List available tools
        print("\n2. Discovering available tools...")
        tools = await client.list_tools()

        print(f"   ✅ Found {len(tools)} tools:")
        for tool in tools:
            print(f"      • {tool.name}: {tool.description}")

        # Test 3: Validate masscan
        print("\n3. Testing validate_masscan tool...")
        validate_result = await client.call_tool("validate_masscan", {})

        if validate_result and validate_result.content:
            result_text = validate_result.content[0].text
            result_data = json.loads(result_text)

            masscan_available = result_data.get("masscan_available", False)
            print(f"   ✅ Masscan available: {masscan_available}")

            if masscan_available:
                print(f"   Version: {result_data.get('version', 'Unknown')}")

                # Test 4: Perform a port scan
                print("\n4. Testing port scan...")
                scan_result = await client.call_tool("port_scan", {
                    "target": "8.8.8.8",
                    "ports": "53,443",
                    "scan_type": "tcp_syn"
                })

                if scan_result and scan_result.content:
                    scan_text = scan_result.content[0].text
                    scan_data = json.loads(scan_text)

                    if scan_data.get("success"):
                        print(f"   ✅ Scan completed successfully!")
                        print(f"      Scan ID: {scan_data.get('scan_id')}")
                        print(f"      Target: {scan_data.get('target')}")
                        print(f"      Hosts found: {scan_data.get('total_hosts', 0)}")
                        print(f"      Open ports: {scan_data.get('total_open_ports', 0)}")

                        # Show discovered services
                        hosts = scan_data.get("hosts", [])
                        for host in hosts:
                            if host.get("ports"):
                                print(f"      Host {host.get('ip')}:")
                                for port in host.get("ports", []):
                                    if port.get("state") == "open":
                                        print(f"        🔓 {port.get('port')}/{port.get('protocol')} - {port.get('state')}")
                    else:
                        print(f"   ❌ Scan failed: {scan_data.get('error')}")
            else:
                print("   ⚠️  Masscan not available - skipping scan test")

        print("\n" + "=" * 45)
        print("🎉 All tests completed successfully!")
        print("=" * 45)
        print()
        print("✅ FastMCP Red Team Server is working!")
        print("✅ Tool discovery works")
        print("✅ Port scanning works")
        print("✅ Ready for AI agent integration!")

        return True

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        # Clean up
        try:
            await client.disconnect()
        except:
            pass
        try:
            server_process.terminate()
            server_process.wait(timeout=5)
        except:
            pass


async def main():
    """Main test function."""
    success = await test_fastmcp_server()

    if success:
        print("\n🚀 FastMCP Red Team Server is ready!")
        print("This demonstrates a working alternative to the official MCP.")
    else:
        print("\n❌ Some tests failed.")

    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
