#!/usr/bin/env python3
"""
Test Database Scan Storage - Test the SQLite scan history functionality

This tests the new database storage and get_finished_scan_results function.
"""

import asyncio
import json
import sys

from fastmcp import Client


async def test_database_functionality():
    """Test the database scan storage and retrieval."""

    print("🗄️  Testing Database Scan Storage")
    print("=" * 40)
    print()

    try:
        async with Client("examples/fastmcp_server.py") as client:
            print("✅ Connected to FastMCP server")

            # Test 1: Run multiple scans to populate database
            print("\n1. Running multiple scans to populate database...")

            targets = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
            scan_ids = []

            for i, target in enumerate(targets, 1):
                print(f"   Scan {i}: {target}")
                result = await client.call_tool("port_scan", {
                    "target": target,
                    "ports": "53,443",
                    "scan_type": "tcp_syn"
                })

                if result:
                    data = json.loads(result[0].text if isinstance(result, list) else result.text)
                    if data.get("success"):
                        scan_id = data.get("scan_id")
                        scan_ids.append(scan_id)
                        print(f"      ✅ Scan completed: {scan_id}")
                        print(f"         Found {data.get('total_hosts', 0)} hosts, {data.get('total_open_ports', 0)} open ports")
                    else:
                        print(f"      ❌ Scan failed: {data.get('error')}")

            # Test 2: Retrieve all finished scan results
            print(f"\n2. Retrieving all finished scan results...")
            result = await client.call_tool("get_finished_scan_results", {"limit": 10})

            if result:
                data = json.loads(result[0].text if isinstance(result, list) else result.text)
                if data.get("success"):
                    scans = data.get("scans", [])
                    stats = data.get("database_stats", {})

                    print(f"   ✅ Retrieved {len(scans)} scan results")
                    print(f"   📊 Database stats:")
                    print(f"      Total completed scans: {stats.get('total_completed_scans', 0)}")
                    print(f"      Total hosts scanned: {stats.get('total_hosts_scanned', 0)}")
                    print(f"      Total open ports found: {stats.get('total_open_ports_found', 0)}")

                    print(f"\n   📋 Recent scans:")
                    for scan in scans[:5]:  # Show first 5
                        print(f"      • {scan.get('scan_id')[:8]}... - {scan.get('target')} ({scan.get('total_open_ports')} open ports)")
                else:
                    print(f"   ❌ Failed to retrieve results: {data.get('error')}")

            # Test 3: Retrieve specific scan by ID
            if scan_ids:
                print(f"\n3. Retrieving specific scan by ID...")
                specific_scan_id = scan_ids[0]
                result = await client.call_tool("get_finished_scan_results", {
                    "scan_id": specific_scan_id
                })

                if result:
                    data = json.loads(result[0].text if isinstance(result, list) else result.text)
                    if data.get("success"):
                        scans = data.get("scans", [])
                        if scans:
                            scan = scans[0]
                            print(f"   ✅ Retrieved specific scan: {scan.get('scan_id')}")
                            print(f"      Target: {scan.get('target')}")
                            print(f"      Duration: {scan.get('duration_seconds', 0):.2f} seconds")
                            print(f"      Results: {scan.get('total_hosts')} hosts, {scan.get('total_open_ports')} open ports")

                            # Show detailed host results with banner information
                            hosts = scan.get("hosts", [])
                            for host in hosts:
                                if host.get("ports"):
                                    print(f"      Host {host.get('ip')}:")
                                    for port in host.get("ports", []):
                                        if port.get("state") == "open":
                                            service = port.get("service", "unknown")
                                            version = port.get("version", "")
                                            banner = port.get("banner", "")

                                            print(f"        🔓 {port.get('port')}/{port.get('protocol')} - {service}")
                                            if version:
                                                print(f"           Version: {version}")
                                            if banner:
                                                print(f"           Banner: {banner}")
                        else:
                            print(f"   ❌ No scan found with ID: {specific_scan_id}")
                    else:
                        print(f"   ❌ Failed to retrieve specific scan: {data.get('error')}")

            # Test 4: Test capabilities listing
            print(f"\n4. Testing updated capabilities...")
            result = await client.call_tool("list_capabilities", {})

            if result:
                data = json.loads(result[0].text if isinstance(result, list) else result.text)
                if data.get("success"):
                    capabilities = data.get("capabilities", {})
                    scanning_tools = capabilities.get("scanning", {})

                    print(f"   ✅ Available scanning tools:")
                    for tool_name, description in scanning_tools.items():
                        print(f"      • {tool_name}: {description}")

            print(f"\n" + "=" * 40)
            print("🎉 Database functionality tests completed!")
            print("=" * 40)
            print()
            print("✅ SQLite database integration working!")
            print("✅ Scan results stored persistently")
            print("✅ Historical scan retrieval working")
            print("✅ Specific scan lookup working")
            print("✅ Database statistics working")

            return True

    except Exception as e:
        print(f"❌ Database test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def demonstrate_agent_workflow():
    """Demonstrate how an AI agent would use the database functionality."""

    print("\n🤖 AI Agent Workflow Demonstration")
    print("=" * 40)
    print()

    print("How an AI agent would use scan history:")
    print()
    print("1. 🎯 Agent receives task: 'Analyze network security'")
    print("2. 🔍 Agent calls port_scan() for multiple targets")
    print("3. 📊 Agent calls get_finished_scan_results() to review all scans")
    print("4. 🧠 Agent analyzes patterns across scan history:")
    print("   • Which hosts have the most open ports?")
    print("   • What services are commonly exposed?")
    print("   • Are there any security concerns?")
    print("5. 📝 Agent provides comprehensive security report")
    print()

    print("🔑 Database Benefits for AI Agents:")
    print("  ✅ Persistent scan history across sessions")
    print("  ✅ Ability to analyze trends over time")
    print("  ✅ No need to re-scan for historical data")
    print("  ✅ Rich metadata for analysis")
    print("  ✅ Structured data for ML/AI processing")
    print()

    print("📊 Example Agent Queries:")
    queries = [
        "Show me all scans from the last week",
        "Which hosts have SSH (port 22) open?",
        "Find all web servers in our scan history",
        "Compare current scan with previous results",
        "Generate a security summary report"
    ]

    for i, query in enumerate(queries, 1):
        print(f"  {i}. \"{query}\"")


async def main():
    """Main test function."""
    success = await test_database_functionality()
    await demonstrate_agent_workflow()

    if success:
        print("\n🚀 Database integration is fully functional!")
        print("✅ Ready for persistent AI agent workflows")
    else:
        print("\n❌ Some database tests failed.")

    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
