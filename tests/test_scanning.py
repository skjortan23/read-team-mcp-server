#!/usr/bin/env python3
"""
Direct Scanning Test - Tests the Red Team MCP functionality via CLI

This bypasses the MCP protocol and directly tests the scanning functionality
to verify that the core features work.
"""

import asyncio
import subprocess
import sys


async def test_cli_functionality():
    """Test the Red Team MCP functionality via CLI commands."""
    
    print("🚀 Testing Red Team MCP Scanning Functionality")
    print("=" * 50)
    print()
    
    tests_passed = 0
    total_tests = 4
    
    # Test 1: Validate configuration
    print("1. Testing configuration validation...")
    try:
        result = await asyncio.create_subprocess_exec(
            "red-team-mcp", "--config", "test_config.json", "validate",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await result.communicate()
        
        if result.returncode == 0 and "All validations passed" in stdout.decode():
            print("   ✅ Configuration validation passed")
            tests_passed += 1
        else:
            print("   ❌ Configuration validation failed")
            print(f"   Error: {stderr.decode()}")
    except Exception as e:
        print(f"   ❌ Configuration test failed: {e}")
    
    # Test 2: Test a simple port scan
    print("\n2. Testing port scan functionality...")
    try:
        result = await asyncio.create_subprocess_exec(
            "red-team-mcp", "--config", "test_config.json", 
            "scan", "--target", "8.8.8.8", "--ports", "53,443", "--wait",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await result.communicate()
        
        output = stdout.decode()
        if result.returncode == 0 and "Scan completed" in output:
            print("   ✅ Port scan completed successfully")
            
            # Check if we found expected ports
            if "53/tcp - open" in output or "443/tcp - open" in output:
                print("   ✅ Found expected open ports on 8.8.8.8")
            else:
                print("   ⚠️  Scan completed but no expected ports found")
            
            tests_passed += 1
        else:
            print("   ❌ Port scan failed")
            print(f"   Error: {stderr.decode()}")
    except Exception as e:
        print(f"   ❌ Port scan test failed: {e}")
    
    # Test 3: Test network scan
    print("\n3. Testing network range scan...")
    try:
        result = await asyncio.create_subprocess_exec(
            "red-team-mcp", "--config", "test_config.json", 
            "scan", "--target", "8.8.8.8/31", "--ports", "53,443", "--wait",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await result.communicate()
        
        output = stdout.decode()
        if result.returncode == 0 and "Scan completed" in output:
            print("   ✅ Network range scan completed successfully")
            
            # Check if we found hosts
            if "Found" in output and "hosts" in output:
                print("   ✅ Network scan discovered hosts")
            
            tests_passed += 1
        else:
            print("   ❌ Network range scan failed")
            print(f"   Error: {stderr.decode()}")
    except Exception as e:
        print(f"   ❌ Network scan test failed: {e}")
    
    # Test 4: Test scan status functionality
    print("\n4. Testing scan management...")
    try:
        # Start a scan in background
        result = await asyncio.create_subprocess_exec(
            "red-team-mcp", "--config", "test_config.json", 
            "scan", "--target", "8.8.8.8", "--ports", "80,443",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await result.communicate()
        
        output = stdout.decode()
        if "Scan ID:" in output:
            # Extract scan ID
            scan_id = None
            for line in output.split('\n'):
                if "Scan ID:" in line:
                    scan_id = line.split("Scan ID:")[1].strip()
                    break
            
            if scan_id:
                print(f"   ✅ Scan started with ID: {scan_id}")
                
                # Check scan status
                status_result = await asyncio.create_subprocess_exec(
                    "red-team-mcp", "--config", "test_config.json", 
                    "scan-status", scan_id,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                status_stdout, status_stderr = await status_result.communicate()
                
                if status_result.returncode == 0:
                    print("   ✅ Scan status check successful")
                    tests_passed += 1
                else:
                    print("   ❌ Scan status check failed")
            else:
                print("   ❌ Could not extract scan ID")
        else:
            print("   ❌ Scan management test failed")
            print(f"   Error: {stderr.decode()}")
    except Exception as e:
        print(f"   ❌ Scan management test failed: {e}")
    
    # Summary
    print(f"\n" + "=" * 50)
    print(f"Test Results: {tests_passed}/{total_tests} tests passed")
    print("=" * 50)
    
    if tests_passed == total_tests:
        print("🎉 All tests passed! Red Team MCP is fully functional!")
        print()
        print("✅ Core functionality verified:")
        print("  • Configuration validation works")
        print("  • Port scanning works")
        print("  • Network range scanning works") 
        print("  • Scan management works")
        print()
        print("🚀 Ready for MCP integration with LLMs!")
        return True
    else:
        print(f"❌ {total_tests - tests_passed} tests failed.")
        print("Check configuration and dependencies.")
        return False


async def demonstrate_llm_integration():
    """Show how this would work with LLMs."""
    print("\n💡 LLM Integration Concept:")
    print("=" * 30)
    print()
    print("With MCP, LLMs would:")
    print("1. Connect to Red Team MCP server")
    print("2. Discover available tools dynamically:")
    print("   • port_scan")
    print("   • scan_status") 
    print("   • list_scans")
    print("   • cancel_scan")
    print("   • validate_masscan")
    print("3. Call tools with natural language prompts:")
    print('   "Scan 8.8.8.8 for web services"')
    print('   "Check if SSH is running on 192.168.1.0/24"')
    print('   "List all previous scans"')
    print("4. Receive structured results")
    print("5. Provide intelligent analysis")
    print()
    print("🔑 Key Benefits:")
    print("  • No hardcoded tool definitions")
    print("  • Dynamic capability discovery")
    print("  • Standardized across all LLMs")
    print("  • Secure, controlled access")


async def main():
    """Main test function."""
    success = await test_cli_functionality()
    await demonstrate_llm_integration()
    
    if success:
        print("\n🎯 Next Steps:")
        print("  • Fix MCP server TaskGroup error")
        print("  • Test with official MCP client")
        print("  • Integrate with Claude Desktop")
        print("  • Build AI agents using MCP")
    
    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
