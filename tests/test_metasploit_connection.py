#!/usr/bin/env python3
"""
Test Metasploit RPC Connection

This specifically tests the connection to the Metasploit RPC server
to help debug connection issues.
"""

import json
import sys
import traceback
from pathlib import Path

# Add the src directory to the path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

def test_pymetasploit3_import():
    """Test if pymetasploit3 can be imported."""
    print("1. Testing pymetasploit3 import...")
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        print("   ✅ pymetasploit3 imported successfully")
        return True, MsfRpcClient
    except ImportError as e:
        print(f"   ❌ Failed to import pymetasploit3: {e}")
        print("   💡 Install with: pip install pymetasploit3")
        return False, None

def test_direct_connection():
    """Test direct connection to Metasploit RPC server."""
    print("\n2. Testing direct RPC connection...")

    success, MsfRpcClient = test_pymetasploit3_import()
    if not success:
        return False

    try:
        # Connection parameters matching your msfrpcd command
        password = "msf"
        host = "127.0.0.1"
        port = 55553
        ssl = False

        print(f"   Connecting to {host}:{port} with password '{password}' (SSL: {ssl})")

        client = MsfRpcClient(password, host=host, port=port, ssl=ssl)

        print("   ✅ Connected successfully!")

        # Test basic functionality
        print("   Testing basic RPC calls...")

        # Get version info
        try:
            version = client.core.version()
            print(f"   ✅ Metasploit version: {version}")
        except Exception as e:
            print(f"   ⚠️  Could not get version: {e}")

        # List modules (limited)
        try:
            modules = client.modules.exploits
            exploit_count = len(modules) if modules else 0
            print(f"   ✅ Found {exploit_count} exploit modules")
        except Exception as e:
            print(f"   ⚠️  Could not list modules: {e}")

        return True

    except Exception as e:
        print(f"   ❌ Connection failed: {e}")
        print(f"   Error type: {type(e).__name__}")
        traceback.print_exc()
        return False

def test_our_metasploit_client():
    """Test our metasploit client wrapper."""
    print("\n3. Testing our Metasploit client wrapper...")

    try:
        from red_team_mcp.metasploit_scanner import get_metasploit_client

        print("   Calling get_metasploit_client()...")
        client = get_metasploit_client()

        print("   ✅ Our client wrapper works!")

        # Test version
        try:
            version = client.core.version()
            print(f"   ✅ Version via wrapper: {version}")
        except Exception as e:
            print(f"   ⚠️  Version call failed: {e}")

        return True

    except Exception as e:
        print(f"   ❌ Our wrapper failed: {e}")
        print(f"   Error type: {type(e).__name__}")
        traceback.print_exc()
        return False

def test_list_exploits():
    """Test basic exploit listing without detailed info."""
    print("\n4. Testing basic exploit listing...")

    try:
        from red_team_mcp.metasploit_scanner import get_metasploit_client

        print("   Getting Metasploit client...")
        client = get_metasploit_client()

        print("   Getting exploit list...")
        all_exploits = client.modules.exploits

        print(f"   ✅ Found {len(all_exploits)} total exploits")

        # Show first few exploit names
        if all_exploits:
            print("   Example exploit names:")
            for i, exploit_name in enumerate(list(all_exploits)[:5]):
                print(f"     {i+1}. {exploit_name}")

        return True

    except Exception as e:
        print(f"   ❌ Exception in basic exploit listing: {e}")
        traceback.print_exc()
        return False

def test_connection_parameters():
    """Test different connection parameters to debug issues."""
    print("\n5. Testing different connection parameters...")

    success, MsfRpcClient = test_pymetasploit3_import()
    if not success:
        return False

    # Test parameters to try
    test_configs = [
        {"password": "msf", "host": "127.0.0.1", "port": 55553, "ssl": False},
        {"password": "msf", "host": "localhost", "port": 55553, "ssl": False},
        {"password": "msf", "host": "127.0.0.1", "port": 55553, "ssl": True},
    ]

    for i, config in enumerate(test_configs):
        print(f"   Config {i+1}: {config}")
        try:
            client = MsfRpcClient(**config)
            print(f"   ✅ Config {i+1} works!")
            return True
        except Exception as e:
            print(f"   ❌ Config {i+1} failed: {e}")

    print("   ❌ All connection configs failed")
    return False

def main():
    """Main test function."""
    print("🔍 Metasploit RPC Connection Test")
    print("=" * 40)
    print()
    print("This test will help debug your Metasploit RPC connection.")
    print("Make sure msfrpcd is running with: msfrpcd -P msf -a 127.0.0.1")
    print()

    tests = [
        test_pymetasploit3_import,
        test_direct_connection,
        test_our_metasploit_client,
        test_list_exploits,
        test_connection_parameters,
    ]

    passed = 0
    total = len(tests)

    for test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"   ❌ Test {test_func.__name__} crashed: {e}")
            traceback.print_exc()

    print(f"\n" + "=" * 40)
    print(f"Results: {passed}/{total} tests passed")
    print("=" * 40)

    if passed == total:
        print("🎉 All tests passed! Metasploit RPC connection is working!")
    elif passed >= 2:
        print("⚠️  Some tests passed. Connection might be working but with issues.")
    else:
        print("❌ Most tests failed. Check your Metasploit RPC setup.")
        print()
        print("Troubleshooting tips:")
        print("1. Make sure msfrpcd is running: msfrpcd -P msf -a 127.0.0.1")
        print("2. Check if port 55553 is open: netstat -an | grep 55553")
        print("3. Try restarting msfrpcd")
        print("4. Check Metasploit logs for errors")

    return 0 if passed >= 2 else 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
