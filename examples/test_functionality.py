#!/usr/bin/env python3
"""
Minimal functionality test for Red Team MCP Server.

Tests core functionality without verbose output.
"""

import asyncio
import sys
import subprocess
from pathlib import Path


async def test_server_startup():
    """Test that the MCP server can start up."""
    try:
        # Test server validation
        result = await asyncio.create_subprocess_exec(
            "red-team-mcp", "--config", "test_config.json", "validate",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await result.communicate()

        if result.returncode == 0:
            print("✅ Server validation passed")
            return True
        else:
            print(f"❌ Server validation failed: {stderr.decode()}")
            return False

    except Exception as e:
        print(f"❌ Server test failed: {e}")
        return False


async def test_scan_functionality():
    """Test basic scan functionality."""
    try:
        # Test a simple scan
        result = await asyncio.create_subprocess_exec(
            "red-team-mcp", "--config", "test_config.json",
            "scan", "--target", "8.8.8.8", "--ports", "53,443", "--wait",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await result.communicate()

        if result.returncode == 0 and "Scan completed" in stdout.decode():
            print("✅ Scan functionality works")
            return True
        else:
            print(f"❌ Scan test failed")
            return False

    except Exception as e:
        print(f"❌ Scan test failed: {e}")
        return False


async def test_mcp_tools():
    """Test MCP server can start."""
    try:
        # Just test that the server can start and respond to help
        result = await asyncio.create_subprocess_exec(
            "red-team-mcp", "--help",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await result.communicate()

        if result.returncode == 0 and "serve" in stdout.decode():
            print("✅ MCP server binary works")
            return True
        else:
            print("❌ MCP server test failed")
            return False

    except Exception as e:
        print(f"❌ MCP test failed: {e}")
        return False


async def main():
    """Run all functionality tests."""
    print("Testing Red Team MCP Server functionality...")

    tests = [
        ("Server Startup", test_server_startup),
        ("Scan Functionality", test_scan_functionality),
        ("MCP Protocol", test_mcp_tools),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"\nTesting {test_name}...")
        if await test_func():
            passed += 1

    print(f"\n{'='*40}")
    print(f"Tests passed: {passed}/{total}")

    if passed == total:
        print("🎉 All tests passed! Server is functional.")
        return 0
    else:
        print("❌ Some tests failed.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
