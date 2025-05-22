#!/usr/bin/env python3
"""
Test script for the Red Team Agno Agent

This script tests the agent configuration without actually running it.
"""

import sys
import os
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from agent.redteam_agent import RedTeamAgentCLI


def test_agent_initialization():
    """Test that the agent can be initialized with Ollama configuration."""
    print("🧪 Testing Red Team Agno Agent initialization...")

    try:
        # Test with default settings
        agent_cli = RedTeamAgentCLI()
        print(f"✅ Default model: {agent_cli.ollama_model}")
        print(f"✅ Default host: {agent_cli.ollama_host}")
        print(f"✅ MCP server command: {agent_cli.mcp_server_command}")

        # Test with custom settings
        agent_cli_custom = RedTeamAgentCLI(
            mcp_server_command="python examples/fastmcp_server.py",
            ollama_model="qwen2.5:14b",
            ollama_host="http://192.168.1.100:11434"
        )
        print(f"✅ Custom model: {agent_cli_custom.ollama_model}")
        print(f"✅ Custom host: {agent_cli_custom.ollama_host}")

        print("🎉 Agent initialization test passed!")
        return True
    except Exception as e:
        print(f"❌ Agent initialization error: {e}")
        return False


def test_imports():
    """Test that all required imports work."""
    print("🧪 Testing imports...")

    try:
        from agno.agent import Agent
        from agno.models.ollama import Ollama
        from agno.tools.mcp import MCPTools
        from agno.tools.reasoning import ReasoningTools
        from agno.storage.agent.sqlite import SqliteAgentStorage
        print("✅ All Agno imports successful")

        import ollama
        print("✅ Ollama client import successful")

        import click
        from rich.console import Console
        print("✅ CLI dependencies import successful")

    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

    print("🎉 All imports test passed!")
    return True



def main():
    """Run all tests."""
    print("🚀 Starting Red Team Agno Agent Tests\n")

    tests = [
        test_imports,
        test_agent_initialization,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        try:
            if test():
                passed += 1
            print()  # Add spacing between tests
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}\n")

    print(f"📊 Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! The agent is ready to use.")
        return 0
    else:
        print("❌ Some tests failed. Please check the configuration.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
