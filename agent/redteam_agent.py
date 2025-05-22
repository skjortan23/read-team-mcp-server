#!/usr/bin/env python3
"""
Red Team MCP Agent - Agno-based Agent

An Agno agent that connects to the Red Team MCP server and provides
intelligent red team operations with reasoning capabilities.
"""

import asyncio
import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from textwrap import dedent

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from agno.agent import Agent
from agno.models.ollama import Ollama
from agno.tools.mcp import MCPTools
from agno.tools.reasoning import ReasoningTools
from agno.storage.agent.sqlite import SqliteAgentStorage


class RedTeamMCPTools(Tool):
    """Custom tool that wraps FastMCP client for red team operations."""

    def __init__(self):
        super().__init__()
        self.client = None

    async def _ensure_client(self):
        """Ensure FastMCP client is connected."""
        if self.client is None:
            from pathlib import Path
            server_script = Path(__file__).parent.parent / "examples" / "fastmcp_server.py"
            self.client = Client(str(server_script))
            await self.client.__aenter__()

    def port_scan(self, target: str, ports: str = "80,443", scan_type: str = "tcp_syn") -> str:
        """
        Perform a port scan on a target using masscan.

        Args:
            target: IP address or CIDR range to scan (e.g., '192.168.1.0/24')
            ports: Ports to scan (e.g., '80,443' or '1-1000')
            scan_type: Type of scan (tcp_syn, tcp_connect, udp, tcp_ack, tcp_window)

        Returns:
            JSON string with scan results
        """
        return asyncio.run(self._call_mcp_tool("port_scan", {
            "target": target,
            "ports": ports,
            "scan_type": scan_type
        }))

    def scan_status(self, scan_id: str) -> str:
        """
        Get the status of a running or completed scan.

        Args:
            scan_id: The ID of the scan to check

        Returns:
            JSON string with scan status and results
        """
        return asyncio.run(self._call_mcp_tool("scan_status", {"scan_id": scan_id}))

    def list_scans(self) -> str:
        """
        List all scan operations.

        Returns:
            JSON string with list of all scans
        """
        return asyncio.run(self._call_mcp_tool("list_scans", {}))

    def validate_masscan(self) -> str:
        """
        Validate that masscan is properly configured.

        Returns:
            JSON string with validation results
        """
        return asyncio.run(self._call_mcp_tool("validate_masscan", {}))

    def get_finished_scan_results(self) -> str:
        """
        Retrieve all completed scan results from the database.

        Returns:
            JSON string with all finished scan results
        """
        return asyncio.run(self._call_mcp_tool("get_finished_scan_results", {}))

    async def _call_mcp_tool(self, tool_name: str, arguments: dict) -> str:
        """Call an MCP tool and return the result."""
        try:
            await self._ensure_client()
            result = await self.client.call_tool(tool_name, arguments)
            if result:
                return result[0].text if isinstance(result, list) else result.text
            return "No result returned"
        except Exception as e:
            return f"Error calling MCP tool {tool_name}: {e}"


class RedTeamAgentCLI:
    """Interactive CLI wrapper for the Red Team Agno Agent."""

    def __init__(self, ollama_model: str = "qwen3", ollama_host: str = "http://localhost:11434"):
        self.console = Console()
        self.ollama_model = ollama_model
        self.ollama_host = ollama_host
        self.agent: Optional[Agent] = None

    async def create_agent(self) -> Agent:
        """Create and configure the Agno agent with MCP tools."""
        # Use local Ollama model
        self.console.print(f"🤖 Using local Ollama model: {self.ollama_model}", style="blue")
        self.console.print(f"🔗 Connecting to Ollama at: {self.ollama_host}", style="blue")

        # Create Ollama model instance
        model = Ollama(
            id=self.ollama_model,
            host=self.ollama_host,
            # Enable structured outputs for better tool use
            structured_outputs=True
        )

        # Create MCP tools connection to our red team server
        mcp_tools = MCPTools(command=self.mcp_server_command)

        # Create the agent with reasoning and MCP tools
        agent = Agent(
            name="Red Team Agent",
            model=model,
            tools=[
                ReasoningTools(add_instructions=True),
                mcp_tools
            ],
            instructions=dedent("""\
                You are a Red Team Security Agent with access to network scanning and reconnaissance tools.

                Your capabilities include:
                - Port scanning using masscan
                - Network reconnaissance
                - Scan result analysis
                - Security assessment

                Guidelines:
                - Always think through your approach before taking action
                - Use reasoning to analyze scan results and provide insights
                - Only scan networks you have permission to test
                - Provide clear, actionable security recommendations
                - Use tables and structured output for scan results
                - Be thorough in your analysis but concise in your responses

                Available MCP tools will be automatically discovered from the red team server.
            """),
            storage=SqliteAgentStorage(
                table_name="red_team_agent",
                db_file="tmp/red_team_agent.db",
                auto_upgrade_schema=True,
            ),
            add_history_to_messages=True,
            num_history_responses=3,
            add_datetime_to_instructions=True,
            markdown=True,
            show_tool_calls=True,
            debug_mode=False,
        )

        return agent

    def display_banner(self):
        """Display the agent banner."""
        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  Red Team Agno Agent                   ║
║                                                              ║
║  AI-Powered Red Team Operations with Local Ollama          ║
║  Model: {self.ollama_model:<48} ║
║  Type your requests in natural language                     ║
╚══════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold cyan")

    async def run_interactive(self):
        """Run the interactive agent session."""
        self.display_banner()

        try:
            # Create the agent with FastMCP client
            self.console.print("🔌 Initializing Red Team Agent with MCP server...", style="yellow")

            # Create custom MCP tools using FastMCP client
            mcp_tools = RedTeamMCPTools()

            # Create agent with MCP tools
            self.agent = await self.create_agent_with_mcp(mcp_tools)

                self.console.print("✅ Agent initialized successfully!", style="green")
                self.console.print("💡 You can now ask the agent to perform red team operations", style="blue")
                self.console.print("   Examples:", style="blue")
                self.console.print("   • 'Scan 127.0.0.1 for common ports'", style="green")
                self.console.print("   • 'Check the status of my last scan'", style="green")
                self.console.print("   • 'List all completed scans'", style="green")
                self.console.print("   • 'Validate that masscan is working'", style="green")
                self.console.print()

                # Interactive loop
                while True:
                    try:
                        user_input = input("red-team> ").strip()

                        if not user_input:
                            continue

                        if user_input.lower() in ['exit', 'quit', 'bye']:
                            self.console.print("👋 Goodbye!", style="cyan")
                            break

                        if user_input.lower() == 'help':
                            self.show_help()
                            continue

                        # Send request to agent
                        self.console.print(f"\n🤖 Processing: {user_input}", style="yellow")
                        await self.agent.aprint_response(
                            user_input,
                            stream=True,
                            show_full_reasoning=True,
                            stream_intermediate_steps=True
                        )
                        self.console.print()

                    except KeyboardInterrupt:
                        self.console.print("\n👋 Goodbye!", style="cyan")
                        break
                    except EOFError:
                        self.console.print("\n👋 Goodbye!", style="cyan")
                        break
                    except Exception as e:
                        self.console.print(f"❌ Error: {e}", style="red")

        except Exception as e:
            self.console.print(f"❌ Failed to initialize agent: {e}", style="red")
            return False

        return True

    async def create_agent_with_mcp(self, mcp_tools: MCPTools) -> Agent:
        """Create agent with the provided MCP tools."""
        # Use local Ollama model
        model = Ollama(
            id=self.ollama_model,
            host=self.ollama_host,
            # Enable structured outputs for better tool use
            structured_outputs=True
        )

        # Create the agent with reasoning and MCP tools
        agent = Agent(
            name="Red Team Agent",
            model=model,
            tools=[
                ReasoningTools(add_instructions=True),
                mcp_tools
            ],
            instructions=dedent("""\
                You are a Red Team Security Agent with access to network scanning and reconnaissance tools.

                Your capabilities include:
                - Port scanning using masscan
                - Network reconnaissance
                - Scan result analysis
                - Security assessment

                Guidelines:
                - Always think through your approach before taking action
                - Use reasoning to analyze scan results and provide insights
                - Only scan networks you have permission to test
                - Provide clear, actionable security recommendations
                - Use tables and structured output for scan results
                - Be thorough in your analysis but concise in your responses

                Available MCP tools will be automatically discovered from the red team server.
            """),
            storage=SqliteAgentStorage(
                table_name="red_team_agent",
                db_file="tmp/red_team_agent.db",
                auto_upgrade_schema=True,
            ),
            add_history_to_messages=True,
            num_history_responses=3,
            add_datetime_to_instructions=True,
            markdown=True,
            show_tool_calls=True,
            debug_mode=False,
        )

        return agent

    def show_help(self):
        """Show help information."""
        help_text = f"""
🛡️  Red Team Agno Agent Help

This is an AI agent powered by local Ollama ({self.ollama_model}) that can perform
red team operations using natural language. The agent has access to network scanning
tools through MCP (Model Context Protocol).

Example Commands:
• "Scan 192.168.1.1 for common ports"
• "Perform a TCP SYN scan on 10.0.0.0/24 ports 80,443,22"
• "Check the status of scan ID abc123"
• "List all my previous scans"
• "Get results from all completed scans"
• "Validate that masscan is properly configured"
• "Cancel the running scan with ID xyz789"

Special Commands:
• help - Show this help message
• exit/quit/bye - Exit the agent

The agent uses reasoning to understand your requests and will automatically
choose the appropriate tools to accomplish your red team objectives.
        """
        self.console.print(help_text, style="blue")


# CLI Entry Point
@click.command()
@click.option('--model', '-m', default="qwen3",
              help="Ollama model to use (default: qwen3)")
@click.option('--host', '-h', default="http://localhost:11434",
              help="Ollama host URL (default: http://localhost:11434)")
@click.option('--debug', is_flag=True, help="Enable debug mode")
def main(model: str, host: str, debug: bool):
    """Red Team Agno Agent - AI-powered red team operations with local Ollama (Qwen3) and inline MCP server."""

    # Create and run the agent CLI
    agent_cli = RedTeamAgentCLI(
        ollama_model=model,
        ollama_host=host
    )

    try:
        asyncio.run(agent_cli.run_interactive())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Agent error: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
