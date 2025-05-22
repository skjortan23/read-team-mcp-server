#!/usr/bin/env python3
"""
Simple Red Team Agno Agent with MCP Integration

A working agent that uses the FastMCP server with proper MCP compatibility.
"""

import asyncio
import sys
from pathlib import Path
from textwrap import dedent

import click
from rich.console import Console

from agno.agent import Agent
from agno.models.ollama import Ollama
from agno.tools.mcp import MCPTools
from agno.tools.reasoning import ReasoningTools
from agno.storage.agent.sqlite import SqliteAgentStorage


class SimpleRedTeamAgent:
    """Simple Red Team Agent with MCP integration."""

    def __init__(self, ollama_model: str = "qwen3", ollama_host: str = "http://localhost:11434",
                 mcp_timeout: int = 300):
        self.console = Console()
        self.ollama_model = ollama_model
        self.ollama_host = ollama_host
        self.mcp_timeout = mcp_timeout
        self.mcp_tools = None
        self.agent = None

    def display_banner(self):
        """Display the agent banner."""
        timeout_mins = self.mcp_timeout // 60
        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  Red Team Agno Agent                   ║
║                                                              ║
║  AI-Powered Red Team Operations with Local Ollama            ║
║  Model: {self.ollama_model:<48} ║

║  Timeout: {timeout_mins} minutes for long-running scans          ║
╚══════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold cyan")

    async def initialize(self):
        """Initialize the agent with MCP tools."""
        try:
            self.console.print("🔌 Initializing MCP connection...", style="yellow")

            # Get the path to the FastMCP server script
            server_script = Path(__file__).parent.parent / "examples" / "fastmcp_server.py"
            mcp_command = f"python {server_script}"

            # Create MCP tools with configurable timeout for port scans (but don't use as context manager to avoid cleanup issues)
            self.mcp_tools = MCPTools(command=mcp_command, timeout_seconds=self.mcp_timeout)
            await self.mcp_tools.__aenter__()

            self.console.print("🤖 Creating Agno agent...", style="yellow")

            # Create Ollama model
            model = Ollama(
                id=self.ollama_model,
                host=self.ollama_host
            )

            # Create the agent
            self.agent = Agent(
                name="Red Team Agent",
                model=model,
                tools=[
                    ReasoningTools(add_instructions=True),
                    self.mcp_tools
                ],
                instructions=dedent("""\
                    You are a Red Team Security Agent with access to network scanning and reconnaissance tools.

                    Your capabilities include:
                    - Port scanning using masscan
                    - Network reconnaissance
        

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

            self.console.print("✅ Agent initialized successfully!", style="green")
            return True

        except Exception as e:
            self.console.print(f"❌ Failed to initialize agent: {e}", style="red")
            return False

    async def run_interactive(self):
        """Run the interactive agent session."""
        self.display_banner()

        if not await self.initialize():
            return False

        self.console.print("💡 You can now ask the agent to perform red team operations", style="blue")
        self.console.print("   Examples:", style="blue")
        self.console.print("   • 'Scan 127.0.0.1 for common ports'", style="green")
        self.console.print("   • 'Check the status of my last scan'", style="green")
        self.console.print("   • 'List all completed scans'", style="green")
        self.console.print("   • 'Validate that masscan is working'", style="green")
        self.console.print()

        # Interactive loop
        try:
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
                    response = await self.agent.arun(user_input)
                    self.console.print(f"\n📝 Response:\n{response.content}", style="white")
                    self.console.print()

                except KeyboardInterrupt:
                    self.console.print("\n👋 Goodbye!", style="cyan")
                    break
                except EOFError:
                    self.console.print("\n👋 Goodbye!", style="cyan")
                    break
                except Exception as e:
                    self.console.print(f"❌ Error: {e}", style="red")

        finally:
            await self.cleanup()

        return True

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

    async def cleanup(self):
        """Clean up resources."""
        if self.mcp_tools:
            try:
                # Don't use __aexit__ to avoid the async context manager issues
                # Just let it clean up naturally
                pass
            except Exception as e:
                self.console.print(f"⚠️  Cleanup warning: {e}", style="yellow")


# CLI Entry Point
@click.command()
@click.option('--model', '-m', default="qwen3",
              help="Ollama model to use (default: qwen3)")
@click.option('--host', '-h', default="http://localhost:11434",
              help="Ollama host URL (default: http://localhost:11434)")
@click.option('--timeout', '-t', default=300,
              help="MCP tool timeout in seconds (default: 300 = 5 minutes)")
@click.option('--debug', is_flag=True, help="Enable debug mode")
def main(model: str, host: str, timeout: int, debug: bool):
    """Simple Red Team Agno Agent - AI-powered red team operations with MCP compatibility."""

    # Create and run the agent
    agent = SimpleRedTeamAgent(ollama_model=model, ollama_host=host, mcp_timeout=timeout)

    try:
        asyncio.run(agent.run_interactive())
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
