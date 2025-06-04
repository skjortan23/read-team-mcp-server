#!/usr/bin/env python3
"""
Simple Red Team Agno Agent with MCP Integration

A working agent that uses the FastMCP server with proper MCP compatibility.
"""

import asyncio
import re
from datetime import datetime
from textwrap import dedent
from typing import Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
import threading
import queue
import readline
import os
import click
from agno.tools.reasoning import ReasoningTools
from rich.console import Console
from rich.table import Table
from agno.agent import Agent
from agno.models.ollama import Ollama
from agno.tools.mcp import MCPTools
from agno.storage.agent.sqlite import SqliteAgentStorage

# Import the hacking agent tool
try:
    from .hacking_agent import hack_machine
except ImportError:
    # Handle direct execution
    import sys
    from pathlib import Path
    sys.path.append(str(Path(__file__).parent))
    from hacking_agent import hack_machine


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AgentTask:
    """Represents a task being executed by the agent."""
    task_id: str
    query: str
    status: TaskStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    result: Optional[str] = None
    error: Optional[str] = None
    asyncio_task: Optional[asyncio.Task] = None

class SimpleRedTeamAgent:
    """Simple Red Team Agent with MCP integration and parallel task execution."""

    def __init__(self, ollama_model: str = "qwen3:14b",
                 ollama_host: str = "http://localhost:11434",
                 mcp_timeout: int = 300):
        self.console = Console()
        self.ollama_model = ollama_model
        self.ollama_host = ollama_host
        self.mcp_timeout = mcp_timeout
        self.mcp_tools = None
        self.agent = None
        self.debug_mode = True

        # Task management
        self.tasks: Dict[str, AgentTask] = {}
        self.task_counter = 0

        # Input handling
        self.input_queue = queue.Queue()
        self.input_thread = None
        self.history_file = os.path.expanduser("~/.red_team_agent_history")

    def _generate_task_name(self, query: str) -> str:
        """Generate a descriptive task name from the query."""
        # Clean the query and extract key terms
        query_lower = query.lower().strip()

        # Common patterns for red team operations
        patterns = {
            r'port\s*scan|scan.*port': 'port-scan',
            r'vuln|vulnerability|vulnerabilities': 'vuln-scan',
            r'ssh.*brute|brute.*ssh': 'ssh-brute',
            r'exploit|metasploit': 'exploit',
            r'banner|grab.*banner': 'banner-grab',
            r'search.*host|list.*host|find.*host|hosts.*with': 'host-search',
            r'search.*exploit|find.*exploit': 'exploit-search',
            r'search.*vuln|find.*vuln': 'vuln-search',
            r'enumerate|enum': 'enumeration',
            r'resolve|dns|hostname': 'dns-lookup',
            r'capabilities|tools|help': 'info-query'
        }

        # Check for pattern matches
        for pattern, name in patterns.items():
            if re.search(pattern, query_lower):
                # Add target info if available
                target_match = re.search(r'(\d+\.\d+\.\d+\.\d+|[\w\.-]+\.\w+|\d+\.\d+\.\d+\.\d+/\d+)', query)
                if target_match:
                    target = target_match.group(1)
                    # Shorten long targets
                    if len(target) > 15:
                        target = target[:12] + "..."
                    return f"{name}-{target}"

                # Add port info if available
                port_match = re.search(r'port\s*(\d+)', query_lower)
                if port_match:
                    port = port_match.group(1)
                    return f"{name}-{port}"

                return name

        # Fallback: use first few words
        words = re.findall(r'\w+', query_lower)
        if words:
            # Take first 2-3 meaningful words, skip common words
            skip_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
            meaningful_words = [w for w in words[:5] if w not in skip_words]
            if meaningful_words:
                name = '-'.join(meaningful_words[:3])
                # Limit length
                if len(name) > 20:
                    name = name[:17] + "..."
                return name

        # Ultimate fallback
        return f"task-{self.task_counter}"

    async def _execute_agent_task(self, task: AgentTask) -> None:
        """Execute an agent task in the background with streaming output."""
        try:
            task.status = TaskStatus.RUNNING
            self.console.print(f"🤖 {task.task_id}: {task.query}", style="yellow")

            # Add timeout to prevent tasks from hanging indefinitely

            # Use arun with streaming to show tool calls in real-time
            response_content = ""
            captured_responses = []

            # Use arun with stream=True to get streaming responses
            # Note: We can't use asyncio.wait_for with async generators, so we'll handle timeout differently
            response_iterator = await self.agent.arun(
                task.query,
                stream=True,
                stream_intermediate_steps=True)

            # Track start time for manual timeout handling
            start_time = datetime.now()

            # Accumulate content chunks to avoid one-character-per-line issue
            content_buffer = ""

            async for response in response_iterator:
                # Handle different types of streaming responses based on Agno's format
                event_type = getattr(response, 'event', None)

                if event_type == 'ToolCallStarted':
                    # Handle tool call start events
                    if hasattr(response, 'tools') and response.tools:
                        for tool in response.tools:
                            tool_name = tool.get('tool_name', 'unknown')
                            tool_args = tool.get('tool_args', {})
                            args_str = ', '.join([f"{k}={v}" for k, v in tool_args.items()])
                            self.console.print(f"[{task.task_id}] 🔧 Calling {tool_name}({args_str})", style="cyan")

                elif event_type == 'ToolCallCompleted':
                    # Handle tool call completion events
                    if hasattr(response, 'tools') and response.tools:
                        for tool in response.tools:
                            tool_name = tool.get('tool_name', 'unknown')
                            self.console.print(f"[{task.task_id}] ✅ Completed {tool_name}", style="green")

                elif hasattr(response, 'content') and response.content:
                    # This is actual content - accumulate it
                    content_buffer += response.content

                elif isinstance(response, str):
                    # Handle string responses - accumulate them
                    content_buffer += response

                else:
                    # Debug: Print what type of response we're getting (only in debug mode)
                    if self.debug_mode:
                        self.console.print(f"[{task.task_id}] 🔍 Response type: {type(response)}, event: {event_type}", style="dim")

            # Print the accumulated content at the end
            if content_buffer.strip():
                self.console.print(f"[{task.task_id}] {content_buffer}", style="white")
                captured_responses.append(content_buffer)

            # Combine all captured responses for storage
            response_content = "\n".join(captured_responses) if captured_responses else "No content captured"

            task.status = TaskStatus.COMPLETED
            task.result = response_content
            task.end_time = datetime.now()

            # Print completion message
            self.console.print(f"\n✅ {task.task_id} completed", style="green")
            self.console.print()  # Add spacing

        except asyncio.CancelledError:
            task.status = TaskStatus.CANCELLED
            task.end_time = datetime.now()
            self.console.print(f"\n🛑 {task.task_id} cancelled", style="yellow")
            raise

        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.end_time = datetime.now()
            self.console.print(f"\n❌ {task.task_id} failed: {e}", style="red")

    def start_background_task(self, query: str) -> str:
        """Start a new background task."""
        self.task_counter += 1

        # Generate a descriptive task name
        task_id = self._generate_task_name(query)

        # Ensure uniqueness by adding counter if needed
        original_task_id = task_id
        counter = 1
        while task_id in self.tasks:
            task_id = f"{original_task_id}-{counter}"
            counter += 1

        task = AgentTask(
            task_id=task_id,
            query=query,
            status=TaskStatus.PENDING,
            start_time=datetime.now()
        )

        # Create and start the asyncio task
        task.asyncio_task = asyncio.create_task(self._execute_agent_task(task))
        self.tasks[task_id] = task

        # Print confirmation that task was started
        return task_id

    def _setup_readline(self):
        """Set up readline for command history and editing."""
        try:
            # Enable tab completion
            readline.parse_and_bind("tab: complete")

            # Enable history search with arrow keys
            readline.parse_and_bind("\\e[A: history-search-backward")
            readline.parse_and_bind("\\e[B: history-search-forward")

            # Load command history if it exists
            if os.path.exists(self.history_file):
                readline.read_history_file(self.history_file)

            # Set history length
            readline.set_history_length(1000)

        except Exception as e:
            # Readline might not be available on all systems
            self.console.print(f"⚠️  Readline setup failed: {e}", style="yellow")

    def _input_thread_worker(self):
        """Worker thread for handling input without blocking the event loop."""
        # Set up readline in the input thread
        self._setup_readline()

        while True:
            try:
                user_input = input("red-team> ")

                # Add to history if it's not empty and not a duplicate
                if user_input.strip():
                    # Check if it's different from the last command
                    history_length = readline.get_current_history_length()
                    if history_length == 0 or readline.get_history_item(history_length) != user_input:
                        readline.add_history(user_input)

                        # Save history to file
                        try:
                            readline.write_history_file(self.history_file)
                        except Exception:
                            pass  # Ignore history save errors

                self.input_queue.put(user_input)
            except EOFError:
                self.input_queue.put(None)  # Signal EOF
                break
            except Exception as e:
                self.input_queue.put(f"ERROR: {e}")
                break

    async def get_user_input(self):
        """Get user input asynchronously."""
        while True:
            try:
                # Check for input without blocking
                return self.input_queue.get_nowait()
            except queue.Empty:
                # No input available, yield control and try again
                await asyncio.sleep(0.1)

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task."""
        if task_id not in self.tasks:
            return False

        task = self.tasks[task_id]
        if task.asyncio_task and not task.asyncio_task.done():
            task.asyncio_task.cancel()
            return True
        return False

    def get_task_status(self, task_id: str) -> Optional[AgentTask]:
        """Get the status of a specific task."""
        return self.tasks.get(task_id)

    def list_tasks(self) -> Dict[str, AgentTask]:
        """List all tasks."""
        return self.tasks.copy()

    def display_tasks_table(self) -> None:
        """Display a table of all tasks."""
        if not self.tasks:
            self.console.print("📋 No tasks found", style="yellow")
            return

        table = Table(title="🛡️ Agent Tasks")
        table.add_column("Task ID", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Query", style="white", max_width=40)
        table.add_column("Start Time", style="blue")
        table.add_column("Duration", style="green")

        for task in self.tasks.values():
            # Calculate duration
            if task.end_time:
                duration = str(task.end_time - task.start_time).split('.')[0]
            else:
                duration = str(datetime.now() - task.start_time).split('.')[0]

            # Status with emoji
            status_emoji = {
                TaskStatus.PENDING: "⏳",
                TaskStatus.RUNNING: "🔄",
                TaskStatus.COMPLETED: "✅",
                TaskStatus.FAILED: "❌",
                TaskStatus.CANCELLED: "🛑"
            }
            status_display = f"{status_emoji.get(task.status, '❓')} {task.status.value}"

            table.add_row(
                task.task_id,
                status_display,
                task.query[:37] + "..." if len(task.query) > 40 else task.query,
                task.start_time.strftime("%H:%M:%S"),
                duration
            )

        self.console.print(table)

    def display_task_result(self, task_id: str) -> None:
        """Display the full result of a specific task."""
        task = self.get_task_status(task_id)
        if not task:
            self.console.print(f"❌ Task {task_id} not found", style="red")
            return

        self.console.print(f"\n📋 Task {task_id} Details:", style="bold cyan")
        self.console.print(f"Query: {task.query}", style="white")
        self.console.print(f"Status: {task.status.value}", style="yellow")
        self.console.print(f"Start Time: {task.start_time}", style="blue")

        if task.end_time:
            duration = task.end_time - task.start_time
            self.console.print(f"Duration: {duration}", style="green")

        if task.result:
            self.console.print("\n📄 Result:", style="bold green")
            # Since we now store the full response as a string, just print it
            self.console.print(task.result, style="white")
        elif task.error:
            self.console.print(f"\n❌ Error: {task.error}", style="red")
        elif task.status == TaskStatus.RUNNING:
            self.console.print("\n🔄 Task is still running...", style="yellow")

    def display_banner(self):
        """Display the agent banner."""
        timeout_mins = self.mcp_timeout // 60
        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  Red Team Agno Agent                  ║
║                     (Non-Blocking Chat)                     ║
║  AI-Powered Red Team Operations with Local Ollama            ║
║  Model: {self.ollama_model:<48} ║ host: {self.ollama_host}              ║
║                                                              ║
║  💬 All queries run in background - keep chatting!          ║
╚══════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold cyan")

    async def initialize(self):

        """Initialize the agent with MCP tools (TCP mode)."""
        try:
            self.console.print("🔌 Initializing MCP connection", style="yellow")

            # Instead of spawning via stdio, connect to the TCP server we started:
            #   — host: 127.0.0.1
            #   — port: 5678
            mcp_url = "http://127.0.0.1:5678/mcp/"
            self.mcp_tools = MCPTools(url=mcp_url, timeout_seconds=self.mcp_timeout, transport='streamable-http')
            await self.mcp_tools.__aenter__()

            print("MCP tools", self.mcp_tools)

            # … rest of your Ollama & Agent setup …
            self.console.print("✅ Agent initialized successfully!", style="green")

            model = Ollama(
                id=self.ollama_model,
                host=self.ollama_host,
                options={
                    "num_ctx": 32768,
                    'temperature': 0.2
                })

            # Create a simple agent without tools initially
            self.agent = Agent(
                name="Red Team Agent",
                model=model,
                tools=[
                    ReasoningTools(add_instructions=True),
                    self.mcp_tools,
                    hack_machine  # Add the hacking tool function
                ],
                instructions=dedent("""\
                    /no_think
                    You are a expert Red Team Security professional with access to network scanning, reconnaissance, and systematic hacking tools.
    
                    Guidelines:
                    - Use the tools default parameters unless you have a specific reason to change them
                    - Use tables and structured output for scan results
                    - Be thorough in your analysis but concise in your responses
                    - If a tool responds with an empty list that means that no findings. Do not run the tool again. 
    
                    SPECIALIZED CAPABILITIES:
                    - hack_machine: Execute systematic penetration testing to gain shell access to target machines
                    - This tool follows a complete methodology: reconnaissance → vulnerability assessment → exploitation → post-exploitation
    
                    Available MCP tools will be automatically discovered from the red team server.
                """),
                storage=SqliteAgentStorage(
                    table_name="red_team_agent",
                    db_file="../../agent/tmp/red_team_agent.db",
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
        """Run the interactive agent session with parallel task support."""
        self.display_banner()

        if not await self.initialize():
            return False

        # Start the input thread
        self.input_thread = threading.Thread(target=self._input_thread_worker, daemon=True)
        self.input_thread.start()

        # Interactive loop
        try:
            while True:
                try:
                    user_input = await self.get_user_input()

                    if user_input is None:  # EOF
                        break

                    user_input = user_input.strip()

                    if not user_input:
                        continue

                    if user_input.lower() in ['exit', 'quit', 'bye']:
                        # Cancel all running tasks before exiting
                        running_tasks = [task for task in self.tasks.values()
                                       if task.status == TaskStatus.RUNNING]
                        if running_tasks:
                            self.console.print(f"🛑 Cancelling {len(running_tasks)} running tasks...", style="yellow")
                            for task in running_tasks:
                                self.cancel_task(task.task_id)
                        self.console.print("👋 Goodbye!", style="cyan")
                        break

                    # Handle special commands
                    if user_input.lower() == 'help':
                        self.show_help()
                        continue
                    elif user_input.lower() == 'tasks':
                        self.display_tasks_table()
                        continue
                    else:
                        # For all other input, start a background task
                        self.start_background_task(user_input)
                        continue

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
🛡️  Red Team Agent Help (Non-Blocking Chat)

This is an AI agent powered by local Ollama ({self.ollama_model}) that can perform
red team operations using natural language. The agent has access to network scanning
tools through MCP (Model Context Protocol).

🚀 Default Behavior:
• ALL queries run in the background automatically
• You can continue chatting while previous queries are processing
• Responses appear when ready, you don't have to wait
• Tool calls are shown in real-time as they happen

📋 Special Commands:
• help              - Show this help message
• tasks             - List all tasks and their status
• task <task-name>  - Show detailed results for a specific task
• task <task-name> cancel - Cancel a running task
• sync <query>      - Run a query synchronously (wait for response)
• exit/quit/bye     - Exit the agent (cancels running tasks)

💡 Usage Examples:
• scan 192.168.1.0/24                            # Runs in background
• enumerate_vulnerabilities 192.168.1.100 22     # Runs in background
• hack_machine 192.168.1.100                     # Systematic penetration test
• validate_masscan                                # Runs in background
• tasks                                           # Check what's running
• sync help me understand port scanning           # Wait for response

🔄 How it works:
1. Type any query → it starts running in background immediately
2. Keep typing more queries while the first is still processing
3. Tool calls and responses stream in real-time with [task-name] prefixes
4. Use 'tasks' to see what's running and 'task <name>' to see results

The agent uses reasoning to understand your requests and will automatically
choose the appropriate tools to accomplish your red team objectives.
        """
        self.console.print(help_text, style="blue")

    async def cleanup(self):
        """Clean up resources and cancel running tasks."""
        # Cancel all running tasks
        running_tasks = [task for task in self.tasks.values()
                        if task.status in [TaskStatus.PENDING, TaskStatus.RUNNING]]

        if running_tasks:
            self.console.print(f"🛑 Cancelling {len(running_tasks)} running tasks...", style="yellow")
            for task in running_tasks:
                if task.asyncio_task and not task.asyncio_task.done():
                    task.asyncio_task.cancel()
                    try:
                        await task.asyncio_task
                    except asyncio.CancelledError:
                        pass
                    except Exception as e:
                        self.console.print(f"⚠️ Task cleanup warning: {e}", style="yellow")

        # Save command history
        try:
            readline.write_history_file(self.history_file)
        except Exception:
            pass  # Ignore history save errors

        # Clean up MCP tools
        if self.mcp_tools:
            try:
                # Don't use __aexit__ to avoid the async context manager issues
                # Just let it clean up naturally
                pass
            except Exception as e:
                self.console.print(f"⚠️ MCP cleanup warning: {e}", style="yellow")


# CLI Entry Point
@click.command()
@click.option('--model', '-m', default="qwen3:14b",
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
    os.environ["OLLAMA_HOST"] = host

    try:
        asyncio.run(agent.run_interactive())
    except KeyboardInterrupt:
        print("\nGoodbye!")
    except Exception as e:
        print(f"❌ Agent error: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
