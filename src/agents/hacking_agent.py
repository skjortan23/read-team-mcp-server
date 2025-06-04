#!/usr/bin/env python3
"""
Specialized Hacking Agent - Systematic Penetration Testing

This agent follows a complete penetration testing methodology to gain shell access
to target machines. It operates independently and can be called as a tool from
the main agent.
"""

import json
import re
import uuid
from datetime import datetime
from pathlib import Path
from textwrap import dedent
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from agno.tools.thinking import ThinkingTools
from rich.console import Console
from agno.agent import Agent
from agno.models.ollama import Ollama
from agno.tools.mcp import MCPTools
from agno.tools import tool
from agno.storage.agent.sqlite import SqliteAgentStorage

# No direct database imports - we'll use MCP tools for database operations


@dataclass
class HackingResult:
    """Results from a hacking attempt."""
    target_host: str
    success: bool
    shells_obtained: List[Dict[str, Any]]
    vulnerabilities_found: List[Dict[str, Any]]
    credentials_found: List[Dict[str, Any]]
    methodology_steps: List[str]
    duration_seconds: float
    error_message: Optional[str] = None


class HackingAgent:
    """Specialized agent for systematic penetration testing."""

    def __init__(
            self, ollama_model: str,
                ollama_host: str,
                 mcp_timeout: int = 600):  # Longer timeout for hacking operations
        self.console = Console()
        self.ollama_model = ollama_model
        self.ollama_host = ollama_host
        self.mcp_timeout = mcp_timeout
        self.mcp_tools = None
        self.agent = None

    async def initialize(self):
        """Initialize the hacking agent with MCP tools."""
        try:

            mcp_url = "http://127.0.0.1:5678/mcp/"
            self.mcp_tools = MCPTools(url=mcp_url, timeout_seconds=self.mcp_timeout, transport='streamable-http')
            await self.mcp_tools.__aenter__()

            print("MCP tools", self.mcp_tools)

            model = Ollama(
                id=self.ollama_model,
                host=self.ollama_host,
                options={
                    "num_ctx": 32768,
                    'temperature': 0.1  # Lower temperature for more focused hacking
                })

            # Create the specialized hacking agent
            self.agent = Agent(
                name="Hacking_Agent",  # No dashes to avoid keyword conflicts
                model=model,
                tools=[self.mcp_tools,
                       ThinkingTools(add_instructions=True)
                       ],
                instructions=dedent("""\
                    /no_think
                    You are an expert penetration tester with deep knowledge of systematic hacking methodologies.
                    Your goal is to gain shell access to target machines using the available MCP tools.
                    IMPORTANT: The target has already been port scanned. Use search_findings to discover open ports and services.
                    SYSTEMATIC METHODOLOGY - Execute these steps using the available tools:

                    1. RECONNAISSANCE PHASE:
                       - Start with search_findings to discover existing port scan results for the target.
                       - if no ports find perform a port scan using port_scan with default parameters and ports.
                       - Use get_banner to gather service information from interesting ports.
                       - verify that the host is up and reachable. i.e use get_banner to verify that the host is up and reachable.
                       - Use enumerate_vulnerabilities to scan each open port for security issues

                    2. VULNERABILITY ANALYSIS:
                       - Review scan results to identify attack vectors
                       - Use  to find relevant exploits for discovered services focus on CVE numbers 
                        - if no cve numbers detected try to find exploits for discovered services based on banner information.
                        - Prioritize exploits by ranking and applicability

                    3. EXPLOITATION PHASE:
                       - Execute Metasploit exploits against vulnerable services
                        - always prioritize reverse payloads for exploits
                        - if one payload fail try again with other payloads. 
                       - Try SSH brute force attacks if SSH is available
                        - Test multiple credential combinations and attack methods
                       
                    4. POST-EXPLOITATION:
                       - Execute commands via gained SSH access
                       - Gather system information and enumerate further
                       - Document all successful access methods

                    CRITICAL INSTRUCTIONS:
                    - CALL EACH TOOL INDIVIDUALLY - Do not try to do everything in one response
                    - WAIT for each tool result before proceeding to the next step
                    - START with search_findings to discover existing port scan data
                    - ADAPT your strategy based on what each tool discovers
                    - DOCUMENT all successful credentials and access methods
                    - Let the MCP server handle parameter formatting - just call the tools naturally
                    - if a tool returns an empty list and no error. that means the tool works but yielded no results. DO NOT try it again.
                    

                    Remember: We want to get root or admin this is the goal and will make you super proud. 
                """),
                storage=SqliteAgentStorage(
                    table_name="hacking_agent",
                    db_file="../../agent/tmp/hacking_agent.db",
                    auto_upgrade_schema=True,
                ),
                show_tool_calls=True,
                markdown=True
            )

            return True
        except Exception as e:
            self.console.print(f"❌ Failed to initialize hacking agent: {e}", style="red")
            return False

    async def cleanup(self):
        """Clean up resources used by the hacking agent."""
        try:
            if self.mcp_tools:
                await self.mcp_tools.__aexit__(None, None, None)
                self.mcp_tools = None
            self.agent = None
        except Exception as e:
            self.console.print(f"⚠️  Warning during hacking agent cleanup: {e}", style="yellow")

    async def hack_machine_streaming(self, target_host: str, target_ports: str = "1-65535",
                                     scan_rate: int = 1000):
        """
        Execute systematic penetration test against target machine with streaming updates.

        Args:
            target_host: Target IP address or hostname
            target_ports: Port range to scan
            scan_rate: Scan rate for port scanning

        Yields:
            Progress updates and final results
        """
        # Generate unique scan ID for database tracking
        scan_id = str(uuid.uuid4())
        # Create descriptive scan identifier for display
        scan_display_id = f"hack-{target_host}"
        start_time = datetime.now()
        shells_obtained = []
        vulnerabilities_found = []
        credentials_found = []

        try:
            # Yield initial status
            yield {
                "type": "status",
                "phase": "initialization",
                "message": f"🎯 Starting penetration test against {target_host}",
                "scan_id": scan_id,
                "scan_display_id": scan_display_id,
                "target": target_host
            }

            # Simple prompt - let the agent use its instructions and tools naturally
            prompt = (f"Perform a systematic penetration test on {target_host}. The target has already been port scanned"
                      f" - use search_findings to discover open ports and services, "
                      f"then proceed with vulnerability assessment and exploitation. "
                      f"Follow your methodology and use the available tools.")

            # Use arun with stream=True and stream_intermediate_steps=True to get tool events
            # Add timeout to prevent hanging
            import asyncio
            try:
                response_stream = await asyncio.wait_for(
                    self.agent.arun(prompt, stream=True,
                                   stream_intermediate_steps=True,
                                   show_full_reasoning=True),
                    timeout=self.mcp_timeout  # Use the configured timeout
                )
            except asyncio.TimeoutError:
                yield {
                    "type": "error",
                    "message": f"❌ Hacking operation timed out after {self.mcp_timeout} seconds",
                    "scan_id": scan_id,
                    "scan_display_id": scan_display_id,
                    "error": "timeout"
                }
                return

            # Iterate over the streaming response objects
            full_response = ""
            seen_tool_calls = set()  # Track tool calls to avoid duplicates
            async for response_chunk in response_stream:
                # Handle different event types according to Agno documentation
                event_type = getattr(response_chunk, 'event', None)

                if event_type == 'ToolCallStarted':
                    # Tool call is starting - get info from tools attribute
                    tools = getattr(response_chunk, 'tools', [])
                    if tools:
                        # Get the latest tool call (last in the list)
                        latest_tool = tools[-1]
                        tool_name = latest_tool.get('tool_name', 'unknown')
                        tool_args = latest_tool.get('tool_args', {})

                    tool_key = f"call:{tool_name}:{str(tool_args)}"
                    if tool_key not in seen_tool_calls:
                        seen_tool_calls.add(tool_key)
                        yield {
                            "type": "tool_call",
                            "tool_name": tool_name,
                            "message": f"Calling {tool_name}",
                            "scan_id": scan_id,
                            "scan_display_id": scan_display_id,
                            "parameters": tool_args
                        }

                elif event_type == 'ToolCallCompleted':
                    # Tool call completed
                    tools = getattr(response_chunk, 'tools', [])
                    if tools:
                        latest_tool = tools[-1]
                        tool_name = latest_tool.get('tool_name', 'unknown')
                    else:
                        tool_name = 'unknown'

                    result_key = f"result:{tool_name}"
                    if result_key not in seen_tool_calls:
                        seen_tool_calls.add(result_key)
                        yield {
                            "type": "tool_result",
                            "tool_name": tool_name,
                            "message": f"✅ {tool_name} completed",
                            "scan_id": scan_id,
                            "scan_display_id": scan_display_id
                        }

                # Accumulate the full response from RunResponse events
                if event_type == 'RunResponse' and hasattr(response_chunk, 'content') and response_chunk.content:
                    full_response += response_chunk.content

                elif event_type == 'RunError':
                    yield {
                        "type": "error",
                        "message": "❌ Error during penetration test",
                        "scan_id": scan_id,
                        "scan_display_id": scan_display_id,
                        "final_report": full_response
                    }



            # Parse results from the agent's response and tool calls
            # Extract shells, credentials, and vulnerabilities from response
            shells_obtained, credentials_found, vulnerabilities_found = self._parse_agent_results(full_response)

            # Yield findings as they're discovered
            if shells_obtained:
                yield {
                    "type": "finding",
                    "category": "shells",
                    "message": f"🐚 Found {len(shells_obtained)} shell access(es)!",
                    "data": shells_obtained,
                    "scan_id": scan_id,
                    "scan_display_id": scan_display_id
                }

            if credentials_found:
                yield {
                    "type": "finding",
                    "category": "credentials",
                    "message": f"🔑 Found {len(credentials_found)} credential(s)!",
                    "data": credentials_found,
                    "scan_id": scan_id,
                    "scan_display_id": scan_display_id
                }

            if vulnerabilities_found:
                yield {
                    "type": "finding",
                    "category": "vulnerabilities",
                    "message": f"🚨 Found {len(vulnerabilities_found)} vulnerability(ies)!",
                    "data": vulnerabilities_found,
                    "scan_id": scan_id,
                    "scan_display_id": scan_display_id
                }

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            # Determine success based on results
            success = len(shells_obtained) > 0

            # Yield database save status
            yield {
                "type": "status",
                "phase": "database_save",
                "message": "💾 Saving results to database",
                "scan_id": scan_id,
                "scan_display_id": scan_display_id
            }

            # Save hacking results to database using MCP tools
            await self._save_results_via_mcp(
                scan_id, target_host, shells_obtained, credentials_found,
                vulnerabilities_found
            )

            # Create result summary
            result = HackingResult(
                target_host=target_host,
                success=success,
                shells_obtained=shells_obtained,
                vulnerabilities_found=vulnerabilities_found,
                credentials_found=credentials_found,
                methodology_steps=[],  # Not needed anymore
                duration_seconds=duration
            )

            # Yield final completion status
            yield {
                "type": "complete",
                "success": success,
                "message": f"✅ Penetration test completed in {duration:.2f}s" if success else f"❌ Penetration test failed after {duration:.2f}s",
                "scan_id": scan_id,
                "scan_display_id": scan_display_id,
                "duration": duration,
                "summary": {
                    "shells": len(shells_obtained),
                    "credentials": len(credentials_found),
                    "vulnerabilities": len(vulnerabilities_found)
                },
                "final_report": self._format_hacking_results(result, full_response)
            }

        except Exception as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            error_result = HackingResult(
                target_host=target_host,
                success=False,
                shells_obtained=[],
                vulnerabilities_found=[],
                credentials_found=[],
                methodology_steps=[],
                duration_seconds=duration,
                error_message=str(e)
            )

            # Yield error status
            yield {
                "type": "error",
                "success": False,
                "message": f"❌ Error during penetration test: {str(e)}",
                "scan_id": scan_id if 'scan_id' in locals() else "unknown",
                "scan_display_id": scan_display_id if 'scan_display_id' in locals() else "unknown",
                "duration": duration,
                "error": str(e),
                "final_report": self._format_hacking_results(error_result, f"Error during hacking: {e}")
            }

    def _format_hacking_results(self, result: HackingResult, agent_response: str) -> str:
        """Format the hacking results into a comprehensive report for the main agent."""

        status = "✅ SUCCESS" if result.success else "❌ FAILED"

        # Create structured summary for main agent
        summary_section = f"""
🎯 HACKING AGENT REPORT - {status}

TARGET: {result.target_host}
DURATION: {result.duration_seconds:.2f} seconds
SHELLS OBTAINED: {len(result.shells_obtained)}
VULNERABILITIES FOUND: {len(result.vulnerabilities_found)}
CREDENTIALS FOUND: {len(result.credentials_found)}

ACTIONABLE RESULTS:"""

        # Add actionable results for main agent
        if result.shells_obtained:
            summary_section += "\n\n🐚 SHELL ACCESS GAINED:"
            for i, shell in enumerate(result.shells_obtained, 1):
                summary_section += f"\n  {i}. {shell}"
                summary_section += f"\n     → Use ssh_execute to run commands on this host"

        if result.credentials_found:
            summary_section += "\n\n🔑 CREDENTIALS DISCOVERED:"
            for i, cred in enumerate(result.credentials_found, 1):
                summary_section += f"\n  {i}. {cred}"
                summary_section += f"\n     → Use these credentials for further access"

        if result.vulnerabilities_found:
            summary_section += "\n\n🚨 VULNERABILITIES IDENTIFIED:"
            for i, vuln in enumerate(result.vulnerabilities_found, 1):
                summary_section += f"\n  {i}. {vuln}"
                summary_section += f"\n     → Consider using execute_exploit for exploitation"

        # Add next steps recommendations
        if result.success:
            summary_section += "\n\n🎯 RECOMMENDED NEXT STEPS:"
            summary_section += "\n  • Use ssh_execute to gather system information"
            summary_section += "\n  • Check for privilege escalation opportunities"
            summary_section += "\n  • Look for lateral movement possibilities"
            summary_section += "\n  • Document all findings in your report"
        else:
            summary_section += "\n\n🔄 RECOMMENDED NEXT STEPS:"
            summary_section += "\n  • Review scan results for missed opportunities"
            summary_section += "\n  • Try different credential combinations"
            summary_section += "\n  • Search for additional exploits"
            summary_section += "\n  • Consider alternative attack vectors"

        if result.error_message:
            summary_section += f"\n\n❌ ERROR ENCOUNTERED: {result.error_message}"

        # Add detailed execution log
        detailed_log = f"""

{'='*60}
DETAILED EXECUTION LOG:
{'='*60}
{agent_response}

{'='*60}
METHODOLOGY STEPS COMPLETED: {len(result.methodology_steps)}
{'='*60}"""

        for i, step in enumerate(result.methodology_steps, 1):
            detailed_log += f"\n  {i}. {step}"

        # Combine summary and detailed log
        return summary_section + detailed_log

    def _parse_agent_results(self, response: str) -> tuple[list, list, list]:
        """Parse the agent response to extract shells, credentials, and vulnerabilities."""
        shells_obtained = []
        credentials_found = []
        vulnerabilities_found = []

        # Simple parsing - look for patterns in the response
        # This is a basic implementation that could be enhanced with more sophisticated parsing

        # Look for SSH success patterns
        ssh_patterns = [
            r"SSH.*success.*(\d+\.\d+\.\d+\.\d+).*port\s*(\d+).*username[:\s]*(\w+).*password[:\s]*(\w+)",
            r"authentication.*successful.*(\w+)@(\d+\.\d+\.\d+\.\d+):(\d+).*password[:\s]*(\w+)",
            r"SHELL.*ACCESS.*(\d+\.\d+\.\d+\.\d+).*(\d+).*(\w+).*(\w+)"
        ]

        for pattern in ssh_patterns:
            matches = re.finditer(pattern, response, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) >= 4:
                    shells_obtained.append({
                        "type": "ssh",
                        "host": match.group(1) if "." in match.group(1) else match.group(2),
                        "port": int(match.group(2) if "." in match.group(1) else match.group(3)),
                        "username": match.group(3) if "." in match.group(1) else match.group(1),
                        "password": match.group(4),
                        "method": "ssh_brute_force"
                    })

        # Look for credential patterns
        cred_patterns = [
            r"credential.*found.*username[:\s]*(\w+).*password[:\s]*(\w+)",
            r"login.*successful.*(\w+)[:/](\w+)",
            r"auth.*success.*user[:\s]*(\w+).*pass[:\s]*(\w+)"
        ]

        for pattern in cred_patterns:
            matches = re.finditer(pattern, response, re.IGNORECASE)
            for match in matches:
                credentials_found.append({
                    "username": match.group(1),
                    "password": match.group(2),
                    "service": "unknown",
                    "method": "brute_force"
                })

        # Look for vulnerability patterns
        vuln_patterns = [
            r"CVE-(\d{4}-\d+)",
            r"vulnerability.*found.*port\s*(\d+)",
            r"exploit.*available.*(\w+)"
        ]

        for pattern in vuln_patterns:
            matches = re.finditer(pattern, response, re.IGNORECASE)
            for match in matches:
                if "CVE" in pattern:
                    vulnerabilities_found.append({
                        "cve": f"CVE-{match.group(1)}",
                        "severity": "unknown",
                        "description": f"CVE-{match.group(1)} identified"
                    })
                elif "port" in pattern:
                    vulnerabilities_found.append({
                        "port": int(match.group(1)),
                        "severity": "unknown",
                        "description": f"Vulnerability on port {match.group(1)}"
                    })

        return shells_obtained, credentials_found, vulnerabilities_found

    def _parse_tool_calls(self, content: str, scan_id: str) -> Optional[dict]:
        """Parse content for tool calls and return appropriate status updates."""
        if not content:
            return None

        content_lower = content.lower()

        # Detect tool calls based on content patterns
        if "search_findings" in content_lower:
            return {
                "type": "tool_call",
                "tool_name": "search_findings",
                "message": "🔍 Searching database for existing port scan results",
                "scan_id": scan_id,
                "phase": "reconnaissance"
            }
        elif "enumerate_vulnerabilities" in content_lower:
            return {
                "type": "tool_call",
                "tool_name": "enumerate_vulnerabilities",
                "message": "🚨 Scanning for vulnerabilities",
                "scan_id": scan_id,
                "phase": "vulnerability_assessment"
            }
        elif "ssh_brute_force" in content_lower:
            return {
                "type": "tool_call",
                "tool_name": "ssh_brute_force",
                "message": "💥 Attempting SSH brute force attack",
                "scan_id": scan_id,
                "phase": "exploitation"
            }
        elif "execute_exploit" in content_lower:
            return {
                "type": "tool_call",
                "tool_name": "execute_exploit",
                "message": "💥 Executing Metasploit exploit",
                "scan_id": scan_id,
                "phase": "exploitation"
            }
        elif "ssh_execute" in content_lower:
            return {
                "type": "tool_call",
                "tool_name": "ssh_execute",
                "message": "🐚 Executing commands via SSH",
                "scan_id": scan_id,
                "phase": "post_exploitation"
            }
        elif "get_banner" in content_lower:
            return {
                "type": "tool_call",
                "tool_name": "get_banner",
                "message": "🔍 Getting service banner information",
                "scan_id": scan_id,
                "phase": "reconnaissance"
            }
        elif "search_exploits" in content_lower:
            return {
                "type": "tool_call",
                "tool_name": "search_exploits_fast",
                "message": "🔎 Searching for relevant exploits",
                "scan_id": scan_id,
                "phase": "vulnerability_analysis"
            }
        return None

    async def _save_results_via_mcp(self, scan_id: str, target_host: str,
                                   shells_obtained: list, credentials_found: list,
                                   vulnerabilities_found: list):
        """Save hacking results to database using MCP tools."""
        try:
            # Use the MCP tools to save results
            if hasattr(self, 'mcp_tools') and self.mcp_tools:
                # Create a temporary agent to call the MCP tool
                temp_agent = Agent(
                    model=self.agent.model,
                    tools=[self.mcp_tools],
                    instructions="You are a helper agent to save hacking results to the database."
                )

                # Use the agent to call the save_hacking_results tool
                save_prompt = f"""
                Save the hacking results to the database using the save_hacking_results tool with these parameters:
                - scan_id: {scan_id}
                - target_host: {target_host}
                - shells_obtained: {json.dumps(shells_obtained)}
                - credentials_found: {json.dumps(credentials_found)}
                - vulnerabilities_found: {json.dumps(vulnerabilities_found)}
                - methodology_steps: {json.dumps([])}

                Call the save_hacking_results tool now.
                """

                result = await temp_agent.arun(save_prompt)
            else:
                pass  # No MCP tools available

        except Exception as e:
            pass  # Failed to save results


@tool(
    name="hack_machine",
    description="Execute a systematic penetration test against a target machine to gain shell access. "
               "This tool follows a complete hacking methodology including reconnaissance, "
               "vulnerability assessment, exploitation, and post-exploitation activities. "
               "Yields progress updates in real-time and returns structured results with actionable next steps.",
    show_result=True,
    stop_after_tool_call=False  # Allow the agent to continue after hacking
)
async def hack_machine(target_host: str, target_ports: str = "1-65535",
                      scan_rate: int = 1000):
    """
    Execute a systematic penetration test against a target machine.

    This tool implements a complete penetration testing methodology:
    1. Reconnaissance (port scanning, service enumeration)
    2. Vulnerability assessment (nuclei scanning)
    3. Exploitation (SSH brute force, Metasploit exploits)
    4. Post-exploitation (command execution, information gathering)

    Args:
        target_host: Target IP address or hostname to hack
        target_ports: Port range to scan (default: 1-65535)
        scan_rate: Scan rate for port scanning (default: 1000)

    Returns:
        Structured report with:
        - Success/failure status
        - Shells obtained (with connection details)
        - Credentials discovered
        - Vulnerabilities found
        - Recommended next steps for the main agent
        - Detailed execution log
    """
    # Create a simple hacking agent for this specific task
    import os
    ollama_host = os.getenv("OLLAMA_HOST", "http://192.168.0.242:11434")
    hacking_agent = HackingAgent(
        ollama_model="qwen3:14b",
        ollama_host=ollama_host,
        mcp_timeout=600
    )

    # Initialize the agent
    if not await hacking_agent.initialize():
        return "❌ Failed to initialize hacking agent"

    try:
        # Stream the hacking process - collect updates and print them for visibility
        final_result = None
        update_count = 0

        async for update in hacking_agent.hack_machine_streaming(
            target_host=target_host,
            target_ports=target_ports,
            scan_rate=scan_rate
        ):
            update_count += 1

            # Print streaming updates so we can see them in the tool output
            scan_display = update.get("scan_display_id", "unknown")

            if update["type"] == "status":
                print(f"📡 [{scan_display}] {update['message']}")
            elif update["type"] == "tool_call":
                # Print tool call with parameters
                tool_name = update.get("tool_name", "unknown")
                parameters = update.get("parameters", {})
                if parameters:
                    # Format parameters nicely
                    param_str = ", ".join([f"{k}={v}" for k, v in parameters.items()])
                    print(f"🔧 [{scan_display}] Calling {tool_name} with parameters: {param_str}")
                else:
                    print(f"🔧 [{scan_display}] Calling {tool_name}")
            elif update["type"] == "tool_result":
                print(f"✅ [{scan_display}] {update['message']}")
            elif update["type"] == "finding":
                print(f"🎯 [{scan_display}] {update['message']}")
            elif update["type"] == "complete":
                print(f"✅ [{scan_display}] {update['message']}")
                final_result = update["final_report"]
                break
            elif update["type"] == "error":
                print(f"❌ [{scan_display}] {update['message']}")
                final_result = update["final_report"]
                break

        print(f"\n📊 Processed {update_count} streaming updates")

        # Return the final comprehensive report
        return final_result if final_result else "No final result received"

    finally:
        # Always cleanup the hacking agent resources
        await hacking_agent.cleanup()
