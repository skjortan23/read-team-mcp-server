#!/usr/bin/env python3
"""
Red Team MCP Agent - Interactive CLI Agent

A command-line agent that connects to the Red Team MCP server and provides
an interactive interface for red team operations.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory

from fastmcp import Client


class RedTeamAgent:
    """Interactive Red Team MCP Agent."""
    
    def __init__(self, server_script: str = "examples/fastmcp_server.py"):
        self.console = Console()
        self.server_script = server_script
        self.client: Optional[Client] = None
        self.tools: List[Dict[str, Any]] = []
        self.session = PromptSession(history=InMemoryHistory())
        
        # Available commands
        self.commands = {
            'help': self.cmd_help,
            'tools': self.cmd_list_tools,
            'scan': self.cmd_port_scan,
            'status': self.cmd_scan_status,
            'list': self.cmd_list_scans,
            'cancel': self.cmd_cancel_scan,
            'validate': self.cmd_validate_masscan,
            'results': self.cmd_get_results,
            'exit': self.cmd_exit,
            'quit': self.cmd_exit,
        }
        
        # Command completer
        self.completer = WordCompleter(list(self.commands.keys()))
    
    async def connect(self) -> bool:
        """Connect to the MCP server."""
        try:
            self.console.print("🔌 Connecting to Red Team MCP server...", style="yellow")
            self.client = Client(self.server_script)
            await self.client.__aenter__()
            
            # Discover available tools
            self.tools = await self.client.list_tools()
            
            self.console.print("✅ Connected successfully!", style="green")
            self.console.print(f"📋 Discovered {len(self.tools)} tools", style="blue")
            return True
            
        except Exception as e:
            self.console.print(f"❌ Connection failed: {e}", style="red")
            return False
    
    async def disconnect(self):
        """Disconnect from the MCP server."""
        if self.client:
            try:
                await self.client.__aexit__(None, None, None)
                self.console.print("🔌 Disconnected from server", style="yellow")
            except Exception as e:
                self.console.print(f"⚠️  Disconnect error: {e}", style="yellow")
    
    def display_banner(self):
        """Display the agent banner."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  Red Team MCP Agent                    ║
║                                                              ║
║  Interactive CLI for Red Team Operations                     ║
║  Type 'help' for available commands                         ║
╚══════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold cyan")
    
    async def cmd_help(self, args: List[str]) -> None:
        """Show help information."""
        table = Table(title="Available Commands", show_header=True, header_style="bold magenta")
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")
        table.add_column("Example", style="green")
        
        help_data = [
            ("help", "Show this help message", "help"),
            ("tools", "List available MCP tools", "tools"),
            ("scan", "Start a port scan", "scan 192.168.1.1 80,443"),
            ("status", "Check scan status", "status <scan_id>"),
            ("list", "List all scans", "list"),
            ("cancel", "Cancel a running scan", "cancel <scan_id>"),
            ("validate", "Validate masscan installation", "validate"),
            ("results", "Get finished scan results", "results"),
            ("exit/quit", "Exit the agent", "exit"),
        ]
        
        for cmd, desc, example in help_data:
            table.add_row(cmd, desc, example)
        
        self.console.print(table)
    
    async def cmd_list_tools(self, args: List[str]) -> None:
        """List available MCP tools."""
        if not self.tools:
            self.console.print("❌ No tools available", style="red")
            return
        
        table = Table(title="Available MCP Tools", show_header=True, header_style="bold magenta")
        table.add_column("Tool Name", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")
        
        for tool in self.tools:
            table.add_row(tool.name, tool.description)
        
        self.console.print(table)
    
    async def cmd_port_scan(self, args: List[str]) -> None:
        """Start a port scan."""
        if len(args) < 1:
            target = Prompt.ask("Enter target IP/CIDR", default="127.0.0.1")
        else:
            target = args[0]
        
        if len(args) < 2:
            ports = Prompt.ask("Enter ports to scan", default="1-1000")
        else:
            ports = args[1]
        
        scan_type = Prompt.ask("Scan type", 
                              choices=["tcp_syn", "tcp_connect", "udp", "tcp_ack", "tcp_window"],
                              default="tcp_syn")
        
        try:
            self.console.print(f"🔍 Starting port scan on {target}:{ports}", style="yellow")
            
            result = await self.client.call_tool("port_scan", {
                "target": target,
                "ports": ports,
                "scan_type": scan_type
            })
            
            if result:
                data = json.loads(result[0].text)
                if data.get("success"):
                    scan_id = data.get("scan_id")
                    self.console.print(f"✅ Scan started successfully!", style="green")
                    self.console.print(f"📋 Scan ID: {scan_id}", style="blue")
                else:
                    self.console.print(f"❌ Scan failed: {data.get('message', 'Unknown error')}", style="red")
            
        except Exception as e:
            self.console.print(f"❌ Error starting scan: {e}", style="red")
    
    async def cmd_scan_status(self, args: List[str]) -> None:
        """Check scan status."""
        if len(args) < 1:
            scan_id = Prompt.ask("Enter scan ID")
        else:
            scan_id = args[0]
        
        try:
            result = await self.client.call_tool("scan_status", {"scan_id": scan_id})
            
            if result:
                data = json.loads(result[0].text)
                if data.get("success"):
                    scan_info = data.get("scan")
                    status = scan_info.get("status")
                    
                    # Create status panel
                    status_text = f"""
Status: {status}
Target: {scan_info.get('target', 'N/A')}
Start Time: {scan_info.get('start_time', 'N/A')}
Duration: {scan_info.get('duration', 'N/A')}s
Total Hosts: {scan_info.get('total_hosts', 0)}
Open Ports: {scan_info.get('total_open_ports', 0)}
                    """
                    
                    panel = Panel(status_text.strip(), title=f"Scan Status: {scan_id[:8]}...", 
                                border_style="blue")
                    self.console.print(panel)
                    
                    # Show results if completed
                    if status == "COMPLETED" and scan_info.get('hosts'):
                        self._display_scan_results(scan_info.get('hosts', []))
                        
                else:
                    self.console.print(f"❌ {data.get('message', 'Scan not found')}", style="red")
            
        except Exception as e:
            self.console.print(f"❌ Error checking status: {e}", style="red")
    
    def _display_scan_results(self, hosts: List[Dict[str, Any]]):
        """Display scan results in a formatted table."""
        if not hosts:
            self.console.print("No hosts found", style="yellow")
            return
        
        table = Table(title="Scan Results", show_header=True, header_style="bold green")
        table.add_column("Host", style="cyan", no_wrap=True)
        table.add_column("Port", style="magenta", no_wrap=True)
        table.add_column("Protocol", style="blue", no_wrap=True)
        table.add_column("Service", style="green")
        table.add_column("Banner", style="white")
        
        for host in hosts:
            ip = host.get('ip', 'Unknown')
            for port_info in host.get('ports', []):
                port = str(port_info.get('port', ''))
                protocol = port_info.get('protocol', 'tcp')
                service = port_info.get('service', 'unknown')
                banner = port_info.get('banner', '')[:50] + ('...' if len(port_info.get('banner', '')) > 50 else '')
                
                table.add_row(ip, port, protocol, service, banner)
        
        self.console.print(table)
    
    async def cmd_list_scans(self, args: List[str]) -> None:
        """List all scans."""
        try:
            result = await self.client.call_tool("list_scans", {})
            
            if result:
                data = json.loads(result[0].text)
                if data.get("success"):
                    scans = data.get("scans", [])
                    
                    if not scans:
                        self.console.print("No scans found", style="yellow")
                        return
                    
                    table = Table(title="All Scans", show_header=True, header_style="bold magenta")
                    table.add_column("Scan ID", style="cyan", no_wrap=True)
                    table.add_column("Status", style="green")
                    table.add_column("Target", style="blue")
                    table.add_column("Start Time", style="white")
                    table.add_column("Hosts", style="yellow")
                    table.add_column("Ports", style="yellow")
                    
                    for scan in scans:
                        scan_id = scan.get('scan_id', '')[:8] + '...'
                        status = scan.get('status', 'Unknown')
                        target = scan.get('target', 'Unknown')
                        start_time = scan.get('start_time', '')[:19] if scan.get('start_time') else 'Unknown'
                        hosts = str(scan.get('total_hosts', 0))
                        ports = str(scan.get('total_open_ports', 0))
                        
                        table.add_row(scan_id, status, target, start_time, hosts, ports)
                    
                    self.console.print(table)
                else:
                    self.console.print(f"❌ {data.get('message', 'Failed to list scans')}", style="red")
            
        except Exception as e:
            self.console.print(f"❌ Error listing scans: {e}", style="red")
