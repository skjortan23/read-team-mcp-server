"""
MCP Tools for Agno Agent

Custom tools that allow Agno agents to interact with the Red Team MCP server.
"""

import asyncio
from typing import Any, Dict, List, Optional

from agno.tools import Tool
from fastmcp import Client


class RedTeamMCPTools(Tool):
    """Tools for interacting with the Red Team MCP server."""
    
    def __init__(self, server_script: str = "examples/fastmcp_server.py"):
        super().__init__()
        self.server_script = server_script
        self.client: Optional[Client] = None
        self.tools: List[Any] = []
        
    async def _ensure_connected(self) -> bool:
        """Ensure we're connected to the MCP server."""
        if self.client is None:
            try:
                self.client = Client(self.server_script)
                await self.client.__aenter__()
                self.tools = await self.client.list_tools()
                return True
            except Exception as e:
                print(f"Failed to connect to MCP server: {e}")
                return False
        return True
    
    async def _call_mcp_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Call an MCP tool and return the result."""
        if not await self._ensure_connected():
            return "Error: Could not connect to MCP server"
        
        try:
            result = await self.client.call_tool(tool_name, arguments)
            if result:
                return result[0].text if isinstance(result, list) else result.text
            return "No result returned"
        except Exception as e:
            return f"Error calling MCP tool {tool_name}: {e}"
    
    def port_scan(self, target: str, ports: str = "1-1000", scan_type: str = "tcp_syn") -> str:
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
        return asyncio.run(self._call_mcp_tool("scan_status", {
            "scan_id": scan_id
        }))
    
    def list_scans(self) -> str:
        """
        List all scan operations.
        
        Returns:
            JSON string with list of all scans
        """
        return asyncio.run(self._call_mcp_tool("list_scans", {}))
    
    def cancel_scan(self, scan_id: str) -> str:
        """
        Cancel a running scan operation.
        
        Args:
            scan_id: The ID of the scan to cancel
        
        Returns:
            JSON string with cancellation result
        """
        return asyncio.run(self._call_mcp_tool("cancel_scan", {
            "scan_id": scan_id
        }))
    
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
    
    async def cleanup(self):
        """Clean up the MCP client connection."""
        if self.client:
            try:
                await self.client.__aexit__(None, None, None)
            except Exception:
                pass
            self.client = None


class RedTeamMCPToolsSync(Tool):
    """Synchronous wrapper for Red Team MCP tools."""
    
    def __init__(self, server_script: str = "examples/fastmcp_server.py"):
        super().__init__()
        self.server_script = server_script
        self._async_tools = RedTeamMCPTools(server_script)
    
    def port_scan(self, target: str, ports: str = "1-1000", scan_type: str = "tcp_syn") -> str:
        """
        Perform a port scan on a target using masscan.
        
        Args:
            target: IP address or CIDR range to scan (e.g., '192.168.1.0/24')
            ports: Ports to scan (e.g., '80,443' or '1-1000')
            scan_type: Type of scan (tcp_syn, tcp_connect, udp, tcp_ack, tcp_window)
        
        Returns:
            JSON string with scan results
        """
        return self._async_tools.port_scan(target, ports, scan_type)
    
    def scan_status(self, scan_id: str) -> str:
        """
        Get the status of a running or completed scan.
        
        Args:
            scan_id: The ID of the scan to check
        
        Returns:
            JSON string with scan status and results
        """
        return self._async_tools.scan_status(scan_id)
    
    def list_scans(self) -> str:
        """
        List all scan operations.
        
        Returns:
            JSON string with list of all scans
        """
        return self._async_tools.list_scans()
    
    def cancel_scan(self, scan_id: str) -> str:
        """
        Cancel a running scan operation.
        
        Args:
            scan_id: The ID of the scan to cancel
        
        Returns:
            JSON string with cancellation result
        """
        return self._async_tools.cancel_scan(scan_id)
    
    def validate_masscan(self) -> str:
        """
        Validate that masscan is properly configured.
        
        Returns:
            JSON string with validation results
        """
        return self._async_tools.validate_masscan()
    
    def get_finished_scan_results(self) -> str:
        """
        Retrieve all completed scan results from the database.
        
        Returns:
            JSON string with all finished scan results
        """
        return self._async_tools.get_finished_scan_results()
