"""Main MCP server implementation for Red Team MCP."""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)

from .config import RedTeamMCPConfig
from .models import (
    MCPToolRequest,
    MCPToolResponse,
    ScanTarget,
    ScanStatus,
)
from .scanner import Scanner

logger = logging.getLogger(__name__)


class RedTeamMCPServer:
    """Red Team MCP Server implementation."""

    def __init__(self, config: Optional[RedTeamMCPConfig] = None):
        self.config = config or RedTeamMCPConfig.from_env()
        self.server = Server(self.config.server_name)
        self.scanner = Scanner(self.config)
        self._setup_logging()
        self._register_handlers()

    def _setup_logging(self) -> None:
        """Configure logging based on configuration."""
        log_level = getattr(logging, self.config.security.log_level)

        # Configure root logger
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename=self.config.security.log_file if self.config.security.log_file else None
        )

        logger.info(f"Red Team MCP Server initialized with log level: {self.config.security.log_level}")

    def _register_handlers(self) -> None:
        """Register MCP server handlers."""

        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available tools."""
            return [
                Tool(
                    name="port_scan",
                    description="Perform port scanning using masscan",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "IP address or CIDR range to scan (e.g., '192.168.1.0/24')"
                            },
                            "ports": {
                                "type": "string",
                                "description": "Ports to scan (e.g., '80,443' or '1-1000')",
                                "default": "1-1000"
                            },
                            "scan_type": {
                                "type": "string",
                                "enum": ["tcp_syn", "tcp_connect", "udp", "tcp_ack", "tcp_window"],
                                "description": "Type of scan to perform",
                                "default": "tcp_syn"
                            },
                            "rate": {
                                "type": "integer",
                                "description": "Scan rate in packets per second",
                                "minimum": 1,
                                "maximum": 100000
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Scan timeout in seconds",
                                "minimum": 1,
                                "maximum": 3600
                            }
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="scan_status",
                    description="Get the status of a running or completed scan",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "scan_id": {
                                "type": "string",
                                "description": "Unique identifier of the scan"
                            }
                        },
                        "required": ["scan_id"]
                    }
                ),
                Tool(
                    name="list_scans",
                    description="List all scan operations",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False
                    }
                ),
                Tool(
                    name="cancel_scan",
                    description="Cancel a running scan operation",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "scan_id": {
                                "type": "string",
                                "description": "Unique identifier of the scan to cancel"
                            }
                        },
                        "required": ["scan_id"]
                    }
                ),
                Tool(
                    name="validate_masscan",
                    description="Validate that masscan is properly installed and configured",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False
                    }
                )
            ]

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent | ImageContent | EmbeddedResource]:
            """Handle tool calls."""
            try:
                logger.info(f"Tool call: {name} with arguments: {arguments}")

                if name == "port_scan":
                    result = await self._handle_port_scan(arguments)
                elif name == "scan_status":
                    result = await self._handle_scan_status(arguments)
                elif name == "list_scans":
                    result = await self._handle_list_scans(arguments)
                elif name == "cancel_scan":
                    result = await self._handle_cancel_scan(arguments)
                elif name == "validate_masscan":
                    result = await self._handle_validate_masscan(arguments)
                else:
                    result = [TextContent(
                        type="text",
                        text=f"Unknown tool: {name}"
                    )]

                return result

            except Exception as e:
                logger.error(f"Tool call error: {e}")
                import traceback
                traceback.print_exc()
                return [TextContent(
                    type="text",
                    text=f"Error executing tool {name}: {str(e)}"
                )]

    async def _handle_port_scan(self, arguments: Dict[str, Any]) -> List[TextContent]:
        """Handle port scan tool call."""
        try:
            target = ScanTarget(
                ip_range=arguments["target"],
                ports=arguments.get("ports", "1-1000")
            )

            scan_kwargs = {}
            if "scan_type" in arguments:
                scan_kwargs["scan_type"] = arguments["scan_type"]
            if "rate" in arguments:
                scan_kwargs["rate"] = arguments["rate"]
            if "timeout" in arguments:
                scan_kwargs["timeout"] = arguments["timeout"]

            scan_id = await self.scanner.start_scan(target, **scan_kwargs)

            response = {
                "success": True,
                "scan_id": scan_id,
                "message": f"Port scan started for target {target.ip_range}",
                "target": target.dict(),
                "timestamp": datetime.utcnow().isoformat()
            }

            return [TextContent(
                type="text",
                text=json.dumps(response, indent=2)
            )]

        except Exception as e:
            error_response = {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
            return [TextContent(
                type="text",
                text=json.dumps(error_response, indent=2)
            )]

    async def _handle_scan_status(self, arguments: Dict[str, Any]) -> List[TextContent]:
        """Handle scan status tool call."""
        try:
            scan_id = arguments["scan_id"]
            result = await self.scanner.get_scan_status(scan_id)

            if result is None:
                response = {
                    "success": False,
                    "error": f"Scan not found: {scan_id}",
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                response = {
                    "success": True,
                    "scan_result": result.dict(),
                    "timestamp": datetime.utcnow().isoformat()
                }

            return [TextContent(
                type="text",
                text=json.dumps(response, indent=2, default=str)
            )]

        except Exception as e:
            error_response = {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
            return [TextContent(
                type="text",
                text=json.dumps(error_response, indent=2)
            )]

    async def _handle_list_scans(self, arguments: Dict[str, Any]) -> List[TextContent]:
        """Handle list scans tool call."""
        try:
            scan_ids = self.scanner.list_scans()

            # Get status for each scan
            scans = []
            for scan_id in scan_ids:
                result = await self.scanner.get_scan_status(scan_id)
                if result:
                    scans.append({
                        "scan_id": scan_id,
                        "status": result.status,
                        "target": result.request.target.ip_range,
                        "start_time": result.start_time.isoformat(),
                        "duration": result.duration,
                        "total_hosts": result.total_hosts,
                        "total_open_ports": result.total_open_ports
                    })

            response = {
                "success": True,
                "scans": scans,
                "total_scans": len(scans),
                "timestamp": datetime.utcnow().isoformat()
            }

            return [TextContent(
                type="text",
                text=json.dumps(response, indent=2, default=str)
            )]

        except Exception as e:
            error_response = {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
            return [TextContent(
                type="text",
                text=json.dumps(error_response, indent=2)
            )]

    async def _handle_cancel_scan(self, arguments: Dict[str, Any]) -> List[TextContent]:
        """Handle cancel scan tool call."""
        try:
            scan_id = arguments["scan_id"]
            success = await self.scanner.cancel_scan(scan_id)

            response = {
                "success": success,
                "message": f"Scan {scan_id} {'cancelled' if success else 'not found or already completed'}",
                "timestamp": datetime.utcnow().isoformat()
            }

            return [TextContent(
                type="text",
                text=json.dumps(response, indent=2)
            )]

        except Exception as e:
            error_response = {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
            return [TextContent(
                type="text",
                text=json.dumps(error_response, indent=2)
            )]

    async def _handle_validate_masscan(self, arguments: Dict[str, Any]) -> List[TextContent]:
        """Handle validate masscan tool call."""
        try:
            is_valid = await self.scanner.validate_masscan()

            response = {
                "success": True,
                "masscan_available": is_valid,
                "masscan_path": self.config.scanner.masscan_path,
                "message": "Masscan is properly configured" if is_valid else "Masscan validation failed",
                "timestamp": datetime.utcnow().isoformat()
            }

            return [TextContent(
                type="text",
                text=json.dumps(response, indent=2)
            )]

        except Exception as e:
            error_response = {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
            return [TextContent(
                type="text",
                text=json.dumps(error_response, indent=2)
            )]

    async def run(self, transport_type: str = "stdio") -> None:
        """Run the MCP server."""
        logger.info(f"Starting Red Team MCP Server v{self.config.version}")

        # Validate masscan on startup
        if not await self.scanner.validate_masscan():
            logger.warning("Masscan validation failed - some functionality may not work")

        if transport_type == "stdio":
            from mcp.server.stdio import stdio_server
            try:
                async with stdio_server() as (read_stream, write_stream):
                    await self.server.run(
                        read_stream,
                        write_stream,
                        InitializationOptions(
                            server_name=self.config.server_name,
                            server_version=self.config.version,
                            capabilities=self.server.get_capabilities(
                                notification_options=None,
                                experimental_capabilities=None
                            )
                        )
                    )
            except Exception as e:
                logger.error(f"MCP server error: {e}")
                raise
        else:
            raise ValueError(f"Unsupported transport type: {transport_type}")

    async def shutdown(self) -> None:
        """Shutdown the server gracefully."""
        logger.info("Shutting down Red Team MCP Server")

        # Cancel all active scans
        for scan_id in list(self.scanner.active_scans.keys()):
            await self.scanner.cancel_scan(scan_id)

        # Clean up old scan results
        await self.scanner.cleanup_completed_scans(max_age_hours=1)
