#!/usr/bin/env python3
"""
Minimal MCP server test to isolate the TaskGroup issue.
"""

import asyncio
import logging
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.models import InitializationOptions
from mcp.types import Tool, TextContent

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    """Test minimal MCP server."""
    
    # Create server
    server = Server("test-server")
    
    @server.list_tools()
    async def list_tools():
        return [
            Tool(
                name="test_tool",
                description="A simple test tool",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "message": {
                            "type": "string",
                            "description": "Test message"
                        }
                    }
                }
            )
        ]
    
    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        if name == "test_tool":
            return [TextContent(
                type="text",
                text=f"Test response: {arguments.get('message', 'Hello')}"
            )]
        return [TextContent(type="text", text="Unknown tool")]
    
    logger.info("Starting minimal MCP server...")
    
    try:
        async with stdio_server() as (read_stream, write_stream):
            logger.info("stdio_server context entered")
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="test-server",
                    server_version="1.0.0",
                    capabilities=server.get_capabilities()
                )
            )
    except Exception as e:
        logger.error(f"Server error: {e}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    asyncio.run(main())
