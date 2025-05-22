"""Red Team MCP Server.

An MCP (Model Context Protocol) server for AI agents to use during red teaming exercises.
"""

__version__ = "0.1.0"
__author__ = "Red Team MCP"
__email__ = "skjortan@gmail.com"

from .server import RedTeamMCPServer

__all__ = ["RedTeamMCPServer"]
