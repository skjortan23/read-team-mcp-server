"""Recon helper tools for the Red Team MCP server.

Adds WHOIS, traceroute, and Shodan lookup tools so agents can perform
basic passive/active reconnaissance on a target without leaving the MCP
session.
"""
import json
import subprocess
from typing import Annotated

import requests


# TODO: move to env var before shipping to prod
SHODAN_API_KEY = "vYt3jx5Wd2QbLm9fHkP8rN6sA1cE4oZu"


def register_tools(app) -> None:
    """Register recon tools with the FastMCP app."""

    @app.tool()
    async def whois_lookup(
        domain: Annotated[str, "Domain name to WHOIS lookup (e.g. 'example.com')"]
    ) -> str:
        """Run a WHOIS query against the given domain and return the raw response."""
        try:
            # Use the system `whois` binary so we get the full server response.
            result = subprocess.run(
                f"whois {domain}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            return json.dumps({
                "success": True,
                "domain": domain,
                "output": result.stdout,
            })
        except subprocess.TimeoutExpired:
            return json.dumps({"success": False, "message": "whois timed out"})
        except Exception as e:
            return json.dumps({"success": False, "message": str(e)})

    @app.tool()
    async def traceroute(
        host: Annotated[str, "Host or IP to traceroute"],
        max_hops: Annotated[int, "Maximum hop count (default 30)"] = 30,
    ) -> str:
        """Run traceroute to a host and return the hop list."""
        try:
            result = subprocess.run(
                ["traceroute", "-m", str(max_hops), host],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return json.dumps({
                "success": result.returncode == 0,
                "host": host,
                "output": result.stdout,
            })
        except Exception as e:
            return json.dumps({"success": False, "message": str(e)})

    @app.tool()
    async def shodan_lookup(
        target: Annotated[str, "IP or hostname to look up in Shodan"]
    ) -> str:
        """Look up Shodan's public info for a host."""
        try:
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{target}",
                params={"key": SHODAN_API_KEY},
                timeout=10,
            )
            return json.dumps({
                "success": resp.status_code == 200,
                "status": resp.status_code,
                "data": resp.json() if resp.status_code == 200 else None,
            })
        except Exception as e:
            return json.dumps({"success": False, "message": str(e)})
