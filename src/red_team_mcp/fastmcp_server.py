#!/usr/bin/env python3
"""
FastMCP Server - Red Team MCP using FastMCP

This creates a minimal but functional red team MCP server using FastMCP.
"""

import json
import subprocess
import socket
from typing import Annotated
from pydantic import BaseModel, Field

from fastmcp import FastMCP
from red_team_mcp import database, nuclei_scanner, masscan_scanner, ssh_scanner

# Pydantic models for better schema control
class PortScanParams(BaseModel):
    target: str = Field(
        description="IP address or CIDR range to scan (e.g., '192.168.1.1' or '10.0.0.0/24')",
        examples=["192.168.1.1", "10.0.0.0/24", "172.16.1.0/24"]
    )
    ports: str = Field(
        default="80,443,22,8080,8443,3389,11434",
        description="Comma-separated ports or ranges (e.g., '80,443' or '1-1000' or '80,443,8080-8090')",
        examples=["80,443", "1-1000", "22,80,443,8080-8090"]
    )
    scan_type: str = Field(
        default="tcp_syn",
        description="Type of scan: must be exactly 'tcp_syn', 'tcp_connect', 'udp', 'tcp_ack', or 'tcp_window'",
        examples=["tcp_syn", "tcp_connect", "udp"]
    )
    rate: int = Field(
        default=100,
        description="Packets per second rate (100-10000, higher = faster but more aggressive)",
        ge=100,
        le=10000,
        examples=[100, 500, 1000]
    )


class VulerabilityScanParameters(BaseModel):
    host: str = Field(
        description="Hostname or IP address to scan for vulnerabilities",
        examples=["example.com", "192.168.1.1", "google.com", "10.0.0.1"]
    )
    port: int = Field(
        description="Port number to scan for vulnerabilities",
        examples=[80, 443, 22, 8080, 3389],
        ge=1,
        le=65535
    )


# Create FastMCP server
app = FastMCP("Red Team MCP")

# Initialize database on startup
database.init_database()

# Register SSH tools
ssh_scanner.register_tools(app)

@app.tool()
def resolve_hostname_to_ip(
    hostname: Annotated[str, "Hostname or domain name to resolve (e.g., 'google.com', 'example.org')"]
) -> str:
    """Resolve a hostname to an IP address."""
    try:
        ip_address = socket.gethostbyname(hostname)
        return json.dumps({
            "success": True,
            "hostname": hostname,
            "ip_address": ip_address,
            "message": "Hostname resolved successfully"
        })
    except Exception as e:
        return json.dumps({
            "success": False,
            "message": f"Failed to resolve hostname: {str(e)}"
        })





@app.tool()
def port_scan(params: PortScanParams) -> str:
    """
    NETWORK PORT SCANNING: Discover open ports on hosts using masscan.

    This tool performs PORT DISCOVERY to find open TCP/UDP ports on target hosts.
    It does NOT scan for vulnerabilities - use vulnerability_scan for that.

    Use this tool when you want to:
    - Find what ports are open on a host
    - Discover services running on a network
    - Map network topology and services

    Examples:
    - Find open ports: target='192.168.1.1', ports='80,443,22'
    - Scan network range: target='10.0.0.0/24', ports='1-1000'
    - Quick web scan: target='example.com', ports='80,443'

    IMPORTANT: This tool only finds OPEN PORTS, not vulnerabilities.
    For vulnerability scanning, use the vulnerability_scan tool instead.
    """
    try:
        # Call the port_scan function from masscan_scanner module
        result = masscan_scanner.port_scan(
            params.target, 
            params.ports, 
            params.scan_type, 
            params.rate
        )

        # Convert the result to JSON string
        return json.dumps(result)

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        })


@app.tool()
def enumerate_vulnerabilities(params: VulerabilityScanParameters) -> str:
    """
    ENUMERATE VULNERABILITIES: Find security issues and CVEs using nuclei scanner.

    This tool ENUMERATES VULNERABILITIES, MISCONFIGURATIONS, and SECURITY ISSUES.
    It does NOT find open ports - use port_scan for port discovery.

    Use this tool when you want to:
    - Enumerate security vulnerabilities (CVEs)
    - Detect misconfigurations
    - Check for exposed sensitive files
    - Identify weak SSL/TLS configurations

    Examples:
    - Enumerate web vulns: host='example.com', port=80
    - HTTPS enumeration: host='example.com', port=443
    - SSH enumeration: host='192.168.1.1', port=22
    - Custom service: host='target.com', port=8080

    IMPORTANT: This tool ENUMERATES VULNERABILITIES, not open ports.
    For port discovery, use the port_scan tool instead.
    """
    try:
        # Call the enumerate_vulnerabilities function from nuclei_scanner module
        result = nuclei_scanner.enumerate_vulnerabilities(
            params.host,
            params.port
        )

        # Convert the result to JSON string
        return json.dumps(result)

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        })


@app.tool()
def get_banner(
    ip: Annotated[str, "IP address to connect to (e.g., '192.168.1.1')"],
    port: Annotated[int, "Port number to connect to (e.g., 80, 443, 22)"],
    timeout: Annotated[int, "Connection timeout in seconds (1-30)"] = 5
) -> str:
    """
    Use netcat to connect to a host:port and retrieve banner information.

    Args:
        ip: IP address to connect to
        port: Port number to connect to
        timeout: Connection timeout in seconds (default: 5)

    Returns:
        JSON string with service, version, and banner information
    """
    try:
        banner_info = masscan_scanner.getBanner(ip, port, timeout)
        return json.dumps({
            "success": True,
            "ip": ip,
            "port": port,
            "service": banner_info.get("service", "unknown"),
            "version": banner_info.get("version", ""),
            "banner": banner_info.get("banner", ""),
            "message": f"Banner retrieved for {ip}:{port}"
        })
    except Exception as e:
        return json.dumps({
            "success": False,
            "ip": ip,
            "port": port,
            "error": str(e),
            "message": f"Failed to retrieve banner for {ip}:{port}"
        })

@app.tool()
def get_finished_scan_results(
    limit: Annotated[int, "Maximum number of scan results to return (1-100)"] = 10,
    scan_id: Annotated[str, "Optional: specific scan ID to retrieve (UUID format)"] = None
) -> str:
    """Get all finished scan results from database."""
    try:
        result = database.get_finished_scan_results(limit, scan_id)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "message": "Failed to retrieve scan results"
        })


@app.tool()
def search_scan_results(
    hostname: Annotated[str, "Hostname to search for (optional)"] = None,
    ip_address: Annotated[str, "IP address to search for (optional)"] = None,
    port: Annotated[int, "Port number to search for (optional)"] = None,
    service: Annotated[str, "Service name to search for (optional)"] = None,
    limit: Annotated[int, "Maximum number of results to return (1-100)"] = 20
) -> str:
    """
    Search scan results by hostname, IP address, port, or service.

    This allows flexible searching across all scan results to find:
    - All ports open on a specific host
    - All hosts running a specific service
    - All instances of a specific port across hosts

    Examples:
    - Find all ports on google.com: hostname='google.com'
    - Find all web servers: port=80 or service='http'
    - Find all SSH services: port=22 or service='ssh'
    """
    try:
        result = database.search_scan_results(hostname, ip_address, port, service, limit)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "message": "Failed to search scan results"
        })


@app.tool()
def search_vulnerability_results(
    hostname: Annotated[str, "Hostname to search for (optional)"] = None,
    ip_address: Annotated[str, "IP address to search for (optional)"] = None,
    port: Annotated[int, "Port number to search for (optional)"] = None,
    severity: Annotated[str, "Severity level to search for (info,low,medium,high,critical)"] = None,
    template_id: Annotated[str, "Template ID to search for (optional)"] = None,
    limit: Annotated[int, "Maximum number of results to return (1-100)"] = 20
) -> str:
    """
    Search vulnerability scan results by various criteria.

    This allows searching across all vulnerability scan results to find:
    - All vulnerabilities on a specific host
    - All high/critical severity issues
    - All instances of a specific vulnerability type

    Examples:
    - Find all vulns on host: hostname='example.com'
    - Find critical issues: severity='critical'
    - Find specific CVE: template_id='CVE-2021-44228'
    """
    try:
        result = database.search_vulnerability_results(hostname, ip_address, port, severity, template_id, limit)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "message": "Failed to search vulnerability results"
        })


@app.tool()
def list_capabilities() -> str:
    """List all available red team capabilities."""
    capabilities = {
        "scanning": {
            "port_scan": "Scan networks and hosts for open ports (includes automatic banner grabbing)",
            "enumerate_vulnerabilities": "Enumerate vulnerabilities and security issues using nuclei scanner",

            "get_finished_scan_results": "Retrieve all completed scan results from database",
            "search_scan_results": "Search scan results by hostname, IP, port, or service",
            "search_vulnerability_results": "Search vulnerability scan results by various criteria",
            "resolve_hostname_to_ip": "Resolve a hostname to an IP address",
            "get_banner": "Use netcat to retrieve service banner from a specific host:port"
        },

        "ssh": {
            "ssh_execute": "Execute commands on remote hosts via SSH with username/password authentication",
            "ssh_brute_force": "Brute force SSH credentials using username and password lists"
        },

        "analysis": {
            "list_capabilities": "Show all available tools and capabilities"
        }
    }

    return json.dumps({
        "success": True,
        "capabilities": capabilities,
        "message": "Red Team MCP capabilities listed"
    })


if __name__ == "__main__":
    # Run the FastMCP server
    app.run()
