#!/usr/bin/env python3
"""
FastMCP Server - Red Team MCP using FastMCP

This creates a minimal but functional red team MCP server using FastMCP.
"""
import argparse
import json
import socket
import subprocess
from typing import Annotated, AsyncGenerator, Dict, List
from pydantic import BaseModel, Field
from fastmcp import FastMCP
from red_team_mcp import database, ssh_scanner, metasploit_scanner, domain_discovery
from red_team_mcp.bannerGrabber import getBanner
import asyncio
from masscan import mass_port_scan
import logging

from red_team_mcp.vulnerability_scanner import scan_with_nuclei


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
        default=500,
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
app = FastMCP(
    name="Red Team MCP server",
    stateless_http=True,
    )

# Initialize database on startup
database.init_database()

# Register SSH tools
ssh_scanner.register_tools(app)

# Register Metasploit tools
metasploit_scanner.register_tools(app)

# Register Domain Discovery tools
domain_discovery.register_tools(app)

@app.tool()
async def resolve_hostname_to_ip(
    hostname: Annotated[str, "Hostname or domain name to resolve (e.g., 'google.com', 'example.org')"]
) -> str:
    """Resolve a hostname to an IP address with timeout."""
    try:
        # Run the blocking socket operation in a thread pool with timeout

        ip_address = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyname, hostname),
            timeout=10.0  # 10 second DNS timeout
        )
        return json.dumps({
            "success": True,
            "hostname": hostname,
            "ip_address": ip_address,
            "message": "Hostname resolved successfully"
        })
    except asyncio.TimeoutError:
        return json.dumps({
            "success": False,
            "message": f"DNS resolution timed out after 10 seconds for hostname: {hostname}"
        })
    except Exception as e:
        return json.dumps({
            "success": False,
            "message": f"Failed to resolve hostname: {str(e)}"
        })


@app.tool()
async def port_scan(params: PortScanParams) -> List[str]:
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

    logging.warning("starting mass scan")
    try:
        res = await mass_port_scan(target=params.target, ports=params.ports)
        logging.warning(res)
        return res
    except Exception as e:
        logging.warning("mass scanning failed:", e)



@app.tool(
    annotations={
        "title": "vulnerability scanner using nuclei scanner",
        "description": (
            "ENUMERATE VULNERABILITIES: Find security issues and CVEs using nuclei scanner with streaming output. "
            "This tool ENUMERATES VULNERABILITIES, MISCONFIGURATIONS, and SECURITY ISSUES. "
            "It does NOT find open ports - use port_scan for port discovery. "
            "Provides real-time progress updates during scanning."
        ),
        "readOnlyHint": False,
        "openWorldHint": True
    },
)
def enumerate_vulnerabilities(host: str, port: int) -> [str]:
    """
    ENUMERATE VULNERABILITIES: Find security issues and CVEs using nuclei scanner with streaming output.

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

    # 1) Build the exact same target URL you use on the CLI
    if port == 443:
        target_url = f"https://{host}:{port}"
    elif port == 80:
        target_url = f"http://{host}"
    else:
        target_url = f"http://{host}:{port}"

    # 2) Build the exact nuclei command that finishes in ~8 s locally
    cmd = [
        "nuclei",
        "-target", target_url,
        "-timeout", "3",         # 3 s per‐template timeout
        "-no-color",             # strip ANSI colors
        "-jsonl",                # JSON Lines output
        "-silent",               # progress → stderr
        "-pt", "http",
        "-severity", "medium,high,critical",
        "-tags", "http,web,ollama,api",
    ]

    logging.warning(f"starting vuln scan: command={" ".join(cmd)}")

    # 3) Run it synchronously with a 60 s hard cap
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90,   # if nuclei never returns in 60 s, bail out
            check=False,
        )
    except subprocess.TimeoutExpired:
        # Return an error message as a one‐element list
        logging.warning("vuln scan timeout")
        return [f"Nuclei scan timed out after 60 s"]

    # 4) (Optional) Log stderr to FastMCP’s logs for debugging
    stderr_text = proc.stderr.decode(errors="ignore").strip()
    if stderr_text:
        print("⏺ nuclei stderr:", stderr_text)

    # 5) Parse JSON Lines from stdout
    stdout_text = proc.stdout.decode(errors="ignore")
    findings = []
    for line in stdout_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            findings.append(json.dumps(json.loads(line)))
        except json.JSONDecodeError:
            # skip any malformed line
            continue

    # 6) If nuclei returned non‐zero, treat that as a failure
    if proc.returncode != 0:
        logging.warning(f"nuclei scan failed: {proc.returncode}")
        return [f"Nuclei exited with code {proc.returncode}, parsed {len(findings)} entries"]

    # 7) Success: return each JSON‐string as its own list element
    logging.warning(f"finished nuclei scan with {len(findings)} entries")
    return findings

@app.tool()
async def get_banner(
    ip: Annotated[str, "IP address to connect to (e.g., '192.168.1.1')"],
    port: Annotated[int, "Port number to connect to (e.g., 80, 443, 22)"],
    timeout: Annotated[int, "Connection timeout in seconds (1-30)"] = 5
) -> str:
    """
    Use host and port and retrieve banner information.

    Args:
        ip: IP address to connect to
        port: Port number to connect to
        timeout: Connection timeout in seconds (default: 5)

    Returns:
        JSON string with service, version, and banner information
    """
    return getBanner(ip, port, timeout)

@app.tool()
async def get_finished_scan_results(
    limit: Annotated[int, "Maximum number of scan results to return (1-100)"] = 10,
    scan_id: Annotated[str, "Optional: specific scan ID to retrieve (UUID format)"] = None
) -> str:
    """Get all finished scan results from database."""
    try:
        # Run the blocking database operation in a thread pool
        import asyncio
        result = await asyncio.to_thread(database.get_finished_scan_results, limit, scan_id)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "message": "Failed to retrieve scan results"
        })


@app.tool()
async def search_scan_results(
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
        # Run the blocking database operation in a thread pool
        import asyncio
        result = await asyncio.to_thread(database.search_scan_results, hostname, ip_address, port, service, limit)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "message": "Failed to search scan results"
        })


@app.tool()
async def search_vulnerability_results(
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
        # Run the blocking database operation in a thread pool
        import asyncio
        result = await asyncio.to_thread(database.search_vulnerability_results, hostname, ip_address, port, severity, template_id, limit)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "message": "Failed to search vulnerability results"
        })


@app.tool()
async def search_findings(
    hostname: Annotated[str, "Hostname to search for (optional)"] = None,
    ip_address: Annotated[str, "IP address to search for (optional)"] = None,
    port: Annotated[int, "Port number to search for (optional)"] = None,
    service: Annotated[str, "Service name to search for (optional)"] = None,
    agent_type: Annotated[str, "Agent type to filter by (port-scan, vuln-scan, ssh-agent, metasploit-agent)"] = None,
    severity: Annotated[str, "Severity level for vulnerabilities (info,low,medium,high,critical)"] = None,
    template_id: Annotated[str, "Template ID for vulnerabilities (optional)"] = None,
    limit: Annotated[int, "Maximum number of results to return (1-100)"] = 20
) -> str:
    """
    Search all findings (port scans, vulnerabilities, SSH results, etc.) by various criteria.

    This unified search allows finding:
    - All findings on a specific host: hostname='example.com'
    - All port scan results: agent_type='port-scan'
    - All vulnerabilities: agent_type='vuln-scan'
    - All SSH findings: agent_type='ssh-agent'
    - All critical vulnerabilities: agent_type='vuln-scan', severity='critical'
    - All findings on a specific port: port=22
    - All SSH services: service='ssh'

    Examples:
    - Find all findings on host: hostname='192.168.1.100'
    - Find all vulnerabilities: agent_type='vuln-scan'
    - Find critical issues: agent_type='vuln-scan', severity='critical'
    - Find SSH findings: agent_type='ssh-agent'
    - Find all port 22 findings: port=22
    """
    try:
        # Run the blocking database operation in a thread pool
        import asyncio
        result = await asyncio.to_thread(database.search_findings, hostname, ip_address, port, service, agent_type, severity, template_id, limit)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "message": "Failed to search findings"
        })


@app.tool()
async def save_hacking_results(
    scan_id: Annotated[str, "Unique scan ID for this hacking session"],
    target_host: Annotated[str, "Target host that was attacked"],
    shells_obtained: Annotated[str, "JSON string of shells obtained (e.g., '[{\"type\":\"ssh\",\"host\":\"1.1.1.1\",\"port\":22,\"username\":\"root\",\"password\":\"admin\"}]')"] = "[]",
    credentials_found: Annotated[str, "JSON string of credentials found (e.g., '[{\"username\":\"admin\",\"password\":\"password123\",\"service\":\"ssh\"}]')"] = "[]",
    vulnerabilities_found: Annotated[str, "JSON string of vulnerabilities found (e.g., '[{\"cve\":\"CVE-2021-44228\",\"port\":8080,\"severity\":\"critical\"}]')"] = "[]",
    methodology_steps: Annotated[str, "JSON string of methodology steps completed"] = "[]"
) -> str:
    """
    Save hacking agent results to the database.

    This tool allows the hacking agent to save its penetration testing results
    to the central database for persistence and later analysis.

    Args:
        scan_id: Unique identifier for this hacking session
        target_host: The target that was attacked
        shells_obtained: JSON array of shell access gained
        credentials_found: JSON array of credentials discovered
        vulnerabilities_found: JSON array of vulnerabilities identified
        methodology_steps: JSON array of steps completed

    Returns:
        JSON response indicating success/failure
    """
    try:
        import json
        from datetime import datetime

        # Parse JSON strings
        shells = json.loads(shells_obtained) if shells_obtained else []
        creds = json.loads(credentials_found) if credentials_found else []
        vulns = json.loads(vulnerabilities_found) if vulnerabilities_found else []
        steps = json.loads(methodology_steps) if methodology_steps else []

        # Save shells as findings
        for shell in shells:
            database.save_scan_result_entry(
                scan_id=scan_id,
                hostname=target_host,
                ip_address=target_host,
                port=shell.get("port", 0),
                protocol="tcp",
                state="open",
                service=shell.get("type", "shell"),
                version=f"SHELL-ACCESS:{shell.get('username', 'unknown')}:{shell.get('password', 'unknown')}",
                banner=f"Shell obtained via {shell.get('method', 'unknown')}",
                agent="hacking-agent"
            )

        # Save credentials as findings
        for cred in creds:
            database.save_scan_result_entry(
                scan_id=scan_id,
                hostname=target_host,
                ip_address=target_host,
                port=cred.get("port", 0),
                protocol="tcp",
                state="open",
                service=cred.get("service", "credential"),
                version=f"CREDENTIAL-FOUND:{cred.get('username', 'unknown')}:{cred.get('password', 'unknown')}",
                banner=f"Credential discovered via {cred.get('method', 'unknown')}",
                agent="hacking-agent"
            )

        # Save vulnerabilities as findings
        for vuln in vulns:
            database.save_scan_result_entry(
                scan_id=scan_id,
                hostname=target_host,
                ip_address=target_host,
                port=vuln.get("port", 0),
                protocol="tcp",
                state="open",
                service=vuln.get("service", "vulnerability"),
                version=f"VULNERABILITY:{vuln.get('cve', 'unknown')}:{vuln.get('severity', 'unknown')}",
                banner=f"Vulnerability: {vuln.get('description', 'No description')}",
                agent="hacking-agent"
            )

        # Run the blocking database operation in a thread pool
        import asyncio
        await asyncio.to_thread(lambda: None)  # Ensure we're in async context

        total_findings = len(shells) + len(creds) + len(vulns)

        return json.dumps({
            "success": True,
            "scan_id": scan_id,
            "target_host": target_host,
            "shells_saved": len(shells),
            "credentials_saved": len(creds),
            "vulnerabilities_saved": len(vulns),
            "total_findings": total_findings,
            "methodology_steps": len(steps),
            "message": f"Saved {total_findings} hacking findings to database"
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "message": "Failed to save hacking results"
        })


@app.tool()
def list_capabilities() -> str:
    """List all available red team capabilities."""
    capabilities = {
        "scanning": {
            "port_scan": "Scan networks and hosts for open ports (includes automatic banner grabbing)",
            "enumerate_vulnerabilities": "Enumerate vulnerabilities and security issues using nuclei scanner with real-time streaming output",
            "get_finished_scan_results": "Retrieve all completed scan results from database",
            "search_findings": "Unified search across all findings (port scans, vulnerabilities, SSH results) by various criteria",
            "search_scan_results": "Search port scan results by hostname, IP, port, or service (legacy)",
            "search_vulnerability_results": "Search vulnerability scan results by various criteria (legacy)",
            "resolve_hostname_to_ip": "Resolve a hostname to an IP address",
            "get_banner": "Use netcat to retrieve service banner from a specific host:port"
        },

        "ssh": {
            "ssh_execute": "Execute commands on remote hosts via SSH with username/password authentication",
            "ssh_brute_force": "Brute force SSH credentials using username and password lists"
        },

        "metasploit": {
            "search_exploits_fast": "Search cached exploits database for fast results with CVE, platform, rank, and author filtering",
            "list_exploits": "List available Metasploit exploits with optional filtering by platform and search terms",
            "execute_exploit": "Execute a Metasploit exploit against a target host with payload and option configuration"
        },

        "domain_discovery": {
            "domain_discovery": "Enumerate subdomains from a top-level domain using subfinder and resolve them to IP addresses"
        },

        "analysis": {
            "list_capabilities": "Show all available tools and capabilities",
            "save_hacking_results": "Save hacking agent results (shells, credentials, vulnerabilities) to database"
        }
    }

    return json.dumps({
        "success": True,
        "capabilities": capabilities,
        "message": "Red Team MCP capabilities listed"
    })

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Red Team MCP Server (TCP mode)")
    parser.add_argument(
        "--host", "-H",
        default="127.0.0.1",
        help="Host or IP to bind (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", "-P",
        type=int,
        default=5678,
        help="TCP port for the MCP server (default: 5678)"
    )
    parser.add_argument(
        "--debug", "-d",
        action="store_true",
        help="Enable debug‐level logging"
    )
    args = parser.parse_args()

    # Create the FastMCP app just as before

    # (Your @app.tool definitions go here… no changes needed.)

    if args.debug:
        # Turn on more verbose logging if you like
        import logging

        logging.basicConfig(level=logging.DEBUG)

    print(f"[MCP Server] Listening on {args.host}:{args.port} (TCP transport)")
    # This starts the server socket and blocks, printing logs to stdout/stderr.
    app.run(transport="streamable-http", host=args.host, port=args.port)