#!/usr/bin/env python3
"""
FastMCP Server - Red Team MCP using FastMCP

This creates a minimal but functional red team MCP server using FastMCP.
"""

import asyncio
import json
import sqlite3
import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
import socket
from typing import Any, Dict

from fastmcp import FastMCP

# Create FastMCP server
app = FastMCP("Red Team MCP")

# Database setup
DB_PATH = "red_team_scans.db"

def init_database():
    """Initialize SQLite database for scan history."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            ports TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            status TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT,
            duration_seconds REAL,
            total_hosts INTEGER DEFAULT 0,
            total_open_ports INTEGER DEFAULT 0,
            results_json TEXT,
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create scan_hosts table for detailed results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            version TEXT,
            banner TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
        )
    """)

    conn.commit()
    conn.close()

# Initialize database on startup
init_database()


def getBanner(ip: str, port: int, timeout: int = 5) -> Dict[str, str]:
    """
    Use socket connection to retrieve banner information from a host:port.

    Args:
        ip: IP address to connect to
        port: Port number to connect to
        timeout: Connection timeout in seconds

    Returns:
        Dictionary with service, version, and banner information
    """
    try:
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Connect to the target
        sock.connect((ip, port))

        # For HTTP services, send a request
        if port in [80, 8080, 8000]:
            request = b"GET / HTTP/1.0\r\n\r\n"
            sock.send(request)

        # Receive banner/response
        banner_text = ""
        try:
            data = sock.recv(1024)
            banner_text = data.decode('utf-8', errors='ignore').strip()
        except:
            pass

        sock.close()

        if banner_text:
            # Try to identify service and version from banner
            service_name = "unknown"
            version = ""
            banner_lower = banner_text.lower()

            # Web servers
            if any(x in banner_lower for x in ['apache', 'httpd']):
                service_name = "http"
                version = "Apache"
            elif 'nginx' in banner_lower:
                service_name = "http"
                version = "nginx"
            elif 'microsoft-iis' in banner_lower or 'iis' in banner_lower:
                service_name = "http"
                version = "Microsoft-IIS"
            elif 'lighttpd' in banner_lower:
                service_name = "http"
                version = "lighttpd"
            elif 'gunicorn' in banner_lower:
                service_name = "http"
                version = "gunicorn"
            elif 'server:' in banner_lower:
                service_name = "http"
                version = "HTTP"

            # SSH
            elif 'openssh' in banner_lower:
                service_name = "ssh"
                version = "OpenSSH"
            elif 'ssh' in banner_lower:
                service_name = "ssh"
                version = "SSH"

            # FTP
            elif 'ftp' in banner_lower:
                service_name = "ftp"
                if 'vsftpd' in banner_lower:
                    version = "vsftpd"
                elif 'proftpd' in banner_lower:
                    version = "ProFTPD"
                else:
                    version = "FTP"

            # Mail services
            elif 'smtp' in banner_lower:
                service_name = "smtp"
                if 'postfix' in banner_lower:
                    version = "Postfix"
                elif 'sendmail' in banner_lower:
                    version = "Sendmail"
                else:
                    version = "SMTP"

            # Database services
            elif 'mysql' in banner_lower:
                service_name = "mysql"
                version = "MySQL"
            elif 'postgresql' in banner_lower:
                service_name = "postgresql"
                version = "PostgreSQL"

            # Other common services
            elif 'telnet' in banner_lower:
                service_name = "telnet"
                version = "Telnet"

            return {
                "service": service_name,
                "version": version,
                "banner": banner_text
            }
        else:
            return {
                "service": "unknown",
                "version": "",
                "banner": ""
            }

    except Exception as e:
        return {
            "service": "unknown",
            "version": "",
            "banner": f"Error: {str(e)}"
        }

@app.tool()
def validate_masscan() -> str:
    """Validate that masscan is available and working."""
    import subprocess

    try:
        result = subprocess.run(
            ["masscan", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )

        # Masscan returns exit code 1 for --version but outputs version info
        version_output = result.stdout or result.stderr

        if "Masscan version" in version_output:
            return json.dumps({
                "success": True,
                "masscan_available": True,
                "version": version_output.strip(),
                "message": "Masscan is available and working"
            })
        else:
            return json.dumps({
                "success": False,
                "masscan_available": False,
                "message": "Masscan validation failed"
            })

    except Exception as e:
        return json.dumps({
            "success": False,
            "masscan_available": False,
            "message": f"Masscan not found or error: {str(e)}"
        })

@app.tool()
def resolve_hostname_to_ip(hostname: str) -> str:
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
def port_scan(target: str, ports: str = "80,443,22, 8080,8443, 3389, 11434", scan_type: str = "tcp_syn", rate: int = 100) -> str:
    """Perform port of an ip addres or cidr range scanning using masscan and store results in database."""
    try:
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        start_time = datetime.now()

        # Save initial scan record to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (scan_id, target, ports, scan_type, status, start_time)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, target, ports, scan_type, "running", start_time.isoformat()))
        conn.commit()
        conn.close()

        # Create temporary output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = Path(f.name)

        # Build masscan command with banner grabbing
        cmd = [
            "sudo", "masscan",
            target,
            "-p", ports,
            "--rate", str(rate),
            "--banners",
            "-oJ", str(output_file)
        ]

        # Execute scan synchronously
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Parse masscan results with banner information
        hosts = []
        banner_data = {}  # Store banner info by ip:port

        if output_file.exists():
            try:
                with open(output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                data = json.loads(line)

                                if 'ip' in data and 'ports' in data:
                                    ip = data.get('ip')
                                    port_data = data.get('ports', [])

                                    if ip and port_data:
                                        for port_info in port_data:
                                            port = port_info.get('port')
                                            protocol = port_info.get('proto', 'tcp')
                                            state = port_info.get('status', 'open')
                                            service_info = port_info.get('service', {})

                                            if port:
                                                port_key = f"{ip}:{port}"

                                                # Check if this is a banner result (has service info)
                                                if service_info:
                                                    service_name = service_info.get('name', 'unknown')
                                                    banner_text = service_info.get('banner', '').strip()

                                                    # Try to extract version info from banner
                                                    version = ""
                                                    banner_lower = banner_text.lower()

                                                    if 'apache' in banner_lower:
                                                        version = "Apache"
                                                    elif 'nginx' in banner_lower:
                                                        version = "nginx"
                                                    elif 'openssh' in banner_lower:
                                                        version = "OpenSSH"
                                                    elif 'microsoft' in banner_lower:
                                                        version = "Microsoft"

                                                    banner_data[port_key] = {
                                                        "service": service_name,
                                                        "version": version,
                                                        "banner": banner_text
                                                    }

                                                    # Update existing port entry if it exists
                                                    for host in hosts:
                                                        if host["ip"] == ip:
                                                            for port_entry in host["ports"]:
                                                                if port_entry["port"] == port:
                                                                    port_entry["service"] = service_name
                                                                    port_entry["version"] = version
                                                                    port_entry["banner"] = banner_text
                                                                    break
                                                            break

                                                else:
                                                    # This is a port discovery result
                                                    # Find or create host entry
                                                    host_entry = None
                                                    for host in hosts:
                                                        if host["ip"] == ip:
                                                            host_entry = host
                                                            break

                                                    if not host_entry:
                                                        host_entry = {"ip": ip, "ports": []}
                                                        hosts.append(host_entry)

                                                    # Check if port already exists
                                                    port_exists = False
                                                    for existing_port in host_entry["ports"]:
                                                        if existing_port["port"] == port:
                                                            port_exists = True
                                                            break

                                                    if not port_exists:
                                                        banner_info = banner_data.get(port_key, {})

                                                        # If no banner info from masscan, try to get it with netcat
                                                        if not banner_info or banner_info.get("service") == "unknown":
                                                            try:
                                                                nc_banner = getBanner(ip, port)
                                                                if nc_banner.get("service") != "unknown" or nc_banner.get("banner"):
                                                                    banner_info = nc_banner
                                                            except Exception:
                                                                pass  # Continue with existing banner_info or defaults

                                                        host_entry["ports"].append({
                                                            "port": port,
                                                            "protocol": protocol,
                                                            "state": state,
                                                            "service": banner_info.get("service", "unknown"),
                                                            "version": banner_info.get("version", ""),
                                                            "banner": banner_info.get("banner", "")
                                                        })

                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                pass

            # Clean up temp file
            try:
                output_file.unlink()
            except:
                pass

        # Calculate stats
        total_hosts = len(hosts)
        total_open_ports = sum(
            len([p for p in host["ports"] if p["state"] == "open"])
            for host in hosts
        )

        # Update database with results
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Update scan record
        cursor.execute("""
            UPDATE scans
            SET status = ?, end_time = ?, duration_seconds = ?,
                total_hosts = ?, total_open_ports = ?, results_json = ?
            WHERE scan_id = ?
        """, ("completed", end_time.isoformat(), duration, total_hosts,
              total_open_ports, json.dumps(hosts), scan_id))

        # Insert host details with banner information
        for host in hosts:
            for port in host["ports"]:
                cursor.execute("""
                    INSERT INTO scan_hosts (scan_id, ip_address, port, protocol, state, service, version, banner)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (scan_id, host["ip"], port["port"], port["protocol"], port["state"],
                      port.get("service", ""), port.get("version", ""), port.get("banner", "")))

        conn.commit()
        conn.close()

        return json.dumps({
            "success": True,
            "scan_id": scan_id,
            "target": target,
            "ports_scanned": ports,
            "scan_type": scan_type,
            "total_hosts": total_hosts,
            "total_open_ports": total_open_ports,
            "hosts": hosts,
            "duration_seconds": duration,
            "message": f"Scan completed - found {total_hosts} hosts with {total_open_ports} open ports"
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "scan_id": scan_id if 'scan_id' in locals() else None
        })


@app.tool()
def get_banner(ip: str, port: int, timeout: int = 5) -> str:
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
        banner_info = getBanner(ip, port, timeout)
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
def get_finished_scan_results(limit: int = 10, scan_id: str = None) -> str:
    """Get all finished scan results from database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        if scan_id:
            # Get specific scan
            cursor.execute("""
                SELECT scan_id, target, ports, scan_type, status, start_time, end_time,
                       duration_seconds, total_hosts, total_open_ports, results_json
                FROM scans
                WHERE scan_id = ?
            """, (scan_id,))
            rows = cursor.fetchall()
        else:
            # Get recent scans
            cursor.execute("""
                SELECT scan_id, target, ports, scan_type, status, start_time, end_time,
                       duration_seconds, total_hosts, total_open_ports, results_json
                FROM scans
                WHERE status = 'completed'
                ORDER BY start_time DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()

        scans = []
        for row in rows:
            scan_data = {
                "scan_id": row[0],
                "target": row[1],
                "ports": row[2],
                "scan_type": row[3],
                "status": row[4],
                "start_time": row[5],
                "end_time": row[6],
                "duration_seconds": row[7],
                "total_hosts": row[8],
                "total_open_ports": row[9],
                "hosts": json.loads(row[10]) if row[10] else []
            }
            scans.append(scan_data)

        # Get summary stats
        cursor.execute("""
            SELECT COUNT(*) as total_scans,
                   SUM(total_hosts) as total_hosts_scanned,
                   SUM(total_open_ports) as total_open_ports_found
            FROM scans
            WHERE status = 'completed'
        """)
        stats = cursor.fetchone()

        conn.close()

        return json.dumps({
            "success": True,
            "scans": scans,
            "total_scans_returned": len(scans),
            "database_stats": {
                "total_completed_scans": stats[0] or 0,
                "total_hosts_scanned": stats[1] or 0,
                "total_open_ports_found": stats[2] or 0
            },
            "message": f"Retrieved {len(scans)} scan results"
        })

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "message": "Failed to retrieve scan results"
        })


@app.tool()
def list_capabilities() -> str:
    """List all available red team capabilities."""
    capabilities = {
        "scanning": {
            "port_scan": "Scan networks and hosts for open ports (includes automatic banner grabbing)",
            "validate_masscan": "Check masscan installation and configuration",
            "get_finished_scan_results": "Retrieve all completed scan results from database",
            "resolve_hostname_to_ip": "Resolve a hostname to an IP address",
            "get_banner": "Use netcat to retrieve service banner from a specific host:port"
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
