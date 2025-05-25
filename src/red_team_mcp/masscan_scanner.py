"""
Masscan Scanner Module - Red Team MCP

This module contains functions for port scanning using masscan.
"""

import json
import subprocess
import socket
from datetime import datetime
from pathlib import Path
import tempfile
import uuid
from typing import Dict, List, Tuple

from red_team_mcp import database

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

def execute_masscan(target: str, ports: str, rate: int = 100, timeout: int = 60) -> tuple[bool, str, Path]:
    """Execute masscan and return success status, stderr output, and output file path."""
    try:
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
            timeout=timeout
        )

        return True, result.stderr, output_file

    except subprocess.TimeoutExpired:
        return False, f"Scan timed out after {timeout} seconds", output_file
    except Exception as e:
        return False, str(e), output_file

def parse_masscan_results(output_file: Path) -> list[dict]:
    """Parse masscan JSON output and return structured host/port data with banner information."""
    hosts = []
    banner_data = {}  # Store banner info by ip:port

    if not output_file.exists():
        return hosts

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

    return hosts

def port_scan(target: str, ports: str, scan_type: str = "tcp_syn", rate: int = 100) -> dict:
    """
    NETWORK PORT SCANNING: Discover open ports on hosts using masscan.

    This function performs PORT DISCOVERY to find open TCP/UDP ports on target hosts.
    
    Args:
        target: IP address or CIDR range to scan
        ports: Comma-separated ports or ranges
        scan_type: Type of scan (tcp_syn, tcp_connect, udp, etc.)
        rate: Packets per second rate
        
    Returns:
        Dictionary with scan results
    """
    try:
        # Generate scan ID and start time
        scan_id = str(uuid.uuid4())
        start_time = datetime.now()

        # Create initial scan record
        database.create_scan_record(scan_id, target, ports, scan_type, start_time)

        # Execute the scan
        success, error_output, output_file = execute_masscan(target, ports, rate, timeout=60)

        if not success:
            # Update scan record with error
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            database.update_scan_status(
                scan_id, 
                "failed", 
                end_time, 
                duration, 
                0, 
                0, 
                "", 
                error_output
            )

            return {
                "success": False,
                "error": f"Masscan command failed: {error_output}",
                "scan_id": scan_id,
                "target": target,
                "ports": ports
            }
        end_time = datetime.now()

        # Parse scan results
        hosts = parse_masscan_results(output_file)

        # Save results to database
        total_hosts, total_open_ports = database.save_scan_results(
            scan_id, target, ports, scan_type, start_time, end_time, hosts
        )

        duration = (end_time - start_time).total_seconds()

        return {
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
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scan_id": scan_id if 'scan_id' in locals() else None
        }