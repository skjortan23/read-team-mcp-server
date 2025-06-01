"""
Nuclei Scanner Module - Red Team MCP

This module contains functions for vulnerability scanning using nuclei.
"""

import json
import subprocess
import socket
import re
import os
import threading
import queue
import asyncio
from datetime import datetime
from typing import List, Dict, Callable, Optional, AsyncGenerator
from pathlib import Path
import uuid
import time

from red_team_mcp.protocol_detector import detect_protocol

try:
    from red_team_mcp import database
    DATABASE_AVAILABLE = True
except ImportError:
    try:
        from . import database
        DATABASE_AVAILABLE = True
    except ImportError:
        print("⚠️  Database module not available, skipping database operations")
        DATABASE_AVAILABLE = False
        database = None


def get_template_config_for_port(port: int) -> dict:
    """
    Get nuclei template configuration based on port number and likely service.

    Returns a dictionary with:
    - service_name: Human readable service name
    - protocol_types: List of nuclei protocol types to use
    - tags: List of nuclei tags to include
    - severity: List of severity levels to include
    """

    # Port-to-service mapping with nuclei template configuration
    port_configs = {
        # Web Services
        80: {
            "service_name": "HTTP",
            "protocol_types": ["http"],
            "tags": ["http", "web", "cms", "panel"],
            "severity": ["low", "medium", "high", "critical"]
        },
        443: {
            "service_name": "HTTPS",
            "protocol_types": ["http", "ssl"],
            "tags": ["http", "web", "cms", "panel", "ssl", "tls"],
            "severity": ["low", "medium", "high", "critical"]
        },
        11434: {
            "service_name": "HTTP Alt",
            "protocol_types": ["http"],
            "tags": ["http", "web", "ollama", "api"],
            "severity": ["low", "medium", "high", "critical"]
        },
        8080: {
            "service_name": "HTTP Alt",
            "protocol_types": ["http"],
            "tags": ["http", "web", "panel", "tomcat", "jenkins"],
            "severity": ["low", "medium", "high", "critical"]
        },
        8443: {
            "service_name": "HTTPS Alt",
            "protocol_types": ["http", "ssl"],
            "tags": ["http", "web", "panel", "ssl"],
            "severity": ["low", "medium", "high", "critical"]
        },
        3000: {
            "service_name": "Node.js/React Dev",
            "protocol_types": ["http"],
            "tags": ["http", "web", "nodejs", "react"],
            "severity": ["medium", "high", "critical"]
        },
        5000: {
            "service_name": "Flask/Python Dev",
            "protocol_types": ["http"],
            "tags": ["http", "web", "python", "flask"],
            "severity": ["medium", "high", "critical"]
        },
        8000: {
            "service_name": "HTTP Dev",
            "protocol_types": ["http"],
            "tags": ["http", "web", "django", "python"],
            "severity": ["medium", "high", "critical"]
        },
        9000: {
            "service_name": "HTTP Management",
            "protocol_types": ["http"],
            "tags": ["http", "web", "panel", "management"],
            "severity": ["medium", "high", "critical"]
        },

        # SSH
        22: {
            "service_name": "SSH",
            "protocol_types": ["tcp"],
            "tags": ["ssh", "tcp", "network"],
            "severity": ["medium", "high", "critical"]
        },

        # FTP
        21: {
            "service_name": "FTP",
            "protocol_types": ["tcp"],
            "tags": ["ftp", "tcp", "network"],
            "severity": ["low", "medium", "high", "critical"]
        },

        # Telnet
        23: {
            "service_name": "Telnet",
            "protocol_types": ["tcp"],
            "tags": ["telnet", "tcp", "network"],
            "severity": ["high", "critical"]
        },

        # SMTP
        25: {
            "service_name": "SMTP",
            "protocol_types": ["tcp"],
            "tags": ["smtp", "email", "tcp"],
            "severity": ["low", "medium", "high"]
        },
        587: {
            "service_name": "SMTP Submission",
            "protocol_types": ["tcp"],
            "tags": ["smtp", "email", "tcp"],
            "severity": ["low", "medium", "high"]
        },

        # DNS
        53: {
            "service_name": "DNS",
            "protocol_types": ["dns"],
            "tags": ["dns", "network"],
            "severity": ["low", "medium", "high"]
        },

        # Database Services
        3306: {
            "service_name": "MySQL",
            "protocol_types": ["tcp"],
            "tags": ["mysql", "database", "tcp"],
            "severity": ["medium", "high", "critical"]
        },
        5432: {
            "service_name": "PostgreSQL",
            "protocol_types": ["tcp"],
            "tags": ["postgresql", "postgres", "database", "tcp"],
            "severity": ["medium", "high", "critical"]
        },
        1433: {
            "service_name": "MSSQL",
            "protocol_types": ["tcp"],
            "tags": ["mssql", "database", "tcp"],
            "severity": ["medium", "high", "critical"]
        },
        27017: {
            "service_name": "MongoDB",
            "protocol_types": ["tcp"],
            "tags": ["mongodb", "database", "tcp"],
            "severity": ["medium", "high", "critical"]
        },
        6379: {
            "service_name": "Redis",
            "protocol_types": ["tcp"],
            "tags": ["redis", "database", "tcp"],
            "severity": ["medium", "high", "critical"]
        },

        # Remote Access
        3389: {
            "service_name": "RDP",
            "protocol_types": ["tcp"],
            "tags": ["rdp", "tcp", "network"],
            "severity": ["medium", "high", "critical"]
        },
        5900: {
            "service_name": "VNC",
            "protocol_types": ["tcp"],
            "tags": ["vnc", "tcp", "network"],
            "severity": ["medium", "high", "critical"]
        },

        # Network Services
        161: {
            "service_name": "SNMP",
            "protocol_types": ["tcp"],
            "tags": ["snmp", "tcp", "network"],
            "severity": ["low", "medium", "high"]
        },
        445: {
            "service_name": "SMB",
            "protocol_types": ["tcp"],
            "tags": ["smb", "tcp", "network"],
            "severity": ["medium", "high", "critical"]
        },
        139: {
            "service_name": "NetBIOS",
            "protocol_types": ["tcp"],
            "tags": ["netbios", "smb", "tcp"],
            "severity": ["medium", "high", 'critical']
        },
    }

    # Check if we have a specific configuration for this port
    if port in port_configs:
        return port_configs[port]

    # Default configuration for unknown ports
    # Try to guess based on port ranges
    if 80 <= port <= 89 or 8000 <= port <= 8999:
        # Likely HTTP services
        return {
            "service_name": f"HTTP (Port {port})",
            "protocol_types": ["http"],
            "tags": ["http", "web"],
            "severity": ["medium", "high", "critical"]
        }
    elif 443 <= port <= 449 or port in [8443, 9443]:
        # Likely HTTPS services
        return {
            "service_name": f"HTTPS (Port {port})",
            "protocol_types": ["http", "ssl"],
            "tags": ["http", "web", "ssl"],
            "severity": ["medium", "high", "critical"]
        }
    else:
        # Generic TCP service
        return {
            "service_name": f"TCP Service (Port {port})",
            "protocol_types": ["tcp"],
            "tags": ["tcp", "network"],
            "severity": ["medium", "high", "critical"]
        }


def parse_nuclei_output(output_lines: list[str]) -> list[dict]:
    """
    Parse nuclei scanner JSON output into structured vulnerability data.

    Expected format: JSON lines from nuclei -jsonl output
    """
    vulnerabilities = []

    for line in output_lines:
        line = line.strip()
        if not line:
            continue

        try:
            # Try to parse as JSON (new nuclei format)
            data = json.loads(line)

            # Extract information from JSON structure
            template_id = data.get("template-id", "unknown")
            template_name = data.get("info", {}).get("name", template_id.replace('-', ' ').title())
            protocol = data.get("type", "unknown")
            severity = data.get("info", {}).get("severity", "unknown")

            # Target information
            host = data.get("host", "")
            port = data.get("port", "")
            scheme = data.get("scheme", "")
            url = data.get("url", "")
            matched_at = data.get("matched-at", url or f"{host}:{port}")

            # Try to parse port as integer
            try:
                port = int(port) if port else None
            except (ValueError, TypeError):
                port = None

            # Extract results
            extracted_results = data.get("extracted-results", [])
            if isinstance(extracted_results, list):
                extracted_results = ", ".join(str(x) for x in extracted_results)
            elif extracted_results:
                extracted_results = str(extracted_results)
            else:
                extracted_results = ""

            # Determine hostname vs IP
            hostname = None
            ip_address = data.get("ip", "")

            # If host is different from IP, it's likely a hostname
            if host and host != ip_address:
                try:
                    import ipaddress
                    ipaddress.ip_address(host)
                    # host is an IP address
                    if not ip_address:
                        ip_address = host
                except ValueError:
                    # host is a hostname
                    hostname = host
            elif host and not ip_address:
                # Try to determine if host is IP or hostname
                try:
                    import ipaddress
                    ipaddress.ip_address(host)
                    ip_address = host
                except ValueError:
                    hostname = host

            # Build description from template info
            description = template_name
            if data.get("info", {}).get("description"):
                description = data["info"]["description"]

            # Build reference
            reference = data.get("template-url", f"nuclei-template:{template_id}")

            vulnerability = {
                "template_id": template_id,
                "template_name": template_name,
                "protocol": protocol,
                "severity": severity,
                "hostname": hostname,
                "ip_address": ip_address,
                "port": port,
                "url": url,
                "matched_at": matched_at,
                "extracted_results": extracted_results,
                "description": description,
                "reference": reference,
                "raw_data": data  # Include full JSON for debugging
            }

            vulnerabilities.append(vulnerability)

        except json.JSONDecodeError:
            # Try to parse as old text format for backward compatibility
            try:
                # Parse old nuclei output format: [template-id] [protocol] [severity] target ["extracted"]
                pattern = r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+([^\s\[]+)(?:\s+\[([^\]]*)\])?'
                match = re.match(pattern, line)

                if match:
                    template_id = match.group(1)
                    protocol = match.group(2)
                    severity = match.group(3)
                    target = match.group(4)
                    extracted = match.group(5) if match.group(5) else ""

                    # Parse target to extract hostname, IP, and port
                    hostname = None
                    ip_address = None
                    port = None
                    url = target

                    # Handle different target formats
                    if target.startswith(('http://', 'https://')):
                        # URL format
                        from urllib.parse import urlparse
                        parsed = urlparse(target)
                        hostname = parsed.hostname
                        port = parsed.port

                        # Default ports
                        if port is None:
                            port = 443 if parsed.scheme == 'https' else 80

                    elif ':' in target and not target.startswith('['):
                        # hostname:port format
                        parts = target.split(':')
                        hostname = parts[0]
                        try:
                            port = int(parts[1])
                        except (ValueError, IndexError):
                            port = None
                    else:
                        # Just hostname or IP
                        hostname = target

                    # Try to resolve IP if we have hostname
                    if hostname and not ip_address:
                        try:
                            # Check if hostname is already an IP
                            import ipaddress
                            ipaddress.ip_address(hostname)
                            ip_address = hostname
                            hostname = None  # It's an IP, not a hostname
                        except ValueError:
                            # It's a hostname, try to resolve it
                            try:
                                ip_address = socket.gethostbyname(hostname)
                            except socket.gaierror:
                                pass

                    vulnerability = {
                        "template_id": template_id,
                        "template_name": template_id.replace('-', ' ').title(),
                        "protocol": protocol,
                        "severity": severity,
                        "hostname": hostname,
                        "ip_address": ip_address,
                        "port": port,
                        "url": url,
                        "matched_at": target,
                        "extracted_results": extracted,
                        "description": f"{template_id} vulnerability detected",
                        "reference": f"nuclei-template:{template_id}"
                    }

                    vulnerabilities.append(vulnerability)
            except Exception:
                # Skip malformed lines but continue processing
                continue
        except Exception as e:
            # Skip malformed lines but continue processing
            continue

    return vulnerabilities

def enumerate_vulnerabilities(host: str, port: int, progress_callback: Optional[Callable] = None, cve_only: bool = False) -> dict:
    """
    ENUMERATE VULNERABILITIES: Find security issues and CVEs using nuclei scanner with streaming output.

    This function scans a host:port for vulnerabilities using nuclei scanner with real-time output.

    Args:
        host: Hostname or IP address to scan
        port: Port number to scan
        progress_callback: Optional callback function to receive real-time progress updates
        cve_only: If True, only run CVE-tagged templates (default: False for all templates)

    Returns:
        Dictionary with scan results
    """
    try:
        # Generate scan ID and start time
        scan_id = str(uuid.uuid4())
        start_time = datetime.now()

        # Build target from host and port
        # Determine if we should use HTTP or HTTPS based on port
        if port == 443:
            target = f"https://{host}:{port}"
        elif port == 80:
            target = f"http://{host}"
        elif port in [8080, 8443, 8000, 8888, 9000, 3000, 5000]:
            # Common HTTP ports - try HTTP first
            target = f"http://{host}:{port}"
        elif port == 21:
            target = f"ftp://{host}"
        else:
            # For non-HTTP ports (like SSH 22), use host:port format
            # This will limit nuclei to network-based templates only
            target = f"{host}:{port}"

        # Test that the port is open first
        print(f"🔌 [{scan_id[:8]}] Testing connectivity to {host}:{port}...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # 5 second timeout for connection test
            result = sock.connect_ex((host, port))
            sock.close()

            if result != 0:
                error_msg = f"Port {port} is not open or not responding on {host}"
                print(f"❌ [{scan_id[:8]}] {error_msg}")

                if progress_callback:
                    progress_callback({
                        "type": "connectivity_failed",
                        "scan_id": scan_id,
                        "host": host,
                        "port": port,
                        "error": error_msg,
                        "message": f"Cannot connect to {host}:{port}"
                    })

                return {
                    "success": False,
                    "error": error_msg,
                    "scan_id": scan_id,
                    "host": host,
                    "port": port,
                    "target": target
                }
            else:
                print(f"✅ [{scan_id[:8]}] Successfully connected to {host}:{port}")

                if progress_callback:
                    progress_callback({
                        "type": "connectivity_success",
                        "scan_id": scan_id,
                        "host": host,
                        "port": port,
                        "message": f"Successfully connected to {host}:{port}"
                    })

        except socket.gaierror as e:
            error_msg = f"DNS resolution failed for {host}: {e}"
            print(f"❌ [{scan_id[:8]}] {error_msg}")

            if progress_callback:
                progress_callback({
                    "type": "dns_failed",
                    "scan_id": scan_id,
                    "host": host,
                    "error": error_msg,
                    "message": f"Cannot resolve hostname {host}"
                })

            return {
                "success": False,
                "error": error_msg,
                "scan_id": scan_id,
                "host": host,
                "port": port,
                "target": target
            }
        except Exception as e:
            error_msg = f"Connection test failed for {host}:{port}: {e}"
            print(f"❌ [{scan_id[:8]}] {error_msg}")

            if progress_callback:
                progress_callback({
                    "type": "connectivity_error",
                    "scan_id": scan_id,
                    "host": host,
                    "port": port,
                    "error": str(e),
                    "message": f"Connection error to {host}:{port}"
                })

            return {
                "success": False,
                "error": error_msg,
                "scan_id": scan_id,
                "host": host,
                "port": port,
                "target": target
            }

        # Create initial scan record
        if DATABASE_AVAILABLE:
            print(f"🔌 Connecting to MongoDB...")
            database.create_scan_record(scan_id, target, "vuln-scan", "nuclei", start_time)
            print(f"✅ MongoDB connection successful")
        else:
            print(f"⚠️  Database not available, skipping scan record creation")

        # Build nuclei command with JSON output for reliable parsing
        cmd = [
            "nuclei",
            "-target", target,
            "-timeout", "10",                         # 10 second timeout per template
            "-no-color",                             # Disable color output for easier parsing
            "-jsonl",                                # JSON Lines output format for structured parsing
            "-silent",                               # Only show findings, not progress (progress goes to stderr)
        ]

        # Smart template selection based on port and service type
        template_config = get_template_config_for_port(port)

        if template_config["protocol_types"]:
            cmd.extend(["-pt", ",".join(template_config["protocol_types"])])
            print(f"🔧 Port {port}: Using protocol types: {', '.join(template_config['protocol_types'])}")

        # Handle tags - combine service tags with CVE filter if requested
        tags_to_use = template_config["tags"].copy() if template_config["tags"] else []
        if cve_only:
            tags_to_use.append("cve")
            print(f"🔍 CVE-only mode enabled - adding 'cve' tag")

        if tags_to_use:
            cmd.extend(["-tags", ",".join(tags_to_use)])
            print(f"🏷️  Port {port}: Using tags: {', '.join(tags_to_use)}")

        if template_config["severity"]:
            cmd.extend(["-severity", ",".join(template_config["severity"])])
            print(f"⚠️  Port {port}: Using severity levels: {', '.join(template_config['severity'])}")

        scan_type = "CVE-only" if cve_only else "full"
        print(f"🎯 {scan_type} template selection for {template_config['service_name']} service on port {port}")

        # Debug: Print command being executed
        print(f"🔍 DEBUG: Executing nuclei command: {' '.join(cmd)}")
        print(f"🎯 DEBUG: Target: {target}")

        if progress_callback:
            progress_callback({
                "type": "scan_started",
                "scan_id": scan_id,
                "target": target,
                "command": ' '.join(cmd),
                "message": f"Starting vulnerability scan on {target}"
            })

        # Execute nuclei scan with streaming output
        # Keep stderr separate since nuclei writes progress to stderr and results to stdout
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0,  # Unbuffered
            universal_newlines=True,
            env={**os.environ, 'PYTHONUNBUFFERED': '1', 'FORCE_COLOR': '0'}  # Force unbuffered output
        )

        stdout_lines = []
        stderr_lines = []
        vulnerabilities = []

        try:
            # Create queues for threaded output reading
            stdout_queue = queue.Queue()
            stderr_queue = queue.Queue()

            # Thread function to read from stdout
            def read_stdout():
                for line in iter(process.stdout.readline, ''):
                    stdout_queue.put(('stdout', line.strip()))
                stdout_queue.put(('stdout', None))  # Signal end

            # Thread function to read from stderr
            def read_stderr():
                for line in iter(process.stderr.readline, ''):
                    stderr_queue.put(('stderr', line.strip()))
                stderr_queue.put(('stderr', None))  # Signal end

            # Start reading threads
            stdout_thread = threading.Thread(target=read_stdout)
            stderr_thread = threading.Thread(target=read_stderr)
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()

            # Read output line by line in real-time (matching working test script)
            start_time_scan = time.time()
            timeout = 60  # 1 minute timeout like working version
            last_status_time = start_time_scan
            stdout_done = False
            stderr_done = False

            print(f"🔄 Starting real-time output monitoring...")
            print(f"⏰ Timeout set to {timeout} seconds")

            while True:
                current_time = time.time()

                # Check for timeout
                if current_time - start_time_scan > timeout:
                    print("⏰ Timeout reached, terminating process")
                    process.terminate()
                    process.wait(timeout=5)
                    break

                # Show periodic status updates (like working version)
                if current_time - last_status_time > 5:  # Every 5 seconds like working version
                    elapsed = current_time - start_time_scan
                    print(f"⏱️  Still running... {elapsed:.0f}s elapsed")
                    print(f"🔍 Process status: running={process.poll() is None}")
                    print(f"📊 Lines: stdout={len(stdout_lines)}, stderr={len(stderr_lines)}")
                    last_status_time = current_time

                # Check if process is done
                if process.poll() is not None and stdout_done and stderr_done:
                    print(f"✅ Process completed!")
                    break

                # Read from stdout queue
                try:
                    stream, line = stdout_queue.get_nowait()
                    if line is None:
                        stdout_done = True
                        print("📡 STDOUT stream ended")
                    elif line:
                        stdout_lines.append(line)
                        print(f"📡 NUCLEI (stdout): {line}")

                        if progress_callback:
                            progress_callback({
                                "type": "output_line",
                                "scan_id": scan_id,
                                "line": line,
                                "stream": "stdout",
                                "message": f"Nuclei stdout: {line}"
                            })

                        # Try to parse vulnerability from this line (JSON format)
                        if line and (line.startswith('{') or '[' in line):
                            parsed_vulns = parse_nuclei_output([line])
                            if parsed_vulns:
                                for vuln in parsed_vulns:
                                    vulnerabilities.append(vuln)
                                    print(f"🚨 VULNERABILITY FOUND: {vuln['template_id']} [{vuln['severity']}] on {vuln.get('matched_at', 'N/A')}")

                                    if progress_callback:
                                        progress_callback({
                                            "type": "vulnerability_found",
                                            "scan_id": scan_id,
                                            "vulnerability": vuln,
                                            "total_found": len(vulnerabilities),
                                            "message": f"Found vulnerability: {vuln['template_id']} [{vuln['severity']}]"
                                        })
                except queue.Empty:
                    pass

                # Read from stderr queue
                try:
                    stream, line = stderr_queue.get_nowait()
                    if line is None:
                        stderr_done = True
                        print("📡 STDERR stream ended")
                    elif line:
                        stderr_lines.append(line)
                        print(f"📡 NUCLEI (stderr): {line}")

                        if progress_callback:
                            progress_callback({
                                "type": "output_line",
                                "scan_id": scan_id,
                                "line": line,
                                "stream": "stderr",
                                "message": f"Nuclei stderr: {line}"
                            })
                except queue.Empty:
                    pass

                # Small delay
                time.sleep(0.01)

        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Final parsing of all output lines
        all_vulnerabilities = parse_nuclei_output(stdout_lines)

        # Merge with real-time found vulnerabilities (remove duplicates)
        seen_vulns = set()
        final_vulnerabilities = []

        for vuln in vulnerabilities + all_vulnerabilities:
            vuln_key = (vuln.get('template_id'), vuln.get('matched_at'))
            if vuln_key not in seen_vulns:
                seen_vulns.add(vuln_key)
                final_vulnerabilities.append(vuln)

        # Check if nuclei command succeeded
        if process.returncode != 0:
            # Update scan record with error
            if DATABASE_AVAILABLE:
                database.update_scan_status(
                    scan_id,
                    "failed",
                    end_time,
                    duration,
                    0,
                    0,
                    "",
                    f"Nuclei failed with return code {process.returncode}: {' '.join(stdout_lines[-10:])}"
                )

            if progress_callback:
                progress_callback({
                    "type": "scan_failed",
                    "scan_id": scan_id,
                    "error": f"Nuclei failed with return code {process.returncode}",
                    "output": ' '.join(stdout_lines[-10:]),
                    "message": f"Vulnerability scan failed"
                })

            return {
                "success": False,
                "error": f"Nuclei command failed with return code {process.returncode}",
                "output": ' '.join(stdout_lines[-10:]),
                "command": ' '.join(cmd),
                "scan_id": scan_id,
                "host": host,
                "port": port,
                "target": target
            }

        print(f"🎯 DEBUG: Parsed {len(final_vulnerabilities)} total vulnerabilities")

        # Save vulnerability results to database
        if DATABASE_AVAILABLE:
            database.save_vulnerability_results(scan_id, final_vulnerabilities)
            print(f"💾 DEBUG: Saved {len(final_vulnerabilities)} vulnerabilities to database")

            # Update scan record
            database.update_scan_status(
                scan_id,
                "completed",
                end_time,
                duration,
                1,
                len(final_vulnerabilities),
                json.dumps(final_vulnerabilities)
            )
        else:
            print(f"⚠️  Database not available, skipping vulnerability save")

        vuln_count = len(final_vulnerabilities)

        if progress_callback:
            progress_callback({
                "type": "scan_complete",
                "scan_id": scan_id,
                "vulnerabilities_found": vuln_count,
                "duration_seconds": duration,
                "message": f"Vulnerability scan completed - found {vuln_count} issues"
            })

        # Prepare debug info for the response
        debug_info = {
            "command": ' '.join(cmd),
            "return_code": process.returncode,
            "output_lines_count": len(stdout_lines),
            "parsing_successful": len(final_vulnerabilities) > 0
        }

        return {
            "success": True,
            "scan_id": scan_id,
            "host": host,
            "port": port,
            "target": target,
            "templates": "default",
            "severity_filter": "all",
            "vulnerabilities_found": vuln_count,
            "vulnerabilities": final_vulnerabilities,
            "duration_seconds": duration,
            "debug": debug_info,
            "message": f"Vulnerability enumeration completed on {host}:{port} - found {vuln_count} issues"
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Vulnerability scan timed out after 600 seconds",
            "scan_id": scan_id if 'scan_id' in locals() else None
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scan_id": scan_id if 'scan_id' in locals() else None
        }

async def async_enumerate_vulnerabilities(host: str, port: int, timeout: int = 60) -> AsyncGenerator[Dict, None]:
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
    # Brief delay so the client's progress_handler can register
    await asyncio.sleep(0.1)

    # Generate scan ID for tracking
    scan_id = str(uuid.uuid4())

    # Initial status
    yield {"_status": f"Starting Nuclei vulnerability scan on {host}:{port}"}

    # Build target from host and port
    # Determine if we should use HTTP or HTTPS based on port
    if port == 443:
        target = f"https://{host}:{port}"
    elif port == 80:
        target = f"http://{host}"
    elif port in [8080, 8443, 8000, 8888, 9000, 3000, 5000]:
        # Common HTTP ports - try HTTP first
        target = f"http://{host}:{port}"
    elif port == 21:
        target = f"ftp://{host}"
    else:
        # For non-HTTP ports (like SSH 22), use host:port format
        # This will limit nuclei to network-based templates only
        target = f"{host}:{port}"

    # Detect protocol for better template selection
    proto = detect_protocol(host, port)

    # Build nuclei command with JSON output for reliable parsing
    cmd_args = [
        "nuclei",
        "-target", target,
        "-timeout", str(min(10, timeout)),
        "-no-color",
        "-jsonl",
        "-silent"
    ]

    # Smart template selection based on port and service type
    template_config = get_template_config_for_port(port)

    if template_config["protocol_types"]:
        cmd_args.extend(["-pt", ",".join(template_config["protocol_types"])])

    # Handle tags
    tags_to_use = template_config["tags"].copy() if template_config["tags"] else []
    if tags_to_use:
        cmd_args.extend(["-tags", ",".join(tags_to_use)])

    if template_config["severity"]:
        cmd_args.extend(["-severity", ",".join(template_config["severity"])])

    # Note: -timeout-nuclei flag is not supported in this version of nuclei
    # cmd_args.extend(["-timeout-nuclei", str(min(30, timeout * 2))])

    yield {"_status": f"[{scan_id}] Detected protocol: {proto}, using tags: {','.join(tags_to_use)}"}

    # Debug: Log the exact command being executed
    cmd_str = " ".join(cmd_args)
    yield {"_debug": f"[{scan_id}] Executing command: {cmd_str}"}

    # Launch Nuclei subprocess
    proc = await asyncio.create_subprocess_exec(
        *cmd_args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    # Reader for stderr (verbose logs)
    async def read_stderr():
        async for raw_err in proc.stderr:
            line = raw_err.decode().rstrip()
            if line:
                yield {"_verbose": f"[{scan_id}] {line}"}

    # Reader for stdout (JSONL vulnerabilities)
    async def read_stdout():
        # Store all output lines for final parsing
        all_output_lines = []

        async for raw_line in proc.stdout:
            line = raw_line.decode().rstrip()
            if line:
                # Store the line for final parsing
                all_output_lines.append(line)

                # Log the raw output for debugging
                yield {"_debug": f"[{scan_id}] Raw output: {line}"}

                try:
                    # Use parse_nuclei_output to parse the line
                    parsed_vulns = parse_nuclei_output([line])
                    if parsed_vulns:
                        for vuln in parsed_vulns:
                            # Add scan ID to vulnerability data
                            vuln["scan_id"] = scan_id
                            yield vuln
                    else:
                        # If parse_nuclei_output couldn't parse it, try direct JSON parsing
                        try:
                            vuln_data = json.loads(line)
                            # Add scan ID to vulnerability data
                            vuln_data["scan_id"] = scan_id
                            yield vuln_data
                        except json.JSONDecodeError:
                            # If we can't parse as JSON, it might be a status message
                            pass
                except Exception as e:
                    # Log parsing errors but continue
                    yield {"_debug": f"[{scan_id}] Error parsing output: {str(e)}"}
                    continue

        # Yield all output lines for final parsing
        yield {"_all_output_lines": all_output_lines}

    stderr_iter = read_stderr()
    stdout_iter = read_stdout()
    stderr_task = asyncio.create_task(stderr_iter.__anext__())
    stdout_task = asyncio.create_task(stdout_iter.__anext__())
    pending = {stderr_task, stdout_task}
    any_yielded = False
    vuln_count = 0
    # Store found vulnerabilities for summary
    found_vulnerabilities = []
    # Store all output lines for final parsing
    all_output_lines = []

    # Interleave whichever stream yields first
    start_time = time.time()

    while pending:
        try:
            # Add timeout to asyncio.wait to prevent hanging
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED, timeout=1.0)

            # Check for timeout
            current_time = time.time()
            if current_time - start_time > timeout:
                yield {"_status": f"[{scan_id}] Scan timeout reached after {timeout} seconds"}
                if proc.returncode is None:  # Process still running
                    proc.terminate()
                    await asyncio.sleep(0.5)
                    if proc.returncode is None:  # Still running after terminate
                        proc.kill()
                break

            # Process completed tasks
            for task in done:
                try:
                    item = task.result()

                    # Check if this is the special message with all output lines
                    if isinstance(item, dict) and "_all_output_lines" in item:
                        all_output_lines.extend(item["_all_output_lines"])
                        # Don't yield the special message
                    else:
                        yield item
                        any_yielded = True

                        # Count vulnerabilities
                        if isinstance(item, dict) and "template-id" in item:
                            vuln_count += 1
                            # Store the vulnerability for summary
                            found_vulnerabilities.append(item)
                            yield {"_status": f"[{scan_id}] Found vulnerability: {item.get('template-id', 'unknown')} [{item.get('info', {}).get('severity', 'unknown')}]"}

                    # Create new task for the same iterator
                    if task is stderr_task:
                        stderr_task = asyncio.create_task(stderr_iter.__anext__())
                        pending.add(stderr_task)
                    else:
                        stdout_task = asyncio.create_task(stdout_iter.__anext__())
                        pending.add(stdout_task)
                except StopAsyncIteration:
                    pass

            # If no tasks completed in this iteration, check if process has exited
            if not done:
                # Check if process has exited
                if proc.returncode is not None:
                    yield {"_status": f"[{scan_id}] Process exited with code {proc.returncode} but no output was received"}
                    break
                continue

        except asyncio.TimeoutError:
            # Check if process has exited
            if proc.returncode is not None:
                yield {"_status": f"[{scan_id}] Process exited with code {proc.returncode} during wait timeout"}
                break

            # Check overall timeout
            current_time = time.time()
            if current_time - start_time > timeout:
                yield {"_status": f"[{scan_id}] Scan timeout reached after {timeout} seconds"}
                if proc.returncode is None:  # Process still running
                    proc.terminate()
                    await asyncio.sleep(0.5)
                    if proc.returncode is None:  # Still running after terminate
                        proc.kill()
                break

    # Wait for Nuclei to exit & handle errors
    try:
        # Wait for process to exit with a timeout
        return_code = await asyncio.wait_for(proc.wait(), timeout=5.0)
        yield {"_status": f"[{scan_id}] Process exited with code {return_code}"}

        # Return code 2 is normal when no vulnerabilities are found
        if return_code != 0 and return_code != 2:
            try:
                # Read stderr with a timeout to prevent hanging
                stderr_data = await asyncio.wait_for(proc.stderr.read(), timeout=3.0)
                error_msg = stderr_data.decode().strip()
                yield {"_error": f"[{scan_id}] Nuclei exited with code {return_code}: {error_msg}"}
            except asyncio.TimeoutError:
                yield {"_error": f"[{scan_id}] Nuclei exited with code {return_code}, but stderr read timed out"}
    except asyncio.TimeoutError:
        yield {"_error": f"[{scan_id}] Timed out waiting for process to exit, forcing termination"}
        if proc.returncode is None:
            proc.terminate()
            await asyncio.sleep(0.5)
            if proc.returncode is None:
                proc.kill()

    # Do a final parsing of all output lines
    if all_output_lines:
        yield {"_status": f"[{scan_id}] Performing final parsing of {len(all_output_lines)} output lines"}

        # Parse all output lines
        final_parsed_vulns = parse_nuclei_output(all_output_lines)

        # Add any new vulnerabilities found
        for vuln in final_parsed_vulns:
            vuln_key = (vuln.get('template_id'), vuln.get('matched_at'))
            # Check if we already have this vulnerability
            is_duplicate = False
            for existing_vuln in found_vulnerabilities:
                existing_key = (existing_vuln.get('template_id'), existing_vuln.get('matched_at'))
                if vuln_key == existing_key:
                    is_duplicate = True
                    break

            # If it's not a duplicate, add it
            if not is_duplicate:
                vuln["scan_id"] = scan_id
                found_vulnerabilities.append(vuln)
                vuln_count += 1
                yield {"_status": f"[{scan_id}] Found additional vulnerability in final parsing: {vuln.get('template_id', 'unknown')} [{vuln.get('severity', 'unknown')}]"}
                yield vuln

    # Final status
    if not found_vulnerabilities:
        yield {"_status": f"[{scan_id}] Scan completed: no vulnerabilities found."}
    else:
        yield {"_status": f"[{scan_id}] Scan completed: {vuln_count} vulnerabilities found."}
        yield {"_summary": {
            "scan_id": scan_id, 
            "host": host, 
            "port": port, 
            "vulnerabilities_found": vuln_count, 
            "target": target,
            "vulnerabilities": found_vulnerabilities
        }}


if __name__ == "__main__":
    # Test the tools directly
    #print(enumerate_vulnerabilities("10.0.0.224", 21))
    print(enumerate_vulnerabilities("192.168.0.242", 11434))

    # Test the async version
    async def _async_enumerate_vulnerabilities():
        print("Testing async_enumerate_vulnerabilities...")
        test_host = "192.168.0.242"
        test_port = 80

        print(f"Running async vulnerability scan on {test_host}:{test_port}")
        async for result in async_enumerate_vulnerabilities(test_host, test_port):
            print(f"Result: {result}")

        # Test with HTTPS port
        https_test_port = 443
        print(f"\nTesting HTTPS vulnerability scan on {test_host}:{https_test_port}")
        async for result in async_enumerate_vulnerabilities(test_host, https_test_port):
            print(f"Result: {result}")

        # Test with problematic port
        problem_port = 11434
        print(f"\nTesting problematic port scan on {test_host}:{problem_port}")
        async for result in async_enumerate_vulnerabilities(test_host, problem_port, timeout=15):
            print(f"Result: {result}")

    # Run the async test
    asyncio.run(_async_enumerate_vulnerabilities())
