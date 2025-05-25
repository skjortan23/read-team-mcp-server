"""
Nuclei Scanner Module - Red Team MCP

This module contains functions for vulnerability scanning using nuclei.
"""

import json
import subprocess
import socket
import re
from datetime import datetime
from typing import List, Dict
from pathlib import Path
import uuid

from red_team_mcp import database

def parse_nuclei_output(output_lines: list[str]) -> list[dict]:
    """
    Parse nuclei scanner output into structured vulnerability data.

    Expected format:
    [template-id] [protocol] [severity] target ["extracted_data"]
    """
    vulnerabilities = []

    for line in output_lines:
        line = line.strip()
        if not line:
            continue

        try:
            # Parse nuclei output format: [template-id] [protocol] [severity] target ["extracted"]
            # Regex to match nuclei output format
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

        except Exception as e:
            # Skip malformed lines but continue processing
            continue

    return vulnerabilities

def enumerate_vulnerabilities(host: str, port: int) -> dict:
    """
    ENUMERATE VULNERABILITIES: Find security issues and CVEs using nuclei scanner.

    This function scans a host:port for vulnerabilities using nuclei scanner.

    Args:
        host: Hostname or IP address to scan
        port: Port number to scan

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
        else:
            # For other ports, use host:port format
            target = f"{host}:{port}"

        # Create initial scan record
        database.create_scan_record(scan_id, target, "vuln-scan", "nuclei", start_time)

        # Build nuclei command with sensible defaults
        cmd = [
            "nuclei",
            "-target", target,
            "-silent",
            "-severity", "low,medium,high,critical",  # All severity levels
            "-timeout", "30",                              # 30 second timeout per template
            "-no-color",                                   # Disable color output for easier parsing
        ]

        # Debug: Print command being executed
        print(f"🔍 DEBUG: Executing nuclei command: {' '.join(cmd)}")
        print(f"🎯 DEBUG: Target: {target}")

        # Execute nuclei scan
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute max timeout
        )

        # Debug: Print raw results
        print(f"📊 DEBUG: Nuclei return code: {result.returncode}")
        print(f"📝 DEBUG: Nuclei stdout length: {len(result.stdout)} chars")
        print(f"📝 DEBUG: Nuclei stdout content:")
        print(f"--- STDOUT START ---")
        print(result.stdout)
        print(f"--- STDOUT END ---")
        if result.stderr:
            print(f"⚠️  DEBUG: Nuclei stderr:")
            print(f"--- STDERR START ---")
            print(result.stderr)
            print(f"--- STDERR END ---")

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Check if nuclei command succeeded
        if result.returncode != 0:
            # Update scan record with error
            database.update_scan_status(
                scan_id, 
                "failed", 
                end_time, 
                duration, 
                0, 
                0, 
                "", 
                f"Nuclei failed with return code {result.returncode}: {result.stderr}"
            )

            return {
                "success": False,
                "error": f"Nuclei command failed with return code {result.returncode}",
                "stderr": result.stderr,
                "command": ' '.join(cmd),
                "scan_id": scan_id,
                "host": host,
                "port": port,
                "target": target
            }

        # Parse nuclei output
        output_lines = result.stdout.strip().split('\n') if result.stdout.strip() else []
        print(f"🔍 DEBUG: Found {len(output_lines)} output lines to parse")
        for i, line in enumerate(output_lines[:5]):  # Show first 5 lines
            print(f"📝 DEBUG: Line {i+1}: {line}")
        if len(output_lines) > 5:
            print(f"📝 DEBUG: ... and {len(output_lines) - 5} more lines")

        vulnerabilities = parse_nuclei_output(output_lines)
        print(f"🎯 DEBUG: Parsed {len(vulnerabilities)} vulnerabilities")

        # Show first few vulnerabilities for debugging
        for i, vuln in enumerate(vulnerabilities[:3]):
            print(f"🔍 DEBUG: Vuln {i+1}: {vuln['template_id']} [{vuln['severity']}] on {vuln.get('hostname', 'N/A')}:{vuln.get('port', 'N/A')}")

        # Save vulnerability results to database
        database.save_vulnerability_results(scan_id, vulnerabilities)
        vuln_count = len(vulnerabilities)
        print(f"💾 DEBUG: Saved {vuln_count} vulnerabilities to database")

        # Update scan record
        database.update_scan_status(
            scan_id, 
            "completed", 
            end_time, 
            duration, 
            1, 
            vuln_count, 
            json.dumps(vulnerabilities)
        )

        # Prepare debug info for the response
        debug_info = {
            "command": ' '.join(cmd),
            "return_code": result.returncode,
            "stdout_length": len(result.stdout),
            "stderr": result.stderr if result.stderr else None,
            "output_lines_count": len(output_lines),
            "first_few_lines": output_lines[:3] if output_lines else [],
            "parsing_successful": len(vulnerabilities) > 0
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
            "vulnerabilities": vulnerabilities,
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
