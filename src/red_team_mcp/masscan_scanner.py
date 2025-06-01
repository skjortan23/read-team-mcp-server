"""
Masscan Scanner Module - Red Team MCP

This module contains functions for port scanning using masscan.
"""

import json
import subprocess

from datetime import datetime
from pathlib import Path
import tempfile
import uuid
from red_team_mcp import database
from red_team_mcp.bannerGrabber import getBanner


def execute_masscan_streaming(target: str, ports: str, rate: int = 100, timeout: int = 300,
                             progress_callback=None) -> tuple[bool, str, Path]:
    """Execute masscan with streaming output processing and return success status, stderr output, and output file path."""
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

        # Execute scan with streaming output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True
        )

        stderr_output = ""
        hosts_found = 0
        ports_found = 0

        try:
            # Monitor the output file for new results
            import time
            start_time = time.time()
            last_size = 0

            while process.poll() is None:
                # Check for timeout
                if time.time() - start_time > timeout:
                    process.terminate()
                    process.wait(timeout=5)
                    return False, f"Scan timed out after {timeout} seconds", output_file

                # Check if output file has grown
                if output_file.exists():
                    current_size = output_file.stat().st_size
                    if current_size > last_size:
                        # Process new content
                        new_results = _process_new_output(output_file, last_size)
                        if new_results:
                            for result in new_results:
                                if 'ip' in result and 'ports' in result:
                                    hosts_found += 1
                                    ports_found += len(result.get('ports', []))

                                    # Call progress callback if provided
                                    if progress_callback:
                                        progress_callback({
                                            'type': 'host_found',
                                            'ip': result.get('ip'),
                                            'ports': result.get('ports', []),
                                            'total_hosts': hosts_found,
                                            'total_ports': ports_found
                                        })

                        last_size = current_size

                # Small delay to avoid busy waiting
                time.sleep(0.1)

            # Wait for process to complete and get stderr
            _, stderr = process.communicate()
            stderr_output = stderr.strip()

            # Process any remaining output
            if output_file.exists():
                final_results = _process_new_output(output_file, last_size)
                if final_results and progress_callback:
                    for result in final_results:
                        if 'ip' in result and 'ports' in result:
                            hosts_found += 1
                            ports_found += len(result.get('ports', []))
                            progress_callback({
                                'type': 'host_found',
                                'ip': result.get('ip'),
                                'ports': result.get('ports', []),
                                'total_hosts': hosts_found,
                                'total_ports': ports_found
                            })

            # Final progress update
            if progress_callback:
                progress_callback({
                    'type': 'scan_complete',
                    'total_hosts': hosts_found,
                    'total_ports': ports_found,
                    'return_code': process.returncode
                })

            return process.returncode == 0, stderr_output, output_file

        except Exception as e:
            process.terminate()
            process.wait(timeout=5)
            raise e

    except subprocess.TimeoutExpired:
        return False, f"Scan timed out after {timeout} seconds", output_file
    except Exception as e:
        return False, str(e), output_file


def _process_new_output(output_file: Path, last_position: int) -> list[dict]:
    """Process new content in the output file since last_position."""
    results = []

    try:
        with open(output_file, 'r') as f:
            f.seek(last_position)
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError:
                        continue
    except Exception:
        pass

    return results


def execute_masscan(target: str, ports: str, rate: int = 100, timeout: int = 300) -> tuple[bool, str, Path]:
    """Execute masscan and return success status, stderr output, and output file path.

    This is the legacy synchronous version for backward compatibility.
    """
    return execute_masscan_streaming(target, ports, rate, timeout, progress_callback=None)

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

def port_scan_streaming(target: str, ports: str, scan_type: str = "tcp_syn", rate: int = 100,
                       progress_callback=None) -> dict:
    """
    NETWORK PORT SCANNING: Discover open ports on hosts using masscan with real-time progress.

    This function performs PORT DISCOVERY to find open TCP/UDP ports on target hosts
    and provides real-time progress updates via callback.

    Args:
        target: IP address or CIDR range to scan
        ports: Comma-separated ports or ranges
        scan_type: Type of scan (tcp_syn, tcp_connect, udp, etc.)
        rate: Packets per second rate
        progress_callback: Function to call with progress updates

    Returns:
        Dictionary with scan results
    """
    try:
        # Generate scan ID and start time
        scan_id = str(uuid.uuid4())
        start_time = datetime.now()

        # Create initial scan record
        database.create_scan_record(scan_id, target, ports, scan_type, start_time)

        # Progress tracking
        discovered_hosts = []
        total_hosts_found = 0
        total_ports_found = 0

        def internal_progress_callback(progress_data):
            nonlocal total_hosts_found, total_ports_found

            if progress_data['type'] == 'host_found':
                # Process and store the new host data immediately
                ip = progress_data['ip']
                port_data = progress_data['ports']

                # Convert to our expected format
                host_entry = {"ip": ip, "ports": []}

                for port_info in port_data:
                    port = port_info.get('port')
                    protocol = port_info.get('proto', 'tcp')
                    state = port_info.get('status', 'open')
                    service_info = port_info.get('service', {})

                    if port:
                        # Get banner info if available
                        banner_info = {}
                        if service_info:
                            service_name = service_info.get('name', 'unknown')
                            banner_text = service_info.get('banner', '').strip()
                            banner_info = {
                                "service": service_name,
                                "version": "",
                                "banner": banner_text
                            }
                        else:
                            # Try to get banner with netcat
                            try:
                                banner_info = getBanner(ip, port)
                            except Exception:
                                banner_info = {"service": "unknown", "version": "", "banner": ""}

                        host_entry["ports"].append({
                            "port": port,
                            "protocol": protocol,
                            "state": state,
                            "service": banner_info.get("service", "unknown"),
                            "version": banner_info.get("version", ""),
                            "banner": banner_info.get("banner", "")
                        })

                discovered_hosts.append(host_entry)
                total_hosts_found = progress_data['total_hosts']
                total_ports_found = progress_data['total_ports']

                # Save incremental results to database
                try:
                    database.save_incremental_scan_result(scan_id, host_entry)
                except Exception as e:
                    print(f"Warning: Failed to save incremental result: {e}")

                # Call user's progress callback
                if progress_callback:
                    progress_callback({
                        'type': 'host_discovered',
                        'scan_id': scan_id,
                        'host': host_entry,
                        'total_hosts': total_hosts_found,
                        'total_ports': total_ports_found,
                        'message': f"Found host {ip} with {len(host_entry['ports'])} open ports"
                    })

            elif progress_data['type'] == 'scan_complete':
                if progress_callback:
                    progress_callback({
                        'type': 'scan_complete',
                        'scan_id': scan_id,
                        'total_hosts': total_hosts_found,
                        'total_ports': total_ports_found,
                        'return_code': progress_data['return_code']
                    })

        # Execute the scan with streaming (use default 5-minute timeout)
        success, error_output, output_file = execute_masscan_streaming(
            target, ports, rate, progress_callback=internal_progress_callback
        )

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        if not success:
            # Update scan record with error
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

        # Final processing of any remaining results
        final_hosts = parse_masscan_results(output_file)

        # Merge with discovered hosts (in case we missed any)
        all_hosts = discovered_hosts.copy()
        for host in final_hosts:
            # Check if we already have this host
            existing_host = None
            for existing in all_hosts:
                if existing["ip"] == host["ip"]:
                    existing_host = existing
                    break

            if not existing_host:
                all_hosts.append(host)

        # Save final results to database
        total_hosts, total_open_ports = database.save_scan_results(
            scan_id, target, ports, scan_type, start_time, end_time, all_hosts
        )

        return {
            "success": True,
            "scan_id": scan_id,
            "target": target,
            "ports_scanned": ports,
            "scan_type": scan_type,
            "total_hosts": total_hosts,
            "total_open_ports": total_open_ports,
            "hosts": all_hosts,
            "duration_seconds": duration,
            "message": f"Scan completed - found {total_hosts} hosts with {total_open_ports} open ports"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scan_id": scan_id if 'scan_id' in locals() else None
        }


def port_scan(target: str, ports, scan_type: str = "tcp_syn", rate: int = 100) -> dict:
    """
    NETWORK PORT SCANNING: Discover open ports on hosts using masscan.

    This function performs PORT DISCOVERY to find open TCP/UDP ports on target hosts.
    This is the legacy synchronous version for backward compatibility.

    Args:
        target: IP address or CIDR range to scan
        ports: Comma-separated ports or ranges
        scan_type: Type of scan (tcp_syn, tcp_connect, udp, etc.)
        rate: Packets per second rate

    Returns:
        Dictionary with scan results
    """
    return port_scan_streaming(target, scan_type, rate, progress_callback=None)

if __name__ == "__main__":
    print( port_scan('192.168.0.242', 'tcp_syn', '500', ))