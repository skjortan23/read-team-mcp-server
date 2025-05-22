#!/usr/bin/env python3
"""
Test script for the getBanner functionality
"""

import subprocess
import socket
from typing import Dict

def getBanner_socket(ip: str, port: int, timeout: int = 5) -> Dict[str, str]:
    """
    Use Python socket to connect to a host:port and retrieve banner information.

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


def getBanner(ip: str, port: int, timeout: int = 5) -> Dict[str, str]:
    """
    Use netcat to connect to a host:port and retrieve banner information.

    Args:
        ip: IP address to connect to
        port: Port number to connect to
        timeout: Connection timeout in seconds

    Returns:
        Dictionary with service, version, and banner information
    """
    # Try socket approach first (more reliable)
    result = getBanner_socket(ip, port, timeout)
    if result.get("banner") and not result.get("banner").startswith("Error:"):
        return result

    # Fallback to netcat approach
    try:
        # Use netcat to connect and get banner
        cmd = ["nc", "-w", str(timeout), ip, str(port)]

        # Try different approaches based on the service
        if port in [80, 8080, 8000]:
            # For HTTP services, send a request and capture response
            http_cmd = f'printf "GET / HTTP/1.0\\r\\n\\r\\n" | nc -w {timeout} {ip} {port}'
            result = subprocess.run(
                http_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
        elif port == 22:
            # For SSH, just connect and capture the banner
            # SSH sends banner immediately upon connection
            result = subprocess.run(
                ["nc", "-w", str(timeout), ip, str(port)],
                input="",
                capture_output=True,
                text=True,
                timeout=timeout
            )
        else:
            # For other services, try to connect and see what happens
            result = subprocess.run(
                cmd,
                input="",
                capture_output=True,
                text=True,
                timeout=timeout
            )

        banner_text = (result.stdout + result.stderr).strip()

        # Debug output
        print(f"DEBUG: Return code: {result.returncode}")
        print(f"DEBUG: stdout: '{result.stdout}'")
        print(f"DEBUG: stderr: '{result.stderr}'")
        print(f"DEBUG: banner_text: '{banner_text}'")

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

def test_banner_function():
    """Test the getBanner function with a known service."""
    print("Testing getBanner function...")

    # Test with GitHub SSH (should give immediate banner)
    print("\n1. Testing with GitHub SSH (github.com:22)...")
    try:
        result = getBanner("github.com", 22, timeout=5)
        print(f"   Service: {result.get('service', 'unknown')}")
        print(f"   Version: {result.get('version', '')}")
        banner = result.get('banner', '')
        if banner:
            print(f"   Banner: {banner[:200]}...")  # First 200 chars
        else:
            print(f"   Banner: (empty)")
    except Exception as e:
        print(f"   Error: {e}")

    # Test with httpbin.org (HTTP service)
    print("\n1b. Testing with httpbin.org:80...")
    try:
        result = getBanner("httpbin.org", 80, timeout=5)
        print(f"   Service: {result.get('service', 'unknown')}")
        print(f"   Version: {result.get('version', '')}")
        banner = result.get('banner', '')
        if banner:
            print(f"   Banner: {banner[:200]}...")  # First 200 chars
        else:
            print(f"   Banner: (empty)")
    except Exception as e:
        print(f"   Error: {e}")

    # Test with a simple echo command to verify nc works
    print("\n2. Testing netcat functionality...")
    try:
        import subprocess
        result = subprocess.run(
            ["echo", "test", "|", "nc", "-w", "1", "httpbin.org", "80"],
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        print(f"   NC test result: {result.returncode}")
        print(f"   Output: {result.stdout[:100]}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test with a non-existent service
    print("\n3. Testing with non-existent service (127.0.0.1:9999)...")
    try:
        result = getBanner("127.0.0.1", 9999, timeout=2)
        print(f"   Service: {result.get('service', 'unknown')}")
        print(f"   Version: {result.get('version', '')}")
        print(f"   Banner: {result.get('banner', '')}")
    except Exception as e:
        print(f"   Error: {e}")

if __name__ == "__main__":
    test_banner_function()
