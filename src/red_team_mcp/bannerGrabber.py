import socket
import http.client
import re
import ssl
from typing import Dict, List, Tuple
from red_team_mcp.constants import ports_by_service


def getBanner(ip: str, port: int, timeout: int = 5) -> Dict[str, str]:
    """
    Retrieve banner information from a host:port.
    Uses HTTP/HTTPS library for web services and socket connections for other services.

    For HTTP/HTTPS services, the function automatically detects the protocol based on the port
    (e.g., 443, 8443 for HTTPS) and uses the appropriate connection method. For HTTPS connections,
    certificate verification is disabled to allow banner grabbing from servers with self-signed
    or invalid certificates.

    Args:
        ip: IP address to connect to
        port: Port number to connect to
        timeout: Connection timeout in seconds

    Returns:
        Dictionary with service, version, and banner information
    """
    try:
        # Initial service guess based on port
        initial_service = _guess_service_by_port(port)

        # Use HTTP/HTTPS library for web services
        if initial_service in ["http", "https"]:
            return _get_web_banner(ip, port, timeout, is_https=(initial_service == "https"))

        # Use socket connection for non-web services
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Connect to the target
        sock.connect((ip, port))

        # Receive banner/response
        banner_text = ""
        try:
            data = sock.recv(1024)
            banner_text = data.decode('utf-8', errors='ignore').strip()
        except:
            pass

        sock.close()

        if banner_text:
            # Identify service and version from banner and port
            service_info = _identify_service(banner_text, port)
            service_name = service_info[0]
            version = service_info[1]
            if "\r\n" in banner_text:
                banner_text = banner_text.split("\r\n")[0]

            return {
                "service": service_name,
                "version": version,
                "banner": banner_text
            }
        else:
            # If no banner text, use port-based guess only
            service_name = _guess_service_by_port(port)
            return {
                "service": service_name,
                "version": "",
                "banner": ""
            }

    except Exception as e:
        return {
            "service": "unknown",
            "version": "",
            "banner": f"Error: {str(e)}"
        }


def _guess_service_by_port(port: int) -> str:
    """
    Make an initial guess about the service based on the port number.

    Args:
        port: Port number

    Returns:
        String with the guessed service name
    """
    # Check for common HTTPS ports first
    if port in [443, 8443]:
        return "https"

    # Check all service types in constants.py
    for service in [
        "http", "ftp", "ssh", "telnet", "smtp", "pop3", "imap", 
        "dns", "ldap", "mysql", "postgresql", "redis", "mongodb",
        "rdp", "vnc", "smb", "ntp", "snmp"
    ]:
        try:
            port_list = [int(p) for p in ports_by_service(service)]
            if port in port_list:
                return service
        except ValueError:
            # Skip if service not found in ports_by_service
            continue

    # Default to unknown if no match found
    return "unknown"


def _get_web_banner(ip: str, port: int, timeout: int, is_https: bool = False) -> Dict[str, str]:
    """
    Use HTTP/HTTPS library to retrieve banner information from a web service.
    Uses regular expressions to extract version information from headers and response body.

    Args:
        ip: IP address to connect to
        port: Port number to connect to
        timeout: Connection timeout in seconds
        is_https: Whether to use HTTPS (True) or HTTP (False)

    Returns:
        Dictionary with service, version, and banner information
    """
    try:
        # Use http.client to send a GET request to get both headers and body
        if is_https:
            # Create an SSL context that doesn't verify certificates
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)

        conn.request("GET", "/")
        response = conn.getresponse()

        # Get headers as a dictionary
        headers = {k.lower(): v for k, v in response.getheaders()}

        # Read response body (limited to prevent huge responses)
        body = response.read(4096).decode('utf-8', errors='ignore')

        # Extract server information
        server = headers.get('server', '')

        # Construct banner text from status line, headers, and a preview of the body
        status_line = f"HTTP/{response.version // 10}.{response.version % 10} {response.status} {response.reason}"
        header_lines = [f"{k}: {v}" for k, v in response.getheaders()]
        banner_text = status_line + "\r\n" + "\r\n".join(header_lines)

        # Determine service and version
        service_name = "https" if is_https else "http"
        version = ""

        # Check for specific services in both headers and body
        content_type = headers.get('content-type', '').lower()
        version_patterns = [
            # Apache version
            {
                "regex": r'Apache(?:/(\d+\.\d+\.\d+))?',
                "format": "Apache{}"
            },
            # Nginx version
            {
                "regex": r'nginx(?:/(\d+\.\d+\.\d+))?',
                "format": "nginx{}"
            },
            # IIS version
            {
                "regex": r'Microsoft-IIS/(\d+\.\d+)',
                "format": "Microsoft-IIS/{}"
            },
            # Lighttpd version
            {
                "regex": r'lighttpd(?:/(\d+\.\d+\.\d+))?',
                "format": "lighttpd{}"
            },
            # Gunicorn version
            {
                "regex": r'gunicorn(?:/(\d+\.\d+\.\d+))?',
                "format": "gunicorn{}"
            },
            # Generic server header
            {
                "regex": r'(.*)',
                "format": "{}"
            }
        ]

        if server:
            for pattern in version_patterns:
                match = re.search(pattern["regex"], server, re.IGNORECASE)
                if match:
                    # If we have a version group, use it
                    if match.groups() and match.group(1):
                        version_str = match.group(1)
                        # Format with a slash between name and version
                        version = pattern["format"].format(f"/{version_str}")
                    else:
                        # Otherwise use the whole match without additional formatting
                        version = pattern["format"].format("")
                    break
        else:
            # If no server header, use generic HTTP
            version = "HTTP"

        return {
            "service": service_name,
            "version": version,
            "banner": banner_text
        }
    except Exception as e:
        return {
            "service": "http",
            "version": "",
            "banner": f"Error: {str(e)}"
        }

def _identify_service(banner_text: str, port: int) -> Tuple[str, str]:
    """
    Identify service and version based on banner text and port using regular expressions.

    Args:
        banner_text: Banner text from the service
        port: Port number

    Returns:
        Tuple of (service_name, version)
    """
    # Initial guess based on port
    service_name = _guess_service_by_port(port)
    version = ""

    # Service detection patterns
    service_patterns = [
        # HTTP/HTTPS detection
        {
            "regex": r'^HTTP/\d\.\d',
            "service": "http"  # Will be overridden if port suggests HTTPS
        },
        # HTTP/HTTPS detection - content type header
        {
            "regex": r'content-type:\s*(?:text/html|application/json|text/xml)',
            "service": "http"  # Will be overridden if port suggests HTTPS
        },
        # Ollama detection
        {
            "regex": r'ollama',
            "service": "http"  # Ollama can be HTTP or HTTPS-based
        },
        # SSH detection
        {
            "regex": r'^SSH-\d\.\d',
            "service": "ssh"
        },
        # FTP detection - look for FTP keywords to distinguish from SMTP
        {
            "regex": r'^220[\s-].*(?:ftp|file|transfer)',
            "service": "ftp"
        },
        # SMTP detection - look for mail keywords
        {
            "regex": r'^220[\s-].*(?:smtp|mail|email|e-mail)',
            "service": "smtp"
        },
        # Generic 220 response (could be FTP or SMTP)
        {
            "regex": r'^220[\s-]',
            "service": "ftp"  # Default to FTP if no other indicators
        },
        # POP3 detection
        {
            "regex": r'^\+OK',
            "service": "pop3"
        },
        # IMAP detection
        {
            "regex": r'^\* OK.*IMAP',
            "service": "imap"
        },
        # MySQL detection
        {
            "regex": r'mysql|mariadb',
            "service": "mysql"
        },
        # PostgreSQL detection
        {
            "regex": r'postgres|postgresql',
            "service": "postgresql"
        },
        # Oracle detection
        {
            "regex": r'oracle',
            "service": "oracle"
        },
        # SQL Server detection
        {
            "regex": r'microsoft.*sql|sql.*server',
            "service": "sqlserver"
        },
        # Telnet detection
        {
            "regex": r'telnet',
            "service": "telnet"
        }
    ]

    # Version detection patterns
    version_patterns = {
        "http": [
            # Ollama detection
            {
                "regex": r'ollama',
                "format": "Ollama"
            },
            # API detection
            {
                "regex": r'content-type:\s*application/json',
                "format": "API"
            },
            # OpenAPI/Swagger detection
            {
                "regex": r'swagger|openapi',
                "format": "API (OpenAPI/Swagger)"
            },
            # Apache version
            {
                "regex": r'Server:\s*Apache(?:/(\d+\.\d+\.\d+))?',
                "format": "Apache{}"
            },
            # Nginx version
            {
                "regex": r'Server:\s*nginx(?:/(\d+\.\d+\.\d+))?',
                "format": "nginx{}"
            },
            # IIS version
            {
                "regex": r'Server:\s*Microsoft-IIS/(\d+\.\d+)',
                "format": "Microsoft-IIS/{}"
            },
            # Generic server header
            {
                "regex": r'Server:\s*([^\r\n]+)',
                "format": "{}"
            }
        ],
        "https": [
            # Ollama detection
            {
                "regex": r'ollama',
                "format": "Ollama (HTTPS)"
            },
            # API detection
            {
                "regex": r'content-type:\s*application/json',
                "format": "API (HTTPS)"
            },
            # OpenAPI/Swagger detection
            {
                "regex": r'swagger|openapi',
                "format": "API (OpenAPI/Swagger) (HTTPS)"
            },
            # Apache version
            {
                "regex": r'Server:\s*Apache(?:/(\d+\.\d+\.\d+))?',
                "format": "Apache{} (HTTPS)"
            },
            # Nginx version
            {
                "regex": r'Server:\s*nginx(?:/(\d+\.\d+\.\d+))?',
                "format": "nginx{} (HTTPS)"
            },
            # IIS version
            {
                "regex": r'Server:\s*Microsoft-IIS/(\d+\.\d+)',
                "format": "Microsoft-IIS/{} (HTTPS)"
            },
            # Generic server header
            {
                "regex": r'Server:\s*([^\r\n]+)',
                "format": "{} (HTTPS)"
            }
        ],
        "ssh": [
            # OpenSSH version
            {
                "regex": r'SSH-\d\.\d-OpenSSH[_-](\d+\.\d+\w*)',
                "format": "OpenSSH {}"
            },
            # Generic SSH version
            {
                "regex": r'SSH-\d\.\d-([^\r\n]+)',
                "format": "{}"
            }
        ],
        "ftp": [
            # VSFTPD version
            {
                "regex": r'220[\s-]+vsftpd\s+(\d+\.\d+\.\d+)',
                "format": "vsftpd {}"
            },
            # ProFTPD version
            {
                "regex": r'220[\s-]+ProFTPD\s+(\d+\.\d+\.\d+)',
                "format": "ProFTPD {}"
            },
            # Generic FTP version
            {
                "regex": r'220[\s-]+([^\r\n]+)',
                "format": "{}"
            }
        ],
        "smtp": [
            # Postfix version
            {
                "regex": r'220[\s-]+.*Postfix[^\d]*(\d+\.\d+\.\d+)',
                "format": "Postfix {}"
            },
            # Sendmail version
            {
                "regex": r'220[\s-]+.*Sendmail[^\d]*(\d+\.\d+\.\d+)',
                "format": "Sendmail {}"
            },
            # Exchange version
            {
                "regex": r'220[\s-]+.*Microsoft.*Exchange.*(\d+\.\d+\.\d+)',
                "format": "Exchange {}"
            },
            # Generic SMTP version
            {
                "regex": r'220[\s-]+([^\r\n]+)',
                "format": "{}"
            }
        ],
        "mysql": [
            # MySQL version
            {
                "regex": r'mysql.*?(\d+\.\d+\.\d+)',
                "format": "MySQL {}"
            },
            # MariaDB version
            {
                "regex": r'mariadb.*?(\d+\.\d+\.\d+)',
                "format": "MariaDB {}"
            }
        ],
        "postgresql": [
            # PostgreSQL version
            {
                "regex": r'postgresql.*?(\d+\.\d+)',
                "format": "PostgreSQL {}"
            }
        ]
    }

    # First, try to identify service from banner
    banner_lower = banner_text.lower()
    for pattern in service_patterns:
        if re.search(pattern["regex"], banner_lower, re.IGNORECASE | re.MULTILINE):
            # For HTTP/HTTPS, use the port-based guess if it's HTTPS
            if pattern["service"] == "http" and _guess_service_by_port(port) == "https":
                service_name = "https"
            else:
                service_name = pattern["service"]
            break

    # Then, try to determine version based on identified service
    if service_name in version_patterns:
        for pattern in version_patterns[service_name]:
            match = re.search(pattern["regex"], banner_text, re.IGNORECASE | re.MULTILINE)
            if match:
                # If we have a version group, use it
                if match.groups():
                    version_str = match.group(1)
                    # Format with appropriate separator between name and version
                    if "/" in pattern["format"] or " " in pattern["format"]:
                        # If format already includes a separator, use as is
                        version = pattern["format"].format(version_str)
                    else:
                        # Otherwise add a space between name and version
                        version = pattern["format"].format(f" {version_str}")
                else:
                    # Otherwise use the whole match
                    version = pattern["format"].format(match.group(0))
                break

        # If no specific version found, use generic service name
        if not version and service_name:
            version = service_name.upper()

    return service_name, version

if __name__ == "__main__":
    res = getBanner('192.168.0.242', 11434)
    print(res)
