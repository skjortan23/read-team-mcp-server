import socket


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
