#!/usr/bin/env python3
"""
Domain Discovery Tool - Red Team MCP

This tool is used to enumerate subdomains from a top level domain using subfinder.

Features:
1. Validate that the domain resolves using DNS
2. Execute subfinder tool to discover subdomains
3. Resolve each subdomain to IP address
4. Store results in database and return structured response
"""

import asyncio
import json
import socket
import subprocess
import uuid
from datetime import datetime
from typing import List, Dict, Optional, Callable
from pathlib import Path

# Handle both relative and absolute imports
try:
    from . import database
except ImportError:
    # When running directly, use absolute import
    import database

# Check if database is available
try:
    database.get_database()
    DATABASE_AVAILABLE = True
except Exception:
    DATABASE_AVAILABLE = False
    print("⚠️  Database not available for domain discovery")


def validate_domain_resolution(domain: str, timeout: int = 10) -> tuple[bool, str, str]:
    """
    Validate that a domain resolves to an IP address.

    Args:
        domain: Domain name to validate
        timeout: DNS resolution timeout in seconds

    Returns:
        Tuple of (success, ip_address, error_message)
    """
    try:
        # Remove any protocol prefixes and paths
        clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]

        # Use asyncio.wait_for equivalent for sync code with signal timeout
        import signal

        def timeout_handler(signum, frame):
            raise socket.timeout(f"DNS resolution timed out after {timeout} seconds")

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)

        try:
            ip_address = socket.gethostbyname(clean_domain)
            return True, ip_address, ""
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    except socket.timeout as e:
        return False, "", str(e)
    except socket.gaierror as e:
        return False, "", f"DNS resolution failed: {str(e)}"
    except Exception as e:
        return False, "", f"Domain validation error: {str(e)}"


def execute_subfinder(domain: str, timeout: int = 300) -> tuple[bool, List[str], str]:
    """
    Execute subfinder tool to discover subdomains.

    Args:
        domain: Target domain to scan for subdomains
        timeout: Execution timeout in seconds

    Returns:
        Tuple of (success, subdomains_list, error_message)
    """
    try:
        # Clean domain name
        clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]

        # Build subfinder command
        cmd = [
            "subfinder",
            "-d", clean_domain,
            "-silent",  # Only output subdomains
            "-timeout", "10",  # Per-request timeout
        ]

        print(f"🔍 Executing subfinder: {' '.join(cmd)}")

        # Execute subfinder with timeout
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            universal_newlines=True
        )

        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            return False, [], f"Subfinder timed out after {timeout} seconds"

        if process.returncode != 0:
            return False, [], f"Subfinder failed with exit code {process.returncode}: {stderr}"

        # Parse subdomains from output
        subdomains = []
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                subdomains.append(line)

        return True, subdomains, ""

    except FileNotFoundError:
        return False, [], "Subfinder tool not found. Please install subfinder: https://github.com/projectdiscovery/subfinder"
    except Exception as e:
        return False, [], f"Subfinder execution error: {str(e)}"


def resolve_subdomain_to_ip(subdomain: str, timeout: int = 5) -> tuple[bool, str, str]:
    """
    Resolve a subdomain to its IP address.

    Args:
        subdomain: Subdomain to resolve
        timeout: DNS resolution timeout in seconds

    Returns:
        Tuple of (success, ip_address, error_message)
    """
    try:
        import signal

        def timeout_handler(signum, frame):
            raise socket.timeout(f"DNS resolution timed out after {timeout} seconds")

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)

        try:
            ip_address = socket.gethostbyname(subdomain)
            return True, ip_address, ""
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    except socket.timeout as e:
        return False, "", str(e)
    except socket.gaierror as e:
        return False, "", f"DNS resolution failed: {str(e)}"
    except Exception as e:
        return False, "", f"Subdomain resolution error: {str(e)}"


def discover_subdomains(domain: str, timeout: int = 300) -> dict:
    """
    Main domain discovery function that orchestrates the entire process.

    Args:
        domain: Target domain to discover subdomains for
        timeout: Overall timeout for the discovery process
        progress_callback: Optional callback for progress updates

    Returns:
        Dictionary with discovery results
    """
    scan_id = str(uuid.uuid4())
    start_time = datetime.now()

    try:
        print(f"🌐 Starting subdomain discovery for: {domain}")



        # Step 1: Validate main domain resolves
        print(f"🔍 Validating domain resolution...")
        domain_valid, domain_ip, domain_error = validate_domain_resolution(domain)

        if not domain_valid:
            error_msg = f"Domain validation failed: {domain_error}"
            print(f"❌ {error_msg}")
            return {
                "success": False,
                "error": error_msg,
                "scan_id": scan_id,
                "domain": domain
            }

        print(f"✅ Domain {domain} resolves to {domain_ip}")


        # Create initial scan record
        if DATABASE_AVAILABLE:
            database.create_scan_record(scan_id, domain, "subdomains", "domain-discovery", start_time)

        # Step 2: Execute subfinder to discover subdomains
        print(f"🔍 [domain-discovery] Discovering subdomains using subfinder...")
        subfinder_success, subdomains, subfinder_error = execute_subfinder(domain, timeout)

        if not subfinder_success:
            error_msg = f"Subfinder execution failed: {subfinder_error}"
            print(f"❌ [domain-discovery] {error_msg}")
            return {
                "success": False,
                "error": error_msg,
                "scan_id": scan_id,
                "domain": domain
            }

        print(f"✅ [domain-discovery] Found {len(subdomains)} subdomains")



        # Step 3: Resolve each subdomain to IP
        print(f"🔍 [domain-discovery] Resolving subdomains to IP addresses...")
        resolved_subdomains = []

        for i, subdomain in enumerate(subdomains):

            resolve_success, subdomain_ip, resolve_error = resolve_subdomain_to_ip(subdomain)

            if resolve_success:
                print(f"✅ [domain-discovery] {subdomain} -> {subdomain_ip}")
                resolved_subdomains.append({
                    "subdomain": subdomain,
                    "ip_address": subdomain_ip,
                    "resolved": True
                })

                # Save to database
                if DATABASE_AVAILABLE:
                    database.save_scan_result_entry(
                        scan_id=scan_id,
                        hostname=subdomain,
                        ip_address=subdomain_ip,
                        port=0,  # Not applicable for domain discovery
                        protocol="dns",
                        state="resolved",
                        service="domain",
                        version="",
                        banner="",
                        agent="domain-discovery"
                    )
            else:
                print(f"❌ [domain-discovery] {subdomain} -> resolution failed: {resolve_error}")
                resolved_subdomains.append({
                    "subdomain": subdomain,
                    "ip_address": "",
                    "resolved": False,
                    "error": resolve_error
                })

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Count successful resolutions
        successful_resolutions = len([s for s in resolved_subdomains if s["resolved"]])

        print(f"✅ [domain-discovery] Discovery completed: {successful_resolutions}/{len(subdomains)} subdomains resolved")

        # Update scan status
        if DATABASE_AVAILABLE:
            database.update_scan_status(
                scan_id,
                "completed",
                end_time,
                duration,
                successful_resolutions,
                len(subdomains),
                json.dumps(resolved_subdomains)
            )

        return {
            "success": True,
            "scan_id": scan_id,
            "domain": domain,
            "domain_ip": domain_ip,
            "total_subdomains": len(subdomains),
            "resolved_subdomains": successful_resolutions,
            "subdomains": resolved_subdomains,
            "duration_seconds": duration,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        }

    except Exception as e:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds() if 'start_time' in locals() else 0

        error_msg = f"Domain discovery error: {str(e)}"
        print(f"❌ [domain-discovery] {error_msg}")

        # Update scan record with error if scan_id exists
        if DATABASE_AVAILABLE and 'scan_id' in locals():
            database.update_scan_status(
                scan_id,
                "failed",
                end_time,
                duration,
                0,
                0,
                "",
                error_msg
            )

        return {
            "success": False,
            "error": error_msg,
            "scan_id": scan_id if 'scan_id' in locals() else None,
            "domain": domain
        }


def register_tools(app):
    """Register domain discovery tools with the FastMCP app."""

    @app.tool()
    async def domain_discovery(
        domain: str,
        timeout: int = 300
    ) -> str:
        """
        DOMAIN DISCOVERY: Enumerate subdomains from a top-level domain using subfinder.

        This tool discovers subdomains for a given domain and resolves them to IP addresses.
        It provides real-time progress updates during the discovery process.

        Process:
        1. Validate that the main domain resolves via DNS
        2. Execute subfinder tool to discover subdomains
        3. Resolve each discovered subdomain to its IP address
        4. Store results in database for later analysis

        Args:
            domain: Target domain to discover subdomains for (e.g., 'example.com')
            timeout: Maximum time to spend on discovery in seconds (default: 300)

        Returns:
            JSON string with discovery results including subdomains and their IP addresses

        Examples:
        - Discover subdomains: domain='example.com'
        - Quick discovery: domain='google.com', timeout=120
        """
        try:
            # Run the blocking domain discovery function in a thread pool (like nuclei scanner)
            result = await asyncio.to_thread(
                discover_subdomains,
                domain,
                timeout
            )

            # Create a concise response for agents
            if result and result.get("success"):
                # Get resolved subdomains
                subdomains = result.get("subdomains", [])
                resolved_subdomains = [s for s in subdomains if s.get("resolved")]

                # Create summary
                summary = {
                    "success": True,
                    "scan_id": result.get("scan_id"),
                    "domain": domain,
                    "domain_ip": result.get("domain_ip"),
                    "total_subdomains_found": result.get("total_subdomains", 0),
                    "subdomains_resolved": result.get("resolved_subdomains", 0),
                    "duration_seconds": result.get("duration_seconds", 0),
                    "message": f"✅ Found {result.get('resolved_subdomains', 0)} resolved subdomains out of {result.get('total_subdomains', 0)} discovered for {domain}"
                }

                # Add top 10 resolved subdomains for display
                if resolved_subdomains:
                    summary["top_resolved_subdomains"] = [
                        f"{sub['subdomain']} -> {sub['ip_address']}"
                        for sub in resolved_subdomains[:10]
                    ]

                    if len(resolved_subdomains) > 10:
                        summary["additional_subdomains"] = len(resolved_subdomains) - 10
                        summary["note"] = f"Showing top 10 of {len(resolved_subdomains)} resolved subdomains. Full results saved to database."

                return json.dumps(summary, indent=2)
            else:
                return json.dumps({
                    "success": False,
                    "domain": domain,
                    "error": "Domain discovery failed or returned no results",
                    "message": f"❌ Domain discovery failed for {domain}"
                })

        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "domain": domain,
                "message": f"❌ Domain discovery failed for {domain}: {str(e)}"
            })


if __name__ == "__main__":
    # Test the domain discovery functionality

    result = discover_subdomains('gofyeo.com')
    print(json.dumps(result, indent=2))
