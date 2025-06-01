import json
import socket
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, DuplicateKeyError
from pymongo.results import InsertOneResult

# Database setup
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "red_team_scans"

# Global MongoDB client
_mongo_client = None
_database = None

def get_database():
    """Get MongoDB database connection with improved connection management."""
    global _mongo_client, _database
    if _mongo_client is None:
        print(f"🔌 Connecting to MongoDB at {MONGO_URI}")
        # Configure MongoDB client with better connection pooling and timeouts
        _mongo_client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=5000,  # 5 second timeout
            connectTimeoutMS=10000,  # 10 second connection timeout
            socketTimeoutMS=30000,  # 30 second socket timeout
            maxPoolSize=50,  # Increase pool size for concurrent operations
            minPoolSize=5,   # Maintain minimum connections
            maxIdleTimeMS=30000,  # Close idle connections after 30 seconds
            waitQueueTimeoutMS=5000,  # Wait max 5 seconds for connection from pool
            document_class=dict,  # Use regular dict instead of SON
            tz_aware=False,  # Disable timezone awareness to avoid serialization issues
            connect=False,  # Don't connect immediately to avoid early serialization issues
            retryWrites=True,  # Enable retry for write operations
            retryReads=True,   # Enable retry for read operations
        )
        _database = _mongo_client[DB_NAME]
        # Test the connection
        try:
            _mongo_client.admin.command('ping')
            print(f"✅ MongoDB connection successful with connection pooling")
        except Exception as e:
            print(f"❌ MongoDB connection failed: {e}")
            raise
    return _database

def close_database():
    """Close MongoDB database connection and cleanup resources."""
    global _mongo_client, _database
    if _mongo_client is not None:
        try:
            _mongo_client.close()
            print("✅ MongoDB connection closed")
        except Exception as e:
            print(f"⚠️  Warning during MongoDB cleanup: {e}")
        finally:
            _mongo_client = None
            _database = None


def init_database():
    """Initialize MongoDB database for scan history."""
    try:
        db = get_database()

        # Create collections (they are created automatically when first document is inserted)
        # But we can create indexes for better performance

        # Create indexes for scans collection
        db.scans.create_index("scan_id", unique=True)
        db.scans.create_index("status")
        db.scans.create_index("start_time")
        db.scans.create_index("scan_type")

        # Create indexes for unified findings collection
        db.findings.create_index("scan_id")
        db.findings.create_index("agent")
        db.findings.create_index("hostname")
        db.findings.create_index("ip_address")
        db.findings.create_index("port")
        db.findings.create_index("service")
        db.findings.create_index("severity")  # For vulnerability findings
        db.findings.create_index("template_id")  # For vulnerability findings
        db.findings.create_index("timestamp")
        db.findings.create_index([("agent", ASCENDING), ("hostname", ASCENDING)])
        db.findings.create_index([("agent", ASCENDING), ("ip_address", ASCENDING)])
        db.findings.create_index([("agent", ASCENDING), ("port", ASCENDING)])
        db.findings.create_index([("hostname", ASCENDING), ("port", ASCENDING)])
        db.findings.create_index([("ip_address", ASCENDING), ("port", ASCENDING)])
        db.findings.create_index([("agent", ASCENDING), ("severity", ASCENDING)])

        # Create indexes for exploits collection
        db.exploits.create_index("name", unique=True)
        db.exploits.create_index("platform")
        db.exploits.create_index("rank")
        db.exploits.create_index("disclosure_date")
        db.exploits.create_index("author")
        db.exploits.create_index("cve_references")
        db.exploits.create_index("compatible_payloads")
        db.exploits.create_index([("platform", ASCENDING), ("rank", ASCENDING)])
        db.exploits.create_index([("name", "text"), ("description", "text")])  # Text search index

        print("MongoDB database initialized successfully")

    except Exception as e:
        print(f"Failed to initialize MongoDB database: {e}")
        raise

def save_scan_results(scan_id: str, target: str, ports: str, scan_type: str,
                     start_time: datetime, end_time: datetime, hosts: list[dict]) -> tuple[int, int]:
    """Save scan results to database with hostname resolution and return (total_hosts, total_open_ports)."""
    duration = (end_time - start_time).total_seconds()

    # Calculate stats
    total_hosts = len(hosts)
    total_open_ports = sum(
        len([p for p in host["ports"] if p["state"] == "open"])
        for host in hosts
    )

    # Update database with results
    db = get_database()

    # Update scan record
    db.scans.update_one(
        {"scan_id": scan_id},
        {
            "$set": {
                "status": "completed",
                "end_time": end_time,
                "duration_seconds": duration,
                "total_hosts": total_hosts,
                "total_open_ports": total_open_ports,
                "results_json": hosts
            }
        }
    )

    # Insert individual port entries with hostname resolution
    finding_docs = []
    for host in hosts:
        ip_address = host["ip"]

        # Resolve hostname for this IP with timeout
        hostname = None
        try:
            # Use a shorter timeout for reverse DNS to avoid blocking
            import signal

            def timeout_handler(signum, frame):
                raise socket.timeout("DNS timeout")

            # Set a 3-second timeout for reverse DNS
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(3)
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)

        except (socket.herror, socket.gaierror, socket.timeout):
            # If reverse DNS fails, try to extract hostname from target if it was a hostname
            if not target.replace('.', '').replace('/', '').replace('-', '').isdigit():
                # Target might be a hostname or CIDR, check if it resolves to this IP
                try:
                    # Also use timeout for forward DNS
                    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                    signal.alarm(3)
                    try:
                        resolved_ip = socket.gethostbyname(target.split('/')[0])
                        if resolved_ip == ip_address:
                            hostname = target.split('/')[0]
                    finally:
                        signal.alarm(0)
                        signal.signal(signal.SIGALRM, old_handler)
                except:
                    pass

        # Create one entry per port
        for port in host["ports"]:
            finding_docs.append({
                "scan_id": scan_id,
                "agent": "port-scan",
                "hostname": hostname,
                "ip_address": ip_address,
                "port": port["port"],
                "protocol": port["protocol"],
                "state": port["state"],
                "service": port.get("service", ""),
                "version": port.get("version", ""),
                "banner": port.get("banner", ""),
                "timestamp": datetime.now()
            })

    # Insert all findings in batch
    if finding_docs:
        db.findings.insert_many(finding_docs)

    return total_hosts, total_open_ports

def create_scan_record(scan_id: str, target: str, ports: str, scan_type: str, start_time: datetime) -> None:
    """Create initial scan record in database."""
    db = get_database()

    scan_doc = {
        "scan_id": scan_id,
        "target": target,
        "ports": ports,
        "scan_type": scan_type,
        "status": "running",
        "start_time": start_time,
        "end_time": None,
        "duration_seconds": None,
        "total_hosts": 0,
        "total_open_ports": 0,
        "results_json": None,
        "error_message": None,
        "created_at": datetime.now()
    }

    db.scans.insert_one(scan_doc)

def save_vulnerability_results(scan_id: str, vulnerabilities: list[dict]) -> None:
    """Save vulnerability scan results to database."""
    db = get_database()

    vuln_docs = []
    for vuln in vulnerabilities:
        vuln_doc = {
            "scan_id": scan_id,
            "agent": "vuln-scan",
            "hostname": vuln.get("hostname"),
            "ip_address": vuln.get("ip_address"),
            "port": vuln.get("port"),
            "protocol": vuln.get("protocol"),
            "template_id": vuln.get("template_id"),
            "template_name": vuln.get("template_name"),
            "severity": vuln.get("severity"),
            "url": vuln.get("url"),
            "matched_at": vuln.get("matched_at"),
            "extracted_results": vuln.get("extracted_results"),
            "description": vuln.get("description"),
            "reference": vuln.get("reference"),
            "timestamp": datetime.now()
        }
        vuln_docs.append(vuln_doc)

    if vuln_docs:
        db.findings.insert_many(vuln_docs)

def save_scan_result_entry(scan_id: str, hostname: str, ip_address: str, port: int,
                          protocol: str, state: str, service: str, version: str, banner: str, agent: str = "port-scan") -> InsertOneResult:
    """Save a single scan result entry to database."""
    db = get_database()

    scan_result_doc = {
        "scan_id": scan_id,
        "agent": agent,
        "hostname": hostname,
        "ip_address": ip_address,
        "port": port,
        "protocol": protocol,
        "state": state,
        "service": service,
        "version": version,
        "banner": banner,
        "timestamp": datetime.now()
    }

    return db.findings.insert_one(scan_result_doc)


def save_incremental_scan_result(scan_id: str, host_entry: dict) -> None:
    """Save incremental scan results for a single host as they are discovered."""
    try:
        import socket

        ip_address = host_entry["ip"]

        # Try to resolve hostname
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror):
            hostname = ip_address

        # Save each port as a separate finding
        for port in host_entry["ports"]:
            save_scan_result_entry(
                scan_id=scan_id,
                hostname=hostname,
                ip_address=ip_address,
                port=port["port"],
                protocol=port["protocol"],
                state=port["state"],
                service=port.get("service", ""),
                version=port.get("version", ""),
                banner=port.get("banner", ""),
                agent="port-scan"
            )
    except Exception as e:
        print(f"Warning: Failed to save incremental scan result: {e}")

def update_scan_status(scan_id: str, status: str, end_time: datetime, duration: float,
                      total_hosts: int, total_open_ports: int, results_json: str, error_message: str = None) -> None:
    """Update scan status in database."""
    db = get_database()

    update_doc = {
        "status": status,
        "end_time": end_time,
        "duration_seconds": duration,
        "total_hosts": total_hosts,
        "total_open_ports": total_open_ports,
        "results_json": results_json
    }

    if error_message is not None:
        update_doc["error_message"] = error_message

    db.scans.update_one(
        {"scan_id": scan_id},
        {"$set": update_doc}
    )

def create_ssh_result_entry(scan_id: str, host: str, port: int, username: str,
                           password: str, command: str, success: bool, output: str) -> None:
    """Save SSH command execution result to database."""
    db = get_database()

    # Create a JSON object to store in the banner field
    result_data = {
        "command": command,
        "success": success,
        "output": output,
        "username": username,
        "password": password
    }

    # Store as a special service type
    ssh_result_doc = {
        "scan_id": scan_id,
        "agent": "ssh-agent",
        "hostname": host,  # Use as both hostname and IP since we don't know which it is
        "ip_address": host,
        "port": port,
        "protocol": "tcp",
        "state": "open" if success else "filtered",
        "service": "ssh-command",
        "version": f"SSH Command Execution ({username})",
        "banner": result_data,  # Store as dict instead of JSON string
        "timestamp": datetime.now()
    }

    db.findings.insert_one(ssh_result_doc)

def get_finished_scan_results(limit: int = 10, scan_id: Optional[str] = None) -> dict:
    """Get all finished scan results from database."""
    try:
        db = get_database()

        if scan_id:
            # Get specific scan
            scans_cursor = db.scans.find({"scan_id": scan_id})
        else:
            # Get recent scans
            scans_cursor = db.scans.find({"status": "completed"}).sort("start_time", DESCENDING).limit(limit)

        scans = []
        for scan_doc in scans_cursor:
            scan_data = {
                "scan_id": scan_doc.get("scan_id"),
                "target": scan_doc.get("target"),
                "ports": scan_doc.get("ports"),
                "scan_type": scan_doc.get("scan_type"),
                "status": scan_doc.get("status"),
                "start_time": scan_doc.get("start_time").isoformat() if scan_doc.get("start_time") else None,
                "end_time": scan_doc.get("end_time").isoformat() if scan_doc.get("end_time") else None,
                "duration_seconds": scan_doc.get("duration_seconds"),
                "total_hosts": scan_doc.get("total_hosts", 0),
                "total_open_ports": scan_doc.get("total_open_ports", 0),
                "hosts": scan_doc.get("results_json", [])
            }
            scans.append(scan_data)

        # Get summary stats using aggregation
        stats_pipeline = [
            {"$match": {"status": "completed"}},
            {"$group": {
                "_id": None,
                "total_scans": {"$sum": 1},
                "total_hosts_scanned": {"$sum": "$total_hosts"},
                "total_open_ports_found": {"$sum": "$total_open_ports"}
            }}
        ]

        stats_result = list(db.scans.aggregate(stats_pipeline))
        stats = stats_result[0] if stats_result else {
            "total_scans": 0,
            "total_hosts_scanned": 0,
            "total_open_ports_found": 0
        }

        return {
            "success": True,
            "scans": scans,
            "total_scans_returned": len(scans),
            "database_stats": {
                "total_completed_scans": stats.get("total_scans", 0),
                "total_hosts_scanned": stats.get("total_hosts_scanned", 0),
                "total_open_ports_found": stats.get("total_open_ports_found", 0)
            },
            "message": f"Retrieved {len(scans)} scan results"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "Failed to retrieve scan results"
        }

def search_findings(hostname: Optional[str] = None, ip_address: Optional[str] = None,
                   port: Optional[int] = None, service: Optional[str] = None,
                   agent: Optional[str] = None, severity: Optional[str] = None,
                   template_id: Optional[str] = None, limit: int = 20) -> dict:
    """
    Search findings by hostname, IP address, port, service, agent, severity, or template ID.

    This allows flexible searching across all findings to find:
    - All ports open on a specific host (agent='port-scan')
    - All vulnerabilities on a specific host (agent='vuln-scan')
    - All hosts running a specific service
    - All instances of a specific port across hosts
    - All critical/high severity vulnerabilities
    - All SSH findings (agent='ssh-agent')
    """
    try:
        print(f"🔍 Searching findings with params: hostname={hostname}, ip={ip_address}, port={port}, service={service}, agent={agent}, limit={limit}")
        db = get_database()

        # Build dynamic query based on provided parameters
        query_filter = {}

        if hostname:
            query_filter["hostname"] = {"$regex": hostname, "$options": "i"}

        if ip_address:
            query_filter["ip_address"] = {"$regex": ip_address, "$options": "i"}

        if port:
            query_filter["port"] = port

        if service:
            query_filter["service"] = {"$regex": service, "$options": "i"}

        if agent:
            query_filter["agent"] = agent

        if severity:
            query_filter["severity"] = severity

        if template_id:
            query_filter["template_id"] = {"$regex": template_id, "$options": "i"}

        # If no conditions, return error
        if not query_filter:
            return {
                "success": False,
                "error": "No search parameters provided",
                "message": "Please provide at least one search parameter"
            }

        print(f"📋 Query filter: {query_filter}")
        print(f"🔍 Executing database query...")

        # Define severity order for sorting (vulnerabilities first by severity, then by timestamp)
        pipeline = [
            {"$match": query_filter},
            {"$lookup": {
                "from": "scans",
                "localField": "scan_id",
                "foreignField": "scan_id",
                "as": "scan_info"
            }},
            {"$unwind": "$scan_info"},
            {"$addFields": {
                "severity_order": {
                    "$switch": {
                        "branches": [
                            {"case": {"$eq": ["$severity", "critical"]}, "then": 1},
                            {"case": {"$eq": ["$severity", "high"]}, "then": 2},
                            {"case": {"$eq": ["$severity", "medium"]}, "then": 3},
                            {"case": {"$eq": ["$severity", "low"]}, "then": 4},
                            {"case": {"$eq": ["$severity", "info"]}, "then": 5}
                        ],
                        "default": 6
                    }
                }
            }},
            {"$sort": {"severity_order": 1, "timestamp": -1}},
            {"$limit": limit},
            {"$project": {
                "scan_id": 1,
                "target": "$scan_info.target",
                "agent": 1,
                "hostname": 1,
                "ip_address": 1,
                "port": 1,
                "protocol": 1,
                "state": 1,
                "service": 1,
                "version": 1,
                "banner": 1,
                "template_id": 1,
                "template_name": 1,
                "severity": 1,
                "url": 1,
                "matched_at": 1,
                "extracted_results": 1,
                "description": 1,
                "reference": 1,
                "scan_time": "$scan_info.start_time",
                "timestamp": 1
            }}
        ]

        results_cursor = db.findings.aggregate(pipeline)
        print(f"✅ Database query executed, processing results...")

        # Format results
        results = []
        for result_doc in results_cursor:
            result = {
                "scan_id": result_doc.get("scan_id"),
                "target": result_doc.get("target"),
                "agent": result_doc.get("agent"),
                "hostname": result_doc.get("hostname"),
                "ip_address": result_doc.get("ip_address"),
                "port": result_doc.get("port"),
                "protocol": result_doc.get("protocol"),
                "state": result_doc.get("state"),
                "service": result_doc.get("service"),
                "version": result_doc.get("version"),
                "banner": result_doc.get("banner"),
                "template_id": result_doc.get("template_id"),
                "template_name": result_doc.get("template_name"),
                "severity": result_doc.get("severity"),
                "url": result_doc.get("url"),
                "matched_at": result_doc.get("matched_at"),
                "extracted_results": result_doc.get("extracted_results"),
                "description": result_doc.get("description"),
                "reference": result_doc.get("reference"),
                "scan_time": result_doc.get("scan_time").isoformat() if result_doc.get("scan_time") else None,
                "timestamp": result_doc.get("timestamp").isoformat() if result_doc.get("timestamp") else None
            }
            results.append(result)

        print(f"📊 Found {len(results)} results, returning response")
        return {
            "success": True,
            "results": results,
            "total_results": len(results),
            "search_params": {
                "hostname": hostname,
                "ip_address": ip_address,
                "port": port,
                "service": service,
                "agent": agent,
                "severity": severity,
                "template_id": template_id
            },
            "message": f"Found {len(results)} matching findings"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "Failed to search findings"
        }

def search_scan_results(hostname: Optional[str] = None, ip_address: Optional[str] = None,
                       port: Optional[int] = None, service: Optional[str] = None,
                       limit: int = 20) -> dict:
    """
    Backward compatibility function for searching port scan results.
    """
    return search_findings(hostname=hostname, ip_address=ip_address, port=port,
                          service=service, agent="port-scan", limit=limit)

def search_vulnerability_results(hostname: Optional[str] = None, ip_address: Optional[str] = None,
                               port: Optional[int] = None, severity: Optional[str] = None,
                               template_id: Optional[str] = None, limit: int = 20) -> dict:
    """
    Backward compatibility function for searching vulnerability results.
    """
    return search_findings(hostname=hostname, ip_address=ip_address, port=port,
                          severity=severity, template_id=template_id, agent="vuln-scan", limit=limit)


# Exploit database functions

def save_exploit_to_database(exploit_data: dict) -> bool:
    """Save a single exploit to the exploits collection."""
    try:
        db = get_database()

        # Use upsert to avoid duplicates
        db.exploits.update_one(
            {"name": exploit_data["name"]},
            {"$set": exploit_data},
            upsert=True
        )
        return True
    except Exception as e:
        print(f"Failed to save exploit {exploit_data.get('name', 'unknown')}: {e}")
        return False


def clear_exploits_database() -> bool:
    """Clear all exploits from the database."""
    try:
        db = get_database()
        result = db.exploits.delete_many({})
        print(f"Cleared {result.deleted_count} exploits from database")
        return True
    except Exception as e:
        print(f"Failed to clear exploits database: {e}")
        return False


def get_exploits_count() -> int:
    """Get the total number of exploits in the database."""
    try:
        db = get_database()
        return db.exploits.count_documents({})
    except Exception as e:
        print(f"Failed to get exploits count: {e}")
        return 0


def search_exploits_database(
    platform: Optional[str] = None,
    search_term: Optional[str] = None,
    cve: Optional[str] = None,
    rank: Optional[str] = None,
    author: Optional[str] = None,
    limit: int = 50
) -> dict:
    """
    Search the cached exploits database for fast results.

    Args:
        platform: Filter by platform (e.g., 'windows', 'linux', 'unix')
        search_term: Search in name and description
        cve: Search for specific CVE reference
        rank: Filter by exploit rank (e.g., 'excellent', 'great', 'good')
        author: Filter by author name
        limit: Maximum number of results to return

    Returns:
        Dictionary with search results
    """
    try:
        db = get_database()

        # Build query filter
        query_filter = {}

        if platform:
            query_filter["platform"] = {"$regex": platform, "$options": "i"}

        if search_term:
            query_filter["$or"] = [
                {"name": {"$regex": search_term, "$options": "i"}},
                {"description": {"$regex": search_term, "$options": "i"}}
            ]

        if cve:
            query_filter["cve_references"] = {"$regex": cve.upper(), "$options": "i"}

        if rank:
            query_filter["rank"] = {"$regex": rank, "$options": "i"}

        if author:
            query_filter["author"] = {"$regex": author, "$options": "i"}

        # Execute query with sorting by rank and disclosure date
        rank_order = {
            "excellent": 1,
            "great": 2,
            "good": 3,
            "normal": 4,
            "average": 5,
            "low": 6,
            "manual": 7
        }

        pipeline = [
            {"$match": query_filter},
            {"$addFields": {
                "rank_order": {
                    "$switch": {
                        "branches": [
                            {"case": {"$eq": ["$rank", "excellent"]}, "then": 1},
                            {"case": {"$eq": ["$rank", "great"]}, "then": 2},
                            {"case": {"$eq": ["$rank", "good"]}, "then": 3},
                            {"case": {"$eq": ["$rank", "normal"]}, "then": 4},
                            {"case": {"$eq": ["$rank", "average"]}, "then": 5},
                            {"case": {"$eq": ["$rank", "low"]}, "then": 6},
                            {"case": {"$eq": ["$rank", "manual"]}, "then": 7}
                        ],
                        "default": 8
                    }
                }
            }},
            {"$sort": {"rank_order": 1, "disclosure_date": -1}},
            {"$limit": limit},
            {"$project": {"rank_order": 0}}  # Remove the temporary field
        ]

        results_cursor = db.exploits.aggregate(pipeline)
        exploits_raw = list(results_cursor)

        # Convert ObjectIds and datetime objects to strings to avoid JSON serialization errors
        exploits = []
        for exploit in exploits_raw:
            # Convert ObjectId to string
            if '_id' in exploit:
                exploit['_id'] = str(exploit['_id'])
            # Convert datetime objects to ISO strings
            if 'disclosure_date' in exploit and exploit['disclosure_date']:
                if hasattr(exploit['disclosure_date'], 'isoformat'):
                    exploit['disclosure_date'] = exploit['disclosure_date'].isoformat()
            if 'created_at' in exploit and exploit['created_at']:
                if hasattr(exploit['created_at'], 'isoformat'):
                    exploit['created_at'] = exploit['created_at'].isoformat()
            if 'updated_at' in exploit and exploit['updated_at']:
                if hasattr(exploit['updated_at'], 'isoformat'):
                    exploit['updated_at'] = exploit['updated_at'].isoformat()
            exploits.append(exploit)

        return {
            "success": True,
            "total_found": len(exploits),
            "exploits": exploits,
            "filters_applied": {
                "platform": platform or "none",
                "search_term": search_term or "none",
                "cve": cve or "none",
                "rank": rank or "none",
                "author": author or "none",
                "limit": limit
            },
            "message": f"Found {len(exploits)} exploits matching criteria"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "Failed to search exploits database"
        }