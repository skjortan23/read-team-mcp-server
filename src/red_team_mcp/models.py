"""Data models for Red Team MCP Server."""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union

from pydantic import BaseModel, Field, validator


class ScanStatus(str, Enum):
    """Status of a scan operation."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PortState(str, Enum):
    """State of a scanned port."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class ScanTarget(BaseModel):
    """Target specification for scanning."""
    
    ip_range: str = Field(..., description="IP range to scan (e.g., '192.168.1.0/24')")
    ports: Union[str, List[int]] = Field(
        default="1-1000",
        description="Ports to scan (e.g., '80,443' or [80, 443] or '1-1000')"
    )
    
    @validator('ip_range')
    def validate_ip_range(cls, v):
        import ipaddress
        try:
            # Try to parse as network
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            try:
                # Try to parse as single IP
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(f"Invalid IP range or address: {v}")
        return v
    
    @validator('ports')
    def validate_ports(cls, v):
        if isinstance(v, str):
            # Validate port range string format
            if '-' in v:
                try:
                    start, end = map(int, v.split('-'))
                    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                        raise ValueError("Invalid port range")
                except ValueError:
                    raise ValueError("Invalid port range format")
            elif ',' in v:
                try:
                    ports = [int(p.strip()) for p in v.split(',')]
                    for port in ports:
                        if not (1 <= port <= 65535):
                            raise ValueError(f"Invalid port number: {port}")
                except ValueError:
                    raise ValueError("Invalid port list format")
            else:
                try:
                    port = int(v)
                    if not (1 <= port <= 65535):
                        raise ValueError(f"Invalid port number: {port}")
                except ValueError:
                    raise ValueError("Invalid port format")
        elif isinstance(v, list):
            for port in v:
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    raise ValueError(f"Invalid port number: {port}")
        return v


class PortResult(BaseModel):
    """Result of scanning a single port."""
    
    port: int = Field(..., description="Port number")
    protocol: str = Field(default="tcp", description="Protocol (tcp/udp)")
    state: PortState = Field(..., description="Port state")
    service: Optional[str] = Field(None, description="Detected service name")
    banner: Optional[str] = Field(None, description="Service banner")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HostResult(BaseModel):
    """Result of scanning a single host."""
    
    ip: str = Field(..., description="IP address")
    hostname: Optional[str] = Field(None, description="Resolved hostname")
    ports: List[PortResult] = Field(default_factory=list, description="Port scan results")
    os_info: Optional[str] = Field(None, description="OS detection info")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ScanRequest(BaseModel):
    """Request to perform a scan."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    target: ScanTarget = Field(..., description="Target specification")
    scan_type: str = Field(default="tcp_syn", description="Type of scan to perform")
    rate: Optional[int] = Field(None, description="Scan rate (packets per second)")
    timeout: Optional[int] = Field(None, description="Scan timeout in seconds")
    options: Dict[str, Union[str, int, bool]] = Field(
        default_factory=dict,
        description="Additional scan options"
    )
    
    @validator('scan_type')
    def validate_scan_type(cls, v):
        valid_types = ['tcp_syn', 'tcp_connect', 'udp', 'tcp_ack', 'tcp_window']
        if v not in valid_types:
            raise ValueError(f"scan_type must be one of {valid_types}")
        return v


class ScanResult(BaseModel):
    """Complete result of a scan operation."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    request: ScanRequest = Field(..., description="Original scan request")
    status: ScanStatus = Field(..., description="Scan status")
    hosts: List[HostResult] = Field(default_factory=list, description="Host results")
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = Field(None, description="Scan completion time")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    stats: Dict[str, Union[int, float]] = Field(
        default_factory=dict,
        description="Scan statistics"
    )
    
    @property
    def duration(self) -> Optional[float]:
        """Calculate scan duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    @property
    def total_hosts(self) -> int:
        """Total number of hosts scanned."""
        return len(self.hosts)
    
    @property
    def total_open_ports(self) -> int:
        """Total number of open ports found."""
        return sum(
            len([p for p in host.ports if p.state == PortState.OPEN])
            for host in self.hosts
        )


class MCPToolRequest(BaseModel):
    """Base class for MCP tool requests."""
    
    tool_name: str = Field(..., description="Name of the tool being called")
    arguments: Dict[str, Union[str, int, bool, List, Dict]] = Field(
        default_factory=dict,
        description="Tool arguments"
    )


class MCPToolResponse(BaseModel):
    """Base class for MCP tool responses."""
    
    success: bool = Field(..., description="Whether the tool call succeeded")
    result: Optional[Union[str, Dict, List]] = Field(None, description="Tool result")
    error: Optional[str] = Field(None, description="Error message if failed")
    metadata: Dict[str, Union[str, int, bool]] = Field(
        default_factory=dict,
        description="Additional metadata"
    )
