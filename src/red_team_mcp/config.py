"""Configuration management for Red Team MCP Server."""

import os
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field, validator


class ScannerConfig(BaseModel):
    """Configuration for the scanner component."""
    
    masscan_path: str = Field(default="masscan", description="Path to masscan binary")
    max_rate: int = Field(default=1000, description="Maximum scan rate (packets per second)")
    max_targets: int = Field(default=1000, description="Maximum number of targets per scan")
    allowed_ports: List[int] = Field(
        default_factory=lambda: list(range(1, 65536)),
        description="List of allowed ports to scan"
    )
    blocked_networks: List[str] = Field(
        default_factory=lambda: [
            "127.0.0.0/8",    # Localhost
            "10.0.0.0/8",     # Private networks
            "172.16.0.0/12",  # Private networks
            "192.168.0.0/16", # Private networks
            "169.254.0.0/16", # Link-local
            "224.0.0.0/4",    # Multicast
        ],
        description="Networks that are blocked from scanning"
    )
    timeout: int = Field(default=300, description="Scan timeout in seconds")
    
    @validator('max_rate')
    def validate_max_rate(cls, v):
        if v <= 0 or v > 100000:
            raise ValueError('max_rate must be between 1 and 100000')
        return v
    
    @validator('max_targets')
    def validate_max_targets(cls, v):
        if v <= 0 or v > 10000:
            raise ValueError('max_targets must be between 1 and 10000')
        return v


class SecurityConfig(BaseModel):
    """Security configuration for the MCP server."""
    
    enable_logging: bool = Field(default=True, description="Enable detailed logging")
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: Optional[str] = Field(default=None, description="Log file path")
    require_auth: bool = Field(default=False, description="Require authentication")
    auth_token: Optional[str] = Field(default=None, description="Authentication token")
    rate_limit_requests: int = Field(default=100, description="Rate limit per minute")
    
    @validator('log_level')
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'log_level must be one of {valid_levels}')
        return v.upper()


class RedTeamMCPConfig(BaseModel):
    """Main configuration for Red Team MCP Server."""
    
    server_name: str = Field(default="red-team-mcp", description="Server name")
    version: str = Field(default="0.1.0", description="Server version")
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    data_dir: Path = Field(
        default_factory=lambda: Path.home() / ".red-team-mcp",
        description="Data directory for storing results"
    )
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def from_env(cls) -> "RedTeamMCPConfig":
        """Load configuration from environment variables."""
        config_data = {}
        
        # Scanner config from env
        scanner_config = {}
        if masscan_path := os.getenv("REDTEAM_MASSCAN_PATH"):
            scanner_config["masscan_path"] = masscan_path
        if max_rate := os.getenv("REDTEAM_MAX_RATE"):
            scanner_config["max_rate"] = int(max_rate)
        if max_targets := os.getenv("REDTEAM_MAX_TARGETS"):
            scanner_config["max_targets"] = int(max_targets)
        if timeout := os.getenv("REDTEAM_TIMEOUT"):
            scanner_config["timeout"] = int(timeout)
        
        if scanner_config:
            config_data["scanner"] = scanner_config
        
        # Security config from env
        security_config = {}
        if log_level := os.getenv("REDTEAM_LOG_LEVEL"):
            security_config["log_level"] = log_level
        if log_file := os.getenv("REDTEAM_LOG_FILE"):
            security_config["log_file"] = log_file
        if auth_token := os.getenv("REDTEAM_AUTH_TOKEN"):
            security_config["auth_token"] = auth_token
            security_config["require_auth"] = True
        if rate_limit := os.getenv("REDTEAM_RATE_LIMIT"):
            security_config["rate_limit_requests"] = int(rate_limit)
        
        if security_config:
            config_data["security"] = security_config
        
        # Data directory from env
        if data_dir := os.getenv("REDTEAM_DATA_DIR"):
            config_data["data_dir"] = Path(data_dir)
        
        return cls(**config_data)
    
    @classmethod
    def from_file(cls, config_path: Path) -> "RedTeamMCPConfig":
        """Load configuration from a JSON file."""
        import json
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        return cls(**config_data)
    
    def save_to_file(self, config_path: Path) -> None:
        """Save configuration to a JSON file."""
        import json
        
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump(self.dict(), f, indent=2, default=str)
