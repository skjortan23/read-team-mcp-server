"""Scanner component for masscan integration."""

import asyncio
import json
import logging
import shlex
import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .config import RedTeamMCPConfig
from .models import (
    HostResult,
    PortResult,
    PortState,
    ScanRequest,
    ScanResult,
    ScanStatus,
    ScanTarget,
)

logger = logging.getLogger(__name__)


class MasscanError(Exception):
    """Exception raised when masscan operations fail."""
    pass


class Scanner:
    """Scanner component that integrates with masscan."""

    def __init__(self, config: RedTeamMCPConfig):
        self.config = config
        self.active_scans: Dict[str, asyncio.Task] = {}
        self.scan_results: Dict[str, ScanResult] = {}

    async def validate_masscan(self) -> bool:
        """Validate that masscan is available and working."""
        try:
            # Build command with or without sudo
            if self.config.scanner.use_sudo:
                cmd = ["sudo", self.config.scanner.masscan_path, "--version"]
            else:
                cmd = [self.config.scanner.masscan_path, "--version"]

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()

            # Masscan returns exit code 1 for --version, but still outputs version info
            version_output = stdout.decode().strip() or stderr.decode().strip()

            if "Masscan version" not in version_output:
                logger.error(f"Masscan validation failed: unexpected output: {version_output}")
                if self.config.scanner.use_sudo and "sudo" in version_output:
                    logger.error("Hint: Check sudo permissions for masscan")
                return False

            logger.info(f"Masscan validation successful: {version_output.split()[2] if len(version_output.split()) > 2 else 'unknown version'}")

            # Additional validation: check if we can run a basic scan command
            if self.config.scanner.use_sudo:
                logger.info("Checking sudo permissions for masscan...")
                test_result = await asyncio.create_subprocess_exec(
                    "sudo", "-n", self.config.scanner.masscan_path, "--help",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await test_result.communicate()
                if test_result.returncode != 0:
                    logger.warning("Sudo access to masscan may require password. Consider setting up NOPASSWD sudo for masscan.")

            return True

        except FileNotFoundError:
            logger.error(f"Masscan not found at: {self.config.scanner.masscan_path}")
            return False
        except Exception as e:
            logger.error(f"Masscan validation error: {e}")
            return False

    def _validate_target(self, target: ScanTarget) -> None:
        """Validate scan target against security policies."""
        import ipaddress

        # Parse target network
        try:
            network = ipaddress.ip_network(target.ip_range, strict=False)
        except ValueError:
            try:
                # Single IP
                ip = ipaddress.ip_address(target.ip_range)
                network = ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}")
            except ValueError:
                raise ValueError(f"Invalid IP range: {target.ip_range}")

        # Check against blocked networks
        for blocked in self.config.scanner.blocked_networks:
            blocked_network = ipaddress.ip_network(blocked)
            if network.overlaps(blocked_network):
                raise ValueError(f"Target {target.ip_range} overlaps with blocked network {blocked}")

        # Validate number of targets
        if network.num_addresses > self.config.scanner.max_targets:
            raise ValueError(
                f"Target range too large: {network.num_addresses} addresses "
                f"(max: {self.config.scanner.max_targets})"
            )

    def _build_masscan_command(self, request: ScanRequest, output_file: Path) -> List[str]:
        """Build masscan command from scan request."""
        # Check if we need sudo for masscan
        use_sudo = self.config.scanner.use_sudo if hasattr(self.config.scanner, 'use_sudo') else True

        if use_sudo:
            cmd = [
                "sudo",
                self.config.scanner.masscan_path,
                request.target.ip_range,
            ]
        else:
            cmd = [
                self.config.scanner.masscan_path,
                request.target.ip_range,
            ]

        # Add ports
        if isinstance(request.target.ports, str):
            cmd.extend(["-p", request.target.ports])
        elif isinstance(request.target.ports, list):
            port_str = ",".join(map(str, request.target.ports))
            cmd.extend(["-p", port_str])

        # Add rate limiting
        rate = request.rate or self.config.scanner.max_rate
        rate = min(rate, self.config.scanner.max_rate)  # Enforce max rate
        cmd.extend(["--rate", str(rate)])

        # Add output format
        cmd.extend(["-oJ", str(output_file)])

        # Add scan type options (masscan defaults to SYN scan, so we only need to specify others)
        if request.scan_type == "tcp_connect":
            cmd.append("--tcp-connect")
        elif request.scan_type == "udp":
            cmd.append("--udp")
        elif request.scan_type == "tcp_ack":
            cmd.append("--tcp-ack")
        elif request.scan_type == "tcp_window":
            cmd.append("--tcp-window")
        # tcp_syn is the default, so no flag needed

        # Add timeout (masscan uses --wait for connection timeout, not scan timeout)
        # For scan timeout, we'll handle it at the process level

        # Add additional options
        for key, value in request.options.items():
            if key.startswith("--"):
                cmd.append(key)
                if value is not True:  # Don't add value for boolean flags
                    cmd.append(str(value))

        return cmd

    def _parse_masscan_output(self, output_file: Path) -> List[HostResult]:
        """Parse masscan JSON output into HostResult objects."""
        hosts: Dict[str, HostResult] = {}

        if not output_file.exists():
            logger.warning(f"Masscan output file not found: {output_file}")
            return []

        try:
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    try:
                        data = json.loads(line)
                        ip = data.get('ip')
                        port_data = data.get('ports', [])

                        if not ip:
                            continue

                        # Get or create host result
                        if ip not in hosts:
                            hosts[ip] = HostResult(ip=ip)

                        # Add port results
                        for port_info in port_data:
                            port = port_info.get('port')
                            protocol = port_info.get('proto', 'tcp')
                            state = port_info.get('status', 'open')

                            if port:
                                port_result = PortResult(
                                    port=port,
                                    protocol=protocol,
                                    state=PortState.OPEN if state == 'open' else PortState.CLOSED,
                                    timestamp=datetime.utcnow()
                                )
                                hosts[ip].ports.append(port_result)

                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse masscan output line: {line} - {e}")
                        continue

        except Exception as e:
            logger.error(f"Error parsing masscan output: {e}")
            return []

        return list(hosts.values())

    async def _run_scan(self, request: ScanRequest) -> ScanResult:
        """Execute a single scan operation."""
        scan_result = ScanResult(
            scan_id=request.scan_id,
            request=request,
            status=ScanStatus.RUNNING,
            start_time=datetime.utcnow()
        )

        try:
            # Validate target
            self._validate_target(request.target)

            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = Path(f.name)

            try:
                # Build and execute masscan command
                cmd = self._build_masscan_command(request, output_file)
                logger.info(f"Executing masscan: {' '.join(shlex.quote(arg) for arg in cmd)}")

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                # Apply timeout at process level
                timeout = request.timeout or self.config.scanner.timeout
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=timeout
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    raise MasscanError(f"Scan timed out after {timeout} seconds")

                if process.returncode != 0:
                    error_msg = stderr.decode().strip()
                    logger.error(f"Masscan failed: {error_msg}")
                    raise MasscanError(f"Masscan execution failed: {error_msg}")

                # Parse results
                hosts = self._parse_masscan_output(output_file)
                scan_result.hosts = hosts
                scan_result.status = ScanStatus.COMPLETED
                scan_result.end_time = datetime.utcnow()

                # Add statistics
                scan_result.stats = {
                    "total_hosts": len(hosts),
                    "total_ports": sum(len(host.ports) for host in hosts),
                    "open_ports": sum(
                        len([p for p in host.ports if p.state == PortState.OPEN])
                        for host in hosts
                    ),
                    "duration_seconds": scan_result.duration or 0,
                }

                logger.info(f"Scan {request.scan_id} completed successfully")

            finally:
                # Clean up temporary file
                try:
                    output_file.unlink()
                except Exception as e:
                    logger.warning(f"Failed to clean up temp file {output_file}: {e}")

        except Exception as e:
            scan_result.status = ScanStatus.FAILED
            scan_result.error_message = str(e)
            scan_result.end_time = datetime.utcnow()
            logger.error(f"Scan {request.scan_id} failed: {e}")

        return scan_result

    async def start_scan(self, target: ScanTarget, **kwargs) -> str:
        """Start a new scan operation."""
        scan_id = str(uuid.uuid4())

        request = ScanRequest(
            scan_id=scan_id,
            target=target,
            **kwargs
        )

        # Create scan task
        task = asyncio.create_task(self._run_scan(request))
        self.active_scans[scan_id] = task

        # Store initial result
        self.scan_results[scan_id] = ScanResult(
            scan_id=scan_id,
            request=request,
            status=ScanStatus.PENDING,
            start_time=datetime.utcnow()
        )

        logger.info(f"Started scan {scan_id} for target {target.ip_range}")
        return scan_id

    async def get_scan_status(self, scan_id: str) -> Optional[ScanResult]:
        """Get the status of a scan operation."""
        if scan_id in self.scan_results:
            # Check if scan is complete
            if scan_id in self.active_scans:
                task = self.active_scans[scan_id]
                if task.done():
                    try:
                        result = await task
                        self.scan_results[scan_id] = result
                        del self.active_scans[scan_id]
                    except Exception as e:
                        logger.error(f"Scan task {scan_id} failed: {e}")

            return self.scan_results[scan_id]

        return None

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan operation."""
        if scan_id in self.active_scans:
            task = self.active_scans[scan_id]
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            del self.active_scans[scan_id]

            # Update scan result
            if scan_id in self.scan_results:
                self.scan_results[scan_id].status = ScanStatus.CANCELLED
                self.scan_results[scan_id].end_time = datetime.utcnow()

            logger.info(f"Cancelled scan {scan_id}")
            return True

        return False

    def list_scans(self) -> List[str]:
        """List all scan IDs."""
        return list(self.scan_results.keys())

    async def cleanup_completed_scans(self, max_age_hours: int = 24) -> int:
        """Clean up old completed scan results."""
        cutoff_time = datetime.utcnow().timestamp() - (max_age_hours * 3600)
        removed_count = 0

        scan_ids_to_remove = []
        for scan_id, result in self.scan_results.items():
            if (result.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED] and
                result.start_time.timestamp() < cutoff_time):
                scan_ids_to_remove.append(scan_id)

        for scan_id in scan_ids_to_remove:
            del self.scan_results[scan_id]
            removed_count += 1

        logger.info(f"Cleaned up {removed_count} old scan results")
        return removed_count
