"""Main entry point for Red Team MCP Server."""

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

import click

from .config import RedTeamMCPConfig
from .server import RedTeamMCPServer

logger = logging.getLogger(__name__)


@click.group()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Configuration file path"
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    default="INFO",
    help="Logging level"
)
@click.option(
    "--log-file",
    type=click.Path(path_type=Path),
    help="Log file path"
)
@click.pass_context
def cli(ctx: click.Context, config: Optional[Path], log_level: str, log_file: Optional[Path]) -> None:
    """Red Team MCP Server - An MCP server for red teaming operations."""

    # Load configuration
    if config:
        mcp_config = RedTeamMCPConfig.from_file(config)
    else:
        mcp_config = RedTeamMCPConfig.from_env()

    # Override log settings from CLI
    if log_level:
        mcp_config.security.log_level = log_level
    if log_file:
        mcp_config.security.log_file = str(log_file)

    ctx.ensure_object(dict)
    ctx.obj["config"] = mcp_config


@cli.command()
@click.option(
    "--transport",
    type=click.Choice(["stdio"]),
    default="stdio",
    help="Transport type for MCP communication"
)
@click.pass_context
def serve(ctx: click.Context, transport: str) -> None:
    """Start the MCP server."""
    config: RedTeamMCPConfig = ctx.obj["config"]

    async def run_server():
        server = RedTeamMCPServer(config)

        try:
            await server.run(transport)
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        except Exception as e:
            logger.error(f"Server run error: {e}")
            raise
        finally:
            await server.shutdown()

    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


@cli.command()
@click.pass_context
def validate(ctx: click.Context) -> None:
    """Validate the server configuration and dependencies."""
    config: RedTeamMCPConfig = ctx.obj["config"]

    async def run_validation():
        from .scanner import Scanner

        click.echo("Validating Red Team MCP Server configuration...")

        # Validate configuration
        click.echo(f"✓ Configuration loaded successfully")
        click.echo(f"  - Server name: {config.server_name}")
        click.echo(f"  - Version: {config.version}")
        click.echo(f"  - Data directory: {config.data_dir}")
        click.echo(f"  - Log level: {config.security.log_level}")

        # Validate masscan
        scanner = Scanner(config)
        click.echo(f"Validating masscan at: {config.scanner.masscan_path}")

        if await scanner.validate_masscan():
            click.echo("✓ Masscan validation successful")
        else:
            click.echo("✗ Masscan validation failed")
            click.echo("  Please ensure masscan is installed and accessible")
            sys.exit(1)

        # Validate permissions
        try:
            config.data_dir.mkdir(parents=True, exist_ok=True)
            test_file = config.data_dir / "test_write"
            test_file.write_text("test")
            test_file.unlink()
            click.echo("✓ Data directory is writable")
        except Exception as e:
            click.echo(f"✗ Data directory not writable: {e}")
            sys.exit(1)

        click.echo("✓ All validations passed")

    try:
        asyncio.run(run_validation())
    except Exception as e:
        click.echo(f"✗ Validation error: {e}")
        sys.exit(1)


@cli.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path for configuration"
)
@click.pass_context
def config_template(ctx: click.Context, output: Optional[Path]) -> None:
    """Generate a configuration template."""
    config: RedTeamMCPConfig = ctx.obj["config"]

    if output:
        config.save_to_file(output)
        click.echo(f"Configuration template saved to: {output}")
    else:
        import json
        click.echo(json.dumps(config.dict(), indent=2, default=str))


@cli.command()
@click.option(
    "--target",
    "-t",
    required=True,
    help="Target IP or CIDR range to scan"
)
@click.option(
    "--ports",
    "-p",
    default="1-1000",
    help="Ports to scan (e.g., '80,443' or '1-1000')"
)
@click.option(
    "--scan-type",
    type=click.Choice(["tcp_syn", "tcp_connect", "udp", "tcp_ack", "tcp_window"]),
    default="tcp_syn",
    help="Type of scan to perform"
)
@click.option(
    "--rate",
    type=int,
    help="Scan rate in packets per second"
)
@click.option(
    "--timeout",
    type=int,
    help="Scan timeout in seconds"
)
@click.option(
    "--wait",
    is_flag=True,
    help="Wait for scan to complete"
)
@click.pass_context
def scan(
    ctx: click.Context,
    target: str,
    ports: str,
    scan_type: str,
    rate: Optional[int],
    timeout: Optional[int],
    wait: bool
) -> None:
    """Perform a standalone port scan (for testing)."""
    config: RedTeamMCPConfig = ctx.obj["config"]

    async def run_scan():
        from .scanner import Scanner
        from .models import ScanTarget

        scanner = Scanner(config)

        # Validate masscan
        if not await scanner.validate_masscan():
            click.echo("✗ Masscan validation failed")
            sys.exit(1)

        # Create scan target
        scan_target = ScanTarget(ip_range=target, ports=ports)

        # Start scan
        scan_kwargs = {"scan_type": scan_type}
        if rate:
            scan_kwargs["rate"] = rate
        if timeout:
            scan_kwargs["timeout"] = timeout

        click.echo(f"Starting scan of {target} on ports {ports}")
        scan_id = await scanner.start_scan(scan_target, **scan_kwargs)
        click.echo(f"Scan ID: {scan_id}")

        if wait:
            click.echo("Waiting for scan to complete...")
            while True:
                result = await scanner.get_scan_status(scan_id)
                if result and result.status.value in ["completed", "failed", "cancelled"]:
                    break
                await asyncio.sleep(1)

            if result:
                click.echo(f"Scan completed with status: {result.status.value}")
                if result.status.value == "completed":
                    click.echo(f"Found {result.total_hosts} hosts with {result.total_open_ports} open ports")
                    for host in result.hosts:
                        if host.ports:
                            click.echo(f"  {host.ip}:")
                            for port in host.ports:
                                if port.state.value == "open":
                                    click.echo(f"    {port.port}/{port.protocol} - {port.state.value}")
                elif result.error_message:
                    click.echo(f"Error: {result.error_message}")
        else:
            click.echo("Scan started in background. Use 'red-team-mcp scan-status' to check progress.")

    try:
        asyncio.run(run_scan())
    except Exception as e:
        click.echo(f"✗ Scan error: {e}")
        sys.exit(1)


@cli.command()
@click.argument("scan_id")
@click.pass_context
def scan_status(ctx: click.Context, scan_id: str) -> None:
    """Check the status of a scan."""
    config: RedTeamMCPConfig = ctx.obj["config"]

    async def check_status():
        from .scanner import Scanner

        scanner = Scanner(config)
        result = await scanner.get_scan_status(scan_id)

        if result:
            click.echo(f"Scan ID: {scan_id}")
            click.echo(f"Status: {result.status.value}")
            click.echo(f"Target: {result.request.target.ip_range}")
            click.echo(f"Start time: {result.start_time}")
            if result.end_time:
                click.echo(f"End time: {result.end_time}")
                click.echo(f"Duration: {result.duration:.2f} seconds")

            if result.status.value == "completed":
                click.echo(f"Hosts found: {result.total_hosts}")
                click.echo(f"Open ports: {result.total_open_ports}")
            elif result.error_message:
                click.echo(f"Error: {result.error_message}")
        else:
            click.echo(f"Scan not found: {scan_id}")

    try:
        asyncio.run(check_status())
    except Exception as e:
        click.echo(f"✗ Error: {e}")
        sys.exit(1)


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
