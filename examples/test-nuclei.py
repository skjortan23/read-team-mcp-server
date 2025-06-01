import asyncio
import json
import shlex
from http.client import HTTPConnection, HTTPSConnection
from typing import AsyncGenerator, Dict

from fastmcp import FastMCP

mcp = FastMCP(name="NucleiScannerMCP")

def detect_protocol(host: str, port: int, timeout: float = 2.0) -> str:
    """
    Check if host:port responds over HTTPS, then HTTP; otherwise “network”.
    """
    try:
        conn = HTTPSConnection(host, port=port, timeout=timeout)
        conn.request("HEAD", "/")
        conn.getresponse()
        conn.close()
        return "https"
    except Exception:
        pass
    try:
        conn = HTTPConnection(host, port=port, timeout=timeout)
        conn.request("HEAD", "/")
        conn.getresponse()
        conn.close()
        return "http"
    except Exception:
        pass
    return "network"

@mcp.tool(
    annotations={
        "title": "vulnerability scan Host with (Verbose Streaming)",
        "description": (
            "Runs a vulnerability scant against a host:port with JSONL (-j) and verbose (-vv) flags, "
            "streams both verbose logs (stderr) and vulnerability JSONs (stdout)."
        ),
        "readOnlyHint": False,
        "openWorldHint": True
    }
)
async def scan_nuclei_stream(host: str, port: int) -> AsyncGenerator[Dict, None]:
    """
    Yields:
      • {"_status": "Starting Nuclei scan on host:port"} immediately
      • For each line on stderr: yield {"_verbose": "<that line>"}
      • For each JSON line on stdout: yield the parsed dict
      • If Nuclei exits with no findings, yield {"_status": "Scan completed: no vulnerabilities found."}
    """
    print(f"Server: Received call for host={host}, port={port}")
    await asyncio.sleep(0.1)
    print("Server: Yielding initial status…")
    yield {"_status": "…"}
    # 1. Immediate status so client knows the scan began
    yield {"_status": f"Starting Nuclei scan on {host}:{port}"}

    # 2. Detect protocol (http/https or “network”)
    proto = detect_protocol(host, port)
    if proto in ("http", "https"):
        target_url = f"{proto}://{host}:{port}"
        tags = "http,dir"
        cmd_args = [
            "nuclei",
            "-u", target_url,
            "-j",      # JSONL: one JSON object per line (stdout)
            "-vv",     # Very verbose: log template loading/execution (stderr)
            "-tags", tags
        ]
    else:
        target_conn = f"{host}:{port}"
        tags = "network"
        cmd_args = [
            "nuclei",
            "-target", target_conn,
            "-j",
            "-vv",
            "-tags", tags
        ]

    # 3. Spawn Nuclei subprocess with separate pipes for stdout and stderr
    proc = await asyncio.create_subprocess_exec(
        *cmd_args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        bufsize=1,
        text=True
    )

    # 4. Define async generators to read stderr and stdout
    async def read_stderr():
        # For each verbose line (template loading, info, etc.), yield as {"_verbose": line}
        async for raw_err in proc.stderr:
            line = raw_err.rstrip()
            if line:
                yield {"_verbose": line}

    async def read_stdout():
        # For each JSON line (actual vulnerability) in stdout, parse and yield
        async for raw_line in proc.stdout:
            line = raw_line.rstrip()
            if line:
                try:
                    vuln = json.loads(line)
                    yield vuln
                except json.JSONDecodeError:
                    # If it’s not valid JSON (unlikely under -j), skip
                    continue

    stderr_iter = read_stderr()
    stdout_iter = read_stdout()

    # 5. Concurrently read whichever arrives first, yield it, then reschedule
    pending = {
        asyncio.create_task(stderr_iter.__anext__()),
        asyncio.create_task(stdout_iter.__anext__())
    }
    any_yielded = False

    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            try:
                item = task.result()
                yield item
                any_yielded = True

                # Reschedule reading from whichever generator produced this item
                # Determine source by inspecting task.get_coro().__self__
                # (the __self__ attribute is the generator instance)
                if task.get_coro().__self__ is stderr_iter:
                    pending.add(asyncio.create_task(stderr_iter.__anext__()))
                else:
                    pending.add(asyncio.create_task(stdout_iter.__anext__()))

            except StopAsyncIteration:
                # That generator is exhausted; do not reschedule
                pass

    # 6. Wait for Nuclei to finish
    return_code = await proc.wait()
    if return_code != 0:
        stderr_data = await proc.stderr.read()
        raise RuntimeError(f"Nuclei exited with code {return_code}: {stderr_data.strip()}")

    # 7. If nothing was yielded (no verbose and no JSON), send a final “no findings” status
    if not any_yielded:
        yield {"_status": "Scan completed: no vulnerabilities or verbose logs."}

if __name__ == "__main__":


    mcp.run(transport="stdio")