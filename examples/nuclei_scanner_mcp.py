import asyncio
import json
from http.client import HTTPConnection, HTTPSConnection
from typing import AsyncGenerator, Dict

from fastmcp import FastMCP

mcp = FastMCP(name="NucleiScannerMCP")

def detect_protocol(host: str, port: int, timeout: float = 2.0) -> str:
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
        "title": "vulnerability scanner using nuclei scanner",
        "description": (
            "Scan a host for vulnerabilities. "
            "Runs Nuclei with -j and -vv, but ensures at least one status update is yielded "
        ),
        "readOnlyHint": False,
        "openWorldHint": True
    }
)
async def scan_nuclei_stream(host: str, port: int) -> AsyncGenerator[Dict, None]:
    # 1. Brief delay so the client’s progress_handler can register
    await asyncio.sleep(0.1)  # 100 ms pause  [oai_citation:39‡pondhouse-data.com](https://www.pondhouse-data.com/blog/create-mcp-server-with-fastmcp?utm_source=chatgpt.com) [oai_citation:40‡Magritek](https://magritek.com/products/benchtop-nmr-spectrometer-spinsolve/spinsolve-80/?utm_source=chatgpt.com)

    # 2. Debug print and initial status
    print(f"[Server] Invoked scan_nuclei_stream for {host}:{port}")
    yield {"_status": f"Starting Nuclei scan on {host}:{port}"}  #  [oai_citation:41‡Bruker](https://www.bruker.com/en/landingpages/bbio/all-in-one-benchtop-nmr-for-protons-15-x-nuclei-analysis.html?utm_source=chatgpt.com) [oai_citation:42‡pondhouse-data.com](https://www.pondhouse-data.com/blog/create-mcp-server-with-fastmcp?utm_source=chatgpt.com)

    # 3. Detect protocol & build Nuclei command
    proto = detect_protocol(host, port)  #  [oai_citation:43‡GitHub](https://github.com/projectdiscovery/nuclei/issues/5669?utm_source=chatgpt.com) [oai_citation:44‡GitHub](https://github.com/projectdiscovery/nuclei/issues/5669?utm_source=chatgpt.com)
    if proto in ("http", "https"):
        target = f"{proto}://{host}:{port}"
        tags = "http,dir"
        cmd_args = ["nuclei", "-u", target, "-j", "-vv", "-tags", tags]
    else:
        target = f"{host}:{port}"
        tags = "network"
        cmd_args = ["nuclei", "-target", target, "-j", "-vv", "-tags", tags]

    # 4. Launch Nuclei subprocess
    proc = await asyncio.create_subprocess_exec(
        *cmd_args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        bufsize=1, text=True  # line-buffered & text mode  [oai_citation:45‡pondhouse-data.com](https://www.pondhouse-data.com/blog/create-mcp-server-with-fastmcp?utm_source=chatgpt.com)
    )

    # 5a. Reader for stderr (verbose logs)
    async def read_stderr():
        async for raw_err in proc.stderr:
            line = raw_err.rstrip()
            if line:
                yield {"_verbose": line}  #  [oai_citation:46‡GitHub](https://github.com/projectdiscovery/nuclei/issues/5669?utm_source=chatgpt.com)

    # 5b. Reader for stdout (JSONL vulnerabilities)
    async def read_stdout():
        async for raw_line in proc.stdout:
            line = raw_line.rstrip()
            if line:
                try:
                    yield json.loads(line)  #  [oai_citation:47‡npmjs.com](https://www.npmjs.com/package/fastmcp?utm_source=chatgpt.com) [oai_citation:48‡GitHub](https://github.com/projectdiscovery/nuclei/issues/5669?utm_source=chatgpt.com)
                except json.JSONDecodeError:
                    continue

    stderr_iter = read_stderr()
    stdout_iter = read_stdout()
    pending = {
        asyncio.create_task(stderr_iter.__anext__()),
        asyncio.create_task(stdout_iter.__anext__())
    }
    any_yielded = False

    # 6. Interleave whichever stream yields first
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            try:
                item = task.result()
                yield item  # {"_verbose": ...} or vulnerability dict
                any_yielded = True
                if task.get_coro().__self__ is stderr_iter:
                    pending.add(asyncio.create_task(stderr_iter.__anext__()))
                else:
                    pending.add(asyncio.create_task(stdout_iter.__anext__()))
            except StopAsyncIteration:
                pass

    # 7. Wait for Nuclei to exit & handle errors
    return_code = await proc.wait()
    if return_code != 0:
        stderr_data = await proc.stderr.read()
        raise RuntimeError(f"Nuclei exited with code {return_code}: {stderr_data.strip()}")

    # 8. Final status if nothing else yielded
    if not any_yielded:
        yield {"_status": "Scan completed: no vulnerabilities or verbose logs."}  #  [oai_citation:49‡Bruker](https://www.bruker.com/en/landingpages/bbio/all-in-one-benchtop-nmr-for-protons-15-x-nuclei-analysis.html?utm_source=chatgpt.com)

if __name__ == "__main__":
    mcp.run(transport="stdio")