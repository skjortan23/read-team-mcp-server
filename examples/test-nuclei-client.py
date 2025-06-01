import asyncio
from agno.agent import Agent
from agno.models.ollama import Ollama
from agno.tools.mcp import MCPTools

model = Ollama("qwen3", host="http://mini:11434")


async def setupTools():
    server_script = "nuclei_scanner_mcp.py"
    mcp_command = f"python {server_script}"
    mcp_tools = MCPTools(command=mcp_command, timeout_seconds=600)
    await mcp_tools.__aenter__()
    return mcp_tools


async def main():
    mcp_tools = await setupTools()

    testAgent = Agent(
        model=model,
        tools=[mcp_tools],
        description="You are a seasoned penetration tester that is a world champion on finding bugs. Finding bugs and misconfigurations is your main driver. Nothing makes you more happy then breaking in and getting a root shell.",
        show_tool_calls=True,
        instructions=[
            "/no_think",
            "Use tables to display data",
            "Only output the report, no other text",
        ],
    )

    await testAgent.aprint_response("do a vulnerability scan against gofyeo.com port 443", stream=True, stream_intermediate_steps=True)
    await mcp_tools.__aexit__(None, None, None)


if __name__ == "__main__":
    asyncio.run(main())