"""
Simple PQC MCP Server Example

Runs an MCP server that verifies PQC signatures
on all incoming tool calls and signs all responses.
"""

import asyncio

from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport import PQCMCPServer

server_identity = AgentIdentity.create("example-server")
server = PQCMCPServer(identity=server_identity)


@server.tool("greet", description="Greet someone by name")
async def greet(name: str) -> str:
    return f"Hello, {name}! This response is PQC-signed."


@server.tool("add", description="Add two numbers")
async def add(a: float, b: float) -> float:
    return a + b


@server.tool("echo", description="Echo back the input")
async def echo(message: str) -> str:
    return message


async def main() -> None:
    print(f"Server DID: {server_identity.did}")
    print(f"Algorithm: {server_identity.signing_keypair.algorithm.value}")
    print("Starting PQC MCP Server on http://localhost:8080")
    print("All responses signed with ML-DSA")
    await server.run(host="0.0.0.0", port=8080)


if __name__ == "__main__":
    asyncio.run(main())
