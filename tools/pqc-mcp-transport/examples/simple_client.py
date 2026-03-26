"""
Simple PQC MCP Client Example

Connects to a PQC MCP server, performs handshake,
and calls a tool with ML-DSA signed messages.
"""

import asyncio

from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport import PQCMCPClient


async def main() -> None:
    # Create agent identity
    agent = AgentIdentity.create("example-client", capabilities=["tools:call"])
    print(f"Client DID: {agent.did}")

    # Connect to server with PQC handshake
    client = PQCMCPClient(
        identity=agent,
        server_url="http://localhost:8080",
    )

    try:
        session = await client.connect()
        print(f"Connected! Session: {session.session_id}")
        print(f"Server DID: {session.peer_did}")

        # Call a tool — request is automatically signed with ML-DSA
        result = await client.call_tool("greet", {"name": "World"})
        print(f"Result: {result}")
        print(f"Response verified: {client.session.last_response_verified}")

        # Show audit log
        for entry in session.get_audit_log():
            print(
                f"  [{entry.timestamp}] {entry.operation}: "
                f"{entry.method} verified={entry.verified}"
            )
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
