"""
Mutual Authentication Example

Demonstrates both client and server verifying each other
in a single script using in-memory transport (no network).
"""

import asyncio

from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport import PQCMCPServer, PQCHandshake, MessageSigner
from pqc_mcp_transport.handshake import HandshakeResponse


async def main() -> None:
    # Create identities for both sides
    client_id = AgentIdentity.create("mutual-auth-client", capabilities=["tools:call"])
    server_id = AgentIdentity.create("mutual-auth-server", capabilities=["tools:serve"])

    print(f"Client DID: {client_id.did}")
    print(f"Server DID: {server_id.did}")
    print(f"Algorithm:  {client_id.signing_keypair.algorithm.value}")
    print()

    # Set up server with a tool
    server = PQCMCPServer(identity=server_id, require_auth=True)

    @server.tool("multiply", description="Multiply two numbers")
    async def multiply(a: float, b: float) -> float:
        return a * b

    # --- Step 1: Mutual Handshake ---
    print("=== Step 1: PQC Handshake ===")
    hs_request, nonce = PQCHandshake.initiate(client_id)
    print(f"  Client sent handshake request (nonce: {nonce[:16]}...)")

    hs_response_dict = await server.handle_handshake(hs_request.to_dict())
    print(f"  Server verified client and responded")

    hs_response = HandshakeResponse.from_dict(hs_response_dict)
    session = PQCHandshake.complete(hs_response, client_id, nonce)
    print(f"  Client verified server")
    print(f"  Session established: {session.session_id[:16]}...")
    print(f"  Mutual authentication: COMPLETE")
    print()

    # --- Step 2: Signed Tool Call ---
    print("=== Step 2: Signed Tool Call ===")
    client_signer = MessageSigner(client_id)

    call_msg = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": "demo-1",
        "params": {"name": "multiply", "arguments": {"a": 6.0, "b": 7.0}},
    }
    signed_call = client_signer.sign_message(call_msg)
    signed_call["_pqc"]["session_id"] = session.session_id
    print(f"  Client signed request with DID: {client_id.did[:32]}...")

    # Server verifies and processes
    response = await server.handle_request(signed_call)
    print(f"  Server verified client signature: OK")

    # --- Step 3: Verify Server Response ---
    print()
    print("=== Step 3: Verify Server Response ===")
    vr = MessageSigner.verify_message(response)
    print(f"  Server signature valid: {vr.valid}")
    print(f"  Server DID confirmed:   {vr.signer_did[:32]}...")
    print(f"  Algorithm:              {vr.algorithm}")

    stripped = MessageSigner.strip_pqc(response)
    result = stripped.get("result", {}).get("content")
    print(f"  Result: 6.0 * 7.0 = {result}")
    print()

    # --- Audit Trail ---
    print("=== Audit Trail ===")
    for entry in session.get_audit_log():
        print(
            f"  [{entry.timestamp}] {entry.operation}: "
            f"method={entry.method} verified={entry.verified}"
        )

    print()
    print("All messages were PQC-signed with ML-DSA.")
    print("Both client and server identities were mutually verified.")


if __name__ == "__main__":
    asyncio.run(main())
