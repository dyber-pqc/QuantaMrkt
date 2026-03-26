# PQC MCP Transport

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-DSA-87](https://img.shields.io/badge/ML--DSA--87-FIPS%20204-green)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)

Post-quantum secured transport layer for the **Model Context Protocol (MCP)**. Every JSON-RPC message is signed with **ML-DSA** (FIPS 204) digital signatures, providing cryptographic authentication, integrity verification, and replay protection that is resistant to both classical and quantum attacks.

## Installation

```bash
pip install pqc-mcp-transport
```

For development:

```bash
pip install pqc-mcp-transport[dev]
```

## Quick Start

### Server

```python
import asyncio
from quantumshield.identity.agent import AgentIdentity
from pqc_mcp_transport import PQCMCPServer

server_identity = AgentIdentity.create("my-server")
server = PQCMCPServer(identity=server_identity)

@server.tool("greet", description="Greet someone")
async def greet(name: str) -> str:
    return f"Hello, {name}!"

asyncio.run(server.run(port=8080))
```

### Client

```python
import asyncio
from quantumshield.identity.agent import AgentIdentity
from pqc_mcp_transport import PQCMCPClient

async def main():
    agent = AgentIdentity.create("my-client")
    client = PQCMCPClient(identity=agent, server_url="http://localhost:8080")

    session = await client.connect()      # PQC handshake
    result = await client.call_tool("greet", {"name": "World"})
    print(result)                          # Verified response
    await client.close()

asyncio.run(main())
```

## Architecture

```
 Client                                          Server
 ------                                          ------
   |                                               |
   |  1. HandshakeRequest (signed with ML-DSA)     |
   |---------------------------------------------->|
   |                                               | verify client sig
   |  2. HandshakeResponse (signed with ML-DSA)    |
   |<----------------------------------------------|
   | verify server sig                             |
   |                                               |
   |  === Session Established (mutual auth) ===    |
   |                                               |
   |  3. JSON-RPC Request + _pqc envelope          |
   |---------------------------------------------->|
   |                                  verify sig,  | check nonce,
   |                                  execute tool | sign response
   |  4. JSON-RPC Response + _pqc envelope         |
   |<----------------------------------------------|
   | verify response sig                           |
```

## Protocol Specification

### Handshake (Mutual Authentication)

1. **Client** generates a nonce, signs `{did}:{nonce}:{timestamp}` with its ML-DSA private key, and sends a `HandshakeRequest`.
2. **Server** verifies the client's signature, generates its own nonce and a session ID, signs `{did}:{client_nonce}:{server_nonce}:{session_id}`, and returns a `HandshakeResponse`.
3. **Client** verifies the server's signature and the echoed nonce. A `PQCSession` is created on both sides.

### Message Format

Every MCP JSON-RPC message carries a `_pqc` envelope:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "id": "abc123",
  "params": { "name": "greet", "arguments": { "name": "World" } },
  "_pqc": {
    "signer_did": "did:pqaid:abcdef...",
    "algorithm": "ML-DSA-65",
    "timestamp": "2025-01-15T10:30:00+00:00",
    "nonce": "a1b2c3d4e5f6...",
    "signature": "3045022100...",
    "public_key": "302a300506..."
  }
}
```

The `_pqc` field is stripped before signing (canonical form) and before passing the message to standard MCP handlers.

### Signing Process

1. Remove `_pqc` from the message.
2. Serialize with `json.dumps(msg, sort_keys=True, separators=(',', ':'))`.
3. Compute `SHA3-256` hash of the canonical bytes.
4. Sign the hash with ML-DSA.
5. Attach the `_pqc` envelope with signature, public key, nonce, and timestamp.

## Security Properties

| Property | Mechanism |
|---|---|
| **Message Authentication** | Every message is ML-DSA signed |
| **Mutual Authentication** | Both client and server verify each other during handshake |
| **Integrity** | Canonical JSON + SHA3-256 hash prevents tampering |
| **Replay Protection** | Per-session nonce tracking rejects duplicates |
| **Session Expiry** | Sessions have a configurable TTL (default: 1 hour) |
| **Quantum Resistance** | ML-DSA (FIPS 204) is resistant to Shor's algorithm |
| **Audit Trail** | Every operation is logged with signature metadata |

## API Reference

### `MessageSigner`

| Method | Description |
|---|---|
| `canonicalize(message)` | Deterministic JSON serialization (static) |
| `sign_message(message)` | Add `_pqc` envelope with ML-DSA signature |
| `verify_message(message)` | Verify `_pqc` envelope, returns `VerificationResult` (static) |
| `strip_pqc(message)` | Remove `_pqc` for standard MCP processing (static) |

### `PQCHandshake`

| Method | Description |
|---|---|
| `initiate(identity)` | Create a signed handshake request |
| `respond(request, server_identity)` | Verify client, create signed response |
| `complete(response, client_identity, nonce)` | Verify server, create session |

### `PQCSession`

| Method | Description |
|---|---|
| `is_valid()` | Check if session has not expired |
| `check_nonce(nonce)` | Register nonce, raise `ReplayAttackError` on reuse |
| `log_operation(...)` | Record operation in audit trail |
| `get_audit_log()` | Return list of `AuditEntry` records |

### `PQCMCPClient`

| Method | Description |
|---|---|
| `connect()` | Perform PQC handshake, return `PQCSession` |
| `call_tool(name, arguments)` | Send signed tool call, verify response |
| `list_tools()` | List available tools (signed request) |
| `close()` | Close connection |

### `PQCMCPServer`

| Method | Description |
|---|---|
| `tool(name, description)` | Decorator to register a tool handler |
| `handle_request(raw_message)` | Process incoming request with PQC verification |
| `handle_handshake(request)` | Handle handshake initiation |
| `get_tool_list()` | Return registered tools |
| `run(host, port)` | Start HTTP server |

### `PQCMiddleware`

ASGI middleware for adding PQC to existing frameworks (Starlette, FastAPI):

```python
from pqc_mcp_transport.middleware import PQCMiddleware
app = PQCMiddleware(app, server_identity=identity)
```

### Exceptions

| Exception | When |
|---|---|
| `PQCTransportError` | Base exception |
| `SignatureVerificationError` | Signature did not verify |
| `HandshakeError` | Handshake failed |
| `SessionExpiredError` | Session timed out |
| `ReplayAttackError` | Nonce reused |
| `PeerNotAuthenticatedError` | No handshake completed |

## Examples

See the `examples/` directory:

- **`simple_server.py`** -- Run a PQC MCP server with signed responses
- **`simple_client.py`** -- Connect to a server with PQC handshake
- **`mutual_auth.py`** -- In-memory mutual authentication demo

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/ tests/
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`pytest`)
5. Submit a pull request

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
