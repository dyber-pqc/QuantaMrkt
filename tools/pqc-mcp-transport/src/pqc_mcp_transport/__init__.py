"""PQC-secured transport layer for Model Context Protocol (MCP).

Wraps MCP transports with ML-DSA post-quantum signatures for
message authentication, mutual identity verification, and replay protection.
"""

__version__ = "0.1.0"

from pqc_mcp_transport.client import PQCMCPClient
from pqc_mcp_transport.handshake import PQCHandshake
from pqc_mcp_transport.server import PQCMCPServer
from pqc_mcp_transport.session import PQCSession
from pqc_mcp_transport.signer import MessageSigner

__all__ = [
    "PQCMCPClient",
    "PQCMCPServer",
    "PQCHandshake",
    "PQCSession",
    "MessageSigner",
]
