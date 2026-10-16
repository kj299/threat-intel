"""Protocol transport scaffolding for non-REST intel feeds (Phase 3).

Bring-your-own-endpoint base classes for gRPC, MQTT, WebSocket, and GraphQL
sources, plus ``misp_zmq``, the first concrete subclass (MISP's ZeroMQ pub-sub,
#162). This package ships no hardcoded endpoint — a concrete adapter is
configured entirely from operator-supplied settings and, where the transport
has any, credentials (see ``threat_intel_mcp.vault.protocols``).
"""

from .base import ProtocolAdapter

__all__ = ["ProtocolAdapter"]
