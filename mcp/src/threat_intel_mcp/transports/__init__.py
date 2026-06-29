"""Protocol transport scaffolding for non-REST intel feeds (Phase 3).

Bring-your-own-endpoint base classes for gRPC, MQTT, WebSocket, and GraphQL
sources. This package ships no live feed and no hardcoded endpoint — a concrete
adapter is configured entirely from operator-supplied credentials (see
``threat_intel_mcp.vault.protocols``).
"""

from .base import ProtocolAdapter

__all__ = ["ProtocolAdapter"]
