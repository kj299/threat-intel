"""Typed multi-field credential bundles for protocol-based intel feeds.

Phase 3 of issue #1: securely store and retrieve credentials for gRPC, MQTT,
WebSocket, and GraphQL intel sources alongside the existing REST feeds. Each
bundle is assembled from the same :class:`CredentialProvider` used everywhere
else (environment variables in dev, HashiCorp Vault in production), so no new
secret store is introduced — only typed accessors with required-field validation.

Storage convention (inherited from the CredentialProvider contract)::

    env:    {ADAPTER}_{KEY}                e.g. CHRONICLE_GRPC_TARGET
    Vault:  {mount}/data/{adapter}/{key}   e.g. secret/data/chronicle_grpc/target

Where ``adapter`` is a name you choose per feed (e.g. ``chronicle_grpc``) and
``key`` is a field below (``target``, ``host``, ``endpoint``, ``token`` …).

No secret value is ever logged or placed in an exception message — errors name
the *missing key*, never the *retrieved value*.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base import CredentialError, CredentialProvider

_TRUTHY = {"1", "true", "yes", "on"}


def _require(provider: CredentialProvider, adapter: str, key: str) -> str:
    """Fetch a mandatory credential field, normalising the not-found error."""
    try:
        value = provider.get(adapter, key)
    except (CredentialError, KeyError):
        raise CredentialError(
            f"Missing required credential '{key}' for protocol feed '{adapter}'. "
            f"Store it as env {adapter.upper()}_{key.upper()} or Vault "
            f"{adapter}/{key}."
        ) from None
    if not value:
        raise CredentialError(
            f"Credential '{key}' for protocol feed '{adapter}' is present but empty."
        )
    return value


def _optional(
    provider: CredentialProvider, adapter: str, key: str, default: str | None = None
) -> str | None:
    """Fetch an optional credential field, returning ``default`` if absent/empty."""
    try:
        value = provider.get(adapter, key)
    except (CredentialError, KeyError):
        return default
    return value or default


def _as_int(value: str, adapter: str, key: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise CredentialError(
            f"Credential '{key}' for protocol feed '{adapter}' must be an integer."
        ) from None


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in _TRUTHY


@dataclass(frozen=True)
class GraphQLCredentials:
    """Credentials for a GraphQL intel source (operator-supplied endpoint)."""

    endpoint: str
    token: str | None = None
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"

    @classmethod
    def from_provider(
        cls, provider: CredentialProvider, adapter: str
    ) -> GraphQLCredentials:
        return cls(
            endpoint=_require(provider, adapter, "endpoint"),
            token=_optional(provider, adapter, "token"),
            auth_header=_optional(provider, adapter, "auth_header", "Authorization")
            or "Authorization",
            auth_scheme=_optional(provider, adapter, "auth_scheme", "Bearer")
            or "Bearer",
        )


@dataclass(frozen=True)
class WebSocketCredentials:
    """Credentials for a WebSocket streaming intel source."""

    url: str
    token: str | None = None
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    subprotocol: str | None = None

    @classmethod
    def from_provider(
        cls, provider: CredentialProvider, adapter: str
    ) -> WebSocketCredentials:
        return cls(
            url=_require(provider, adapter, "url"),
            token=_optional(provider, adapter, "token"),
            auth_header=_optional(provider, adapter, "auth_header", "Authorization")
            or "Authorization",
            auth_scheme=_optional(provider, adapter, "auth_scheme", "Bearer")
            or "Bearer",
            subprotocol=_optional(provider, adapter, "subprotocol"),
        )


@dataclass(frozen=True)
class MQTTCredentials:
    """Credentials for an MQTT broker delivering real-time intel."""

    host: str
    port: int = 8883
    topic: str = "#"
    username: str | None = None
    password: str | None = None
    tls: bool = True

    @classmethod
    def from_provider(
        cls, provider: CredentialProvider, adapter: str
    ) -> MQTTCredentials:
        host = _require(provider, adapter, "host")
        port = _as_int(_optional(provider, adapter, "port", "8883") or "8883", adapter, "port")
        return cls(
            host=host,
            port=port,
            topic=_optional(provider, adapter, "topic", "#") or "#",
            username=_optional(provider, adapter, "username"),
            password=_optional(provider, adapter, "password"),
            tls=_as_bool(_optional(provider, adapter, "tls"), default=True),
        )


@dataclass(frozen=True)
class GRPCCredentials:
    """Credentials for a gRPC intel endpoint, with optional mTLS materials.

    ``client_cert`` and ``client_key`` form an mTLS pair: supply both or neither.
    ``root_cert`` (CA PEM) is optional and used to verify the server certificate.
    """

    target: str  # host:port
    root_cert: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    use_tls: bool = True

    def __post_init__(self) -> None:
        if bool(self.client_cert) != bool(self.client_key):
            raise CredentialError(
                "gRPC mTLS requires both 'client_cert' and 'client_key' "
                "(or neither). Only one was provided."
            )

    @classmethod
    def from_provider(
        cls, provider: CredentialProvider, adapter: str
    ) -> GRPCCredentials:
        return cls(
            target=_require(provider, adapter, "target"),
            root_cert=_optional(provider, adapter, "root_cert"),
            client_cert=_optional(provider, adapter, "client_cert"),
            client_key=_optional(provider, adapter, "client_key"),
            use_tls=_as_bool(_optional(provider, adapter, "use_tls"), default=True),
        )


# Registry mapping a protocol name to its credential bundle class.
PROTOCOL_CREDENTIALS: dict[str, type] = {
    "graphql": GraphQLCredentials,
    "websocket": WebSocketCredentials,
    "mqtt": MQTTCredentials,
    "grpc": GRPCCredentials,
}


def load_protocol_credentials(
    protocol: str, provider: CredentialProvider, adapter: str
):
    """Load and validate the credential bundle for ``protocol`` and ``adapter``.

    Raises:
        CredentialError: if the protocol is unsupported or a required field is
            missing / malformed.
    """
    try:
        bundle_cls = PROTOCOL_CREDENTIALS[protocol]
    except KeyError:
        raise CredentialError(
            f"Unsupported protocol '{protocol}'. "
            f"Supported: {sorted(PROTOCOL_CREDENTIALS)}."
        ) from None
    return bundle_cls.from_provider(provider, adapter)
