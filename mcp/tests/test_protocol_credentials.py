"""Tests for the protocol credential bundles (Phase 3).

Verifies required/optional field handling, type coercion, mTLS pairing, and that
error messages name the missing key — never a secret value.
"""

from __future__ import annotations

import pytest

from threat_intel_mcp.vault.base import CredentialError
from threat_intel_mcp.vault.protocols import (
    GRPCCredentials,
    GraphQLCredentials,
    MQTTCredentials,
    WebSocketCredentials,
    load_protocol_credentials,
)


class DictCredentials:
    """In-memory CredentialProvider backed by a {(adapter, key): value} dict."""

    def __init__(self, values: dict[tuple[str, str], str]):
        self._values = values

    def get(self, adapter_name: str, key: str) -> str:
        try:
            return self._values[(adapter_name, key)]
        except KeyError:
            raise CredentialError(f"no such secret {adapter_name}/{key}") from None


# ---------------------------------------------------------------------------
# GraphQL
# ---------------------------------------------------------------------------


class TestGraphQL:
    def test_minimal_requires_only_endpoint(self):
        creds = DictCredentials({("rf_graphql", "endpoint"): "https://example/graphql"})
        bundle = GraphQLCredentials.from_provider(creds, "rf_graphql")
        assert bundle.endpoint == "https://example/graphql"
        assert bundle.token is None
        assert bundle.auth_header == "Authorization"
        assert bundle.auth_scheme == "Bearer"

    def test_missing_endpoint_raises_naming_the_key(self):
        creds = DictCredentials({("rf_graphql", "token"): "secret-token-value"})
        with pytest.raises(CredentialError) as exc:
            GraphQLCredentials.from_provider(creds, "rf_graphql")
        msg = str(exc.value)
        assert "endpoint" in msg
        assert "secret-token-value" not in msg  # never leak a value

    def test_optional_overrides(self):
        creds = DictCredentials(
            {
                ("g", "endpoint"): "https://e/graphql",
                ("g", "token"): "t",
                ("g", "auth_header"): "X-API-Key",
                ("g", "auth_scheme"): "Token",
            }
        )
        bundle = GraphQLCredentials.from_provider(creds, "g")
        assert bundle.token == "t"
        assert bundle.auth_header == "X-API-Key"
        assert bundle.auth_scheme == "Token"

    def test_empty_required_value_rejected(self):
        creds = DictCredentials({("g", "endpoint"): ""})
        with pytest.raises(CredentialError, match="empty"):
            GraphQLCredentials.from_provider(creds, "g")


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------


class TestWebSocket:
    def test_minimal(self):
        creds = DictCredentials({("ws", "url"): "wss://feed/stream"})
        bundle = WebSocketCredentials.from_provider(creds, "ws")
        assert bundle.url == "wss://feed/stream"
        assert bundle.subprotocol is None

    def test_missing_url_raises(self):
        creds = DictCredentials({})
        with pytest.raises(CredentialError, match="url"):
            WebSocketCredentials.from_provider(creds, "ws")

    def test_subprotocol_carried(self):
        creds = DictCredentials(
            {("ws", "url"): "wss://feed", ("ws", "subprotocol"): "stix"}
        )
        assert WebSocketCredentials.from_provider(creds, "ws").subprotocol == "stix"


# ---------------------------------------------------------------------------
# MQTT
# ---------------------------------------------------------------------------


class TestMQTT:
    def test_defaults(self):
        creds = DictCredentials({("mq", "host"): "broker.example"})
        bundle = MQTTCredentials.from_provider(creds, "mq")
        assert bundle.host == "broker.example"
        assert bundle.port == 8883
        assert bundle.topic == "#"
        assert bundle.tls is True
        assert bundle.username is None

    def test_explicit_values(self):
        creds = DictCredentials(
            {
                ("mq", "host"): "broker",
                ("mq", "port"): "1883",
                ("mq", "topic"): "intel/iocs",
                ("mq", "username"): "u",
                ("mq", "password"): "p",
                ("mq", "tls"): "false",
            }
        )
        bundle = MQTTCredentials.from_provider(creds, "mq")
        assert bundle.port == 1883
        assert bundle.topic == "intel/iocs"
        assert bundle.username == "u"
        assert bundle.tls is False

    def test_bad_port_raises(self):
        creds = DictCredentials({("mq", "host"): "b", ("mq", "port"): "notaport"})
        with pytest.raises(CredentialError, match="port"):
            MQTTCredentials.from_provider(creds, "mq")

    @pytest.mark.parametrize(
        "raw,expected",
        [("true", True), ("1", True), ("YES", True), ("on", True),
         ("false", False), ("0", False), ("no", False)],
    )
    def test_tls_parsing(self, raw, expected):
        creds = DictCredentials({("mq", "host"): "b", ("mq", "tls"): raw})
        assert MQTTCredentials.from_provider(creds, "mq").tls is expected


# ---------------------------------------------------------------------------
# gRPC
# ---------------------------------------------------------------------------


class TestGRPC:
    def test_minimal_target_only(self):
        creds = DictCredentials({("g", "target"): "host:443"})
        bundle = GRPCCredentials.from_provider(creds, "g")
        assert bundle.target == "host:443"
        assert bundle.use_tls is True
        assert bundle.client_cert is None

    def test_missing_target_raises(self):
        with pytest.raises(CredentialError, match="target"):
            GRPCCredentials.from_provider(DictCredentials({}), "g")

    def test_full_mtls_pair(self):
        creds = DictCredentials(
            {
                ("g", "target"): "host:443",
                ("g", "root_cert"): "CA-PEM",
                ("g", "client_cert"): "CERT-PEM",
                ("g", "client_key"): "KEY-PEM",
            }
        )
        bundle = GRPCCredentials.from_provider(creds, "g")
        assert bundle.client_cert == "CERT-PEM"
        assert bundle.client_key == "KEY-PEM"

    def test_half_mtls_pair_rejected(self):
        creds = DictCredentials(
            {("g", "target"): "host:443", ("g", "client_cert"): "CERT-PEM"}
        )
        with pytest.raises(CredentialError, match="mTLS"):
            GRPCCredentials.from_provider(creds, "g")


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


class TestDispatch:
    def test_load_known_protocol(self):
        creds = DictCredentials({("mq", "host"): "broker"})
        bundle = load_protocol_credentials("mqtt", creds, "mq")
        assert isinstance(bundle, MQTTCredentials)

    def test_unsupported_protocol_raises(self):
        with pytest.raises(CredentialError, match="Unsupported protocol"):
            load_protocol_credentials("smtp", DictCredentials({}), "x")
