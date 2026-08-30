"""Tests for structured audit logging and secret redaction.

``audit.py`` is the last line of defence against a credential reaching a log
sink. Several adapters authenticate via a **query parameter** (Shodan's
``key=``), and httpx logs every request URL at INFO — so without the redacting
filter installed here, running the server at INFO would write live API keys to
the log. That failure is silent: nothing breaks, the key just leaks.

These tests therefore assert the *negative* — that the secret value never
appears in captured output — rather than only asserting the redacted form is
present. A regression that half-redacts would pass the latter and fail these.
"""

from __future__ import annotations

import logging

import pytest

from threat_intel_mcp.audit import (
    _RedactingFilter,
    log_tool_call,
    redact_headers,
    redact_url,
)

# A distinctive value so an assertion on "not in caplog.text" cannot pass by luck.
_SECRET = "sk-live-DO-NOT-LEAK-8f3a91c2b7"


class TestRedactUrl:
    @pytest.mark.parametrize(
        "param",
        ["key", "api_key", "api-key", "apikey", "token", "api_token", "secret", "password"],
    )
    def test_credential_query_params_are_redacted(self, param):
        url = f"https://api.example.com/search?{param}={_SECRET}&q=malware"
        out = redact_url(url)
        assert _SECRET not in out
        assert "[REDACTED]" in out
        assert "q=malware" in out, "non-secret params must survive"

    def test_case_insensitive(self):
        assert _SECRET not in redact_url(f"https://x.test/?API_KEY={_SECRET}")

    def test_bearer_and_basic_tokens(self):
        assert _SECRET not in redact_url(f"Authorization: Bearer {_SECRET}")
        assert "dXNlcjpwYXNz" not in redact_url("Authorization: Basic dXNlcjpwYXNz=")

    def test_clean_url_is_unchanged(self):
        url = "https://api.example.com/v2/hosts?q=labels%3Amalware&per_page=100"
        assert redact_url(url) == url

    def test_shodan_shape_end_to_end(self):
        """The real leak vector: Shodan puts the key in the query string."""
        url = f"https://api.shodan.io/shodan/host/search?key={_SECRET}&query=category:malware"
        out = redact_url(url)
        assert _SECRET not in out
        assert "query=category:malware" in out


class TestRedactHeaders:
    @pytest.mark.parametrize(
        "header", ["Authorization", "authorization", "X-API-Key", "x-auth-token", "Cookie"]
    )
    def test_sensitive_headers_redacted_case_insensitively(self, header):
        out = redact_headers({header: _SECRET, "Accept": "application/json"})
        assert out[header] == "[REDACTED]"
        assert _SECRET not in str(out)

    def test_benign_headers_preserved(self):
        headers = {"Accept": "application/json", "User-Agent": "threat-intel-mcp/0.14"}
        assert redact_headers(headers) == headers

    def test_returns_a_copy(self):
        original = {"Authorization": _SECRET}
        redact_headers(original)
        assert original["Authorization"] == _SECRET, "must not mutate the caller's dict"


class TestRedactingFilter:
    def test_installed_on_http_client_loggers(self):
        """Import-time installation is what makes this defence automatic."""
        for name in ("httpx", "httpcore"):
            filters = logging.getLogger(name).filters
            assert any(isinstance(f, _RedactingFilter) for f in filters), (
                f"{name} logger has no _RedactingFilter — request URLs would log raw"
            )

    def test_rewrites_a_record_containing_a_secret(self):
        record = logging.LogRecord(
            name="httpx", level=logging.INFO, pathname=__file__, lineno=1,
            msg='HTTP Request: GET https://api.shodan.io/x?key=%s "200 OK"' % _SECRET,
            args=(), exc_info=None,
        )
        assert _RedactingFilter().filter(record) is True
        assert _SECRET not in record.getMessage()
        assert "[REDACTED]" in record.getMessage()

    def test_clean_record_passes_through_untouched(self):
        msg = 'HTTP Request: GET https://api.example.com/v1/health "200 OK"'
        record = logging.LogRecord(
            name="httpx", level=logging.INFO, pathname=__file__, lineno=1,
            msg=msg, args=(), exc_info=None,
        )
        assert _RedactingFilter().filter(record) is True
        assert record.getMessage() == msg

    def test_unformattable_record_is_not_dropped(self):
        """A record whose getMessage() raises must still be emitted, not swallowed.

        Losing log records to a redaction bug would be its own incident.
        """
        record = logging.LogRecord(
            name="httpx", level=logging.INFO, pathname=__file__, lineno=1,
            msg="bad format %d %d", args=("not-an-int",), exc_info=None,
        )
        assert _RedactingFilter().filter(record) is True

    def test_secret_never_reaches_caplog_via_httpx_logger(self, caplog):
        """End-to-end: the installed filter protects real httpx-style logging."""
        with caplog.at_level(logging.INFO, logger="httpx"):
            logging.getLogger("httpx").info(
                'HTTP Request: GET https://api.shodan.io/shodan/host/search?key=%s "200 OK"',
                _SECRET,
            )
        assert _SECRET not in caplog.text
        assert "[REDACTED]" in caplog.text


class TestLogToolCall:
    def test_ok_status_logs_at_info(self, caplog):
        with caplog.at_level(logging.INFO, logger="threat_intel_mcp.audit"):
            log_tool_call("demo_fetch_iocs", {"time_range": "7d"}, record_count=5, latency_ms=12.34)
        assert caplog.records[-1].levelno == logging.INFO
        assert "demo_fetch_iocs" in caplog.text
        assert "12.3" in caplog.text, "latency should be rounded to 1dp"

    @pytest.mark.parametrize("status", ["error", "partial"])
    def test_non_ok_status_logs_at_warning_with_error_field(self, caplog, status):
        with caplog.at_level(logging.INFO, logger="threat_intel_mcp.audit"):
            log_tool_call(
                "demo_fetch_iocs", {"time_range": "7d"},
                record_count=0, latency_ms=1.0, status=status, error="ConnectTimeout",
            )
        assert caplog.records[-1].levelno == logging.WARNING
        assert "ConnectTimeout" in caplog.text

    def test_error_field_omitted_when_absent(self, caplog):
        with caplog.at_level(logging.INFO, logger="threat_intel_mcp.audit"):
            log_tool_call("demo", {}, record_count=1, latency_ms=1.0)
        assert "'error'" not in caplog.text


class TestProtocolCredentialRedaction:
    """Issue #1's second acceptance criterion, for the protocols it names.

    `vault/protocols.py` ships typed credential bundles for gRPC, MQTT,
    WebSocket and GraphQL, but the redactor only understood `name=value` and
    `Bearer <token>` — REST shapes. Measured before the fix, a gRPC mTLS private
    key, an MQTT `user:pass@host` connection string and a quoted
    `'Authorization': 'token …'` header each passed through `redact_url`
    unchanged. The credential *storage* for those protocols shipped; the
    redaction did not follow it.
    """

    SECRETS = ("SEKRET123", "hunter2", "MIIEvQIBADANBg", "abc.def.ghi")

    @pytest.mark.parametrize(
        ("label", "line"),
        [
            ("rest query key", "GET https://api.shodan.io/search?key=SEKRET123"),
            ("bearer header", "Authorization: Bearer abc.def.ghi"),
            (
                "grpc mtls private key",
                "loading -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----",
            ),
            ("mqtt connection string", "connect mqtts://alice:hunter2@broker.example:8883"),
            ("websocket access_token", "wss://feed.example/stream?access_token=SEKRET123"),
            ("graphql single-quoted", "headers={'Authorization': 'token SEKRET123'}"),
            ("graphql double-quoted", 'headers={"api_key": "SEKRET123"}'),
            ("bare colon password", "password: hunter2"),
            ("hyphenated api-key", "GET /v1/x?api-key=SEKRET123"),
        ],
    )
    def test_no_credential_shape_survives_redaction(self, label: str, line: str):
        redacted = redact_url(line)
        leaked = [s for s in self.SECRETS if s in redacted]
        assert not leaked, f"{label}: {leaked} still present in {redacted!r}"

    @pytest.mark.parametrize(
        "benign",
        [
            "monkey=banana",
            "turkey=roast",
            "latency_ms: 812",
            "records=3541",
            "GET https://api.cisa.gov/kev.json 200 OK",
            "https://threatfox.abuse.ch/export/csv/recent/",
        ],
    )
    def test_benign_lines_are_not_over_redacted(self, benign: str):
        """Over-redaction is not free: a log that hides `monkey=banana` is a log
        that lies about what happened. `monkey` matched before a boundary was
        added — and `\\b` was the wrong boundary, because it also stopped
        `access_token=` from matching and let a real token through."""
        assert redact_url(benign) == benign

    def test_every_protocol_transport_logger_is_filtered(self):
        """Ties logger coverage to the protocols that have credential bundles.

        The filter list was `("httpx", "httpcore")` while `protocols.py` held
        bundles for four other transports, each of which logs through its own
        logger. A credential bundle whose transport logs unfiltered is a
        credential in the log.
        """
        from threat_intel_mcp.audit import REDACTED_LOGGERS

        for name in ("websockets", "paho.mqtt", "grpc", "gql"):
            assert name in REDACTED_LOGGERS, f"{name} has a credential bundle but no log filter"
            installed = logging.getLogger(name).filters
            assert any(type(f).__name__ == "_RedactingFilter" for f in installed), (
                f"{name} is listed but the filter is not installed on it"
            )

    def test_protocol_bundles_and_filtered_loggers_stay_in_step(self):
        """If a fifth protocol bundle is added, its logger must be covered too.

        Asserted by name so the failure says which one, rather than a count
        mismatch that leaves the reader guessing.
        """
        from threat_intel_mcp.audit import REDACTED_LOGGERS
        from threat_intel_mcp.vault import protocols

        bundle_to_logger = {
            "GraphQLCredentials": "gql",
            "WebSocketCredentials": "websockets",
            "MQTTCredentials": "paho",
            "GRPCCredentials": "grpc",
        }
        defined = {
            name
            for name in dir(protocols)
            if name.endswith("Credentials") and not name.startswith("_")
        }
        unmapped = defined - set(bundle_to_logger)
        assert not unmapped, (
            f"new credential bundle(s) {sorted(unmapped)} have no logger mapping — "
            "add the transport's logger to REDACTED_LOGGERS and map it here"
        )
        for bundle, log_name in bundle_to_logger.items():
            if bundle in defined:
                assert log_name in REDACTED_LOGGERS, f"{bundle} -> {log_name} not filtered"
