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
