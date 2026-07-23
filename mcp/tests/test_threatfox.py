"""Tests for the ThreatFox (abuse.ch) public IOC adapter.

Uses pytest-httpx to intercept HTTP calls — no live network access in CI.
The mock CSV mirrors the real feed columns (0..14):
  first_seen, id, value, type, threat_type, fk_malware, malware_aliases,
  malware_printable, last_seen, confidence_level, is_compromised, reference,
  tags, anonymous, reporter
"""

from __future__ import annotations

import httpx
import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.threatfox import (
    ThreatFoxAdapter,
    _map_confidence,
    _normalize_row,
    _parse_ip,
)

_FEED_URL = "https://threatfox.abuse.ch/export/csv/recent/"


def _row(value, ioc_type, conf="90", malware="Cobalt Strike", threat="botnet_cc"):
    # 15 columns, matching the real feed layout.
    return [
        "2026-07-01 12:00:00", "500", value, ioc_type, threat, "cobalt_strike",
        "beacon", malware, "2026-07-02 12:00:00", conf, "false",
        "https://threatfox.abuse.ch/ioc/500/", "tag1,tag2", "0", "anon",
    ]


def _csv(rows):
    import csv
    import io
    buf = io.StringIO()
    buf.write("# ThreatFox recent\n")
    w = csv.writer(buf)
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


@pytest.fixture()
def adapter():
    return ThreatFoxAdapter()


class TestHelpers:
    def test_map_confidence(self):
        assert _map_confidence(90) == "High"
        assert _map_confidence(60) == "Medium"
        assert _map_confidence(10) == "Low"

    def test_parse_ip_ipv4_port(self):
        assert _parse_ip("1.2.3.4:443") == ("1.2.3.4", 4)

    def test_parse_ip_bare(self):
        assert _parse_ip("8.8.8.8") == ("8.8.8.8", 4)

    def test_parse_ip_ipv6_bracket_port(self):
        assert _parse_ip("[2001:db8::1]:443") == ("2001:db8::1", 6)

    def test_parse_ip_garbage(self):
        assert _parse_ip("not-an-ip") is None

    def test_normalize_ip_port(self):
        out = _normalize_row(_row("1.2.3.4:443", "ip:port"))
        assert out["type"] == "IPv4"
        assert out["value"] == "1.2.3.4"
        assert out["action"] == "block"
        assert out["confidence"] == "High"
        assert out["associated_threat"] == "Cobalt Strike"
        assert "port:443" in out["tags"] and "botnet_cc" in out["tags"]

    def test_normalize_domain(self):
        out = _normalize_row(_row("evil.example.com", "domain"))
        assert out["type"] == "Domain" and out["value"] == "evil.example.com"

    def test_normalize_url(self):
        out = _normalize_row(_row("http://evil.example/x", "url"))
        assert out["type"] == "URL"

    def test_hash_skipped(self):
        assert _normalize_row(_row("a" * 64, "sha256_hash")) is None
        assert _normalize_row(_row("a" * 32, "md5_hash")) is None

    def test_unknown_malware_not_attached(self):
        out = _normalize_row(_row("evil.example.com", "domain", malware="Unknown malware"))
        assert "associated_threat" not in out


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_network_types_only(self, adapter, httpx_mock: HTTPXMock):
        rows = [
            _row("1.2.3.4:443", "ip:port"),
            _row("evil.example.com", "domain"),
            _row("http://bad.test/x", "url"),
            _row("a" * 64, "sha256_hash"),  # skipped
        ]
        httpx_mock.add_response(url=_FEED_URL, text=_csv(rows))
        result = await adapter.fetch()
        assert result.source == "ThreatFox"
        assert result.tier == 9
        assert result.record_count == 3  # hash dropped
        assert {i["type"] for i in result.iocs} == {"IPv4", "Domain", "URL"}

    @pytest.mark.asyncio
    async def test_no_credential_needed(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_FEED_URL, text=_csv([_row("1.2.3.4:443", "ip:port")]))
        result = await adapter.fetch()
        assert result.record_count == 1
        assert adapter.requires_credential is False

    @pytest.mark.asyncio
    async def test_unknown_feed_type_raises(self, adapter):
        with pytest.raises(ValueError, match="Unknown feed_type"):
            await adapter.fetch(feed_types=["nope"])

    @pytest.mark.asyncio
    async def test_upstream_error_raises(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_FEED_URL, status_code=500)
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.fetch()

    @pytest.mark.asyncio
    async def test_cache_avoids_second_request(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_FEED_URL, text=_csv([_row("1.2.3.4:443", "ip:port")]))
        await adapter.fetch()
        result = await adapter.fetch()
        assert result.record_count == 1
