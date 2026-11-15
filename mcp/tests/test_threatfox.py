"""Synthetic JSON API tests and historical CSV parser regressions.

Uses pytest-httpx to intercept HTTP calls — no live network access in CI.
The mock CSV mirrors the real feed columns (0..14):
  first_seen, id, value, type, threat_type, fk_malware, malware_aliases,
  malware_printable, last_seen, confidence_level, is_compromised, reference,
  tags, anonymous, reporter
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from threat_intel_mcp.vault.base import CredentialNotFoundError, CredentialError
from tests.test_abusech import FakeCredentials

import httpx
import pytest

from threat_intel_mcp.adapters.threatfox import (
    ThreatFoxAdapter,
    _map_confidence,
    _normalize_row,
    _parse_ip,
)

_FEED_URL = "https://threatfox-api.abuse.ch/api/v1/"


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


def _csv_abusech(rows):
    """Serialise rows the way abuse.ch actually does: every field quoted, fields
    separated by **comma-then-space**.

    ``_csv`` above uses ``csv.writer``, which emits minimal quoting and no
    spaces — a shape the default reader dialect happens to parse correctly. That
    mismatch is exactly why the adapter passed its tests while returning zero
    records against the live feed on 2026-07-25. Tests that feed the live shape
    belong here; keep both, because the parser must handle either.
    """
    header = "# first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type\n"
    body = "\n".join(
        ", ".join('"{}"'.format(field) for field in row) for row in rows
    )
    return header + body + "\n"


@pytest.fixture()
def adapter():
    return ThreatFoxAdapter(FakeCredentials())


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


def _entry(value="malware.example", kind="domain", age=1):
    return {"ioc": value, "ioc_type": kind, "threat_type": "botnet_cc",
            "malware_printable": "Test", "confidence_level": 90,
            "first_seen": (datetime.now(timezone.utc) - timedelta(hours=age)).strftime(
                "%Y-%m-%d %H:%M:%S UTC")}


@pytest.mark.asyncio
async def test_post_contract_and_network_mapping(adapter, httpx_mock):
    data = [_entry(), _entry("192.0.2.1:443", "ip:port"),
            _entry("https://malware.example/a", "url"), _entry("a"*64, "sha256_hash")]
    httpx_mock.add_response(url=_FEED_URL, method="POST", json={"query_status": "ok", "data": data})
    result = await adapter.fetch(time_range="25h")
    assert result.record_count == 3
    assert {i["type"] for i in result.iocs} == {"Domain", "IPv4", "URL"}
    request = httpx_mock.get_request()
    assert json.loads(request.content) == {"query": "get_iocs", "days": 2}
    assert request.headers["Auth-Key"] == "abusech-test-key"
    assert result.iocs[0]["first_seen"].endswith("+00:00")


@pytest.mark.asyncio
async def test_exact_window_and_future_filter(adapter, httpx_mock):
    httpx_mock.add_response(json={"query_status": "ok", "data": [
        _entry(age=1), _entry("old.example", age=25), _entry("future.example", age=-1)]})
    result = await adapter.fetch(time_range="24h")
    assert [i["value"] for i in result.iocs] == ["malware.example"]


@pytest.mark.asyncio
async def test_cache_reuses_fetch_timestamp_and_filters_per_window(adapter, httpx_mock):
    httpx_mock.add_response(json={"query_status": "ok", "data": [_entry(age=12)]})
    first = await adapter.fetch(time_range="24h")
    second = await adapter.fetch(time_range="1h")
    assert first.record_count == 1 and second.record_count == 0
    assert first.retrieved_at == second.retrieved_at
    assert len(httpx_mock.get_requests()) == 1


@pytest.mark.asyncio
async def test_cache_separated_by_api_days(adapter, httpx_mock):
    for _ in range(2):
        httpx_mock.add_response(json={"query_status": "ok", "data": []})
    await adapter.fetch(time_range="1d")
    await adapter.fetch(time_range="7d")
    assert len(httpx_mock.get_requests()) == 2


@pytest.mark.asyncio
async def test_seven_day_cap_is_partial(adapter, httpx_mock):
    httpx_mock.add_response(json={"query_status": "ok", "data": []})
    result = await adapter.fetch(time_range="2w")
    assert json.loads(httpx_mock.get_request().content)["days"] == 7
    assert result.partial_failure and "7 days" in result.partial_failure[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", [None, FakeCredentials(None)])
async def test_missing_key_fails_before_network(provider, httpx_mock):
    with pytest.raises(CredentialNotFoundError):
        await ThreatFoxAdapter(provider).fetch()
    assert not httpx_mock.get_requests()


@pytest.mark.asyncio
async def test_provider_outage_propagates(httpx_mock):
    class Broken:
        def get(self, *args):
            raise CredentialError("unavailable")
    with pytest.raises(CredentialError):
        await ThreatFoxAdapter(Broken()).fetch()
    assert not httpx_mock.get_requests()


@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs", [{"feed_types": ["nope"]}, {"time_range": "0d"},
                                     {"time_range": "nonsense"}])
async def test_bad_caller_input(adapter, kwargs):
    with pytest.raises(ValueError):
        await adapter.fetch(**kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [[], {}, {"query_status": "unknown_auth_key"},
    {"query_status": "ok", "data": "bad"}, {"query_status": "ok", "data": [{}]},
    {"query_status": "ok", "data": [_entry() | {"first_seen": None}]},
    {"query_status": "ok", "data": [_entry() | {"first_seen": "bad"}]},
    {"query_status": "ok", "data": [_entry() | {"ioc": None}]}])
async def test_untrusted_json_never_quiet_success(adapter, httpx_mock, body):
    httpx_mock.add_response(json=body)
    with pytest.raises(RuntimeError):
        await adapter.fetch()
    assert not adapter._cache


@pytest.mark.asyncio
async def test_html_failure_and_retry(adapter, httpx_mock):
    httpx_mock.add_response(text="<html>denied</html>")
    with pytest.raises(RuntimeError):
        await adapter.fetch()
    httpx_mock.add_response(json={"query_status": "ok", "data": [_entry()]})
    assert (await adapter.fetch()).record_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 410, 429, 500])
async def test_http_failure(adapter, httpx_mock, status):
    httpx_mock.add_response(status_code=status)
    with pytest.raises(httpx.HTTPStatusError):
        await adapter.fetch()


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{"query_status": "no_result"},
    {"query_status": "ok", "data": []},
    {"query_status": "ok", "data": [_entry("a"*64, "sha256_hash")]}])
async def test_legitimate_empty(adapter, httpx_mock, body):
    httpx_mock.add_response(json=body)
    assert (await adapter.fetch()).record_count == 0


def test_historical_csv_dialect_regression(adapter):
    rows = [_row("192.0.2.1:443", "ip:port"), _row("bad.example", "domain")]
    for text in (_csv(rows), _csv_abusech(rows)):
        parsed = adapter._parse_csv(text)
        assert len(parsed) == 2 and parsed[0]["value"] == "192.0.2.1"
        assert "port:443" in parsed[0]["tags"]
    assert adapter._parse_csv("# empty\n") == []
    assert adapter._parse_csv(_csv([_row("a"*64, "sha256_hash")])) == []
    with pytest.raises(RuntimeError):
        adapter._parse_csv("<html>error</html>")


def test_every_registered_source_that_takes_credentials_gets_them():
    """An adapter that accepts a credential provider but is registered without
    one silently runs unauthenticated. ThreatFox did for weeks after the
    abuse.ch key was added, while six docs said the key was sent."""
    import inspect

    from threat_intel_mcp import server

    missing = []
    for source in [*server._FEED_SOURCES, *server._VULN_SOURCES]:
        adapter = source.adapter
        reads_a_key = "_credentials.get(" in inspect.getsource(type(adapter))
        if reads_a_key and getattr(adapter, "_credentials", None) is not server._credentials:
            missing.append(source.name)
    assert not missing, f"registered without the server's credential provider: {missing}"


@pytest.mark.asyncio
async def test_in_band_status_does_not_echo_secret(adapter, httpx_mock, caplog):
    secret = "synthetic-private-error-sentinel"
    httpx_mock.add_response(json={"query_status": secret, "data": secret})
    with pytest.raises(RuntimeError) as exc:
        await adapter.fetch()
    assert secret not in str(exc.value) and secret not in caplog.text


@pytest.mark.asyncio
async def test_no_result_cannot_hide_records(adapter, httpx_mock):
    httpx_mock.add_response(json={"query_status": "no_result", "data": [_entry()]})
    with pytest.raises(RuntimeError):
        await adapter.fetch()
