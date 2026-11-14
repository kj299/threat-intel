"""Behavioral regressions found by the repository retrospective."""
import asyncio
import io
import logging
from copy import deepcopy
import pytest
from threat_intel_mcp.audit import _RedactingFilter, redact_headers, redact_url
from threat_intel_mcp.normalize import finalize_iocs
from threat_intel_mcp.resilience import CircuitBreaker, guarded_fetch
from threat_intel_mcp.secret_fields import SECRET_HEADERS
from threat_intel_mcp.vulns import deduplicate_vulns


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('vulns', [False, True])
def test_merge_restrictions(reverse, vulns):
    records = [dict(type='IPv4', value='8.8.8.8', confidence='High', source='A', tlp='WHITE', cvss_score=9.8, cve_id='CVE-2026-12345'), dict(type='IPv4', value='8.8.8.8', confidence='Low', source='B', tlp='RED', cvss_score=3.0, cve_id='CVE-2026-12345')]
    if reverse:
        records.reverse()
    original = deepcopy(records)
    result = (deduplicate_vulns if vulns else finalize_iocs)(records)[0]
    assert result['tlp'] == 'RED'
    assert {e['source']: e['tlp'] for e in result['source_evidence']} == {'A': 'WHITE', 'B': 'RED'}
    assert records == original


@pytest.mark.parametrize(('kind', 'value'), [('IPv4', 'not-an-ip'), ('IPv4', '999.1.2.3'), ('IPv4', '1[.]2[.]3[.]4'), ('IPv6', 'not:ipv6'), ('Domain', '1.2.3.4'), ('Domain', 'evil..example'), ('URL', 'https://'), ('URL', 'javascript:alert(1)'), ('URL', 'https://evil.example:99999'), ('CIDR_Range', '1.2.3.4/99'), ('JA3', 'x' * 32), ('SSL_Certificate_Hash', '1234')])
def test_invalid_indicators(kind, value):
    assert finalize_iocs([dict(type=kind, value=value, confidence='High', source='fixture')]) == []


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', [KeyError, asyncio.CancelledError])
async def test_trial_recovery(failure):
    breaker = CircuitBreaker('fixture', failure_threshold=1, reset_timeout=0)
    breaker.record_failure()
    class Adapter:
        async def fetch(self, **kwargs):
            raise failure('fixture')
    with pytest.raises(failure):
        await guarded_fetch(Adapter(), breaker, time_range='7d', no_retry_on=(KeyError,))
    assert breaker.state == 'half_open'
    assert breaker.allow()


@pytest.mark.asyncio
async def test_deadline():
    cancelled = asyncio.Event()
    class Adapter:
        async def fetch(self, **kwargs):
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()
    breaker = CircuitBreaker('fixture', failure_threshold=1)
    with pytest.raises(TimeoutError):
        await guarded_fetch(Adapter(), breaker, time_range='7d', timeout_seconds=0.01)
    assert cancelled.is_set()
    assert breaker.state == 'open'


def test_child_logger():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(_RedactingFilter())
    logger = logging.getLogger('paho.mqtt')
    logger.addHandler(handler)
    try:
        logging.getLogger('paho.mqtt.client').warning('password=SYNTHETIC_SECRET')
    finally:
        logger.removeHandler(handler)
    assert 'SYNTHETIC_SECRET' not in stream.getvalue()
    assert '[REDACTED]' in stream.getvalue()


@pytest.mark.parametrize('header', SECRET_HEADERS)
def test_header_redaction(header):
    assert redact_headers({header: 'SYNTHETIC_SECRET'})[header] == '[REDACTED]'
    assert 'SYNTHETIC_SECRET' not in redact_url(str({header: 'SYNTHETIC_SECRET'}))


def test_complete_runtime_schema_matches_published_contract():
    import json
    from pathlib import Path
    from threat_intel_mcp.normalize import _IOC_NETWORK_SCHEMA
    root = Path(__file__).resolve().parents[2]
    published = json.loads((root / "skills/cyber-threat-intel/schemas/output.schema.json").read_text())
    assert _IOC_NETWORK_SCHEMA == published["definitions"]["ioc_network"]


@pytest.mark.asyncio
async def test_discovery_retains_access_limited_integrations():
    import json
    from importlib.resources import files
    from threat_intel_mcp.server import list_available_feeds
    result = await list_available_feeds()
    registry = json.loads(files("threat_intel_mcp").joinpath("feed_status.json").read_text())
    feeds = {f["name"]: f for group in ("feeds", "cve_sources", "enrichment_sources") for f in result[group]}
    assert set(feeds) == set(registry)
    for name, feed in feeds.items():
        assert feed["tool"] == registry[name]["tool"]
        assert feed["integration_status"]["implemented"]
        assert not feed["integration_status"]["credential_presence_is_health_check"]
    assert feeds["ThreatFox"]["integration_status"]["verification_status"] == "known_endpoint_failure"
    assert all(name in feeds for name in ("ANY.RUN", "Intel 471", "Censys", "Pulsedive"))
