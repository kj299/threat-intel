"""threat-intel-mcp: MCP server for live threat intelligence feed integration.

Exposes Q-Feeds, AbuseIPDB, VirusTotal, and AlienVault OTX as MCP tools that
Claude can call to retrieve live IOCs and incorporate them into threat intelligence
reports using the threat-intel skill (kj299/threat-intel).

Transport: stdio (for use with Claude Code / Claude Desktop).
Run: threat-intel-mcp   (after `pip install -e .`)
Credentials: set VAULT_ADDR + VAULT_ROLE_ID + VAULT_SECRET_ID for HashiCorp Vault,
or QFEEDS_API_KEY / ABUSEIPDB_API_KEY / VT_API_KEY / OTX_API_KEY for env-var mode.
"""

from __future__ import annotations

import logging
import sys

from typing import Any

from mcp.server.fastmcp import FastMCP

from .adapters.abuseipdb import AbuseIPDBAdapter
from .adapters.otx import OTXAdapter
from .adapters.qfeeds import QFeedsAdapter, FEED_TYPES as QFEEDS_FEED_TYPES
from .adapters.virustotal import VirusTotalAdapter, FEED_TYPES as VT_FEED_TYPES
from .audit import log_tool_call
from .fanout import FeedSource, fan_out
from .normalize import deduplicate_iocs, validate_iocs
from .resilience import CircuitBreaker
from .vault.base import CredentialError
from .vault.factory import credential_provider_from_env

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

mcp = FastMCP(
    "threat-intel-mcp",
    instructions=(
        "Live threat intelligence feed tools. Call these to retrieve current IOCs "
        "from subscribed commercial feeds (Q-Feeds Tier 2, AbuseIPDB Tier 3, "
        "VirusTotal Tier 2, AlienVault OTX Tier 2). "
        "Use fetch_all_iocs to query every configured feed at once (concurrent, "
        "with per-source circuit breakers and merged deduplication), or call an "
        "individual feed tool for a single source. "
        "After calling a feed tool, pass the returned iocs array as context and set "
        "skill_input.feed_integrations in the threat-intel skill output so the "
        "Coverage Ledger (Appendix A) correctly marks the source as consulted."
    ),
)

# Initialise the credential provider and adapters at startup.
# Selects VaultCredentialProvider when VAULT_ADDR is set, else EnvCredentialProvider.
_credentials = credential_provider_from_env()
_qfeeds = QFeedsAdapter(_credentials)
_abuseipdb = AbuseIPDBAdapter(_credentials)
_virustotal = VirusTotalAdapter(_credentials)
_otx = OTXAdapter(_credentials)

# Fan-out registry: each source carries its own circuit breaker so one flaky
# feed cannot take down a fetch_all_iocs call. Credential/config errors are
# treated as non-retryable and surface as "unverified" in the Coverage Ledger.
_CONFIG_ERRORS: tuple[type[BaseException], ...] = (CredentialError, KeyError)
_FEED_SOURCES = [
    FeedSource(_qfeeds, 2, "Q-Feeds", CircuitBreaker("Q-Feeds"), _CONFIG_ERRORS),
    FeedSource(_abuseipdb, 3, "AbuseIPDB", CircuitBreaker("AbuseIPDB"), _CONFIG_ERRORS),
    FeedSource(_virustotal, 2, "VirusTotal", CircuitBreaker("VirusTotal"), _CONFIG_ERRORS),
    FeedSource(_otx, 2, "AlienVault OTX", CircuitBreaker("AlienVault OTX"), _CONFIG_ERRORS),
]


@mcp.tool()
async def qfeeds_fetch_iocs(
    time_range: str = "7d",
    feed_types: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch current malicious IP and domain indicators from Q-Feeds (Tier 2 CTI).

    Returns ioc_network objects in the threat-intel output.schema.json shape,
    ready to incorporate into a threat intelligence report. De-duplicated and
    schema-validated before return.

    Args:
        time_range: Lookback window from the calling threat-intel skill (e.g. "7d").
            Informational only — Q-Feeds always returns the current blocklist, not
            a historical window. Recorded in the result for the Coverage Ledger.
        feed_types: Feed types to fetch. Defaults to all available types.
            Available: malware_ip, malware_domains.

    Returns:
        dict with keys: iocs, source, tier, retrieved_at, record_count,
        latency_ms, feed_types_fetched, partial_failure, coverage_ledger_entry.

    Usage with the threat-intel skill:
        1. Call this tool; receive iocs.
        2. Pass iocs as context to the skill invocation.
        3. Set skill_input.feed_integrations = [{"name": "Q-Feeds", "tier": 2,
           "access_level": "premium"}] so the Coverage Ledger marks it consulted.
    """
    result = await _qfeeds.fetch(time_range=time_range, feed_types=feed_types)

    validated = validate_iocs(result.iocs)
    deduped = deduplicate_iocs(validated)

    status = "consulted"
    if result.partial_failure:
        status = "partial" if deduped else "unverified"

    return {
        "iocs": deduped,
        "source": result.source,
        "tier": result.tier,
        "retrieved_at": result.retrieved_at,
        "record_count": len(deduped),
        "latency_ms": result.latency_ms,
        "feed_types_fetched": result.feed_types_fetched,
        "partial_failure": result.partial_failure,
        "coverage_ledger_entry": {
            "tier": 2,
            "source": "Q-Feeds",
            "status": status,
        },
    }


@mcp.tool()
async def abuseipdb_fetch_blocklist(
    time_range: str = "7d",
    feed_types: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch the current AbuseIPDB IP blacklist (Tier 3 CTI).

    Returns ioc_network objects in the threat-intel output.schema.json shape,
    ready to incorporate into a threat intelligence report. De-duplicated and
    schema-validated before return.

    Args:
        time_range: Lookback window from the calling threat-intel skill (e.g. "7d").
            Informational only — AbuseIPDB always returns the current blacklist,
            not a historical window. Recorded in the result for the Coverage Ledger.
        feed_types: Accepted for interface compatibility; ignored (AbuseIPDB exposes
            a single blacklist endpoint).

    Returns:
        dict with keys: iocs, source, tier, retrieved_at, record_count,
        latency_ms, feed_types_fetched, partial_failure, coverage_ledger_entry.

    Usage with the threat-intel skill:
        1. Call this tool; receive iocs.
        2. Pass iocs as context to the skill invocation.
        3. Set skill_input.feed_integrations = [{"name": "AbuseIPDB", "tier": 3,
           "access_level": "free"}] so the Coverage Ledger marks it consulted.
    """
    try:
        result = await _abuseipdb.fetch(time_range=time_range, feed_types=feed_types)
    except (CredentialError, KeyError) as exc:
        logger.warning("AbuseIPDB credential error: %s", exc)
        return {
            "iocs": [],
            "source": "AbuseIPDB",
            "tier": 3,
            "retrieved_at": "",
            "record_count": 0,
            "latency_ms": 0.0,
            "feed_types_fetched": [],
            "partial_failure": ["blacklist"],
            "coverage_ledger_entry": {
                "tier": 3,
                "source": "AbuseIPDB",
                "status": "unverified",
            },
            "error": "AbuseIPDB credential not configured. Set ABUSEIPDB_API_KEY.",
        }

    validated = validate_iocs(result.iocs)
    deduped = deduplicate_iocs(validated)

    return {
        "iocs": deduped,
        "source": result.source,
        "tier": result.tier,
        "retrieved_at": result.retrieved_at,
        "record_count": len(deduped),
        "latency_ms": result.latency_ms,
        "feed_types_fetched": result.feed_types_fetched,
        "partial_failure": result.partial_failure,
        "coverage_ledger_entry": {
            "tier": 3,
            "source": "AbuseIPDB",
            "status": "consulted",
        },
    }


@mcp.tool()
async def virustotal_fetch_iocs(
    time_range: str = "7d",
    feed_types: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch recent malicious IP and domain indicators from VirusTotal (Tier 2 CTI).

    Returns ioc_network objects in the threat-intel output.schema.json shape,
    ready to incorporate into a threat intelligence report. De-duplicated and
    schema-validated before return.

    Requires a VirusTotal Intelligence subscription. Set VT_API_KEY (env-var mode)
    or configure the HashiCorp Vault path ``virustotal/api_key``.

    Args:
        time_range: Lookback window from the calling threat-intel skill (e.g. "7d").
            Informational only — VirusTotal feeds return a rolling window controlled
            by VT's own retention policy. Recorded in the result for the Coverage Ledger.
        feed_types: Feed types to fetch. Defaults to all available types.
            Available: malicious_ips, malicious_domains.

    Returns:
        dict with keys: iocs, source, tier, retrieved_at, record_count,
        latency_ms, feed_types_fetched, partial_failure, coverage_ledger_entry.

    Usage with the threat-intel skill:
        1. Call this tool; receive iocs.
        2. Pass iocs as context to the skill invocation.
        3. Set skill_input.feed_integrations = [{"name": "VirusTotal", "tier": 2,
           "access_level": "intelligence"}] so the Coverage Ledger marks it consulted.
    """
    try:
        result = await _virustotal.fetch(time_range=time_range, feed_types=feed_types)
    except (CredentialError, KeyError) as exc:
        logger.warning("VirusTotal credential error: %s", type(exc).__name__)
        return {
            "iocs": [],
            "source": "VirusTotal",
            "tier": 2,
            "retrieved_at": "",
            "record_count": 0,
            "latency_ms": 0.0,
            "feed_types_fetched": [],
            "partial_failure": feed_types or list(VT_FEED_TYPES.keys()),
            "coverage_ledger_entry": {
                "tier": 2,
                "source": "VirusTotal",
                "status": "unverified",
            },
            "error": "VT_API_KEY credential not configured",
        }

    validated = validate_iocs(result.iocs)
    deduped = deduplicate_iocs(validated)

    status = "consulted"
    if result.partial_failure:
        status = "partial" if deduped else "unverified"

    return {
        "iocs": deduped,
        "source": result.source,
        "tier": result.tier,
        "retrieved_at": result.retrieved_at,
        "record_count": len(deduped),
        "latency_ms": result.latency_ms,
        "feed_types_fetched": result.feed_types_fetched,
        "partial_failure": result.partial_failure,
        "coverage_ledger_entry": {
            "tier": 2,
            "source": "VirusTotal",
            "status": status,
        },
    }


@mcp.tool()
async def otx_fetch_iocs(
    time_range: str = "7d",
    feed_types: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch threat indicators from AlienVault OTX subscribed pulses (Tier 2 CTI).

    Retrieves indicators from pulses modified within the given time_range,
    returning ioc_network objects in the threat-intel output.schema.json shape.
    De-duplicated and schema-validated before return.

    Args:
        time_range: Lookback window, e.g. "7d" or "24h". OTX is queried with
            modified_since = now - time_range.
        feed_types: Accepted for interface compatibility; OTX does not segment
            by feed type. Pass None or omit.

    Returns:
        dict with keys: iocs, source, tier, retrieved_at, record_count,
        latency_ms, feed_types_fetched, partial_failure, coverage_ledger_entry.

    Usage with the threat-intel skill:
        1. Call this tool; receive iocs.
        2. Pass iocs as context to the skill invocation.
        3. Set skill_input.feed_integrations = [{"name": "AlienVault OTX", "tier": 2,
           "access_level": "community"}] so the Coverage Ledger marks it consulted.
    """
    try:
        result = await _otx.fetch(time_range=time_range, feed_types=feed_types)
    except (CredentialError, KeyError) as exc:
        logger.warning("OTX credential error: %s", exc)
        return {
            "iocs": [],
            "source": "AlienVault OTX",
            "tier": 2,
            "retrieved_at": "",
            "record_count": 0,
            "latency_ms": 0.0,
            "feed_types_fetched": [],
            "partial_failure": ["subscribed"],
            "coverage_ledger_entry": {
                "tier": 2,
                "source": "AlienVault OTX",
                "status": "unverified",
            },
            "error": "OTX credentials not configured. Set OTX_API_KEY environment variable.",
        }

    validated = validate_iocs(result.iocs)
    deduped = deduplicate_iocs(validated)

    status = "consulted"
    if result.partial_failure:
        status = "partial" if deduped else "unverified"

    return {
        "iocs": deduped,
        "source": result.source,
        "tier": result.tier,
        "retrieved_at": result.retrieved_at,
        "record_count": len(deduped),
        "latency_ms": result.latency_ms,
        "feed_types_fetched": result.feed_types_fetched,
        "partial_failure": result.partial_failure,
        "coverage_ledger_entry": {
            "tier": 2,
            "source": "AlienVault OTX",
            "status": status,
        },
    }


@mcp.tool()
async def fetch_all_iocs(time_range: str = "7d") -> dict[str, Any]:
    """Fetch and merge IOCs from ALL configured feeds concurrently (Tier 2-3 CTI).

    Queries Q-Feeds, AbuseIPDB, VirusTotal, and AlienVault OTX at the same time,
    schema-validates and deduplicates each source, then merges everything into a
    single deduplicated ioc_network array (cross-source duplicates collapse to the
    highest-confidence copy). Each source is guarded by its own circuit breaker and
    bounded backoff retry, so one slow or failing feed degrades to an "unverified"
    Coverage-Ledger entry instead of failing the whole call.

    Prefer this over calling each feed tool serially: a typical report touches all
    four feeds, and concurrent fan-out keeps total latency near the slowest single
    feed rather than the sum.

    Args:
        time_range: Lookback window from the calling threat-intel skill (e.g. "7d").
            Forwarded to each adapter; feeds that only expose a current blocklist
            record it for the Coverage Ledger but return their live set.

    Returns:
        dict with keys: iocs (merged + deduplicated), record_count, retrieved_at,
        latency_ms, sources_consulted, sources_degraded, per_source (compact
        per-feed breakdown), and coverage_ledger (ready for Appendix A).

    Usage with the threat-intel skill:
        1. Call this tool once; receive the merged iocs and coverage_ledger.
        2. Pass iocs as context to the skill invocation.
        3. Set skill_input.feed_integrations from sources_consulted so the
           Coverage Ledger marks each consulted source correctly; degraded
           sources map to "unverified".
    """
    result = await fan_out(_FEED_SOURCES, time_range=time_range)

    degraded = result["sources_degraded"]
    log_tool_call(
        "fetch_all_iocs",
        {"time_range": time_range},
        record_count=result["record_count"],
        latency_ms=result["latency_ms"],
        status="partial" if degraded else "ok",
        error=(
            f"degraded sources: {[d['source'] for d in degraded]}" if degraded else None
        ),
    )
    return result


@mcp.tool()
async def list_available_feeds() -> dict[str, Any]:
    """List the threat intelligence feeds available in this MCP server instance.

    Returns each feed's name, tier, supported feed_types, and whether credentials
    are currently configured.
    """
    qfeeds_cred_ok = True
    try:
        _credentials.get("qfeeds", "api_key")
    except (KeyError, CredentialError):
        qfeeds_cred_ok = False

    abuseipdb_cred_ok = True
    try:
        _credentials.get("abuseipdb", "api_key")
    except (KeyError, CredentialError):
        abuseipdb_cred_ok = False

    vt_cred_ok = True
    try:
        _credentials.get("virustotal", "api_key")
    except (KeyError, CredentialError):
        vt_cred_ok = False

    otx_cred_ok = True
    try:
        _credentials.get("otx", "api_key")
    except (KeyError, CredentialError):
        otx_cred_ok = False

    return {
        "feeds": [
            {
                "name": "Q-Feeds",
                "tier": 2,
                "domain": "qfeeds.com",
                "description": "Real-time IP/domain CTI feeds, MITRE ATT&CK mapped, 2500+ sources",
                "feed_types": list(QFEEDS_FEED_TYPES.keys()),
                "credential_configured": qfeeds_cred_ok,
                "tool": "qfeeds_fetch_iocs",
            },
            {
                "name": "AbuseIPDB",
                "tier": 3,
                "domain": "abuseipdb.com",
                "description": "IP blacklist with crowd-sourced abuse reports; up to 10,000 IPs per request",
                "feed_types": ["blacklist"],
                "credential_configured": abuseipdb_cred_ok,
                "tool": "abuseipdb_fetch_blocklist",
            },
            {
                "name": "VirusTotal",
                "tier": 2,
                "domain": "virustotal.com",
                "description": "VirusTotal Intelligence feeds: recent malicious IPs and domains",
                "feed_types": list(VT_FEED_TYPES.keys()),
                "credential_configured": vt_cred_ok,
                "tool": "virustotal_fetch_iocs",
            },
            {
                "name": "AlienVault OTX",
                "tier": 2,
                "domain": "otx.alienvault.com",
                "description": "Community and commercial threat pulses with IP, domain, and URL indicators",
                "feed_types": ["subscribed"],
                "credential_configured": otx_cred_ok,
                "tool": "otx_fetch_iocs",
            },
        ],
        "aggregate_tool": "fetch_all_iocs",
        "aggregate_description": (
            "Queries all credential-configured feeds concurrently, with per-source "
            "circuit breakers and merged deduplication; degraded feeds surface as "
            "'unverified' in the returned coverage_ledger."
        ),
        "phase": "3 (Q-Feeds + AbuseIPDB + VirusTotal + AlienVault OTX + concurrent fan-out + HashiCorp Vault or env-var credentials)",
        "planned": ["Shodan", "Recorded Future"],
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
