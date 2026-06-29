"""threat-intel-mcp: MCP server for live threat intelligence feed integration.

Exposes Q-Feeds, AbuseIPDB, VirusTotal (and future adapters) as MCP tools that
Claude can call to retrieve live IOCs and incorporate them into threat intelligence
reports using the threat-intel skill (kj299/threat-intel).

Transport: stdio (for use with Claude Code / Claude Desktop).
Run: threat-intel-mcp   (after `pip install -e .`)
Credentials: set VAULT_ADDR + VAULT_ROLE_ID + VAULT_SECRET_ID for HashiCorp Vault,
or QFEEDS_API_KEY / ABUSEIPDB_API_KEY / VT_API_KEY for env-var mode (dev / local only).
"""

from __future__ import annotations

import logging
import sys

from typing import Any

from mcp.server.fastmcp import FastMCP

from .adapters.abuseipdb import AbuseIPDBAdapter
from .adapters.qfeeds import QFeedsAdapter, FEED_TYPES as QFEEDS_FEED_TYPES
from .adapters.virustotal import VirusTotalAdapter, FEED_TYPES as VT_FEED_TYPES
from .normalize import deduplicate_iocs, validate_iocs
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
        "from subscribed commercial feeds (Q-Feeds Tier 2, AbuseIPDB Tier 3, VirusTotal Tier 2). "
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
        ],
        "phase": "3 (Q-Feeds + AbuseIPDB + VirusTotal + HashiCorp Vault or env-var credentials)",
        "planned": ["AlienVault OTX", "Shodan", "Recorded Future"],
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
