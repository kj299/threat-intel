"""threat-intel-mcp: MCP server for live threat intelligence feed integration.

Exposes Q-Feeds, AbuseIPDB, VirusTotal, AlienVault OTX, Shodan, GreyNoise, ANY.RUN,
Intel 471, Censys, and the free abuse.ch feed ThreatFox as IOC tools, plus
the CVE feeds CISA KEV, NVD and VulnCheck KEV as vulnerability tools, that Claude can call to
retrieve live indicators/vulnerabilities and incorporate them into threat intelligence
reports using the threat-intel skill (kj299/threat-intel).

Transport: stdio (for use with Claude Code / Claude Desktop).
Run: threat-intel-mcp   (after `pip install -e .`)
Credentials: set VAULT_ADDR + VAULT_ROLE_ID + VAULT_SECRET_ID for HashiCorp Vault,
or QFEEDS_API_KEY / ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY / OTX_API_KEY / SHODAN_API_KEY /
GREYNOISE_API_KEY / ANYRUN_API_KEY / INTEL471_EMAIL + INTEL471_API_KEY /
CENSYS_API_ID + CENSYS_API_SECRET / VULNCHECK_API_KEY for env-var mode.
"""

from __future__ import annotations

import logging
import sys

from typing import Any

# mcp 2.0.0 removed mcp.server.fastmcp; MCPServer is the successor and keeps
# a compatible .tool() decorator and .run() (stdio remains the default).
from mcp.server import MCPServer

from . import __version__
from .adapters.abuseipdb import AbuseIPDBAdapter
from .adapters.cisa_kev import CISAKEVAdapter, FEED_TYPES as CISA_KEV_FEED_TYPES
from .adapters.nvd import NVDAdapter, FEED_TYPES as NVD_FEED_TYPES
from .adapters.otx import OTXAdapter
from .adapters.qfeeds import QFeedsAdapter, FEED_TYPES as QFEEDS_FEED_TYPES
from .adapters.anyrun import AnyRunAdapter, FEED_TYPES as ANYRUN_FEED_TYPES
from .adapters.censys import CensysAdapter, FEED_TYPES as CENSYS_FEED_TYPES
from .adapters.greynoise import GreyNoiseAdapter, FEED_TYPES as GREYNOISE_FEED_TYPES
from .adapters.threatfox import ThreatFoxAdapter, FEED_TYPES as THREATFOX_FEED_TYPES
from .adapters.intel471 import Intel471Adapter, FEED_TYPES as INTEL471_FEED_TYPES
from .adapters.shodan import ShodanAdapter, FEED_TYPES as SHODAN_FEED_TYPES
from .adapters.virustotal import VirusTotalAdapter, FEED_TYPES as VT_FEED_TYPES
from .adapters.vulncheck import (
    VulnCheckAdapter,
    FEED_TYPES as VULNCHECK_FEED_TYPES,
)
from .audit import log_tool_call
from .fanout import FeedSource, fan_out
from .normalize import finalize_iocs
from .resilience import CircuitBreaker
from .vault.base import CredentialError
from .vault.factory import credential_provider_from_env
from .vulns import VulnFeedSource, fan_out_vulns, finalize_vulns

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

mcp = MCPServer(
    "threat-intel-mcp",
    # Without this the server advertises version "" in its initialize
    # response, so a client has no way to tell which build it is talking to.
    version=__version__,
    instructions=(
        "Live threat intelligence feed tools. Call these to retrieve current IOCs "
        "from subscribed commercial feeds (Q-Feeds Tier 2, AbuseIPDB Tier 3, "
        "VirusTotal Tier 2, AlienVault OTX Tier 2, Shodan Tier 3, GreyNoise Tier 3, "
        "ANY.RUN Tier 9, Intel 471 Tier 2, Censys Tier 3; plus the free abuse.ch "
        "feed ThreatFox Tier 9, no credential needed). "
        "For vulnerabilities, call the Tier 1 CVE feeds: CISA KEV and NVD are "
        "government sources needing no credential (NVD accepts an optional key "
        "for a higher rate limit), and VulnCheck KEV is a vendor catalogue that "
        "requires one. Use cisa_kev_fetch_cves / nvd_fetch_cves / "
        "vulncheck_fetch_cves, or fetch_all_cves for all three at once — these "
        "return CVE-keyed vulnerability records, not IOCs. "
        "Use fetch_all_iocs to query every configured IOC feed at once (concurrent, "
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
_shodan = ShodanAdapter(_credentials)
_greynoise = GreyNoiseAdapter(_credentials)
_threatfox = ThreatFoxAdapter()  # public feed, no credential
_anyrun = AnyRunAdapter(_credentials)
_intel471 = Intel471Adapter(_credentials)
_censys = CensysAdapter(_credentials)
_cisa_kev = CISAKEVAdapter()  # public feed, no credential
_nvd = NVDAdapter(_credentials)  # credential optional (higher rate limit if set)
_vulncheck = VulnCheckAdapter(_credentials)  # community KEV; credential required

# Fan-out registry: each source carries its own circuit breaker so one flaky
# feed cannot take down a fetch_all_iocs call. Credential/config errors are
# treated as non-retryable and surface as "unverified" in the Coverage Ledger.
# ValueError covers caller mistakes (bad time_range / feed_types) — not an
# upstream-health signal, so it must not trip a breaker or be retried.
_CONFIG_ERRORS: tuple[type[BaseException], ...] = (CredentialError, KeyError, ValueError)


def _degraded_tool_result(
    source: str, tier: int, partial: list[str], error: str
) -> dict[str, Any]:
    """Uniform degraded response for a single-feed tool that could not fetch."""
    return {
        "iocs": [],
        "source": source,
        "tier": tier,
        "retrieved_at": "",
        "record_count": 0,
        "latency_ms": 0.0,
        "feed_types_fetched": [],
        "partial_failure": partial,
        "coverage_ledger_entry": {
            "tier": tier,
            "source": source,
            "status": "unverified",
        },
        "error": error,
    }


_FEED_SOURCES = [
    FeedSource(_qfeeds, 2, "Q-Feeds", CircuitBreaker("Q-Feeds"), _CONFIG_ERRORS),
    FeedSource(_abuseipdb, 3, "AbuseIPDB", CircuitBreaker("AbuseIPDB"), _CONFIG_ERRORS),
    FeedSource(_virustotal, 2, "VirusTotal", CircuitBreaker("VirusTotal"), _CONFIG_ERRORS),
    FeedSource(_otx, 2, "AlienVault OTX", CircuitBreaker("AlienVault OTX"), _CONFIG_ERRORS),
    FeedSource(_shodan, 3, "Shodan", CircuitBreaker("Shodan"), _CONFIG_ERRORS),
    FeedSource(_greynoise, 3, "GreyNoise", CircuitBreaker("GreyNoise"), _CONFIG_ERRORS),
    FeedSource(_anyrun, 9, "ANY.RUN", CircuitBreaker("ANY.RUN"), _CONFIG_ERRORS),
    FeedSource(_intel471, 2, "Intel 471", CircuitBreaker("Intel 471"), _CONFIG_ERRORS),
    FeedSource(_censys, 3, "Censys", CircuitBreaker("Censys"), _CONFIG_ERRORS),
    FeedSource(_threatfox, 9, "ThreatFox", CircuitBreaker("ThreatFox"), _CONFIG_ERRORS),
]

# Vulnerability feeds emit CVE-keyed vuln records (see vulns.py), not
# ioc_network indicators, so they run through their own fan-out/dedup path and
# a separate aggregate tool (fetch_all_cves).
#
# All three are Tier 1 -- the tier names a data category ("Vulnerability
# Databases & Exploit Repositories"), not an operator, so VulnCheck sits here
# beside the two government sources rather than in Tier 2. The two KEV catalogs
# are complements: finalize_vulns dedupes by CVE ID and preserves corroboration,
# so a CVE in both becomes one record naming both sources.
_VULN_SOURCES = [
    VulnFeedSource(_cisa_kev, 1, "CISA KEV", CircuitBreaker("CISA KEV"), _CONFIG_ERRORS),
    VulnFeedSource(_nvd, 1, "NVD", CircuitBreaker("NVD"), _CONFIG_ERRORS),
    VulnFeedSource(
        _vulncheck, 1, "VulnCheck KEV", CircuitBreaker("VulnCheck KEV"), _CONFIG_ERRORS
    ),
]


def _degraded_vuln_result(
    source: str, tier: int, partial: list[str], error: str
) -> dict[str, Any]:
    """Uniform degraded response for a single vuln-feed tool that could not fetch."""
    return {
        "vulns": [],
        "source": source,
        "tier": tier,
        "retrieved_at": "",
        "record_count": 0,
        "latency_ms": 0.0,
        "feed_types_fetched": [],
        "partial_failure": partial,
        "coverage_ledger_entry": {
            "tier": tier,
            "source": source,
            "status": "unverified",
        },
        "error": error,
    }


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
    try:
        result = await _qfeeds.fetch(time_range=time_range, feed_types=feed_types)
    except (CredentialError, KeyError) as exc:
        logger.warning("Q-Feeds credential error: %s", type(exc).__name__)
        return _degraded_tool_result(
            "Q-Feeds",
            2,
            feed_types or list(QFEEDS_FEED_TYPES.keys()),
            "Q-Feeds credential not configured. Set QFEEDS_API_KEY.",
        )
    except ValueError:
        raise  # invalid feed_types — a caller error worth surfacing verbatim
    except Exception as exc:
        logger.warning("Q-Feeds upstream fetch failed: %s", type(exc).__name__)
        return _degraded_tool_result(
            "Q-Feeds",
            2,
            feed_types or list(QFEEDS_FEED_TYPES.keys()),
            f"upstream fetch failed: {type(exc).__name__}",
        )

    deduped = finalize_iocs(result.iocs)

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
    except ValueError:
        # Caller error: surface verbatim, never degrade (adapters/base.py
        # taxonomy). The adapter ignores time_range/feed_types today so this
        # cannot fire yet; it is here so the tool matches the other nine and a
        # future validation in the adapter does not get swallowed into a
        # misleading `unverified`.
        raise
    except (CredentialError, KeyError) as exc:
        logger.warning("AbuseIPDB credential error: %s", type(exc).__name__)
        return _degraded_tool_result(
            "AbuseIPDB",
            3,
            ["blacklist"],
            "AbuseIPDB credential not configured. Set ABUSEIPDB_API_KEY.",
        )
    except Exception as exc:
        logger.warning("AbuseIPDB upstream fetch failed: %s", type(exc).__name__)
        return _degraded_tool_result(
            "AbuseIPDB", 3, ["blacklist"], f"upstream fetch failed: {type(exc).__name__}"
        )

    deduped = finalize_iocs(result.iocs)

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

    Requires a VirusTotal Intelligence subscription. Set VIRUSTOTAL_API_KEY (env-var mode)
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
        return _degraded_tool_result(
            "VirusTotal",
            2,
            feed_types or list(VT_FEED_TYPES.keys()),
            "VIRUSTOTAL_API_KEY credential not configured",
        )
    except ValueError:
        raise  # invalid feed_types — a caller error worth surfacing verbatim
    except Exception as exc:
        logger.warning("VirusTotal upstream fetch failed: %s", type(exc).__name__)
        return _degraded_tool_result(
            "VirusTotal",
            2,
            feed_types or list(VT_FEED_TYPES.keys()),
            f"upstream fetch failed: {type(exc).__name__}",
        )

    deduped = finalize_iocs(result.iocs)

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
        logger.warning("OTX credential error: %s", type(exc).__name__)
        return _degraded_tool_result(
            "AlienVault OTX",
            2,
            ["subscribed"],
            "OTX credentials not configured. Set OTX_API_KEY environment variable.",
        )
    except ValueError:
        raise  # invalid time_range — a caller error worth surfacing verbatim
    except Exception as exc:
        logger.warning("OTX upstream fetch failed: %s", type(exc).__name__)
        return _degraded_tool_result(
            "AlienVault OTX",
            2,
            ["subscribed"],
            f"upstream fetch failed: {type(exc).__name__}",
        )

    deduped = finalize_iocs(result.iocs)

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
async def shodan_fetch_iocs(
    time_range: str = "7d",
    feed_types: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch malware C2 / infrastructure detections from Shodan (Tier 3 CTI).

    Queries Shodan's documented search API for hosts flagged by its Malware
    Hunter crawlers (category:malware) and returns ioc_network objects in the
    threat-intel output.schema.json shape. De-duplicated and schema-validated
    before return. Detections are crawler heuristics, so IOCs carry
    action=alert (investigate, don't auto-block).

    Requires a Shodan membership/API plan with query credits. Set
    SHODAN_API_KEY (env-var mode) or Vault path ``shodan/api_key``.

    Args:
        time_range: Lookback window from the calling threat-intel skill (e.g.
            "7d"). Informational only — Shodan search reflects the crawlers'
            current view; each IOC's last_seen carries the crawl timestamp.
        feed_types: Feed types to fetch. Defaults to all available types.
            Available: malware_c2.

    Returns:
        dict with keys: iocs, source, tier, retrieved_at, record_count,
        latency_ms, feed_types_fetched, partial_failure, coverage_ledger_entry.

    Usage with the threat-intel skill:
        1. Call this tool; receive iocs.
        2. Pass iocs as context to the skill invocation.
        3. Set skill_input.feed_integrations = [{"name": "Shodan", "tier": 3,
           "access_level": "membership"}] so the Coverage Ledger marks it consulted.
    """
    try:
        result = await _shodan.fetch(time_range=time_range, feed_types=feed_types)
    except (CredentialError, KeyError) as exc:
        logger.warning("Shodan credential error: %s", type(exc).__name__)
        return _degraded_tool_result(
            "Shodan",
            3,
            feed_types or list(SHODAN_FEED_TYPES.keys()),
            "Shodan credential not configured. Set SHODAN_API_KEY.",
        )
    except ValueError:
        raise  # invalid feed_types — a caller error worth surfacing verbatim
    except Exception as exc:
        logger.warning("Shodan upstream fetch failed: %s", type(exc).__name__)
        return _degraded_tool_result(
            "Shodan",
            3,
            feed_types or list(SHODAN_FEED_TYPES.keys()),
            f"upstream fetch failed: {type(exc).__name__}",
        )

    deduped = finalize_iocs(result.iocs)

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
            "tier": 3,
            "source": "Shodan",
            "status": status,
        },
    }


@mcp.tool()
async def greynoise_fetch_iocs(
    time_range: str = "7d",
    feed_types: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch GreyNoise malicious-scanner IPs (Tier 3 CTI).

    Runs a GNQL ``classification:malicious`` search and returns the confirmed-
    malicious internet scanners/attackers as ioc_network objects in the
    threat-intel output.schema.json shape. De-duplicated and schema-validated
    before return. GreyNoise's "malicious" is its own high-confidence verdict,
    so IOCs carry confidence=High and action=block.

    Requires a GreyNoise Enterprise/GNQL subscription. Set GREYNOISE_API_KEY
    (env-var mode) or the Vault path ``greynoise/api_key``.

    Args:
        time_range: Lookback window (e.g. "7d"); folded into the GNQL query as a
            last_seen filter when expressed in days.
        feed_types: Feed types to fetch. Defaults to all available types.
            Available: malicious_scanners.

    Returns:
        dict with keys: iocs, source, tier, retrieved_at, record_count,
        latency_ms, feed_types_fetched, partial_failure, coverage_ledger_entry.

    Usage with the threat-intel skill:
        1. Call this tool; receive iocs.
        2. Pass iocs as context to the skill invocation.
        3. Set skill_input.feed_integrations = [{"name": "GreyNoise", "tier": 3,
           "access_level": "enterprise"}] so the Coverage Ledger marks it consulted.
    """
    try:
        result = await _greynoise.fetch(time_range=time_range, feed_types=feed_types)
    except (CredentialError, KeyError) as exc:
        logger.warning("GreyNoise credential error: %s", type(exc).__name__)
        return _degraded_tool_result(
            "GreyNoise",
            3,
            feed_types or list(GREYNOISE_FEED_TYPES.keys()),
            "GreyNoise credential not configured. Set GREYNOISE_API_KEY.",
        )
    except ValueError:
        raise  # invalid feed_types — a caller error worth surfacing verbatim
    except Exception as exc:
        logger.warning("GreyNoise upstream fetch failed: %s", type(exc).__name__)
        return _degraded_tool_result(
            "GreyNoise",
            3,
            feed_types or list(GREYNOISE_FEED_TYPES.keys()),
            f"upstream fetch failed: {type(exc).__name__}",
        )

    deduped = finalize_iocs(result.iocs)

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
            "tier": 3,
            "source": "GreyNoise",
            "status": status,
        },
    }


@mcp.tool()
async def anyrun_fetch_iocs(
    time_range: str = "7d",
    feed_types: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch ANY.RUN TAXII/STIX malicious network indicators (Tier 9 CTI).

    Returns ioc_network objects in the threat-intel output.schema.json shape,
    de-duplicated and schema-validated before return.
    Requires an ANY.RUN TI subscription. Set ANYRUN_API_KEY (the full
    Authorization value). Feed types: ip, domain, url.

    Returns:
        dict with keys: iocs, source, tier, retrieved_at, record_count,
        latency_ms, feed_types_fetched, partial_failure, coverage_ledger_entry.
    """
    try:
        result = await _anyrun.fetch(time_range=time_range, feed_types=feed_types)
    except (CredentialError, KeyError) as exc:
        logger.warning("ANY.RUN credential error: %s", type(exc).__name__)
        return _degraded_tool_result(
            "ANY.RUN", 9, feed_types or list(ANYRUN_FEED_TYPES.keys()),
            "ANY.RUN credential not configured. Set ANYRUN_API_KEY.",
        )
    except ValueError:
        raise
    except Exception as exc:
        logger.warning("ANY.RUN upstream fetch failed: %s", type(exc).__name__)
        return _degraded_tool_result(
            "ANY.RUN", 9, feed_types or list(ANYRUN_FEED_TYPES.keys()),
            f"upstream fetch failed: {type(exc).__name__}",
        )

    deduped = finalize_iocs(result.iocs)
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
        "coverage_ledger_entry": {"tier": 9, "source": "ANY.RUN", "status": status},
    }


@mcp.tool()
async def intel471_fetch_iocs(
    time_range: str = "7d",
    feed_types: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch Intel 471 malware network indicators (Tier 2 CTI).

    Returns ioc_network objects in the threat-intel output.schema.json shape,
    de-duplicated and schema-validated before return.
    Requires an Intel 471 subscription. Set INTEL471_EMAIL + INTEL471_API_KEY
    (HTTP Basic). Maps IP and URL indicators; file hashes are skipped.

    Returns:
        dict with keys: iocs, source, tier, retrieved_at, record_count,
        latency_ms, feed_types_fetched, partial_failure, coverage_ledger_entry.
    """
    try:
        result = await _intel471.fetch(time_range=time_range, feed_types=feed_types)
    except (CredentialError, KeyError) as exc:
        logger.warning("Intel 471 credential error: %s", type(exc).__name__)
        return _degraded_tool_result(
            "Intel 471", 2, feed_types or list(INTEL471_FEED_TYPES.keys()),
            "Intel 471 credentials not configured. Set INTEL471_EMAIL and INTEL471_API_KEY.",
        )
    except ValueError:
        raise
    except Exception as exc:
        logger.warning("Intel 471 upstream fetch failed: %s", type(exc).__name__)
        return _degraded_tool_result(
            "Intel 471", 2, feed_types or list(INTEL471_FEED_TYPES.keys()),
            f"upstream fetch failed: {type(exc).__name__}",
        )

    deduped = finalize_iocs(result.iocs)
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
        "coverage_ledger_entry": {"tier": 2, "source": "Intel 471", "status": status},
    }


@mcp.tool()
async def censys_fetch_iocs(
    time_range: str = "7d",
    feed_types: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch Censys malware/C2-labelled infrastructure hosts (Tier 3 CTI).

    Returns ioc_network objects in the threat-intel output.schema.json shape,
    de-duplicated and schema-validated before return.
    Requires a Censys subscription. Set CENSYS_API_ID + CENSYS_API_SECRET.
    Detections are attack-surface observations, so IOCs carry action=alert.

    Returns:
        dict with keys: iocs, source, tier, retrieved_at, record_count,
        latency_ms, feed_types_fetched, partial_failure, coverage_ledger_entry.
    """
    try:
        result = await _censys.fetch(time_range=time_range, feed_types=feed_types)
    except (CredentialError, KeyError) as exc:
        logger.warning("Censys credential error: %s", type(exc).__name__)
        return _degraded_tool_result(
            "Censys", 3, feed_types or list(CENSYS_FEED_TYPES.keys()),
            "Censys credentials not configured. Set CENSYS_API_ID and CENSYS_API_SECRET.",
        )
    except ValueError:
        raise
    except Exception as exc:
        logger.warning("Censys upstream fetch failed: %s", type(exc).__name__)
        return _degraded_tool_result(
            "Censys", 3, feed_types or list(CENSYS_FEED_TYPES.keys()),
            f"upstream fetch failed: {type(exc).__name__}",
        )

    deduped = finalize_iocs(result.iocs)
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
        "coverage_ledger_entry": {"tier": 3, "source": "Censys", "status": status},
    }


@mcp.tool()
async def threatfox_fetch_iocs(
    time_range: str = "7d",
    feed_types: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch IOCs from ThreatFox — the free, public abuse.ch feed (Tier 9 CTI).

    Recent malicious network IOCs (IPs/domains/URLs; hashes excluded, action=block). Returns ioc_network objects in the threat-intel output.schema.json
    shape. De-duplicated and schema-validated before return. **No credential
    required** — this is a public feed.

    Args:
        time_range: Lookback window; informational only (the feed is a fixed
            "recent" window). Recorded for the Coverage Ledger.
        feed_types: Defaults to all available. Available: recent_iocs.

    Returns:
        dict with keys: iocs, source, tier, retrieved_at, record_count,
        latency_ms, feed_types_fetched, partial_failure, coverage_ledger_entry.

    Usage with the threat-intel skill:
        1. Call this tool; receive iocs.
        2. Pass iocs as context to the skill invocation.
        3. Set skill_input.feed_integrations = [{"name": "ThreatFox", "tier": 9,
           "access_level": "public"}] so the Coverage Ledger marks it consulted.
    """
    try:
        result = await _threatfox.fetch(time_range=time_range, feed_types=feed_types)
    except ValueError:
        raise  # invalid feed_types — a caller error worth surfacing verbatim
    except Exception as exc:
        logger.warning("ThreatFox upstream fetch failed: %s", type(exc).__name__)
        return _degraded_tool_result(
            "ThreatFox",
            9,
            feed_types or list(THREATFOX_FEED_TYPES.keys()),
            f"upstream fetch failed: {type(exc).__name__}",
        )

    deduped = finalize_iocs(result.iocs)
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
            "tier": 9,
            "source": "ThreatFox",
            "status": status,
        },
    }


@mcp.tool()
async def fetch_all_iocs(time_range: str = "7d") -> dict[str, Any]:
    """Fetch and merge IOCs from ALL configured feeds concurrently (Tier 2-3 CTI).

    Queries all configured feeds (Q-Feeds, AbuseIPDB, VirusTotal, AlienVault OTX,
    Shodan, GreyNoise, ANY.RUN, Intel 471, Censys) at the same time,
    schema-validates and deduplicates each source, then merges everything into a
    single deduplicated ioc_network array (cross-source duplicates collapse to the
    highest-confidence copy). Each source is guarded by its own circuit breaker and
    bounded backoff retry, so one slow or failing feed degrades to an "unverified"
    Coverage-Ledger entry instead of failing the whole call.

    Prefer this over calling each feed tool serially: a typical report touches
    many feeds, and concurrent fan-out keeps total latency near the slowest single
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
async def cisa_kev_fetch_cves(
    time_range: str = "7d",
    feed_types: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch the CISA Known Exploited Vulnerabilities (KEV) catalog (Tier 1 gov).

    Returns vulnerability records (NOT ioc_network objects) keyed by CVE ID:
    every entry is a CVE with confirmed in-the-wild exploitation, carrying
    exploit_status=known_exploited plus the KEV due-date, required action, and
    ransomware-campaign flag. Sanitised, schema-validated, and de-duplicated by
    CVE ID before return. **No credential required** — public government feed.

    Args:
        time_range: Accepted for interface compatibility; the KEV catalog is a
            full standing list, not a time-windowed feed, so it is recorded for
            the Coverage Ledger but does not filter results.
        feed_types: Defaults to all available. Available: kev_catalog.

    Returns:
        dict with keys: vulns, source, tier, retrieved_at, record_count,
        latency_ms, feed_types_fetched, partial_failure, coverage_ledger_entry.

    Usage with the threat-intel skill:
        1. Call this tool; receive vulns.
        2. Pass vulns as context to the skill invocation (vulnerability section).
        3. Set skill_input.feed_integrations = [{"name": "CISA KEV", "tier": 1,
           "access_level": "public"}] so the Coverage Ledger marks it consulted.
    """
    try:
        result = await _cisa_kev.fetch(time_range=time_range, feed_types=feed_types)
    except ValueError:
        raise  # invalid feed_types — a caller error worth surfacing verbatim
    except Exception as exc:
        logger.warning("CISA KEV upstream fetch failed: %s", type(exc).__name__)
        return _degraded_vuln_result(
            "CISA KEV",
            1,
            feed_types or list(CISA_KEV_FEED_TYPES.keys()),
            f"upstream fetch failed: {type(exc).__name__}",
        )

    finalized = finalize_vulns(result.vulns)
    status = "consulted"
    if result.partial_failure:
        status = "partial" if finalized else "unverified"
    return {
        "vulns": finalized,
        "source": result.source,
        "tier": result.tier,
        "retrieved_at": result.retrieved_at,
        "record_count": len(finalized),
        "latency_ms": result.latency_ms,
        "feed_types_fetched": result.feed_types_fetched,
        "partial_failure": result.partial_failure,
        "coverage_ledger_entry": {
            "tier": 1,
            "source": "CISA KEV",
            "status": status,
        },
    }


@mcp.tool()
async def vulncheck_fetch_cves(
    time_range: str = "7d",
    feed_types: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch the VulnCheck KEV catalog (Tier 1 vulnerability database).

    Returns vulnerability records (NOT ioc_network objects) keyed by CVE ID.
    Every entry is reported as exploited in the wild, carrying
    exploit_status=known_exploited plus the URLs that reported the exploitation.
    Sanitised, schema-validated, and de-duplicated by CVE ID before return.

    Complements cisa_kev_fetch_cves rather than replacing it: VulnCheck's
    catalog is broader than the U.S. binding-directive list, and a CVE in both
    de-duplicates into one record naming both sources.

    **Credential required**: VULNCHECK_API_KEY (free community tier).

    Args:
        time_range: Accepted for interface compatibility; a KEV catalog is a
            full standing list, not a time-windowed feed, so it is recorded for
            the Coverage Ledger but does not filter results.
        feed_types: Defaults to all available. Available: kev_catalog.

    Returns:
        dict with keys: vulns, source, tier, retrieved_at, record_count,
        latency_ms, feed_types_fetched, partial_failure, coverage_ledger_entry.

    Usage with the threat-intel skill:
        1. Call this tool; receive vulns.
        2. Pass vulns as context to the skill invocation (vulnerability section).
        3. Set skill_input.feed_integrations = [{"name": "VulnCheck KEV",
           "tier": 1, "access_level": "community"}] so the Coverage Ledger marks
           it consulted.
    """
    try:
        result = await _vulncheck.fetch(time_range=time_range, feed_types=feed_types)
    except ValueError:
        raise  # invalid feed_types — a caller error worth surfacing verbatim
    except (CredentialError, KeyError) as exc:
        logger.warning("VulnCheck credential error: %s", type(exc).__name__)
        return _degraded_vuln_result(
            "VulnCheck KEV",
            1,
            feed_types or list(VULNCHECK_FEED_TYPES.keys()),
            "VulnCheck credential not configured. Set VULNCHECK_API_KEY.",
        )
    except Exception as exc:
        logger.warning("VulnCheck upstream fetch failed: %s", type(exc).__name__)
        return _degraded_vuln_result(
            "VulnCheck KEV",
            1,
            feed_types or list(VULNCHECK_FEED_TYPES.keys()),
            f"upstream fetch failed: {type(exc).__name__}",
        )

    finalized = finalize_vulns(result.vulns)
    status = "consulted"
    if result.partial_failure:
        status = "partial" if finalized else "unverified"
    return {
        "vulns": finalized,
        "source": result.source,
        "tier": result.tier,
        "retrieved_at": result.retrieved_at,
        "record_count": len(finalized),
        "latency_ms": result.latency_ms,
        "feed_types_fetched": result.feed_types_fetched,
        "partial_failure": result.partial_failure,
        "coverage_ledger_entry": {
            "tier": 1,
            "source": "VulnCheck KEV",
            "status": status,
        },
    }


@mcp.tool()
async def nvd_fetch_cves(
    time_range: str = "7d",
    feed_types: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch recently-modified CVEs from the NIST NVD 2.0 API (Tier 1 gov).

    Returns vulnerability records (NOT ioc_network objects) keyed by CVE ID,
    enriched with CVSS base score/severity, CWEs, and references. Sanitised,
    schema-validated, and de-duplicated by CVE ID before return. **Credential is
    optional** — NVD serves the API unauthenticated at a lower rate limit; set
    NVD_API_KEY (or Vault path ``nvd/api_key``) for the higher limit.

    Args:
        time_range: Lookback window (e.g. "7d", "24h") mapped to NVD's
            lastModStartDate/lastModEndDate. Capped at NVD's 120-day maximum
            window; sub-day windows round up to one day.
        feed_types: Defaults to all available. Available: recent_cves.

    Returns:
        dict with keys: vulns, source, tier, retrieved_at, record_count,
        latency_ms, feed_types_fetched, partial_failure, coverage_ledger_entry.

    Usage with the threat-intel skill:
        1. Call this tool; receive vulns.
        2. Pass vulns as context to the skill invocation (vulnerability section).
        3. Set skill_input.feed_integrations = [{"name": "NVD", "tier": 1,
           "access_level": "public"}] so the Coverage Ledger marks it consulted.
    """
    try:
        result = await _nvd.fetch(time_range=time_range, feed_types=feed_types)
    except (CredentialError, KeyError) as exc:
        # Only a provider *failure* (e.g. Vault outage) reaches here — a missing
        # key falls back to unauthenticated inside the adapter.
        logger.warning("NVD credential provider error: %s", type(exc).__name__)
        return _degraded_vuln_result(
            "NVD",
            1,
            feed_types or list(NVD_FEED_TYPES.keys()),
            "NVD credential provider unavailable",
        )
    except ValueError:
        raise  # invalid feed_types / time_range — a caller error, surface verbatim
    except Exception as exc:
        logger.warning("NVD upstream fetch failed: %s", type(exc).__name__)
        return _degraded_vuln_result(
            "NVD",
            1,
            feed_types or list(NVD_FEED_TYPES.keys()),
            f"upstream fetch failed: {type(exc).__name__}",
        )

    finalized = finalize_vulns(result.vulns)
    status = "consulted"
    if result.partial_failure:
        status = "partial" if finalized else "unverified"
    return {
        "vulns": finalized,
        "source": result.source,
        "tier": result.tier,
        "retrieved_at": result.retrieved_at,
        "record_count": len(finalized),
        "latency_ms": result.latency_ms,
        "feed_types_fetched": result.feed_types_fetched,
        "partial_failure": result.partial_failure,
        "coverage_ledger_entry": {
            "tier": 1,
            "source": "NVD",
            "status": status,
        },
    }


@mcp.tool()
async def fetch_all_cves(time_range: str = "7d") -> dict[str, Any]:
    """Fetch and merge CVE records from ALL vulnerability feeds concurrently (Tier 1).

    Queries the government CVE feeds (CISA KEV, NVD) at the same time,
    sanitises/validates/deduplicates each source, then merges everything into a
    single set de-duplicated by CVE ID (a CVE present in both keeps the
    highest-CVSS copy and gains a corroborated-by tag plus KEV's
    exploit_status/due-date enrichment). Each source is guarded by its own
    circuit breaker and bounded backoff retry, so one slow or failing feed
    degrades to an "unverified" Coverage-Ledger entry instead of failing the
    whole call.

    This is the vulnerability counterpart to fetch_all_iocs — use it to populate
    the vulnerability/exposure section of a threat-intel report, then use
    fetch_all_iocs for network indicators.

    Args:
        time_range: Lookback window (e.g. "7d") forwarded to each feed; KEV
            returns its full standing catalog, NVD filters by last-modified.

    Returns:
        dict with keys: vulns (merged + deduplicated), record_count,
        retrieved_at, latency_ms, sources_consulted, sources_degraded,
        per_source, and coverage_ledger (ready for Appendix A).

    Usage with the threat-intel skill:
        1. Call this tool once; receive the merged vulns and coverage_ledger.
        2. Pass vulns as context to the skill invocation.
        3. Set skill_input.feed_integrations from sources_consulted so the
           Coverage Ledger marks each consulted source correctly; degraded
           sources map to "unverified".
    """
    result = await fan_out_vulns(_VULN_SOURCES, time_range=time_range)

    degraded = result["sources_degraded"]
    log_tool_call(
        "fetch_all_cves",
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

    shodan_cred_ok = True
    try:
        _credentials.get("shodan", "api_key")
    except (KeyError, CredentialError):
        shodan_cred_ok = False

    greynoise_cred_ok = True
    try:
        _credentials.get("greynoise", "api_key")
    except (KeyError, CredentialError):
        greynoise_cred_ok = False

    anyrun_cred_ok = True
    try:
        _credentials.get("anyrun", "api_key")
    except (KeyError, CredentialError):
        anyrun_cred_ok = False

    intel471_cred_ok = True
    try:
        _credentials.get("intel471", "email")
        _credentials.get("intel471", "api_key")
    except (KeyError, CredentialError):
        intel471_cred_ok = False

    censys_cred_ok = True
    try:
        _credentials.get("censys", "api_id")
        _credentials.get("censys", "api_secret")
    except (KeyError, CredentialError):
        censys_cred_ok = False

    # NVD's API key is optional (unauthenticated access works at a lower rate
    # limit); report whether the higher-limit key is configured.
    nvd_cred_ok = True
    try:
        _credentials.get("nvd", "api_key")
    except (KeyError, CredentialError):
        nvd_cred_ok = False

    # VulnCheck's key is required, not optional: reported here so a caller can
    # see the feed exists but is unconfigured, rather than inferring it from a
    # degraded ledger entry after the fact.
    vulncheck_cred_ok = True
    try:
        _credentials.get("vulncheck", "api_key")
    except (KeyError, CredentialError):
        vulncheck_cred_ok = False

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
            {
                "name": "Shodan",
                "tier": 3,
                "domain": "shodan.io",
                "description": "Malware Hunter C2/infrastructure detections via documented search API (category:malware)",
                "feed_types": list(SHODAN_FEED_TYPES.keys()),
                "credential_configured": shodan_cred_ok,
                "tool": "shodan_fetch_iocs",
            },
            {
                "name": "GreyNoise",
                "tier": 3,
                "domain": "greynoise.io",
                "description": "GNQL classification:malicious — confirmed-malicious internet scanners/attackers",
                "feed_types": list(GREYNOISE_FEED_TYPES.keys()),
                "credential_configured": greynoise_cred_ok,
                "tool": "greynoise_fetch_iocs",
            },
            {
                "name": "ANY.RUN",
                "tier": 9,
                "domain": "any.run",
                "description": "TAXII 2.1 STIX feed of sandbox-derived malicious IPs, domains, and URLs",
                "feed_types": list(ANYRUN_FEED_TYPES.keys()),
                "credential_configured": anyrun_cred_ok,
                "tool": "anyrun_fetch_iocs",
            },
            {
                "name": "Intel 471",
                "tier": 2,
                "domain": "intel471.com",
                "description": "Titan malware indicators stream (IP + URL network indicators)",
                "feed_types": list(INTEL471_FEED_TYPES.keys()),
                "credential_configured": intel471_cred_ok,
                "tool": "intel471_fetch_iocs",
            },
            {
                "name": "Censys",
                "tier": 3,
                "domain": "censys.io",
                "description": "Search v2 hosts labelled malware/C2 (attack-surface observations, action=alert)",
                "feed_types": list(CENSYS_FEED_TYPES.keys()),
                "credential_configured": censys_cred_ok,
                "tool": "censys_fetch_iocs",
            },
            {
                "name": "ThreatFox",
                "tier": 9,
                "domain": "threatfox.abuse.ch",
                "description": "Free public feed of recent malicious IOCs, network types (no credential required)",
                "feed_types": list(THREATFOX_FEED_TYPES.keys()),
                "credential_configured": True,
                "tool": "threatfox_fetch_iocs",
            },
        ],
        "cve_sources": [
            {
                "name": "CISA KEV",
                "tier": 1,
                "domain": "cisa.gov",
                "description": "Known Exploited Vulnerabilities catalog — CVEs with confirmed in-the-wild exploitation (no credential required)",
                "feed_types": list(CISA_KEV_FEED_TYPES.keys()),
                "credential_configured": True,
                "tool": "cisa_kev_fetch_cves",
            },
            {
                "name": "NVD",
                "tier": 1,
                "domain": "nvd.nist.gov",
                "description": "NIST National Vulnerability Database CVE 2.0 API — recently-modified CVEs with CVSS, CWEs, references (credential optional)",
                "feed_types": list(NVD_FEED_TYPES.keys()),
                "credential_configured": nvd_cred_ok,
                "tool": "nvd_fetch_cves",
            },
            {
                "name": "VulnCheck KEV",
                "tier": 1,
                "domain": "vulncheck.com",
                "description": "VulnCheck Known Exploited Vulnerabilities catalog — broader than CISA KEV, carries the URLs reporting exploitation (credential required)",
                "feed_types": list(VULNCHECK_FEED_TYPES.keys()),
                "credential_configured": vulncheck_cred_ok,
                "tool": "vulncheck_fetch_cves",
            },
        ],
        "aggregate_tool": "fetch_all_iocs",
        "aggregate_description": (
            "Queries all credential-configured feeds concurrently, with per-source "
            "circuit breakers and merged deduplication; degraded feeds surface as "
            "'unverified' in the returned coverage_ledger."
        ),
        "cve_aggregate_tool": "fetch_all_cves",
        "cve_aggregate_description": (
            "Queries all government CVE feeds (CISA KEV, NVD) concurrently and "
            "merges into one set de-duplicated by CVE ID; degraded feeds surface "
            "as 'unverified' in the returned coverage_ledger. Emits vulnerability "
            "records (CVE-keyed), not ioc_network indicators."
        ),
        "phase": "5 (10 IOC feeds + 2 government CVE feeds: CISA KEV + NVD via a CVE-keyed vulnerability-output path; concurrent fan-out + hardening + HashiCorp Vault or env-var credentials)",
        "planned": ["Recorded Future (API docs are subscription-gated; adapter deferred until access is available)"],
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
