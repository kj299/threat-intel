"""Vulnerability-output pipeline: sanitise -> validate -> dedupe + fan-out.

This is the vulnerability counterpart to the ``ioc_network`` pipeline in
``normalize.py`` / ``fanout.py``. Government CVE feeds (CISA KEV, NVD) emit
*vulnerability records* keyed by CVE ID rather than network indicators, so they
need their own schema, sanitiser, deduplicator, and concurrent fan-out — the
``ioc_network`` schema has no place for a CVSS score or a KEV due-date.

The design deliberately mirrors the IOC path so the two share one mental model:

  - ``finalize_vulns`` = ``sanitize_vulns`` -> ``validate_vulns`` -> ``deduplicate_vulns``
    (same order-matters reasoning as ``finalize_iocs``: clean first so validation
    and dedup both run on cleaned values).
  - ``fan_out_vulns`` reuses the exact ``CircuitBreaker`` / ``guarded_fetch``
    resilience primitives, so a slow or failing CVE feed degrades to an
    "unverified" Coverage-Ledger entry instead of failing the whole call.

Dates are promoted to RFC 3339 date-time strings by the adapters (CISA KEV emits
bare ``YYYY-MM-DD`` dates), so a single ``date-time`` format check covers every
timestamp field — no second format-checker path.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import jsonschema

from .resilience import CircuitBreaker, CircuitOpenError, guarded_fetch
from .sanitize import _clean_str, _strip_chars

logger = logging.getLogger(__name__)

# Length caps for feed-controlled free-text. Descriptions are legitimately long
# (a full CVE summary), so they get a larger bound than the IOC annotation cap.
_MAX_TEXT_LEN = 512
_MAX_DESC_LEN = 4096
_MAX_SOURCE_LEN = 128
_MAX_URL_LEN = 2048
_MAX_LIST = 64


@dataclass
class VulnFetchResult:
    """Normalised result from a single vulnerability-feed fetch call.

    The vulnerability analogue of :class:`adapters.base.FetchResult`: it carries
    ``vulns`` (CVE-keyed records) instead of ``iocs`` (network indicators).
    """

    vulns: list[dict[str, Any]]
    source: str
    tier: int
    retrieved_at: str          # ISO 8601 UTC timestamp
    record_count: int
    latency_ms: float
    feed_types_fetched: list[str]
    partial_failure: list[str] = field(default_factory=list)


# Inline vulnerability-record schema. Kept deliberately small and independent of
# output.schema.json (which models ioc_network, not vulnerabilities). Only
# ``cve_id`` and ``source`` are required — a feed that can name a CVE and itself
# has said something worth recording; everything else is best-effort enrichment.
_VULN_RECORD_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["cve_id", "source"],
    "properties": {
        "cve_id": {"type": "string", "pattern": r"^CVE-\d{4}-\d{4,}$"},
        "source": {
            "type": "string",
            "minLength": 1,
            "not": {"enum": ["unknown", "general knowledge", "n/a"]},
        },
        "vulnerability_name": {"type": "string"},
        "description": {"type": "string"},
        "vendor_project": {"type": "string"},
        "product": {"type": "string"},
        "cvss_score": {"type": "number", "minimum": 0.0, "maximum": 10.0},
        "cvss_severity": {
            "type": "string",
            "enum": ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        },
        "cvss_version": {"type": "string"},
        "published": {"type": "string", "format": "date-time"},
        "last_modified": {"type": "string", "format": "date-time"},
        "date_added": {"type": "string", "format": "date-time"},
        "due_date": {"type": "string", "format": "date-time"},
        "known_ransomware_use": {"type": "string", "enum": ["Known", "Unknown"]},
        "required_action": {"type": "string"},
        "exploit_status": {
            "type": "string",
            "enum": ["known_exploited", "unknown"],
        },
        "cwes": {"type": "array", "items": {"type": "string"}},
        "references": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "minLength": 1},
                    "source": {"type": "string"},
                },
            },
        },
        "tags": {"type": "array", "items": {"type": "string"}},
        "tlp": {
            "type": "string",
            "enum": ["WHITE", "GREEN", "AMBER", "AMBER+STRICT", "RED"],
        },
    },
}

# FormatChecker enforces "date-time" at runtime (rfc3339-validator, already a
# dependency for the IOC path). Adapters promote bare dates to date-time so this
# single check covers every timestamp field.
_validator = jsonschema.Draft7Validator(
    _VULN_RECORD_SCHEMA, format_checker=jsonschema.FormatChecker()
)


def validate_vulns(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only vulnerability records that pass schema validation.

    Invalid records are logged and dropped — a malformed CVE record in the output
    (a bad CVE ID, an out-of-range CVSS score) is worse than a missing one.
    """
    valid: list[dict[str, Any]] = []
    for vuln in vulns:
        errors = list(_validator.iter_errors(vuln))
        if errors:
            logger.warning(
                "Dropping invalid vuln record (schema validation failed): "
                "cve_id=%r errors=%s",
                vuln.get("cve_id", "?"),
                [e.message for e in errors],
            )
        else:
            valid.append(vuln)
    return valid


def _clean_references(refs: Any) -> list[dict[str, str]]:
    """Sanitise a list of reference objects, dropping any without a clean URL."""
    if not isinstance(refs, list):
        return []
    cleaned: list[dict[str, str]] = []
    for ref in refs[:_MAX_LIST]:
        if not isinstance(ref, dict):
            continue
        raw_url = ref.get("url")
        if not isinstance(raw_url, str):
            continue
        url = _strip_chars(raw_url)
        # Never truncate a URL: a clipped URL is a different, plausible-looking
        # link — that is fabrication (R3). Drop over-length / emptied URLs.
        if not url or len(url) > _MAX_URL_LEN:
            continue
        out: dict[str, str] = {"url": url}
        src = ref.get("source")
        if isinstance(src, str) and (clean_src := _clean_str(src, _MAX_SOURCE_LEN)):
            out["source"] = clean_src
        cleaned.append(out)
    return cleaned


def _clean_str_list(values: Any, max_len: int) -> list[str]:
    """Sanitise a list of strings, dropping any that clean to empty."""
    if not isinstance(values, list):
        return []
    return [
        cleaned
        for item in values[:_MAX_LIST]
        if isinstance(item, str) and (cleaned := _clean_str(item, max_len))
    ]


# Free-text fields that are length-capped during cleaning (truncation here loses
# detail but cannot mint a false CVE ID or a wrong CVSS number).
_TEXT_FIELDS = (
    "vulnerability_name",
    "vendor_project",
    "product",
    "required_action",
)


def sanitize_vuln(vuln: dict[str, Any]) -> dict[str, Any] | None:
    """Return a sanitised copy of one vuln record, or ``None`` to drop it.

    ``cve_id`` is an identifier: it is stripped of hidden characters but never
    truncated — a clipped CVE ID is a *different* CVE, which is fabrication (R3).
    A record whose ``cve_id`` cleans to empty is dropped.
    """
    out = dict(vuln)

    raw_id = out.get("cve_id")
    if isinstance(raw_id, str):
        cleaned_id = _strip_chars(raw_id)
        if not cleaned_id:
            logger.warning("Dropping vuln whose cve_id sanitised to empty.")
            return None
        out["cve_id"] = cleaned_id

    if isinstance(out.get("source"), str):
        out["source"] = _clean_str(out["source"], _MAX_SOURCE_LEN)

    if isinstance(out.get("description"), str):
        out["description"] = _clean_str(out["description"], _MAX_DESC_LEN)

    for fname in _TEXT_FIELDS:
        if isinstance(out.get(fname), str):
            out[fname] = _clean_str(out[fname], _MAX_TEXT_LEN)

    if "references" in out:
        out["references"] = _clean_references(out.get("references"))
    if "cwes" in out:
        out["cwes"] = _clean_str_list(out.get("cwes"), _MAX_TEXT_LEN)
    if "tags" in out:
        out["tags"] = _clean_str_list(out.get("tags"), _MAX_TEXT_LEN)

    return out


def sanitize_vulns(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sanitise a list of vuln records, dropping any that clean to empty cve_id."""
    return [cleaned for v in vulns if (cleaned := sanitize_vuln(v)) is not None]


def _merge_duplicate(kept: dict[str, Any], other: dict[str, Any]) -> dict[str, Any]:
    """Fold a duplicate CVE record into the kept copy without losing corroboration.

    Returns a NEW dict (inputs may be references into adapters' in-process
    caches, so in-place mutation would corrupt cached results). Two feeds
    reporting the same CVE is signal: the second source is recorded as a
    ``corroborated-by:<source>`` tag, and references / CWEs are unioned so the
    merged record carries both feeds' enrichment.
    """
    merged = {**kept}

    tags = list(merged.get("tags", []))
    for tag in other.get("tags", []):
        if tag not in tags:
            tags.append(tag)
    other_source = other.get("source")
    if other_source and other_source != merged.get("source"):
        corroboration = f"corroborated-by:{other_source}"
        if corroboration not in tags:
            tags.append(corroboration)
    if tags:
        merged["tags"] = tags

    cwes = list(merged.get("cwes", []))
    for cwe in other.get("cwes", []):
        if cwe not in cwes:
            cwes.append(cwe)
    if cwes:
        merged["cwes"] = cwes

    refs = list(merged.get("references", []))
    seen_urls = {r.get("url") for r in refs if isinstance(r, dict)}
    for ref in other.get("references", []):
        if isinstance(ref, dict) and ref.get("url") not in seen_urls:
            refs.append(ref)
            seen_urls.add(ref.get("url"))
    if refs:
        merged["references"] = refs

    # KEV-only enrichment (exploit_status, due_date, required_action,
    # known_ransomware_use) is high-value; keep it if only the other copy has it.
    for enrich in ("exploit_status", "due_date", "required_action",
                   "known_ransomware_use", "date_added"):
        if enrich not in merged and enrich in other:
            merged[enrich] = other[enrich]

    return merged


def deduplicate_vulns(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate by ``cve_id``, keeping the highest-CVSS copy.

    Duplicates are merged, not discarded: tags/CWEs/references are unioned and a
    cross-source duplicate gains a ``corroborated-by:<source>`` tag. When only
    one copy carries a CVSS score, that copy is kept as the base (a scored record
    is more useful than an unscored one).
    """
    seen: dict[str, dict[str, Any]] = {}
    for vuln in vulns:
        key = vuln["cve_id"]
        if key not in seen:
            seen[key] = vuln
            continue
        existing = seen[key]
        existing_score = existing.get("cvss_score", -1.0)
        new_score = vuln.get("cvss_score", -1.0)
        if new_score > existing_score:
            seen[key] = _merge_duplicate(vuln, existing)
        else:
            seen[key] = _merge_duplicate(existing, vuln)
    return list(seen.values())


def finalize_vulns(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sanitise, validate, then deduplicate — the standard vuln output pipeline.

    Order mirrors ``finalize_iocs``: sanitise first (strip hidden characters,
    drop records with an emptied CVE ID), so schema validation and dedup both run
    on cleaned values.
    """
    return deduplicate_vulns(validate_vulns(sanitize_vulns(vulns)))


# --- Concurrent fan-out over vulnerability feeds ---------------------------

_SUMMARY_KEYS = (
    "source",
    "tier",
    "status",
    "record_count",
    "latency_ms",
    "partial_failure",
    "error",
)


@dataclass
class VulnFeedSource:
    """A single vulnerability adapter plus the resilience state that guards it."""

    adapter: Any
    tier: int
    name: str
    breaker: CircuitBreaker
    no_retry_on: tuple[type[BaseException], ...] = field(default_factory=tuple)


def _degraded(name: str, tier: int, reason: str, t0: float) -> dict[str, Any]:
    return {
        "source": name,
        "tier": tier,
        "status": "unverified",
        "vulns": [],
        "record_count": 0,
        "latency_ms": round((time.monotonic() - t0) * 1000, 1),
        "retrieved_at": "",
        "feed_types_fetched": [],
        "partial_failure": ["*"],
        "error": reason,
    }


async def _run_source(
    source: VulnFeedSource, *, time_range: str, retry_kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Fetch one vuln source; never raises — failures become degraded dicts."""
    name, tier = source.name, source.tier
    t0 = time.monotonic()
    try:
        result = await guarded_fetch(
            source.adapter,
            source.breaker,
            time_range=time_range,
            feed_types=None,
            no_retry_on=source.no_retry_on,
            **retry_kwargs,
        )
    except source.no_retry_on as exc:  # credential / config error
        logger.warning("vuln source %s unconfigured: %s", name, type(exc).__name__)
        return _degraded(name, tier, type(exc).__name__, t0)
    except CircuitOpenError:
        return _degraded(name, tier, "circuit_open", t0)
    except Exception as exc:
        logger.warning("vuln source %s failed: %s", name, type(exc).__name__)
        return _degraded(name, tier, type(exc).__name__, t0)

    assert isinstance(result, VulnFetchResult)
    finalized = finalize_vulns(result.vulns)
    status = "consulted"
    if result.partial_failure:
        status = "partial" if finalized else "unverified"

    return {
        "source": name,
        "tier": tier,
        "status": status,
        "vulns": finalized,
        "record_count": len(finalized),
        "latency_ms": result.latency_ms,
        "retrieved_at": result.retrieved_at,
        "feed_types_fetched": result.feed_types_fetched,
        "partial_failure": result.partial_failure,
        "error": None,
    }


async def fan_out_vulns(
    sources: list[VulnFeedSource],
    *,
    time_range: str = "7d",
    retry_kwargs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fetch every vuln source concurrently and merge into one deduplicated set.

    Returns a dict with the merged ``vulns`` (cross-source duplicates collapsed to
    the highest-CVSS copy), a per-source breakdown, consulted vs. degraded source
    lists, and a ``coverage_ledger`` ready to fold into the skill's Appendix A —
    the vulnerability analogue of ``fanout.fan_out``.
    """
    retry_kwargs = retry_kwargs or {}
    t0 = time.monotonic()

    per_source = await asyncio.gather(
        *(
            _run_source(s, time_range=time_range, retry_kwargs=retry_kwargs)
            for s in sources
        )
    )

    merged = deduplicate_vulns([v for r in per_source for v in r["vulns"]])
    latency_ms = round((time.monotonic() - t0) * 1000, 1)

    consulted = [r["source"] for r in per_source if r["status"] == "consulted"]
    degraded = [
        {"source": r["source"], "status": r["status"], "error": r["error"]}
        for r in per_source
        if r["status"] != "consulted"
    ]

    return {
        "vulns": merged,
        "record_count": len(merged),
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "latency_ms": latency_ms,
        "sources_consulted": consulted,
        "sources_degraded": degraded,
        "per_source": [{k: r[k] for k in _SUMMARY_KEYS} for r in per_source],
        "coverage_ledger": [
            {"tier": r["tier"], "source": r["source"], "status": r["status"]}
            for r in per_source
        ],
    }
