"""VulnCheck KEV (Known Exploited Vulnerabilities) adapter.

Fetches VulnCheck's community KEV index and normalises each entry to a
vulnerability record (see ``vulns.py``). Every entry in a KEV catalog is, by
definition, reported as exploited in the wild, so records carry
``exploit_status: known_exploited`` — the same treatment ``cisa_kev.py`` gives
its own catalog.

Why a second KEV
----------------
VulnCheck states its KEV covers materially more exploited CVEs than the CISA
catalog. The two are complements rather than substitutes: CISA KEV is the U.S.
government's binding-directive list, VulnCheck's is a broader vendor-curated
one. ``finalize_vulns`` dedupes by CVE ID and preserves corroboration, so a CVE
present in both is one record naming both sources — which is exactly the signal
an analyst wants.

.. warning::

   **THE RECORD SCHEMA BELOW IS UNVERIFIED.** Everything in "Feed contract" was
   assembled from VulnCheck's published Go SDK and secondary sources, **not**
   from a response this code has seen. The dev sandbox's egress proxy blocks
   ``docs.vulncheck.com`` and every feed host, and the OpenAPI document in
   ``vulncheck-oss/sdk-go-v2`` is too large to read through the available
   fetcher.

   That is precisely the condition that produced #100: a ThreatFox parser
   written from belief returned 0 records from a live 1 MB response while its
   tests passed. The mitigation here is structural, not optimistic —
   ``guard_parsed`` turns a wrong guess into a loud ``UpstreamFormatError``
   (degrade + retry) instead of a confident ``0 records``.

   **Record a cassette before trusting this adapter's output.** Run the
   ``record-cassettes`` workflow with ``feeds: vulncheck``; GitHub runners have
   the egress this sandbox lacks. Correct the parser against those bytes and
   delete this warning.

Feed contract (VERIFIED transport, UNVERIFIED record shape)
-----------------------------------------------------------
Verified from VulnCheck's own Go SDK (``vulncheck-oss/sdk-go``, which documents
``sdk.Connect("https://api.vulncheck.com", "vulncheck_token")``, and
``sdk-go-v2``, whose generated client authenticates a ``Bearer`` API key):

  - Base URL: ``https://api.vulncheck.com``
  - Auth: ``Authorization: Bearer <token>``
  - Index endpoint: ``GET /v3/index/vulncheck-kev``
  - Response envelope carries a ``data`` array (the SDK's own example indexes
    ``response.Data[0]``).

Unverified, and therefore parsed defensively:

  - ``cve`` — reported by secondary sources as an **array of strings**, not a
    single ID like CISA KEV's ``cveID``. Both shapes are accepted; a list
    expands to one vuln record per CVE, since ``finalize_vulns`` keys on a
    single ``cve_id``.
  - ``date_added`` — timestamp.
  - ``vulncheck_xdb`` — array of ``{xdb_id, xdb_url, date_added}``.
  - ``vulncheck_reported_exploitation`` — array of ``{url, date_added}``.
  - ``vendorProject`` / ``product`` / ``shortDescription`` — CISA-KEV-shaped.

Pagination is deliberately NOT guessed. The index is paginated, but the
parameter and metadata names could not be confirmed, and inventing them would
either silently truncate or silently loop. This adapter fetches one page and
says so in the log when that page comes back full. Restoring full pagination is
a follow-up gated on the cassette, mirroring how ``nvd.py``'s page walk is
pinned by a recording rather than by belief.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call
from ..netpolicy import egress_event_hooks
from ..vault.base import CredentialProvider
from ..vulns import VulnFetchResult
from .base import guard_parsed

logger = logging.getLogger(__name__)

_API_HOST = "api.vulncheck.com"
_INDEX_URL = f"https://{_API_HOST}/v3/index/vulncheck-kev"

FEED_TYPES: dict[str, str] = {"kev_catalog": _INDEX_URL}
DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

# The catalog moves a few times a day at most; match cisa_kev.py's 6 hours so
# repeated report generations in one session stay cheap.
CACHE_TTL_SECONDS = 21600
_CACHE_KEY = "vulncheck_kev"

# See the pagination note in the module docstring: one page, and a warning when
# it comes back full. Deliberately not a page walk.
PAGE_LIMIT = 1000


def _to_rfc3339(raw: Any) -> str | None:
    """Coerce a VulnCheck timestamp to RFC 3339, or None if unreadable.

    The feed's exact datetime format is unverified, so three shapes are tried:
    a full ISO-8601 timestamp (what the SDK's ``time.Time`` implies), a bare
    ``YYYY-MM-DD`` calendar date, and a ``Z``-suffixed timestamp that
    ``fromisoformat`` rejects on older interpreters. Anything else yields None
    and the field is simply omitted — the vuln schema validates ``date-time``
    at runtime, so emitting a half-understood string would drop the whole
    record rather than just the field.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            dt = datetime.strptime(text, "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _cve_ids(entry: dict[str, Any]) -> list[str]:
    """Every CVE ID this entry names.

    ``cve`` is reported to be a list, unlike CISA KEV's scalar ``cveID``. Both
    are accepted rather than asserted: if the shape is the other one, this still
    reads it instead of returning nothing, and ``guard_parsed`` still fires when
    neither is present anywhere in the payload.
    """
    raw = entry.get("cve")
    if isinstance(raw, str):
        candidates = [raw]
    elif isinstance(raw, list):
        candidates = [c for c in raw if isinstance(c, str)]
    else:
        candidates = []
    # Tolerate the CISA-shaped key too; costs one lookup, and a silent zero here
    # would be indistinguishable from a quiet catalog.
    fallback = entry.get("cveID")
    if not candidates and isinstance(fallback, str):
        candidates = [fallback]
    return [c.strip() for c in candidates if c.strip()]


def _references(entry: dict[str, Any]) -> list[dict[str, str]]:
    """Collect exploit and XDB URLs as reference objects.

    These are the fields that justify VulnCheck as a *second* KEV: the URL that
    reported exploitation is evidence, and dropping it would leave a record that
    asserts "exploited" with nothing behind it.
    """
    refs: list[dict[str, str]] = []
    for key, label in (
        ("vulncheck_reported_exploitation", "VulnCheck reported exploitation"),
        ("vulncheck_xdb", "VulnCheck XDB"),
    ):
        items = entry.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            url = item.get("url") or item.get("xdb_url")
            if isinstance(url, str) and url.strip():
                refs.append({"url": url.strip(), "source": label})
    return refs


def _normalize_entry(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Map one VulnCheck KEV entry to vuln records — one per CVE it names.

    Returns a list, not a single record, because ``cve`` is a list: the vuln
    schema keys on exactly one ``cve_id``, and collapsing several CVEs into one
    record would discard real coverage. Fields are copied verbatim; nothing is
    inferred.
    """
    ids = _cve_ids(entry)
    if not ids:
        return []

    base: dict[str, Any] = {
        "source": "VulnCheck KEV",
        "exploit_status": "known_exploited",
        "tlp": "WHITE",
        "tags": ["vulncheck-kev", "known-exploited"],
    }

    for src_key, dst_key in (
        ("vendorProject", "vendor_project"),
        ("product", "product"),
        ("vulnerabilityName", "vulnerability_name"),
        ("shortDescription", "description"),
        ("required_action", "required_action"),
    ):
        value = entry.get(src_key)
        if isinstance(value, str) and value.strip():
            base[dst_key] = value.strip()

    date_added = _to_rfc3339(entry.get("date_added"))
    if date_added:
        base["date_added"] = date_added

    refs = _references(entry)
    if refs:
        base["references"] = refs

    return [dict(base, cve_id=cve_id) for cve_id in ids]


class VulnCheckAdapter:
    """Adapter for the VulnCheck KEV index (community tier)."""

    name = "VulnCheck KEV"
    # Tier 1 describes the data category -- "Vulnerability Databases & Exploit
    # Repositories" -- not the operator. VulnCheck is a commercial vendor, but
    # a KEV catalog is Tier 1 material in the same way NVD is, and filing it as
    # Tier 2 "Commercial Threat Intelligence" would misrepresent what it holds.
    tier = 1
    requires_credential = True

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self, token: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "threat-intel-mcp/0.13 (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks(_API_HOST),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> VulnFetchResult:
        """Fetch the VulnCheck KEV catalog as vulnerability records.

        ``time_range`` is accepted for interface compatibility and recorded for
        the Coverage Ledger, but does not filter — a KEV entry is a standing
        "this is being exploited" item regardless of when it was added, which is
        the same reasoning ``cisa_kev.py`` documents. Filtering on an unverified
        date field would silently drop records.
        """
        requested = feed_types or DEFAULT_FEED_TYPES
        unknown = [t for t in requested if t not in FEED_TYPES]
        if unknown:
            raise ValueError(
                f"Unknown feed_type(s): {unknown}. Valid: {list(FEED_TYPES.keys())}"
            )

        t_start = time.monotonic()

        now = time.monotonic()
        cached = self._cache.get(_CACHE_KEY)
        if cached is not None and now < cached[1]:
            vulns = cached[0]
        else:
            # Raises CredentialNotFoundError when unset -- a config error the
            # server degrades non-retryably, per the adapters/base.py taxonomy.
            token = self._credentials.get("vulncheck", "api_key")
            async with self._make_client(token) as client:
                resp = await client.get(_INDEX_URL, params={"limit": PAGE_LIMIT})
                resp.raise_for_status()
                body = resp.json()
            vulns = self._parse_index(body)
            self._cache[_CACHE_KEY] = (vulns, now + CACHE_TTL_SECONDS)

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "vulncheck_fetch_cves",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(vulns),
            latency_ms=latency_ms,
            status="ok",
        )
        return VulnFetchResult(
            vulns=vulns,
            source="VulnCheck KEV",
            tier=1,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(vulns),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=["kev_catalog"],
        )

    def _parse_index(self, body: Any) -> list[dict[str, Any]]:
        """Parse the index JSON body into vuln records.

        A malformed body is an *upstream* problem, so it raises ``RuntimeError``
        rather than ``ValueError``: the server tool reserves ``ValueError`` for
        caller mistakes it surfaces verbatim, and degrades everything else to an
        "unverified" ledger entry (see ``adapters/base.py``).
        """
        if not isinstance(body, dict):
            raise RuntimeError("VulnCheck response was not a JSON object")
        # Presence check, not truthiness: `{"data": []}` is a real empty result,
        # while a body with no `data` key is one we failed to recognise.
        if "data" not in body:
            raise RuntimeError("VulnCheck response missing 'data' key")
        entries = body.get("data")
        if not isinstance(entries, list):
            raise RuntimeError("VulnCheck 'data' was not a list")

        vulns: list[dict[str, Any]] = []
        understood = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            records = _normalize_entry(entry)
            if records:
                understood += 1
                vulns.extend(records)

        guard_parsed(
            "VulnCheck KEV",
            envelope_found=True,  # checked above, with its own message
            envelope_desc="a 'data' list",
            items_seen=len(entries),
            items_understood=understood,
        )

        if len(entries) >= PAGE_LIMIT:
            logger.warning(
                "VulnCheck returned a full page (%d entries); this adapter "
                "fetches one page only, so the catalog is likely truncated. "
                "Record a cassette and restore pagination -- see the module "
                "docstring.",
                len(entries),
            )
        return vulns
