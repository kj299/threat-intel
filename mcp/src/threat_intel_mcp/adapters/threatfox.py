"""ThreatFox authenticated JSON API adapter.

Uses the documented get_iocs POST API (https://threatfox.abuse.ch/api/).
ABUSECH_AUTH_KEY is optional configuration, but required to consult this source.
The retired CSV parser remains only for historical fixture regression tests.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import logging
import math
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..audit import log_tool_call
from ..netpolicy import egress_event_hooks
from ..vault.base import CredentialNotFoundError
from .base import FetchResult

logger = logging.getLogger(__name__)

_FEED_URL = "https://threatfox-api.abuse.ch/api/v1/"

FEED_TYPES: dict[str, str] = {"recent_iocs": _FEED_URL}
DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

CACHE_TTL_SECONDS = 900

_MIN_COLS = 10  # need at least through confidence_level (col 9)

# The dialect abuse.ch actually emits. See the module docstring: without
# skipinitialspace the whole feed parses to nothing and still reports HTTP 200.
_DIALECT = {"delimiter": ",", "quotechar": '"', "skipinitialspace": True}

# Every ioc_type the feed is known to emit. Network types are normalised;
# hash types are ioc_host and skipped. Membership here means "the row was
# understood", which is what distinguishes a quiet feed from a broken parse.
_NETWORK_TYPES = {"ip:port", "domain", "url"}
_HASH_TYPES = {"md5_hash", "sha1_hash", "sha256_hash"}
_KNOWN_TYPES = _NETWORK_TYPES | _HASH_TYPES


def _map_confidence(level: int) -> str:
    if level >= 80:
        return "High"
    if level >= 50:
        return "Medium"
    return "Low"


def _parse_ip(value: str) -> tuple[str, int] | None:
    """Extract a bare IP (dropping any :port) from a ThreatFox ip:port value.

    Returns (ip_string, ip_version) or None if it is not a parseable address.
    """
    v = value.strip()
    # Bracketed IPv6 with port: [2001:db8::1]:443
    if v.startswith("["):
        v = v[1:].split("]", 1)[0]
    else:
        try:
            return str(ipaddress.ip_address(v)), ipaddress.ip_address(v).version
        except ValueError:
            # IPv4:port — strip the trailing :port
            v = v.rsplit(":", 1)[0]
    try:
        addr = ipaddress.ip_address(v)
    except ValueError:
        return None
    return str(addr), addr.version


def _to_rfc3339(raw: str) -> str | None:
    raw = raw.strip().removesuffix(" UTC")
    if not raw:
        return None
    try:
        dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc).isoformat()


def _normalize_row(row: list[str]) -> dict[str, Any] | None:
    """Map one ThreatFox CSV row to an ioc_network dict, or None to skip."""
    if len(row) < _MIN_COLS:
        return None
    value = row[2].strip()
    ioc_type = row[3].strip()
    if not value:
        return None

    if ioc_type == "ip:port":
        parsed = _parse_ip(value)
        if parsed is None:
            return None
        ip, version = parsed
        net_type, net_value = ("IPv4" if version == 4 else "IPv6"), ip
    elif ioc_type == "domain":
        net_type, net_value = "Domain", value
    elif ioc_type == "url":
        net_type, net_value = "URL", value
    else:
        # md5_hash / sha1_hash / sha256_hash → ioc_host, not network. Skip.
        return None

    threat_type = row[4].strip()
    malware = row[7].strip()
    try:
        confidence = _map_confidence(int(row[9]))
    except (ValueError, TypeError):
        confidence = "Medium"

    tags = ["threatfox"]
    if threat_type:
        tags.append(threat_type)
    if ioc_type == "ip:port" and ":" in value:
        tags.append(f"port:{value.rsplit(':', 1)[-1]}")

    ioc: dict[str, Any] = {
        "type": net_type,
        "value": net_value,
        "confidence": confidence,
        "source": "ThreatFox",
        "action": "block",
        "tlp": "WHITE",
        "tags": tags,
    }
    if malware and malware.lower() not in ("unknown malware", "unknown"):
        ioc["associated_threat"] = malware
    first_seen = _to_rfc3339(row[0])
    if first_seen:
        ioc["first_seen"] = first_seen
    return ioc


class ThreatFoxAPIStatusError(RuntimeError):
    """An API-level refusal with a fixed, non-sensitive diagnostic."""


class ThreatFoxAdapter:
    """Adapter for the ThreatFox (abuse.ch) recent IOC feed."""

    name = "ThreatFox"
    tier = 9
    requires_credential = True

    def __init__(self, credentials: Any = None) -> None:
        self._credentials = credentials
        self._cache: dict[int, tuple[list[dict[str, Any]], float, str]] = {}

    def _auth_header(self) -> dict[str, str]:
        """Resolve credentials before network access; never log their value."""
        if self._credentials is None:
            raise CredentialNotFoundError("ABUSECH_AUTH_KEY is not configured")
        key = self._credentials.get("abusech", "auth_key")
        if not key:
            raise CredentialNotFoundError("ABUSECH_AUTH_KEY is not configured")
        return {"Auth-Key": key}

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={"Accept": "application/json", **self._auth_header()},
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("threatfox-api.abuse.ch"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch the recent ThreatFox IOC feed (network indicators only)."""
        requested = feed_types or DEFAULT_FEED_TYPES
        unknown = [t for t in requested if t not in FEED_TYPES]
        if unknown:
            raise ValueError(
                f"Unknown feed_type(s): {unknown}. Valid: {list(FEED_TYPES.keys())}"
            )

        match = re.fullmatch(r"([1-9][0-9]*)([mhdw])", time_range)
        if not match:
            raise ValueError("time_range must be a positive integer followed by m, h, d or w")
        seconds = int(match[1]) * {"m": 60, "h": 3600, "d": 86400, "w": 604800}[match[2]]
        days = min(7, math.ceil(seconds / 86400))
        # Validate current credential availability even on cache hits.
        self._auth_header()
        t_start = time.monotonic()
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=min(seconds, 604800))
        cached = self._cache.get(days)
        if cached is not None and time.monotonic() < cached[1]:
            records, _, retrieved_at = cached
        else:
            async with self._make_client() as client:
                resp = await client.post(_FEED_URL, json={"query": "get_iocs", "days": days})
                resp.raise_for_status()
                try:
                    body = resp.json()
                except ValueError as exc:
                    raise RuntimeError("ThreatFox returned invalid JSON") from exc
                records = self._parse_json(body)
            retrieved_at = now.isoformat()
            self._cache[days] = (records, time.monotonic() + CACHE_TTL_SECONDS, retrieved_at)
        iocs = [ioc.copy() for ioc in records
                if cutoff <= datetime.fromisoformat(ioc["first_seen"]) <= now]
        partial = []
        if seconds > 604800:
            partial.append("ThreatFox get_iocs supports at most 7 days; requested window truncated")
        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call("threatfox_fetch_iocs",
                      {"time_range": time_range, "feed_types": requested},
                      record_count=len(iocs), latency_ms=latency_ms, status="ok")
        return FetchResult(
            iocs=iocs, source="ThreatFox", tier=self.tier,
            retrieved_at=retrieved_at, record_count=len(iocs),
            latency_ms=round(latency_ms, 1), feed_types_fetched=["recent_iocs"],
            partial_failure=partial,
        )

    @staticmethod
    def _parse_json(body: Any) -> list[dict[str, Any]]:
        if not isinstance(body, dict):
            raise RuntimeError("ThreatFox response must be an object")
        status = body.get("query_status")
        if status == "no_result":
            if body.get("data") not in (None, []):
                raise RuntimeError("ThreatFox empty status contradicts response data")
            return []
        if status != "ok":
            # Never echo an untrusted body or status into diagnostics.
            raise ThreatFoxAPIStatusError(
                "ThreatFox API returned a non-success status; verify account/key access "
                "and API compatibility (response details withheld)"
            )
        if not isinstance(body.get("data"), list):
            raise RuntimeError("ThreatFox API data shape was not recognised")
        result = []
        for item in body["data"]:
            if not isinstance(item, dict) or item.get("ioc_type") not in _KNOWN_TYPES:
                raise RuntimeError("ThreatFox API record shape is unrecognised")
            if item["ioc_type"] in _HASH_TYPES:
                continue
            raw_date = item.get("first_seen")
            if not isinstance(raw_date, str) or not _to_rfc3339(raw_date):
                raise RuntimeError("ThreatFox network record has no valid first_seen")
            if not isinstance(item.get("ioc"), str):
                raise RuntimeError("ThreatFox network record has no valid indicator")
            row = [raw_date, "", item["ioc"], item["ioc_type"],
                   str(item.get("threat_type") or ""), "", "",
                   str(item.get("malware_printable") or ""), "",
                   str(item.get("confidence_level", ""))]
            normalized = _normalize_row(row)
            if normalized is None:
                raise RuntimeError("ThreatFox network indicator could not be parsed")
            result.append(normalized)
        return result

    def _parse_csv(self, text: str) -> list[dict[str, Any]]:
        """Parse the feed body into ioc_network dicts.

        Raises ``RuntimeError`` when the body carries data rows but not one of
        them is recognisable — a format break upstream. Per the taxonomy in
        ``adapters/base.py`` that is an upstream problem (case 3), so the tool
        degrades to ``unverified`` and the fan-out retries, rather than
        reporting a confident, wrong ``0 records``.
        """
        lines = (ln for ln in io.StringIO(text) if not ln.startswith("#"))
        reader = csv.reader(lines, **_DIALECT)

        iocs: list[dict[str, Any]] = []
        data_rows = 0
        understood_rows = 0

        for row in reader:
            if not row or not any(field.strip() for field in row):
                continue  # blank line, not a data row
            data_rows += 1
            if len(row) >= _MIN_COLS and row[3].strip() in _KNOWN_TYPES:
                understood_rows += 1
            if (normalized := _normalize_row(row)) is not None:
                iocs.append(normalized)

        # A feed with nothing to report is legitimate (data_rows == 0), and so is
        # a batch that happens to be all hashes (understood_rows > 0, iocs == []).
        # Data rows that are *all* unintelligible are not.
        if data_rows and not understood_rows:
            raise RuntimeError(
                f"ThreatFox feed format not recognised: {data_rows} data row(s) "
                f"parsed, none carrying a known ioc_type in column 3. "
                f"Expected one of {sorted(_KNOWN_TYPES)}. "
                "The feed layout or CSV dialect has probably changed upstream."
            )

        if data_rows and not iocs:
            logger.info(
                "ThreatFox returned %d row(s), none of them network indicators "
                "(hash-only batch) — 0 IOCs is correct here.",
                data_rows,
            )
        return iocs
