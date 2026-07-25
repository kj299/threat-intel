"""ThreatFox (abuse.ch) IOC adapter.

Fetches recent indicators from the **public** ThreatFox CSV feed
(https://threatfox.abuse.ch/export/csv/recent/) and normalises the network
indicators to ioc_network objects compatible with output.schema.json from
kj299/threat-intel.

No credential required — this is a free, unauthenticated feed. (Verified against
the OpenCTI ThreatFox connector, which fetches the same CSV via a plain
``urllib.request.urlopen`` with no Auth-Key header.)

Feed characteristics (verified from the OpenCTI connector, 2026):
  - GET https://threatfox.abuse.ch/export/csv/recent/
  - Response: CSV; comment lines start with ``#``. Columns (0-indexed):
    ``first_seen, id, value, type, threat_type, fk_malware, malware_aliases,
    malware_printable, last_seen, confidence_level, is_compromised, reference,
    tags, anonymous, reporter`` (0..14).
  - ``type`` values: ``ip:port``, ``domain``, ``url``, ``md5_hash``,
    ``sha1_hash``, ``sha256_hash``. Only the first three are network indicators;
    hashes are ioc_host and are skipped here.
  - **Fields are quoted and separated by comma-then-space** (``"a", "b", "c"``),
    so the reader needs ``skipinitialspace=True``. This is not cosmetic: with
    the default dialect the space before each ``"`` means the quote is no longer
    a quote character, so every field after the first keeps its literal quotes
    (``row[3]`` is ``'"ip:port"'``, never ``'ip:port'``) and any field that
    itself contains a comma — the ``tags`` column — splits into extra columns.
    Every row then fails the ``type`` match and is skipped, and the feed parses
    to **zero records while returning HTTP 200**. Observed live on 2026-07-25: a
    1,016,687-byte response yielded 0 IOCs. The OpenCTI connector registers the
    same ``skipinitialspace=True`` dialect for this exact URL.

``skipinitialspace=True`` is safe whether or not the space is present — it only
ever discards whitespace between a delimiter and the following field — so it is
the correct setting regardless of which way abuse.ch formats a future export.

ThreatFox indicators are confirmed-malicious C2 / payload-delivery IOCs, so
network IOCs are emitted with ``action: block`` and confidence derived from the
feed's own ``confidence_level`` (0-100).
"""

from __future__ import annotations

import csv
import io
import ipaddress
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call
from ..netpolicy import egress_event_hooks
from .base import FetchResult

logger = logging.getLogger(__name__)

_FEED_URL = "https://threatfox.abuse.ch/export/csv/recent/"

FEED_TYPES: dict[str, str] = {"recent_iocs": _FEED_URL}
DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

CACHE_TTL_SECONDS = 900
_CACHE_KEY = "threatfox_recent"

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
    raw = raw.strip()
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


class ThreatFoxAdapter:
    """Adapter for the ThreatFox (abuse.ch) recent IOC feed."""

    name = "ThreatFox"
    tier = 9
    requires_credential = False

    def __init__(self, credentials: Any = None) -> None:
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "Accept": "text/csv, text/plain",
                "User-Agent": "threat-intel-mcp/0.12 (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("threatfox.abuse.ch"),
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

        t_start = time.monotonic()

        now = time.monotonic()
        cached = self._cache.get(_CACHE_KEY)
        if cached is not None and now < cached[1]:
            iocs = cached[0]
        else:
            async with self._make_client() as client:
                resp = await client.get(_FEED_URL)
                resp.raise_for_status()
                iocs = self._parse_csv(resp.text)
            self._cache[_CACHE_KEY] = (iocs, now + CACHE_TTL_SECONDS)

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "threatfox_fetch_iocs",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(iocs),
            latency_ms=latency_ms,
            status="ok",
        )
        return FetchResult(
            iocs=iocs,
            source="ThreatFox",
            tier=9,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=["recent_iocs"],
        )

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
