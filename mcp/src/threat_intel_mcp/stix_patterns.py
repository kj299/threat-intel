"""Minimal STIX 2.x indicator-pattern extraction for network IOCs.

Several feeds (Any.Run TAXII, Intel 471's STIX mapper) express indicators as
STIX 2.1 objects whose ``pattern`` is a comparison expression such as::

    [ipv4-addr:value = '203.0.113.7']
    [ipv6-addr:value = '2001:db8::1']
    [domain-name:value = 'evil.example']
    [url:value = 'http://evil.example/x']

This module extracts the (ioc_network type, value) pairs from such patterns.
It is deliberately conservative: it recognises the four network object types
that map onto the ``ioc_network`` schema and ignores everything else (file
hashes, email-addr, etc.) rather than guessing. It does not implement the full
STIX patterning grammar — only the ``<obj-type>:value = '<literal>'``
comparisons that carry network indicators, which is what these feeds emit.
"""

from __future__ import annotations

import re

# STIX object-path -> ioc_network type.
_STIX_TYPE_MAP = {
    "ipv4-addr": "IPv4",
    "ipv6-addr": "IPv6",
    "domain-name": "Domain",
    "url": "URL",
}

# Matches `<obj-type>:value = '<literal>'` (or :value=... , = "..."), the STIX
# comparison form these feeds use. Captures the object type and the quoted value.
_COMPARISON_RE = re.compile(
    r"(ipv4-addr|ipv6-addr|domain-name|url)\s*:\s*value\s*=\s*"
    r"(?:'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\")",
    re.IGNORECASE,
)


def _unescape(literal: str) -> str:
    # STIX string literals backslash-escape ' and \\.
    return literal.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")


def extract_network_iocs(pattern: str) -> list[tuple[str, str]]:
    """Return ``(ioc_network_type, value)`` pairs found in a STIX pattern.

    A pattern may contain more than one comparison (e.g. an ``OR``); each
    recognised network comparison yields one pair. Unrecognised object types
    are skipped. Returns an empty list for non-network or unparseable patterns.
    """
    if not pattern:
        return []
    out: list[tuple[str, str]] = []
    for m in _COMPARISON_RE.finditer(pattern):
        obj_type = m.group(1).lower()
        value = _unescape(m.group(2) if m.group(2) is not None else m.group(3))
        ioc_type = _STIX_TYPE_MAP.get(obj_type)
        if ioc_type and value:
            out.append((ioc_type, value))
    return out
