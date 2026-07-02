"""Schema validation for normalised adapter output.

Validates ioc_network objects against the ioc_network definition in
output.schema.json from kj299/threat-intel before they are returned to Claude.
Malformed objects are dropped with a warning rather than crashing the tool call.
"""

from __future__ import annotations

import logging
from typing import Any

import jsonschema

from .sanitize import sanitize_iocs

logger = logging.getLogger(__name__)

# Inline the ioc_network schema so this package has no file-system dependency
# on the threat-intel repo at runtime. Keep in sync with output.schema.json.
_IOC_NETWORK_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["type", "value", "confidence", "source"],
    "properties": {
        "type": {
            "type": "string",
            "enum": [
                "IPv4", "IPv6", "Domain", "URL", "SSL_Certificate_Hash",
                "JA3", "JA3S", "JARM", "HTTP_Header", "User_Agent", "CIDR_Range",
            ],
        },
        "value": {"type": "string", "minLength": 1},
        "confidence": {"type": "string", "enum": ["High", "Medium", "Low"]},
        "source": {
            "type": "string",
            "minLength": 1,
            "not": {"enum": ["unknown", "general knowledge", "n/a"]},
        },
        "first_seen": {"type": "string", "format": "date-time"},
        "last_seen": {"type": "string", "format": "date-time"},
        "associated_threat": {"type": "string"},
        "associated_actor": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "kill_chain_phase": {"type": "string"},
        "tlp": {"type": "string", "enum": ["WHITE", "GREEN", "AMBER", "AMBER+STRICT", "RED"]},
        "mitre_technique": {"type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$"},
        "action": {"type": "string", "enum": ["block", "alert", "hunt"]},
    },
}

# FormatChecker enforces "format": "date-time" on first_seen/last_seen at
# runtime (requires the rfc3339-validator package, declared in pyproject).
_validator = jsonschema.Draft7Validator(
    _IOC_NETWORK_SCHEMA, format_checker=jsonschema.FormatChecker()
)


def validate_iocs(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only the ioc_network objects that pass schema validation.

    Invalid objects are logged and dropped rather than propagated to Claude —
    a malformed IOC in the output is worse than a missing one.
    """
    valid: list[dict[str, Any]] = []
    for ioc in iocs:
        errors = list(_validator.iter_errors(ioc))
        if errors:
            logger.warning(
                "Dropping invalid IOC (schema validation failed): value=%r errors=%s",
                ioc.get("value", "?"),
                [e.message for e in errors],
            )
        else:
            valid.append(ioc)
    return valid


_CONF_RANK = {"High": 3, "Medium": 2, "Low": 1}


def _merge_duplicate(kept: dict[str, Any], other: dict[str, Any]) -> dict[str, Any]:
    """Fold a duplicate IOC into the kept copy without losing corroboration.

    Returns a NEW dict — the inputs are often references into adapters'
    in-process caches, so in-place mutation would corrupt cached results.
    Tags are unioned, and an independent second source is recorded as a
    ``corroborated-by:<source>`` tag (two feeds reporting the same indicator
    is signal, not noise).
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
    return merged


def deduplicate_iocs(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate by (type, value), keeping the highest-confidence copy.

    Duplicates are merged, not discarded: tags are unioned and cross-source
    duplicates gain a ``corroborated-by:<source>`` tag on the kept copy.
    """
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen[key] = ioc
            continue
        existing = seen[key]
        existing_rank = _CONF_RANK.get(existing.get("confidence", "Low"), 1)
        new_rank = _CONF_RANK.get(ioc.get("confidence", "Low"), 1)
        if new_rank > existing_rank:
            seen[key] = _merge_duplicate(ioc, existing)
        else:
            seen[key] = _merge_duplicate(existing, ioc)
    return list(seen.values())


def finalize_iocs(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sanitise, validate, then deduplicate — the standard adapter output pipeline.

    Order matters: sanitisation first (strip control/zero-width chars, drop
    emptied or over-length values), so that schema validation always runs on
    the *cleaned* values, then dedup on those cleaned values so that
    hidden-character variants of the same indicator collapse together.
    """
    return deduplicate_iocs(validate_iocs(sanitize_iocs(iocs)))
