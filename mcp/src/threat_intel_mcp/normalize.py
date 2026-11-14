"""Schema validation for normalised adapter output.

Validates ioc_network objects against the ioc_network definition in
output.schema.json from kj299/threat-intel before they are returned to Claude.
Malformed objects are dropped with a warning rather than crashing the tool call.
"""

from __future__ import annotations

import logging
import json
from importlib.resources import files
from typing import Any

import jsonschema

from .provenance import merge_evidence

from .sanitize import sanitize_iocs
from .indicator_values import valid_value

logger = logging.getLogger(__name__)

# Packaged from the published contract; parity is verified by the test suite.
_IOC_NETWORK_SCHEMA: dict[str, Any] = json.loads(
    files(__package__).joinpath("ioc_network.schema.json").read_text()
)

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
        elif not valid_value(ioc["type"], ioc["value"]):
            logger.warning("Dropping IOC whose value is invalid for type %s", ioc["type"])
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
    merged = merge_evidence(kept, other)
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
