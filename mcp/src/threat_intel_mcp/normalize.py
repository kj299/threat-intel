"""Schema validation for normalised adapter output.

Validates ioc_network objects against the ioc_network definition in
output.schema.json from kj299/threat-intel before they are returned to Claude.
Malformed objects are dropped with a warning rather than crashing the tool call.
"""

from __future__ import annotations

import logging
from typing import Any

import jsonschema

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

_validator = jsonschema.Draft7Validator(_IOC_NETWORK_SCHEMA)


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


def deduplicate_iocs(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate by (type, value), keeping the highest-confidence copy."""
    _conf_rank = {"High": 3, "Medium": 2, "Low": 1}
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen[key] = ioc
        else:
            existing_rank = _conf_rank.get(seen[key].get("confidence", "Low"), 1)
            new_rank = _conf_rank.get(ioc.get("confidence", "Low"), 1)
            if new_rank > existing_rank:
                seen[key] = ioc
    return list(seen.values())
