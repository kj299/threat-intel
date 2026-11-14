"""Preserve source evidence and distribution restrictions across merges."""
from copy import deepcopy

_TLP_RANK = {"WHITE": 0, "GREEN": 1, "AMBER": 2, "AMBER+STRICT": 3, "RED": 4}
_FIELDS = ("source", "confidence", "tlp", "first_seen", "last_seen", "retrieved_at",
           "cvss_score", "exploit_status", "references")


def merge_evidence(kept: dict, other: dict) -> dict:
    """Merge annotations without treating confidence as permission to share.

    Missing TLP is unknown, not an affirmative grant. Existing restrictions
    survive, and original evidence stays attached to each contributing source.
    """
    result = dict(kept)
    evidence = []
    for record in (kept, other):
        entries = record.get("source_evidence") or [
            {key: record[key] for key in _FIELDS if key in record}
        ]
        for entry in entries:
            if entry not in evidence:
                evidence.append(deepcopy(entry))
    result["source_evidence"] = evidence
    labels = [r["tlp"] for r in (kept, other) if r.get("tlp") in _TLP_RANK]
    if labels:
        result["tlp"] = max(labels, key=_TLP_RANK.__getitem__)
    return result
