"""Emit every named source in the checked-out matrix as an unattempted receipt.

This is a research checklist, never evidence of consultation. Populate a copy
with actual attempts; do not write a completed historical report back to repo.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path


def members(name):
    """Expand matrix groups, preserving aliases such as Mandiant / Google TI.

    Commas outside parentheses enumerate members; commas in an organization's
    qualifier do not. X's open-ended account scope is explicitly unresolved,
    not implied covered by visiting one of the named hashtags.
    """
    service_groups = {
        "FBI IC3 / Flash Alerts": ["FBI IC3", "FBI Flash Alerts"],
        "SWIFT CSCF and Security Updates": ["SWIFT CSCF", "SWIFT Security Updates"],
    }
    if name in service_groups:
        return service_groups[name]
    if name.startswith("Twitter/X hashtags: "):
        tags, accounts = name.removeprefix("Twitter/X hashtags: ").split(" + ", 1)
        return ["Twitter/X " + tag.strip() for tag in tags.split(",")] + [
            "Twitter/X " + accounts + " (unspecified scope)"
        ]
    name = name.removesuffix(" (Mastodon)")
    parts = re.split(r",\s*(?![^()]*\))", name)
    return [re.sub(r" \([a-zA-Z0-9.-]+\.[a-zA-Z]+\)$", "", part.strip())
            for part in parts]


def identity(tier, name):
    """Stable across row ordering and description/priority edits, tier-scoped."""
    key = f"{tier}:{name.casefold()}".encode()
    return f"tier-{tier}:" + hashlib.sha256(key).hexdigest()[:20]


def roster(text):
    tier = None
    rows = []
    for line in text.splitlines():
        heading = re.match(r"## Tier (\d+):", line)
        if heading:
            tier = int(heading[1])
        if tier and line.startswith("- ") and re.search(r"\[(MUST|SHOULD)\]", line):
            entry = line[2:]
            name = re.sub(r" \[(MUST|SHOULD)\]$", "", entry.split(" — ", 1)[0])
            names = members(name)
            parent_id = identity(tier, "matrix:" + json.dumps(sorted(names, key=str.casefold)))
            for member in names:
                rows.append({"tier": tier, "source": member,
                             "source_id": identity(tier, member),
                             "matrix_entry_id": parent_id, "matrix_entry": entry,
                             "outcome": "not_attempted", "attempts": [],
                             "reason": "Research pending; each member requires its own receipt"})
    if {r["tier"] for r in rows} != set(range(1, 10)):
        raise ValueError("Matrix structure changed; review roster parser")
    if len({r["source_id"] for r in rows}) != len(rows):
        raise ValueError("Duplicate member identity; review source matrix grouping")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=Path(__file__).resolve().parents[1]
                        / "skills/cyber-threat-intel/references/source-matrix.md")
    args = parser.parse_args()
    raw = args.matrix.read_bytes()
    rows = roster(raw.decode())
    print(json.dumps({"matrix_sha256": hashlib.sha256(raw).hexdigest(),
                      "matrix_entry_count": len({r["matrix_entry_id"] for r in rows}),
                      "member_receipt_count": len(rows), "sources": rows}, indent=2))


if __name__ == "__main__":
    main()
