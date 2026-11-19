"""Emit every named source in the checked-out matrix as an unattempted receipt.

This is a research checklist, never evidence of consultation. Populate a copy
with actual attempts; do not write a completed historical report back to repo.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path


def roster(text):
    tier = None
    rows = []
    for line in text.splitlines():
        heading = re.match(r"## Tier (\d+):", line)
        if heading:
            tier = int(heading[1])
        if tier and line.startswith("- ") and re.search(r"\[(MUST|SHOULD)\]", line):
            name = line[2:].split(" — ", 1)[0]
            rows.append({"tier": tier, "source": name, "matrix_entry": line[2:],
                         "outcome": "not_attempted", "attempts": [],
                         "reason": "Research pending; registry membership is not consultation"})
    if {r["tier"] for r in rows} != set(range(1, 10)):
        raise ValueError("Matrix structure changed; review roster parser")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=Path(__file__).resolve().parents[1]
                        / "skills/cyber-threat-intel/references/source-matrix.md")
    args = parser.parse_args()
    raw = args.matrix.read_bytes()
    print(json.dumps({"matrix_sha256": hashlib.sha256(raw).hexdigest(),
                      "sources": roster(raw.decode())}, indent=2))


if __name__ == "__main__":
    main()
