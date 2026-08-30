"""CLI: render an executive overview from a validated skill-output JSON file.

    python -m threat_intel_mcp.render report.json -o overview.html

Deliberately not an MCP tool. The server's tool surface is the *feed* contract,
mirrored in both skill files and asserted by the skill-to-server parity test
(#79); rendering is a local transform of data the caller already holds, so
adding it there would widen that contract for no benefit.
"""

from __future__ import annotations

import argparse
import json
import sys

from .executive import render_executive_overview


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m threat_intel_mcp.render",
        description="Render an executive overview (HTML) from skill output JSON.",
    )
    parser.add_argument("input", help="path to the skill output JSON, or - for stdin")
    parser.add_argument("-o", "--output", help="write here instead of stdout")
    args = parser.parse_args(argv)

    raw = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8").read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: input is not valid JSON: {exc}", file=sys.stderr)
        return 2

    html = render_executive_overview(payload)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(html)
    else:
        sys.stdout.write(html)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
