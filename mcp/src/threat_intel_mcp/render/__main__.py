"""CLI: render skill output to HTML.

    python -m threat_intel_mcp.render report.json -o overview.html   # executive overview
    python -m threat_intel_mcp.render report.md -o report.html       # the markdown report, as a page

The input type picks the renderer (``.md`` / ``.markdown`` is a report page,
anything else is skill-output JSON for the executive overview); ``--format``
overrides that, which is how stdin selects the report renderer.

Deliberately not an MCP tool. The server's tool surface is the *feed* contract,
mirrored in both skill files and asserted by the skill-to-server parity test
(#79); rendering is a local transform of data the caller already holds, so
adding it there would widen that contract for no benefit.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .executive import render_executive_overview
from .report import render_report_page

_REPORT_SUFFIXES = {".md", ".markdown"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m threat_intel_mcp.render",
        description=(
            "Render skill output to HTML: an executive overview from skill output JSON, "
            "or a self-contained page from a markdown report."
        ),
    )
    parser.add_argument("input", help="skill output JSON or a markdown report, or - for stdin")
    parser.add_argument("-o", "--output", help="write here instead of stdout")
    parser.add_argument(
        "--format",
        choices=("auto", "executive", "report"),
        default="auto",
        help="auto: .md/.markdown is a report, anything else (and stdin) is executive JSON",
    )
    parser.add_argument(
        "--label",
        default="",
        help='tag a report page, e.g. "Live feeds", so two renderings cannot be confused',
    )
    args = parser.parse_args(argv)

    fmt = args.format
    if fmt == "auto":
        suffix = pathlib.Path(args.input).suffix.lower() if args.input != "-" else ""
        fmt = "report" if suffix in _REPORT_SUFFIXES else "executive"

    try:
        raw = sys.stdin.read() if args.input == "-" else pathlib.Path(args.input).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read {args.input}: {exc}", file=sys.stderr)
        return 2

    if fmt == "report":
        name = "stdin" if args.input == "-" else pathlib.Path(args.input).name
        try:
            html = render_report_page(raw, source_name=name, label=args.label)
        except RuntimeError as exc:  # markdown-it-py not installed
            print(f"error: {exc}", file=sys.stderr)
            return 3
    else:
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
