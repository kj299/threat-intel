"""Render a threat-intel markdown report as one self-contained HTML page.

    python -m threat_intel_mcp.render report.md -o report.html --label "Live feeds"

The skill's scheduled run publishes its report as markdown to a job log, which is
a poor way to read a week of intelligence. This turns that markdown into a page
that reads well on a desktop and a phone, follows the executive renderer's
conventions (a sequential single-hue ramp for priority rather than red/amber/
green, nothing encoded by colour alone, a `MINIMAL` report that *looks* thinner),
and is safe to open.

**The report text is untrusted.** It is built from feed content, so a feed string
can carry markup (R6: source content is data, not instructions). The page is
therefore built to be inert whatever the markdown says, in layers:

* raw HTML in the source is *escaped*, never rendered (`html=False`);
* images are disabled outright -- an ``<img>`` pointing at a feed-supplied URL is
  an exfiltration beacon;
* links survive only for ``http``, ``https``, ``mailto`` and in-page anchors, so
  ``javascript:``, ``data:``, ``file:`` and relative paths stay literal text;
* every surviving external link gets ``rel="noopener noreferrer nofollow"`` and
  its **real destination host** shown beside it, so link text cannot pose as one
  site while pointing at another (an IDN host is shown in its punycode form, which
  is what exposes a homograph);
* the document carries a Content-Security-Policy that forbids scripts, frames,
  images and every network request, and a ``no-referrer`` policy, so something
  that slipped through the first four still cannot run or phone home.

``markdown-it-py`` is imported only when a page is rendered. It is the
``report`` extra (and part of ``dev``), so the server, the feed adapters and the
executive renderer never need it.
"""

from __future__ import annotations

import datetime
import hashlib
import html
import re
from urllib.parse import urlsplit

_INSTALL_HINT = (
    "rendering a markdown report needs markdown-it-py: "
    "pip install 'threat-intel-mcp[report]'"
)

_HEADER_KEYS = ("Generated", "Coverage", "Time Range", "Scope", "Persona")
_ALLOWED_LINK = re.compile(r"^(https?://|mailto:|#)", re.IGNORECASE)

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#16202a;--muted:#5b6672;--rule:#d9dee4;--accent:#1f4e79;
--code:#eef1f4;--p1:#08306b;--p2:#2171b5;--p3:#6baed6;--p4:#bdd7e7;--p5:#eff3ff;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#10151b;--card:#18202a;--ink:#e6ebf0;--muted:#9aa7b4;--rule:#2b3643;--accent:#7fb2e5;
--code:#202b37;--p1:#deebf7;--p2:#9ecae1;--p3:#6baed6;--p4:#3182bd;--p5:#08519c}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:24px 16px 64px}
header.card{background:var(--card);border:1px solid var(--rule);border-radius:12px;padding:20px 24px;margin-bottom:20px}
header.card h1{margin:0 0 12px;font-size:1.05rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:4px 18px;margin:0}
dl.meta dt{color:var(--muted)}dl.meta dd{margin:0;font-weight:600;overflow-wrap:anywhere}
.badge{display:inline-block;padding:1px 10px;border-radius:999px;border:2px solid var(--accent);font-weight:700;letter-spacing:.04em}
.badge.minimal{border-style:dashed;color:var(--muted);border-color:var(--muted);font-weight:600}
.badge.partial{border-style:solid;border-width:1px}
.thin{margin-top:14px;padding:10px 14px;border-left:4px dashed var(--muted);background:var(--code);color:var(--muted);border-radius:4px}
nav.toc{background:var(--card);border:1px solid var(--rule);border-radius:12px;padding:12px 24px;margin-bottom:20px}
nav.toc ol{margin:6px 0;padding-left:20px;columns:2;column-gap:32px}nav.toc a{color:var(--accent)}
article{background:var(--card);border:1px solid var(--rule);border-radius:12px;padding:8px 24px 24px}
h2{margin:36px 0 8px;padding-bottom:6px;border-bottom:2px solid var(--rule);font-size:1.4rem;scroll-margin-top:12px}
h3{margin:28px 0 6px;font-size:1.12rem;scroll-margin-top:12px}h4{margin:20px 0 4px;font-size:1rem}
a{color:var(--accent)}a[data-host]::after{content:" \\2039" attr(data-host) "\\203a";font-size:.78em;color:var(--muted);white-space:nowrap}
p,ul,ol{overflow-wrap:anywhere}li{margin:3px 0}
code{font:0.88em var(--mono);background:var(--code);padding:1px 5px;border-radius:4px}
pre{background:var(--code);border:1px solid var(--rule);border-radius:8px;padding:12px 14px;overflow-x:auto;line-height:1.45}
pre code{background:none;padding:0;font-size:.85rem}
.tablewrap{overflow-x:auto;margin:12px 0;border:1px solid var(--rule);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:.92rem}
th,td{padding:7px 10px;border-bottom:1px solid var(--rule);text-align:left;vertical-align:top}
th{background:var(--code);white-space:nowrap}tr:last-child td{border-bottom:none}
.pri{display:inline-block;padding:0 8px;border-radius:4px;font-weight:700;white-space:nowrap;border:1px solid currentColor}
.pri.p1{background:var(--p1);color:var(--bg)}.pri.p2{background:var(--p2);color:var(--bg)}
.pri.p3{background:var(--p3);color:#10151b}.pri.p4{background:var(--p4);color:#10151b}.pri.p5{background:var(--p5);color:var(--ink)}
blockquote{margin:16px 0;padding:2px 16px;border-left:4px solid var(--accent);background:var(--code);border-radius:4px}
hr{border:0;border-top:1px solid var(--rule);margin:24px 0}
footer{margin-top:20px;color:var(--muted);font-size:.82rem;overflow-wrap:anywhere}
@media (max-width:640px){.wrap{padding:12px 8px 48px}article,header.card,nav.toc{padding-left:14px;padding-right:14px}
nav.toc ol{columns:1}dl.meta{grid-template-columns:1fr}dl.meta dt{margin-top:6px}}
@media print{body{background:#fff;color:#000}.wrap{max-width:none;padding:0}nav.toc{display:none}
header.card,article{border:none;padding:0}a{color:#000}pre,.tablewrap{break-inside:avoid}}
"""

_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"


def _is_allowed_link(url: str) -> bool:
    return bool(_ALLOWED_LINK.match(url.strip()))


def _display_host(href: str) -> str:
    """The destination host as it will really resolve, or '' if there is none.

    A non-ASCII host is shown as punycode: that is the form that makes a
    look-alike (a Cyrillic ``а`` in ``apple.com``) visibly different.
    """
    try:
        host = urlsplit(href).hostname or ""
    except ValueError:  # e.g. an unterminated IPv6 literal
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _harden_links(state) -> None:
    """markdown-it core rule: tag every surviving link with rel and its host."""
    for block in state.tokens:
        if block.type != "inline":
            continue
        for token in block.children or []:
            if token.type != "link_open":
                continue
            token.attrSet("rel", "noopener noreferrer nofollow")
            host = _display_host(token.attrGet("href") or "")
            if host:
                token.attrSet("data-host", host)


def _parser():
    try:
        from markdown_it import MarkdownIt
    except ImportError as exc:  # pragma: no cover - exercised by test via sys.modules
        raise RuntimeError(_INSTALL_HINT) from exc
    md = (
        MarkdownIt("commonmark", {"html": False, "linkify": False})
        .enable("table")
        .disable("image")
    )
    md.validateLink = _is_allowed_link
    md.core.ruler.push("harden_links", _harden_links)
    return md


def _slug(text: str) -> str:
    plain = html.unescape(re.sub(r"<[^>]+>", "", text)).lower()
    return re.sub(r"[^a-z0-9]+", "-", plain).strip("-") or "section"


def _split_header(markdown: str) -> tuple[dict[str, str], str]:
    """Pull the plain-text header block off the top, if the report has one.

    The skill's header is five ``Key: value`` lines with no blank line between
    them, which markdown would fuse into one paragraph.
    """
    lines = markdown.splitlines()
    if not lines or not lines[0].strip().upper().startswith("THREAT INTELLIGENCE REPORT"):
        return {}, markdown
    pattern = re.compile(r"^(%s):\s*(.+)$" % "|".join(map(re.escape, _HEADER_KEYS)))
    meta: dict[str, str] = {}
    i = 1
    while i < len(lines):
        match = pattern.match(lines[i].strip())
        if not match:
            break
        meta[match.group(1)] = match.group(2).strip()
        i += 1
    return (meta, "\n".join(lines[i:])) if meta else ({}, markdown)


def _decorate(body: str) -> tuple[str, list[tuple[str, str]]]:
    """Heading ids and a contents list, scrollable tables, priority chips."""
    toc: list[tuple[str, str]] = []
    seen: dict[str, int] = {}

    def heading(match: re.Match) -> str:
        level, inner = match.group(1), match.group(2)
        base = _slug(inner)
        count = seen.get(base, 0)
        seen[base] = count + 1
        sid = base if count == 0 else f"{base}-{count + 1}"  # ids must be unique
        if level == "2":
            # Plain text, not the heading's HTML: a link inside a heading must
            # not become a nested anchor (or an external link) in the contents.
            toc.append((sid, html.unescape(re.sub(r"<[^>]+>", "", inner))))
        return f'<h{level} id="{sid}">{inner}</h{level}>'

    body = re.sub(r"<h([234])>(.*?)</h\1>", heading, body, flags=re.S)
    body = body.replace("<table>", '<div class="tablewrap"><table>').replace(
        "</table>", "</table></div>"
    )

    def chip(match: re.Match) -> str:
        return f'{match.group(1)}<span class="pri p{match.group(3)}">{match.group(2)}</span>'

    # Only inside table cells, and the label text is always kept, so priority is
    # never encoded by colour alone. `P2-HIGH` and a bare `P2` both qualify; the
    # lookarounds keep `TOP1` and `P1x` from being mistaken for one.
    def cell(match: re.Match) -> str:
        return re.sub(r"(^|[\s>(])(P([1-5])(?:-[A-Z]+)?)(?![\w-])", chip, match.group(0))

    return re.sub(r"<td>.*?</td>", cell, body, flags=re.S), toc


def render_report_page(
    markdown: str,
    *,
    source_name: str = "report.md",
    label: str = "",
    now: datetime.datetime | None = None,
) -> str:
    """Return one self-contained HTML document for a markdown report.

    ``label`` tags the page (for instance ``Live feeds``) so two renderings of the
    same day cannot be confused; ``now`` fixes the footer timestamp for tests.
    """
    meta, rest = _split_header(markdown)
    body, toc = _decorate(_parser().render(rest))

    coverage = meta.get("Coverage", "").upper()
    modifier = {"MINIMAL": "minimal", "PARTIAL": "partial"}.get(coverage, "")
    badge_class = f"badge {modifier}".strip()
    rows = "".join(
        f"<dt>{html.escape(key)}</dt><dd>"
        + (
            f'<span class="{badge_class}">COVERAGE: {html.escape(value.upper())}</span>'
            if key == "Coverage"
            else html.escape(value)
        )
        + "</dd>"
        for key, value in meta.items()
    )
    thin = (
        '<div class="thin">Limited source coverage. This page should not be read as a full '
        "picture of the period; see the Intelligence Gaps section and the Source Coverage "
        "Ledger for exactly what was and was not consulted.</div>"
        if coverage == "MINIMAL"
        else ""
    )
    heading = "Threat Intelligence Report" + (f" · {html.escape(label)}" if label else "")
    header = (
        f'<header class="card"><h1>{heading}</h1><dl class="meta">{rows}</dl>{thin}</header>'
        if meta
        else ""
    )
    nav = (
        '<nav class="toc" aria-label="Contents"><strong>Contents</strong><ol>'
        + "".join(f'<li><a href="#{sid}">{html.escape(text)}</a></li>' for sid, text in toc)
        + "</ol></nav>"
        if len(toc) > 2
        else ""
    )
    title = " — ".join(
        html.escape(part)
        for part in ("Threat Intelligence Report", meta.get("Persona", ""), meta.get("Generated", ""), label)
        if part
    )
    digest = hashlib.sha256(markdown.encode("utf-8")).hexdigest()[:12]
    stamp = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>{title}</title><style>{_CSS}</style></head><body><div class=\"wrap\">"
        f"{header}{nav}<article>{body}</article>"
        f"<footer>Rendered {stamp} from <code>{html.escape(source_name)}</code> (sha256 {digest}). "
        "Raw HTML in the source is escaped, not rendered; this page loads no scripts, images or "
        "external resources.</footer></div></body></html>"
    )
