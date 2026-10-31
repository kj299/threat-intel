"""The markdown-report HTML renderer (``threat_intel_mcp.render.report``).

The report it renders is built from feed content, so it is untrusted (R6): a feed
string can carry markup, a script, a beacon image or a link whose text lies about
its destination. The tests therefore check the one property that matters -- *what
the page can contain* -- by parsing the output and holding every tag, attribute and
link target to an allowlist, rather than grepping for the bad strings someone
thought of. The allowlist is applied to a hostile document and to every real report
in the frozen corpus, so a new rendering path that emits something outside it fails
on input nobody had to craft.

Rendering cosmetics (the header card, priority chips, the contents list) get their
own tests, because an unreadable report is a failure too, just a quieter one.
"""

from __future__ import annotations

import datetime
import hashlib
import io
import pathlib
import re
import subprocess
import sys
from html.parser import HTMLParser

import pytest

from threat_intel_mcp.render import render_report_page
from threat_intel_mcp.render.__main__ import main

_REPO = pathlib.Path(__file__).resolve().parents[2]
_REPORTS = sorted((_REPO / "reports").glob("*.md"))
_NOW = datetime.datetime(2026, 10, 28, 12, 0, tzinfo=datetime.timezone.utc)

# Every tag the renderer may emit, and the attributes each may carry. Anything
# else -- <script>, <iframe>, <img>, <form>, <link>, <object>, an on* handler, a
# src -- is a failure by construction.
_TAGS = {
    "html", "head", "meta", "title", "style", "body", "div", "header", "footer", "article", "nav",
    "h1", "h2", "h3", "h4", "p", "br", "hr", "ul", "ol", "li", "dl", "dt", "dd", "span", "a",
    "strong", "em", "code", "pre", "blockquote", "table", "thead", "tbody", "tr", "th", "td",
}  # fmt: skip
_ATTRS = {
    "html": {"lang"},
    "meta": {"charset", "name", "content", "http-equiv"},
    "div": {"class"},
    "header": {"class"},
    "dl": {"class"},
    "span": {"class"},
    "nav": {"class", "aria-label"},
    "h2": {"id"},
    "h3": {"id"},
    "h4": {"id"},
    "a": {"href", "rel", "data-host"},
    "ol": {"start"},
    "code": {"class"},
    "th": {"style"},
    "td": {"style"},
}
_HREF = re.compile(r"^(https?://|mailto:|#)")
_ALIGN = re.compile(r"^text-align:(left|right|center)$")

_HEADER = (
    "THREAT INTELLIGENCE REPORT\n"
    "Generated: 2026-10-28\n"
    "Coverage: {coverage}\n"
    "Time Range: 2026-10-23 to 2026-10-28\n"
    "Scope: all emerging threats\n"
    "Persona: enterprise_soc\n\n"
)

_HOSTILE = (
    "THREAT INTELLIGENCE REPORT\n"
    "Generated: 2026-10-28<img src=x onerror=alert(1)>\n"
    "Coverage: MINIMAL\"><script>alert(1)</script>\n"
    "Time Range: a to b\nScope: s\nPersona: enterprise_soc<b>\n\n"
    "# H1 <script>alert(1)</script>\n\n"
    "## Section <img src=x onerror=alert(1)>\n\n"
    "<script>fetch('https://evil.example/x')</script>\n"
    '<iframe src="https://evil.example"></iframe>\n'
    '<div onclick="x()">raw</div>\n'
    "<style>@import url(https://evil.example/x.css)</style>\n\n"
    "[js](javascript:alert(1)) [vb](vbscript:x) [data](data:text/html,<script>alert(1)</script>) "
    "[file](file:///etc/passwd) [rel](../secret.md) [ftp](ftp://evil.example/x)\n\n"
    "[ok](https://example.org/p?q=1&r=2) [mail](mailto:a@example.org) [anchor](#section)\n\n"
    "![beacon](https://evil.example/pixel.png) ![ref][r]\n\n"
    "[r]: https://evil.example/ref.png\n\n"
    "| a | b |\n|:--|--:|\n| P1-CRITICAL <b onmouseover=alert(1)>x</b> | `<script>` |\n\n"
    "```html\n<script>alert(1)</script>\n```\n\n"
    "<https://evil.example/autolink> and a bare https://evil.example/bare\n"
)


class _Parse(HTMLParser):
    """Collect every start tag with its attributes, and every link target."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def of(self, name: str) -> list[dict[str, str | None]]:
        return [a for t, a in self.tags if t == name]

    def hrefs(self) -> list[str]:
        return [a["href"] for a in self.of("a")]


def _parse(page: str) -> _Parse:
    parser = _Parse()
    parser.feed(page)
    return parser


def _assert_inert(page: str) -> _Parse:
    """The page contains nothing outside the allowlist; returns the parse."""
    parsed = _parse(page)
    for tag, attrs in parsed.tags:
        assert tag in _TAGS, f"<{tag}> is not an element the renderer may emit"
        extra = set(attrs) - _ATTRS.get(tag, set())
        assert not extra, f"<{tag}> carries attribute(s) outside the allowlist: {sorted(extra)}"
        if tag in {"th", "td"} and attrs.get("style"):
            assert _ALIGN.match(attrs["style"]), f"unexpected cell style {attrs['style']!r}"
        if tag == "a":
            assert _HREF.match(attrs["href"] or ""), f"link target {attrs['href']!r} is not allowed"
            if not (attrs["href"] or "").startswith("#"):
                assert "noopener" in (attrs.get("rel") or ""), "an external link lacks rel=noopener"
    assert "<script" not in page.lower() and "<iframe" not in page.lower()
    return parsed


# --- The page is inert, whatever the markdown says ---------------------------


def test_hostile_markdown_is_escaped_not_rendered():
    page = render_report_page(_HOSTILE, now=_NOW)
    _assert_inert(page)
    # Escaped, not dropped: an analyst still sees what the feed tried to say.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;iframe" in page and "&lt;div onclick" in page


def test_only_http_https_mailto_and_anchor_links_survive():
    hrefs = _parse(render_report_page(_HOSTILE, now=_NOW)).hrefs()
    # javascript:, vbscript:, data:, file:, ftp: and the relative path stay literal text.
    assert sorted(hrefs) == sorted(
        [
            "https://example.org/p?q=1&r=2",
            "mailto:a@example.org",
            "#section",
            "https://evil.example/autolink",
            "https://evil.example/pixel.png",  # the image, demoted to a link the reader must click
            "https://evil.example/ref.png",
        ]
    )
    page = render_report_page("[x](javascript:alert(1)) [y](../secret.md)", now=_NOW)
    assert "[x](javascript:alert(1))" in page and "[y](../secret.md)" in page


def test_images_are_never_emitted():
    parsed = _parse(render_report_page(_HOSTILE, now=_NOW))
    assert not parsed.of("img")
    assert all("src" not in attrs for _, attrs in parsed.tags)


def test_a_bare_url_is_not_turned_into_a_link():
    assert "https://evil.example/bare" not in _parse(render_report_page(_HOSTILE, now=_NOW)).hrefs()


def test_the_document_forbids_scripts_frames_images_and_network_access():
    metas = _parse(render_report_page("# x", now=_NOW)).of("meta")
    policy = next(m["content"] for m in metas if m.get("http-equiv") == "Content-Security-Policy")
    assert "default-src 'none'" in policy
    assert "script-src" not in policy and "unsafe-eval" not in policy and "https:" not in policy
    assert any(m.get("name") == "referrer" and m.get("content") == "no-referrer" for m in metas)


def test_header_values_title_label_and_source_name_are_escaped():
    page = render_report_page(_HOSTILE, source_name="x<y>.md", label="<b>Live</b>", now=_NOW)
    parsed = _assert_inert(page)
    assert "x&lt;y&gt;.md" in page and "&lt;b&gt;Live&lt;/b&gt;" in page
    assert not parsed.of("b")


@pytest.mark.parametrize("report", _REPORTS, ids=lambda p: p.name)
def test_every_frozen_report_renders_inert(report):
    page = render_report_page(report.read_text(encoding="utf-8"), source_name=report.name, now=_NOW)
    parsed = _assert_inert(page)
    assert len(parsed.of("h2")) >= 2, "a real report renders with its sections"


def test_the_frozen_corpus_was_found():
    assert len(_REPORTS) == 11, "reports/ is the frozen eval corpus; the renderer test walks all of it"


# --- Links: the real destination is always visible ----------------------------


def test_external_links_are_hardened_and_show_their_real_host():
    page = render_report_page(
        "[Tenable](https://www.tenable.com/blog/x) and [cisa.gov](https://evil.example/login)", now=_NOW
    )
    links = _parse(page).of("a")
    assert [a["data-host"] for a in links] == ["www.tenable.com", "evil.example"]
    assert all(a["rel"] == "noopener noreferrer nofollow" for a in links)


def test_an_idn_host_is_shown_as_punycode_so_a_lookalike_is_visible():
    page = render_report_page("[apple](https://аpple.com/)", now=_NOW)  # Cyrillic a
    host = _parse(page).of("a")[0]["data-host"]
    assert host.startswith("xn--") and host.endswith(".com")


def test_in_page_anchors_and_malformed_urls_do_not_break_rendering():
    page = render_report_page("[a](#top) [b](http://[::1/) [c](mailto:x@example.org)", now=_NOW)
    parsed = _assert_inert(page)  # no exception, nothing outside the allowlist
    anchors = {a["href"]: a for a in parsed.of("a")}
    assert "data-host" not in anchors["#top"]
    assert "data-host" not in anchors["mailto:x@example.org"]


# --- The report reads well ------------------------------------------------------


@pytest.mark.parametrize(
    ("coverage", "css", "thin"),
    [("MINIMAL", "minimal", True), ("PARTIAL", "partial", False), ("FULL", "", False)],
)
def test_header_block_becomes_a_card_and_a_minimal_report_looks_thinner(coverage, css, thin):
    page = render_report_page(_HEADER.format(coverage=coverage) + "## S\n\ntext\n", now=_NOW)
    parsed = _assert_inert(page)
    assert f"COVERAGE: {coverage}" in page
    badge = next(a for a in parsed.of("span") if "badge" in (a.get("class") or ""))
    assert badge["class"] == f"badge {css}".strip()
    assert ("Limited source coverage" in page) is thin
    # The five header lines are a definition list, not one fused paragraph.
    assert [k for k in ("Generated", "Coverage", "Time Range", "Scope", "Persona") if f"<dt>{k}</dt>" in page] == [
        "Generated", "Coverage", "Time Range", "Scope", "Persona"
    ]  # fmt: skip
    assert "THREAT INTELLIGENCE REPORT\nGenerated" not in page


def test_a_report_without_the_header_block_renders_its_body_only():
    page = render_report_page("## Findings\n\nNothing this week.\n", now=_NOW)
    assert 'class="card"' not in page and "Nothing this week." in page


def test_priority_labels_become_chips_inside_tables_only_and_keep_their_text():
    md = (
        "P1-CRITICAL outside a table is plain prose.\n\n"
        "| item | priority |\n|---|---|\n"
        "| a | P1-CRITICAL |\n| b | P2 |\n| c | TOP1 |\n| d | P1x |\n| e | P6 |\n| f | P4-LOW |\n"
    )
    page = render_report_page(md, now=_NOW)
    chips = re.findall(r'<span class="pri p([1-5])">([^<]+)</span>', page)
    # The label text is the content; colour is only an extra, never the signal.
    assert chips == [("1", "P1-CRITICAL"), ("2", "P2"), ("4", "P4-LOW")]
    assert "P1-CRITICAL outside a table is plain prose." in page


def test_headings_get_unique_ids_and_the_contents_list_is_plain_anchors():
    md = "## Notes\n\n## Notes\n\n## See [CISA](https://www.cisa.gov/x)\n\n### Sub\n"
    page = render_report_page(md, now=_NOW)
    parsed = _assert_inert(page)
    ids = [a["id"] for t, a in parsed.tags if t in {"h2", "h3"}]
    assert ids == ["notes", "notes-2", "see-cisa", "sub"] and len(set(ids)) == len(ids)
    nav = re.search(r"<nav.*?</nav>", page, re.S).group(0)
    assert re.findall(r'href="([^"]+)"', nav) == ["#notes", "#notes-2", "#see-cisa"]
    assert "data-host" not in nav, "a link inside a heading must not leak into the contents list"


def test_a_short_report_has_no_contents_list():
    assert "<nav" not in render_report_page("## One\n\n## Two\n", now=_NOW)


def test_tables_scroll_and_code_is_kept_as_escaped_text():
    md = "| a | b |\n|---|---|\n| 1 | 2 |\n\n```csv\nIPv4,1.2.3.4,<x>\n```\n"
    page = render_report_page(md, now=_NOW)
    assert page.count('class="tablewrap"') == page.count("<table>") == 1
    assert "IPv4,1.2.3.4,&lt;x&gt;" in page


def test_the_footer_is_deterministic_and_names_its_source():
    md = "## S\n\ntext\n"
    first = render_report_page(md, source_name="a.md", label="L", now=_NOW)
    assert first == render_report_page(md, source_name="a.md", label="L", now=_NOW)
    assert "2026-10-28 12:00 UTC" in first and "a.md" in first
    assert hashlib.sha256(md.encode()).hexdigest()[:12] in first


def test_the_title_names_persona_date_and_label():
    page = render_report_page(_HEADER.format(coverage="MINIMAL"), label="Live feeds", now=_NOW)
    title = re.search(r"<title>(.*?)</title>", page).group(1)
    assert title == "Threat Intelligence Report — enterprise_soc — 2026-10-28 — Live feeds"


# --- The dependency is optional and loaded lazily --------------------------------


def test_the_package_does_not_import_the_markdown_parser_until_a_page_is_rendered():
    code = (
        "import sys, threat_intel_mcp.render, threat_intel_mcp.render.executive as e;"
        "assert 'markdown_it' not in sys.modules, 'markdown_it loaded at import time'"
    )
    done = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_a_missing_parser_gives_an_actionable_error(monkeypatch, tmp_path, capsys):
    monkeypatch.setitem(sys.modules, "markdown_it", None)  # makes `import markdown_it` fail
    with pytest.raises(RuntimeError, match=r"threat-intel-mcp\[report\]"):
        render_report_page("## x", now=_NOW)
    src = tmp_path / "r.md"
    src.write_text("## x\n", encoding="utf-8")
    assert main([str(src)]) == 3
    assert "threat-intel-mcp[report]" in capsys.readouterr().err


# --- CLI ---------------------------------------------------------------------------


def test_cli_renders_a_markdown_file_by_suffix(tmp_path):
    src, dest = tmp_path / "week.md", tmp_path / "week.html"
    src.write_text(_HEADER.format(coverage="MINIMAL") + "## Findings\n\nok\n", encoding="utf-8")
    assert main([str(src), "-o", str(dest), "--label", "Live feeds"]) == 0
    page = dest.read_text(encoding="utf-8")
    _assert_inert(page)
    assert page.startswith("<!doctype html>") and "Live feeds" in page and "week.md" in page


def test_cli_reads_a_report_from_stdin_with_format_report(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("## From stdin\n"))
    assert main(["-", "--format", "report"]) == 0
    out = capsys.readouterr().out
    assert "From stdin" in out and "stdin" in out.split("<footer>")[1]


def test_cli_still_treats_json_as_the_executive_overview(tmp_path, capsys):
    src = tmp_path / "out.json"
    src.write_text("{not json", encoding="utf-8")
    assert main([str(src)]) == 2  # routed to the JSON path, not the markdown one
    assert "not valid JSON" in capsys.readouterr().err


def test_cli_reports_an_unreadable_input_cleanly(tmp_path, capsys):
    assert main([str(tmp_path / "missing.md")]) == 2
    assert "cannot read" in capsys.readouterr().err
