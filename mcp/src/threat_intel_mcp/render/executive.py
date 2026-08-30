"""Rendered HTML executive overview (issue #110).

Turns an `enterprise_executive` skill output into a single self-contained,
landscape HTML page. No new data is required: everything rendered already exists
in the validated output object.

─── Why the risk scale is one hue rather than red/amber/green ────────────────

The obvious choice is the status palette (green/amber/orange/red). It fails the
brief. Measured greyscale luminance of those four steps:

    good     #0ca30c  0.263
    warning  #fab219  0.522   <- lightest
    serious  #ec835a  0.348
    critical #d03b3b  0.169   <- darkest

That ordering is not monotonic: printed or photocopied, "low" (0.263) and
"high" (0.348) are nearly the same grey, and "moderate" is *lighter* than both.
Issue #110 calls this out directly — "a red/amber/green dashboard that degrades
to three identical greys is worse than a table".

A risk score is a magnitude, so it takes a sequential single-hue ramp instead,
which is monotonic in lightness by construction:

    low       #86b6ef  0.448   contrast 2.06
    moderate  #5598e7  0.302   contrast 2.91
    high      #2a78d6  0.188   contrast 4.30
    critical  #184f95  0.080   contrast 7.89

Minimum adjacent greyscale gap 0.108, and contrast rises with severity, so the
more serious band is always the darker mark on paper as well as on screen.
`#86b6ef` is the documented light-surface floor for this ramp (2.06:1).

The status palette is still used, but only for `alert_level` — a genuine state
rather than a magnitude — where the icon-plus-label pairing is the documented
mitigation for status hues that cannot carry meaning alone.

─── Redundant encoding ───────────────────────────────────────────────────────

Nothing here is encoded by colour alone. Every risk carries its numeral and its
band word; every trend carries an arrow glyph and the word; the alert level
carries an icon and its name. Strip all colour and the page still reads.

Trend is deliberately *not* colour-coded at all. Risk level and direction of
travel are different axes, and colouring a falling trend green next to a
critical score tells the reader two contradictory things at once.
"""

from __future__ import annotations

import html
import re
from typing import Any

# ─── Thresholds ──────────────────────────────────────────────────────────────
# Explicit and deterministic so two reports a week apart are comparable. Bands
# are inclusive on both ends and must tile 0-100 without gaps; asserted in tests.
RISK_BANDS: tuple[tuple[int, int, str, str], ...] = (
    (0, 39, "Low", "#86b6ef"),
    (40, 59, "Moderate", "#5598e7"),
    (60, 79, "High", "#2a78d6"),
    (80, 100, "Critical", "#184f95"),
)

# Status palette, used only for alert level. Always paired with icon + label.
_ALERT_STATUS: dict[str, tuple[str, str]] = {
    "low": ("#0ca30c", "●"),
    "guarded": ("#0ca30c", "●"),
    "elevated": ("#fab219", "▲"),
    "high": ("#ec835a", "▲"),
    "severe": ("#d03b3b", "■"),
    "critical": ("#d03b3b", "■"),
}

# Trend glyphs. The data already carries arrows for categories; normalise both
# the arrow form and the word form to one (glyph, word) pair.
_TRENDS: dict[str, tuple[str, str]] = {
    "↑": ("↑", "rising"),
    "→": ("→", "flat"),
    "↓": ("↓", "falling"),
    "increasing": ("↑", "rising"),
    "stable": ("→", "flat"),
    "decreasing": ("↓", "falling"),
}

_TOP_N_CATEGORIES = 3


def risk_band(score: int | float) -> tuple[str, str]:
    """Map a 0-100 risk score to its (label, hex) band. Raises outside range."""
    for low, high, label, hex_ in RISK_BANDS:
        if low <= score <= high:
            return label, hex_
    raise ValueError(f"risk score {score!r} is outside 0-100")


def _trend(value: str | None) -> tuple[str, str]:
    if not value:
        return "", "not reported"
    return _TRENDS.get(str(value).strip().lower(), _TRENDS.get(str(value).strip(), ("", str(value))))


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _pct(score: float) -> float:
    """Clamp a score to a 0-100 bar width."""
    return max(0.0, min(100.0, float(score)))


def render_executive_overview(skill_output: dict[str, Any]) -> str:
    """Render an executive overview as a self-contained HTML document.

    `skill_output` is the validated `skill_output` object (or a bare output
    object carrying the same keys). Absent sections render as an explicit
    absence, never as a reassuring default — R3 applies to presentation as much
    as to content: a confident-looking rendering of nothing is worse than an
    obviously sparse one.
    """
    so = skill_output.get("skill_output", skill_output)
    meta = so.get("metadata") or {}
    dash = so.get("risk_dashboard") or {}
    summary = so.get("executive_summary") or {}

    badge = meta.get("coverage_badge")
    parts: list[str] = [
        _head(meta),
        _coverage_band(badge, so.get("coverage_ledger")),
        _alert(so.get("alert_level") or {}),
        _hero(dash),
        _categories(dash.get("risk_by_category") or []),
        _summary(summary),
        _financial(so.get("financial_impact") or {}),
        _investments(so.get("investment_recommendations") or []),
        _footer(meta, so.get("coverage_ledger")),
    ]
    body = "\n".join(p for p in parts if p)
    return _DOCUMENT.format(style=_STYLE, body=body)


# ─── Sections ────────────────────────────────────────────────────────────────


def _head(meta: dict[str, Any]) -> str:
    generated = _esc(meta.get("generated_at") or "date not reported")
    version = _esc(meta.get("skill_version") or "unknown")
    return (
        '<header class="hd"><div><h1>Executive Threat Overview</h1>'
        f'<p class="sub">Generated {generated} · cyber-threat-intel v{version}</p></div></header>'
    )


def _coverage_band(badge: str | None, ledger: Any) -> str:
    """Coverage badge, rendered prominently rather than footnoted.

    A missing badge is reported as missing. Defaulting it would manufacture
    confidence the data does not support, which is the failure #110 names.
    MINIMAL gets a visibly thinner, muted treatment so the page's weight
    matches how much is actually known.
    """
    known = {"FULL", "PARTIAL", "MINIMAL"}
    value = (badge or "").upper()
    if value not in known:
        return (
            '<section class="cov cov-unknown"><span class="cov-k">COVERAGE NOT REPORTED</span>'
            '<span class="cov-n">This overview carries no source-coverage badge. '
            "Treat its completeness as unknown, not as full.</span></section>"
        )
    tiers = len(ledger) if isinstance(ledger, list) else 0
    detail = f"{tiers} source tiers itemised in the ledger" if tiers else "ledger not attached"
    notes = {
        "FULL": "Broad source coverage this period.",
        "PARTIAL": "Partial source coverage — read alongside the gaps section.",
        "MINIMAL": "Limited source coverage this period. Few sources were reachable; "
        "this page is correspondingly thin and should not be read as a full picture.",
    }
    return (
        f'<section class="cov cov-{value.lower()}"><span class="cov-k">COVERAGE: {value}</span>'
        f'<span class="cov-n">{notes[value]} ({detail})</span></section>'
    )


def _alert(alert: dict[str, Any]) -> str:
    level = str(alert.get("level") or "").strip()
    if not level:
        return ""
    # The schema carries a `color`, but palette choices are not delegated to
    # model output: an arbitrary hex would break both the greyscale guarantee
    # and the reserved-status discipline. Map the level ourselves.
    colour, icon = _ALERT_STATUS.get(level.lower(), ("#52514e", "●"))
    message = _esc(alert.get("message") or "")
    return (
        f'<section class="alert" style="border-left-color:{colour}">'
        f'<span class="alert-i" style="color:{colour}" aria-hidden="true">{icon}</span>'
        f'<span class="alert-l">ALERT: {_esc(level.upper())}</span>'
        f'<span class="alert-m">{message}</span></section>'
    )


def _hero(dash: dict[str, Any]) -> str:
    score = dash.get("overall_risk_score")
    if score is None:
        return '<section class="hero"><p class="empty">No overall risk score in this report.</p></section>'
    label, hex_ = risk_band(score)
    glyph, word = _trend(dash.get("risk_trend"))
    delta = _esc(dash.get("trend_percentage") or "")
    peer = _peer(dash.get("peer_comparison") or {}, score)
    return (
        '<section class="hero">'
        f'<div class="score" style="--band:{hex_}">'
        f'<div class="score-n">{_esc(score)}</div>'
        f'<div class="score-m"><span class="pill" style="background:{hex_}">{label} risk</span>'
        f'<span class="trend">{glyph} {word} {delta}</span></div>'
        '<div class="score-c">Overall risk score (0-100)</div></div>'
        f"{peer}</section>"
    )


def _peer(peer: dict[str, Any], ours: float) -> str:
    """Peer comparison as an actual comparison: one shared 0-100 scale."""
    rows = [
        ("This organisation", peer.get("our_score", ours)),
        ("Peer average", peer.get("peer_average")),
        ("Industry best", peer.get("industry_best")),
    ]
    rows = [(name, val) for name, val in rows if val is not None]
    if len(rows) < 2:
        return ""
    bars = []
    for name, val in rows:
        _, hex_ = risk_band(val)
        bars.append(
            f'<div class="bar-r"><span class="bar-l">{_esc(name)}</span>'
            f'<span class="bar-t"><span class="bar-f" style="width:{_pct(val):.0f}%;background:{hex_}"></span></span>'
            f'<span class="bar-v">{_esc(val)}</span></div>'
        )
    note = _esc(peer.get("assessment") or "")
    return (
        '<div class="peer"><h2>Peer comparison <span class="modelled">MODELLED</span></h2>'
        f'{"".join(bars)}'
        f'<p class="peer-a">{note}</p>'
        '<p class="cav">Peer and industry figures are modelled estimates produced by this '
        "skill, not survey measurements. Do not cite them as observed data.</p></div>"
    )


def _categories(cats: list[dict[str, Any]]) -> str:
    if not cats:
        return (
            '<section class="cats"><h2>Top risks by category</h2>'
            '<p class="empty">No category risk scores in this report.</p></section>'
        )
    ranked = sorted(cats, key=lambda c: c.get("score", 0), reverse=True)[:_TOP_N_CATEGORIES]
    tiles = []
    for c in ranked:
        score = c.get("score", 0)
        label, hex_ = risk_band(score)
        glyph, word = _trend(c.get("trend"))
        tiles.append(
            f'<div class="cat" style="--band:{hex_}">'
            f'<div class="cat-h">{_esc(c.get("category", "—"))}</div>'
            f'<div class="cat-s">{_esc(score)}<span class="cat-b">{label}</span></div>'
            f'<div class="cat-t">{glyph} {word}</div>'
            f'<div class="cat-bar"><span style="width:{_pct(score):.0f}%;background:{hex_}"></span></div>'
            "</div>"
        )
    more = len(cats) - len(ranked)
    extra = f'<p class="more">{more} further categories in the full report.</p>' if more > 0 else ""
    return (
        f'<section class="cats"><h2>Top {len(ranked)} risks by category</h2>'
        f'<div class="cat-g">{"".join(tiles)}</div>{extra}</section>'
    )


def _summary(summary: dict[str, Any]) -> str:
    headline = summary.get("headline")
    actions = summary.get("critical_actions") or []
    if not headline and not actions:
        return ""
    items = "".join(f"<li>{_esc(a)}</li>" for a in actions)
    acts = f'<div class="acts"><h2>Decisions required</h2><ol>{items}</ol></div>' if items else ""
    head = f'<p class="headline">{_esc(headline)}</p>' if headline else ""
    return f'<section class="summ">{head}{acts}</section>'


def _financial(fin: dict[str, Any]) -> str:
    if not fin:
        return ""
    labels = {
        "potential_breach_cost": "Potential breach cost",
        "regulatory_fine_risk": "Regulatory fine risk",
        "reputation_impact": "Reputation impact",
        "insurance_coverage": "Insurance position",
    }
    tiles = [
        f'<div class="fin"><div class="fin-k">{labels[k]}'
        f'<span class="modelled">MODELLED</span></div><div class="fin-v">{_esc(fin[k])}</div></div>'
        for k in labels
        if fin.get(k)
    ]
    if not tiles:
        return ""
    return (
        '<section class="fins"><h2>Financial exposure</h2>'
        f'<div class="fin-g">{"".join(tiles)}</div>'
        '<p class="cav">Every figure above is a modelled estimate produced by this skill from '
        "published sector averages. None is an observed loss for this organisation.</p></section>"
    )


def _investments(recs: list[dict[str, Any]]) -> str:
    if not recs:
        return ""
    rows = "".join(
        "<tr>"
        f'<td>{_esc(r.get("initiative", "—"))}</td>'
        f'<td>{_esc(r.get("investment", "—"))}</td>'
        f'<td>{_esc(r.get("risk_reduction", "—"))}</td>'
        f'<td>{_esc(r.get("roi", "—"))}</td>'
        f'<td>{_esc(r.get("timeline", "—"))}</td>'
        "</tr>"
        for r in recs
    )
    return (
        '<section class="inv"><h2>Investment recommendations '
        '<span class="modelled">MODELLED</span></h2>'
        "<table><thead><tr><th>Initiative</th><th>Investment</th>"
        "<th>Risk reduction</th><th>ROI</th><th>Timeline</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        '<p class="cav">Risk-reduction and ROI figures are modelled projections, not '
        "guaranteed outcomes.</p></section>"
    )


def _footer(meta: dict[str, Any], ledger: Any) -> str:
    """Name the companion artifact and say where the evidence lives.

    An executive overview found on its own, months later, must not be
    mistakable for the whole analysis.
    """
    generated = str(meta.get("generated_at") or "")
    date = re.match(r"(\d{4}-\d{2}-\d{2})", generated)
    companion = (
        f"reports/{date.group(1)}-threat-intel.md" if date else "the technical report for this run"
    )
    tiers = len(ledger) if isinstance(ledger, list) else 0
    appendix = (
        f"Source Coverage Ledger: {tiers} tiers, in Appendix A of {companion}."
        if tiers
        else f"The Source Coverage Ledger (Appendix A) is in {companion}."
    )
    return (
        '<footer class="ft"><p><strong>This is a summary, not the analysis.</strong> '
        f"Every finding here is drawn from {companion}, which carries the indicators, "
        f"CVEs, detections and full source accounting. {appendix}</p>"
        "<p>Figures marked MODELLED are estimates produced by this skill, not measurements. "
        "No indicator, CVE or attribution is rendered here that the underlying report does "
        "not contain.</p></footer>"
    )


# ─── Presentation ────────────────────────────────────────────────────────────
# Inline only: no stylesheet link, no script, no font or image fetch. These get
# emailed and opened offline, and a security report that phones out to a CDN is
# an awkward artifact.

_STYLE = """
:root{--s:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--line:#e2e1dc;}
*{box-sizing:border-box}
body{margin:0;background:var(--s);color:var(--ink);
 font:13px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
.pg{max-width:1120px;margin:0 auto;padding:18px 22px}
h1{font-size:19px;margin:0}
h2{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink2);margin:0 0 8px}
.sub{margin:2px 0 0;color:var(--ink2);font-size:11px}
.hd{display:flex;justify-content:space-between;align-items:baseline;
 border-bottom:2px solid var(--ink);padding-bottom:8px;margin-bottom:12px}
section{margin-bottom:14px}
.cov{display:flex;gap:10px;align-items:baseline;padding:8px 10px;border:1px solid var(--line);
 border-left-width:6px;background:#fff}
.cov-k{font-weight:700;letter-spacing:.05em;white-space:nowrap}
.cov-n{color:var(--ink2);font-size:12px}
.cov-full{border-left-color:#184f95}
.cov-partial{border-left-color:#2a78d6}
.cov-minimal{border-left-color:#86b6ef;opacity:.85;font-style:italic}
.cov-unknown{border-left-color:#52514e;background:#f4f3f0}
.alert{display:flex;gap:9px;align-items:baseline;padding:8px 10px;background:#fff;
 border:1px solid var(--line);border-left-width:6px}
.alert-i{font-size:15px}
.alert-l{font-weight:700;letter-spacing:.04em;white-space:nowrap}
.alert-m{color:var(--ink2)}
.hero{display:grid;grid-template-columns:230px 1fr;gap:16px;align-items:start}
.score{border:1px solid var(--line);border-top:4px solid var(--band);padding:10px 12px;background:#fff}
.score-n{font-size:52px;font-weight:750;line-height:1}
.score-m{display:flex;gap:8px;align-items:center;margin-top:4px;flex-wrap:wrap}
.pill{color:#fff;padding:2px 8px;border-radius:9px;font-size:11px;font-weight:650}
.trend{font-size:12px;color:var(--ink2)}
.score-c{margin-top:6px;font-size:11px;color:var(--ink2)}
.peer{border:1px solid var(--line);padding:10px 12px;background:#fff}
.bar-r{display:grid;grid-template-columns:132px 1fr 34px;gap:8px;align-items:center;margin-bottom:5px}
.bar-l{font-size:12px;color:var(--ink2)}
.bar-t{background:#eeede9;height:14px;border-radius:3px;overflow:hidden}
.bar-f{display:block;height:100%;border-radius:0 3px 3px 0}
.bar-v{font-variant-numeric:tabular-nums;font-weight:650;text-align:right}
.peer-a{margin:6px 0 0;font-size:12px}
.cat-g{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.cat{border:1px solid var(--line);border-top:4px solid var(--band);padding:9px 11px;background:#fff}
.cat-h{font-weight:650;margin-bottom:3px}
.cat-s{font-size:27px;font-weight:750;line-height:1.1;display:flex;align-items:baseline;gap:7px}
.cat-b{font-size:11px;font-weight:600;color:var(--ink2);text-transform:uppercase;letter-spacing:.04em}
.cat-t{font-size:12px;color:var(--ink2);margin-bottom:5px}
.cat-bar{background:#eeede9;height:5px;border-radius:3px;overflow:hidden}
.cat-bar span{display:block;height:100%}
.headline{font-size:15px;font-weight:650;margin:0 0 8px}
.acts ol{margin:0;padding-left:19px}
.acts li{margin-bottom:3px}
.fin-g{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.fin{border:1px solid var(--line);padding:9px 11px;background:#fff}
.fin-k{font-size:11px;color:var(--ink2);text-transform:uppercase;letter-spacing:.04em;
 display:flex;flex-wrap:wrap;gap:5px;align-items:center}
.fin-v{font-size:15px;font-weight:700;margin-top:3px}
.modelled{font-size:9px;font-weight:700;letter-spacing:.07em;background:#f4f3f0;color:var(--ink2);
 border:1px solid var(--line);border-radius:3px;padding:1px 4px;white-space:nowrap}
table{width:100%;border-collapse:collapse;font-size:12px;background:#fff}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line)}
th{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink2);
 border-bottom:2px solid var(--ink)}
.cav{margin:6px 0 0;font-size:11px;color:var(--ink2);font-style:italic}
.empty{margin:0;color:var(--ink2);font-style:italic}
.more{margin:6px 0 0;font-size:11px;color:var(--ink2)}
.ft{border-top:1px solid var(--line);padding-top:9px;font-size:11px;color:var(--ink2)}
.ft p{margin:0 0 4px}
@media print{
 @page{size:landscape;margin:11mm}
 body{background:#fff}
 .pg{max-width:none;padding:0}
 section{break-inside:avoid}
}
"""

_DOCUMENT = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Executive Threat Overview</title>
<style>{style}</style></head>
<body><div class="pg">
{body}
</div></body></html>
"""
