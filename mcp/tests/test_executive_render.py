"""Tests for the HTML executive overview (issue #110).

These assert the *honesty* properties, not just that HTML comes out. A rendered
dashboard makes modelled numbers look measured, so the checks that matter are
the ones about provenance, redundant encoding, and sparse-week behaviour.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from threat_intel_mcp.render import RISK_BANDS, render_executive_overview, risk_band

EXAMPLES = (
    pathlib.Path(__file__).resolve().parents[2]
    / "skills"
    / "cyber-threat-intel"
    / "examples"
    / "outputs.json"
)


@pytest.fixture(scope="module")
def executive_output() -> dict:
    """The committed enterprise_executive example — no new data invented."""
    data = json.loads(EXAMPLES.read_text(encoding="utf-8"))
    for example in data["examples"]:
        if example["persona"] == "enterprise_executive":
            return example["output"]
    pytest.fail("no enterprise_executive example in outputs.json")


@pytest.fixture(scope="module")
def rendered(executive_output: dict) -> str:
    return render_executive_overview(executive_output)


# ─── Thresholds are deterministic ────────────────────────────────────────────


def test_bands_tile_0_to_100_without_gaps_or_overlap():
    """Two reports a week apart must band the same score identically."""
    covered = set()
    for low, high, _, _ in RISK_BANDS:
        span = set(range(low, high + 1))
        assert not (covered & span), "risk bands overlap"
        covered |= span
    assert covered == set(range(0, 101)), "risk bands do not tile 0-100"


@pytest.mark.parametrize(
    ("score", "label"),
    [(0, "Low"), (39, "Low"), (40, "Moderate"), (59, "Moderate"),
     (60, "High"), (79, "High"), (80, "Critical"), (100, "Critical")],
)
def test_band_boundaries(score: int, label: str):
    assert risk_band(score)[0] == label


@pytest.mark.parametrize("score", [-1, 101])
def test_score_outside_range_raises(score: int):
    with pytest.raises(ValueError):
        risk_band(score)


# ─── The greyscale guarantee ─────────────────────────────────────────────────


def _luminance(hex_colour: str) -> float:
    channels = []
    for offset in (1, 3, 5):
        value = int(hex_colour[offset : offset + 2], 16) / 255
        channels.append(value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4)
    r, g, b = channels
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def test_band_colours_are_monotonically_darker():
    """The whole point of not using red/amber/green.

    Printed or photocopied, a more severe band must be a darker grey. The status
    palette fails this (moderate is lighter than low *and* high); a sequential
    ramp passes by construction. Guards against someone "fixing" the palette
    back to traffic lights.
    """
    lums = [_luminance(hex_) for _, _, _, hex_ in RISK_BANDS]
    assert lums == sorted(lums, reverse=True), f"bands not monotonic in greyscale: {lums}"
    gaps = [abs(a - b) for a, b in zip(lums, lums[1:])]
    assert min(gaps) > 0.05, f"adjacent bands too close in greyscale: {gaps}"


# ─── Nothing is encoded by colour alone ──────────────────────────────────────


def test_every_score_carries_its_numeral_and_band_word(rendered: str, executive_output: dict):
    dash = executive_output["risk_dashboard"]
    overall = dash["overall_risk_score"]
    assert f">{overall}<" in rendered, "overall score numeral missing"
    assert f"{risk_band(overall)[0]} risk" in rendered, "overall band word missing"
    for category in dash["risk_by_category"][:3]:
        label = risk_band(category["score"])[0]
        assert label in rendered, f"band word for {category['category']} missing"


def test_trend_carries_a_word_not_just_an_arrow(rendered: str):
    assert "rising" in rendered or "falling" in rendered or "flat" in rendered


def test_alert_level_carries_icon_and_label(rendered: str, executive_output: dict):
    level = executive_output["alert_level"]["level"].upper()
    assert f"ALERT: {level}" in rendered


def test_model_supplied_colour_is_not_trusted(rendered: str, executive_output: dict):
    """The schema carries alert_level.color; rendering must not delegate palette
    choices to model output — an arbitrary hex breaks both the greyscale
    guarantee and the reserved-status discipline."""
    assert executive_output["alert_level"]["color"] not in rendered


# ─── Modelled figures are labelled where they are displayed ──────────────────


def test_financial_tiles_are_labelled_modelled(rendered: str):
    """#110's central risk: a bold number in a coloured tile reads as fact and
    gets repeated to a board. The label must be in the tile, not a footnote."""
    section = rendered.split('class="fins"')[1].split("</section>")[0]
    tile_count = section.count('class="fin-k"')
    assert tile_count >= 3
    assert section.count("MODELLED") >= tile_count, "a financial tile lacks its MODELLED chip"


def test_peer_comparison_is_labelled_modelled(rendered: str):
    section = rendered.split('class="peer"')[1].split("</div>")[0]
    assert "MODELLED" in section


def test_investment_projections_are_labelled_modelled(rendered: str):
    section = rendered.split('class="inv"')[1].split("</section>")[0]
    assert "MODELLED" in section


# ─── Coverage honesty ────────────────────────────────────────────────────────


def test_absent_coverage_badge_is_reported_as_absent(rendered: str):
    """The committed example carries no coverage_badge. Defaulting it would
    manufacture confidence the data does not support."""
    assert "COVERAGE NOT REPORTED" in rendered
    assert "completeness as unknown" in rendered


def test_minimal_coverage_renders_visibly_thinner(executive_output: dict):
    sparse = json.loads(json.dumps(executive_output))
    sparse["metadata"]["coverage_badge"] = "MINIMAL"
    html = render_executive_overview(sparse)
    assert "COVERAGE: MINIMAL" in html
    assert "cov-minimal" in html
    assert "Limited source coverage" in html
    assert "should not be read as a full picture" in html


def test_full_and_minimal_are_visually_distinguishable(executive_output: dict):
    def render_with(badge: str) -> str:
        record = json.loads(json.dumps(executive_output))
        record["metadata"]["coverage_badge"] = badge
        return render_executive_overview(record)

    assert render_with("FULL") != render_with("MINIMAL")


# ─── R3 in presentation: empty renders as empty ──────────────────────────────


def test_empty_categories_render_as_empty_not_reassuring(executive_output: dict):
    record = json.loads(json.dumps(executive_output))
    record["risk_dashboard"]["risk_by_category"] = []
    html = render_executive_overview(record)
    assert "No category risk scores in this report" in html
    # Match the markup, not the always-present CSS rule of the same name.
    assert '<div class="cat-g">' not in html, "empty category set still rendered tiles"
    assert '<div class="cat"' not in html


def test_missing_overall_score_renders_as_absent(executive_output: dict):
    record = json.loads(json.dumps(executive_output))
    del record["risk_dashboard"]["overall_risk_score"]
    html = render_executive_overview(record)
    assert "No overall risk score" in html


def test_renders_from_almost_nothing_without_raising():
    html = render_executive_overview({"metadata": {}})
    assert "COVERAGE NOT REPORTED" in html
    assert "<html" in html


# ─── Self-contained ──────────────────────────────────────────────────────────


def test_no_external_network_references(rendered: str):
    """These get emailed and opened offline. A security report that phones out
    to a CDN is an awkward artifact."""
    for pattern in ("http://", "https://", "//cdn", "<script", "@import", "url("):
        assert pattern not in rendered, f"external reference or script found: {pattern}"
    assert not re.search(r"<link\b", rendered), "external stylesheet linked"


def test_style_is_inline(rendered: str):
    assert "<style>" in rendered


def test_print_landscape_is_declared(rendered: str):
    assert "size:landscape" in rendered


# ─── Provenance: the overview names the analysis it came from ────────────────


def test_names_its_companion_technical_report(rendered: str, executive_output: dict):
    date = executive_output["metadata"]["generated_at"][:10]
    assert f"reports/{date}-threat-intel.md" in rendered
    assert "This is a summary, not the analysis" in rendered


def test_points_at_the_source_coverage_ledger(rendered: str):
    assert "Source Coverage Ledger" in rendered


# ─── Escaping ────────────────────────────────────────────────────────────────


def test_content_is_escaped(executive_output: dict):
    """Report content quotes adversary-controlled text; it must not become markup."""
    record = json.loads(json.dumps(executive_output))
    record["executive_summary"]["headline"] = '<img src=x onerror=alert(1)>"'
    html = render_executive_overview(record)
    assert "<img src=x" not in html
    assert "&lt;img" in html


# ─── CLI ─────────────────────────────────────────────────────────────────────


def test_cli_writes_html_to_a_file(tmp_path, executive_output: dict):
    from threat_intel_mcp.render.__main__ import main

    src = tmp_path / "in.json"
    src.write_text(json.dumps(executive_output), encoding="utf-8")
    dest = tmp_path / "out.html"
    assert main([str(src), "-o", str(dest)]) == 0
    assert "<html" in dest.read_text(encoding="utf-8")


def test_cli_rejects_invalid_json(tmp_path, capsys):
    from threat_intel_mcp.render.__main__ import main

    src = tmp_path / "bad.json"
    src.write_text("{not json", encoding="utf-8")
    assert main([str(src)]) == 2
    assert "not valid JSON" in capsys.readouterr().err
