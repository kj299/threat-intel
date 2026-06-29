"""Tests for feed-data sanitisation (Phase 4 hardening)."""

from __future__ import annotations

from threat_intel_mcp.sanitize import sanitize_ioc, sanitize_iocs


def _ioc(**over):
    base = {"type": "IPv4", "value": "1.2.3.4", "confidence": "High", "source": "Feed"}
    base.update(over)
    return base


class TestSanitizeIoc:
    def test_clean_ioc_unchanged_in_essentials(self):
        out = sanitize_ioc(_ioc())
        assert out["value"] == "1.2.3.4"
        assert out["type"] == "IPv4"
        assert out["confidence"] == "High"

    def test_strips_control_chars_from_value(self):
        out = sanitize_ioc(_ioc(value="1.2.3.4\x00\x07\x1f"))
        assert out["value"] == "1.2.3.4"

    def test_strips_zero_width_and_bidi_from_value(self):
        # ZWSP (200b) between octets, RLO override (202e), BOM (feff)
        out = sanitize_ioc(_ioc(value="1.2​.3‮.4﻿"))
        assert out["value"] == "1.2.3.4"

    def test_value_emptied_by_cleaning_is_dropped(self):
        assert sanitize_ioc(_ioc(value="​\x00\x07")) is None

    def test_free_text_fields_cleaned_and_capped(self):
        out = sanitize_ioc(
            _ioc(
                associated_threat="Emotet\x00",
                associated_actor="TA542" + "​" * 5,
                kill_chain_phase="delivery",
            )
        )
        assert out["associated_threat"] == "Emotet"
        assert out["associated_actor"] == "TA542"
        assert out["kill_chain_phase"] == "delivery"

    def test_long_free_text_truncated(self):
        out = sanitize_ioc(_ioc(associated_threat="x" * 5000))
        assert len(out["associated_threat"]) == 512

    def test_tags_cleaned_filtered_and_capped(self):
        # "ev‍il" has a zero-width joiner (200d) inside → cleans to "evil".
        out = sanitize_ioc(
            _ioc(tags=["ok", "ev‍il", "", 123, None, "  spaced  "] + ["t"] * 50)
        )
        # non-strings dropped, empties dropped, zero-width stripped, trimmed
        assert "ok" in out["tags"]
        assert "evil" in out["tags"]
        assert "spaced" in out["tags"]
        assert 123 not in out["tags"]
        assert "" not in out["tags"]
        assert len(out["tags"]) <= 32

    def test_source_field_cleaned(self):
        out = sanitize_ioc(_ioc(source="Feed\x00​"))
        assert out["source"] == "Feed"

    def test_does_not_mutate_input(self):
        original = _ioc(value="1.2.3.4\x00")
        sanitize_ioc(original)
        assert original["value"] == "1.2.3.4\x00"  # caller's dict untouched

    def test_enum_fields_left_alone(self):
        out = sanitize_ioc(_ioc(tlp="AMBER", action="block"))
        assert out["tlp"] == "AMBER"
        assert out["action"] == "block"


class TestSanitizeIocs:
    def test_drops_emptied_keeps_rest(self):
        iocs = [_ioc(value="1.1.1.1"), _ioc(value="​\x00"), _ioc(value="2.2.2.2")]
        out = sanitize_iocs(iocs)
        assert [i["value"] for i in out] == ["1.1.1.1", "2.2.2.2"]
