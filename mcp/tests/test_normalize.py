"""Tests for the normaliser: schema validation and deduplication."""

from threat_intel_mcp.normalize import deduplicate_iocs, finalize_iocs, validate_iocs


def _ioc(type_: str, value: str, confidence: str = "High", source: str = "Q-Feeds") -> dict:
    return {"type": type_, "value": value, "confidence": confidence, "source": source}


class TestValidateIocs:
    def test_valid_ipv4_passes(self):
        result = validate_iocs([_ioc("IPv4", "1.2.3.4")])
        assert len(result) == 1

    def test_valid_domain_passes(self):
        result = validate_iocs([_ioc("Domain", "evil.example.com")])
        assert len(result) == 1

    def test_valid_url_passes(self):
        result = validate_iocs([_ioc("URL", "https://evil.example.com/payload")])
        assert len(result) == 1

    def test_invalid_type_dropped(self):
        result = validate_iocs([_ioc("NotAType", "1.2.3.4")])
        assert result == []

    def test_invalid_confidence_dropped(self):
        result = validate_iocs([_ioc("IPv4", "1.2.3.4", confidence="VeryHigh")])
        assert result == []

    def test_placeholder_source_dropped(self):
        result = validate_iocs([_ioc("IPv4", "1.2.3.4", source="unknown")])
        assert result == []

    def test_empty_value_dropped(self):
        result = validate_iocs([_ioc("IPv4", "")])
        assert result == []

    def test_mixed_valid_invalid(self):
        iocs = [
            _ioc("IPv4", "1.2.3.4"),
            _ioc("BadType", "x"),
            _ioc("Domain", "legit.example.com"),
        ]
        result = validate_iocs(iocs)
        assert len(result) == 2
        assert all(i["type"] in {"IPv4", "Domain"} for i in result)

    def test_cidr_range_passes(self):
        result = validate_iocs([_ioc("CIDR_Range", "192.168.1.0/24")])
        assert len(result) == 1

    def test_ipv6_passes(self):
        result = validate_iocs([_ioc("IPv6", "2001:db8::1")])
        assert len(result) == 1


class TestDeduplicateIocs:
    def test_no_duplicates_unchanged(self):
        iocs = [_ioc("IPv4", "1.1.1.1"), _ioc("IPv4", "2.2.2.2")]
        result = deduplicate_iocs(iocs)
        assert len(result) == 2

    def test_duplicate_same_confidence_keeps_first(self):
        iocs = [
            _ioc("IPv4", "1.1.1.1", confidence="High"),
            _ioc("IPv4", "1.1.1.1", confidence="High"),
        ]
        result = deduplicate_iocs(iocs)
        assert len(result) == 1

    def test_duplicate_higher_confidence_wins(self):
        iocs = [
            _ioc("IPv4", "1.1.1.1", confidence="Low"),
            _ioc("IPv4", "1.1.1.1", confidence="High"),
        ]
        result = deduplicate_iocs(iocs)
        assert len(result) == 1
        assert result[0]["confidence"] == "High"

    def test_different_types_not_deduped(self):
        iocs = [_ioc("IPv4", "1.1.1.1"), _ioc("Domain", "1.1.1.1")]
        result = deduplicate_iocs(iocs)
        assert len(result) == 2


class TestFinalizeIocs:
    """finalize_iocs = sanitize -> validate -> dedupe (issue #57 ordering)."""

    def test_sanitizes_before_validating(self):
        # Dirty-but-salvageable value is cleaned, then validated, then kept.
        iocs = [
            {"type": "IPv4", "value": "1.2.3.4\x00", "confidence": "High", "source": "F"},
        ]
        out = finalize_iocs(iocs)
        assert [i["value"] for i in out] == ["1.2.3.4"]

    def test_drops_over_length_and_emptied_values(self):
        long_url = "https://evil.example/" + "a" * 3000
        iocs = [
            {"type": "URL", "value": long_url, "confidence": "High", "source": "F"},
            {"type": "IPv4", "value": "\x00\x07", "confidence": "High", "source": "F"},
            {"type": "IPv4", "value": "5.5.5.5", "confidence": "High", "source": "F"},
        ]
        out = finalize_iocs(iocs)
        assert [i["value"] for i in out] == ["5.5.5.5"]

    def test_dedupes_on_cleaned_values(self):
        # Hidden-character variant of the same indicator collapses after cleaning.
        iocs = [
            {"type": "IPv4", "value": "1.2.3.4", "confidence": "Low", "source": "A"},
            {"type": "IPv4", "value": "1.2\u200b.3.4", "confidence": "High", "source": "B"},
        ]
        out = finalize_iocs(iocs)
        assert len(out) == 1
        assert out[0]["confidence"] == "High"
