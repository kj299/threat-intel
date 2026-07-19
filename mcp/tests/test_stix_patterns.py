"""Tests for the STIX 2.x network-pattern extractor."""

from __future__ import annotations

from threat_intel_mcp.stix_patterns import extract_network_iocs


def test_ipv4():
    assert extract_network_iocs("[ipv4-addr:value = '203.0.113.7']") == [
        ("IPv4", "203.0.113.7")
    ]


def test_ipv6():
    assert extract_network_iocs("[ipv6-addr:value = '2001:db8::1']") == [
        ("IPv6", "2001:db8::1")
    ]


def test_domain():
    assert extract_network_iocs("[domain-name:value = 'evil.example']") == [
        ("Domain", "evil.example")
    ]


def test_url_double_quotes():
    assert extract_network_iocs('[url:value = "http://evil.example/x"]') == [
        ("URL", "http://evil.example/x")
    ]


def test_multiple_comparisons_or():
    out = extract_network_iocs(
        "[ipv4-addr:value = '1.1.1.1'] OR [domain-name:value = 'a.test']"
    )
    assert out == [("IPv4", "1.1.1.1"), ("Domain", "a.test")]


def test_unrecognised_types_skipped():
    # file hashes and email are not ioc_network
    assert extract_network_iocs(
        "[file:hashes.'SHA-256' = 'abc'] OR [email-addr:value = 'a@b.c']"
    ) == []


def test_escaped_quote_in_value():
    assert extract_network_iocs(r"[url:value = 'http://x/a\'b']") == [
        ("URL", "http://x/a'b")
    ]


def test_empty_and_garbage():
    assert extract_network_iocs("") == []
    assert extract_network_iocs("not a pattern") == []
