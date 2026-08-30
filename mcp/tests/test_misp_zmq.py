"""Tests for the MISP ZeroMQ adapter (issue #162).

Frames are built to MISP's documented shape — `<topic><space><json>` in a single
frame, with the attribute payload from the official misp-book example — so the
parser is exercised against the real contract rather than one convenient to it.

No live network: the socket test publishes over an in-process `zmq.PUB` bound to
an ephemeral loopback port, which is the ZeroMQ analogue of the cassettes the
REST adapters use.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from threat_intel_mcp.adapters.base import UpstreamFormatError
from threat_intel_mcp.transports.misp_zmq import (
    KEEPALIVE_TOPIC,
    MISPZMQAdapter,
    parse_frames,
)

pytest.importorskip("zmq", reason="pyzmq is required for the MISP ZeroMQ adapter")

# Importing the submodule binds `zmq` too, so this one line gives both the
# constants (zmq.SUB/PUB) and zmq.asyncio.Context without rebinding the name.
import zmq.asyncio  # noqa: E402


def frame(topic: str, payload: dict) -> bytes:
    """Build a frame exactly as MISP does: one frame, split on the first space."""
    return f"{topic} {json.dumps(payload)}".encode()


# The attribute body is the example published in MISP's own misp-book, with the
# value changed so nothing here reads as a real indicator.
def attribute(**overrides) -> dict:
    base = {
        "to_ids": "1",
        "timestamp": 1505235275,
        "distribution": "5",
        "deleted": "0",
        "disable_correlation": "0",
        "event_id": "625",
        "category": "Network activity",
        "type": "domain",
        "value": "example-indicator.invalid",
        "comment": "",
        "batch_import": "0",
        "uuid": "59b8114b-1c80-4149-be3a-03e9c0a83832",
        "sharing_group_id": 0,
        "value1": "example-indicator.invalid",
        "value2": "",
        "id": "164363",
    }
    base.update(overrides)
    return base


# ─── Framing ─────────────────────────────────────────────────────────────────


def test_frame_is_split_on_the_first_space_not_multipart():
    """The detail most likely to be assumed wrong.

    MISP sends one frame with the topic and JSON separated by the first space
    (`tools/misp-zmq/sub.py`). A multipart reader — the natural guess — gets
    nothing. Same class of error as the ThreatFox comma-then-space dialect.
    """
    iocs = parse_frames([frame("misp_json_attribute", {"Attribute": attribute()})])
    assert [i["value"] for i in iocs] == ["example-indicator.invalid"]


def test_json_containing_spaces_survives_the_split():
    """`partition(" ")` must split once, not on every space — a comment field
    with spaces would otherwise truncate the payload."""
    attr = attribute(comment="seen in phishing kit")
    iocs = parse_frames([frame("misp_json_attribute", {"Attribute": attr})])
    assert iocs[0]["associated_threat"] == "seen in phishing kit"


def test_event_frame_yields_every_attribute():
    """`misp_json` carries a whole published event, not a single attribute."""
    event = {
        "Event": {
            "id": "625",
            "info": "campaign",
            "Attribute": [
                attribute(value="a.invalid", value1="a.invalid"),
                attribute(type="ip-dst", value="198.18.0.1", value1="198.18.0.1"),
            ],
        }
    }
    iocs = parse_frames([frame("misp_json", event)])
    assert {i["type"] for i in iocs} == {"Domain", "IPv4"}


@pytest.mark.parametrize(
    "bad",
    [b"misp_json_attribute {not json", b"\xff\xfe binary", b"no_space_at_all", b""],
)
def test_malformed_frames_are_skipped_not_raised(bad: bytes):
    """One bad frame must not abort a window that also carried good ones."""
    good = frame("misp_json_attribute", {"Attribute": attribute()})
    assert len(parse_frames([bad, good])) == 1


# ─── MISP field semantics ────────────────────────────────────────────────────


def test_to_ids_false_is_context_not_an_indicator():
    """`to_ids` is MISP's own "actionable for detection" flag. Emitting a
    to_ids=0 attribute as a blockable IOC would misrepresent what MISP said."""
    frames = [frame("misp_json_attribute", {"Attribute": attribute(to_ids="0")})]
    assert parse_frames(frames) == []


def test_to_ids_is_read_as_a_string_not_a_bool():
    """MISP publishes `"1"`/`"0"` as strings. A truthiness check on the raw value
    would treat the string "0" as True and emit every non-actionable attribute."""
    assert parse_frames([frame("misp_json_attribute", {"Attribute": attribute(to_ids="0")})]) == []
    assert len(parse_frames([frame("misp_json_attribute", {"Attribute": attribute(to_ids="1")})])) == 1


def test_deleted_attributes_are_not_re_emitted():
    frames = [frame("misp_json_attribute", {"Attribute": attribute(deleted="1")})]
    assert parse_frames(frames) == []


def test_non_network_types_are_skipped_not_guessed():
    """MISP has ~100 attribute types; most have no `ioc_network` equivalent.
    An unmapped type is skipped rather than coerced into one that fits."""
    frames = [
        frame("misp_json_attribute", {"Attribute": attribute(type="md5", value="d41d8c" * 5)})
    ]
    assert parse_frames(frames) == []


def test_confidence_is_not_inflated():
    """MISP publishes no confidence score. Claiming High would assert a
    judgement the feed never made."""
    iocs = parse_frames([frame("misp_json_attribute", {"Attribute": attribute()})])
    assert iocs[0]["confidence"] == "Medium"


# ─── The empty-parse distinction (#106) ──────────────────────────────────────


def test_all_attributes_filtered_returns_zero_without_error():
    """The false-alarm case `guard_parsed` exists to avoid.

    A batch of nothing but file hashes, or nothing but to_ids=0 context, was
    parsed correctly and legitimately retained nothing. Counting only *retained*
    records as understood would raise here — which is why the adapter counts
    recognised attribute structures instead.
    """
    frames = [
        frame("misp_json_attribute", {"Attribute": attribute(type="md5", value="abc")}),
        frame("misp_json_attribute", {"Attribute": attribute(to_ids="0")}),
    ]
    assert parse_frames(frames) == []


def test_unrecognisable_attribute_structures_raise():
    """Items present, none understood — the real format break."""
    frames = [
        frame("misp_json_attribute", {"Attribute": {"unexpected": "shape"}}),
        frame("misp_json_attribute", {"Attribute": {"also": "wrong"}}),
    ]
    with pytest.raises(UpstreamFormatError):
        parse_frames(frames)


def test_no_frames_at_all_is_not_an_error():
    """A genuinely quiet window is a valid `0`, not a failure."""
    assert parse_frames([]) == []


def test_keepalive_alone_is_a_quiet_window_not_a_break():
    """`misp_json_self` proves the subscription is live while carrying no
    indicators — the signal that separates "connected, quiet" from "dead"."""
    assert parse_frames([frame(KEEPALIVE_TOPIC, {"status": "ok", "uptime": 3600})]) == []


# ─── Endpoint policy ─────────────────────────────────────────────────────────


def test_no_default_endpoint_is_committed():
    """Bring-your-own-endpoint. MISP's own default is localhost-only; baking it
    in would be a guess about someone else's deployment."""
    with pytest.raises(ValueError, match="requires an endpoint"):
        MISPZMQAdapter(endpoint="")


def test_adapter_declares_no_credential_protocol():
    """This adapter proves the transport, not the credential path.

    MISP ZMQ has no authentication, so `protocol` deliberately does not name a
    bundle in `vault/protocols.py`. If that ever changes, this test should fail
    and make someone think about it.
    """
    from threat_intel_mcp.vault.protocols import PROTOCOL_CREDENTIALS

    assert MISPZMQAdapter(endpoint="tcp://x.invalid:1").protocol == "zmq"
    assert "zmq" not in PROTOCOL_CREDENTIALS


# ─── Over a real socket, in-process ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_fetch_over_a_real_zmq_socket():
    """End to end against an in-process PUB — the ZeroMQ analogue of a cassette.

    Proves the whole `ProtocolAdapter` path works against a live socket: this is
    the first concrete subclass, and a base class with no implementation is a
    design sketch.
    """
    context = zmq.asyncio.Context.instance()
    publisher = context.socket(zmq.PUB)
    port = publisher.bind_to_random_port("tcp://127.0.0.1")
    adapter = MISPZMQAdapter(endpoint=f"tcp://127.0.0.1:{port}", window_seconds=2.0)

    async def publish() -> None:
        # PUB/SUB drops messages sent before the subscriber attaches; a short
        # settle is the standard ZeroMQ handling, not a flake workaround.
        await asyncio.sleep(0.4)
        for _ in range(3):
            await publisher.send(frame("misp_json_attribute", {"Attribute": attribute()}))
            await publisher.send(frame(KEEPALIVE_TOPIC, {"status": "ok"}))
            await asyncio.sleep(0.1)

    try:
        task = asyncio.create_task(publish())
        result = await adapter.fetch(time_range="7d")
        await task
    finally:
        publisher.close(linger=0)

    assert result.source == "MISP (ZeroMQ)"
    assert result.record_count >= 1
    assert result.iocs[0]["type"] == "Domain"
    # Deduplication is the base class's job; three identical attributes collapse.
    assert result.record_count == 1


@pytest.mark.asyncio
async def test_quiet_window_returns_zero_without_raising():
    """Nothing published: a valid empty result, not a failure.

    The keep-alive escalation only applies to windows long enough to have seen
    one (>=61s), so a short quiet window stays a plain zero.
    """
    context = zmq.asyncio.Context.instance()
    publisher = context.socket(zmq.PUB)
    port = publisher.bind_to_random_port("tcp://127.0.0.1")
    adapter = MISPZMQAdapter(endpoint=f"tcp://127.0.0.1:{port}", window_seconds=0.5)
    try:
        result = await adapter.fetch(time_range="7d")
    finally:
        publisher.close(linger=0)
    assert result.record_count == 0
    assert result.partial_failure == []
