"""MISP ZeroMQ pub-sub adapter — the first concrete :class:`ProtocolAdapter`.

Issue #162. This proves the **transport abstraction** works against something
real: ``ProtocolAdapter`` had no live subclass, and a base class with no
implementation is a design sketch.

─── It proves nothing about credential handling ─────────────────────────────

MISP's ZeroMQ interface has **no authentication mechanism**. The official
documentation states the channel "is available to localhost only," relying on
network isolation rather than credentials. So this adapter loads no credential
bundle and exercises none of ``vault/protocols.py``.

That distinction is the whole reason #162 was narrowed away from #1's scope. A
merged ZeroMQ adapter is not evidence that the protocol credential path works;
that stays unexercised until a feed with real auth appears.

─── The contract, read rather than recalled ─────────────────────────────────

From MISP's own subscriber tool (``MISP/tools/misp-zmq/sub.py``):

    socket = context.socket(zmq.SUB)
    socket.setsockopt(zmq.SUBSCRIBE, b'')
    message = socket.recv()
    topic, s, m = message.decode('utf-8').partition(" ")

**One frame**, topic and JSON separated by the **first space** — not a multipart
message, which is the natural assumption and is wrong. Getting this from the
source rather than from memory is the same discipline that the ThreatFox
comma-then-space dialect earned the hard way (#100), where a plausible guess
returned 0 IOCs from a live 1 MB response.

─── Why a bounded collection window ─────────────────────────────────────────

A subscriber is a stream; ``fetch_all_iocs`` is request/response. This adapter
collects for a bounded window per call and returns what arrived. The trade is
explicit: **messages published between calls are missed.** A background
subscriber draining into a buffer would capture everything, but it would
introduce this server's first long-lived task and the lifecycle it drags along,
which is a larger change than "prove the transport works" warrants. If the gap
matters in practice, that is the follow-up — and it is a behaviour change worth
making deliberately rather than by accident.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from ..adapters.base import UpstreamFormatError, guard_parsed
from .base import ProtocolAdapter

logger = logging.getLogger(__name__)

# Channels that carry indicators. The others (`misp_json_user`,
# `misp_json_organisation`) are administrative, and `misp_json_self` is a
# keep-alive handled separately below.
INDICATOR_TOPICS = ("misp_json", "misp_json_attribute")

# Emitted every minute regardless of activity. This is what distinguishes
# "connected, nothing published" from "never connected" — the transport-level
# form of the empty-parse distinction in #106. Without it, a silent window and a
# broken subscription look identical, and reporting a confident `0` from a
# connection that never opened is exactly the failure that guard exists for.
KEEPALIVE_TOPIC = "misp_json_self"

# MISP attribute type -> ioc_network type. MISP has ~100 attribute types; only
# the network ones map. Anything absent is skipped rather than guessed, which is
# why `_normalize` returns None instead of inventing a type.
_TYPE_MAP = {
    "ip-src": "IPv4",
    "ip-dst": "IPv4",
    "ip-src|port": "IPv4",
    "ip-dst|port": "IPv4",
    "domain": "Domain",
    "hostname": "Domain",
    "domain|ip": "Domain",
    "url": "URL",
    "uri": "URL",
    "user-agent": "User_Agent",
    "ja3-fingerprint-md5": "JA3",
    "jarm-fingerprint": "JARM",
    "x509-fingerprint-sha1": "SSL_Certificate_Hash",
    "x509-fingerprint-sha256": "SSL_Certificate_Hash",
    "x509-fingerprint-md5": "SSL_Certificate_Hash",
}


class MISPZMQAdapter(ProtocolAdapter):
    """Subscribe to a MISP ZeroMQ pub-sub channel for a bounded window.

    The endpoint is **operator-supplied**; no hostname is committed, per the
    bring-your-own-endpoint rule the base class documents. MISP's own default is
    ``tcp://127.0.0.1:50000``, but a default here would be a guess about someone
    else's deployment.
    """

    name = "MISP (ZeroMQ)"
    tier = 6
    protocol = "zmq"

    def __init__(
        self,
        endpoint: str,
        *,
        window_seconds: float = 5.0,
        topics: tuple[str, ...] = INDICATOR_TOPICS,
    ) -> None:
        if not endpoint:
            raise ValueError(
                "MISPZMQAdapter requires an endpoint, e.g. 'tcp://10.0.0.5:50000'. "
                "No default is committed: MISP's own default is localhost-only and "
                "assuming it would be a guess about the operator's deployment."
            )
        self.endpoint = endpoint
        self.window_seconds = window_seconds
        self.topics = topics

    # ─── Transport ───────────────────────────────────────────────────────────

    async def _collect(
        self,
        *,
        time_range: str,
        feed_types: list[str] | None,
        partial_failure: list[str],
    ) -> list[Any]:
        """Subscribe and drain for `window_seconds`, then return what arrived.

        Raises rather than returning empty when the subscription itself fails —
        the fan-out then degrades this source to `unverified`, which is the
        honest answer. Returning `[]` would publish a confident zero from a
        connection that never opened.
        """
        try:
            import zmq  # noqa: PLC0415
            import zmq.asyncio  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise RuntimeError(
                "pyzmq is required for the MISP ZeroMQ adapter; install the "
                "'zmq' extra."
            ) from exc

        wanted = set(feed_types) if feed_types else set(self.topics)
        context = zmq.asyncio.Context.instance()
        socket = context.socket(zmq.SUB)
        # Subscribe to everything and filter in Python, exactly as MISP's own
        # sub.py does. Byte-prefix filtering at the socket would also drop the
        # keep-alive, and the keep-alive is how a quiet window is told apart
        # from a dead one.
        socket.setsockopt(zmq.SUBSCRIBE, b"")
        raw: list[dict[str, Any]] = []
        saw_any_frame = False
        try:
            socket.connect(self.endpoint)
            deadline = asyncio.get_running_loop().time() + self.window_seconds
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                try:
                    frame = await asyncio.wait_for(socket.recv(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                saw_any_frame = True
                topic, payload = self._split_frame(frame)
                if topic is None:
                    continue
                if topic == KEEPALIVE_TOPIC:
                    continue  # liveness only; carries no indicators
                if topic not in wanted:
                    continue
                raw.extend(self._records_from(topic, payload))
        finally:
            socket.close(linger=0)

        # Connected but not one frame — not even the per-minute keep-alive —
        # over a window long enough to have seen one. That is a subscription
        # that is not receiving, not a quiet MISP instance, so say so rather
        # than reporting zero.
        if not saw_any_frame and self.window_seconds >= 61:
            raise UpstreamFormatError(
                f"{self.name}: no frames in {self.window_seconds}s, including no "
                f"'{KEEPALIVE_TOPIC}' keep-alive (published every minute) — the "
                "subscription is not receiving"
            )
        return raw

    @staticmethod
    def _split_frame(frame: bytes) -> tuple[str | None, dict[str, Any] | None]:
        """Split one frame into (topic, parsed JSON).

        MISP sends `<topic><space><json>` in a **single** frame. A malformed
        frame is skipped, not raised on: one bad message must not abort a
        window that also carried good ones.
        """
        try:
            topic, _, body = frame.decode("utf-8").partition(" ")
        except UnicodeDecodeError:
            logger.warning("MISP ZMQ: undecodable frame skipped")
            return None, None
        if not body:
            return None, None
        try:
            return topic, json.loads(body)
        except json.JSONDecodeError:
            logger.warning("MISP ZMQ: unparseable JSON on topic %s", topic)
            return None, None

    def _records_from(self, topic: str, payload: dict[str, Any] | None) -> list[dict[str, Any]]:
        """Flatten a message into attribute dicts.

        `misp_json_attribute` carries one attribute; `misp_json` carries a whole
        published event whose `Event.Attribute` array holds many.
        """
        if not isinstance(payload, dict):
            return []
        if topic == "misp_json_attribute":
            attribute = payload.get("Attribute")
            return [attribute] if isinstance(attribute, dict) else []
        event = payload.get("Event")
        if not isinstance(event, dict):
            return []
        attributes = event.get("Attribute")
        return [a for a in attributes if isinstance(a, dict)] if isinstance(attributes, list) else []

    # ─── Normalisation ───────────────────────────────────────────────────────

    def _normalize(self, raw: Any) -> dict[str, Any] | None:
        """Map one MISP attribute to `ioc_network`, or None to skip.

        Two MISP-specific rules, both from the real field semantics rather than
        convenience:

        * ``to_ids`` is MISP's own flag for "this is actionable for detection",
          and it is a **string** ``"1"``/``"0"``, not a bool. An attribute with
          ``to_ids`` false is context, not an indicator, and is skipped —
          emitting it as a blockable IOC would misrepresent what MISP said.
        * ``deleted`` attributes are published on the same channel and must not
          be re-emitted as live indicators.
        """
        if not isinstance(raw, dict):
            return None
        if str(raw.get("deleted", "0")) in ("1", "True", "true"):
            return None
        if str(raw.get("to_ids", "0")) not in ("1", "True", "true"):
            return None

        ioc_type = _TYPE_MAP.get(str(raw.get("type", "")).lower())
        value = raw.get("value") or raw.get("value1")
        if not ioc_type or not value:
            return None

        # Composite types carry "value1|value2"; the network half is value1.
        if "|" in str(raw.get("type", "")) and raw.get("value1"):
            value = raw["value1"]

        ioc: dict[str, Any] = {
            "type": ioc_type,
            "value": str(value),
            # MISP publishes no confidence score. "Medium" is the honest floor
            # for an analyst-curated, to_ids-flagged attribute — claiming High
            # would assert a judgement the feed never made.
            "confidence": "Medium",
            "source": self.name,
            "action": "alert",
        }
        if comment := raw.get("comment"):
            ioc["associated_threat"] = str(comment)[:200]
        if category := raw.get("category"):
            ioc["tags"] = [str(category)]
        return ioc


def parse_frames(frames: list[bytes]) -> list[dict[str, Any]]:
    """Parse raw frames to `ioc_network` dicts, with no socket involved.

    Exposed so the framing and normalisation can be tested against recorded
    bytes without a broker — the same reason the REST adapters are tested
    against cassettes rather than live endpoints.
    """
    adapter = MISPZMQAdapter(endpoint="tcp://recorded.invalid:50000")
    out: list[dict[str, Any]] = []
    seen = 0
    understood = 0
    for frame in frames:
        topic, payload = adapter._split_frame(frame)
        if topic is None or topic == KEEPALIVE_TOPIC:
            continue
        for record in adapter._records_from(topic, payload):
            seen += 1
            # "Understood" means the MISP attribute structure was recognised —
            # NOT that it was kept. An attribute with to_ids=0, or a file-hash
            # type with no ioc_network equivalent, was parsed correctly and then
            # legitimately filtered; counting only retained records here would
            # raise UpstreamFormatError on a batch of perfectly valid non-network
            # attributes, which is the false-alarm case guard_parsed's docstring
            # explicitly warns against.
            if isinstance(record, dict) and "type" in record:
                understood += 1
            if (ioc := adapter._normalize(record)) is not None:
                out.append(ioc)
    guard_parsed(
        source="MISP (ZeroMQ)",
        envelope_found=True,
        envelope_desc="ZeroMQ frames",
        items_seen=seen,
        items_understood=understood,
    )
    return out
