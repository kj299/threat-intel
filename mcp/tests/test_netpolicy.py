"""Tests for the egress allowlist (Phase 4 hardening).

The guard is exercised directly and end-to-end through an httpx client (with a
mock transport) to confirm it fires before the request leaves the process.
"""

from __future__ import annotations

import httpx
import pytest

from threat_intel_mcp.netpolicy import (
    EgressNotAllowedError,
    egress_event_hooks,
    make_egress_guard,
)


class TestGuard:
    @pytest.mark.asyncio
    async def test_allows_listed_host(self):
        guard = make_egress_guard({"api.example.com"})
        req = httpx.Request("GET", "https://api.example.com/v1/feed")
        await guard(req)  # no raise

    @pytest.mark.asyncio
    async def test_blocks_unlisted_host(self):
        guard = make_egress_guard({"api.example.com"})
        req = httpx.Request("GET", "https://evil.attacker.test/exfil")
        with pytest.raises(EgressNotAllowedError, match="evil.attacker.test"):
            await guard(req)

    @pytest.mark.asyncio
    async def test_host_match_is_case_and_dot_insensitive(self):
        guard = make_egress_guard({"API.Example.com"})
        req = httpx.Request("GET", "https://api.example.com./path")
        await guard(req)  # trailing dot + case differences normalised

    @pytest.mark.asyncio
    async def test_error_does_not_leak_query_string(self):
        guard = make_egress_guard({"api.example.com"})
        req = httpx.Request("GET", "https://evil.test/x?api_key=supersecret")
        with pytest.raises(EgressNotAllowedError) as exc:
            await guard(req)
        assert "supersecret" not in str(exc.value)


class TestThroughClient:
    @pytest.mark.asyncio
    async def test_allowed_request_passes_through_transport(self):
        transport = httpx.MockTransport(lambda req: httpx.Response(200, text="ok"))
        async with httpx.AsyncClient(
            transport=transport, event_hooks=egress_event_hooks("good.example.com")
        ) as client:
            resp = await client.get("https://good.example.com/feed")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_blocked_request_never_reaches_transport(self):
        hits = []

        def handler(req):
            hits.append(req)
            return httpx.Response(200)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(
            transport=transport, event_hooks=egress_event_hooks("good.example.com")
        ) as client:
            with pytest.raises(EgressNotAllowedError):
                await client.get("https://bad.example.com/feed")
        assert hits == []  # transport never invoked
