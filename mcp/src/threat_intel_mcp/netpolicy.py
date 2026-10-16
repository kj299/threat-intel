"""Egress allowlist for adapter HTTP clients.

A compromised or buggy adapter should not be able to make outbound requests to
arbitrary hosts — that is the exfiltration path an attacker would use to ship
stolen credentials or scraped data off the box. This module provides an httpx
``request`` event hook that rejects any request whose host is not in an explicit
per-adapter allowlist, before the request leaves the process.

Each adapter declares the single host it legitimately talks to and installs the
hook on its client. The guard runs on every hop, so an adapter that follows a
redirect (OpenPhish, whose feed URL 30x's to its GitHub mirror) must allowlist
each host it may land on; every other adapter talks to one host and allows one. This is the application-level half of the issue #1 security checklist's
"egress allowlist"; a network/proxy-level allowlist remains recommended in
production as defence in depth.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Coroutine
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class EgressNotAllowedError(RuntimeError):
    """Raised when an adapter attempts a request to a non-allowlisted host."""


def _normalise(host: str) -> str:
    return host.strip().lower().rstrip(".")


def make_egress_guard(
    allowed_hosts: set[str] | frozenset[str],
) -> Callable[[httpx.Request], Coroutine[Any, Any, None]]:
    """Return an async httpx request hook enforcing the host allowlist."""
    allowed = frozenset(_normalise(h) for h in allowed_hosts)

    async def _guard(request: httpx.Request) -> None:
        host = _normalise(request.url.host)
        if host not in allowed:
            # Do not log the full URL — it may carry credential-bearing query args.
            raise EgressNotAllowedError(
                f"Blocked outbound request to disallowed host {host!r}. "
                f"Allowed hosts: {sorted(allowed)}."
            )

    return _guard


def egress_event_hooks(
    *allowed_hosts: str,
) -> dict[str, list[Callable[[httpx.Request], Coroutine[Any, Any, None]]]]:
    """Build an httpx ``event_hooks`` dict that allowlists ``allowed_hosts``.

    Usage::

        httpx.AsyncClient(..., event_hooks=egress_event_hooks("api.example.com"))
    """
    return {"request": [make_egress_guard(set(allowed_hosts))]}
