"""Structured audit logging with automatic secret redaction.

Every tool invocation is logged with: tool name, input parameters (redacted),
upstream HTTP status, record count, and latency. Raw response bodies, auth
headers, and query strings carrying credentials are never logged.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("threat_intel_mcp.audit")

# Patterns that look like credentials in a URL query string or header value,
# each paired with the replacement that neutralises it. Every pattern keeps the
# *name* of what was redacted (so logs stay debuggable) and drops the value.
#
# The replacement is per-pattern for a reason: a single generic replacement that
# assumed a ``name=value`` shape silently failed on the scheme-prefixed forms —
# ``Bearer <token>`` has no ``=``, so splitting on ``=`` returned the whole match
# and produced ``Bearer <token>=[REDACTED]``, i.e. the secret was still in the
# log while *looking* redacted. Keep the name in group 1 of every pattern.
#
# The first two patterns cover REST, which is how every shipped adapter
# authenticates. The rest cover the shapes the *protocol* credential bundles in
# `vault/protocols.py` hold (issue #1: gRPC / MQTT / WebSocket / GraphQL). Those
# were unprotected: a gRPC mTLS private key, an MQTT `user:pass@host` connection
# string and a quoted `'Authorization': 'token …'` header each passed through
# this function unchanged, because none of them is a `name=value` pair. The
# credential *storage* for those protocols shipped; the redaction did not
# follow it.
_SECRET_PATTERNS = [
    (
        # (?<![A-Za-z]) rather than \b. Without any boundary, `key` matched
        # inside any word ending in those letters and a benign `monkey=banana`
        # logged as `monkey=[REDACTED]` — safe, but the log then lies about
        # what was there. \b is the wrong fix: in `access_token=` the boundary
        # before `token` sits after `_`, which is a word character, so \b did
        # not match and a real WebSocket token leaked. Rejecting only a
        # preceding *letter* keeps `monkey` out and `access_token` in.
        re.compile(r"(?i)(?<![A-Za-z])(api[_-]?token|api[_-]?key|token|key|secret|password)=[^&\s]+"),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*"),
        r"\1 [REDACTED]",
    ),
    # PEM blocks — gRPC mTLS client keys. Matched whole rather than line-by-line
    # because a partially redacted key is still a leaked key.
    (
        re.compile(
            r"(?is)-----BEGIN ([A-Z ]*PRIVATE KEY|CERTIFICATE)-----.*?-----END \1-----"
        ),
        r"[REDACTED \1]",
    ),
    # URL userinfo — `mqtts://alice:hunter2@broker:8883`. The username is kept:
    # knowing *which* principal connected is exactly what an audit log is for.
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+):[^\s@]+@"),
        r"\1:[REDACTED]@",
    ),
    # Quoted auth values — how header dicts and client kwargs render in a log
    # line: {'Authorization': 'token abc'}. The value is matched as a whole
    # quoted string: a scheme-prefixed value like 'token abc' contains a space,
    # and an unquoted-value pattern stopped at it, leaving the secret in the log
    # directly after the [REDACTED] marker.
    (
        re.compile(
            r"(?i)(['\"](?:authorization|api[_-]?token|api[_-]?key|token|secret|password)"
            r"['\"]\s*:\s*)(['\"])[^'\"]*\2"
        ),
        r"\1\2[REDACTED]\2",
    ),
    # Bare colon-separated form — `password: hunter2` in a connection log.
    (
        re.compile(
            r"(?i)(?<![A-Za-z])(authorization|api[_-]?token|api[_-]?key|token|secret|password)"
            r"(\s*:\s*)[^\s,'\"}\]]+"
        ),
        r"\1\2[REDACTED]",
    ),
]


def redact_url(url: str) -> str:
    """Remove credential-bearing query parameters and auth schemes before logging."""
    for pattern, replacement in _SECRET_PATTERNS:
        url = pattern.sub(replacement, url)
    return url


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers with Authorization and similar fields redacted."""
    sensitive = {"authorization", "x-api-key", "x-auth-token", "cookie"}
    return {
        k: "[REDACTED]" if k.lower() in sensitive else v
        for k, v in headers.items()
    }


class _RedactingFilter(logging.Filter):
    """Redact credential-bearing substrings from third-party log records.

    httpx logs every request at INFO including the full URL — for APIs that
    authenticate via a query parameter (Shodan's ``key=``), that would write
    the API key to the server log. This filter rewrites such records in place.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        redacted = redact_url(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


# Loggers the filter is installed on, at import time — every adapter imports
# this module, so third-party request logging is always credential-safe.
#
# The protocol entries are not speculative. `vault/protocols.py` holds typed
# credential bundles for gRPC, MQTT, WebSocket and GraphQL (issue #1), and each
# of those client libraries logs through its own logger, none of which was
# covered while only httpx/httpcore were listed. A credential bundle whose
# transport logs unfiltered is a credential in the log.
#
# Filters attach to a logger by name whether or not the library is installed, so
# listing one that is not a dependency yet costs nothing and closes the gap
# before the first protocol feed is wired rather than after.
REDACTED_LOGGERS = (
    # REST — every shipped adapter
    "httpx",
    "httpcore",
    # Protocol transports, per vault/protocols.py
    "websockets",  # WebSocketCredentials
    "paho",  # MQTTCredentials (paho-mqtt logs under "paho.mqtt.client")
    "paho.mqtt",
    "grpc",  # GRPCCredentials (mTLS cert/key)
    "gql",  # GraphQLCredentials
    "gql.transport",
)

for _logger_name in REDACTED_LOGGERS:
    logging.getLogger(_logger_name).addFilter(_RedactingFilter())


def log_tool_call(
    tool_name: str,
    params: dict[str, Any],
    *,
    record_count: int,
    latency_ms: float,
    status: str = "ok",
    error: str | None = None,
) -> None:
    """Emit a single structured audit log entry for a completed tool invocation."""
    entry: dict[str, Any] = {
        "event": "tool_call",
        "tool": tool_name,
        "params": params,   # caller must pre-redact any sensitive param values
        "record_count": record_count,
        "latency_ms": round(latency_ms, 1),
        "status": status,
    }
    if error:
        entry["error"] = error
    if status == "ok":
        logger.info("%s", entry)
    else:
        logger.warning("%s", entry)
