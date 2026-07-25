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
_SECRET_PATTERNS = [
    (
        re.compile(r"(?i)(api[_-]?token|api[_-]?key|token|key|secret|password)=[^&\s]+"),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*"),
        r"\1 [REDACTED]",
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


# Installed at import time: every adapter imports this module, so the HTTP
# client libraries' request logging is always credential-safe.
for _logger_name in ("httpx", "httpcore"):
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
