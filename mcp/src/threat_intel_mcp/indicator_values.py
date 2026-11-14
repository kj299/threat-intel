"""Semantic validation of machine-consumable indicators.

Runtime feeds must supply concrete values, not defanged display strings or
wildcards. Defanging belongs at the presentation boundary; this validator never
silently turns a display placeholder into an actionable indicator.
"""
import ipaddress
import re
from urllib.parse import urlsplit


def valid_domain(value: str) -> bool:
    try:
        name = value.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return False
    if len(name) > 253 or "." not in name or not re.search(r"[a-zA-Z]", name):
        return False
    return all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
               for label in name.split("."))


def valid_value(kind: str, value: str) -> bool:
    try:
        if kind in ("IPv4", "IPv6"):
            return ipaddress.ip_address(value).version == (4 if kind == "IPv4" else 6) and "%" not in value
        if kind == "CIDR_Range":
            ipaddress.ip_network(value, strict=True)
            return "/" in value
        if kind == "Domain":
            return valid_domain(value)
        if kind == "URL":
            url = urlsplit(value)
            if url.scheme not in ("http", "https", "ftp") or not url.hostname or any(c.isspace() for c in value):
                return False
            if url.port is not None and not 1 <= url.port <= 65535:
                return False
            try:
                ipaddress.ip_address(url.hostname)
                return True
            except ValueError:
                return valid_domain(url.hostname)
        if kind in ("JA3", "JA3S"):
            return bool(re.fullmatch(r"[0-9a-fA-F]{32}", value))
        if kind == "JARM":
            return bool(re.fullmatch(r"[0-9a-fA-F]{62}", value))
        if kind == "SSL_Certificate_Hash":
            return bool(re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", value))
    except ValueError:
        return False
    return True  # HTTP_Header and User_Agent are intentionally free text.
