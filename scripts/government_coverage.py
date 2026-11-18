"""Plan official advisory discovery and evaluate recorded receipts (no network).

This validates caller-supplied evidence, not whether browsing actually occurred.
It emits gaps without blocking report delivery or inventing source success.
"""

import argparse
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

SOURCES = {
    "cisa_advisories": {
        "name": "CISA Advisories",
        "primary": "https://www.cisa.gov/news-events/cybersecurity-advisories",
        "fallback": "site:content.govdelivery.com/accounts/USDHSCISA/bulletins/",
        "crosscheck": "site:cisa.gov OR site:content.govdelivery.com/accounts/USDHSCISA/bulletins/",
    },
    "cert_eu": {
        "name": "CERT-EU",
        "primary": "https://cert.europa.eu/publications/security-advisories/{year}",
        "fallback": "https://cert.europa.eu/publications/security-advisories-rss",
        "crosscheck": "site:cert.europa.eu/publications/security-advisories/",
    },
}


def stamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timezone required")
    return result


def official(source, url):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        return False
    host = parsed.hostname
    if source == "cert_eu":
        return host in {
            "cert.europa.eu",
            "www.cert.europa.eu",
        } and parsed.path.startswith("/publications/security-advisories/")
    return (
        host in {"cisa.gov", "www.cisa.gov"} and parsed.path.startswith("/news-events/")
    ) or (
        host == "content.govdelivery.com"
        and parsed.path.startswith("/accounts/USDHSCISA/bulletins/")
    )


def plan(end, cves, start=None):
    if any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve) for cve in cves):
        raise ValueError("invalid CVE identifier")
    start = start or end - timedelta(days=1)
    return {
        key: {
            **value,
            "primary": value["primary"].format(year=end.year),
            "previous_year_index": (
                value["primary"].format(year=start.year)
                if key == "cert_eu" and start.year != end.year
                else None
            ),
            "crosschecks": [f"{value['crosscheck']} {cve}" for cve in cves],
        }
        for key, value in SOURCES.items()
    }


def evaluate(document):
    start, end = stamp(document["window_start"]), stamp(document["window_end"])
    if start >= end:
        raise ValueError("invalid reporting window")
    cves = document.get("high_impact_cves", [])
    discovery = plan(end, cves, start)
    rows = []
    for source, route in discovery.items():
        receipts = [
            r for r in document.get("receipts", []) if r.get("source") == source
        ]
        row = {
            "source": route["name"],
            "status": "unverified",
            "outcome": "not_attempted",
            "gaps": [],
            "attempts": [],
            "reviewed_urls": [],
            "verified_current_urls": [],
        }
        rows.append(row)
        if len(receipts) != 1:
            row["gaps"].append(
                "Missing or duplicate publisher receipt; KEV/another publisher cannot substitute"
            )
            continue
        receipt = receipts[0]
        row["attempts"] = receipt.get("attempts", [])
        fresh = []
        for attempt in row["attempts"]:
            try:
                checked = stamp(attempt["checked_at"])
                if not end - timedelta(hours=2) <= checked <= end:
                    raise ValueError("stale check")
                if attempt["outcome"] not in {
                    "retrieved",
                    "zero_hits",
                    "http_error",
                    "transport_error",
                    "unsupported_format",
                }:
                    raise ValueError("unknown outcome")
                target = attempt.get("target", "")
                if not target:
                    raise ValueError("missing target")
                if attempt.get("route") == "primary" and target.rstrip("/") != route[
                    "primary"
                ].rstrip("/"):
                    raise ValueError("wrong publisher primary route")
                if attempt.get("route") == "fallback" and not (
                    route["fallback"] in target or route["crosscheck"] in target
                ):
                    raise ValueError("wrong publisher fallback route")
                if attempt.get("route") == "crosscheck" and not (
                    attempt.get("cve") in cves
                    and attempt["cve"] in target
                    and route["crosscheck"] in target
                ):
                    raise ValueError("unscoped CVE cross-check")
                if (
                    attempt.get("http_status", 200) >= 400
                    and attempt["outcome"] == "retrieved"
                ):
                    raise ValueError("HTTP error labelled success")
                fresh.append(attempt)
            except (KeyError, ValueError, TypeError, AttributeError):
                row["gaps"].append("Invalid, stale or future attempt metadata")
        required = {"primary", "fallback"}
        if not required <= {a.get("route") for a in fresh}:
            row["gaps"].append(
                "Primary and complementary/fallback discovery must both be attempted"
            )
        if route["previous_year_index"] and not any(
            a.get("route") == "previous_year"
            and a.get("target") == route["previous_year_index"]
            for a in fresh
        ):
            row["gaps"].append(
                "Missing previous-year index across reporting-window boundary"
            )
        for cve in cves:
            if not any(
                a.get("route") == "crosscheck" and a.get("cve") == cve for a in fresh
            ):
                row["gaps"].append(f"Missing government cross-check for {cve}")
        discovered = receipt.get("items", [])
        for item in discovered:
            try:
                url = item["url"]
                if not official(source, url):
                    raise ValueError("unverified publisher URL")
                low, high = stamp(item["published_start"]), stamp(item["published_end"])
                if low > high:
                    raise ValueError("invalid publication interval")
                disposition = item.get("disposition")
                if disposition not in {"included", "corroborates", "excluded"} or (
                    disposition == "excluded" and not item.get("exclusion_reason")
                ):
                    raise ValueError("candidate lacks report disposition")
                row["reviewed_urls"].append(url)
                if high < start or low > end:
                    if disposition != "excluded":
                        raise ValueError("out-of-window candidate presented as current")
                    continue
                if not (start <= low <= high <= end) or item.get("timestamp_conflict"):
                    raise ValueError(
                        "publication timing uncertain; retain raw timestamps and investigate"
                    )
                if item.get("content_read") is not True or not item.get(
                    "evidence_note"
                ):
                    raise ValueError(
                        "index/search discovery is not advisory-content consultation"
                    )
                if not any(
                    a.get("route") == "content"
                    and a.get("target") == url
                    and a["outcome"] == "retrieved"
                    for a in fresh
                ):
                    raise ValueError(
                        "No successful fresh advisory-content retrieval receipt"
                    )
                retrieved = stamp(item["retrieved_at"])
                if not end - timedelta(hours=2) <= retrieved <= end:
                    raise ValueError("stale or future content retrieval")
                row["verified_current_urls"].append(url)
            except (KeyError, ValueError, TypeError, AttributeError) as exc:
                row["gaps"].append(str(exc))
        accessible = any(a["outcome"] in {"retrieved", "zero_hits"} for a in fresh)
        if row["verified_current_urls"]:
            row["status"] = "partial" if row["gaps"] else "consulted"
            row["outcome"] = "verified_current_content"
        elif accessible:
            row["status"] = "partial"
            row["outcome"] = "discovery_only" if discovered else "no_verified_items"
        elif fresh:
            row["outcome"] = "access_failed"
        if not row["verified_current_urls"]:
            row["gaps"].append(
                "No verified in-window advisory content; not proof of no government alerts"
            )
        row["next_step"] = (
            "Resolve recorded gaps with official content or disclose them; deliver report on time"
        )
    return {
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "delivery": "continue_with_disclosed_gaps",
        "sources": rows,
        "limitations": [
            "Receipt validation cannot prove actual browsing or exhaustive publication coverage."
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipts", type=Path)
    parser.add_argument("--window-end")
    parser.add_argument("--cve", action="append", default=[])
    args = parser.parse_args()
    if args.receipts:
        output = evaluate(json.loads(args.receipts.read_text()))
    else:
        output = plan(stamp(args.window_end), args.cve)
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
