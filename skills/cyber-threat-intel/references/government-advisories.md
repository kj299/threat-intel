# Government advisory discovery receipt

For each daily report, record **CISA Advisories** and **CERT-EU** independently
before composition. CISA KEV is a separate vulnerability catalogue; a KEV fetch
or another Tier 8 publisher cannot satisfy either advisory check. This does not
change source-count targets or justify delaying delivery. Missing access is a gap,
not a silent omission and not evidence that no government alerts exist.

## Verified official discovery routes

- CISA primary: https://www.cisa.gov/news-events/cybersecurity-advisories .
  Also search the official bulletin channel with
  `site:content.govdelivery.com/accounts/USDHSCISA/bulletins/` and the report
  dates. Open candidate bulletins and their linked CISA advisories. CISA's
  [distribution notice](https://www.cisa.gov/news-events/alerts/2025/05/12/update-how-cisa-shares-cyber-related-alerts-and-notifications)
  confirms email/GovDelivery use but also says immediate distribution changes
  were paused: do not claim all alerts permanently moved off the website.
  Use already authorized email only when available; do not subscribe or infer
  mailbox access. No unverified CISA RSS endpoint is assumed.
- CERT-EU primary: `https://cert.europa.eu/publications/security-advisories/<year>`;
  cover both years across a year boundary. Complement with the official
  https://cert.europa.eu/publications/security-advisories-rss feed and scoped
  `site:cert.europa.eu/publications/security-advisories/` search. The
  [publisher's RSS announcement](https://cert.europa.eu/blog/read-feed-and-lead-fresh-features-for-our-cyber-fans)
  explains category feeds; verify the current feed link on the publisher site.
  RSS is a finite latest-publications list, not an exhaustive date-window query.
  An old latest entry, truncated feed, or zero search hits does not establish
  that the publisher was quiet. Compare the year index and open candidates;
  follow actual linked HTML/Markdown/PDF alternatives, never guessed endpoints.

For every high-impact CVE selected for the report (critical/high severity, active
exploitation, or otherwise prioritized exposure), run both publishers' scoped
CVE searches even if the vulnerability already has a vendor citation. Search
publication and update dates separately from the CVE's original disclosure date.
Keep government corroboration as another citation on the existing finding;
absence of a new finding is not a reason to discard a new government advisory.

## Evidence and freshness gates

Record each attempted URL/query, route (`primary`, `fallback`, `previous_year`, `crosscheck`, `content`),
checked_at with UTC offset, outcome (`retrieved`, `zero_hits`, `http_error`,
`transport_error`, `unsupported_format`), HTTP status where actually observed,
and CVE for crosschecks. Run discovery during the two hours before the actual
report cutoff. Preserve an earlier failed attempt even if an official fallback
succeeds. Bound attempts to the primary route, complementary route, one scoped
query per selected CVE, and relevant candidates within the reporting deadline.
If still blocked, disclose the precise error and continue delivery.

Every candidate gets its official URL, raw publication/update timestamp and
provenance, normalized `published_start`/`published_end`, `publication_source_url`,
`publication_evidence_note`, explicit `window_basis`, `retrieved_at`,
`content_read`, a brief `evidence_note`, and a disposition: `included`,
`corroborates`, or `excluded` with `exclusion_reason`. Unresolved candidates stay
visible as gaps. Search snippets/index summaries are discovery, not full-advisory
consultation. Do not infer that a link was fetched merely because search found it.

Keep GovDelivery envelope sent time distinct from the body's update time.
Preserve conflicting EST/EDT labels rather than silently choosing an offset;
record `timestamp_conflict` and investigate. For a date-only item use an interval
in the publisher's evidenced timezone. If that interval overlaps the cutoff,
mark timing uncertain; do not assign midnight as an exact publication time.
An advisory published after the cutoff belongs in the next window or an explicitly
retimed update, never backdated into the earlier report.

### Original publication versus material update

Set `window_basis` to `publication` or `material_update`; never silently replace
an old publication date with retrieval time, a feed refresh or HTTP Last-Modified.
Always preserve the original `published_start`/`published_end` and its official
`publication_source_url` plus `publication_evidence_note`. Optional `published_raw`
retains the publisher's literal timestamp. Missing or conflicting publication
metadata remains a gap even if a claimed update is current.

For a materially revised older advisory, additionally record `material_update`:

```json
{
  "start": "2026-11-18T10:00:00Z",
  "end": "2026-11-18T10:00:00Z",
  "source_url": "https://cert.europa.eu/publications/security-advisories/2026-021/",
  "evidence_note": "Illustrative only: publisher version history dates this revision",
  "material_change": "Illustrative only: new exploitation evidence and changed mitigation",
  "raw": "Illustrative timestamp: 18 November 2026 10:00 UTC"
}
```

This JSON illustrates the contract, not an observed update to that advisory.
The update needs independently recorded timing evidence and a sourced description
of the substantive change; a generic last-updated label alone is insufficient.
The publication and update evidence URLs may be the same advisory if its content
independently establishes both events. Both require successful fresh retrieval
receipts. Set `publication_timestamp_conflict` or the update's `timestamp_conflict`
when evidence disagrees; the existing generic `timestamp_conflict` also remains
conservative. Updates preceding or overlapping an uncertain publication interval
are unresolved. The selected interval must lie wholly inside the report window.
An old publication plus a current evidenced material update is eligible under
`material_update`; it is not a newly published advisory. `verified_current_items`
retains both intervals, provenance, raw timestamps and the chosen basis so the
report can explain why it included the item. The validator checks assertions and
cannot itself prove that the stated change is material.

## Local receipt validator

From the repository root, build the discovery plan:

```sh
python scripts/government_coverage.py --window-end 2026-11-18T12:00:00Z --cve CVE-2026-114938
```

Record real observations in JSON with `window_start`, `window_end`,
`high_impact_cves`, and `receipts`. Each receipt has `source` (`cisa_advisories`
or `cert_eu`), `attempts`, and `items` with the fields above. Then run:

```sh
python scripts/government_coverage.py --receipts government-receipts.json
```

The command performs no network access and uses no credentials. It always emits
both publisher rows; missing receipt = `unverified/not_attempted`, all access
failures = `unverified/access_failed`, successful empty discovery =
`partial/no_verified_items`, index-only discovery = `partial/discovery_only`.
Only fresh in-window content with a successful matching `content` retrieval
receipt, an explicit disposition and completed scoped
checks can yield `consulted`; that means content was consulted, not exhaustive
publisher coverage. Failed primary access followed by verified official content
can recover coverage while preserving the failure in `attempts`.

Attach these rows/gaps to Appendix A and retain the receipts with report evidence.
If Python is unavailable apply the same checks explicitly and say the validator
was not run. Do not stall email to make a row green. The validator checks recorded
assertions and metadata, not the truth of browsing or the completeness of a search.
It is not an MCP feed or an unattended crawler and is not automatically invoked
by a separately configured daily automation until that caller adopts the contract.

## November 18 verification and limitation

The web tool returned 403 for CISA's index and could not fetch bulletin 4332a87
or the direct CERT-EU 2026-021 URL. CERT-EU's official year index did open and
listed 2026-021 at 10:11:05 CET (09:11:05 UTC). The RSS endpoint was indexed by
web search, but direct web reading rejected XML and the local HTTP probe got
403; neither counts as a successful live RSS parse. These differing outcomes
motivate complementary discovery, not a claim that either advisory body was
retrieved. This change addresses a repository omission; it does not establish
which searches the separate November 18 daily-report runtime actually performed.
