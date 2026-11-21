# Feed operations and evidence

An integration is retained when source access is unavailable. Missing credentials,
network restrictions, account entitlements, and quota exhaustion are operational
states, not reasons to delete an adapter. Endpoint retirement is a separate
compatibility problem; retain the integration while verifying its replacement.

`list_available_feeds` reports credentials separately from `integration_status`.
The packaged `mcp/src/threat_intel_mcp/feed_status.json` records historical known
limitations. Unknown verification dates remain null. Discovery performs no live
requests and makes no current-health promise. Actual fetch results and their
coverage ledger remain the evidence for a report. No status entry disables a feed.

ThreatFox's legacy CSV route returned HTTP 410 in the documented 2026-10-28 run.
The replacement follows [official ThreatFox API documentation](https://threatfox.abuse.ch/api/):
JSON `POST https://threatfox-api.abuse.ch/api/v1/` with an `Auth-Key` header and
`{"query":"get_iocs","days":N}`. Configure the shared `ABUSECH_AUTH_KEY` securely;
it is optional for server startup but required for this feed. Without it, retain
ThreatFox as `unverified`, not keyless or successfully consulted. Provider usage
terms apply; commercial/for-profit use may require an enhanced subscription.

`get_iocs` supports 1–7 days (provider default: 3), based on `first_seen`, not
`last_seen`. Wider requested windows are capped and disclosed, not presented as
complete historical coverage. Date filtering must preserve the requested window;
retrieval time is not an IOC observation time. In-band API statuses distinguish
quiet results from authentication, quota, or format failures. Unit fixtures do
not prove current upstream access. Authenticated collection was validated and a
credential-scrubbed JSON API cassette (`mcp/tests/cassettes/threatfox_api.yaml`)
was recorded on 2026-11-16, with playback tests in `test_cassette_playback.py`;
that is dated evidence, not a current-health promise. The old CSV cassette
(`threatfox.yaml`) is kept as historical evidence, not replacement-API validation.

Shodan empty responses require an entitlement check; Pulsedive refusal requires a
quota/plan check. ANY.RUN, Intel 471 and Censys remain implemented despite absent
recordings in this environment.

## Data contracts

Runtime IOC values must be concrete machine-consumable indicators. Defanged IPs,
wildcards, malformed addresses and type/value mismatches are rejected, not guessed
or silently refanged. Report display schemas may allow defanged representations;
they are a different boundary. The runtime validates IPs, CIDRs, domains, URLs,
JA3/JA3S, JARM and certificate hashes semantically.

Merged IOC and CVE records preserve `source_evidence` with source-specific
confidence, TLP, timestamps and applicable vulnerability annotations. The aggregate
retains the most restrictive supplied TLP regardless of confidence or input order.
Missing TLP is not permission to redistribute; account licensing still applies.
Existing `source` and corroboration tags remain for compatibility.

Each guarded source has a 300-second overall deadline including retries and backoff,
in addition to transport timeouts. Callers may override `timeout_seconds` through
retry options. Cancellation releases a half-open probe without treating caller
cancellation as an upstream fault. Synchronous credential-provider calls cannot be
interrupted by an asyncio deadline; external request timeouts still matter.

Application entrypoints attach redaction to output handlers, so descendant logger
records are filtered. Embedders adding handlers must attach the redacting filter to
those handlers. Logging and cassette recording share credential-header names.
Redaction is defense in depth; never log raw credentials or response bodies.

## Remaining external verification

Confirm the historical abuse.ch key has been revoked and bindings rotated. As of
2026-11-21, private vulnerability reporting and automatic head-branch deletion are
confirmed on through GitHub's public API; secret scanning and push protection were
enabled by the maintainer the same day but are visible only to admins, so
re-check them in settings rather than trusting this paragraph. These operations
require authorized repository-settings access and provider access. Do not retrieve or
print old key values, and do not treat history cleanup as a replacement for revocation.

Monitor successful delivery artifacts and per-source contribution/freshness, not
commits to the frozen `reports/` evaluation corpus. The legacy staleness alarm
stays manual regardless: it watches commits to the frozen `reports/` corpus, so it
only becomes meaningful once a home for new, non-frozen-corpus reports is chosen
(see `report-staleness.yml`).

The read-only `report-delivery` workflow checks successful generator runs for
an unexpired, nonempty `threat-intel-report` artifact within ten days. A green job
without an artifact does not satisfy delivery. It opens no issues and sends no
messages. Local decision tests cover missing, failed, expired, and stale delivery;
It has run on its daily schedule on GitHub since 2026-11-16 (checked 2026-11-20, all green). Artifact presence
proves delivery, not report correctness. The old corpus-based staleness workflow
remains manual.


## CISA KEV access recovery

CISA KEV is public: no CISA API key or login is needed. An NVD API key is for a
separate service and does not fix CISA access failures. Try the canonical JSON
feed first. If it returns HTTP 403/429/5xx or a transport failure, use only CISA's
official mirror:
https://raw.githubusercontent.com/cisagov/kev-data/refs/heads/develop/known_exploited_vulnerabilities.json
([CISA mirror documentation](https://github.com/cisagov/kev-data)).

Record the failed route/status, actual retrieval URL/time, `catalogVersion`,
`dateReleased`, and count. Validate the envelope before ingestion; preserve this
provenance when serving a cached response. Report the source once as CISA KEV,
not two independently confirming sources. A recovered mirror is usable evidence,
with the primary-route failure and unverified mirror lag disclosed in the ledger.
The adapter conservatively exposes this caveat via `partial_failure`. If both
routes fail, report unverified/unavailable rather than an empty/quiet-day result.
Do not forward credentials, disable TLS, or use arbitrary third-party proxies.

CISA says the mirror usually syncs within minutes; verify the returned metadata,
not that promise alone. A catalog release older than the report window can be
normal on quiet days/weekends: it does not prove either staleness or no activity.
Compare available versions/releases or a last-known-good snapshot when possible;
flag regressions and freshness uncertainty. `dateAdded` has calendar-day precision,
so never fabricate an intra-day publication time. Never relabel older entries as
new intelligence. For web-only skill use, follow the same recovery steps before
declaring CISA inaccessible. Other unavailable sources require their own verified
primary alternatives; the CISA workaround does not authenticate social posts.


## Recovery for every source-coverage gap

Before marking any source unavailable, make a bounded recovery pass: verify the
canonical URL and requested date, distinguish HTTP/network failure from malformed
or empty content, then check the publisher's official feed, API, repository,
syndicated bulletin or alternate primary publication. Reuse authorized connectors
where appropriate. Validate ownership, content, dates and freshness before treating
an alternative as consulted. A search snippet or secondary retelling is a lead,
not primary confirmation; do not count alternate routes as independent sources.

Record each attempted route, observed status/error, recovered evidence and its
provenance, unresolved reason, coverage impact and smallest next step in the
ledger. If the response gives no cause, say cause unknown rather than guessing
bot filtering or missing credentials. Respect rate limits with bounded backoff;
no unapproved credentials, paid subscriptions, permission changes, CAPTCHA
bypass, TLS disabling, or arbitrary proxies. Continue useful independent research
and report residual gaps; never convert retrieval failure to "no threats".
Review recurring failures after each run and propose or implement authorized,
tested publisher-specific recovery in the adapter and mirrored skill guidance.
Keep integration availability, credential configuration, upstream health and
report freshness distinct; do not remove a source merely because access failed.
