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
Keep its tool and adapter while obtaining authoritative API documentation, access,
and a scrubbed cassette for migration. Do not infer a replacement URL or auth scheme.
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

Confirm the historical abuse.ch key has been revoked and bindings rotated. Inspect
GitHub's actual private vulnerability reporting and secret scanning/push protection
settings; historical documentation is not proof of current settings. These operations
require authorized repository-settings access and provider access. Do not retrieve or
print old key values, and do not treat history cleanup as a replacement for revocation.

Monitor successful delivery artifacts and per-source contribution/freshness, not
commits to the frozen `reports/` evaluation corpus. Keep the legacy staleness alarm
manual until a delivery monitor is validated against actual workflow run metadata.

The new read-only `report-delivery` workflow checks successful generator runs for
an unexpired, nonempty `threat-intel-report` artifact within ten days. A green job
without an artifact does not satisfy delivery. It opens no issues and sends no
messages. Local decision tests cover missing, failed, expired, and stale delivery;
GitHub execution still needs validation after the workflow lands. Artifact presence
proves delivery, not report correctness. The old corpus-based staleness workflow
remains manual.
