# threat-intel-mcp

MCP server that connects Claude to live threat intelligence feeds, normalising their output to the [threat-intel skill schema](https://github.com/kj299/threat-intel).

Implements the architecture described in [threat-intel issue #1](https://github.com/kj299/threat-intel/issues/1).

## How it fits together

```
Claude Code
  │  skill: threat-intel  (SKILL.md + output.schema.json)
  │  skill_input.feed_integrations = [{"name": "Q-Feeds", "tier": 2}, ...]
  │
  │  MCP tool calls: fetch_all_iocs            (all feeds at once)
  │                  qfeeds_fetch_iocs         (single feed)
  │                  abuseipdb_fetch_blocklist / virustotal_fetch_iocs /
  │                  otx_fetch_iocs / shodan_fetch_iocs / greynoise_fetch_iocs /
  │                  anyrun_fetch_iocs / intel471_fetch_iocs / censys_fetch_iocs
  ▼
threat-intel-mcp  (this package, stdio MCP server)
  │  reads API keys from CredentialProvider (env vars or HashiCorp Vault)
  │  fetch_all_iocs fans out concurrently, each source behind a circuit breaker
  │  calls upstream feed APIs; normalises → ioc_network[] per output.schema.json
  │  schema-validates + deduplicates (per-source and across sources) before returning
  │  a failing/unconfigured/open-circuit feed degrades to "unverified", never crashes
  ▼
Claude receives ioc_network[] + coverage_ledger, cites sources (R2/R5)
```

## Current state

| Feature | Status |
|---|---|
| Q-Feeds REST adapter (malware_ip, malware_domains) | ✅ Phase 1 |
| Env-var credential provider (dev) | ✅ Phase 1 |
| Schema validation + deduplication | ✅ Phase 1 |
| Structured audit logging with redaction | ✅ Phase 1 |
| MCP tool: `qfeeds_fetch_iocs` | ✅ Phase 1 |
| MCP tool: `list_available_feeds` | ✅ Phase 1 |
| pytest suite (no live calls) | ✅ Phase 1 |
| HashiCorp Vault credential provider | ✅ Phase 2 |
| AbuseIPDB blacklist adapter | ✅ Phase 3 |
| VirusTotal Intelligence adapter (malicious IPs + domains) | ✅ Phase 3 |
| AlienVault OTX subscribed-pulses adapter | ✅ Phase 3 |
| MCP tool: `abuseipdb_fetch_blocklist` | ✅ Phase 3 |
| MCP tool: `virustotal_fetch_iocs` | ✅ Phase 3 |
| MCP tool: `otx_fetch_iocs` | ✅ Phase 3 |
| Shodan Malware Hunter adapter + `shodan_fetch_iocs` | ✅ Phase 2 (deferred item) |
| GreyNoise malicious-scanner adapter + `greynoise_fetch_iocs` | ✅ Phase 2 (deferred item) |
| URLhaus + ThreatFox adapters (free public abuse.ch feeds, no key) | ✅ Phase 2 |
| ANY.RUN TAXII/STIX adapter + `anyrun_fetch_iocs` | ✅ Phase 2 (deferred item) |
| Intel 471 indicators adapter + `intel471_fetch_iocs` | ✅ Phase 2 (deferred item) |
| Censys hosts adapter + `censys_fetch_iocs` | ✅ Phase 2 (deferred item) |
| Concurrent fan-out (`fetch_all_iocs`) | ✅ Phase 4 |
| Circuit breakers + backoff retry per source | ✅ Phase 4 |
| Partial-failure surfacing → Coverage Ledger | ✅ Phase 4 |
| Protocol credential bundles (gRPC/MQTT/WebSocket/GraphQL) | ✅ Phase 3 |
| `ProtocolAdapter` bring-your-own-endpoint base | ✅ Phase 3 |
| Feed-data sanitization (control/zero-width/bidi, length caps) | ✅ Phase 4 |
| Per-adapter egress allowlist | ✅ Phase 4 |
| Secrets-rotation playbook | ✅ Phase 4 (docs) |
| Live gRPC / MQTT / WebSocket / GraphQL **feeds** | needs a real named feed per protocol |

## Quick start

### 1. Install

```bash
pip install -e ".[dev]"
```

### 2. Set your API keys

```bash
cp .env.example .env
# Edit .env and set the keys you have:
#   QFEEDS_API_KEY      — https://tip.qfeeds.com (Manage API Keys)
#   ABUSEIPDB_API_KEY   — https://www.abuseipdb.com/account/api
#   VIRUSTOTAL_API_KEY          — https://www.virustotal.com/gui/user/apikey
#   OTX_API_KEY         — https://otx.alienvault.com/settings (API Integration)
#   SHODAN_API_KEY      — https://account.shodan.io (membership plan with query credits)
#   GREYNOISE_API_KEY   — https://viz.greynoise.io/account/ (Enterprise / GNQL plan)
#   ANYRUN_API_KEY      — https://app.any.run (TI subscription; full Authorization value)
#   INTEL471_EMAIL + INTEL471_API_KEY — https://portal.intel471.com/api
#   CENSYS_API_ID + CENSYS_API_SECRET — https://search.censys.io/account/api
export $(grep -v '^#' .env | xargs)
```

Keys are optional individually — the server starts with whatever keys are configured and marks unconfigured feeds as `unverified` in the Coverage Ledger. **URLhaus and ThreatFox need no key** (free public abuse.ch feeds) and are always available.

### 3. Run the tests

```bash
pytest
```

### 4. Wire into Claude Code

Add to your Claude Code MCP config (`~/.claude/mcp_servers.json` or `.claude/mcp_servers.json`):

```json
{
  "mcpServers": {
    "threat-intel-mcp": {
      "command": "threat-intel-mcp",
      "env": {
        "QFEEDS_API_KEY": "your-qfeeds-key",
        "ABUSEIPDB_API_KEY": "your-abuseipdb-key",
        "VIRUSTOTAL_API_KEY": "your-virustotal-key",
        "OTX_API_KEY": "your-otx-key",
        "SHODAN_API_KEY": "your-shodan-key",
        "GREYNOISE_API_KEY": "your-greynoise-key",
        "ANYRUN_API_KEY": "API-Key your-anyrun-token",
        "INTEL471_EMAIL": "you@example.com",
        "INTEL471_API_KEY": "your-intel471-key",
        "CENSYS_API_ID": "your-censys-id",
        "CENSYS_API_SECRET": "your-censys-secret"
      }
    }
  }
}
```

Omit keys you don't have — the server runs with however many feeds are configured.

## Vault Credentials (Phase 2)

To use [HashiCorp Vault](https://www.vaultproject.io/) instead of plain environment variables, set the following three variables before starting the server:

```bash
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_ROLE_ID=<your-approle-role-id>
export VAULT_SECRET_ID=<your-approle-secret-id>
```

When `VAULT_ADDR` is present, `VaultCredentialProvider` is selected automatically; otherwise the server falls back to `EnvCredentialProvider` (env-var mode, dev only).

### Auth method

AppRole is the only supported auth method. Create a role with read-only access to the KV v2 engine and issue a role ID / secret ID pair.

### Secret path structure

Secrets must be stored in KV v2 under:

```
{mount_point}/data/{adapter_name}/{key}
```

The default mount point is `secret`. Examples:

```bash
vault kv put secret/qfeeds/api_key     api_key=<your-qfeeds-key>
vault kv put secret/abuseipdb/api_key  api_key=<your-abuseipdb-key>
vault kv put secret/virustotal/api_key api_key=<your-vt-key>
vault kv put secret/otx/api_key        api_key=<your-otx-key>
vault kv put secret/shodan/api_key     api_key=<your-shodan-key>
vault kv put secret/greynoise/api_key  api_key=<your-greynoise-key>
vault kv put secret/anyrun/api_key     api_key=<your-anyrun-authorization>
vault kv put secret/intel471/email     api_key=<you@example.com>
vault kv put secret/intel471/api_key   api_key=<your-intel471-key>
vault kv put secret/censys/api_id      api_key=<your-censys-id>
vault kv put secret/censys/api_secret  api_key=<your-censys-secret>
```

Note the path is `{adapter}/{key}` and the field inside the secret repeats the
key name — the provider reads field `api_key` from the secret at
`secret/data/{adapter}/api_key`.

### Claude Code MCP config (Vault mode)

```json
{
  "mcpServers": {
    "threat-intel-mcp": {
      "command": "threat-intel-mcp",
      "env": {
        "VAULT_ADDR": "https://vault.example.com:8200",
        "VAULT_ROLE_ID": "your-role-id",
        "VAULT_SECRET_ID": "your-secret-id"
      }
    }
  }
}
```

### 5. Use with the threat-intel skill

In Claude Code, after the MCP server is connected:

```
/cyber-threat-intel
feed_integrations: [
  {"name": "Q-Feeds",       "tier": 2, "access_level": "premium"},
  {"name": "AbuseIPDB",     "tier": 3, "access_level": "free"},
  {"name": "VirusTotal",    "tier": 2, "access_level": "intelligence"},
  {"name": "AlienVault OTX","tier": 2, "access_level": "community"},
  {"name": "Shodan",        "tier": 3, "access_level": "membership"},
  {"name": "GreyNoise",     "tier": 3, "access_level": "enterprise"},
  {"name": "ANY.RUN",       "tier": 9, "access_level": "ti"},
  {"name": "Intel 471",     "tier": 2, "access_level": "titan"},
  {"name": "Censys",        "tier": 3, "access_level": "search"}
]
```

Claude will call the relevant `*_fetch_iocs` tools, blend live IOCs with its training-data knowledge, and cite each source in the Coverage Ledger (Appendix A) without marking findings as `unverified`.

## Implementing a paid-subscription feed adapter

Most Tier 2–3 sources in the [Source Matrix](../skills/cyber-threat-intel/references/source-matrix.md) are subscription APIs. Adding one is a well-worn path: every adapter here (`qfeeds.py`, `virustotal.py`, `abuseipdb.py`, `otx.py`, `shodan.py`) is the same shape, and the fan-out, resilience, sanitization, and Coverage-Ledger plumbing come for free once you conform to the `SourceAdapter` protocol.

> **Ground your adapter in the vendor's own API docs — never in guesswork.** Each subscription source publishes an authoritative API reference (table below). Copy the real base URL, auth scheme, endpoint path, and response shape from there. This repo's rule is *no fictional infrastructure*: an adapter built against an invented endpoint or a guessed response field is worse than no adapter, because it silently emits wrong IOCs. If you can't read the docs (many are behind a login), you don't yet have enough to build the adapter.

### The contract

A `SourceAdapter` (see `adapters/base.py`) is any object with:

```python
name: str
tier: int
async def fetch(self, *, time_range: str, feed_types: list[str] | None = None) -> FetchResult
```

`FetchResult` carries `iocs` (raw `ioc_network` dicts), `source`, `tier`, `retrieved_at`, `record_count`, `latency_ms`, `feed_types_fetched`, and `partial_failure`. You do **not** validate, sanitize, or deduplicate in the adapter — the tool layer runs `normalize.finalize_iocs` (sanitize → validate → dedup) on your output.

### Worked example: VirusTotal Intelligence (a real paid feed already in this repo)

`adapters/virustotal.py` is the canonical subscription-API adapter. VirusTotal Intelligence (the `feeds` API) requires a **paid VT Enterprise/Intelligence licence** — a free key returns 403. The adapter, distilled to its load-bearing parts (read the vendor reference at <https://docs.virustotal.com/reference/> for the full contract):

```python
from ..audit import log_tool_call
from ..netpolicy import egress_event_hooks
from ..vault.base import CredentialProvider
from .base import FetchResult

_API_BASE = "https://www.virustotal.com/api/v3"          # 1. real base URL, from the docs
FEED_TYPES = {"malicious_ips": "ip_address", "malicious_domains": "domain"}

class VirusTotalAdapter:
    name = "VirusTotal"
    tier = 2

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        self._cache: dict[str, tuple[list[dict], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        api_key = self._credentials.get("virustotal", "api_key")   # 2. key from the provider only
        return httpx.AsyncClient(
            headers={"x-apikey": api_key},                         #    real auth header, from the docs
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("www.virustotal.com"),  # 3. egress allowlist: one host
        )

    async def fetch(self, *, time_range="7d", feed_types=None) -> FetchResult:
        requested = feed_types or list(FEED_TYPES)
        api_key = self._credentials.get("virustotal", "api_key")   # 4. fail fast on a missing key
        failed, last_exc, iocs = [], None, []
        async with self._make_client() as client:
            for ft in requested:
                try:
                    iocs.extend(await self._fetch_feed(client, ft))
                except Exception as exc:
                    failed.append(ft); last_exc = exc              # 5. per-feed-type partial failure
        if last_exc is not None and len(failed) == len(requested):
            raise last_exc                                         # 6. TOTAL failure propagates
        return FetchResult(iocs=iocs, source="VirusTotal", tier=2, ...,
                           feed_types_fetched=[t for t in requested if t not in failed],
                           partial_failure=failed)

    def _normalize(self, entry, feed_type) -> dict | None:         # 7. map ONE record → ioc_network
        value = entry.get("id")
        if not value:
            return None
        malicious = (entry.get("attributes") or {}).get("last_analysis_stats", {}).get("malicious", 0)
        confidence = "High" if malicious >= 10 else "Medium" if malicious >= 3 else "Low"
        ioc_type = "IPv4" if entry.get("type") == "ip_address" else "Domain"
        return {"type": ioc_type, "value": value, "confidence": confidence,
                "source": "VirusTotal", "action": "block", "tlp": "WHITE"}
```

The seven numbered points are the whole recipe; the rest (pagination, caching, rate-limit backoff) is feed-specific detail you take from the docs.

### Step-by-step

1. **Store the credential** under a new adapter name. Env mode reads `{ADAPTER}_{KEY}` — `credentials.get("recordedfuture", "api_key")` → `RECORDEDFUTURE_API_KEY`. Vault mode reads `secret/data/recordedfuture/api_key` (see the rotation section above). Nothing else in the codebase needs the raw key.
2. **Copy the real auth scheme from the vendor docs.** Header (`x-apikey`, `Key`, `X-OTX-API-KEY`), HTTP Basic (`auth=(user, key)`, as Q-Feeds uses), or a `key` **query parameter** (Shodan). If the key rides in the URL, it will otherwise land in httpx's INFO logs — `audit.py` already installs a redaction filter for that case; keep your own logging to endpoint/query-name/exception-*type* only.
3. **Add the host to the egress allowlist**: `event_hooks=egress_event_hooks("api.vendor.com")`. A compromised or buggy adapter then physically cannot exfiltrate to another host.
4. **Fail fast on a missing credential** by fetching the key before opening the client, so an unconfigured feed raises `CredentialError`/`KeyError` cleanly (the tool layer turns that into an `unverified` Coverage-Ledger entry, not a crash).
5. **Return partial failures, raise total ones.** If some feed types succeed, return them with `partial_failure` populated. If *every* requested feed type fails, `raise` — that lets the fan-out's circuit breaker and backoff retry engage (a swallowed failure disables both).
6. **Set honest confidence and `action`.** Map the vendor's own score/verdict to `High`/`Medium`/`Low`; use `action: block` only for high-confidence blocklists, `action: alert` for heuristic/crawler detections (as `shodan.py` does). Never invent a confidence the source doesn't support (R3).
7. **Normalize to `ioc_network`** with at least `type`, `value`, `confidence`, `source`. Parse IPs with `ipaddress` (rejects malformed octets), and normalise any naive timestamps to RFC 3339 so runtime date-time validation passes (see `shodan.py::_normalize_timestamp`). Return `None` to skip a record rather than emitting a half-populated one.
8. **Register it.** Add a `{name}_fetch_iocs` tool in `server.py` (copy an existing one — they're identical except for names/tiers), append a `FeedSource(..., CircuitBreaker("Name"), _CONFIG_ERRORS)` to `_FEED_SOURCES` so `fetch_all_iocs` picks it up, and add a `list_available_feeds` entry.
9. **Test with `pytest-httpx`** — no live calls in CI. Mock the documented response, assert normalization, pagination stop, cache reuse, the total-failure `raise`, and (if the key is in the URL) that it never appears in `caplog`. See `tests/test_shodan.py` for the full set.

### API contract for each paid subscription source

Base URL and auth below were read from each vendor's **official SDK source** (GitHub/PyPI) — not from memory — so they are safe to build against. The endpoint paths and response shapes still come from the vendor's own API reference: read it (portal in the last column) and treat any endpoint you can't confirm there as unbuilt.

| Source (tier) | Access | Base URL | Auth (from official SDK) | Provenance |
|---|---|---|---|---|
| Q-Feeds (T2) | subscription | `https://api.qfeeds.com/api` | HTTP Basic (`api_token`:key) | **implemented** — `qfeeds.py` |
| VirusTotal (T3) | Intelligence/Enterprise licence | `https://www.virustotal.com/api/v3` | header `x-apikey` | **implemented** — `virustotal.py`; SDK `VirusTotal/vt-py` |
| Shodan (T3) | membership + query credits | `https://api.shodan.io` | `key` query param | **implemented** — `shodan.py`; SDK `achillean/shodan-python` |
| AbuseIPDB (T3) | free + paid tiers | `https://api.abuseipdb.com/api/v2` | header `Key` | **implemented** — `abuseipdb.py` |
| AlienVault OTX (T3) | free/commercial pulses | `https://otx.alienvault.com` | header `X-OTX-API-KEY` | **implemented** — `otx.py`; SDK `AlienVault-OTX/OTX-Python-SDK` |
| GreyNoise (T3) | Enterprise / GNQL subscription | `https://api.greynoise.io/v3/gnql` | header `key` | **implemented** — `greynoise.py`; SDK `pygreynoise` |
| Censys (T3) | paid Search/Platform tiers | `https://search.censys.io/api/v2/hosts/search` | HTTP Basic (API ID + secret) | **implemented** — `censys.py` |
| ONYPHE (T2) | subscription | `https://www.onyphe.io/api/v2` | `apikey` param | SDK `sebdraven/pyonyphe` |
| BinaryEdge (T2) | subscription | `https://api.binaryedge.io/v2` | header `X-Key` | SDK `Te-k/pybinaryedge` |
| Intelligence X (T3) | subscription | `https://2.intelx.io` | header `x-key` | SDK `IntelligenceX/SDK` |
| Intel 471 (T2/T7) | subscription | `https://api.intel471.com/v1/indicators/stream` | HTTP Basic (email + key) | **implemented** — `intel471.py` |
| Any.Run (T9) | subscription | `https://api.any.run/v1/feeds/taxii2/...` | header `Authorization` | **implemented** — `anyrun.py` |
| Hybrid Analysis (T9) | free + paid tiers | `https://www.hybrid-analysis.com/api/v2` | header `api-key` | SDK `PayloadSecurity/VxAPI` |

Sources with **no reachable public SDK** — base URL/auth left blank rather than guessed; read the vendor's docs before building: Recorded Future (`support.recordedfuture.com`), Mandiant / Google TI (`cloud.google.com/security`), CrowdStrike Falcon Intel (`falcon.crowdstrike.com`, OAuth2), SecurityTrails (`docs.securitytrails.com`), Pulsedive (`pulsedive.com/api`), and the Tier-7 dark-web feeds Flashpoint / Cybersixgill / DarkOwl / Kela / SOCRadar / ReliaQuest / ZeroFox / Searchlight.

> The base URLs above were verified by cloning each vendor's official SDK and reading the source; the "no reachable public SDK" list is left deliberately blank because asserting an endpoint you haven't confirmed is the exact fabrication this repo forbids.

For **non-REST** subscription sources (a gRPC feed like Chronicle, an MQTT partner broker, a GraphQL intel endpoint), use the protocol credential bundles and `ProtocolAdapter` base instead — see the next section and [`docs/protocol-adapters.md`](../docs/protocol-adapters.md).

## Protocol feeds (gRPC / MQTT / WebSocket / GraphQL)

Beyond the REST adapters, the server ships secure **credential storage** and a
**bring-your-own-endpoint adapter base** for non-REST intel transports. Typed
credential bundles (cert/key/CA for gRPC mTLS, host/port/topic for MQTT,
URL/token for WebSocket, endpoint/token for GraphQL) load through the same
env-var / Vault `CredentialProvider`, and `ProtocolAdapter` standardises
validation, dedup, and `FetchResult` assembly so a concrete feed implements only
`_collect` + `_normalize`.

No live protocol feed (and no protocol client library) ships here: a concrete
adapter is wired to a **real, operator-supplied endpoint** — inventing one would
violate the repo's no-fabrication rule. See
[`docs/protocol-adapters.md`](../docs/protocol-adapters.md) for the credential
paths and a worked GraphQL example.

## Security notes

- `EnvCredentialProvider` reads API keys from the environment. Suitable for local development only — env vars are visible in process listings and container inspection. Use `VaultCredentialProvider` for any non-local deployment.
- API keys are passed as HTTP headers (Basic auth for Q-Feeds; a `key` query parameter for Shodan). They never appear in logs — `audit.py` redacts auth headers and credential-bearing query strings, and installs a redaction filter on the `httpx`/`httpcore` loggers so the client library's own request logging can't leak a query-string key either.
- **Schema validation + sanitization.** Upstream responses are schema-validated, then sanitized (`sanitize.py`): control, zero-width, and bidirectional-override characters are stripped from feed-controlled free-text fields, lengths are capped, and any indicator whose value cleans to empty is dropped. This is the runtime counterpart to the skill's R6 rule ("source content is data, not instructions") — malformed or payload-bearing feed data is neutralised before it reaches Claude. All paths (single-feed tools, fan-out, protocol adapters) run the same `normalize.finalize_iocs` = sanitize → validate → dedup pipeline.
- **Egress allowlist.** Each adapter's HTTP client (`netpolicy.py`) blocks any outbound request to a host outside its one-host allowlist, before the request leaves the process — a compromised adapter cannot exfiltrate to an attacker-controlled host. A network/proxy-level allowlist is still recommended in production as defence in depth.

### Secrets rotation playbook

Rotate a feed's credential without downtime:

1. **Issue** the new key in the provider's console (most allow two live keys during overlap).
2. **Store** it: env mode — update the env var and restart the server; Vault mode — `vault kv put secret/<adapter>/api_key api_key=<new-key>` (KV v2 keeps the prior version, so rollback is `vault kv rollback -mount=secret <adapter>/api_key`). Multi-field protocol creds rotate the same way, key by key.
3. **Verify** with `list_available_feeds` (`credential_configured: true`) and a `fetch_all_iocs` call — the rotated source should return `consulted`, not `unverified`.
4. **Revoke** the old key once traffic is confirmed on the new one.

The server fetches credentials lazily per client, so Vault rotations are picked up on the next fetch without a restart; env-var rotations require a restart.

## Project structure

```
src/threat_intel_mcp/
├── server.py              MCP entrypoint; tool registration
├── vault/
│   ├── base.py            CredentialProvider Protocol + CredentialError
│   ├── env.py             EnvCredentialProvider (dev only)
│   ├── hashicorp.py       VaultCredentialProvider (AppRole + KV v2)
│   ├── factory.py         credential_provider_from_env() selector
│   └── protocols.py       Typed gRPC/MQTT/WebSocket/GraphQL credential bundles
├── transports/
│   └── base.py            ProtocolAdapter: bring-your-own-endpoint base class
├── adapters/
│   ├── base.py            SourceAdapter Protocol + FetchResult dataclass
│   ├── qfeeds.py          Q-Feeds REST adapter (20-min cache)
│   ├── abuseipdb.py       AbuseIPDB blacklist adapter (60-min cache)
│   ├── virustotal.py      VirusTotal Intelligence adapter (15-min cache, 15s rate limit)
│   ├── otx.py             AlienVault OTX subscribed-pulses adapter (60-min cache)
│   ├── shodan.py          Shodan Malware Hunter adapter (key param log-redacted, 60-min cache)
│   ├── greynoise.py       GreyNoise GNQL malicious-scanner adapter (60-min cache)
│   ├── anyrun.py          ANY.RUN TAXII 2.1 STIX feed adapter (60-min cache)
│   ├── intel471.py        Intel 471 Titan indicators-stream adapter (60-min cache)
│   └── censys.py          Censys Search v2 hosts adapter (60-min cache)
├── fanout.py              fetch_all_iocs: concurrent multi-source merge + dedup
├── resilience.py          CircuitBreaker + retry_with_backoff + guarded_fetch
├── netpolicy.py           Per-adapter egress allowlist (httpx request hook)
├── sanitize.py            Strip control/zero-width/bidi + cap feed free-text
├── normalize.py           Schema validation + sanitize + dedup (finalize_iocs)
└── audit.py               Structured logging with secret redaction
tests/
├── test_qfeeds.py         Q-Feeds adapter tests (pytest-httpx, no live calls)
├── test_abuseipdb.py      AbuseIPDB adapter tests
├── test_virustotal.py     VirusTotal adapter tests
├── test_otx.py            OTX adapter tests
├── test_shodan.py         Shodan adapter tests (incl. key-never-logged regression)
├── test_greynoise.py      GreyNoise adapter tests
├── test_urlhaus.py        URLhaus adapter tests
├── test_threatfox.py      ThreatFox adapter tests
├── test_anyrun.py         ANY.RUN adapter tests
├── test_intel471.py       Intel 471 adapter tests
├── test_censys.py         Censys adapter tests
├── test_stix_patterns.py  STIX pattern extractor tests
├── test_fanout.py         Fan-out merge / dedup / degrade tests (fake adapters)
├── test_resilience.py     Circuit breaker + backoff retry tests
├── test_integration.py    Real adapter -> fan-out -> guarded_fetch -> breaker (end-to-end)
├── test_server_smoke.py   Server wiring: tools registered, all 9 sources degrade gracefully
├── test_docs_consistency.py  Docs-as-code: env-var + Vault-path guards match the code
├── test_sanitize.py       Feed-data sanitization tests
├── test_netpolicy.py      Egress allowlist tests (incl. mock-transport e2e)
├── test_protocol_credentials.py  gRPC/MQTT/WS/GraphQL credential bundle tests
├── test_protocol_adapter.py      ProtocolAdapter base + fan-out integration tests
├── test_normalize.py      Normaliser / validator tests
└── test_vault.py          Vault provider + factory tests (hvac mocked)
```

## Relationship to threat-intel

This package provides the **runtime and live data**. [`kj299/threat-intel`](https://github.com/kj299/threat-intel) provides the **prompt and schema**. The AI assistant uses both together: the skill structures the report; this server supplies current IOCs from subscribed feeds.

Schema contract: `ioc_network` objects from this server match the definition in [`skills/cyber-threat-intel/schemas/output.schema.json`](https://github.com/kj299/threat-intel/blob/main/skills/cyber-threat-intel/schemas/output.schema.json) exactly.
