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
  │                  abuseipdb_fetch_blocklist / virustotal_fetch_iocs / otx_fetch_iocs
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
| Concurrent fan-out (`fetch_all_iocs`) | ✅ Phase 4 |
| Circuit breakers + backoff retry per source | ✅ Phase 4 |
| Partial-failure surfacing → Coverage Ledger | ✅ Phase 4 |
| Protocol credential bundles (gRPC/MQTT/WebSocket/GraphQL) | ✅ Phase 3 |
| `ProtocolAdapter` bring-your-own-endpoint base | ✅ Phase 3 |
| Egress allowlist, response sanitization, rotation playbook | Phase 4 (pending) |
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
#   VT_API_KEY          — https://www.virustotal.com/gui/user/apikey
#   OTX_API_KEY         — https://otx.alienvault.com/settings (API Integration)
export $(grep -v '^#' .env | xargs)
```

Keys are optional individually — the server starts with whatever keys are configured and marks unconfigured feeds as `unverified` in the Coverage Ledger.

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
        "VT_API_KEY": "your-virustotal-key",
        "OTX_API_KEY": "your-otx-key"
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
vault kv put secret/qfeeds    api_key=<your-qfeeds-key>
vault kv put secret/abuseipdb api_key=<your-abuseipdb-key>
vault kv put secret/virustotal api_key=<your-vt-key>
vault kv put secret/otx       api_key=<your-otx-key>
```

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
  {"name": "AlienVault OTX","tier": 2, "access_level": "community"}
]
```

Claude will call the relevant `*_fetch_iocs` tools, blend live IOCs with its training-data knowledge, and cite each source in the Coverage Ledger (Appendix A) without marking findings as `unverified`.

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
- API keys are passed as HTTP headers (or Basic auth for Q-Feeds). They never appear in logs — `audit.py` redacts auth headers and credential-bearing query strings.
- Upstream responses are schema-validated before being returned to Claude. Malformed IOCs (including any prompt-injection attempt embedded in feed data) are dropped at the normalisation layer.

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
│   └── otx.py             AlienVault OTX subscribed-pulses adapter (60-min cache)
├── fanout.py              fetch_all_iocs: concurrent multi-source merge + dedup
├── resilience.py          CircuitBreaker + retry_with_backoff + guarded_fetch
├── normalize.py           Schema validation + deduplication
└── audit.py               Structured logging with secret redaction
tests/
├── test_qfeeds.py         Q-Feeds adapter tests (pytest-httpx, no live calls)
├── test_abuseipdb.py      AbuseIPDB adapter tests
├── test_virustotal.py     VirusTotal adapter tests
├── test_otx.py            OTX adapter tests
├── test_fanout.py         Fan-out merge / dedup / degrade tests (fake adapters)
├── test_resilience.py     Circuit breaker + backoff retry tests
├── test_protocol_credentials.py  gRPC/MQTT/WS/GraphQL credential bundle tests
├── test_protocol_adapter.py      ProtocolAdapter base + fan-out integration tests
├── test_normalize.py      Normaliser / validator tests
└── test_vault.py          Vault provider + factory tests (hvac mocked)
```

## Relationship to threat-intel

This package provides the **runtime and live data**. [`kj299/threat-intel`](https://github.com/kj299/threat-intel) provides the **prompt and schema**. The AI assistant uses both together: the skill structures the report; this server supplies current IOCs from subscribed feeds.

Schema contract: `ioc_network` objects from this server match the definition in [`skills/cyber-threat-intel/schemas/output.schema.json`](https://github.com/kj299/threat-intel/blob/main/skills/cyber-threat-intel/schemas/output.schema.json) exactly.
