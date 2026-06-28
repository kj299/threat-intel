# threat-intel-mcp

MCP server that connects Claude to live threat intelligence feeds, normalising their output to the [threat-intel skill schema](https://github.com/kj299/threat-intel).

Implements the architecture described in [threat-intel issue #1](https://github.com/kj299/threat-intel/issues/1).

## How it fits together

```
Claude Code
  │  skill: threat-intel  (SKILL.md + output.schema.json)
  │  skill_input.feed_integrations = [{"name": "Q-Feeds", "tier": 2}]
  │
  │  MCP tool call: qfeeds_fetch_iocs(time_range="7d")
  ▼
threat-intel-mcp  (this repo, stdio MCP server)
  │  reads QFEEDS_API_KEY from CredentialProvider
  │  calls https://api.qfeeds.com/api (malware_ip, malware_domains)
  │  normalises → ioc_network[] per output.schema.json
  │  schema-validates + deduplicates before returning
  ▼
Claude receives ioc_network[], cites "Q-Feeds" in Coverage Ledger (R2/R5)
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
| VirusTotal / Shodan / Recorded Future adapters | Phase 3 |
| gRPC / MQTT / WebSocket / GraphQL adapters | Phase 3 |
| Circuit breakers, async fan-out, egress allowlist | Phase 4 |

## Quick start

### 1. Install

```bash
pip install -e ".[dev]"
```

### 2. Set your API key

```bash
cp .env.example .env
# Edit .env and set QFEEDS_API_KEY
# Obtain your key at: https://tip.qfeeds.com (Manage API Keys → Create Free API Key)
export $(grep -v '^#' .env | xargs)
```

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
        "QFEEDS_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

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

The default mount point is `secret`. Example for the Q-Feeds API key:

```
secret/data/qfeeds/api_key
```

Create it with:

```bash
vault kv put secret/qfeeds api_key=<your-qfeeds-key>
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
/threat-intel
feed_integrations: [{"name": "Q-Feeds", "tier": 2, "access_level": "premium"}]
```

Claude will call `qfeeds_fetch_iocs`, blend live Q-Feeds IOCs with its training-data knowledge, and cite Q-Feeds in the Coverage Ledger (Appendix A) without marking findings as `unverified`.

## Security notes

- `EnvCredentialProvider` reads `QFEEDS_API_KEY` from the environment. Suitable for local development only — env vars are visible in process listings and container inspection. Use `VaultCredentialProvider` for any non-local deployment (see [Vault Credentials](#vault-credentials-phase-2) above).
- The API key is used for HTTP Basic auth. It never appears in logs — `audit.py` redacts auth headers and credential-bearing query strings.
- Upstream responses are schema-validated before being returned to Claude. Malformed IOCs (including any prompt-injection attempt embedded in feed data) are dropped.

## Project structure

```
src/threat_intel_mcp/
├── server.py          MCP entrypoint; tool registration
├── vault/
│   ├── base.py        CredentialProvider Protocol + CredentialError
│   ├── env.py         EnvCredentialProvider (dev only)
│   ├── hashicorp.py   VaultCredentialProvider (AppRole + KV v2)
│   └── factory.py     credential_provider_from_env() selector
├── adapters/
│   ├── base.py        SourceAdapter Protocol + FetchResult dataclass
│   └── qfeeds.py      Q-Feeds REST adapter
├── normalize.py       Schema validation + deduplication
└── audit.py           Structured logging with secret redaction
tests/
├── test_qfeeds.py     Adapter tests (pytest-httpx, no live calls)
├── test_normalize.py  Normaliser / validator tests
└── test_vault.py      Vault provider + factory tests (hvac mocked)
```

## Relationship to threat-intel

This repo provides the **runtime and live data**. [`kj299/threat-intel`](https://github.com/kj299/threat-intel) provides the **prompt and schema**. The AI assistant uses both together: the skill structures the report; this server supplies current IOCs from subscribed feeds.

Schema contract: `ioc_network` objects from this server match the definition in [`skills/cyber-threat-intel/schemas/output.schema.json`](https://github.com/kj299/threat-intel/blob/main/skills/cyber-threat-intel/schemas/output.schema.json) exactly.
