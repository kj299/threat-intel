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

## Phase 1 — current state

| Feature | Status |
|---|---|
| Q-Feeds REST adapter (malware_ip, malware_domains) | ✅ |
| Env-var credential provider (dev) | ✅ |
| Schema validation + deduplication | ✅ |
| Structured audit logging with redaction | ✅ |
| MCP tool: `qfeeds_fetch_iocs` | ✅ |
| MCP tool: `list_available_feeds` | ✅ |
| pytest suite (no live calls) | ✅ |
| HashiCorp Vault credential provider | Phase 2 |
| VirusTotal / Shodan / Recorded Future adapters | Phase 2 |
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

### 5. Use with the threat-intel skill

In Claude Code, after the MCP server is connected:

```
/threat-intel
feed_integrations: [{"name": "Q-Feeds", "tier": 2, "access_level": "premium"}]
```

Claude will call `qfeeds_fetch_iocs`, blend live Q-Feeds IOCs with its training-data knowledge, and cite Q-Feeds in the Coverage Ledger (Appendix A) without marking findings as `unverified`.

## Security notes

- **Phase 1 only:** `EnvCredentialProvider` reads `QFEEDS_API_KEY` from the environment. This is suitable for local development. Replace with `HashicorpVaultProvider` before deploying.
- The API key is used for HTTP Basic auth. It never appears in logs — `audit.py` redacts auth headers and credential-bearing query strings.
- Upstream responses are schema-validated before being returned to Claude. Malformed IOCs (including any prompt-injection attempt embedded in feed data) are dropped.

## Project structure

```
src/threat_intel_mcp/
├── server.py          MCP entrypoint; tool registration
├── vault/
│   ├── base.py        CredentialProvider Protocol
│   └── env.py         EnvCredentialProvider (dev only)
├── adapters/
│   ├── base.py        SourceAdapter Protocol + FetchResult dataclass
│   └── qfeeds.py      Q-Feeds REST adapter
├── normalize.py       Schema validation + deduplication
└── audit.py           Structured logging with secret redaction
tests/
├── test_qfeeds.py     Adapter tests (pytest-httpx, no live calls)
└── test_normalize.py  Normaliser / validator tests
```

## Relationship to threat-intel

This repo provides the **runtime and live data**. [`kj299/threat-intel`](https://github.com/kj299/threat-intel) provides the **prompt and schema**. The AI assistant uses both together: the skill structures the report; this server supplies current IOCs from subscribed feeds.

Schema contract: `ioc_network` objects from this server match the definition in [`skills/cyber-threat-intel/schemas/output.schema.json`](https://github.com/kj299/threat-intel/blob/main/skills/cyber-threat-intel/schemas/output.schema.json) exactly.
