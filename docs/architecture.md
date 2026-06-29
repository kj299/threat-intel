# Architecture: Intelligence Feed Data Flow

This diagram shows how the threat-intel skill, the MCP server, and external intelligence
feeds interact to produce a live-sourced threat intelligence report.

```mermaid
flowchart TD
    subgraph CC["Claude Code"]
        User["User\n/cyber-threat-intel"]
        Skill["Skill\nskills/cyber-threat-intel/SKILL.md"]
        Output["Output\nValidated against\noutput.schema.json"]
    end

    subgraph MCP["threat-intel-mcp (stdio transport)"]
        Server["MCP Server\nserver.py\ntool: qfeeds_fetch_iocs"]

        subgraph Cred["CredentialProvider"]
            EnvCred["Phase 1: EnvCredentialProvider\nreads QFEEDS_API_KEY"]
            VaultCred["Phase 2: VaultCredentialProvider\nreads from HashiCorp Vault"]
        end

        subgraph Adapters["Adapters"]
            QFeeds["QFeedsAdapter\nadapters/qfeeds.py\nHTTP Basic auth\n20-min cache"]
            OTX["AlienVault OTX\n(planned)"]
            AbuseIPDB["AbuseIPDB\n(planned)"]
            VT["VirusTotal\n(planned)"]
        end

        Normalize["normalize.py\nvalidate_iocs + deduplicate_iocs\nioc_network schema"]
        FetchResult["FetchResult\niocs · source · tier\nrecord_count · retrieved_at"]
    end

    subgraph Ext["External Feeds"]
        QFeedsAPI["Q-Feeds API\nhttps://api.qfeeds.com/api\npaginated · malware_ip · malware_domains"]
        OTX_API["AlienVault OTX API\n(planned)"]:::planned
        AbuseIPDB_API["AbuseIPDB API\n(planned)"]:::planned
        VT_API["VirusTotal API\n(planned)"]:::planned
    end

    User -->|"invokes skill"| Skill
    Skill -->|"calls MCP tool"| Server
    Server --> EnvCred
    Server -.->|"Phase 2"| VaultCred
    EnvCred -->|"api_key"| QFeeds
    VaultCred -.->|"api_key (Phase 2)"| QFeeds
    QFeeds -->|"GET /api?feed_type=..&page=N"| QFeedsAPI
    QFeedsAPI -->|"plain-text indicators"| QFeeds
    QFeeds -->|"raw ioc_network objects"| Normalize
    Normalize -->|"validated + deduped IOCs"| FetchResult
    FetchResult -->|"iocs · coverage_ledger_entry"| Server
    Server -->|"FetchResult dict"| Skill
    Skill -->|"cites as source: Q-Feeds (live)\nincorporates IOCs into report"| Output
    Output -->|"validated JSON"| User

    Server -.->|"planned"| OTX
    Server -.->|"planned"| AbuseIPDB
    Server -.->|"planned"| VT
    OTX -.->|"planned"| OTX_API
    AbuseIPDB -.->|"planned"| AbuseIPDB_API
    VT -.->|"planned"| VT_API

    classDef planned stroke-dasharray:6 4,fill:#f9f9f9,color:#888
    class OTX,AbuseIPDB,VT,OTX_API,AbuseIPDB_API,VT_API planned
```

## Component Notes

| Component | File | Role |
|-----------|------|------|
| Skill | `skills/cyber-threat-intel/SKILL.md` | Entrypoint; guides analysis workflow and report structure |
| MCP Server | `mcp/src/threat_intel_mcp/server.py` | FastMCP stdio server; exposes `qfeeds_fetch_iocs` and `list_available_feeds` |
| EnvCredentialProvider | `mcp/src/threat_intel_mcp/vault/env.py` | Phase 1: reads `QFEEDS_API_KEY` from environment |
| VaultCredentialProvider | `mcp/src/threat_intel_mcp/vault/` | Phase 2: reads credentials from HashiCorp Vault (planned) |
| QFeedsAdapter | `mcp/src/threat_intel_mcp/adapters/qfeeds.py` | Fetches paginated malware IP and domain feeds; 20-min in-process cache |
| normalize.py | `mcp/src/threat_intel_mcp/normalize.py` | Validates `ioc_network` objects against inline schema; deduplicates by `(type, value)` |
| FetchResult | `mcp/src/threat_intel_mcp/adapters/base.py` | Dataclass: `iocs`, `source`, `tier`, `record_count`, `retrieved_at`, `latency_ms` |
| Output schema | `skills/cyber-threat-intel/schemas/output.schema.json` | JSON Schema the final report is validated against |

Dashed boxes and dashed arrows indicate components planned for a future phase but not yet implemented.
