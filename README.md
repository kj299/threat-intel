# Cyber Threat Intelligence Skill

An [Anthropic Agent Skill](https://code.claude.com/docs/en/skills) that guides Claude Code (and other Skill-aware AI assistants) to produce professional-grade cyber threat intelligence reports with strong source-coverage guidance, per-IOC source citations, and a strict no-fabrication rule. Source-coverage targets are recommendations, not quotas: when little is retrievable for the requested scope and time range, the report says so plainly rather than padding or inventing data.

The "paste this prompt into another LLM" workflow is also supported -- use the self-contained [standalone/cyber-threat-intel-prompt.md](standalone/cyber-threat-intel-prompt.md) (the long-form canonical prompt also lives at [skills/cyber-threat-intel/references/original-prompt.md](skills/cyber-threat-intel/references/original-prompt.md)).

---

## Install

### Personal install (available across all projects)

**macOS / Linux:**
```bash
mkdir -p ~/.claude/skills
cp -R skills/cyber-threat-intel ~/.claude/skills/
```

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.claude\skills" | Out-Null
Copy-Item -Recurse -Force skills\cyber-threat-intel "$env:USERPROFILE\.claude\skills\"
```

Claude Code picks up the skill on next session start (or immediately, if the `~/.claude/skills` directory already existed). Invoke as:

```
/cyber-threat-intel
```

Or just ask Claude something like "What ransomware groups are active right now?" and it will load the skill automatically (description-based discovery).

### Project install

If you want the skill scoped to a single project, copy it under that project's `.claude/skills/`:

**macOS / Linux:**
```bash
mkdir -p .claude/skills
cp -R skills/cyber-threat-intel .claude/skills/
```

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Force -Path .claude\skills | Out-Null
Copy-Item -Recurse -Force skills\cyber-threat-intel .claude\skills\
```

### Use as-is from this repo

If you've cloned this repo and want to invoke the skill in-place, the standard Claude Code discovery paths are `~/.claude/skills/` and `<workdir>/.claude/skills/`. A `<repo>/skills/` directory is not on the default search path (though it can be reached via plugin / marketplace mechanisms). The simplest path is to copy the skill into one of the standard locations as shown above.

---

## What the Skill Does

When invoked it produces a structured report with:

- A **Coverage badge** (`FULL` / `PARTIAL` / `MINIMAL`) in the header — an honest self-report of how many source tiers were actually consulted. `MINIMAL` on a genuinely sparse scope/time range is the correct outcome, not a failure.
- A **Source Coverage Ledger** in Appendix A listing which sources were queried per tier, which were skipped, and why.
- A prioritized threat list with MITRE ATT&CK mappings -- every item carries a `source` field (no unsourced claims).
- (Optional, default on) IOCs (IPs, domains, hashes, behavioral indicators) formatted for SIEM/EDR import, toggled by the `build_iocs_and_queries` input.
- Detection rules in YARA, Sigma, KQL, SPL, and Snort/Suricata formats.
- **SPL/KQL hunting & detection starters** built on normalized schema (Splunk CIM, Sentinel ASIM, Defender XDR) — concrete, runnable queries with placeholders only on environment-specific bits, each paired with a discovery query to confirm datasets and adapt.
- **CWE-chain analysis** for AI-assisted attacks — models weakness-class chains (primary → resultant) with a mandatory defensive break-point per chain, plus an AI-assist factor and time-to-exploit velocity.
- CSV, STIX 2.1, and JSON exports. For any delimited/batch export, the skill emits clean structured rows and leaves input validation/sanitization to the consuming tool.
- Recommended actions matrix with owners, timelines, and success metrics.

Items that cannot be verified are marked `unverified (source inaccessible)` rather than fabricated.

---

## Repository Layout

```
threat-intel/
+-- README.md                                         # this file
+-- LICENSE
+-- CLAUDE.md                                         # AI-assistant project context
+-- docs/                                             # ALL prose documentation
|   +-- index.md                                      # the deep reference (protocol, personas, scoring, validation)
|   +-- architecture.md                               # Mermaid data-flow diagram
|   +-- report-runbook.md                             # generating reports; the staleness alarm
+-- changelog.md
+-- contributing.md
+-- .github/workflows/validate.yml                    # CI: layout + schema + parity checks
+-- tests/invalid/                                    # negative fixtures (must be rejected)
+-- skills/
    +-- cyber-threat-intel/
        +-- SKILL.md                                  # Agent Skill entrypoint
        +-- spec.yaml                                 # structured spec (personas, scoring, tiers)
        +-- references/
        |   +-- source-matrix.md                      # 150+ named sources across 9 tiers
        |   +-- extraction-framework.md               # IOC/TTP/actor field schemas
        |   +-- cwe-chaining.md                       # CWE-chain analysis (AI-assisted) + break-points
        |   +-- scoring.md                            # scoring formula + priority mapping
        |   +-- personas.md                           # 6 supported personas
        |   +-- output-templates.md                   # per-persona report sections
        |   +-- siem-queries.md                       # SPL/KQL authoring: starter-first, normalized CIM/ASIM (no invented datasets)
        |   +-- compliance-frameworks.md              # NIST/ISO/PCI/DORA/NYDFS/SOX/GDPR
        |   +-- original-prompt.md                    # long-form prompt for non-Claude assistants
        +-- schemas/
        |   +-- output.schema.json                    # JSON Schema for output validation
        +-- examples/
            +-- outputs.json                          # one example per persona
+-- evals/                                           # skill-output honesty evals (invariants + scenarios)
+-- standalone/                                      # flattened single-file distributions (hand-maintained mirrors)
|   +-- cyber-threat-intel-prompt.md                # self-contained prompt (any LLM)
|   +-- cyber-threat-intel-skill.md                 # self-contained Agent Skill
+-- mcp/                                             # threat-intel-mcp server (v0.13.0)
    +-- pyproject.toml                               # package definition (threat-intel-mcp)
    +-- src/threat_intel_mcp/
    |   +-- server.py                                # FastMCP stdio server entry point
    |   +-- normalize.py                             # ioc_network schema validation + dedup
    |   +-- audit.py                                 # structured audit logging + secret redaction
    |   +-- fanout.py                                # fetch_all_iocs: concurrent multi-source IOC merge
    |   +-- vulns.py                                 # fetch_all_cves: CVE-keyed vuln validate/dedup/fan-out
    |   +-- resilience.py                            # circuit breaker + backoff retry (guarded_fetch)
    |   +-- netpolicy.py                             # per-adapter egress allowlist (httpx hook)
    |   +-- sanitize.py                              # feed free-text sanitization (R6 runtime defense)
    |   +-- adapters/
    |   |   +-- base.py                              # FetchResult dataclass, SourceAdapter protocol
    |   |   +-- qfeeds.py                            # Q-Feeds HTTP adapter (paginated, 20-min cache)
    |   |   +-- abuseipdb.py                         # AbuseIPDB blacklist adapter (60-min cache)
    |   |   +-- virustotal.py                        # VirusTotal Intelligence adapter (15-min cache)
    |   |   +-- otx.py                               # AlienVault OTX pulses adapter (60-min cache)
    |   |   +-- shodan.py                            # Shodan Malware Hunter adapter (60-min cache)
    |   |   +-- greynoise.py                         # GreyNoise GNQL malicious-scanner adapter (60-min cache)
    |   |   +-- threatfox.py                         # ThreatFox public IOC feed (no key)
    |   |   +-- anyrun.py                            # ANY.RUN TAXII 2.1 STIX feed adapter
    |   |   +-- intel471.py                          # Intel 471 Titan indicators-stream adapter
    |   |   +-- censys.py                            # Censys Search v2 hosts adapter
    |   |   +-- cisa_kev.py                          # CISA KEV catalog adapter (public JSON, no key)
    |   |   +-- nvd.py                               # NIST NVD 2.0 CVE adapter (key optional)
    |   +-- transports/
    |   |   +-- base.py                              # ProtocolAdapter: bring-your-own-endpoint base
    |   +-- vault/
    |       +-- base.py                              # CredentialProvider protocol + error types
    |       +-- env.py                               # EnvCredentialProvider (env vars)
    |       +-- hashicorp.py                         # VaultCredentialProvider (AppRole + KV v2)
    |       +-- factory.py                           # credential_provider_from_env() selector
    |       +-- protocols.py                         # gRPC/MQTT/WebSocket/GraphQL credential bundles
    +-- tests/                                       # 312 unit + httpx-mock integration tests
```

---

## How it behaves

Three properties are worth knowing before you run it. Each is explained in full in
**[docs/index.md](docs/index.md)** — the deep reference — rather than restated here.

- **Source Coverage Protocol (R1–R6).** Six rules applied as *strong guidance*, not a hard
  gate: per-tier source targets, a citation on every claim, and — the hard line — **no
  fabrication**. An inaccessible source is marked `unverified`, never replaced with an
  invented IP, hash or CVE, and a quiet week is reported as quiet. Every report carries an
  honest `FULL`/`PARTIAL`/`MINIMAL` badge and a per-tier ledger in Appendix A. Source
  content is treated as evidence, never as instruction (prompt-injection defence).
  → [the six rules in full](docs/index.md#source-coverage-protocol) ·
  [the source matrix](skills/cyber-threat-intel/references/source-matrix.md)

- **Six personas.** `enterprise_soc`, `enterprise_executive`, `smb_security`,
  `individual_researcher`, `individual_privacy`, `red_team` — the persona drives section
  list, tone and depth. A single run can also emit an executive overview alongside the
  technical report via the `executive_overview` input.
  → [what each persona gets](docs/index.md#personas) ·
  [personas.md](skills/cyber-threat-intel/references/personas.md) ·
  [`spec.yaml`](skills/cyber-threat-intel/spec.yaml) under `persona_profiles`

- **Threat scoring.** A weighted score over exploitability, impact, relevance and urgency,
  mapped to P1–P5 with response times.
  → [formula and priority bands](docs/index.md#threat-scoring) ·
  [scoring.md](skills/cyber-threat-intel/references/scoring.md)

---

## MCP Server (`mcp/`)

The `mcp/` directory contains `threat-intel-mcp`, an [MCP](https://modelcontextprotocol.io/) server that gives Claude Code live access to threat intelligence feeds. It is the runtime counterpart to the prompt skill — the skill structures the analysis; the MCP server fetches real indicators.

**Current (v0.13.0, Phase 5):** IOC feeds — Q-Feeds, AbuseIPDB, VirusTotal Intelligence, AlienVault OTX, Shodan, GreyNoise, ANY.RUN, Intel 471, Censys, and the free public abuse.ch feed ThreatFox; government CVE feeds — CISA KEV and NVD (Tier 1) via a CVE-keyed vulnerability-output path; concurrent fan-out (`fetch_all_iocs` / `fetch_all_cves`) with per-source circuit breakers; feed-data sanitization and egress allowlists; env-var or HashiCorp Vault credentials; protocol credential bundles + bring-your-own-endpoint adapter base for gRPC/MQTT/WebSocket/GraphQL.

```bash
cd mcp
pip install -e .
# Set whichever API keys you have:
export QFEEDS_API_KEY=...
export ABUSEIPDB_API_KEY=...
export VIRUSTOTAL_API_KEY=...
export OTX_API_KEY=...
export SHODAN_API_KEY=...
export GREYNOISE_API_KEY=...
export ANYRUN_API_KEY=... INTEL471_EMAIL=... INTEL471_API_KEY=... CENSYS_API_ID=... CENSYS_API_SECRET=...
export NVD_API_KEY=...   # optional — NVD works without a key at a lower rate limit
# ThreatFox and CISA KEV are free public feeds and need no key
threat-intel-mcp   # stdio transport; wire into Claude Code via .claude/mcp.json
```

Configure in Claude Code (`~/.claude/mcp.json` or project `.claude/mcp.json`):

```json
{
  "mcpServers": {
    "threat-intel": {
      "command": "threat-intel-mcp",
      "env": {
        "QFEEDS_API_KEY": "your-qfeeds-key",
        "ABUSEIPDB_API_KEY": "your-abuseipdb-key",
        "VIRUSTOTAL_API_KEY": "your-vt-key",
        "OTX_API_KEY": "your-otx-key",
        "SHODAN_API_KEY": "your-shodan-key",
        "GREYNOISE_API_KEY": "your-greynoise-key",
        "ANYRUN_API_KEY": "API-Key your-anyrun-token",
        "INTEL471_EMAIL": "you@example.com", "INTEL471_API_KEY": "your-intel471-key",
        "CENSYS_API_ID": "your-censys-id", "CENSYS_API_SECRET": "your-censys-secret"
      }
    }
  }
}
```

Tools exposed — IOC feeds: `fetch_all_iocs` (all IOC feeds concurrently, merged + deduplicated), `qfeeds_fetch_iocs`, `abuseipdb_fetch_blocklist`, `virustotal_fetch_iocs`, `otx_fetch_iocs`, `shodan_fetch_iocs`, `greynoise_fetch_iocs`, `anyrun_fetch_iocs`, `intel471_fetch_iocs`, `censys_fetch_iocs`, `threatfox_fetch_iocs`; CVE feeds: `fetch_all_cves` (CISA KEV + NVD, merged + deduplicated by CVE ID), `cisa_kev_fetch_cves`, `nvd_fetch_cves`; plus `list_available_feeds`.

See [`mcp/README.md`](mcp/README.md) for full setup, Vault credentials, and feed-specific details — including a step-by-step [worked example of implementing a paid-subscription feed adapter](mcp/README.md#implementing-a-paid-subscription-feed-adapter) grounded in the VirusTotal Intelligence adapter, with a table of subscription sources and their official API-documentation portals.

---

## Output Validation

```bash
pip install jsonschema rfc3339-validator
jsonschema -i your-output.json skills/cyber-threat-intel/schemas/output.schema.json
```

CI runs the same validation plus version, persona, user-input, tier and source-list parity checks across `spec.yaml`, the schema, the examples, the changelog and the mirrored prompt files. See [.github/workflows/validate.yml](.github/workflows/validate.yml).

For the conforming output shape and a table of common validation errors with their fixes, see [docs/index.md](docs/index.md#schema-validation).

---

## Generated Reports (`reports/`)

Dated threat-intelligence reports produced by running the skill on a schedule (default: `enterprise_soc` persona, 7-day lookback). Each report opens with an honest **coverage badge** (`FULL`/`PARTIAL`/`MINIMAL`), a **methodology notice** stating what retrieval was actually available, and closes with **Appendix A: Source Coverage Ledger** — what was and wasn't consulted. Reports never contain fabricated indicators: a run without live feed access says so and emits no literal IOC values.

How they're generated, how to run one manually (including wiring the MCP server for live-data reports), and the weekly staleness alarm that fires if the cadence dies: see [docs/report-runbook.md](docs/report-runbook.md).

---

## Architecture

See [docs/architecture.md](docs/architecture.md) for a Mermaid flowchart showing the full data flow: User → Skill → MCP Server → CredentialProvider → Adapters (IOC feeds Q-Feeds, AbuseIPDB, VirusTotal, AlienVault OTX, Shodan, GreyNoise, ANY.RUN, Intel 471, Censys, ThreatFox; CVE feeds CISA KEV, NVD) → external feed APIs → normalize.py / vulns.py → FetchResult / VulnFetchResult → report output.

---

## Using this skill from an external consumer

The skill is built to be driven programmatically and to feed upstream/downstream cyber-ops
tooling such as a SIEM importer or batch-audit tool. Two things matter most:

- **Feed [`standalone/cyber-threat-intel-prompt.md`](standalone/cyber-threat-intel-prompt.md)**,
  which inlines everything the model needs. Do **not** feed `spec.yaml` alone — it is the CI
  spec and carries no workflow or SIEM guidance.
- **The consumer owns input validation.** The skill emits raw typed values and never escapes,
  quotes or sanitizes on a tool's behalf, because anything upstream can violate the contract.

Full hand-off contract, the `delimited_batch_export` column mapping, and the importer
limitations that follow from that design: **[docs/index.md](docs/index.md#using-this-skill-from-an-external-consumer)**.

---

## Limitations

Without the `threat-intel-mcp` server configured, output reflects the model's training data
only. Validate IOCs against trusted sources before deploying them to detection or blocking
systems, whether they came from training data or a live feed. Detection rules should be
tested in a lab first. This skill structures AI output; it does not guarantee accuracy and
does not replace professional threat intelligence or incident response.

Full list, including the `delimited_batch_export` ingestibility constraints:
**[docs/index.md](docs/index.md#limitations)**.

---

## Contributing

Contributions are welcome. See [contributing.md](contributing.md) for guidelines.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Links

- [Repository](https://github.com/kj299/threat-intel)
- [Issues](https://github.com/kj299/threat-intel/issues)
- [Changelog](changelog.md)
- [Anthropic Agent Skills documentation](https://code.claude.com/docs/en/skills)
