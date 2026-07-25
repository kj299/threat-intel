# CLAUDE.md

## Project Overview

This is a cyber threat intelligence skill for Claude Code (and other Anthropic Agent Skills consumers) -- a structured prompt skill, persona specification, and output schema for generating threat intel reports.

This is NOT a product, platform, or service. It is a packaged Anthropic Agent Skill.

## Layout

- `.claude-plugin/plugin.json` -- plugin manifest. Makes the repo installable as a Claude Code plugin, which is what exposes the skill as a slash command: a top-level `skills/` directory is **not** a skill-discovery location (Claude Code looks in `~/.claude/skills/`, `.claude/skills/`, and plugins), so a plain clone offers no `/cyber-threat-intel`. Plugin skills live at `<plugin-root>/skills/<name>/SKILL.md`, which is the layout below already. Load it from a clone with `claude --plugin-dir .` at the repository root. The manifest also bundles the MCP server, launched as `python -m threat_intel_mcp`.

The skill follows the [Anthropic Agent Skills](https://code.claude.com/docs/en/skills) convention:

- `skills/cyber-threat-intel/SKILL.md` -- skill entrypoint with YAML frontmatter (name, description) and the workflow Claude follows
- `skills/cyber-threat-intel/spec.yaml` -- structured spec (personas, scoring, source-tier minimums, compliance mappings); consumed by CI validators
- `skills/cyber-threat-intel/references/` -- supporting reference docs loaded only when needed
  - `source-matrix.md` -- the full named source list across 9 tiers (R1/R2 guidance)
  - `extraction-framework.md` -- IOC, TTP, actor, and forecast field schemas
  - `cwe-chaining.md` -- weakness-class (CWE) chaining for AI-assisted attacks, with defensive break-points
  - `scoring.md` -- threat scoring formula and priority mapping
  - `personas.md` -- the 6 supported personas
  - `output-templates.md` -- per-persona section lists and the mandatory Source Coverage Ledger template
  - `siem-queries.md` -- Splunk SPL / Sentinel KQL authoring (discovery-first, schema-driven, no invented datasets)
  - `compliance-frameworks.md` -- NIST/ISO/PCI/DORA/NYDFS/SOX/GDPR mappings
  - `original-prompt.md` -- the original long-form prompt, kept for non-Claude assistants and as the canonical source for tier-name parity checks
- `skills/cyber-threat-intel/schemas/output.schema.json` -- JSON Schema for validating structured output
- `skills/cyber-threat-intel/examples/outputs.json` -- one example output per persona
- `tests/invalid/` -- negative schema fixtures (must be rejected)
- `.github/workflows/validate.yml` -- CI: layout, JSON/YAML syntax, schema conformance, version parity, persona parity, coverage-ledger consistency, tier parity, feed consistency, negative fixtures, source-list content parity (3 mirrored files), excluded-origin denylist; second job runs `mcp/` pytest suite (incl. skill-to-server tool parity) + ruff lint
- `.github/workflows/report-staleness.yml` -- weekly alarm: opens/bumps an issue if `reports/` goes >10 days without a new report (see `docs/report-runbook.md`)
- `mcp/` -- `threat-intel-mcp` MCP server (stdio transport); runtime counterpart to the prompt skill
  - `mcp/src/threat_intel_mcp/adapters/` -- IOC feed adapters: Q-Feeds, AbuseIPDB, VirusTotal, AlienVault OTX, Shodan, GreyNoise, ANY.RUN (TAXII/STIX), Intel 471, Censys, plus the free public abuse.ch feed ThreatFox; CVE feed adapters: CISA KEV (public JSON) + NVD (key optional). Each carries an in-process cache + egress allowlist. `base.py` documents the adapter **error taxonomy** (see Conventions)
  - `mcp/src/threat_intel_mcp/fanout.py` + `resilience.py` -- `fetch_all_iocs` concurrent fan-out; per-source circuit breaker + backoff retry
  - `mcp/src/threat_intel_mcp/normalize.py` + `sanitize.py` -- `finalize_iocs` = sanitize -> validate (ioc_network schema, runtime date-time checking) -> dedupe (corroboration-preserving)
  - `mcp/src/threat_intel_mcp/vulns.py` -- CVE-keyed vulnerability-output path (counterpart to normalize.py/fanout.py): `finalize_vulns` = sanitize -> validate (inline CVE-record schema) -> dedupe by CVE ID; `fan_out_vulns` = `fetch_all_cves` concurrent fan-out
  - `mcp/src/threat_intel_mcp/vault/` -- credential providers: `EnvCredentialProvider` (dev) and `VaultCredentialProvider` (HashiCorp AppRole + KV v2); `protocols.py` = typed gRPC/MQTT/WebSocket/GraphQL credential bundles
  - `mcp/src/threat_intel_mcp/transports/` -- `ProtocolAdapter` bring-your-own-endpoint base (no live protocol feed ships; see docs/protocol-adapters.md)
  - `mcp/src/threat_intel_mcp/__main__.py` -- `python -m threat_intel_mcp` entry point. The `threat-intel-mcp` console script only resolves when the interpreter's scripts directory is on `PATH`, which it frequently is not on Windows; the module form always works and is what the plugin manifest and the documented `claude mcp add` registration use
  - `mcp/src/threat_intel_mcp/server.py` -- FastMCP entry point: `fetch_all_iocs` + 11 single-feed IOC tools; `fetch_all_cves` + `cisa_kev_fetch_cves` + `nvd_fetch_cves`; `list_available_feeds` (IOC feeds under `feeds`, CVE feeds under `cve_sources`)
  - `mcp/tests/` -- unit + httpx-mock integration tests (no live network)

Repo-root `README.md`, `LICENSE`, `CLAUDE.md`, `changelog.md`, `contributing.md`, `docs.md` stay at the root.

## Conventions

- Skill follows Anthropic Agent Skills spec: `SKILL.md` with YAML frontmatter (`name`, `description`), `name` is lowercase-hyphen and matches directory name, body under 500 lines, supporting files in `references/` / `schemas/` / `examples/` referenced from `SKILL.md`.
- File naming inside the skill: kebab-case (`source-matrix.md`, `output.schema.json`).
- Repo root: lowercase for project files, UPPERCASE for standard GitHub files (README, LICENSE, etc.).
- YAML: 2-space indent, snake_case keys.
- All claims about capabilities should be honest about what prompt engineering can and cannot do.
- No fictional infrastructure (fake domains, fake email addresses, fake pricing).
- **Source Governance** (authoritative in `skills/cyber-threat-intel/references/source-matrix.md`): additions need a verified org + official URL with the verification source named in the PR; sources based in CN/RU/KP/BY/IR are excluded; CI enforces mirror parity and an excluded-origin denylist.
- **MCP adapter error taxonomy** (authoritative in `mcp/src/threat_intel_mcp/adapters/base.py`): an adapter's `fetch` raises `ValueError` **only** for caller errors (bad `feed_types`/`time_range`) — the server tool surfaces these verbatim; `CredentialError`/`KeyError` for missing/unreadable credentials — degrade to `unverified`, non-retryable; and **anything else** (`httpx` errors, `RuntimeError`, parse failures, and a **malformed 200 body**) for upstream/transient problems — degrade + retryable. Never raise `ValueError` for a malformed upstream body: the tool re-raises it and crashes instead of degrading. Every single-feed tool has a malformed-body degrade guard in `mcp/tests/test_server_smoke.py`.
- **Empty results** (authoritative in `mcp/src/threat_intel_mcp/adapters/base.py`): an adapter must never report a confident `0 records` from a body it could not read. Every parse routes through `guard_parsed`, which raises `UpstreamFormatError` (a `RuntimeError`, so the tool degrades and the fan-out retries) when items are present but **none** is understood. A payload with no items, and one whose items are understood then filtered out, both still return `0` with no error — that distinction is what keeps the guard from firing on quiet weeks.
- **When a repository change alters what the code does, update the architecture/layout docs to match** — `docs/architecture.md`, the layout above, and `mcp/README.md` must reflect the real code, not an aspirational version.
