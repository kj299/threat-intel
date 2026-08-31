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
  - `personas.md` -- the 6 supported personas, and how `executive_overview` pairs one report with an executive overview
  - `output-templates.md` -- per-persona section lists and the mandatory Source Coverage Ledger template. `executive_overview` is **orthogonal** to these: it prepends or splits off the overview without changing which sections the chosen template emits
  - `siem-queries.md` -- Splunk SPL / Sentinel KQL authoring (discovery-first, schema-driven, no invented datasets)
  - `compliance-frameworks.md` -- NIST/ISO/PCI/DORA/NYDFS/SOX/GDPR mappings
  - `original-prompt.md` -- the original long-form prompt, kept for non-Claude assistants and as the canonical source for tier-name parity checks
- `standalone/` -- self-contained copies for consumers that cannot install a plugin: `cyber-threat-intel-prompt.md` (long-form) and `cyber-threat-intel-skill.md` (condensed). **These are mirrors, not derivatives generated at build time**, so they drift silently unless CI compares them: the source-list check covers three files (matrix + original-prompt + standalone prompt) and the user-input check covers four (SKILL.md + original-prompt + both standalone files). The latter exists because `original-prompt.md` went a whole release missing input #10 (#168).
- `skills/cyber-threat-intel/schemas/output.schema.json` -- JSON Schema for validating structured output
- `skills/cyber-threat-intel/examples/outputs.json` -- one example output per persona
- `tests/invalid/` -- negative schema fixtures (must be rejected)
- `evals/` -- skill-output honesty evals (#83). `invariants.py` checks a generated report for the R1-R6 properties CI otherwise ignores (badge present and **not over-claimed**, ledger present, no-fabrication claim, no reserved-range indicators, sparse reports saying so in prose); `scenarios.py` defines six golden scenarios including R6 injection resistance; `run.py --corpus` checks every committed report offline (PR-gated), `run.py --scenario KEY` invokes the skill (model call, on demand). Assertions match **substance across several real phrasings, not exact labels** -- an exact-string draft false-alarmed on two honest reports -- and the badge check is **directional**: over-claiming fails, under-claiming is a style note, because a report consulting 14 training-data sources is right to badge MINIMAL
- `.github/workflows/validate.yml` -- CI: layout, JSON/YAML syntax, schema conformance, version parity, persona parity, **user-input parity across the four mirrored prompt files**, coverage-ledger consistency, tier parity, feed consistency, negative fixtures, source-list content parity (3 mirrored files), excluded-origin denylist; second job runs `mcp/` pytest suite (incl. skill-to-server tool parity) + ruff lint
- `.github/workflows/report-staleness.yml` -- weekly alarm: opens/bumps an issue if `reports/` goes >10 days without a new report (see `docs/report-runbook.md`)
- `.github/workflows/live-feed-check.yml` -- weekly live check of the keyless feeds (ThreatFox, CISA KEV, NVD) against their **real** endpoints; opens/bumps an issue on failure and closes it on recovery. Runs `pytest -m live`, which `pyproject.toml` deselects by default so PR CI stays mock-only (#78)
- `mcp/` -- `threat-intel-mcp` MCP server (stdio transport); runtime counterpart to the prompt skill
  - `mcp/src/threat_intel_mcp/adapters/` -- IOC feed adapters: Q-Feeds, AbuseIPDB, VirusTotal, AlienVault OTX, Shodan, GreyNoise, ANY.RUN (TAXII/STIX), Intel 471, Censys, plus the free public abuse.ch feed ThreatFox; CVE feed adapters: CISA KEV (public JSON) + NVD (key optional). Each carries an in-process cache + egress allowlist. `base.py` documents the adapter **error taxonomy** (see Conventions)
  - `mcp/src/threat_intel_mcp/fanout.py` + `resilience.py` -- `fetch_all_iocs` concurrent fan-out; per-source circuit breaker + backoff retry
  - `mcp/src/threat_intel_mcp/normalize.py` + `sanitize.py` -- `finalize_iocs` = sanitize -> validate (ioc_network schema, runtime date-time checking) -> dedupe (corroboration-preserving)
  - `mcp/src/threat_intel_mcp/vulns.py` -- CVE-keyed vulnerability-output path (counterpart to normalize.py/fanout.py): `finalize_vulns` = sanitize -> validate (inline CVE-record schema) -> dedupe by CVE ID; `fan_out_vulns` = `fetch_all_cves` concurrent fan-out
  - `mcp/src/threat_intel_mcp/vault/` -- credential providers: `EnvCredentialProvider` (dev) and `VaultCredentialProvider` (HashiCorp AppRole + KV v2); `protocols.py` = typed gRPC/MQTT/WebSocket/GraphQL credential bundles
  - `mcp/src/threat_intel_mcp/transports/` -- `ProtocolAdapter` bring-your-own-endpoint base; `misp_zmq.py` is its **first concrete subclass** (#162), subscribing to MISP's ZeroMQ pub-sub. **It uses no credentials** -- MISP ZMQ has no auth and relies on network isolation -- so it proves the *transport* abstraction, not the credential path, which stays unexercised until a feed with real auth appears. Framing is one frame with topic and JSON split on the **first space**, read from MISP's own `sub.py` rather than assumed (a multipart reader, the natural guess, gets nothing)
  - `mcp/src/threat_intel_mcp/render/` -- presentation layer (#110). `executive.py` renders an `enterprise_executive` output as a self-contained landscape HTML page; `python -m threat_intel_mcp.render in.json -o out.html`. **Not an MCP tool by design** -- the server's tool surface is the feed contract, mirrored in both skill files and asserted by the skill-to-server parity test, and rendering is a local transform of data the caller already holds. Risk uses a sequential single-hue ramp rather than red/amber/green because status hues are non-monotonic in lightness and collapse in greyscale; nothing is encoded by colour alone, and modelled figures are labelled in the tile
  - `mcp/src/threat_intel_mcp/__main__.py` -- `python -m threat_intel_mcp` entry point. The `threat-intel-mcp` console script only resolves when the interpreter's scripts directory is on `PATH`, which it frequently is not on Windows; the module form always works and is what the plugin manifest and the documented `claude mcp add` registration use
  - `mcp/src/threat_intel_mcp/server.py` -- FastMCP entry point: `fetch_all_iocs` + 11 single-feed IOC tools; `fetch_all_cves` + `cisa_kev_fetch_cves` + `nvd_fetch_cves`; `list_available_feeds` (IOC feeds under `feeds`, CVE feeds under `cve_sources`)
  - `mcp/tests/` -- unit + httpx-mock integration tests (no live network); `test_pipeline_duplication.py` is the **#84 trip-wire** -- the IOC and CVE output pipelines are a sanctioned pair, and CI fails if a *third* copy of the fan-out/finalize machinery lands or if the two existing copies **structurally diverge** (compared as control-flow shape with identifiers stripped, not text similarity -- a 0.90 difflib floor missed a real four-line drift)
  - `mcp/tests/cassettes/` + `mcp/tests/vcr_config.py` + `mcp/scripts/record_cassettes.py` -- vcrpy cassettes: real feed responses recorded once and replayed offline, so at least one test per adapter runs against bytes the service actually sent rather than a fixture written from belief (#105). Recording needs egress the dev sandbox lacks -- use the `record-cassettes` workflow. Cassette tests **skip** when no recording is present. Credential scrubbing is asserted in CI by `tests/test_vcr_harness.py`

Repo-root `README.md`, `LICENSE`, `SECURITY.md`, `CLAUDE.md`, `changelog.md`, `contributing.md` stay at the root. **All prose documentation lives in `docs/`** -- `docs.md` was folded to `docs/index.md` (#86) because a root file and a root directory with near-identical names is navigation friction, and CI now fails on any broken relative markdown link outside the historical `docs/releases/` snapshots.

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
