# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

---

## [1.18.0] - 2026-07-24

### Added

- **Government CVE feeds** in `threat-intel-mcp` (v0.13.0): `cisa_kev_fetch_cves` (CISA Known Exploited Vulnerabilities catalog — every entry `exploit_status: known_exploited`, with KEV due-date, required action, and ransomware-campaign flag; no credential) and `nvd_fetch_cves` (NIST NVD 2.0 recently-modified CVEs enriched with CVSS base score/severity, CWEs, and references; **credential optional** — unauthenticated works at a lower rate limit, `NVD_API_KEY` raises it), plus `fetch_all_cves` for concurrent fan-out over both. Endpoint + response shapes verified against the OpenCTI CISA-KEV and CVE connectors.
- **Vulnerability-output path** (`vulns.py`): a CVE-keyed record schema + sanitise → validate → dedupe pipeline (`finalize_vulns`) and resilient fan-out (`fan_out_vulns`) mirroring the `ioc_network` path. CVE feeds emit *vulnerability records*, not `ioc_network` indicators; `list_available_feeds` reports them under a separate `cve_sources` key. Cross-source dedup by CVE ID keeps the highest-CVSS copy and folds in KEV exploit-status/due-date enrichment.

### Changed

- **Skill live-feed loop** (Workflow step 2a) in `SKILL.md` and the standalone skill file now cites the CVE tools and folds returned vulnerability records into the Vulnerability/Exposure section; a CVE in KEV escalates urgency. CISA KEV and NVD were already Tier 1 `[MUST]` matrix sources (public government feeds, not operator-authenticated feeds), so input #9's authenticated-feed list and the source matrix are unchanged.

### Other

- **Version bumped to 1.18.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog. `threat-intel-mcp` bumped to **0.13.0**.

---

## [1.17.0] - 2026-07-23

### Added

- **Free public abuse.ch feeds** in `threat-intel-mcp` (v0.12.0): `urlhaus_fetch_iocs` (Tier 9, recent confirmed-malicious URLs) and `threatfox_fetch_iocs` (Tier 9, recent malicious network IOCs — IPs/domains/URLs; hashes excluded). Both are **public CSV feeds requiring no credential**, joining the `fetch_all_iocs` fan-out with their own circuit breakers. Endpoint + CSV column layout verified against the OpenCTI URLhaus/ThreatFox connectors. Workflow step 2a's tool list and input #9's examples updated across `SKILL.md` and both `standalone/` files (both were already Tier 9 `[MUST]` matrix sources).

### Other

- **Version bumped to 1.17.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.16.0] - 2026-07-19

### Added

- **Three SDK-verified live-feed adapters** in `threat-intel-mcp` (v0.11.0), each with endpoint + response shape verified against the vendor's official SDK before building:
  - **ANY.RUN** (`anyrun_fetch_iocs`, Tier 9): TAXII 2.1 STIX feed (`/v1/feeds/taxii2/api1/collections/{ip|domain|url}/objects`); a shared `stix_patterns` helper extracts network IOCs from STIX `[ipv4-addr:value = '…']`-style patterns. action=block.
  - **Intel 471** (`intel471_fetch_iocs`, Tier 2): Titan malware indicators stream (`/v1/indicators/stream`, HTTP Basic email:key, cursor pagination); maps IP + URL indicators (file hashes are ioc_host, skipped). action=block.
  - **Censys** (`censys_fetch_iocs`, Tier 3): Search v2 hosts labelled malware/C2 (`/api/v2/hosts/search?q=labels:malware`, HTTP Basic id:secret); attack-surface observations, so action=alert (Shodan precedent).
  - All join the `fetch_all_iocs` fan-out (now 9 feeds) with their own circuit breakers. Workflow step 2a + input #9 examples updated in `SKILL.md` and both standalone files; no matrix change (all three were already named sources).

### Other

- **Version bumped to 1.16.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.15.0] - 2026-07-19

### Added

- **GreyNoise live-feed adapter** in `threat-intel-mcp` (v0.10.0): new `greynoise_fetch_iocs` tool runs a GNQL `classification:malicious` search against the documented `/v3/gnql` endpoint and returns confirmed-malicious internet scanners/attackers as `ioc_network` IPs (confidence High, action block), joining the `fetch_all_iocs` fan-out with its own circuit breaker. GreyNoise's bare `last_seen` dates are promoted to RFC 3339 datetimes so runtime date-time validation holds; both the nested and flat GNQL record forms are read. Endpoint/response shape verified against the official `pygreynoise` SDK. Workflow step 2a's tool list and input #9's examples updated across `SKILL.md` and both `standalone/` files (GreyNoise was already a Tier 3 `[MUST]` matrix source).

### Other

- **Version bumped to 1.15.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.14.0] - 2026-07-02

### Added

- **Shodan live-feed adapter** in `threat-intel-mcp` (v0.9.0): new `shodan_fetch_iocs` tool queries Shodan's documented search API (`/shodan/host/search`, `category:malware`) for Malware Hunter C2/infrastructure detections and joins the `fetch_all_iocs` fan-out with its own circuit breaker. Detections are crawler heuristics, so IOCs carry `action: alert` and Medium/High confidence; Shodan's naive crawl timestamps are normalised to RFC 3339 so runtime date-time validation holds. Workflow step 2a's tool list and input #9's examples updated across `SKILL.md` and both `standalone/` files (Shodan was already a Tier 3 `[MUST]` matrix source).
- **Credential-safe HTTP logging**: Shodan authenticates via a `key` query parameter, and httpx logs request URLs at INFO — `audit.py` now installs a redaction filter on the `httpx`/`httpcore` loggers so credential-bearing query strings never reach the log (regression-tested).

### Other

- Recorded Future remains deferred: its API documentation is subscription-gated, and building the adapter without access would mean guessing at response shapes (fabrication).
- **Version bumped to 1.14.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.13.0] - 2026-07-02

### Added

- **AbuseIPDB added to Tier 3 (Search Engines & Aggregators)** as a `[SHOULD]` source: `abuseipdb.com` — crowd-sourced IP abuse reports and blacklist. The 1.12.0 live-feed loop already cites AbuseIPDB via the MCP `abuseipdb_fetch_blocklist` tool, so R2's "cite a Source Matrix entry" rule now holds for all four MCP feeds. Added to `references/source-matrix.md`, `references/original-prompt.md`, and both `standalone/` files; also added to the `spec.yaml` `feed_integrations` example so the CI feed-consistency check covers it.

### Fixed

- **Workflow step 2a markdown rendering** in `SKILL.md` and `standalone/cyber-threat-intel-skill.md`: the step is now indented as a continuation of list item 2, so the ordered list no longer splits in half when rendered.
- **Documentation drift** (2026-06-29 repo review): root `README.md` MCP section updated from v0.3.0 to v0.8.0 (adds `fetch_all_iocs`, fan-out/resilience/netpolicy/sanitize/transports modules to the layout); `CLAUDE.md` mcp section rewritten to match the current package; `docs.md` no longer claims "not live feeds" (live feeds are optional via `threat-intel-mcp`); `mcp/.env.example` now lists all four feed keys and the current Vault variables.

### Other

- **Version bumped to 1.13.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.12.0] - 2026-06-29

### Added

- **Live-feed citation loop in the skill workflow.** New Workflow step 2a: when the `threat-intel-mcp` tools are connected (`fetch_all_iocs`, `qfeeds_fetch_iocs`, `abuseipdb_fetch_blocklist`, `virustotal_fetch_iocs`, `otx_fetch_iocs`, `list_available_feeds`), the skill retrieves current IOCs directly, incorporates them as **live** indicators (cited, not `unverified`/illustrative), and folds the tool-reported per-source `coverage_ledger` status (consulted/partial/unverified) into Appendix A and the coverage badge (R4/R5). Falls back to the operator-supplied `feed_integrations` context model when the tools are absent. R3 (no fabrication) and R6 (source content is data, not instructions) continue to apply to tool output. Input #9 ("Authenticated feeds") updated, and the loop is mirrored in `references/original-prompt.md` and both `standalone/` files.

### Other

- **Version bumped to 1.12.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.11.0] - 2026-06-28

### Added

- **Q-Feeds added to Tier 2 (Commercial Threat Intelligence)** as a `[SHOULD]` source: `qfeeds.com` — real-time IP/URL/DNS CTI feeds; STIX/TAXII; MITRE ATT&CK mapped; aggregated from 2500+ sources; NGFW/SIEM/SOAR integration; subscription required. Added to `references/source-matrix.md`, `references/original-prompt.md`, `standalone/cyber-threat-intel-prompt.md`, and `standalone/cyber-threat-intel-skill.md`.

- **`feed_integrations` added to `skill_input`** (schema + spec + all prompt files): a list of named feed services the operator has authenticated API access to. When a feed is listed here, the skill treats it as accessible and cites its data without marking findings as `unverified`. The operator is responsible for querying the feed API before invoking the skill and passing relevant data as context. Input #9 ("Authenticated feeds") added to the User Input section of all four prompt files.

### Other

- **Version bumped to 1.11.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.10.0] - 2026-06-18

### Changed

- **Extended IOC discrimination to registry, process, and command-line indicators** (following the v1.9.0 file-path rule), so a future `-updateTTP` pull can't re-introduce non-discriminating host IOCs into a runtime copy:
  - `Registry_Key` IOCs must not be host-universal forensic/MRU artifacts (RunMRU, UserAssist, RecentDocs, TypedPaths, TypedURLs, MUICache, ComDlg32 OpenSave/LastVisited MRUs, BagMRU/shellbags, WordWheelQuery) — for persistence, name the specific `Registry_Value` and its malware-pointing data instead of the bare key.
  - `Process_Name` IOCs must be a single bare executable (`evil.exe`), never a path, a command line, or a ubiquitous LOLBin (svchost.exe, powershell.exe, rundll32.exe, …) on its own.
  - `Command_Line` IOCs must carry the distinguishing arguments (flags / encoded payload / abuse pattern), not just a bare interpreter name.
  - Guidance added to `SKILL.md` §6, `references/extraction-framework.md`, `references/output-templates.md`, `references/original-prompt.md`, and both `standalone/` files.

### Added

- **Schema guards** in `ioc_host`: `Registry_Key` rejects globs and the MRU/forensic-artifact family; `Process_Name` rejects whitespace, path separators, and globs (misclassification signals); `Command_Line` requires whitespace-separated arguments. New negative fixtures `tests/invalid/ioc_host/registry_runmru.json`, `process_name_is_commandline.json`, and `command_line_bare_process.json`.

### Other

- **Version bumped to 1.10.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.9.0] - 2026-06-16

### Changed

- **File-path IOCs must now be discriminating.** The IOC generator no longer emits broad path globs that match ubiquitous legitimate files (e.g. `…\Downloads\*`, `…\Startup\*.lnk`, browser-profile files like `…\Network\Cookies` / `…\Login Data` / `…\Web Data`, `…\AppData\…\*.log`) — these exist on every host and only produce false CRITICALs in downstream consumers. Guidance added to `SKILL.md` §6, `references/extraction-framework.md` (Host IOCs), `references/output-templates.md`, `references/original-prompt.md`, and both `standalone/` files: prefer a **file hash** or a **named malware binary / specific dropper filename**; use a path only when it is itself specific (a known-bad filename, not a wildcard over a common directory); leave generic "suspicious file in a common location" logic to the consuming tool's heuristics.

### Added

- **Schema guard:** `ioc_host` entries of type `File_Path`/`File_Name` now reject glob wildcards (`*`, `?`) in `value`, and the `delimited_batch_export` `detection_value` description forbids non-discriminating file-path values. New negative fixture `tests/invalid/ioc_host/file_path_glob.json` proves a globbed path IOC is rejected.

### Other

- **Version bumped to 1.9.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.8.0] - 2026-06-15

### Changed

- **Source URLs added next to every named source.** `references/source-matrix.md` now lists a domain for each source that previously had only a name (e.g. Recorded Future → `recordedfuture.com`, Bugcrowd → `bugcrowd.com`, FBI IC3 → `ic3.gov`, ENISA → `enisa.europa.eu`). Domains are short-form (no scheme); prepend `https://` to resolve. Sources that already carried a domain are unchanged.
- Mirrored the same additions into the full source lists in `references/original-prompt.md` and `standalone/cyber-threat-intel-prompt.md` so they stay line-for-line with the matrix. The condensed `standalone/cyber-threat-intel-skill.md` gained domains on its individual MUST entries; its grouped SHOULD lines stay compact by design.
- **Version bumped to 1.8.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.7.0] - 2026-06-14

### Added

- **Free-form IOC/intel search lookback.** The `time_range` input is no longer limited to the four presets (`48h`/`7d`/`30d`/`90d`) — it now accepts **any positive integer + unit**: `h` (hours), `d` (days), `w` (weeks), `mo` (months), e.g. `12h`, `3w`, `6mo`. The schema `time_range` definition changed from an `enum` to the pattern `^[1-9][0-9]*(h|d|w|mo)$` (default still `7d`; the old presets remain valid). The prompt computes the report's `<from>`/`<to>` window from the value.
- Negative fixtures `tests/invalid/time_range/` (`7y`, `weekly`, `0d`) prove the pattern still rejects bad lookbacks.

### Changed

- Updated the `time_range` guidance in `SKILL.md`, `references/original-prompt.md`, both `standalone/` files, `docs.md`, and the `spec.yaml` `user_inputs` question (now a `duration` type with the pattern + unit map and the presets as quick-picks).
- **Version bumped to 1.7.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.6.0] - 2026-06-10

### Added

- **External-consumer integration docs (P1).** New "Using this skill from an external consumer" section in `README.md` and `docs.md` (and `standalone/README.md`): feed the self-contained `standalone/cyber-threat-intel-prompt.md` (not `spec.yaml` alone, and note the legacy `cyber_threat_skill.yaml` was renamed/split in 1.2.0 so that path no longer resolves), how the `delimited_batch_export` rows map to an importer's columns, and that the consumer owns input validation. Closes the failure mode where a consumer auto-discovering the old filename loads nothing and produces empty output.
- **Known-limitations sections** in `README.md` and `standalone/README.md` documenting downstream-importer ingestibility: rows with shell metacharacters / non-ASCII in `detection_value`, or a `detection_method` outside the common six, are dropped by strict importers; `wmi query` indicators (quotes/parens) almost always drop and should be surfaced as behavioral/hunting IOCs; no generator-side sanitization.

### Changed

- **Hardened `delimited_batch_export` row guidance (P2)** so generated rows are actually ingestible by a downstream importer: `SKILL.md` §6, `references/original-prompt.md` §6, both `standalone/` files, `references/output-templates.md`, and the schema now state that `detection_value` must be a **concrete, literal, printable-ASCII, metacharacter-free** indicator (not a `<PLACEHOLDER>` — those belong only in the SPL/KQL starters), and recommend a `detection_method` from the common six. `detection_method` is **kept schema-open (recommended, not enum-locked)** so the export stays tool-agnostic. `spec.yaml` `delimited_batch_export` gains `detection_value_rules` + `detection_method_recommended` + a `known_limitation` note.
- **Version bumped to 1.6.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.5.0] - 2026-06-10

### Fixed

- **Near-empty SPL/KQL output.** The discovery-first SIEM guidance was over-suppressing concrete queries: when the environment's raw `index`/`sourcetype`/table was unknown — almost always for a generic run with no internal data dictionary — the skill defaulted to a discovery-only query or `status: needs_schema` and produced little usable content, leaving the analyst without a starting point.

### Changed

- **Rebalanced SIEM query authoring to "starter-first".** The skill now always emits a **concrete** query built on **normalized schema** (Splunk CIM data models, Sentinel ASIM functions, Defender XDR tables) — which runs **without** a guessed raw index/sourcetype/table — with `<PLACEHOLDERS>` only on genuinely environment-specific bits, **paired** with a coverage-check/discovery query to confirm datasets and adapt. The no-fabrication rule still holds: the raw index/sourcetype/table is the one thing never invented. Requires ≥1 SPL and ≥1 KQL starter when queries are built; default query status is now `needs_validation`, with `needs_schema` reserved for genuinely unknowable coverage.
- **Rewrote `references/siem-queries.md`** with concrete CIM/ASIM/Defender starters per category (process creation, network/firewall, web/proxy, DNS, authentication, file-hash, registry autorun, named-pipe/WMI), coverage-check queries to pair with each, and a **CIM vendor-alignment cheat-sheet** (Zscaler, Palo Alto, Cisco, CrowdStrike, Microsoft Defender, Proofpoint, Cloudflare → CIM data models). Ideas drawn from the public `kj299/siem_fun` query-builder skill pack.
- Updated `SKILL.md` §7, `references/original-prompt.md` §7, both `standalone/` files, `references/output-templates.md`, the schema `hunting_queries` description, and `spec.yaml` `siem_query_rules`. The `enterprise_soc` example's SPL hunting query was upgraded from discovery-only to a concrete CIM `Endpoint.Processes` starter (`status: needs_validation`).
- **Version bumped to 1.5.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.4.0] - 2026-06-10

### Added

- **Wired the optional `delimited_batch_export` output for programmatic consumers.** Threat-intel pipelines that call this skill (via Claude or another model) and feed a downstream importer — a SIEM loader, a batch-audit tool, a TIP — can now rely on a structured export. When `build_iocs_and_queries` is on, the skill emits `delimited_batch_export` rows: `mitre_id`, `name`, `fields` (`detection_method`, `detection_value`, `severity` ∈ CRITICAL/WARNING/INFO, `actor`), `source`, `confidence`. The named columns are a dependable contract; `fields` keeps `additionalProperties` open so other importers can add columns.
- **Safety boundary preserved.** The skill emits **typed JSON only** — the consuming tool delimits, escapes, and validates for its own input path. The generator never pre-formats a delimited string and never applies a shell-metacharacter blocklist on a tool's behalf (anything upstream — a different model, a compromised feed — can violate that contract, so validation lives in the consumer). The export stays tool-agnostic (no downstream project named in the skill).
- Wired into `SKILL.md` §6, `references/original-prompt.md` §6, `references/output-templates.md`, both `standalone/` files, the schema (`delimited_batch_export.fields` gains named typed properties), and `spec.yaml` (`output_templates.delimited_batch_export`). A `delimited_batch_export` example added to the `enterprise_soc` output.
- **Version bumped to 1.4.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.3.0] - 2026-06-08

### Changed

- **Source Coverage Protocol reframed from a hard "enforcement contract" to strong guidance** (R1-R6) across `SKILL.md`, `references/original-prompt.md`, `references/output-templates.md`, `references/extraction-framework.md`, `spec.yaml`, and both `standalone/` distributions:
  - Per-tier source numbers are now **targets, not quotas**. "MANDATORY", "enforcement contract", "output is invalid / must be regenerated", and "rejected" framing is replaced with "strongly recommended" / "should" / "aim for".
  - The **coverage badge is an honest self-report**: a `MINIMAL` badge on a genuinely sparse scope/time range is the correct outcome, not a failure to paper over. When little is retrievable, the report says so plainly (e.g. "little new activity in the last 7 days for X") instead of padding.
  - **R3 (no fabrication) stays the hard line** — plausible-but-fake IOCs poison detection pipelines, so unverifiable findings are marked `unverified`, never invented.
- **Honesty self-report tightened** in the schema `coverage_badge` description and the spec `source_coverage_protocol` / `enforcement_rules` wording.

### Added

- **`build_iocs_and_queries` input (default: `true`)** — toggles whether the report includes generated IOCs and detection/hunting queries in the standard formats (CSV, STIX 2.1, JSON, YARA/Sigma/KQL/SPL/Snort). When `false`, the report stays narrative. Wired into `SKILL.md`, `references/original-prompt.md`, both `standalone/` files, `spec.yaml` (`user_inputs.defaults` + an `initial_questions` entry, `soc_ioc_package.build_toggle`), and the schema (`skill_input.build_iocs_and_queries`).

### Removed

- **The `doze_sec` pipe-delimited integration and its shell-metacharacter blocklist.** Generating unescaped rows engineered to flow straight into a tool's execution path — with the generator acting as that tool's character-blocklist sanitizer — is a fragile design: input validation has to live in the consuming tool's own input handling, because anything upstream (a different model, a compromised feed) can violate the contract. Removed from the schema (`doze_sec_iocs` property under `skill_output`, replaced with a generic optional `delimited_batch_export`), `spec.yaml` (`doze_sec_integration` block, `pipe_delimited` dropped from `soc_ioc_package.ioc_formats` and capabilities), `references/output-templates.md`, `references/original-prompt.md`, and both `standalone/` files. Delimited/batch exports now emit clean structured rows and document their columns, leaving validation to the consumer.
- **Version bumped to 1.3.0** across `spec.yaml`, `schemas/output.schema.json`, every `examples/outputs.json` `skill_version`, and this changelog.

---

## [1.2.0] - 2026-06-06

### Added

- **Source refresh — zero-day tracking sources** (closes the source-robustness review). Added across all four mirror files (`references/source-matrix.md`, `references/original-prompt.md`, `standalone/cyber-threat-intel-prompt.md`, `standalone/cyber-threat-intel-skill.md`):
  - **Tier 1** new "Zero-Day Trackers & Exploit-Timeline Intelligence" subsection: **Zero Day Initiative (ZDI)** advisories (`zerodayinitiative.com/advisories/published`) + machine-readable RSS (`zerodayinitiative.com/rss/published/<year>`) [MUST]; **Zero Day Tracker** (`zerodaytracker.com`) [SHOULD]; **Zero Day Clock** (`zerodayclock.com`, time-to-exploit analytics across 80k+ CVEs) [SHOULD]; **Zero-Day.cz** (`zero-day.cz`) [SHOULD].
  - **Tier 5**: **Project Zero** entry migrated from the deprecated `googleprojectzero.blogspot.com` to `projectzero.google`, and added the **Project Zero "0day In the Wild"** tracker (`projectzero.google/0day.html`) [MUST].
- **Deeper CWE-chaining analysis** (`references/cwe-chaining.md`, schema, spec, extraction-framework, example):
  - **Chain-type taxonomy**: `chain_type` ∈ {`primary_resultant`, `composite`, `named_chain`, `multi_branch`}, with a worked multi-branch chain whose shared-primary break-point collapses all branches.
  - **CWE view provenance**: `cwe_view` cites where a link relationship comes from (CWE-1000 Research Concepts `CanPrecede`/`CanFollow`, CWE-709 Named Chains, CWE-1003 NVD mapping, CWE Top 25 for prioritization).
  - **Per-link detection payload**: `detection_opportunity` + `data_source` on each link, and `detection_telemetry` on detective break-points — wiring chains into the SIEM hunting queries.
  - **Exploit-velocity modeling**: chain-level `time_to_exploit` (`observed_days`, `trend`, `source`) tied to Zero Day Clock TTE data; an `accelerating` trend with moderate/high `ai_assist_factor`, or a contributing CWE class in CISA KEV / Project Zero ITW, escalates priority.
  - **Break-point selection algorithm** (shared-primary → preventive-at-earliest → detective-at-resultant → corrective-backstop) and `terminal_impact` for the chain score's impact dimension.
  - Schema additions are all **additive and optional** (existing outputs stay valid); `spec.yaml` `analysis_modules.vulnerability_chaining.cwe_chaining` and `ai_assisted_attack_analysis.time_to_exploit_tracking` expanded; the red_team example gains a multi-branch and a named-chain illustration.
- **Version bumped to 1.2.0** across `spec.yaml`, `schemas/output.schema.json`, all `examples/outputs.json` `skill_version` fields, and this changelog (CI cross-file version consistency).

### Changed

- **Repository restructured to follow the [Anthropic Agent Skills](https://code.claude.com/docs/en/skills) convention** (closes #12). The skill now lives at `skills/cyber-threat-intel/` with a proper `SKILL.md` entrypoint (YAML frontmatter `name` + `description`), and supporting files split into `references/`, `schemas/`, and `examples/` subdirectories. The skill can now be installed into `~/.claude/skills/cyber-threat-intel/` and invoked as `/cyber-threat-intel`.
- **Renamed/relocated files** (history preserved via `git mv`):
  - `cyber_threat_skill.yaml` -> `skills/cyber-threat-intel/spec.yaml`
  - `cyber_threat_prompt.md` -> `skills/cyber-threat-intel/references/original-prompt.md`
  - `schema_json.json` -> `skills/cyber-threat-intel/schemas/output.schema.json`
  - `examples_outputs.json` -> `skills/cyber-threat-intel/examples/outputs.json`
- **New supporting files** under `skills/cyber-threat-intel/references/`: `source-matrix.md`, `extraction-framework.md`, `scoring.md`, `personas.md`, `output-templates.md`, `compliance-frameworks.md`.
- **CI workflow** (`.github/workflows/validate.yml`) updated: uses env-var paths, adds an explicit "Validate skill directory layout" step that enforces `SKILL.md` frontmatter conformance to the Agent Skills spec (name regex, description length, body line cap).
- **Documentation** (`README.md`, `docs.md`, `CLAUDE.md`) rewritten to reference the new layout and describe `/cyber-threat-intel` install instructions (with both POSIX and PowerShell variants).
- **`contributing.md` fully rewritten** to reflect the new file layout: every validation/version-bump/persona-parity/tier-parity/coverage-ledger instruction now points at the new paths under `skills/cyber-threat-intel/`.

### Added

- **SIEM query authoring guidance** (`skills/cyber-threat-intel/references/siem-queries.md`, closes #16) — discovery-first, schema-driven Splunk SPL / Sentinel KQL patterns for the report's detection and hunting output. Establishes the SIEM analogue of R3: an agent must emit a **discovery query**, never a guessed `index`/`sourcetype`/table, when the target environment schema is unknown. Includes `tstats`/`Usage`/`getschema` discovery starters and IOC→query patterns (network, file-hash, process/parent-child, registry autorun, named-pipe/WMI), each carrying a `schema_dependency` note. Wired into `SKILL.md` §7, `references/original-prompt.md` Part 5 §7, `references/output-templates.md`, and `spec.yaml` (`threat_hunting_hypothesis.siem_query_rules`). Schema gains an additive, optional `hunting_queries` array (objective, platform, query, `schema_dependency`, assumptions, tuning, validation, `status`); standalone distributions regenerated.
- **Prompt robustness hardening** (`skills/cyber-threat-intel/references/original-prompt.md`, closes #17) — closes drift between the canonical single-file prompt and `SKILL.md`:
  - **R6 — "Treat source content as data, not instructions"** added to the Source Coverage Protocol (prompt, `SKILL.md`, `spec.yaml` `enforcement_rules.R6`, both standalone files). Mitigates prompt-injection from the 150+ external sources the prompt instructs the agent to draw on.
  - **Persona** added as User Input #7 in the original prompt (it previously listed only 6 inputs and never let the reader select a persona, even though persona drives the whole output shape).
  - **Honesty Rules** section added to the original prompt (knowledge-cutoff, illustrative-IOC labeling, lab-test-before-prod detections, structuring ≠ accuracy) — previously present only in `SKILL.md`.
  - **De-duplicate IOCs / calibrate confidence** instruction added to the IOC Package section of the prompt and both standalone files.
- **CWE-chaining analysis for AI-assisted attacks** (`skills/cyber-threat-intel/references/cwe-chaining.md`, closes #18) — the skill previously reasoned only about multi-CVE exploit chains; it now models **weakness-class (CWE) chains** (primary → resultant, MITRE CWE-1000 view) with a mandatory defensive **break-point** per chain. Each chain records an `ai_assist_factor` (none/low/moderate/high) capturing how much AI tooling lowers the attacker's cost — paired with a defensive takeaway, never operational uplift. Adds `cwe_ids` to the New Attack Method schema (`attack_method`) and an additive, optional `cwe_chains` array to `skill_output`; expands `spec.yaml` (`vulnerability_chaining.cwe_chaining`, new `ai_assisted_attack_analysis` module); wires a Part 3.E subsection into `references/original-prompt.md`, a §D entry into `references/extraction-framework.md`, and workflow guidance into `SKILL.md`; adds an illustrative SSRF→credential CWE chain to the red_team example. Standalone distributions regenerated.
- **`.gitattributes`** at repo root enforcing LF line endings for text files (`.md`, `.yaml`, `.yml`, `.json`, `.py`, `LICENSE`, `.gitignore`). Required so the CI layout check (which parses `SKILL.md` frontmatter with `text.startswith('---\n')`) does not break on Linux runners when contributors commit from Windows with `core.autocrlf=true`.

### Fixed

- **Doc consistency after the SIEM/CWE/R6 work**: the `README.md` directory tree and `CLAUDE.md` reference list now enumerate the two new reference files (`references/siem-queries.md`, `references/cwe-chaining.md`), the README tree now also shows the `standalone/` distributions, and `contributing.md` now says "source coverage rules (R1-R6)" (an R6 was added) and reminds contributors to update both `standalone/` files.

---

## [1.1.0] - 2026-04-26

### Added

- **Source Coverage Protocol** in `cyber_threat_prompt.md` — enforcement contract (rules R1–R5) that compels agents to actually search across source tiers rather than producing superficial output from general knowledge
- Per-tier source minimums (Tier 1: ≥5, Tier 2: ≥4, Tier 8: ≥3, etc.) with a total of 25 MUST-sources required for `FULL` coverage
- **Coverage badge** in every report header: `FULL` / `PARTIAL` / `MINIMAL`
- **Source Coverage Ledger** in Appendix A of every report — tracks consulted vs skipped sources with reasons
- Mandatory `source:` field on every IOC, TTP, threat actor profile, and detection rule
- No-fabrication rule: unverifiable findings marked `status: unverified (source inaccessible)`, never invented
- `source_coverage_protocol` section in `cyber_threat_skill.yaml` formalizing R1–R5
- **Quick Start section** in `README.md` — 3-step onboarding (choose AI → copy prompt → paste & ask) so new users can produce a first report in under 2 minutes
- **Schema Validation Examples** in `docs.md` — valid-output shape reference plus a table of common validation errors with causes and fixes (sourced from actual `schema_json.json` enums)
- **Contributor guidance** in `contributing.md` — `Testing Your Changes Locally` (YAML/JSON validation commands), `Commit Message Examples` (good vs bad), and `What Makes a Good Contribution` (accepted vs rejected change types)
- `docs/releases/` folder containing the v1.1.0 review and release-readiness records

### Changed

- **Token optimization**: `cyber_threat_prompt.md` reduced ~54% (738 → 339 lines) by collapsing verbose source descriptions to single-line entries, removing blank template rows from IOC tables, consolidating six output-format code blocks into one structured spec, and removing three duplicate "begin immediately" instructions — all original source entries preserved
- **Token optimization**: `cyber_threat_skill.yaml` reduced ~67% (1143 → 372 lines) by deduplicating the source list (now single-source-of-truth in `cyber_threat_prompt.md`), tightening persona definitions, and trimming aspirational sections
- Source Matrix entries now tagged `[MUST]` or `[SHOULD]` so agents can prioritize quota-bearing sources
- **Limitations section** in `README.md` expanded with explicit warnings: AI knowledge cutoff (no last-24/48h threats), illustrative IOCs (validate before deploying), no live feeds (Matrix entries are training-data references, not API integrations)
- **Source-tier table** in `docs.md` now annotated as orientation-only, with `cyber_threat_prompt.md` called out as the canonical source matrix used for R1–R5 enforcement (prevents future duplication drift)
- **Documentation file casing**: renamed `CHANGELOG.md` → `changelog.md` and `DOCS.md` → `docs.md` so all project documentation files use lowercase per the CLAUDE.md convention. `README.md`, `LICENSE`, and `CLAUDE.md` retain uppercase (GitHub-special / Claude Code auto-loaded)

### Fixed

- Documentation link to `contributing.md` in `README.md` (`[CONTRIBUTING.md](CONTRIBUTING.md)` was broken on case-sensitive filesystems since the actual file is lowercase)
- Repository directory tree in `README.md` now reflects the actual filenames (all project docs lowercase: `changelog.md`, `contributing.md`, `docs.md`)

### Removed

- Duplicated source lists between `cyber_threat_prompt.md` and `cyber_threat_skill.yaml` (single source of truth is now the prompt)
- `nlp_query_engine` section (aspirational, not actionable in prompt form)
- `real_time_feeds` with Telegram/Discord/Twitter handles (rot-prone, unenforceable)
- `geopolitical_intelligence` and `economic_indicators` sections (unused)

---

## [1.0.0] - 2026-03-30

### Added

- Comprehensive threat intelligence prompt template with intake questions
- 150+ intelligence sources organized into 9 tiers
- Structured extraction frameworks for IOCs, TTPs, and attack methods
- MITRE ATT&CK mapping across all 14 tactics
- 6 adaptive personas (Enterprise SOC, Executive, SMB, Researcher, Individual, Red Team)
- Multi-dimensional threat scoring model (Exploitability, Impact, Relevance, Urgency)
- Skill specification in YAML format with persona profiles and analysis workflows
- JSON Schema for validating structured output
- Example outputs for all 6 personas
- Output templates: Executive Brief, Technical Report, IOC Package, Personal Guide, Checklist
- Detection rule templates for YARA, Sigma, Snort, KQL, SPL
- IOC format support for STIX 2.1, OpenIOC, CSV, JSON, MISP
- Compliance mapping for NIST CSF 2.0, ISO 27001, PCI DSS 4.0, DORA, SOX, GDPR
- Threat scenario modeling templates
- Business risk analysis framework for new initiatives
