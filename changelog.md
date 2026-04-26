# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
