# CLAUDE.md

## Project Overview

This is a cyber threat intelligence skill for Claude Code (and other Anthropic Agent Skills consumers) -- a structured prompt skill, persona specification, and output schema for generating threat intel reports.

This is NOT a product, platform, or service. It is a packaged Anthropic Agent Skill.

## Layout

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
- `.github/workflows/validate.yml` -- CI: layout, JSON/YAML syntax, schema conformance, version parity, persona parity, coverage-ledger consistency, tier parity, negative fixtures

Repo-root `README.md`, `LICENSE`, `CLAUDE.md`, `changelog.md`, `contributing.md`, `docs.md` stay at the root.

## Conventions

- Skill follows Anthropic Agent Skills spec: `SKILL.md` with YAML frontmatter (`name`, `description`), `name` is lowercase-hyphen and matches directory name, body under 500 lines, supporting files in `references/` / `schemas/` / `examples/` referenced from `SKILL.md`.
- File naming inside the skill: kebab-case (`source-matrix.md`, `output.schema.json`).
- Repo root: lowercase for project files, UPPERCASE for standard GitHub files (README, LICENSE, etc.).
- YAML: 2-space indent, snake_case keys.
- All claims about capabilities should be honest about what prompt engineering can and cannot do.
- No fictional infrastructure (fake domains, fake email addresses, fake pricing).
