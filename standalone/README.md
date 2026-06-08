# Standalone Artifacts

Two self-contained files. No sibling references, no `spec.yaml`, no schema files, no examples directory required. Either can be copied out of this repo and used independently of the rest of the project.

## Files

- [`cyber-threat-intel-prompt.md`](cyber-threat-intel-prompt.md) — single-file **prompt**. Paste into any capable LLM chat (Claude, GPT, Gemini, Llama, etc.) as the system or first user message.
- [`cyber-threat-intel-skill.md`](cyber-threat-intel-skill.md) — single-file **Anthropic Agent Skill** (`SKILL.md` with YAML frontmatter). Drop into any Agent Skills consumer (Claude Code, Claude API skills, or compatible runtimes). Rename to `SKILL.md` and place at `skills/cyber-threat-intel/SKILL.md` in the target project.

## What's inlined

Both files embed everything previously split across `skills/cyber-threat-intel/references/` and `spec.yaml`:

- The R1–R6 Source Coverage Protocol (strong guidance, not a hard gate)
- The full 9-tier Source Matrix (the prompt has the long-form list; the skill has a tighter version with the same MUST sources and SHOULD groups)
- IOC / TTP / actor / forecast / business-risk extraction schemas
- Threat scoring formula and P1–P5 priority mapping
- All 6 personas and their section lists
- Compliance framework mappings (NIST CSF, ISO 27001, PCI DSS, DORA, NYDFS, SOX, GDPR)
- Output sections, the optional `build_iocs_and_queries` toggle, and the Appendix A Source Coverage Ledger template

## What's intentionally not included

- **No JSON Schema.** The structured `output.schema.json` in the main skill is for CI validation. A standalone prompt or skill running in a chat doesn't need it; the field shapes are described inline.
- **No examples file.** The main skill's `examples/outputs.json` is for schema validation in CI, not few-shot prompting.
- **No `spec.yaml`.** All persona profiles, scoring weights, and tier minimums that lived there are inlined as tables.

## Versioning

These files are regenerated from the canonical sources in [`../skills/cyber-threat-intel/`](../skills/cyber-threat-intel/) whenever the protocol, source matrix, scoring, or personas change. They are not the source of truth — they're flattened distributions.
