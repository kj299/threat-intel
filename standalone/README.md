# Standalone Artifacts

Two self-contained files. No sibling references, no `spec.yaml`, no schema files, no examples directory required. Either can be copied out of this repo and used independently of the rest of the project.

## Files

- [`cyber-threat-intel-prompt.md`](cyber-threat-intel-prompt.md) — single-file **prompt**. Paste into any capable LLM chat (Claude, GPT, Gemini, Llama, etc.) as the system or first user message.
- [`cyber-threat-intel-skill.md`](cyber-threat-intel-skill.md) — single-file **Anthropic Agent Skill** (`SKILL.md` with YAML frontmatter). Drop into any Agent Skills consumer (Claude Code, Claude API skills, or compatible runtimes). Rename to `SKILL.md` and place at `skills/cyber-threat-intel/SKILL.md` in the target project.

## What's inlined

Both files embed everything previously split across `skills/cyber-threat-intel/references/` and `spec.yaml`:

- The R1–R6 Source Coverage Protocol (strong guidance, not a hard gate)
- The full 9-tier Source Matrix (the prompt has the long-form list; the skill has a tighter version with the same preferred `[MUST]` sources and optional `[SHOULD]` sources)
- IOC / TTP / actor / forecast / business-risk extraction schemas
- Threat scoring formula and P1–P5 priority mapping
- All 6 personas and their section lists
- Compliance framework mappings (NIST CSF, ISO 27001, PCI DSS, DORA, NYDFS, SOX, GDPR)
- Output sections, the optional `build_iocs_and_queries` toggle, and the Appendix A Source Coverage Ledger template

## What's intentionally not included

- **No JSON Schema.** The structured `output.schema.json` in the main skill is for CI validation. A standalone prompt or skill running in a chat doesn't need it; the field shapes are described inline.
- **No examples file.** The main skill's `examples/outputs.json` is for schema validation in CI, not few-shot prompting.
- **No `spec.yaml`.** All persona profiles, scoring weights, and per-tier coverage targets that lived there are inlined as tables.

## Using these with an external consumer

`cyber-threat-intel-prompt.md` is the file to feed a programmatic consumer (a CLI like Claude Code, an OpenAI pipeline, or a SIEM/batch-audit importer). It is self-contained — point your tool at it directly. The legacy single-file `cyber_threat_skill.yaml` was split/renamed in the main skill's 1.2.0 restructure and no longer exists, so a consumer auto-discovering that name will load nothing.

## Known limitations

- **`delimited_batch_export` ingestibility.** A strict downstream importer rejects rows whose `detection_value` contains shell metacharacters (quotes, backtick, `$ ; | & < > ( ) { } ^`) or non-ASCII characters, or whose `detection_method` is outside the common six (`registry key`, `event id`, `process name`, `file path`, `named pipe`, `wmi query`). The prompt is guided to emit concrete, ASCII, metacharacter-free literals, but any row that legitimately needs a blocked character will be dropped by such a consumer — by design (the consumer owns sanitization).
- **`wmi query` indicators** inherently contain quotes/parentheses and are therefore usually dropped by metacharacter-filtering importers; surface them as behavioral/hunting IOCs instead of batch-export rows.
- **No generator-side sanitization.** These prompts emit raw typed values and never escape on a tool's behalf — a consumer that ingests the output without its own input validation owns the injection risk.

## Versioning

These files are regenerated from the canonical sources in [`../skills/cyber-threat-intel/`](../skills/cyber-threat-intel/) whenever the protocol, source matrix, scoring, or personas change. They are not the source of truth — they're flattened distributions.
