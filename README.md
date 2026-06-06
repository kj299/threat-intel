# Cyber Threat Intelligence Skill

An [Anthropic Agent Skill](https://code.claude.com/docs/en/skills) that guides Claude Code (and other Skill-aware AI assistants) to produce professional-grade cyber threat intelligence reports with enforced source coverage, mandatory IOC citations, and a strict no-fabrication rule.

The legacy "paste this prompt into ChatGPT" workflow is also still supported -- the long-form prompt is preserved at [skills/cyber-threat-intel/references/original-prompt.md](skills/cyber-threat-intel/references/original-prompt.md).

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

- A **Coverage badge** (`FULL` / `PARTIAL` / `MINIMAL`) in the header indicating how many mandatory source tiers were actually consulted.
- A **Source Coverage Ledger** in Appendix A listing which sources were queried per tier, which were skipped, and why.
- A prioritized threat list with MITRE ATT&CK mappings -- every item carries a `source` field (no unsourced claims).
- IOCs (IPs, domains, hashes, behavioral indicators) formatted for SIEM/EDR import.
- Detection rules in YARA, Sigma, KQL, SPL, and Snort/Suricata formats.
- CSV, STIX 2.1, and pipe-delimited (doze_sec) exports.
- Recommended actions matrix with owners, timelines, and success metrics.

Items that cannot be verified are marked `unverified (source inaccessible)` rather than fabricated.

---

## Repository Layout

```
threat-intel/
+-- README.md                                         # this file
+-- LICENSE
+-- CLAUDE.md                                         # AI-assistant project context
+-- docs.md                                           # human-readable spec documentation
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
        |   +-- siem-queries.md                       # SPL/KQL authoring: discovery-first, schema-driven
        |   +-- compliance-frameworks.md              # NIST/ISO/PCI/DORA/NYDFS/SOX/GDPR
        |   +-- original-prompt.md                    # long-form prompt for non-Claude assistants
        +-- schemas/
        |   +-- output.schema.json                    # JSON Schema for output validation
        +-- examples/
            +-- outputs.json                          # one example per persona
+-- standalone/                                      # flattened single-file distributions
    +-- cyber-threat-intel-prompt.md                 # self-contained prompt (any LLM)
    +-- cyber-threat-intel-skill.md                  # self-contained Agent Skill
```

---

## Source Coverage Protocol (R1-R5)

The skill enforces five rules to prevent shallow output drawn from general knowledge:

- **R1 -- Per-tier minimums.** Each tier has a minimum: T1 >=5, T2 >=4, T3 >=3, T4 >=2, T5 >=2, T6 >=3, T7 best-effort, T8 >=3, T9 >=3. Total MUST minimum: 25 sources.
- **R2 -- Source citation on every claim.** Every IOC, TTP, threat actor profile, and detection rule carries a `source:` field. `source: unknown` / `general knowledge` / `n/a` is rejected.
- **R3 -- No fabrication.** Inaccessible sources are marked `status: unverified (source inaccessible)` -- never substituted with invented IPs, hashes, or CVEs.
- **R4 -- Coverage badge.** Header is stamped `COVERAGE: FULL` (>=25), `PARTIAL` (13-24), or `MINIMAL` (<13).
- **R5 -- Coverage Ledger.** Appendix A is the per-tier ledger with consulted/skipped/met columns.

Full source matrix (with MUST/SHOULD tags) is in [skills/cyber-threat-intel/references/source-matrix.md](skills/cyber-threat-intel/references/source-matrix.md).

---

## Personas

The skill adapts output style and depth based on who is asking:

| Persona | Output Style | Key Features |
|---------|--------------|--------------|
| Enterprise SOC | Technical depth | IOCs, detection rules, MITRE ATT&CK mapping |
| Executive | Business focus | Risk dashboards, financial impact, peer comparison |
| SMB Security | Actionable checklists | Budget-conscious, step-by-step guides |
| Researcher | Learning-focused | Methodology explanations, lab exercises |
| Individual | Jargon-free | Family safety, personal device protection |
| Red Team | Exploit-focused | Attack chains, tool recommendations |

Persona definitions: [skills/cyber-threat-intel/references/personas.md](skills/cyber-threat-intel/references/personas.md). Structured config: [skills/cyber-threat-intel/spec.yaml](skills/cyber-threat-intel/spec.yaml) under `persona_profiles`.

---

## Threat Scoring

```
Score = (Exploitability x 0.25) + (Impact x 0.25) + (Relevance x 0.30) + (Urgency x 0.20)
```

| Priority | Score | Suggested Response Time |
|----------|-------|-------------------------|
| P1-CRITICAL | 90-100 | 0-4 hours |
| P2-HIGH | 75-89 | 4-24 hours |
| P3-MEDIUM | 50-74 | 1-7 days |
| P4-LOW | 25-49 | 7-30 days |
| P5-INFO | 0-24 | Awareness only |

Full breakdown: [skills/cyber-threat-intel/references/scoring.md](skills/cyber-threat-intel/references/scoring.md).

---

## Output Validation

```bash
pip install jsonschema rfc3339-validator
jsonschema -i your-output.json skills/cyber-threat-intel/schemas/output.schema.json
```

CI runs the same validation plus version/persona/tier parity checks across `spec.yaml`, the schema, the examples, and the changelog. See [.github/workflows/validate.yml](.github/workflows/validate.yml).

---

## Limitations

- **Knowledge cutoff.** Output reflects the model's training data. For breaking threats (last 24-48 hours), consult professional threat intelligence services -- this skill cannot surface intelligence newer than the model behind it.
- **Illustrative IOCs.** Generated IOCs (IPs, hashes, domains) are examples drawn from known patterns in training data, not real-time indicators. Validate every IOC against trusted feeds before deploying to detection or blocking systems.
- **No live feeds.** This skill does not integrate with live threat feeds. Sources listed in the Matrix are references the AI draws from based on training data, not API integrations.
- This skill structures AI output; it does not guarantee accuracy. Always verify critical findings.
- Detection rules should be tested in a lab environment before production deployment.
- This is not a replacement for professional threat intelligence services or incident response.

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
