# Output Templates

The persona-specific section lists. The Source Coverage Ledger (Appendix A, R5) belongs in every template.

The `build_iocs_and_queries` input (default: on) applies to **all** templates below, not just the SOC IOC Package. When it is off, drop each template's generated-artifact sections — IOC packages/summaries, detection rules, and hunting queries — and keep that template's remaining narrative and advisory sections; always keep the Source Coverage Ledger (Appendix A). Concretely: the SOC IOC Package keeps Header, Deployment Priority, Response Playbooks, False-Positive Guidance, and the Ledger; the Technical Report drops IOC Summary and Detection Recommendations; the Executive Brief and Personal Security Guide have no generated-artifact sections, so they are unaffected.

## Executive Brief (max 2 pages)

1. Threat Alert Banner
2. Executive Summary
3. Risk Dashboard
4. Key Metrics
5. Investment Recommendations
6. Appendix A: Source Coverage Ledger

## Technical Report (Enterprise SOC default)

1. Header with Coverage Badge
2. Executive Summary
3. Threat Landscape
4. Vulnerability Analysis
5. IOC Summary
6. TTP Mapping (MITRE ATT&CK)
7. Threat Actor Profiles
8. Detection Recommendations
9. Mitigation Priorities
10. Technical Appendix
11. Appendix A: Source Coverage Ledger

## SOC IOC Package

1. Header with Coverage Badge
2. Deployment Priority
3. High-Confidence IOCs
4. Detection Rules (CSV, STIX 2.1, JSON, YARA, Sigma, Snort, KQL, SPL)
5. Hunting Queries (KQL, SPL) — author per [siem-queries.md](siem-queries.md): discovery-first, schema-driven, no invented `index`/`sourcetype`/table; each query carries `schema_dependency` + tuning + a validation step
6. Response Playbooks
7. False-Positive Guidance
8. Appendix A: Source Coverage Ledger

## Personal Security Guide (friendly tone)

1. Current Threats Affecting You
2. Simple Action Checklist
3. Why This Matters
4. Step-by-Step Guides
5. Resources for Learning
6. Appendix A: Source Coverage Ledger

## Delimited / batch exports for downstream tools

For programmatic consumption (a SIEM importer, a batch-audit tool, a TIP — including pipelines that call this skill via Claude or another model), populate the structured `delimited_batch_export` array: one row per new TTP with `mitre_id`, `name`, `fields` (`detection_method`, `detection_value`, `severity` ∈ CRITICAL/WARNING/INFO, `actor`), `source`, and `confidence`. The named columns are a dependable contract; a consumer may add extra columns under `fields`.

Emit **typed values only** — the consuming tool does the delimiting, escaping, and validation for its own input path. Do not pre-format a delimited string, do not hand-craft data engineered to flow straight into another tool's execution path, and do not rely on the generator to enforce a character blocklist on the tool's behalf: anything upstream (a different model, a compromised feed) can violate that contract, so the validation has to live in the consumer's own input handling.

## Appendix A: Source Coverage Ledger (include in every report)

| Tier | Required Min | Consulted | Skipped (with reason) | Met? |
|------|--------------|-----------|------------------------|------|
| 1    | 5            | `<comma-sep list>` | `<source: reason>`     | yes/no |
| 2    | 4            |           |                        | yes/no |
| 3    | 3            |           |                        | yes/no |
| 4    | 2            |           |                        | yes/no |
| 5    | 2            |           |                        | yes/no |
| 6    | 3            |           |                        | yes/no |
| 7    | best-effort  |           |                        | n/a    |
| 8    | 3            |           |                        | yes/no |
| 9    | 3            |           |                        | yes/no |

**Total preferred-source targets consulted:** `<N>` / ≈25
**Coverage badge (honest self-report):** `FULL` (≈25+) | `PARTIAL` (13–24) | `MINIMAL` (<13). A `MINIMAL` badge on a genuinely sparse scope/time range is the correct outcome, not a failure.
**Fabrication check:** confirm no IOC, CVE, hash, or actor attribution was invented. Any `status: unverified` items are listed below with reason. If little was retrievable for the requested scope and time range, state that plainly here.
