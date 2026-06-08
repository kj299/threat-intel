# Output Templates

The persona-specific section lists. The Source Coverage Ledger (Appendix A, R5) belongs in every template.

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

If a consumer (a SIEM importer, a batch audit tool, a TIP) ingests a specific delimited format, build clean structured rows in that shape and document the columns — but **leave input validation and sanitization to the consuming tool**. Do not hand-craft data engineered to flow straight into another tool's execution path, and do not rely on the generator to enforce a character blocklist on the tool's behalf: anything upstream (a different model, a compromised feed) can violate that contract, so the validation has to live in the consumer's own input handling. Emit each indicator with its `source` and `confidence`, the same as every other IOC.

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
