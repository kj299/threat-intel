# Output Templates

The persona-specific section lists. The Source Coverage Ledger (Appendix A, R5) is mandatory in every template.

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
4. Detection Rules (CSV, STIX 2.1, pipe-delimited, YARA, Sigma, Snort, KQL, SPL)
5. Hunting Queries (KQL, SPL)
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

## doze_sec Pipe-Delimited Integration

Schema: `MITRE_ID|Name|Detection_Method|Detection_Value|Severity|Actor`

Detection methods (exact lowercase strings, with spaces, not underscores): `registry key`, `event id`, `process name`, `file path`, `named pipe`, `wmi query`.

Severity (uppercase only): `CRITICAL`, `WARNING`, `INFO`.

Rules:
- New TTPs only (not in any provided existing IOC list).
- One indicator per line. No header row, no preamble, no markdown, no commentary.
- `Detection_Method` MUST exactly match one of the listed values.
- `Severity` MUST be one of the three uppercase values.
- `Detection_Value` is ASCII-only, ≤260 chars, must not contain any of: `"` `'` `` ` `` `$` `;` `|` `&` `<` `>` `(` `)` `{` `}` `^`.
- Exactly 5 pipe separators per row (6 fields total).

Example rows that pass the sanitizer:
```
T1547.001|Boot Autostart Execution|registry key|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MalService|CRITICAL|APT29
T1059.001|PowerShell Script Block Logging|event id|4104|WARNING|LockBit
T1055.012|Process Hollowing|process name|svchost_update.exe|CRITICAL|BlackCat
T1021.002|SMB Admin Share|named pipe|\\.\pipe\atsvc|WARNING|APT29
T1047|WMI Process Creation|wmi query|SELECT Name FROM Win32_Process WHERE Name=cmd.exe|INFO|Unknown
```

## Appendix A: Source Coverage Ledger (mandatory in every report)

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

**Total MUST-minimum sources consulted:** `<N>` / 25
**Coverage badge:** `FULL` (≥25) | `PARTIAL` (13–24) | `MINIMAL` (<13)
**Fabrication check:** confirm no IOC, CVE, hash, or actor attribution was invented. Any `status: unverified` items are listed below with reason.
