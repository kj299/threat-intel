# Extraction Framework

Field schemas for every emitted finding. One row per item that actually exists — do not emit blank template rows.

## A. New Attack Method (one row per distinct technique)

`technique_name | mitre_id | tactic | cves | cwes | cvss | exploit_maturity (none/poc/weaponized/itw) | first_observed | source | sophistication | targeted_sectors | targeted_tech | description | business_impact`

`cwes` is the list of underlying weakness classes (e.g. `CWE-89`, `CWE-502`) the technique exploits — the bridge to CWE-chain analysis (§D).

## B. Indicators of Compromise

Every IOC row should include `source` and `confidence (high/med/low)`. If an indicator can't be attributed to a real source, don't emit it as confirmed.

**Network IOCs** — `type (ipv4/ipv6/domain/url/cert_hash/ja3/ja3s/jarm/user_agent/cidr) | value | confidence | source | first_seen | last_seen | threat | mitre_id | action (block/alert/hunt) | tlp`

**Host IOCs** — `type (sha256/sha1/md5/ssdeep/imphash/filename/path/registry_key/registry_value/scheduled_task/service/mutex/named_pipe/process/cmdline/wmi_sub) | value | confidence | source | threat | platform | action | detection_source`

For `filename`/`path` IOCs, emit only **discriminating** values: a specific known-bad filename or full path to a named malware binary/dropper. Do **not** emit globs or paths to files that exist on essentially every host — `…\Downloads\*`, `…\Startup\*.lnk`, browser-profile files (`…\Network\Cookies`, `…\Login Data`, `…\Web Data`), `…\AppData\…\*.log`, etc. — they only generate false positives downstream. Prefer a **hash** over a path when one is available, and leave generic "suspicious file in a common location" logic to the consuming tool's heuristics.

The same discrimination and correct-classification rules apply to the other host types:

- `registry_key` — never emit host-universal forensic/MRU artifacts (RunMRU, UserAssist, RecentDocs, TypedPaths, TypedURLs, MUICache, ComDlg32 OpenSave/LastVisited MRU, BagMRU/shellbags, WordWheelQuery): they exist on every Windows box. For persistence, emit a `registry_value` IOC naming the specific value and its malware-pointing data, not the bare autorun key.
- `process` — a single bare executable name (`evil.exe`), not a path, not a command line, and not a ubiquitous LOLBin (`svchost.exe`, `explorer.exe`, `powershell.exe`, `cmd.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe`) on its own — the discriminating signal there is the command line or a hash.
- `cmdline` — must carry the distinguishing arguments (the flags / encoded payload / abuse pattern that make the invocation malicious); a bare interpreter name with no arguments is a misclassified `process`, not a command line.

**Email IOCs** — `type (sender/sender_domain/reply_to/subject_pattern/attachment_name/attachment_hash/x_orig_ip) | value | confidence | source | campaign | action`

**Behavioral IOCs** — `behavior | data_source | detection_logic | mitre_id | threshold | source`

## C. TTP Mapping (MITRE ATT&CK)

One row per technique observed. `tactic | technique_id | technique_name | sub_technique | procedure | detection_method | data_sources | source`

Tactics to cover if present: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact.

## D. Pattern Analysis

- Cross-source correlation: threats appearing in ≥2 sources
- Technique evolution: modifications of known TTPs
- Tool development: new malware families or frameworks
- Infrastructure shifts: C2, hosting, ASN changes
- Exploit chains: multi-CVE combinations
- **CWE chains: weakness-class sequences** (primary → resultant) — see [cwe-chaining.md](cwe-chaining.md). Emit one `cwe_chain` per distinct chain: `chain_id | name | chain_type (primary_resultant/composite/named_chain/multi_branch) | cwe_view (CWE-1000/CWE-709/CWE-1003) | links[] (cwe_id, role, mitre_id, tactic, evidence, detection_opportunity, data_source, source) | enabling_conditions | ai_assist_factor (none/low/moderate/high) | time_to_exploit (observed_days, trend accelerating/stable/decelerating, source) | break_points[] (at_link, control, control_type, rationale, mapped_mitigation, detection_telemetry) | terminal_impact | score | priority | confidence | source`. Every chain MUST carry at least one `break_point` (the defensive deliverable); `ai_assist_factor` records how much AI tooling lowers the chain's cost for an attacker and `time_to_exploit.trend` quantifies it — an `accelerating` trend with moderate/high `ai_assist_factor` escalates priority. In a `multi_branch` chain, the break-point at the shared primary collapses every branch.
- Living-off-the-land: new abuse of legitimate tools

## E. Predictive IOCs

For each predicted indicator, state the basis (which observed pattern generated it) and mark `confidence: low` unless evidence supports higher.

- DGA domain patterns
- ASN / hosting provider affinities
- File naming conventions
- Expected behavioral signatures
- C2 protocol characteristics

## F. Threat Actor Updates

`actor | type (apt/criminal/hacktivist) | motivation | new_ttps | new_infra | target_changes | confidence | source`

## G. Exploitation Forecast

`cve | days_since_disclosure | exploit_maturity | mass_exploitation (yes/no, GreyNoise) | org_exposure | priority | source`

## H. Business Risk (only if new business context provided)

**Exposure Delta** — `factor (attack_surface / actor_interest / data_value / regulatory / third_party / tech_stack / customer_profile) | current | post_expansion | delta | relevant_threats | source`

**Scenario Modeling** — for each major threat: scenario_id, actor_profile, initial_access, full_chain (recon→weaponize→deliver→exploit→install→c2→actions), mitre_map, likelihood (1–5), impact (financial $ / operational / reputational / regulatory), existing_controls, control_gaps, detection_opportunities, mitigations, source.

## I. Internal Document Integration (if an internal doc is provided)

1. Correlate external intel with internal findings.
2. Identify detection gaps (external threat present, no internal coverage).
3. Validate internal assessments against external intelligence.
4. Map internal incidents to external actor TTPs; update IOCs and recommendations accordingly.
