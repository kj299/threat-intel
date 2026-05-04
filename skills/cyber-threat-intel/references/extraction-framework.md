# Extraction Framework

Field schemas for every emitted finding. One row per item that actually exists — do not emit blank template rows.

## A. New Attack Method (one row per distinct technique)

`technique_name | mitre_id | tactic | cves | cvss | exploit_maturity (none/poc/weaponized/itw) | first_observed | source | sophistication | targeted_sectors | targeted_tech | description | business_impact`

## B. Indicators of Compromise

Every IOC row MUST include `source` and `confidence (high/med/low)`.

**Network IOCs** — `type (ipv4/ipv6/domain/url/cert_hash/ja3/ja3s/jarm/user_agent/cidr) | value | confidence | source | first_seen | last_seen | threat | mitre_id | action (block/alert/hunt) | tlp`

**Host IOCs** — `type (sha256/sha1/md5/ssdeep/imphash/filename/path/registry_key/registry_value/scheduled_task/service/mutex/named_pipe/process/cmdline/wmi_sub) | value | confidence | source | threat | platform | action | detection_source`

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
