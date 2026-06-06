# CWE Chaining (AI-Assisted Attacks)

Threat intel that tracks only single CVEs misses how real intrusions compose. Adversaries chain **weakness classes** (CWE) — an input-validation gap feeds an injection, which yields code execution, which a deserialization flaw escalates. AI assistance is lowering the cost of *finding and ordering* those links, so the report should reason about chains and, more importantly, about where to **break** them.

This reference is defensive. It captures CWE chains as analysis — enabling conditions, the cheapest break-point, the detection opportunity — not as an exploitation recipe. No step-by-step weaponization; the offensive uplift stays abstract on purpose.

## CWE vs CVE — why chains matter

- A **CVE** is one named vulnerability in one product version. A **CWE** is the underlying weakness *type* (e.g. CWE-89 SQL Injection, CWE-502 Unsafe Deserialization). One CWE explains many CVEs.
- Defenders who patch CVE-by-CVE play whack-a-mole. Defenders who recognize the **chain pattern** can place one control that neutralizes a whole class of future CVEs sharing that link.
- MITRE's CWE research view (CWE-1000) formalizes chain relationships: a **Primary** weakness enables a **Resultant** weakness. A **Composite** requires several weaknesses present together. Threat-intel chains are mostly Primary→Resultant sequences mapped onto ATT&CK tactics.

## `cwe_chain` field schema

One object per distinct chain. Speculative links are marked `confidence: low`; every link names a `source` (R2/R3 apply to CWE IDs and chain claims exactly as they do to IOCs — do not invent a CWE ID or assert a link a source doesn't support).

`chain_id | name | links[] | enabling_conditions | ai_assist_factor | break_points[] | score | confidence | source`

Each entry in `links[]`:

`cwe_id | role (primary | resultant) | mitre_id | tactic | evidence | source`

Each entry in `break_points[]` (the defensive payload — at least one per chain):

`at_link (cwe_id) | control | control_type (preventive | detective | corrective) | rationale | mapped_mitigation (NIST/ISO/MITRE M-id)`

## Common chain patterns (illustrative, defensive framing)

| Chain | Link sequence (primary → resultant) | Cheapest break-point |
|-------|--------------------------------------|----------------------|
| Web app to RCE | CWE-20 Improper Input Validation → CWE-89 SQLi → CWE-78 OS Command Injection | Parameterized queries at CWE-89 collapse the rest |
| Auth to takeover | CWE-287 Improper Authentication → CWE-269 Improper Privilege Management → CWE-502 Unsafe Deserialization | Least-privilege at CWE-269 caps blast radius |
| SSRF to cloud creds | CWE-918 SSRF → CWE-200 Exposure of Sensitive Info → CWE-522 Insufficiently Protected Credentials | Enforce IMDSv2 / egress filter at CWE-918 |
| Supply-chain to persistence | CWE-1357 Reliance on Untrusted Component → CWE-494 Download of Code Without Integrity Check → CWE-829 Inclusion of Functionality from Untrusted Sphere | Signature/integrity verification at CWE-494 |

The break-point column is the point: identify the **single link whose mitigation invalidates the largest downstream tail**, and prioritize that control.

## How AI assistance changes the calculus

Treat `ai_assist_factor` (none / low / moderate / high) as an analysis input describing how much cheaper AI tooling makes a given chain for an attacker — which is exactly what raises a chain's *urgency* for defenders. Each factor pairs with a defensive takeaway:

| AI-assist factor (attacker cost ↓) | Defensive takeaway |
|------------------------------------|--------------------|
| **Automated weakness discovery** — LLM-assisted code/triage surfaces candidate CWEs across large codebases faster | Assume shorter time-to-discovery; shrink exposure windows, prioritize SAST/secret-scanning on the primary-link CWE classes |
| **Variant generation** — models produce many payload variants of a known weakness | Signature-only detection decays; favor behavioral/anomaly detection at the resultant link |
| **Chain synthesis / ordering** — models propose plausible link orderings a human might miss | Don't assume the "obvious" path is the only one; harden every primary link, not just the first |
| **PoC drafting** — models accelerate moving from weakness to working check | Compress patch SLAs for CWE classes with known primary→resultant chains and active campaigns |

The intel value is the **factor and its takeaway**, never the generated exploit. The report records *that* AI lowers a chain's cost and *which break-point* to fund — it does not produce the weaponization.

## Scoring a chain

Reuse the threat-scoring engine ([scoring.md](scoring.md)) at the chain level: the chain inherits the **exploitability** of its weakest (most exploitable) primary link, the **impact** of its terminal resultant link, and an **urgency** uplift when `ai_assist_factor` is moderate/high or a contributing CWE class is under active exploitation. Map the chain score to P1–P5 and drive the break-point control into the Actions Matrix at that priority.

## Reporting

- In the report body, present chains under Pattern Analysis / Exploit Chains (extraction §D), each with its `break_points`.
- Every chain carries a `source`; links the evidence doesn't support are omitted or marked `confidence: low` (R3).
- The defensive recommendation (break-point control) is the deliverable. A chain reported without at least one `break_point` is incomplete.
