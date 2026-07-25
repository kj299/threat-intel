# CWE Chaining (AI-Assisted Attacks)

Threat intel that tracks only single CVEs misses how real intrusions compose. Adversaries chain **weakness classes** (CWE) — an input-validation gap feeds an injection, which yields code execution, which a deserialization flaw escalates. AI assistance is lowering the cost of *finding and ordering* those links, so the report should reason about chains and, more importantly, about where to **break** them.

This reference is defensive. It captures CWE chains as analysis — enabling conditions, the cheapest break-point, the detection opportunity — not as an exploitation recipe. No step-by-step weaponization; the offensive uplift stays abstract on purpose.

## CWE vs CVE — why chains matter

- A **CVE** is one named vulnerability in one product version. A **CWE** is the underlying weakness *type* (e.g. CWE-89 SQL Injection, CWE-502 Unsafe Deserialization). One CWE explains many CVEs.
- Defenders who patch CVE-by-CVE play whack-a-mole. Defenders who recognize the **chain pattern** can place one control that neutralizes a whole class of future CVEs sharing that link.
- MITRE's CWE research view (CWE-1000) formalizes chain relationships: a **Primary** weakness enables a **Resultant** weakness. A **Composite** requires several weaknesses present together. Threat-intel chains are mostly Primary→Resultant sequences mapped onto ATT&CK tactics.

## CWE views & provenance (cite which view a link comes from)

Record `cwe_view` on each chain so a reviewer can trace where the relationship is sourced. R2/R3 apply: the relationship must come from a real CWE view or a cited campaign report, never invented.

| View | What it gives you | Use it for |
|------|-------------------|------------|
| **CWE-1000** Research Concepts | Full `CanPrecede` / `CanFollow` / `PeerOf` / `ChildOf` relationships between weaknesses | Establishing that a primary→resultant link is real, not assumed |
| **CWE-709** Named Chains | MITRE's curated, named chain relationships (e.g. *CWE-680: Integer Overflow → Buffer Overflow*) | Anchoring a chain to a recognized, pre-vetted sequence |
| **CWE-1003** NVD mapping view | The CWE subset NVD assigns to CVEs | Mapping observed CVEs onto their weakness classes |
| **CWE Top 25 + "On the Cusp"** | The most prevalent/impactful weaknesses for the year | Prioritizing which primary links to harden first |

When a chain is taken from MITRE's named-chain catalog, set `chain_type: named_chain` and `cwe_view: CWE-709`. When it is inferred from campaign evidence using `CanPrecede` relationships, set `chain_type: primary_resultant` and `cwe_view: CWE-1000`.

## Chain types

Set `chain_type` so the consumer knows the shape of the chain:

- **`primary_resultant`** — linear A→B→C, the primary weakness enables the next (most intel chains).
- **`composite`** — several weaknesses that must be present *together* to be exploitable (CWE composites, e.g. CWE-352 CSRF requires predictable requests + no token + state-changing action). Order doesn't fully capture it; `enabling_conditions` carries the co-requisites.
- **`named_chain`** — a chain that matches an entry in CWE-709 (cite it).
- **`multi_branch`** — a chain graph where one link enables more than one downstream path (a primary that can fan out to either RCE or data theft). Model the branches in `links[]` and note the fork in `enabling_conditions`; the break-point at the shared primary collapses *all* branches and is therefore the highest-value control.

## `cwe_chain` field schema

One object per distinct chain. Speculative links are marked `confidence: low`; every link names a `source` (R2/R3 apply to CWE IDs and chain claims exactly as they do to IOCs — do not invent a CWE ID or assert a link a source doesn't support).

`chain_id | name | chain_type | cwe_view | links[] | enabling_conditions | ai_assist_factor | time_to_exploit | break_points[] | terminal_impact | score | priority | confidence | source`

Each entry in `links[]`:

`cwe_id | role (primary | resultant) | mitre_id | tactic | evidence | detection_opportunity | data_source | source`

`detection_opportunity` + `data_source` are the per-link detective payload: *what observable this link produces* and *where you'd see it* (e.g. "anomalous outbound from web tier to 169.254.169.254" / "VPC flow logs"). They feed the SIEM hunting queries (see [siem-queries.md](siem-queries.md)).

Each entry in `break_points[]` (the defensive payload — at least one per chain):

`at_link (cwe_id) | control | control_type (preventive | detective | corrective) | rationale | mapped_mitigation (NIST/ISO/MITRE M-id) | detection_telemetry`

`time_to_exploit` (chain-level, optional but recommended) records exploit velocity:

`observed_days (median days disclosure→exploitation for the contributing CWE classes) | trend (accelerating | stable | decelerating) | source`

## Common chain patterns (illustrative, defensive framing)

| Chain | Type | Link sequence (primary → resultant) | Cheapest break-point |
|-------|------|--------------------------------------|----------------------|
| Web app to RCE | primary_resultant | CWE-20 Improper Input Validation → CWE-89 SQLi → CWE-78 OS Command Injection | Parameterized queries at CWE-89 collapse the rest |
| Auth to takeover | primary_resultant | CWE-287 Improper Authentication → CWE-269 Improper Privilege Management → CWE-502 Unsafe Deserialization | Least-privilege at CWE-269 caps blast radius |
| SSRF to cloud creds | multi_branch | CWE-918 SSRF → CWE-200 Exposure of Sensitive Info → {CWE-522 Insufficiently Protected Credentials \| CWE-1391 Use of Weak Credentials} | Enforce IMDSv2 / egress filter at CWE-918 collapses both branches |
| Supply-chain to persistence | primary_resultant | CWE-1357 Reliance on Untrusted Component → CWE-494 Download of Code Without Integrity Check → CWE-829 Inclusion of Functionality from Untrusted Sphere | Signature/integrity verification at CWE-494 |
| Memory-safety (named) | named_chain (CWE-709) | CWE-190 Integer Overflow → CWE-787 Out-of-bounds Write → CWE-94 Code Injection | Bounds/overflow checks at CWE-190→787 boundary |
| File upload to webshell | primary_resultant | CWE-434 Unrestricted Upload → CWE-22 Path Traversal → CWE-98 PHP Remote File Inclusion | Content-type allowlist + execute-disabled upload dir at CWE-434 |
| Deserialization to RCE | primary_resultant | CWE-20 Improper Input Validation → CWE-502 Unsafe Deserialization → CWE-913 Improper Control of Dynamically-Managed Resources | Reject untrusted serialized input / allowlist types at CWE-502 |

The break-point column is the point: identify the **single link whose mitigation invalidates the largest downstream tail**, and prioritize that control.

## Break-point selection algorithm

When choosing which control to fund, rank break-points by *downstream tail invalidated × feasibility*:

1. **Prefer the shared primary.** In a `multi_branch` chain, a control at the fork invalidates every branch — always the highest-value candidate.
2. **Prefer preventive at the earliest enabling link** when the control is cheap and reliable (parameterized queries, IMDSv2, signature verification). One preventive control upstream beats N detective controls downstream.
3. **Layer detective at the resultant link** when the primary can't be fully closed (legacy component, third-party code). Pair the `break_point` with concrete `detection_telemetry` so the SOC can hunt the resultant link.
4. **Add corrective only as backstop** (rollback, credential rotation) for links where prevention and detection both have gaps.
5. **Every chain ships ≥1 break-point.** A chain reported without one is incomplete — the defensive recommendation is the deliverable, not the chain narrative.

## How AI assistance changes the calculus

Treat `ai_assist_factor` (none / low / moderate / high) as an analysis input describing how much cheaper AI tooling makes a given chain for an attacker — which is exactly what raises a chain's *urgency* for defenders. Each factor pairs with a defensive takeaway:

| AI-assist factor (attacker cost ↓) | Defensive takeaway |
|------------------------------------|--------------------|
| **Automated weakness discovery** — LLM-assisted code/triage surfaces candidate CWEs across large codebases faster | Assume shorter time-to-discovery; shrink exposure windows, prioritize SAST/secret-scanning on the primary-link CWE classes |
| **Variant generation** — models produce many payload variants of a known weakness | Signature-only detection decays; favor behavioral/anomaly detection at the resultant link |
| **Chain synthesis / ordering** — models propose plausible link orderings a human might miss | Don't assume the "obvious" path is the only one; harden every primary link, not just the first |
| **PoC drafting** — models accelerate moving from weakness to working check | Compress patch SLAs for CWE classes with known primary→resultant chains and active campaigns |

The intel value is the **factor and its takeaway**, never the generated exploit. The report records *that* AI lowers a chain's cost and *which break-point* to fund — it does not produce the weaponization.

## Time-to-exploit & exploit velocity

`ai_assist_factor` is qualitative; pair it with the quantitative **time-to-exploit (TTE)** trend. Industry TTE telemetry (e.g. **Zero Day Clock**, zerodayclock.com — median TTE across 80k+ CVEs from CISA KEV / Exploit-DB / Metasploit) shows the disclosure→exploitation window collapsing from ~months toward ~days, with AI cited as the inflection. Use it to set `time_to_exploit`:

- **`observed_days`** — median days from disclosure to in-the-wild exploitation for the chain's contributing CWE classes (cite the TTE source).
- **`trend`** — `accelerating` when the window is shrinking year-over-year (raises urgency and compresses patch SLA), `stable`, or `decelerating`.
- A chain whose `ai_assist_factor` is moderate/high **and** whose `time_to_exploit.trend` is `accelerating` should escalate by at least one priority band and drive its break-point control to the front of the Actions Matrix.

Cross-check chains against the **CISA KEV** catalog and **Project Zero "0day In the Wild"** tracker (projectzero.google/0day.html): a contributing CWE class with a KEV or ITW entry is under active exploitation and forces an urgency uplift regardless of modeled TTE.

## Enabling chain analysis (`cwe_chaining`)

Chain modelling is controlled by the `cwe_chaining` input:

| Value | Behaviour |
|-------|-----------|
| `off` | No chain modelling. Vulnerabilities are reported individually. |
| `catalog` | Chains only from MITRE's own relationship data — CWE-709 named chains and CWE-1000 `CanPrecede`/`CanFollow`. Deterministic and fully attributable; no web-sourced material. |
| `osint` *(default)* | `catalog`, plus chains evidenced in public reporting — vendor advisories, incident write-ups, CERT bulletins, exploit-chain disclosures. |

`catalog` exists for operators who want chain analysis without web-sourced
inference in the deliverable. `off` is appropriate when the report is a
straight IOC package and chain narrative is noise.

## OSINT-sourced chains

Under `cwe_chaining: osint`, chain evidence comes from what has actually been
*reported*, not from what seems plausible. Legitimate sources, in descending
order of weight:

1. **Named chain disclosures** — a vendor advisory or researcher write-up that
   explicitly describes CVE-A being used to reach CVE-B (e.g. an SSRF used to
   obtain credentials then used against an admin endpoint).
2. **Incident and IR reporting** — post-incident analyses describing the
   observed path through an environment.
3. **CERT/national-agency bulletins** — CISA, NCSC, JPCERT and peers frequently
   describe multi-stage exploitation explicitly.
4. **Exploit-chain research** — Pwn2Own entries, Project Zero write-ups, and
   conference material that document composition rather than a single bug.

Set `evidence_basis` to record which of three worlds a chain came from:

- **`named_chain_catalog`** — it is a CWE-709 entry. Strongest.
- **`osint_reported`** — a named public source describes this composition. Cite
  it in `source`.
- **`inferred`** — nobody reported it; this analysis composed it from CWE-1000
  relationships and the operator's stack. **An inferred chain is a hypothesis
  and MUST carry `confidence: low`.**

### The discipline that keeps this honest

Chain analysis is the most fabrication-prone part of this skill, because a
plausible-sounding chain is easy to generate and hard to falsify. R3 applies
with full force:

- **Never invent a CVE-to-CVE link.** "These two CVEs are in the same product
  and could plausibly chain" is `inferred`, not `osint_reported`, no matter how
  reasonable it sounds.
- **Never invent the *reachability*.** A chain requires that the output of one
  weakness actually reaches the input of the next. If the reporting does not
  establish that, say so in `enabling_conditions` rather than assuming it.
- **A chain nobody has reported is still worth reporting** — as a hypothesis,
  labelled as one, with its assumptions stated. That is useful analysis. What
  is not acceptable is presenting it with the same confidence as an observed
  chain.
- **Absence of reported chaining is not evidence of safety**, and should not be
  written as though it were.

## Re-prioritising low-CVSS vulnerabilities

This is the practical payoff, and the reason `cwe_chaining` is worth enabling.

CVSS scores a vulnerability **in isolation**. It has no way to express that a
5.3 information disclosure hands an attacker exactly the input a 6.1
server-side request forgery needs, which in turn reaches an unauthenticated
internal admin endpoint. Each score is individually defensible. The composition
is critical. Patch queues ordered by CVSS descending will not reach any of them
for months.

So a chain records **both** numbers and the gap between them:

- `contributing_cves[]` — each CVE with its own `cvss_score` and
  `role_in_chain`
- `max_component_cvss` — the highest individual score
- `chain_severity` — the severity of the *composed* path
- `severity_uplift_rationale` — required whenever `chain_severity` outranks
  `max_component_cvss`

**The gap is the finding.** A chain whose components top out at 6.1 but whose
`chain_severity` is `Critical` is telling a patch owner something CVSS
structurally cannot.

### Worked example (illustrative, not a live finding)

| Contributing CVE | CVSS | Role in chain |
|---|---|---|
| CVE-YYYY-AAAA | 4.3 (Medium) | Entry: CWE-200 exposes internal hostnames |
| CVE-YYYY-BBBB | 6.1 (Medium) | Pivot: CWE-918 SSRF reaches those hosts |
| CVE-YYYY-CCCC | 5.4 (Medium) | Terminal: CWE-306 missing auth on the internal admin API |

`max_component_cvss: 6.1` · `chain_severity: Critical` ·
`severity_uplift_rationale`: "No component is individually exploitable to
impact. Composed, an unauthenticated external attacker reaches an internal
administrative API. The SSRF is the shared primary — egress filtering at that
link collapses the path regardless of the other two."

Nothing here would surface in a CVSS-ordered queue. All three sit below the
7.0 threshold most organisations use to trigger expedited patching.

### Scoping to the operator's stack

Chain relevance is stack-specific, which is why `technology_stack` gates this
work. Record `stack_relevance` naming the declared stack entries a chain
applies to.

- A chain that matches **nothing** in the declared stack is not an org finding.
  Report it, if at all, as general landscape — not in the Actions Matrix.
- A chain that matches **several** stack entries is more urgent than its score
  alone implies: the same break-point control pays off in more places.
- When `technology_stack` is empty, chains are reported generically and
  `stack_relevance` is omitted. Do not guess the stack from the sector.

### Effect on priority

A chain's break-point control enters the Actions Matrix at the **chain's**
priority, not at the priority its individual CVEs would have earned. That is
the entire point: it moves a set of individually-deferred patches, or one
compensating control, up the queue on evidence rather than on intuition.

Where a single control breaks the chain, prefer funding that control over
patching every component — it is usually cheaper, faster, and it holds against
future CVEs in the same weakness class.

## Scoring a chain

Reuse the threat-scoring engine ([scoring.md](scoring.md)) at the chain level: the chain inherits the **exploitability** of its weakest (most exploitable) primary link, the **impact** of its terminal resultant link (record it in `terminal_impact`), and an **urgency** uplift when `ai_assist_factor` is moderate/high, when `time_to_exploit.trend` is `accelerating`, or when a contributing CWE class is under active exploitation (KEV/ITW). Map the chain score to P1–P5 and drive the break-point control into the Actions Matrix at that priority.

## Reporting

- In the report body, present chains under Pattern Analysis / Exploit Chains (extraction §D), each with its `break_points`, `chain_type`, and `terminal_impact`.
- Every chain carries a `source` and a `cwe_view`; links the evidence doesn't support are omitted or marked `confidence: low` (R3).
- For each link's `detection_opportunity`, emit a matching hunting query per [siem-queries.md](siem-queries.md) (discovery-first, schema-driven).
- The defensive recommendation (break-point control) is the deliverable. A chain reported without at least one `break_point` is incomplete.
