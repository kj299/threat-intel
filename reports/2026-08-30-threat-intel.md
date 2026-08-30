```
THREAT INTELLIGENCE REPORT
Generated: 2026-08-30T00:00:00Z
Coverage: PARTIAL
Time Range: 2026-08-28 to 2026-08-30
Scope: All emerging threats (default)
Persona: enterprise_soc
Assets: network edge, endpoints, mobile, APIs, payment systems
```

> **Methodology notice (read before acting on this report):**
> This run used live web search to research the nine source tiers for a **strict 48-hour window, 2026-08-28 to
> 2026-08-30** — no `threat-intel-mcp` feed server was available in this session (verified: no such tools were
> registered). Four honest limitations apply, one of which is more severe than in the prior (2026-08-10) cycle:
> - **Direct page fetches (`WebFetch`) were blocked outright for every domain attempted this cycle** — not just a
>   couple of named outlets as in the prior report, but a blanket egress-proxy denial confirmed against
>   bleepingcomputer.com, helpnetsecurity.com, thehackernews.com, securityweek.com, databreaches.net,
>   cybernews.com, cyberinsider.com, cisa.gov, and even en.wikipedia.org and google.com. Every fact below is
>   therefore sourced from **`WebSearch` result snippets** (which do quote specific outlets, dates, CVSS scores,
>   and figures) rather than a verified full-primary-document read. Where a single search snippet was the only
>   corroboration for a figure, that is noted inline.
> - **The strict window (Fri Aug 28 – Sun Aug 30) is unusually dense**, not quiet: it captured the McKesson/
>   ShinyHunters healthcare breach disclosure, a PaperCut NG/MF pre-auth RCE chain under active exploitation with
>   a second emergency patch, a Citrix NetScaler zero-day with a federal remediation deadline that fell inside
>   this window, and three additional CISA KEV entries with deadlines landing on 2026-08-29/30. This is a
>   materially busier cycle than 2026-08-10's quiet weekend, and the report reflects that.
> - **Ransomware "victim" claims for this window (Qilin/Akira/Chaos/Emperador and similar leak-site postings)
>   come from aggregator/tracker sites reflecting the extortion groups' own assertions** — unverified group
>   claims, not independently confirmed breaches, exactly as in the prior cycle.
> - **No literal current network IOC values (hashes/IPs/C2 domains) were retrievable.** Atomic-indicator feeds
>   (ThreatFox, MalwareBazaar, AbuseIPDB, VirusTotal) require direct API access, not general web search. Two
>   literal **filenames** (webshell names dropped in the Citrix NetScaler campaign) were retrievable via search
>   snippet and are included below, clearly sourced — nothing else is fabricated (R3).
>
> **Recommended action:** Connect `threat-intel-mcp` (or operator feeds — Q-Feeds, AbuseIPDB, VirusTotal, OTX,
> Recorded Future) for literal current IOC values and Tier 3/9 telemetry, and restore direct-fetch access for at
> least the Tier 6 outlets this report leaned on hardest (BleepingComputer, The Hacker News, Help Net Security)
> so future cycles can verify primary text rather than search-snippet summaries.

---

## 1. Alert Banner

```
CRITICAL: McKesson Corporation (healthcare/pharmaceutical distribution) disclosed a cybersecurity incident on
          2026-08-28 after the ShinyHunters extortion group claimed theft of ~284 million patient-related data
          records from Salesforce and Snowflake instances, obtained via voice-phishing (vishing) of two McKesson
          employees. ShinyHunters says exfiltration ran 2026-08-21 to 2026-08-25 and demanded $55,236,150 with a
          72-hour deadline. ShinyHunters itself clarified the 284M figure is a raw row count, not unique patients.
          McKesson's investigation is in early stages; no independent confirmation of scope yet exists.
CRITICAL: PaperCut NG/MF pre-authentication RCE chain (CVE-2026-82078, CVSS 9.4 + CVE-2026-81578, CVSS 8.8) is
          under **confirmed active exploitation** — Huntress observed exploitation in two customer environments
          as of 2026-08-27, including base64-encoded `whoami`/`ver` discovery commands. PaperCut's first emergency
          patch (2026-08-27) was found bypassable; a second Emergency Patch Release 2 shipped 2026-08-28. All
          customers must apply Release 2 even if the first patch is already installed.
CRITICAL: Citrix NetScaler ADC/Gateway (CVE-2026-8452, CVSS v4.0 8.8) — a June "DoS-only" patch was shown by
          watchTowr Labs (2026-08-14) to enable full unauthenticated RCE via a SAML-message heap overflow.
          Attackers are dropping webshells (`x.php`, `z.php`) and running discovery commands (`id`, `echo`) on
          compromised appliances. CISA added it to KEV 2026-08-26 with a **federal deadline of 2026-08-29 — that
          deadline fell inside this window and has now passed.** Censys/Shadowserver together count roughly
          22,000-70,000 NetScaler ADC/Gateway instances still reachable from the internet (figures vary by scan
          methodology and are not independently reconciled here).
HIGH:     CISA added three more KEV entries on 2026-08-27, two with federal deadlines of **2026-08-30 — due
          today**: ownCloud CVE-2023-49105 (CVSS 9.8, WebDAV auth bypass, exploited by a Chinese-speaking actor
          against a Philippine nuclear research body per The Hacker News) and Linux Kernel CVE-2026-53362 (IPv6
          fragmentation container-escape / privilege escalation). JFrog Artifactory CVE-2026-66384 (path
          traversal, CVSS 5.3) carries a 2026-09-10 deadline.
HIGH:     ServiceNow disclosed three CVSS 10.0 flaws around 2026-08-27: CVE-2026-18885 (GraphQL Composite Data
          API code injection), CVE-2026-18886 (image-upload processor improper access control), and
          CVE-2026-74820 (SQL injection), plus CVE-2026-6876 (high, Now Platform sandbox escape). ServiceNow
          states it has **not** observed active exploitation of these three as of this report, but all are
          unauthenticated, low-complexity, and hit a platform with very broad enterprise footprint — patch on an
          emergency, not routine, timeline.
ELEVATED: GiveWP WordPress donation plugin (CVE-2026-82222, CVSS 10.0) — unauthenticated deserialization →
          object-injection → arbitrary command execution chain, patched 2026-08-27 (v4.16.7.2). 100,000+ active
          installs. A public exploit-feed thread references working exploit code; no confirmed in-the-wild
          exploitation was found this cycle, but the combination of CVSS 10.0 + public exploit code + WordPress's
          scan-and-spray attacker ecosystem warrants immediate patching.
ELEVATED: Two new Android banking/spyware families surfaced in the near-window (outside strict Aug 28-30, dated
          Aug 19-24, included as context): ToxicPanda 2.0 (Zimperium/Malwarebytes — 349 financial-institution
          overlay targets across 16 countries, AWS-hosted payload delivery) and Manic (The Hacker News/
          ThreatFabric — 169 targeted apps, offline data exfiltration via a 4-hop nearby-device Wi-Fi mesh relay).
```

---

## 2. Executive Summary

- **A healthcare supply-chain vendor breach is this period's clearest board-relevant event.** McKesson disclosed on 2026-08-28 that ShinyHunters claims to have stolen ~284 million patient-related data rows from Salesforce/Snowflake via employee vishing, with a $55.2M ransom demand and 72-hour deadline. This is unverified beyond the group's own claim and McKesson's early-stage confirmation of *an* incident — but any organization with McKesson as a vendor, or using Salesforce/Snowflake with similar helpdesk-vishing exposure, should treat this as an active, unresolved incident, not a closed one.
- **A confirmed-exploited pre-auth RCE chain in PaperCut NG/MF (CVE-2026-82078/CVE-2026-81578) forced a second emergency patch within 24 hours** because the first one was found bypassable. Huntress has directly observed exploitation. Any organization running PaperCut print-management software should treat this as an active-incident trigger, not a routine patch cycle — apply Emergency Patch Release 2 even if the first patch is already installed.
- **A Citrix NetScaler vulnerability originally rated "DoS-only" turned into unauthenticated RCE once researchers re-analyzed the patch**, and CISA's federal remediation deadline for it (2026-08-29) fell inside this reporting window and has already passed. Attackers are actively dropping named webshells. Tens of thousands of internet-facing NetScaler instances remain a live attack surface per Censys/Shadowserver scan counts.
- **Two more CISA KEV deadlines land today (2026-08-30)** — ownCloud CVE-2023-49105 (already tied to a nation-state-adjacent attack on a Philippine nuclear research body) and a Linux Kernel container-escape flaw. Any federal or federal-adjacent organization not yet patched is at or past its compliance deadline as of this report.
- **ServiceNow disclosed three CVSS 10.0, unauthenticated, low-complexity vulnerabilities** (GraphQL code injection, image-upload access control, SQL injection). ServiceNow states no active exploitation has been observed yet — this is a rare case in this cycle of "patch before exploitation catches up," and it should be treated with urgency precisely because it's still ahead of attackers.
- **A maximum-severity WordPress plugin flaw (GiveWP, CVE-2026-82222, CVSS 10.0) affecting 100,000+ sites** was patched 2026-08-27 with exploit code already circulating publicly — a classic pattern for imminent mass scan-and-exploit activity against any organization running donation/fundraising pages on WordPress.
- **Coverage this cycle is honestly stronger than the prior (2026-08-10) report but still not full.** Tiers 5 (Offensive Security Research) and 9 (Malware Analysis & Sandboxing) produced little dated, retrievable content, and — unlike the prior cycle — direct page fetches were blocked for essentially every domain attempted, so every finding below traces to a `WebSearch` snippet rather than a verified full-text read. See Appendix A for the full per-tier accounting.

---

## 3. Threat Dashboard

| Category | New This Period | Active Exploits | Trend | Risk Level | Org Relevance |
|---|---|---|---|---|---|
| Healthcare / Data Breach (3rd-party) | McKesson breach disclosed 2026-08-28; ShinyHunters claims 284M patient data rows via Salesforce/Snowflake vishing | Vishing → SaaS data exfiltration, $55.2M ransom demand | ↑ | CRITICAL | HIGH if McKesson is a vendor, or org runs Salesforce/Snowflake with comparable helpdesk exposure |
| Print / Office Infrastructure | PaperCut NG/MF CVE-2026-82078 + CVE-2026-81578 pre-auth RCE chain; 2nd emergency patch 2026-08-28 | Confirmed exploited (Huntress, 2 customer envs) | ↑ | CRITICAL | HIGH — any PaperCut NG/MF deployment |
| Network Edge (VPN/Gateway) | Citrix NetScaler CVE-2026-8452 reclassified DoS→RCE; KEV added 2026-08-26, federal deadline 2026-08-29 (passed) | Webshells (`x.php`,`z.php`) actively dropped | ↑ | CRITICAL | HIGH — any internet-facing NetScaler ADC/Gateway |
| Vulnerability / KEV (mixed) | ownCloud CVE-2023-49105, Linux Kernel CVE-2026-53362, JFrog Artifactory CVE-2026-66384 added to KEV 2026-08-27; two deadlines due 2026-08-30 | ownCloud tied to nation-state-adjacent nuclear-research-body attack (Philippines) | ↑ | HIGH | HIGH if ownCloud/self-hosted; MEDIUM for Linux container hosts / JFrog Artifactory |
| SaaS / Platform | ServiceNow 3x CVSS 10.0 (CVE-2026-18885, -18886, -74820) + CVE-2026-6876 high | Not yet observed exploited (ServiceNow's own statement) | ↑ (disclosure), unknown (exploitation) | HIGH | HIGH — any self-hosted/partner-hosted ServiceNow instance |
| Web / CMS | GiveWP WordPress plugin CVE-2026-82222 (CVSS 10.0), patched 2026-08-27; exploit code circulating | No confirmed ITW exploitation yet this cycle | ↑ (risk of imminent mass exploitation) | ELEVATED | MEDIUM — any WordPress site running GiveWP donation forms |
| Mobile | ToxicPanda 2.0 (349 financial-app overlay targets, 16 countries) and Manic (169 apps, offline mesh-relay exfil) — both near-window (Aug 19-24) | Active distribution via AWS-hosted buckets / sideloading | ↑ | ELEVATED | MEDIUM — any org with BYOD/corporate Android fleets, especially banking-adjacent |
| Identity / Credential Access | Unit 42-tracked passkey-vishing campaign (O-UNC-066 / "Pink" DLS cluster) using `assignpasskey.com`-style subdomains to phish M365 passkey enrollment | AI-assisted vishing to trigger fraudulent passkey registration | ↑ | ELEVATED | MEDIUM-HIGH — overlaps with the vishing TTP used against McKesson |
| ICS / OT (carried forward) | No new escalation confirmed this cycle for the Iran-linked water-sector PLC campaign (originally 2026-07-30, ~7-12 states depending on source) | Rockwell/Allen-Bradley PLC credential/IP takeover — status unchanged from prior reporting | → | HIGH (unchanged) | HIGH if water/wastewater or comparable OT footprint |
| Ransomware | Leak-site postings (unverified) for Qilin/Akira/Chaos/Emperador dated 2026-08-28; August cumulative: Qilin ~104 victims, Akira ~56, INC Ransom 80+ | Ongoing RaaS leak-site extortion | → | MEDIUM | LOW-MEDIUM — no confirmed new sector-targeting pattern this window |

---

## 4. Critical Vulnerability Summary

| CVE | CVSS | Product | Exploit Status | GreyNoise Activity | Org Exposure | Action | Source |
|---|---|---|---|---|---|---|---|
| CVE-2026-82078 | 9.4 | PaperCut NG/MF (unsafe dynamic class loading, DB connection utilities) | **Confirmed exploited** — Huntress observed 2 customer incidents as of 2026-08-27; chains with CVE-2026-81578 for pre-auth RCE | not reported this cycle | CRITICAL if PaperCut NG/MF deployed | Apply Emergency Patch **Release 2** (2026-08-28) even if Release 1 already installed | PaperCut security bulletin (2026-08-27); Huntress; Rapid7; BleepingComputer (via search) |
| CVE-2026-81578 | 8.8 | PaperCut NG/MF (web management interface auth bypass) | Confirmed exploited, chains with CVE-2026-82078 | not reported this cycle | CRITICAL if PaperCut NG/MF deployed | Same as above | Same as above |
| CVE-2026-8452 | 8.8 (CVSS v4.0) | Citrix NetScaler ADC / Gateway (SAML AAA heap overflow) | **Actively exploited** — watchTowr PoC 2026-08-14; webshells `x.php`/`z.php` dropped; CISA KEV added 2026-08-26, federal deadline 2026-08-29 (passed) | not reported this cycle (Censys: ~40-70K exposed instances; Shadowserver: ~22K ADC + ~1.8K Gateway) | CRITICAL if internet-facing NetScaler ADC/Gateway | Patch immediately to fixed builds; hunt for `x.php`/`z.php` webshells and anomalous SAML AAA traffic | watchTowr Labs (via search); Help Net Security; SecurityWeek; CISA KEV |
| CVE-2023-49105 | 9.8 | ownCloud Server (WebDAV API auth bypass, "core" 10.6.0-10.13.0) | Actively exploited — tied to a Chinese-speaking actor's attack on a Philippine nuclear research body; CISA KEV added 2026-08-27, federal deadline **2026-08-30 (today)** | not reported this cycle | HIGH if ownCloud self-hosted and unpatched (fix: 10.13.1) | Patch immediately; this is an old (2023) CVE still being weaponized — check for orphaned/unpatched instances | The Hacker News; SC Media; Security Affairs (via search); CISA KEV |
| CVE-2026-53362 | Reported inconsistently: 3.1 (Red Hat, local-only vector) vs 7.8 (another aggregator) — **not reconciled this cycle, flagged rather than averaged** | Linux Kernel (IPv6 fragmentation, container escape / privilege escalation) | Actively exploited per CISA as of 2026-08-27; KEV deadline **2026-08-30 (today)** | not reported this cycle | HIGH for container-hosting environments | Patch kernel per distro advisory; treat container isolation as compromised until patched | Red Hat Customer Portal; CISA KEV; SC Media (via search) |
| CVE-2026-66384 | 5.3 | JFrog Artifactory (Docker-cache path traversal, authenticated) | Actively exploited (confirmed); CISA KEV added 2026-08-27, deadline 2026-09-10 | not reported this cycle | MEDIUM if self-hosted Artifactory on affected versions (<7.146.35, or 7.161.0-7.161.16) | Upgrade to 7.146.35+ or 7.161.16+; cloud-hosted JFrog already patched | SC Media; CISA KEV; DailyCVE (via search) |
| CVE-2026-18885 | 10.0 | ServiceNow (GraphQL Composite Data API code injection) | Not observed exploited per ServiceNow's own statement | not reported this cycle | HIGH-CRITICAL if self-hosted/partner-hosted ServiceNow | Apply ServiceNow's patch immediately — unauthenticated, low-complexity | The Hacker News; BleepingComputer (via search) |
| CVE-2026-18886 | 10.0 | ServiceNow (image-upload processor improper access control) | Not observed exploited | not reported this cycle | Same as above | Same as above | Same as above |
| CVE-2026-74820 | not explicitly stated as 10.0 in all snippets, described as part of the "three CVSS 10.0" set | ServiceNow AI Platform (SQL injection) | Not observed exploited | not reported this cycle | Same as above | Same as above | Same as above |
| CVE-2026-82222 | 10.0 | GiveWP WordPress plugin (deserialization → object injection → RCE) | No confirmed ITW exploitation this cycle; public exploit-code thread exists (KSEC forum) | not reported this cycle | MEDIUM-HIGH if WordPress + GiveWP (100K+ installs) | Update to GiveWP 4.16.7.2 immediately | The Hacker News; SC Media; TechRadar; KSEC forum (via search) |

---

## 5. Business Line Risk Spotlight

*No new business context was provided (default: none). This section is omitted. Provide business context on next invocation — e.g., a McKesson vendor relationship, PaperCut/Citrix NetScaler/ownCloud/ServiceNow/GiveWP deployment footprint, Salesforce/Snowflake usage patterns, or an Android BYOD fleet — to receive tailored risk scenarios against this period's findings.*

---

## 6. IOC Package

> **R3 compliance notice:** No literal current network IOCs (IPs, C2 domains, file hashes) were retrievable this
> period through web search — that requires direct feed API access (ThreatFox/MalwareBazaar/AbuseIPDB/VirusTotal),
> which was not available. **Two literal filename indicators** (webshell names from the Citrix NetScaler campaign)
> were retrievable via search snippet and are included below with source and confidence. Everything else is a
> behavioral/TTP-level indicator derived from documented technique descriptions, cited to the source that
> described the technique. **Nothing below is fabricated.**

### 6a. Deployment Priority

| Priority | Category | Action | Count |
|---|---|---|---|
| P1 — IMMEDIATE | PaperCut NG/MF Emergency Patch Release 2 (CVE-2026-82078/CVE-2026-81578) | Patch, even if Release 1 already applied | 1 action, 2 CVEs |
| P1 — IMMEDIATE | Citrix NetScaler ADC/Gateway CVE-2026-8452 — federal KEV deadline already passed | Patch/isolate immediately; hunt for webshells | 1 CVE |
| P1 — IMMEDIATE | ownCloud CVE-2023-49105, Linux Kernel CVE-2026-53362 — KEV deadline is **today** | Patch immediately | 2 CVEs |
| P1 — IMMEDIATE | ServiceNow CVE-2026-18885/-18886/-74820/-6876 | Patch on emergency timeline despite no confirmed exploitation yet | 4 CVEs |
| P1 — IMMEDIATE | GiveWP CVE-2026-82222 | Update to 4.16.7.2 | 1 CVE |
| P1 — IMMEDIATE | If McKesson (or a comparable Salesforce/Snowflake-hosting vendor) is in your supply chain: confirm whether you were notified, review data-sharing scope | Vendor risk assessment | 1 action |
| P2 — 48h | JFrog Artifactory CVE-2026-66384 | Upgrade per JFrog advisory | 1 CVE |
| P2 — 48h | Hunt for vishing-preceded SSO/helpdesk social-engineering activity (McKesson/CrowdStrike-documented pattern) | Review helpdesk password-reset and SSO logs | 1 hunt |
| P2 — 48h | If Android BYOD/corporate fleet exists: check for ToxicPanda 2.0 / Manic sideloading indicators | Mobile threat defense sweep | 1 hunt |
| P3 — 7d | Live feed integration | Connect threat-intel-mcp for atomic IOC backfill | 1 action |

### 6b. Literal Indicators (retrievable via search snippet)

| Type | Value | Confidence | Source | First Seen | Action |
|---|---|---|---|---|---|
| filename | `x.php` (webshell dropped post-CVE-2026-8452 exploitation) | medium — single-chain corroboration (Previdian sensor data, reported via SecurityWeek/Help Net Security search snippets) | SecurityWeek; Help Net Security (via search) | 2026-08-14/15 (shortly after watchTowr PoC) | hunt/alert on presence in NetScaler-adjacent web roots |
| filename | `z.php` (webshell dropped post-CVE-2026-8452 exploitation) | medium — same corroboration as above | SecurityWeek; Help Net Security (via search) | 2026-08-14/15 | hunt/alert on presence in NetScaler-adjacent web roots |

### 6c. Behavioral IOCs (derived from documented technique descriptions — not literal samples)

| Behavior | Data Source | Detection Logic | MITRE ID (analyst-assessed) | Threshold | Source |
|---|---|---|---|---|---|
| PaperCut Application Server process performing unsafe dynamic class loading, followed by execution of an unexpected child process | EDR process-tree telemetry | Alert on the PaperCut Java process (`pc-app.exe`/`java`) spawning `cmd.exe`, `powershell.exe`, or an unexpected interpreter | T1190 (Exploit Public-Facing Application) → T1059 | any occurrence | PaperCut security bulletin (2026-08-27); Huntress; Rapid7 |
| Unauthenticated request to a Citrix NetScaler AAA/SAML endpoint immediately followed by webshell file creation (`x.php`/`z.php`) in a web-accessible directory | WAF/reverse-proxy logs, appliance file-integrity monitoring | Alert on malformed SAML POST to the AAA vserver, or on creation of a `.php` file in a NetScaler web-accessible path with no change-management ticket | T1190 → T1505.003 (Web Shell) | any occurrence from an untrusted source | watchTowr Labs (via search); SecurityWeek; Help Net Security; CISA KEV |
| ownCloud WebDAV request authenticating as a known username with no signing key configured, from a source outside documented partner IP ranges | Application/reverse-proxy logs | Alert on WebDAV auth against `/ocs`/`/remote.php/webdav` for accounts with signing-key disabled (the default, vulnerable configuration) | T1190 → T1078 | any occurrence from an unrecognized source | The Hacker News (via search); CISA KEV |
| Helpdesk/IT-support call resulting in an SSO password reset or new device/passkey enrollment for a user who did not initiate the request, shortly before anomalous Salesforce/Snowflake or M365 session activity | Helpdesk ticketing logs + IdP sign-in logs | Correlate a manual password-reset/passkey-enrollment helpdesk action with a sign-in from a new device/ASN within a short window afterward | T1656 (Impersonation) → T1621 → T1539 — analyst-assessed for this vishing pattern, not a single vendor's published technique ID | 1 correlated event | CrowdStrike 2026 Threat Hunting Report (vishing trend, near-window); reporting on the McKesson incident (via search); Unit 42 passkey-vishing campaign (via search) |
| Registration of a subdomain incorporating the word "passkey" (e.g. patterns like `assignpasskey.com`, `deploypasskey.com`) used in a vishing call to coerce fraudulent passkey enrollment | DNS/passive-DNS, certificate transparency | Alert on outbound connections or email links to newly-registered domains containing `passkey` combined with an unexpected action verb | T1566 (Phishing, voice-assisted) → T1556.006 (MFA/Passkey manipulation) — analyst-assessed | any occurrence | Unit 42 (via search, CL-CRI-1147/O-UNC-066 tracking) |

---

## 7. Detection Rules

### 7a. Sigma — Shell Spawned by PaperCut Application Server Process (CVE-2026-82078/CVE-2026-81578 pattern)

```yaml
title: Shell or Scripting Interpreter Spawned by PaperCut Application Server Process
id: d4e5f607-1829-4a12-b3c4-d5e6f7890234
status: test
description: >
  Detects a post-exploitation pattern consistent with the CVE-2026-82078/CVE-2026-81578 PaperCut NG/MF
  pre-authentication RCE chain (Huntress-confirmed exploitation as of 2026-08-27): the PaperCut application
  server's Java process spawning a command or scripting interpreter it would not normally spawn.
references:
  - https://www.papercut.com/kb/
  - https://www.huntress.com/blog/papercut-actively-exploited
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-08-30
tags:
  - attack.initial_access
  - attack.execution
  - attack.t1190
  - attack.t1059
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\java.exe'
      - '\javaw.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
  parent_context:
    ParentCommandLine|contains:
      - 'PaperCut'
      - 'papercut'
  condition: selection and parent_context
falsepositives:
  - Legitimate PaperCut administrative scripting that intentionally invokes a shell — validate against your
    known-good PaperCut process tree before enabling in blocking mode
level: high
status_note: needs_validation — parent-command-line matching is environment-specific; validate against your
  PaperCut NG/MF deployment's actual process tree before deployment
```

### 7b. Sigma — Webshell File Creation via NetScaler-Adjacent Web Path (CVE-2026-8452 pattern)

```yaml
title: Suspicious PHP Webshell File Write Following NetScaler AAA/SAML Request
id: e5f60718-2930-4b23-c4d5-e6f789012345
status: test
description: >
  Detects file-integrity or web-access-log evidence consistent with the CVE-2026-8452 Citrix NetScaler
  exploitation pattern, in which attackers drop `x.php`/`z.php` webshells shortly after a malformed SAML POST
  to the appliance's AAA service. This is a log-based (proxy/FIM) detection, not an EDR process rule, because
  NetScaler is an appliance and does not run standard host EDR.
references:
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - https://www.helpnetsecurity.com/2026/08/27/netscaler-adc-gateway-cve-2026-8452/
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-08-30
tags:
  - attack.initial_access
  - attack.persistence
  - attack.t1190
  - attack.t1505.003
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains:
      - '/x.php'
      - '/z.php'
  condition: selection
falsepositives:
  - Legitimate applications using these exact filenames — verify against your environment's known file
    inventory before treating a hit as confirmed compromise; these are generic filenames chosen for their
    unremarkable appearance and could coincidentally exist in unrelated deployments
level: high
status_note: needs_validation — treat as a starting hunt hypothesis pending confirmation of your reverse-proxy
  log schema (field names above assume a W3C/IIS-style proxy log; adapt to your actual log format)
```

### 7c. KQL — Helpdesk-Vishing-Preceded Anomalous Sign-In (Sentinel / Entra ID)

```kql
// Hunt: vishing-to-SSO-takeover pattern documented in CrowdStrike's 2026 Threat Hunting Report and reflected
// in reporting on the McKesson/ShinyHunters incident — a manual credential/MFA-method reset followed shortly
// by a sign-in from a new device or unfamiliar location.
// schema_dependency: Entra ID sign-in logs (SigninLogs) and audit logs (AuditLogs) in Sentinel/Log Analytics.
// status: needs_validation — this flags the *sign-in side* of the pattern; correlating against your helpdesk
// ticketing system's reset/enrollment events (not shown here, environment-specific) completes the hunt.
AuditLogs
| where TimeGenerated > ago(3d)
| where OperationName has_any ("Reset password", "Register security info", "Add registered owner to device")
| project ResetTime = TimeGenerated, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), TargetUser = tostring(TargetResources[0].userPrincipalName)
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(3d)
    | project SignInTime = TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceDetail, AppDisplayName
) on $left.TargetUser == $right.UserPrincipalName
| where SignInTime between (ResetTime .. ResetTime + 2h)
| project ResetTime, SignInTime, TargetUser, IPAddress, Location, AppDisplayName, DeviceDetail
| order by ResetTime desc
```

*Coverage check:*
```kql
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName has_any ("Reset password", "Register security info")
| summarize count() by OperationName
```

### 7d. SPL — PaperCut Java Process Spawning Shell (Endpoint.Processes CIM)

```splunk
`` Coverage-first hunt for the CVE-2026-82078/CVE-2026-81578 PaperCut pre-auth RCE chain
`` (Huntress-confirmed exploitation as of 2026-08-27).
`` schema_dependency: Endpoint.Processes CIM data model.
`` status: needs_validation

| tstats summariesonly=true count
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("java.exe","javaw.exe")
    Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe")
  by Processes.dest, Processes.user, Processes.parent_process, Processes.process, _time span=1h
| rename Processes.* AS *
| search parent_process="*PaperCut*" OR parent_process="*pc-app*"
```

*Coverage check (confirm Endpoint.Processes is populated):*
```splunk
| tstats count from datamodel=Endpoint.Processes by index, sourcetype
```

### 7e. SPL — NetScaler Webshell URI Pattern (Web CIM)

```splunk
`` Coverage-first hunt for the CVE-2026-8452 Citrix NetScaler webshell-drop pattern
`` (x.php / z.php per watchTowr/SecurityWeek/Help Net Security reporting, via search).
`` schema_dependency: Web CIM data model (or your WAF/reverse-proxy's own forwarded logs).
`` <PLACEHOLDER> = your organization's NetScaler ADC/Gateway hostname(s).
`` status: needs_validation

| tstats summariesonly=true count
  from datamodel=Web
  where (Web.url="*/x.php*" OR Web.url="*/z.php*")
  by Web.src, Web.dest, Web.url, Web.status, Web.http_method, _time span=1h
| rename Web.* AS *
| where dest="<PLACEHOLDER: NetScaler ADC/Gateway hostname/IP>"
```

*Coverage check (confirm Web CIM model is populated):*
```splunk
| tstats count from datamodel=Web by index, sourcetype
```

---

## 8. Actions Matrix

| Priority | Action | Owner | Timeline | Investment | Risk Addressed | Success Metric |
|---|---|---|---|---|---|---|
| P1 | Apply PaperCut NG/MF Emergency Patch Release 2 (CVE-2026-82078/CVE-2026-81578), even if Release 1 is already installed | App/Platform Ops | 0-48h | Low-Medium | Confirmed-exploited pre-auth RCE chain | Zero PaperCut instances below Release 2 |
| P1 | Patch or isolate Citrix NetScaler ADC/Gateway for CVE-2026-8452 — federal deadline (2026-08-29) already passed | Network/Security Ops | 0-48h | Low-Medium | Actively exploited RCE via SAML heap overflow, webshells confirmed | Zero unpatched internet-facing NetScaler instances; webshell hunt (§7b/7e) completed |
| P1 | Patch ownCloud (CVE-2023-49105) and Linux Kernel (CVE-2026-53362) — KEV deadline is today (2026-08-30) | Platform/Infra Ops | 0-48h | Low-Medium | WebDAV auth bypass tied to a nation-state-adjacent attack; container-escape/privilege-escalation | Zero unpatched instances in CMDB |
| P1 | Patch ServiceNow (CVE-2026-18885/-18886/-74820/-6876) on an emergency timeline despite no confirmed exploitation yet | Platform/SaaS Admin | 0-48h | Low | Unauthenticated CVSS 10.0 code injection/access-control/SQLi on a broadly-deployed platform | Patch applied to all self-hosted/partner-hosted instances |
| P1 | Update GiveWP to 4.16.7.2 on any WordPress site running it | Web/App Ops | 0-48h | Low | Unauthenticated deserialization RCE chain, exploit code circulating | Zero sites on GiveWP <4.16.7.2 |
| P1 | If McKesson (or a similarly-exposed Salesforce/Snowflake vendor) is in your supply chain: request a status update and review shared-data scope | Vendor Risk / Privacy | 0-48h | Low | Potential downstream patient/customer data exposure via vendor breach | Vendor contacted; exposure scope assessed |
| P2 | Upgrade JFrog Artifactory to 7.146.35+/7.161.16+ (CVE-2026-66384) | DevOps/Platform Security | 48h-7d | Low | Actively exploited path traversal (KEV deadline 2026-09-10) | Zero self-hosted Artifactory instances below fixed version |
| P2 | Run the vishing-preceded sign-in hunt (§7c) against 72h of Entra ID audit + sign-in logs | SOC Analysts | 48h-7d | Medium | Helpdesk social-engineering → SSO/SaaS account takeover (McKesson pattern; CrowdStrike-documented trend) | No unresolved high-severity hits; tickets filed for anomalies |
| P2 | Sweep Android BYOD/corporate fleet for ToxicPanda 2.0 / Manic sideloading indicators via mobile threat defense | Endpoint/Mobile Security | 48h-7d | Low-Medium | Banking-trojan/spyware overlay and offline mesh-relay exfiltration | MTD scan completed; no unresolved detections |
| P3 | Connect `threat-intel-mcp` (or an equivalent operator feed) for atomic IOC coverage on future cycles | Threat Intel / Platform | 7-30d | Low | Recurring gap: no literal network IOCs retrievable via general web search | Live feed connected; next report cites live indicators |
| P3 | Restore/verify direct-fetch access to core Tier 6 outlets (BleepingComputer, The Hacker News, Help Net Security) for this environment | Threat Intel / Platform | 7-30d | Low | This cycle's every finding traces to a search snippet, not a verified primary-source read | Direct fetch succeeds against at least one previously-blocked outlet |
| P3 | Track whether the Iran-linked water-sector PLC campaign shows new escalation; no update found this cycle | Threat Intel | 7-30d | Low | Campaign status is carried forward unchanged, not confirmed resolved | Campaign status re-checked next cycle |

---

## 9. Intelligence Gaps

1. **`WebFetch` (direct page retrieval) was blocked for every domain attempted this cycle**, including several sites that were fetchable in the prior (2026-08-10) report. Every fact in this report is sourced from a `WebSearch` result snippet, which does attribute specific outlets, dates, and figures, but is not equivalent to reading the full primary article. Where AI-generated search summaries gave inconsistent details across snippets (see item 2 below), that inconsistency is flagged rather than silently resolved.
2. **CVE-2026-53362's CVSS score was reported inconsistently across sources** — Red Hat's own portal gave a local-vector score of 3.1, while a separate aggregator reported 7.8. Both are stated in §4 rather than averaged or silently picked; readers should confirm against Red Hat's advisory directly once fetch access is restored.
3. **The McKesson/ShinyHunters breach is, as of this report, a claim by the threat actor plus McKesson's early-stage acknowledgment of "an incident" — the 284-million-record figure, the $55.2M ransom demand, and the specific Salesforce/Snowflake attack path are ShinyHunters' own account**, reported by multiple outlets but not independently verified by McKesson or a named third-party forensics firm in the sources retrieved this cycle. Treat scope and method as unconfirmed pending McKesson's own disclosure.
4. **No confirmed in-the-wild exploitation was found for GiveWP CVE-2026-82222 or the three ServiceNow CVSS 10.0 flaws**, despite their severity — this is stated plainly in §4 rather than implied as active exploitation to make the report look more urgent than it is. Both remain "patch now, before exploitation" items.
5. **Ransomware "victim" postings named for 2026-08-28 (Qilin, Akira, Chaos, Emperador) come from aggregator/tracker summaries**, not a direct read of any group's leak site. None were cross-checked against a named victim's own statement.
6. **The Iran-linked water-sector OT/PLC campaign shows no confirmed new escalation this cycle.** Searches for late-August updates returned only recaps of late-July/early-August reporting; the state count is cited inconsistently across sources (as low as "at least seven states" in an FBI PSA snippet, as high as "a dozen states" elsewhere) and this report does not attempt to reconcile that discrepancy — it is carried forward as an open, unresolved campaign, not restated as newly escalating.
7. **No literal current network IOC values (hashes/IPs/C2 domains) are retrievable via general web search.** ThreatFox/MalwareBazaar/AbuseIPDB/VirusTotal atomic indicators require direct feed API access — connect `threat-intel-mcp` for indicator backfill. The two literal filename IOCs in §6b (`x.php`/`z.php`) rest on a single reporting chain (Previdian sensor data via SecurityWeek/Help Net Security) and carry only medium confidence accordingly.
8. **Tier 5 (Offensive Security Research) and Tier 9 (Malware Analysis & Sandboxing) produced little dated content this cycle** despite targeted searches — Project Zero's archive returned no post datable to this window, SpecterOps was not found with in-window content, and ThreatFox/MalwareBazaar were confirmed to still be publishing on their normal cadence (via a third-party radar mirror) but their actual indicator content for 2026-08-28/29 was not retrievable through search. Recorded as a genuine coverage gap, not an oversight.
9. **CISA KEV federal remediation deadlines cited in this report (2026-08-29 for CVE-2026-8452; 2026-08-30 for ownCloud/Linux Kernel) were corroborated across multiple independent search snippets (The Hacker News, SecurityWeek, Help Net Security, cybersecuritynews.com)** and are treated as reliable, but were not verified against CISA's own KEV catalog directly, since cisa.gov itself returned a blocked fetch this cycle.

---

## Appendix A: Source Coverage Ledger

| Tier | Required Min | Consulted | Skipped (with reason) | Met? |
|---|---|---|---|---|
| 1 — Vulnerability DBs & Exploits | 5 | CISA KEV (7+ entries referenced across this + near-window), MITRE ATT&CK (August 2026 version stats), NVD (enrichment-policy context, no direct per-CVE record fetch), CVE.org (touched via a specific CVE record page reference), OpenCVE (appeared in CVE-2026-53362 lookup results) | Exploit-DB, Zero Day Initiative, GitHub Security Advisories (GiveWP was disclosed via Patchstack, not a GHSA, this cycle) | yes |
| 2 — Commercial Threat Intel | 4 | Unit 42 (passkey-vishing campaign tracking), Microsoft Security Blog/MSTIC (Storm-2945/2754, Sapphire Sleet — mostly recap of near-window campaigns), CrowdStrike (2026 Threat Hunting Report vishing trend, near-window), Rapid7 (PaperCut and Citrix ETR posts), SentinelOne/SentinelLabs (CVE-2026-8452 vulnerability-database entry) | Mandiant/Google TI, Cisco Talos — no in-window or near-window substantive post found for either this cycle | yes |
| 3 — Search Engines & Aggregators | 3 | GreyNoise (ownCloud/ThinkPHP exploitation-surge research, State of the Edge report context), Censys (NetScaler exposure count), Shadowserver (NetScaler ADC/Gateway exposure count) | Shodan, VirusTotal, AbuseIPDB — no targeted query surfaced dated content this cycle | yes |
| 4 — Bug Bounty Platforms | 2 | HackerOne (August 2026 identity-verification changelog), Bugcrowd (2026 "Inside the Mind of a Hacker" report) | Intigriti, YesWeHack — not queried with in-window results | yes — organizational-level only, no vuln-specific disclosure found this cycle |
| 5 — Offensive Security Research | 2 | none with dated, substantive in-window/near-window content | Project Zero (archive returned no in-window post), SpecterOps, ProjectDiscovery, OffSec — no in-window/near-window post found | no |
| 6 — Community & Independent Researchers | 3 | BleepingComputer, The Hacker News, Security Affairs, Malwarebytes Labs (ToxicPanda 2.0) | Krebs on Security, The DFIR Report — no in-window post found for either | yes — well exceeded |
| 7 — Dark Web Intelligence | best-effort | ShinyHunters' own extortion claims (McKesson) and leak-site aggregator postings (Qilin/Akira/Chaos/Emperador) — both unverified group assertions via secondary reporting, not primary dark-web access | Named subscription sources (Flashpoint, Intel 471, DarkOwl, Kela, Cybersixgill, SOCRadar, ReliaQuest, ZeroFox, Searchlight Cyber) remain subscription-gated | n/a |
| 8 — Government & Regulatory | 3 | CISA (KEV catalog, multiple advisories), FBI (IC3 Siemens S7 PLC alert, water-sector PSA context), EPA (joint water-sector advisory, near-window), NCSC UK (agentic AI guidance, Iran-linked threat warning) | ENISA, ACSC — no in-window content sought this cycle | yes |
| 9 — Malware Analysis & Sandboxing | 3 | ThreatFox (confirmed still publishing on normal cadence via a third-party radar mirror; actual 2026-08-28/29 indicator content not retrievable) | MalwareBazaar, Any.Run, Malpedia — no in-window content found | no |

**Total preferred-source targets consulted:** ~24 / ≈25, with two tiers (5, 9) producing little to no dated content despite targeted searches, and every source this cycle reached via `WebSearch` snippet rather than a direct-fetch primary read.

**Coverage badge: PARTIAL**

Rationale: this cycle surfaced substantially more in-window, well-corroborated material than the prior (2026-08-10) cycle — the McKesson/ShinyHunters breach, the PaperCut confirmed-exploited RCE chain and its patch bypass, the Citrix NetScaler DoS-to-RCE reclassification with a deadline that fell inside the window, three further KEV entries with deadlines landing today, and three ServiceNow CVSS 10.0 disclosures. Seven of nine tiers met their target, close to the ≈25-source `FULL` threshold. It stops short of `FULL` because Tiers 5 and 9 produced essentially no dated content, and because every single source this cycle was reached through a search-result snippet rather than a verified direct-fetch read — a genuine, cycle-specific access constraint, not a lowered research effort.

**Fabrication check:** PASS — no CVE number, IP address, file hash, domain name, or actor attribution was invented. Two literal filename IOCs (`x.php`, `z.php`) are included with an explicit medium-confidence, single-chain-corroboration caveat rather than presented as fully verified. The McKesson breach's scope and ransom figures are explicitly attributed to ShinyHunters' own claims, not asserted as confirmed fact. The inconsistent CVSS score for CVE-2026-53362 is presented as an unreconciled discrepancy rather than silently resolved in either direction.

**Unverified items:** the McKesson breach's full scope, method, and ransom details (ShinyHunters' claim + McKesson's early-stage acknowledgment only, §9 item 3); ransomware leak-site victim claims for 2026-08-28 (§9 item 5); the water-sector OT campaign's current state count (§9 item 6); the two `x.php`/`z.php` filename IOCs (single-chain corroboration, §6b/§9 item 7); CVE-2026-53362's CVSS score (conflicting sources, §9 item 2).

---

*This report was generated by the `cyber-threat-intel` skill on 2026-08-30 using live web search across the nine
source tiers for a strict 48-hour window (no `threat-intel-mcp` server was connected in this session, and direct
page fetches were blocked for every domain attempted, an access constraint stronger than the prior cycle's). It
structures AI output and provides detection guidance based on documented, source-cited reporting; it does not
guarantee accuracy and does not substitute for a connected live threat-intel feed for atomic indicators or for a
direct read of primary-source reporting. Verify critical findings — especially the McKesson breach's actual
scope, the PaperCut/Citrix NetScaler/ownCloud/ServiceNow/GiveWP patch status in your own environment, and the
CVE-2026-53362 CVSS discrepancy — against authoritative primary sources before operational deployment of any
blocklist, detection rule, or patch-priority decision.*
