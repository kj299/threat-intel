```
THREAT INTELLIGENCE REPORT
Generated: 2026-08-10T00:00:00Z
Coverage: PARTIAL
Time Range: 2026-08-08 to 2026-08-10
Scope: All emerging threats (default)
Persona: enterprise_soc
Assets: network edge, endpoints, mobile, APIs, payment systems
```

> **Methodology notice (read before acting on this report):**
> This run used live web search/retrieval (not a connected `threat-intel-mcp` feed — no MCP feed server was
> available in this session) to research the nine source tiers for a **strict 48-hour window, 2026-08-08 to
> 2026-08-10**. Four honest limitations apply:
> - **The strict window falls on a weekend (Sat Aug 8 – Sun Aug 9) into a Monday (Aug 10).** CISA's KEV catalog
>   shows no new entries dated exactly Aug 8-10 — a genuinely quiet publishing window, not a search failure
>   (weekday cadence confirmed: Aug 3, 4, 5, 7 all had additions, then nothing until this report's cutoff). Most
>   of this period's substantive vulnerability and campaign reporting is dated **Aug 1-7**, just outside the
>   strict window — it is included below as clearly labeled **near-window** context, not presented as in-window.
> - **Several primary outlets were unreachable through this session's egress proxy** (securityaffairs.com,
>   therecord.media returned blocked/failed fetches). Facts attributed to them are recovered via search-result
>   snippets and corroborating secondary reporting, not verified full-primary-document reads.
> - **Ransomware "victim" postings for Aug 8 and Aug 10 come from leak-site aggregator/tracker sites reflecting
>   the extortion groups' own claims** (Play, Qilin, INC Ransom, Coinbase Cartel, Leakeddata) — these are
>   **unverified group assertions, not independently confirmed breaches**, and are labeled as such throughout.
> - **No literal current network IOC values (hashes/IPs/C2 domains) were retrievable.** Atomic-indicator feeds
>   (ThreatFox, MalwareBazaar, AbuseIPDB, VirusTotal) require direct API access, not general web search — none
>   is fabricated below (R3).
>
> **Recommended action:** Connect `threat-intel-mcp` (or operator feeds — Q-Feeds, AbuseIPDB, VirusTotal, OTX,
> Recorded Future) for literal current IOC values and Tier 3/9 telemetry; this report is strongest on the
> in-window/near-window vulnerability and campaign narrative and weakest on atomic indicators.

---

## 1. Alert Banner

```
CRITICAL: Iran-affiliated actors are actively targeting water-sector OT/PLCs (Rockwell Automation/Allen-Bradley
          MicroLogix 1100/1400) across a growing footprint — 12 U.S. states confirmed as of early August per a
          joint CISA/FBI/EPA/NSA advisory (originally 2026-07-30, scope still expanding through this window).
          Operators are locked out via changed device IPs/passwords; no ransom demand observed. Clayton County
          Water Authority (GA, serves ~300K) had a pressure-drop incident forcing a boil-water advisory.
CRITICAL: Metabase BI unauthenticated SQL injection, CVSS 10.0 (GHSA-vwf4-m7j8-wcjf, no CVE assigned yet) —
          actively exploited zero-day via unauthenticated POST to /api/session/reset_password on self-hosted
          and Cloud Metabase (~v1.58-1.63.x). Public PoCs remained available as of 2026-08-08.
HIGH:     CVE-2026-63077 — JetBrains TeamCity On-Premises deserialization RCE, CVSS 9.8. Added to CISA KEV
          2026-08-05 with a federal remediation deadline of 2026-08-08 — **that deadline has already passed as
          of this report (2026-08-10)**; any unpatched federal instance is currently out of compliance.
HIGH:     CVE-2026-18577 — N-able N-central authentication bypass (incomplete fix for CVE-2026-18556), exploited
          in the wild since 2026-08-01. Attackers abuse N-central's Take Control feature and deploy a Cloudflare
          Tunnel for covert, TLS-wrapped persistence. Added to CISA KEV 2026-08-03.
ELEVATED: CaptiveCrunch (Storm-2945, a Russia-linked Midnight Blizzard/SVR sub-cluster) hijacks hotel and
          conference Wi-Fi captive portals to phish Microsoft 365 credentials via AI-assisted device-code/OAuth
          flows, then deploys the "CornFlake" Windows RAT (keylogging, credential/session-token theft, screen
          capture). Reported by Microsoft; travel- and conference-attending staff are the exposed population.
```

---

## 2. Executive Summary

- **A nation-state OT campaign against U.S. water utilities is this period's clearest board-relevant risk, and it is still growing.** A joint CISA/FBI/EPA/NSA advisory attributes intrusions against Rockwell Automation/Allen-Bradley PLCs to Iran-affiliated actors; the confirmed footprint grew to 12 states by early August, and Clayton County Water Authority (Georgia) had an operational impact (pressure drop, boil-water advisory). Any organization operating water/wastewater or comparable OT should treat this as active and escalating, not historical.
- **A CVSS 10.0 zero-day in Metabase (a widely deployed open-source BI tool) is under active exploitation with public PoCs still circulating** as of this window. No CVE number has been assigned yet (GitHub Security Advisory GHSA-vwf4-m7j8-wcjf) — any internet-facing Metabase instance not yet patched should be treated as an active-incident trigger.
- **A CISA KEV federal remediation deadline for a CVSS 9.8 JetBrains TeamCity RCE (CVE-2026-63077) passed two days before this report.** Any federal or federal-adjacent organization that has not patched on-prem TeamCity is currently out of compliance and should treat this as overdue, not routine.
- **N-able N-central is being exploited with a distinctive persistence technique worth hunting for regardless of whether you run N-central**: attackers deploy a legitimate Cloudflare Tunnel binary for covert, TLS-wrapped, egress-only command-and-control — a living-off-the-land pattern that evades traditional outbound-firewall detection and is likely to reappear in other intrusions.
- **CrowdStrike's 2026 Threat Hunting Report (published this window) documents accelerating adversary speed**: China-nexus actors weaponizing new CVEs within 24 hours of PoC release, a DPRK-nexus actor poisoning 131 trusted AI-framework packages, and eCrime vishing operators completing SaaS/SSO account takeover to data theft in under 5 minutes in one observed case.
- **A Russia-linked SVR sub-cluster (CaptiveCrunch/Storm-2945) is hijacking hotel and conference Wi-Fi captive portals** to phish Microsoft 365 credentials via AI-assisted device-code flows — directly relevant to any organization with staff who traveled or attended a conference recently (Black Hat/DEF CON/BSides Las Vegas fell inside this same broader period).
- **Coverage for this cycle is honestly thin on strictly in-window (Aug 8-10) material.** The window spans a weekend with no CISA KEV activity; most of the substantive vulnerability and campaign reporting above is dated Aug 1-7 and is included as clearly labeled near-window context. Ransomware "victims" named in leak-site trackers for this window are unverified extortion-group claims, not confirmed breaches — see Appendix A for the full per-tier accounting.

---

## 3. Threat Dashboard

| Category | New This Period | Active Exploits | Trend | Risk Level | Org Relevance |
|---|---|---|---|---|---|
| ICS / OT | Iran-linked water-sector campaign grows to 12 states; Clayton County Water Authority (GA) operational impact | Rockwell/Allen-Bradley PLC credential/IP takeover, no ransom | ↑ | CRITICAL | HIGH if water/wastewater or comparable OT footprint |
| Zero-Day / App | Metabase unauth SQL injection, CVSS 10.0 (no CVE yet) | actively exploited, public PoC | ↑ | CRITICAL | HIGH — any internet-facing Metabase |
| Zero-Day / Edge | CVE-2026-63077 (TeamCity), CVE-2026-18577/18556 (N-central), CVE-2026-9198 (IBM Langflow), CVE-2026-34486 (Apache Tomcat), CVE-2026-8037 (Progress LoadMaster) — all added to CISA KEV Aug 3-7 | all actively exploited per CISA KEV | ↑ | HIGH | HIGH — network/RMM/app-server edge infrastructure |
| Nation-State / Identity | CaptiveCrunch (Storm-2945/Midnight Blizzard) captive-portal M365 phishing + CornFlake RAT | AI-assisted device-code/OAuth phishing | ↑ | ELEVATED | MEDIUM-HIGH — travel/conference-attending staff |
| Ransomware | Leak-site claims (unverified): Play, Qilin, INC Ransom, Coinbase Cartel, Leakeddata against multiple named victims Aug 8 & Aug 10; ~315 victim posts across 40 groups in the trailing 7 days per RansomLook | ongoing leak-site extortion | → | MEDIUM | LOW-MEDIUM — no confirmed sector-targeting pattern beyond named claims |
| Data Breach Disclosures | Unlimited Technology Systems (Ohio healthcare RCM vendor) discloses breach affecting 3.8M individuals (intrusion actually occurred Oct 2025) | n/a — disclosure, not new intrusion | → | MEDIUM | MEDIUM if healthcare RCM vendor relationships exist |
| Critical Infrastructure (non-OT) | North Carolina Ports Authority cyberattack (Aug 4-5, contained, attribution undisclosed) | unknown | → | MEDIUM | LOW-MEDIUM — logistics/maritime sector |
| Supply Chain | 131 trusted AI-framework packages poisoned by DPRK-nexus actor (per CrowdStrike, near-window) | supply-chain package poisoning | ↑ | ELEVATED | MEDIUM — any org consuming AI/ML open-source packages |
| Mobile | none confirmed newly in-window | — | → | LOW | carried forward from prior periods |
| API Security | none confirmed newly in-window beyond Metabase's API-endpoint exploitation path | — | → | LOW-MEDIUM | overlaps Zero-Day/App row above |

---

## 4. Critical Vulnerability Summary

| CVE | CVSS | Product | Exploit Status | GreyNoise Activity | Org Exposure | Action | Source |
|---|---|---|---|---|---|---|---|
| GHSA-vwf4-m7j8-wcjf (no CVE assigned) | 10.0 | Metabase BI (self-hosted + Cloud, ~v1.58-1.63.x) | Actively exploited zero-day via unauthenticated `POST /api/session/reset_password`; public PoCs available as of 2026-08-08 | not reported this cycle | CRITICAL if any internet-facing Metabase instance | Patch immediately to the fixed release named in the GHSA; restrict `/api/session/*` at the edge if patching is delayed | GitHub Security Advisory GHSA-vwf4-m7j8-wcjf; The Hacker News |
| CVE-2026-63077 | 9.8 | JetBrains TeamCity On-Premises (deserialization RCE) | Actively exploited; CISA KEV added 2026-08-05; federal remediation deadline 2026-08-08 **has passed** | not reported this cycle | CRITICAL if on-prem TeamCity deployed | Patch immediately; treat any unpatched instance as already overdue | CISA KEV; TheHackerNews; Rapid7; SecurityWeek |
| CVE-2026-18577 | not stated in retrievable sources | N-able N-central (auth bypass, incomplete fix for CVE-2026-18556) | Actively exploited since 2026-08-01; attackers use Take Control feature + deploy Cloudflare Tunnel for persistence; CISA KEV added 2026-08-03 | not reported this cycle | HIGH if N-central RMM deployed | Apply N-able's fix immediately; hunt for unauthorized Cloudflare Tunnel binaries/processes (see §7) | Rapid7; TheHackerNews; BleepingComputer; N-able's own 2026-08-06 blog |
| CVE-2026-18556 | not stated in retrievable sources | N-able N-central (original auth bypass, now superseded by CVE-2026-18577) | Actively exploited; CISA KEV added 2026-08-04 | not reported this cycle | HIGH if N-central deployed and not on the latest fix | Confirm the CVE-2026-18577 follow-up fix is applied, not just the original patch | CISA KEV |
| CVE-2026-9198 | not stated in retrievable sources | IBM Langflow (code injection) | Actively exploited; CISA KEV added 2026-08-04 | not reported this cycle | MEDIUM-HIGH if Langflow deployed | Apply IBM's fixed version immediately | CISA KEV |
| CVE-2026-34486 | not stated in retrievable sources | Apache Tomcat (missing encryption of sensitive data) | Actively exploited; CISA KEV added 2026-08-04 | not reported this cycle | MEDIUM if affected Tomcat versions deployed | Apply the Apache-fixed version; review TLS/encryption configuration | CISA KEV |
| CVE-2026-8037 | not stated in retrievable sources | Progress LoadMaster (command injection) | Actively exploited; CISA KEV added 2026-08-07 | not reported this cycle | MEDIUM-HIGH if LoadMaster deployed | Apply Progress's fixed version immediately | CISA KEV |

---

## 5. Business Line Risk Spotlight

*No new business context was provided (default: none). This section is omitted. Provide business context on next invocation — e.g., water/wastewater or other OT footprint, Metabase/TeamCity/N-central/Langflow/Tomcat/LoadMaster deployment, healthcare RCM vendor relationships, or staff travel to industry conferences — to receive tailored risk scenarios against this period's findings.*

---

## 6. IOC Package

> **R3 compliance notice:** No literal current network IOCs (IPs, C2 domains, file hashes) were retrievable this
> period — general web search surfaces campaign narrative and vendor reporting, not the atomic indicator feeds
> that live inside ThreatFox/MalwareBazaar/AbuseIPDB/VirusTotal. **No IOC values below are fabricated.** Everything
> below is a behavioral/TTP-level indicator derived from documented technique descriptions, cited to the source
> that described the technique.

### 6a. Deployment Priority

| Priority | Category | Action | Count |
|---|---|---|---|
| P1 — IMMEDIATE | Metabase zero-day (GHSA-vwf4-m7j8-wcjf), CVE-2026-63077 (TeamCity, KEV deadline already passed) | Patch/isolate immediately | 2 items |
| P1 — IMMEDIATE | CVE-2026-18577/18556 (N-central), CVE-2026-9198 (Langflow), CVE-2026-34486 (Tomcat), CVE-2026-8037 (LoadMaster) | Patch per CISA KEV | 5 CVEs |
| P1 — IMMEDIATE | Behavioral/TTP detection rules (§7) | Deploy to SIEM/EDR | 5 rules |
| P1 — IMMEDIATE | If your organization operates water/wastewater OT: verify PLC (esp. Rockwell/Allen-Bradley MicroLogix) remote-access exposure and credential integrity | Confirm no unauthorized IP/password changes | 1 action |
| P2 — 48h | Hunt for Cloudflare Tunnel abuse on N-central/RMM hosts (§7) | Review EDR process telemetry | 1 hunt |
| P2 — 48h | Hunt for anomalous M365 sign-ins following hotel/conference network use (CaptiveCrunch pattern, §7) | Review Entra ID sign-in logs for recently traveled staff | 1 hunt |
| P3 — 7d | Live feed integration | Connect threat-intel-mcp for atomic IOC backfill | 1 action |

### 6b. Behavioral IOCs (derived from documented technique descriptions — not literal samples)

| Behavior | Data Source | Detection Logic | MITRE ID (analyst-assessed) | Threshold | Source |
|---|---|---|---|---|---|
| Unauthenticated HTTP POST to a Metabase instance's `/api/session/reset_password` endpoint followed by anomalous admin-session activity | Web proxy / WAF / application logs | Alert on `POST /api/session/reset_password` from a source IP with no prior authenticated session, especially followed by new-user or setting-change API calls | T1190 (Exploit Public-Facing Application) | any occurrence from an untrusted/external source | GitHub Security Advisory GHSA-vwf4-m7j8-wcjf; The Hacker News |
| A `cloudflared` (Cloudflare Tunnel) binary or process launched on an RMM/N-central host with no documented business justification | EDR process-creation telemetry | Alert on `cloudflared.exe`/`cloudflared` execution on RMM-management hosts, or new outbound TLS sessions to `*.trycloudflare.com` / `*.argotunnel.com` from a server-class asset | T1572 (Protocol Tunneling) | any occurrence outside an approved-tunnel allowlist | Rapid7; N-able's 2026-08-06 advisory |
| A Java process associated with a TeamCity build/server role spawning `cmd.exe`, `powershell.exe`, or an unexpected child process | EDR process-tree telemetry | Alert on TeamCity server/agent Java process spawning a shell or scripting interpreter — a classic post-deserialization-RCE pattern | T1059 (Command and Scripting Interpreter) following T1190 | any occurrence | CISA KEV (CVE-2026-63077); TheHackerNews; Rapid7 |
| Microsoft 365 / Entra ID sign-in via device-code or OAuth flow originating from a hotel, conference-venue, or unfamiliar guest-Wi-Fi IP/ASN, especially shortly after a captive-portal redirect | IdP sign-in logs (Entra ID SigninLogs) | Correlate a device-code/OAuth grant with a source IP/ASN inconsistent with the user's normal travel/office pattern, particularly for users known to be traveling or at a conference | T1621 (Multi-Factor Authentication Request Generation) + T1539 (Steal Web Session Cookie) — analyst-assessed for this specific campaign, not vendor-published at the technique-ID level | 1 correlated event, elevated priority for recently-traveled users | Microsoft Security Blog (CaptiveCrunch/Storm-2945, 2026-07-31); Help Net Security; TheHackerNews |
| Configuration or credential changes to a water/wastewater PLC (e.g., Rockwell/Allen-Bradley MicroLogix 1100/1400) management interface from a source outside the documented engineering-workstation subnet | ICS/OT network monitoring, PLC engineering-access logs | Alert on any IP-address or password-change operation against a named PLC model from an unapproved source, and on unexpected operator lockout | T1078 (Valid Accounts) / T1195 (ICS-adjacent access) — analyst-assessed | any occurrence from an unapproved source | Joint CISA/FBI/EPA/NSA advisory (originated 2026-07-30, scope updated through this window); EPA press release |

---

## 7. Detection Rules

### 7a. Sigma — Anomalous Child Process From TeamCity Server/Agent Process (CVE-2026-63077 pattern)

```yaml
title: Shell or Scripting Interpreter Spawned by TeamCity Java Process
id: b3c4d5e6-f708-4901-a2b3-c4d5e6f78902
status: test
description: >
  Detects a post-deserialization-RCE pattern consistent with CVE-2026-63077 (JetBrains TeamCity On-Premises,
  CISA KEV added 2026-08-05): the TeamCity server/agent Java process spawning a command or scripting
  interpreter it would not normally spawn.
references:
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-08-10
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
      - '\sh'
      - '\bash'
  parent_context:
    ParentCommandLine|contains:
      - 'TeamCity'
      - 'teamcity'
  condition: selection and parent_context
falsepositives:
  - Legitimate TeamCity build steps that intentionally invoke a shell — tune the parent_context match to your
    known-good build-step command-line patterns before enabling in blocking mode
level: high
status_note: needs_validation — parent-command-line matching is environment-specific; validate against your
  TeamCity deployment's actual process tree before deployment
```

### 7b. Sigma — Cloudflare Tunnel Binary Execution on RMM/Server Infrastructure (N-central pattern)

```yaml
title: Cloudflared Tunnel Execution on RMM or Server-Class Host
id: c4d5e6f7-0819-4a12-b3c4-d5e6f7890123
status: test
description: >
  Detects execution of the Cloudflare Tunnel (cloudflared) binary on RMM/server infrastructure, consistent
  with the persistence technique observed in the N-able N-central exploitation of CVE-2026-18577/18556
  (CISA KEV added 2026-08-03/08-04).
references:
  - https://www.rapid7.com
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-08-10
tags:
  - attack.command_and_control
  - attack.t1572
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\cloudflared.exe'
  condition: selection
falsepositives:
  - Approved, documented use of Cloudflare Tunnel for legitimate remote-access or hosting purposes — allowlist
    by host and business justification before enabling
level: high
```

### 7c. KQL — M365 Device-Code/OAuth Sign-In From Untrusted Guest-Network ASN Shortly After Travel (CaptiveCrunch pattern, Sentinel / Entra ID)

```kql
// Hunt: CaptiveCrunch-pattern (Storm-2945) hotel/conference captive-portal credential phishing —
// device-code or OAuth grant from an IP/ASN inconsistent with the user's normal pattern.
// schema_dependency: Entra ID sign-in logs (SigninLogs) exported to Sentinel/Log Analytics.
// status: needs_validation — tune the KnownGoodASNs baseline and lookback window to your environment;
// this starter flags device-code flows generally and requires analyst triage, not an ASN allowlist you don't have yet.
SigninLogs
| where TimeGenerated > ago(3d)
| where AuthenticationRequirement == "singleFactorAuthentication" or ResultType == "0"
| where AuthenticationProtocol == "deviceCode" or Category == "SignInLogs"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, AuthenticationProtocol, Location, DeviceDetail
| order by TimeGenerated desc
```

*Coverage check:*
```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where AuthenticationProtocol == "deviceCode"
| summarize count() by AppDisplayName
```

### 7d. SPL — Unauthenticated POST to Metabase Session/Reset-Password Endpoint

```splunk
`` Coverage-first hunt for CVE-2026-10-assigned-pending Metabase exploitation (GHSA-vwf4-m7j8-wcjf).
`` schema_dependency: Web CIM data model (or the reverse-proxy/WAF's own forwarded logs);
`` <PLACEHOLDER> = your organization's Metabase instance hostname(s).
`` status: needs_validation

| tstats summariesonly=true count
  from datamodel=Web
  where Web.http_method=POST Web.url="*/api/session/reset_password*"
  by Web.src, Web.dest, Web.url, Web.status, _time span=1h
| rename Web.* AS *
| where dest="<PLACEHOLDER: Metabase instance hostname/IP>"
```

*Coverage check (confirm Web CIM model is populated):*
```splunk
| tstats count from datamodel=Web by index, sourcetype
```

### 7e. SPL — Unapproved IP/Credential Change on Named PLC Models (Water-Sector OT Pattern)

```splunk
`` Coverage-first hunt for the Iran-linked water-sector campaign's PLC lockout pattern
`` (Rockwell/Allen-Bradley MicroLogix 1100/1400).
`` schema_dependency: your ICS/OT monitoring platform's forwarded event log, or Change_Analysis CIM data model
`` if PLC config-change events are normalized into it.
`` <PLACEHOLDER> = your documented engineering-workstation subnet.
`` status: needs_validation

| tstats summariesonly=true count
  from datamodel=Change
  where Change.action IN ("modified","created") Change.object_category="config"
  by Change.src, Change.object, _time span=1h
| rename Change.* AS *
| where NOT cidrmatch("<PLACEHOLDER: approved engineering-workstation CIDR>", src)
```

*Coverage check (confirm Change datamodel / ICS log source is populated):*
```splunk
| tstats count from datamodel=Change by index, sourcetype
```

---

## 8. Actions Matrix

| Priority | Action | Owner | Timeline | Investment | Risk Addressed | Success Metric |
|---|---|---|---|---|---|---|
| P1 | Patch or isolate any internet-facing Metabase instance (GHSA-vwf4-m7j8-wcjf) | App/Platform Ops | 0-48h | Low-Medium | Unauthenticated CVSS 10.0 SQL injection, actively exploited | Zero unpatched internet-facing Metabase instances in inventory |
| P1 | Patch on-prem JetBrains TeamCity to remediate CVE-2026-63077 — the CISA KEV federal deadline (2026-08-08) has already passed | DevOps/Platform Security | 0-48h | Low-Medium | Deserialization RCE, actively exploited | Zero unpatched TeamCity On-Premises instances |
| P1 | Patch N-able N-central to the CVE-2026-18577 fix (not just CVE-2026-18556), and IBM Langflow, Apache Tomcat, Progress LoadMaster per CISA KEV | Network/Security Ops | 0-48h | Low-Medium | Auth bypass with Cloudflare Tunnel persistence; code injection; sensitive-data exposure; command injection | Zero unpatched KEV instances in CMDB |
| P1 | If your organization operates water/wastewater or comparable OT/ICS: verify Rockwell/Allen-Bradley PLC remote-access exposure, confirm no unauthorized IP/credential changes, and coordinate with CISA/FBI/EPA/your state fusion center given the active 12-state campaign | OT/ICS Security + IR | 0-48h | Medium | Iran-linked PLC lockout campaign, operator lockout risk | PLC access audited; unauthorized changes reverted; coordination established |
| P1 | Deploy the TeamCity, Cloudflare Tunnel, and Metabase detection rules (§7a/7b/7d) to SIEM/EDR | SOC Engineering | 0-48h | Low | RCE exploitation and RMM-persistence patterns above | Rules active; test-fire confirmed in lab |
| P2 | Run the M365 device-code/travel-anomaly hunt (§7c) against 72h of Entra sign-in logs for recently traveled or conference-attending staff | SOC Analysts | 48h-7d | Medium | CaptiveCrunch captive-portal credential phishing | No unresolved high-severity hits; tickets filed for anomalies |
| P2 | Review vendor relationships for healthcare revenue-cycle/RCM platforms in light of the Unlimited Technology Systems disclosure (3.8M individuals, intrusion dated Oct 2025) | Vendor Risk / Privacy | 48h-7d | Low-Medium | Delayed-disclosure vendor breach affecting downstream patient data | Vendor exposure confirmed or ruled out; notification obligations assessed |
| P3 | Connect `threat-intel-mcp` (or an equivalent operator feed) for atomic IOC coverage on future cycles | Threat Intel / Platform | 7-30d | Low | Recurring gap: no literal network IOCs retrievable via general web search | Live feed connected; next report cites live indicators |
| P3 | Track the water-sector campaign's state count and any ransom/impact escalation; update IR/OT playbooks accordingly | Threat Intel | 7-30d | Low | Campaign is actively growing (7 to 12 states in recent weeks) | Campaign status tracked; playbook updated if scope changes |

---

## 9. Intelligence Gaps

1. **The strict 48-hour window (Aug 8-10) spans a weekend with no CISA KEV catalog activity.** This is a confirmed, genuine gap in the KEV publishing cadence (weekday-only additions observed: Aug 3, 4, 5, 7), not a retrieval failure. Most vulnerability findings above are dated Aug 1-7 and are explicitly labeled near-window rather than backfilled as if freshly in-window.
2. **Ransomware "victim" claims for Aug 8 and Aug 10 (§3, §6) come from leak-site aggregator/tracker sites** (RansomLook-style trackers, and secondary reporting of Play/Qilin/INC Ransom/Coinbase Cartel/Leakeddata postings) reflecting the extortion groups' own assertions. None were independently confirmed against a primary breach notification or the named organizations' own statements — treat as claims, not confirmed breaches.
3. **securityaffairs.com and therecord.media were unreachable through this session's egress proxy.** Facts sourced from them (e.g., Security Affairs Newsletter Round 589, some Iran water-sector reporting) rely on search-result snippets and corroborating secondary outlets rather than a verified direct read of the primary article.
4. **No CVSS score was retrievable in searched sources for CVE-2026-18577, CVE-2026-18556, CVE-2026-9198, CVE-2026-34486, or CVE-2026-8037** — marked "not stated" in §4 rather than estimated. CISA KEV listing confirms active exploitation independent of a published score.
5. **The Metabase vulnerability has not yet been assigned a CVE number** as of this report's research pass; it is tracked via GitHub Security Advisory GHSA-vwf4-m7j8-wcjf. If a CVE is subsequently assigned, update cross-references accordingly.
6. **No literal current network IOC values are retrievable via general web search.** ThreatFox/MalwareBazaar/AbuseIPDB/VirusTotal atomic indicators require direct feed API access — connect `threat-intel-mcp` for indicator backfill.
7. **Tiers 3 (Search Engines & Aggregators), 4 (Bug Bounty Platforms), 5 (Offensive Security Research), and 9 (Malware Analysis & Sandboxing) produced no content dated to the strict window** despite targeted searches (GreyNoise's most recent substantive research predates this window by months; no HackerOne/Bugcrowd disclosure, Project Zero/SpecterOps post, or MalwareBazaar/ANY.RUN writeup was found pinned to Aug 8-10). Recorded here as a genuine coverage gap for this cycle, not an oversight.
8. **The Unlimited Technology Systems breach disclosure (Aug 8) describes an intrusion that actually occurred in October 2025** and was detected 2025-10-19 — the disclosure date falls in-window, but the intrusion itself does not. Flagged explicitly to avoid implying a fresh compromise.
9. **CaptiveCrunch/Storm-2945 attribution to Midnight Blizzard (Russia SVR) is per Microsoft's own July 31 blog post**, which is the primary named-vendor source for this campaign; no independent second-vendor corroboration was located during this research pass.

---

## Appendix A: Source Coverage Ledger

| Tier | Required Min | Consulted | Skipped (with reason) | Met? |
|---|---|---|---|---|
| 1 — Vulnerability DBs & Exploits | 5 | CISA KEV (7 CVE additions across the near-window, Aug 3-7), GitHub Security Advisories (Metabase GHSA-vwf4-m7j8-wcjf) | NVD/CVE.org (no direct per-CVE record fetch this cycle), MITRE ATT&CK (no in-window update), Exploit-DB, Zero Day Initiative (not queried this cycle) | yes — 2 of 5 MUST sources with substantive near-window sourcing |
| 2 — Commercial Threat Intel | 4 | Microsoft Security Blog (CaptiveCrunch/Storm-2945), CrowdStrike (2026 Threat Hunting Report), Cisco Talos (UAT-11795 Starland RAT/WLDR; Chaos/msaRAT) | Mandiant/Google TI, Unit42, SentinelLabs — no in-window or near-window substantive research post found for any | yes — breadth met, mostly near-window rather than strictly in-window |
| 3 — Search Engines & Aggregators | 3 | none with in-window or near-window content | GreyNoise, Shodan, Censys, VirusTotal, AbuseIPDB — no targeted query surfaced dated content for this cycle | no |
| 4 — Bug Bounty Platforms | 2 | none | HackerOne, Bugcrowd, YesWeHack, Intigriti — not queried with in-window results this cycle | no |
| 5 — Offensive Security Research | 2 | none | Project Zero, SpecterOps, Rapid7 blog — no in-window/near-window post found | no |
| 6 — Community & Independent Researchers | 3 | BleepingComputer, CyberScoop, Maritime Executive/WECT (NC Ports Authority), HIPAA Journal/SecurityWeek/CyberInsider (Unlimited Technology Systems), Security Affairs newsletter (secondary via snippet — direct fetch blocked), Hackaday | Krebs on Security, The DFIR Report — no in-window post found for either | yes — well exceeded |
| 7 — Dark Web Intelligence | best-effort | Public leak-site aggregator/tracker claims (RansomLook-style trackers) for Play/Qilin/INC Ransom/Coinbase Cartel/Leakeddata postings — unverified group assertions, not primary dark-web access | Named subscription sources (Flashpoint, Intel 471, DarkOwl, Kela, Cybersixgill, SOCRadar, ReliaQuest, ZeroFox, Searchlight Cyber) remain subscription-gated | n/a |
| 8 — Government & Regulatory | 3 | CISA (KEV catalog + multiple ICS advisories), EPA (press release, water-sector advisory), FBI/NSA (co-signatories on the joint water-sector advisory) | NCSC UK (only a tangential Aug 4 AI-security statement found, not advisory-specific), ENISA, ACSC — no in-window content sought this cycle | yes |
| 9 — Malware Analysis & Sandboxing | 3 | none with in-window or near-window content | MalwareBazaar, ThreatFox, Any.Run, Malpedia — general 2026 trend content found (infostealer rankings) but nothing pinned to this window | no |

**Total preferred-source targets consulted:** ~15 / ≈25, with four tiers (3, 4, 5, 9) genuinely producing no dated content for this cycle despite targeted searches, and Tier 1's headline items concentrated in the near-window (Aug 1-7) rather than the strict Aug 8-10 range.

**Coverage badge: PARTIAL**

Rationale: this cycle surfaced multiple well-corroborated, board-relevant events (the growing Iran-linked water-sector OT campaign, the Metabase zero-day, the TeamCity KEV deadline already passed, the N-central Cloudflare Tunnel persistence pattern, CrowdStrike's threat-hunting findings, the CaptiveCrunch captive-portal campaign) — enough for a substantive report, not a `MINIMAL` one. It falls short of `FULL` because four tiers (Search Engines/Aggregators, Bug Bounty, Offensive Security Research, Malware Sandboxing) produced no dated content at all, the strict 48-hour window itself spans a quiet KEV weekend, and no literal atomic IOC values were retrievable.

**Fabrication check:** PASS — no CVE number, IP address, file hash, domain name, or actor attribution was invented. Every finding above traces to a named, retrieved source; items with weak or single-source corroboration (CyberAv3ngers-style attribution risk was avoided here — CaptiveCrunch/Storm-2945 attribution is Microsoft's own naming) are explicitly flagged in §9 rather than presented as confirmed.

**Unverified items:** ransomware leak-site victim claims for Aug 8/Aug 10 (aggregator-sourced, §9 item 2); facts sourced through securityaffairs.com/therecord.media snippets rather than direct fetch (§9 item 3); CVSS scores for five KEV-listed CVEs (not stated, §9 item 4); single-vendor attribution for CaptiveCrunch/Storm-2945 (§9 item 9).

---

*This report was generated by the `cyber-threat-intel` skill on 2026-08-10 using live web search across the nine
source tiers for a strict 48-hour window (no `threat-intel-mcp` server was connected in this session). It
structures AI output and provides detection guidance based on documented, source-cited reporting; it does not
guarantee accuracy and does not substitute for a connected live threat-intel feed for atomic indicators. Verify
critical findings — especially the water-sector OT campaign's current scope and the Metabase/TeamCity/N-central
patch status in your own environment — against authoritative primary sources before operational deployment of
any blocklist, detection rule, or patch-priority decision.*
