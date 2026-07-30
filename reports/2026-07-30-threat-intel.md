```
THREAT INTELLIGENCE REPORT
Generated: 2026-07-30T00:00:00Z
Coverage: PARTIAL
Time Range: 2026-07-28 to 2026-07-30
Scope: All emerging threats (default)
Persona: enterprise_soc
Assets: network edge, endpoints, mobile, APIs, payment systems
```

> **Methodology notice (read before acting on this report):**
> This run used live web search/retrieval (not a connected `threat-intel-mcp` feed — no MCP feed server was
> available in this session) to research the nine source tiers for a **strict 48-hour window, 2026-07-28 to
> 2026-07-30**. Three honest limitations apply:
> - **A 48-hour lookback is narrow.** Several tiers (search-engine/aggregator telemetry, bug bounty disclosures,
>   offensive-security research, malware-sandbox reporting) simply did not publish anything dated inside this
>   exact window during retrieval — this is stated plainly per-tier in Appendix A rather than padded with
>   older material presented as current.
> - **Direct page fetches to several primary sources were blocked (HTTP 403)** — ncsc.gov.uk, kfgo.com, and
>   others rejected direct fetch. Facts attributed to these are recovered via search-result snippets and
>   corroborating secondary reporting (BleepingComputer, The Hacker News, Infosecurity Magazine, The Register),
>   not verified full-primary-document reads.
> - **No literal current network IOC values (hashes/IPs/C2 domains) were retrievable.** Atomic-indicator feeds
>   (ThreatFox, MalwareBazaar, AbuseIPDB, VirusTotal) require direct API access, not general web search — none
>   is fabricated below (R3). One research pass initially surfaced two dark-web actor handles that could not be
>   traced back to any real source on verification; they were dropped rather than reported (see §9, item 5).
>
> **Recommended action:** Connect `threat-intel-mcp` (or operator feeds — Q-Feeds, AbuseIPDB, VirusTotal, OTX,
> Recorded Future) for literal current IOC values and Tier 3/9 telemetry; this report is strongest on the
> in-window vulnerability/campaign narrative and weakest on atomic indicators.

---

## 1. Alert Banner

```
CRITICAL: Coordinated OT cyberattack against 30+ Minnesota community water utilities (weekend of Jul 26-27,
          2026; disclosed Jul 28). Braham's treatment plant taken offline; Plymouth, South St. Paul, and Maple
          Plain reported control/communications disruption. The Register (Jul 29) reports Iran-linked
          CyberAv3ngers is suspected — NOT yet confirmed by a named security vendor. Water/wastewater OT
          exposure is the standout risk this period.
CRITICAL: CVE-2026-16812 — Arista VeloCloud Orchestrator (on-prem), unauthenticated OS command injection,
          CVSS 10.0. Actively exploited as a zero-day before patch; CISA KEV federal remediation deadline is
          TODAY (2026-07-30). Full SD-WAN management compromise with potential downstream Edge-device access.
HIGH:     CVE-2026-20316 — Cisco Secure Firewall Management Center static hard-coded credential, actively
          exploited; added to CISA KEV 2026-07-29. Allows unauthenticated low-privilege login and sensitive
          data access; Cisco notes it is chainable with other FMC bugs for privilege escalation.
HIGH:     ShinyHunters escalating vishing-driven SSO takeover (Okta/Entra/Google) against healthcare and
          med-tech organizations — Health-ISAC warning, 2026-07-29. Help-desk social engineering resets
          MFA/enrolls rogue devices, then pivots through SSO into Salesforce/M365 for extortion.
ELEVATED: TELESHIM/MIXEDKEY/BINDCLOAK — a previously undocumented three-stage malware suite (East Asia-nexus,
          unattributed) targeting Middle East governments via a signed-binary DLL side-load and Telegram Bot
          API C2 (Zscaler ThreatLabz, 2026-07-27 — at the edge of the 48h window, included for its detection
          relevance).
```

---

## 2. Executive Summary

- **A coordinated OT attack against 30+ Minnesota water utilities is this period's clearest board-relevant event.** Multiple community water systems lost automated-control visibility over the July 26-27 weekend, with Braham's plant taken fully offline. Attribution (Iran-linked CyberAv3ngers) is reported by one outlet (The Register) and is **not yet corroborated by a named security vendor or U.S. government attribution statement** — treat as a working hypothesis, not confirmed fact, while incident response continues.
- **A CISA KEV federal remediation deadline for a CVSS 10.0 zero-day lands today.** CVE-2026-16812 (Arista VeloCloud Orchestrator command injection) grants unauthenticated full control of on-prem SD-WAN management; any organization running on-prem VCO that has not patched to 5.2.3.14/6.1.3.4/6.4.2.4+/7.0.0.1 is out of federal compliance as of 2026-07-30 and should treat this as an active-incident trigger, not a routine patch item.
- **A second Cisco/Fortinet-class KEV cluster landed in the same 72 hours.** CVE-2026-20316 (Cisco Secure FMC static credential) and CVE-2025-68686 (FortiOS sensitive-information exposure) were both added to KEV within the window — edge/perimeter infrastructure continues to be the most consistently exploited asset class period over period.
- **ShinyHunters is actively escalating a healthcare-sector SSO takeover campaign.** Health-ISAC's July 29 warning describes help-desk vishing to reset MFA or enroll rogue devices, consistent with the group's July 13 OAuth/Salesloft-Gainsight abuse pattern reported by Microsoft. Any organization with an Okta/Entra/Google Workspace help-desk reset process without strong out-of-band verification is exposed.
- **A new, unattributed East-Asia-nexus malware suite (TELESHIM/MIXEDKEY/BINDCLOAK) is targeting Middle East governments** via DLL side-loading from a weaponized ISO and Telegram Bot API for C2 — a technique pattern (legitimate-service C2, signed-binary side-loading) worth hunting for regardless of sector, since both techniques are commodity-adjacent and likely to reappear against other targets.
- **A public pre-auth RCE PoC (CVE-2026-61511, vBulletin) was released July 27** against a bug patched July 1 — no confirmed active exploitation yet, but any internet-facing vBulletin forum not yet on 6.2.2 should be treated as imminently exploitable.
- **Coverage for this cycle is honestly thinner than a full weekly report.** A strict 48-hour window under-serves several tiers (bug bounty, offensive-security research, malware-sandbox telemetry, search-engine/scanner data) that simply had no new dated content in-window; see Appendix A for the per-tier accounting rather than treating this as a comprehensive sweep.

---

## 3. Threat Dashboard

| Category | New This Period | Active Exploits | Trend | Risk Level | Org Relevance |
|---|---|---|---|---|---|
| ICS / OT | Coordinated attack on 30+ MN water utilities (Braham offline) | suspected CyberAv3ngers (unconfirmed) | ↑ | CRITICAL | HIGH if water/wastewater or similar OT footprint |
| Zero-Day / Edge | CVE-2026-16812 (Arista VeloCloud), CVE-2026-20316 (Cisco FMC), CVE-2025-68686 (FortiOS) | all three actively exploited, all added to CISA KEV within 72h | ↑ | CRITICAL | HIGH — network edge/SD-WAN/firewall management |
| Cloud / Identity | ShinyHunters healthcare SSO-vishing escalation (Health-ISAC alert) | Okta/Entra/Google help-desk MFA-reset abuse | ↑ | HIGH | HIGH — any org with human-staffed identity help desk |
| APT / Nation-State | TELESHIM/MIXEDKEY/BINDCLOAK (unattributed East-Asia-nexus) vs. Middle East govts | DLL side-load + Telegram Bot API C2 | ↑ | ELEVATED | MEDIUM — technique pattern transferable beyond named targets |
| Exploit / PoC | CVE-2026-61511 vBulletin pre-auth RCE PoC published | no confirmed active exploitation yet | ↑ | ELEVATED | MEDIUM if vBulletin forums exposed |
| Ransomware | claimed victims: Malaysian Nuclear Agency (TheGentlemen/Storm-2697, low-confidence), Bretford Manufacturing (Aur0ra, confirmed via leak-site record) | ongoing leak-site extortion | → | MEDIUM | LOW–MEDIUM — no pattern evidence of sector targeting beyond named victims |
| Supply Chain | none confirmed newly in-window | — | → | LOW | carried forward from prior periods |
| Mobile | none confirmed newly in-window | — | → | LOW | carried forward from prior periods |
| API Security | none confirmed newly in-window | — | → | LOW | carried forward from prior periods |

---

## 4. Critical Vulnerability Summary

| CVE | CVSS | Product | Exploit Status | GreyNoise Activity | Org Exposure | Action | Source |
|---|---|---|---|---|---|---|---|
| CVE-2026-16812 | 10.0 | Arista VeloCloud Orchestrator (on-prem, OS command injection) | Actively exploited as zero-day; CISA KEV added 2026-07-27, **federal deadline 2026-07-30 (today)** | not reported this cycle | CRITICAL if on-prem VCO deployed | Patch to 5.2.3.14 / 6.1.3.4 / 6.4.2.4 / 7.0.0.1 immediately; audit VCO admin API exposure | The Hacker News; BleepingComputer; SecurityWeek; Security Affairs |
| CVE-2026-20316 | 5.3 (low score; high-impact pre-auth data exposure) | Cisco Secure Firewall Management Center (static hard-coded credential) | Actively exploited; CISA KEV added 2026-07-29; chainable with other FMC bugs for privilege escalation per Cisco | not reported this cycle | HIGH if Secure FMC (7.0-7.7, 10.0) deployed | Apply Cisco's fixed software immediately; no complete workaround exists | BleepingComputer; The Hacker News; CISA KEV alert (2026-07-29) |
| CVE-2025-68686 | not stated in retrievable sources | Fortinet FortiOS (exposure of sensitive information, CWE-200) | Actively exploited per CISA; added to KEV 2026-07-27 alongside CVE-2026-16812; reported to bypass a prior symlink-persistence patch | not reported this cycle | MEDIUM–HIGH if FortiOS deployed | Verify patch level against Fortinet's advisory; treat prior symlink-backdoor remediation as unverified until re-checked | Security Affairs; CISA KEV alert (2026-07-27) |
| CVE-2026-61511 | 9.8 (NVD 3.1) / 9.3 (CVSS 4.0) | vBulletin (pre-auth RCE via `vB5_Template_Runtime::runMaths()` template-math sanitization bypass) | Working PoC published 2026-07-27 by SSD Secure Disclosure; **no confirmed active exploitation** as of this report | not reported this cycle | MEDIUM if internet-facing vBulletin forum below 6.2.2 | Confirm upgrade to vBulletin 6.2.2 (released Jul 1); treat as imminently exploitable given public PoC | LatestHackingNews; The Hacker News; SecurityOnline.info |

---

## 5. Business Line Risk Spotlight

*No new business context was provided (default: none). This section is omitted. Provide business context on next invocation — e.g., water/wastewater or other OT footprint, Arista VeloCloud / Cisco FMC / FortiOS deployment, or an identity-provider help-desk process — to receive tailored risk scenarios against this period's findings.*

---

## 6. IOC Package

> **R3 compliance notice:** No literal current network IOCs (IPs, C2 domains, file hashes) were retrievable this
> period — general web search surfaces campaign narrative and vendor reporting, not the atomic indicator feeds
> that live inside ThreatFox/MalwareBazaar/AbuseIPDB/VirusTotal. **No IOC values below are fabricated.** A prior
> research pass surfaced two dark-web actor handles ("xpl0itrs", "astra_operator") in connection with a
> forum-access-auction claim; on verification neither could be traced to any real retrieved source, so **both
> are deliberately excluded** — reported here only as a caught-and-corrected fabrication risk, not as a finding
> (see §9, item 5). Everything below is a behavioral/TTP-level indicator derived from documented technique
> descriptions.

### 6a. Deployment Priority

| Priority | Category | Action | Count |
|---|---|---|---|
| P1 — IMMEDIATE | CVE-2026-16812 (Arista VeloCloud, KEV deadline today) | Patch/isolate immediately | 1 CVE |
| P1 — IMMEDIATE | CVE-2026-20316 (Cisco FMC), CVE-2025-68686 (FortiOS) | Patch per CISA KEV | 2 CVEs |
| P1 — IMMEDIATE | Behavioral/TTP detection rules (§7) | Deploy to SIEM/EDR | 4 rules |
| P2 — 48h | CVE-2026-61511 (vBulletin PoC) | Confirm patch level, treat as imminently exploitable | 1 CVE |
| P2 — 48h | ShinyHunters help-desk vishing hunt (§7) | Review identity-provider audit logs | 1 hunt |
| P3 — 7d | Live feed integration | Connect threat-intel-mcp for atomic IOC backfill | 1 action |

### 6b. Behavioral IOCs (derived from documented technique descriptions — not literal samples)

| Behavior | Data Source | Detection Logic | MITRE ID (analyst-assessed) | Threshold | Source |
|---|---|---|---|---|---|
| Legitimately signed binary (e.g. an ASUS-signed executable) loaded from a mounted ISO/optical image, followed by a heavily obfuscated sideloaded DLL | EDR process/module-load telemetry | Alert on a signed vendor binary executing from a mounted `.iso`/removable-media path with a co-located DLL not part of the vendor's normal install tree | T1574.002 (Hijack Execution Flow: DLL Side-Loading) | any occurrence outside approved software-distribution paths | Zscaler ThreatLabz — TELESHIM/MIXEDKEY reporting (via The Hacker News, 2026-07-27) |
| Outbound HTTPS traffic to `api.telegram.org` from a host/process with no legitimate business reason to use Telegram (e.g., a server, not an approved chat client) | Proxy/DNS/EDR network telemetry | Alert on `api.telegram.org` contacted by non-browser, non-approved-messaging processes, especially from server-class or internet-facing hosts | T1102.002 (Web Service: Bidirectional Communication) | any occurrence from a server-class asset | Zscaler ThreatLabz — TELESHIM C2 abuse of Telegram Bot API |
| Help-desk-initiated MFA factor reset or new device enrollment on an identity provider (Okta/Entra/Google Workspace), immediately followed by SSO access to a high-value SaaS app (Salesforce, M365) from a new/unrecognized device | IdP audit logs (Okta System Log, Entra sign-in/audit logs) | Correlate an MFA-reset or device-registration event with an SSO sign-in to a sensitive app within a short window; flag if the reset was not preceded by a verified out-of-band callback | T1656 (Impersonation) + T1098.005 (Account Manipulation: Device Registration) — analyst-assessed, not vendor-published for this specific campaign | 1 correlated event | Health-ISAC alert (2026-07-29); Microsoft Security Blog (2026-07-13, ShinyHunters OAuth background) |
| Unauthenticated or unexpected administrative-API requests to an on-prem Arista VeloCloud Orchestrator management interface from outside the approved management network | VCO application logs / network flow logs | Alert on any VCO admin-API call sourced from outside the documented management CIDR, regardless of auth outcome | T1190 (Exploit Public-Facing Application) | any occurrence from an unapproved source | The Hacker News; BleepingComputer (CVE-2026-16812 reporting) |

---

## 7. Detection Rules

### 7a. Sigma — Signed-Binary DLL Side-Load From Removable/Optical Media (TELESHIM-pattern)

```yaml
title: Signed Vendor Binary Executed From Mounted ISO With Co-Located DLL
id: f1a2b3c4-d5e6-4789-a0b1-c2d3e4f56789
status: test
description: >
  Detects the TELESHIM initial-access pattern (Zscaler ThreatLabz, 2026-07-27): a legitimately signed
  binary (observed: ASUS) executed from a mounted ISO/optical image, side-loading an obfuscated DLL that
  is not part of the vendor's normal installation tree.
references:
  - https://thehackernews.com/2026/07/teleshim-abuses-telegram-for-c2-in.html
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-07-30
tags:
  - attack.defense_evasion
  - attack.t1574.002
logsource:
  category: image_load
  product: windows
detection:
  selection:
    ImageLoaded|endswith: '.dll'
  media_mount:
    ParentImage|contains:
      - '\Device\CdRom'
      - ':\'  # optical/mounted-image drive letters vary by environment; tune to observed mount points
  condition: selection and media_mount
falsepositives:
  - Legitimate vendor installers run from officially distributed ISO images — tune to your approved software-distribution process
level: high
status_note: needs_validation — mount-path matching is environment-specific; validate against your endpoint's actual optical/virtual-media path conventions before deployment
```

### 7b. Sigma — Non-Browser Process Contacting Telegram Bot API (C2 abuse of legitimate service)

```yaml
title: Server-Class Process Contacting Telegram Bot API
id: a2b3c4d5-e6f7-4890-b1c2-d3e4f5678901
status: test
description: Detects non-approved processes (particularly server-class assets) contacting api.telegram.org, consistent with TELESHIM's C2-over-Telegram-Bot-API technique.
references:
  - https://thehackernews.com/2026/07/teleshim-abuses-telegram-for-c2-in.html
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-07-30
tags:
  - attack.command_and_control
  - attack.t1102.002
logsource:
  category: proxy
  product: null
detection:
  selection:
    dest_host: 'api.telegram.org'
  filter_approved:
    process_name|in:
      - 'chrome.exe'
      - 'msedge.exe'
      - 'TelegramDesktop.exe'
  condition: selection and not filter_approved
falsepositives:
  - Approved Telegram-based bots/integrations used for legitimate business notification workflows — allowlist by process/host before enabling
level: medium
```

### 7c. KQL — Help-Desk MFA Reset Followed by New-Device SSO to Sensitive App (Sentinel / Entra ID)

```kql
// Hunt: ShinyHunters-pattern vishing-driven SSO takeover — MFA/device-registration change
// followed by sign-in to a high-value app from a new device, within a short window.
// schema_dependency: Entra ID sign-in and audit logs (SigninLogs, AuditLogs) exported to Sentinel/Log Analytics.
// status: needs_validation — tune SensitiveApps list and the correlation window to your environment.
let SensitiveApps = dynamic(["Salesforce", "Office 365 Exchange Online", "Microsoft 365"]);
AuditLogs
| where TimeGenerated > ago(2d)
| where OperationName has_any ("Reset password", "Update user", "Register security info", "Add registered owner to device")
| project ResetTime = TimeGenerated, UserId = tostring(TargetResources[0].userPrincipalName), OperationName
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(2d)
    | where AppDisplayName has_any (SensitiveApps)
    | where DeviceDetail.trustType == "" or isempty(DeviceDetail.deviceId)
    | project SignInTime = TimeGenerated, UserId = UserPrincipalName, AppDisplayName, IPAddress
) on UserId
| where SignInTime - ResetTime between (0min .. 120min)
| project UserId, OperationName, ResetTime, AppDisplayName, SignInTime, IPAddress
```

*Coverage check:*
```kql
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName has_any ("Reset password", "Register security info")
| summarize count() by OperationName
```

### 7d. SPL — Anomalous Administrative Access to Arista VeloCloud Orchestrator Management Interface

```splunk
`` Coverage-first hunt for CVE-2026-16812 exploitation attempts against on-prem VCO.
`` schema_dependency: Network_Traffic CIM data model (or the VCO application's own forwarded logs);
`` <PLACEHOLDER> = your organization's documented VCO management CIDR.
`` status: needs_validation

| tstats summariesonly=true count
  from datamodel=Network_Traffic
  where All_Traffic.dest_port=443
  by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port, _time span=1h
| rename All_Traffic.* AS *
| where dest_ip="<PLACEHOLDER: on-prem VCO management IP>" AND NOT cidrmatch("<PLACEHOLDER: approved management CIDR>", src_ip)
```

*Coverage check (confirm Network_Traffic CIM model is populated):*
```splunk
| tstats count from datamodel=Network_Traffic by index, sourcetype
```

---

## 8. Actions Matrix

| Priority | Action | Owner | Timeline | Investment | Risk Addressed | Success Metric |
|---|---|---|---|---|---|---|
| P1 | Patch on-prem Arista VeloCloud Orchestrator to 5.2.3.14 / 6.1.3.4 / 6.4.2.4 / 7.0.0.1; the CISA KEV federal deadline is today (2026-07-30) | Network Ops + Vuln Mgmt | 0–48h | Low–Medium | CVE-2026-16812 unauthenticated RCE, full SD-WAN compromise | Zero unpatched on-prem VCO instances in CMDB |
| P1 | Patch Cisco Secure FMC and FortiOS per CISA KEV (CVE-2026-20316, CVE-2025-68686) | Network/Security Ops | 0–48h | Low–Medium | Static-credential bypass and sensitive-data exposure on edge/firewall management infrastructure | Zero unpatched KEV instances in CMDB |
| P1 | Deploy the DLL side-load and Telegram-C2 Sigma rules (§7a/§7b) to SIEM/EDR | SOC Engineering | 0–48h | Low | TELESHIM-pattern initial access and C2-over-legitimate-service | Rules active; test-fire confirmed in lab |
| P1 | If your organization operates water/wastewater or similar OT/ICS assets: verify segmentation between IT and OT networks, confirm remote-access paths to control systems are MFA-protected, and open a line to CISA/FBI/your state fusion center given the active Minnesota campaign | OT/ICS Security + IR | 0–48h | Medium | Coordinated OT attack pattern reported against water utilities | Segmentation validated; remote-access audit completed |
| P2 | Run the help-desk MFA-reset / new-device SSO hunt (§7c) against 48h of Entra/Okta audit logs | SOC Analysts | 48h–7d | Medium | ShinyHunters vishing-driven SSO takeover | No unresolved high-severity hits; tickets filed for anomalies |
| P2 | Confirm vBulletin instances are upgraded to 6.2.2 given the public PoC for CVE-2026-61511 | Web/App Ops | 48h–7d | Low | Pre-auth RCE via template-math sanitization bypass | Version confirmed ≥6.2.2 on all internet-facing instances |
| P2 | Review identity-provider help-desk reset procedures for out-of-band verification strength (callback to a pre-registered number, not a number provided during the call) | Identity/IAM Team | 48h–7d | Low–Medium | Vishing-based help-desk social engineering (ShinyHunters pattern) | Verification procedure updated and communicated to help-desk staff |
| P3 | Connect `threat-intel-mcp` (or an equivalent operator feed) for atomic IOC coverage on future cycles | Threat Intel / Platform | 7–30d | Low | Recurring gap: no literal network IOCs retrievable via general web search | Live feed connected; next report cites live indicators |
| P3 | Track attribution developments for the Minnesota water-utility attack (CyberAv3ngers is currently unconfirmed by a named vendor) and update IR playbooks accordingly | Threat Intel | 7–30d | Low | Attribution uncertainty affecting IR prioritization | Confirmed or retracted attribution logged |

---

## 9. Intelligence Gaps

1. **A strict 48-hour window is narrow by design, and it shows in the tier coverage.** Tiers 3 (Search Engines & Aggregators — GreyNoise/Shodan/Censys), 4 (Bug Bounty Platforms), and 5 (Offensive Security Research — Project Zero, SpecterOps) produced no content dated specifically inside 2026-07-28–2026-07-30 during retrieval. This is stated plainly rather than backfilled with older material presented as current.
2. **CyberAv3ngers attribution for the Minnesota water-utility attack is single-sourced (The Register) and not yet corroborated** by CISA, FBI, or a named commercial threat-intel vendor as of this report. Treat as a working hypothesis.
3. **CISA's own KEV alert pages and the specific ICS advisory pages (ICSA-26-209-01 through -07) could not be directly fetched** (HTTP 403 on some, unconfirmed content on others) — CVE additions and dates rely on multiple corroborating secondary outlets (The Hacker News, BleepingComputer, SecurityWeek, Security Affairs) rather than verified primary CISA text.
4. **No literal current network IOC values are retrievable via general web search.** ThreatFox/MalwareBazaar/AbuseIPDB/VirusTotal atomic indicators require direct feed API access — connect `threat-intel-mcp` for indicator backfill.
5. **A fabrication risk was caught and corrected during this cycle.** An earlier research pass produced two dark-web actor handles ("xpl0itrs", "astra_operator") tied to an alleged forum access-auction; on verification, neither traced to any actually-retrieved source. They are excluded from this report per R3 rather than presented as findings — flagged here as a transparency note on the research process itself.
6. **The "TheGentlemen"/Storm-2697 claim against the Malaysian Nuclear Agency rests on a leak-site aggregator (ransomware.live) that could not be independently confirmed via direct fetch.** Presented in §3 with explicit low-confidence labeling; the Aur0ra/Bretford Manufacturing claim, by contrast, was confirmed via a direct ransomware.live victim record.
7. **RAMP/Exploit.in dark-web forum activity (Tier 7) had no confirmed in-window listing.** General forum-context sources were consulted but yielded no specific, dated, sourceable finding for this period — recorded as best-effort with no result, which is the correct honest outcome for a mostly-paywalled tier, not a retrieval failure.
8. **CVSS score for CVE-2025-68686 (FortiOS) was not present in retrievable search snippets** — marked "not stated" in §4 rather than estimated.
9. **Tier 9 (Malware Analysis & Sandboxing)** had no in-window primary-source content; the closest available material (weekly ANY.RUN-derived malware rankings, loader/infostealer writeups) was dated to the week of 2026-07-20–07-26, outside the strict window, and is not included as an in-window finding.

---

## Appendix A: Source Coverage Ledger

| Tier | Required Min | Consulted | Skipped (with reason) | Met? |
|---|---|---|---|---|
| 1 — Vulnerability DBs & Exploits | 5 | CISA KEV (3 CVE additions across two alerts), SSD Secure Disclosure (vBulletin PoC), CVE identifiers cited via secondary reporting (CVE.org-style references, not direct fetch) | NVD (no direct per-CVE record fetch this cycle), MITRE ATT&CK (no in-window update — v19 is April 2026, background only), Exploit-DB (no targeted query run) | no — 2 of 5 met with direct in-window sourcing |
| 2 — Commercial Threat Intel | 4 | Zscaler ThreatLabz (TELESHIM suite, via secondary coverage), Recorded Future (Golden Chickens/TAG-195, near-window), Microsoft Security Blog (ShinyHunters OAuth background), CrowdStrike (2026 Global Threat Report, background), Cisco Talos (UAT-7810/UAT-11795, outside window), Unit42 (TheGentlemen group profile, general) | Mandiant/Google TI, SentinelLabs, Secureworks CTU, Sophos X-Ops, Trend Micro, FortiGuard, ESET, Check Point, Proofpoint — no in-window content found for any | yes — breadth met, but most items are near-window or background rather than strictly in-window |
| 3 — Search Engines & Aggregators | 3 | none with in-window content | GreyNoise, Shodan, Censys, VirusTotal, AbuseIPDB — no targeted in-window query surfaced dated content | no |
| 4 — Bug Bounty Platforms | 2 | none with in-window content | HackerOne, Bugcrowd, YesWeHack, Intigriti — no in-window disclosure surfaced | no |
| 5 — Offensive Security Research | 2 | SSD Secure Disclosure (vBulletin PoC, arguably Tier 1/5 hybrid) | Project Zero, SpecterOps, Rapid7 blog — no in-window post found | no — 1 of 2, hybrid-tier source |
| 6 — Community & Independent Researchers | 3 | BleepingComputer, The Hacker News, SecurityWeek, Security Affairs, Infosecurity Magazine, Help Net Security, GBHackers, cyberpress.org, The Register | Krebs on Security, The DFIR Report — no in-window post found for either | yes — well exceeded via SHOULD-tier sources |
| 7 — Dark Web Intelligence | best-effort | Flare, SOCRadar, KELA (general RAMP/Exploit.in context — no in-window listing confirmed) | Named subscription sources (Flashpoint, Intel 471, DarkOwl, Cybersixgill, ReliaQuest, ZeroFox, Searchlight Cyber) remain subscription-gated | n/a |
| 8 — Government & Regulatory | 3 | CISA (KEV catalog, 2 alerts), NCSC UK (guidance publication, via secondary Infosecurity Magazine — direct fetch blocked), FBI IC3 (deepfake-impersonation PSA, 2026-07-20 — at the edge of window) | NSA, ENISA, ACSC — no in-window content sought this cycle | yes |
| 9 — Malware Analysis & Sandboxing | 3 | none with in-window content | MalwareBazaar, ThreatFox, Any.Run, Hybrid Analysis, Malpedia — closest available material (ANY.RUN weekly ranking) is dated to the week prior, outside strict window | no |

**Total preferred-source targets consulted:** ~15 / ≈25, with several tiers (3, 4, 5, 9) genuinely empty for this strict 48-hour window rather than under-searched.

**Coverage badge: PARTIAL**

Rationale: this cycle surfaced multiple well-corroborated, genuinely in-window, board-relevant events (the Minnesota OT attack, three CISA KEV additions, the ShinyHunters healthcare warning, the TELESHIM malware suite at the window's edge) — enough for a substantive report, not a `MINIMAL` one. It falls short of `FULL` because four tiers (Search Engines/Aggregators, Bug Bounty, Offensive Security Research, Malware Sandboxing) produced no dated in-window content despite targeted searches, several primary-source fetches were blocked (HTTP 403), and no literal atomic IOC values were retrievable at all.

**Fabrication check:** PASS — no CVE number, IP address, file hash, domain name, or actor attribution was invented. Two dark-web actor handles surfaced by an earlier research pass were verified as untraceable to any real source and were **excluded** from this report rather than published (see §9, item 5) — this is the no-fabrication rule working as intended, not a clean pass by luck.

**Unverified items:** CyberAv3ngers attribution for the Minnesota water-utility attack (single-sourced, §9 item 2); NCSC UK guidance content (direct fetch blocked, relying on secondary reporting, §9 item 3); TheGentlemen/Storm-2697 claim against the Malaysian Nuclear Agency (leak-site aggregator only, §9 item 6); CVSS score for CVE-2025-68686 (not stated, §9 item 8).

---

*This report was generated by the `cyber-threat-intel` skill on 2026-07-30 using live web search across the nine source tiers for a strict 48-hour window (no `threat-intel-mcp` server was connected in this session). It structures AI output and provides detection guidance based on documented, source-cited reporting; it does not guarantee accuracy and does not substitute for a connected live threat-intel feed for atomic indicators. Verify critical findings — especially the Minnesota OT-attack attribution and the KEV patch deadlines — against authoritative primary sources before operational deployment of any blocklist, detection rule, or patch-priority decision.*
