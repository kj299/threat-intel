```
THREAT INTELLIGENCE REPORT
Generated: 2026-08-02T00:00:00Z
Coverage: MINIMAL
Time Range: 2026-07-31 to 2026-08-02
Scope: All emerging threats (default)
Persona: enterprise_soc
Assets: network edge, endpoints, mobile, APIs, payment systems
```

> **Methodology notice (read before acting on this report):**
> This run used live web search/retrieval (not a connected `threat-intel-mcp` feed — no MCP feed server was
> available in this session) to research the nine source tiers for a **strict 48-hour window, 2026-07-31 to
> 2026-08-02**. A direct fetch of the CISA KEV JSON feed was attempted and returned HTTP 403 (consistent with
> the egress restriction previously logged in `docs/report-runbook.md` for this environment class), so this
> cycle relies entirely on general web search rather than any direct feed connection. Four honest limitations
> apply:
> - **A 48-hour lookback is narrow, and this particular window was quiet.** Several tiers (search-engine/
>   scanner telemetry, bug bounty disclosures, offensive-security research, government/regulatory advisories)
>   produced no content dated specifically inside this exact window during retrieval. Two items that looked
>   promising on first search — a CISA joint advisory on router hygiene and a BreachForums-successor database
>   breach — were verified to be dated 2026-07-13 and 2026-01-09 respectively, **outside the window**, and are
>   excluded from findings below rather than presented as current (see §9).
> - **No literal current network IOC values (hashes/IPs/C2 domains) were retrievable.** Atomic-indicator feeds
>   (ThreatFox, MalwareBazaar, AbuseIPDB, VirusTotal) require direct API access, not general web search — none
>   is fabricated below (R3).
> - **One retrieved source (GreyNoise scanning-surge data) contained internally inconsistent dates** — it cited
>   scanning spikes on August 3, 21, and 26, which postdate this report's generation date of 2026-08-02. Rather
>   than reconcile or guess which (if any) of those dates is correct, it is **excluded entirely** from this
>   report as unreliable (see §9, item 4).
> - **This is a genuinely thinner cycle than the prior report (2026-07-30, PARTIAL).** The coverage badge below
>   reflects that honestly rather than padding the count — see Appendix A.
>
> **Recommended action:** Connect `threat-intel-mcp` (or operator feeds — Q-Feeds, AbuseIPDB, VirusTotal, OTX,
> Recorded Future) for literal current IOC values; this report is strongest on the single critical vulnerability
> disclosure in-window and weakest on breadth of corroborating tiers.

---

## 1. Alert Banner

```
CRITICAL: CVE-2026-48449 — Adobe Campaign Classic (ACC), unauthenticated incorrect-authorization RCE, CVSS
          3.1 base 10.0. No user interaction required; network-exploitable with low attack complexity. Adobe
          shipped a fix (v7: 7.4.3 build 9398) on 2026-08-01. Adobe states it is not aware of in-the-wild
          exploitation as of this report, and no public PoC has been located — treat as urgent-patch, not yet
          confirmed active exploitation.
HIGH:     AtlasRAT — a four-stage, largely in-memory RAT loader distributed via a fake "AGE Flash Player"
          installer signed with a Microsoft-themed certificate, discovered 2026-07-31 (ASEC/Malwarebytes).
          Attributed by Proofpoint to TA4922 (Chinese-speaking cybercrime cluster using HR/finance lures).
          Injects into WeChat, keylogs offline, and profiles 33 security-related processes before further
          action.
ELEVATED: Encore Enterprises, Inc. (US commercial real estate) claimed by the Crpxo ransomware-as-a-service
          group, 700GB claimed leaked — first published on ransomware.live 2026-08-02. Crpxo is a group first
          observed June 2026; this specific claim is **unverified beyond the leak-site listing** (no
          confirmation from the victim or a named IR firm as of this report).
```

---

## 2. Executive Summary

- **A CVSS 10.0 unauthenticated RCE in Adobe Campaign Classic is this period's clearest actionable event.** CVE-2026-48449 requires no authentication or user interaction and grants arbitrary code execution against any internet-reachable, unpatched ACC instance. Adobe has not confirmed in-the-wild exploitation and no public PoC was found in this search pass, but the combination of a maximum CVSS score and a marketing-automation platform that is frequently internet-facing makes this a same-day patch priority rather than a routine update.
- **A companion high-severity SQL injection (CVE-2026-48448, CVSS 8.6) in the same Adobe advisory allows arbitrary file reads** and should be patched in the same maintenance window (both are fixed in the same 7.4.3 build 9398 release).
- **A new in-memory RAT (AtlasRAT) is spreading via a trojanized "Flash Player" installer**, a technique pattern (fake legacy-software installer, signed loader, WeChat process injection, offline keylogging) worth hunting for on endpoints regardless of whether an organization has direct exposure to the TA4922 cluster's typical HR/finance lure themes.
- **A single new ransomware claim (Encore Enterprises, Crpxo group) surfaced in-window** via leak-site monitoring; it carries the appropriate caution of a single-source, unconfirmed claim from a group active for less than two months.
- **Coverage this cycle is honestly thin.** A strict 48-hour window over what appears to have been a quiet stretch produced confirmed, dated content in only about a third of the nine source tiers; two items that initially looked relevant (a CISA router-hygiene advisory, a BreachForums-successor breach) were verified to be weeks-to-months old and are excluded rather than reported as current. See Appendix A for the full per-tier accounting and the honest `MINIMAL` badge this cycle earns.
- **No literal, deployable network IOCs (IPs, hashes, domains) are included below.** This run had no connection to `threat-intel-mcp` or any authenticated feed; only behavioral/technique-level detection guidance is provided, consistent with R3 (no fabricated indicators).

---

## 3. Threat Dashboard

| Category | New This Period | Active Exploits | Trend | Risk Level | Org Relevance |
|---|---|---|---|---|---|
| Vulnerability / Enterprise App | CVE-2026-48449 (Adobe Campaign Classic, CVSS 10.0), CVE-2026-48448 (CVSS 8.6, same advisory) | not confirmed exploited in the wild as of this report; no public PoC found | ↑ (new disclosure) | CRITICAL | HIGH if Adobe Campaign Classic is internet-facing |
| Malware / Endpoint | AtlasRAT via fake Flash Player installer (TA4922) | active distribution campaign, discovered 2026-07-31 | ↑ | HIGH | MEDIUM-HIGH — endpoint/messaging-app (WeChat) targeting |
| Ransomware | Encore Enterprises, Inc. claimed by Crpxo (700GB claimed) | single unconfirmed leak-site claim | → | ELEVATED | LOW-MEDIUM — commercial real estate sector, no pattern evidence of broader sector targeting yet |
| Edge / Network | Cisco Secure FMC (CVE-2026-20316) federal remediation deadline fell within this window (2026-08-01) | carried over from the 2026-07-29 KEV addition — not a new finding this cycle | → | carried over | HIGH if Secure FMC still unpatched past the federal deadline |
| ICS / OT | none confirmed newly in-window | — | → | LOW | carried forward from prior periods |
| Cloud / Identity | none confirmed newly in-window | — | → | LOW | carried forward from prior periods |
| Supply Chain | none confirmed newly in-window (ongoing "Mini Shai-Hulud" npm/PyPI activity is from April-May 2026, outside window) | — | → | LOW | carried forward — monitor for recurrence |
| Mobile | none confirmed newly in-window | — | → | LOW | carried forward from prior periods |
| API Security | none confirmed newly in-window | — | → | LOW | carried forward from prior periods |

---

## 4. Critical Vulnerability Summary

| CVE | CVSS | Product | Exploit Status | GreyNoise Activity | Org Exposure | Action | Source |
|---|---|---|---|---|---|---|---|
| CVE-2026-48449 | 10.0 (3.1) | Adobe Campaign Classic (ACC) — incorrect authorization (CWE-863) enabling unauthenticated RCE | Not confirmed exploited in the wild per Adobe; no public PoC located this cycle | not reported this cycle (Tier-3 telemetry unavailable — see §9) | CRITICAL if ACC is internet-reachable | Patch to ACC v7: 7.4.3 build 9398 (Windows and Linux) immediately | The Hacker News (2026-08-01); Security Affairs; Tenable CVE record; GBHackers |
| CVE-2026-48448 | 8.6 | Adobe Campaign Classic — SQL injection enabling arbitrary file reads | Not confirmed exploited in the wild; same advisory as above | not reported this cycle | HIGH if ACC is internet-reachable | Apply the same 7.4.3 build 9398 fix | The Hacker News (2026-08-01); Tenable CVE record |
| CVE-2026-20316 | 5.3 (low score; high-impact pre-auth data exposure) | Cisco Secure Firewall Management Center (static hard-coded credential) | Actively exploited; CISA KEV federal remediation deadline was 2026-08-01, falling inside this report's window (KEV addition itself was 2026-07-29, outside window — carried over, not a new finding) | not reported this cycle | HIGH if Secure FMC (7.0-7.7, 10.0) still unpatched | Confirm patch applied by the 2026-08-01 deadline; escalate any instance still exposed | CISA KEV (addition 2026-07-29); prior cycle's report (2026-07-30) |

---

## 5. Business Line Risk Spotlight

*No new business context was provided (default: none). This section is omitted. Provide business context on next invocation — e.g., whether your organization runs Adobe Campaign Classic, Cisco Secure FMC, or has exposure to HR/finance-themed phishing lures — to receive tailored risk scenarios against this period's findings.*

---

## 6. IOC Package

> **R3 compliance notice:** No literal current network IOCs (IPs, C2 domains, file hashes) were retrievable this
> period — general web search surfaces campaign narrative and vendor reporting, not the atomic indicator feeds
> that live inside ThreatFox/MalwareBazaar/AbuseIPDB/VirusTotal. **No IOC values below are fabricated.**
> Everything below is a behavioral/TTP-level indicator derived from documented technique descriptions, cited to
> the vendor reporting that described them.

### 6a. Deployment Priority

| Priority | Category | Action | Count |
|---|---|---|---|
| P1 — IMMEDIATE | CVE-2026-48449 / CVE-2026-48448 (Adobe Campaign Classic) | Patch to 7.4.3 build 9398 immediately | 2 CVEs |
| P1 — IMMEDIATE | Confirm CVE-2026-20316 (Cisco FMC) remediation past the 2026-08-01 KEV deadline | Verify/patch any remaining exposed instance | 1 CVE |
| P2 — 48h | AtlasRAT behavioral detection rules (§7) | Deploy to EDR | 2 rules |
| P2 — 48h | Ransomware encryption-behavior hunt (§7) | Run against endpoint telemetry given the Crpxo claim | 1 hunt |
| P3 — 7d | Live feed integration | Connect `threat-intel-mcp` for atomic IOC backfill | 1 action |

### 6b. Behavioral IOCs (derived from documented technique descriptions — not literal samples)

| Behavior | Data Source | Detection Logic | MITRE ID (analyst-assessed) | Threshold | Source |
|---|---|---|---|---|---|
| A Delphi-compiled binary presenting itself as a "Flash Player" or similarly retired/legacy software installer, signed with a certificate impersonating a Microsoft-themed issuer, spawning a multi-stage in-memory loader chain | EDR process-creation + code-signing telemetry | Alert on any process claiming to install long-EOL software (Adobe Flash Player has been end-of-life since 2020) regardless of signature validity; flag certificate issuer/subject mismatches against known Microsoft cert templates | T1204.002 (User Execution: Malicious File), T1553.002 (Subvert Trust Controls: Code Signing) | any occurrence — Flash Player installers should not appear in a modern fleet at all | Malwarebytes, ASEC, cybersecuritynews — AtlasRAT reporting (2026-07-31) |
| Unexpected DLL injection into `WeChat.exe` (or another messaging-app process) by a non-WeChat parent process, followed by outbound TLS traffic using a non-browser TLS fingerprint | EDR process/module-load + network telemetry | Alert on module load into a messaging-app process from a parent outside that app's normal install/update tree, correlated with anomalous outbound TLS from the same process | T1055 (Process Injection), T1573.001 (Encrypted Channel: Symmetric Cryptography — reported ChaCha20 C2) | any occurrence | Malwarebytes, GBHackers — AtlasRAT C2 reporting |
| A process enumerating an unusually large, specific set of security-tool executables (AV/EDR process names) in rapid succession shortly after execution of an untrusted/unsigned-chain binary | EDR process-enumeration telemetry | Alert on a newly executed, non-inventoried binary that queries running-process lists against a security-tool allowlist within seconds of launch | T1518.001 (Software Discovery: Security Software Discovery) | any occurrence correlated with a first-seen binary | ASEC — AtlasRAT reporting (via Malwarebytes summary, 2026-07-31) |
| Rapid, bulk file-extension change / mass file-write activity consistent with ransomware encryption, on a host in a commercial-real-estate or similarly targeted vertical | EDR file-system telemetry | Alert on abnormal file-modification/rename rate per process per minute exceeding a tuned baseline, especially against document/financial-data shares | T1486 (Data Encrypted for Impact) | tune to environment baseline; start conservative and adjust after false-positive review | ransomware.live — Encore Enterprises / Crpxo claim (2026-08-02) — **unverified beyond the leak-site listing** |

---

## 7. Detection Rules

### 7a. Sigma — Fake Legacy-Software Installer Impersonating Adobe Flash Player (AtlasRAT-pattern)

```yaml
title: Process Execution Impersonating Adobe Flash Player Installer
id: b7c8d9e0-f1a2-4b3c-8d4e-5f6a7b8c9d01
status: test
description: >
  Adobe Flash Player has been end-of-life since December 2020 and should never legitimately install in a
  modern fleet. Detects process names/window titles referencing "Flash Player" installers, consistent with
  the AtlasRAT delivery campaign described by ASEC/Malwarebytes (2026-07-31).
references:
  - https://www.malwarebytes.com/blog/news/2026/07/fake-flash-player-installs-atlasrat
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-08-02
tags:
  - attack.initial_access
  - attack.t1204.002
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|contains: 'flash'
    OriginalFileName|contains: 'flash'
  condition: selection
falsepositives:
  - Legacy internal tooling that still references "flash" in its filename — verify against your software inventory before enabling in blocking mode
level: high
status_note: needs_validation — tune the string match against your endpoint telemetry's actual field names and any legitimate internal use of the term
```

### 7b. Sigma — Anomalous Module Injection Into Messaging-App Process (AtlasRAT WeChat pattern)

```yaml
title: Non-Standard Parent Process Injecting Into WeChat
id: c8d9e0f1-a2b3-4c4d-9e5f-6a7b8c9d0e12
status: test
description: Detects DLL/module injection into WeChat.exe from a parent process outside WeChat's normal install/update tree, consistent with AtlasRAT's messaging-app injection technique.
references:
  - https://cybersecuritynews.com/fake-flash-player-installer/
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-08-02
tags:
  - attack.defense_evasion
  - attack.t1055
logsource:
  category: image_load
  product: windows
detection:
  selection:
    Image|endswith: '\WeChat.exe'
  filter_approved:
    ParentImage|contains:
      - '\WeChat\'
      - '\Tencent\'
  condition: selection and not filter_approved
falsepositives:
  - Legitimate WeChat auto-update or plugin components not installed under the standard Tencent path — validate your environment's actual install tree before tuning
level: medium
```

### 7c. SPL — Ransomware-Pattern Mass File-Extension Change (Crpxo-pattern hunt)

```splunk
`` Coverage-first hunt for bulk file-rename/extension-change behavior consistent with ransomware encryption
`` (Crpxo claim against Encore Enterprises, ransomware.live, 2026-08-02 — this hunt is generic ransomware-behavior
`` detection, not specific to any Crpxo sample, since no literal Crpxo IOC was retrievable this cycle).
`` schema_dependency: Endpoint.Filesystem CIM data model.
`` status: needs_validation

| tstats summariesonly=true count
  from datamodel=Endpoint.Filesystem
  where Filesystem.action="modified"
  by Filesystem.process_name, Filesystem.dest, _time span=5m
| where count > 100
```

*Coverage check (confirm Endpoint.Filesystem CIM model is populated):*
```splunk
| tstats count from datamodel=Endpoint.Filesystem by index, sourcetype
```

### 7d. KQL — Adobe Campaign Classic Anomalous Admin/API Requests (CVE-2026-48449 / CVE-2026-48448 hunt)

```kql
// Hunt: unusual requests to an on-prem Adobe Campaign Classic instance ahead of confirming the
// 7.4.3 build 9398 patch is applied. schema_dependency: your reverse proxy / WAF logs ingested into
// a custom table, or Sentinel's normalized Web (ASIM) schema if ACC sits behind a covered proxy.
// status: needs_validation — <PLACEHOLDER> = your ACC hostname/path prefix.
_Im_WebSession(starttime=ago(2d), endtime=now())
| where Url has "<PLACEHOLDER: your ACC hostname or path prefix>"
| where HttpStatusCode >= 200 and HttpStatusCode < 300
| summarize RequestCount = count() by SrcIpAddr, Url, UrlOriginal
| where RequestCount > 50
```

*Coverage check:*
```kql
_Im_WebSession
| where TimeGenerated > ago(1d)
| summarize count() by Url
| take 20
```

---

## 8. Actions Matrix

| Priority | Action | Owner | Timeline | Investment | Risk Addressed | Success Metric |
|---|---|---|---|---|---|---|
| P1 | Patch Adobe Campaign Classic to v7: 7.4.3 build 9398 (fixes CVE-2026-48449 and CVE-2026-48448) | App/Web Ops + Vuln Mgmt | 0–48h | Low–Medium | Unauthenticated RCE (CVSS 10.0) and arbitrary file read on a marketing-automation platform | Zero unpatched ACC instances in CMDB |
| P1 | Confirm Cisco Secure FMC is patched against CVE-2026-20316; the federal KEV deadline (2026-08-01) has passed | Network/Security Ops | 0–48h | Low | Static-credential unauthenticated login bypass | Zero unpatched KEV instances in CMDB |
| P2 | Deploy the AtlasRAT behavioral Sigma rules (§7a/§7b) to EDR | SOC Engineering | 48h–7d | Low | Fake-installer initial access and messaging-app process injection | Rules active; test-fire confirmed in lab |
| P2 | Run the mass file-extension-change hunt (§7c) against 7 days of endpoint filesystem telemetry given the Crpxo claim | SOC Analysts | 48h–7d | Medium | Ransomware encryption behavior, unconfirmed Crpxo claim against Encore Enterprises | No unresolved high-severity hits; tickets filed for anomalies |
| P3 | Connect `threat-intel-mcp` (or an equivalent operator feed) for atomic IOC coverage on future cycles | Threat Intel / Platform | 7–30d | Low | Recurring gap: no literal network IOCs retrievable via general web search | Live feed connected; next report cites live indicators |
| P3 | Track whether the Crpxo/Encore Enterprises claim is independently confirmed and update the ledger accordingly | Threat Intel | 7–30d | Low | Single-source leak-site claim, not yet victim- or IR-confirmed | Confirmed or retracted claim logged |

---

## 9. Intelligence Gaps

1. **This cycle's window (2026-07-31 to 2026-08-02) was genuinely quiet relative to the prior cycle.** Tiers 3 (Search Engines & Aggregators), 4 (Bug Bounty Platforms), 5 (Offensive Security Research), and 8 (Government & Regulatory) produced no content dated specifically inside the window during retrieval. This is stated plainly rather than backfilled with older material presented as current.
2. **Two initially promising leads were verified to be stale and are excluded from findings.** A CISA/NSA/FBI/DC3 joint advisory on router hygiene against Russian FSB Center 16 targeting ("AA26-194A") was confirmed dated 2026-07-13, and a BreachForums-successor database breach was confirmed dated 2026-01-09 — both roughly three weeks to seven months outside this 48-hour window. Neither is reported as a current finding.
3. **The CISA KEV JSON feed could not be fetched directly this cycle (HTTP 403).** All CVE/KEV facts above rely on secondary reporting (The Hacker News, Security Affairs, GBHackers, Tenable's CVE record), not a verified direct read of the primary CISA feed or advisory page.
4. **A GreyNoise scanning-activity result was discarded as unreliable.** It described scanning surges against Cisco ASA and Fortinet SSL VPN dated August 3, 21, and 26, 2026 — all of which postdate this report's own generation date (2026-08-02). Rather than guess whether the underlying dates were mistyped, misindexed, or reference a different year, the entire result is excluded from this report.
5. **No literal current network IOC values are retrievable via general web search.** ThreatFox/MalwareBazaar/AbuseIPDB/VirusTotal atomic indicators require direct feed API access — connect `threat-intel-mcp` for indicator backfill.
6. **The Crpxo/Encore Enterprises ransomware claim rests on a single leak-site aggregator (ransomware.live)** that could not be independently corroborated via a named IR firm, the victim organization, or a second tracker. Presented in §1/§3/§6b with explicit unverified labeling.
7. **No confirmed in-window content was found for Tier 9 (Malware Analysis & Sandboxing) beyond the AtlasRAT reporting itself**, which is counted there but is really a Tier 2/6 vendor-blog finding republished across sandboxing-adjacent outlets rather than a raw sandbox/detonation report.
8. **A near-window item (Sekoia's ChocoPoC trojanized-PoC-repository research) was dated to approximately 2026-07-27–07-29**, just outside the strict window, and is not included as an in-window finding — noted here for awareness on the next cycle.

---

## Appendix A: Source Coverage Ledger

| Tier | Required Min | Consulted | Skipped (with reason) | Met? |
|---|---|---|---|---|
| 1 — Vulnerability DBs & Exploits | 5 | Tenable CVE record (CVE-2026-48449), CISA KEV (CVE-2026-20316, carried over — via secondary reporting, direct fetch returned HTTP 403) | NVD (no direct per-CVE record fetch this cycle), MITRE ATT&CK (no in-window update; mappings above are analyst-assessed), CVE.org (no direct fetch), Exploit-DB (no targeted query run) | no — 2 of 5 met with direct in-window sourcing |
| 2 — Commercial Threat Intel | 4 | Malwarebytes (AtlasRAT), Proofpoint (TA4922 attribution, via Malwarebytes/GBHackers summary) | ASEC (Tier 2/9 hybrid — counted under Tier 9), Zscaler, CrowdStrike, Mandiant/Google TI, Recorded Future, SentinelLabs, Secureworks CTU, Sophos X-Ops, Trend Micro, FortiGuard, ESET, Check Point — no in-window content found for any | no — 2 of 4 |
| 3 — Search Engines & Aggregators | 3 | ransomware.live (Encore Enterprises victim record) | GreyNoise (discarded as unreliable — see §9 item 4), Shodan, Censys, VirusTotal, AbuseIPDB — no targeted in-window query surfaced dated content | no |
| 4 — Bug Bounty Platforms | 2 | none with in-window content | HackerOne, Bugcrowd, YesWeHack, Intigriti — no in-window disclosure surfaced | no |
| 5 — Offensive Security Research | 2 | none with in-window content (Sekoia ChocoPoC research is near-window, 2026-07-27–07-29, excluded — see §9 item 8) | Project Zero, SpecterOps, Rapid7, SSD Secure Disclosure — no in-window post found | no |
| 6 — Community & Independent Researchers | 3 | The Hacker News, Security Affairs, GBHackers, cybersecuritynews.com | BleepingComputer, Infosecurity Magazine, Help Net Security, The Register, Krebs on Security, The DFIR Report — no in-window post found for any | yes |
| 7 — Dark Web Intelligence | best-effort | ransomware.live leak-site listing (Crpxo/Encore Enterprises — Tier 3/7 hybrid) | Named subscription sources (Flashpoint, Intel 471, DarkOwl, Cybersixgill, ReliaQuest, ZeroFox, Searchlight Cyber, KELA) remain subscription-gated; the one dark-web-forum lead found (BreachForums successor breach) was verified stale (2026-01-09) and excluded | n/a |
| 8 — Government & Regulatory | 3 | none with genuinely in-window content (CISA KEV deadline enforcement carried over from a prior addition, not a new government action this cycle; the router-hygiene joint advisory was verified stale and excluded) | CISA (no new in-window advisory found), NSA, FBI/IC3, NCSC UK, ENISA, ACSC — no in-window content sought or found this cycle | no |
| 9 — Malware Analysis & Sandboxing | 3 | ASEC (AtlasRAT technical analysis, via Malwarebytes/cybersecuritynews summary) | MalwareBazaar, ThreatFox, Any.Run, Hybrid Analysis, Malpedia — no in-window primary sandboxing content found | no — 1 of 3 |

**Total preferred-source targets consulted:** ~7 / ≈25, with six of nine tiers falling short of target for this strict 48-hour window.

**Coverage badge: MINIMAL**

Rationale: this cycle surfaced exactly one board-relevant, well-corroborated, genuinely in-window event (the Adobe Campaign Classic CVSS 10.0 disclosure), one credible endpoint-malware campaign (AtlasRAT), and one single-source ransomware claim (Crpxo/Encore Enterprises). Six of nine tiers produced no confirmed in-window content despite targeted searches, the CISA KEV feed could not be fetched directly, and two initially promising leads were caught as stale and correctly excluded rather than reported. `MINIMAL` is the honest badge for this window — not a failure to paper over (R4).

**Fabrication check:** PASS — no CVE number, IP address, file hash, domain name, or actor attribution was invented. One retrieved data point (GreyNoise scanning-surge dates) was internally inconsistent with the report's own generation date and was excluded entirely rather than reconciled by guesswork (see §9, item 4).

**Unverified items:** Crpxo/Encore Enterprises ransomware claim (single leak-site source, §1/§6b/§9 item 6); whether CVE-2026-48449 has any active in-the-wild exploitation beyond Adobe's own "not aware of" statement.

---

*This report was generated by the `cyber-threat-intel` skill on 2026-08-02 using live web search across the nine source tiers for a strict 48-hour window (no `threat-intel-mcp` server was connected in this session; a direct fetch to the CISA KEV feed returned HTTP 403). It structures AI output and provides detection guidance based on documented, source-cited reporting; it does not guarantee accuracy and does not substitute for a connected live threat-intel feed for atomic indicators. Verify critical findings — especially the Adobe Campaign Classic patch status and the unconfirmed Crpxo ransomware claim — against authoritative primary sources before operational deployment of any blocklist, detection rule, or patch-priority decision.*
