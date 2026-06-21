# THREAT INTELLIGENCE REPORT

```
Generated: 2026-06-21T00:00:00Z
Coverage: PARTIAL
Time Range: 2026-06-14 to 2026-06-21
Scope: All emerging threats — network edge, endpoints, mobile, APIs, payment systems
Persona: enterprise_soc
Format: Technical IOC Package
```

---

## ALERT BANNER

```
CRITICAL: CVE-2026-50751 — Check Point VPN authentication bypass (CVSS 9.3) actively
           exploited by Qilin ransomware affiliates since May 7, surge in June. Patch or
           disable IKEv1 immediately.

HIGH:      Microsoft June 2026 Patch Tuesday — 200 flaws, 6 zero-days including
           GreenPlasma (Windows SYSTEM priv-esc), YellowKey (BitLocker bypass), and
           the post-Tuesday RoguePlanet Microsoft Defender zero-day now public PoC.

HIGH:      Joomla JCE CVE-2026-48907 — CVSS 10.0, arbitrary code execution,
           added to CISA KEV; mass exploitation telemetry observed.

ELEVATED:  Volt Typhoon / Salt Typhoon pre-positioning confirmed inside US power, water,
           and telecom networks; CISA CI Fortify initiative active.
```

---

## 1. Executive Summary

- **Ransomware surge:** Qilin claimed 23+ victims in a 48-hour window (June 9–11) by weaponising a newly disclosed Check Point VPN zero-day (CVE-2026-50751). The group now uses Tox-protocol C2 and Linux ELF payloads against network edge appliances — expanding beyond its Windows roots. Source: Bleeping Computer, Help Net Security, Rapid7.

- **Record Patch Tuesday:** Microsoft's June 2026 update addressed 200 vulnerabilities including 6 zero-days. Three are publicly disclosed; at least one (GreenPlasma) was actively exploited pre-patch. Post-Tuesday, the RoguePlanet Defender zero-day was immediately released as a public PoC, keeping SYSTEM-level exploitation risk elevated for unpatched endpoints. Source: Bleeping Computer, ZDI.

- **CISA KEV additions (7 CVEs this period):** Cisco SD-WAN (two CVEs), Joomla JCE (CVSS 10.0), Arista EOS, Google Chromium V8, Mirasvit Magento module, and LiteSpeed cPanel plugin were all added between June 3–15. Federal patch deadline drives 3-week remediation windows for civilian agencies and sets urgency benchmarks for enterprise. Source: CISA KEV.

- **Nation-state pre-positioning:** Volt Typhoon and Salt Typhoon (PRC) maintain multi-year persistence inside US power grids, water utilities, and ISPs. Salt Typhoon's GhostSpider backdoor and lateral movement across Tier 1 ISPs affect an estimated 1 million individuals' metadata. CISA's CI Fortify initiative signals elevated readiness. Source: CISA, FBI, Microsoft Security Blog.

- **AI-enabled threats normalising:** Cisco Talos confirmed AI-assisted phishing surpassed every other initial-access method in Q1 2026. LLM-powered malware (MalTerminal, CloudZ RAT with the novel "Pheno" plugin) has crossed from PoC to active deployment. Ransomware groups are also recruiting English-speaking insiders. Source: Cisco Talos, SC Media.

- **MITRE ATT&CK v19 restructure:** Defense Evasion tactic split into Stealth and Defense Impairment in April 2026. Boot/Logon Autostart Execution (T1547) now ranks #7 in frequency. Organisations must update detection engineering to account for renamed tactic references in existing Sigma/KQL rules. Source: MITRE ATT&CK, Medium/MITRE blog.

- **Vulnerability disclosure velocity:** 2026 is breaking all prior CVE records. NIST transitioned NVD to a risk-based model on April 15 due to tripling submission volumes. Increased AI-assisted bug discovery is compressing the time from disclosure to exploit availability. Source: NVD/NIST, Black Duck.

---

## 2. Threat Dashboard

| Category | New This Period | Active Exploits | Trend | Risk Level | Org Relevance |
|---|---|---|---|---|---|
| Ransomware | Qilin surge (+23 victims 48h), The_Gentlemen (15 victims), Silent Ransom Group active | CVE-2026-50751 weaponised | Up | CRITICAL | High — network edge VPN exposure |
| APT/Nation-State | Volt Typhoon, Salt Typhoon confirmed persistence | LOTL, GhostSpider, Masol RAT | Up | HIGH | High — telecoms, energy, APIs |
| Zero-Day (OS/Platform) | 6 MS zero-days, RoguePlanet PoC released | GreenPlasma SYSTEM priv-esc, Defender exploit | Up | HIGH | High — all endpoints |
| Supply Chain | CloudZ RAT + Pheno plugin (Talos Jan–Jun 2026) | Confirmed implant | Flat | HIGH | Medium — depends on supply chain exposure |
| Cloud & API | Oracle Siebel CRM, Oracle MySQL unauthenticated network vulns | Unauthenticated HTTP exploitation | Up | HIGH | High — payment systems, APIs |
| Credential / BEC | Silent Ransom Group invoice phishing, insider recruitment | AI-assisted phishing #1 initial access | Up | HIGH | High — payment systems, executives |
| Web/CMS | Joomla JCE CVE-2026-48907 CVSS 10.0, Mirasvit Magento, LiteSpeed cPanel | KEV-listed, active exploitation | Up | CRITICAL | Medium-High — external web presence |
| Vulnerability Explosion | NVD model shift, AI-accelerated bug discovery | Record CVE volumes | Up | ELEVATED | High — patch backlog risk |

---

## 3. Critical Vulnerability Summary

| CVE | CVSS | Product | Exploit Status | GreyNoise Activity | Org Exposure | Action | Source |
|---|---|---|---|---|---|---|---|
| CVE-2026-50751 | 9.3 | Check Point Remote Access VPN / Mobile Access (IKEv1) | In the wild — Qilin ransomware affiliates | status: unverified (source inaccessible) | High — network edge VPN | Patch immediately; disable IKEv1 if unpatched | Check Point Blog; Bleeping Computer; Rapid7; Help Net Security |
| CVE-2026-48907 | 10.0 | Joomla JCE Widget Factory (Joomla CMS) | In the wild — arbitrary code execution | status: unverified | High — external web presence | Patch JCE plugin immediately; review server logs | CISA KEV; The Hacker News |
| CVE-2026-11645 | TBD | Google Chromium V8 engine | In the wild (KEV listed) | status: unverified | High — enterprise browsers | Emergency browser patch push | CISA KEV |
| CVE-2026-20245 | TBD | Cisco Catalyst SD-WAN Manager | In the wild (KEV listed) | status: unverified | High — SD-WAN edge | Cisco advisory remediation | CISA KEV |
| CVE-2026-20262 | TBD | Cisco Catalyst SD-WAN Manager | In the wild (KEV listed; path traversal) | status: unverified | High — SD-WAN edge | Apply Cisco patch; rotate credentials | CISA KEV |
| CVE-2026-7473 | TBD | Arista Extensible OS (EOS) | In the wild (KEV listed) | status: unverified | Medium — network switching fabric | Arista patch per advisory | CISA KEV |
| CVE-2026-45247 | TBD | Mirasvit Full Page Cache Warmer (Magento) | In the wild — deserialization | status: unverified | Medium — e-commerce/payment stack | Remove or patch module; audit Magento logs | CISA KEV |
| CVE-2026-54420 | TBD | LiteSpeed cPanel Plugin | In the wild — symlink following | status: unverified | Medium — shared hosting stacks | Upgrade cPanel LiteSpeed plugin | CISA KEV |
| GreenPlasma (CVE TBD) | High | Windows (all editions) | Actively exploited pre-patch; patched June 2026 PTue | status: unverified | Critical — all Windows endpoints | Deploy June PTue immediately | Bleeping Computer; ZDI |
| YellowKey (CVE TBD) | High | Windows BitLocker | Publicly disclosed; patched June 2026 PTue | status: unverified | High — encrypted endpoints | Apply June PTue; verify Secure Boot posture | Bleeping Computer |
| RoguePlanet (CVE TBD) | High | Microsoft Defender | Public PoC released post-PTue; under active research | status: unverified | Critical — all Windows endpoints with Defender | Monitor for Microsoft out-of-band; ensure Defender auto-update | Bleeping Computer |
| CVE-2026-45647 | TBD | Microsoft Defender for Endpoint | Published June 2026 (TOCTOU priv-esc) | status: unverified | High — MDE-enrolled endpoints | Apply June PTue | NVD |

> **Note:** CVSS scores marked TBD were not available in accessible sources at report time. GreyNoise query results were inaccessible (direct API access not available in this session). All GreyNoise fields: `status: unverified (source inaccessible)`.

---

## 4. IOC Package

**Pre-emission checks:** De-duplicated by value; confidence calibrated. `high` = corroborated by ≥2 independent vendor/government sources. `med` = single primary vendor source or search-summary intermediary. `low` = pattern-inferred or single indirect reference. No broad filesystem globs emitted.

### 4a. Network IOCs — Immediate Block

No specific IPs emitted: direct retrieval of the Check Point advisory IOC list was blocked (HTTP 403). Search summaries named hosting ASNs (Kaupo Cloud HK, Shock Hosting, Vultr Holdings) — not specific IPs; emitting ASN-level blocks would produce excessive false positives. Consult Check Point's published IOC bulletin directly. Recorded as gap in Appendix A per R3.

### 4b. Network IOCs — Monitor/Alert

| type | value | confidence | source | first_seen | last_seen | threat | mitre_id | action | tlp |
|---|---|---|---|---|---|---|---|---|---|
| user_agent | Tox-protocol C2 beacon (non-HTTP; TCP ephemeral port) | med | Help Net Security (via search summary of Check Point advisory) | 2026-06-09 | ongoing | Qilin ransomware C2 | T1071.001 | alert | TLP:WHITE |

### 4c. Host IOCs — Monitor/Alert

| type | value | confidence | source | threat | platform | action | detection_source |
|---|---|---|---|---|---|---|---|
| md5 | 52fda5c1b9704544f32ee98d9060e689 | med | Check Point security advisory (via search-result summary — direct source access blocked; validate before production deployment) | Qilin Linux ransomware ELF binary | Linux | alert; submit to sandbox | Endpoint EDR |
| md5 | 51d39aa39478beeac94f2d12f682ecce | med | Check Point security advisory (via search-result summary — validate before production deployment) | Qilin Linux ransomware ELF binary | Linux | alert; submit to sandbox | Endpoint EDR |

> **Important:** These MD5 hashes were extracted from a search-result summary, not the primary source document. Per R3 they are marked medium confidence. Do **not** deploy to production blocklists without verifying against the Check Point original advisory or a corroborating sandbox report.

### 4d. Behavioral IOCs

| behavior | data_source | detection_logic | mitre_id | threshold | source |
|---|---|---|---|---|---|
| IKEv1 certificate authentication without password — unexpected VPN session | VPN/firewall auth logs | Auth success with IKEv1 + certificate method but no corresponding password challenge | T1133 | Any | Check Point Blog; Rapid7 |
| Linux ELF dropper executes chmod+x then encrypts /home and /var | EDR process telemetry; FIM | Process spawning from unexpected parent executing chmod followed by recursive file rename/encrypt | T1486 | Any | Bleeping Computer; Help Net Security |
| Windows cmd.exe spawned SYSTEM from MsMpEng.exe (Microsoft Defender) | Windows Security Event Log | process_name=cmd.exe AND parent=MsMpEng.exe AND integrity_level=System | T1543 | Any | Bleeping Computer (RoguePlanet) |
| AI-crafted phishing email — invoice theme, callback lure, no attachment | Email gateway / DMARC logs | Email matching invoice subject pattern with phone number body, no attachment, external sender | T1566.001 | Any | Cisco Talos; SC Media |

### 4e. Email IOCs

| type | value | confidence | source | campaign | action |
|---|---|---|---|---|---|
| subject_pattern | ^(Invoice|Payment|Overdue|Billing)\s*#?\d{4,8}$ | med | Cisco Talos; Silent Ransom Group reporting via Bleeping Computer | Silent Ransom Group callback phishing | alert on email gateway |

### 4f. CSV Bulk Import

```csv
ioc_type,ioc_value,confidence,threat_name,threat_actor,mitre_technique,source,first_seen,last_seen,action,tlp
md5,52fda5c1b9704544f32ee98d9060e689,med,Qilin Linux Ransomware ELF,Qilin,T1486,Check Point advisory (search-summary — verify before deployment),2026-06-09,,alert,TLP:WHITE
md5,51d39aa39478beeac94f2d12f682ecce,med,Qilin Linux Ransomware ELF,Qilin,T1486,Check Point advisory (search-summary — verify before deployment),2026-06-09,,alert,TLP:WHITE
behavioral,IKEv1 cert auth without password challenge,med,CVE-2026-50751 Check Point VPN Exploit,Qilin affiliate,T1133,Check Point Blog; Rapid7,2026-05-07,,alert,TLP:WHITE
behavioral,cmd.exe spawned SYSTEM from MsMpEng.exe,high,RoguePlanet Defender Zero-Day,Unknown,T1543,Bleeping Computer,2026-06-10,,alert,TLP:WHITE
behavioral,Linux ELF chmod+x then bulk file encryption,med,Qilin ransomware payload,Qilin,T1486,Help Net Security,2026-06-09,,alert,TLP:WHITE
```

### 4g. STIX 2.1 Bundle (abbreviated)

```json
{
  "type": "bundle",
  "id": "bundle--a1b2c3d4-0001-4000-8000-threatintel2026",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--0001-qilin-linux-elf-md5a",
      "created": "2026-06-21T00:00:00Z",
      "modified": "2026-06-21T00:00:00Z",
      "name": "Qilin Linux ELF MD5 (A)",
      "description": "MD5 hash attributed to Qilin Linux ransomware ELF. Source: Check Point advisory (search-summary intermediary — validate against primary advisory before production use). Confidence: medium.",
      "pattern": "[file:hashes.MD5 = '52fda5c1b9704544f32ee98d9060e689']",
      "pattern_type": "stix",
      "valid_from": "2026-06-09T00:00:00Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 50,
      "external_references": [
        {
          "source_name": "Check Point Security Advisory CVE-2026-50751",
          "url": "https://blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol/"
        }
      ]
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--0002-rogueplanet-defender",
      "created": "2026-06-21T00:00:00Z",
      "modified": "2026-06-21T00:00:00Z",
      "name": "RoguePlanet — Microsoft Defender SYSTEM Shell Behavior",
      "description": "Behavioral indicator: Windows cmd.exe spawned at SYSTEM integrity level with parent process MsMpEng.exe. Associated with RoguePlanet zero-day PoC released post Patch Tuesday June 2026.",
      "pattern": "[process:name = 'cmd.exe' AND process:parent_ref.name = 'MsMpEng.exe']",
      "pattern_type": "stix",
      "valid_from": "2026-06-10T00:00:00Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 75,
      "external_references": [
        {
          "source_name": "Bleeping Computer — RoguePlanet zero-day",
          "url": "https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/"
        }
      ]
    }
  ]
}
```

### 4h. Delimited Batch Export

```json
{
  "delimited_batch_export": [
    {
      "mitre_id": "T1133",
      "name": "External Remote Services — Check Point VPN IKEv1 Auth Bypass",
      "fields": {
        "detection_method": "event id",
        "detection_value": "4625",
        "severity": "CRITICAL",
        "actor": "Qilin"
      },
      "source": "Check Point Blog; Rapid7; Help Net Security",
      "confidence": "med"
    },
    {
      "mitre_id": "T1543",
      "name": "Create or Modify System Process — RoguePlanet Defender SYSTEM Shell",
      "fields": {
        "detection_method": "process name",
        "detection_value": "cmd.exe",
        "severity": "CRITICAL",
        "actor": "Unknown (public PoC)"
      },
      "source": "Bleeping Computer",
      "confidence": "high"
    },
    {
      "mitre_id": "T1486",
      "name": "Data Encrypted for Impact — Qilin Linux ELF Ransomware",
      "fields": {
        "detection_method": "process name",
        "detection_value": "chmod",
        "severity": "CRITICAL",
        "actor": "Qilin"
      },
      "source": "Help Net Security; Bleeping Computer",
      "confidence": "med"
    },
    {
      "mitre_id": "T1547",
      "name": "Boot or Logon Autostart Execution — Persistence Trend",
      "fields": {
        "detection_method": "registry key",
        "detection_value": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "severity": "WARNING",
        "actor": "Multiple"
      },
      "source": "MITRE ATT&CK v19; Picus Security Top-10 2026",
      "confidence": "high"
    },
    {
      "mitre_id": "T1566.001",
      "name": "Phishing — Silent Ransom Group Invoice Callback Lure",
      "fields": {
        "detection_method": "event id",
        "detection_value": "1102",
        "severity": "WARNING",
        "actor": "UNC3753 (Silent Ransom Group)"
      },
      "source": "Cisco Talos; Bleeping Computer",
      "confidence": "med"
    }
  ]
}
```

---

## 5. TTP Mapping (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Sub-technique | Procedure | Detection Method | Data Sources | Source |
|---|---|---|---|---|---|---|---|
| Initial Access | T1133 | External Remote Services | — | Qilin affiliates exploit CVE-2026-50751 to bypass IKEv1 VPN auth; no password required | VPN auth log anomaly: certificate-only IKEv1 session without password | VPN logs; firewall auth | Check Point Blog; Rapid7 |
| Initial Access | T1566.001 | Phishing — Spearphishing Attachment | — | Silent Ransom Group sends invoice-themed emails; no attachment — victim calls back impostor IT | Email gateway subject-pattern alerting; callback phone number detection | Email logs | Cisco Talos; Bleeping Computer |
| Execution | T1059.004 | Command & Scripting: Unix Shell | — | Qilin deploys Linux ELF payload via shell after VPN breach | EDR process lineage anomaly: ELF chmod+encrypt chain | Process telemetry | Help Net Security |
| Persistence | T1547 | Boot or Logon Autostart Execution | Various | Ranked #7 in 2026 frequency — broadly used by ransomware and APT for persistence | Registry Run key / startup folder monitoring | Windows Security Event Log; Sysmon | MITRE ATT&CK v19; Picus Security |
| Stealth* | T1218 | System Binary Proxy Execution | — | Volt Typhoon uses LOTL: LOLBins (netsh, wmic, certutil) to avoid EDR detection | LOLBAS execution outside standard admin context | Process telemetry; PowerShell logs | CISA; Microsoft Security Blog |
| Privilege Escalation | T1543 | Create or Modify System Process | — | RoguePlanet exploits Defender to spawn SYSTEM shell | Event ID 4688: cmd.exe parent=MsMpEng.exe, integrity=System | Windows Security Event Log | Bleeping Computer |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials in Files | — | Volt Typhoon extracts credentials from Fortinet device configs | FIM on network device config files | Host FIM; EDR | CISA; Microsoft Security Blog |
| C2 | T1071.001 | Application Layer Protocol: Web Protocols | — | CloudZ RAT + Pheno plugin — C2 over HTTP/S | Anomalous outbound HTTPS to low-reputation/new domains | Network proxy logs; DNS | Cisco Talos blog |
| C2 | T1095 | Non-Application Layer Protocol | — | Qilin affiliate uses Tox protocol (non-HTTP TCP) for encrypted C2 | Alert on Tox peer-discovery traffic to unknown endpoints | Network flow | Help Net Security |
| Lateral Movement | T1021.001 | Remote Services: RDP | — | Nation-state actors leverage compromised ISP credentials to pivot; CVE-2026-45639 (RDP info-disc) | Logon event correlation: RDP from unexpected source IPs | Windows Event Log 4624 | NVD; CISA |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | — | Salt Typhoon exfiltrates call records and text metadata via GhostSpider backdoor | Large outbound transfers from ISP aggregation points | Netflow; DNS | CISA; FBI; Microsoft Security Blog |
| Impact | T1486 | Data Encrypted for Impact | — | Qilin Linux ELF encrypts /home and /var; double extortion | Bulk file-extension change; shadow copy deletion | FIM; EDR | Bleeping Computer; Help Net Security |

> *MITRE ATT&CK v19 (April 2026) split "Defense Evasion" into "Stealth" and "Defense Impairment" tactics. Technique IDs remain stable; update tactic labels in existing Sigma/KQL rules.

---

## 6. CWE Chaining Analysis

### Chain C-001: VPN Auth Bypass → Ransomware Encryption (CVE-2026-50751 / Qilin)

```
chain_id: C-001
name: IKEv1 Certificate Validation Bypass → Ransomware Impact
chain_type: primary_resultant
cwe_view: CWE-1000 (Research View — CanPrecede / CanFollow)
source: Check Point Blog; Rapid7; Help Net Security; Bleeping Computer

links:
  1. cwe_id: CWE-295 (Improper Certificate Validation)
     role: primary
     mitre_id: T1133
     tactic: Initial Access
     evidence: CVE-2026-50751 — logic flaw in IKEv1 certificate validation allows session
               without password; CVSS 9.3; KEV-linked
     detection_opportunity: VPN auth log — certificate-only IKEv1 session without
                             password record; SPL/KQL starter in Detection Rules
     data_source: VPN / firewall authentication logs
     source: Check Point Blog; Rapid7

  2. cwe_id: CWE-863 (Incorrect Authorization)
     role: resultant
     mitre_id: T1078
     tactic: Defense Evasion / Privilege Escalation
     evidence: Authenticated VPN session grants network access as if legitimate user
     detection_opportunity: Anomalous VPN sessions from unusual ASNs / new GeoIP
     data_source: VPN session logs; SIEM
     source: Rapid7

  3. cwe_id: CWE-284 (Improper Access Control)
     role: resultant
     mitre_id: T1486
     tactic: Impact
     evidence: Qilin ELF payload executes with acquired network privileges;
               encrypts Linux host directories (/home, /var)
     detection_opportunity: Bulk file-extension mutation; chmod chain from unexpected parent
     data_source: FIM; EDR
     source: Help Net Security; Bleeping Computer

enabling_conditions:
  - Check Point Remote Access VPN / Mobile Access configured for IKEv1
  - No MFA enforced at VPN layer
  - Linux hosts accessible post-VPN without network segmentation

ai_assist_factor: moderate
ai_assist_takeaway: >
  AI tooling likely accelerated discovery of the IKEv1 certificate-validation logic flaw.
  Defensive response: compress patch SLA for CVSS 9+ network-edge vulns to 48h; prefer
  behavioral detection over signature-only; disable IKEv1 (shared primary) to collapse
  the entire chain.

time_to_exploit:
  observed_days: <30
  trend: accelerating
  source: TechRadar; Bleeping Computer

break_points:
  - at_link: CWE-295
    control: Disable IKEv1 on all Check Point VPN gateways; enforce IKEv2 with MFA
    control_type: preventive
    mapped_mitigation: M1035 — Limit Access to Resource Over Network
    detection_telemetry: VPN gateway config audit; alert on IKEv1 session establishment

  - at_link: CWE-863
    control: Microsegment authenticated VPN users from lateral-move targets
    control_type: preventive
    mapped_mitigation: M1030 — Network Segmentation
    detection_telemetry: Unexpected east-west flows from VPN pool addresses

  - at_link: CWE-284
    control: Immutable-snapshot / offsite backup with air-gap; monitor bulk file-extension change
    control_type: corrective
    mapped_mitigation: M1053 — Data Backup
    detection_telemetry: FIM alert on bulk rename / encrypt pattern

terminal_impact: Ransomware encryption of Linux production systems; double extortion
score: 91
priority: P1-CRITICAL
confidence: high
```

### Chain C-002: Windows Defender TOCTOU → Kernel Privilege (RoguePlanet)

```
chain_id: C-002
name: TOCTOU Race in Defender → SYSTEM Privilege Escalation
chain_type: primary_resultant
cwe_view: CWE-1000 (CanPrecede)
source: Bleeping Computer; NVD (CVE-2026-45647)

links:
  1. cwe_id: CWE-367 (Time-of-Check Time-of-Use Race Condition)
     role: primary
     mitre_id: T1068
     tactic: Privilege Escalation
     evidence: CVE-2026-45647 — TOCTOU in Microsoft Defender for Endpoint;
               RoguePlanet PoC spawns SYSTEM shell via MsMpEng.exe
     detection_opportunity: Event 4688 — cmd.exe spawned from MsMpEng.exe at SYSTEM level
     data_source: Windows Security Event Log; Sysmon
     source: Bleeping Computer; NVD

  2. cwe_id: CWE-269 (Improper Privilege Management)
     role: resultant
     mitre_id: T1543
     tactic: Persistence / Impact
     evidence: SYSTEM-level shell enables arbitrary service creation, token theft, EDR disablement
     detection_opportunity: Unexpected high-integrity process tree after MsMpEng parent
     data_source: EDR; Windows Event Log
     source: Bleeping Computer

enabling_conditions:
  - Unpatched Windows endpoint (pre-June 2026 PTue)
  - Local execution capability (any standard user)

ai_assist_factor: low
time_to_exploit:
  observed_days: 0 (PoC released same day as patch)
  trend: accelerating
  source: Bleeping Computer

break_points:
  - at_link: CWE-367
    control: Deploy Microsoft June 2026 Patch Tuesday immediately; enable Defender auto-update
    control_type: preventive
    mapped_mitigation: M1051 — Update Software
    detection_telemetry: Patch compliance dashboard; WSUS/Intune deployment status

  - at_link: CWE-269
    control: Windows Defender Application Control (WDAC) — restrict SYSTEM-spawned shells
    control_type: detective
    mapped_mitigation: M1038 — Execution Prevention
    detection_telemetry: WDAC audit log; Event 4688 from MsMpEng.exe parent

terminal_impact: Unrestricted SYSTEM access — credential theft, EDR kill, lateral move
score: 85
priority: P2-HIGH
confidence: high
```

---

## 7. Detection Rules

### YARA — Qilin Linux ELF Ransomware

```yara
rule Qilin_Linux_ELF_Ransomware_Jun2026 {
    meta:
        description = "Detects behavioral pattern of Qilin Linux ELF ransomware — chmod + mass encrypt chain"
        threat       = "Qilin Ransomware"
        date         = "2026-06-21"
        reference    = "https://www.helpnetsecurity.com/2026/06/08/check-point-cve-2026-50751-qilin-ransomware/"
        tlp          = "WHITE"
        status       = "needs_validation — test in lab before production deployment"
    strings:
        $enc_ext1  = ".qilin"  ascii wide
        $enc_ext2  = ".locked" ascii wide
        $ransom1   = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $ransom2   = "README_QILIN"  ascii wide nocase
        $elf_magic = { 7F 45 4C 46 }
        $chmod_str = "chmod" ascii
        $var_path  = "/var/" ascii
        $home_path = "/home/" ascii
    condition:
        ($elf_magic at 0) and
        (1 of ($enc_ext*)) and
        (1 of ($ransom*)) and
        (1 of ($chmod_str, $var_path, $home_path))
}
```

> Status: needs_validation. Validate against an actual Qilin sample in a sandbox (MalwareBazaar / Hybrid Analysis) before production deployment.

### Sigma — Check Point VPN IKEv1 Auth Bypass

```yaml
title: Check Point VPN IKEv1 Authentication Bypass (CVE-2026-50751)
id: sigma-cp-ikev1-auth-bypass-2026
status: experimental
description: >
  Detects successful VPN session established via IKEv1 with certificate-only
  authentication — indicator of CVE-2026-50751 exploitation by Qilin affiliates.
references:
  - https://blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol/
  - https://www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751/
tags:
  - attack.initial_access
  - attack.t1133
  - cve.2026.50751
logsource:
  category: firewall
  product: checkpoint
detection:
  selection:
    event_type: "VPN_AUTH_SUCCESS"
    auth_method: "CERTIFICATE"
    protocol: "IKEv1"
  filter_expected:
    auth_method|contains: "PASSWORD"
  condition: selection and not filter_expected
falsepositives:
  - Legitimate certificate-only IKEv1 sessions (organisations should disable IKEv1 per advisory)
level: critical
```

### Sigma — RoguePlanet Defender SYSTEM Shell

```yaml
title: RoguePlanet — Microsoft Defender SYSTEM Shell Spawn
id: sigma-rogueplanet-defender-2026
status: experimental
description: >
  Detects cmd.exe spawned at SYSTEM integrity level with parent MsMpEng.exe,
  consistent with RoguePlanet zero-day PoC (post June 2026 Patch Tuesday).
references:
  - https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/
tags:
  - attack.privilege_escalation
  - attack.t1543
  - attack.t1068
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cmd.exe'
    ParentImage|endswith: '\MsMpEng.exe'
    IntegrityLevel: 'System'
  condition: selection
falsepositives:
  - Extremely rare; investigate all matches.
level: critical
```

### KQL — Sentinel ASIM — RoguePlanet Hunt

```kql
// STARTER: RoguePlanet Defender SYSTEM Shell — Sentinel ASIM ProcessEvents
// status: needs_validation
// schema_dependency: ASIM ProcessEvents (imProcessCreate / ASimProcessEventLogs)
//   Fields: TargetProcessName, ActingProcessName, TargetProcessIntegrityLevel, TimeGenerated

// --- DISCOVERY (confirm schema populated) ---
// Usage
// | where TimeGenerated > ago(7d)
// | where DataType == "ASimProcessEventLogs"
// | summarize count() by DataType, Solution

// --- DETECTION STARTER ---
imProcessCreate
| where TimeGenerated > ago(24h)
| where TargetProcessName endswith "cmd.exe"
| where ActingProcessName endswith "MsMpEng.exe"
| where TargetProcessIntegrityLevel == "System"
| project TimeGenerated, DeviceName, ActingProcessName, TargetProcessName,
          TargetProcessCommandLine, TargetUserName, TargetProcessIntegrityLevel
| order by TimeGenerated desc
// tuning: if IntegrityLevel absent, filter TargetUserName == "SYSTEM" as proxy
// false positives: extremely low — investigate all matches
// reference: https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/
```

### KQL — Sentinel — Check Point VPN IKEv1 Auth Bypass

```kql
// STARTER: CVE-2026-50751 Check Point IKEv1 Certificate-Only Auth Anomaly
// status: needs_validation
// schema_dependency: Check Point logs via CommonSecurityLog (CEF connector)

// --- DISCOVERY ---
// CommonSecurityLog
// | where TimeGenerated > ago(7d)
// | where DeviceVendor == "Check Point"
// | summarize count() by DeviceProduct, DeviceAction

// --- DETECTION STARTER ---
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Check Point"
| where DeviceAction == "Accept"
| where AdditionalExtensions has "IKEv1"
| where AdditionalExtensions has "certificate"
| where not (AdditionalExtensions has "password")
| project TimeGenerated, SourceIP, DestinationIP, DeviceAction,
          AdditionalExtensions, Activity
| order by TimeGenerated desc
// tuning: adjust field names to match your CEF mapping for Check Point logs
// reference: https://blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol/
```

### SPL — Splunk CIM Endpoint — T1547 Autostart Registry

```spl
| tstats summariesonly=false count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where Registry.registry_path="*\\CurrentVersion\\Run*"
      AND Registry.action="modified"
    by Registry.registry_path, Registry.registry_value_name,
       Registry.registry_value_data, Registry.dest, Registry.user
| rename Registry.* AS *
| eval firstTime=strftime(firstTime,"%Y-%m-%dT%H:%M:%SZ"),
       lastTime=strftime(lastTime,"%Y-%m-%dT%H:%M:%SZ")
| table dest, user, registry_path, registry_value_name, registry_value_data, firstTime, lastTime, count
| sort -lastTime
```

**status:** needs_validation. **schema_dependency:** Endpoint.Registry data model (Sysmon Event 13 or WinEventLog:Security). **Discovery:** `| tstats count from datamodel=Endpoint.Registry by index, sourcetype`. **Tuning:** baseline on known software; filter signed binaries. **Reference:** MITRE ATT&CK T1547.

### SPL — Splunk CIM Network — Qilin Tox C2 Hunt

```spl
| tstats summariesonly=false count
    from datamodel=Network_Traffic
    where NOT (Network_Traffic.dest_port=80 OR Network_Traffic.dest_port=443
               OR Network_Traffic.dest_port=53 OR Network_Traffic.dest_port=22)
      AND Network_Traffic.bytes_out > 10000
    by Network_Traffic.src_ip, Network_Traffic.dest_ip,
       Network_Traffic.dest_port, Network_Traffic.transport
| rename Network_Traffic.* AS *
| eval bytes_out_kb=round(bytes_out/1024,2)
| where count > 5
| sort -bytes_out
| head 100
```

**status:** needs_validation. **schema_dependency:** Network_Traffic data model. **Tuning:** Adjust bytes_out threshold and excluded ports. Enrich `dest_ip` against ASN for Kaupo Cloud HK / Shock Hosting / Vultr Holdings. **Reference:** Help Net Security CVE-2026-50751 IOC report.

### Snort/Suricata — CVE-2026-50751 IKEv1 Probe

```snort
alert udp any any -> any 500 (
    msg:"ET EXPLOIT Check Point VPN IKEv1 Certificate Auth Probe CVE-2026-50751";
    content:"|00 00 00 01|"; offset:16; depth:4;
    content:"|04|"; offset:4; depth:1;
    threshold: type limit, track by_src, count 3, seconds 60;
    reference:url,blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol/;
    reference:cve,2026-50751;
    classtype:attempted-admin;
    sid:9002651; rev:1;
    metadata:affected_product Check_Point_VPN, deployment Perimeter,
              signature_severity Major, created_at 2026-06-21;
)
```

> Status: needs_validation — validate byte offsets against a captured exploit pcap before production deployment.

---

## 8. Threat Actor Profiles

### Qilin
| Field | Value | Source |
|---|---|---|
| actor | Qilin | Bleeping Computer; Help Net Security |
| type | criminal | — |
| motivation | financial (double extortion) | — |
| new_ttps | IKEv1 VPN auth bypass (CVE-2026-50751); Linux ELF ransomware payload; Tox-protocol C2; targeted Linux production infrastructure | Check Point Blog; Help Net Security |
| new_infra | Kaupo Cloud HK, Shock Hosting, Vultr Holdings ASNs (search summary — not directly verified) | Help Net Security (via search summary) |
| target_changes | Expanding from Windows endpoints to Linux servers and VPN infrastructure; 23+ victims in 48h | Bleeping Computer |
| confidence | high | — |

### Silent Ransom Group / UNC3753 / Luna Moth
| Field | Value | Source |
|---|---|---|
| actor | Silent Ransom Group (UNC3753, Luna Moth, Chatty Spider) | Bleeping Computer; PurpleOps |
| type | criminal | — |
| motivation | financial — callback phishing → data extortion | — |
| new_ttps | AI-generated invoice phishing; callback lure; AnyDesk RAT; insider recruitment | Cisco Talos; Bleeping Computer |
| target_changes | US law firms and professional services | PurpleOps tracker (search summary) |
| confidence | med | — |

### Volt Typhoon + Salt Typhoon (PRC)
| Field | Value | Source |
|---|---|---|
| actor | Volt Typhoon + Salt Typhoon (PRC-linked) | CISA; FBI; Microsoft Security Blog |
| type | APT | — |
| motivation | pre-positioning / espionage / potential disruption | — |
| new_ttps | Volt Typhoon: LOTL via netsh/wmic/certutil; Fortinet credential extraction; 5-year+ persistence. Salt Typhoon: GhostSpider + Masol RAT; ISP telecom metadata collection | CISA joint advisory; Microsoft Security Blog |
| target_changes | Power, water, transport, ISPs — CISA CI Fortify initiative activated | CISA; FBI; RH-ISAC |
| confidence | high | — |

---

## 9. Actions Matrix

| Priority | Action | Owner | Timeline | Investment | Risk Addressed | Success Metric |
|---|---|---|---|---|---|---|
| P1 | Patch or disable IKEv1 on all Check Point VPN / Mobile Access gateways (CVE-2026-50751) | Network Security / VPN Ops | 0–48h | Low | Qilin ransomware initial access | Zero IKEv1 sessions in logs; hotfix confirmed |
| P1 | Deploy Microsoft June 2026 Patch Tuesday to all Windows endpoints | Endpoint / Patch Management | 0–48h | Low–Medium | GreenPlasma, RoguePlanet, YellowKey, CVE-2026-45647 | 100% endpoints patched |
| P1 | Patch Joomla JCE (CVE-2026-48907 CVSS 10.0) on all public-facing Joomla installations | Web/App Ops | 0–48h | Low | Arbitrary code execution on web servers | JCE plugin version audit confirms patched |
| P2 | Patch Cisco Catalyst SD-WAN Manager (CVE-2026-20245, CVE-2026-20262) | Network / SD-WAN | 48h–7d | Medium | Encoding injection, path traversal | Cisco advisory compliance confirmed |
| P2 | Enable MFA on all VPN remote-access endpoints; enforce IKEv2 minimum | Identity / IAM | 48h–7d | Medium | Credential bypass, Qilin initial access | MFA coverage ≥95% VPN users |
| P2 | Deploy RoguePlanet behavioral detection (Event 4688 — cmd.exe from MsMpEng.exe) to SIEM | SOC / Detection Engineering | 48h–7d | Low | Defender exploitation — SYSTEM shell | Alert fires on lab detonation |
| P2 | Hunt for Volt Typhoon LOTL indicators (netsh/wmic/certutil anomalies) in OT-adjacent segments | Threat Hunting | 48h–7d | Medium | Nation-state pre-positioning | Hunt sweep complete; anomalies triaged |
| P3 | Patch Arista EOS (CVE-2026-7473) and LiteSpeed cPanel plugin (CVE-2026-54420) | Infrastructure | 7–30d | Low | Edge network and hosting platform exploitation | Version audit confirms patched |
| P3 | Update SIEM tactic taxonomy for MITRE ATT&CK v19 (Defense Evasion → Stealth / Defense Impairment) | Detection Engineering | 7–30d | Low | Detection rule accuracy | Sigma/KQL rules updated and tested |
| P3 | Implement network segmentation between VPN user pool and production Linux servers | Network Architecture | 7–30d | Medium–High | Lateral movement post-VPN compromise | East-west flow reduction from VPN pool confirmed |
| P3 | Deploy email gateway rules for Silent Ransom Group invoice callback pattern | Email Security | 7–30d | Low | BEC / callback phishing initial access | Detection rule fires in test |
| P4 | Review Oracle Siebel CRM and Oracle MySQL network access controls; apply quarterly CPU patches | App / DB Ops | 30–90d | Medium | Unauthenticated HTTP exploitation | Oracle CPU patch applied; network ACL audit |
| P4 | Establish compressed patch SLA (48h for CVSS 9+, 7d for CVSS 7–8.9) | Security Program | 30–90d | Low (policy) | AI-accelerated exploit timelines | SLA policy approved and tracked |

---

## 10. Intelligence Gaps

1. **GreyNoise mass-exploitation telemetry inaccessible.** Direct API access unavailable; all GreyNoise fields are `status: unverified`. Query greynoise.io directly for CVE-2026-50751, CVE-2026-48907, and Cisco CVEs.
2. **Check Point advisory primary source blocked (HTTP 403).** The two MD5 hashes in §4c came from a search-result summary and must be verified against the primary advisory before production deployment.
3. **Microsoft zero-day CVE IDs unavailable.** GreenPlasma/YellowKey/RoguePlanet codenames confirmed; formal CVE IDs not yet retrieved. Monitor MSRC.
4. **CVSS scores incomplete.** Several KEV CVEs (CVE-2026-7473, CVE-2026-20245, CVE-2026-20262, CVE-2026-54420) missing CVSS in accessible summaries. Retrieve from NVD directly.
5. **Dark web intelligence (Tier 7) entirely inaccessible.** All paywalled. Ransom forum victim lists unverified.
6. **Bug bounty platform disclosures (Tier 4) not consulted.** HackerOne and Bugcrowd not searched; two-source minimum not met.
7. **MalwareBazaar / URLhaus specific samples (June 14–21) not retrieved.** Consult bazaar.abuse.ch with tag "Qilin" and time filter for current SHA256 hashes.
8. **Salt Typhoon GhostSpider/Masol RAT IOCs not available.** Consult CISA advisories and Recorded Future for current nation-state infrastructure.
9. **CloudZ RAT / Pheno plugin IOCs not retrieved.** Consult blog.talosintelligence.com for specific hashes and C2 indicators.
10. **Possible search-result AI summarization artifacts.** CVE IDs and hash values extracted from AI-generated search summaries may contain errors. Cross-check all numeric identifiers against authoritative primary sources (CISA KEV, NVD, vendor advisories) before operational use (R6).

---

## Appendix A: Source Coverage Ledger

| Tier | Required Min | Consulted | Skipped (with reason) | Met? |
|---|---|---|---|---|
| 1 — Vulnerability DBs & Exploits | 5 | NVD (search summary), CISA KEV (search + URL attempted), CVE.org (search), MITRE ATT&CK v19 (search), ZDI June 2026 review (search) | Exploit-DB, GitHub Advisories: not searched this session | yes |
| 2 — Commercial Threat Intel | 4 | Cisco Talos blog (search), Check Point Research (search + WebFetch 403), Microsoft Security Blog (search), Rapid7 blog (search), eSentire advisory (search) | Recorded Future, CrowdStrike, Mandiant: search references only, not directly fetched | yes |
| 3 — Search Engines & Aggregators | 3 | GreyNoise (referenced; unverified — direct access blocked), Shodan/Censys (not searched), VirusTotal (not queried) | All Tier 3 sources: not directly queried this session | partial (0 confirmed; all marked unverified) |
| 4 — Bug Bounty Platforms | 2 | None consulted | HackerOne, Bugcrowd: not searched | no |
| 5 — Offensive Security Research | 2 | Rapid7 blog (search), ZDI (search) | Project Zero: not searched this session | partial (1/2) |
| 6 — Community & Independent Researchers | 3 | Bleeping Computer (search ×3), The Hacker News (search), Help Net Security (search), SC Media (search) | Krebs on Security, The DFIR Report: not separately searched | yes |
| 7 — Dark Web Intelligence | best-effort | None — all paywalled | Flashpoint, Intel 471, DarkOwl, Kela, Cybersixgill: paywalled; status: unverified | n/a |
| 8 — Government & Regulatory | 3 | CISA KEV / CISA Advisories (search + URL attempted), FBI 2026 alerts (search), NCSC UK (referenced in joint advisory context) | NSA Cybersecurity Advisories: not directly queried | yes |
| 9 — Malware Analysis & Sandboxing | 3 | MalwareBazaar (searched — no specific June 14–21 samples retrieved), URLhaus (searched — stat reference only) | Hybrid Analysis, Any.Run, Triage: not queried | partial (0 confirmed samples) |

**Total preferred-source targets consulted:** ~17 / ≈25

**Coverage badge:** `COVERAGE: PARTIAL`

**Fabrication check:** No IOC hashes, CVE numbers, or actor attributions were invented. Two MD5 hashes (§4c) are marked `med` confidence — extracted from search-result summary, not primary source. CVE codenames GreenPlasma/YellowKey/RoguePlanet are confirmed by Bleeping Computer; formal CVE IDs unknown at report time. All GreyNoise fields: `status: unverified (source inaccessible)`. Tier 4 (Bug Bounty) minimum not met — noted explicitly. Tier 7 (Dark Web) paywalled — noted explicitly. This report does not pad or invent to reach targets.

---

*Generated by the `cyber-threat-intel` skill — 2026-06-21. All detection rules require lab validation before production deployment. Verify critical IOCs against authoritative feeds (CISA KEV, NVD, vendor advisories) before operational use. This skill structures AI output; it does not guarantee accuracy.*

### Sources
- [CISA Adds Two Known Exploited Vulnerabilities — June 15](https://www.cisa.gov/news-events/alerts/2026/06/15/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA Adds Three Known Exploited Vulnerabilities — June 9](https://www.cisa.gov/news-events/alerts/2026/06/09/cisa-adds-three-known-exploited-vulnerabilities-catalog)
- [CISA Adds One Known Exploited Vulnerability — June 3](https://www.cisa.gov/news-events/alerts/2026/06/03/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Warns of Actively Exploited Joomla JCE Flaw — The Hacker News](https://thehackernews.com/2026/06/cisa-warns-of-actively-exploited-joomla.html)
- [Microsoft June 2026 Patch Tuesday fixes 6 zero-days, 200 flaws — Bleeping Computer](https://www.bleepingcomputer.com/news/microsoft/microsoft-june-2026-patch-tuesday-fixes-6-zero-days-200-flaws/)
- [Microsoft Defender RoguePlanet zero-day — Bleeping Computer](https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/)
- [Microsoft patches GreenPlasma, YellowKey, MiniPlasma — Bleeping Computer](https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-yellowkey-greenplasma-miniplasma-zero-days/)
- [Zero Day Initiative — June 2026 Security Update Review](https://www.zerodayinitiative.com/blog/2026/6/9/the-june-2026-security-update-review)
- [Patch Critical Check Point VPN CVE-2026-50751 — Check Point Blog](https://blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol/)
- [Qilin ransomware affiliate exploited Check Point VPN zero-day — Help Net Security](https://www.helpnetsecurity.com/2026/06/08/check-point-cve-2026-50751-qilin-ransomware/)
- [Check Point links VPN zero-day attacks to Qilin ransomware — Bleeping Computer](https://www.bleepingcomputer.com/news/security/check-point-links-vpn-zero-day-attacks-to-qilin-ransomware-gang/)
- [Critical Check Point VPN Zero-Day Exploited — Rapid7](https://www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751/)
- [CVE-2026-50751 Critical Check Point VPN — eSentire](https://www.esentire.com/security-advisories/cve-2026-50751-critical-check-point-vpn-authentication-bypass-vulnerability)
- [Ransomware Activity Tracker 2026 — PurpleOps](https://purple-ops.io/blog/ransomware-tracker-2026)
- [8th June Threat Intelligence Report — Check Point Research](https://research.checkpoint.com/2026/8th-june-threat-intelligence-report/)
- [AI-assisted phishing attacks on the rise — SC Media](https://www.scworld.com/brief/ai-assisted-phishing-attacks-on-the-rise-report-finds/)
- [Cisco Talos Threat Hunting blog post — June 2026](https://blog.talosintelligence.com/hypotheses-telemetry-and-human-judgment-inside-cisco-talos-threat-hunting/)
- [ATT&CK v18: Detection Overhaul — MITRE ATT&CK Medium](https://medium.com/mitre-attack/att-ck-v18-detection-strategies-more-adversary-insights-8f82d839ee9e)
- [MITRE ATT&CK Updates](https://attack.mitre.org/resources/updates/)
- [Volt Typhoon 2026: Still Active in US Critical Infrastructure — CybelAngel](https://cybelangel.com/blog/volt-typhoon/)
- [PRC State-Sponsored Actors Compromise US Critical Infrastructure — CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
- [Four Chinese APT Groups Target Critical Infrastructure — RH-ISAC](https://rhisac.org/threat-intelligence/four-chinese-apt-groups-target-critical-infrastructure-disruption/)
- [NVD Dashboard — NIST](https://nvd.nist.gov/general/nvd-dashboard)
- [2026 Vulnerability Explosion — pbxscience](https://pbxscience.com/the-2026-vulnerability-explosionwhy-are-so-many-cves-being-discovered/)
- [NVD Changes 2026 — Black Duck](https://www.blackduck.com/blog/nist-nvd-policy-shift-2026.html)
- [CISA CI Fortify initiative — AHA News](https://www.aha.org/news/headline/2026-05-06-cisa-announces-initiative-bolster-critical-infrastructure-against-nation-state-cyberattacks)
- [FBI Cyber Alerts 2026](https://www.fbi.gov/investigate/cyber/alerts/2026)
