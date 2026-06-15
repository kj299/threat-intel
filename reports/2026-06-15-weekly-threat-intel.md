# THREAT INTELLIGENCE REPORT

```
Generated:  2026-06-15T00:00:00Z
Coverage:   PARTIAL
Time Range: 2026-06-08 to 2026-06-15
Scope:      All emerging threats
Persona:    enterprise_soc
```

---

## ALERT BANNER

```
CRITICAL: CVE-2026-50751 — Check Point Remote Access VPN zero-day (CVSS 9.3) actively
          exploited by Qilin ransomware affiliates since May 7. Hotfix available;
          no comprehensive patch. Disable IKEv1 immediately.

CRITICAL: CVE-2026-45657 — Windows Kernel TCP/IP RCE (CVSS 9.8), wormable profile
          comparable to EternalBlue (WannaCry). Unauthenticated, no user interaction.
          Apply June 2026 Patch Tuesday now.

HIGH:     CVE-2026-20245 — Cisco Catalyst SD-WAN Manager root command execution,
          NO PATCH AVAILABLE. Mandiant confirmed in-the-wild exploitation.

HIGH:     Qilin ransomware surging: 18 victims claimed in 24 hours (June 11),
          energy and manufacturing sectors targeted.
```

---

## 1. Executive Summary

- **Check Point VPN zero-day weaponized by ransomware.** CVE-2026-50751 (CVSS 9.3) is an IKEv1 authentication-bypass flaw that Qilin ransomware affiliates have exploited since at least May 7, 2026. Exploitation requires no valid credentials. Organizations running legacy IKEv1/Remote Access clients face immediate ransomware risk. A hotfix is available; IKEv1 should be disabled where possible and machine-certificate authentication enforced.
- **Wormable Windows Kernel RCE demands emergency patching.** CVE-2026-45657 (CVSS 9.8, Windows Kernel TCP/IP, June 2026 Patch Tuesday) is a use-after-free condition that allows unauthenticated remote code execution at SYSTEM level with self-propagating potential across networks — researchers at ZDI have characterized it as EternalBlue-class. CVE-2026-47291 (HTTP.sys, CVSS 9.8) adds a second unauthenticated RCE vector on the same Patch Tuesday.
- **Cisco SD-WAN has an unpatched zero-day.** CVE-2026-20245 enables an authenticated attacker with netadmin privileges to execute arbitrary OS commands as root via a crafted file upload. Mandiant identified limited in-the-wild exploitation; no patch exists. The bug is chainable from earlier SD-WAN credential flaws (CVE-2026-20182, CVE-2026-20127).
- **Qilin ransomware is the dominant RaaS threat in Q2 2026.** Operating as a ransomware-as-a-service entity (MITRE S1242), Qilin claimed 18 victims in 24 hours on June 11 across manufacturing and energy. Their TTPs include VPN exploitation, Rclone for staged exfiltration, Tox protocol C2, and volume shadow copy deletion.
- **Nation-state APTs heavily targeting energy and utilities.** CYFIRMA reported that the energy/utilities sector appeared in 66% of all APT campaigns in the last 90 days. Mustang Panda (China), Lazarus Group (DPRK), and Sandworm (Russia — DynoWiper, Poland power grid) all remain active. Unit 42 measured initial access to exfiltration in as little as 72 minutes — four times faster than 2025.
- **Silent Ransom Group escalating pure-extortion campaigns.** UNC3753 (Luna Moth / Chatty Spider) targets US law firms and professional services with invoice-themed phishing leading to AnyDesk remote sessions, data theft, and extortion demands issued within 30 minutes — no encryption, no EDR-triggering ransomware binary.
- **June Patch Tuesday is record-breaking.** Microsoft released patches for 206+ CVEs including 6 zero-days and 37 Critical-rated vulnerabilities. Organizations with delayed patching SLAs face compounding exposure across the Windows ecosystem.

---

## 2. Threat Dashboard

| Category | New This Period | Active Exploits | Trend | Risk Level | Org Relevance |
|----------|----------------|-----------------|-------|------------|---------------|
| Ransomware | Qilin surge (18 victims/24h, June 11); Silent Ransom Group extortion campaign | CVE-2026-50751 (Check Point VPN) | ↑ Up | CRITICAL | High — manufacturing, energy, legal, professional services |
| APT / Nation-State | Lazarus energy ops; APT42 Iran phishing; Sandworm DynoWiper carry-forward | CVE-2026-20245 (Cisco SD-WAN, possibly nation-state initial exploitation) | ↑ Up | HIGH | High — energy, telecom, defense supply chain |
| Zero-Day | 3 CISA KEV additions (June 9); Microsoft 6 zero-days (June 10); Check Point zero-day | CVE-2026-50751, CVE-2026-45657, CVE-2026-47291, CVE-2026-20245, CVE-2026-11645 | ↑ Up | CRITICAL | High — all environments |
| Supply Chain | Cisco SD-WAN multi-CVE chaining | CVE-2026-20182 → CVE-2026-20127 → CVE-2026-20245 | ↑ Up | HIGH | Medium — SD-WAN deployments |
| Cloud / API | No major new cloud-specific this period | — | → Flat | MEDIUM | Medium |
| Credential / BEC | Silent Ransom Group invoice phishing; APT42 account compromise | AnyDesk RAT deployment post-phishing | ↑ Up | HIGH | High — law firms, financial services, policy organizations |
| Insider | No new reporting this period | — | → Flat | LOW | Low |
| Mobile | Android Framework ITW (CVE-2025-48595) — CISA KEV June 2 | Android exploitation | → Flat | MEDIUM | Medium — BYOD / unmanaged Android fleets |

---

## 3. Critical Vulnerability Summary

| CVE | CVSS | Product | Exploit Status | GreyNoise Activity | Org Exposure | Action | Source |
|-----|------|---------|---------------|-------------------|--------------|--------|--------|
| CVE-2026-50751 | 9.3 | Check Point Remote Access VPN, Mobile Access, Spark Firewall (IKEv1) | ITW — Qilin ransomware since May 7 | Elevated IKEv1 port scanning observed | **CRITICAL** — widespread Check Point VPN deployments | Apply hotfix immediately; disable IKEv1; enforce machine-cert auth; also patch co-disclosed CVE-2026-50752 | CISA KEV 2026-06-09; Check Point Blog; Rapid7 ETR; Help Net Security; eSentire |
| CVE-2026-45657 | 9.8 | Windows Kernel (x64 / ARM64 — Win 11, Server 2022/2025) | Disclosed June 10; wormable profile | Moderate scanning expected post-disclosure | **CRITICAL** — all unpatched Windows | Apply June 2026 Patch Tuesday immediately; prioritize internet-exposed systems; network-segment to limit worm spread | ZDI June 2026 Review; Bleeping Computer; CrowdStrike PT Analysis |
| CVE-2026-47291 | 9.8 | Windows HTTP.sys (Win 10/11, Server 2012–2025) | Disclosed June 10 | Moderate | **HIGH** — all Windows web servers; systems at default MaxRequestBytes (≤16 KB) unaffected | Apply June 2026 Patch Tuesday; verify `MaxRequestBytes` registry value | ZDI; Bleeping Computer; threat-modeling.com |
| CVE-2026-20245 | 7.8 | Cisco Catalyst SD-WAN Manager — all deployment types (on-prem, Cloud-Pro, FedRAMP) | ITW — Mandiant-confirmed limited exploitation | Limited | **HIGH** — all SD-WAN Manager environments | **NO PATCH** — restrict netadmin role; isolate SD-WAN Manager; audit CLI file upload logs; monitor for configuration pushes to edge devices | CISA KEV 2026-06-09; Mandiant; Cisco; The Hacker News |
| CVE-2026-11645 | Critical | Google Chromium V8 (all Chromium-based browsers) | ITW, CISA KEV June 9 | Unknown | **HIGH** — all Chromium/Chrome browser users | Update Chrome/Chromium immediately | CISA KEV 2026-06-09; Google Chrome security blog |
| CVE-2026-7473 | N/A | Arista Extensible Operating System (EOS) | ITW, CISA KEV June 9 | Limited | Medium — Arista network device fleets | Apply Arista security patch; audit EOS version fleet | CISA KEV 2026-06-09 |
| CVE-2025-48595 | N/A | Android Framework (Integer Overflow) | ITW, CISA KEV June 2 | Unknown | Medium — Android device fleets | Push security patch via MDM; enforce patch compliance | CISA KEV 2026-06-02 |
| CVE-2022-0492 | 7.8 | Linux Kernel — cgroup v1 (Improper Authentication) | Newly re-active exploitation, CISA KEV June 2 | Moderate | Medium — unpatched Linux hosts | Patch; disable cgroup v1 if unused; audit container escape risk | CISA KEV 2026-06-02 |
| CVE-2026-45247 | N/A | Mirasvit Full Page Cache Warmer (Magento/Adobe Commerce plugin) | ITW, CISA KEV June 3 | Limited | Low–Medium — e-commerce platforms | Update plugin; audit Adobe Commerce environments | CISA KEV 2026-06-03 |

---

## 4. IOC Package

> **Honesty notice (R3):** Specific IPs and file hashes from the Check Point VPN exploitation campaign (CVE-2026-50751) were referenced in vendor reports by infrastructure provider (Kaupo Cloud HK, Shock Hosting, Vultr Holdings) but specific values were not returned by this run's source queries. Consult the Check Point Blog IOC appendix, CISA advisory, and Rapid7 ETR directly for the current blocklist. The behavioral and process-based IOCs below are drawn from confirmed TTP reporting and carry source citations. Confidence calibration: `high` = ≥2 independent corroborating sources; `med` = single credible source; `low` = inferred from pattern.

### 4a. Immediate Block — Network IOCs (high confidence)

| Type | Value | Confidence | Source | First Seen | Threat | MITRE ID | Action | TLP |
|------|-------|-----------|--------|-----------|--------|----------|--------|-----|
| ASN | Kaupo Cloud HK (ASN context) | med | Rapid7 ETR; eSentire CVE-2026-50751 | 2026-05-07 | Qilin / CVE-2026-50751 C2 hosting | T1583.003 | Block outbound to this ASN; investigate existing sessions | TLP:WHITE |
| ASN | Shock Hosting (ASN context) | med | Rapid7 ETR; Check Point Blog | 2026-05-07 | Qilin C2 staging | T1583.003 | Alert / investigate | TLP:WHITE |
| ASN | Vultr Holdings VPS | med | Rapid7 ETR | 2026-05-07 | Qilin post-exploitation ELF payload hosting | T1583.003 | Alert / hunt | TLP:WHITE |

> **Note:** Specific IPs within the above ASNs are in Check Point's hotfix advisory and CISA KEV detail page. Retrieve via `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` filtered by date 2026-06-09 and cross-reference with Check Point Blog IOC appendix. Do not block entire ASNs in production without confirming no legitimate tenant overlap.

### 4b. Monitor / Alert — Host IOCs (high confidence)

| Type | Value | Confidence | Source | Threat | Platform | Action | Detection Source |
|------|-------|-----------|--------|--------|----------|--------|-----------------|
| process | rclone.exe | high | MITRE ATT&CK S1242; Dexpose.io; Cyble Qilin Profile | Qilin data exfiltration | Windows / Linux | Alert; capture CLI args | EDR process telemetry |
| process | AnyDesk.exe | high | Help Net Security; PurpleOps Ransomware Tracker 2026 | Silent Ransom Group remote access | Windows | Alert when launched from uncommon parent (phishing) | EDR |
| cmdline | vssadmin delete shadows | high | MITRE ATT&CK T1490; Qilin TTP profiles (Cyble, Blackpoint) | Ransomware shadow copy deletion | Windows | BLOCK / alert; pre-stage killswitch | EDR / SIEM |
| cmdline | vssadmin.exe Delete Shadows /All /Quiet | high | MITRE ATT&CK T1490; Qilin TTP profiles | Ransomware shadow copy deletion | Windows | BLOCK | EDR |
| named_pipe | (Qilin Go-binary IPC patterns — verify via MalwareBazaar sample analysis) | low | MITRE ATT&CK S1242 (inferred) | Qilin C2 internal | Windows | Hunt | EDR named-pipe telemetry |
| file_path | C:\Users\Public\rclone.exe | med | Threat hunting patterns; DFIR community | Qilin exfil staging | Windows | Alert; quarantine | EDR |
| wmi_sub | Any WMI subscription created within 10s of shadow copy deletion | med | Qilin persistence patterns (Blackpoint) | Qilin persistence | Windows | Alert | WMI subscription telemetry |

### 4c. Watchlist — Behavioral IOCs (hunt queries)

| Behavior | Data Source | Detection Logic | MITRE ID | Threshold | Source |
|----------|------------|----------------|----------|-----------|--------|
| IKEv1 VPN session established with no prior auth-failure event from same source IP | Check Point VPN logs / CEF | `auth_success=true AND auth_fail_count=0` for same SourceIP within same hour | T1133 | Any occurrence | Rapid7 ETR; eSentire CVE-2026-50751 |
| Rclone sync/copy to external cloud endpoint | Proxy / DNS / Network | DNS query for `rclone.io`, `*.backblaze.com`, `*.wasabi.com`, `*.sftp.*` from endpoint shortly after large local file read | T1048.002 | >100 MB data movement | Dexpose.io; KELA Qilin profile |
| AnyDesk installed silently from non-IT parent process | EDR | `Image ENDSWITH AnyDesk.exe AND parent NOT IN (msiexec.exe, sccm.exe, intune.exe)` | T1219 | Any occurrence | Help Net Security; PurpleOps tracker |
| Cisco SD-WAN CLI file upload (CVE-2026-20245 exploitation) | Cisco SD-WAN audit logs | File upload events via SD-WAN Manager CLI workflow by netadmin-role accounts; followed by root-level process execution | T1059.004 | Any file upload to CLI by netadmin | Mandiant; CISA KEV |
| Chromium V8 RCE in-browser exploit (CVE-2026-11645) | EDR / Proxy | Child processes spawned from Chrome renderer that are not `chrome.exe`; unusual JS engine crashes | T1203 | Any renderer→system process | CISA KEV 2026-06-09 |

### 4d. CSV Bulk Import

```csv
ioc_type,ioc_value,confidence,threat_name,threat_actor,mitre_technique,source,first_seen,last_seen,action,tlp
asn,Kaupo Cloud HK,med,Qilin Ransomware C2,Qilin,T1583.003,Rapid7 ETR CVE-2026-50751; eSentire,2026-05-07,2026-06-15,block-investigate,TLP:WHITE
asn,Shock Hosting,med,Qilin Ransomware Staging,Qilin,T1583.003,Rapid7 ETR; Check Point Blog,2026-05-07,2026-06-15,alert,TLP:WHITE
asn,Vultr Holdings,med,Qilin ELF Payload Hosting,Qilin,T1583.003,Rapid7 ETR,2026-05-07,2026-06-15,hunt,TLP:WHITE
process,rclone.exe,high,Data Exfiltration Tool,Qilin,T1048.002,MITRE ATT&CK S1242; Cyble; Dexpose.io,2022-01-01,2026-06-15,alert,TLP:WHITE
process,AnyDesk.exe,high,Remote Access Tool - Extortion,Silent Ransom Group,T1219,Help Net Security; PurpleOps 2026,2024-01-01,2026-06-15,alert,TLP:WHITE
cmdline,vssadmin delete shadows,high,Shadow Copy Deletion,Qilin,T1490,MITRE ATT&CK T1490; Blackpoint Qilin Profile,2022-01-01,2026-06-15,block,TLP:WHITE
behavioral,IKEv1-session-no-auth-failure,high,Check Point VPN Exploit,Qilin,T1133,Rapid7 ETR; eSentire CVE-2026-50751,2026-05-07,2026-06-15,alert-investigate,TLP:WHITE
```

### 4e. STIX 2.1 Bundle (representative indicators)

```json
{
  "type": "bundle",
  "id": "bundle--cti-20260615-weekly",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--qilin-rclone-exfil",
      "spec_version": "2.1",
      "name": "Rclone Exfiltration Tool - Qilin",
      "pattern": "[process:name = 'rclone.exe']",
      "pattern_type": "stix",
      "valid_from": "2026-06-08T00:00:00Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 85,
      "description": "Rclone.exe observed as data exfiltration staging tool in Qilin ransomware campaigns",
      "external_references": [
        {"source_name": "MITRE ATT&CK", "external_id": "S1242", "url": "https://attack.mitre.org/software/S1242/"},
        {"source_name": "Dexpose.io", "url": "https://www.dexpose.io/qilin-ransomware/"}
      ]
    },
    {
      "type": "indicator",
      "id": "indicator--vssadmin-shadow-delete",
      "spec_version": "2.1",
      "name": "VSS Shadow Copy Deletion - Ransomware",
      "pattern": "[process:name = 'vssadmin.exe' AND process:command_line MATCHES 'delete.*shadows']",
      "pattern_type": "stix",
      "valid_from": "2026-06-08T00:00:00Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 90,
      "description": "VSS shadow copy deletion used by Qilin and most ransomware families to prevent recovery",
      "external_references": [
        {"source_name": "MITRE ATT&CK", "external_id": "T1490"},
        {"source_name": "Blackpoint Cyber Qilin Profile", "url": "https://blackpointcyber.com/threat-profile/qilin-ransomware/"}
      ]
    },
    {
      "type": "indicator",
      "id": "indicator--anydesk-silent-install",
      "spec_version": "2.1",
      "name": "AnyDesk Silent Install - Silent Ransom Group",
      "pattern": "[process:name = 'AnyDesk.exe' AND process:command_line MATCHES '--silent|--install']",
      "pattern_type": "stix",
      "valid_from": "2026-06-08T00:00:00Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 75,
      "description": "Silent Ransom Group (Luna Moth/UNC3753) installs AnyDesk post-phishing for remote access and data exfiltration",
      "external_references": [
        {"source_name": "Help Net Security", "url": "https://www.helpnetsecurity.com/2026/06/08/check-point-cve-2026-50751-qilin-ransomware/"},
        {"source_name": "KELA Cyber", "url": "https://www.kelacyber.com/blog/ransomware-threat-actor-profile-qilin/"}
      ]
    },
    {
      "type": "vulnerability",
      "id": "vulnerability--cve-2026-50751",
      "spec_version": "2.1",
      "name": "CVE-2026-50751",
      "description": "Check Point Remote Access VPN IKEv1 authentication bypass (CVSS 9.3). ITW exploitation by Qilin ransomware.",
      "external_references": [
        {"source_name": "cve", "external_id": "CVE-2026-50751", "url": "https://cve.org/CVERecord?id=CVE-2026-50751"},
        {"source_name": "CISA KEV", "url": "https://www.cisa.gov/news-events/alerts/2026/06/09/cisa-adds-three-known-exploited-vulnerabilities-catalog"}
      ]
    },
    {
      "type": "threat-actor",
      "id": "threat-actor--qilin",
      "spec_version": "2.1",
      "name": "Qilin",
      "aliases": ["Agenda"],
      "threat_actor_types": ["criminal"],
      "sophistication": "intermediate",
      "resource_level": "criminal-infrastructure",
      "primary_motivation": "financial-gain",
      "external_references": [
        {"source_name": "MITRE ATT&CK", "external_id": "S1242", "url": "https://attack.mitre.org/software/S1242/"},
        {"source_name": "Cyble", "url": "https://cyble.com/threat-actor-profiles/qilin-ransomware-group/"}
      ]
    }
  ]
}
```

### 4f. Delimited Batch Export (for programmatic / SIEM importer consumption)

```json
[
  {
    "mitre_id": "T1048.002",
    "name": "Rclone Data Exfiltration - Qilin",
    "fields": {
      "detection_method": "process name",
      "detection_value": "rclone.exe",
      "severity": "WARNING",
      "actor": "Qilin"
    },
    "source": "MITRE ATT&CK S1242; Dexpose.io; Cyble Qilin Threat Actor Profile",
    "confidence": "high"
  },
  {
    "mitre_id": "T1490",
    "name": "VSS Shadow Copy Deletion Pre-Ransomware",
    "fields": {
      "detection_method": "process name",
      "detection_value": "vssadmin.exe",
      "severity": "CRITICAL",
      "actor": "Qilin"
    },
    "source": "MITRE ATT&CK T1490; Blackpoint Cyber Qilin Profile; Cyble",
    "confidence": "high"
  },
  {
    "mitre_id": "T1219",
    "name": "AnyDesk Remote Access - Silent Ransom Group",
    "fields": {
      "detection_method": "process name",
      "detection_value": "AnyDesk.exe",
      "severity": "WARNING",
      "actor": "Silent Ransom Group"
    },
    "source": "Help Net Security; PurpleOps Ransomware Tracker 2026; KELA Cyber",
    "confidence": "high"
  },
  {
    "mitre_id": "T1133",
    "name": "Check Point VPN IKEv1 Auth Bypass Session",
    "fields": {
      "detection_method": "event id",
      "detection_value": "IKEv1_SESSION_NO_AUTH_FAILURE",
      "severity": "CRITICAL",
      "actor": "Qilin"
    },
    "source": "Rapid7 ETR CVE-2026-50751; eSentire; Check Point Blog",
    "confidence": "high"
  },
  {
    "mitre_id": "T1059.004",
    "name": "Cisco SD-WAN CLI File Upload - Root Execution",
    "fields": {
      "detection_method": "file path",
      "detection_value": "sdwan-manager-cli-upload",
      "severity": "CRITICAL",
      "actor": "unknown"
    },
    "source": "Mandiant CVE-2026-20245 discovery; The Hacker News; CISA KEV 2026-06-09",
    "confidence": "med"
  },
  {
    "mitre_id": "T1203",
    "name": "Chromium V8 OOB Browser Exploitation",
    "fields": {
      "detection_method": "process name",
      "detection_value": "chrome.exe",
      "severity": "WARNING",
      "actor": "unknown"
    },
    "source": "CISA KEV 2026-06-09; Google Chrome Security",
    "confidence": "med"
  }
]
```

---

## 5. TTP Mapping (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Sub-Technique | Procedure | Detection Method | Data Sources | Source |
|--------|-------------|---------------|---------------|-----------|-----------------|-------------|--------|
| Initial Access | T1190 | Exploit Public-Facing Application | — | CVE-2026-50751: Check Point VPN IKEv1 auth bypass without valid credentials | Monitor VPN auth logs for sessions with no prior failure | VPN auth logs; CEF/Syslog | CISA KEV; Rapid7; Check Point Blog |
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | — | Silent Ransom Group invoice-themed email delivering AnyDesk session initiation | Email gateway attachment scanning; AnyDesk parent-process analysis | Email logs; EDR | Help Net Security; PurpleOps |
| Initial Access | T1078 | Valid Accounts | T1078.001 | Qilin affiliates purchase or use leaked credentials for initial VPN/RDP access | Credential stuffing detection; impossible travel; anomalous login times | Identity logs; SIEM | MITRE ATT&CK S1242; KELA |
| Execution | T1059.001 | Command and Scripting: PowerShell | — | Qilin: PowerShell used post-access for reconnaissance and tool staging | PowerShell logging (ScriptBlock logging enabled); 4104 events | Windows Event Logs | MITRE ATT&CK S1242; Dexpose.io |
| Execution | T1059.004 | Command and Scripting: Unix Shell | — | CVE-2026-20245: root shell via crafted file upload in SD-WAN CLI | SD-WAN audit logs; process creation as root | Cisco SD-WAN logs | Mandiant; CISA KEV |
| Persistence | T1053.005 | Scheduled Task | — | Qilin creates scheduled tasks for persistence before encryption phase | Windows Task Scheduler creation events (4698) | Windows Event Logs | MITRE ATT&CK S1242; Blackpoint |
| Persistence | T1547 | Boot/Logon Autostart | — | Qilin registry run-key persistence | Registry modification monitoring | EDR; Sysmon Event ID 13 | Cyble Qilin Profile |
| Defense Evasion | T1562.001 | Impair Defenses: Disable/Modify Tools | — | Qilin kills AV/EDR services before encryption | Service stop events; AV telemetry gap | Windows Event Logs (7036) | MITRE ATT&CK S1242 |
| Defense Evasion | T1070.001 | Indicator Removal: Clear Windows Event Logs | — | Qilin clears security logs post-encryption | Event log cleared (1102/104); sudden log gap | Windows Security Log | MITRE ATT&CK S1242; Blackpoint |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | — | Qilin dumps LSASS for lateral movement credential harvesting | LSASS access by non-system processes; Mimikatz signatures | EDR; Windows Security 4656/4663 | MITRE ATT&CK S1242; Dexpose.io |
| Discovery | T1083 | File and Directory Discovery | — | Silent Ransom Group: directory enumeration to identify high-value data before exfil | `dir` / `tree` CLI commands; unusual file-read volume | EDR process telemetry | PurpleOps; KELA |
| Lateral Movement | T1210 | Exploitation of Remote Services | — | Qilin: CVE-2026-50751 (Check Point VPN) enables lateral pivot via established VPN session | Network anomaly: new VPN segment access post-initial-auth | Network flow; VPN logs | Rapid7 ETR; MITRE ATT&CK S1242 |
| Lateral Movement | T1021.001 | Remote Services: RDP | — | Qilin moves laterally via RDP using harvested credentials | Failed/successful RDP logins (4625/4624 from new sources) | Windows Security Log | Dexpose.io; Cyble |
| Collection | T1005 | Data from Local System | — | Silent Ransom Group and Qilin collect files before exfil | Large-scale file read events; DLP alert volume spike | EDR; DLP | PurpleOps; KELA |
| Exfiltration | T1048.002 | Exfiltration Over Alternative Protocol: Exfiltration over Asymmetric Encrypted Non-C2 Protocol | — | Qilin uses Rclone to exfiltrate to cloud storage (Backblaze, Mega, etc.) | Rclone.exe process + outbound traffic to cloud storage APIs | EDR; Proxy; Network | MITRE ATT&CK S1242; Dexpose.io |
| Command & Control | T1219 | Remote Access Software | — | Silent Ransom Group: AnyDesk installed for persistent remote access and C2 | AnyDesk process; outbound to AnyDesk relay infrastructure | EDR; Network | Help Net Security; PurpleOps |
| Command & Control | T1573 | Encrypted Channel | — | Qilin: Tox protocol for operator C2 communications | Tox protocol patterns in network traffic | Network; IDS | Rapid7 ETR |
| Impact | T1490 | Inhibit System Recovery | — | Qilin: `vssadmin delete shadows /all /quiet` and disabling Windows Recovery | VSS deletion telemetry; BCDEdit calls | EDR; Windows Event Log | MITRE ATT&CK T1490; Blackpoint |
| Impact | T1486 | Data Encrypted for Impact | — | Qilin encrypts files using AES; appends custom extension | File modification volume spike; extension change | EDR; File Integrity Monitoring | MITRE ATT&CK S1242; Cyble |

---

## 6. Threat Actor Updates

| Actor | Type | Motivation | New TTPs (This Period) | New Infra | Target Changes | Confidence | Source |
|-------|------|-----------|----------------------|-----------|---------------|-----------|--------|
| Qilin (Agenda) | Criminal RaaS | Financial | CVE-2026-50751 (Check Point VPN zero-day exploitation); 18-victim 24h surge; Rclone + Tox C2 | VPS via Kaupo Cloud HK, Shock Hosting, Vultr | Expanding into energy sector (June 11 surge); manufacturing | high | MITRE ATT&CK S1242; Rapid7; Help Net Security; Cyble; KELA |
| Silent Ransom Group (UNC3753 / Luna Moth / Chatty Spider) | Criminal | Financial (extortion) | Invoice phishing → AnyDesk → sub-30-min extortion demand; no encryption; pure data-theft model | AnyDesk relay infrastructure | US law firms, professional services firms | high | PurpleOps Ransomware Tracker 2026; Help Net Security |
| Sandworm (APT44 — Russian GRU) | Nation-State | Disruption / Geopolitical | DynoWiper (novel wiper malware) deployed against Polish power sector (Dec 2025 – Jan 2026); carry-forward threat to European energy | Poland-adjacent infrastructure | Energy / utilities (European grid, NATO-aligned) | high | The Hacker News (DynoWiper); Industrial Cyber |
| Mustang Panda (Bronze President — Chinese PLA-linked) | Nation-State | Espionage | Energy/utilities targeting (66% of APT campaigns per CYFIRMA) | — | Energy and utilities sector | med | Industrial Cyber; CYFIRMA report |
| Lazarus Group (DPRK) | Nation-State / Criminal | Financial + Espionage | Energy sector active targeting (CYFIRMA top 3) | — | Energy, cryptocurrency, defense | med | Industrial Cyber |
| APT42 (Iranian IRGC-IO) | Nation-State | Espionage | Phishing + account compromise targeting diaspora, journalists, academics, policy professionals | — | Diaspora communities, think tanks, policy orgs | med | CloudSEK; SecurityWeek |

---

## 7. CWE Chains

### Chain 1: Check Point VPN IKEv1 Authentication Bypass → Ransomware Deployment

```
chain_id:     CHAIN-2026-001
name:         Check Point VPN Zero-Day to Ransomware
chain_type:   primary_resultant
cwe_view:     CWE-1000 (Research View)

links:
  - cwe_id:               CWE-303
    role:                 primary
    name:                 Incorrect Implementation of Authentication Algorithm
    mitre_id:             T1190
    tactic:               Initial Access
    evidence:             IKEv1 certificate validation logic flaw — session established
                          without valid user credential (Check Point Blog; Rapid7 ETR)
    detection_opportunity: IKEv1 VPN session with no preceding auth-failure from same IP
    data_source:          Check Point VPN logs / CEF
    source:               CISA KEV 2026-06-09; Check Point Blog; Rapid7

  - cwe_id:               CWE-287
    role:                 resultant
    name:                 Improper Authentication
    mitre_id:             T1078 / T1133
    tactic:               Initial Access → Lateral Movement
    evidence:             Unauthorized VPN session grants network access; Qilin moves
                          laterally and deploys ransomware (Rapid7 ETR)
    detection_opportunity: Anomalous internal traffic from new VPN endpoint
    data_source:          Network flow; EDR
    source:               Rapid7 ETR; eSentire CVE-2026-50751

enabling_conditions:  Legacy IKEv1/Remote Access client enabled; machine-cert auth NOT enforced
ai_assist_factor:     low (logic flaw exploitation; straightforward after disclosure)
time_to_exploit:
  observed_days:  1 (exploited same week as disclosure)
  trend:          accelerating
  source:         Rapid7 ETR; Help Net Security (PoC released June 12)

break_points:
  - at_link:            CWE-303
    control:            Disable IKEv1 and deprecated Remote Access client support
    control_type:       preventive
    mapped_mitigation:  M1042 (Disable or Remove Feature or Program)
    detection_telemetry: Zero IKEv1 handshake events in VPN logs post-remediation
  - at_link:            CWE-287
    control:            Enforce mandatory machine-certificate authentication
    control_type:       preventive
    mapped_mitigation:  M1032 (Multi-factor Authentication)
    detection_telemetry: All VPN sessions require valid machine cert; auth-fail logged

terminal_impact: Ransomware encryption across VPN-reachable network segment; data exfil via Rclone
score:           9.1  (exploitability=10·0.25 + impact=9·0.25 + relevance=9·0.30 + urgency=10·0.20)
priority:        P1
confidence:      high
source:          CISA KEV 2026-06-09; Check Point Blog; Rapid7 ETR; eSentire
```

### Chain 2: Cisco SD-WAN Credential Escalation → Root Command Execution

```
chain_id:     CHAIN-2026-002
name:         Cisco SD-WAN Credential Theft → Root Execution (CVE-2026-20245 Chain)
chain_type:   composite
cwe_view:     CWE-1000 (CWE-116 CanPrecede CWE-78)

links:
  - cwe_id:               CWE-522
    role:                 primary (enabling)
    name:                 Insufficiently Protected Credentials
    mitre_id:             T1078
    tactic:               Initial Access / Defense Evasion
    evidence:             Prior CVE-2026-20182 or CVE-2026-20127 enables credential
                          theft or privilege gain to netadmin level (Mandiant; Cisco)
    detection_opportunity: Anomalous netadmin account login; login from unusual IP/time
    data_source:          Cisco SD-WAN Manager audit logs; Identity logs
    source:               Mandiant; The Hacker News CVE-2026-20245

  - cwe_id:               CWE-116
    role:                 primary
    name:                 Improper Encoding or Escaping of Output
    mitre_id:             T1059.004
    tactic:               Execution
    evidence:             Insufficient sanitization of user-supplied input during CLI
                          file upload processing (Mandiant; Cisco; CISA KEV)
    detection_opportunity: File upload events via SD-WAN Manager CLI by netadmin role
    data_source:          Cisco SD-WAN CLI audit log
    source:               Mandiant; CISA KEV 2026-06-09; The Hacker News

  - cwe_id:               CWE-78
    role:                 resultant
    name:                 OS Command Injection
    mitre_id:             T1059.004
    tactic:               Execution → Privilege Escalation
    evidence:             Crafted file upload triggers arbitrary OS command execution
                          as root user (Mandiant confirmed ITW; Cisco disclosure)
    detection_opportunity: Unexpected root-level process spawned from SD-WAN Manager process
    data_source:          Linux/Cisco process audit; syslog
    source:               Mandiant; GBHackers; CyberExpress

enabling_conditions:  Attacker has netadmin privileges (from stolen creds or prior vuln chain);
                      SD-WAN Manager CLI accessible; no patch available
ai_assist_factor:     moderate (AI assists crafting malicious file payload to trigger injection)
time_to_exploit:
  observed_days:  unknown (limited ITW exploitation reported; chain involves ≥2 steps)
  trend:          accelerating
  source:         Mandiant CVE-2026-20245; Daily Security Review

break_points:
  - at_link:            CWE-522 (enabling)
    control:            Restrict netadmin role to named principals; enforce MFA on all
                        privileged SD-WAN Manager accounts; rotate credentials
    control_type:       preventive
    mapped_mitigation:  M1026 (Privileged Account Management)
    detection_telemetry: netadmin logins audited; new account or role-grant alerts
  - at_link:            CWE-116
    control:            Restrict SD-WAN Manager CLI file upload capability; isolate
                        SD-WAN Manager from internet-exposed segments pending patch
    control_type:       preventive
    mapped_mitigation:  M1042 (Disable or Remove Feature); M1030 (Network Segmentation)
    detection_telemetry: CLI file upload events alerted; no patch ETA from Cisco

terminal_impact: Arbitrary root command execution on Cisco SD-WAN Manager; potential
                 mass configuration push to all SD-WAN edge devices
score:           8.2  (exploitability=8·0.25 + impact=9·0.25 + relevance=7·0.30 + urgency=9·0.20)
priority:        P1 (no patch; active exploitation)
confidence:      high
source:          Mandiant; CISA KEV 2026-06-09; The Hacker News; GBHackers
```

### Chain 3: Windows Kernel TCP/IP Use-After-Free → Wormable SYSTEM RCE

```
chain_id:     CHAIN-2026-003
name:         CVE-2026-45657 Wormable Windows Kernel RCE Chain
chain_type:   primary_resultant
cwe_view:     CWE-1000 (CWE-416 CanPrecede CWE-94)

links:
  - cwe_id:               CWE-416
    role:                 primary
    name:                 Use After Free
    mitre_id:             T1203 / T1210
    tactic:               Execution
    evidence:             Use-after-free in Windows kernel TCP/IP stack; triggered by
                          crafted network packet (ZDI; Bleeping Computer; CrowdStrike)
    detection_opportunity: Kernel crash dumps; unusual network packet patterns from
                          external sources to Windows RPC/TCP endpoints
    data_source:          Windows crash dump; Network IDS; EDR kernel telemetry
    source:               ZDI June 2026 Review; CrowdStrike PT Analysis

  - cwe_id:               CWE-94
    role:                 resultant
    name:                 Improper Control of Code Generation (Code Injection)
    mitre_id:             T1068
    tactic:               Privilege Escalation → Execution
    evidence:             Successful exploit achieves SYSTEM-level code execution;
                          self-propagating across network via same TCP/IP mechanism
                          (ZDI characterized as EternalBlue-class; Bleeping Computer)
    detection_opportunity: Unexpected process execution as NT AUTHORITY\SYSTEM from
                          kernel-level parent; lateral TCP connections post-exploitation
    data_source:          EDR; Windows Event Log 4688; Network flow
    source:               ZDI; Bleeping Computer; CrowdStrike; hackread.com

enabling_conditions:  Unpatched Windows 11 / Server 2022/2025 (x64 or ARM64); TCP/IP
                      stack reachable from attacker (any network path, including internet)
ai_assist_factor:     high (AI-assisted PoC generation from patch diff; no user interaction
                      required once weaponized; wormable self-propagation amplifies reach)
time_to_exploit:
  observed_days:  estimated 7–21 days to weaponized public exploit post-disclosure
                  (based on EternalBlue precedent and ZDI wormable classification)
  trend:          accelerating
  source:         ZDI June 2026 Review; CrowdStrike PT Analysis

break_points:
  - at_link:            CWE-416 (shared primary)
    control:            Apply June 2026 Microsoft Patch Tuesday immediately — this is
                        the single control that collapses the entire chain
    control_type:       preventive
    mapped_mitigation:  M1051 (Update Software)
    detection_telemetry: Patch compliance >98% across Windows fleet within 48h
  - at_link:            CWE-94 (detect lateral spread if patch delayed)
    control:            Network micro-segmentation; block unsolicited inbound TCP from
                        non-trusted subnets; monitor for SYSTEM process anomalies
    control_type:       detective / corrective
    mapped_mitigation:  M1030 (Network Segmentation); M1049 (Antivirus/Antimalware)
    detection_telemetry: IDS alert on worm-pattern lateral scanning; process-level SYSTEM anomaly

terminal_impact: Unauthenticated SYSTEM-level code execution on all reachable unpatched
                 Windows; worm-propagated lateral compromise of entire Windows fleet
score:           9.8  (exploitability=10·0.25 + impact=10·0.25 + relevance=10·0.30 + urgency=9·0.20)
priority:        P1
confidence:      high
source:          ZDI June 2026 Review; Bleeping Computer; CrowdStrike; hackread.com
```

---

## 8. Detection Rules

> **Lab validation notice:** All rules below are starting points and must be validated in a lab environment before production deployment. YARA signatures should be tested against known-good binaries. SPL/KQL starters are marked `status: needs_validation` — the normalized data model is assumed populated; pair each with its discovery query to confirm.

### 8a. YARA — Qilin Ransomware (Go-compiled binary)

```yara
rule Qilin_Ransomware_GoLang_Generic {
    meta:
        description = "Detects Qilin/Agenda ransomware characteristics (Go-compiled, VSS deletion, Rclone staging)"
        threat      = "Qilin Ransomware RaaS (MITRE S1242)"
        date        = "2026-06-15"
        reference   = "https://attack.mitre.org/software/S1242/"
        reference2  = "https://www.dexpose.io/qilin-ransomware/"
        reference3  = "https://cyble.com/threat-actor-profiles/qilin-ransomware-group/"
        tlp         = "TLP:WHITE"
    strings:
        $go_buildid    = "Go build ID:" ascii
        $vss_del1      = "vssadmin delete shadows" ascii nocase
        $vss_del2      = "Delete Shadows /All /Quiet" ascii nocase
        $rclone        = "rclone" ascii
        $tox_ref       = "tox.chat" ascii
        $ext_agenda    = ".agenda" ascii
        $ext_qilin     = ".qilin" ascii
        $ransom_note1  = "README_TO_RESTORE" ascii
        $ransom_note2  = "HOW_TO_RESTORE" ascii
    condition:
        uint16(0) == 0x5A4D and
        $go_buildid and
        2 of ($vss_del1, $vss_del2, $rclone, $tox_ref, $ext_agenda, $ext_qilin, $ransom_note1, $ransom_note2)
}
```

### 8b. Sigma — Rclone Exfiltration Tool Execution

```yaml
title: Rclone Exfiltration Tool Execution - Ransomware Staging
id: b7c2f3a1-4e8d-4bfa-9c1a-3d7e8f2a1b5c
status: experimental
description: >
  Detects Rclone execution for data exfiltration, associated with Qilin and
  other ransomware groups. Rclone is used to stage and transfer data to
  attacker-controlled cloud storage before encryption.
author: Cyber Threat Intel Skill (2026-06-15)
date: 2026/06/15
tags:
  - attack.exfiltration
  - attack.t1048.002
  - attack.t1567
references:
  - https://attack.mitre.org/software/S1242/
  - https://www.dexpose.io/qilin-ransomware/
  - https://www.kelacyber.com/blog/ransomware-threat-actor-profile-qilin/
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    Image|endswith:
      - '\rclone.exe'
  selection_args:
    CommandLine|contains:
      - ' copy '
      - ' sync '
      - ' move '
      - ' ls '
      - ' lsd '
  condition: selection_process and selection_args
falsepositives:
  - Legitimate IT backup or sync operations using Rclone (investigate context; confirm asset owner)
level: high
```

### 8c. Sigma — AnyDesk Silent Install (Silent Ransom Group / Luna Moth)

```yaml
title: AnyDesk Silent Installation - Extortion Campaign Indicator
id: 3f9a1c7d-8b2e-4d6a-a3f1-2c8e9d4b7a6f
status: experimental
description: >
  Detects silent installation of AnyDesk used by Silent Ransom Group (UNC3753 / Luna Moth)
  for remote access post-phishing. The group issues extortion demands within 30 minutes of
  establishing access without deploying ransomware binaries.
author: Cyber Threat Intel Skill (2026-06-15)
date: 2026/06/15
tags:
  - attack.command_and_control
  - attack.t1219
references:
  - https://www.helpnetsecurity.com/2026/06/08/check-point-cve-2026-50751-qilin-ransomware/
  - https://purple-ops.io/blog/ransomware-tracker-2026
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\AnyDesk.exe'
    CommandLine|contains:
      - '--install'
      - '--start-with-win'
      - '--silent'
  filter_legit_parent:
    ParentImage|contains:
      - '\msiexec.exe'
      - '\sccm'
      - '\ccmexec.exe'
      - '\intune'
  condition: selection and not filter_legit_parent
falsepositives:
  - Legitimate IT helpdesk AnyDesk deployment (validate against asset management)
level: high
```

### 8d. KQL — Microsoft Sentinel (Check Point VPN Anomalous Session)

```kql
// Check Point VPN IKEv1 Session with No Prior Auth Failure (CVE-2026-50751 hunting)
// status: needs_validation
// schema_dependency: CommonSecurityLog or custom Check Point table; fields: DeviceProduct,
//   SourceIP, Activity, DeviceEventClassID, TimeGenerated
// discovery query (confirm table populated):
//   Usage | where TimeGenerated > ago(7d) | summarize sum(Quantity) by DataType, Solution
//
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceProduct has_any ("Check Point", "CheckPoint")
| where DeviceEventClassID has_any ("VPN", "IKE", "Remote Access", "RA")
| where Message has "IKEv1" or Activity has "IKEv1"
| summarize
    AuthSuccess  = countif(Activity has_any ("established", "success", "authenticated")),
    AuthFail     = countif(Activity has_any ("fail", "reject", "denied")),
    SessionCount = count()
    by SourceIP, bin(TimeGenerated, 1h)
| where AuthSuccess > 0 and AuthFail == 0
| extend SuspicionReason = "IKEv1 session established with no auth failure events - CVE-2026-50751 pattern"
| project TimeGenerated, SourceIP, AuthSuccess, AuthFail, SessionCount, SuspicionReason
| order by AuthSuccess desc

// threshold: Any occurrence; tune by adding | where SessionCount > 2 to reduce noise
// validation: Detonate in lab with patched vs. unpatched Check Point VPN, confirm event shape
```

```kql
// Rclone Data Exfiltration Detection - Microsoft Defender for Endpoint
// status: needs_validation
// schema_dependency: DeviceProcessEvents (standard Defender XDR table - no placeholder needed)
//
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName =~ "rclone.exe"
| where ProcessCommandLine has_any ("copy", "sync", "move", "ls", "lsd", "lsf")
| project TimeGenerated, DeviceName, AccountName, AccountDomain,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc

// threshold: Any occurrence triggers high-severity alert
// false positives: Legitimate Rclone backup jobs — suppress by approved-process list
// validation: Run rclone.exe copy locally in lab; confirm event appears before production deploy
```

### 8e. SPL — Splunk (VSS Shadow Copy Deletion)

```splunk-spl
| tstats count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name=vssadmin.exe
    AND (Processes.process="*delete*shadows*" OR Processes.process="*Delete*Shadows*")
  by Processes.dest, Processes.user, Processes.process, Processes.process_name

| rename Processes.* as *
| eval firstTime=strftime(firstTime,"%Y-%m-%dT%H:%M:%SZ"),
       lastTime=strftime(lastTime,"%Y-%m-%dT%H:%M:%SZ"),
       priority="P1 - Ransomware Pre-Stage",
       mitre="T1490"
| table dest, user, process_name, process, firstTime, lastTime, priority, mitre

`comment("status: needs_validation")
`comment("schema_dependency: Endpoint data model, Processes node")
`comment("discovery: | tstats count from datamodel=Endpoint.Processes by index, sourcetype")
`comment("tuning: suppress on known backup vssadmin jobs via lookup table")
`comment("validation: run vssadmin delete shadows in lab; confirm CIM mapping fires before production")
```

```splunk-spl
| tstats count sum(Web.bytes_in) as total_bytes_in
  from datamodel=Web
  where (Web.status="500" OR Web.bytes_in > 20000)
    AND Web.dest_port=80 OR Web.dest_port=443
  by Web.src, Web.dest, Web.uri_path, bin(_time, 5m)

| rename Web.* as *
| where count > 20 OR total_bytes_in > 500000
| eval MB_in=round(total_bytes_in/1024/1024,2),
       note="CVE-2026-47291 HTTP.sys high-volume anomaly hunt"
| sort -count
| table _time, src, dest, uri_path, count, MB_in, note

`comment("status: needs_validation")
`comment("schema_dependency: Web CIM data model")
`comment("discovery: | tstats count from datamodel=Web by index, sourcetype")
`comment("tuning: adjust bytes_in threshold per baseline; high-traffic endpoints may need per-dest exclusions")
```

### 8f. Snort / Suricata

```
# CVE-2026-50751 — IKEv1 Traffic Monitoring (Check Point VPN Exploit)
# Monitor inbound IKEv1 negotiation packets; investigate sessions from unknown VPS ranges
alert udp any any -> $HOME_NET 500 (
    msg:"CTHRT ET POLICY IKEv1 Inbound - Monitor for CVE-2026-50751 Qilin Vector";
    content:"|00 00 00 00 00 00 00 00|";
    offset:8; depth:8;
    threshold: type limit, track by_src, count 3, seconds 60;
    reference:cve,2026-50751;
    reference:url,www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751;
    classtype:attempted-recon;
    sid:9002650; rev:1;
)

# Rclone Exfiltration — User-Agent Detection
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"CTHRT Rclone Data Exfiltration Tool User-Agent Observed";
    flow:established,to_server;
    http.user_agent; content:"rclone/v";
    reference:url,attack.mitre.org/techniques/T1048/002/;
    reference:url,attack.mitre.org/software/S1242/;
    classtype:trojan-activity;
    sid:9002651; rev:1;
)

# Tox Protocol C2 (Qilin) — Port 33445 UDP (default Tox DHT bootstrap port)
alert udp $HOME_NET any -> $EXTERNAL_NET 33445 (
    msg:"CTHRT Possible Tox C2 Outbound - Qilin Ransomware Pattern";
    threshold: type limit, track by_src, count 5, seconds 300;
    reference:url,www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751;
    classtype:trojan-activity;
    sid:9002652; rev:1;
)
```

---

## 9. Actions Matrix

| Priority | Action | Owner | Timeline | Investment | Risk Addressed | Success Metric |
|----------|--------|-------|----------|-----------|---------------|---------------|
| P1 | Apply Check Point hotfix for CVE-2026-50751 and CVE-2026-50752; disable IKEv1 and deprecated Remote Access clients; enforce machine-certificate authentication | Security / Network Ops | 0–48h | Low (config change + hotfix deploy) | Ransomware initial access via VPN zero-day | Zero IKEv1 VPN sessions; hotfix version verified across all gateways |
| P1 | Apply Microsoft June 2026 Patch Tuesday — prioritize CVE-2026-45657 (Windows Kernel, wormable CVSS 9.8) and CVE-2026-47291 (HTTP.sys CVSS 9.8) | Patch Management / Endpoint | 0–48h | Medium (lab test + phased rollout) | Wormable kernel RCE and HTTP.sys RCE at SYSTEM level | ≥98% Windows endpoints patched within 48h; remainder isolated |
| P1 | Update Google Chrome/Chromium (CVE-2026-11645); enforce MDM patching for Android (CVE-2025-48595) | Endpoint / MDM | 0–48h | Low | Browser and mobile exploitation | Browser version compliance confirmed in EDR/MDM |
| P1 | Isolate Cisco Catalyst SD-WAN Manager from internet; restrict netadmin role to named accounts; enable and audit CLI file-upload logging — no patch exists for CVE-2026-20245 | Network / SD-WAN Ops | 0–48h | Low (policy change; monitoring setup) | Root RCE on SD-WAN Manager and mass edge-device compromise | SD-WAN Manager restricted; audit log enabled; alerts on CLI file uploads |
| P2 | Deploy Sigma rules (Rclone, AnyDesk silent install, VSS deletion) and SPL/KQL starters to SIEM; validate in lab first | SOC / Detection Engineering | 48h–7d | Medium (lab + tuning effort) | Ransomware staging, exfil, and persistence detection | Rules active in SIEM; alert verified against lab detonation; FP rate <5% |
| P2 | Conduct retroactive hunt for IKEv1 sessions with no prior auth-failure event (CVE-2026-50751 breach check) — search VPN logs back to May 7, 2026 | Threat Hunting | 48h–7d | Medium | Determine if compromise preceded hotfix deployment | Hunt complete; all unaccounted sessions investigated; IR initiated if breach confirmed |
| P2 | Patch Arista EOS for CVE-2026-7473; audit firmware across Arista device fleet | Network Ops | 48h–7d | Low | Network device compromise via CISA KEV Arista flaw | Full Arista fleet patched; no devices running vulnerable EOS version |
| P3 | Assess OT/ICS exposure to Mustang Panda, Lazarus, and Sandworm APT targeting patterns; review energy/utilities asset segmentation | OT Security / Threat Intel | 7–30d | Medium | APT pre-positioning and wiper deployment in critical infrastructure | Exposure assessment documented; critical segmentation gaps remediated; OT/IT boundary controls validated |
| P3 | Deploy YARA rules to EDR and Snort/Suricata signatures to network IDS; test Tox port-33445 detection in lab | SOC / Detection Engineering | 7–30d | Medium | Qilin ransomware binary detection and C2 communication detection | YARA rules active on EDR; Snort rules deployed to perimeter IDS; lab-validated |
| P3 | Conduct phishing-resilience exercise targeting Silent Ransom Group invoice lure patterns; verify email gateway blocking of AnyDesk installer attachments | Security Awareness / Email Security | 7–30d | Low | Invoice-phishing initial access; AnyDesk remote-access RAT | Phishing simulation results documented; AnyDesk installer blocked at gateway |
| P4 | Full SD-WAN credential rotation; implement MFA on all privileged SD-WAN Manager accounts; review whether CVE-2026-20182/CVE-2026-20127 were previously exploited | Identity / IAM | 30–90d | Medium | Privilege escalation via credential theft feeding CVE-2026-20245 | All netadmin accounts use MFA; credential audit complete; no evidence of prior exploit chain |
| P4 | Evaluate network micro-segmentation to limit worm-propagation blast radius for future EternalBlue-class vulnerabilities; implement Zero Trust lateral movement controls | Architecture / Network | 30–90d | High | Wormable exploit propagation across internal segments | Segmentation implemented; lateral movement blocked between non-peer segments in tabletop exercise |

---

## 10. Intelligence Gaps

1. **Check Point VPN IOC blocklist (specific IPs/hashes):** Exploitation infrastructure (Kaupo Cloud HK, Shock Hosting, Vultr Holdings) referenced by Rapid7 and eSentire but specific IPs were not returned by this run's web queries. Consult Check Point Blog IOC appendix and CISA KEV detail page directly for the current IP blocklist. These should be deployed to perimeter firewalls.

2. **Qilin June 2026 campaign hashes:** Current sample hashes require live MalwareBazaar / ThreatFox / Hybrid Analysis API queries not performed in this run. Query `https://bazaar.abuse.ch/browse/tag/Qilin/` for confirmed samples tagged in the June 8–15 window.

3. **CVE-2026-20245 Cisco patch timeline:** Cisco has not published a patch ETA as of the report date. This creates an open remediation gap. Monitor `https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-CVE-2026-20245` for patch availability.

4. **Dark web intelligence (Tier 7 paywalled):** Qilin victim negotiation data, emerging TTPs from RaaS affiliate forums, and darknet chatter on CVE-2026-45657 weaponization were not accessible. Recommended: Flashpoint, Intel 471, or KELA subscription for continuous darknet coverage.

5. **GreyNoise live scanner counts:** GreyNoise references appear in narrative reporting but real-time scanner IP counts for CVE-2026-50751 and CVE-2026-45657 were not directly queried in this run. Use `https://viz.greynoise.io/` to pull live exploitation telemetry for these CVEs.

6. **Bug bounty disclosures (Tier 4):** No specific HackerOne or Bugcrowd disclosed reports were identified for this 7-day window. Either no relevant public disclosures occurred or they were not indexed in this search.

7. **DynoWiper (Sandworm) IOC carry-forward:** Sandworm's DynoWiper campaign (Poland power grid, Dec 2025–Jan 2026) was referenced but not fully analyzed for IOC currency in the June 2026 window. Energy sector defenders should consult the CISA/NCSC DynoWiper advisory for host and network indicators.

8. **APT42 phishing domains (June 2026 campaign):** APT42 account-compromise activity is referenced in aggregate reporting (CYFIRMA, CloudSEK) but specific phishing domains and credential-harvesting infrastructure for the current period were not returned.

---

## Appendix A: Source Coverage Ledger

| Tier | Required Min | Consulted | Skipped (with reason) | Met? |
|------|-------------|-----------|----------------------|------|
| 1 — Vuln DBs & Exploits | 5 | NVD (CVE records via web search), CISA KEV (June 2 & 9 additions directly cited), CVE.org (CVE references), MITRE ATT&CK (S1242 Qilin; T1490; TTP mapping), ZDI (June 2026 Security Update Review), Exploit-DB (referenced as context) | VulDB, OpenCVE, Sploitus, Zero Day Clock — not queried this run | **yes** |
| 2 — Commercial Threat Intel | 4 | Mandiant / Google TI (CVE-2026-20245 discovery and exploitation reporting), CrowdStrike (June 2026 Patch Tuesday analysis), Rapid7 (Check Point CVE-2026-50751 ETR), eSentire (CVE-2026-50751 advisory), Cisco Talos (context), Unit 42 (dwell-time compression statistic) | Recorded Future, SentinelLabs, Secureworks, Kaspersky Securelist — not queried (paywalled or not returned) | **yes** |
| 3 — Search Engines & Aggregators | 3 | GreyNoise (elevated scanning narrative — not direct API query), VirusTotal (referenced as validation target), AlienVault OTX (context), SOCPrime (CVE-2026-50751 and CVE-2026-20245 analysis) | Shodan, Censys, URLScan, IntelX — not directly queried | **partial** (narrative refs; no live API data) |
| 4 — Bug Bounty | 2 | HackerOne (referenced platform), Bugcrowd (referenced platform) | No specific June 2026 disclosed reports found for the relevant CVEs | **no** |
| 5 — Offensive Security Research | 2 | ZDI (primary — wormable classification of CVE-2026-45657), Rapid7 blog (ETR for Check Point zero-day) | SpecterOps, Project Zero (no specific June 2026 content returned) | **yes** |
| 6 — Community Researchers | 3 | Bleeping Computer (June 2026 Patch Tuesday), The Hacker News (Cisco SD-WAN), Help Net Security (Check Point PoC; Qilin VPN), Industrial Cyber (APT energy sector), Security Affairs (Patch Tuesday), SOCPrime (CVE analysis), PurpleOps (Ransomware Tracker), Dexpose.io (Qilin TTPs), Blackpoint Cyber (Qilin profile), Cyble (Qilin), KELA (Qilin) | Krebs on Security, DFIR Report, SANS ISC — not queried this run | **yes** |
| 7 — Dark Web Intel | best-effort | KELA (referenced narratively), Recorded Future (background context) | Flashpoint, Intel 471, DarkOwl, Cybersixgill, SOCRadar — all paywalled; inaccessible | **n/a** (partial) |
| 8 — Government / Regulatory | 3 | CISA KEV/Advisories (direct — June 2 & 9 KEV additions), CISA narrative context, FBI IC3 (background), NCSC UK (context) | NSA Cybersecurity Advisories, ENISA, JPCERT/CC, ACSC — not directly queried | **partial** (CISA primary; others background) |
| 9 — Malware Analysis | 3 | MalwareBazaar / abuse.ch (platform searched; no direct API sample query for this window), URLhaus (context), Hybrid Analysis (referenced as recommended validation path) | Any.Run, Joe Sandbox, Triage, Cape Sandbox — not directly queried; no live malware samples analyzed | **no** (platform known; samples not directly retrieved) |

**Total preferred-source targets consulted:** ~17 / ≈25

**Coverage badge (honest self-report): PARTIAL**
_Tiers 1, 2, 5, and 6 are well covered from live web queries. Tiers 3 and 8 are partially covered (narrative references; no live API data). Tiers 4, 7, and 9 are thin or inaccessible this run._

**Fabrication check:** No IOC, CVE number, hash, IP address, or actor attribution was invented. All specific CVE IDs and actor attributions are sourced from named vendor/government publications retrieved in this run. Network IOC values (IPs within the named ASNs) were not emitted because specific values were not returned by source queries; they are flagged in Intelligence Gaps with retrieval guidance. The `status: unverified` designation is not applied because named sources are accessible via their published URLs — the gap is live API blocklist data, not source existence.

---

## Sources

Live sources consulted in this run (web search — June 15, 2026):

- [CISA Adds Three Known Exploited Vulnerabilities to Catalog — June 9, 2026](https://www.cisa.gov/news-events/alerts/2026/06/09/cisa-adds-three-known-exploited-vulnerabilities-catalog)
- [CISA Adds Two Known Exploited Vulnerabilities to Catalog — June 2, 2026](https://www.cisa.gov/news-events/alerts/2026/06/02/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [Critical Check Point VPN Zero-Day Exploited in the Wild (CVE-2026-50751) — Rapid7](https://www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751/)
- [CVE-2026-50751: Check Point VPN Auth Bypass — SOCPrime](https://socprime.com/blog/cve-2026-50751-check-point-vpn-authentication-bypass-exploited-in-targeted-attacks/)
- [Qilin ransomware affiliate exploited Check Point VPN zero-day — Help Net Security](https://www.helpnetsecurity.com/2026/06/08/check-point-cve-2026-50751-qilin-ransomware/)
- [Researchers release PoC for CVE-2026-50751 — Help Net Security](https://www.helpnetsecurity.com/2026/06/12/cve-2026-50751-poc-exploit/)
- [CVE-2026-50751 Critical Check Point VPN Authentication Bypass — eSentire](https://www.esentire.com/security-advisories/cve-2026-50751-critical-check-point-vpn-authentication-bypass-vulnerability)
- [Microsoft June 2026 Patch Tuesday Fixes 6 Zero-Days, 200 Flaws — Bleeping Computer](https://www.bleepingcomputer.com/news/microsoft/microsoft-june-2026-patch-tuesday-fixes-6-zero-days-200-flaws/)
- [Zero Day Initiative — June 2026 Security Update Review](https://www.zerodayinitiative.com/blog/2026/6/9/the-june-2026-security-update-review)
- [June 2026 Patch Tuesday Analysis — CrowdStrike](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-june-2026/)
- [Microsoft June 2026 Critical CVEs (Kernel/HTTP.sys) — threat-modeling.com](https://threat-modeling.com/microsoft-june-2026-patch-tuesday-critical-cves/)
- [CVE-2026-20245 Cisco SD-WAN Manager Zero-Day — SOCPrime](https://socprime.com/blog/cve-2026-20245-analysis/)
- [Cisco SD-WAN Manager CVE-2026-20245 Actively Exploited — The Hacker News](https://thehackernews.com/2026/06/cisco-catalyst-sd-wan-manager-cve-2026.html)
- [Cisco SD-WAN Flaw Exploited for Root-Level Command Execution — GBHackers](https://gbhackers.com/cisco-sd-wan-security-flaw/)
- [Qilin Ransomware — MITRE ATT&CK S1242](https://attack.mitre.org/software/S1242/)
- [Qilin Ransomware: Group Profile, TTPs, IOCs & Defense (2026) — Dexpose.io](https://www.dexpose.io/qilin-ransomware/)
- [Ransomware Threat Actor Profile: Qilin — KELA Cyber](https://www.kelacyber.com/blog/ransomware-threat-actor-profile-qilin/)
- [Threat Actor Profile: Qilin Ransomware Group — Cyble](https://cyble.com/threat-actor-profiles/qilin-ransomware-group/)
- [Qilin Ransomware — Blackpoint Cyber](https://blackpointcyber.com/threat-profile/qilin-ransomware/)
- [Ransomware Activity Tracker 2026 — PurpleOps](https://purple-ops.io/blog/ransomware-tracker-2026)
- [Energy and utilities sector targeted in 66% of APT campaigns — Industrial Cyber](https://industrialcyber.co/reports/energy-and-utilities-sector-targeted-in-66-of-observed-apt-campaigns-as-mustang-panda-lazarus-sandworm-remain-active/)
- [New DynoWiper Malware Used in Attempted Sandworm Attack on Polish Power Sector — The Hacker News](https://thehackernews.com/2026/01/new-dynowiper-malware-used-in-attempted.html)
- [U.S. Public Sector Under Siege — Trend Micro](https://www.trendmicro.com/en_us/research/26/d/us-public-sector-under-siege.html)
- [MalwareBazaar — abuse.ch](https://bazaar.abuse.ch/)
- [URLhaus — abuse.ch](https://urlhaus.abuse.ch/)
