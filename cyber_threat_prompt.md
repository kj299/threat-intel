# Cyber Threat Intelligence Prompt

## User Input

**Answer the following to scope the analysis. If no input is provided, defaults are used automatically.**

1. **Search Scope**: What is your primary focus area?
   - [ ] All emerging threats (comprehensive scan) **(DEFAULT)**
   - [ ] Specific threat category (ransomware, APT, supply chain, etc.)
   - [ ] Industry-specific (financial services, banking, fintech)
   - [ ] Geographic focus (nation-state actors, regional threats)

2. **Time Range**: How recent should the intelligence be?
   - [ ] Last 24-48 hours (breaking threats)
   - [ ] Last 7 days **(DEFAULT)**
   - [ ] Last 30 days
   - [ ] Last 90 days

3. **New Business Context**: What new business line is the organization entering? (optional)
   - [User Input -- skip if not applicable]

4. **Specific Assets of Concern**:
   - Network edge devices, endpoints, mobile, APIs, payment systems **(DEFAULT)**
   - [Or specify your own: cloud infrastructure, OT/ICS, IoT, etc.]

5. **Depth of Technical Detail**:
   - [ ] Executive-level (business impact focus)
   - [ ] Technical summary (IOCs + TTPs)
   - [ ] Full technical (exploit details, PoC references, IOCs, detection rules) **(DEFAULT)**

> **If the user does not provide answers to the above questions, proceed immediately using all default values. Do not ask clarifying questions -- begin the analysis.**

---

## Part 1: Comprehensive Threat Intelligence Source Matrix

### Search across ALL of the following sources for the latest cyber threat intelligence:

---

### TIER 1: Vulnerability Databases & Exploit Repositories

**Primary Vulnerability Databases**
- MITRE ATT&CK Framework (attack.mitre.org) - Latest techniques, tactics, and procedures
- NIST National Vulnerability Database (nvd.nist.gov) - Official CVE records
- CISA Known Exploited Vulnerabilities (KEV) Catalog
- CVE.org - Primary CVE assignment database
- CVE Details (cvedetails.com) - Vulnerability statistics, trends, and vendor tracking
- VulDB - Comprehensive vulnerability database
- OpenCVE (opencve.io) - CVE alerting and tracking platform

**Exploit Databases & Proof-of-Concept Sources**
- Exploit-DB (exploit-db.com) - Archive of exploits and vulnerable software
- Vulners (vulners.com) - Vulnerability intelligence search engine
- Packet Storm Security (packetstormsecurity.com) - Exploits, tools, and advisories
- Rapid7 Vulnerability Database
- Sploitus - Exploit and hacking tools search engine
- ExploitPack (exploitpack.com) - Advanced exploitation framework and exploit collection
- 0day.today - Exploit database
- GitHub Security Advisories
- GitHub exploit PoC repositories (search: "CVE-[YEAR]" + "PoC")

---

### TIER 2: Commercial Threat Intelligence Platforms

**Premium Threat Intelligence**
- Recorded Future - Real-time threat intelligence, dark web monitoring, IOC feeds
- Mandiant/Google Threat Intelligence - APT tracking, incident response insights
- CrowdStrike Falcon Intelligence - Adversary profiles, threat reports
- Microsoft Threat Intelligence Center (MSTIC) - Nation-state tracking
- Microsoft Security Blog - Latest vulnerabilities and threat research
- Cisco Talos Intelligence - Malware analysis, threat trends
- Palo Alto Unit 42 - Threat research and adversary playbooks
- SentinelOne Labs (SentinelLabs) - Malware research, APT analysis
- Secureworks Counter Threat Unit
- Sophos X-Ops - Threat reports and active adversary analysis
- Trend Micro Research
- Fortinet FortiGuard Labs
- Kaspersky Securelist
- ESET Research
- Check Point Research
- Proofpoint Threat Insight

**Attack Surface & Exposure Intelligence**
- GreyNoise Intelligence (greynoise.io) - Internet-wide scan data, mass exploitation tracking
- Shodan - Internet-connected device intelligence
- Censys - Attack surface management intelligence
- BinaryEdge - Threat intelligence and attack surface
- ZoomEye - Cyberspace search engine
- ONYPHE - Cyber defense search engine
- Hunter.io - Email and domain intelligence
- SecurityTrails - DNS and domain intelligence

---

### TIER 3: Cybersecurity Search Engines & Aggregators

**Specialized Security Search Engines**
(Note: Some sources appear in multiple tiers when they serve dual purposes -- e.g., VirusTotal is both a search engine and a malware analysis tool.)
- Shodan (shodan.io) - IoT and infrastructure search
- Censys (censys.io) - Certificate and host search
- GreyNoise (greynoise.io) - Scan and attack traffic analysis
- ZoomEye (zoomeye.org) - Cyberspace mapping
- Fofa (fofa.info) - Network asset search
- Hunter (hunter.io) - Email discovery
- FullHunt (fullhunt.io) - Attack surface discovery
- CRT.sh - Certificate transparency search
- DNSDumpster - DNS reconnaissance
- VirusTotal - Malware and URL analysis
- Hybrid Analysis - Free malware analysis
- Any.Run - Interactive malware sandbox
- URLScan.io - Website scanning and analysis
- PublicWWW - Source code search engine
- Pulsedive - Threat intelligence search
- ThreatCrowd - Threat intelligence mashup
- AlienVault OTX - Open threat exchange
- IntelX (intelx.io) - OSINT search engine
- LeakIX - Exposed services search
- Netlas.io - Attack surface discovery
- OSINT Framework - OSINT tool collection
- CVE Details (cvedetails.com) - CVE browsing by vendor, product, and version
- Nuclei Templates (github.com/projectdiscovery/nuclei-templates) - Community detection templates

---

### TIER 4: Bug Bounty & Vulnerability Disclosure Platforms

**Bug Bounty Platforms (Real-World Vulnerability Discoveries)**
- HackerOne (hackerone.com) - Disclosed vulnerability reports, hacker insights
- Bugcrowd - Vulnerability disclosures and researcher findings
- Hackrate (hackrate.co) - European bug bounty platform
- Detectify (detectify.com) - Crowdsourced security scanner findings
- Synack - Red team vulnerability discoveries
- Cobalt - Pentest-as-a-Service findings
- Intigriti - Bug bounty disclosures
- YesWeHack - European bug bounty platform
- Open Bug Bounty - Non-profit disclosure platform

---

### TIER 5: Penetration Testing & Offensive Security Resources

**Vulnerable Application Labs & Training Platforms**
- bWAPP (buggy Web Application) - Web vulnerability reference
- OWASP Mutillidae II - Deliberately vulnerable web application
- Google Gruyere - Web application security training
- Defend The Web (defendtheweb.net) - Hacking challenges and community
- DVWA (Damn Vulnerable Web Application)
- HackTheBox - Attack techniques and methodologies
- TryHackMe - Offensive security training
- VulnHub - Vulnerable VM downloads
- PentesterLab - Web penetration testing
- PortSwigger Web Security Academy
- OWASP WebGoat
- CyberDefenders - Blue team CTF challenges
- LetsDefend - SOC analyst training platform
- Root Me - Hacking and security challenges

**Offensive Security Research**
- OffSec (offsec.com) - Exploit development research, OSCP/OSEP training, Exploit-DB maintainers
- ExploitPack (exploitpack.com) - Exploitation framework with 39,000+ exploits
- SANS Penetration Testing Blog
- Red Team Journal
- SpecterOps Blog - Adversary simulation research
- Cobalt Strike Blog - Red team TTPs
- Metasploit Blog
- Rapid7 Blog
- Pentest Partners Blog - IoT and automotive security research
- ProjectDiscovery Blog - Open-source security tooling (Nuclei, httpx)

---

### TIER 6: Community & Independent Researcher Sources

**Reddit Security Communities**
- r/netsec - Information security news and discussion
- r/cybersecurity - General cybersecurity discussion
- r/hacking - General hacking discussion and news
- r/hackernews - Hacker News discussion and security links
- r/hackers - Hacker culture and security discussion
- r/masterhacker - Security humor and awareness (parody/educational)
- r/bugbounty - Bug bounty findings, tips, and platform discussion
- r/Hacking_Tutorials - Hacking tutorials and learning resources
- r/ExploitDev - Exploit development techniques and research
- r/malware - Malware analysis and research
- r/ReverseEngineering - Binary analysis and exploitation
- r/AskNetsec - Security Q&A
- r/blueteamsec - Defensive security
- r/redteamsec - Offensive security
- r/Pentesting - Penetration testing
- r/sysadmin - System administration and infrastructure security
- r/homesecurity - Home and personal security (physical and digital)
- r/crypto - Cryptography
- r/privacy - Privacy and security
- r/computerforensics - Digital forensics and incident response

**Hacker News & Tech Communities**
- Hacker News / Y Combinator (news.ycombinator.com) - Security-tagged submissions
- Lobste.rs - Security tag
- Slashdot Security
- Stack Exchange Information Security

**Independent Security Researchers & Blogs**
- Krebs on Security (krebsonsecurity.com)
- Schneier on Security (schneier.com)
- Graham Cluley (grahamcluley.com)
- Troy Hunt (troyhunt.com)
- The Hacker News (thehackernews.com)
- Cybersecurity News (cybersecuritynews.com)
- Bleeping Computer (bleepingcomputer.com)
- Dark Reading
- Threatpost
- Security Affairs
- The DFIR Report
- Malwarebytes Labs
- SANS Internet Storm Center (ISC)
- SANS Reading Room
- Risky Business News (risky.biz) - Cybersecurity podcast and newsletter
- tl;dr sec - Weekly security newsletter

**Twitter/X Security Community**
- #infosec, #threatintel, #malware, #APT, #CVE
- Security researcher accounts and threat intel sharing

**Mastodon / Fediverse**
- infosec.exchange - Primary infosec Mastodon instance
- ioc.exchange - Threat intel sharing community

---

### TIER 7: Dark Web & Underground Intelligence

**Dark Web Intelligence Platforms** (legally accessible reports and feeds)
- Recorded Future Dark Web Intelligence
- Flashpoint - Deep and dark web monitoring
- Intel 471 - Underground intelligence
- DarkOwl - Darknet data intelligence
- Kela - Cyber threat intelligence
- Cybersixgill - Deep web intelligence
- SOCRadar - Dark web monitoring and attack surface management
- ReliaQuest (formerly Digital Shadows) - Digital risk protection
- ZeroFox - External threat intelligence and takedown services
- Searchlight Cyber - Dark web monitoring

---

### TIER 8: Government & Regulatory Advisories

**U.S. Government**
- CISA Alerts and Advisories (cisa.gov)
- FBI Internet Crime Complaint Center (IC3)
- FBI Flash Alerts
- NSA Cybersecurity Advisories
- US-CERT
- DHS Cybersecurity
- NIST Cybersecurity Publications

**International Government**
- NCSC UK - Threat Reports and Advisories
- ACSC Australia - Advisories
- CCCS Canada - Cyber Centre Alerts
- BSI Germany
- ANSSI France
- ENISA (EU) - Threat Landscape Reports
- JPCERT/CC Japan - Coordination Center alerts
- CERT-In India - Vulnerability notes and advisories

**Financial Sector Specific**
- FS-ISAC (Financial Services ISAC) - Alerts and threat sharing
- SWIFT CSCF and Security Updates
- FCA (UK) Cyber Alerts
- OCC (US) Cybersecurity Bulletins
- Federal Reserve Cybersecurity
- Bank of England Operational Resilience
- FFIEC Cybersecurity Guidance
- PCI Security Standards Council

---

### TIER 9: Malware Analysis & Sandboxing

**Malware Repositories & Analysis**
- VirusTotal (virustotal.com) - Multi-engine scanning
- Hybrid Analysis (hybrid-analysis.com) - Free malware analysis
- Any.Run (any.run) - Interactive sandbox
- Joe Sandbox
- Triage (tria.ge) - Malware sandbox
- MalwareBazaar (bazaar.abuse.ch) - Malware sample sharing
- URLhaus (urlhaus.abuse.ch) - Malicious URL tracking
- ThreatFox (threatfox.abuse.ch) - IOC sharing by abuse.ch
- Malpedia - Malware encyclopedia
- YARA Rules Repository
- Malshare
- theZoo - Live malware repository
- Hatching Triage - Automated malware analysis
- Cape Sandbox - Open-source malware sandbox

---

## Part 2: Threat Intelligence Extraction Framework

### For each source searched, extract and categorize:

#### A. New Attack Methods & Techniques
| Field | Details |
|-------|---------|
| **Technique Name** | |
| **MITRE ATT&CK ID** | (T####.###) |
| **Attack Vector** | Initial Access / Execution / Persistence / Priv Esc / Defense Evasion / Credential Access / Discovery / Lateral Movement / Collection / C2 / Exfiltration / Impact |
| **CVE(s) Associated** | |
| **CVSS Score** | |
| **Exploit Availability** | None / PoC / Weaponized / In-The-Wild |
| **First Observed** | Date |
| **Source(s)** | |
| **Sophistication Level** | Basic / Intermediate / Advanced / Nation-State |
| **Targeted Sectors** | |
| **Targeted Technologies** | |
| **Technical Description** | |
| **Business Impact** | |

#### B. Indicators of Compromise (IOCs)
Extract and categorize all IOCs found. For each IOC, include: value, confidence level, source, first/last seen dates, associated threat actor, MITRE technique, recommended action (block/alert/hunt), and TLP marking.

**Network-Based IOCs**
| Type | Value | Confidence | Source | First Seen | Last Seen | Associated Threat | MITRE Technique | Action | TLP |
|------|-------|------------|--------|------------|-----------|-------------------|-----------------|--------|-----|
| IPv4 Address | | High/Med/Low | | | | | | Block/Alert/Hunt | |
| IPv6 Address | | | | | | | | | |
| Domain | | | | | | | | | |
| URL | | | | | | | | | |
| SSL Cert Hash | | | | | | | | | |
| JA3 Fingerprint | | | | | | | | | |
| JA3S Fingerprint | | | | | | | | | |
| JARM Fingerprint | | | | | | | | | |
| User Agent | | | | | | | | | |
| CIDR Range | | | | | | | | | |

**Host-Based IOCs**
| Type | Value | Confidence | Source | Associated Threat | Platform | Action | Detection Source |
|------|-------|------------|--------|-------------------|----------|--------|-----------------|
| SHA-256 Hash | | | | | Win/Lin/Mac | Block/Alert | EDR/AV |
| SHA-1 Hash | | | | | | | |
| MD5 Hash | | | | | | | |
| SSDEEP | | | | | | | |
| IMPHASH | | | | | | | |
| File Name | | | | | | | |
| File Path | | | | | | | Sysmon/EDR |
| Registry Key | | | | | Windows | | Sysmon Event 12/13 |
| Registry Value | | | | | Windows | | Sysmon Event 13 |
| Scheduled Task | | | | | Windows | | Event ID 4698 |
| Service Name | | | | | Windows | | Event ID 7045 |
| Mutex | | | | | | | EDR |
| Named Pipe | | | | | | | Sysmon Event 17/18 |
| Process Name | | | | | | | Sysmon Event 1 |
| Command Line | | | | | | | Sysmon Event 1 |
| WMI Subscription | | | | | Windows | | Sysmon Event 19/20/21 |

**Email-Based IOCs**
| Type | Value | Confidence | Campaign | Action |
|------|-------|------------|----------|--------|
| Sender Address | | | | Block at gateway |
| Sender Domain | | | | Block at gateway |
| Reply-To Address | | | | Alert |
| Subject Pattern | | | | Mail rule/alert |
| Attachment Name | | | | Block at gateway |
| Attachment Hash | | | | Block at gateway |
| X-Originating-IP | | | | Block/investigate |

**Behavioral IOCs & Anomaly Indicators**
For each behavioral indicator, specify: the detection data source, SIEM query logic, and alert threshold.

| Behavior | Data Source | Detection Logic | MITRE Technique | Alert Threshold |
|----------|------------|-----------------|-----------------|-----------------|
| Unusual authentication patterns | Auth logs / Azure AD | Failed logins > N in M minutes | T1110 | 10 failures in 5 min |
| Abnormal data transfer volumes | Proxy / DLP logs | Outbound transfer > X GB | T1041 | >500MB to new destination |
| Off-hours activity | SIEM correlation | Activity outside business hours | T1078 | Privileged account, 1-5 AM |
| Impossible travel | Azure AD / IdP | Login from 2 locations < travel time | T1078 | Any occurrence |
| Privilege escalation sequences | Windows Security logs | Privilege change events (4672, 4673) | T1068 | Non-admin to admin |
| Lateral movement patterns | Network / EDR logs | SMB/WMI/WinRM to multiple hosts | T1021 | >3 hosts in 1 hour |
| Data staging behaviors | EDR / file monitoring | Large archive creation in temp dirs | T1074 | >100MB archive in %TEMP% |
| C2 beaconing patterns | Proxy / DNS logs | Regular interval callbacks | T1071 | Consistent interval +/- jitter |
| DNS tunneling | DNS logs | High volume / long subdomain queries | T1071.004 | >50 unique subdomains/hour |
| Process injection | EDR / Sysmon | Cross-process memory writes | T1055 | Any occurrence |

#### C. Tactics, Techniques & Procedures (TTPs)
Map to MITRE ATT&CK framework:

| Tactic | Technique ID | Technique Name | Sub-Technique | Procedure Details | Detection Method | Data Sources |
|--------|--------------|----------------|---------------|-------------------|------------------|--------------|
| Reconnaissance | | | | | | |
| Resource Development | | | | | | |
| Initial Access | | | | | | |
| Execution | | | | | | |
| Persistence | | | | | | |
| Privilege Escalation | | | | | | |
| Defense Evasion | | | | | | |
| Credential Access | | | | | | |
| Discovery | | | | | | |
| Lateral Movement | | | | | | |
| Collection | | | | | | |
| Command and Control | | | | | | |
| Exfiltration | | | | | | |
| Impact | | | | | | |

---

## Part 3: Threat Extrapolation & Inference Engine

### Based on gathered intelligence, infer and extrapolate:

#### A. Emerging Attack Pattern Analysis
1. **Cross-Source Correlation**: What threats appear across multiple sources?
2. **Technique Evolution**: How are known techniques being modified or combined?
3. **Tool Development**: New malware families, frameworks, or offensive tools?
4. **Infrastructure Shifts**: Changes in C2, hosting, or operational patterns?
5. **Exploit Chains**: How are multiple vulnerabilities being combined?
6. **Living-off-the-Land**: New abuse of legitimate tools?

#### B. Predictive IOC Generation
Based on observed patterns, infer likely future IOCs:
- **Domain Generation Algorithms (DGA)**: Predict potential malicious domains
- **Infrastructure Patterns**: Identify ASNs, hosting providers, or regions likely to host malicious infrastructure
- **File Naming Conventions**: Predict malware file names based on campaign patterns
- **Behavioral Signatures**: Anticipate process behaviors based on technique evolution
- **C2 Protocol Patterns**: Expected communication characteristics

#### C. Threat Actor Profile Updates
| Actor/Group | Type | Motivation | New TTPs | New Infrastructure | Target Changes | Confidence |
|-------------|------|------------|----------|-------------------|----------------|------------|
| | APT/Criminal/Hacktivist | | | | | |

#### D. Vulnerability Exploitation Forecast
Based on GreyNoise, Recorded Future, and bug bounty data:
| CVE | Days Since Disclosure | Exploit Maturity | Mass Exploitation Detected | Org Exposure | Priority |
|-----|----------------------|------------------|---------------------------|---------------|----------|
| | | PoC/Weaponized/ITW | Yes/No (GreyNoise) | | |

---

## Part 4: High-Profile Business Risk Analysis

### Given the organization's expansion into [new business line], assess:

#### Increased Threat Exposure Matrix
| Factor | Current State | Post-Expansion State | Risk Delta | Relevant Threats |
|--------|---------------|----------------------|------------|------------------|
| Attack Surface | | | | |
| Threat Actor Interest | | | | |
| Data Value to Attackers | | | | |
| Regulatory Scrutiny | | | | |
| Third-Party Risk | | | | |
| Technology Stack Changes | | | | |
| Customer Profile Changes | | | | |

#### Threat Scenario Modeling
For each major threat identified, model the attack scenario:

**Scenario Template:**
1. **Scenario ID & Name**: 
2. **Threat Actor Profile**: 
3. **Initial Access Vector**: 
4. **Complete Attack Chain**: (Recon → Weaponize → Deliver → Exploit → Install → C2 → Actions)
5. **MITRE ATT&CK Mapping**: 
6. **Likelihood Score**: (1-5 with rationale)
7. **Impact Assessment**: 
   - Financial: $
   - Operational: 
   - Reputational: 
   - Regulatory: 
8. **Existing Controls**: 
9. **Control Gaps**: 
10. **Detection Opportunities**: 
11. **Recommended Mitigations**: 

---

## Part 5: Executive Summary Output

### Structure the final briefing as follows:

#### 1. Critical Alert Banner (if applicable)
```
🔴 CRITICAL: [Active exploitation / Zero-day / Imminent threat requiring immediate action]
🟠 HIGH: [Significant threat with near-term risk]
🟡 ELEVATED: [Notable threats requiring attention]
```

#### 2. Executive Summary (5-7 bullet points)
- Most critical threats requiring board/executive awareness
- New threat actors or campaigns targeting financial services
- Key vulnerability trends (CVEs, exploit availability)
- Attack surface changes relevant to new business
- Regulatory implications
- Peer institution incidents (if applicable)
- Key metric changes from previous period

#### 3. Threat Dashboard

| Threat Category | New This Period | Active Exploits | Trend | Risk Level | Org Relevance |
|-----------------|-----------------|-----------------|-------|------------|----------------|
| Ransomware | | | ↑↓→ | | |
| APT/Nation-State | | | ↑↓→ | | |
| Supply Chain | | | ↑↓→ | | |
| Zero-Day | | | ↑↓→ | | |
| Cloud Security | | | ↑↓→ | | |
| API Security | | | ↑↓→ | | |
| Insider Threat | | | ↑↓→ | | |
| Credential Attacks | | | ↑↓→ | | |
| BEC/Social Engineering | | | ↑↓→ | | |

#### 4. Critical Vulnerability Summary
| CVE | CVSS | Product | Exploit Status | GreyNoise Activity | Org Exposure | Action Required |
|-----|------|---------|----------------|-------------------|---------------|-----------------|
| | | | | | | |

#### 5. New Business Line Risk Spotlight
Dedicated section on how expansion increases threat profile with specific, actionable concerns.

#### 6. IOC Package for Security Operations

Provide exportable IOC lists formatted for direct SIEM/EDR/firewall ingestion. Each IOC must include: value, type, confidence level, associated threat, source, first seen date, and recommended action.

**Immediate Block (High Confidence)**

Network IOCs -- formatted for firewall/proxy block rules:
```
# FORMAT: type | value | threat | source | first_seen | TLP
IPv4 | 185.220.101.xxx | LockBit 3.0 C2 | Recorded Future | 2026-03-24 | AMBER
Domain | update-service[.]cloud | LockBit payload delivery | Mandiant | 2026-03-23 | AMBER
URL | https://malicious[.]site/payload.exe | Dropper URL | MalwareBazaar | 2026-03-25 | AMBER
```

Host IOCs -- formatted for EDR/endpoint block rules:
```
# FORMAT: type | value | threat | source | platform
SHA256 | a1b2c3d4e5f6... | LockBit 3.0 encryptor | MalwareBazaar | Windows
SHA256 | f7e8d9c0b1a2... | Cobalt Strike beacon | Hybrid Analysis | Windows
File_Name | svchost_update.exe | LockBit loader | The DFIR Report | Windows
```

Email IOCs -- formatted for mail gateway rules:
```
# FORMAT: type | value | confidence | campaign
Sender_Domain | phishing-domain[.]com | High | BEC Campaign Q1
Subject_Pattern | "Urgent: Invoice.*Payment" | Medium | Phishing Wave
Attachment_Hash | SHA256:abc123... | High | Emotet distribution
```

**Monitor/Alert (Medium Confidence)**
```
# IOCs requiring investigation before blocking -- deploy as SIEM alerts, not blocks
# FORMAT: type | value | reason_to_monitor | associated_threat
IPv4 | 192.168.x.x | Seen in 2 threat reports, not yet confirmed malicious | APT29
Domain | suspicious-cdn[.]net | DGA pattern match, under investigation | Unknown
JA3 | abc123def456... | Associated with known C2 framework | Cobalt Strike
```

**Watchlist (Low Confidence / Threat Hunting)**
```
# IOCs for proactive hunting queries -- correlate with internal telemetry
# FORMAT: type | value | hunt_hypothesis | data_source_to_check
Registry_Key | HKLM\Software\...\RunOnce | Persistence mechanism | EDR / Sysmon
Mutex | Global\MutexName123 | Malware family indicator | EDR process telemetry
Named_Pipe | \\.\pipe\msagent_## | Lateral movement tool | Sysmon Event ID 17/18
User_Agent | Mozilla/5.0 (compatible;...) | Known C2 user agent string | Proxy logs
```

**CSV Export for SIEM Bulk Import:**
```csv
ioc_type,ioc_value,confidence,threat_name,threat_actor,mitre_technique,source,first_seen,last_seen,action,tlp
IPv4,185.220.101.xxx,High,LockBit 3.0,LockBit Gang,T1071.001,Recorded Future,2026-03-24,2026-03-28,block,AMBER
Domain,update-service[.]cloud,High,LockBit 3.0,LockBit Gang,T1105,Mandiant,2026-03-23,2026-03-28,block,AMBER
SHA256,a1b2c3d4e5f6...,High,LockBit Encryptor,LockBit Gang,T1486,MalwareBazaar,2026-03-22,2026-03-28,block,AMBER
```

**STIX 2.1 Bundle (for TIP/MISP import):**
```json
{
  "type": "bundle",
  "id": "bundle--uuid",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--uuid",
      "created": "2026-03-28T00:00:00Z",
      "modified": "2026-03-28T00:00:00Z",
      "pattern": "[ipv4-addr:value = '185.220.101.xxx']",
      "pattern_type": "stix",
      "valid_from": "2026-03-24T00:00:00Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 90,
      "description": "LockBit 3.0 C2 server"
    }
  ]
}
```

#### 7. Detection Rule Recommendations

Provide ready-to-deploy detection rules for each major threat identified:

**YARA Rules** (for file scanning / EDR):
```yara
rule Example_Malware_Detection {
    meta:
        description = "Detects [malware family]"
        threat = "[threat name]"
        date = "[date]"
        reference = "[source URL]"
    strings:
        $s1 = "[string1]"
        $s2 = "[string2]"
    condition:
        uint16(0) == 0x5A4D and all of them
}
```

**Sigma Rules** (for SIEM -- translates to KQL, SPL, EQL):
```yaml
title: Detect [Threat Behavior]
status: experimental
description: Detects [specific TTP]
references:
    - [source URL]
logsource:
    category: [process_creation|driver_load|network_connection]
    product: windows
detection:
    selection:
        FieldName|contains:
            - 'suspicious_value'
    condition: selection
level: high
tags:
    - attack.t1xxx
```

**KQL Queries** (for Microsoft Sentinel):
```kql
// Hunt for [threat behavior]
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "suspicious.exe"
    or ProcessCommandLine contains "malicious_pattern"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

**SPL Queries** (for Splunk):
```spl
index=main sourcetype=sysmon EventCode=1
| search (process_name="suspicious.exe" OR CommandLine="*malicious_pattern*")
| table _time host process_name CommandLine parent_process_name
| sort -_time
```

**Snort/Suricata Rules** (for network IDS):
```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"[Threat] C2 Communication Detected"; content:"|xx xx xx|"; sid:1000001; rev:1; classtype:trojan-activity; reference:url,[source];)
```

#### 8. Recommended Actions Matrix

| Priority | Action | Owner | Timeline | Investment | Risk Addressed | Success Metric |
|----------|--------|-------|----------|------------|----------------|----------------|
| P1 - Critical | | | 0-48 hrs | | | |
| P2 - High | | | 48 hrs-7 days | | | |
| P3 - Medium | | | 7-30 days | | | |
| P4 - Strategic | | | 30-90 days | | | |

#### 9. Intelligence Gaps & Follow-Up Required
- What couldn't be determined?
- What requires deeper investigation?
- What internal data would improve analysis?

---

## Part 6: Internal Document Integration

### Analyze the provided internal document and:

1. **Correlate** external intelligence with internal findings
2. **Identify gaps** between external threats and internal detection capabilities
3. **Validate** internal threat assessments against latest external intelligence
4. **Prioritize** internal findings based on external threat activity
5. **Enhance** internal IOCs with externally gathered intelligence
6. **Map** internal incidents to external threat actor TTPs

### Integration Checklist:
- [ ] All internal threats mapped to external intelligence
- [ ] IOCs from document cross-referenced with threat feeds
- [ ] TTPs aligned with current MITRE ATT&CK framework (v14+)
- [ ] GreyNoise/Recorded Future data integrated
- [ ] Bug bounty relevant findings incorporated
- [ ] Gaps between internal view and external reality identified
- [ ] Detection coverage gaps documented
- [ ] Recommendations updated based on combined intelligence

---

## Output Configuration

**Format Options** (select one -- defaults to Technical IOC Package if not specified):
- [ ] Technical IOC Package (IOCs + TTPs + detection rules for SOC) **(DEFAULT)**
- [ ] Full Report (all sections, 8-12 pages)
- [ ] Executive Brief (summary + dashboard + actions, 2 pages)
- [ ] Board Presentation (high-level, business impact focus, 1 page + appendix)
- [ ] CISO Briefing (balanced technical and business, 3-4 pages)

**Export Formats**:
- IOC list (CSV/STIX 2.1/OpenIOC/JSON)
- Detection rules (YARA/Sigma/Snort)
- MITRE ATT&CK Navigator layer (JSON)
- Narrative report (Word/PDF)
- Machine-readable threat intel (TAXII feed format)

---

**If the user has not provided input, begin analysis immediately using all default values. Do not wait for responses -- generate the full technical IOC package with all emerging threats from the last 7 days targeting network edge devices, endpoints, mobile, APIs, and payment systems.**