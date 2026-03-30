# Executive Cyber Threat Intelligence Prompt for Microsoft Copilot

## Initial User Input Required

**Before proceeding, please answer the following:**

1. **Search Scope**: What is your primary focus area?
   - [ ] All emerging threats (comprehensive scan)
   - [ ] Specific threat category (ransomware, APT, supply chain, etc.)
   - [ ] Industry-specific (financial services, banking, fintech)
   - [ ] Geographic focus (nation-state actors, regional threats)

2. **Time Range**: How recent should the intelligence be?
   - [ ] Last 24-48 hours (breaking threats)
   - [ ] Last 7 days
   - [ ] Last 30 days
   - [ ] Last 90 days

3. **New Business Context**: What new business line is the bank entering?
   - [User Input Required]

4. **Specific Assets of Concern**: (optional)
   - Cloud infrastructure, endpoints, mobile, APIs, payment systems, etc.

5. **Depth of Technical Detail**:
   - [ ] Executive-level (business impact focus)
   - [ ] Technical summary (IOCs + TTPs)
   - [ ] Full technical (exploit details, PoC references, detection rules)

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
- CVE Details - Vulnerability statistics and trends
- VulDB - Comprehensive vulnerability database

**Exploit Databases & Proof-of-Concept Sources**
- Exploit-DB (exploit-db.com) - Archive of exploits and vulnerable software
- Vulners (vulners.com) - Vulnerability intelligence search engine
- Packet Storm Security (packetstormsecurity.com) - Exploits, tools, and advisories
- Rapid7 Vulnerability Database
- Sploitus - Exploit and hacking tools search engine
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
(Reference: cybersecuritynews.com/cyber-security-search-engines/)
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

**Offensive Security Research**
- Offensive Security (offensive-security.com) - Exploit development research
- SANS Penetration Testing Blog
- Red Team Journal
- SpecterOps Blog - Adversary simulation research
- Cobalt Strike Blog - Red team TTPs
- Metasploit Blog
- Rapid7 Blog

---

### TIER 6: Community & Independent Researcher Sources

**Reddit Security Communities**
- r/netsec - Information security news and discussion
- r/cybersecurity - General cybersecurity discussion
- r/malware - Malware analysis and research
- r/ReverseEngineering - Binary analysis and exploitation
- r/AskNetsec - Security Q&A
- r/blueteamsec - Defensive security
- r/redteamsec - Offensive security
- r/crypto - Cryptography
- r/privacy - Privacy and security
- r/hacking - General hacking discussion
- r/Pentesting - Penetration testing

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

**Twitter/X Security Community**
- #infosec, #threatintel, #malware, #APT, #CVE
- Security researcher accounts and threat intel sharing

---

### TIER 7: Dark Web & Underground Intelligence

**Dark Web Intelligence Platforms** (legally accessible reports and feeds)
- Recorded Future Dark Web Intelligence
- Flashpoint - Deep and dark web monitoring
- Intel 471 - Underground intelligence
- DarkOwl - Darknet data intelligence
- Kela - Cyber threat intelligence
- Cybersixgill - Deep web intelligence
- SOCRadar - Dark web monitoring
- Digital Shadows (now ReliaQuest)

---

### TIER 8: Government & Regulatory Advisories

**U.S. Government**
- CISA Alerts and Advisories (cisa.gov)
- FBI Internet Crime Complaint Center (IC3)
- FBI Flash Alerts
- NSA Cybersecurity Advisories
- US-CERT
- DHS Cybersecurity

**International Government**
- NCSC UK - Threat Reports and Advisories
- ACSC Australia - Advisories
- CCCS Canada - Cyber Centre Alerts
- BSI Germany
- ANSSI France
- ENISA (EU) - Threat Landscape Reports

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
- Malpedia - Malware encyclopedia
- YARA Rules Repository
- Malshare
- theZoo - Live malware repository

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
| **Exploit Availability** | None / PoC / Weaponized / Active Exploitation |
| **First Observed** | Date |
| **Source(s)** | |
| **Sophistication Level** | Basic / Intermediate / Advanced / Nation-state |
| **Targeted Sectors** | |
| **Targeted Technologies** | |
| **Technical Description** | |
| **Business Impact** | |

#### B. Indicators of Compromise (IOCs)
Extract and categorize all IOCs found:

**Network-Based IOCs**
| Type | Value | Confidence | Source | First Seen | Associated Threat |
|------|-------|------------|--------|------------|-------------------|
| IPv4 Address | | High/Med/Low | | | |
| IPv6 Address | | | | | |
| Domain | | | | | |
| URL | | | | | |
| SSL Cert Hash | | | | | |
| JA3 Fingerprint | | | | | |
| JA3S Fingerprint | | | | | |
| JARM Fingerprint | | | | | |

**Host-Based IOCs**
| Type | Value | Confidence | Source | Associated Threat |
|------|-------|------------|--------|-------------------|
| MD5 Hash | | | | |
| SHA-1 Hash | | | | |
| SHA-256 Hash | | | | |
| File Name | | | | |
| File Path | | | | |
| Registry Key | | | | |
| Registry Value | | | | |
| Scheduled Task | | | | |
| Service Name | | | | |
| Mutex | | | | |
| Named Pipe | | | | |
| Process Name | | | | |
| Command Line | | | | |

**Email-Based IOCs**
| Type | Value | Confidence | Campaign |
|------|-------|------------|----------|
| Sender Address | | | |
| Sender Domain | | | |
| Subject Pattern | | | |
| Attachment Name | | | |
| Attachment Hash | | | |

**Behavioral IOCs & Anomaly Indicators**
- Unusual authentication patterns
- Abnormal data transfer volumes
- Off-hours activity
- Impossible travel
- Privilege escalation sequences
- Lateral movement patterns
- Data staging behaviors
- C2 beaconing patterns

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
| Command & Control | | | | | | |
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
| CVE | Days Since Disclosure | Exploit Maturity | Mass Exploitation Detected | Bank Exposure | Priority |
|-----|----------------------|------------------|---------------------------|---------------|----------|
| | | PoC/Weaponized/ITW | Yes/No (GreyNoise) | | |

---

## Part 4: High-Profile Business Risk Analysis

### Given the bank's expansion into [new business line], assess:

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

| Threat Category | New This Period | Active Exploits | Trend | Risk Level | Bank Relevance |
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
| CVE | CVSS | Product | Exploit Status | GreyNoise Activity | Bank Exposure | Action Required |
|-----|------|---------|----------------|-------------------|---------------|-----------------|
| | | | | | | |

#### 5. New Business Line Risk Spotlight
Dedicated section on how expansion increases threat profile with specific, actionable concerns.

#### 6. IOC Package for Security Operations
Provide exportable IOC list for immediate ingestion:

**Immediate Block (High Confidence)**
```
[IP addresses, domains, hashes - formatted for SIEM/EDR import]
```

**Monitor/Alert (Medium Confidence)**
```
[IOCs requiring investigation before blocking]
```

**Watchlist (Low Confidence / Suspicious)**
```
[IOCs for threat hunting and correlation]
```

#### 7. Detection Rule Recommendations
- YARA rules for new malware
- Sigma rules for behavioral detection
- Snort/Suricata rules for network detection
- KQL/SPL queries for SIEM

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

**Format Options** (select one):
- [ ] Full Report (all sections, 8-12 pages)
- [ ] Executive Brief (summary + dashboard + actions, 2 pages)
- [ ] Technical IOC Package (IOCs + TTPs + detection rules for SOC)
- [ ] Board Presentation (high-level, business impact focus, 1 page + appendix)
- [ ] CISO Briefing (balanced technical and business, 3-4 pages)

**Export Formats**:
- Narrative report (Word/PDF)
- IOC list (CSV/STIX 2.1/OpenIOC/JSON)
- MITRE ATT&CK Navigator layer (JSON)
- Detection rules (YARA/Sigma/Snort)
- Executive slides (PowerPoint)
- Machine-readable threat intel (TAXII feed format)

---

**Please provide your search parameters and internal document, and I will conduct the comprehensive threat intelligence analysis.**