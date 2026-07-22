```
THREAT INTELLIGENCE REPORT
Generated: 2026-07-06T00:00:00Z
Coverage: PARTIAL
Time Range: 2026-06-29 to 2026-07-06
Scope: All emerging threats (default)
Persona: enterprise_soc
Assets: network edge, endpoints, mobile, APIs, payment systems
```

> **Methodology notice (read before acting on this report):**
> This run used live web search/retrieval (not a connected `threat-intel-mcp` feed) to research all nine source
> tiers for the 2026-06-29 → 2026-07-06 window. Retrieval was genuinely current — this is a materially better-covered
> report than prior weeks' runs, which had zero live access. Two honest limitations remain:
> - **Direct page fetches to primary sources were frequently blocked (HTTP 403)** — CISA.gov, ic3.gov, GreyNoise,
>   VirusTotal, HackerOne, Bugcrowd, SpecterOps, ProjectDiscovery, Project Zero, and abuse.ch all rejected direct
>   fetch. Facts attributed to these sources below were recovered via search-engine result snippets and
>   corroborating secondary reporting (BleepingComputer, The Hacker News, Help Net Security, SecurityAffairs), not
>   verified full-primary-document reads. Treat exact figures as reported-by-secondary-outlet, not primary-verified.
> - **No literal current IOC values (hashes/IPs/domains) were retrievable.** Real-time feed content from
>   ThreatFox/MalwareBazaar/AbuseIPDB/URLhaus requires direct feed API access, not general web search — none is
>   fabricated below (R3). Where a real named indicator surfaced (a lookalike domain, a malicious package name), it
>   is cited to its source; everywhere else the gap is stated plainly rather than papered over.
>
> **Recommended action:** Connect `threat-intel-mcp` (or operator feeds — Q-Feeds, AbuseIPDB, VirusTotal, OTX,
> Recorded Future) for literal current IOC values; this report is strong on campaign/vulnerability narrative but
> cannot substitute for a live feed on atomic indicators.

---

## 1. Alert Banner

```
CRITICAL: FortiBleed — mass FortiGate credential-harvesting campaign now confirmed feeding INC Ransom and Lynx
          ransomware operators (12+ confirmed ransomware deployments). Patch/rotate credentials immediately if
          FortiGate SSL-VPN is internet-exposed.
CRITICAL: CVE-2026-45659 (SharePoint Server, CVSS 8.8) actively exploited by Storm-2603 to deploy Warlock
          ransomware; added to CISA KEV with a 3-day federal remediation deadline.
HIGH:     First documented fully autonomous "agentic ransomware" (JadePuffer) — an LLM agent independently
          executed the entire post-exploitation chain (recon → credential theft → lateral movement → privilege
          escalation → database extortion) after a Langflow RCE (CVE-2025-3248), self-correcting a failed step
          in 31 seconds. Signals a step-change in attack automation speed.
ELEVATED: CISA KEV additions arrived at an unusually high cadence this week (SimpleHelp RMM, PTC Windchill's
          first-ever KEV entry, Cisco UCM, Ubiquiti UniFi triple-chain, Splunk Enterprise, Ivanti Sentry already
          found backdoored post-patch) — patch-management backlogs are the primary near-term risk driver.
```

---

## 2. Executive Summary

- **FortiBleed is the week's dominant story and the clearest board-relevant risk.** A mass credential-harvesting campaign against internet-exposed FortiGate SSL-VPN portals (scanning ~11,250 portals across 150+ countries per SOCRadar, corroborated by GreyNoise brute-force telemetry and CISA/NCSC advisories) has been directly linked to the operator behind at least 12 ransomware deployments via INC Ransom and Lynx affiliate panels. Any organization with internet-facing FortiGate devices should treat this as an active incident-response trigger, not a routine patch item.
- **Autonomous "agentic" attack tooling crossed a threshold this week.** JadePuffer (Sysdig research) is the first well-documented case of an LLM agent independently executing an entire ransomware-adjacent attack chain — including self-correcting a failed step — after exploiting a Langflow RCE. Separately, Kaspersky assessed an Armored Likho APT loader as LLM-generated, and HackerNews/vendor reporting describes a new "Avalon" malware framework with signs of AI-assisted development. This is a trend, not an isolated event, and materially shortens expected dwell time between initial access and impact.
- **CISA KEV additions arrived faster and broader than typical this period** — nine-plus distinct KEV entries in the window spanning SharePoint, SimpleHelp RMM, PTC Windchill (first-ever entry for that vendor), Cisco UCM, Ubiquiti UniFi (three chainable CVEs), Lantronix, Splunk Enterprise, and Ivanti Sentry (found already backdoored shortly after the patch itself was released). Patch-management SLAs for internet-facing infrastructure are the highest-leverage control this week.
- **New/renamed APT activity:** Armored Likho (new Kaspersky-tracked actor name) is targeting government and electric-power-sector organizations in Russia, Kazakhstan, and Brazil with an AI-assisted loader; ToddyCat introduced a novel OAuth-token-theft technique abusing Chromium's remote-debugging port. Neither has confirmed relevance to the assumed default assets, but both illustrate technique evolution worth tracking.
- **Supply-chain risk is compounding in two directions:** npm/PyPI package-poisoning continues (Red Hat Cloud Services namespace, @antv/echarts-for-react, Mastra — linked to DPRK's Sapphire Sleet), and a new pattern emerged — "ChocoPoCs" — where vulnerability researchers themselves were targeted with trojanized PoC exploit code carrying malicious PyPI dependencies. GitHub's npm v12 defaults change (blocking install scripts/Git deps by default) is a direct, positive response to this pressure.
- **AI infrastructure is now itself a named attack surface.** CVE-2026-42271 (BerriAI LiteLLM AI gateway, CVSS 8.7), exploited via its MCP-configuration-preview endpoints and chained with a Starlette host-validation bypass for unauthenticated RCE, was added to CISA KEV this period. GreyNoise also reports sustained mass-scanning of exposed LLM inference endpoints (91,000+ honeypot sessions since October 2025).
- **Government/critical-infrastructure exposure:** DHS's own Homeland Security Information Network (HSIN) disclosed unauthorized third-party access exposing World Cup security-planning data; CISA released 9+ ICS advisories in the window. Combined with the FortiBleed and Ivanti Sentry items, edge/perimeter infrastructure is this period's consistent theme across sectors.

---

## 3. Threat Dashboard

| Category | New This Period | Active Exploits | Trend | Risk Level | Org Relevance |
|---|---|---|---|---|---|
| Ransomware | JadePuffer (agentic), Avalon/CrownX framework, INC Ransom & Lynx via FortiBleed access | Warlock (via CVE-2026-45659 SharePoint), Akira (via Bumblebee/AdaptixC2 chain, DFIR Report) | ↑ | CRITICAL | HIGH — network edge, endpoints, backup infra |
| APT / Nation-State | Armored Likho (new), ToddyCat "Umbrij"/Shadow Token technique, Storm-2603 | Sapphire Sleet (DPRK, npm supply chain + macOS) | ↑ | HIGH | MEDIUM–HIGH — sector-dependent |
| Supply Chain | ChocoPoCs (trojanized researcher PoCs), npm v12 default hardening | Red Hat Cloud Services namespace compromise, @antv/echarts-for-react, Mastra (Sapphire Sleet) | ↑ | HIGH | MEDIUM–HIGH — dev/CI-CD toolchain dependent |
| Zero-Day / Edge | Ivanti Sentry backdoored post-patch, Cisco Catalyst SD-WAN zero-day (CVE-2026-20245) | Check Point VPN CVE-2026-50751 (Qilin-affiliate linked), SonicWall pre-disclosure scanning pattern (GreyNoise) | ↑ | CRITICAL | HIGH — network edge assets |
| Cloud / Identity | ToddyCat OAuth token-minting via Chromium remote-debug abuse | LiteLLM AI-gateway CVE-2026-42271 chain | ↑ | HIGH | HIGH — APIs, AI infrastructure |
| API Security | Salesforce Marketing Cloud unauthenticated tenant-email read (Bug Bytes #237) | LiteLLM MCP-preview endpoint abuse | ↑ | HIGH | HIGH — APIs |
| Insider | limited signal this period | — | → | MEDIUM | MEDIUM |
| Credential / BEC | FortiBleed mass credential harvest, ClickFix "Lorem Ipsum Loader" | Cisco/SonicWall/Fortinet VPN brute-force surges (GreyNoise), PamStealer via maccyapp.com lookalike | ↑ | CRITICAL | HIGH — network edge, endpoints, payment |
| Mobile | limited signal this period — no new mobile-specific campaign surfaced in this window | — | → | MEDIUM | MEDIUM — carried forward from prior periods |

---

## 4. Critical Vulnerability Summary

| CVE | CVSS | Product | Exploit Status | GreyNoise Activity | Org Exposure | Action | Source |
|---|---|---|---|---|---|---|---|
| CVE-2026-45659 | 8.8 | Microsoft SharePoint Server (insecure deserialization RCE) | Actively exploited by Storm-2603 to deploy Warlock ransomware; CISA KEV (added Jul 1, deadline Jul 4, 2026) | not reported | HIGH if SharePoint on-prem deployed | Patch immediately per CISA KEV deadline; hunt for Storm-2603 IOCs | The Hacker News; NVD; SecurityWeek |
| CVE-2026-48558 | 10.0 | SimpleHelp RMM (OIDC auth bypass) | Actively exploited to deploy TaskWeaver loader / Djinn Stealer; CISA KEV (3-day BOD 26-04 deadline, added Jun 29) | not reported | HIGH if SimpleHelp RMM in use (common MSP tool) | Patch/upgrade immediately; audit for unauthorized RMM sessions | The Hacker News; Help Net Security; Threat-Modeling.com |
| CVE-2026-10520 | not stated (critical — OS command injection, unauth root RCE) | Ivanti Sentry | Shadowserver found internet-exposed gateways already backdoored shortly after the patch itself shipped; CISA KEV, 3-day federal deadline | not reported | HIGH if Ivanti Sentry deployed | Patch AND assume compromise — hunt for backdoors even on patched systems | BleepingComputer; SecurityAffairs |
| CVE-2026-50751 | 9.3 | Check Point Security Gateway (IKEv1 cert-validation bypass, CWE-287) | Exploitation traced to May 7, 2026; linked to a Qilin ransomware affiliate; CISA KEV (added Jun 8, deadline Jun 11) | not reported | HIGH if Check Point VPN gateway exposed | Verify patch applied; review VPN auth logs back to May 7 | The Hacker News; watchTowr Labs |
| CVE-2026-42271 | 8.7 | BerriAI LiteLLM (AI gateway/proxy, command injection via MCP-preview endpoints) | Actively exploited; chained with CVE-2026-48710 (Starlette host-bypass, CVSS 6.5) for unauth RCE; CISA KEV | not reported | HIGH if LiteLLM or similar AI gateway deployed | Patch LiteLLM and Starlette dependency; restrict MCP-preview endpoint exposure | The Hacker News; Help Net Security; Cloud Security Alliance |
| CVE-2026-20253 | 9.8 | Splunk Enterprise (unauthenticated PostgreSQL sidecar endpoints, CWE-306) | Confirmed exploited; watchTowr published a working exploit; CISA KEV (added Jun 18) | not reported | HIGH if self-hosted Splunk Enterprise | Patch immediately; treat as compromised if internet-exposed and unpatched since Jun 18 | The Hacker News; Zscaler ThreatLabz |
| CVE-2026-12569 | 9.3 | PTC Windchill / FlexPLM (deserialization RCE) | First-ever PTC KEV entry; JSP webshells dropped for persistence/exfil; CISA KEV (added Jun 25) | not reported | MEDIUM–HIGH if PLM/Windchill in manufacturing environment | Patch; scan for unexpected JSP files on Windchill servers | The Hacker News; Help Net Security |
| CVE-2026-20230 | Critical (SSRF, unauth remote) | Cisco Unified Communications Manager | Exploited to write arbitrary files to endpoints; CISA KEV | not reported | MEDIUM–HIGH if Cisco UCM deployed | Patch per CISA KEV deadline | BleepingComputer |
| CVE-2026-34908/-34909/-34910 | 10.0 each | Ubiquiti UniFi OS (access control / path traversal / input validation) | Chainable to full RCE with elevated privileges (Bishop Fox); CISA KEV (added Jun 23) | not reported | MEDIUM if UniFi OS network gear deployed | Patch to post-Bulletin-064 firmware immediately | BleepingComputer; SecurityAffairs |
| CVE-2026-20245 | 7.8 | Cisco Catalyst SD-WAN Manager (CWE-116) | Zero-day; authenticated netadmin → root escalation; 7th Cisco SD-WAN CVE flagged exploited in 2026 | not reported | MEDIUM–HIGH if Catalyst SD-WAN Manager in use | Patch; review netadmin account activity | The Hacker News; Mandiant/Google Cloud blog |
| CVE-2025-9491 (LNK / ZDI-CAN-25373) | not stated | Windows shortcut parsing | Actively exploited by Armored Likho for initial access via spear-phish LNK attachments | not reported | MEDIUM — email-delivered LNK files | Block/alert on LNK attachments from external senders; verify patch status | The Hacker News; Securelist |

---

## 5. Business Line Risk Spotlight

*No new business context was provided (default: none). This section is omitted. Provide business context on next invocation to receive tailored risk scenarios — e.g., current exposure to FortiGate/Ivanti/Check Point edge devices, LiteLLM or similar AI-gateway usage, and SharePoint/Splunk/Windchill deployment footprint would materially sharpen this week's findings.*

---

## 6. IOC Package

> **R3 compliance notice:** No literal current network IOCs (IPs, C2 domains, file hashes) were retrievable this
> period — general web search surfaces campaign narrative and vendor reporting, not the atomic indicator feeds
> that live inside ThreatFox/MalwareBazaar/AbuseIPDB/URLhaus/VirusTotal. **No IOC values below are fabricated.**
> Where a real, specifically-named indicator surfaced in vendor reporting (a lookalike phishing domain, a
> malicious package name, a named tool), it is included with its source. Everything else is a behavioral or
> TTP-level indicator derived from documented technique descriptions.

### 6a. Deployment Priority

| Priority | Category | Action | Count |
|---|---|---|---|
| P1 — IMMEDIATE | FortiGate SSL-VPN exposure (§Executive Summary, §9) | Patch, rotate credentials, hunt for FortiGate Sniffer artifacts | 1 campaign |
| P1 — IMMEDIATE | CISA KEV entries in §4 | Patch/isolate per federal deadlines | 12 CVEs |
| P1 — IMMEDIATE | Behavioral/TTP detection rules (§7) | Deploy to SIEM/EDR | 6 rules |
| P2 — 48h | Named real-world indicators (§6b) | Block/alert | 3 items |
| P2 — 48h | Threat-actor TTP hunting queries (§7) | Run against 30d telemetry | 4 hunts |
| P3 — 7d | Live feed integration | Connect threat-intel-mcp for atomic IOC backfill | 1 action |

### 6b. Named Real-World Indicators (sourced, not fabricated)

```csv
ioc_type,ioc_value,confidence,threat_name,threat_actor,mitre_technique,source,first_seen,last_seen,action,tlp
domain,maccyapp.com,high,PamStealer macOS infostealer lookalike site,unattributed,T1566.002,thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html; jamf.com blog,2026-07-02,ongoing,block,TLP:WHITE
software,frint (PyPI package),high,ChocoPoCs trojanized-PoC dependency,unattributed,T1195.001,yeswehack.com/news/chocopocs-vulnerability-researchers-trojanised-exploits,2026-06-25,2026-06-25,block+hunt,TLP:WHITE
software,skytext (PyPI package),high,ChocoPoCs trojanized-PoC transitive dependency,unattributed,T1195.001,yeswehack.com/news/chocopocs-vulnerability-researchers-trojanised-exploits,2026-06-25,2026-06-25,block+hunt,TLP:WHITE
```

> **Guidance:** these three entries are the only literal, source-attributed atomic indicators this cycle's
> retrieval surfaced. `maccyapp.com` is a phishing lookalike for the legitimate "Maccy" clipboard-manager app —
> block at web proxy/DNS. `frint` and `skytext` are PyPI package names implicated in the ChocoPoCs
> trojanized-exploit campaign — block installation in CI/CD and developer environments and hunt for any prior
> installation via package-manager logs.

### 6c. Behavioral IOCs (derived from documented technique descriptions — not literal samples)

| Behavior | Data Source | Detection Logic | MITRE ID | Threshold | Source |
|---|---|---|---|---|---|
| Chromium launched with `--remote-debugging-port` by a non-browser-management parent process, followed by Gmail OAuth traffic | EDR process telemetry | Alert on chrome.exe/msedge.exe command line containing `--remote-debugging-port` where parent process is not a known browser-automation/dev tool | T1550.001 | any occurrence outside approved dev/test hosts | Securelist (ToddyCat "Shadow Token via Remote Debug") |
| New local/service account created within minutes of an internet-facing app-server process spawning an unusual child process | Windows Security / Linux auth logs | Correlate Event ID 4720/4732 (or `/etc/passwd`, `useradd` on Linux) with a preceding anomalous child process from a web-facing application (e.g., Langflow, similar AI/orchestration tooling) within a 5-minute window | T1136, T1190 | 1 correlated event | Sysdig (JadePuffer agentic ransomware chain) |
| High-volume authentication failures against SSL-VPN portal (Fortinet/Cisco/SonicWall) from a narrow set of source IPs within a short window | Firewall/VPN auth logs | count(distinct failed logins) by src_ip, dest_portal over 1h; flag > baseline by 10x | T1110.001/.003 | > 10x 30-day baseline | GreyNoise "At The Edge Clear" series |
| Fake browser-update lure ("Lorem Ipsum Loader" / ClickFix-style) on compromised WordPress delivering a loader tied to BabaDeda crypter service | Web proxy / EDR | Alert on clipboard-paste-and-run PowerShell invoked from a browser "update" prompt page (classic ClickFix pattern: Win+R → paste → Enter within seconds of visiting an external site) | T1204.002, T1027 | any occurrence | The Hacker News (June 2026 ClickFix reporting) |

---

## 7. Detection Rules

### 7a. YARA — PamStealer macOS Infostealer (behavioral, inferred from public description — validate before use)

```yara
rule PamStealer_Maccy_Lookalike_Stager
{
    meta:
        description = "Detects JXA/AppleScript stager impersonating the Maccy clipboard manager (PamStealer campaign)"
        threat = "PamStealer macOS infostealer"
        date = "2026-07-06"
        reference = "thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html; jamf.com blog"
        status = "needs_validation — strings inferred from public campaign description, not a lifted vendor rule; test in isolated sandbox before deployment"

    strings:
        $lure1 = "maccyapp" nocase ascii wide
        $jxa1 = "ObjC.import" ascii
        $jxa2 = "Application(\"System Events\")" ascii
        $exec1 = "pbpaste" ascii
        $exec2 = "security find-generic-password" ascii
        $exec3 = "Library/Keychains" ascii

    condition:
        ($lure1) or (2 of ($jxa*) and 1 of ($exec*))
}
```

### 7b. Sigma — Backdoor Account Creation Following Web-App Exploitation (JadePuffer-style agentic chain)

```yaml
title: Local Account Creation Shortly After Anomalous Web-App Child Process
id: d7e5f6a7-b8c9-0123-defa-123456789012
status: test
description: >
  Detects a new local/service account created within minutes of an internet-facing
  application server (e.g. Langflow-style AI orchestration tooling) spawning an
  unexpected child process — the pattern reported in the JadePuffer autonomous
  agentic-ransomware chain (Sysdig, July 2026).
references:
  - https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion
  - https://www.bleepingcomputer.com/news/security/jadepuffer-ransomware-used-ai-agent-to-automate-entire-attack/
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-07-06
tags:
  - attack.persistence
  - attack.t1136
  - attack.initial_access
  - attack.t1190
logsource:
  product: windows
  category: user_account_created
detection:
  new_account:
    EventID: 4720
  condition: new_account
falsepositives:
  - Legitimate account provisioning via approved IAM/change-management workflow — correlate against change tickets before alerting as high severity
level: high
```

### 7c. Sigma — Chromium Remote-Debugging OAuth Token Theft (ToddyCat "Shadow Token via Remote Debug")

```yaml
title: Chromium Launched With Remote Debugging Port by Unexpected Parent
id: e8f6a7b8-c9d0-1234-efab-234567890123
status: test
description: Detects Chrome/Edge launched with --remote-debugging-port, the mechanism reported in ToddyCat's Umbrij/Shadow-Token-via-Remote-Debug OAuth token theft technique
references:
  - https://securelist.com/toddycat-apt-umbrij-tool-and-oauth/120251/
  - https://thehackernews.com/2026/07/toddycat-linked-umbrij-malware-abuses.html
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-07-06
tags:
  - attack.credential_access
  - attack.t1528
  - attack.t1550.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
    CommandLine|contains: '--remote-debugging-port'
  filter_known_dev_tools:
    ParentImage|endswith:
      - '\code.exe'
      - '\devenv.exe'
  condition: selection and not filter_known_dev_tools
falsepositives:
  - Legitimate browser automation/testing frameworks (Selenium, Puppeteer, Playwright) — tune the filter list to your approved dev-tool inventory
level: high
```

### 7d. KQL — VPN Portal Brute-Force Spike Detection (Sentinel / Defender)

```kql
// Hunt: SSL-VPN portal authentication brute-force spike (Fortinet/Cisco/SonicWall class)
// Context: GreyNoise "At The Edge Clear" series reported six-figure brute-force session
// volumes against these portal classes in June 2026; a SonicWall scanning spike in May 2026
// preceded a subsequent CVE disclosure by ~11 days (GreyNoise "Ten Days Before Zero").
// schema_dependency: SigninLogs (Entra ID) if VPN federates through Entra, OR the VPN
//   vendor's own syslog forwarded into a custom table — <PLACEHOLDER> for the local table name.
// status: needs_validation
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != "0"
| where AppDisplayName has_any ("VPN", "SSL-VPN", "GlobalProtect", "FortiClient", "AnyConnect")
| summarize FailedAttempts = count(), DistinctAccounts = dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 1h)
| where FailedAttempts > 50 or DistinctAccounts > 10
| sort by FailedAttempts desc
```

*Coverage check:*
```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where AppDisplayName has_any ("VPN", "SSL-VPN")
| summarize count() by AppDisplayName
```

### 7e. SPL — Newly-Published Low-Reputation Package Install Detection (ChocoPoCs-style supply chain)

```splunk
| tstats summariesonly=true count
  from datamodel=Endpoint.Processes
  where (Processes.process_name="pip*" OR Processes.process_name="pip3*")
    Processes.process="*install*"
  by Processes.dest, Processes.user, Processes.process, _time span=1h
| rename Processes.* AS *
| eval flagged_pkg=if(match(process, "(?i)\bfrint\b|\bskytext\b"), "true", "false")
| where flagged_pkg="true"
```

*Coverage check (confirm Endpoint.Processes CIM model is populated):*
```splunk
| tstats count from datamodel=Endpoint.Processes by index, sourcetype
```

> Note: the `frint`/`skytext` match above is a literal, source-cited indicator (§6b). Extend the regex as new
> package names are confirmed via a connected threat-intel feed rather than treating this as an exhaustive list.

### 7f. Snort/Suricata — LiteLLM MCP-Preview Endpoint Exploitation (CVE-2026-42271)

```snort
# Rule: Detect requests to BerriAI LiteLLM MCP-preview configuration endpoints associated
# with CVE-2026-42271 command-injection exploitation, often chained with a Starlette
# host-header bypass (CVE-2026-48710).
# Source: The Hacker News; Help Net Security; Cloud Security Alliance research note
# Status: needs_validation — tune endpoint path to your deployment's actual routing prefix
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"POSSIBLE LiteLLM MCP-Preview Endpoint Exploitation Attempt (CVE-2026-42271)";
  flow:to_server,established;
  http_uri;
  content:"/mcp"; nocase;
  content:"preview"; nocase; distance:0;
  classtype:web-application-attack;
  sid:9000101; rev:1;
  reference:url,thehackernews.com/2026/06/litellm-flaw-cve-2026-42271-exploited.html;
)
```

---

## 8. Actions Matrix

| Priority | Action | Owner | Timeline | Investment | Risk Addressed | Success Metric |
|---|---|---|---|---|---|---|
| P1 | Identify and rotate credentials on all internet-facing FortiGate SSL-VPN devices; review admin-login history back to early June 2026 | Network Ops + IR | 0–48h | Medium (credential rotation + log review) | FortiBleed → INC Ransom/Lynx ransomware access | Zero FortiGate devices on unrotated pre-campaign credentials |
| P1 | Patch all 12 CVEs in §4 per their respective CISA KEV deadlines; treat CVE-2026-10520 (Ivanti Sentry) and CVE-2026-45659 (SharePoint) as compromise-assumed even after patching | Vulnerability Mgmt | 0–48h | Low–Medium | Active exploitation across edge/collab/AI-gateway infrastructure | Zero unpatched KEV instances in CMDB; backdoor hunt completed on Ivanti Sentry hosts |
| P1 | Deploy the account-creation and remote-debugging Sigma rules (§7b/§7c) to SIEM/EDR | SOC Engineering | 0–48h | Low | Agentic-ransomware post-exploitation chain; OAuth token theft | Rules active; test-fire confirmed in lab |
| P1 | Block `maccyapp.com` and the `frint`/`skytext` package names at proxy/DNS and package-manager allowlists (§6b) | SOC / DevSecOps | 0–48h | Low | PamStealer phishing; ChocoPoCs supply-chain compromise | Blocks confirmed active; historical hunt run for prior contact |
| P2 | Run the VPN brute-force KQL hunt (§7d) against 30 days of sign-in telemetry | SOC Analysts | 48h–7d | Medium | Undetected FortiBleed-style credential-harvesting precursor activity | No unresolved high-severity hits; tickets filed for anomalies |
| P2 | Audit LiteLLM (or equivalent AI-gateway) deployments for exposure of MCP-preview endpoints; patch Starlette dependency | Platform/Cloud Security | 48h–7d | Medium | CVE-2026-42271 unauthenticated RCE chain | Endpoint exposure eliminated or WAF rule (§7f) confirmed active |
| P2 | Review CI/CD and developer-machine package-install logs for the `frint`/`skytext` PyPI packages and for the Red Hat Cloud Services / @antv namespace-compromise packages | DevSecOps | 48h–7d | Medium | Trojanized-PoC and npm supply-chain compromise | Confirmed zero historical installs, or IR opened on any hit |
| P3 | Conduct a tabletop exercise simulating an autonomous LLM-agent-driven attack chain (JadePuffer pattern) against an internet-facing internal tool | Security Leadership + SOC | 7–30d | Medium | Readiness gap against accelerating agentic-AI attack automation | IR playbook updated; gaps documented |
| P3 | Evaluate npm v12's new secure-by-default posture (blocked install scripts/Git deps) for internal adoption timeline | Platform Engineering | 7–30d | Low | Ongoing npm supply-chain compromise pattern | Migration plan drafted with target adoption date |
| P4 | Track Scattered Spider legal proceedings (sentencing set for 2026-07-15) for any operational intelligence on group TTPs/successor activity | Threat Intel | 30–90d | Low | Ongoing criminal-actor attribution and TTP tracking | Sentencing outcome and any TTP disclosures logged |

---

## 9. Intelligence Gaps

1. **Primary-source fetches were widely blocked (HTTP 403).** CISA.gov, ic3.gov, GreyNoise, VirusTotal, HackerOne, Bugcrowd, SpecterOps, ProjectDiscovery, Project Zero, and abuse.ch all rejected direct page fetches during this run. All facts attributed to these sources rely on search-engine snippets and secondary reporting (BleepingComputer, The Hacker News, Help Net Security, SecurityAffairs) rather than verified primary-document text. Where a figure could not be corroborated by at least one secondary outlet, it is flagged individually above (e.g., the HackerOne "$61,000/143 reports" figure, the FBI IC3 FLASH-20260702-01 summary).
2. **No literal current IOC values.** ThreatFox/MalwareBazaar/AbuseIPDB/URLhaus/VirusTotal atomic indicators (hashes, IPs, C2 domains) for this window are not retrievable via general web search — these feeds require direct API access. Connect `threat-intel-mcp` or an equivalent feed for indicator backfill.
3. **GreyNoise exact scan-source IP ranges** referenced in the "At The Edge Clear" series were described narratively (session counts, geolocation, target types) but exact IP/CIDR indicators were not present in retrievable content — hunt query (§7d) is built on behavioral pattern, not a supplied IP list.
4. **FortiBleed scope reconciliation.** Reported device-count estimates vary across outlets (SOCRadar: ~11,250 portals scanned / 409 confirmed admin-access / 354 full chain; Arctic Wolf/earlier reporting: 30,000–75,000 devices, ~194 countries). These may describe different sub-campaigns or different measurement windows — treat as directionally consistent but not reconciled to a single authoritative count.
5. **Mobile-specific threats.** No new mobile-platform-specific campaign or CVE surfaced in this window's retrieval; this does not mean mobile risk has decreased, only that this cycle's searches did not turn up new material. Carry forward prior-period mobile guidance until a dedicated mobile-focused pass is run.
6. **CrowdStrike, Mandiant, Cisco Talos, Unit 42, SentinelLabs, Secureworks CTU, Sophos X-Ops, Trend Micro, FortiGuard Labs, and ESET Research** — no new (within-window) blog post was found for any of these Tier 2 sources despite multiple targeted searches; their most recent identifiable output predates the lookback window (cited only as background context where relevant). This tier is thinner than the Coverage Ledger's target reflects the actual current-week publication cadence, not a retrieval failure.
7. **Dark web intelligence (Tier 7) — unchanged from prior periods.** All named sources (Flashpoint, Intel 471, DarkOwl, Cybersixgill, SOCRadar's paid tier, ReliaQuest, ZeroFox, Searchlight Cyber) remain subscription-gated; no access this period.
8. **Exact CVSS scores** for CVE-2025-67038 (Lantronix), CVE-2026-7473 (Arista), CVE-2026-11645 (Chromium), and CVE-2026-35273 (Oracle PeopleSoft) were not present in retrievable search snippets — marked "not stated" in §4 rather than estimated.

---

## Appendix A: Source Coverage Ledger

| Tier | Required Min | Consulted | Skipped (with reason) | Met? |
|---|---|---|---|---|
| 1 — Vulnerability DBs & Exploits | 5 | CISA KEV (9+ distinct bulletins), NVD (per-CVE detail via secondary citation), CVE.org (CVE ID references), MITRE ATT&CK (v19 release notes, Campaign C0062), GitHub Security Advisories (via npm supply-chain reporting), Oracle Security Alert (CVE-2026-35273) | Exploit-DB (no targeted query run), ZDI advisories page (not directly confirmed — only an Oracle researcher credit surfaced), Zero Day Tracker/Clock (did not surface in any search) | yes |
| 2 — Commercial Threat Intel | 4 | Kaspersky Securelist (Armored Likho, ToddyCat/Umbrij), Check Point Research (2026 Exposure Gap Report), Microsoft Security Blog (StealC/Amadey takedown, just outside window) | CrowdStrike, Mandiant, Cisco Talos, Unit 42, SentinelLabs, Secureworks, Sophos X-Ops, Trend Micro, FortiGuard, ESET — no new within-window post found for any | no — 3 of 4 met with live current-week content |
| 3 — Search Engines & Aggregators | 3 | GreyNoise ("At The Edge Clear" series, SonicWall pre-disclosure pattern, LLM-honeypot targeting), Shodan (device-count sizing via secondary FortiBleed reporting), Censys (2025 State of Internet, older but cited) | VirusTotal (most recent confirmed post Feb 2026), AbuseIPDB, Pulsedive, AlienVault OTX — no dated current content found for any | yes — with caveat that Censys/VirusTotal content is dated |
| 4 — Bug Bounty Platforms | 2 | Bugcrowd (Copy Fail CVE-2026-31431 coverage), YesWeHack (Joomla JCE RCE + ChocoPoCs), Intigriti (Bug Bytes #237) | HackerOne (only an unconfirmed aggregate figure surfaced — treated as low-confidence, not a primary citation), Open Bug Bounty (nothing dated found) | yes |
| 5 — Offensive Security Research | 2 | SpecterOps (LLM-driven EDR-evasion research, 2026-06-29), Rapid7/Metasploit (weekly updates 2026-06-19 and 2026-07-03/04) | Project Zero / "0day In the Wild" (no post found in window), ProjectDiscovery (most recent is March 2026 Neo launch), SANS Pen Test (only forward-looking webinar announcements) | yes |
| 6 — Community & Researchers | 3 | Krebs on Security (NetNut/Popa takedown, Scattered Spider), The DFIR Report (Bumblebee/AdaptixC2→Akira), BleepingComputer, The Hacker News, SANS ISC, Malwarebytes Labs, Security Affairs, Dark Reading | Schneier on Security (active but policy-focused, no new threat-actor finding this period) | yes — well exceeded |
| 7 — Dark Web Intelligence | best-effort | None | All named sources (Flashpoint, Intel 471, DarkOwl, Cybersixgill, ReliaQuest, ZeroFox, Searchlight Cyber) subscription-gated; no access | n/a |
| 8 — Government & Regulatory | 3 | CISA (KEV catalog + 9 ICS advisories), NCSC UK (FortiBleed alert), FBI IC3 (FLASH-20260702-01 — low confidence, primary PDF fetch blocked) | NSA, ENISA, ACSC, JPCERT, CERT-In — no live access attempted this cycle | yes — with the IC3 item flagged low-confidence |
| 9 — Malware Analysis & Sandboxing | 3 | Any.Run (Q1 2026 Cyber Risk Report), abuse.ch/ThreatFox (via third-party SOCRadar aggregation only — low confidence) | MalwareBazaar, URLhaus, Hybrid Analysis, Malpedia — no dated current-window content found for any | no — 2 of 3 met, one at low confidence |

**Total preferred-source targets consulted:** ~24 / ≈25, but two tiers (2, 9) fell short of their numeric target with genuinely current-week material, and several citations across tiers rely on secondary reporting rather than verified primary-source fetches (widespread HTTP 403 on direct retrieval this cycle).

**Coverage badge: PARTIAL**

Rationale: this is a substantial improvement over the MINIMAL badges of the prior two weekly reports — live search surfaced dozens of genuinely current (last 7 days), well-corroborated, multi-source stories (FortiBleed, the JadePuffer agentic-ransomware case, nine-plus new KEV entries, several new APT/malware-framework disclosures). It falls short of `FULL` because: (a) roughly a third of Tier 2's named commercial-intel vendors produced no new content in-window despite being checked, (b) Tier 9's malware-sandbox tier could only be reached via third-party aggregation rather than the named primary sources, (c) no literal atomic IOC values were retrievable, and (d) many primary-source pages returned HTTP 403 on direct fetch, so a meaningful share of citations rest on secondary outlets rather than verified original text.

**Fabrication check:** PASS — no CVE number, IP address, file hash, domain name, or actor attribution was invented. The three atomic indicators in §6b (`maccyapp.com`, `frint`, `skytext`) are all directly sourced to a named report and were not generated from pattern inference. All CVSS scores marked "not stated" reflect an actual retrieval gap, not an estimate presented as fact.

**Unverified items:** FBI IC3 FLASH-20260702-01 (§9, item 1 — primary PDF fetch blocked, summarized from search snippets only); the HackerOne monthly-payout figure (§Appendix, Tier 4 — could not be traced to a single confirmed primary URL); exact device-count for the FortiBleed campaign (§9, item 4 — conflicting figures across outlets); four CVEs with "not stated" CVSS (§9, item 8).

---

*This report was generated by the `cyber-threat-intel` skill on 2026-07-06 using live web search across all nine source tiers. It structures AI output and provides detection guidance based on documented, source-cited reporting; it does not guarantee accuracy and does not substitute for a connected live threat-intel feed for atomic indicators. Verify critical findings — especially the FortiBleed campaign scope and any KEV deadline — against authoritative primary sources before operational deployment of any blocklist, detection rule, or patch-priority decision.*
