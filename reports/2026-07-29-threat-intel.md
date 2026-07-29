```
THREAT INTELLIGENCE REPORT
Generated: 2026-07-29T00:00:00Z
Coverage: PARTIAL
Time Range: 2026-07-27 to 2026-07-29
Scope: All emerging threats (default)
Persona: enterprise_soc
Assets: network edge, endpoints, mobile, APIs, payment systems
```

> **Methodology notice (read before acting on this report):**
> This run used live web search/retrieval (the `threat-intel-mcp` server was not connected in this session — no
> MCP tools were present) to research all nine source tiers for the tight 2026-07-27 -> 2026-07-29 (48h) window.
> Retrieval was genuinely current for narrative/campaign reporting. Three honest limitations:
> - **Direct primary-source fetches were blocked (HTTP 403).** `cisa.gov` and `huggingface.co` both rejected
>   direct page fetches during this run. Facts attributed to CISA (KEV catalog, ICS advisories) and to the
>   Hugging Face incident disclosure were recovered via secondary reporting (BleepingComputer, The Hacker News,
>   SecurityWeek, Help Net Security, Axios) and search-result snippets, not a verified primary-document read.
> - **No literal current IOC values (hashes/IPs/domains) were retrievable this cycle.** Unlike the prior report
>   (which surfaced three source-attributed atomic indicators), general web search for this narrow 48h window
>   turned up named tools/files and malware-family names but no new hash/IP/domain values. None are fabricated
>   below (R3) -- where a real named artifact surfaced (a sideloaded DLL, a malware family name), it is cited to
>   its source; everywhere else the gap is stated plainly.
> - **A 48-hour lookback is close to the edge of what general web search indexes reliably.** Some items below
>   (GreyNoise's most recent dated bulletin, the Hugging Face incident) fall just outside the strict window and
>   are included as directly relevant background, clearly marked as such.
>
> **Recommended action:** Connect `threat-intel-mcp` (or operator feeds -- Q-Feeds, AbuseIPDB, VirusTotal, OTX,
> Shodan, GreyNoise) for literal current IOC values and CVE-feed cross-checks; this report is strong on
> vulnerability/campaign narrative for the window but cannot substitute for a live feed on atomic indicators.

---

## 1. Alert Banner

```
CRITICAL: CVE-2026-56155 (AD FS DKM ACL elevation of privilege, CVSS 7.8) was exploited in the wild as a
          zero-day before a patch existed. CISA's federal remediation deadline is 2026-07-28 -- effectively
          today relative to this report. Administrative AD FS access exposes the token-signing certificate
          used to prove identity to every federated application; treat overdue instances as compromised.
CRITICAL: CVE-2026-16723 (Fastjson 1.x, CVSS 9.0) is under active exploitation against US business, financial
          services, healthcare, and retail organizations, and **no patch exists** -- the 1.x line is EOL and
          the flaw is exploitable under stock default configuration (no AutoType, no gadget chain required).
CRITICAL: CVE-2026-12569 (PTC Windchill/FlexPLM deserialization RCE, CVSS 9.3) is fueling an active Cl0p
          extortion campaign that intensified starting 2026-07-20, targeting aerospace, automotive,
          manufacturing, and retail/apparel with mass "Windchill PDMLink module serious data leak" emails.
HIGH:     A 22-year-old IPMI/BMC authentication flaw (CVE-2013-4786) leaves 24,650 internet-exposed Baseboard
          Management Controllers -- mostly Supermicro -- disclosing crackable password hashes pre-authentication;
          a third were cracked outright using the default 10-character password printed on the chassis sticker.
HIGH:     A public pre-auth RCE PoC (CVE-2026-61511) for vBulletin dropped 2026-07-27, four weeks after a silent
          patch; not yet confirmed exploited in the wild or KEV-listed, but the historical pattern for vBulletin
          disclosures is fast weaponization once a PoC is public.
ELEVATED: A new malware toolset (TELESHIM/MIXEDKEY/BINDCLOAK) from an East-Asia-linked actor is targeting Middle
          East government entities via a weaponized ISO and Telegram-Bot-API C2, reported 2026-07-27 (Zscaler).
          Separately, Qilin ransomware affiliates continue exploiting the Palo Alto GlobalProtect auth bypass
          (CVE-2026-0257) for rapid perimeter-to-domain-encryption intrusions.
```

---

## 2. Executive Summary

- **Three CVEs in active exploitation this window carry immediate, board-relevant urgency.** AD FS (CVE-2026-56155) has a CISA federal deadline landing essentially today; Fastjson 1.x (CVE-2026-16723) is under active attack across multiple US sectors **with no patch available at all** (only mitigation: upgrade off the EOL 1.x line or virtually patch); and PTC Windchill (CVE-2026-12569) is driving a live Cl0p extortion campaign against manufacturing-sector organizations. Any of the three, if present and internet-facing, should trigger incident-response posture, not routine patch-cycle handling.
- **A 22-year-old protocol flaw (IPMI 2.0 / CVE-2013-4786) was newly shown to expose 24,650 servers' BMC interfaces** to pre-authentication password-hash disclosure, with roughly a third crackable using factory-default credentials printed on the hardware itself (predominantly Supermicro). This is a pure asset-inventory and network-segmentation problem, not a patchable-software one -- BMC/IPMI (UDP/TCP 623) should never be internet-reachable.
- **Ransomware initial-access vectors this window are dominated by edge/perimeter and PLM infrastructure**, not phishing: Qilin via a Palo Alto GlobalProtect auth-bypass, Cl0p via PTC Windchill deserialization, and a newly public vBulletin pre-auth RCE PoC that fits the same pattern (internet-facing app -> unauthenticated code execution -> ransomware/extortion).
- **New/renamed threat activity this window:** an East-Asia-linked actor deployed previously undocumented tooling (TELESHIM, MIXEDKEY, BINDCLOAK) against Middle Eastern government targets, using Telegram's Bot API for C2 and volume-serial-number-derived decryption keys to evade sandbox analysis (Zscaler, 2026-07-27). The Golden Chickens malware-as-a-service operation (tracked as TAG-195) resurfaced with four new modular families (TinyEgg, ChonkyChicken + a modular variant, ChromEggscalator) including live Chrome-session hijacking, deployed in part via ClickFix-style social engineering (Recorded Future).
- **Crimeware-enablement services are professionalizing further.** "Cruciferra," a crypter-as-a-service first seen in late 2025 ($450-2,000/month), combines BYOVD driver abuse, Process Ghosting, and 90+ mix-and-match encryption routines to cloak commodity RATs/infostealers (AsyncRAT, XWorm, Remcos, AgentTesla, and others) for multiple unrelated criminal clusters -- consistent with ANY.RUN's weekly sandbox trend data, which still shows infostealers (Vidar, StealC, Lumma) and RATs (AsyncRAT, XWorm, Remcos, Quasar) dominating uploaded samples.
- **Supply-chain pressure on npm/PyPI continues without a pause.** Four additional campaigns landed between early June and 2026-07-14 (a Shai-Hulud worm variant, typosquatted payment SDKs, a stolen publishing token, and a hijacked CI pipeline), and a single npm publisher account ("marketfront") batch-published 25 packages on 2026-07-01 carrying a README lure previously tracked across four other accounts.
- **Bug-bounty market structure shifted in a way worth tracking for VDP-dependent orgs:** GitHub cut its public bug-bounty payouts in half and moved top-tier rewards behind an invite-only program (reported 2026-07-27), while both HackerOne and Bugcrowd continue tightening anti-abuse controls against AI-generated low-quality submissions -- a signal that public-program signal-to-noise is degrading industry-wide.

---

## 3. Threat Dashboard

| Category | New This Period | Active Exploits | Trend | Risk Level | Org Relevance |
|---|---|---|---|---|---|
| Ransomware / Extortion | Public vBulletin pre-auth RCE PoC (CVE-2026-61511); The Gentlemen adds 16 claimed (unpublished) victims | Cl0p via PTC Windchill (CVE-2026-12569), Qilin via Palo Alto GlobalProtect (CVE-2026-0257) | ↑ | CRITICAL | HIGH -- network edge, PLM/manufacturing systems |
| Zero-Day / Edge | CVE-2026-56155 (AD FS, KEV, federal deadline today); Fastjson 1.x RCE with no patch | CVE-2026-56155, CVE-2026-16723 actively exploited | ↑ | CRITICAL | HIGH -- identity infra, Java app servers |
| APT / Nation-State | TELESHIM/MIXEDKEY/BINDCLOAK (new toolset, East-Asia-linked actor vs. Middle East govt) | -- | ↑ | HIGH | MEDIUM -- sector/geography-dependent |
| Malware-as-a-Service | Golden Chickens/TAG-195 four new families (TinyEgg, ChonkyChicken, ChromEggscalator); Cruciferra crypter-as-a-service | Commodity RAT/infostealer delivery (AsyncRAT, XWorm, Vidar, StealC, Lumma) via ClickFix and cracked-service lures | ↑ | HIGH | HIGH -- endpoints |
| Infrastructure Exposure | 24,650 internet-exposed BMCs leaking IPMI password hashes (CVE-2013-4786) | Offline hash cracking against exposed BMCs | ↑ | HIGH | MEDIUM-HIGH -- data center / OOB management networks |
| Supply Chain | npm "marketfront" 25-package batch publish (README-lure pattern) | Ongoing Shai-Hulud-variant, typosquat, stolen-token, hijacked-CI-pipeline campaigns | ↑ | HIGH | MEDIUM-HIGH -- dev/CI-CD toolchain |
| AI / Agentic Systems | -- (Hugging Face incident falls just outside window, see below) | -- | → | MEDIUM | MEDIUM -- AI/ML infrastructure, agent tooling |
| Credential / Identity | AD FS DKM ACL flaw exposes token-signing certificate material | CVE-2026-56155 | ↑ | CRITICAL | HIGH -- federated identity |
| Mobile | limited signal this period -- no new mobile-specific campaign surfaced in this 48h window | -- | → | MEDIUM | MEDIUM -- carried forward from prior periods |
| Bug Bounty / VDP Market | GitHub halves public payouts, moves top rewards to invite-only tier | -- | ↑ (industry shift) | LOW-MEDIUM | LOW-MEDIUM -- VDP-dependent orgs |

---

## 4. Critical Vulnerability Summary

| CVE | CVSS | Product | Exploit Status | GreyNoise Activity | Org Exposure | Action | Source |
|---|---|---|---|---|---|---|---|
| CVE-2026-56155 | 7.8 | Microsoft AD FS (Windows Server 2012 R2 ESU-2025) | Confirmed exploited in the wild pre-patch (zero-day); CISA KEV, federal deadline 2026-07-28 | Not stated (no GreyNoise tag surfaced in retrieval) | HIGH if AD FS is deployed -- federated identity/token-signing certs at risk | Patch immediately; if past federal deadline, treat as compromise-assumed and rotate DKM-protected token-signing/encryption certificates | CISA KEV; cve.halosecurity.com; bytevanguard.com |
| CVE-2026-16723 | 9.0 | Fastjson 1.2.68-1.2.83 (EOL 1.x line) | Actively exploited against US business/financial/healthcare/retail sectors; **no patch exists** | Not stated | HIGH if any Java service parses untrusted JSON via Fastjson 1.x | Emergency mitigation: upgrade to Fastjson2, or virtually patch (WAF rule blocking known deserialization gadget payloads) pending migration; inventory all Java services for the dependency | Imperva; The Hacker News; SecurityWeek; latesthackingnews.com |
| CVE-2026-12569 | 9.3 | PTC Windchill / FlexPLM | Confirmed exploited (Cl0p); CISA KEV since end of June; extortion-email campaign intensified 2026-07-20 | Not stated | HIGH for manufacturing/aerospace/automotive/retail-apparel with Windchill/FlexPLM internet exposure | Confirm patch applied (released 2026-06-17); hunt for JSP webshells and prior IoCs published by PTC; treat as compromise-assumed if internet-facing before the patch date | SecurityWeek; Help Net Security; Ransom-ISAC |
| CVE-2026-0257 | 7.8 | Palo Alto PAN-OS GlobalProtect (portal/gateway) | Confirmed exploited by Qilin ransomware affiliates since mid-May 2026, ongoing through this window | Not stated (see GreyNoise "At The Edge Clear" background item, §9) | HIGH for internet-facing GlobalProtect with auth-override cookies enabled | Confirm patch (2026-05-13); terminate all active GlobalProtect sessions post-patch; disable auth-override cookies or use a dedicated certificate | Arctic Wolf Labs; The Hacker News; BleepingComputer |
| CVE-2026-61511 | Not stated (described as "critical") | vBulletin <=6.2.1 / <=6.1.6 | Public pre-auth RCE PoC released 2026-07-27; **not yet confirmed exploited in the wild; not yet in CISA KEV** as of this report | Not stated | MEDIUM-HIGH for any internet-facing vBulletin forum still unpatched | Apply 6.2.2 (released 2026-07-01) immediately -- do not wait for KEV listing given public PoC | SSD Secure Disclosure; BleepingComputer; The Hacker News |
| CVE-2013-4786 | Not stated (auth weakness, not a CVSS-scored RCE) | IPMI 2.0 / BMC firmware (predominantly Supermicro) | Not "exploited" in the RCE sense -- pre-auth password-hash disclosure enabling offline cracking; ~1/3 of exposed hosts crackable via default credentials | Not stated | MEDIUM-HIGH for any org with internet-reachable BMC/IPMI (port 623) | Remove BMC/IPMI from internet exposure entirely; segment to an out-of-band management network; rotate default/sticker credentials fleet-wide | BleepingComputer; Help Net Security; Dark Reading (Lava research) |

---

## 5. Business Line Risk Spotlight

*No new business context was provided (default: none). This section is omitted. Provide business context on the
next invocation -- e.g., current AD FS/Fastjson/PTC Windchill/vBulletin/Palo Alto GlobalProtect footprint, or
whether any data-center BMC/IPMI management interfaces are internet-reachable -- to receive tailored risk
scenarios for this week's specific findings.*

---

## 6. IOC Package

> **R3 compliance notice:** No literal current network IOCs (IPs, C2 domains, file hashes) were retrievable for
> this specific 48-hour window -- general web search surfaces campaign narrative and named artifacts, not the
> atomic indicator feeds that live inside ThreatFox/MalwareBazaar/AbuseIPDB/URLhaus/VirusTotal, and no
> `threat-intel-mcp` connection was available this session. **No IOC values below are fabricated.** Where a
> real, specifically-named artifact surfaced in vendor reporting (a sideloaded DLL name, a malware family name),
> it is included with its source. Everything else is a behavioral/TTP-level indicator derived from documented
> technique descriptions.

### 6a. Deployment Priority

| Priority | Category | Action | Count |
|---|---|---|---|
| P1 -- IMMEDIATE | CISA KEV entries in §4 (CVE-2026-56155, CVE-2026-12569) | Patch/isolate per federal deadlines; AD FS deadline is effectively today | 2 CVEs |
| P1 -- IMMEDIATE | Fastjson 1.x exposure (CVE-2026-16723, no patch) | Inventory, migrate/virtually patch | 1 CVE |
| P1 -- IMMEDIATE | Named real-world artifacts (§6b) | Hunt/detect | 2 items |
| P1 -- IMMEDIATE | Behavioral/TTP detection rules (§7) | Deploy to SIEM/EDR | 6 rules |
| P2 -- 48h | vBulletin PoC (CVE-2026-61511) and Palo Alto GlobalProtect (CVE-2026-0257) | Patch/hunt | 2 CVEs |
| P2 -- 48h | BMC/IPMI internet exposure (CVE-2013-4786) | Inventory + segment + rotate credentials | 1 finding class |
| P3 -- 7d | Live feed integration | Connect threat-intel-mcp for atomic IOC backfill | 1 action |

### 6b. Named Real-World Artifacts (sourced, not fabricated)

```csv
artifact_type,artifact_value,confidence,threat_name,threat_actor,mitre_technique,source,first_seen,last_seen,action,tlp
file_name,AsTaskSched.dll,high,TELESHIM initial-access DLL sideload payload,unattributed (East-Asia-linked),T1574.002,zscaler.com ThreatLabz "Targeted Attack on Government Entities in the Middle East Part 1",2026-07-27,2026-07-27,hunt+block,TLP:WHITE
file_name,RegSchdTask.exe,high,ASUS-signed binary abused to sideload AsTaskSched.dll (TELESHIM),unattributed (East-Asia-linked),T1574.002,zscaler.com ThreatLabz "Targeted Attack on Government Entities in the Middle East Part 1",2026-07-27,2026-07-27,hunt,TLP:WHITE
```

> **Guidance:** these two entries are the only literal, source-attributed artifacts this cycle's retrieval
> surfaced for the strict 48h window. `RegSchdTask.exe` is a legitimate ASUS-signed binary being abused for DLL
> sideloading -- do not blocklist the binary itself (it may be legitimately present on ASUS hardware); instead
> alert on its co-occurrence with `AsTaskSched.dll` outside expected ASUS utility install paths. Malware *family
> names* (TinyEgg, ChonkyChicken, ChromEggscalator, Cruciferra, MIXEDKEY, BINDCLOAK) are cited throughout this
> report and are useful for threat-intel-platform tagging and EDR/AV signature-name correlation, but are not
> themselves atomic indicators and are not repeated in this table.

### 6c. Behavioral IOCs (derived from documented technique descriptions -- not literal samples)

| Behavior | Data Source | Detection Logic | MITRE ID | Threshold | Source |
|---|---|---|---|---|---|
| ASUS-signed `RegSchdTask.exe` loading a non-standard, recently-written DLL (e.g. named `AsTaskSched.dll`) from a user-writable or non-default install path | EDR image-load/process telemetry | Alert on `RegSchdTask.exe` (or other signed ASUS scheduler binaries) with a child/loaded-module DLL outside the standard ASUS install directory, written within the prior 24h | T1574.002 | any occurrence outside known-good ASUS software inventory | Zscaler ThreatLabz (TELESHIM) |
| Outbound HTTPS to `api.telegram.org` with a `/bot<token>/` URI path, originating from a process that is not a known messaging/automation application | Proxy / DNS / EDR network telemetry | Flag `api.telegram.org` connections where the parent process is not an approved chat/bot-automation tool | T1102.002, T1071.001 | any occurrence outside an approved bot-integration allowlist | Zscaler ThreatLabz (TELESHIM C2 channel) |
| Unauthenticated POST to a vBulletin `runtime.php`/template-render endpoint containing arithmetic-operator-heavy payloads (digits, parentheses, `^`, binary operators) consistent with `runMaths()` eval-injection | Web server / WAF logs | Alert on POST bodies to `*/includes/vb5/template/*` matching a dense arithmetic-expression pattern from an unauthenticated session | T1190, T1059 | any match pending WAF tuning | SSD Secure Disclosure (CVE-2026-61511) |
| RMCP+/IPMI (UDP/TCP 623) session-open request from an external/internet-sourced address, not preceded by any prior successful authentication | Firewall / NetFlow | Any inbound UDP/TCP 623 from outside the management VLAN should itself be the alert -- BMC/IPMI has no legitimate internet-facing use case | T1110, T1595 | any occurrence | BleepingComputer; Dark Reading (Lava BMC/IPMI research) |
| New local/service account created within minutes of an internet-facing PTC Windchill/FlexPLM process spawning an unusual child process (webshell-drop pattern) | Windows Security / application logs | Correlate Event ID 4720/4732 with a preceding anomalous child process from `windchill`/`flexplm`-associated services within a 5-minute window | T1136, T1190, T1505.003 | 1 correlated event | SecurityWeek; Ransom-ISAC (Cl0p/Windchill campaign) |

---

## 7. Detection Rules

### 7a. Sigma -- ASUS Scheduler Binary Sideloading Unexpected DLL (TELESHIM initial access)

```yaml
title: Signed ASUS RegSchdTask Binary Loading Non-Standard DLL
id: a1b2c3d4-e5f6-4789-9abc-def012345678
status: test
description: >
  Detects the ASUS-signed RegSchdTask.exe binary being abused to sideload a malicious
  AsTaskSched.dll, the initial-access technique reported by Zscaler ThreatLabz in the
  TELESHIM/MIXEDKEY/BINDCLOAK campaign against Middle East government targets (July 2026).
references:
  - https://www.zscaler.com/blogs/security-research/targeted-attack-government-entities-middle-east-part-1
  - https://thehackernews.com/2026/07/teleshim-abuses-telegram-for-c2-in.html
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-07-29
tags:
  - attack.defense_evasion
  - attack.t1574.002
  - attack.initial_access
logsource:
  category: image_load
  product: windows
detection:
  selection:
    Image|endswith: '\RegSchdTask.exe'
  suspicious_module:
    ImageLoaded|endswith: '\AsTaskSched.dll'
  filter_known_path:
    ImageLoaded|startswith:
      - 'C:\Program Files\ASUS\'
      - 'C:\Program Files (x86)\ASUS\'
  condition: selection and suspicious_module and not filter_known_path
falsepositives:
  - Legitimate ASUS utility installations outside the default install directory -- validate the ASUS software
    inventory and adjust filter_known_path before enabling in blocking mode
level: high
status_note: needs_validation -- test in an isolated environment against a genuine ASUS install before deploying
```

### 7b. Sigma -- Telegram Bot API Used as C2 Channel by Non-Messaging Process

```yaml
title: Telegram Bot API Contacted by Unexpected Process
id: b2c3d4e5-f6a7-4890-abcd-ef0123456789
status: test
description: >
  Detects outbound connections to api.telegram.org using a bot-API URI pattern from a
  process that is not an approved messaging/bot-automation tool -- the C2 channel used by
  TELESHIM (Zscaler ThreatLabz, July 2026).
references:
  - https://www.zscaler.com/blogs/security-research/targeted-attack-government-entities-middle-east-part-1
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-07-29
tags:
  - attack.command_and_control
  - attack.t1102.002
  - attack.t1071.001
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationHostname: 'api.telegram.org'
    Initiated: 'true'
  filter_approved:
    Image|contains:
      - '\Teams\'
      - '\Slack\'
  condition: selection and not filter_approved
falsepositives:
  - Legitimate internal Telegram bot integrations -- build an explicit allowlist of approved bot-automation
    hosts/processes before enabling in blocking mode
level: medium
status_note: needs_validation
```

### 7c. Sigma (web) -- vBulletin runMaths Eval-Injection Attempt (CVE-2026-61511)

```yaml
title: vBulletin Runtime Template runMaths Eval Injection Attempt
id: c3d4e5f6-a7b8-4901-bcde-f01234567890
status: test
description: >
  Detects unauthenticated POST requests to vBulletin's runtime template endpoint containing
  arithmetic-expression payloads consistent with the runMaths() eval() injection disclosed
  by SSD Secure Disclosure (CVE-2026-61511, public PoC 2026-07-27).
references:
  - https://ssd-disclosure.com/vbulletin-runtime-template-runmaths-preauth-rce/
  - https://www.bleepingcomputer.com/news/security/vbulletin-fixes-critical-pre-auth-rce-flaw-with-public-exploit/
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-07-29
tags:
  - attack.initial_access
  - attack.t1190
  - attack.t1059
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains: '/includes/vb5/template/'
    cs-method: 'POST'
  suspicious_body:
    cs-body|re: '[0-9()^+\-*/]{20,}'
  condition: selection and suspicious_body
falsepositives:
  - Legitimate template-rendering traffic with numeric parameters -- tune the regex threshold against a baseline
    of normal forum traffic before enabling in blocking mode
level: high
status_note: needs_validation -- schema_dependency is generic web-server access-log fields (IIS/W3C or Apache
  combined format field names); map cs-uri-stem/cs-method/cs-body to the local log schema before deployment
```

### 7d. KQL -- Fastjson-Style Deserialization RCE Spawn Detection (Sentinel / Defender for Endpoint)

```kql
// Hunt: Java process spawning a command interpreter shortly after network activity, consistent with
// Fastjson 1.x (CVE-2026-16723) deserialization RCE -- no patch exists for this CVE, so detection/virtual
// patching is the primary control until migration off the 1.x line completes.
// schema_dependency: DeviceProcessEvents (Microsoft Defender for Endpoint). status: needs_validation
DeviceProcessEvents
| where Timestamp > ago(2d)
| where InitiatingProcessFileName in~ ("java.exe", "javaw.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "sh", "bash", "curl", "wget")
| where InitiatingProcessCommandLine has_any ("json", "fastjson", "parseObject", "JSON.parse")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

*Coverage check:*
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("java.exe", "javaw.exe")
| summarize count() by DeviceName
```

### 7e. SPL -- Internet-Sourced IPMI/RMCP+ (Port 623) Session Attempts

```splunk
`` Hunt: any inbound IPMI/RMCP+ session-open request (UDP/TCP 623) from outside the management network.
`` No legitimate BMC/IPMI use case involves internet sourcing -- CVE-2013-4786 (pre-auth password-hash
`` disclosure) affects any exposed BMC regardless of vendor patch level unless IPMI 2.0 cipher-suite-0 is
`` disabled. schema_dependency: Network_Traffic CIM data model (firewall/NetFlow). status: needs_validation
| tstats summariesonly=true count
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=623
    AND NOT (All_Traffic.src_ip="10.0.0.0/8" OR All_Traffic.src_ip="172.16.0.0/12" OR All_Traffic.src_ip="192.168.0.0/16")
  by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port, _time span=1h
| rename All_Traffic.* AS *
```

*Coverage check (confirm Network_Traffic CIM model is populated for this environment):*
```splunk
| tstats count from datamodel=Network_Traffic.All_Traffic by index, sourcetype
```

> Note: the private-range exclusion above is illustrative -- replace with the environment's actual internal
> CIDR ranges via `<PLACEHOLDER>` before deployment; any true positive here means a BMC is directly internet
> reachable and should be remediated regardless of what the query returns afterward.

### 7f. Snort/Suricata -- PAN-OS GlobalProtect Auth-Override Cookie Abuse (CVE-2026-0257)

```snort
# Rule: Detect GlobalProtect portal/gateway authentication attempts presenting an auth-override cookie
# where no prior valid session establishment occurred -- pattern associated with CVE-2026-0257 exploitation
# by Qilin ransomware affiliates (Arctic Wolf Labs reporting, ongoing through July 2026).
# Source: Arctic Wolf Labs; The Hacker News
# Status: needs_validation -- tune to the deployment's actual GlobalProtect portal path/cookie name
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"POSSIBLE PAN-OS GlobalProtect Auth-Override Cookie Abuse Attempt (CVE-2026-0257)";
  flow:to_server,established;
  http_uri;
  content:"/global-protect/"; nocase;
  content:"Cookie|3a| "; http_header; nocase;
  content:"PHPSESSID"; http_header; distance:0; nocase;
  classtype:attempted-admin;
  sid:9000201; rev:1;
  reference:url,thehackernews.com/2026/07/qilin-ransomware-attackers-exploit-pan.html;
)
```

---

## 8. Actions Matrix

| Priority | Action | Owner | Timeline | Investment | Risk Addressed | Success Metric |
|---|---|---|---|---|---|---|
| P1 | Patch/verify CVE-2026-56155 on all AD FS servers; if the 2026-07-28 federal deadline was missed, rotate DKM-protected token-signing/encryption certificates | Identity/IAM + IR | 0-48h | Medium | AD FS zero-day exploited pre-patch; federated-identity compromise | Zero unpatched AD FS instances; cert rotation completed where deadline was missed |
| P1 | Inventory all Java services for the Fastjson 1.x dependency (CVE-2026-16723); migrate to Fastjson2 or deploy WAF/virtual patch immediately since no vendor patch exists | AppSec + Platform Eng | 0-48h | Medium-High | Fastjson deserialization RCE with no available fix | Zero services on unmitigated Fastjson 1.x |
| P1 | Confirm PTC Windchill/FlexPLM is patched (2026-06-17 release); hunt for JSP webshells and prior IoCs published by PTC | Vulnerability Mgmt + IR | 0-48h | Medium | Active Cl0p extortion campaign against Windchill/FlexPLM | Patch confirmed; webshell hunt completed with zero findings or IR opened |
| P1 | Deploy the TELESHIM DLL-sideload and Telegram-C2 Sigma rules (§7a/§7b) to SIEM/EDR | SOC Engineering | 0-48h | Low | TELESHIM/MIXEDKEY/BINDCLOAK initial access and C2 | Rules active; test-fired in lab |
| P2 | Patch Palo Alto GlobalProtect (CVE-2026-0257) if not already done; terminate all active sessions post-patch; disable auth-override cookies or move to a dedicated certificate | Network Security | 48h-7d | Medium | Qilin ransomware initial access via VPN auth bypass | Patch confirmed; session-termination completed; cookie mitigation in place |
| P2 | Apply vBulletin 6.2.2 to any internet-facing forum instance (CVE-2026-61511); deploy the web-log Sigma rule (§7c) in the interim | Web/App Ops | 48h-7d | Low | Public pre-auth RCE PoC against internet-facing forum software | Patch confirmed on all instances |
| P2 | Inventory all BMC/IPMI (port 623) exposure; remove from internet reach and place on an isolated out-of-band management network; rotate any default/sticker credentials fleet-wide | Data Center / Infra Ops | 48h-7d | Medium | CVE-2013-4786 pre-auth password-hash disclosure on 24,650+ exposed BMCs industry-wide | Zero internet-reachable BMC/IPMI interfaces in the environment |
| P2 | Run the Fastjson RCE-spawn KQL hunt (§7d) against 48h of endpoint telemetry | SOC Analysts | 48h-7d | Low-Medium | Undetected Fastjson exploitation prior to full mitigation | No unresolved high-severity hits, or IR opened on any hit |
| P3 | Review EDR/AV coverage against Cruciferra-cloaked commodity malware (AsyncRAT, XWorm, Remcos, AgentTesla, StealC, Vidar, Lumma) and tune detections beyond static signatures given the crypter's evasion techniques | SOC Engineering | 7-30d | Medium | Cruciferra crypter-as-a-service defeating signature-based AV across multiple criminal clusters | Behavioral/EDR detections validated against current sample set |
| P3 | Audit CI/CD publish-token handling and review recent npm/PyPI dependency additions against the ongoing supply-chain campaign pattern (Shai-Hulud variant, typosquats, stolen tokens, hijacked pipelines) | DevSecOps | 7-30d | Medium | Ongoing npm/PyPI supply-chain compromise pattern | Token rotation completed; dependency review documented |
| P4 | Evaluate MITRE ATLAS v5.4.0 (16 tactics / 84 techniques, including "Publish Poisoned AI Agent Tool" and "Escape to Host") for internal AI/agent threat-modeling adoption, informed by the Hugging Face autonomous-agent incident (§9) | Security Leadership + AppSec | 30-90d | Low-Medium | Growing agentic-AI attack-automation and AI-infrastructure risk | ATLAS mapping incorporated into threat-model reviews for AI-adjacent systems |

---

## 9. CWE Chain Analysis

**Chain: vBulletin `runMaths()` Pre-Auth Eval Injection (CVE-2026-61511)**

- **chain_type:** primary_resultant
- **cwe_view:** CWE-1003 (Weaknesses for Simplified Mapping of Published Vulnerabilities)
- **Chain:** CWE-20 (Improper Input Validation -- the regex meant to restrict `runMaths()` input to safe
  arithmetic characters is insufficient) -> CWE-95 (Improper Neutralization of Directives in Dynamically
  Evaluated Code / Eval Injection) -> CWE-94 (Code Injection, realized as arbitrary PHP execution via `eval()`)
- **ai_assist_factor:** low -- this is a classic manual vulnerability-research finding (SSD Secure Disclosure),
  with no reported AI-assistance in discovery or the public PoC.
- **time_to_exploit (Zero Day Clock TTE) / velocity:** patch released 2026-07-01 (silent), public PoC 2026-07-27
  -- a ~26-day patch-to-PoC gap, consistent with vBulletin's historical weaponization pattern once a PoC lands.
  Not yet CISA KEV-listed as of this report; the historical pattern is that KEV listing and in-the-wild
  exploitation for this platform tend to follow public PoC release within days to a few weeks -- **treat as an
  accelerating-risk item worth re-checking within the next few days**, not a closed matter because it isn't
  KEV-listed yet.
- **Defensive break-points** (source: CWE.mitre.org definitions; SSD Secure Disclosure PoC writeup):
  - **shared-primary (highest leverage):** fix the root CWE-20 defect -- apply vBulletin 6.2.2, which corrects
    the input-validation logic at the source rather than any downstream mitigation.
  - **preventive:** WAF rule blocking dense arithmetic-expression payloads to `*/includes/vb5/template/*`
    endpoints (mirrors §7c's detection logic in blocking mode).
  - **detective:** the Sigma rule at §7c, tuned against baseline forum traffic.
  - **corrective:** if compromise is suspected, treat as full server compromise (arbitrary PHP execution) --
    rebuild from a known-good state rather than attempting in-place remediation.

---

## 10. Intelligence Gaps

1. **No live feed / MCP connection this cycle.** No `threat-intel-mcp` server was present in this session, so no
   literal current IOC values (IPs, hashes, domains) were retrievable for this specific 48h window. Connect the
   MCP server or an operator-supplied feed (Q-Feeds, AbuseIPDB, VirusTotal, OTX, Shodan, GreyNoise) for atomic
   indicator backfill on next invocation.
2. **Primary-source fetches were blocked (HTTP 403).** Direct fetches to `cisa.gov` and `huggingface.co` were
   both rejected during this run. All facts attributed to CISA (KEV catalog entries, the 7 ICS advisories
   published 2026-07-28) and to the Hugging Face incident disclosure rely on secondary reporting
   (BleepingComputer, The Hacker News, SecurityWeek, Help Net Security, Axios) rather than a verified
   primary-document read.
3. **CISA's 7 ICS advisories published 2026-07-28** (ICSA-26-209-01 through -07) were confirmed to exist via
   search-result snippets, but individual vendor/product names were not retrieved in this cycle -- flagged as
   consulted-at-summary-level only, not analyzed per-advisory.
4. **GreyNoise's most recent dated bulletin found ("At The Edge Clear," 2026-07-06 to -13)** falls just outside
   this strict 48h window; no fresher GreyNoise weekly publication was located during this run. Included in §4's
   context only as unconfirmed background, not as a within-window finding.
5. **The Hugging Face autonomous-AI-agent incident (disclosed 2026-07-16, attribution updated 2026-07-21)**
   falls outside the strict 48h window but is included in §8/§9 as directly relevant background given this
   report's persistent AI-agentic-threat framing. It was later attributed to an authorized internal OpenAI
   red-team evaluation, not a malicious external breach -- this distinction is preserved rather than presented
   as an active incident.
6. **Dark web intelligence (Tier 7) is thin this cycle.** The only surfaced item was an aggregator/X-account
   listing of "The Gentlemen" ransomware group's leak-site additions (16 organizations, all marked
   "unpublished" by the group itself) -- **these are unconfirmed claims by the threat actor, not verified
   breaches**, and are not repeated as confirmed victims anywhere else in this report. All named subscription-
   gated Tier 7 sources (Flashpoint, Intel 471, DarkOwl, Cybersixgill, ReliaQuest, ZeroFox, Searchlight Cyber)
   remain inaccessible.
7. **Malware-sandboxing tier (9) is thin.** Only ANY.RUN's public weekly trends tracker surfaced dated content
   for the window; MalwareBazaar, URLhaus, Hybrid Analysis, and Malpedia had no dated within-window content
   found via general web search.
8. **Mobile-specific threats.** No new mobile-platform-specific campaign or CVE surfaced in this window's
   retrieval. This does not indicate reduced mobile risk, only that this cycle's searches did not turn up new
   material -- carry forward prior-period mobile guidance.
9. **Exact CVSS score for CVE-2026-61511 (vBulletin)** was not present in retrievable search snippets; sources
   describe it only as "critical" without a numeric score, and it is marked "not stated" in §4 rather than
   estimated.

---

## Appendix A: Source Coverage Ledger

| Tier | Target | Consulted | Skipped (with reason) | Met? |
|---|---|---|---|---|
| 1 -- Vulnerability DBs & Exploits | 5 | CISA KEV (CVE-2026-56155, CVE-2026-12569 entries, via secondary citation), NVD/CVE.org (per-CVE identifiers for all six §4 CVEs, via secondary citation), CWE.mitre.org (CWE-20/95/94 chain definitions, §9), Imperva vulnerability advisory (Fastjson) | Exploit-DB (no targeted query run); direct CISA.gov fetch blocked (403), relied on secondary reporting throughout | yes |
| 2 -- Commercial Threat Intel | 4 | Zscaler ThreatLabz (TELESHIM/MIXEDKEY/BINDCLOAK), Arctic Wolf Labs (Qilin/CVE-2026-0257), Recorded Future Insikt Group / TAG-195 (Golden Chickens), Proofpoint (Cruciferra) | CrowdStrike, Mandiant, Cisco Talos, Unit 42, SentinelLabs, Secureworks, Sophos X-Ops, Trend Micro, FortiGuard, ESET -- no new within-window post found for any during this cycle's searches | yes |
| 3 -- Search Engines & Aggregators | 3 | BleepingComputer, The Hacker News, SecurityWeek, SC Media, SecurityAffairs, Help Net Security | Shodan, Censys -- no dated current-window content surfaced for either this cycle | yes -- well exceeded |
| 4 -- Bug Bounty Platforms | 2 | TechTimes/The Hacker News (GitHub bug-bounty payout cuts, 2026-07-27), HackerOne (Hai Triage context), Bugcrowd (anti-abuse policy context) | Intigriti, YesWeHack, Open Bug Bounty -- no dated within-window content found for any | yes |
| 5 -- Offensive Security Research | 2 | SSD Secure Disclosure (vBulletin runMaths PoC), FearsOff Cybersecurity (Fastjson research underlying CVE-2026-16723 disclosure) | Project Zero, SpecterOps -- no dated post found in window despite targeted search | yes |
| 6 -- Community & Independent Researchers | 3 | GBHackers, CyberPress, Dark Reading (BMC/IPMI research), Thomas Harris independent blog, KSEC community forum, latesthackingnews.com | Krebs on Security, Schneier on Security -- no new within-window threat-actor finding surfaced for either | yes -- well exceeded |
| 7 -- Dark Web Intelligence | best-effort | Dark Web Intelligence (X/@DailyDarkWeb) leak-site listing -- unconfirmed actor claims only, explicitly flagged as such | All named subscription-gated sources (Flashpoint, Intel 471, DarkOwl, Cybersixgill, ReliaQuest, ZeroFox, Searchlight Cyber) inaccessible | n/a |
| 8 -- Government & Regulatory | 3 | CISA KEV catalog, CISA ICS advisories (7 published 2026-07-28, summary-level only), CISA SB26-208 weekly vulnerability bulletin | NCSC UK, FBI IC3, NSA, ENISA, ACSC, JPCERT, CERT-In -- no live access attempted this cycle | yes |
| 9 -- Malware Analysis & Sandboxing | 3 | ANY.RUN Malware Trends Tracker (week of 2026-07-20 to -26) | MalwareBazaar, URLhaus, Hybrid Analysis, Malpedia -- no dated current-window content found for any | no -- 1 of 3 met |

**Total preferred sources consulted this cycle: ~24-26 across 7 of 9 tiers met.** Two tiers (7 -- Dark Web, 9 --
Malware Sandboxing) fell short of target, and no atomic IOC values were retrievable without a live feed
connection. **Coverage badge: PARTIAL** -- strong on vulnerability and campaign narrative for the window, weak
on dark-web corroboration and sandbox-derived indicators, and entirely dependent on secondary reporting where
primary-source fetches were blocked.
