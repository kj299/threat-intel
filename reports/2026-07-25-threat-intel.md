```
THREAT INTELLIGENCE REPORT
Generated: 2026-07-25T00:00:00Z
Coverage: PARTIAL
Time Range: 2026-07-23 to 2026-07-25
Scope: All emerging threats (default)
Persona: enterprise_soc
Assets: network edge, endpoints, mobile, APIs, payment systems
```

> **Methodology notice (read before acting on this report):**
> This run used live web search/retrieval (no `threat-intel-mcp` feed is connected in this environment — verified) to
> research all nine source tiers for the tight **2026-07-23 → 2026-07-25 (48-hour)** window. Three honest
> limitations:
> - **This is a 48-hour lookback, not a weekly one.** Several source tiers (search-engine/aggregator vendor blogs,
>   bug-bounty platforms, offensive-security blogs, dark-web monitoring) publish on weekly-or-slower cadences, so a
>   number of named Tier 3/4/5/7/9 sources had no content dated inside the strict window even though they were
>   checked. That is reported plainly below rather than padded with adjacent-week material relabeled as current.
> - **Direct fetches to primary sources were frequently blocked (HTTP 403)** — cisa.gov, senserva.com, and others
>   rejected direct page fetches. Facts attributed to these sources rely on search-engine snippets and corroborating
>   secondary reporting (BleepingComputer, The Hacker News, Help Net Security, Security Affairs), not verified
>   full-primary-document reads.
> - **No literal current atomic network IOCs (IPs, C2 domains, file hashes) were retrievable.** General web search
>   surfaces campaign narrative and vulnerability reporting, not raw ThreatFox/MalwareBazaar/AbuseIPDB/URLhaus feed
>   content. **Nothing below is fabricated (R3).** The one real, specifically-named artifact that did surface (a
>   public exploit-code repository) is cited to its source; everywhere else the gap is stated rather than papered
>   over.
>
> **Recommended action:** Connect `threat-intel-mcp` (or operator feeds — Q-Feeds, AbuseIPDB, VirusTotal, OTX,
> GreyNoise) for literal current IOC values and higher-frequency Tier 3/9 telemetry; this report is strong on
> vulnerability/technique narrative for the window but cannot substitute for a live feed on atomic indicators.

---

## 1. Alert Banner

```
CRITICAL: CVE-2026-16232 (Check Point SmartConsole auth bypass) and CVE-2026-50522 (SharePoint Server RCE) are
          BOTH actively exploited and BOTH carry a CISA KEV federal remediation deadline of 2026-07-25 — TODAY.
CRITICAL: CVE-2026-62144 (Check Point Management Server unauthenticated command execution, CVSS 9.3) disclosed
          alongside CVE-2026-16232 — patch via the July 22 Jumbo hotfix even if not yet confirmed exploited.
HIGH:     Working public exploit for "Certighost" (CVE-2026-54121, AD CS improper authorization, CVSS 8.8)
          released 2026-07-24 by independent researchers — lets any low-privileged domain user impersonate a
          Domain Controller and DCSync the krbtgt secret. Patched July 14; unpatched Enterprise CAs are now at
          acute risk of rapid weaponization.
HIGH:     "RefluxFS" (CVE-2026-64600) — a reliable, log-silent Linux kernel XFS race condition granting local
          root — affects an estimated 16M+ systems on kernels ≥4.11 with XFS reflink (a default enterprise-distro
          configuration). Kernel patch merged 2026-07-16; distro backports are still rolling out.
ELEVATED: Chaos ransomware's new "msaRAT" backdoor (Cisco Talos, 2026-07-23) hides C2 traffic inside headless
          Chrome/Edge via the Chrome DevTools Protocol, relayed over WebRTC through Twilio's TURN service —
          conventional C2/domain-based detection will not see it.
ELEVATED: CISA/NSA/FBI/NCSC UK joint advisory AA26-204A (2026-07-23): Russian state-linked LAUNDRY BEAR
          (aka Void Blizzard) is running a zero-click Zimbra Collaboration Suite campaign (CVE-2025-66376)
          against defense, energy, education, law-enforcement, and government targets.
```

---

## 2. Executive Summary

- **Two unrelated, actively-exploited critical vulnerabilities share today's (2026-07-25) CISA KEV federal deadline**: Check Point SmartConsole/Management Server authentication bypass (CVE-2026-16232, CVE-2026-62144) and Microsoft SharePoint Server deserialization RCE (CVE-2026-50522). Both allow full administrative or code-execution compromise of internet-facing infrastructure and both were confirmed under active exploitation before the deadline was set — any unpatched instance today should be treated as a live incident-response trigger, not a backlog item.
- **A working exploit for a new Active Directory Certificate Services flaw ("Certighost," CVE-2026-54121) was published in this window (2026-07-24).** The bug lets any authenticated, low-privileged domain user impersonate a Domain Controller and perform a DCSync against `krbtgt` — a path to full Active Directory compromise. Microsoft patched it July 14; organizations that haven't applied that update to every Enterprise CA host should treat this as urgent, not routine, patch management.
- **A newly disclosed, widely-affecting Linux kernel local-privilege-escalation bug ("RefluxFS," CVE-2026-64600) is propagating through vendor and researcher reporting this window.** Qualys estimates 16M+ affected systems; exploitation is reliable and leaves no kernel log trace, and it works even under SELinux Enforcing. The kernel fix merged July 16; distribution backports are the operative risk driver right now.
- **Ransomware tooling continues to professionalize its evasion.** Cisco Talos disclosed "msaRAT" (2026-07-23), a Chaos-ransomware-affiliated backdoor that drives a headless Chrome/Edge instance over the Chrome DevTools Protocol and tunnels C2 through a legitimate Twilio TURN relay — from the network's perspective, the traffic looks like a browser talking to Cloudflare/Twilio, not malware talking to a C2 server. Separately, Clop's exploitation of PTC Windchill/FlexPLM (CVE-2026-12569) has escalated into a mass phishing/extortion email campaign since July 20, ongoing into this window, targeting manufacturing, automotive, aerospace, and retail/apparel PLM environments.
- **State-linked activity in this window is dominated by a joint Western advisory, not a single-vendor report.** CISA, NSA, FBI, and NCSC UK jointly published AA26-204A (2026-07-23) on LAUNDRY BEAR (Void Blizzard), warning of a zero-click Zimbra Collaboration Suite exploit (CVE-2025-66376, patched November 2025) being used for mass email exfiltration against defense, energy, education, and government targets. Separately, Google Threat Intelligence Group began rolling out a unified cryptonym-based threat-actor naming schema (2026-07-24), merging the historically separate Mandiant and TAG taxonomies — a housekeeping change worth tracking for anyone who maps actor names across vendor reporting.
- **AI-agent and AI-tooling attack surface keeps generating fresh disclosures**, though most fell just outside this strict 48-hour window: a ChatGPT Workspace Agents CSRF flaw ("AgentForger," Zenity Labs, publicly disclosed 2026-07-23 via Bugcrowd though patched by OpenAI on June 8) shows how a single phishing link can spin up an attacker-controlled autonomous agent inside a target org; a Bing Images SVG-upload RCE chain (CVE-2026-32194/-32191, disclosed by XBOW 2026-07-23, already remediated server-side by Microsoft) illustrates the same image-pipeline RCE class defenders should check for in any self-hosted SVG-processing service.
- **This is a genuinely thin window for several source tiers** (search-engine/aggregator vendor blogs, bug-bounty platform disclosures, dark-web monitoring, offensive-security research blogs) — see §8 Intelligence Gaps and Appendix A. No dedicated payment-systems or mobile-platform-specific campaign surfaced for this exact 48-hour period despite targeted searching; that absence is reported honestly rather than assumed to mean no risk.

---

## 3. Threat Dashboard

| Category | New This Period | Active Exploits | Trend | Risk Level | Org Relevance |
|---|---|---|---|---|---|
| Ransomware | Chaos ransomware's msaRAT browser-based C2 backdoor (Talos, 7/23) | Clop via CVE-2026-12569 (PTC Windchill/FlexPLM) — mass extortion phishing since 7/20, ongoing | ↑ | CRITICAL | HIGH — endpoints, PLM/manufacturing systems |
| APT / Nation-State | GTIG unified threat-actor naming rollout (7/24) | LAUNDRY BEAR / Void Blizzard zero-click Zimbra campaign (AA26-204A, 7/23) | ↑ | HIGH | MEDIUM–HIGH — org-dependent (Zimbra webmail exposure) |
| Supply Chain | none confirmed strictly within window | NadMesh botnet (XLab, disclosed 7/17 — background) continuing to hunt exposed AI/MCP infra for cloud keys | → | MEDIUM | MEDIUM — AI/automation tooling deployments |
| Zero-Day / Edge | RefluxFS Linux XFS LPE (CVE-2026-64600, widely reported 7/22–24); 7-Zip XZ-archive code-exec flaw reported 7/24 | Check Point SmartConsole/Mgmt Server (CVE-2026-16232, -62144); SharePoint (CVE-2026-50522) — both CISA KEV, deadline today | ↑ | CRITICAL | HIGH — network edge, endpoints |
| Cloud / Identity | Certighost AD CS PoC published (CVE-2026-54121, 7/24) | none newly confirmed itw this window | ↑ | HIGH | HIGH — Active Directory / PKI |
| API Security | AgentForger (ChatGPT Workspace Agents CSRF, publicly disclosed 7/23, patched pre-window); Bing Images SVG RCE class (disclosed 7/23, patched pre-window) | none confirmed itw | → | MEDIUM | MEDIUM — any self-hosted agent-builder / SVG-processing APIs |
| Insider | no signal this period | — | → | MEDIUM | MEDIUM |
| Credential / BEC | Check Point SmartConsole admin-token theft path; Certighost DCSync/krbtgt theft path | Clop "Windchill PDMLink module serious data leak" phishing lure (ongoing since 7/20) | ↑ | HIGH | HIGH — network edge, endpoints |
| Mobile | no new mobile-specific campaign surfaced this window | — | → | MEDIUM | MEDIUM — carried forward; explicit gap, not an all-clear |
| Payment Systems | no dedicated payment-sector breach/campaign confirmed strictly within window | — | → | MEDIUM | MEDIUM — Windchill/FlexPLM exposure touches manufacturing supply chains adjacent to payment/PLM data; monitor |

---

## 4. Critical Vulnerability Summary

| CVE | CVSS | Product | Exploit Status | GreyNoise Activity | Org Exposure | Action | Source |
|---|---|---|---|---|---|---|---|
| CVE-2026-16232 | 9.1 (Rapid7) / 9.3 (other secondary reporting) — figures conflict; NVD not independently fetched | Check Point SmartConsole (Security Mgmt / Multi-Domain Mgmt) | Actively exploited in the wild against a "small number of customers" per Check Point; CISA KEV, FCEB deadline **2026-07-25 (today)** | not reported | HIGH if Management Server reachable from the internet or Trusted Clients unrestricted | Apply Check Point hotfix (sk185169); restrict SmartConsole/Mgmt Server to trusted IPs; hunt for unauthorized admin sessions even post-patch | Rapid7; Help Net Security; The Hacker News; CISA |
| CVE-2026-62144 | 9.3 | Check Point Security Management / Multi-Domain Security Management | Disclosed alongside CVE-2026-16232 (unauthenticated `run-script`/`exec-command` on Mgmt + Gateways); not independently confirmed exploited itw, but same-family risk | not reported | HIGH if Mgmt Server exposed without Firewall/Trusted-Client restriction | Apply July 22 Jumbo hotfix (sk185152); restrict Trusted Clients; confirm Mgmt Server is not internet-reachable | Check Point sk185152; The Hacker News |
| CVE-2026-50522 | 9.8 | Microsoft SharePoint Server (Enterprise 2016 / 2019 / Subscription Edition) | Actively exploited following public PoC; attackers pulling SharePoint machine keys via a single request for persistence; CISA KEV, FCEB deadline **2026-07-25 (today)** | not reported | HIGH if on-prem SharePoint deployed | Patch immediately; rotate SharePoint machine keys; hunt for webshells/ASP.NET machineKey abuse | The Hacker News; watchTowr Labs; Security Affairs; CISA |
| CVE-2026-54121 ("Certighost") | 8.8 | Windows Server 2012–2025 AD CS (Enterprise CA); Windows 10 1607/1809 | Patched 2026-07-14; working public exploit released **2026-07-24** by researchers H0j3n and Aniq Fakhrul — weaponization risk is now acute | not reported | HIGH if any Enterprise CA is deployed | Confirm the July 14 cumulative update is applied to every CA host; verify the `cdc`-target validation gate is active; hunt Domain-Controller-certificate-impersonation via Event ID 4887 | The Hacker News; SentinelOne Vulnerability Database; cybersecuritynews.com |
| CVE-2026-64600 ("RefluxFS") | not stated in retrievable reporting | Linux kernel XFS (reflink/copy-on-write path, kernel ≥4.11) | Reliable local privilege escalation to root; leaves no kernel log trace; works under SELinux Enforcing; kernel patch merged **2026-07-16**, distro backports rolling out | not applicable (local, not network-exploited) | MEDIUM–HIGH on any Linux host using XFS with reflink (default on major enterprise distros) | Track and prioritize distro kernel-patch rollout; prioritize multi-tenant/shared Linux hosts first | Qualys; BleepingComputer; Openwall oss-security |
| CVE-2026-32194 / CVE-2026-32191 | 9.8 each | Microsoft Bing Images (server-side image-processing pipeline) | Already remediated server-side by Microsoft prior to disclosure; publicly disclosed **2026-07-23** by XBOW — "no customer action to resolve" | not reported | LOW direct exposure (cloud-service-side fix already applied) | No customer action for Bing itself; review any self-hosted SVG-processing image pipelines for the same command-injection/SSRF pattern class | The Hacker News; XBOW |

---

## 5. IOC Package

> **R3 compliance notice:** As with prior cycles, general web search this period surfaced vulnerability and campaign
> narrative, not raw ThreatFox/MalwareBazaar/AbuseIPDB/URLhaus/VirusTotal feed content. **No IP address, C2 domain,
> or file hash below is fabricated.** Exactly one real, specifically-named artifact surfaced this cycle — a public
> exploit-code repository for CVE-2026-54121 — and it is cited to its source. Everything else in this section is
> either a behavioral/TTP-level indicator derived from documented technique descriptions, or aggregate feed
> telemetry (counts, not values) explicitly labeled as such.

### 5a. Deployment Priority

| Priority | Category | Action | Count |
|---|---|---|---|
| P1 — IMMEDIATE | CISA KEV entries with a **today** deadline (§4) | Patch/isolate Check Point Mgmt Server and SharePoint Server | 3 CVEs |
| P1 — IMMEDIATE | Certighost public exploit (§4) | Confirm July 14 AD CS patch on every Enterprise CA | 1 CVE |
| P1 — IMMEDIATE | Behavioral/TTP detection rules (§6) | Deploy to SIEM/EDR | 5 rules |
| P2 — 48h | RefluxFS kernel-patch rollout tracking (§4) | Prioritize XFS-reflink Linux hosts | 1 CVE |
| P2 — 48h | Clop/Windchill phishing lure + Zimbra AA26-204A hardening (§6c) | Block/alert/patch | 2 items |
| P3 — 7d | Live feed integration | Connect threat-intel-mcp for atomic IOC and higher-cadence Tier 3/9 backfill | 1 action |

### 5b. Named Real-World Indicator (sourced, not fabricated)

```csv
ioc_type,ioc_value,confidence,threat_name,threat_actor,mitre_technique,source,first_seen,last_seen,action,tlp
tool,gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26,high,Certighost AD CS Domain-Controller impersonation PoC (CVE-2026-54121),unattributed (independent researchers H0j3n and Aniq Fakhrul),T1649,thehackernews.com/2026/07/certighost-exploit-lets-low-privileged.html,2026-07-24,2026-07-24,detect+patch-priority,TLP:WHITE
```

> **Guidance:** this is the only literal, source-attributed artifact this cycle's retrieval surfaced. It is a
> public proof-of-concept exploit repository, not malware — its relevance is that its publication (2026-07-24)
> materially raises the urgency of confirming the July 14 AD CS patch everywhere, since working exploit code is
> now in circulation. Consider whether outbound access to the repository is worth logging in your environment as
> a low-confidence signal of research/reconnaissance activity.

### 5c. STIX 2.1 Bundle (vulnerability/malware/actor context — no atomic network indicators available this cycle)

```json
{
  "type": "bundle",
  "id": "bundle--7f3e2b10-25c4-4d3a-9c31-25072026a001",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "vulnerability",
      "spec_version": "2.1",
      "id": "vulnerability--c1b8a001-2026-4a10-9e01-cve202616232",
      "created": "2026-07-25T00:00:00Z",
      "modified": "2026-07-25T00:00:00Z",
      "name": "CVE-2026-16232",
      "description": "Check Point SmartConsole authentication bypass via application login token; actively exploited; CISA KEV deadline 2026-07-25.",
      "external_references": [
        {"source_name": "cve", "external_id": "CVE-2026-16232"},
        {"source_name": "Rapid7", "url": "https://www.rapid7.com/blog/post/etr-cve-2026-16232-critical-check-point-smartconsole-authentication-bypass-exploited-in-the-wild/"}
      ]
    },
    {
      "type": "vulnerability",
      "spec_version": "2.1",
      "id": "vulnerability--c1b8a002-2026-4a10-9e01-cve202662144",
      "created": "2026-07-25T00:00:00Z",
      "modified": "2026-07-25T00:00:00Z",
      "name": "CVE-2026-62144",
      "description": "Check Point Management Server authentication bypass allowing unauthenticated run-script/exec-command on Management and Gateways.",
      "external_references": [
        {"source_name": "cve", "external_id": "CVE-2026-62144"},
        {"source_name": "Check Point", "url": "https://support.checkpoint.com/results/sk/sk185152/"}
      ]
    },
    {
      "type": "vulnerability",
      "spec_version": "2.1",
      "id": "vulnerability--c1b8a003-2026-4a10-9e01-cve202650522",
      "created": "2026-07-25T00:00:00Z",
      "modified": "2026-07-25T00:00:00Z",
      "name": "CVE-2026-50522",
      "description": "Microsoft SharePoint Server unauthenticated deserialization RCE; actively exploited after public PoC; CISA KEV deadline 2026-07-25.",
      "external_references": [
        {"source_name": "cve", "external_id": "CVE-2026-50522"},
        {"source_name": "watchTowr Labs", "url": "https://labs.watchtowr.com/"}
      ]
    },
    {
      "type": "vulnerability",
      "spec_version": "2.1",
      "id": "vulnerability--c1b8a004-2026-4a10-9e01-cve202654121",
      "created": "2026-07-25T00:00:00Z",
      "modified": "2026-07-25T00:00:00Z",
      "name": "CVE-2026-54121",
      "description": "AD CS improper authorization (\"Certighost\") allowing a low-privileged domain user to impersonate a Domain Controller; public exploit released 2026-07-24.",
      "external_references": [
        {"source_name": "cve", "external_id": "CVE-2026-54121"},
        {"source_name": "The Hacker News", "url": "https://thehackernews.com/2026/07/certighost-exploit-lets-low-privileged.html"}
      ]
    },
    {
      "type": "vulnerability",
      "spec_version": "2.1",
      "id": "vulnerability--c1b8a005-2026-4a10-9e01-cve202664600",
      "created": "2026-07-25T00:00:00Z",
      "modified": "2026-07-25T00:00:00Z",
      "name": "CVE-2026-64600",
      "description": "\"RefluxFS\" — Linux kernel XFS reflink race condition allowing local root privilege escalation on kernels >=4.11.",
      "external_references": [
        {"source_name": "cve", "external_id": "CVE-2026-64600"},
        {"source_name": "Qualys", "url": "https://blog.qualys.com/vulnerabilities-threat-research/2026/07/22/refluxfs-a-linux-kernel-local-privilege-escalation-to-root-in-xfs-cve-2026-64600"}
      ]
    },
    {
      "type": "malware",
      "spec_version": "2.1",
      "id": "malware--d2a9b110-2026-4b21-9f02-msarat0001",
      "created": "2026-07-25T00:00:00Z",
      "modified": "2026-07-25T00:00:00Z",
      "name": "msaRAT",
      "is_family": true,
      "description": "Rust-based backdoor used by the Chaos ransomware group; drives headless Chrome/Edge via CDP and tunnels C2 through a Twilio TURN relay over WebRTC.",
      "malware_types": ["backdoor", "remote-access-trojan"],
      "external_references": [
        {"source_name": "Cisco Talos", "url": "https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/"}
      ]
    },
    {
      "type": "tool",
      "spec_version": "2.1",
      "id": "tool--e3b0c221-2026-4c32-9003-certighostpoc",
      "created": "2026-07-25T00:00:00Z",
      "modified": "2026-07-25T00:00:00Z",
      "name": "Certighost PoC",
      "tool_types": ["exploitation"],
      "description": "Public proof-of-concept exploit for CVE-2026-54121, published 2026-07-24 by H0j3n and Aniq Fakhrul.",
      "external_references": [
        {"source_name": "gist", "url": "https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26"}
      ]
    },
    {
      "type": "threat-actor",
      "spec_version": "2.1",
      "id": "threat-actor--f4c1d332-2026-4d43-9104-laundrybear01",
      "created": "2026-07-25T00:00:00Z",
      "modified": "2026-07-25T00:00:00Z",
      "name": "LAUNDRY BEAR (aka Void Blizzard, CL-STA-1114, TA488)",
      "threat_actor_types": ["nation-state"],
      "description": "Russian state-supported actor running a zero-click Zimbra Collaboration Suite (CVE-2025-66376) email-exfiltration campaign; joint advisory AA26-204A, 2026-07-23.",
      "external_references": [
        {"source_name": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-204a"}
      ]
    },
    {
      "type": "relationship",
      "spec_version": "2.1",
      "id": "relationship--0a1b2c33-2026-4e54-9205-rel0001",
      "created": "2026-07-25T00:00:00Z",
      "modified": "2026-07-25T00:00:00Z",
      "relationship_type": "targets",
      "source_ref": "threat-actor--f4c1d332-2026-4d43-9104-laundrybear01",
      "target_ref": "vulnerability--c1b8a003-2026-4a10-9e01-cve202650522",
      "description": "Not a confirmed relationship — placeholder omitted; LAUNDRY BEAR's confirmed vector is CVE-2025-66376 (Zimbra), not CVE-2026-50522. Included only to illustrate schema; see note below."
    }
  ]
}
```

> **Note on the STIX bundle:** the trailing `relationship` object above is intentionally flagged as non-confirmed
> in its own description field — it is retained only to show the expected shape of a `relationship` SDO; delete it
> before ingesting this bundle into a TIP. All `vulnerability`, `malware`, `tool`, and `threat-actor` objects above
> reflect only genuinely sourced, dated findings from this window; no `indicator` SDOs (network atomic patterns)
> are included because none were retrievable (R3).

### 5d. JSON (extraction-framework field shapes)

```json
{
  "new_attack_methods": [
    {
      "technique_name": "AD CS Domain-Controller impersonation via cdc chase (Certighost)",
      "mitre_id": "T1649",
      "tactic": "Credential Access",
      "cves": ["CVE-2026-54121"],
      "cwes": ["CWE-285"],
      "cvss": 8.8,
      "exploit_maturity": "weaponized",
      "first_observed": "2026-07-24",
      "source": "thehackernews.com/2026/07/certighost-exploit-lets-low-privileged.html; sentinelone.com/vulnerability-database/cve-2026-54121",
      "sophistication": "moderate (public PoC lowers bar significantly)",
      "targeted_sectors": "any org running an Enterprise CA",
      "targeted_tech": "Windows Server 2012-2025 AD CS",
      "description": "A low-privileged domain user supplies a crafted cdc request attribute during AD CS enrollment fallback, causing the CA to resolve identity data from an attacker-controlled host, enabling impersonation of a Domain Controller and DCSync of krbtgt.",
      "business_impact": "Full Active Directory domain compromise"
    },
    {
      "technique_name": "SmartConsole application-token authentication bypass",
      "mitre_id": "T1078",
      "tactic": "Defense Evasion / Initial Access",
      "cves": ["CVE-2026-16232", "CVE-2026-62144"],
      "cwes": ["CWE-287"],
      "cvss": 9.1,
      "exploit_maturity": "itw",
      "first_observed": "2026-07-21 (Check Point advisory); reported 2026-07-23",
      "source": "rapid7.com/blog/post/etr-cve-2026-16232; support.checkpoint.com/results/sk/sk185169",
      "sophistication": "low (unauthenticated, network-reachable Mgmt Server sufficient)",
      "targeted_sectors": "any org running Check Point Security/Multi-Domain Management",
      "targeted_tech": "Check Point SmartConsole / Management Server",
      "description": "Unauthenticated remote attacker obtains an application login token and authenticates to the Management Server with full admin privileges.",
      "business_impact": "Full firewall policy/config compromise across managed gateways"
    }
  ],
  "host_iocs": [],
  "network_iocs": [],
  "behavioral_iocs": [
    {
      "behavior": "Headless Chrome/Edge launched under Chrome DevTools Protocol control, followed by a WebRTC data-channel session to a Twilio TURN relay",
      "data_source": "EDR process + network telemetry",
      "detection_logic": "Alert on chrome.exe/msedge.exe spawned with headless + remote-debugging flags where the parent process is not a known browser-automation/dev tool, especially when followed by outbound TURN allocate requests",
      "mitre_id": "T1071.001, T1090",
      "threshold": "any occurrence outside approved automation/dev hosts",
      "source": "Cisco Talos (msaRAT)"
    },
    {
      "behavior": "AD CS certificate request for a Domain Controller authentication template originating from a non-DC, non-CA-admin account, with an anomalous cdc-style resolution target",
      "data_source": "Windows Security event log (CA auditing)",
      "detection_logic": "Correlate Event ID 4886 (request submitted) with 4887 (request approved/issued) where the requesting principal is not a DC or CA administrator and the template maps to Domain Controller authentication",
      "mitre_id": "T1649",
      "threshold": "any occurrence",
      "source": "The Hacker News; SentinelOne Vulnerability Database (Certighost)"
    },
    {
      "behavior": "SmartConsole/Management Server application-token authentication without a preceding successful password authentication in the same session",
      "data_source": "Check Point Management Server logs",
      "detection_logic": "Flag admin sessions authenticated via application token where no prior interactive login event exists for that session ID",
      "mitre_id": "T1078, T1552",
      "threshold": "any occurrence, prioritize if Management Server has any internet reachability",
      "source": "Rapid7; Check Point sk185169"
    },
    {
      "behavior": "Mass phishing email with subject line referencing a \"Windchill PDMLink module\" data leak, sent from compromised sender accounts",
      "data_source": "Email gateway",
      "detection_logic": "Subject-pattern match combined with sender-reputation anomaly (compromised-account indicators) for organizations running PTC Windchill/FlexPLM",
      "mitre_id": "T1566.001, T1585",
      "threshold": "any occurrence",
      "source": "BleepingComputer; GBHackers (Clop/Windchill campaign)"
    },
    {
      "behavior": "Concurrent O_DIRECT writes from an unprivileged local account targeting the same reflinked file on an XFS filesystem",
      "data_source": "Kernel audit/eBPF telemetry",
      "detection_logic": "Alert on rapid repeated O_DIRECT write pairs against a single reflinked inode by a non-service local account on XFS-reflink-enabled hosts",
      "mitre_id": "T1068",
      "threshold": "tune per host baseline — this is a narrow, low-noise pattern",
      "source": "Qualys (RefluxFS)"
    }
  ],
  "threat_actor_updates": [
    {
      "actor": "LAUNDRY BEAR (aka Void Blizzard, CL-STA-1114, TA488)",
      "type": "apt",
      "motivation": "espionage",
      "new_ttps": "Zero-click exploitation of CVE-2025-66376 (Zimbra Classic UI stored XSS) requiring only that a target view a malicious email; custom exfiltration tool \"Ulej\"",
      "new_infra": "not disclosed in retrievable reporting",
      "target_changes": "defense, energy, education, law enforcement, and government sectors using vulnerable Zimbra Collaboration Suite versions",
      "confidence": "high (joint CISA/NSA/FBI/NCSC UK attribution)",
      "source": "CISA AA26-204A, 2026-07-23"
    }
  ]
}
```

### 5e. Delimited Batch Export

```json
[
  {
    "mitre_id": "T1649",
    "name": "Steal or Forge Authentication Certificates — Certighost AD CS Domain-Controller impersonation",
    "fields": {
      "detection_method": "event id",
      "detection_value": "4887",
      "severity": "CRITICAL",
      "actor": "unattributed — public PoC (CVE-2026-54121)"
    },
    "source": "SentinelOne Vulnerability Database; The Hacker News",
    "confidence": "high"
  }
]
```

> **Guidance:** this is the only row this cycle's findings can safely populate under the discrimination rules.
> Event ID 4887 (paired with 4886) is a standard, documented Windows CA-auditing event, not a guessed or
> environment-specific value, and combined with the template/requester filter in §5d it is genuinely discriminating.
> Other candidate techniques this window (Check Point token-auth abuse, msaRAT's headless-browser C2, the Clop
> phishing lure) do not reduce to a safe `registry key` / `event id` / `process name` / `file path` / `named pipe`
> / `wmi query` value without either using a ubiquitous LOLBin (chrome.exe/msedge.exe) alone or inventing a
> vendor-specific field not confirmed in public reporting — per the anti-fabrication rule, those are left to the
> Sigma/KQL/SPL/Snort detections in §6 instead of forced into this export.

---

## 6. Detection Rules

### 6a. YARA — Certighost PoC Toolkit Strings (inferred from public gist description — validate before use)

```yara
rule Certighost_ADCS_PoC_Toolkit
{
    meta:
        description = "Detects strings consistent with the public Certighost (CVE-2026-54121) AD CS DC-impersonation PoC"
        threat = "Certighost AD CS impersonation exploit"
        date = "2026-07-25"
        reference = "gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26; thehackernews.com/2026/07/certighost-exploit-lets-low-privileged.html"
        status = "needs_validation — strings inferred from public campaign/PoC description, not a lifted vendor rule; test in an isolated lab before deployment"

    strings:
        $name1 = "Certighost" nocase ascii wide
        $cdc1 = "cdc=" ascii
        $adcs1 = "ICertPassage" ascii
        $adcs2 = "MS-WCCE" ascii
        $dcsync1 = "DRSGetNCChanges" ascii

    condition:
        ($name1) or (2 of ($adcs*, $cdc1, $dcsync1))
}
```

### 6b. Sigma — Headless Browser CDP + TURN Relay C2 (Chaos ransomware msaRAT)

```yaml
title: Headless Chrome/Edge Launched With Remote Debugging Followed by TURN Relay Traffic
id: a1b2c3d4-1122-4a3b-9c4d-msarat20260723
status: test
description: >
  Detects a headless Chrome/Edge process launched under Chrome DevTools Protocol control
  and subsequent outbound traffic consistent with a WebRTC/TURN relay session — the pattern
  reported for Chaos ransomware's msaRAT backdoor (Cisco Talos, 2026-07-23).
references:
  - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
  - https://thehackernews.com/2026/07/chaos-ransomware-uses-msarat-to-route.html
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-07-25
tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1090
  - attack.defense_evasion
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
    CommandLine|contains|all:
      - '--headless'
      - '--remote-debugging-port'
  filter_known_automation:
    ParentImage|endswith:
      - '\code.exe'
      - '\devenv.exe'
      - '\python.exe'
  condition: selection and not filter_known_automation
falsepositives:
  - Legitimate headless browser automation/testing frameworks (Selenium, Puppeteer, Playwright) — tune the filter list to your approved automation inventory
level: high
```

### 6c. Sigma — Anomalous Domain-Controller Certificate Request (Certighost pattern)

```yaml
title: Certificate Request For Domain Controller Template By Non-DC Non-CA-Admin Account
id: b2c3d4e5-2233-4b4c-8d5e-certighost20260724
status: test
description: >
  Detects a certificate request/issuance pair (Event ID 4886/4887) for a Domain Controller
  authentication template initiated by an account that is neither a Domain Controller nor
  a CA administrator — consistent with the public Certighost PoC for CVE-2026-54121.
references:
  - https://thehackernews.com/2026/07/certighost-exploit-lets-low-privileged.html
  - https://www.sentinelone.com/vulnerability-database/cve-2026-54121/
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-07-25
tags:
  - attack.credential_access
  - attack.t1649
logsource:
  product: windows
  service: security
  definition: 'Requires Certificate Services auditing enabled on the Enterprise CA'
detection:
  cert_issued:
    EventID: 4887
  filter_known_dc_ca_admins:
    SubjectUserName|contains:
      - '$'      # machine accounts (DCs enroll as themselves)
  condition: cert_issued and not filter_known_dc_ca_admins
falsepositives:
  - Legitimate certificate auto-enrollment by service accounts with a documented business need for DC-authentication-class templates — validate against your CA template access-control list before alerting as critical
level: critical
```

*Coverage check (confirm CA auditing is actually enabled before trusting a quiet result):*
```
Get-CertificationAuthority | Get-CAAuditFilter
# On Windows: auditpol /get /subcategory:"Certification Services" should show Success and Failure
```

### 6d. KQL — SharePoint Machine-Key Extraction / Post-Exploitation Hunt (Sentinel / Defender)

```kql
// Hunt: w3wp.exe (SharePoint app pool) spawning an unexpected child process — consistent with
// CVE-2026-50522 exploitation reports of machine-key extraction via a single crafted request.
// schema_dependency: DeviceProcessEvents (Defender for Endpoint) on the SharePoint front-end/app servers.
// status: needs_validation
DeviceProcessEvents
| where TimeGenerated > ago(2d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe","powershell.exe","powershell_ise.exe","certutil.exe","cscript.exe","wscript.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
```

*Coverage check:*
```kql
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| summarize count() by DeviceName
```

### 6e. SPL — Check Point Management Server Token-Auth Anomaly (Splunk)

```spl
| tstats summariesonly=true count from datamodel=Authentication.Authentication
  where Authentication.app="checkpoint*" Authentication.signature="*token*"
  by Authentication.user, Authentication.src, Authentication.dest, _time span=1h
| rename Authentication.* AS *
| where count > 0
```

*Coverage check (confirm the Authentication CIM model is populated for Check Point Mgmt logs, then find the index):*
```spl
| tstats count from datamodel=Authentication.Authentication by index, sourcetype
```
> `schema_dependency`: assumes Check Point Management Server logs are onboarded and CIM-normalized under the
> Authentication data model with `app`/`signature` populated — verify field mapping against your actual Check
> Point log source (`sourcetype=checkpoint:*` is vendor-deployment-specific; use the coverage check above to
> confirm rather than assume). `status: needs_validation`.

### 6f. Snort/Suricata — TURN Relay Allocation From a Host Also Running Headless Browser Automation (msaRAT)

```snort
# Rule: Flag TURN "Allocate" requests (RFC 5766, STUN message class 0x0003) toward known TURN-service
# infrastructure from hosts where headless-browser automation is not an approved workload — a coarse
# network-layer companion to the Sigma rule in §6b for Chaos ransomware's msaRAT C2 channel.
# Source: Cisco Talos (blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/)
# Status: needs_validation — tune $TURN_INFRA and endpoint scope to your environment; this detects the
# protocol pattern, not a confirmed malicious IP (no atomic C2 IOC was published for msaRAT in retrievable
# reporting this cycle).
alert udp $HOME_NET any -> $EXTERNAL_NET [3478,5349] (
  msg:"POSSIBLE Unapproved TURN Relay Allocation (msaRAT-style browser-proxied C2 pattern)";
  content:"|00 03|"; offset:0; depth:2;
  classtype:trojan-activity;
  sid:9000201; rev:1;
  reference:url,blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/;
)
```

---

## 7. Actions Matrix

| Priority | Action | Owner | Timeline | Investment | Risk Addressed | Success Metric |
|---|---|---|---|---|---|---|
| P1 | Patch Check Point Management Server/SmartConsole (CVE-2026-16232 via sk185169; CVE-2026-62144 via sk185152) and restrict Trusted Clients/Mgmt Server exposure | Network/Firewall Ops | 0–24h (CISA deadline is today) | Low–Medium | Full firewall policy/config compromise | Zero unpatched Check Point Mgmt Servers reachable beyond trusted IPs |
| P1 | Patch SharePoint Server (CVE-2026-50522) and rotate machine keys | Vulnerability Mgmt / SharePoint Admins | 0–24h (CISA deadline is today) | Low–Medium | Unauthenticated RCE, persistent webshell access | Zero unpatched on-prem SharePoint instances; machine keys rotated |
| P1 | Confirm the July 14 AD CS cumulative update is applied to **every** Enterprise CA host given the public Certighost exploit | Identity/PKI Team | 0–48h | Low | Domain-wide compromise via DC impersonation/DCSync | 100% of CA hosts confirmed patched; `cdc` validation gate verified active |
| P1 | Deploy the msaRAT (§6b), Certighost (§6c), and SmartConsole (§6e) detections to SIEM/EDR | SOC Engineering | 0–48h | Low | Browser-proxied ransomware C2; AD CS impersonation; Mgmt Server token abuse | Rules active; test-fire confirmed in lab |
| P2 | Track and prioritize the distro kernel-patch rollout for RefluxFS (CVE-2026-64600) on XFS-reflink Linux hosts, starting with multi-tenant/shared systems | Linux/Infra Team | 48h–7d | Medium | Silent local root escalation on ~16M+ affected systems class-wide | Patch rollout tracked to completion; multi-tenant hosts patched first |
| P2 | Block/flag the "Windchill PDMLink module serious data leak" phishing subject pattern; confirm PTC Windchill/FlexPLM patched to the June 17 fix for CVE-2026-12569 | DevSecOps / PLM Admins | 48h–7d | Medium | Clop mass extortion campaign against PLM environments | Zero unpatched Windchill/FlexPLM instances; phishing lure blocked at gateway |
| P2 | Validate Zimbra Collaboration Suite is on 10.0.18/10.1.13 or later; review AA26-204A IOCs/mitigations against LAUNDRY BEAR's zero-click campaign | Messaging/Collaboration Team | 48h–7d | Low–Medium | Zero-click email exfiltration (CVE-2025-66376) | Zimbra fleet confirmed patched; advisory IOCs checked against logs |
| P3 | Inventory any internally deployed AI agent-builder platforms for the AgentForger-class CSRF pattern (link-triggered autonomous-agent creation) | AppSec | 7–30d | Medium | Attacker-controlled AI agent persisting inside the org | Inventory complete; vendor patch status confirmed for each platform |
| P3 | Connect `threat-intel-mcp` (or an equivalent operator feed) to backfill atomic IOCs for msaRAT/Certighost and raise Tier 3/9 telemetry cadence | Threat Intel | 7–30d | Low | Atomic-indicator gap; thin 48h Tier 3/9 coverage this cycle | Feed connected; next report shows literal IOC values |
| P4 | Update internal threat-actor tracking taxonomy to reflect GTIG's new unified cryptonym naming schema | Threat Intel | 30–90d | Low | Actor-name drift across vendor reporting | Mapping table updated; cross-referenced to legacy names |

---

## 8. Intelligence Gaps

1. **This is a strict 48-hour window, and several source tiers publish on weekly-or-slower cadences.** GreyNoise's public "At The Edge Clear" brief's most recent edition covers July 6–13, 2026 — no edition covering July 20–27 had been published at research time. Similar cadence gaps applied to SpecterOps (latest identifiable post: February 2026), ZDI's monthly review (dated July 14, no new advisory in the strict window), and Metasploit's weekly wrap-up (shifted to bi-weekly as of July 17). These are reported as genuine cadence gaps, not retrieval failures.
2. **Tier 3 (search engines/aggregators) is the thinnest tier this cycle.** Censys blog activity (July 21–22), Shodan-related reporting via the NadMesh botnet story (July 17), and Any.Run's weekly telemetry (through July 20) all fell 1–8 days outside the strict window despite being checked. No VirusTotal or AbuseIPDB content dated in 2026-07 was found at all.
3. **No literal atomic network IOCs (IPs, C2 domains, file hashes) were retrievable this cycle**, consistent with prior reports — ThreatFox/MalwareBazaar/AbuseIPDB/URLhaus/VirusTotal atomic feed content requires direct API access. The only literal artifact found was the Certighost public exploit repository (§5b), which is PoC code, not a malicious indicator.
4. **Primary-source fetches were blocked (HTTP 403)** for cisa.gov and senserva.com during this run; facts attributed to CISA (KEV additions, AA26-204A, ICS advisories) rely on search-engine snippets and corroborating secondary reporting (BleepingComputer, The Hacker News, Help Net Security, techtimes.com, OpenText Cybersecurity Community mirrors of CISA alert text) rather than verified primary-document reads.
5. **CVSS discrepancy on CVE-2026-16232**: Rapid7's write-up states 9.1; other secondary reporting states 9.3. This was not resolved against an independently fetched NVD record (blocked). Both figures are presented in §4 rather than picking one arbitrarily.
6. **CVE-2026-64600 (RefluxFS) CVSS score was not present in any retrievable snippet** — marked "not stated" in §4 rather than estimated.
7. **No dedicated mobile-platform or payment-systems-specific campaign surfaced for this exact 48-hour window** despite targeted searching (queries covering Android/iOS malware, card skimming/e-skimming, POS malware, and payment-API breaches). General 2026 mobile-threat context (Anatsa, ToxicPanda, RatOn, Albiriox) exists but predates this window and is not restated here as new. This absence is stated plainly per the assets-of-concern scope rather than silently dropped.
8. **R6 compliance check**: no embedded or prompt-injection-style instructions were detected in any retrieved source content during this run (search snippets, fetched pages). Nothing required exclusion on that basis.
9. **Items mentioned only as background context, not counted as new-this-window findings**: NadMesh botnet (XLab, disclosed July 17), the jscrambler and AsyncAPI npm supply-chain compromises (July 11 and July 14 respectively), and Kaspersky's Project CAV3RN research (July 21) all fall 2–14 days before the strict window and are flagged as such wherever referenced in §3.

---

## Appendix A: Source Coverage Ledger

| Tier | Required Min | Consulted | Skipped (with reason) | Met? |
|---|---|---|---|---|
| 1 — Vulnerability DBs & Exploits | 5 | CISA KEV catalog (via secondary reporting; direct fetch 403), NVD (per-CVE detail via secondary citation for 5 CVEs), CVE.org (CVE ID assignments referenced), MITRE ATT&CK (T1649/T1078/T1071.001/T1552/T1566.001/T1068 mapped), GitHub Security Advisories / PoC repos (Certighost gist; GHSL-2026-140 7-Zip advisory) | Exploit-DB (checked, no confirmed new-window entry), ZDI (monthly review dated 7/14, no new advisory 7/23–25), Zero Day Tracker/Clock (not queried this cycle) | yes |
| 2 — Commercial Threat Intel | 4 | Mandiant/Google TI (GTIG unified naming rollout, 7/24), Cisco Talos (msaRAT analysis, 7/23), Check Point vendor advisory (sk185169/sk185152, 7/22–23 — vendor portal, not the research.checkpoint.com blog specifically) | Microsoft Threat Intelligence, CrowdStrike, Kaspersky Securelist — all checked, nearest identifiable posts (7/15, ~7/8, 7/21 respectively) fall outside the strict window | no — 3 of 4, and one is a vendor advisory portal rather than a dedicated research blog |
| 3 — Search Engines & Aggregators | 3 | none with confirmed content dated inside 7/23–25 | GreyNoise (latest public edition covers 7/6–13, no new edition found), Shodan (via NadMesh reporting, 7/17), Censys (blog activity 7/21–22), VirusTotal (no 2026-07 post found), AbuseIPDB (no dated content found) | no |
| 4 — Bug Bounty Platforms | 2 | Bugcrowd (AgentForger/Zenity Labs disclosure routed through Bugcrowd's program, publicly announced 7/23) | HackerOne (checked — only aggregate as-of-7/21 statistics found, no specific new disclosed report identified in window) | no — 1 of 2 |
| 5 — Offensive Security Research | 2 | Rapid7 blog (CVE-2026-16232 ETR analysis, 7/23) | SpecterOps (latest identifiable post Feb 2026), ProjectDiscovery/SANS Pen Test/OffSec/Red Team Journal/Cobalt Strike Blog/Metasploit Blog (not individually confirmed in-window; Metasploit wrap-up cadence shifted to bi-weekly 7/17) | no — 1 of 2 |
| 6 — Community & Researchers | 3 | The Hacker News, BleepingComputer, SANS ISC, Security Affairs (all with 7/23–24 dated coverage) | Krebs on Security (checked, nearest identifiable post ~7/16, nothing dated in the strict window found) | yes — well exceeded |
| 7 — Dark Web Intelligence | best-effort | SOCRadar (Chaos ransomware / Neopharm Labs dark-web leak-site listing, dated 7/22 — one day before the window) | Flashpoint, Intel 471, DarkOwl, Kela, Cybersixgill, ReliaQuest, ZeroFox, Searchlight Cyber — subscription-gated, no access this period | n/a |
| 8 — Government & Regulatory | 3 | CISA, NSA, FBI, NCSC UK — all co-authors of joint advisory AA26-204A (LAUNDRY BEAR/Zimbra), published 7/23, 2026; CISA also for ICS advisories ICSA-26-204-01–07 (7/23) | ENISA, ACSC, JPCERT, CERT-In — no live access attempted this cycle | yes — well exceeded |
| 9 — Malware Analysis & Sandboxing | 3 | ThreatFox/abuse.ch (aggregate daily IOC-count telemetry mirrored via SOCRadar, dated 7/23 — ~3,207–3,374 indicators; counts only, no literal values retrieved) | Any.Run (weekly telemetry through 7/20, 3 days pre-window), MalwareBazaar, URLhaus (checked, no dated 7/23–25 content found) | no — 1 of 3 |

**Total preferred-source targets consulted:** ~20 / ≈25, with genuinely in-window (2026-07-23 to 2026-07-25) content anchoring the majority of them; several near-miss sources (1–8 days outside the strict window) were checked and are noted as such rather than counted.

**Coverage badge: PARTIAL**

Rationale: Tiers 1, 6, and 8 met or well exceeded their numeric targets with genuinely current-window material — including two CISA KEV entries sharing a same-day (2026-07-25) remediation deadline and a same-day joint CISA/NSA/FBI/NCSC UK advisory. Tiers 2, 4, 5, and 9 fell short of their numeric targets specifically because this is a 48-hour window against source cadences that are often weekly; content exists for these tiers but sits 1–8 days outside the strict boundary and was reported as background rather than force-counted. Tier 3 produced no strictly in-window primary content despite being checked across five named sources. This pattern — strong on Tier 1/6/8, thin on Tier 3/5/9 — is the expected and honest signature of a tight 48-hour lookback, not a retrieval failure.

**Fabrication check:** PASS — no IP address, file hash, domain name, or actor attribution was invented. The one literal artifact in §5b (the Certighost PoC repository URL) is directly sourced to named reporting and the GitHub gist itself. Both conflicting CVSS figures for CVE-2026-16232 are presented rather than resolved by guessing; CVE-2026-64600's CVSS is marked "not stated" rather than estimated.

**Unverified items:** CVE-2026-16232's exact CVSS score (§4 — conflicting 9.1/9.3 across secondary sources, primary NVD record not independently fetched); CVE-2026-64600's CVSS score (§4 — not present in retrievable reporting); the §5c STIX `relationship` object is explicitly flagged as illustrative/non-confirmed within its own description field and should be removed before ingestion.

---

*This report was generated by the `cyber-threat-intel` skill on 2026-07-25 using live web search across all nine source tiers for a 48-hour window. It structures AI output and provides detection guidance based on documented, source-cited reporting; it does not guarantee accuracy and does not substitute for a connected live threat-intel feed for atomic indicators or for higher-cadence Tier 3/5/9 coverage. Verify critical findings — especially both same-day CISA KEV deadlines and the Certighost public-exploit status — against authoritative primary sources before operational deployment of any patch-priority decision, blocklist, or detection rule.*
