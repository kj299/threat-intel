```
THREAT INTELLIGENCE REPORT
Generated: 2026-07-31T00:00:00Z
Coverage: PARTIAL
Time Range: 2026-07-29 to 2026-07-31
Scope: All emerging threats (default)
Persona: enterprise_soc
Assets: network edge, endpoints, mobile, APIs, payment systems
```

> **Methodology notice (read before acting on this report):**
> This run used live web search/retrieval (no `threat-intel-mcp` server was connected in this session) to
> research the nine source tiers for a **strict 48-hour window, 2026-07-29 to 2026-07-31**. This cycle updates
> and carries forward several still-open items from [`2026-07-30-threat-intel.md`](2026-07-30-threat-intel.md)
> (Cisco FMC, the Minnesota water-utility attack, ShinyHunters, vBulletin) rather than re-deriving them from
> scratch — where a fact is unchanged since yesterday's report, this report says so explicitly rather than
> re-citing it as new. Three honest limitations apply:
> - **Direct API/page fetches to primary sources were blocked (HTTP 403)** for `cisa.gov` (raw KEV JSON and the
>   advisory HTML), `services.nvd.nist.gov`, and `threatfox.abuse.ch` — consistent with the network-egress
>   restriction this runbook flagged as verified-blocked on 2026-07-24. CVE facts below rely on multiple
>   corroborating secondary outlets, not a verified primary-document read.
> - **No literal current network IOC values (hashes/IPs/C2 domains) were retrievable.** Atomic-indicator feeds
>   (ThreatFox, MalwareBazaar, AbuseIPDB, VirusTotal, GreyNoise per-CVE tagging) require direct API access, not
>   general web search — none is fabricated below (R3).
> - **A strict 48-hour window under-serves several tiers** (Bug Bounty, and parts of Malware Sandboxing) that
>   had no dated in-window content at retrieval time — stated plainly per-tier in Appendix A.
>
> **Recommended action:** Connect `threat-intel-mcp` (or operator feeds — Q-Feeds, AbuseIPDB, VirusTotal, OTX,
> Recorded Future, GreyNoise) for literal current IOC values and CVE-specific scanning telemetry; this report
> remains strongest on the in-window vulnerability/campaign narrative and weakest on atomic indicators.

---

## 1. Alert Banner

```
CRITICAL: VMware vCenter Server authentication bypass, CVE-2026-59309 / CVE-2026-59310, CVSS 9.8. Broadcom
          published VMSA-2026-0006 (2026-07-29): an unauthenticated attacker with network access to vCenter
          can bypass authentication entirely and gain full administrative control of the managed VM/datastore
          estate. No vendor workaround exists -- patching is the only mitigation. No exploitation or public PoC
          observed yet (Rapid7, as of 2026-07-30).
HIGH:     ShinyHunters set a same-day extortion deadline against Ernst & Young (EY): stolen data claimed
          2026-07-27 on the group's leak site, with "come talk to us" and a threatened leak/disruption if EY
          does not respond by end of day 2026-07-31 (today). This sits inside the same active ShinyHunters
          vishing-driven SSO-takeover campaign flagged in yesterday's report (Health-ISAC, 2026-07-29).
HIGH:     CVE-2026-20316 -- Cisco Secure Firewall Management Center static hard-coded credential (carried
          forward from 2026-07-30; unchanged CVSS 5.3, still actively exploited, CISA KEV federal remediation
          deadline is now TOMORROW, 2026-08-01). New this cycle: a criminal-forum listing (reported by Cyberoo
          I-SOC) offers what it claims is a pre-auth root-RCE chain for the same product for $500,000 --
          **this capability claim is unverified and is a seller's own marketing, not a confirmed exploit.**
ELEVATED: The Minnesota water-utility coordinated OT attack (30+ systems, Braham plant offline, weekend of
          2026-07-26/27) remains under active investigation. CyberAv3ngers attribution is now echoed by a
          second source (Tenable, in addition to The Register) but is **still not confirmed** by CISA, FBI, or
          a formal government attribution statement -- unchanged assessment from yesterday's report, now with
          slightly broader (still unofficial) corroboration.
ELEVATED: Amazon formally attributed the debug/chalk/axios/typo-crypto npm supply-chain compromises to a
          single DPRK-linked actor, Sapphire Sleet (aka BlueNoroff / Stardust Chollima), on 2026-07-29 --
          the first consolidation of this year-plus campaign under one named threat actor.
```

*Carried forward, no material change since 2026-07-30:* CVE-2026-16812 (Arista VeloCloud Orchestrator, CVSS 10.0)
-- the federal KEV deadline (2026-07-30) has now **passed**; verify patch compliance today rather than treating
it as pending. CVE-2026-61511 (vBulletin pre-auth RCE PoC) -- still no confirmed active exploitation as of the
latest retrievable reporting (2026-07-27/28).

---

## 2. Executive Summary

- **A second no-workaround critical vulnerability landed in the network/virtualization-infrastructure space this
  period.** CVE-2026-59309/59310 (VMware vCenter, CVSS 9.8) joins CVE-2026-16812 (Arista, CVSS 10.0, patched
  yesterday) and CVE-2026-20316 (Cisco FMC, KEV deadline tomorrow) as the third piece of core network/
  virtualization management infrastructure to receive a critical, actively-tracked advisory in four days. No
  exploitation confirmed yet for the VMware flaw -- patch before that changes.
- **ShinyHunters' extortion campaign has a same-day deadline.** The group's claimed Ernst & Young breach carries
  an end-of-day 2026-07-31 ultimatum, inside the same vishing/SSO-takeover campaign Health-ISAC warned healthcare
  organizations about on 2026-07-29. Any organization with a human-staffed identity help desk remains exposed to
  this technique regardless of sector.
- **The Cisco FMC zero-day now has a criminal-market angle.** A dark-web forum listing claims a $500,000 pre-auth
  root-RCE chain for the same product already in CISA KEV -- unverified, but it raises the stakes on the
  2026-08-01 federal deadline regardless of whether the claim itself is real.
- **DPRK's npm supply-chain campaign was formally consolidated under one actor.** Amazon's 2026-07-29 research
  ties Sapphire Sleet (BlueNoroff/Stardust Chollima) to the debug, chalk, axios, and typo-crypto compromises --
  relevant to any organization consuming npm packages in CI/CD, not just direct victims.
- **Minnesota water-utility attribution is still unconfirmed, now with broader informal consensus.** Tenable's
  independent assessment echoes The Register's CyberAv3ngers suspicion, but neither CISA nor a formal government
  statement has confirmed it as of this report -- treat as a working hypothesis, unchanged from yesterday.
- **Two of the last three days' KEV deadlines have now passed or are imminent.** Arista's federal deadline
  (2026-07-30) has passed -- confirm compliance today; Cisco FMC's (2026-08-01) is tomorrow.
- **Coverage remains honestly partial.** A strict 48-hour window continues to under-serve Bug Bounty and parts
  of Malware Sandboxing; see Appendix A for the per-tier accounting.

---

## 3. Threat Dashboard

| Category | New This Period | Active Exploits | Trend | Risk Level | Org Relevance |
|---|---|---|---|---|---|
| Virtualization / Hypervisor Mgmt | CVE-2026-59309/59310 (VMware vCenter auth bypass, no workaround) | none observed yet | ↑ (new critical disclosure) | CRITICAL | HIGH if vCenter deployed -- not an explicitly listed asset but core infrastructure |
| Zero-Day / Network Edge | CVE-2026-20316 (Cisco FMC) unchanged; new dark-web exploit-broker listing | actively exploited (KEV); dark-web claim unverified | ↑ | HIGH | HIGH -- network edge is an explicit in-scope asset |
| Cloud / Identity | ShinyHunters/EY extortion deadline today; ongoing vishing-driven SSO takeover | Okta/Entra/Google help-desk MFA-reset abuse | ↑ | HIGH | HIGH -- any org with a human-staffed identity help desk |
| Software Supply Chain | Sapphire Sleet formally attributed across debug/chalk/axios/typo-crypto npm campaign | historic, ongoing campaign; no new compromise this cycle | → (attribution, not new activity) | MEDIUM | Direct -- APIs/build-pipeline dependency |
| ICS / OT | none new; Minnesota investigation still active, attribution still unconfirmed (broader informal consensus) | suspected CyberAv3ngers (unconfirmed) | → | CRITICAL (carried forward) | HIGH if water/wastewater or similar OT footprint |
| Zero-Day / SD-WAN | CVE-2026-16812 (Arista) -- federal deadline passed 2026-07-30 | actively exploited; patch available | → (post-deadline) | HIGH (carried forward) | HIGH if on-prem VCO deployed |
| Exploit / PoC | none new; CVE-2026-61511 (vBulletin) still PoC-only | no confirmed active exploitation | → | ELEVATED (carried forward) | MEDIUM if vBulletin exposed |
| Edge-device scanning | GreyNoise weekly telemetry (through 2026-07-27): sustained credential-harvesting/RDP-brute-force fleets; scanning spikes vs. FortiOS, Cisco SSL VPN, Ivanti EPMM, NETGEAR | mass scanning, not a named CVE yet | ↑ | MEDIUM | Direct -- network edge; historically precedes new disclosures |
| Commodity Malware | 0 novel families; 1 newer loader chain (TinyEgg → ChonkyChicken via ClickFix/OCX) | Vidar, AsyncRAT, XWorm remain top sandbox detonations | → | MEDIUM | Direct -- endpoints |
| Ransomware | 0 new named incident in-window | N/A | → | MEDIUM | Direct |

---

## 4. Critical Vulnerability Summary

| CVE | CVSS | Product | Exploit Status | GreyNoise / Scanning Activity | Org Exposure | Action | Source |
|---|---|---|---|---|---|---|---|
| CVE-2026-59309 | 9.8 (Critical) | VMware vCenter Server (VMware Directory Service auth bypass) | No known exploitation or public PoC as of 2026-07-30 (Rapid7) | Not queried live (no CVE-specific tag confirmed) | HIGH if vCenter deployed; no workaround exists | Patch to vCenter 9.1.0.0300+ immediately; restrict management-plane network reachability until patched | [Broadcom VMSA-2026-0006](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38017); [Rapid7 ETR](https://www.rapid7.com/blog/post/etr-critical-vmware-vcenter-vulnerabilities-allow-authentication-bypass-and-remote-code-execution-cve-2026-59309-cve-2026-59310/); [CVE.org](https://www.cve.org/CVERecord?id=CVE-2026-59309) |
| CVE-2026-59310 | 9.8 (Critical) | VMware vCenter Server (companion RCE/escalation flaw in same advisory) | Same as above | Not queried live | Same as above | Same patch as above | Same as above |
| CVE-2026-20316 | 5.3 (Medium score; high-impact pre-auth access) | Cisco Secure Firewall Management Center (static hard-coded credential) | Actively exploited (CISA KEV, added 2026-07-29); unverified dark-web listing claims a chained pre-auth root RCE ($500K ask) | Not queried live | HIGH if Secure FMC deployed (versions before 7.0.9.1/7.2.11.1/7.4.7.1/7.6.5.1/7.7.12.1/10.0.1.1) | Patch by federal deadline **2026-08-01 (tomorrow)**; restrict web-UI access to a management network in the interim | [CISA KEV addition, 2026-07-29](https://www.cisa.gov/news-events/alerts/2026/07/29/cisa-adds-one-known-exploited-vulnerability-catalog); [The Hacker News](https://thehackernews.com/2026/07/cisco-fmc-zero-day-actively-exploited.html); [Cyberoo (dark-web listing, unverified)](https://cert.cyberoo.com/en/possible-cisco-fmc-0-day-for-sale-on-the-dark-web/) |
| CVE-2026-16812 | 10.0 (Critical) | Arista VeloCloud Orchestrator (on-prem, OS command injection) | Actively exploited as zero-day; patched by Arista; **federal KEV deadline 2026-07-30 has passed** | Not queried live | HIGH if on-prem VCO not yet patched | Confirm patch to 5.2.3.14/6.1.3.4/6.4.2.4/7.0.0.1 today if not already done -- treat any unpatched instance as overdue, not merely late | Carried forward from 2026-07-30 report; [The Hacker News](https://thehackernews.com/2026/07/attackers-exploit-arista-velocloud.html); [BleepingComputer](https://www.bleepingcomputer.com/news/security/arista-patches-velocloud-orchestrator-zero-day-exploited-in-attacks/) |
| CVE-2026-61511 | 9.8 (NVD 3.1) | vBulletin (pre-auth RCE, template-math sanitization bypass) | Public PoC since 2026-07-27; **no confirmed active exploitation** as of latest retrievable reporting | Not queried live | MEDIUM if internet-facing vBulletin below 6.2.2 | Confirm upgrade to 6.2.2 (released 2026-07-01) | Carried forward from 2026-07-30 report |

---

## 5. Business Line Risk Spotlight

*No new business context was provided (default: none). This section is omitted. Provide business context on the
next invocation -- e.g., a vCenter-managed virtualization estate, water/wastewater or other OT footprint, an
Okta/Entra/Google-Workspace-backed identity help desk, or npm-dependent CI/CD pipelines -- to receive tailored
risk scenarios against this period's findings.*

---

## 6. IOC Package

> **R3 compliance notice:** No literal current network IOCs (IPs, C2 domains, file hashes) were retrievable this
> period -- see the Methodology notice above. Everything below is a CVE/version-level identifier, a named-entity
> attribution, or a behavioral/TTP-level indicator derived from documented technique descriptions; none is a
> fabricated atomic indicator.

### 6a. Deployment Priority

| Priority | Category | Action | Count |
|---|---|---|---|
| P1 -- IMMEDIATE | CVE-2026-59309/59310 (VMware vCenter, no workaround) | Patch immediately | 2 CVEs |
| P1 -- IMMEDIATE | CVE-2026-20316 (Cisco FMC, KEV deadline tomorrow) | Patch/mitigate | 1 CVE |
| P1 -- IMMEDIATE | CVE-2026-16812 (Arista, deadline passed) | Confirm patch compliance today | 1 CVE |
| P1 -- IMMEDIATE | Behavioral/detection rules (Section 7) | Deploy to SIEM/EDR | 3 new rules |
| P2 -- 48h | Sapphire Sleet npm dependency audit (debug/chalk/axios/typo-crypto version ranges) | Scan CI/CD and developer environments | 1 action |
| P2 -- 48h | ShinyHunters help-desk vishing hunt (Section 7, carried forward from 2026-07-30) | Review identity-provider audit logs, extend to today's EY deadline window | 1 hunt |
| P3 -- 7d | Live feed integration | Connect `threat-intel-mcp` for atomic IOC backfill | 1 action |

### 6b. Confirmed identifiers and attributions

| Type | Value | Confidence | First Seen (this cycle) | Action | Source |
|---|---|---|---|---|---|
| cve_id | CVE-2026-59309 | confirmed | 2026-07-29 | patch | Broadcom VMSA-2026-0006 |
| cve_id | CVE-2026-59310 | confirmed | 2026-07-29 | patch | Broadcom VMSA-2026-0006 |
| affected_version | VMware vCenter < 9.1.0.0300 | confirmed | 2026-07-29 | upgrade | Broadcom VMSA-2026-0006 |
| threat_actor | Sapphire Sleet (aka BlueNoroff, Stardust Chollima) | confirmed (attribution) | 2026-07-29 | monitor supply chain / audit dependencies | Amazon Security Blog |
| unverified_claim | Pre-auth root RCE chain for Cisco FMC offered for $500,000 on a criminal forum | unverified -- seller's own claim, single secondary reporter | 2026-07-30 | monitor, do not act on capability claim as fact | Cyberoo I-SOC |

### 6c. Behavioral IOCs (carried-forward TTPs from 2026-07-30 remain valid and are not re-listed here -- see that
report's Section 6b for the TELESHIM DLL side-load, Telegram-C2, ShinyHunters MFA-reset, and Arista admin-API
detection logic, all still current)

| Behavior | Data Source | Detection Logic | MITRE ID (analyst-assessed) | Threshold | Source |
|---|---|---|---|---|---|
| vCenter privileged administrative action (VM create/delete, permission grant, datastore change) with no preceding successful interactive SSO login for the acting principal | vCenter audit event log | Correlate admin-action events against login events within a 15-minute window; flag actions with no matching login | T1190 (Exploit Public-Facing Application) | any occurrence outside known service-account/API-token automation | Broadcom VMSA-2026-0006 (technique inferred from the auth-bypass mechanism, not vendor-published detection guidance) |
| Outbound network connection initiated during `npm install` (`preinstall`/`postinstall` script execution) to a destination outside the organization's known package-registry allowlist | EDR process-attributed network telemetry | Alert on `node`/`npm` process-initiated connections at install time to non-allowlisted destinations | T1195.002 (Compromise Software Supply Chain) | any occurrence to a non-allowlisted destination | Amazon Security Blog (Sapphire Sleet npm campaign technique pattern) |
| `regsvr32` invocation with a remote `/i:` flag and `scrobj.dll`, consistent with the ClickFix-lure OCX loader chain (TinyEgg → ChonkyChicken) | EDR command-line telemetry | Alert on `regsvr32` command lines containing both a remote `/i:` URL and `scrobj.dll` | T1218.010 (System Binary Proxy Execution: Regsvr32) | any occurrence -- validate against your environment's legitimate `regsvr32` usage first | ANY.RUN cybersecurity blog (secondary reference, July 2026; no confirmed sample hash) |

---

## 7. Detection Rules

### 7a. Sigma -- VMware vCenter Admin Action With No Prior Successful Login (Possible CVE-2026-59309/59310 Exploitation)

```yaml
title: VMware vCenter Admin Action With No Prior Successful Login
id: b3c4d5e6-f708-4901-a1b2-c3d4e5f67890
status: test
description: >
  Hunts for vCenter administrative actions (VM create/delete, permission grant, datastore modification) not
  preceded by a corresponding successful SSO login for the acting principal within the correlation window --
  consistent with an authentication-bypass exploitation pattern (CVE-2026-59309/59310, Broadcom VMSA-2026-0006,
  2026-07-29).
references:
  - https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38017
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-07-31
tags:
  - attack.initial_access
  - attack.privilege_escalation
  - attack.t1190
logsource:
  category: application
  product: vmware
  service: vcenter_audit
detection:
  admin_action:
    EventType:
      - VmCreatedEvent
      - VmRemovedEvent
      - PermissionAddedEvent
      - DatastoreRenamedEvent
  prior_login:
    EventType: UserLoginSessionEvent
  timeframe: 15m
  condition: admin_action and not prior_login
falsepositives:
  - Scheduled automation/service accounts using API tokens rather than interactive SSO login -- baseline before enabling in production
level: high
status_note: needs_validation -- test in a lab vCenter instance (API-token action vs. interactive login) before production deployment
```

### 7b. Sigma -- npm Install-Time Outbound Connection to Non-Allowlisted Destination

```yaml
title: Node/npm Install-Time Network Connection Outside Registry Allowlist
id: c4d5e6f7-0819-4a12-b2c3-d4e5f6789012
status: test
description: >
  Detects outbound network connections initiated by node/npm processes during package installation to
  destinations outside the organization's known package-registry allowlist -- the general TTP behind the
  Sapphire Sleet npm supply-chain campaign (debug/chalk/axios/typo-crypto), formally attributed by Amazon on
  2026-07-29.
references:
  - https://aws.amazon.com/blogs/security/amazon-identifies-north-korean-hacker-group-behind-open-source-supply-chain-attacks/
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-07-31
tags:
  - attack.initial_access
  - attack.t1195.002
logsource:
  category: network_connection
  product: null
detection:
  selection:
    Image|endswith:
      - '\node.exe'
      - '\npm.cmd'
  filter_allowlist:
    DestinationHostname|endswith:
      - 'registry.npmjs.org'
      - 'npm.pkg.github.com'
      # extend with any internal/private registry mirrors your org uses
  condition: selection and not filter_allowlist
falsepositives:
  - Legitimate use of alternate private registries/mirrors not yet in the allowlist -- extend filter_allowlist rather than disabling the rule
level: medium
status_note: needs_validation -- requires EDR sensors capable of process-attributed network telemetry; pure firewall logs typically lack this
```

### 7c. YARA -- ClickFix-to-OCX Loader Chain (behavioral, pattern-based)

```yara
rule Suspicious_ClickFix_OCX_Regsvr32_Chain
{
    meta:
        description = "Flags regsvr32 command-line patterns consistent with ClickFix-lure OCX-payload loader chains reported by ANY.RUN (TinyEgg/ChonkyChicken family, July 2026)"
        status = "needs_validation -- pattern-based, not hash-based; no confirmed sample hash retrieved this cycle"
        source = "ANY.RUN cybersecurity blog (secondary reference, July 2026)"
        date = "2026-07-31"
    strings:
        $cmdline1 = "regsvr32" nocase
        $cmdline2 = "/i:http" nocase
        $cmdline3 = "scrobj.dll" nocase
    condition:
        2 of ($cmdline*)
}
```

### 7d. Hunting Queries -- SPL / KQL (normalized starters per `siem-queries.md`)

**Objective:** Confirm vCenter audit-log coverage, then run the admin-action-without-login hunt for CVE-2026-59309/59310.

```spl
`` schema_dependency: vCenter audit events forwarded to Splunk (no standard CIM data model covers vCenter
`` audit events directly -- this uses a raw search against the forwarding sourcetype).
`` <PLACEHOLDER> = your environment's actual vCenter-forwarding index/sourcetype, confirmed via the
`` coverage-check query below.
`` status: needs_validation

index=<PLACEHOLDER: vcenter_index> sourcetype=<PLACEHOLDER: vcenter_sourcetype>
  EventType IN ("VmCreatedEvent","VmRemovedEvent","PermissionAddedEvent","DatastoreRenamedEvent")
| stats earliest(_time) as action_time by UserName, EventType
| join type=left UserName [
    search index=<PLACEHOLDER: vcenter_index> sourcetype=<PLACEHOLDER: vcenter_sourcetype> EventType="UserLoginSessionEvent"
    | stats latest(_time) as login_time by UserName ]
| where isnull(login_time) OR (action_time - login_time) > 900
| table _time, UserName, EventType, action_time, login_time
```

*Coverage check (Splunk -- confirm vCenter events are being forwarded at all):*
```spl
| tstats count where index=* sourcetype=*vcenter* by index, sourcetype
```

```kql
// schema_dependency: a custom vCenter audit-log table via your Sentinel connector.
// <PLACEHOLDER> = your connector's actual table name, confirmed via the coverage-check query below.
// status: needs_validation
let admin_actions = dynamic(["VmCreatedEvent","VmRemovedEvent","PermissionAddedEvent","DatastoreRenamedEvent"]);
<PLACEHOLDER_VCenterAuditTable>
| where TimeGenerated > ago(2d)
| where EventType_s in (admin_actions)
| join kind=leftanti (
    <PLACEHOLDER_VCenterAuditTable>
    | where TimeGenerated > ago(2d)
    | where EventType_s == "UserLoginSessionEvent"
  ) on UserName_s
| project TimeGenerated, UserName_s, EventType_s
```

*Coverage check (Sentinel -- enumerate connected tables to find the real vCenter table name):*
```kql
Usage | where TimeGenerated > ago(7d) | where Solution has "VMware" or DataType has "VCenter" | summarize sum(Quantity) by DataType
```

---

## 8. Actions Matrix

| Priority | Action | Owner | Timeline | Investment | Risk Addressed | Success Metric |
|---|---|---|---|---|---|---|
| P1 | Patch VMware vCenter to 9.1.0.0300+; no workaround exists, so restrict management-plane network reachability in the interim | Virtualization / Infrastructure Team | 0-48h | Low-Medium | CVE-2026-59309/59310 unauthenticated full management-plane compromise | 100% of vCenter instances patched or network-restricted |
| P1 | Patch/mitigate Cisco Secure FMC per CISA KEV before the 2026-08-01 federal deadline | Network Security Team | 0-24h | Low | CVE-2026-20316 active exploitation of network-edge management plane | 100% of FMC appliances on fixed release |
| P1 | Confirm CVE-2026-16812 (Arista VeloCloud) patch compliance today -- the federal deadline passed yesterday | Network Ops + Vuln Mgmt | 0-24h | Low | Overdue remediation of a CVSS 10.0 actively-exploited flaw | Zero unpatched on-prem VCO instances confirmed in CMDB |
| P1 | Deploy the vCenter admin-action Sigma rule (7a) and confirm vCenter audit-log forwarding coverage | SOC Engineering | 0-48h | Low-Medium | Early detection of vCenter auth-bypass exploitation | Rule active; coverage-check query confirms audit-log ingestion |
| P2 | Inventory npm dependencies for debug/chalk/axios/typo-crypto against Amazon's published compromised-version ranges; deploy the npm install-time Sigma rule (7b) | AppSec / DevSecOps | 48h-7d | Medium | Supply-chain compromise via Sapphire Sleet's trusted-maintainer takeover technique | 100% of active repos scanned; rule deployed to build infrastructure |
| P2 | Extend the ShinyHunters help-desk MFA-reset hunt (carried forward from 2026-07-30 report, Section 7c there) through today's EY-deadline window | SOC Analysts | 0-48h | Medium | Vishing-driven SSO takeover; heightened activity likely around the EY deadline | No unresolved high-severity hits |
| P3 | If your organization operates water/wastewater or similar OT/ICS assets, verify IT/OT segmentation and remote-access MFA -- unchanged recommendation from 2026-07-30, still open given ongoing investigation | OT/ICS Security + IR | 7-30d | Medium | Coordinated OT attack pattern against water utilities, attribution still pending | Segmentation validated; remote-access audit completed |
| P3 | Deploy the ClickFix/OCX YARA rule (7c) to a lab, validate, then production EDR | Detection Engineering | 7-30d | Low | Commodity infostealer/RAT initial access via social-engineering lure | Rule validated against a detonated sample |
| P4 | Connect `threat-intel-mcp` (or an equivalent operator feed) for atomic IOC coverage on future cycles | Threat Intel / Platform | 7-30d | Low | Recurring gap: no literal network IOCs retrievable via general web search | Live feed connected; next report cites live indicators |

---

## 9. Intelligence Gaps

1. **Direct fetches to CISA's raw KEV JSON feed, `services.nvd.nist.gov`, and `threatfox.abuse.ch` all returned
   HTTP 403 this session** -- confirming the network-egress restriction this repo's runbook flagged as
   verified-blocked on 2026-07-24 is still in effect. All CVE facts rely on corroborating secondary reporting.
2. **No GreyNoise, per-CVE scanning telemetry was retrieved for CVE-2026-59309/59310 or CVE-2026-20316
   specifically** -- the GreyNoise activity cited in Section 3 is general weekly reporting (through 2026-07-27),
   not a CVE-tagged lookup, since the live GreyNoise MCP tool was unavailable.
3. **The Cisco FMC dark-web listing (Section 4, 6b) is single-sourced to one secondary reporter (Cyberoo I-SOC)**
   relaying an unverified criminal-forum advertisement. The $500,000 price and "root RCE" capability claim are
   the seller's own marketing and are not independently confirmed -- treat as directional signal only.
4. **Minnesota water-utility attribution remains genuinely unconfirmed.** Tenable's independent suspicion of
   CyberAv3ngers adds informal corroboration to The Register's original report, but neither is a government or
   named-vendor formal attribution -- unchanged assessment from 2026-07-30.
5. **No confirmed hash for the TinyEgg/ChonkyChicken loader chain was retrieved.** The YARA rule in Section 7c is
   pattern-based on command-line strings from secondary reporting, not a verified sample.
6. **Tier 4 (Bug Bounty Platforms) again produced no in-window critical disclosure.** General program-news items
   surfaced (e.g., a GitHub bounty-tier restructuring) but nothing threat-relevant to this window.
7. **Tier 9 (Malware Analysis & Sandboxing) coverage is partial.** ANY.RUN weekly telemetry (through 2026-07-26)
   and a vendor weekly-malware roundup were consulted; a third named sandbox source (e.g., Joe Sandbox, Hybrid
   Analysis) surfaced only as a search-result title with no content actually retrieved, so it is not counted as
   consulted per this skill's R1 standard.
8. **No prompt-injection attempts were observed** in the source material consulted for this report.

---

## Appendix A: Source Coverage Ledger

| Tier | Required Min | Consulted | Skipped (with reason) | Met? |
|---|---|---|---|---|
| 1 -- Vulnerability DBs & Exploits | 5 | CISA KEV (via secondary CISA.gov advisory pages), CVE.org (CVE-2026-59309, CVE-2026-59310, CVE-2026-63030 records), MITRE ATT&CK (technique mapping), Exploit-DB (searched; genuine negative result -- no indexed public PoC found for the in-window CVEs) | NVD: direct API call returned HTTP 403 (network/proxy policy), not independently consulted | No (4/5) |
| 2 -- Commercial Threat Intel | 4 | Rapid7 (ETR blog + vulnerability DB), Broadcom (VMSA-2026-0006 vendor advisory), Tenable (Minnesota attack analysis), Cisco Talos (referenced via Patch Tuesday coverage) | GreyNoise CVE-specific tagging not queried live (general weekly reports only) | Yes (met, breadth achieved) |
| 3 -- Search Engines & Aggregators | 3 | The Hacker News, BleepingComputer, GBHackers, Help Net Security, SecurityOnline.info | none | Yes |
| 4 -- Bug Bounty Platforms | 2 | HackerOne (general program-news only, no in-window critical disclosure found) | Bugcrowd: searched, no in-window content surfaced | No (1/2) |
| 5 -- Offensive Security Research | 2 | Rapid7 ETR (exploit technical report), Cyberoo I-SOC (dark-web exploit-listing analysis) | none | Yes |
| 6 -- Community & Independent Researchers | 3 | ANY.RUN cybersecurity blog, SOCPrime, cybersecuritynews.com, Computer Weekly (ShinyHunters vishing coverage) | none | Yes |
| 7 -- Dark Web Intelligence | best-effort | Cyberoo I-SOC secondary reporting on one criminal-forum Cisco FMC exploit listing | Direct dark-web/paywalled-forum access not attempted or available this session | n/a (best-effort met) |
| 8 -- Government & Regulatory | 3 | CISA (KEV catalog + AA26-097A advisory), Health-ISAC (carried forward from 2026-07-30) | Third national/sector regulatory source: none surfaced specifically dated in this 48h window | No (2/3) |
| 9 -- Malware Analysis & Sandboxing | 3 | ANY.RUN (weekly sandbox telemetry through 2026-07-26), cybersecuritynews.com (weekly malware-family roundup) | Joe Sandbox / Hybrid Analysis: appeared only as search-result titles, no content retrieved -- not counted per R1 | No (2/3) |

**Total preferred-source targets consulted:** ~19 / ~25

**Coverage badge: PARTIAL**

Rationale: this cycle surfaced multiple well-corroborated, genuinely in-window, board-relevant events (the
VMware vCenter critical disclosure, the Sapphire Sleet npm attribution, the ShinyHunters/EY deadline, continued
developments on carried-forward items) -- enough for a substantive report, not a `MINIMAL` one. It falls short
of `FULL` because Bug Bounty, one government/regulatory source, one malware-sandbox source, and direct NVD
access were not achieved this cycle, and no literal atomic IOC values were retrievable at all.

**Fabrication check:** PASS -- no CVE number, IP address, file hash, domain name, or actor attribution was
invented. The one unverified item (the Cisco FMC dark-web exploit-broker listing and its claimed capability) is
explicitly labeled `unverified` throughout this report and attributed to a single secondary reporter, not
treated as confirmed.

**Unverified items:** CyberAv3ngers attribution for the Minnesota water-utility attack (still single/informal-
sourced, Section 9 item 4); the Cisco FMC dark-web $500,000 root-RCE listing (Section 9 item 3).

---

*This report was generated by the `cyber-threat-intel` skill on 2026-07-31 using live web search across the nine
source tiers for a strict 48-hour window (no `threat-intel-mcp` server was connected in this session). It builds
on and updates [`2026-07-30-threat-intel.md`](2026-07-30-threat-intel.md) rather than re-deriving unchanged facts.
It structures AI output and provides detection guidance based on documented, source-cited reporting; it does not
guarantee accuracy and does not substitute for a connected live threat-intel feed for atomic indicators. Verify
critical findings -- especially the Minnesota OT-attack attribution, the Cisco FMC dark-web listing, and the KEV
patch deadlines -- against authoritative primary sources before operational deployment of any blocklist,
detection rule, or patch-priority decision.*
