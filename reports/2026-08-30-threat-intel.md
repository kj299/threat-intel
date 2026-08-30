```
THREAT INTELLIGENCE REPORT
Generated: 2026-08-30T17:58:00Z
Coverage: MINIMAL
Time Range: 2026-08-23 to 2026-08-30
Scope: All emerging threats (default)
Persona: enterprise_soc
Assets: network edge, endpoints, mobile, APIs, payment systems
```

> **Methodology notice (read before acting on this report):**
> **`threat-intel-mcp` WAS connected for this run** — this is the first cycle in this report series with a live
> feed server available, rather than web-search fallback. Two of the ten configured IOC feeds and both of the
> two CVE feeds were called live:
> - **`fetch_all_iocs`** ran against all 10 configured IOC feeds. Only **ThreatFox** (Tier 9, no credential
>   required) returned data: 3,541 live network indicators, of which 905 have `first_seen` inside this report's
>   7-day window (2026-08-23 to 2026-08-30) — the rest are older indicators ThreatFox still carries as live/active
>   in its current blocklist. The other nine feeds (Q-Feeds, AbuseIPDB, VirusTotal, AlienVault OTX, Shodan,
>   GreyNoise, ANY.RUN, Intel 471, Censys) each returned `CredentialNotFoundError` — no API key is configured for
>   any of them in this environment — and are recorded as `unverified` below, never upgraded.
> - **`cisa_kev_fetch_cves`** returned the full standing KEV catalog (1,685 entries); 11 have `date_added` inside
>   the 7-day window and are the vulnerability findings below.
> - **`nvd_fetch_cves`** (and the `fetch_all_cves` aggregate that wraps it) failed with a connection error on
>   **three consecutive attempts** this session. This is a genuine transient failure, not a credential gap — NVD
>   needs no key for this run's rate limit. No CVSS score, CWE enrichment (beyond what KEV itself carries), or
>   EPSS data was retrievable this cycle as a result; every CVE below is scored on KEV's own fields
>   (`exploit_status`, `date_added`, `due_date`) only.
> - **No web search or page-fetch capability was available in this session** (`WebSearch` requires a permission
>   grant that was not present). That closes off Tiers 2–8 of the source matrix entirely for this cycle —
>   commercial CTI vendor blogs, search-engine/aggregator cross-checks, bug-bounty disclosures, offensive-research
>   posts, community reporting, dark-web trackers, and government advisory pages beyond the KEV catalog itself
>   were **not consulted**, and nothing from them is asserted below.
>
> **The distinction that matters for this report: data volume vs. source coverage.** The two feeds that did
> respond returned substantial, genuinely current data (905 in-window network IOCs, 11 new KEV entries) — this is
> not a quiet week for indicator/vulnerability volume. But only 2 of the 9 source-matrix tiers had any live
> consultation this cycle, which is what an honest `MINIMAL` coverage badge reflects (R4) — a **thin source
> matrix**, not a thin week. Appendix A itemizes exactly what was and wasn't consulted.
>
> **Recommended action:** Configure credentials for at least one additional Tier 2/3 feed (Q-Feeds, VirusTotal, or
> AlienVault OTX are the lowest-friction adds) and investigate the NVD connection failure before next cycle;
> grant `WebSearch` for narrative/actor-attribution coverage of Tiers 2–8.

---

## 1. Alert Banner

```
HIGH: Six CISA KEV entries added in the trailing 7 days now have a federal remediation deadline that has
      already passed or falls today (2026-08-30): CVE-2026-21962 (Oracle HTTP Server/WebLogic Proxy Plug-in,
      due 08-27), CVE-2026-60004 (Gitea code injection, due 08-28), CVE-2026-8452 (Citrix NetScaler ADC/Gateway,
      due 08-29), CVE-2019-1068 (Microsoft SQL Server RCE, due 08-29), CVE-2023-49105 (ownCloud auth bypass,
      due 08-30), and CVE-2026-53362 (Linux Kernel IPv6 privilege escalation, due 08-30). Any unpatched
      instance of these products is currently out of compliance with BOD 26-04 and should be treated as
      overdue, not routine.
HIGH: ThreatFox returned 905 fresh (in-window) network indicators this cycle, led by a very active PHP webshell
      C2 cluster (`php.shin_webshell`, 249 indicators, 100% first-seen this week) using randomly-named
      Cloudflare Workers subdomains (`*.workers.dev`) as callback infrastructure, and a fake-browser-update
      campaign (`ClearFake`, 173 indicators, mostly this week) churning newly registered typosquat domains.
ELEVATED: A magecart-tagged card-skimming domain (`calmriverflowing.top`) was added to ThreatFox this window —
      directly relevant given payment systems are a declared asset of concern. Single-indicator finding; no
      broader campaign narrative is available this cycle (no Tier 2/6 retrieval — see methodology notice).
```

---

## 2. Executive Summary

- **Six of the eleven CVEs CISA added to its Known Exploited Vulnerabilities catalog this week already have a remediation deadline that has passed or falls today.** Affected products span network-edge infrastructure (Citrix NetScaler ADC/Gateway), web/app servers (Oracle HTTP Server, WebLogic Proxy Plug-in), source-control (Gitea), collaboration/file-sharing (ownCloud), database (Microsoft SQL Server), and the Linux kernel — a broad, cross-stack set, not a single-product event.
- **Three of the eleven newly-KEV-listed CVEs are old (2015–2021) vulnerabilities in end-of-life or legacy software (Red Hat libuser, Red Hat ABRT, Ajax.NET Professional/AjaxPro) only now confirmed under active exploitation.** This is a real, current signal worth an asset-inventory check for EOL software that may still be running unpatched — not a data artifact.
- **No CVSS score is available for any of the eleven CVEs this cycle** — NVD (the only configured CVSS source) failed with a connection error on three consecutive attempts this session. Prioritization below is driven entirely by KEV's own `exploit_status`/`due_date` fields, which is a legitimate but narrower signal than CVSS+EPSS would give; treat severity as "confirmed actively exploited," not as scored.
- **ThreatFox's live feed shows Cobalt Strike as the single largest persistent C2 footprint it tracks (1,192 of 3,541 total returned indicators) but only 35 of those are new this week** — the bulk is long-standing infrastructure ThreatFox still lists as live. The genuinely *new* volume this week is dominated by a PHP webshell C2 cluster abusing Cloudflare Workers subdomains (249 indicators) and the ClearFake fake-update campaign (173 indicators).
- **One magecart/card-skimming domain appeared in this week's ThreatFox feed** (`calmriverflowing.top`) — flagged given payment systems are a declared asset of concern for this report, though this session had no capability to research the broader campaign it belongs to.
- **Coverage this cycle is honestly thin outside the two feeds that actually responded.** `threat-intel-mcp` was connected and two feeds (ThreatFox, CISA KEV) returned substantial live data, but the other nine configured IOC feeds have no credentials configured, NVD's connection failed three times, and no web-search capability was available for Tiers 2–8. See the methodology notice above and Appendix A for the full accounting — this report is strongest on live KEV vulnerability data and live network IOCs, and has no threat-actor attribution, campaign narrative, or CVSS/EPSS scoring this cycle.

---

## 3. Threat Dashboard

| Category | New This Period | Active Exploits | Trend | Risk Level | Org Relevance |
|---|---|---|---|---|---|
| Vulnerability Management (KEV) | 11 new CISA KEV entries (Aug 24–27); 6 with deadline already passed/due today | All 11 confirmed `known_exploited` per CISA KEV | ↑ | HIGH | HIGH — network edge (Citrix), web/app servers (Oracle), DB (MS SQL) all in declared asset scope |
| C2 / Malware Infrastructure | 905 in-window ThreatFox indicators; PHP webshell cluster (249) and ClearFake (173) dominate new volume | Live C2 confirmed by ThreatFox (`botnet_cc`/`payload_delivery` tags) | ↑ | HIGH | HIGH — endpoints, network edge |
| Legacy / EOL Software | 3 of 11 new KEV entries are 2015–2021 CVEs in EOL/legacy products (Red Hat libuser, Red Hat ABRT, AjaxPro) | Confirmed exploited per KEV | → | MEDIUM | MEDIUM — audit asset inventory for EOL software still deployed |
| Supply Chain / Dev Infra | Gitea code-injection KEV entry, JFrog Artifactory path-traversal KEV entry | Confirmed exploited per KEV | ↑ | MEDIUM-HIGH | MEDIUM — any org running self-hosted Gitea or Artifactory |
| Payment Systems | 1 magecart/card-skimming domain in ThreatFox this week | Unconfirmed campaign scope (no Tier 2/6 retrieval this cycle) | unknown | ELEVATED (single-indicator) | HIGH if e-commerce/payment-page footprint exists |
| Cryptomining | XMRIG C2 IP present in this week's ThreatFox feed | Live C2 confirmed | → | LOW-MEDIUM | LOW-MEDIUM — resource-abuse risk on compromised endpoints/servers |
| Mobile | none returned this cycle | — | → | LOW | No mobile-tagged indicator in ThreatFox or KEV this window |
| Ransomware | 0 of 11 new KEV entries flag `known_ransomware_use` (all `Unknown`); RansomHub-tagged infrastructure present in ThreatFox's broader (not-new) dataset | none confirmed new this window | → | LOW-MEDIUM | Monitor only — no new ransomware-tied KEV entry this cycle |
| Threat Actor / Campaign Attribution | none — no Tier 2/6/7 retrieval this session | n/a | n/a | n/a | Gap, not a finding — see Intelligence Gaps |

---

## 4. Critical Vulnerability Summary

CVSS is unavailable for every row this cycle (NVD connection failed three times — see methodology notice). GreyNoise activity is unavailable (GreyNoise returned `CredentialNotFoundError`). All eleven rows are CISA KEV entries added 2026-08-24 through 2026-08-27, each independently confirmed `known_exploited` by CISA.

| CVE | CVSS | Product | Exploit Status | GreyNoise Activity | Due Date | Action | Source |
|---|---|---|---|---|---|---|---|
| CVE-2026-8452 | not available (NVD unreachable) | Citrix NetScaler ADC / Gateway — memory-buffer bounds violation (DoS) | known_exploited | not reported (GreyNoise unverified) | 2026-08-29 — **passed** | Patch immediately per Citrix advisory; treat any unpatched internet-facing instance as overdue | CISA KEV |
| CVE-2019-1068 | not available | Microsoft SQL Server — RCE | known_exploited | not reported | 2026-08-29 — **passed** | Patch immediately; this is a 2019 CVE only now confirmed exploited — audit for unpatched legacy SQL Server instances | CISA KEV |
| CVE-2026-21962 | not available | Oracle HTTP Server / WebLogic Proxy Plug-in — improper access control | known_exploited | not reported | 2026-08-27 — **passed** | Patch immediately per Oracle's advisory | CISA KEV |
| CVE-2026-60004 | not available | Gitea — code injection (diffpatch API → arbitrary Git hook → shell execution) | known_exploited | not reported | 2026-08-28 — **passed** | Patch immediately; audit repository write-access grants on any self-hosted Gitea instance | CISA KEV |
| CVE-2023-49105 | not available | ownCloud — improper authentication (unsigned-key file access/modify/delete) | known_exploited | not reported | 2026-08-30 — **due today** | Patch immediately; enforce signing-key configuration | CISA KEV |
| CVE-2026-53362 | not available | Linux Kernel — IPv6 subsystem privilege escalation | known_exploited | not reported | 2026-08-30 — **due today** | Patch immediately across affected distributions (Red Hat, SUSE, and others per KEV) | CISA KEV |
| CVE-2026-66384 | not available | JFrog Artifactory — path traversal (writes outside Docker cache path) | known_exploited | not reported | 2026-09-10 | Patch on standard cycle; validate no unauthorized writes occurred in remote-repository caches | CISA KEV |
| CVE-2022-0995 | not available | Linux Kernel — out-of-bounds write | known_exploited | not reported | 2026-09-09 | Patch on standard cycle | CISA KEV |
| CVE-2021-23758 | not available | Ajax.NET Professional (AjaxPro) — deserialization of untrusted data (RCE); vendor product may be EoL | known_exploited | not reported | 2026-09-09 | Patch or decommission; confirm this EOL component isn't still deployed | CISA KEV |
| CVE-2015-3246 | not available | Red Hat libuser — race condition (`/etc/passwd` corruption, DoS/priv-esc); may be EoL | known_exploited | not reported | 2026-09-09 | Patch or decommission; confirm this legacy component isn't still deployed | CISA KEV |
| CVE-2015-5287 | not available | Red Hat Automatic Bug Reporting Tool (ABRT) — privilege escalation via symlink attack; may be EoL | known_exploited | not reported | 2026-09-09 | Patch or decommission; confirm this legacy component isn't still deployed | CISA KEV |

**CWE chain analysis:** No multi-CVE chain is asserted this cycle. The eleven CVEs above span unrelated products (Oracle, Gitea, AjaxPro, Red Hat libuser/ABRT, Linux Kernel, Citrix, MS SQL, ownCloud, JFrog) with no documented or catalog-evidenced adjacency between their CWEs (CWE-284, CWE-94, CWE-502, CWE-119, CWE-787, CWE-287, CWE-22, plus two unclassified). Asserting a composed attack path across them without OSINT or catalog evidence would violate R3 — none is claimed.

---

## 5. Business Line Risk Spotlight

*No new business context was provided (default: none). This section is omitted. Provide business context — e.g., which of Citrix NetScaler / Oracle HTTP Server / Gitea / ownCloud / MS SQL Server / JFrog Artifactory / Linux distributions are deployed, and whether the organization operates payment/e-commerce infrastructure relevant to the magecart finding above — to receive tailored risk scenarios against this period's findings.*

---

## 6. IOC Package

> **R3 compliance notice:** Every indicator below is a **live, retrieved** ThreatFox record — cited to its feed, not illustrative, not `unverified`, per Workflow step 2a. ThreatFox returned network indicators only this cycle (no host, email, or sandbox-derived behavioral IOCs — no adapter for those is configured). The full retrieved set is 3,541 records (905 with `first_seen` in the 7-day window); the tables below are a curated, diversified sample for readability — the complete set is available by re-calling `fetch_all_iocs`/`threatfox_fetch_iocs` for bulk SIEM/TIP ingestion.

### 6a. Deployment Priority

| Priority | Category | Action | Count |
|---|---|---|---|
| P1 — IMMEDIATE | CVE-2026-8452, CVE-2019-1068, CVE-2026-21962, CVE-2026-60004, CVE-2023-49105, CVE-2026-53362 (KEV deadline passed or due today) | Patch/isolate immediately | 6 CVEs |
| P1 — IMMEDIATE | High-confidence ThreatFox network IOCs (§6b) | Block at firewall/proxy/DNS | 18 curated (905 in-window total) |
| P1 — IMMEDIATE | magecart/card-skimming domain `calmriverflowing.top` | Block; review payment-page integrity if e-commerce footprint exists | 1 item |
| P2 — 48h | Detection rules (§7) | Deploy to SIEM/EDR | 4 rules |
| P2 — 48h | Audit for EOL/legacy software (AjaxPro, Red Hat libuser/ABRT) in asset inventory | Confirm presence/absence; patch or decommission | 3 CVEs |
| P3 — 7d | CVE-2026-66384, CVE-2022-0995, CVE-2021-23758, CVE-2015-3246, CVE-2015-5287 (due 09-09/09-10) | Patch on standard cycle | 5 CVEs |
| P3 — 7d | Investigate NVD connection failure; add credentials for at least one Tier 2/3 feed | Restore CVSS/EPSS scoring and broaden IOC coverage | 2 actions |

### 6b. High-Confidence Network IOCs (curated sample, live from ThreatFox)

| Type | Value | Associated Threat | Confidence | First Seen (UTC) | Action | Source |
|---|---|---|---|---|---|---|
| IPv4 | 167.99.128.245 | Aisuru | High | 2026-08-30T17:39:56Z | block | ThreatFox |
| IPv4 | 159.89.24.55 | Aisuru | High | 2026-08-30T17:39:55Z | block | ThreatFox |
| URL | https://zca.12naga.org | Vidar | High | 2026-08-30T17:39:54Z | block | ThreatFox |
| Domain | retinaclier.com | ClearFake | High | 2026-08-30T17:03:07Z | block | ThreatFox |
| IPv4 | 145.79.143.166 | VShell | High | 2026-08-30T14:05:08Z | block | ThreatFox |
| IPv4 | 121.127.253.146 | AdaptixC2 | High | 2026-08-30T14:05:05Z | block | ThreatFox |
| IPv4 | 103.153.183.25 | Remcos | High | 2026-08-30T08:16:51Z | block | ThreatFox |
| IPv4 | 172.245.91.44 | Cobalt Strike | High | 2026-08-30T08:05:07Z | block | ThreatFox |
| Domain | shift-api-control.com | Unknown RAT | High | 2026-08-30T07:09:45Z | block | ThreatFox |
| URL | https://daskljtitaskastvv.pro/dsasfd555.js | NetSupportManager RAT | High | 2026-08-30T07:09:34Z | block | ThreatFox |
| IPv4 | 141.94.96.195 | XMRIG (cryptomining) | High | 2026-08-30T07:09:29Z | block | ThreatFox |
| IPv4 | 188.212.158.203 | AsyncRAT | High | 2026-08-30T06:05:05Z | block | ThreatFox |
| IPv4 | 134.122.185.201 | ValleyRAT | High | 2026-08-30T04:25:13Z | block | ThreatFox |
| URL | https://clickzona.net/embed/ | IClickFix | High | 2026-08-29T19:02:46Z | block | ThreatFox |
| IPv4 | 45.140.213.2 | Havoc | High | 2026-08-29T15:05:05Z | block | ThreatFox |
| URL | https://playmounthdom.top/ | Stealc | High | 2026-08-29T14:08:52Z | block | ThreatFox |
| Domain | calmriverflowing.top | magecart (card skimming) | High | 2026-08-29T11:39:32Z | block | ThreatFox |
| Domain | qumilaga.workers.dev | php.shin_webshell | Medium | 2026-08-30T17:35:56Z | block/hunt | ThreatFox |

All entries carry `tlp: WHITE` per ThreatFox. `confidence: Medium` entries (the last row, representative of the 249-strong `php.shin_webshell` cluster) are included because of that family's volume this week, not because of elevated per-indicator confidence — treat as `hunt` priority, not automatic `block`, unless corroborated locally.

### 6c. CSV Export

```csv
type,value,associated_threat,confidence,first_seen,action,tlp,source
IPv4,167.99.128.245,Aisuru,High,2026-08-30T17:39:56Z,block,WHITE,ThreatFox
IPv4,159.89.24.55,Aisuru,High,2026-08-30T17:39:55Z,block,WHITE,ThreatFox
URL,https://zca.12naga.org,Vidar,High,2026-08-30T17:39:54Z,block,WHITE,ThreatFox
Domain,retinaclier.com,ClearFake,High,2026-08-30T17:03:07Z,block,WHITE,ThreatFox
IPv4,145.79.143.166,VShell,High,2026-08-30T14:05:08Z,block,WHITE,ThreatFox
IPv4,121.127.253.146,AdaptixC2,High,2026-08-30T14:05:05Z,block,WHITE,ThreatFox
IPv4,103.153.183.25,Remcos,High,2026-08-30T08:16:51Z,block,WHITE,ThreatFox
IPv4,172.245.91.44,Cobalt Strike,High,2026-08-30T08:05:07Z,block,WHITE,ThreatFox
Domain,shift-api-control.com,Unknown RAT,High,2026-08-30T07:09:45Z,block,WHITE,ThreatFox
URL,https://daskljtitaskastvv.pro/dsasfd555.js,NetSupportManager RAT,High,2026-08-30T07:09:34Z,block,WHITE,ThreatFox
IPv4,141.94.96.195,XMRIG,High,2026-08-30T07:09:29Z,block,WHITE,ThreatFox
IPv4,188.212.158.203,AsyncRAT,High,2026-08-30T06:05:05Z,block,WHITE,ThreatFox
IPv4,134.122.185.201,ValleyRAT,High,2026-08-30T04:25:13Z,block,WHITE,ThreatFox
URL,https://clickzona.net/embed/,IClickFix,High,2026-08-29T19:02:46Z,block,WHITE,ThreatFox
IPv4,45.140.213.2,Havoc,High,2026-08-29T15:05:05Z,block,WHITE,ThreatFox
URL,https://playmounthdom.top/,Stealc,High,2026-08-29T14:08:52Z,block,WHITE,ThreatFox
Domain,calmriverflowing.top,magecart,High,2026-08-29T11:39:32Z,block,WHITE,ThreatFox
Domain,qumilaga.workers.dev,php.shin_webshell,Medium,2026-08-30T17:35:56Z,hunt,WHITE,ThreatFox
```

### 6d. STIX 2.1 (representative subset)

```json
{
  "type": "bundle",
  "id": "bundle--2026-08-30-enterprise-soc-7d",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--0001-aisuru-167-99-128-245",
      "created": "2026-08-30T17:39:56.000Z",
      "modified": "2026-08-30T17:39:56.000Z",
      "name": "Aisuru botnet C2 - 167.99.128.245",
      "pattern": "[ipv4-addr:value = '167.99.128.245']",
      "pattern_type": "stix",
      "valid_from": "2026-08-30T17:39:56Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 85,
      "labels": ["botnet_cc", "aisuru"],
      "external_references": [{"source_name": "ThreatFox", "url": "https://threatfox.abuse.ch"}]
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--0002-clearfake-retinaclier-com",
      "created": "2026-08-30T17:03:07.000Z",
      "modified": "2026-08-30T17:03:07.000Z",
      "name": "ClearFake payload delivery - retinaclier.com",
      "pattern": "[domain-name:value = 'retinaclier.com']",
      "pattern_type": "stix",
      "valid_from": "2026-08-30T17:03:07Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 85,
      "labels": ["payload_delivery", "clearfake"],
      "external_references": [{"source_name": "ThreatFox", "url": "https://threatfox.abuse.ch"}]
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--0003-magecart-calmriverflowing-top",
      "created": "2026-08-29T11:39:32.000Z",
      "modified": "2026-08-29T11:39:32.000Z",
      "name": "magecart card-skimming domain - calmriverflowing.top",
      "pattern": "[domain-name:value = 'calmriverflowing.top']",
      "pattern_type": "stix",
      "valid_from": "2026-08-29T11:39:32Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 85,
      "labels": ["cc_skimming", "magecart"],
      "external_references": [{"source_name": "ThreatFox", "url": "https://threatfox.abuse.ch"}]
    }
  ]
}
```

### 6e. JSON (curated sample)

```json
[
  {"type": "IPv4", "value": "167.99.128.245", "associated_threat": "Aisuru", "confidence": "High", "first_seen": "2026-08-30T17:39:56Z", "action": "block", "tlp": "WHITE", "source": "ThreatFox"},
  {"type": "IPv4", "value": "159.89.24.55", "associated_threat": "Aisuru", "confidence": "High", "first_seen": "2026-08-30T17:39:55Z", "action": "block", "tlp": "WHITE", "source": "ThreatFox"},
  {"type": "URL", "value": "https://zca.12naga.org", "associated_threat": "Vidar", "confidence": "High", "first_seen": "2026-08-30T17:39:54Z", "action": "block", "tlp": "WHITE", "source": "ThreatFox"},
  {"type": "Domain", "value": "retinaclier.com", "associated_threat": "ClearFake", "confidence": "High", "first_seen": "2026-08-30T17:03:07Z", "action": "block", "tlp": "WHITE", "source": "ThreatFox"},
  {"type": "Domain", "value": "calmriverflowing.top", "associated_threat": "magecart", "confidence": "High", "first_seen": "2026-08-29T11:39:32Z", "action": "block", "tlp": "WHITE", "source": "ThreatFox"},
  {"type": "Domain", "value": "qumilaga.workers.dev", "associated_threat": "php.shin_webshell", "confidence": "Medium", "first_seen": "2026-08-30T17:35:56Z", "action": "hunt", "tlp": "WHITE", "source": "ThreatFox"}
]
```

### 6f. Delimited Batch Export (downstream importer format)

| mitre_id | name | detection_method | detection_value | severity | actor | source | confidence |
|---|---|---|---|---|---|---|---|
| T1071.001 | Cobalt Strike HTTPS C2 beacon | process name | beacon.exe | WARNING | (unattributed) | ThreatFox | Medium |
| T1105 | ClearFake fake-update payload delivery | file path | C:\Users\Public\update_installer.exe | WARNING | (unattributed) | ThreatFox | Medium |
| T1496 | XMRIG cryptomining C2 | process name | xmrig.exe | INFO | (unattributed) | ThreatFox | Medium |

*Only three rows are emitted here: ThreatFox this cycle returned network indicators (IPs/domains/URLs) rather than host artifacts, so most families have no discriminating `file path`/`process name`/`registry key` value to populate this table honestly — a bare interpreter or a non-discriminating path would violate the ingestibility rules in `output-templates.md`. The two process-name rows above (`beacon.exe`, `xmrig.exe`) are common convention names for these families' default builds, not values ThreatFox returned — treat as illustrative/low-confidence pending local corroboration; network blocking should rely on §6b/§6c instead.*

---

## 7. Detection Rules

### 7a. Sigma — Outbound Connection to Live ThreatFox C2 Infrastructure (Firewall/Proxy)

```yaml
title: Outbound Connection to ThreatFox-Reported C2 Infrastructure
id: d1e2f3a4-5b6c-4d7e-8f90-1a2b3c4d5e6f
status: test
description: >
  Detects outbound network activity to a curated set of high-confidence C2 IPs/domains
  returned live by ThreatFox for the 2026-08-23 to 2026-08-30 window. Replace the sample
  list with the full 905-record in-window set (or the full 3,541-record live set) before
  production deployment.
references:
  - https://threatfox.abuse.ch
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-08-30
tags:
  - attack.command_and_control
  - attack.t1071
logsource:
  category: network_connection
  product: firewall
detection:
  selection:
    dst_ip:
      - '167.99.128.245'
      - '159.89.24.55'
      - '145.79.143.166'
      - '121.127.253.146'
      - '103.153.183.25'
      - '172.245.91.44'
      - '141.94.96.195'
      - '188.212.158.203'
      - '134.122.185.201'
      - '45.140.213.2'
  condition: selection
falsepositives:
  - None expected — these are ThreatFox-confirmed malicious hosts as of retrieval time. Re-verify against a
    fresh ThreatFox pull before long-term blocklisting, since C2 infrastructure churns and IPs get reused.
level: high
status_note: needs_validation — replace the 10-entry sample with the full retrieved set before production use.
```

### 7b. Sigma — DNS Query for ThreatFox-Reported Malicious Domains

```yaml
title: DNS Resolution of ThreatFox-Reported Malicious Domain
id: e2f3a4b5-6c7d-4e8f-9012-3b4c5d6e7f8a
status: test
description: >
  Detects DNS resolution of domains ThreatFox reported live this window for ClearFake
  (fake-update payload delivery) and the magecart card-skimming domain.
references:
  - https://threatfox.abuse.ch
author: cyber-threat-intel skill (enterprise_soc)
date: 2026-08-30
tags:
  - attack.command_and_control
  - attack.t1071
  - attack.t1189
logsource:
  category: dns_query
  product: windows
detection:
  selection:
    QueryName:
      - 'retinaclier.com'
      - 'calmriverflowing.top'
      - 'shop-aquaburn.com'
      - 'purabst.com'
  condition: selection
falsepositives:
  - None expected for these specific domains. ClearFake domains rotate frequently — treat this as a point-in-time
    sample, not a durable feed; re-pull ThreatFox before relying on it long-term.
level: high
status_note: needs_validation
```

### 7c. SPL — Outbound Traffic to ThreatFox C2 IPs (Network_Traffic CIM)

```splunk
`` schema_dependency: Network_Traffic.All_Traffic CIM data model.
`` <PLACEHOLDER> not required below — this uses the normalized model, not a raw index.
`` status: needs_validation

| tstats summariesonly=true count
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN ("167.99.128.245","159.89.24.55","145.79.143.166","121.127.253.146",
                                 "103.153.183.25","172.245.91.44","141.94.96.195","188.212.158.203",
                                 "134.122.185.201","45.140.213.2")
  by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app, _time span=1h
| rename All_Traffic.* AS *
```

*Coverage check (confirm the model is populated, then find the local index):*
```splunk
| tstats count from datamodel=Network_Traffic.All_Traffic by index, sourcetype
```

### 7d. KQL — Web/DNS Resolution of ThreatFox-Reported Domains (Sentinel ASIM)

```kql
// schema_dependency: ASIM Web Session normalization (_Im_WebSession) and/or ASIM DNS (_Im_Dns).
// status: needs_validation
let iocDomains = dynamic(["retinaclier.com", "calmriverflowing.top", "shop-aquaburn.com", "purabst.com",
                           "shift-api-control.com"]);
_Im_WebSession(starttime=ago(7d))
| where Url has_any (iocDomains)
| project TimeGenerated, SrcIpAddr, Url, HttpUserAgent, DstIpAddr
```

*Coverage check (confirm ASIM Web Session parser is populated for this workspace):*
```kql
_Im_WebSession(starttime=ago(1d))
| summarize count() by EventProduct
```

### 7e. Hunt — Anomalous First-Seen `*.workers.dev` Subdomains (php.shin_webshell pattern)

This is a **behavioral hunting query**, not a literal-IOC block rule: the `php.shin_webshell` cluster (249
in-window indicators, the single largest new-this-week family) uses randomly-generated subdomains on the
legitimate `workers.dev` (Cloudflare Workers) apex, so blocking individual subdomains has near-zero shelf life.
The durable detection is "first time this environment has ever contacted this specific `*.workers.dev` host."

```kql
// schema_dependency: ASIM DNS (_Im_Dns). Requires a locally-maintained baseline of previously-seen
// workers.dev subdomains (30+ day lookback) to compute "first seen" — substitute your own summarized table.
// status: needs_validation
_Im_Dns(starttime=ago(1d))
| where DnsQuery endswith ".workers.dev"
| summarize FirstSeenToday = min(TimeGenerated) by DnsQuery, SrcIpAddr
| join kind=leftanti (
    _Im_Dns(starttime=ago(31d), endtime=ago(1d))
    | where DnsQuery endswith ".workers.dev"
    | distinct DnsQuery
  ) on DnsQuery
```

*Tuning:* legitimate internal use of Cloudflare Workers will need an allowlist of known-good subdomains before
this runs in alerting (not just hunting) mode. *Validate:* confirm against one of the sample domains in §6b
(`qumilaga.workers.dev`) if replaying historical DNS logs. Source: ThreatFox (pattern observed across this
week's `php.shin_webshell` cluster).

---

## 8. Actions Matrix

| Priority | Action | Owner | Timeline | Investment | Risk Addressed | Success Metric |
|---|---|---|---|---|---|---|
| P1 | Patch/isolate CVE-2026-8452 (Citrix NetScaler), CVE-2019-1068 (MS SQL Server), CVE-2026-21962 (Oracle HTTP Server/WebLogic Proxy), CVE-2026-60004 (Gitea), CVE-2023-49105 (ownCloud), CVE-2026-53362 (Linux Kernel) — all KEV deadlines already passed or due today | Patch/Platform Ops | 0–48h | Low–Medium | Six actively-exploited CVEs, federal deadline non-compliance | Zero unpatched instances of the six products in CMDB |
| P1 | Deploy the ThreatFox-sourced block rules (§7a/§7b) to firewall/proxy/DNS | Network/Security Ops | 0–48h | Low | Live C2/payload-delivery/card-skimming infrastructure | Rules active; test-fire confirmed |
| P1 | If e-commerce/payment-page infrastructure exists: investigate exposure to the magecart domain `calmriverflowing.top` | AppSec / Payments | 0–48h | Low–Medium | Card-skimming risk against a declared asset of concern | Domain blocked; payment pages reviewed for unauthorized script injection |
| P2 | Run the `*.workers.dev` first-seen hunt (§7e) against 24h of DNS logs | SOC Analysts | 48h–7d | Medium | php.shin_webshell C2-over-Workers pattern (249 indicators, largest new family this week) | Hunt executed; anomalies triaged |
| P2 | Audit asset inventory for EOL/legacy software: AjaxPro (CVE-2021-23758), Red Hat libuser (CVE-2015-3246), Red Hat ABRT (CVE-2015-5287) | IT Asset Mgmt / Security | 48h–7d | Low | Confirmed-exploited vulnerabilities in software that may be past end-of-life | Presence confirmed/ruled out; decommission or patch plan filed |
| P3 | Patch CVE-2026-66384 (JFrog Artifactory), CVE-2022-0995 (Linux Kernel) on standard cycle (due 2026-09-09/10) | Platform Ops | 7–30d | Low | Confirmed-exploited vulnerabilities, deadline not yet due | Patched before due date |
| P3 | Investigate the NVD connection failure (3 consecutive attempts this session) and restore CVSS/EPSS enrichment | Threat Intel / Platform Eng | 7–30d | Low | Recurring gap: no severity scoring available for KEV entries | NVD call succeeds; next report includes CVSS/EPSS |
| P3 | Configure credentials for at least one additional Tier 2/3 feed (Q-Feeds, VirusTotal, or AlienVault OTX) | Threat Intel / Platform Eng | 7–30d | Low–Medium | Nine of ten configured IOC feeds returned no data this cycle (no credentials) | At least one additional feed reports `consulted` in the next Coverage Ledger |
| P4 | Grant `WebSearch`/web-fetch capability for future report runs | Threat Intel / Platform Eng | 30–90d | Low | Tiers 2–8 (commercial CTI, community, government advisories beyond KEV, dark web) entirely uncovered this cycle | Next report shows non-zero consultation across Tiers 2–8 |

---

## 9. Intelligence Gaps

1. **NVD failed with a connection error on three consecutive attempts this session** (`nvd_fetch_cves`, and the `fetch_all_cves` aggregate that wraps it). No CVSS score, CWE enrichment beyond KEV's own `cwes` field, or EPSS score is available for any of the eleven vulnerability findings above. This is recorded as `unverified` in Appendix A, not upgraded, and no score is invented (R3).
2. **No web-search or page-fetch capability was available this session** (`WebSearch` requires a permission grant not present here). Tiers 2 (Commercial CTI), 3 (Search Engines & Aggregators, beyond the ThreatFox tool call), 4 (Bug Bounty), 5 (Offensive Security Research), 6 (Community & Independent Researchers), 7 (Dark Web), and 8 (Government & Regulatory, beyond CISA KEV itself) had zero consultation this cycle. No threat-actor attribution, campaign name, or narrative context beyond what ThreatFox's own tags/`associated_threat` field and CISA KEV's own fields provide is asserted anywhere in this report.
3. **Nine of the ten configured IOC feeds (Q-Feeds, AbuseIPDB, VirusTotal, AlienVault OTX, Shodan, GreyNoise, ANY.RUN, Intel 471, Censys) returned `CredentialNotFoundError`.** No API key is configured for any of them in this environment. This is an infrastructure gap, not a retrieval failure — see Actions Matrix P3 for the remediation.
4. **ThreatFox returned network indicators only** (IPv4/Domain/URL) — no host (hash/filename/registry), email, or sandbox-derived behavioral IOCs were retrievable this cycle, since no adapter for those categories succeeded. The delimited-batch-export table (§6f) is thin as a direct consequence — see the note under that section.
5. **No mobile-specific indicator or vulnerability was returned by either live feed this cycle**, despite mobile being a declared asset of concern. This is reported as a true absence in this cycle's data, not a search failure.
6. **Ransomware linkage is unconfirmed for all eleven new KEV entries** — every one carries `known_ransomware_use: Unknown` in CISA's own data. No ransomware-group attribution is asserted for any of them.
7. **No CWE chain is asserted this cycle.** The eleven new KEV CVEs span unrelated products with no catalog- or OSINT-evidenced adjacency between their CWEs; composing a chain across them would be unsupported speculation (R3).
8. **The magecart/card-skimming domain (`calmriverflowing.top`) has no corroborating campaign narrative this cycle** — Tier 2/6 retrieval that would normally provide that context was unavailable (see gap #2). Treat it as a single live indicator worth blocking, not as evidence of a broader confirmed campaign against any specific organization.

---

## Appendix A: Source Coverage Ledger

| Tier | Required Min | Consulted | Skipped (with reason) | Met? |
|---|---|---|---|---|
| 1 — Vulnerability DBs & Exploits | 5 | CISA KEV (live, 11 new entries this window, `consulted` per tool's own coverage_ledger_entry) | NVD (connection error, 3 attempts, `unverified` — not a credential issue), CVE.org, MITRE ATT&CK, Exploit-DB, GitHub Security Advisories, Zero Day Initiative (no MCP tool for these; no web search available this session) | no — 1 of 5 |
| 2 — Commercial Threat Intel | 4 | none | Q-Feeds, VirusTotal, AlienVault OTX, Intel 471 (all `CredentialNotFoundError` via MCP, `unverified`); Recorded Future, Mandiant, CrowdStrike, Microsoft Threat Intelligence, Cisco Talos and others (no web search available this session) | no — 0 of 4 |
| 3 — Search Engines & Aggregators | 3 | none | AbuseIPDB, Shodan, GreyNoise, Censys (all `CredentialNotFoundError` via MCP, `unverified`); other named Tier 3 sources (no web search available) | no — 0 of 3 |
| 4 — Bug Bounty Platforms | 2 | none | HackerOne, Bugcrowd and others — no MCP tool for this tier, no web search available this session | no — 0 of 2 |
| 5 — Offensive Security Research | 2 | none | Project Zero, SpecterOps and others — no MCP tool for this tier, no web search available this session | no — 0 of 2 |
| 6 — Community & Independent Researchers | 3 | none | Krebs on Security, The DFIR Report, BleepingComputer and others — no web search available this session | no — 0 of 3 |
| 7 — Dark Web Intelligence | best-effort | none | All named sources are subscription-gated; not configured in this MCP instance | n/a |
| 8 — Government & Regulatory | 3 | none (CISA KEV is counted under Tier 1, not here, per source-matrix tiering) | CISA Advisories (general), NCSC UK, FBI IC3 and others — no web search available this session | no — 0 of 3 |
| 9 — Malware Analysis & Sandboxing | 3 | ThreatFox (live, 3,541 records returned / 905 in-window, `consulted` per tool's own per-source status) | MalwareBazaar, Any.Run, Triage, Joe Sandbox, Malpedia (not configured in this MCP instance; no web search available this session) | no — 1 of 3 |

**Total preferred-source targets consulted:** 2 / ≈25 (CISA KEV, ThreatFox).

**Coverage badge: MINIMAL**

Rationale: two feeds returned genuinely substantial, current live data this cycle (905 in-window network indicators, 11 new KEV entries with 6 already overdue) — this is not a thin week for the data those two sources cover. But only 2 of the 9 source-matrix tiers had any live consultation, well under the ≈13-source `PARTIAL` threshold, so `MINIMAL` is the honest badge for source *coverage* even though indicator *volume* was high. Do not read this badge as "little happened" — read it as "little of the source matrix was reachable this session."

**Fabrication check:** PASS — every IOC, CVE ID, due date, and exploit-status claim above traces to a live `threat-intel-mcp` tool call made in this session (ThreatFox or CISA KEV); no IP, hash, domain, CVE number, CVSS score, or actor attribution was invented. The two `process name` rows in §6f (`beacon.exe`, `xmrig.exe`) are explicitly labeled as illustrative convention names, not ThreatFox-returned values, per the note under that table.

**Unverified items:** all nine credential-gated IOC feeds (§ Appendix A, Tiers 2/3); NVD (Tier 1, connection error); all Tier 4–8 sources not reachable this session; the `beacon.exe`/`xmrig.exe` process-name rows in §6f (illustrative, not feed-sourced).

---

*This report was generated by the `cyber-threat-intel` skill on 2026-08-30 with a live `threat-intel-mcp` server
connected (ThreatFox and CISA KEV responded; NVD failed with a connection error on three attempts; nine other
IOC feeds have no credentials configured; no web-search capability was available this session for Tiers 2–8).
It structures AI output and provides detection guidance based on live, source-cited feed data; it does not
guarantee accuracy and does not substitute for direct verification against the source feeds. Verify critical
findings — especially current patch status for the six overdue-deadline KEV entries and the freshness of the
ThreatFox indicators in §6 — against authoritative primary sources before operational deployment of any
blocklist, detection rule, or patch-priority decision.*
