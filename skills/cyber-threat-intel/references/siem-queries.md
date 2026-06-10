# SIEM Query Authoring (Splunk SPL / Microsoft Sentinel KQL)

How to shape the **detection** and **hunting** queries a threat-intel report emits (`SKILL.md` §7 / "Hunting Queries", `output-templates.md` SOC IOC Package).

**The deliverable is always a runnable starting point — never an empty section, never a bare "needs schema."** The way to give a concrete query *and* stay honest is to lean on **normalized data models**: Splunk CIM data models, Sentinel ASIM functions, and the well-known Defender XDR tables. These run against a documented schema **without** needing the environment's raw `index`/`sourcetype`/table name — so they're concrete and copy-pasteable even when you don't know the reader's deployment. Only the *raw* index/sourcetype/table is environment-specific, and that is the one thing you never invent (the SIEM analogue of R3): leave it as a `<PLACEHOLDER>` and hand the reader a discovery query to resolve it.

## Output contract (whenever queries are built)

For every report that emits SIEM content, produce — at minimum — **one concrete SPL starter and one concrete KQL starter** relevant to the threats found, plus the discovery/coverage queries to adapt them:

- **Concrete + normalized.** Build on CIM / ASIM / Defender XDR tables so the query runs without a guessed raw dataset. Put `<ANGLE_BRACKET>` placeholders only on the genuinely environment-specific bits (a raw index, an EDR sourcetype, an IOC value to fill in).
- **Pair with a coverage check.** Follow each starter with a one-line discovery query (below) that confirms the data model/table is populated and reveals the local index — so the reader can verify and adapt rather than trust on faith.
- **Status.** `needs_validation` is the *normal* state for a normalized starter (runnable, but test before production). Use `ready` only when the user supplied real schema. Reserve `needs_schema` for the narrow case where even normalized-model coverage can't be assumed — and even then, still emit the normalized starter as the primary output.

A report that returns only discovery queries, or an empty Detection/Hunting section, is under-delivering. Give the analyst something to run today, with a clear path to harden it.

## Truth order (highest wins)

1. An internal data dictionary URL or excerpt the user supplied.
2. Explicit dataset/field names the user gave.
3. **Documented normalized schema (Splunk CIM data models; Sentinel ASIM; Defender XDR tables) — the default starting point: concrete and runnable without a raw index name.**
4. A raw vendor `sourcetype`/table — only when actually known (or mapped via the vendor cheat-sheet below); otherwise a `<PLACEHOLDER>`, never invented.
5. A discovery / coverage query — paired with the starter to confirm datasets and adapt.

Do not let a lower-priority guess override a higher-priority fact. Never assert a raw `index`/`sourcetype`/table the reader hasn't confirmed — but *do* always ship the normalized starter from level 3.

## Golden rules

- **Starter-first.** Always give a concrete normalized query as the deliverable. Discovery queries *accompany* it; they never replace it.
- **Never invent the raw index/sourcetype/table.** Normalized models sidestep this; for raw queries, use `<PLACEHOLDERS>` and a discovery query.
- **Constrain scope before logic.** Time bound + exact dataset first, then fielded predicates, then parsing, then aggregation. Filter early, parse late, aggregate last.
- **Fielded over raw.** Prefer documented field names over `rex`/raw-text scans and ad-hoc `search "string"`.
- **Every query carries provenance.** Each detection/hunt query carries `source` (the Matrix entry the logic derives from) and a `schema_dependency` note listing the datasets/fields it assumes.
- **Small results.** Project only needed columns (`| table` / `project`); stop at the smallest useful output.

## Normalized starters (concrete, runnable — copy and adapt)

These run against the normalized model without a raw index name. `summariesonly=true` assumes the CIM data model is accelerated — drop it if it isn't (or if very recent events matter). Field prefixes use the root dataset (`Processes.*`, `All_Traffic.*`).

### Process creation / parent-child (Execution, T1059 / T1055 / many)

```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes
  where Processes.process_name=<CHILD_PROC> Processes.parent_process_name=<PARENT_PROC>
  by Processes.dest, Processes.user, Processes.process, Processes.parent_process
| rename Processes.* AS *
```
```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName =~ "<CHILD_PROC>" and InitiatingProcessFileName =~ "<PARENT_PROC>"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```
ASIM variant (cross-EDR): `_Im_ProcessCreate(starttime=ago(7d)) | where TargetProcessName has "<CHILD_PROC>"`.

### Network / proxy / firewall (C2, exfil, IOC IP match)

```spl
| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN (<IOC_IP_1>,<IOC_IP_2>)
  by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app
| rename All_Traffic.* AS *
```
```kql
let iocs = dynamic(["<IOC_IP_1>","<IOC_IP_2>"]);
_Im_NetworkSession(starttime=ago(7d))
| where DstIpAddr in (iocs)
| project TimeGenerated, SrcIpAddr, DstIpAddr, DstPortNumber, Dvc, EventProduct
```

### Web / proxy URL or domain match

```spl
| tstats summariesonly=true count from datamodel=Web.Web
  where Web.url IN (<IOC_URL_1>,<IOC_URL_2>) OR Web.dest IN (<IOC_DOMAIN_1>)
  by Web.src, Web.user, Web.url, Web.action
| rename Web.* AS *
```
```kql
let domains = dynamic(["<IOC_DOMAIN_1>","<IOC_DOMAIN_2>"]);
_Im_WebSession(starttime=ago(7d))
| where Url has_any (domains)
| project TimeGenerated, SrcIpAddr, Url, HttpUserAgent, DstIpAddr
```

### DNS resolution (DGA / C2 domain)

```spl
| tstats summariesonly=true count from datamodel=Network_Resolution.DNS
  where DNS.query IN (<IOC_DOMAIN_1>,<IOC_DOMAIN_2>)
  by DNS.src, DNS.query, DNS.answer, DNS.record_type
| rename DNS.* AS *
```
```kql
let domains = dynamic(["<IOC_DOMAIN_1>","<IOC_DOMAIN_2>"]);
_Im_Dns(starttime=ago(7d))
| where DnsQuery has_any (domains)
| project TimeGenerated, SrcIpAddr, DnsQuery, DnsResponseName
```

### Authentication (credential attacks, T1110 / T1078)

```spl
| tstats summariesonly=true count from datamodel=Authentication.Authentication
  where Authentication.action="failure"
  by Authentication.user, Authentication.src, Authentication.app, _time span=1h
| where count > <THRESHOLD>
| rename Authentication.* AS *
```
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != "0"
| summarize failures = count() by UserPrincipalName, IPAddress, AppDisplayName, bin(TimeGenerated, 1h)
| where failures > <THRESHOLD>
```

### File-hash match (malware delivery)

```spl
| tstats summariesonly=true count from datamodel=Endpoint.Filesystem
  where Filesystem.file_hash IN (<SHA256_1>,<SHA256_2>)
  by Filesystem.dest, Filesystem.user, Filesystem.file_name, Filesystem.file_path
| rename Filesystem.* AS *
```
```kql
let hashes = dynamic(["<SHA256_1>","<SHA256_2>"]);
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where SHA256 in (hashes)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FolderPath, SHA256
```

### Registry autorun persistence (T1547.001)

```spl
| tstats summariesonly=true count from datamodel=Endpoint.Registry
  where Registry.registry_path="*\\CurrentVersion\\Run*"
  by Registry.dest, Registry.user, Registry.registry_path, Registry.registry_value_name
| rename Registry.* AS *
```
```kql
DeviceRegistryEvents
| where TimeGenerated > ago(7d)
| where RegistryKey has @"\CurrentVersion\Run"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

### Named-pipe / WMI persistence (T1021.002 / T1047)

Sysmon-specific (no CIM root dataset), so this one carries a raw-sourcetype placeholder — pair it with the discovery query.

```spl
index=<EDR_INDEX> sourcetype=<SYSMON_SOURCETYPE> EventCode IN (17,18) pipe_name=<NAMED_PIPE>
| table _time, host, process_name, pipe_name
```
```kql
DeviceEvents
| where TimeGenerated > ago(7d)
| where ActionType in ("NamedPipeEvent","WmiBindEvent")
| where AdditionalFields has "<NAMED_PIPE_OR_WMI_FILTER>"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName, AdditionalFields
```

## Coverage check / discovery starters (pair one with every query)

These confirm the model/table is populated and reveal the local index, so the reader can trust or adapt the starter above.

### Splunk — confirm the CIM model is populated, then find the index

```spl
| tstats count from datamodel=Endpoint.Processes by index, sourcetype
```
```spl
| datamodel Endpoint search | head 5
```
An empty result means the model isn't accelerated/populated for that source — fall back to a raw search against the index the next query reveals:
```spl
| tstats count where index=* by index, sourcetype
```

### Sentinel — enumerate tables and confirm columns

```kql
Usage | where TimeGenerated > ago(7d)
| summarize TotalGB = sum(Quantity)/1024 by DataType, Solution | sort by TotalGB desc
```
```kql
<TableName> | getschema      // columns + types, no event scan
<TableName> | take 5         // cheapest look at real values
```

## CIM vendor alignment cheat-sheet

When the threat is tied to a known product, map its raw `sourcetype` to a CIM data model so the normalized starter applies. Indexes are deployment-specific — never assume them; the coverage-check query reveals them.

| Data model | Root dataset | Core fields |
|---|---|---|
| Web | Web | action, src, dest, url, uri_path, http_method, status, http_user_agent, user |
| Network_Traffic | All_Traffic | action, src, dest, dest_port, transport, app, rule, bytes_in, bytes_out, user |
| Network_Resolution | DNS | src, dest, query, reply_code, record_type, answer |
| Authentication | Authentication | action, app, src, dest, user, signature, authentication_method |
| Endpoint | Processes, Filesystem, Registry, Services | process, process_name, parent_process_name, dest, user, action |
| Malware | Malware_Attacks | signature, action, file_name, file_path, file_hash, dest, user, vendor_product |
| Email | All_Email | action, src_user, recipient, subject, file_name, file_hash, url, message_id |
| Intrusion_Detection | IDS_Attacks | signature, severity, action, src, dest, category, vendor_product |

| Vendor (sourcetype) | CIM data model(s) |
|---|---|
| Zscaler (`zscalernss-web` / `-fw` / `-dns`) | Web / Network_Traffic / Network_Resolution |
| Palo Alto (`pan:traffic` / `pan:threat` / `pan:globalprotect`) | Network_Traffic / Intrusion_Detection+Malware (URL→Web) / Authentication+Network_Sessions |
| Cisco (`cisco:asa` / `cisco:umbrella:dns` / `cisco:ise:syslog`) | Network_Traffic+Authentication / Network_Resolution+Web / Authentication |
| CrowdStrike (`crowdstrike:events:sensor`) | Endpoint, Malware, Intrusion_Detection (FDR field names differ — verify) |
| Microsoft Defender (`ms:defender:atp:alerts`) | Alerts, Malware, Endpoint |
| Proofpoint (`proofpoint:tap:siem` / `pps_messagelog`) | Email+Malware / Email |
| Cloudflare (`cloudflare:json`) | Web / Network_Resolution (Gateway DNS) |
| Web proxy generic (`bluecoat:proxysg:access:*`, `squid:access`) | Web |

**Cross-vendor strategy:** query the shared data model once instead of OR-ing sourcetypes, and `by ... sourcetype` (or `vendor_product`) so per-vendor gaps stay visible. If one vendor isn't CIM-mapped, add a separate raw-sourcetype query rather than weakening the CIM query.

## Detection output shape

When the report emits a **detection** (not just a hunt), attach the operational metadata that makes it deployable. Match the structured `hunting_queries` schema (objective, platform, query, schema_dependency, assumptions, tuning, validation, status):

- **Objective** — the analyst goal in one line.
- **Query** — the normalized starter above with placeholders for env-specific bits.
- **schema_dependency** — datasets + fields the query assumes; the single fact (often the raw index) that would remove ambiguity.
- **Assumptions** — accelerated vs un-accelerated model, time window, parser/connector caveats.
- **Tuning** — threshold options, false-positive levers, suppression ideas, field substitutions for alternate schemas.
- **Validate** — how to confirm it fires (detonate the TTP in a lab, replay a known-bad sample) before production.
- **Status** — `needs_validation` for a normalized starter (the norm); `ready` only with confirmed schema.

## Translation (SPL ⇄ KQL)

Preserve intent before syntax: map scope → filters → parsing → aggregation. Prefer normalized↔normalized (CIM ↔ ASIM) mappings. If no safe one-to-one mapping exists (e.g. an SPL index has no documented Sentinel table equivalent), give the closest normalized pattern plus a discovery query — do not assert a table name on faith.

## Honesty parity

The raw `index`/`sourcetype`/table is the only thing that's environment-specific and unguessable — leave it a `<PLACEHOLDER>` and pair a discovery query, the SIEM counterpart of R3. But always ship the normalized (CIM/ASIM/Defender) starter as the runnable deliverable, marked `status: needs_validation`. Record genuinely unresolvable schema gaps in Intelligence Gaps. The failure mode to avoid is the opposite of fabrication: shipping an empty or discovery-only section that leaves the analyst with nothing to run.
