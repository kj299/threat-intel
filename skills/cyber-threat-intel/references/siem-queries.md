# SIEM Query Authoring (Splunk SPL / Microsoft Sentinel KQL)

How to shape the **detection** and **hunting** queries a threat-intel report emits (`SKILL.md` §7–§"Hunting Queries", `output-templates.md` SOC IOC Package). The rules below are the SIEM analogue of the no-fabrication rule (R3): **never invent a dataset name when discovery is safer.** A query that references an `index`, `sourcetype`, or Sentinel table that does not exist in the reader's environment is as useless — and as misleading — as a fabricated IOC.

These patterns are environment-agnostic by design. They carry placeholders, not guessed production names. The consumer substitutes real dataset/field names (ideally from an internal data dictionary) before running anything.

## Truth order (highest wins)

1. An internal data dictionary URL or excerpt the user supplied.
2. Explicit dataset/field names the user gave.
3. Documented normalized schema (Splunk CIM data models; Sentinel ASIM / normalized tables).
4. **Discovery query** — when none of the above is known.

Do not let a lower-priority guess override a higher-priority fact. If the schema is unknown, emit a *discovery* query and stop — do not emit a confident production query against an invented dataset.

## Golden rules

- **Discovery-first.** Unknown `index`/`sourcetype` (Splunk) or table/connector (Sentinel) → return a discovery starter (below), mark the detection `status: needs schema`, and say what single fact would unblock it. Same weight as R3.
- **Constrain scope before logic.** Time bound + exact dataset first, then fielded predicates, then parsing, then aggregation. Filter early, parse late, aggregate last.
- **Fielded over raw.** Prefer documented field names over `rex`/raw-text scans and over ad-hoc `search "string"`.
- **Every query carries provenance.** Each detection/hunt query in the report carries `source` (the Matrix entry the logic derives from) and a `schema_dependency` note listing the datasets/fields it assumes.
- **Small results.** Project only needed columns (`| table` / `project`); stop at the smallest useful output.
- **Prefer normalized models** (CIM / ASIM) when coverage is known; they survive schema drift better than vendor-specific sourcetypes.

## Discovery starters (run these first when schema is unknown)

### Splunk — `tstats` (reads indexed metadata, cheap)

```spl
| tstats count where index=* by index, sourcetype
```
```spl
| tstats count from datamodel=Endpoint where nodename=Endpoint.Processes by index
```
```spl
| tstats values(YOUR_FIELD) where index=YOUR_INDEX
```
An empty `values()` result means the field is not indexed — a raw-event search with extraction is required.

### Sentinel — metadata tables + `getschema`

```kql
Usage | where TimeGenerated > ago(7d)
| summarize TotalGB = sum(Quantity) / 1024 by DataType, Solution
| sort by TotalGB desc
```
```kql
Heartbeat | where TimeGenerated > ago(24h)
| summarize LastSeen = max(TimeGenerated) by Computer, OSType, Category
```
```kql
TableName | getschema      // columns + types, no event scan
TableName | take 5         // cheapest look at real values
```

Return a discovery query (and stop) when: the exact index/sourcetype or table is unknown; a CIM/ASIM detection is requested but model coverage is unclear; or a translation hinges on which index/table receives the source data.

## IOC → query patterns

Placeholders in `<ANGLE_BRACKETS>` are substituted from the data dictionary. Each pattern names the schema it assumes so the consumer can map or run discovery.

### Network IOC match (IP / domain) — `block`/`alert` IOCs as a hunt

Schema assumed: a network/proxy/DNS dataset with `dest_ip`, `dest`/`query` (Splunk CIM `Network_Traffic` / `Web` / `DNS`); Sentinel `CommonSecurityLog` / `DnsEvents` / ASIM `_Im_NetworkSession`.

```spl
| tstats summariesonly=t count from datamodel=Network_Traffic
  where All_Traffic.dest_ip IN (<IOC_IP_1>,<IOC_IP_2>) by All_Traffic.src_ip, All_Traffic.dest_ip
| rename All_Traffic.* AS *
```
```kql
let iocs = dynamic(["<IOC_IP_1>","<IOC_IP_2>"]);
_Im_NetworkSession(starttime=ago(7d))
| where DstIpAddr in (iocs)
| project TimeGenerated, SrcIpAddr, DstIpAddr, Dvc, EventProduct
```

### File-hash match

Schema assumed: endpoint/file-event dataset with a hash field (CIM `Endpoint.Filesystem` / Sysmon `file_hash`; Sentinel `DeviceFileEvents.SHA256` or ASIM `_Im_FileEvent`).

```spl
index=<EDR_INDEX> sourcetype=<EDR_SOURCETYPE> (file_hash=<SHA256_1> OR file_hash=<SHA256_2>)
| table _time, host, user, process_name, file_path, file_hash
```
```kql
let hashes = dynamic(["<SHA256_1>","<SHA256_2>"]);
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where SHA256 in (hashes)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FolderPath, SHA256
```

### Suspicious process / parent-child (TTP behavior)

Schema assumed: process-creation telemetry (CIM `Endpoint.Processes`; Sysmon EID 1; Sentinel `DeviceProcessEvents` / ASIM `_Im_ProcessCreate`).

```spl
| tstats summariesonly=t count from datamodel=Endpoint.Processes
  where Processes.process_name=<CHILD_PROC> Processes.parent_process_name=<PARENT_PROC>
  by Processes.dest, Processes.user, Processes.process
| rename Processes.* AS *
```
```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName =~ "<CHILD_PROC>" and InitiatingProcessFileName =~ "<PARENT_PROC>"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Registry autorun persistence (T1547.001)

Schema assumed: registry telemetry (Sysmon EID 12/13; Sentinel `DeviceRegistryEvents`).

```spl
index=<EDR_INDEX> sourcetype=<SYSMON_SOURCETYPE> EventCode IN (12,13)
  registry_path="*\\CurrentVersion\\Run*"
| table _time, host, user, registry_path, registry_value_name, registry_value_data
```
```kql
DeviceRegistryEvents
| where TimeGenerated > ago(7d)
| where RegistryKey has @"\CurrentVersion\Run"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

### Named-pipe / WMI persistence (T1021.002 / T1047)

Schema assumed: Sysmon EID 17/18 (pipes), EID 19/20/21 (WMI); Sentinel `DeviceEvents` (`ActionType` for named-pipe / WMI events).

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

## Detection output shape

When the report emits a **detection** (not just a hunt), attach the operational metadata that makes it deployable. Match the structured `hunting_queries` schema (objective, platform, query, schema_dependency, assumptions, tuning, validation):

- **Objective** — the analyst goal in one line.
- **Query** — the SPL/KQL above with placeholders resolved (or a discovery query if unresolved).
- **schema_dependency** — datasets + fields the query assumes; the single fact that would remove ambiguity.
- **Assumptions** — normalized vs raw, time window, parser/connector caveats.
- **Tuning** — threshold options, false-positive levers, suppression ideas, field substitutions for alternate schemas.
- **Validate** — how to confirm it fires (detonate the TTP in a lab, replay a known-bad sample) before production.

## Translation (SPL ⇄ KQL)

Preserve intent before syntax: map scope → filters → parsing → aggregation. If no safe one-to-one mapping exists (e.g. the SPL index has no documented Sentinel table equivalent), say so and provide the closest operational pattern plus a discovery query — do not assert a table name on faith.

## Honesty parity

Unknown schema is marked, never guessed — the SIEM counterpart of R3. A detection that depends on an unverified `index`/`sourcetype`/table is emitted as a discovery query with `status: needs schema`, recorded in Intelligence Gaps, and never stamped as a ready-to-deploy rule.
