# Cyber Threat Intelligence Prompt Toolkit

A structured prompt toolkit for generating comprehensive cyber threat intelligence analysis using AI assistants (Microsoft Copilot, ChatGPT, Claude, etc.).

---

## What Is This?

This project provides a detailed, structured prompt template that guides AI assistants to produce professional-grade threat intelligence reports. It includes:

- **A comprehensive prompt** ([cyber_threat_prompt.md](cyber_threat_prompt.md)) -- the main template you paste into an AI assistant
- **A skill specification** ([cyber_threat_skill.yaml](cyber_threat_skill.yaml)) -- personas, scoring models, and analysis workflows
- **A JSON schema** ([schema_json.json](schema_json.json)) -- validates structured output
- **Example outputs** ([examples_outputs.json](examples_outputs.json)) -- sample reports for all 6 personas

This is **not** a standalone product or platform. It is a prompt engineering toolkit that leverages AI assistants' existing knowledge to produce structured threat intelligence analysis.

---

## How to Use Each File

### 1. The Prompt Template -- `cyber_threat_prompt.md`

This is the core of the toolkit. Copy and paste the entire contents into any AI assistant to generate a threat intelligence report.

**Basic usage (no input needed):**
1. Open your preferred AI assistant (Copilot, ChatGPT, Claude, etc.)
2. Paste the full contents of [cyber_threat_prompt.md](cyber_threat_prompt.md)
3. The AI will immediately generate a full technical IOC package using defaults: all emerging threats from the last 7 days targeting network edge devices, endpoints, mobile, APIs, and payment systems

**Custom usage:**
1. Paste the prompt
2. Before or after pasting, provide your own parameters:
   - **Search scope** -- narrow to a specific threat (e.g., "focus on ransomware targeting healthcare")
   - **Time range** -- change from the default 7 days (e.g., "last 24 hours" or "last 90 days")
   - **Assets** -- specify your environment (e.g., "AWS cloud infrastructure and Kubernetes")
   - **Detail level** -- request executive-level or technical summary instead of full technical

**What you get back:**
- Prioritized threat list with MITRE ATT&CK mappings
- IOCs (IPs, domains, hashes, behavioral indicators) formatted for SIEM/EDR import
- Detection rules in YARA, Sigma, KQL, SPL, and Snort/Suricata formats
- CSV and STIX 2.1 exports ready for ingestion
- Recommended actions matrix with owners and timelines

**Example queries to add after pasting the prompt:**
```
What ransomware groups are currently targeting financial services?
```
```
Generate a board-ready cyber risk briefing for our digital transformation initiative.
```
```
I think I clicked a phishing link. What should I do?
```

### 2. The Skill Specification -- `cyber_threat_skill.yaml`

This YAML file is a reference specification, not something you paste into an AI. It defines:

- **Persona profiles** -- how the output adapts for SOC analysts, executives, SMBs, researchers, individuals, and red teamers
- **Threat scoring model** -- the weighted formula (exploitability, impact, relevance, urgency) and priority levels (P1-P5)
- **Input configuration** -- all the questions the prompt asks and their valid options
- **Analysis workflows** -- the step-by-step process the prompt follows
- **Source categories** -- the 9 tiers of intelligence sources with priorities

**When to use it:**
- As a reference when customizing the prompt for your organization
- As a configuration spec if building automation around the prompt
- To understand the scoring weights and how priorities are assigned
- To see the full list of persona-specific output adaptations

See [DOCS.md](DOCS.md) for the full human-readable documentation of this specification.

### 3. The JSON Schema -- `schema_json.json`

This is a JSON Schema (draft-07) that defines the structure of valid threat intelligence output. Use it to validate that AI-generated output conforms to the expected format.

**When to use it:**
- Validate AI output programmatically before feeding it into your SIEM or TIP
- Build parsers that extract IOCs from the structured JSON output
- Integrate with automation pipelines that expect consistent output format

**How to validate output:**
```bash
pip install jsonschema
jsonschema -i your-output.json schema_json.json
```

**What it defines:**
- IOC schemas (network, host, email, behavioral) with required fields, types, and enums
- TTP mapping structure aligned to MITRE ATT&CK
- Threat actor profiles with attribution confidence
- Vulnerability forecasts with EPSS scores and exploit maturity
- Threat scoring dimensions and priority levels
- Detection rule containers (Sigma, YARA, Snort, KQL, SPL)

### 4. Example Outputs -- `examples_outputs.json`

This file contains complete example outputs for all 6 personas so you can see exactly what the prompt generates before using it.

**When to use it:**
- Preview what each persona's output looks like before choosing one
- Use as test fixtures when building parsers or integrations
- Reference when customizing the prompt -- see what fields are generated
- Validate your schema setup by running examples through the validator

**Examples included:**

| Persona | Example | What it shows |
|---------|---------|---------------|
| Enterprise SOC | Ransomware threat analysis | Full IOCs, Sigma/YARA/KQL rules, MITRE mappings |
| Executive | Board-ready threat brief | Risk dashboard, financial impact, investment recommendations |
| SMB Security | Ransomware protection checklist | Step-by-step actions with costs and difficulty ratings |
| Researcher | APT29 TTP deep dive | Lab exercises, methodology walkthrough, detection queries |
| Individual | Family online safety guide | Jargon-free tips, device setup instructions, scam alerts |
| Red Team | AWS cloud attack paths | Attack chains, tool recommendations, evasion techniques |

**Validate examples against the schema:**
```bash
# Extract a single example and validate
python -c "
import json
with open('examples_outputs.json') as f:
    data = json.load(f)
print(json.dumps(data['examples'][0]['output'], indent=2))
" > test_output.json

jsonschema -i test_output.json schema_json.json
```

---

## Supported Personas

The prompt adapts its output based on audience:

| Persona | Output Style | Key Features |
|---------|--------------|--------------|
| Enterprise SOC | Technical depth | IOCs, detection rules, MITRE ATT&CK mapping |
| Executive | Business focus | Risk dashboards, financial impact, peer comparison |
| SMB Security | Actionable checklists | Budget-conscious, step-by-step guides |
| Researcher | Learning-focused | Methodology explanations, lab exercises |
| Individual | Jargon-free | Family safety, personal device protection |
| Red Team | Exploit-focused | Attack chains, tool recommendations |

---

## Repository Structure

```
threat-intel/
├── README.md                  # This file
├── cyber_threat_prompt.md     # Main prompt template
├── cyber_threat_skill.yaml    # Skill specification (personas, scoring, workflows)
├── DOCS.md                    # Detailed documentation
├── schema_json.json           # JSON Schema for output validation
├── examples_outputs.json      # Example outputs for all personas
├── CHANGELOG.md               # Version history
├── CONTRIBUTING.md            # Contribution guidelines
├── LICENSE                    # MIT License
├── CLAUDE.md                  # AI assistant project context
└── .gitignore                 # Git ignore rules
```

---

## Intelligence Source Tiers

The prompt references 150+ sources organized by priority:

| Tier | Category | Examples |
|------|----------|----------|
| 1 | Vulnerability Databases | NVD, CISA KEV, Exploit-DB, CVE Details, ExploitPack, OpenCVE |
| 2 | Commercial Threat Intel | Recorded Future, Mandiant, CrowdStrike, Microsoft, Cisco Talos |
| 3 | Search Engines & Aggregators | Shodan, Censys, VirusTotal, GreyNoise, Nuclei Templates |
| 4 | Bug Bounty Platforms | HackerOne, Bugcrowd, Synack, Intigriti |
| 5 | Offensive Security Resources | OffSec, ExploitPack, HackTheBox, PortSwigger, TryHackMe |
| 6 | Community & Blogs | r/netsec, r/hacking, r/bugbounty, r/ExploitDev, r/sysadmin, Krebs on Security |
| 7 | Dark Web Intel | Flashpoint, Intel 471, DarkOwl, Cybersixgill, SOCRadar |
| 8 | Government Advisories | CISA, FBI, NSA, NCSC, ENISA, FS-ISAC, JPCERT/CC |
| 9 | Malware Analysis | MalwareBazaar, URLhaus, ThreatFox, Malpedia, Cape Sandbox |

These are reference sources for the AI to draw from, not live API integrations.

---

## Output Formats

The prompt supports several output structures:

- **Executive Brief** -- 2-page summary with threat dashboard and action items
- **Full Technical Report** -- IOCs, TTPs, detection rules, MITRE ATT&CK mapping
- **IOC Package** -- Exportable indicators for SIEM/EDR ingestion
- **Personal Security Guide** -- Jargon-free guidance for individuals
- **Checklist** -- Prioritized action items for resource-constrained teams

### Detection Rule Formats

The prompt can generate detection rules in: YARA, Sigma, Snort/Suricata, KQL (Microsoft Sentinel), SPL (Splunk)

### IOC Formats

Structured IOC output supports: STIX 2.1, OpenIOC, CSV, JSON, MISP, pipe-delimited (doze_sec)

---

## Threat Scoring

The prompt uses a multi-dimensional scoring model for prioritization:

```
Score = (Exploitability x 0.25) + (Impact x 0.25) +
        (Relevance x 0.30) + (Urgency x 0.20)
```

| Priority | Score | Suggested Response Time |
|----------|-------|-------------------------|
| P1-CRITICAL | 90-100 | 0-4 hours |
| P2-HIGH | 75-89 | 4-24 hours |
| P3-MEDIUM | 50-74 | 1-7 days |
| P4-LOW | 25-49 | 7-30 days |
| P5-INFO | 0-24 | Awareness only |

---

## Compliance Mapping

The prompt can map findings to common frameworks:

- NIST CSF 2.0
- ISO 27001:2022
- PCI DSS 4.0
- DORA (EU)
- SOX Section 404
- GDPR
- NYDFS 23 NYCRR 500

---

## Limitations

- This toolkit guides AI output structure; it does not guarantee accuracy. Always verify critical findings.
- Source references are for the AI to draw from -- there are no live API integrations.
- Output quality depends on the AI model used and its training data.
- Detection rules and IOCs generated should be reviewed before deployment.
- This is not a replacement for professional threat intelligence services or incident response.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Links

- [Repository](https://github.com/kj299/threat-intel)
- [Issues](https://github.com/kj299/threat-intel/issues)
- [Changelog](CHANGELOG.md)
