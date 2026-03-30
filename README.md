# Cyber Threat Intelligence Prompt Toolkit

A structured prompt toolkit for generating comprehensive cyber threat intelligence analysis using AI assistants (Microsoft Copilot, ChatGPT, Claude, etc.).

---

## What Is This?

This project provides a detailed, structured prompt template that guides AI assistants to produce professional-grade threat intelligence reports. It includes:

- **A comprehensive prompt** ([cyber_threat_prompt.md](cyber_threat_prompt.md)) with intake questions, 150+ source references organized into tiers, extraction frameworks for IOCs/TTPs, and structured output templates
- **A skill specification** ([cyber_threat_skill.yaml](cyber_threat_skill.yaml)) defining personas, scoring models, and analysis workflows (see [DOCS.md](DOCS.md) for full documentation)
- **A JSON schema** ([schema_json.json](schema_json.json)) for validating structured output
- **Example outputs** ([examples_outputs.json](examples_outputs.json)) showing what generated reports look like across different personas

This is **not** a standalone product or platform. It is a prompt engineering toolkit that leverages AI assistants' existing knowledge to produce structured threat intelligence analysis.

---

## Quick Start

1. Open your preferred AI assistant (Copilot, ChatGPT, Claude, etc.)
2. Paste the contents of [cyber_threat_prompt.md](cyber_threat_prompt.md)
3. Answer the intake questions (scope, time range, business context, detail level)
4. Receive structured threat intelligence output

### Example Queries

**For a security team:**
```
What ransomware groups are currently targeting financial services?
```

**For an executive:**
```
Generate a board-ready cyber risk briefing for our digital transformation initiative.
```

**For an individual:**
```
I think I clicked a phishing link. What should I do?
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
└── .gitignore                 # Git ignore rules
```

---

## Intelligence Source Tiers

The prompt references 150+ sources organized by priority:

| Tier | Category | Examples |
|------|----------|----------|
| 1 | Vulnerability Databases | NVD, CISA KEV, Exploit-DB, Vulners |
| 2 | Commercial Threat Intel | Recorded Future, Mandiant, CrowdStrike |
| 3 | Search Engines & Aggregators | Shodan, Censys, VirusTotal, GreyNoise |
| 4 | Bug Bounty Platforms | HackerOne, Bugcrowd |
| 5 | Offensive Security Resources | OWASP, HackTheBox, PortSwigger |
| 6 | Community & Blogs | Reddit r/netsec, Krebs on Security, BleepingComputer |
| 7 | Dark Web Intel | Flashpoint, Intel 471, DarkOwl |
| 8 | Government Advisories | CISA, FBI, NSA, NCSC, ENISA |
| 9 | Malware Analysis | MalwareBazaar, URLhaus, Malpedia |

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

The prompt can generate detection rules in: YARA, Sigma, Snort, KQL (Microsoft Sentinel), SPL (Splunk)

### IOC Formats

Structured IOC output supports: STIX 2.1, OpenIOC, CSV, JSON, MISP

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
