# Cyber Threat Intelligence Prompt Toolkit -- Skill Documentation

**Version:** 1.0.0 | **License:** MIT | **Author:** kj299 | **Last Updated:** 2026-03-30

**Supported Platforms:** Microsoft Copilot, ChatGPT, Claude, other LLM-based assistants

**Personas:** enterprise_soc, enterprise_executive, smb_security, individual_researcher, individual_privacy, red_team

## Overview

This is a structured prompt toolkit that guides AI assistants to produce professional-grade threat intelligence reports. It references 150+ intelligence sources, supports 6 user personas, and outputs structured analysis including IOCs, TTPs, detection rules, and executive summaries.

## How It Works

1. The user pastes the prompt template into their AI assistant
2. The AI assistant asks intake questions to scope the analysis
3. The user provides context (industry, time range, focus areas, detail level)
4. The AI generates a structured threat intelligence report adapted to the user's persona

## Personas

The toolkit adapts output style and depth based on who is asking:

### Enterprise SOC
- Comprehensive technical reports
- STIX 2.1 formatted IOCs
- Detection rules for SIEM/EDR (Sigma, YARA, KQL, SPL)
- Playbook recommendations
- Compliance mapping (NIST, ISO, PCI-DSS, DORA)

### Executive Leadership / Board
- 2-page executive briefs
- Business impact focus
- Risk heatmaps and trend indicators
- Peer benchmarking
- Investment recommendations

### Small/Medium Business (SMB)
- Actionable checklists
- Budget-conscious recommendations
- Prioritized free tools
- Step-by-step guides
- Focus on ransomware and phishing defense

### Security Researcher / Enthusiast
- Technical deep dives
- Methodology explanations
- Reference materials and further reading
- Lab exercises
- CTF and lab-safe content

### Privacy-Conscious Individual
- Simple, jargon-free language
- Personal device protection
- Family safety guidance
- Identity theft prevention
- Social media privacy tips

### Red Team / Penetration Tester
- Attack chain analysis
- Tool recommendations
- PoC references
- Simulation scenarios
- Detection opportunity notes

## Intelligence Source Tiers

The prompt references sources organized by priority:

| Tier | Category | Example Sources |
|------|----------|----------------|
| 1 | Vulnerability Databases | NVD, CISA KEV, Exploit-DB, Vulners, Packet Storm |
| 2 | Commercial Threat Intel | Recorded Future, Mandiant, CrowdStrike, Microsoft, Cisco Talos |
| 3 | Search Engines & Aggregators | Shodan, Censys, VirusTotal, GreyNoise |
| 4 | Bug Bounty Platforms | HackerOne, Bugcrowd, Synack |
| 5 | Offensive Security Resources | OWASP, HackTheBox, PortSwigger Academy |
| 6 | Community & Blogs | Reddit r/netsec, Krebs on Security, BleepingComputer |
| 7 | Dark Web Intel | Flashpoint, Intel 471, DarkOwl |
| 8 | Government Advisories | CISA, FBI, NSA, NCSC, ENISA, FS-ISAC |
| 9 | Malware Analysis | MalwareBazaar, URLhaus, Malpedia |

These are references for the AI to draw from based on its training data. There are no live API integrations.

## Threat Scoring

Multi-dimensional scoring for prioritization:

```
Score = (Exploitability x 0.25) + (Impact x 0.25) +
        (Relevance x 0.30) + (Urgency x 0.20)
```

| Priority | Score Range | Suggested Response Time |
|----------|-------------|-------------------------|
| P1-CRITICAL | 90-100 | 0-4 hours |
| P2-HIGH | 75-89 | 4-24 hours |
| P3-MEDIUM | 50-74 | 1-7 days |
| P4-LOW | 25-49 | 7-30 days |
| P5-INFO | 0-24 | Awareness only |

## Output Formats

### Reports
- Executive Brief (2 pages)
- Full Technical Report
- Personal Security Guide
- SOC IOC Package
- Actionable Checklist

### Export Formats
- **IOCs**: CSV, STIX 2.1, OpenIOC, JSON, MISP
- **Detection Rules**: YARA, Sigma, Snort, Suricata, KQL, SPL
- **Frameworks**: MITRE ATT&CK Navigator layers

## Compliance Mapping

The prompt can map findings to:

| Framework | Coverage Areas |
|-----------|---------------|
| NIST CSF 2.0 | ID.RA-1, ID.RA-2, ID.RA-3, PR.IP-12, RS.AN-1, RS.AN-2 |
| ISO 27001:2022 | A.5.7, A.8.8, A.8.9 |
| PCI DSS 4.0 | 5.2, 6.3, 11.3 |
| DORA (EU) | Article 13, 17, 19 |
| NYDFS 23 NYCRR 500 | 500.05, 500.07, 500.09 |
| SOX | Section 404 (IT Controls) |
| GDPR | Data breach notification |

## Usage Tips

- Be specific in your intake answers for better results
- Use the "Full Technical" detail level for SOC teams
- Use the "Executive" detail level for board presentations
- Always verify IOCs and detection rules before deploying to production
- Cross-reference critical findings with primary sources
- Output quality varies by AI model -- more capable models produce better results

## Limitations

- The AI draws from training data, not live feeds. Results reflect knowledge up to the model's cutoff date.
- Generated IOCs are illustrative examples based on known patterns, not real-time indicators.
- Detection rules should be tested in a lab environment before production deployment.
- This toolkit does not replace professional threat intelligence services or incident response capabilities.

## Schema Validation

Use [schema_json.json](schema_json.json) to validate structured output:

```bash
pip install jsonschema
jsonschema -i output.json schema_json.json
```

## Examples

See [examples_outputs.json](examples_outputs.json) for complete example outputs across all 6 personas.
