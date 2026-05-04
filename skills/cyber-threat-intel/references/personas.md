# Personas

Output and analysis depth adapt to persona. Structured definitions live in [../spec.yaml](../spec.yaml) under `persona_profiles`. This file is the human-readable summary.

| Persona | Output Style | Format | Distinguishing Features |
|---------|--------------|--------|-------------------------|
| `enterprise_soc` | Comprehensive technical | Structured report (STIX 2.1 IOCs) | Detection rules, playbooks, full threat modeling, attack simulation, deep supply-chain, insider-threat enabled |
| `enterprise_executive` | Executive summary | Visual dashboard (≤2 pages) | Financial impact, peer comparison, trend arrows, business-impact-only modeling |
| `smb_security` | Actionable | Checklist | Free-tool-first, step-by-step, budget-conscious; focus on ransomware, phishing, backups, MFA |
| `individual_researcher` | Technical deep-dive | Educational | Methodology and references, lab-safe simulations, learning-focused |
| `individual_privacy` | Simple actionable | Friendly guide | No jargon, includes "why"; focus on passwords, phishing, social-media privacy, device security, identity-theft prevention |
| `red_team` | Exploit-focused | Technical brief | PoC references, tool suggestions, attack-chain visualization, full-chain simulation, supply-chain exploitation vectors |

## Default Persona

If none specified: `enterprise_soc` with `output_format: technical_ioc_package`.

## Persona-Specific Output Sections

See [output-templates.md](output-templates.md) for the section list per persona.
