# Personas

Output and analysis depth adapt to persona. Structured definitions live in [../spec.yaml](../spec.yaml) under `persona_profiles`. This file is the human-readable summary.

| Persona | Output Style | Format | Distinguishing Features |
|---------|--------------|--------|-------------------------|
| `enterprise_soc` | Comprehensive technical | Structured report (STIX 2.1 IOCs) | Detection rules, playbooks, full threat modeling, attack simulation, deep supply-chain, insider-threat enabled |
| `enterprise_executive` | Executive summary | Visual dashboard (≤2 pages) — [renderable to HTML](#rendering-the-visual-dashboard) | Financial impact, peer comparison, trend arrows, business-impact-only modeling |
| `smb_security` | Actionable | Checklist | Free-tool-first, step-by-step, budget-conscious; focus on ransomware, phishing, backups, MFA |
| `individual_researcher` | Technical deep-dive | Educational | Methodology and references, lab-safe simulations, learning-focused |
| `individual_privacy` | Simple actionable | Friendly guide | No jargon, includes "why"; focus on passwords, phishing, social-media privacy, device security, identity-theft prevention |
| `red_team` | Exploit-focused | Technical brief | PoC references, tool suggestions, attack-chain visualization, full-chain simulation, supply-chain exploitation vectors |

## Default Persona

If none specified: `enterprise_soc` with `output_format: technical_ioc_package`.

## Persona-Specific Output Sections

See [output-templates.md](output-templates.md) for the section list per persona.

## Rendering the visual dashboard

`enterprise_executive` declares `format: visual_dashboard`, and the skill emits
the data for one — `risk_dashboard`, `financial_impact`,
`investment_recommendations` — as validated JSON. **The skill itself emits
markdown**; the dashboard is produced by rendering that JSON:

```bash
python -m threat_intel_mcp.render report.json -o overview.html
```

The result is a single self-contained landscape page (no external stylesheet,
script, font or image), suitable for emailing and printing.

Three properties of that renderer are deliberate and enforced by tests, because
a dashboard makes modelled numbers look measured:

- **Risk uses a sequential single-hue ramp, not red/amber/green.** Status hues
  are not monotonic in lightness — printed in greyscale, "moderate" comes out
  *lighter* than "low", so a photocopied traffic-light dashboard is worse than
  a table. The ramp darkens with severity, so paper and screen agree.
- **Nothing is encoded by colour alone.** Every score carries its numeral and
  band word; every trend carries an arrow *and* the word. Trend is not
  colour-coded at all — risk level and direction of travel are separate axes.
- **Modelled figures are labelled where they are displayed**, not in a
  footnote, and an absent coverage badge renders as `COVERAGE NOT REPORTED`
  rather than defaulting to something reassuring (R3, R4).

See issue #110 for the full rationale.
