# Contributing to SENTINEL-X

Thank you for your interest in contributing to SENTINEL-X! This document provides guidelines and instructions for contributing to this cyber threat intelligence skill.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Contribution Workflow](#contribution-workflow)
- [Style Guidelines](#style-guidelines)
- [Testing Requirements](#testing-requirements)
- [Documentation Standards](#documentation-standards)
- [Security Considerations](#security-considerations)
- [Recognition](#recognition)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming, inclusive, and harassment-free experience for everyone. We pledge to act and interact in ways that contribute to an open, diverse, and healthy community.

### Standards

**Positive behaviors include:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Unacceptable behaviors include:**
- Harassment, trolling, or insulting comments
- Publishing others' private information
- Sharing malicious code or exploits without authorization
- Any conduct that could be considered inappropriate in a professional setting

### Enforcement

Violations may be reported to security-ops-conduct@example.com. All complaints will be reviewed and investigated promptly and fairly.

---

## How Can I Contribute?

### 🐛 Reporting Bugs

Before creating a bug report:
1. Check the [existing issues](https://github.com/security-ops/sentinel-x/issues) to avoid duplicates
2. Collect relevant information (version, persona, inputs used)
3. Try to reproduce the issue

**Bug Report Template:**

```markdown
## Bug Description
[Clear description of the bug]

## Environment
- SENTINEL-X Version: [e.g., 3.0.0]
- Platform: [e.g., Microsoft Copilot, Copilot Studio]
- Persona: [e.g., enterprise_soc]

## Steps to Reproduce
1. [First step]
2. [Second step]
3. [...]

## Expected Behavior
[What you expected to happen]

## Actual Behavior
[What actually happened]

## Screenshots/Logs
[If applicable]

## Additional Context
[Any other relevant information]
```

### 💡 Suggesting Features

Feature requests are welcome! Please include:

```markdown
## Feature Description
[Clear description of the proposed feature]

## Use Case
[Who would benefit and how?]

## Persona Applicability
- [ ] Enterprise SOC
- [ ] Enterprise Executive
- [ ] SMB Security
- [ ] Individual Researcher
- [ ] Individual Privacy
- [ ] Red Team

## Proposed Implementation
[Optional: How you envision this working]

## Alternatives Considered
[Other approaches you've considered]
```

### 🔒 Reporting Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead, email security-ops-security@example.com with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and work with you on remediation.

### 📚 Improving Documentation

Documentation improvements are always welcome:
- Fix typos or grammatical errors
- Clarify confusing sections
- Add examples for complex features
- Translate documentation
- Improve code comments

### 🔌 Adding Intelligence Sources

We actively welcome new intelligence source contributions:

```yaml
# Source Template
- name: "Source Name"
  url: "https://source.url"
  type: "blog|platform|database|search_engine|feed"
  data_types:
    - "threat_intel"
    - "IOCs"
    - "malware"
  priority: "critical|high|medium|low"
  update_frequency: "real-time|daily|weekly"
  requires_api_key: true|false
  free_tier_available: true|false
```

**Requirements for new sources:**
- Must be legitimate and reputable
- Must provide actionable threat intelligence
- Must have consistent availability (>95% uptime)
- Must not violate any terms of service
- Must include proper attribution

### 🎨 Creating Visualizations

Contribute new visualization types:
- Attack flow diagrams
- Risk matrices
- Trend charts
- Geographic maps
- Relationship graphs

### 🌐 Adding Translations

Help make SENTINEL-X accessible globally:
- Translate user-facing strings
- Localize date/time formats
- Adapt cultural references
- Review existing translations

---

## Development Setup

### Prerequisites

```bash
# Required
- Git
- Text editor with YAML support
- JSON Schema validator

# Recommended
- VS Code with YAML extension
- yamllint
- jsonschema CLI
```

### Local Setup

```bash
# Clone the repository
git clone https://github.com/security-ops/sentinel-x.git
cd sentinel-x

# Install validation tools
pip install yamllint jsonschema

# Validate YAML syntax
yamllint sentinel-x-skill.yaml

# Validate against schema
jsonschema -i test-output.json schema.json
```

### Directory Structure

```
sentinel-x/
├── sentinel-x-skill.yaml    # Main skill definition
├── SKILL.md                  # Documentation with frontmatter
├── schema.json               # JSON Schema for validation
├── CHANGELOG.md              # Version history
├── CONTRIBUTING.md           # This file
├── LICENSE                   # License file
├── examples/                 # Example outputs
│   ├── enterprise_soc/
│   ├── enterprise_executive/
│   ├── smb_security/
│   ├── individual_researcher/
│   ├── individual_privacy/
│   └── red_team/
├── tests/                    # Test files
│   ├── inputs/
│   └── expected_outputs/
└── integrations/             # Integration configs
    ├── splunk/
    ├── sentinel/
    └── misp/
```

---

## Contribution Workflow

### 1. Fork and Clone

```bash
# Fork via GitHub UI, then:
git clone https://github.com/YOUR-USERNAME/sentinel-x.git
cd sentinel-x
git remote add upstream https://github.com/security-ops/sentinel-x.git
```

### 2. Create a Branch

```bash
# Use descriptive branch names
git checkout -b feature/add-new-source
git checkout -b fix/ioc-parsing-bug
git checkout -b docs/improve-examples
```

### 3. Make Changes

- Follow the [Style Guidelines](#style-guidelines)
- Include tests for new features
- Update documentation as needed

### 4. Validate Changes

```bash
# Validate YAML
yamllint sentinel-x-skill.yaml

# Validate schema
jsonschema -i examples/test-output.json schema.json

# Run tests
./scripts/run-tests.sh
```

### 5. Commit Changes

```bash
# Use conventional commits
git commit -m "feat: add new threat intel source XYZ"
git commit -m "fix: correct IOC parsing for IPv6 addresses"
git commit -m "docs: add example for red team persona"
```

**Commit Message Format:**

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting (no code change)
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

### 6. Push and Create PR

```bash
git push origin feature/add-new-source
```

Then create a Pull Request via GitHub with:
- Clear title and description
- Reference to related issues
- Screenshots/examples if applicable
- Checklist of completed items

---

## Style Guidelines

### YAML Style

```yaml
# DO: Use 2-space indentation
persona_profiles:
  enterprise_soc:
    name: "Enterprise SOC"
    
# DON'T: Use tabs or 4-space indentation
persona_profiles:
    enterprise_soc:
        name: "Enterprise SOC"

# DO: Quote strings with special characters
description: "Multi-line description
  that continues here"

# DO: Use lowercase_snake_case for keys
threat_scoring_engine:
  scoring_dimensions:
  
# DON'T: Use camelCase or PascalCase
threatScoringEngine:
  ScoringDimensions:

# DO: Add comments for complex sections
# This section defines the AI cognitive capabilities
ai_capabilities:
  cognitive_pattern_engine:
```

### Documentation Style

```markdown
# DO: Use clear, concise language
The threat scoring engine calculates risk using four dimensions.

# DON'T: Use jargon without explanation
The TSE leverages multidimensional vector analysis for risk quantification.

# DO: Include examples
Example: `threat_score = exploitability * 0.25 + impact * 0.25 + ...`

# DO: Use tables for comparisons
| Feature | v2.0 | v3.0 |
|---------|------|------|
| Sources | 150  | 150+ |

# DO: Use code blocks for technical content
```yaml
scoring_dimensions:
  - dimension: "exploitability"
    weight: 0.25
```
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Files | lowercase-kebab | `threat-intel-skill.yaml` |
| YAML keys | lowercase_snake | `threat_scoring_engine` |
| Enum values | UPPERCASE or lowercase_snake | `"P1-CRITICAL"` or `"enterprise_soc"` |
| Documentation headers | Title Case | `## Threat Scoring Engine` |

---

## Testing Requirements

### Required Tests

All contributions must include:

1. **Syntax Validation**
   ```bash
   yamllint sentinel-x-skill.yaml
   ```

2. **Schema Validation**
   ```bash
   jsonschema -i output.json schema.json
   ```

3. **Persona Coverage**
   - Test with at least 2 personas if applicable

4. **Edge Cases**
   - Empty inputs
   - Maximum length inputs
   - Special characters

### Test File Template

```yaml
# tests/inputs/test-feature-name.yaml
test_name: "Feature Name Test"
description: "Tests the new feature"
inputs:
  user_persona: "enterprise_soc"
  query_mode: "guided"
  # ... other inputs

expected_outputs:
  - contains: "expected string"
  - matches_schema: true
  - alert_level: "high"
```

---

## Documentation Standards

### Required Documentation

All features must include:

1. **YAML Comments**: Explain complex logic
2. **SKILL.md Updates**: Document user-facing changes
3. **CHANGELOG.md Entry**: Version history
4. **Examples**: At least one example per persona affected

### Example Requirements

Each example must include:
- Input configuration
- Expected output (truncated if lengthy)
- Use case description
- Any prerequisites

```markdown
### Example: Ransomware Threat Brief

**Use Case:** SOC team needs latest ransomware intelligence

**Input:**
```yaml
user_persona: "enterprise_soc"
threat_categories: ["Ransomware"]
time_range: "7d"
output_format: "technical"
```

**Output:** (truncated)
```json
{
  "alert_level": "high",
  "threats": [
    {
      "technique_name": "LockBit 3.0",
      "mitre_attack_id": "T1486",
      ...
    }
  ]
}
```
```

---

## Security Considerations

### Sensitive Data

**NEVER** include in contributions:
- API keys or tokens
- Credentials
- Internal URLs
- PII or customer data
- Classified information
- Active exploit code

### Source Validation

When adding intelligence sources:
- Verify the source is legitimate
- Check for any legal restrictions
- Ensure compliance with terms of service
- Validate data quality and freshness

### Code Review

All security-related changes require:
- Review by at least 2 maintainers
- Security team approval for new integrations
- Vulnerability assessment for new code paths

---

## Recognition

### Contributors

All contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Eligible for contributor badges

### Contribution Levels

| Level | Requirements | Badge |
|-------|--------------|-------|
| 🌱 Contributor | 1+ merged PRs | Bronze |
| 🌿 Regular | 5+ merged PRs | Silver |
| 🌳 Core | 20+ merged PRs + maintainer approval | Gold |
| 🏆 Maintainer | Ongoing commitment + team approval | Platinum |

### Hall of Fame

Outstanding contributions may be featured in:
- Project README
- Release announcements
- Conference presentations
- Blog posts

---

## Questions?

- **General Questions**: Open a [Discussion](https://github.com/security-ops/sentinel-x/discussions)
- **Bug Reports**: Open an [Issue](https://github.com/security-ops/sentinel-x/issues)
- **Security Issues**: Email security-ops-security@example.com
- **Partnership Inquiries**: Email security-ops-partners@example.com

---

## License

By contributing, you agree that your contributions will be licensed under the same dual license as the project:
- **Enterprise**: Commercial license
- **Personal**: Free for individual use

---

Thank you for contributing to SENTINEL-X! Together, we're building the future of cyber threat intelligence. 🛡️