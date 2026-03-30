# Contributing

Thank you for your interest in contributing to the Cyber Threat Intelligence Prompt Toolkit.

---

## How to Contribute

### Reporting Issues

- Check [existing issues](https://github.com/kj299/threat-intel/issues) first
- Include: what you tried, what you expected, what happened
- Mention which AI assistant you used (Copilot, ChatGPT, Claude, etc.)

### Suggesting Improvements

- Open an issue describing the improvement
- Include example inputs/outputs if applicable
- Note which persona(s) it affects

### Submitting Changes

1. Fork the repository
2. Create a branch (`git checkout -b feature/your-change`)
3. Make your changes
4. Validate YAML syntax if you edited the skill file (`yamllint cyber_threat_skill.yaml`)
5. Validate JSON if you edited the schema (`jsonschema -i examples_outputs.json schema_json.json`)
6. Commit with a clear message (`git commit -m "Add new intelligence source tier"`)
7. Push and open a Pull Request

### What We Welcome

- New or updated intelligence source references
- Improved extraction templates and output structures
- New persona profiles or persona refinements
- Better detection rule templates
- Documentation improvements
- Translations

---

## Style Guidelines

### YAML
- 2-space indentation
- `lowercase_snake_case` for keys
- Quote strings containing special characters

### Markdown
- Clear, concise language
- Tables for comparisons
- Code blocks for technical content

### Commit Messages
```
<type>: <description>

Types: feat, fix, docs, refactor, chore
```

---

## Security

Do not include in contributions:
- API keys, tokens, or credentials
- Internal URLs or PII
- Active exploit code without clear educational context

For security vulnerabilities, open a private issue or contact the maintainer directly.

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
