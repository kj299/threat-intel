# Contributing

Thank you for your interest in contributing to the Cyber Threat Intelligence Skill.

---

## How to Contribute

### Reporting Issues

- Check [existing issues](https://github.com/kj299/threat-intel/issues) first
- Include: what you tried, what you expected, what happened
- Mention which AI assistant you used (Claude, Copilot, ChatGPT, etc.)

### Suggesting Improvements

- Open an issue describing the improvement
- Include example inputs/outputs if applicable
- Note which persona(s) it affects

### Submitting Changes

1. Fork the repository
2. Create a branch (`git checkout -b feature/your-change`)
3. Make your changes
4. **Validate locally** (see Testing Changes section below)
5. Commit with a clear message (see Commit Message Examples section below)
6. Push and open a Pull Request

### Testing Your Changes Locally

> A GitHub Actions workflow ([`validate`](.github/workflows/validate.yml)) runs the same JSON/YAML/schema-conformance checks on every PR. Catching errors locally is faster, but the server check is the source of truth.

Before submitting a PR, validate your changes:

**If you edited YAML:**
```bash
python -c "import yaml; yaml.safe_load(open('skills/cyber-threat-intel/spec.yaml', encoding='utf-8'))"
# No output = success. If error appears, fix it before committing.
```

**If you edited JSON:**
```bash
python -m json.tool skills/cyber-threat-intel/schemas/output.schema.json > /dev/null
python -m json.tool skills/cyber-threat-intel/examples/outputs.json > /dev/null
# If no error output appears, JSON is valid.
```

**If you edited markdown files:**
```bash
# Check for broken links (case-sensitive)
grep -r "\[.*\](.*\.md)" *.md skills/ | grep -i CONTRIBUTING
grep -r "\[.*\](.*\.md)" *.md skills/ | grep -i CHANGELOG
# Both should return lowercase filenames: contributing.md, changelog.md
```

**If you edited `SKILL.md`:**
- Frontmatter must remain valid YAML between `---` fences with `name: cyber-threat-intel` and a `description` ≤1024 chars
- Body should stay under 500 lines (offload detail to `references/`); CI enforces both
- Every Markdown link (e.g. `[label](relative/path)`) should resolve to a file under `skills/cyber-threat-intel/`

**After editing the prompt or skill file:**
- Read through the full file to ensure changes are reflected consistently
- If you add a source, verify it's tagged `[MUST]` or `[SHOULD]` in `skills/cyber-threat-intel/references/source-matrix.md` *and* `skills/cyber-threat-intel/references/original-prompt.md`
- If you modify source coverage rules (R1-R6), update all references in `SKILL.md`, `references/`, `original-prompt.md`, `spec.yaml`, and both `standalone/` distributions

**If you bumped the version:**
The version string lives in four places. CI fails if they disagree. Bump all four together (source of truth: `skills/cyber-threat-intel/spec.yaml` -> `skill.version`):

1. `skills/cyber-threat-intel/spec.yaml` -> `skill.version`
2. `skills/cyber-threat-intel/schemas/output.schema.json` -> `version`
3. `changelog.md` -> add a new `## [X.Y.Z] - YYYY-MM-DD` section above existing entries
4. `skills/cyber-threat-intel/examples/outputs.json` -> every example's `metadata.skill_version`

**If you added or removed a persona:**
The set of personas in `skills/cyber-threat-intel/spec.yaml` (`persona_profiles` keys) must match exactly the set of `persona` values across `skills/cyber-threat-intel/examples/outputs.json` examples -- one example per persona, no missing, no extras. CI fails on drift. Update `skills/cyber-threat-intel/references/personas.md` to match.

**If you changed `output.schema.json`:**
CI also runs negative fixtures from `tests/invalid/` to prove the schema still rejects malformed input (missing required fields, bad enums, R2 placeholder source values like `"unknown"` / `"general knowledge"` / `"n/a"`, malformed `date-time`, bad `coverage_badge`, type/value mismatches, malformed hashes). Layout: `tests/invalid/<def_name>/<case>.json`, where `<def_name>` matches a key in `output.schema.json` `definitions/` (or `skill_output_metadata` for the metadata block). When loosening a constraint, also remove or update the corresponding fixture; when tightening one, add a fixture for the new rejection.

**If you added a new IOC value:**
Hashes (`MD5`, `SHA1`, `SHA256`, `SHA512`) are length-pinned hex -- placeholders like `"a1b2c3d4...[truncated]"` will fail validation. Use a full-length illustrative value (e.g. 64 hex chars for SHA256). For network IOCs, defanged forms (`update-service[.]cloud`, `185[.]220[.]101[.]50`) and `xxx`-redacted IPs are accepted; pure type/value mismatches (e.g. `IPv4` carrying `"example.com"`, `Domain` carrying `"12345"`) are rejected. URL pattern enforcement is out of scope -- defanged URL forms vary too much to encode reliably.

**If you added, removed, or renamed a source tier:**
Four files describe the nine-tier source matrix and CI requires they stay in sync:
1. `skills/cyber-threat-intel/references/original-prompt.md` -- one `### Tier N: <name>` heading per tier (canonical for tier-name parity check)
2. `skills/cyber-threat-intel/references/source-matrix.md` -- mirrored source list with `## Tier N: <name>` headings
3. `skills/cyber-threat-intel/spec.yaml` -- `source_coverage_protocol.tier_minimums` keys and `source_tiers` keys (both prefixed `tier_<N>_...`)
4. `skills/cyber-threat-intel/schemas/output.schema.json` -- the `coverage_ledger.items.properties.tier` `minimum`/`maximum` range

CI fails if the set of tier numbers disagrees across these sources, or if a prompt heading and the corresponding `source_tiers.<name>` share no significant word. The name-overlap check is intentionally lenient (token intersection, not string equality) so different abbreviations of the same domain across files are fine.

**If you edited an example's `coverage_ledger` or coverage metadata:**
CI cross-checks each example with coverage data. If any of `coverage_ledger`, `metadata.sources_referenced`, or `metadata.coverage_badge` is present, all three must be, and the following must hold:
- `sources_referenced` equals the sum of `len(entry.consulted)` across the ledger
- `coverage_badge` matches the badge derived from that total against `skills/cyber-threat-intel/spec.yaml` (`must_minimum_total` for FULL, half of it for PARTIAL/MINIMAL)
- Each ledger entry's `required_min` matches the YAML `tier_minimums` value for that tier (with `best-effort`/`best_effort` treated as equivalent)
- For numeric `required_min`, `met` equals `len(consulted) >= required_min`
- Every numeric tier defined in YAML appears in the ledger

### Commit Message Examples

**Bad commit messages:**
```
update
fix stuff
changes
```

**Good commit messages:**
```
feat: add Tor Project to Tier 3 search engines

Adds Tor Project directory as SHOULD-source for anonymous infrastructure reconnaissance.
Aligns with existing coverage tier requirements and improves search engine diversity.

feat: add KQL detection rule for Cobalt Strike beacon patterns

Adds new detection rule for identifying Cobalt Strike beacon C2 communication.
Includes behavioral IOC for beacon metadata structure.
Applies to enterprise_soc and red_team personas.

fix: correct NIST CSF mapping for incident response section

Updates compliance mapping reference from ID.RA-1 to RS.AN-2 per NIST CSF 2.0 specification.

docs: clarify source coverage protocol in README

Expands explanation of the R1-R6 source-coverage guidance with examples.
Adds note about preferred (MUST) vs optional (SHOULD) source priorities.
```

Format: `<type>: <description>` where type is one of:
- `feat` — new feature, source, or persona
- `fix` — bug fix or correction
- `docs` — documentation improvements
- `refactor` — code structure improvement (rarely needed)
- `chore` — maintenance task

### What Makes a Good Contribution

**Accepted:**
- Adding new intelligence sources (with verification they exist)
- Improving persona definitions or output templates
- New detection rule formats or examples
- Documentation corrections and clarity improvements
- Typo fixes
- Expanding compliance framework mappings
- Translations or localization efforts

**Not Accepted:**
- Changes that weaken the no-fabrication rule (R3) or the honest-reporting framing of the Source Coverage Protocol (R1-R6) — e.g. re-introducing "pad the coverage to hit the number" behavior
- Unsourced IOCs, CVEs, or threat actor attributions presented as confirmed
- Modifications to the source coverage targets without clear justification
- Re-introducing output engineered to flow straight into a downstream tool's execution path (the consuming tool owns input validation/sanitization)
- Removal of established personas or breaking changes to the output schema
- Active exploit code or other content that violates security guidelines (see Security section)

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
