# Security Policy

This repository is a packaged [Anthropic Agent Skill](https://code.claude.com/docs/en/skills)
plus `threat-intel-mcp`, an MCP server that holds API credentials for up to ten
commercial threat-intelligence feeds. The credential handling is the part most
worth reporting a bug in.

It is a small project maintained by one person. The commitments below are
deliberately modest so they can actually be kept.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting:**
[Report a vulnerability](https://github.com/kj299/threat-intel/security/advisories/new).

That channel is used rather than an email address because this project has no
security mailing list, and publishing a personal address here would be
[fictional infrastructure](CLAUDE.md) of the kind the repository's own
conventions forbid. GitHub's form delivers privately to the maintainer and
gives you a thread to track the response in.

**Please do not open a public issue for a security problem.** Public issues are
the right place for everything else.

### What to include

- What an attacker can do, and what they need in order to do it
- The affected file or component, and a version or commit if you have one
- A reproduction, ideally the smallest one that works

### What to expect

| | |
|---|---|
| Acknowledgement | Best effort, typically within a week |
| Assessment and plan | With the acknowledgement, or shortly after |
| Fix | Depends entirely on severity and scope |
| Credit | Offered in the changelog unless you'd rather not |

There is no bug bounty and no guaranteed response time. If a report goes
unanswered for two weeks, opening a public issue that says only *"awaiting a
response on a private report"* — with no detail — is a reasonable nudge.

## Supported versions

The `main` branch is what is supported. Fixes land there; there is no
backporting to earlier tags, and released versions are not maintained in
parallel. Pin a tag if you need stability, but track `main` for fixes.

## What is in scope

Most valuable first:

- **Credential handling** in `mcp/src/threat_intel_mcp/vault/` — leakage through
  logs, error messages, tool responses, or subprocess environments
- **The egress allowlist** (`netpolicy.py`) — anything that reaches a host it
  should not
- **Sanitisation and validation** (`sanitize.py`, `normalize.py`, `vulns.py`) —
  malformed or hostile upstream feed data reaching a consumer unfiltered
- **Prompt injection through retrieved content.** The skill's whole job is
  ingesting adversary-controlled text. A feed entry that makes it misreport its
  own coverage, drop its intelligence-gaps section, or emit fabricated
  indicators is a real finding — see `evals/` for the resistance checks that
  already exist (issue #83)
- **Anything that puts a feed credential into the agent's reach** in
  `.github/workflows/scheduled-report.yml` — CI blocks this (issue #149), so a
  bypass is worth reporting

## What is out of scope

- **The accuracy of any generated report.** The skill structures AI output and
  is explicit that it does not guarantee correctness. A wrong finding is not a
  vulnerability; a report that *lies about its own coverage* is, and belongs
  under prompt injection above.
- **Vulnerabilities in the upstream feeds themselves** — report those to the
  feed operator.
- **Missing hardening with no demonstrated impact.** A concrete path to harm
  makes a report actionable; a scanner's output on its own usually does not.

## What this project already does

So you can tell the difference between a gap and a deliberate choice:

- Credentials are never committed. `.env` is git-ignored, `mcp/.env.example`
  carries names only, and vcrpy cassettes are scrubbed with the scrubbing
  itself asserted in CI (issue #111).
- Audit logging redacts credential-shaped values (`audit.py`).
- Each adapter carries an egress allowlist; feeds cannot be pointed elsewhere
  by configuration alone.
- HashiCorp Vault is supported for non-local deployments;
  `EnvCredentialProvider` documents itself as development-only.
- The report-generation workflow is barred by CI from holding feed
  credentials at all, because it runs an agent over untrusted content.
