"""Docs-as-code guards.

Two of this project's worst bugs were documentation that contradicted the code
and would break a real operator: the Vault ``kv put`` path pointing where the
provider never reads (issue #55), and the VirusTotal env var documented as
``VT_API_KEY`` while the provider only ever reads ``VIRUSTOTAL_API_KEY``. Prose
isn't exercised until someone follows it, so these tests exercise it.
"""

from __future__ import annotations

import pathlib
import re

_MCP_DIR = pathlib.Path(__file__).resolve().parents[1]
_ADAPTERS_DIR = _MCP_DIR / "src" / "threat_intel_mcp" / "adapters"
_ENV_EXAMPLE = _MCP_DIR / ".env.example"
_README = _MCP_DIR / "README.md"

# Every (adapter_name, key) the code reads from the CredentialProvider.
_CRED_RE = re.compile(r'credentials\.get\(\s*"([a-z0-9_]+)"\s*,\s*"([a-z_]+)"')


def _code_credentials() -> set[tuple[str, str]]:
    creds: set[tuple[str, str]] = set()
    for py in _ADAPTERS_DIR.glob("*.py"):
        creds |= set(_CRED_RE.findall(py.read_text(encoding="utf-8")))
    return creds


def test_every_adapter_credential_documented_in_env_example():
    """Each ``credentials.get(adapter, key)`` in the adapters maps to env var
    ``{ADAPTER}_{KEY}`` (EnvCredentialProvider's convention). That exact var must
    appear in .env.example — the check that would have caught the VT_API_KEY bug
    (adapter reads virustotal/api_key -> VIRUSTOTAL_API_KEY, docs said VT_API_KEY)."""
    env_text = _ENV_EXAMPLE.read_text(encoding="utf-8")
    creds = _code_credentials()
    assert creds, "no credentials.get(...) calls found — regex/refactor drift?"
    missing = []
    for adapter, key in sorted(creds):
        env_var = f"{adapter.upper()}_{key.upper()}"
        if not re.search(rf"\b{re.escape(env_var)}\b", env_text):
            missing.append(env_var)
    assert not missing, f"env vars read by adapters but undocumented in .env.example: {missing}"


def test_vault_kv_put_examples_match_provider_path_convention():
    """VaultCredentialProvider reads ``{mount}/data/{adapter}/{key}`` — i.e. the
    ``kv put`` target must be ``secret/<adapter>/<key>`` (three path segments).
    The original #55 docs wrote ``secret/<adapter>`` (two), which the provider
    never reads. Guard the shape."""
    readme = _README.read_text(encoding="utf-8")
    puts = re.findall(r"vault kv put (secret/\S+)", readme)
    assert puts, "no 'vault kv put secret/...' examples found in mcp/README.md"
    bad = []
    for path in puts:
        segments = path.split("/")
        # secret / <adapter> / <key>
        if len(segments) != 3 or segments[0] != "secret":
            bad.append(path)
    assert not bad, f"vault kv put paths not in secret/<adapter>/<key> form: {bad}"


def test_env_example_keys_match_documented_key_source_comments():
    """The uncommented ``NAME=...`` assignments in .env.example are exactly the
    env vars the adapters read — no orphan doc-only vars, no undocumented ones."""
    env_text = _ENV_EXAMPLE.read_text(encoding="utf-8")
    assigned = set(re.findall(r"^([A-Z][A-Z0-9_]+)=", env_text, re.MULTILINE))
    expected = {f"{a.upper()}_{k.upper()}" for a, k in _code_credentials()}
    # .env.example may legitimately omit nothing here; both directions must match.
    assert expected <= assigned, f"adapter creds missing an assignment: {expected - assigned}"


# --- Skill ⟷ server tool parity -------------------------------------------

_REPO_ROOT = _MCP_DIR.parent
_SERVER_PY = _MCP_DIR / "src" / "threat_intel_mcp" / "server.py"
_SKILL_FILES = (
    _REPO_ROOT / "skills" / "cyber-threat-intel" / "SKILL.md",
    _REPO_ROOT / "standalone" / "cyber-threat-intel-skill.md",
)

# Tool names registered on the FastMCP server.
_TOOL_DEF_RE = re.compile(r"@mcp\.tool\(\)\s*\nasync def (\w+)")
# Backticked identifiers in the skill docs that are meant to be MCP tool names.
_DOC_TOOL_RE = re.compile(r"`(fetch_all_\w+|\w+_fetch_\w+|abuseipdb_fetch_blocklist|list_available_feeds)`")


def test_skill_docs_name_exactly_the_registered_tools():
    """Every tool registered in server.py is named in BOTH skill files, and no
    skill file names a tool that isn't registered.

    The skill's Workflow step 2a instructs Claude to call these tools by name.
    A tool renamed or added in server.py without updating the skill (or vice
    versa) makes the skill call a nonexistent function — silently, at runtime,
    in a user's session. This is the same docs-drift class as the VT_API_KEY
    and Vault-path bugs; nothing else guards this seam (issue #79).
    """
    registered = set(_TOOL_DEF_RE.findall(_SERVER_PY.read_text(encoding="utf-8")))
    assert registered, "no @mcp.tool() registrations found — regex/refactor drift?"

    for skill_file in _SKILL_FILES:
        documented = set(_DOC_TOOL_RE.findall(skill_file.read_text(encoding="utf-8")))
        missing = registered - documented
        phantom = documented - registered
        assert not missing, (
            f"{skill_file.name}: registered tools not documented: {sorted(missing)}"
        )
        assert not phantom, (
            f"{skill_file.name}: documents tools that do not exist in server.py: "
            f"{sorted(phantom)}"
        )
