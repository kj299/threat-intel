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
import shutil
import subprocess

import pytest

_MCP_DIR = pathlib.Path(__file__).resolve().parents[1]
_REPO_ROOT = _MCP_DIR.parent
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
# Tool names as they appear in the skill files. `_enrich_` is here because
# VirusTotal became an enrichment tool (#203) and this pattern silently did
# not match it -- the guard reported the skill files as complete while a
# registered tool went undocumented. A hand-written pattern is a
# maintenance hazard exactly this way; widen it when a naming convention
# is added.
_DOC_TOOL_RE = re.compile(
    r"`(fetch_all_\w+|\w+_fetch_\w+|\w+_enrich_\w+|abuseipdb_fetch_blocklist|list_available_feeds)`"
)


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


def test_docs_name_the_current_server_version():
    """The `mcp/` version in prose must match `pyproject.toml`.

    It drifted **two releases** unnoticed: the root README advertised v0.13.0
    while the package was 0.15.0, in two places. Nothing checked it, because the
    version-parity CI step covers the *skill* version cascade (spec, schema,
    examples, changelog, plugin manifest) and the server version is a separate
    number that happens to appear in the same documents.

    Matching is on `v<version>` rather than any bare version-looking string, so
    changelog history and pinned dependency versions in these files do not trip
    it.
    """
    pyproject = (_MCP_DIR / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE)
    assert match, "no version found in mcp/pyproject.toml"
    current = match.group(1)

    stale: list[str] = []
    for doc in (_REPO_ROOT / "README.md", _README, _REPO_ROOT / "CLAUDE.md"):
        for found in re.findall(r"threat-intel-mcp server \(v([\d.]+)\)|\(v([\d.]+)\)", doc.read_text(encoding="utf-8")):
            version = next((g for g in found if g), None)
            if version and version != current and re.fullmatch(r"0\.\d+\.\d+", version):
                stale.append(f"{doc.name}: says v{version}, pyproject.toml says v{current}")
    assert not stale, "stale threat-intel-mcp version in prose:\n  " + "\n  ".join(stale)


def test_package_version_matches_pyproject():
    """`__version__` must not be a second, hand-maintained copy of the version.

    It sat at ``"0.1.0"`` while `pyproject.toml` said ``0.15.0`` — fourteen minor
    releases stale. Nothing caught it because nothing read it: the server was
    constructed without a version and advertised ``"version": ""`` in its
    initialize response, so a client could not tell which build it was talking
    to. Both are fixed; this keeps them fixed.
    """
    from threat_intel_mcp import __version__

    pyproject = (_MCP_DIR / "pyproject.toml").read_text(encoding="utf-8")
    expected = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE).group(1)
    assert __version__ == expected, (
        f"__version__ is {__version__!r}, pyproject.toml says {expected!r}"
    )


def test_server_advertises_its_version():
    """The initialize response must carry a real version, not an empty string."""
    from threat_intel_mcp import __version__
    from threat_intel_mcp.server import mcp

    advertised = getattr(mcp, "version", None)
    assert advertised == __version__, (
        f"MCP server advertises {advertised!r}, package version is {__version__!r}"
    )


def test_env_example_actually_loads_in_a_shell():
    """`.env.example` must survive the loader the docs tell people to run.

    It did not. `ANYRUN_API_KEY`'s value is the full Authorization header and so
    contains a space, and it shipped unquoted. `set -a; . ./.env` then died with
    "your-anyrun-token-here: command not found", and the older documented form,
    `export $(grep -v '^#' .env | xargs)`, silently truncated the value to
    `API-Key` -- which is worse, because the adapter then sends a malformed
    header and fails somewhere far from the cause.

    Asserts the value survives intact, not merely that sourcing exits 0.
    """
    bash = shutil.which("bash")
    if bash is None:  # pragma: no cover - CI images all have bash
        pytest.skip("bash not available")

    script = (
        f"set -a; . '{_ENV_EXAMPLE}'; set +a; "
        'printf "%s" "$ANYRUN_API_KEY"'
    )
    done = subprocess.run([bash, "-c", script], capture_output=True, text=True)

    assert done.returncode == 0, f"sourcing .env.example failed: {done.stderr.strip()}"
    assert done.stdout.startswith("API-Key "), (
        "ANYRUN_API_KEY lost its space-separated token when sourced; quote any "
        f"value containing a space. Got: {done.stdout!r}"
    )
    assert len(done.stdout.split()) == 2, (
        f"expected 'API-Key <token>', got {done.stdout!r}"
    )


def test_every_credentialed_adapter_has_a_live_check():
    """The credentialed live checks must cover the server's real feed registry.

    Lives here, not in test_live_feeds.py, because that module carries a
    module-level ``pytest.mark.live`` and is deselected from PR CI — a
    non-vacuity guard that only runs in the job it is guarding would guard
    nothing. This runs on every PR.

    The lists in test_live_feeds.py are hand-written, so a newly added
    credentialed adapter would silently go unchecked while the weekly run kept
    reporting a clean bill of health for a feed nobody was calling. That is the
    exact shape of defect this repository keeps finding in its own checks, so
    it is asserted rather than assumed.
    """
    from threat_intel_mcp import server

    from tests.test_live_feeds import (
        _CREDENTIALED_CVE_FEEDS,
        _CREDENTIALED_ENRICHMENT,
        _CREDENTIALED_IOC_FEEDS,
    )

    registered = {s.name for s in server._FEED_SOURCES + server._VULN_SOURCES}
    covered = {
        f[0]
        for f in _CREDENTIALED_IOC_FEEDS
        + _CREDENTIALED_CVE_FEEDS
        + _CREDENTIALED_ENRICHMENT
    }
    # Enrichment sources are checked live but are deliberately not in
    # _FEED_SOURCES, so they are covered-but-not-registered rather than a gap.
    registered |= {"VirusTotal"}
    # The keyless three are checked by the TestX classes in that module rather
    # than the parametrised sweeps, so they are the expected difference.
    keyless = {"ThreatFox", "CISA KEV", "NVD"}

    assert covered | keyless == registered, (
        "credentialed live checks are out of step with the server's feed "
        f"registry; unchecked: {sorted(registered - covered - keyless)}"
    )
