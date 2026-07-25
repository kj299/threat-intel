# Report Runbook — Windows / PowerShell 5.1

A step-by-step walkthrough of [`report-runbook.md`](report-runbook.md)'s manual
generation path on Windows, in **Windows PowerShell 5.1** — the `powershell.exe`
that ships with Windows 11, not PowerShell 7 (`pwsh`). Every command here is 5.1
compatible.

The generic runbook stays the source of truth for *what* a report is and *why*
the honesty markers matter. This file only covers *how to run one on Windows*,
because that is where the first live attempt (issue #76) hit four distinct
failures, none of them related to threat intelligence.

> **Check your shell first.** If `$PSVersionTable.PSVersion.Major` is 7 or
> higher you are in PowerShell 7 and can use the generic runbook's commands with
> minor adjustment. This file assumes 5.1.

```powershell
$PSVersionTable.PSVersion
```

---

## Two things about PowerShell 5.1 that will confuse you

Read these before starting, or you will misread ordinary output as failure.

**1. Native-command stderr is rendered as a PowerShell error.** `pip`, `git`,
and `python` write ordinary progress and warnings to stderr. PowerShell 5.1
wraps every one of those lines in a red `NativeCommandError` block with a
stack-trace-looking header. In the #76 run this made a *successful* install and
a *successful* `git checkout` both look like crashes:

```
git : Switched to a new branch 'feat/first-connected-report'
    + CategoryInfo          : NotSpecified: (Switched to a n...:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
```

That is a success message. **Judge native commands by `$LASTEXITCODE`, not by
red text:**

```powershell
git status
"exit code: $LASTEXITCODE"      # 0 means success regardless of colour
```

**2. TLS defaults to 1.0.** All three feed hosts require TLS 1.2 or better, so
`Invoke-WebRequest` fails with an unhelpful "underlying connection was closed"
until you raise it. The setting lasts for the session only.

---

## Step 0 — Preflight

```powershell
# PS 5.1 defaults to TLS 1.0; the feed hosts require 1.2+
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Without this, multi-MB downloads crawl behind the progress bar renderer
$ProgressPreference = 'SilentlyContinue'

# Confirm the toolchain. python and git must both resolve.
python --version
git --version
claude --version
```

> **Do not use `py -3`.** The Python launcher is not installed with
> Store-installed Python, which is what Windows 11 offers by default. `py` was
> the first thing to fail in the #76 run. Use `python` throughout.

### Egress check

The report is only worth generating if the feeds are reachable. Check before
installing anything:

```powershell
$urls = @(
  'https://threatfox.abuse.ch/export/csv/recent/',
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1'
)

foreach ($u in $urls) {
  try {
    $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 40
    '{0,-58} {1}  {2:N0} bytes' -f $u.Substring(8, [Math]::Min(57, $u.Length-8)), $r.StatusCode, $r.RawContentLength
  } catch {
    '{0,-58} FAIL  {1}' -f $u.Substring(8, [Math]::Min(57, $u.Length-8)), $_.Exception.Message
  }
}
```

Expect `200` and a non-trivial byte count on all three. A corporate proxy or
endpoint agent that blocks these will surface here rather than three steps
later. If any host fails, stop — a report generated now would be a no-live-data
report, and the generic runbook's egress note applies.

---

## Step 1 — Clone and update

```powershell
git clone https://github.com/kj299/threat-intel.git
Set-Location threat-intel
# or, in an existing clone:
git pull
```

---

## Step 2 — Virtual environment

```powershell
python -m venv .venv
```

If `.\.venv\Scripts\Activate.ps1` is blocked by execution policy, unblock it for
**this process only** — the setting evaporates when the window closes, so there
is nothing to undo afterwards:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\.venv\Scripts\Activate.ps1
```

Your prompt should now be prefixed `(.venv)`. Confirm you are inside it:

```powershell
python -c "import sys; print(sys.prefix)"     # must end in \threat-intel\.venv
```

> **Why the venv matters beyond hygiene.** Without it, `pip install` falls back
> to user site-packages and puts the `threat-intel-mcp` shim in a directory that
> is not on `PATH` — the cause of the `Failed to connect` in #76. Inside a venv
> the scripts directory *is* on `PATH` while activated.

---

## Step 3 — Install

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".\mcp[dev]" -c mcp\constraints-dev.txt
```

**The quotes around `".\mcp[dev]"` are required.** Unquoted, PowerShell treats
`[dev]` as a wildcard character class and the path silently fails to match.

`-c mcp\constraints-dev.txt` installs the exact pinned dependency set CI uses.
Omit it only if you are deliberately testing against newer dependencies.

Sanity check the install:

```powershell
python -m pytest mcp\tests -q
```

---

## Step 4 — Probe the feeds through the adapters

The Step 0 check proved the *hosts* are reachable. This proves the *adapters*
can parse what they return — a distinction that matters, because ThreatFox once
returned a 1 MB response that parsed to zero records (fixed in #100).

```powershell
$py = @'
import asyncio
from threat_intel_mcp.adapters.threatfox import ThreatFoxAdapter
from threat_intel_mcp.adapters.cisa_kev import CISAKEVAdapter
from threat_intel_mcp.adapters.nvd import NVDAdapter
from threat_intel_mcp.vault.factory import credential_provider_from_env

async def main():
    creds = credential_provider_from_env()
    for a in (ThreatFoxAdapter(), CISAKEVAdapter(), NVDAdapter(creds)):
        try:
            r = await a.fetch(time_range="7d")
            recs = getattr(r, "iocs", None) or getattr(r, "vulns", [])
            print("%-10s OK   %6d records %8.0f ms" % (a.name, r.record_count, r.latency_ms))
            if recs:
                print("           sample: %s" % str(recs[0])[:130])
        except Exception as e:
            print("%-10s FAIL %s: %s" % (a.name, type(e).__name__, str(e)[:90]))

asyncio.run(main())
'@

$probe = Join-Path $env:TEMP 'feedcheck.py'
Set-Content -Path $probe -Value $py -Encoding ASCII   # ASCII avoids the PS 5.1 UTF-8 BOM
python $probe
```

Two PowerShell 5.1 details in that block, both load-bearing:

- **The closing `'@` must be at column 0** with nothing before it on the line.
  Indent it and the here-string never terminates.
- **`-Encoding ASCII`.** `Set-Content`'s default in 5.1 writes a UTF-8 BOM,
  which Python reports as `SyntaxError: invalid non-printable character U+FEFF`.

**Expect non-zero counts on all three.** A `FAIL` line, or an `OK` with `0
records`, is a real finding — file it with the traceback. Since #100, a
ThreatFox format break raises instead of quietly reporting zero, so `0 records`
from ThreatFox now means the feed genuinely had nothing, not that parsing broke.

The `EnvCredentialProvider is active` warning is expected and harmless — it
reports that credentials come from environment variables, which is correct for a
local run.

---

## Step 5 — Load the skill and the server

```powershell
claude --plugin-dir .        # run from the repository root
```

That single flag loads both halves: the `cyber-threat-intel` skill *and* the
`threat-intel` MCP server, which the plugin manifest launches as
`python -m threat_intel_mcp`. Approve the server when prompted.

> **`/cyber-threat-intel` does not exist in a plain clone.** Claude Code
> discovers skills from `~/.claude/skills/`, `.claude/skills/`, and installed
> plugins; a top-level `skills/` directory at a repository root is not a
> discovery location. `--plugin-dir .` is what makes the command exist. This is
> why the first attempt reported `Unknown command`.
>
> It must also be run **from the repository root** — a plugin directory is not
> discovered by walking up from a subdirectory.

Inside the session, confirm the server connected:

```
/mcp
```

### If you would rather register the server persistently

```powershell
claude mcp add threat-intel-mcp -- python -m threat_intel_mcp
claude mcp list      # expect: threat-intel-mcp - √ Connected
```

Use `python -m threat_intel_mcp`, **not** the bare `threat-intel-mcp` command.
The console script only resolves when the interpreter's scripts directory is on
`PATH`; the module form resolves through the interpreter and works wherever the
package is importable. If you registered it outside the activated venv, point at
that interpreter explicitly so the server starts in the environment the package
is installed in:

```powershell
$venvPython = (Resolve-Path .\.venv\Scripts\python.exe).Path
claude mcp add threat-intel-mcp -- $venvPython -m threat_intel_mcp
```

Registering persistently means the server launches on every future session in
this directory — remove it with `claude mcp remove threat-intel-mcp` when done
(see [#96](https://github.com/kj299/threat-intel/issues/96)).

---

## Step 6 — Generate

Inside the interactive `claude` session — **not at the PowerShell prompt**:

```
/cyber-threat-intel
```

Or `/threat-intel:cyber-threat-intel` if another command has claimed the short
name. Typing this at the PowerShell prompt gives
`The term '/cyber-threat-intel' is not recognized`, and `claude
/cyber-threat-intel` gives `Unknown command` — both were seen in the #76 run.

Defaults are the `enterprise_soc` persona over a `7d` window.

---

## Step 7 — Review before committing

The honesty markers are the point of the report, so check them rather than
skimming:

- **Coverage badge matches the ledger count.** `MINIMAL` on a quiet week is the
  correct answer.
- **Every IOC and CVE cites the feed it came from.** No indicator should appear
  without a real `source`.
- **The methodology notice matches reality** — it should state that live
  `threat-intel-mcp` feeds were connected, and which ones.
- **Sources the tools reported as degraded are still `unverified`** in the
  ledger. They are never upgraded.

---

## Step 8 — Commit

Only after a report file actually exists. In the #76 run this step ran against
a report that had never been generated, which pushed an empty branch:

```powershell
$today = Get-Date -Format 'yyyy-MM-dd'
$report = "reports\$today-threat-intel.md"

if (-not (Test-Path $report)) {
  Write-Warning "No report at $report - nothing to commit. Go back to Step 6."
} else {
  git checkout -b "feat/report-$today" origin/main
  git add $report
  git commit -m "Add scheduled threat-intel report: $today (enterprise_soc, 7d)"
  git push -u origin "feat/report-$today"
}
```

Then open a PR for the pushed branch.

---

## Step 9 — Teardown

When you are finished with the host, [#96](https://github.com/kj299/threat-intel/issues/96)
covers removing the MCP registration, uninstalling the packages, deleting the
probe artifacts, and verifying no security setting was left loosened.

---

## Troubleshooting

Every row here was observed on a real Windows 11 host during #76.

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `py : The term 'py' is not recognized` | No Python launcher; Store Python does not install it | Use `python -m venv .venv` |
| `Activate.ps1 ... is not recognized` | The venv was never created, because the previous command failed | Re-run Step 2 and check for `(.venv)` in the prompt |
| `Defaulting to user installation because normal site-packages is not writeable` | Installing outside a venv | Activate the venv first (Step 2) |
| `WARNING: The script threat-intel-mcp.exe is installed in '...' which is not on PATH` | Store Python's user scripts directory is not on `PATH` | Harmless inside a venv. Otherwise register with `python -m threat_intel_mcp` |
| `threat-intel-mcp: × Failed to connect` | Registered the bare command name, which the host cannot resolve | `claude mcp remove threat-intel-mcp`, then re-add with `-- python -m threat_intel_mcp` |
| `The term '/cyber-threat-intel' is not recognized` | Typed at the PowerShell prompt | It is a slash command *inside* an interactive `claude` session |
| `Unknown command: /cyber-threat-intel` | Repo not loaded as a plugin | Start with `claude --plugin-dir .` from the repository root |
| `SyntaxError: invalid non-printable character U+FEFF` | `Set-Content` wrote a UTF-8 BOM | Add `-Encoding ASCII` |
| Here-string never closes | Closing `'@` is indented | It must sit at column 0 |
| `Invoke-WebRequest`: "underlying connection was closed" | TLS 1.0 default | Set `SecurityProtocol` to `Tls12` (Step 0) |
| Red `NativeCommandError` around ordinary output | PS 5.1 renders native stderr as an error | Check `$LASTEXITCODE`; `0` is success |
| `pathspec 'reports\...' did not match any files` | No report was generated | Go back to Step 6; do not push the branch |
| Feed returns `OK` with `0 records` | Genuinely empty feed, or a format break | Since #100 a ThreatFox format break raises instead of reporting zero, so `0` here means genuinely empty |
