"""Tests for the ``python -m threat_intel_mcp`` entry point.

The console script alone was not enough: on Windows it installs into a scripts
directory that is frequently absent from ``PATH``, so ``claude mcp add`` would
register a command the host could not resolve and the health check reported
``Failed to connect`` (issue #76). Running the package as a module goes through
the interpreter instead, so it works wherever the package is importable — and it
is what ``.claude-plugin/plugin.json`` uses to launch the server.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys


def test_main_module_exists():
    """The package is runnable with ``-m``."""
    assert importlib.util.find_spec("threat_intel_mcp.__main__") is not None


def test_main_module_reexports_the_console_script_entry_point():
    """``-m`` and the console script must start the *same* server.

    ``pyproject.toml`` points the ``threat-intel-mcp`` script at
    ``threat_intel_mcp.server:main``; if these ever diverge, one launch path
    would silently start something else.
    """
    import threat_intel_mcp.__main__ as module
    import threat_intel_mcp.server as server

    assert module.main is server.main


def test_importing_main_module_does_not_start_the_server():
    """Guarded by ``if __name__ == '__main__'``.

    Without the guard, importing the module — which the two tests above do —
    would block on stdio forever.
    """
    source = (
        importlib.util.find_spec("threat_intel_mcp.__main__").origin
    )
    with open(source, encoding="utf-8") as handle:
        assert '__name__ == "__main__"' in handle.read()


def test_module_launch_starts_and_shuts_down_cleanly():
    """End-to-end: ``python -m threat_intel_mcp`` serves stdio and exits 0 on EOF.

    This is the exact invocation the plugin manifest and the documented
    ``claude mcp add ... -- python -m threat_intel_mcp`` registration use, so a
    regression here breaks both.
    """
    result = subprocess.run(
        [sys.executable, "-m", "threat_intel_mcp"],
        input=b"",
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert b"Traceback" not in result.stderr
