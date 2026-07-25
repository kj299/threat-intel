"""Module entry point: ``python -m threat_intel_mcp``.

The ``threat-intel-mcp`` console script (declared in ``pyproject.toml``) is the
usual way to start the server, but it only works when the interpreter's scripts
directory is on ``PATH``. On Windows — particularly with Store-installed Python,
where user scripts land in
``%LOCALAPPDATA%\\Packages\\PythonSoftwareFoundation.Python.3.x_*\\LocalCache\\
local-packages\\Python3x\\Scripts`` and that directory is *not* on ``PATH`` — the
shim is installed but unreachable, so registering the server with

    claude mcp add threat-intel-mcp -- threat-intel-mcp

succeeds while the health check reports ``Failed to connect``. Observed on a
Windows 11 host during the first live feed run (issue #76).

``python -m threat_intel_mcp`` resolves through the interpreter instead of
``PATH``, so it works wherever the package is importable:

    claude mcp add threat-intel-mcp -- python -m threat_intel_mcp

This is also the form the bundled plugin manifest (``.claude-plugin/plugin.json``)
uses to launch the server.
"""

from __future__ import annotations

from .server import main

if __name__ == "__main__":  # pragma: no cover - exercised by `python -m`
    main()
