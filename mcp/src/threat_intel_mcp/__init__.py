"""threat-intel-mcp: MCP server for live threat intelligence feed integration.

The version is read from installed package metadata rather than restated here.
The literal was ``"0.1.0"`` while ``pyproject.toml`` said ``0.15.0`` — fourteen
minor releases stale, and nothing noticed because nothing read it. Deriving it
means there is only one number to get right.
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("threat-intel-mcp")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
