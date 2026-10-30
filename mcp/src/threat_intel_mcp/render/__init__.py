"""Presentation layer: renders validated skill output into shareable artifacts.

The skill emits typed JSON; rendering lives here, in the consuming tool. That
split is issue #110's open question 1, answered its third way: a projection
computed from validated data belongs in the tool, not in the prompt, because it
is deterministic and therefore testable.

``executive`` renders validated JSON; ``report`` renders the markdown report the
scheduled run publishes, treating its text as untrusted (see its docstring).
"""

from .executive import RISK_BANDS, render_executive_overview, risk_band
from .report import render_report_page

__all__ = ["RISK_BANDS", "render_executive_overview", "render_report_page", "risk_band"]
