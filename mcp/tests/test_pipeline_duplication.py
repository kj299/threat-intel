"""Guards on the duplicated per-type output pipeline (issue #84).

#84 says the refactor is **deliberately deferred** until a third output type is
real, and files the issue so the trigger is written down. Its acceptance
criteria are therefore not a change request:

    [ ] No third copy of the fan-out/finalize machinery ever lands
    [ ] Refactor PR precedes (or accompanies) any third output type

As written those are unenforceable — a hope recorded in a backlog nobody
re-reads at the moment it matters. This module makes them mechanical, which is
the same move this repo already makes for source governance (#88), skill/server
tool parity (#79), and agent credential isolation (#149).

Two distinct risks, only one of which #84 names:

1. **Copy #3 lands** — the stated trigger. `test_no_third_copy_of_the_fanout_
   machinery` fails the build when a third module grows the signature, with the
   refactor plan in the failure message.

2. **Copies #1 and #2 diverge** — the *present-day* risk, and the one that bites
   before a third type ever exists. `_degraded` is 99% identical between
   `fanout.py` and `vulns.py` and `_run_source` is 96% at identical line counts,
   so a fix applied to one and not the other is invisible: both paths keep
   passing their own tests while behaving differently. The sync tests below
   pin the shared contract that duplication puts at risk.

Neither test refactors anything. Deferral is the issue's explicit instruction;
these make the deferral safe to keep honouring.
"""

from __future__ import annotations

import ast
import difflib
import pathlib

import pytest

_SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "threat_intel_mcp"

# The machinery #84 counts copies of. A module carrying all of these is a
# per-type output pipeline, whatever its record type is called.
_PIPELINE_SIGNATURE = frozenset({"_SUMMARY_KEYS", "_degraded", "_run_source"})

# The two sanctioned copies. Copy #2 was a deliberate call (CVE records genuinely
# do not fit `ioc_network`); copy #3 is the line.
_SANCTIONED = {"fanout.py", "vulns.py"}

_REFACTOR_PLAN = """
Per issue #84, extract the shared machinery BEFORE adding a third output type:

  1. A generic `fan_out(sources, finalize, record_key)` parameterised by the
     finalize pipeline and result field name.
  2. One result dataclass with a typed `records` field, keeping `iocs`/`vulns`
     as thin views so tool payloads do not change.
  3. Per-type modules keep only: schema, sanitizer field lists, dedupe policy.
  4. Tool response shapes must not change — consumers and tests pin them.
"""


def _top_level_names(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def _pipeline_modules() -> set[str]:
    return {
        path.name
        for path in sorted(_SRC.glob("*.py"))
        if _PIPELINE_SIGNATURE <= _top_level_names(path)
    }


def _function_source(path: pathlib.Path, name: str) -> str:
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            segment = ast.get_source_segment(src, node)
            assert segment is not None
            return segment
    raise AssertionError(f"{name!r} not found in {path.name}")


# ─── #84's stated trigger ────────────────────────────────────────────────────


def test_the_signature_still_describes_the_real_pipelines():
    """Guards the guard.

    If the machinery is renamed and this signature stops matching, every check
    below would pass vacuously — a detector that silently detects nothing is
    worse than no detector, because it reads as coverage.
    """
    found = _pipeline_modules()
    assert found == _SANCTIONED, (
        f"pipeline signature {sorted(_PIPELINE_SIGNATURE)} now matches {sorted(found)}, "
        f"expected {sorted(_SANCTIONED)}. If the machinery was renamed, update "
        f"_PIPELINE_SIGNATURE; if a copy was added or removed, see the other tests."
    )


def test_no_third_copy_of_the_fanout_machinery():
    """#84 acceptance criterion 1, made mechanical.

    Copy #2 was justified and deliberate. Copy #3 is the refactor trigger, and
    the whole point of the issue is that the trigger fires at the moment someone
    is adding it — not months later in a backlog review.
    """
    found = _pipeline_modules()
    extra = found - _SANCTIONED
    assert not extra, (
        f"a third copy of the per-type output pipeline landed in {sorted(extra)}.\n"
        f"{_REFACTOR_PLAN}\n"
        "If this copy is genuinely warranted, the refactor comes first — that is "
        "issue #84's acceptance criterion, not a suggestion."
    )


def test_refactoring_down_to_one_pipeline_is_not_blocked():
    """The desired end state must not fail the build.

    A guard that fires when the duplication is *removed* would punish exactly
    the change it exists to encourage.
    """
    found = _pipeline_modules()
    assert len(found) <= len(_SANCTIONED), "more pipelines than sanctioned — see the test above"


# ─── The risk #84 does not name: the two copies drifting apart ───────────────


class _Skeleton(ast.NodeTransformer):
    """Strip every identifier, constant and docstring, leaving control flow.

    What legitimately differs between the two copies is naming: the record type
    (`iocs`/`vulns`), the local it is bound to (`deduped`/`finalized`), the log
    label ("fan-out source" / "vuln source"), and the docstring. What must not
    differ is the *shape* — which branches exist, what is called, how many
    statements run.

    Normalising each legitimate difference by name was the first approach and it
    trends toward vacuity: every real divergence looks like one more name to add
    to the exemption list. Comparing shape draws the line in a place that cannot
    erode. The specific contract details naming does carry — the degraded-result
    keys and `_SUMMARY_KEYS` — get their own explicit tests below.
    """

    def visit_Name(self, node: ast.Name) -> ast.Name:  # noqa: N802
        return ast.copy_location(ast.Name(id="_", ctx=node.ctx), node)

    def visit_Attribute(self, node: ast.Attribute) -> ast.Attribute:  # noqa: N802
        self.generic_visit(node)
        node.attr = "_"
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.Constant:  # noqa: N802
        return ast.copy_location(ast.Constant(value="_"), node)

    def visit_arg(self, node: ast.arg) -> ast.arg:  # noqa: N802
        self.generic_visit(node)
        node.arg = "_"
        return node

    def visit_keyword(self, node: ast.keyword) -> ast.keyword:  # noqa: N802
        self.generic_visit(node)
        if node.arg is not None:
            node.arg = "_"
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:  # noqa: N802
        return self._strip(node)

    def visit_AsyncFunctionDef(self, node):  # noqa: N802, ANN001, ANN202
        return self._strip(node)

    def _strip(self, node):  # noqa: ANN001, ANN202
        node.name = "_"
        if (
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        ):
            node.body = node.body[1:]  # drop the docstring
        self.generic_visit(node)
        return node


def _normalised_structure(path: pathlib.Path, name: str) -> str:
    tree = ast.parse(_function_source(path, name).strip())
    return ast.dump(_Skeleton().visit(tree), annotate_fields=True, include_attributes=False)


@pytest.mark.parametrize("shared", ["_degraded", "_run_source"])
def test_duplicated_functions_stay_structurally_in_sync(shared: str):
    """A fix applied to one copy and not the other is invisible.

    Both modules keep passing their own tests while behaving differently, and
    nothing else in CI compares them.

    This compares **normalised ASTs, not text similarity**. The first version
    used a difflib ratio with a 0.90 floor and it did not catch a simulated
    four-line divergence: the copies sit at 96.2% today and a realistic
    single-copy fix only dropped them to 91.5%, so no threshold separates
    "reformatted" from "behaviour changed" without being brittle in one
    direction or the other. Structure does separate them — control flow and
    calls must match exactly, while `iocs`/`vulns` naming is normalised away.

    A deliberate divergence is fine; make it explicit here in the same commit.
    """
    ioc = _normalised_structure(_SRC / "fanout.py", shared)
    vuln = _normalised_structure(_SRC / "vulns.py", shared)
    if ioc != vuln:
        diff = "\n".join(
            difflib.unified_diff(
                ioc.replace("), ", "),\n").splitlines(),
                vuln.replace("), ", "),\n").splitlines(),
                "fanout.py",
                "vulns.py",
                lineterm="",
                n=1,
            )
        )
        pytest.fail(
            f"{shared}() has structurally diverged between fanout.py and vulns.py.\n"
            "Port the change to both copies, or do the #84 refactor so there is "
            f"only one.\n\n{diff[:1800]}"
        )


def test_degraded_result_keys_match_across_pipelines():
    """The tool payload contract, asserted across both copies.

    `_degraded` builds the dict a consumer sees when a source fails. If the two
    pipelines disagree on its keys, a caller that handles a degraded IOC source
    breaks on a degraded CVE source — the exact class of bug duplication hides.
    """
    keys = {}
    for module in ("fanout.py", "vulns.py"):
        src = _function_source(_SRC / module, "_degraded")
        tree = ast.parse(src.strip())
        returns = [n for n in ast.walk(tree) if isinstance(n, ast.Return)]
        assert returns, f"{module}: _degraded has no return"
        literal = returns[-1].value
        assert isinstance(literal, ast.Dict), f"{module}: _degraded does not return a dict literal"
        keys[module] = {k.value for k in literal.keys if isinstance(k, ast.Constant)}

    ioc_only = keys["fanout.py"] - keys["vulns.py"]
    vuln_only = keys["vulns.py"] - keys["fanout.py"]
    # The record-list key is legitimately type-specific: `iocs` vs `vulns`.
    assert ioc_only == {"iocs"} and vuln_only == {"vulns"}, (
        f"degraded-result keys diverged beyond the record field: "
        f"only in fanout.py {sorted(ioc_only)}, only in vulns.py {sorted(vuln_only)}"
    )


def test_summary_keys_agree_on_everything_but_the_record_field():
    """`_SUMMARY_KEYS` is what gets stripped to build the coverage-ledger
    summary. The two copies must agree, or the ledger means different things
    depending on which pipeline produced the row."""
    from threat_intel_mcp import fanout, vulns

    ioc, vuln = set(fanout._SUMMARY_KEYS), set(vulns._SUMMARY_KEYS)
    assert ioc - vuln <= {"iocs"}, f"only in fanout: {sorted(ioc - vuln)}"
    assert vuln - ioc <= {"vulns"}, f"only in vulns: {sorted(vuln - ioc)}"
