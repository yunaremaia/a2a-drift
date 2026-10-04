"""Guards that keep ``requires-python`` and the dev extra honest.

The declared floor is only a promise if something checks it, and the ``dev``
extra is only usable if it exists. These tests fail whenever the metadata and
the code drift apart -- or when CI names a tool the extra has never heard of --
so neither can quietly become a lie again.
"""

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
PACKAGE_DIR = REPO_ROOT / "a2a_drift"
CONTRIBUTING = REPO_ROOT / "CONTRIBUTING.md"


def _declared_floor() -> tuple:
    """Return the minimum ``(major, minor)`` version in ``requires-python``."""
    match = re.search(
        r'requires-python\s*=\s*">=\s*(\d+)\.(\d+)', PYPROJECT.read_text()
    )
    assert match, "requires-python with a >= floor not found in pyproject.toml"
    return int(match.group(1)), int(match.group(2))


def _matrix_versions() -> list:
    """Return the Python versions the CI test matrix actually runs on."""
    match = re.search(r"python-version:\s*\[([^\]]*)\]", CI_WORKFLOW.read_text())
    assert match, "no python-version matrix list found in .github/workflows/ci.yml"
    return re.findall(r"(\d+\.\d+)", match.group(1))


def _as_tuple(version: str) -> tuple:
    major, minor = version.split(".", 1)
    return int(major), int(minor)


class TestRequiresPythonIsHonest:
    def test_ci_matrix_covers_the_declared_floor(self):
        """CI must exercise the floor, or the floor is untested fiction."""
        floor = _declared_floor()
        matrix = _matrix_versions()
        floor_str = f"{floor[0]}.{floor[1]}"

        assert floor_str in matrix, (
            f"requires-python declares >= {floor_str} but the CI matrix "
            f"({', '.join(matrix)}) does not test it, so the declared floor is "
            f"never exercised and can rot silently"
        )

    def test_no_matrix_version_is_below_the_declared_floor(self):
        """Every tested version must actually satisfy requires-python."""
        floor = _declared_floor()
        below = [v for v in _matrix_versions() if _as_tuple(v) < floor]

        assert not below, (
            f"CI matrix tests {', '.join(below)}, which is below the declared "
            f"requires-python floor {floor[0]}.{floor[1]}"
        )


class TestSourceParsesOnTheFloor:
    """Reject syntax the declared floor cannot even parse.

    Builtin generics (``list[X]``, ``dict[K, V]``) are PEP 585 and work at
    runtime from Python 3.9, so they are fine. PEP 604 unions (``X | None``)
    are 3.10+ and raise ``TypeError`` on 3.9 whenever they are evaluated --
    which is exactly what happens without ``from __future__ import annotations``.
    """

    def _modules(self):
        return sorted(PACKAGE_DIR.glob("*.py"))

    @staticmethod
    def _has_future_annotations(tree: ast.Module) -> bool:
        return any(
            isinstance(node, ast.ImportFrom)
            and node.module == "__future__"
            and any(a.name == "annotations" for a in node.names)
            for node in tree.body
        )

    @staticmethod
    def _annotations(tree: ast.Module):
        """Yield every annotation expression in a module."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                annotations = [node.returns] if node.returns else []
                args = node.args
                for arg in (
                    list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
                ):
                    if arg and arg.annotation:
                        annotations.append(arg.annotation)
                if args.vararg is not None and args.vararg.annotation:
                    annotations.append(args.vararg.annotation)
                if args.kwarg is not None and args.kwarg.annotation:
                    annotations.append(args.kwarg.annotation)
                yield from annotations
            elif isinstance(node, ast.AnnAssign):
                yield node.annotation

    def test_no_pep604_unions_without_deferred_annotations(self):
        offenders = []
        for path in self._modules():
            tree = ast.parse(path.read_text(), filename=str(path))
            # With deferred annotations the unions are strings at runtime and
            # never evaluated, so PEP 604 becomes legal on the 3.9 floor.
            if self._has_future_annotations(tree):
                continue
            for annotation in self._annotations(tree):
                for node in ast.walk(annotation):
                    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
                        offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
                        break

        assert not offenders, (
            "PEP 604 union syntax (`X | None`) is Python 3.10+ and raises "
            "TypeError on the declared 3.9 floor when evaluated at definition "
            "time. Either add `from __future__ import annotations` to these "
            "modules or use typing.Optional/Union: " + ", ".join(offenders)
        )

    @pytest.mark.parametrize("version", ["3.9"], ids=["declared-floor"])
    def test_package_imports_cleanly_on_the_declared_floor(self, version):
        """Smoke-test that this interpreter is at or above the floor."""
        import sys

        floor = _declared_floor()
        current = sys.version_info[:2]

        assert current >= floor, (
            f"running Python {current[0]}.{current[1]} is below the declared "
            f"floor {floor[0]}.{floor[1]}"
        )


def _dev_extra() -> list:
    """Return the requirement names declared in the ``dev`` extra.

    Read from the raw TOML text rather than ``tomllib``: the 3.9 leg of the CI
    matrix has no ``tomllib`` (it is 3.11+), and this module already parses
    ``pyproject.toml`` with regexes for the same reason.
    """
    text = PYPROJECT.read_text()
    section = re.search(
        r"^\[project\.optional-dependencies\]\s*$(.*?)(?=^\[|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert section, (
        "pyproject.toml declares no [project.optional-dependencies], so "
        "`pip install -e '.[dev]'` installs nothing beyond the package itself"
    )

    dev = re.search(r"^dev\s*=\s*\[(.*?)\]", section.group(1), re.DOTALL | re.MULTILINE)
    assert dev, (
        "pyproject.toml declares [project.optional-dependencies] but no 'dev' "
        "extra, so `pip install -e '.[dev]'` still installs no tools"
    )

    return [
        req.strip().strip('"').strip("'")
        for req in dev.group(1).split(",")
        if req.strip()
    ]


def _requirement_name(requirement: str) -> str:
    """The distribution name of a requirement, without extras or a version pin."""
    return re.split(r"[<>=!~ ;\[]", requirement, maxsplit=1)[0].strip().lower()


def _ci_installed_tools() -> set:
    """Distribution names CI installs by name, excluding ``pip`` and ``-e .``.

    This is the coupling that makes the extra honest: if a tool is added to a
    CI install step, it is a development dependency, and a contributor running
    ``pip install -e '.[dev]'`` should get it.
    """
    tools = set()
    for line in CI_WORKFLOW.read_text().splitlines():
        match = re.search(r"python -m pip install\s+(.*)$", line)
        if not match:
            continue
        args = match.group(1).split()
        # `-e .` is the project itself and `--upgrade pip` is pip, not a tool.
        if any(arg in {"-e", "--upgrade", "."} for arg in args):
            continue
        tools.update(_requirement_name(arg) for arg in args)
    return tools


class TestDevExtraIsDeclared:
    """``pip install -e '.[dev]'`` must actually install the dev tools.

    pip does not fail on an unknown extra: it warns and exits 0, so the
    documented setup command looked like it worked while providing no tools at
    all. CI masked it by installing pytest/ruff/mypy by hand.
    """

    def test_the_dev_extra_is_declared(self):
        extra = _dev_extra()

        assert extra, "the dev extra is declared but empty"

    @pytest.mark.parametrize(
        "tool",
        ["pytest", "pytest-cov", "ruff", "mypy"],
        ids=["pytest", "pytest-cov", "ruff", "mypy"],
    )
    def test_each_tool_this_project_uses_is_in_the_extra(self, tool):
        """These four are what CI and CONTRIBUTING tell contributors to run."""
        declared = [_requirement_name(req) for req in _dev_extra()]

        assert tool in declared, (
            f"'{tool}' is installed by CI and named in CONTRIBUTING.md but is "
            f"missing from the [dev] extra (declared: {declared or 'nothing'})"
        )

    def test_every_tool_ci_installs_is_in_the_extra(self):
        """The general rule behind the four cases above."""
        declared = {_requirement_name(req) for req in _dev_extra()}
        missing = sorted(_ci_installed_tools() - declared)
        installed = sorted(declared) or "nothing"

        assert not missing, (
            f"CI installs {missing} by name, so they are development "
            f"dependencies, but the [dev] extra declares only {installed}"
        )

    def test_contributing_points_at_the_extra(self):
        """The docs must tell contributors to use the extra that now exists."""
        assert ".[dev]" in CONTRIBUTING.read_text(), (
            "CONTRIBUTING.md still tells contributors to install dev tools "
            "explicitly; it should document `pip install -e '.[dev]'` now that "
            "the extra exists"
        )
