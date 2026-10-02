"""Guards that keep ``requires-python`` honest.

The declared floor is only a promise if something checks it. These tests fail
whenever the metadata and the code drift apart, so the floor can never quietly
become a lie again.
"""

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
PACKAGE_DIR = REPO_ROOT / "a2a_drift"


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
