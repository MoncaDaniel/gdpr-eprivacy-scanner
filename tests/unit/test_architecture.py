"""Architecture rules that keep judgement pure (ADR-0003)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).parents[2] / "src" / "privacy_scanner"
PURE = ["domain", "classifier", "rules", "scoring", "reporting", "pipeline.py", "formatting.py"]


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text("utf-8"))):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _files(target: str) -> list[Path]:
    path = SRC / target
    return [path] if path.is_file() else sorted(path.rglob("*.py"))


@pytest.mark.parametrize("target", PURE)
def test_judgement_layers_never_import_the_browser_or_collector(target: str) -> None:
    for file in _files(target):
        forbidden = {
            name
            for name in _imports(file)
            if name.startswith(("privacy_scanner.collector", "playwright", "privacy_scanner.cli"))
        }
        assert not forbidden, f"{file.relative_to(SRC)} imports {forbidden}"


def test_domain_imports_nothing_from_the_project_but_itself() -> None:
    for file in _files("domain"):
        project = {n for n in _imports(file) if n.startswith("privacy_scanner")}
        assert all(n.startswith("privacy_scanner.domain") for n in project), file
