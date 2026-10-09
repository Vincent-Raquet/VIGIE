"""Analyse statique (SECURITY.md C2, C10), en complément de la règle ruff TID251."""

import ast
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

SRC = REPO_ROOT / "src" / "vigie"
CONNECTORS = SRC / "connectors"
NETWORK_MODULES = ("httpx", "requests", "urllib", "aiohttp", "socket", "http", "subprocess")
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_MODULES = ("pickle", "marshal", "shelve", "subprocess")


def _modules(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute | ast.Name)
            and getattr(node.func, "attr", getattr(node.func, "id", ""))
            in ("import_module", "__import__")
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            found.add(str(node.args[0].value))
    return found


def _py_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "migrations" not in p.parts)


@pytest.mark.parametrize(
    "path", [p for p in _py_files(CONNECTORS) if p.name != "base.py"], ids=lambda p: p.name
)
def test_connectors_have_no_raw_network_access(path: Path) -> None:
    modules = _modules(ast.parse(path.read_text()))
    bad = sorted(m for m in modules if m.split(".")[0] in NETWORK_MODULES)
    assert not bad, f"{path.name} importe {bad} : passer par SafeClient"


@pytest.mark.parametrize("path", _py_files(SRC), ids=lambda p: str(p.relative_to(SRC)))
def test_no_dangerous_constructs(path: Path) -> None:
    tree = ast.parse(path.read_text())
    modules = _modules(tree)
    assert not [m for m in modules if m.split(".")[0] in FORBIDDEN_MODULES]
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            # Seules les fonctions natives (eval(…), pas re.compile(…)).
            name = func.id if isinstance(func, ast.Name) else ""
            assert name not in FORBIDDEN_CALLS, f"{path.name}:{node.lineno} appelle {name}()"
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                qualified = f"{func.value.id}.{func.attr}"
                assert qualified not in (
                    "os.system",
                    "os.popen",
                    "yaml.load",
                    "yaml.unsafe_load",
                    "yaml.full_load",
                ), f"{path.name}:{node.lineno} appelle {qualified}()"


def test_detector_catches_violations(tmp_path: Path) -> None:
    sample = "import httpx\nfrom urllib.request import urlopen\nimportlib.import_module('socket')\n"
    assert {"httpx", "urllib.request", "socket"} <= _modules(ast.parse(sample))


def test_only_base_imports_httpx() -> None:
    importers = sorted(
        p.relative_to(SRC).as_posix()
        for p in _py_files(SRC)
        if any(m.split(".")[0] == "httpx" for m in _modules(ast.parse(p.read_text())))
    )
    assert importers == ["connectors/base.py"]
