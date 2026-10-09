"""Garde-fous de vigie-web (SECURITY.md C9, CLAUDE.md règle 5)."""

import ast
import re
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from tests.webfixtures import csrf_of, login
from vigie.db.enums import AppRole
from vigie.web.security import CSP

WEB = Path(__file__).resolve().parents[2] / "src" / "vigie" / "web"


# --- Statique : gabarits et fichiers servis ---------------------------------------------


def _templates() -> list[Path]:
    return sorted((WEB / "templates").rglob("*.html"))


@pytest.mark.parametrize("path", _templates(), ids=lambda p: p.name)
def test_templates_have_no_inline_code(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for tag in re.findall(r"<script\b[^>]*>", text, re.IGNORECASE):
        assert "src=" in tag, f"script inline dans {path.name}"
    assert not re.search(r"\sstyle\s*=", text, re.IGNORECASE), f"attribut style dans {path.name}"
    assert not re.search(r"<style\b", text, re.IGNORECASE), f"bloc style dans {path.name}"
    assert not re.search(r"\son[a-z]+\s*=", text, re.IGNORECASE), (
        f"gestionnaire on* dans {path.name}"
    )
    assert not re.search(r"hx-on|javascript:", text, re.IGNORECASE)
    assert not re.search(r"\|\s*safe\b", text), f"filtre |safe dans {path.name}"


def test_no_external_resources() -> None:
    files = [*_templates(), WEB / "static" / "vigie.css", WEB / "static" / "app.js"]
    for f in files:
        text = f.read_text(encoding="utf-8")
        assert not re.search(r"(https?:)?//[a-z0-9.-]+\.[a-z]{2,}", text, re.IGNORECASE), f.name


def test_vendored_files_are_documented() -> None:
    vendor = (WEB / "static" / "VENDOR.md").read_text(encoding="utf-8")
    for f in [
        *(WEB / "static" / "fonts").glob("*.woff2"),
        WEB / "static" / "vendor" / "htmx.min.js",
    ]:
        assert f.name in vendor


# --- Séparation des processus -------------------------------------------------------------

FORBIDDEN_IMPORTS = (
    "vigie.connectors",
    "vigie.collect",
    "vigie.engine.llm",
    "vigie.engine.refine",
    "vigie.engine.context",
    "anthropic",
    "httpx",
    "requests",
    "subprocess",
)
ALLOWED_SECRETS = {"web_session_key", "entra_client_secret"}


@pytest.mark.parametrize("path", sorted(WEB.rglob("*.py")), ids=lambda p: p.name)
def test_web_imports_nothing_from_the_worker(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module, *(f"{node.module}.{a.name}" for a in node.names)]
        for name in names:
            assert not name.startswith(FORBIDDEN_IMPORTS), f"{path.name} importe {name}"
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "get_secret":
            arg = node.args[0]
            assert isinstance(arg, ast.Constant) and arg.value in ALLOWED_SECRETS, path.name


# --- En-têtes, cookie, CSRF ---------------------------------------------------------------


@pytest.mark.db
@pytest.mark.parametrize("path", ["/healthz", "/login", "/static/vigie.css", "/inexistant"])
def test_security_headers_everywhere(make_client: Callable[..., TestClient], path: str) -> None:
    r = make_client(env={}).get(path)
    assert r.headers["content-security-policy"] == CSP
    assert "unsafe" not in CSP
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["strict-transport-security"].startswith("max-age=")
    assert "server" not in r.headers or "uvicorn" not in r.headers["server"]


@pytest.mark.db
def test_cookie_flags(make_client: Callable[..., TestClient]) -> None:
    prod = make_client(env={}).get("/login").headers["set-cookie"].lower()
    assert all(flag in prod for flag in ("httponly", "samesite=lax", "secure", "max-age=28800"))
    dev = make_client().get("/login").headers["set-cookie"].lower()
    assert "secure" not in dev and "httponly" in dev
    assert "strict-transport-security" not in make_client().get("/login").headers


@pytest.mark.db
def test_csrf_required_on_every_mutation(client: TestClient, seeded: Session) -> None:
    token = login(client, seeded, "Vincent", AppRole.admin)
    for data, headers in (({}, {}), ({"csrf_token": "faux"}, {}), ({}, {"X-CSRF-Token": "faux"})):
        r = client.post("/logout", data=data, headers=headers)
        assert r.status_code == 403, (data, headers)
    assert client.get("/aujourdhui").status_code == 200  # toujours connecté
    assert client.post("/logout", headers={"X-CSRF-Token": token}).status_code == 303


@pytest.mark.db
def test_csrf_token_rotates_at_login(client: TestClient, seeded: Session) -> None:
    before = csrf_of(client)
    after = login(client, seeded, "Vincent", AppRole.admin)
    assert before != after
