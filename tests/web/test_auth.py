"""Connexion : développement, Entra (simulé), bris de glace, session, déconnexion."""

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.responses import RedirectResponse
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.webfixtures import GROUPS, TENANT, csrf_of, login, person_id
from vigie.db import models
from vigie.db.enums import AppRole
from vigie.web.auth import enable_breakglass

pytestmark = pytest.mark.db
ADMIN_GROUP, MANAGER_GROUP, TECH_GROUP, _ = list(GROUPS)


def audits(session: Session, action: str) -> list[models.AuditLog]:
    return list(session.scalars(select(models.AuditLog).where(models.AuditLog.action == action)))


def test_anonymous_is_redirected_to_login(client: TestClient) -> None:
    for path in ("/", "/aujourdhui", "/semaine"):
        r = client.get(path)
        assert (r.status_code, r.headers["location"]) == (303, "/login")
    assert client.get("/healthz").text == "ok"
    assert "Connexion de développement" in client.get("/login").text


def test_dev_login_then_logout(client: TestClient, seeded: Session) -> None:
    token = login(client, seeded, "Giovanni", AppRole.tech)
    page = client.get("/aujourdhui")
    assert page.status_code == 200 and "Connecté : Giovanni" in page.text
    assert "Connexion de <strong>développement</strong>" in page.text
    assert audits(seeded, "login")[-1].details == {"role": "tech"}
    r = client.post("/logout", data={"csrf_token": token})
    assert r.status_code == 303 and client.get("/aujourdhui").status_code == 303


@pytest.mark.parametrize(
    ("env", "web"),
    [
        ({}, {}),
        ({"VIGIE_ENV": "prod"}, {}),
        ({"VIGIE_ENV": "dev"}, {"dev_login": False}),
        ({"VIGIE_ENV": "dev"}, {"host": "0.0.0.0"}),  # noqa: S104 - cas refusé testé
    ],
)
def test_dev_login_is_impossible_outside_dev(
    make_client: Callable[..., TestClient],
    seeded: Session,
    env: dict[str, str],
    web: dict[str, Any],
) -> None:
    client = make_client(env=env, **web)
    assert client.get("/dev-login").status_code == 404
    token = csrf_of(client)
    r = client.post(
        "/dev-login",
        data={"person_id": person_id(seeded, "Vincent"), "role": "admin", "csrf_token": token},
    )
    # 404 (route absente) ou 403 (hors dev, cookie Secure non renvoyé en http : CSRF).
    assert r.status_code in (403, 404)
    assert "Connexion de développement" not in client.get("/login").text


def test_session_expires(
    client: TestClient, seeded: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    login(client, seeded, "Vincent", AppRole.admin)
    later = time.time() + 9 * 3600
    monkeypatch.setattr(time, "time", lambda: later)
    assert client.get("/aujourdhui").status_code == 303


class FakeEntra:
    def __init__(self, claims: dict[str, Any] | Exception) -> None:
        self.claims = claims

    async def authorize_redirect(self, request: Any, redirect_uri: str) -> RedirectResponse:
        assert redirect_uri.endswith("/auth/callback")
        return RedirectResponse("https://login.microsoftonline.com/fake", status_code=302)

    async def authorize_access_token(self, request: Any) -> dict[str, Any]:
        if isinstance(self.claims, Exception):
            raise self.claims
        return {"userinfo": self.claims}


def claims(**kw: Any) -> dict[str, Any]:
    base = {
        "tid": TENANT,
        "email": "giovanni@example.be",
        "name": "Giovanni D.",
        "groups": [TECH_GROUP],
    }
    base.update(kw)
    return base


def test_entra_login_maps_highest_group_and_person(
    make_client: Callable[..., TestClient], seeded: Session
) -> None:
    client = make_client(oidc=FakeEntra(claims(groups=[TECH_GROUP, MANAGER_GROUP, "inconnu"])))
    assert (
        client.get("/auth/login")
        .headers["location"]
        .startswith("https://login.microsoftonline.com/")
    )
    r = client.get("/auth/callback")
    assert (r.status_code, r.headers["location"]) == (303, "/aujourdhui")
    page = client.get("/aujourdhui").text
    assert "Connecté : Giovanni" in page and "rôle manager · Entra ID" in page


@pytest.mark.parametrize(
    ("bad", "reason"),
    [
        (claims(groups=[]), "aucun groupe"),
        (claims(groups=["autre"]), "aucun groupe"),
        (claims(groups=None, _claim_names={"groups": "src1"}), "trop de groupes"),
        (claims(tid="99999999-9999-9999-9999-999999999999"), "locataire"),
        (claims(email=None, preferred_username=None), "adresse e-mail"),
    ],
)
def test_entra_denials(
    make_client: Callable[..., TestClient], seeded: Session, bad: dict[str, Any], reason: str
) -> None:
    client = make_client(oidc=FakeEntra(bad))
    r = client.get("/auth/callback")
    assert r.status_code == 403 and reason in r.text
    assert client.get("/aujourdhui").status_code == 303
    assert reason in audits(seeded, "login_denied")[-1].details["reason"]


def test_entra_failure_and_inactive_person(
    make_client: Callable[..., TestClient], seeded: Session
) -> None:
    client = make_client(oidc=FakeEntra(ValueError("state mismatch")))
    r = client.get("/auth/callback")
    assert (r.status_code, r.headers["location"]) == (303, "/login")
    assert "La connexion Entra a échoué" in client.get("/login").text
    gio = seeded.get(models.Person, person_id(seeded, "Giovanni"))
    assert gio is not None
    gio.active = False
    seeded.commit()
    r = make_client(oidc=FakeEntra(claims())).get("/auth/callback")
    assert r.status_code == 403 and "désactivée" in r.text


def test_entra_routes_absent_without_configuration(client: TestClient) -> None:
    assert client.get("/auth/login").status_code == 404
    assert client.get("/auth/callback").status_code == 404


def test_breakglass_single_use(client: TestClient, seeded: Session) -> None:
    assert client.get("/breakglass").status_code == 404
    password = enable_breakglass(seeded, timedelta(hours=1), datetime.now(UTC))
    seeded.commit()
    assert "Accès de secours" in client.get("/login").text
    token = csrf_of(client, "/breakglass")
    assert (
        client.post("/breakglass", data={"password": "faux", "csrf_token": token}).status_code
        == 403
    )
    assert audits(seeded, "login_failed")
    r = client.post("/breakglass", data={"password": password, "csrf_token": token})
    assert r.status_code == 303
    page = client.get("/aujourdhui").text
    assert "Session de secours" in page and "rôle admin" in page
    assert seeded.get(models.Setting, "breakglass") is None  # consommé


def test_breakglass_expired(client: TestClient, seeded: Session) -> None:
    password = enable_breakglass(seeded, timedelta(hours=1), datetime.now(UTC) - timedelta(hours=2))
    seeded.commit()
    assert client.get("/breakglass").status_code == 404
    token = csrf_of(client)
    assert (
        client.post("/breakglass", data={"password": password, "csrf_token": token}).status_code
        == 404
    )
