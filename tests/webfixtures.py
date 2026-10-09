"""Fixtures de l'application web (base de test, connexion de dev) : plugin pytest."""

import re
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, select
from sqlalchemy.orm import Session

from tests.conftest import REPO_ROOT
from vigie.config import OIDCConfig, VigieConfig, WebConfig
from vigie.db import models
from vigie.db.enums import AppRole
from vigie.seed import apply_seed, load_seed_data
from vigie.web.app import create_app

SESSION_KEY = "test-session-key-" + "x" * 32
DEV = {"VIGIE_ENV": "dev"}
TENANT = "11111111-1111-1111-1111-111111111111"
GROUPS = {
    "aaaaaaaa-0000-0000-0000-000000000001": AppRole.admin,
    "aaaaaaaa-0000-0000-0000-000000000002": AppRole.manager,
    "aaaaaaaa-0000-0000-0000-000000000003": AppRole.tech,
    "aaaaaaaa-0000-0000-0000-000000000004": AppRole.viewer,
}


def config(**web: Any) -> VigieConfig:
    oidc = OIDCConfig(tenant_id=TENANT, client_id=TENANT.replace("1", "2"), groups=GROUPS)
    return VigieConfig(web=WebConfig(**{"dev_login": True, "oidc": oidc, **web}))


@pytest.fixture
def seeded(db_session: Session) -> Session:
    apply_seed(db_session, load_seed_data(REPO_ROOT / "config", REPO_ROOT / "roles"))
    db_session.commit()
    return db_session


@pytest.fixture
def make_client(db_conn: Connection, seeded: Session) -> Iterator[Callable[..., TestClient]]:
    clients: list[TestClient] = []

    def factory(env: dict[str, str] | None = None, oidc: Any = None, **web: Any) -> TestClient:
        app = create_app(
            config(**web),
            session_key=SESSION_KEY,
            oidc_client=oidc,
            engine=db_conn,
            env=DEV if env is None else env,
        )
        client = TestClient(app, base_url="http://127.0.0.1", follow_redirects=False)
        clients.append(client)
        return client

    yield factory
    for c in clients:
        c.close()


@pytest.fixture
def client(make_client: Callable[..., TestClient]) -> TestClient:
    return make_client()


def csrf_of(client: TestClient, path: str = "/login") -> str:
    page = client.get(path)
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text) or re.search(
        r'"X-CSRF-Token": "([^"]+)"', page.text
    )
    assert match, f"jeton CSRF introuvable sur {path}"
    return match.group(1)


def person_id(session: Session, name: str) -> int:
    pid = session.scalar(select(models.Person.id).where(models.Person.name == name))
    assert pid is not None
    return pid


def login(client: TestClient, session: Session, name: str, role: AppRole) -> str:
    """Connexion de développement ; renvoie le jeton CSRF de la nouvelle session."""
    token = csrf_of(client, "/dev-login")
    r = client.post(
        "/dev-login",
        data={"person_id": person_id(session, name), "role": role.value, "csrf_token": token},
    )
    assert r.status_code == 303, r.text
    return csrf_of(client, "/semaine")
