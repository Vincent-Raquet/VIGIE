"""Aide en ligne : accessible à tous les rôles, valeurs lues dans la configuration en vigueur."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from tests.webfixtures import login
from vigie.db import models
from vigie.db.enums import AppRole

pytestmark = pytest.mark.db

PAGES = ("/aide", "/aide/principes", "/aide/fonctionnement", "/aide/mode-emploi")


def test_anonymous_is_redirected(client: TestClient) -> None:
    for path in PAGES:
        r = client.get(path, follow_redirects=False)
        assert (r.status_code, r.headers["location"]) == (303, "/login"), path


@pytest.mark.parametrize("role", list(AppRole))
def test_every_role_reads_help(client: TestClient, seeded: Session, role: AppRole) -> None:
    login(client, seeded, "Vincent", role)
    for path in PAGES:
        r = client.get(path)
        assert r.status_code == 200, (role, path)
        assert 'href="/aide"' in r.text  # entrée du menu
    assert client.get("/aide/inconnue").status_code == 404
    page = client.get("/aide/mode-emploi").text
    assert f"le rôle <strong>{role.value}</strong>" in page


def test_values_follow_current_scoring(client: TestClient, seeded: Session) -> None:
    login(client, seeded, "Vincent", AppRole.tech)
    page = client.get("/aide/fonctionnement").text
    assert "Zabbix sévérité Disaster" in page  # règle d'override par défaut
    assert "07:15" in page
    thresholds = {"P1": 70, "P2": 40, "P3": 12}
    seeded.merge(models.Setting(key="scoring", value={"thresholds": thresholds}))
    seeded.commit()
    page = client.get("/aide/fonctionnement").text
    assert '<td class="num">70</td>' in page and '<td class="num">12</td>' in page
