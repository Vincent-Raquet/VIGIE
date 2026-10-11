"""Réglage du barème depuis Paramètres (rodage, phase 9)."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.webfixtures import login
from vigie.db import models
from vigie.db.enums import AppRole, Category
from vigie.engine.settings import load_scoring

pytestmark = pytest.mark.db


def _post(client: TestClient, seeded: Session, data: dict[str, str]) -> str:
    token = login(client, seeded, "Vincent", AppRole.admin)
    r = client.post("/parametres/bareme", data=data, headers={"X-CSRF-Token": token})
    assert r.status_code == 303 and r.headers["location"] == "/parametres#bareme"
    return client.get("/parametres").text


def test_form_shows_current_values(client: TestClient, seeded: Session) -> None:
    login(client, seeded, "Vincent", AppRole.admin)
    page = client.get("/parametres").text
    scoring = load_scoring(seeded)
    assert 'id="bareme"' in page
    assert f'name="thr_P1" inputmode="decimal" value="{scoring.thresholds["P1"]:g}"' in page
    assert 'name="age_per_day"' in page and 'name="est_network"' in page


def test_save_updates_only_sent_fields(client: TestClient, seeded: Session) -> None:
    before = load_scoring(seeded)
    page = _post(
        client,
        seeded,
        {"thr_P1": "65", "sev_4": "40,5", "est_network": "2,5", "cw_backup": "1,4"},
    )
    assert "Barème enregistré" in page
    seeded.expire_all()
    after = load_scoring(seeded)
    assert after.thresholds["P1"] == 65 and after.severity_weight[4] == 40.5
    assert after.estimate_h(Category.network) == 2.5
    assert after.category_weight["backup"] == 1.4
    assert after.overrides == before.overrides  # règles d'override intactes
    assert after.thresholds["P2"] == before.thresholds["P2"]
    entry = seeded.scalars(
        select(models.AuditLog).where(models.AuditLog.action == "scoring_save")
    ).one()
    assert set(entry.details["changes"]) == {
        "thresholds",
        "severity_weight",
        "default_estimate_h",
        "category_weight",
    }


def test_empty_category_weight_falls_back_to_default(client: TestClient, seeded: Session) -> None:
    _post(client, seeded, {"cw_security": ""})
    seeded.expire_all()
    scoring = load_scoring(seeded)
    assert "security" not in scoring.category_weight
    assert scoring.category_factor(Category.security) == scoring.category_weight.get("default", 1)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"thr_P1": "30"}, "P1 &gt; P2 &gt; P3"),  # sous P2 (texte échappé)
        ({"sev_3": "beaucoup"}, "sev_3"),
        ({"est_backup": "40"}, "est_backup"),  # au-delà de 16 h
        ({"age_per_day": "-1"}, "age_per_day"),
    ],
)
def test_invalid_values_are_refused_without_writing(
    client: TestClient, seeded: Session, data: dict[str, str], message: str
) -> None:
    before = seeded.get(models.Setting, "scoring")
    snapshot = dict(before.value) if before else None
    page = _post(client, seeded, data)
    assert "Barème non enregistré" in page and message in page
    seeded.expire_all()
    after = seeded.get(models.Setting, "scoring")
    assert (dict(after.value) if after else None) == snapshot
    assert not seeded.scalars(
        select(models.AuditLog).where(models.AuditLog.action == "scoring_save")
    ).all()


def test_unchanged_form_writes_nothing(client: TestClient, seeded: Session) -> None:
    scoring = load_scoring(seeded)
    page = _post(client, seeded, {"thr_P1": f"{scoring.thresholds['P1']:g}"})
    assert "Barème inchangé" in page
    assert not seeded.scalars(
        select(models.AuditLog).where(models.AuditLog.action == "scoring_save")
    ).all()
