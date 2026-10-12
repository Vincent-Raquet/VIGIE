"""Choix du modèle d'IA : défaut dans Paramètres (admin), ponctuel pour un plan ou une question."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.webfixtures import login
from vigie.ai_models import SETTING_KEY
from vigie.db import models
from vigie.db.enums import AppRole, JobKind

pytestmark = pytest.mark.db


def set_default(client: TestClient, token: str, model: str) -> int:
    r = client.post("/parametres/modele", data={"model": model}, headers={"X-CSRF-Token": token})
    return r.status_code


def test_admin_sets_default_model_audited(client: TestClient, seeded: Session) -> None:
    token = login(client, seeded, "Vincent", AppRole.admin)
    page = client.get("/parametres").text
    assert 'value="claude-fable-5-1"' in page and "Claude Opus 5.5" in page
    assert set_default(client, token, "claude-opus-5-5") == 303
    seeded.expire_all()
    assert seeded.get(models.Setting, SETTING_KEY).value == "claude-opus-5-5"  # type: ignore[union-attr]
    entry = seeded.scalars(
        select(models.AuditLog).where(models.AuditLog.action == "llm_model_set")
    ).one()
    assert entry.details == {"avant": "claude-sonnet-5-5", "après": "claude-opus-5-5"}
    assert set_default(client, token, "gpt-4") == 422


@pytest.mark.parametrize("role", [AppRole.manager, AppRole.tech, AppRole.viewer])
def test_only_admin_sets_default(client: TestClient, seeded: Session, role: AppRole) -> None:
    token = login(client, seeded, "Giovanni", role)
    assert set_default(client, token, "claude-fable-5-1") == 403
    assert seeded.get(models.Setting, SETTING_KEY) is None


def test_plan_generation_with_model(client: TestClient, seeded: Session) -> None:
    token = login(client, seeded, "Vincent", AppRole.manager)
    assert 'name="model"' in client.get("/aujourdhui").text
    day = datetime.now(UTC).date().isoformat()
    form = {"kind": "daily", "day": day, "use_llm": "oui", "model": "claude-fable-5-1"}
    r = client.post("/plans/generer", data=form, headers={"X-CSRF-Token": token})
    assert r.status_code == 303
    job = seeded.scalars(
        select(models.JobRequest).where(models.JobRequest.kind == JobKind.plan_generate)
    ).one()
    assert job.payload["model"] == "claude-fable-5-1"
    assert "Claude Fable 5.1" in client.get("/plans/generation/etat").text
    form = {**form, "model": "gpt-4"}
    assert (
        client.post("/plans/generer", data=form, headers={"X-CSRF-Token": token}).status_code == 422
    )


def test_chat_question_with_model(client: TestClient, plans: dict, seeded: Session) -> None:
    inc = seeded.scalars(select(models.Incident).order_by(models.Incident.id)).first()
    assert inc is not None
    token = login(client, seeded, "Giovanni", AppRole.tech)
    data = {"anchor": "incident", "anchor_id": str(inc.id), "content": "Pourquoi ?"}
    bad = client.post("/chat/questions", data={**data, "model": "gpt-4"},
                      headers={"X-CSRF-Token": token})  # fmt: skip
    assert "Modèle d&#39;IA inconnu" in bad.text  # apostrophe échappée par Jinja
    client.post("/chat/questions", data={**data, "model": "claude-opus-5-5"},
                headers={"X-CSRF-Token": token})  # fmt: skip
    [m] = seeded.scalars(select(models.ChatMessage)).all()
    assert m.model == "claude-opus-5-5"
    page = client.get(f"/chat/panneau?anchor=incident&anchor_id={inc.id}").text
    assert "Claude Opus 5.5" in page
