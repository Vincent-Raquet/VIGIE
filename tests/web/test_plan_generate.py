"""« Générer le plan maintenant » : demande déposée par le web, coût précédent affiché."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.webfixtures import login
from vigie.db import models
from vigie.db.enums import AppRole, JobKind, JobStatus, LLMOutcome

pytestmark = pytest.mark.db

TODAY = datetime.now(UTC).date()


def _call(session: Session, cost: str) -> None:
    session.add(
        models.LLMCall(
            at=datetime.now(UTC),
            model="claude-sonnet-5-5",
            cost_usd=Decimal(cost),
            prompt_hash="b" * 64,
            outcome=LLMOutcome.ok,
        )
    )
    session.commit()


def _ask(client: TestClient, token: str, **form: str) -> int:
    data = {"kind": "daily", "day": TODAY.isoformat(), "use_llm": "oui", **form}
    r = client.post("/plans/generer", data=data, headers={"X-CSRF-Token": token})
    return r.status_code


def _jobs(session: Session) -> list[models.JobRequest]:
    session.expire_all()
    return list(
        session.scalars(
            select(models.JobRequest).where(models.JobRequest.kind == JobKind.plan_generate)
        )
    )


def audit_actor(session: Session) -> str:
    """Acteur journalisé pour la demande : la même identité que `requested_by`."""
    return session.scalars(
        select(models.AuditLog.actor).where(models.AuditLog.action == "plan_generate_requested")
    ).one()


def test_panel_shows_last_cost_and_month_spend(client: TestClient, seeded: Session) -> None:
    _call(seeded, "0.0512")
    login(client, seeded, "Vincent", AppRole.manager)
    page = client.get("/aujourdhui").text
    assert "Générer maintenant…" in page
    assert "Dernière itération IA : <strong>0.0512 $</strong>" in page
    assert "Ce mois : 0.05 $ sur 30.00 $." in page
    assert "consommé à plus de 80 %" not in page
    assert 'name="kind" value="daily"' in page
    assert 'name="kind" value="weekly"' in client.get("/semaine").text


def test_budget_warning_from_80_percent(client: TestClient, seeded: Session) -> None:
    _call(seeded, "24.5")
    login(client, seeded, "Vincent", AppRole.admin)
    assert "consommé à plus de 80 %" in client.get("/aujourdhui").text


def test_request_is_queued_audited_and_deduplicated(client: TestClient, seeded: Session) -> None:
    token = login(client, seeded, "Vincent", AppRole.admin)
    r = client.post(
        "/plans/generer",
        data={"kind": "daily", "day": TODAY.isoformat(), "use_llm": "non", "next": "/aujourdhui"},
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 303 and r.headers["location"] == "/aujourdhui"
    [job] = _jobs(seeded)
    assert job.status is JobStatus.pending
    assert job.requested_by == audit_actor(seeded)
    assert job.payload == {"kind": "daily", "day": TODAY.isoformat(), "use_llm": False}
    audit = seeded.scalars(
        select(models.AuditLog).where(models.AuditLog.action == "plan_generate_requested")
    ).one()
    assert audit.details == {"kind": "daily", "day": TODAY.isoformat(), "use_llm": False}
    page = client.get("/aujourdhui").text
    assert "Génération demandée" in page and "en attente" in page
    assert 'hx-trigger="every 5s"' in page  # suivi automatique tant que la demande vit
    assert _ask(client, token) == 409  # une seule génération à la fois
    assert len(_jobs(seeded)) == 1


@pytest.mark.parametrize(
    "form",
    [
        {"day": (TODAY + timedelta(days=15)).isoformat()},
        {"day": "pas-une-date"},
        {"use_llm": "peut-être"},
        {"kind": "monthly"},
    ],
)
def test_invalid_requests(client: TestClient, seeded: Session, form: dict[str, str]) -> None:
    token = login(client, seeded, "Vincent", AppRole.admin)
    assert _ask(client, token, **form) == 422
    assert _jobs(seeded) == []


def test_refused_to_tech_and_viewer(client: TestClient, seeded: Session) -> None:
    for role in (AppRole.tech, AppRole.viewer):
        token = login(client, seeded, "Giovanni", role)
        assert _ask(client, token) == 403
        assert client.get("/plans/generation/etat").status_code == 403
    login(client, seeded, "Giovanni", AppRole.tech)
    assert "Générer maintenant" not in client.get("/aujourdhui").text
    assert _jobs(seeded) == []


def test_status_fragment_after_completion(client: TestClient, seeded: Session) -> None:
    job = models.JobRequest(
        kind=JobKind.plan_generate,
        payload={"kind": "daily", "day": "2026-10-12", "use_llm": True},
        requested_by="vincent@example.test",
        status=JobStatus.done,
        result={"ok": True, "plan_id": 42, "cost_usd": "0.0498", "detail": "plan n° 42"},
    )
    seeded.add(job)
    seeded.commit()
    login(client, seeded, "Vincent", AppRole.admin)
    fragment = client.get("/plans/generation/etat").text
    assert "terminée" in fragment and "plan n° 42" in fragment and "coût 0.0498 $" in fragment
    assert "/aujourdhui?day=2026-10-12" in fragment
    assert "hx-trigger" not in fragment  # terminé : plus de rafraîchissement
