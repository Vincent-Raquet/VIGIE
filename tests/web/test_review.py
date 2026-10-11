"""Rodage (phase 9) : revue des tâches et des plans par le coordinateur, page Rodage."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.webfixtures import login, tasks_of
from vigie import rodage
from vigie.db import models
from vigie.db.enums import AppRole

pytestmark = pytest.mark.db


def _review(
    client: TestClient, token: str, task_id: int, relevant: str, assigned: str, note: str = ""
) -> int:
    r = client.post(
        f"/taches/{task_id}/revue",
        data={"relevant": relevant, "well_assigned": assigned, "note": note},
        headers={"X-CSRF-Token": token, "HX-Request": "true"},
    )
    return r.status_code


def test_lead_reviews_a_task_with_htmx(
    client: TestClient, plans: dict[str, models.Plan], seeded: Session
) -> None:
    token = login(client, seeded, "Vincent", AppRole.manager)
    task = tasks_of(seeded, "Giovanni", plans["daily"])[0]
    r = client.post(
        f"/taches/{task.id}/revue",
        data={"relevant": "oui", "well_assigned": "non", "note": "plutôt pour Cédric"},
        headers={"X-CSRF-Token": token, "HX-Request": "true"},
    )
    assert r.status_code == 200
    assert f'id="task-{task.id}"' in r.text and "✗ mal affectée" in r.text
    seeded.expire_all()
    review = seeded.get(models.TaskReview, task.id)
    assert review is not None and review.relevant and not review.well_assigned
    assert review.note == "plutôt pour Cédric"
    entry = seeded.scalars(
        select(models.AuditLog).where(models.AuditLog.action == "task_review")
    ).one()
    assert entry.details == {"relevant": True, "well_assigned": False}  # sans la note

    # Un second jugement remplace le premier.
    assert _review(client, token, task.id, "oui", "oui") == 200
    seeded.expire_all()
    review = seeded.get(models.TaskReview, task.id)
    assert review is not None and review.well_assigned and review.note == ""


def test_review_refused_to_tech_and_viewer(
    client: TestClient, plans: dict[str, models.Plan], seeded: Session
) -> None:
    task = tasks_of(seeded, "Giovanni", plans["daily"])[0]
    for role in (AppRole.tech, AppRole.viewer):
        token = login(client, seeded, "Giovanni", role)
        assert _review(client, token, task.id, "oui", "oui") == 403
    assert seeded.get(models.TaskReview, task.id) is None


def test_review_validates_values(
    client: TestClient, plans: dict[str, models.Plan], seeded: Session
) -> None:
    token = login(client, seeded, "Vincent", AppRole.admin)
    task = tasks_of(seeded, "Giovanni", plans["daily"])[0]
    assert _review(client, token, task.id, "peut-être", "oui") == 422
    assert _review(client, token, task.id, "oui", "oui", "x" * 301) == 422
    assert _review(client, token, 999_999, "oui", "oui") == 404


def test_review_form_shown_to_leads_only(
    client: TestClient, plans: dict[str, models.Plan], seeded: Session
) -> None:
    login(client, seeded, "Vincent", AppRole.admin)
    page = client.get("/aujourdhui", params={"day": "2026-10-09"}).text
    assert "/revue" in page and "Revue du plan (rodage)" in page
    login(client, seeded, "Giovanni", AppRole.tech)
    page = client.get("/aujourdhui", params={"day": "2026-10-09"}).text
    assert "/revue" not in page and "Revue du plan" not in page


def test_plan_review(client: TestClient, plans: dict[str, models.Plan], seeded: Session) -> None:
    token = login(client, seeded, "Vincent", AppRole.admin)
    plan = plans["daily"]
    r = client.post(
        f"/plans/{plan.id}/revue",
        data={
            "missing": "Le renouvellement du certificat VPN",
            "next": "/aujourdhui?day=2026-10-09",
        },
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 303 and r.headers["location"] == "/aujourdhui?day=2026-10-09"
    seeded.expire_all()
    review = seeded.get(models.PlanReview, plan.id)
    assert review is not None and review.missing == "Le renouvellement du certificat VPN"
    page = client.get("/aujourdhui", params={"day": "2026-10-09"}).text
    assert "Le renouvellement du certificat VPN" in page


def test_rodage_stats_and_page(
    client: TestClient, plans: dict[str, models.Plan], seeded: Session
) -> None:
    token = login(client, seeded, "Vincent", AppRole.admin)
    daily = plans["daily"]
    planned = [
        t
        for t in seeded.scalars(select(models.Task).where(models.Task.plan_id == daily.id))
        if t.assignee_id is not None and (t.not_before is None or t.not_before <= daily.period_end)
    ]
    assert planned
    for i, task in enumerate(planned):
        bad = i == 0
        assert _review(client, token, task.id, "non" if bad else "oui", "oui", "doublon") == 200

    seeded.expire_all()
    [day] = [d for d in rodage.day_stats(seeded) if d.plan_id == daily.id]
    assert day.planned == len(planned) and day.reviewed == len(planned)
    assert day.both == len(planned) - 1
    assert day.validated == ((len(planned) - 1) / len(planned) >= 0.8)

    page = client.get("/rodage").text
    assert "jours validés consécutifs" in page
    assert "non pertinente" in page and "doublon" in page
    assert planned[0].title in page
