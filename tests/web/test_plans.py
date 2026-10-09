"""Écrans des plans, suivi des tâches, validation : rôles et contenus."""

from datetime import date
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.unit.engine.test_pipeline_db import NOW, load_zabbix
from tests.webfixtures import login, person_id
from vigie.config import PlansConfig
from vigie.db import models
from vigie.db.enums import AppRole, PlanKind, PlanStatus, TaskOrigin, TaskStatus
from vigie.engine.planner import build_plan, run_engine, save_plan
from vigie.web.routes.plans import safe_next

pytestmark = pytest.mark.db

TZ = ZoneInfo("Europe/Brussels")
FRIDAY = date(2026, 10, 9)
AI = {
    "by_llm": True,
    "summary_exec": "Deux urgences réseau.\nProxys à rétablir.",
    "per_person": {},
    "risks": [{"text": "Capacité système faible.", "severity": "medium"}],
    "escalations": [{"text": "Arbitrer le backlog.", "to": "manager"}],
    "rejections": ["incident:77 : référence inconnue ignorée"],
}


@pytest.fixture
def plans(seeded: Session) -> dict[str, models.Plan]:
    load_zabbix(seeded)
    run_engine(seeded, NOW)
    daily = build_plan(seeded, PlanKind.daily, FRIDAY, NOW, PlansConfig(), tz=TZ)
    weekly = build_plan(seeded, PlanKind.weekly, date(2026, 10, 13), NOW, PlansConfig(), tz=TZ)
    saved = {
        "daily": save_plan(seeded, daily, "", ai=AI),
        "weekly": save_plan(
            seeded, weekly, "", ai={"by_llm": False, "without_ai_reason": "option --no-llm"}
        ),
    }
    seeded.commit()
    return saved


def tasks_of(session: Session, name: str, plan: models.Plan) -> list[models.Task]:
    return list(
        session.scalars(
            select(models.Task).where(
                models.Task.plan_id == plan.id, models.Task.assignee_id == person_id(session, name)
            )
        )
    )


@pytest.mark.parametrize(
    ("role", "path", "status"),
    [
        (AppRole.admin, "/aujourdhui", 200),
        (AppRole.manager, "/aujourdhui", 200),
        (AppRole.tech, "/aujourdhui", 200),
        (AppRole.viewer, "/aujourdhui", 403),
        (AppRole.viewer, "/semaine", 200),
        (AppRole.tech, "/semaine", 200),
    ],
)
def test_page_access_by_role(
    client: TestClient,
    plans: dict[str, models.Plan],
    seeded: Session,
    role: AppRole,
    path: str,
    status: int,
) -> None:
    login(client, seeded, "Giovanni", role)
    assert client.get(path, params={"day": "2026-10-09"}).status_code == status


def test_landing_page_depends_on_role(client: TestClient, seeded: Session) -> None:
    login(client, seeded, "Giovanni", AppRole.viewer)
    assert client.get("/").headers["location"] == "/semaine"
    nav = client.get("/semaine").text
    assert (
        'href="/semaine"' in nav and 'href="/aujourdhui"' not in nav and 'href="/equipe"' not in nav
    )


def test_today_page_content(
    client: TestClient, plans: dict[str, models.Plan], seeded: Session
) -> None:
    login(client, seeded, "Vincent", AppRole.admin)
    page = client.get("/aujourdhui", params={"day": "2026-10-09"}).text
    assert "Plan du vendredi 9 octobre 2026" in page
    assert "brouillon non validé" in page and "affiné par l'IA" in page
    assert "<h3>Vincent</h3>" in page and "<h3>Giovanni</h3>" in page
    assert "Synthèse de l'IA" in page and "Proxys à rétablir." in page
    assert "Capacité système faible." in page and "Arbitrer le backlog." in page
    assert "1 proposition(s) de l'IA écartée(s)" in page
    assert "Valider le plan" in page
    assert '<meter class="cap"' in page


def test_week_page_content(
    client: TestClient, plans: dict[str, models.Plan], seeded: Session
) -> None:
    login(client, seeded, "Cédric", AppRole.tech)
    page = client.get("/semaine", params={"day": "2026-10-13"}).text
    assert "Semaine du 12/10 au 16/10/2026" in page
    assert "sans IA (option --no-llm)" in page
    assert "absent" in page  # Cédric et Angelo ne sont présents qu'un jour
    assert "Valider le plan" not in page and "Ajouter une tâche" not in page  # tech


def test_no_plan_yet(client: TestClient, seeded: Session) -> None:
    login(client, seeded, "Vincent", AppRole.admin)
    assert "Aucun plan quotidien" in client.get("/aujourdhui", params={"day": "2020-01-06"}).text
    assert client.get("/aujourdhui", params={"day": "pas-une-date"}).status_code == 422


def test_tech_updates_own_task_only(
    client: TestClient, plans: dict[str, models.Plan], seeded: Session
) -> None:
    token = login(client, seeded, "Giovanni", AppRole.tech)
    own = tasks_of(seeded, "Giovanni", plans["daily"])[0]
    other = tasks_of(seeded, "Vincent", plans["daily"])[0]
    headers = {"X-CSRF-Token": token, "HX-Request": "true"}
    r = client.post(f"/taches/{own.id}/statut", data={"status": "in_progress"}, headers=headers)
    assert r.status_code == 200 and f'id="task-{own.id}"' in r.text and "<html" not in r.text
    seeded.refresh(own)
    assert own.status is TaskStatus.in_progress
    r = client.post(f"/taches/{other.id}/statut", data={"status": "done"}, headers=headers)
    assert r.status_code == 403
    seeded.refresh(other)
    assert other.status is TaskStatus.todo
    assert (
        client.post("/taches/999999/statut", data={"status": "done"}, headers=headers).status_code
        == 404
    )


def test_status_rules(client: TestClient, plans: dict[str, models.Plan], seeded: Session) -> None:
    token = login(client, seeded, "Vincent", AppRole.admin)
    task = tasks_of(seeded, "Giovanni", plans["daily"])[0]
    headers = {"X-CSRF-Token": token}
    assert (
        client.post(
            f"/taches/{task.id}/statut", data={"status": "wont_do"}, headers=headers
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/taches/{task.id}/statut", data={"status": "pending_done"}, headers=headers
        ).status_code
        == 422
    )
    r = client.post(
        f"/taches/{task.id}/statut",
        data={"status": "wont_do", "reason": "Doublon du ticket", "next": "//evil.test"},
        headers=headers,
    )
    assert (r.status_code, r.headers["location"]) == (303, "/aujourdhui")
    seeded.refresh(task)
    assert (task.status, task.status_reason) == (TaskStatus.wont_do, "Doublon du ticket")
    audit = seeded.scalars(
        select(models.AuditLog).where(models.AuditLog.action == "task_status")
    ).all()
    assert audit[-1].details == {"before": "todo", "after": "wont_do"}


def test_comments(client: TestClient, plans: dict[str, models.Plan], seeded: Session) -> None:
    token = login(client, seeded, "Cédric", AppRole.tech)
    task = tasks_of(seeded, "Vincent", plans["daily"])[0]
    r = client.post(
        f"/taches/{task.id}/commentaires",
        data={"body": "<b>Je regarde jeudi</b>"},
        headers={"X-CSRF-Token": token, "HX-Request": "true"},
    )
    assert r.status_code == 200
    assert "&lt;b&gt;Je regarde jeudi&lt;/b&gt;" in r.text  # échappé
    assert seeded.scalars(select(models.TaskComment)).one().author_id == person_id(seeded, "Cédric")


def test_validate_then_publish(
    client: TestClient, plans: dict[str, models.Plan], seeded: Session
) -> None:
    weekly = plans["weekly"]
    token = login(client, seeded, "Giovanni", AppRole.tech)
    assert (
        client.post(f"/plans/{weekly.id}/valider", headers={"X-CSRF-Token": token}).status_code
        == 403
    )
    token = login(client, seeded, "Vincent", AppRole.manager)
    headers = {"X-CSRF-Token": token}
    assert client.post(f"/plans/{weekly.id}/valider", headers=headers).status_code == 303
    seeded.refresh(weekly)
    assert weekly.status is PlanStatus.validated and weekly.validated_by == person_id(
        seeded, "Vincent"
    )
    assert client.post(f"/plans/{weekly.id}/valider", headers=headers).status_code == 409
    assert client.post(f"/plans/{weekly.id}/publier", headers=headers).status_code == 303
    seeded.refresh(weekly)
    assert weekly.status is PlanStatus.published and weekly.published_at is not None
    assert client.post(f"/plans/{weekly.id}/publier", headers=headers).status_code == 409
    assert client.post("/plans/999999/publier", headers=headers).status_code == 404


def test_manual_task(client: TestClient, plans: dict[str, models.Plan], seeded: Session) -> None:
    weekly = plans["weekly"]
    token = login(client, seeded, "Vincent", AppRole.admin)
    form = {
        "csrf_token": token,
        "title": "Préparer la venue d'Angelo",
        "category": "server",
        "priority": "P3",
        "estimate_h": "0.5",
        "assignee_id": str(person_id(seeded, "Giovanni")),
        "day": "2026-10-12",
    }
    assert client.post(f"/plans/{weekly.id}/taches", data=form).status_code == 303
    task = seeded.scalars(select(models.Task).where(models.Task.origin == TaskOrigin.human)).one()
    assert (task.not_before, task.title) == (date(2026, 10, 12), "Préparer la venue d'Angelo")
    assert (
        client.post(f"/plans/{weekly.id}/taches", data={**form, "day": "2026-11-30"}).status_code
        == 422
    )
    assert (
        client.post(f"/plans/{weekly.id}/taches", data={**form, "assignee_id": "x"}).status_code
        == 422
    )
    assert (
        client.post(
            f"/plans/{weekly.id}/taches", data={**form, "assignee_id": "", "day": ""}
        ).status_code
        == 303
    )


def test_safe_next() -> None:
    assert safe_next("/semaine?day=2026-10-13", "/") == "/semaine?day=2026-10-13"
    for bad in ("//evil.test", "https://evil.test", "/\\evil", None, ""):
        assert safe_next(bad, "/x") == "/x"
