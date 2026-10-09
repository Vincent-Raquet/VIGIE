"""API JSON (SPEC §10) : rôles, CSRF, visibilité, mêmes règles que l'interface."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.webfixtures import login, tasks_of
from vigie.db import models
from vigie.db.enums import AppRole, JobKind, PlanStatus

pytestmark = pytest.mark.db


def test_api_requires_authentication(client: TestClient) -> None:
    for path in ("/api/plans", "/api/incidents", "/api/costs"):
        r = client.get(path)
        assert r.status_code == 401 and r.json() == {"detail": "Authentification requise."}


def test_plans_listing_and_detail(
    client: TestClient, plans: dict[str, models.Plan], seeded: Session
) -> None:
    login(client, seeded, "Giovanni", AppRole.tech)
    listed = client.get("/api/plans").json()
    assert {p["kind"] for p in listed} == {"daily", "weekly"}
    assert [p["kind"] for p in client.get("/api/plans", params={"kind": "daily"}).json()] == [
        "daily"
    ]
    assert client.get("/api/plans", params={"date": "2026-10-09"}).json()[0]["kind"] == "daily"
    detail = client.get(f"/api/plans/{plans['daily'].id}").json()
    assert detail["ai"]["summary_exec"].startswith("Deux urgences")
    assert detail["tasks"] and {"title", "status", "assignee_id", "day"} <= set(detail["tasks"][0])

    login(client, seeded, "Giovanni", AppRole.viewer)
    assert {p["kind"] for p in client.get("/api/plans").json()} == {"weekly"}
    assert client.get(f"/api/plans/{plans['daily'].id}").status_code == 404
    assert client.get(f"/api/plans/{plans['weekly'].id}").status_code == 200
    assert client.get("/api/incidents").status_code == 403


def test_patch_task(client: TestClient, plans: dict[str, models.Plan], seeded: Session) -> None:
    token = login(client, seeded, "Giovanni", AppRole.tech)
    own = tasks_of(seeded, "Giovanni", plans["daily"])[0]
    other = tasks_of(seeded, "Vincent", plans["daily"])[0]
    assert client.patch(f"/api/tasks/{own.id}", json={"status": "done"}).status_code == 403  # CSRF
    h = {"X-CSRF-Token": token}
    r = client.patch(
        f"/api/tasks/{own.id}", json={"status": "done", "comment": "Réglé."}, headers=h
    )
    assert r.status_code == 200 and r.json()["status"] == "done"
    assert seeded.scalars(select(models.TaskComment)).one().body == "Réglé."
    assert (
        client.patch(f"/api/tasks/{other.id}", json={"status": "done"}, headers=h).status_code
        == 403
    )
    assert client.patch(f"/api/tasks/{own.id}", json={}, headers=h).status_code == 422
    assert (
        client.patch(f"/api/tasks/{own.id}", json={"status": "wont_do"}, headers=h).status_code
        == 422
    )
    assert client.patch(f"/api/tasks/{own.id}", json={"evil": 1}, headers=h).status_code == 422
    assert client.patch("/api/tasks/999999", json={"status": "done"}, headers=h).status_code == 404


def test_validate_via_api(
    client: TestClient, plans: dict[str, models.Plan], seeded: Session
) -> None:
    token = login(client, seeded, "Giovanni", AppRole.tech)
    url = f"/api/plans/{plans['weekly'].id}/validate"
    assert client.post(url, headers={"X-CSRF-Token": token}).status_code == 403
    token = login(client, seeded, "Vincent", AppRole.manager)
    r = client.post(url, headers={"X-CSRF-Token": token})
    assert r.status_code == 200 and r.json()["status"] == PlanStatus.validated.value
    assert client.post(url, headers={"X-CSRF-Token": token}).status_code == 409


def test_incidents_signals_sources_costs(
    client: TestClient, plans: dict[str, models.Plan], seeded: Session
) -> None:
    token = login(client, seeded, "Vincent", AppRole.admin)
    incidents = client.get("/api/incidents", params={"priority": "P1"}).json()
    assert incidents and all(i["priority"] == "P1" for i in incidents)
    sigs = client.get("/api/signals", params={"source": "zabbix", "limit": 5}).json()
    assert len(sigs) == 5 and "details" not in sigs[0]
    assert client.get("/api/signals", params={"limit": 10_000}).status_code == 422
    assert client.get("/api/sources").json()[0]["name"] == "zabbix"
    assert (
        client.post("/api/sources/zabbix/test", headers={"X-CSRF-Token": token}).status_code == 404
    )  # non configurée
    client.app.state.cfg.sources["zabbix"] = object()  # type: ignore[attr-defined]
    r = client.post("/api/sources/zabbix/test", headers={"X-CSRF-Token": token})
    assert r.status_code == 202 and r.json()["status"] == "pending"
    assert seeded.scalars(select(models.JobRequest)).one().kind is JobKind.source_test
    costs = client.get("/api/costs").json()
    assert costs["calls"] == 0 and costs["budget_usd"] == "30.00" and costs["spent_usd"] == "0.0000"
    login(client, seeded, "Vincent", AppRole.manager)
    assert client.get("/api/costs").status_code == 403
