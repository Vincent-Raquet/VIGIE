"""Signaux & incidents, sources (test de connexion via le worker), audit & coûts."""

from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.unit.engine.test_pipeline_db import NOW, load_zabbix
from tests.webfixtures import login
from vigie.connectors.base import HealthStatus, SourceCallError
from vigie.db import models
from vigie.db.enums import AppRole, JobKind, JobStatus, LLMOutcome
from vigie.engine.planner import run_engine
from vigie.jobs_runner import run_pending
from vigie.links import source_link

pytestmark = pytest.mark.db


@pytest.fixture
def incidents(seeded: Session) -> Session:
    load_zabbix(seeded)
    run_engine(seeded, NOW)
    seeded.commit()
    return seeded


def test_source_links_are_built_safely() -> None:
    base = "https://zabbix.example.test"
    assert source_link("zabbix", {"eventid": "1", "triggerid": "2"}, base) == (
        "https://zabbix.example.test/tr_events.php?triggerid=2&eventid=1"
    )
    assert source_link("zabbix", {"hostid": "10959"}, base + "/").endswith("hostids%5B%5D=10959")
    assert source_link("zabbix", {"eventid": "1 OR 1=1", "triggerid": "2"}, base) is None
    assert source_link("zabbix", {"eventid": "1", "triggerid": "2"}, "http://zabbix.test") is None
    assert source_link("zabbix", {"eventid": "1"}, base) is None
    assert source_link("veeam", {"id": "1"}, base) is None
    assert source_link("zabbix", {"eventid": "1", "triggerid": "2"}, None) is None


def test_signals_list_filters_and_detail(client: TestClient, incidents: Session) -> None:
    login(client, incidents, "Giovanni", AppRole.tech)
    page = client.get("/signaux").text
    assert "sw-wg-ot-01" in page and "proxy-wg-01" in page
    only_p1 = client.get("/signaux", params={"priority": "P1"}).text
    assert "sw-wg-ot-01" in only_p1 and "proxy-wg-01" not in only_p1
    assert "Aucun incident" in client.get("/signaux", params={"company": "FWD"}).text
    assert "Aucun incident" in client.get("/signaux", params={"source": "veeam"}).text
    assert client.get("/signaux", params={"status": "nimporte"}).status_code == 422

    incident = incidents.scalars(
        select(models.Incident).where(models.Incident.asset == "sw-wg-ot-01")
    ).one()
    detail = client.get(f"/signaux/incidents/{incident.id}").text
    assert "Raison de la priorité" in detail and "Interface Fa1/7(): FCS ERRORS" in detail
    assert "ouvrir" not in detail  # pas d'URL de base Zabbix configurée : aucun lien
    assert client.get("/signaux/incidents/999999").status_code == 404


def test_signals_forbidden_for_viewer(client: TestClient, incidents: Session) -> None:
    login(client, incidents, "Giovanni", AppRole.viewer)
    assert client.get("/signaux").status_code == 403


def test_detail_link_when_base_url_configured(
    make_client: Any, incidents: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = make_client()
    cfg = client.app.state.cfg  # type: ignore[attr-defined]
    monkeypatch.setitem(
        cfg.sources, "zabbix", SimpleNamespace(base_url="https://zabbix.example.test", enabled=True)
    )
    login(client, incidents, "Vincent", AppRole.admin)
    incident = incidents.scalars(
        select(models.Incident).where(models.Incident.asset == "sw-wg-ot-01")
    ).one()
    detail = client.get(f"/signaux/incidents/{incident.id}").text
    assert 'href="https://zabbix.example.test/tr_events.php?triggerid=' in detail
    assert 'rel="noopener noreferrer"' in detail


def test_sources_page_and_connection_test(make_client: Any, incidents: Session) -> None:
    client = make_client()
    cfg = client.app.state.cfg  # type: ignore[attr-defined]
    cfg.sources["zabbix"] = SimpleNamespace(base_url="https://zabbix.example.test", enabled=True)
    token = login(client, incidents, "Giovanni", AppRole.tech)
    assert client.get("/sources").status_code == 403
    assert client.post("/sources/zabbix/tester", headers={"X-CSRF-Token": token}).status_code == 403
    token = login(client, incidents, "Vincent", AppRole.admin)
    page = client.get("/sources").text
    assert "zabbix" in page and "Tester la connexion" in page
    r = client.post("/sources/zabbix/tester", headers={"X-CSRF-Token": token})
    assert (r.status_code, r.headers["location"]) == (303, "/sources")
    job = incidents.scalars(select(models.JobRequest)).one()
    assert (job.kind, job.payload, job.status) == (
        JobKind.source_test,
        {"source": "zabbix"},
        JobStatus.pending,
    )
    assert "Test de zabbix demandé" in client.get("/sources").text
    assert (
        client.post("/sources/inconnue/tester", headers={"X-CSRF-Token": token}).status_code == 404
    )


class FakeConnector:
    def __init__(self, health: HealthStatus | Exception) -> None:
        self.health = health

    def healthcheck(self) -> HealthStatus:
        if isinstance(self.health, Exception):
            raise self.health
        return self.health


def test_worker_runs_pending_jobs(seeded: Session) -> None:
    from vigie.db.jobs import new_job_request

    for name in ("zabbix", "veeam", "ninjaone"):
        seeded.add(new_job_request("source_test", {"source": name}, requested_by="admin"))
    bad = models.JobRequest(
        kind=JobKind.source_test, payload={"source": "x", "extra": 1}, requested_by="?"
    )
    seeded.add(bad)
    seeded.flush()
    results = {
        "zabbix": FakeConnector(HealthStatus(ok=True, version="7.4.0", latency_ms=12.5)),
        "veeam": FakeConnector(SourceCallError("veeam : HTTP 503 (GET /api/v1/serverInfo)")),
        "ninjaone": FakeConnector(RuntimeError("secret ninjaone absent : valeur=xyz")),
    }
    done = run_pending(
        seeded, lambda name: results[name], now=lambda: datetime(2026, 10, 9, tzinfo=UTC)
    )
    by_source = {j.payload.get("source"): j for j in done}
    assert by_source["zabbix"].status is JobStatus.done
    assert by_source["zabbix"].result == {
        "ok": True,
        "detail": "",
        "version": "7.4.0",
        "latency_ms": 12.5,
    }
    assert (
        by_source["veeam"].status is JobStatus.failed
        and "HTTP 503" in by_source["veeam"].result["detail"]
    )
    ninja = by_source["ninjaone"].result
    assert ninja == {"ok": False, "detail": "échec (RuntimeError)"}  # pas de contenu d'exception
    assert by_source["x"].result == {"ok": False, "detail": "demande invalide"}
    assert all(j.done_at is not None for j in done)
    assert run_pending(seeded, lambda name: results[name]) == []


def test_audit_page(client: TestClient, incidents: Session) -> None:
    incidents.add(
        models.LLMCall(
            at=datetime.now(UTC),
            model="claude-sonnet-5-5",
            input_tokens=15000,
            cached_tokens=5000,
            output_tokens=5000,
            cost_usd=Decimal("0.0871"),
            prompt_hash="a" * 64,
            outcome=LLMOutcome.ok,
        )
    )
    incidents.commit()
    token = login(client, incidents, "Giovanni", AppRole.manager)
    assert client.get("/audit").status_code == 403
    login(client, incidents, "Vincent", AppRole.admin)
    page = client.get("/audit").text
    assert "0.09 $" in page and "claude-sonnet-5-5" in page and "25 %" in page
    assert "login" in page  # les connexions sont journalisées
    assert "login" in client.get("/audit", params={"action": "login"}).text
    assert client.get("/audit", params={"page": 0}).status_code == 422
    assert token
