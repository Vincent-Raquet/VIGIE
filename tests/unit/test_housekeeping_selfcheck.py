"""Purge de rétention, indicateurs de supervision et accès de secours en CLI."""

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import Engine, delete, func, select
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from tests.conftest import TEST_DB_URL
from vigie.cli import app
from vigie.collect import ensure_source, record_failure
from vigie.config import LLMConfig, SourceConfig, VigieConfig
from vigie.db import models
from vigie.db.enums import (
    Category,
    GeneratedBy,
    IncidentStatus,
    JobKind,
    JobStatus,
    LLMOutcome,
    PlanKind,
    PlanStatus,
    Priority,
)
from vigie.housekeeping import purge
from vigie.selfcheck import collect_metrics, write_metrics

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 10, 2, 30, tzinfo=UTC)


def _count(session: Session, model: type[models.Base]) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


def test_purge_respects_retention(db_session: Session) -> None:
    ensure_source(db_session, "zabbix", kind="zabbix")
    old, recent = NOW - timedelta(days=120), NOW - timedelta(days=10)

    def signal(ext: str, resolved: datetime | None) -> models.Signal:
        return models.Signal(
            source="zabbix",
            external_id=ext,
            fingerprint="f" * 64,
            asset="a",
            category=Category.server,
            severity=3,
            title="t",
            first_seen=old,
            last_seen=old,
            resolved_at=resolved,
            raw_hash="h" * 64,
        )

    db_session.add_all([signal("old", old), signal("recent", recent), signal("open", None)])
    db_session.add_all(
        [
            models.Incident(
                fingerprint_group="g1",
                category=Category.server,
                priority=Priority.P3,
                status=IncidentStatus.resolved,
                created_at=old,
                updated_at=old,
            ),
            models.Incident(
                fingerprint_group="g2",
                category=Category.server,
                priority=Priority.P3,
                status=IncidentStatus.open,
                created_at=old,
                updated_at=old,
            ),
        ]
    )
    old_call = models.LLMCall(
        at=NOW - timedelta(days=400),
        model="m",
        prompt_hash="p" * 64,
        outcome=LLMOutcome.ok,
        cost_usd=Decimal(1),
    )
    db_session.add(old_call)
    db_session.flush()

    def plan(end: date, call: int | None = None) -> models.Plan:
        return models.Plan(
            kind=PlanKind.daily,
            period_start=end,
            period_end=end,
            status=PlanStatus.published,
            generated_by=GeneratedBy.llm,
            llm_call_id=call,
            created_at=NOW,
        )

    kept = plan(date(2025, 6, 1), old_call.id)
    db_session.add_all([plan(date(2024, 1, 1)), kept])
    db_session.add_all(
        [
            models.JobRequest(
                kind=JobKind.source_test,
                payload={"source": "zabbix"},
                requested_by="a",
                status=JobStatus.done,
                requested_at=NOW - timedelta(days=40),
            ),
            models.JobRequest(
                kind=JobKind.source_test,
                payload={"source": "zabbix"},
                requested_by="a",
                status=JobStatus.pending,
                requested_at=NOW - timedelta(days=40),
            ),
        ]
    )
    db_session.flush()

    counts = purge(db_session, NOW)
    assert counts == {
        "incident": 1,
        "signal": 1,
        "plan": 1,
        "llm_call": 1,
        "audit_log": 0,
        "job_request": 1,
    }
    assert {s.external_id for s in db_session.scalars(select(models.Signal))} == {"recent", "open"}
    db_session.refresh(kept)
    assert kept.llm_call_id is None  # plan conservé, appel IA purgé
    assert _count(db_session, models.JobRequest) == 1  # la demande en attente reste


def test_selfcheck_metrics_and_files(db_session: Session, tmp_path: Path) -> None:
    cfg = VigieConfig(
        sources={"zabbix": SourceConfig(enabled=True), "veeam": SourceConfig(enabled=True)},
        llm=LLMConfig(monthly_budget_usd=20),
    )
    ensure_source(db_session, "zabbix", kind="zabbix")
    record_failure(db_session, "zabbix", "zabbix : HTTP 503", NOW - timedelta(minutes=5))
    db_session.add(
        models.LLMCall(
            at=NOW, model="m", prompt_hash="p" * 64, outcome=LLMOutcome.ok, cost_usd=Decimal("5")
        )
    )
    db_session.flush()
    metrics = collect_metrics(db_session, cfg, NOW)
    assert metrics["sources_down"] == 2  # zabbix en échec, veeam jamais collecté
    assert metrics["source.zabbix.last_ok_age_min"] == -1
    assert metrics["llm_budget_pct"] == 25.0
    assert metrics["last_daily_plan_age_h"] == -1 and metrics["paused"] == 0
    write_metrics(tmp_path, metrics)
    assert (tmp_path / "sources_down").read_text() == "2\n"
    assert '"llm_budget_pct": 25.0' in (tmp_path / "selfcheck.json").read_text()
    with pytest.raises(ValueError):
        write_metrics(tmp_path, {"../evil": 1})


@pytest.fixture
def config(tmp_path: Path, db_engine: Engine) -> Path:
    path = tmp_path / "vigie.toml"
    path.write_text(f'[database]\nurl = "{TEST_DB_URL}"\n')
    yield path
    with Session(db_engine) as session:
        session.execute(delete(models.Setting).where(models.Setting.key == "breakglass"))
        session.commit()


def test_cli_breakglass_selfcheck_housekeeping(
    config: Path, db_engine: Engine, tmp_path: Path
) -> None:
    runner = CliRunner()
    r = runner.invoke(app, ["--config", str(config), "breakglass", "--enable", "--ttl", "30m"])
    assert r.exit_code == 0, r.output
    assert "Accès de secours actif 30 min" in r.output and "Mot de passe : " in r.output
    with Session(db_engine) as session:
        assert session.get(models.Setting, "breakglass") is not None
        assert session.scalars(
            select(models.AuditLog).where(models.AuditLog.action == "breakglass_enable")
        ).first()
    assert runner.invoke(app, ["--config", str(config), "breakglass", "--disable"]).exit_code == 0
    with Session(db_engine) as session:
        assert session.get(models.Setting, "breakglass") is None
    assert (
        runner.invoke(
            app, ["--config", str(config), "breakglass", "--enable", "--ttl", "3d"]
        ).exit_code
        == 2
    )
    out = tmp_path / "sc"
    r = runner.invoke(app, ["--config", str(config), "selfcheck", "--out", str(out)])
    assert r.exit_code == 0 and (out / "selfcheck.json").exists()
    r = runner.invoke(app, ["--config", str(config), "housekeeping"])
    assert r.exit_code == 0 and r.output.startswith("Purge : ")


def test_cli_migrate_is_idempotent(config: Path) -> None:
    r = CliRunner().invoke(app, ["--config", str(config), "migrate"])
    assert r.exit_code == 0, r.output
    assert "Base déjà à jour (révision 0011)" in r.output


def test_selfcheck_certificate_days(db_session: Session, tmp_path: Path) -> None:
    from tests.unit.test_certs import cert

    crt = cert(tmp_path / "defender.crt", 25)
    cfg = VigieConfig(
        sources={
            "defender": SourceConfig(enabled=True, certificate=str(crt)),
            "other": SourceConfig(enabled=True, certificate=str(tmp_path / "absent.crt")),
        }
    )
    metrics = collect_metrics(db_session, cfg, datetime.now(UTC))
    assert metrics["cert.defender.days_left"] == 25
    assert metrics["cert.other.days_left"] == -1
    write_metrics(tmp_path / "sc", metrics)
    assert (tmp_path / "sc" / "cert.defender.days_left").read_text() == "25\n"
