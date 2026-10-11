"""Worker : demandes `plan_generate` (filtre par type, génération, pause, fenêtre de dates)."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session
from typer.testing import CliRunner

import vigie.cli as cli
from tests.conftest import TEST_DB_URL
from vigie.db import models
from vigie.db.enums import JobKind, JobStatus
from vigie.db.jobs import new_job_request
from vigie.pause import set_pause

pytestmark = pytest.mark.db

TODAY = datetime.now(UTC).date()


@pytest.fixture
def config(tmp_path: Path, db_engine: Engine) -> Iterator[Path]:
    path = tmp_path / "vigie.toml"
    path.write_text(f'[database]\nurl = "{TEST_DB_URL}"\n')
    yield path
    with Session(db_engine) as session:
        session.execute(delete(models.JobRequest))
        session.execute(delete(models.Plan))
        session.execute(delete(models.Setting).where(models.Setting.key == "pause"))
        session.commit()


def queue(engine: Engine, day: str | None = None, use_llm: bool = False) -> int:
    payload = {"kind": "daily", "day": day or TODAY.isoformat(), "use_llm": use_llm}
    with Session(engine) as session:
        job = new_job_request(JobKind.plan_generate, payload, "admin@example.test")
        session.add(job)
        session.commit()
        return job.id


def run(config: Path, *args: str) -> str:
    result = CliRunner().invoke(cli.app, ["--config", str(config), "jobs", "--run-pending", *args])
    assert result.exit_code == 0, result.output
    return result.output


def job(engine: Engine, job_id: int) -> models.JobRequest:
    with Session(engine) as session:
        found = session.get(models.JobRequest, job_id)
        assert found is not None
        return found


def test_source_test_unit_never_runs_plan_generation(config: Path, db_engine: Engine) -> None:
    job_id = queue(db_engine)
    assert "0 demande(s) traitée(s)" in run(config)  # défaut : source_test seulement
    assert job(db_engine, job_id).status is JobStatus.pending


def test_plan_generation_without_llm(config: Path, db_engine: Engine) -> None:
    job_id = queue(db_engine)
    output = run(config, "--kind", "plan_generate")
    assert "plan_generate" in output and ": done" in output
    done = job(db_engine, job_id)
    assert done.status is JobStatus.done and done.done_at is not None
    result = done.result or {}
    assert result["ok"] is True and result["by_llm"] is False and result["cost_usd"] is None
    with Session(db_engine) as session:
        plan = session.get(models.Plan, result["plan_id"])
        assert plan is not None and plan.period_start == TODAY
        assert plan.data["ai"]["without_ai_reason"] == "option --no-llm"


def test_paused_generation_fails_cleanly(config: Path, db_engine: Engine) -> None:
    with Session(db_engine) as session:
        set_pause(session, collect=False, plan=True)
        session.commit()
    job_id = queue(db_engine)
    run(config, "--kind", "plan_generate")
    failed = job(db_engine, job_id)
    assert failed.status is JobStatus.failed
    assert failed.result == {"ok": False, "detail": "génération des plans en pause"}
    with Session(db_engine) as session:
        assert session.scalars(select(models.Plan)).first() is None


def test_day_outside_window_is_refused_by_the_worker(config: Path, db_engine: Engine) -> None:
    job_id = queue(db_engine, day=(TODAY + timedelta(days=30)).isoformat())
    run(config, "--kind", "plan_generate")
    refused = job(db_engine, job_id)
    assert refused.status is JobStatus.failed
    assert "fenêtre" in (refused.result or {})["detail"]
