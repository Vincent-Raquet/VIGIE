"""`vigie collect` sans --dry-run : écriture réelle dans vigie_test (nettoyée ensuite)."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from tests.conftest import TEST_DB_URL
from vigie.cli import app
from vigie.db import models

pytestmark = pytest.mark.db

FIXTURES = Path(__file__).parents[1] / "contract" / "zabbix"


@pytest.fixture
def config(tmp_path: Path, db_engine: Engine) -> Iterator[Path]:
    path = tmp_path / "vigie.toml"
    path.write_text(
        f'[database]\nurl = "{TEST_DB_URL}"\n\n'
        '[sources.zabbix]\nenabled = true\nbase_url = "https://zabbix.test"\n'
    )
    yield path
    with Session(db_engine) as session:
        session.execute(delete(models.Signal))
        session.execute(delete(models.Source))
        session.commit()


def collect(config: Path, fixtures: Path) -> tuple[int, str]:
    result = CliRunner().invoke(
        app,
        ["--config", str(config), "collect", "--source", "zabbix", "--fixtures", str(fixtures)],
    )
    return result.exit_code, result.output


@pytest.mark.usefixtures("frozen_zabbix_clock")
def test_collect_writes_signals_then_resolves(
    config: Path, db_engine: Engine, tmp_path: Path
) -> None:
    code, output = collect(config, FIXTURES)
    assert code == 0, output
    assert "zabbix : 46 signal(s) — 46 nouveau(x)" in output
    with Session(db_engine) as session:
        source = session.get(models.Source, "zabbix")
        assert source is not None and source.last_ok_at is not None
        assert len(session.scalars(select(models.Signal)).all()) == 46

    empty = tmp_path / "empty"
    empty.mkdir()
    for name in ("problem.get.json", "trigger.get.json", "proxy.get.json"):
        (empty / name).write_text("[]")
    code, output = collect(config, empty)
    assert code == 0, output
    assert "46 résolu(s)" in output


def test_collect_failure_records_source_down(
    config: Path, db_engine: Engine, tmp_path: Path
) -> None:
    code, output = collect(config, tmp_path)  # aucune fixture : HTTP 404
    assert code == 1
    assert "source injoignable" in output
    with Session(db_engine) as session:
        down = session.scalars(select(models.Signal).where(models.Signal.source == "vigie")).one()
        assert down.external_id == "source_down:zabbix"
        assert down.resolved_at is None
