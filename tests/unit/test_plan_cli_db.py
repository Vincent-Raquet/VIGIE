"""`vigie plan` avec IA (faux client) et `vigie budget`, sur la base de test vide."""

import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session
from typer.testing import CliRunner

import vigie.cli as cli
from tests.conftest import TEST_DB_URL
from vigie.config import SecretError
from vigie.db import models
from vigie.db.enums import LLMOutcome

pytestmark = pytest.mark.db

VALID = {
    "summary_exec": "Rien d'urgent cette semaine.",
    "per_person": [],
    "tasks": [],
    "risks": [{"text": "Peu de capacité système.", "severity": "medium"}],
    "escalations": [],
}


@pytest.fixture
def config(tmp_path: Path, db_engine: Engine) -> Iterator[Path]:
    path = tmp_path / "vigie.toml"
    path.write_text(f'[database]\nurl = "{TEST_DB_URL}"\n')
    yield path
    with Session(db_engine) as session:
        session.execute(delete(models.LLMCall))
        session.commit()


class Fake:
    def __init__(self, payload: Any) -> None:
        self.payload = payload
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **kwargs: Any) -> Any:
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=json.dumps(self.payload))],
            stop_reason="end_turn",
            model="claude-sonnet-5-5",
            usage=SimpleNamespace(
                input_tokens=1200,
                cache_creation_input_tokens=0,
                cache_read_input_tokens=3000,
                output_tokens=400,
                iterations=None,
            ),
        )


def run(config: Path, *args: str) -> tuple[int, str]:
    result = CliRunner().invoke(cli.app, ["--config", str(config), *args])
    return result.exit_code, result.output


def test_plan_with_ai_logs_the_call_even_in_dry_run(
    config: Path, db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "get_secret", lambda name: SecretStr("fake-key"))
    monkeypatch.setattr(cli, "llm_client_factory", lambda key, cfg: Fake(VALID))
    code, output = run(config, "plan", "--kind", "weekly", "--date", "2026-10-13", "--dry-run")
    assert code == 0, output
    assert "Brouillon affiné par l'IA puis validé automatiquement" in output
    assert "## Synthèse exécutive" in output and "Rien d'urgent cette semaine." in output
    assert "## Risques signalés par l'IA" in output
    assert "Appel IA (claude-sonnet-5-5) : ok" in output
    with Session(db_engine) as session:
        [call] = session.scalars(select(models.LLMCall)).all()
        assert (call.outcome, call.cached_tokens) == (LLMOutcome.ok, 3000)
        assert session.scalars(select(models.Plan)).all() == []  # simulation

    code, output = run(config, "budget")
    assert code == 0, output
    assert "Appels : 1 (ok 1)" in output
    assert "Part des jetons d'entrée servis par le cache : 71 %" in output


def test_invalid_ai_output_falls_back_to_rules(
    config: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "get_secret", lambda name: SecretStr("fake-key"))
    monkeypatch.setattr(cli, "llm_client_factory", lambda key, cfg: Fake({"oops": 1}))
    code, output = run(config, "plan", "--kind", "daily", "--date", "2026-10-13", "--dry-run")
    assert code == 0, output
    assert "Brouillon généré sans IA (règles déterministes : sortie invalide" in output


def test_missing_key_falls_back_without_call(config: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_secret(name: str) -> SecretStr:
        raise SecretError("absent")

    monkeypatch.setattr(cli, "get_secret", no_secret)
    code, output = run(config, "plan", "--kind", "daily", "--date", "2026-10-13", "--dry-run")
    assert code == 0, output
    assert "règles déterministes : clé API Anthropic indisponible" in output


def test_no_llm_and_saved_plan(config: Path, db_engine: Engine) -> None:
    code, output = run(config, "plan", "--kind", "daily", "--date", "2026-10-13", "--no-llm")
    assert code == 0, output
    assert "Brouillon généré sans IA (règles déterministes) le" in output
    assert "enregistré en brouillon" in output
    with Session(db_engine) as session:
        session.execute(delete(models.Plan))
        session.commit()


def test_budget_without_calls(config: Path) -> None:
    code, output = run(config, "budget")
    assert code == 0, output
    assert "0.0000 $ dépensés sur 30.00 $" in output
    assert "Appels : 0 (aucun)" in output


def test_pause_is_respected_by_the_worker(config: Path, db_engine: Engine) -> None:
    from vigie.pause import set_pause

    with Session(db_engine) as session:
        set_pause(session, collect=True, plan=True)
        session.commit()
    try:
        code, output = run(config, "plan", "--kind", "daily", "--no-llm")
        assert code == 0 and "en pause" in output and "enregistré" not in output
        # La simulation reste possible pendant la pause.
        code, output = run(config, "plan", "--kind", "daily", "--no-llm", "--dry-run")
        assert code == 0 and "Simulation" in output
    finally:
        with Session(db_engine) as session:
            session.execute(delete(models.Setting).where(models.Setting.key == "pause"))
            session.commit()
