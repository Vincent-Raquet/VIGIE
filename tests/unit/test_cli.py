from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.conftest import EXAMPLE_CONFIG
from vigie.cli import EXIT_NOT_IMPLEMENTED, app

runner = CliRunner()

COMMANDS = [
    "collect",
    "plan",
    "notify",
    "check",
    "seed",
    "budget",
    "web",
    "housekeeping",
    "selfcheck",
    "breakglass",
]


def test_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in COMMANDS:
        assert command in result.output


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.startswith("vigie ")


@pytest.mark.parametrize(
    "args",
    [
        ["plan", "--kind", "daily", "--dry-run", "--no-llm"],
        ["notify", "--plan", "latest-daily", "--dry-run"],
        ["budget"],
        ["web", "--reload"],
        ["housekeeping"],
        ["selfcheck"],
        ["breakglass", "--enable"],
    ],
)
def test_stubs_exit_not_implemented(args: list[str]) -> None:
    result = runner.invoke(app, args)
    assert result.exit_code == EXIT_NOT_IMPLEMENTED
    assert "non implémentée" in result.output


def test_plan_rejects_unknown_kind() -> None:
    result = runner.invoke(app, ["plan", "--kind", "monthly"])
    assert result.exit_code == 2  # erreur d'usage Click
    assert "non implémentée" not in result.output


def test_check_lists_sources_then_checks_database() -> None:
    # La base « vigie » de la config d'exemple n'existe pas en dev : erreur attendue.
    result = runner.invoke(app, ["--config", str(EXAMPLE_CONFIG), "check"])
    assert "Configuration valide" in result.output
    assert "source zabbix : activée" in result.output
    assert "source wazuh : désactivée" in result.output
    assert result.exit_code == 1
    assert "base injoignable" in result.output


def test_check_missing_config(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--config", str(tmp_path / "absent.toml"), "check"])
    assert result.exit_code == 1
    assert "introuvable" in result.output


def test_commands_never_fall_back_to_dev_config_in_tests() -> None:
    # Garde-fou : sans --config, les tests ne doivent jamais toucher vigie_dev.
    result = runner.invoke(app, ["seed", "--dry-run"])
    assert result.exit_code == 1
    assert "absent-vigie.toml" in result.output


ZABBIX_FIXTURES = Path(__file__).parents[1] / "contract" / "zabbix"


def test_collect_dry_run_on_fixtures() -> None:
    result = runner.invoke(
        app,
        [
            "--config",
            str(EXAMPLE_CONFIG),
            "collect",
            "--source",
            "zabbix",
            "--dry-run",
            "--fixtures",
            str(ZABBIX_FIXTURES),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "46 signal(s)" in result.output
    assert "Par sévérité : 4=7, 3=15, 2=24" in result.output
    assert "24 problèmes ouverts sur WI-backup-01" in result.output


def test_collect_unknown_source() -> None:
    result = runner.invoke(
        app, ["--config", str(EXAMPLE_CONFIG), "collect", "--source", "nope", "--dry-run"]
    )
    assert result.exit_code == 1
    assert "aucun connecteur" in result.output


def test_collect_without_secret_fails_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    monkeypatch.delenv("VIGIE_ENV", raising=False)
    result = runner.invoke(
        app, ["--config", str(EXAMPLE_CONFIG), "collect", "--source", "zabbix", "--dry-run"]
    )
    assert result.exit_code == 1
    assert "zabbix_api_token" in result.output


def test_check_sources_reports_missing_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    monkeypatch.delenv("VIGIE_ENV", raising=False)
    result = runner.invoke(app, ["--config", str(EXAMPLE_CONFIG), "check", "--sources"])
    assert result.exit_code == 1
    assert "source zabbix : activée, connecteur installé" in result.output
    assert "ERREUR secret zabbix_api_token" in result.output
