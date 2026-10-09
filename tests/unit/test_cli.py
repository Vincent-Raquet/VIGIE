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
        ["collect", "--source", "zabbix", "--dry-run"],
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
