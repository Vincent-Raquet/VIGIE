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
        ["seed"],
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
    assert result.exit_code != 0
    assert result.exit_code != EXIT_NOT_IMPLEMENTED


def test_check_valid_example_config() -> None:
    result = runner.invoke(app, ["--config", str(EXAMPLE_CONFIG), "check"])
    assert result.exit_code == 0, result.output
    assert "Configuration valide" in result.output
    assert "source zabbix : activée" in result.output
    assert "source wazuh : désactivée" in result.output


def test_check_missing_config(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--config", str(tmp_path / "absent.toml"), "check"])
    assert result.exit_code == 1
    assert "introuvable" in result.output
