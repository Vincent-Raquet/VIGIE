from datetime import time
from pathlib import Path

import pytest

from tests.conftest import EXAMPLE_CONFIG
from vigie.config import (
    DEFAULT_CONFIG_PATH,
    ConfigError,
    VigieConfig,
    load_config,
    resolve_config_path,
)


def test_example_config_is_valid() -> None:
    cfg = load_config(EXAMPLE_CONFIG)
    assert cfg.general.timezone == "Europe/Brussels"
    assert cfg.plans.daily_at == time(7, 15)
    assert cfg.llm.monthly_budget_usd == 30
    assert cfg.enabled_sources() == ["veeam", "zabbix"]


def test_source_specific_fields_are_kept_for_the_connector() -> None:
    cfg = load_config(EXAMPLE_CONFIG)
    veeam = cfg.sources["veeam"]
    assert veeam.interval_min == 30
    assert veeam.model_extra is not None
    assert veeam.model_extra["instances"][0]["name"] == "vbr-main"


def test_defaults_without_file_content(tmp_path: Path) -> None:
    path = tmp_path / "vigie.toml"
    path.write_text("")
    assert load_config(path) == VigieConfig()


def test_unknown_key_in_known_section_rejected(tmp_path: Path) -> None:
    path = tmp_path / "vigie.toml"
    path.write_text('[llm]\nmodle = "typo"\n')
    with pytest.raises(ConfigError, match="modle"):
        load_config(path)


def test_unknown_section_rejected(tmp_path: Path) -> None:
    path = tmp_path / "vigie.toml"
    path.write_text("[surprise]\nx = 1\n")
    with pytest.raises(ConfigError):
        load_config(path)


@pytest.mark.parametrize("name", ["Zabbix", "../etc", "a-b", "1abc"])
def test_invalid_source_name_rejected(tmp_path: Path, name: str) -> None:
    path = tmp_path / "vigie.toml"
    path.write_text(f'[sources."{name}"]\nenabled = true\n')
    with pytest.raises(ConfigError, match="nom de source invalide"):
        load_config(path)


def test_interval_bounds(tmp_path: Path) -> None:
    path = tmp_path / "vigie.toml"
    path.write_text("[sources.zabbix]\ninterval_min = 0\n")
    with pytest.raises(ConfigError):
        load_config(path)


def test_unknown_timezone_rejected(tmp_path: Path) -> None:
    path = tmp_path / "vigie.toml"
    path.write_text('[general]\ntimezone = "Mars/Olympus"\n')
    with pytest.raises(ConfigError, match="fuseau"):
        load_config(path)


def test_invalid_toml(tmp_path: Path) -> None:
    path = tmp_path / "vigie.toml"
    path.write_text("[general\n")
    with pytest.raises(ConfigError, match="TOML invalide"):
        load_config(path)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="introuvable"):
        load_config(tmp_path / "absent.toml")


def test_config_path_resolution_order(tmp_path: Path) -> None:
    explicit = tmp_path / "a.toml"
    assert resolve_config_path(explicit, {"VIGIE_CONFIG": "b.toml"}) == explicit
    assert resolve_config_path(None, {"VIGIE_CONFIG": "b.toml"}) == Path("b.toml")
    assert resolve_config_path(None, {}) == DEFAULT_CONFIG_PATH


def test_no_implicit_fallback_to_etc() -> None:
    # La VM est aussi machine de dev : jamais de lecture implicite de la conf de prod.
    assert not str(resolve_config_path(None, {})).startswith("/etc")
