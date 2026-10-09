"""Chargement des secrets (SECURITY.md C7)."""

from pathlib import Path

import pytest

from vigie.config import SecretError, get_secret

FAKE = "fake-secret-value-for-tests"


@pytest.fixture
def cred_dir(tmp_path: Path) -> Path:
    d = tmp_path / "creds"
    d.mkdir()
    (d / "zabbix_token").write_text(FAKE + "\n")
    return d


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    f = tmp_path / ".env.local"
    f.write_text(
        "# commentaire\n"
        f"VIGIE_SECRET_ZABBIX_TOKEN={FAKE}\n"
        "export VIGIE_SECRET_QUOTED='with spaces'\n"
        "ligne sans egal\n"
    )
    return f


def test_reads_from_credentials_directory(cred_dir: Path) -> None:
    secret = get_secret("zabbix_token", env={"CREDENTIALS_DIRECTORY": str(cred_dir)})
    assert secret.get_secret_value() == FAKE


def test_credentials_directory_has_priority_and_no_fallback(cred_dir: Path, env_file: Path) -> None:
    env = {"CREDENTIALS_DIRECTORY": str(cred_dir), "VIGIE_ENV": "dev"}
    with pytest.raises(SecretError):
        get_secret("quoted", env=env, env_file=env_file)


def test_reads_env_file_in_dev(env_file: Path) -> None:
    env = {"VIGIE_ENV": "dev"}
    assert get_secret("zabbix_token", env=env, env_file=env_file).get_secret_value() == FAKE
    assert get_secret("quoted", env=env, env_file=env_file).get_secret_value() == "with spaces"


@pytest.mark.parametrize("vigie_env", [None, "prod", "DEV", ""])
def test_env_file_ignored_outside_dev(env_file: Path, vigie_env: str | None) -> None:
    env = {} if vigie_env is None else {"VIGIE_ENV": vigie_env}
    with pytest.raises(SecretError):
        get_secret("zabbix_token", env=env, env_file=env_file)


def test_process_environment_is_never_a_secret_source(env_file: Path) -> None:
    env = {"VIGIE_ENV": "dev", "VIGIE_SECRET_OTHER": "leak"}
    with pytest.raises(SecretError):
        get_secret("other", env=env, env_file=env_file)


def test_missing_env_file(tmp_path: Path) -> None:
    with pytest.raises(SecretError):
        get_secret("zabbix_token", env={"VIGIE_ENV": "dev"}, env_file=tmp_path / "absent")


@pytest.mark.parametrize(
    "name", ["../../etc/shadow", "/etc/passwd", "a/b", "Zabbix", "", "x" * 65, "a.b"]
)
def test_invalid_names_rejected(cred_dir: Path, name: str) -> None:
    with pytest.raises(SecretError, match="nom de secret invalide"):
        get_secret(name, env={"CREDENTIALS_DIRECTORY": str(cred_dir)})


def test_secret_value_never_rendered(cred_dir: Path) -> None:
    secret = get_secret("zabbix_token", env={"CREDENTIALS_DIRECTORY": str(cred_dir)})
    for rendered in (repr(secret), str(secret), f"{secret}", f"{secret!r}"):
        assert FAKE not in rendered


def test_error_messages_never_contain_values(env_file: Path) -> None:
    with pytest.raises(SecretError) as excinfo:
        get_secret("absent", env={"VIGIE_ENV": "dev"}, env_file=env_file)
    assert FAKE not in str(excinfo.value)
