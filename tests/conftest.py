import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from vigie.db.migrate import alembic_config

pytest_plugins = ["tests.webfixtures"]  # application web sur la base de test

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG = REPO_ROOT / "config" / "vigie.example.toml"
TEST_DB_URL = os.environ.get("VIGIE_TEST_DATABASE_URL", "postgresql+psycopg:///vigie_test")


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Le shell de dev exporte VIGIE_ENV/VIGIE_CONFIG : les tests n'en dépendent pas.

    Une commande lancée sans --config ne doit jamais retomber sur config/vigie.toml
    (base vigie_dev) : VIGIE_CONFIG pointe vers un fichier inexistant.
    """
    for var in ("VIGIE_ENV", "CREDENTIALS_DIRECTORY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("VIGIE_CONFIG", str(tmp_path / "absent-vigie.toml"))


@pytest.fixture(scope="session")
def db_engine() -> Iterator[Engine]:
    """Base vigie_test remise à zéro puis migrée jusqu'à head, une fois par session."""
    engine = create_engine(TEST_DB_URL)
    try:
        with engine.begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
            command.upgrade(alembic_config(conn), "head")
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL de test injoignable ({TEST_DB_URL}) : {type(exc).__name__}")
    yield engine
    engine.dispose()


@pytest.fixture
def db_conn(db_engine: Engine) -> Iterator[Connection]:
    """Connexion dans une transaction annulée à la fin du test."""
    with db_engine.connect() as conn:
        trans = conn.begin()
        yield conn
        trans.rollback()


@pytest.fixture
def db_session(db_conn: Connection) -> Iterator[Session]:
    with Session(bind=db_conn, join_transaction_mode="create_savepoint") as session:
        yield session


ZABBIX_FIXTURES_NOW = 1791563400  # heure de référence des fixtures Zabbix (README du dossier)


@pytest.fixture
def frozen_zabbix_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fige l'horloge du connecteur Zabbix : l'âge des proxys des fixtures ne dérive pas."""
    from datetime import UTC, datetime

    import vigie.connectors.zabbix as zabbix

    class Frozen(datetime):
        @classmethod
        def now(cls, tz: object = None) -> "Frozen":  # type: ignore[override]
            return cls.fromtimestamp(ZABBIX_FIXTURES_NOW, UTC)

    monkeypatch.setattr(zabbix, "datetime", Frozen)
