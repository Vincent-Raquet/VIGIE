"""État des migrations Alembic (utilisé par `vigie check` et les tests)."""

from __future__ import annotations

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine

SCRIPT_LOCATION = "vigie.db:migrations"


def alembic_config(connection: Connection | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", SCRIPT_LOCATION)
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def head_revision() -> str | None:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()
