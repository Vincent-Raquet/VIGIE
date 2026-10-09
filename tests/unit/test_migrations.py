import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine

from vigie.db.migrate import alembic_config, current_revision, head_revision
from vigie.db.models import Base

pytestmark = pytest.mark.db


def test_models_match_migrations(db_engine: Engine) -> None:
    with db_engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []


def test_database_is_at_head(db_engine: Engine) -> None:
    assert head_revision() == "0007"
    assert current_revision(db_engine) == head_revision()


def test_downgrade_then_upgrade_roundtrip(db_engine: Engine) -> None:
    with db_engine.begin() as conn:
        command.downgrade(alembic_config(conn), "base")
    assert current_revision(db_engine) is None
    with db_engine.begin() as conn:
        command.upgrade(alembic_config(conn), "head")
    assert current_revision(db_engine) == head_revision()
