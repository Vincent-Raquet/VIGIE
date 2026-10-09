from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, create_engine

from vigie.config import load_config
from vigie.db.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _url() -> str:
    url = context.get_x_argument(as_dictionary=True).get("url")
    return url or load_config().database.url


def _configure(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # Connexion fournie par l'appelant (tests, `vigie check`), sinon créée ici.
    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        return
    engine = create_engine(_url())
    with engine.connect() as conn:
        _configure(conn)
    engine.dispose()


if context.is_offline_mode():
    raise SystemExit("Mode hors ligne non supporté : appliquer les migrations sur la base.")
run_migrations_online()
