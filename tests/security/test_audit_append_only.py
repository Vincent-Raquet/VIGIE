"""audit_log append-only (SECURITY.md C8, SPEC §5.2)."""

import pytest
from sqlalchemy import Connection, text

from tests.dbhelpers import allowed, denied

pytestmark = pytest.mark.db


def _insert(conn: Connection, *, backdated: bool = False) -> int:
    sql = text(
        "INSERT INTO audit_log (at, actor, action, object, details) "
        "VALUES (now() - make_interval(days => :days), 'test', 'test', '', '{}') RETURNING id"
    )
    return int(conn.execute(sql, {"days": 400 if backdated else 0}).scalar_one())


def _insert_old(conn: Connection) -> int:
    # Seul le propriétaire peut contourner le trigger d'insertion (c'est le but du test).
    conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_insert"))
    row_id = _insert(conn, backdated=True)
    conn.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_insert"))
    return row_id


def test_update_refused(db_conn: Connection) -> None:
    row_id = _insert(db_conn)
    error = denied(db_conn, "UPDATE audit_log SET actor = 'x' WHERE id = :id", {"id": row_id})
    assert "append-only" in error


def test_delete_recent_refused(db_conn: Connection) -> None:
    row_id = _insert(db_conn)
    assert "append-only" in denied(db_conn, "DELETE FROM audit_log WHERE id = :id", {"id": row_id})


def test_truncate_refused(db_conn: Connection) -> None:
    _insert(db_conn)
    assert "append-only" in denied(db_conn, "TRUNCATE audit_log")


def test_delete_older_than_one_year_allowed(db_conn: Connection) -> None:
    row_id = _insert_old(db_conn)
    allowed(db_conn, "DELETE FROM audit_log WHERE id = :id", {"id": row_id})


def test_backdated_insert_is_forced_to_now(db_conn: Connection) -> None:
    row_id = _insert(db_conn, backdated=True)
    recent = db_conn.execute(
        text("SELECT at > now() - interval '1 minute' FROM audit_log WHERE id = :id"),
        {"id": row_id},
    ).scalar_one()
    assert recent is True
