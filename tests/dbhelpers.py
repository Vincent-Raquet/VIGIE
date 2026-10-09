"""Assertions SQL : chaque instruction tourne dans un savepoint annulé."""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from sqlalchemy import Connection, text
from sqlalchemy.exc import DBAPIError

ROLES = ("vigie_web", "vigie_worker")


def denied(conn: Connection, sql: str, params: dict[str, Any] | None = None) -> str:
    savepoint = conn.begin_nested()
    try:
        conn.execute(text(sql), params or {})
    except DBAPIError as exc:
        savepoint.rollback()
        return str(exc.orig)
    savepoint.rollback()
    pytest.fail(f"autorisé à tort : {sql}")


def allowed(conn: Connection, sql: str, params: dict[str, Any] | None = None) -> None:
    savepoint = conn.begin_nested()
    try:
        conn.execute(text(sql), params or {})
    except DBAPIError as exc:
        savepoint.rollback()
        pytest.fail(f"refusé à tort : {sql} : {exc.orig}")
    savepoint.rollback()


@contextmanager
def as_role(conn: Connection, role: str) -> Iterator[None]:
    assert role in ROLES
    conn.execute(text(f"SET ROLE {role}"))
    try:
        yield
    finally:
        conn.execute(text("RESET ROLE"))


def roles_exist(conn: Connection) -> bool:
    count = conn.execute(
        text("SELECT count(*) FROM pg_roles WHERE rolname = ANY(:roles)"), {"roles": list(ROLES)}
    ).scalar_one()
    member = conn.execute(
        text(
            "SELECT bool_and(pg_has_role(current_user, r, 'MEMBER')) "
            "FROM unnest(CAST(:roles AS text[])) r"
        ),
        {"roles": list(ROLES)},
    ).scalar_one()
    return bool(count == len(ROLES) and member)
