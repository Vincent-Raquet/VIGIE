"""Droits PostgreSQL des rôles d'exécution (SECURITY.md C8)."""

from collections.abc import Iterator

import pytest
from sqlalchemy import Connection, text

from tests.dbhelpers import ROLES, allowed, as_role, denied, roles_exist
from vigie.db.models import Base

pytestmark = pytest.mark.db


@pytest.fixture
def conn(db_conn: Connection) -> Iterator[Connection]:
    if not roles_exist(db_conn):
        pytest.skip("rôles vigie_web/vigie_worker absents ou nadmin non membre (docs/DEV.md)")
    yield db_conn


@pytest.mark.parametrize("role", ROLES)
def test_every_table_readable(conn: Connection, role: str) -> None:
    for table in Base.metadata.tables:
        ok = conn.execute(
            text("SELECT has_table_privilege(:role, :table, 'SELECT')"),
            {"role": role, "table": table},
        ).scalar_one()
        assert ok, f"{role} ne peut pas lire {table} (droits oubliés dans une migration ?)"


def test_web_cannot_write_engine_tables(conn: Connection) -> None:
    with as_role(conn, "vigie_web"):
        denied(conn, "DELETE FROM signal")
        denied(conn, "UPDATE incident SET priority = 'P4'")
        denied(conn, "INSERT INTO llm_call (model, prompt_hash, outcome) VALUES ('m', 'h', 'ok')")
        denied(conn, "UPDATE source SET enabled = true")
        denied(conn, "UPDATE job_request SET status = 'done'")


def test_web_task_and_plan_columns(conn: Connection) -> None:
    with as_role(conn, "vigie_web"):
        allowed(conn, "UPDATE task SET status = 'done', status_reason = '' WHERE false")
        denied(conn, "UPDATE task SET title = 'x' WHERE false")
        denied(conn, "UPDATE task SET assignee_id = 1 WHERE false")
        denied(conn, "DELETE FROM task")
        allowed(conn, "UPDATE plan SET status = 'validated', validated_at = now() WHERE false")
        denied(conn, "UPDATE plan SET summary_md = 'x' WHERE false")


def test_review_tables(conn: Connection) -> None:
    with as_role(conn, "vigie_web"):
        allowed(conn, "UPDATE task_review SET relevant = true, note = '' WHERE false")
        allowed(conn, "UPDATE plan_review SET missing = '' WHERE false")
        denied(conn, "DELETE FROM task_review")
    with as_role(conn, "vigie_worker"):
        denied(conn, "UPDATE task_review SET relevant = false WHERE false")
        denied(conn, "INSERT INTO plan_review (plan_id, missing, reviewer_id) VALUES (1, '', 1)")


def test_web_config_crud(conn: Connection) -> None:
    with as_role(conn, "vigie_web"):
        allowed(conn, "INSERT INTO company (code, name, criticality) VALUES ('ZZ', 'Test', 1)")
        allowed(conn, "UPDATE policy_axis SET weight = 3 WHERE false")
        denied(conn, "UPDATE role_skill_version SET body_md = 'x' WHERE false")


def test_worker_cannot_edit_configuration(conn: Connection) -> None:
    with as_role(conn, "vigie_worker"):
        denied(conn, "UPDATE person SET app_role = 'admin'")
        denied(conn, "INSERT INTO company (code, name, criticality) VALUES ('ZZ', 'Test', 1)")
        denied(conn, "DELETE FROM policy_rule")
        allowed(conn, "UPDATE signal SET occurrences = 2 WHERE false")


@pytest.mark.parametrize("role", ROLES)
def test_audit_log_is_insert_only(conn: Connection, role: str) -> None:
    with as_role(conn, role):
        allowed(
            conn,
            "INSERT INTO audit_log (actor, action, object, details) VALUES ('t', 't', '', '{}')",
        )
        denied(conn, "UPDATE audit_log SET actor = 'x'")
        denied(conn, "TRUNCATE audit_log")


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize(
    "ddl",
    [
        "ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only",
        "ALTER TABLE audit_log DISABLE TRIGGER ALL",
        "DROP TRIGGER audit_log_append_only ON audit_log",
        "DROP TRIGGER audit_log_no_truncate ON audit_log",
        "ALTER TABLE audit_log ADD COLUMN x int",
        "ALTER TABLE audit_log RENAME TO audit_old",
        "DROP TABLE audit_log",
        "DROP FUNCTION audit_log_guard()",
        "CREATE OR REPLACE FUNCTION audit_log_guard() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
    ],
)
def test_runtime_roles_cannot_tamper_with_audit(conn: Connection, role: str, ddl: str) -> None:
    with as_role(conn, role):
        error = denied(conn, ddl)
    assert "must be owner" in error or "permission denied" in error


@pytest.mark.parametrize("role", ROLES)
def test_runtime_roles_do_not_own_tables(conn: Connection, role: str) -> None:
    owned = conn.execute(
        text("SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tableowner = :r"),
        {"r": role},
    ).scalar_one()
    assert owned == 0


def test_chat_tables(conn: Connection) -> None:
    cid = {
        "cid": conn.execute(
            text(
                "INSERT INTO chat_conversation (owner, anchor, anchor_id, status) "
                "VALUES ('t@example.test', 'incident', 1, 'active') RETURNING id"
            )
        ).scalar_one()
    }
    question = (
        "INSERT INTO chat_message (conversation_id, role, content, status, tokens) "
        "VALUES (:cid, 'user', 'q', 'pending', 0)"
    )
    with as_role(conn, "vigie_web"):
        allowed(
            conn,
            "INSERT INTO chat_conversation (owner, anchor, anchor_id, status) "
            "VALUES ('t@example.test', 'incident', 1, 'active')",
        )
        allowed(conn, question, cid)
        # Le web ne peut pas fabriquer une réponse de l'IA ni une proposition (déclencheur).
        denied(conn, question.replace("'user'", "'assistant'"), cid)
        denied(conn, question.replace("'pending'", "'done'"), cid)
        denied(conn, question.replace(", 0)", ", 5)"), cid)
        denied(conn, "UPDATE chat_message SET content = 'x' WHERE false")
        denied(
            conn,
            "INSERT INTO chat_proposal (message_id, kind, payload, rationale, status) "
            "VALUES (1, 'incident_priority', '{}', '', 'proposed')",
        )
        denied(conn, "UPDATE chat_conversation SET context_json = 'x' WHERE false")
        allowed(conn, "UPDATE chat_conversation SET status = 'archived' WHERE false")
        allowed(conn, "UPDATE chat_proposal SET status = 'applied' WHERE false")
        denied(conn, "UPDATE chat_proposal SET payload = '{}' WHERE false")
        allowed(conn, "UPDATE incident SET manual_priority = 'P1', manual_reason = '' WHERE false")
        denied(conn, "UPDATE incident SET priority = 'P1' WHERE false")
        denied(conn, "DELETE FROM chat_conversation")
    with as_role(conn, "vigie_worker"):
        allowed(conn, "UPDATE chat_message SET status = 'done' WHERE false")
        allowed(conn, "UPDATE chat_conversation SET context_json = 'x' WHERE false")
        denied(conn, "UPDATE chat_conversation SET status = 'active' WHERE false")
        denied(conn, "UPDATE chat_proposal SET status = 'applied' WHERE false")
