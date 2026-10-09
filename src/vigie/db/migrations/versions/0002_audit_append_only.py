"""audit_log append-only (SECURITY.md C8, SPEC §5.1)

UPDATE et TRUNCATE sont toujours refusés. DELETE n'est accepté que pour les lignes de plus
de 365 jours (purge de rétention, SPEC §5.2). `at` est forcé à now() à l'insertion : on ne
peut pas antidater une entrée pour la rendre purgeable.

Ces garanties ne tiennent que contre les rôles qui ne possèdent pas la table : en prod, le
propriétaire est vigie_migrate, jamais un rôle d'exécution (docs/DEV.md).

Revision ID: 0002
Revises: 0001
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION audit_log_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                NEW.at := now();
                RETURN NEW;
            END IF;
            IF TG_OP = 'DELETE' AND OLD.at < now() - interval '365 days' THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION 'audit_log est append-only : % refusé', TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER audit_log_insert BEFORE INSERT ON audit_log "
        "FOR EACH ROW EXECUTE FUNCTION audit_log_guard()"
    )
    op.execute(
        "CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log "
        "FOR EACH ROW EXECUTE FUNCTION audit_log_guard()"
    )
    op.execute(
        "CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log "
        "FOR EACH STATEMENT EXECUTE FUNCTION audit_log_guard()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER audit_log_no_truncate ON audit_log")
    op.execute("DROP TRIGGER audit_log_append_only ON audit_log")
    op.execute("DROP TRIGGER audit_log_insert ON audit_log")
    op.execute("DROP FUNCTION audit_log_guard()")
