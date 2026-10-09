"""Droits des rôles d'exécution (SECURITY.md C8)

Appliqués seulement si les rôles existent (créés par Ansible en prod, à la main en dev).
Toute nouvelle table doit recevoir ses droits dans sa propre migration ; un test vérifie
que chaque table est lisible par vigie_web et vigie_worker.

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLES = ("vigie_web", "vigie_worker")

# Tables de configuration éditées dans l'UI.
WEB_CONFIG_TABLES = (
    "person",
    "person_skill",
    "absence",
    "company",
    "asset_rule",
    "policy_axis",
    "policy_rule",
    "project",
    "project_company",
    "project_axis",
    "milestone",
    "milestone_dependency",
    "role_skill",
    "setting",
)

GRANTS = {
    "vigie_web": [
        "GRANT USAGE ON SCHEMA public TO vigie_web",
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO vigie_web",
        f"GRANT INSERT, UPDATE, DELETE ON {', '.join(WEB_CONFIG_TABLES)} TO vigie_web",
        # Versions de skills et commentaires : ajout seulement.
        "GRANT INSERT ON role_skill_version, task_comment TO vigie_web",
        # Création manuelle de tâches (F10) ; seuls statut et motif sont modifiables.
        "GRANT INSERT ON task, task_incident TO vigie_web",
        "GRANT UPDATE (status, status_reason) ON task TO vigie_web",
        # Validation / publication des plans (point D).
        "GRANT UPDATE (status, validated_by, validated_at, published_at) ON plan TO vigie_web",
        # Demandes au worker (point B).
        "GRANT INSERT ON job_request TO vigie_web",
        "GRANT INSERT ON audit_log TO vigie_web",
        "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO vigie_web",
    ],
    "vigie_worker": [
        "GRANT USAGE ON SCHEMA public TO vigie_worker",
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO vigie_worker",
        "GRANT INSERT, UPDATE, DELETE ON signal, incident, incident_signal, task, "
        "task_incident, plan, llm_call TO vigie_worker",
        "GRANT INSERT, UPDATE ON source TO vigie_worker",
        "GRANT UPDATE ON job_request TO vigie_worker",
        # DELETE borné par le trigger aux lignes de plus d'un an (purge de rétention).
        "GRANT INSERT, DELETE ON audit_log TO vigie_worker",
        "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO vigie_worker",
    ],
}


def _if_role_exists(role: str, statements: list[str]) -> str:
    body = "\n".join(f"        EXECUTE {_quote(s)};" for s in statements)
    # Rôles et instructions sont des constantes de ce module, aucune donnée externe.
    return (
        "DO $$\nBEGIN\n"  # noqa: S608
        f"    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN\n"
        f"{body}\n"
        "    END IF;\nEND\n$$"
    )


def _quote(statement: str) -> str:
    return "'" + statement.replace("'", "''") + "'"


def upgrade() -> None:
    for role, statements in GRANTS.items():
        op.execute(_if_role_exists(role, statements))


def downgrade() -> None:
    for role in ROLES:
        op.execute(
            _if_role_exists(
                role,
                [
                    f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role}",
                    f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {role}",
                    f"REVOKE USAGE ON SCHEMA public FROM {role}",
                ],
            )
        )
