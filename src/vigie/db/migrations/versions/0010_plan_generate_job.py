"""job_request.kind : ajoute plan_generate (« Générer le plan maintenant » depuis le web)

Revision ID: 0010
Revises: 0009
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

BEFORE = ("source_test",)
AFTER = (*BEFORE, "plan_generate")


def _check(values: tuple[str, ...]) -> None:
    op.drop_constraint(op.f("ck_job_request_kind"), "job_request", type_="check")
    allowed = ", ".join(f"'{v}'" for v in values)
    op.create_check_constraint("kind", "job_request", f"kind IN ({allowed})")


def upgrade() -> None:
    _check(AFTER)


def downgrade() -> None:
    op.execute("DELETE FROM job_request WHERE kind = 'plan_generate'")
    _check(BEFORE)
