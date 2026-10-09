"""Rodage : jugement des tâches et des plans par le coordinateur (task_review, plan_review)

Revision ID: 0009
Revises: 0008
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("task_review", "plan_review")


def _at() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(
        "at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
    )


def upgrade() -> None:
    op.create_table(
        "task_review",
        sa.Column("task_id", sa.BigInteger(), nullable=False),
        sa.Column("relevant", sa.Boolean(), nullable=False),
        sa.Column("well_assigned", sa.Boolean(), nullable=False),
        sa.Column("note", sa.String(length=300), nullable=False),
        sa.Column("reviewer_id", sa.Integer(), nullable=False),
        _at(),
        sa.ForeignKeyConstraint(
            ["reviewer_id"], ["person.id"], name=op.f("fk_task_review_reviewer_id_person")
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["task.id"], name=op.f("fk_task_review_task_id_task"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("task_id", name=op.f("pk_task_review")),
    )
    op.create_table(
        "plan_review",
        sa.Column("plan_id", sa.Integer(), nullable=False),
        sa.Column("missing", sa.String(length=1000), nullable=False),
        sa.Column("reviewer_id", sa.Integer(), nullable=False),
        _at(),
        sa.ForeignKeyConstraint(
            ["reviewer_id"], ["person.id"], name=op.f("fk_plan_review_reviewer_id_person")
        ),
        sa.ForeignKeyConstraint(
            ["plan_id"], ["plan.id"], name=op.f("fk_plan_review_plan_id_plan"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("plan_id", name=op.f("pk_plan_review")),
    )
    for table in TABLES:
        # Jugement saisi dans l'interface ; le worker le lit (tableau de rodage, purge en cascade).
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON {table} TO vigie_web")
        op.execute(f"GRANT SELECT ON {table} TO vigie_worker")


def downgrade() -> None:
    op.drop_table("plan_review")
    op.drop_table("task_review")
