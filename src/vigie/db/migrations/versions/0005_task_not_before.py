"""task.not_before : tâche à ne pas planifier avant une date (suivi chez un spécialiste)

Ex. « Analyse de cause racine » prévue au prochain jour de présence de Cédric, ou P2
reportée au jour du spécialiste dans le délai SLA (SPEC §7.5).

Revision ID: 0005
Revises: 0004
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("task", sa.Column("not_before", sa.Date(), nullable=True))


def downgrade() -> None:
    op.drop_column("task", "not_before")
