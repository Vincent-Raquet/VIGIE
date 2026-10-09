"""plan.data : données structurées du plan pour l'interface web

Synthèses de l'IA (exécutive, par personne), risques, escalades, raison d'un plan généré
sans IA, rejets du validateur, capacité et charge par personne et par jour, jalons à risque.
Le web lit ces données au lieu de réinterpréter le Markdown.

Revision ID: 0006
Revises: 0005
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "plan",
        sa.Column(
            "data",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("plan", "data")
