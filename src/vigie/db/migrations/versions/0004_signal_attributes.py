"""signal.attributes : attributs structurés fournis par le connecteur (overrides, SPEC §7.4)

Ex. Zabbix : kind (problem, aggregate, proxy_down), maintenance, asset_criticality.
Données de la source : jamais interprétées comme instructions, seulement comparées par les
règles déclaratives de `vigie.engine.rules`.

Revision ID: 0004
Revises: 0003
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "signal",
        sa.Column(
            "attributes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("signal", "attributes")
