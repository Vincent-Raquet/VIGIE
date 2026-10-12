"""chat_message.model : modèle d'IA demandé (question) ou utilisé (réponse)

Revision ID: 0012
Revises: 0011
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("chat_message", sa.Column("model", sa.String(length=50), nullable=True))
    # Valeurs bornées à des identifiants de modèle (le web les valide aussi).
    op.create_check_constraint(
        "model", "chat_message", "model IS NULL OR model ~ '^[a-z0-9-]{1,50}$'"
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_chat_message_model"), "chat_message", type_="check")
    op.drop_column("chat_message", "model")
