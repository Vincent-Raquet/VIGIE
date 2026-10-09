"""vigie_worker : DELETE sur job_request (purge de rétention des demandes traitées)

Revision ID: 0008
Revises: 0007
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("GRANT DELETE ON job_request TO vigie_worker")


def downgrade() -> None:
    op.execute("REVOKE DELETE ON job_request FROM vigie_worker")
