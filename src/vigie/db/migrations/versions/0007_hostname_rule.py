"""asset_rule.match_type : ajoute hostname_contains (criticité par type d'actif)

Rodage 2026-10 : une caméra ou une antenne Wi-Fi rangée dans un groupe « Réseau » héritait de
la criticité du cœur de réseau (×1,5). Une règle sur le nom d'hôte, plus spécifique, l'emporte.

Revision ID: 0007
Revises: 0006
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

BEFORE = (
    "hostgroup_prefix", "hostgroup_suffix", "org_id", "adom", "devname_prefix", "job_prefix",
    "agent_group",
)  # fmt: skip
AFTER = (*BEFORE, "hostname_contains")


def _check(values: tuple[str, ...]) -> None:
    op.drop_constraint(op.f("ck_asset_rule_match_type"), "asset_rule", type_="check")
    allowed = ", ".join(f"'{v}'" for v in values)
    op.create_check_constraint("match_type", "asset_rule", f"match_type IN ({allowed})")


def upgrade() -> None:
    _check(AFTER)


def downgrade() -> None:
    op.execute("DELETE FROM asset_rule WHERE match_type = 'hostname_contains'")
    _check(BEFORE)
