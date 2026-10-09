"""Rattachement des actifs aux sociétés et criticité (règles `asset_rule`, SPEC §5.1).

Implémente `vigie.connectors.base.CompanyMapper`. Les règles viennent de la base (worker) ou
du YAML d'amorçage (`vigie collect --dry-run`, sans base). Aucune société n'est codée en dur
dans un connecteur.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.connectors.base import CompanyMapper
from vigie.db import models
from vigie.db.enums import MatchType

# Séparateurs qui bornent un préfixe/suffixe de groupe : « WI » capte « WI - Serveurs »,
# « WI-Réseau », « Switchs/WI », mais pas « WIFI-Bornes ».
_SEPARATORS = frozenset(" -_/.()")


def normalize(text: str) -> str:
    """Minuscules, sans accents ni espaces superflus (« Réseau » == « reseau »)."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c)).casefold().strip()


@dataclass(frozen=True)
class AssetRuleData:
    source: str
    match_type: MatchType
    pattern: str
    company_code: str | None = None
    asset_criticality: float | None = None

    def matches(self, value: str) -> bool:
        v, p = normalize(value), normalize(self.pattern)
        if not p:
            return False
        match self.match_type:
            case MatchType.hostgroup_prefix:
                return v.startswith(p) and (len(v) == len(p) or v[len(p)] in _SEPARATORS)
            case MatchType.hostgroup_suffix:
                return v.endswith(p) and (len(v) == len(p) or v[-len(p) - 1] in _SEPARATORS)
            case MatchType.devname_prefix | MatchType.job_prefix:
                return v.startswith(p)
            case MatchType.org_id | MatchType.adom | MatchType.agent_group:
                return v == p


class RuleMapper:
    """Règle la plus spécifique (motif le plus long) d'abord."""

    def __init__(self, rules: Iterable[AssetRuleData]) -> None:
        self._rules = sorted(rules, key=lambda r: len(r.pattern), reverse=True)

    def _matching(self, source: str, match_type: str, value: str) -> list[AssetRuleData]:
        return [
            r
            for r in self._rules
            if r.source == source and r.match_type == match_type and r.matches(value)
        ]

    def company_for(self, source: str, match_type: str, value: str) -> str | None:
        return next(
            (r.company_code for r in self._matching(source, match_type, value) if r.company_code),
            None,
        )

    def asset_criticality(self, source: str, match_type: str, value: str) -> float | None:
        return next(
            (
                r.asset_criticality
                for r in self._matching(source, match_type, value)
                if r.asset_criticality is not None
            ),
            None,
        )

    @classmethod
    def from_session(cls, session: Session) -> RuleMapper:
        rows = session.scalars(select(models.AssetRule)).all()
        return cls(
            AssetRuleData(
                source=r.source,
                match_type=r.match_type,
                pattern=r.pattern,
                company_code=r.company_code,
                asset_criticality=r.asset_criticality,
            )
            for r in rows
        )

    @classmethod
    def from_seed_dir(cls, from_dir: Path) -> RuleMapper:
        """Règles lues dans `companies.yaml` (ou `companies.example.yaml`), sans base."""
        from vigie.seed import load_companies

        data = load_companies(from_dir)
        return cls(
            AssetRuleData(
                source=r.source,
                match_type=r.match,
                pattern=r.pattern,
                company_code=r.company,
                asset_criticality=r.asset_criticality,
            )
            for r in data.asset_rules
        )


def companies_for(
    mapper: CompanyMapper, source: str, match_type: str, values: Sequence[str]
) -> set[str]:
    """Sociétés distinctes rattachées à une liste de valeurs (ex. groupes d'un hôte)."""
    return {c for v in values if (c := mapper.company_for(source, match_type, v)) is not None}


def max_criticality(
    mapper: CompanyMapper, source: str, match_type: str, values: Sequence[str]
) -> float | None:
    found = [
        c for v in values if (c := mapper.asset_criticality(source, match_type, v)) is not None
    ]
    return max(found, default=None)
