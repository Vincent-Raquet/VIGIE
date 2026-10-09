"""Overrides de priorité déclaratifs (SPEC §7.4, point H de la roadmap).

Une règle est une conjonction de conditions `{field, op, value}` : aucune expression n'est
interprétée. Les champs viennent des faits de l'incident (`source`, `category`, `severity`,
`company`, `hours_open`, `title` : titres de ses signaux) ou des attributs du signal le plus
sévère (`attr.<clé>`). Une comparaison entre types incompatibles est simplement fausse.
"""

from __future__ import annotations

import operator
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from vigie.db.enums import Priority
from vigie.mapping import normalize

Op = Literal["eq", "ne", "gt", "ge", "lt", "le", "in", "contains_any"]
Scalar = str | int | float | bool | None

_COMPARE: dict[str, Callable[[Any, Any], bool]] = {
    "eq": operator.eq,
    "ne": operator.ne,
    "gt": operator.gt,
    "ge": operator.ge,
    "lt": operator.lt,
    "le": operator.le,
}
FACT_FIELDS = frozenset({"source", "category", "severity", "company", "hours_open", "title"})
PRIORITY_RANK = {Priority.P1: 1, Priority.P2: 2, Priority.P3: 3, Priority.P4: 4}


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str = Field(
        pattern=r"^(source|category|severity|company|hours_open|title|attr\.[a-z_]{1,40})$"
    )
    op: Op
    value: Scalar | list[Scalar]

    def holds(self, facts: Mapping[str, Any]) -> bool:
        if self.field.startswith("attr."):
            attrs = facts.get("attributes") or {}
            actual = attrs.get(self.field.removeprefix("attr."))
        else:
            actual = facts.get(self.field)
        if self.op == "in":
            return isinstance(self.value, list) and actual in self.value
        if self.op == "contains_any":
            # Sous-chaîne, sans casse ni accents (ex. titres d'alertes matérielles).
            if not isinstance(actual, str) or not isinstance(self.value, list):
                return False
            text = normalize(actual)
            return any(
                isinstance(v, str) and v.strip() and normalize(v) in text for v in self.value
            )
        if actual is None or isinstance(self.value, list):
            return False
        if isinstance(actual, bool) != isinstance(self.value, bool):
            return False
        try:
            return bool(_COMPARE[self.op](actual, self.value))
        except TypeError:
            return False


class OverrideRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    priority: Priority
    reason: str = Field(min_length=1, max_length=200)
    all: list[Condition] = Field(min_length=1)

    def matches(self, facts: Mapping[str, Any]) -> bool:
        return all(c.holds(facts) for c in self.all)


def strongest(rules: Sequence[OverrideRule], facts: Mapping[str, Any]) -> OverrideRule | None:
    """Règle applicable la plus prioritaire (P1 avant P2), ou None."""
    matching = [r for r in rules if r.matches(facts)]
    return min(matching, key=lambda r: PRIORITY_RANK[r.priority], default=None)
