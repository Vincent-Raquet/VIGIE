from typing import Any

import pytest
from pydantic import ValidationError

from vigie.db.enums import Priority
from vigie.engine.rules import Condition, OverrideRule, strongest

FACTS: dict[str, Any] = {
    "source": "zabbix",
    "category": "network",
    "severity": 4,
    "company": "WG",
    "hours_open": 1.5,
    "attributes": {"kind": "vpn_down", "maintenance": False, "cvss": 9.8},
}


@pytest.mark.parametrize(
    ("field", "op", "value", "expected"),
    [
        ("source", "eq", "zabbix", True),
        ("source", "ne", "zabbix", False),
        ("severity", "ge", 4, True),
        ("severity", "gt", 4, False),
        ("hours_open", "gt", 0.5, True),
        ("hours_open", "lt", 1, False),
        ("company", "in", ["WG", "CC"], True),
        ("company", "in", ["WI"], False),
        ("attr.kind", "eq", "vpn_down", True),
        ("attr.cvss", "ge", 9, True),
        ("attr.missing", "eq", "x", False),
        ("attr.missing", "lt", 5, False),
        ("attr.kind", "gt", 3, False),  # types incompatibles : faux, pas d'exception
        ("attr.maintenance", "eq", False, True),
        ("attr.maintenance", "eq", 0, False),  # bool ≠ int
        ("severity", "eq", True, False),
        ("severity", "eq", [4], False),
    ],
)
def test_condition(field: str, op: str, value: Any, expected: bool) -> None:
    assert Condition(field=field, op=op, value=value).holds(FACTS) is expected  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"field": "__class__", "op": "eq", "value": 1},
        {"field": "attr.Kind", "op": "eq", "value": 1},
        {"field": "attr.a.b", "op": "eq", "value": 1},
        {"field": "severity", "op": "matches", "value": 1},
        {"field": "severity", "op": "eq", "value": {"x": 1}},
        {"field": "severity", "op": "eq", "value": 1, "extra": 1},
    ],
)
def test_condition_schema_is_strict(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Condition(**kwargs)


def rule(rule_id: str, priority: str, *conds: tuple[str, str, Any]) -> OverrideRule:
    return OverrideRule(
        id=rule_id,
        priority=Priority(priority),
        reason="r",
        all=[Condition(field=f, op=o, value=v) for f, o, v in conds],  # type: ignore[arg-type]
    )


def test_strongest_prefers_p1_and_requires_all_conditions() -> None:
    rules = [
        rule("p2", "P2", ("attr.kind", "eq", "vpn_down")),
        rule("p1", "P1", ("attr.kind", "eq", "vpn_down"), ("hours_open", "gt", 0.5)),
        rule("no", "P1", ("attr.kind", "eq", "vpn_down"), ("company", "eq", "WI")),
    ]
    found = strongest(rules, FACTS)
    assert found is not None and found.id == "p1"
    assert strongest(rules, {**FACTS, "hours_open": 0.1}).id == "p2"  # type: ignore[union-attr]
    assert strongest(rules, {"attributes": {}}) is None


def test_rule_needs_conditions() -> None:
    with pytest.raises(ValidationError):
        OverrideRule(id="x", priority=Priority.P1, reason="r", all=[])
