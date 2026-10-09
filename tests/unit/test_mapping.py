"""Rattachement société / criticité par règles asset_rule."""

from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from tests.conftest import REPO_ROOT
from vigie.db.enums import MatchType
from vigie.mapping import AssetRuleData, RuleMapper, companies_for, max_criticality, normalize
from vigie.seed import apply_seed, load_seed_data

P, S = MatchType.hostgroup_prefix, MatchType.hostgroup_suffix

RULES = [
    AssetRuleData("zabbix", P, "WI", company_code="WI"),
    AssetRuleData("zabbix", P, "WG", company_code="WG"),
    AssetRuleData("zabbix", P, "SPL", company_code="SPL"),
    AssetRuleData("zabbix", P, "Switchs/WI", company_code="WI"),
    AssetRuleData("zabbix", P, "Switchs/WG", company_code="WG"),
    AssetRuleData("zabbix", S, "Réseau", asset_criticality=1.5),
    AssetRuleData("zabbix", S, "Serveurs", asset_criticality=1.3),
    AssetRuleData("veeam", MatchType.job_prefix, "SPL-", company_code="SPL"),
    AssetRuleData("ninjaone", MatchType.org_id, "12", company_code="CC"),
]
mapper = RuleMapper(RULES)


def test_normalize() -> None:
    assert normalize("  Réseau ") == "reseau"


@pytest.mark.parametrize(
    ("group", "company"),
    [
        ("WI - Serveurs", "WI"),
        ("WI-Réseau", "WI"),
        ("wi", "WI"),
        ("WG-Reseau", "WG"),
        ("Switchs/WI", "WI"),
        ("Switchs/WG-IT", "WG"),
        ("Switchs/WG-OT", "WG"),
        ("SPL-CAMERAS", "SPL"),
        ("WIFI-Bornes", None),
        ("Switchs", None),
        ("Hypervisors", None),
        ("(vm)", None),
    ],
)
def test_hostgroup_prefix(group: str, company: str | None) -> None:
    assert mapper.company_for("zabbix", P, group) == company


def test_rules_are_scoped_by_source_and_type() -> None:
    assert mapper.company_for("veeam", P, "WI - Serveurs") is None
    assert mapper.company_for("zabbix", S, "WI - Serveurs") is None


@pytest.mark.parametrize(
    ("group", "crit"),
    [("WI-Réseau", 1.5), ("WG-Reseau", 1.5), ("SPL - Serveurs", 1.3), ("Préréseau", None)],
)
def test_hostgroup_suffix_criticality(group: str, crit: float | None) -> None:
    assert mapper.asset_criticality("zabbix", S, group) == crit


def test_other_match_types() -> None:
    assert mapper.company_for("veeam", MatchType.job_prefix, "SPL-Daily") == "SPL"
    assert mapper.company_for("veeam", MatchType.job_prefix, "WI-Daily") is None
    assert mapper.company_for("ninjaone", MatchType.org_id, "12") == "CC"
    assert mapper.company_for("ninjaone", MatchType.org_id, "123") is None


def test_most_specific_rule_wins() -> None:
    m = RuleMapper(
        [
            AssetRuleData("zabbix", P, "Switchs", company_code="WI"),
            AssetRuleData("zabbix", P, "Switchs/SPL", company_code="SPL"),
        ]
    )
    assert m.company_for("zabbix", P, "Switchs/SPL") == "SPL"
    assert m.company_for("zabbix", P, "Switchs/WG") == "WI"


def test_helpers_over_groups() -> None:
    groups = ["WI - Serveurs", "Hypervisors", "WI-Réseau"]
    assert companies_for(mapper, "zabbix", P, groups) == {"WI"}
    assert companies_for(mapper, "zabbix", P, ["WI-Réseau", "WG-Reseau"]) == {"WI", "WG"}
    assert max_criticality(mapper, "zabbix", S, groups) == 1.5
    assert max_criticality(mapper, "zabbix", S, ["Hypervisors"]) is None


def test_from_seed_dir_example(tmp_path: Path) -> None:
    example = REPO_ROOT / "config" / "companies.example.yaml"
    (tmp_path / "companies.example.yaml").write_text(example.read_text(encoding="utf-8"))
    m = RuleMapper.from_seed_dir(tmp_path)
    assert m.company_for("zabbix", P, "FWD-RUT") == "FWD"
    assert m.company_for("zabbix", P, "Switchs/SPL") == "SPL"


@pytest.mark.db
def test_from_session(db_session: Session) -> None:
    apply_seed(db_session, load_seed_data(REPO_ROOT / "config", REPO_ROOT / "roles"))
    m = RuleMapper.from_session(db_session)
    assert m.company_for("zabbix", P, "CC-Réseau") == "CC"
    assert m.asset_criticality("zabbix", S, "CC-Réseau") == 1.5
