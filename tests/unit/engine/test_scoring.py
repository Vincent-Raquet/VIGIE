from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from tests.conftest import REPO_ROOT
from vigie.db.enums import Category, Priority
from vigie.engine.scoring import Axis, IncidentFacts, compute, threshold_priority
from vigie.engine.settings import ScoringConfig

NOW = datetime(2026, 10, 13, 9, 0, tzinfo=UTC)
CFG = ScoringConfig()
BACKUP_AXIS = Axis(
    "Sauvegardes fiables et testées", 5, frozenset({"backup"}), frozenset({"veeam", "restauration"})
)
NETWORK_AXIS = Axis("Stabilité réseau inter-sites", 3, frozenset({"network"}), frozenset({"vpn"}))


def facts(**kw: object) -> IncidentFacts:
    base: dict[str, object] = {
        "source": "zabbix",
        "category": Category.server,
        "severity": 4,
        "company_code": "WI",
        "company_criticality": 1.0,
        "asset_criticality": None,
        "opened_at": NOW,
        "recurrences": 0,
        "text": "Unavailable by ICMP ping",
        "attributes": {},
    }
    base.update(kw)
    return IncidentFacts(**base)  # type: ignore[arg-type]


# Calibrage (point F) : exemples du plan de la phase 4.
@pytest.mark.parametrize(
    ("kw", "score", "priority"),
    [
        ({"asset_criticality": 1.3}, 45.5, Priority.P2),  # High serveur de prod
        (
            {
                "category": Category.network,
                "asset_criticality": 1.5,
                "opened_at": NOW - timedelta(days=3),
            },
            74.2,
            Priority.P1,
        ),  # High cœur réseau ouvert depuis 3 j : 35 × 1,5 × 1,3 + axe réseau 6
        ({"severity": 3, "asset_criticality": 1.3}, 26.0, Priority.P3),  # Average serveur
        (
            {"severity": 2, "category": Category.endpoint, "asset_criticality": 0.6},
            6.0,
            Priority.P4,
        ),  # Warning imprimante
        (
            {"severity": 3, "category": Category.backup, "text": "Veeam Backup: Failed session"},
            36.0,
            Priority.P2,
        ),  # échec Veeam + axe sauvegarde
    ],
)
def test_calibration(kw: dict[str, object], score: float, priority: Priority) -> None:
    result = compute(facts(**kw), CFG, [BACKUP_AXIS, NETWORK_AXIS], NOW)
    assert (result.score, result.priority) == (score, priority)


def test_factors_and_reason() -> None:
    result = compute(
        facts(
            severity=3,
            company_criticality=1.2,
            asset_criticality=1.5,
            opened_at=NOW - timedelta(days=20),
            recurrences=3,
            category=Category.backup,
            text="restauration",
        ),
        CFG,
        [BACKUP_AXIS],
        NOW,
    )
    # 20 × 1,2 × 1,5 × 2 (âge plafonné à 10 j) × 1,15 × 1,3 + 10
    assert result.score == round(20 * 1.2 * 1.5 * 2 * 1.15 * 1.3 + 10, 1)
    assert result.reason.startswith("Score 117,6 : sévérité 3 (20), société ×1,2, actif ×1,5")
    assert "récurrence ×1,15" in result.reason
    assert "politique +10 (Sauvegardes fiables et testées)" in result.reason


def test_criticalities_are_clamped_and_unit_factors_hidden() -> None:
    result = compute(facts(company_criticality=3.0, asset_criticality=0.1), CFG, [], NOW)
    assert result.score == 26.2  # 35 × 1,5 × 0,5 arrondi au dixième
    plain = compute(facts(), CFG, [], NOW)
    assert plain.reason == "Score 35 : sévérité 4 (35)"


def test_policy_bonus_is_capped_and_axes_dated() -> None:
    big = [Axis(f"a{i}", 5, frozenset({"server"})) for i in range(5)]
    assert compute(facts(), CFG, big, NOW).score == 35 + 20
    expired = Axis("vieux", 5, frozenset({"server"}), valid_to=date(2026, 1, 1))
    future = Axis("futur", 5, frozenset({"server"}), valid_from=date(2027, 1, 1))
    assert compute(facts(), CFG, [expired, future], NOW).score == 35


def test_keyword_match_ignores_case_and_accents() -> None:
    axis = Axis("x", 1, keywords=frozenset({"Réplication"}))
    assert axis.matches(Category.server, "REPLICATION - WI vers SPL")
    assert not Axis("y", 1, keywords=frozenset({" "})).matches(Category.server, "a b")


def test_override_raises_but_never_lowers() -> None:
    disaster = compute(facts(severity=5, asset_criticality=0.5), CFG, [], NOW)
    assert disaster.priority is Priority.P1
    assert disaster.override_id == "zabbix_disaster"
    assert disaster.reason.startswith("Override zabbix_disaster : Zabbix sévérité Disaster ; Score")

    down = facts(
        source="vigie",
        category=Category.monitoring,
        attributes={"kind": "source_down"},
        opened_at=NOW - timedelta(hours=1),
    )
    assert compute(down, CFG, [], NOW).priority is Priority.P2
    assert compute(replace(down, opened_at=NOW - timedelta(hours=5)), CFG, [], NOW).priority is (
        Priority.P1
    )
    # Score déjà P1 : un override P2 ne l'abaisse pas.
    hot = facts(
        severity=5,
        source="vigie",
        asset_criticality=1.5,
        attributes={"kind": "proxy_down"},
        opened_at=NOW - timedelta(days=2),
    )
    result = compute(hot, CFG, [], NOW)
    assert (result.priority, result.override_id) == (Priority.P1, None)


def test_threshold_priority() -> None:
    assert [threshold_priority(s, CFG) for s in (60, 59.9, 35, 15, 14.9)] == [
        Priority.P1,
        Priority.P2,
        Priority.P2,
        Priority.P3,
        Priority.P4,
    ]


def test_example_scoring_file_matches_code_defaults() -> None:
    data = yaml.safe_load((REPO_ROOT / "config" / "scoring.example.yaml").read_text())
    assert ScoringConfig.model_validate(data) == ScoringConfig()


@pytest.mark.parametrize(
    "bad",
    [
        {"severity_weight": {0: 1, 1: 2}},
        {"thresholds": {"P1": 10, "P2": 35, "P3": 15}},
        {"unknown": 1},
        {"category_skill": {"nope": ["x"]}},
    ],
)
def test_invalid_scoring(bad: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ScoringConfig.model_validate(bad)


def test_category_skill_accepts_strings_and_estimates() -> None:
    cfg = ScoringConfig.model_validate({"category_skill": {"network": "reseau"}})
    assert cfg.category_skill[Category.network] == ["reseau"]
    assert CFG.estimate_h(Category.backup) == 1.5
    assert CFG.category_factor(Category.firewall) == 1.2
    assert CFG.category_factor(Category.server) == 1.0
    assert Path
