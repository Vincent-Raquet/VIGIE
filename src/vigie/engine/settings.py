"""Paramètres du moteur : `setting["scoring"]` (écrit par `vigie seed` depuis scoring.yaml)
et `setting["sla_hours"]`. Défauts en code, identiques à `config/scoring.example.yaml`.

Calibrage (point F de la roadmap) : `W_sev` rééchelonné pour que, avec les seuils 60/35/15,
un Zabbix *High* sur serveur de production tombe en P2 et un *Warning* en P4.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from vigie.db import models
from vigie.db.enums import Category, Priority
from vigie.engine.rules import Condition, OverrideRule

DEFAULT_SEVERITY_WEIGHT = {0: 1.0, 1: 4.0, 2: 10.0, 3: 20.0, 4: 35.0, 5: 50.0}
DEFAULT_SLA_HOURS = {Priority.P1: 4, Priority.P2: 24, Priority.P3: 72, Priority.P4: 168}


def _rule(id_: str, priority: str, reason: str, *conds: tuple[str, str, Any]) -> OverrideRule:
    return OverrideRule(
        id=id_,
        priority=Priority(priority),
        reason=reason,
        all=[Condition(field=f, op=o, value=v) for f, o, v in conds],
    )


HARDWARE_FAILURE_TITLES = [
    "SMART status fail",
    "above critical threshold",
    "power supply is in critical state",
    "power supply failed",
    "disk array controller is in critical state",
    "physical disk is in critical state",
    "RAID is degraded",
]

DEFAULT_OVERRIDES = [
    _rule(
        "hardware_failure",
        "P1",
        "défaillance matérielle (disque, RAID, alimentation, température critique)",
        ("severity", "ge", 4),
        ("title", "contains_any", HARDWARE_FAILURE_TITLES),
    ),
    _rule(
        "zabbix_disaster",
        "P1",
        "Zabbix sévérité Disaster",
        ("source", "eq", "zabbix"),
        ("severity", "eq", 5),
    ),
    _rule(
        "source_down", "P2", "source de supervision injoignable", ("attr.kind", "eq", "source_down")
    ),
    _rule(
        "source_down_4h",
        "P1",
        "source de supervision injoignable depuis plus de 4 h",
        ("attr.kind", "eq", "source_down"),
        ("hours_open", "gt", 4),
    ),
    _rule("proxy_down", "P2", "proxy Zabbix sans contact", ("attr.kind", "eq", "proxy_down")),
    _rule(
        "backup_no_success_24h",
        "P1",
        "sauvegarde critique sans succès depuis plus de 24 h",
        ("category", "eq", "backup"),
        ("attr.hours_since_last_success", "gt", 24),
        ("attr.asset_critical", "eq", True),
    ),
    _rule(
        "backup_two_failures",
        "P1",
        "deux échecs de sauvegarde consécutifs",
        ("category", "eq", "backup"),
        ("attr.consecutive_failures", "ge", 2),
    ),
    _rule(
        "repo_95",
        "P1",
        "repository de sauvegarde > 95 %",
        ("category", "eq", "backup"),
        ("attr.repo_used_pct", "gt", 95),
    ),
    _rule(
        "repo_90",
        "P2",
        "repository de sauvegarde > 90 %",
        ("category", "eq", "backup"),
        ("attr.repo_used_pct", "gt", 90),
    ),
    _rule(
        "firewall_down",
        "P1",
        "pare-feu hors ligne ou HA dégradée",
        ("category", "eq", "firewall"),
        ("attr.state", "in", ["offline", "ha_degraded"]),
    ),
    _rule(
        "vpn_down_30m",
        "P1",
        "VPN site-à-site down depuis plus de 30 min",
        ("attr.kind", "eq", "vpn_down"),
        ("hours_open", "gt", 0.5),
    ),
    _rule(
        "wazuh_level12",
        "P1",
        "Wazuh règle de niveau ≥ 12",
        ("source", "eq", "wazuh"),
        ("attr.rule_level", "ge", 12),
    ),
    _rule(
        "critical_vuln_cvss",
        "P1",
        "vulnérabilité CVSS ≥ 9 sur un actif exposé",
        ("attr.cvss", "ge", 9),
        ("attr.exposed", "eq", True),
    ),
    _rule(
        "critical_vuln_kev",
        "P1",
        "vulnérabilité CISA KEV sur un actif exposé",
        ("attr.kev", "eq", True),
        ("attr.exposed", "eq", True),
    ),
    _rule(
        "cert_7d",
        "P1",
        "certificat expirant sous 7 jours",
        ("attr.kind", "eq", "cert_expiry"),
        ("attr.days_left", "lt", 7),
    ),
    _rule(
        "cert_21d",
        "P2",
        "certificat expirant sous 21 jours",
        ("attr.kind", "eq", "cert_expiry"),
        ("attr.days_left", "lt", 21),
    ),
]


class ExtraSkill(BaseModel):
    """Compétence supplémentaire selon un attribut (point I : patching + systeme si serveur)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: Category
    when: Condition
    skills: list[str] = Field(min_length=1)


class ScoringConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    severity_weight: dict[int, float] = Field(default_factory=lambda: dict(DEFAULT_SEVERITY_WEIGHT))
    category_weight: dict[str, float] = Field(
        default_factory=lambda: {"backup": 1.3, "security": 1.3, "firewall": 1.2, "default": 1.0}
    )
    asset_criticality_default: float = Field(1.0, ge=0.5, le=1.5)
    age_factor_per_day: float = Field(0.03, ge=0)
    age_factor_max_days: int = Field(10, ge=0)
    recurrence_factor: float = Field(0.05, ge=0)
    recurrence_max: int = Field(10, ge=0)
    recurrence_window_days: int = Field(7, ge=1)
    policy_bonus_per_weight: float = Field(2, ge=0)
    policy_bonus_max: float = Field(20, ge=0)
    thresholds: dict[str, float] = Field(
        default_factory=lambda: {"P1": 60.0, "P2": 35.0, "P3": 15.0}
    )
    category_skill: dict[Category, list[str]] = Field(
        default_factory=lambda: {
            Category.network: ["reseau"],
            Category.firewall: ["fortinet"],
            Category.security: ["securite"],
            Category.vulnerability: ["patching"],
            Category.backup: ["backup"],
            Category.server: ["systeme"],
            Category.endpoint: ["poste"],
            Category.user_support: ["support"],
            Category.m365: ["m365"],
            Category.monitoring: ["supervision"],
        }
    )
    extra_skills: list[ExtraSkill] = Field(
        default_factory=lambda: [
            ExtraSkill(
                category=Category.vulnerability,
                when=Condition(field="attr.asset_type", op="eq", value="server"),
                skills=["systeme"],
            )
        ]
    )
    default_estimate_h: dict[Category, float] = Field(
        default_factory=lambda: {
            Category.network: 2,
            Category.firewall: 2,
            Category.security: 2,
            Category.vulnerability: 3,
            Category.backup: 1.5,
            Category.server: 1.5,
            Category.endpoint: 0.5,
            Category.user_support: 0.5,
            Category.m365: 1,
            Category.monitoring: 1,
            Category.project: 2,
        }
    )
    overrides: list[OverrideRule] = Field(default_factory=lambda: list(DEFAULT_OVERRIDES))

    @field_validator("category_skill", mode="before")
    @classmethod
    def _skills_as_lists(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: [v] if isinstance(v, str) else v for k, v in value.items()}
        return value

    @field_validator("severity_weight")
    @classmethod
    def _all_severities(cls, value: dict[int, float]) -> dict[int, float]:
        if set(value) != set(range(6)):
            raise ValueError("severity_weight doit couvrir les sévérités 0 à 5")
        return value

    @field_validator("thresholds")
    @classmethod
    def _ordered_thresholds(cls, value: dict[str, float]) -> dict[str, float]:
        if set(value) != {"P1", "P2", "P3"} or not value["P1"] > value["P2"] > value["P3"]:
            raise ValueError("thresholds : P1 > P2 > P3 attendus")
        return value

    def category_factor(self, category: Category) -> float:
        return self.category_weight.get(category.value, self.category_weight.get("default", 1.0))

    def estimate_h(self, category: Category) -> float:
        return self.default_estimate_h.get(category, 1.0)


def load_scoring(session: Session) -> ScoringConfig:
    row = session.get(models.Setting, "scoring")
    return ScoringConfig.model_validate(row.value) if row is not None else ScoringConfig()


def load_sla_hours(session: Session) -> dict[Priority, int]:
    row = session.get(models.Setting, "sla_hours")
    if row is None:
        return dict(DEFAULT_SLA_HOURS)
    return {**DEFAULT_SLA_HOURS, **{Priority(k): int(v) for k, v in row.value.items()}}
