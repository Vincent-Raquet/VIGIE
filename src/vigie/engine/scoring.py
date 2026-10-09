"""Score et priorité des incidents (SPEC §7.4).

score = W_sev × C_company × C_asset × F_age × F_recurrence × W_category + min(B_policy, max)

La priorité vient des seuils, puis des overrides, qui ne peuvent que la relever. La raison
est lisible par l'équipe (elle apparaît dans les plans).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vigie.db import models
from vigie.db.enums import Category, IncidentStatus, Priority
from vigie.engine.rules import PRIORITY_RANK, strongest
from vigie.engine.settings import ScoringConfig, load_scoring
from vigie.mapping import normalize


@dataclass(frozen=True)
class Axis:
    title: str
    weight: int
    categories: frozenset[str] = frozenset()
    keywords: frozenset[str] = frozenset()
    valid_from: date | None = None
    valid_to: date | None = None

    def active(self, day: date) -> bool:
        return (self.valid_from is None or self.valid_from <= day) and (
            self.valid_to is None or day <= self.valid_to
        )

    def matches(self, category: Category, text: str) -> bool:
        if category.value in self.categories:
            return True
        words = normalize(text)
        return any(normalize(k) in words for k in self.keywords if k.strip())


@dataclass(frozen=True)
class IncidentFacts:
    source: str
    category: Category
    severity: int
    company_code: str | None
    company_criticality: float
    asset_criticality: float | None
    opened_at: datetime
    recurrences: int  # réapparitions sur la fenêtre (0 = première fois)
    text: str  # titres, pour les mots-clés de la politique
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScoreResult:
    score: float
    priority: Priority
    reason: str
    override_id: str | None = None


def _num(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".").replace(".", ",")


def threshold_priority(score: float, cfg: ScoringConfig) -> Priority:
    for name in ("P1", "P2", "P3"):
        if score >= cfg.thresholds[name]:
            return Priority(name)
    return Priority.P4


def compute(
    facts: IncidentFacts, cfg: ScoringConfig, axes: Sequence[Axis], now: datetime
) -> ScoreResult:
    w_sev = cfg.severity_weight[facts.severity]
    c_company = min(max(facts.company_criticality, 0.5), 1.5)
    c_asset = min(max(facts.asset_criticality or cfg.asset_criticality_default, 0.5), 1.5)
    days_open = max((now - facts.opened_at).total_seconds(), 0) / 86400
    f_age = 1 + cfg.age_factor_per_day * min(days_open, cfg.age_factor_max_days)
    f_rec = 1 + cfg.recurrence_factor * min(facts.recurrences, cfg.recurrence_max)
    w_cat = cfg.category_factor(facts.category)
    matched = [a for a in axes if a.active(now.date()) and a.matches(facts.category, facts.text)]
    bonus = min(sum(a.weight * cfg.policy_bonus_per_weight for a in matched), cfg.policy_bonus_max)
    score = round(w_sev * c_company * c_asset * f_age * f_rec * w_cat + bonus, 1)

    parts = [f"sévérité {facts.severity} ({_num(w_sev)})"]
    for label, value in (
        ("société", c_company),
        ("actif", c_asset),
        ("âge", f_age),
        ("récurrence", f_rec),
        ("catégorie", w_cat),
    ):
        if round(value, 2) != 1:
            parts.append(f"{label} ×{_num(value)}")
    if matched:
        parts.append(f"politique +{_num(bonus)} ({', '.join(a.title for a in matched)})")
    priority = threshold_priority(score, cfg)
    reason = f"Score {_num(score)} : " + ", ".join(parts)

    hours_open = max((now - facts.opened_at).total_seconds(), 0) / 3600
    rule = strongest(
        cfg.overrides,
        {
            "source": facts.source,
            "category": facts.category.value,
            "severity": facts.severity,
            "company": facts.company_code,
            "hours_open": hours_open,
            "attributes": facts.attributes,
        },
    )
    if rule is not None and PRIORITY_RANK[rule.priority] < PRIORITY_RANK[priority]:
        return ScoreResult(
            score, rule.priority, f"Override {rule.id} : {rule.reason} ; {reason}", rule.id
        )
    return ScoreResult(score, priority, reason)


# --- En base -------------------------------------------------------------------------


def load_axes(session: Session) -> list[Axis]:
    return [
        Axis(
            title=a.title,
            weight=a.weight,
            categories=frozenset(a.categories),
            keywords=frozenset(a.keywords),
            valid_from=a.valid_from,
            valid_to=a.valid_to,
        )
        for a in session.scalars(select(models.PolicyAxis))
    ]


def incident_facts(
    session: Session,
    signals: Sequence[models.Signal],
    criticality: Mapping[str, float],
    cfg: ScoringConfig,
    now: datetime,
) -> IncidentFacts:
    """Faits d'un incident à partir de ses signaux ouverts (le plus sévère fait foi)."""
    lead = max(signals, key=lambda s: (s.severity, s.last_seen))
    window_start = now - timedelta(days=cfg.recurrence_window_days)
    same = session.scalar(
        select(func.count())
        .select_from(models.Signal)
        .where(
            models.Signal.fingerprint == lead.fingerprint, models.Signal.first_seen >= window_start
        )
    )
    recurrences = max(int(same or 0) - 1, 0) + sum(s.occurrences - 1 for s in signals)
    crit = lead.attributes.get("asset_criticality") if lead.attributes else None
    return IncidentFacts(
        source=lead.source,
        category=lead.category,
        severity=lead.severity,
        company_code=lead.company_code,
        company_criticality=criticality.get(lead.company_code or "", 1.0),
        asset_criticality=float(crit) if isinstance(crit, int | float) else None,
        opened_at=min(s.first_seen for s in signals),
        recurrences=recurrences,
        text=" ".join(s.title for s in signals),
        attributes=dict(lead.attributes or {}),
    )


def score_incidents(session: Session, now: datetime) -> int:
    """Recalcule score, priorité, catégorie et raison des incidents ouverts."""
    cfg = load_scoring(session)
    axes = load_axes(session)
    criticality = {c.code: c.criticality for c in session.scalars(select(models.Company))}
    rows = session.execute(
        select(models.Incident, models.Signal)
        .join(models.IncidentSignal, models.IncidentSignal.incident_id == models.Incident.id)
        .join(models.Signal, models.Signal.id == models.IncidentSignal.signal_id)
        .where(models.Incident.status == IncidentStatus.open, models.Signal.resolved_at.is_(None))
    ).all()
    members: dict[int, tuple[models.Incident, list[models.Signal]]] = {}
    for incident, signal in rows:
        members.setdefault(incident.id, (incident, []))[1].append(signal)
    for incident, signals in members.values():
        facts = incident_facts(session, signals, criticality, cfg, now)
        result = compute(facts, cfg, axes, now)
        incident.score = result.score
        incident.priority = result.priority
        incident.priority_reason = result.reason
        incident.category = facts.category
        incident.updated_at = now
    session.flush()
    return len(members)
