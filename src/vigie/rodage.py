"""Rodage (phase 9) : mesure du critère d'acceptation à partir des jugements du coordinateur.

Critère (ROADMAP) : ≥ 80 % des tâches jugées pertinentes **et** bien affectées, sur 5 jours
ouvrés consécutifs, avant d'activer la diffusion à l'équipe.

- Un jour (plan quotidien) est **validé** si au moins 90 % de ses tâches planifiées sont
  jugées et si au moins 80 % des tâches jugées sont à la fois pertinentes et bien affectées.
- La **série** compte les jours validés consécutifs, du plus récent au plus ancien ; les
  plans les plus récents encore sans aucun jugement (plan du jour pas encore relu) sont
  ignorés, tout autre jour non validé interrompt la série.
"""

from __future__ import annotations

import calendar
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal

from sqlalchemy import ColumnElement, and_, func, or_, select
from sqlalchemy.orm import Session

from vigie.db import models
from vigie.db.enums import PlanKind

RATE_THRESHOLD = 0.8
COVERAGE_THRESHOLD = 0.9
STREAK_TARGET = 5
HISTORY_DAYS = 20


@dataclass(frozen=True)
class DayStats:
    plan_id: int
    day: date
    planned: int
    reviewed: int
    relevant: int
    well_assigned: int
    both: int
    cost_usd: Decimal

    @property
    def coverage(self) -> float:
        return self.reviewed / self.planned if self.planned else 0.0

    def _rate(self, n: int) -> float | None:
        return n / self.reviewed if self.reviewed else None

    @property
    def relevant_rate(self) -> float | None:
        return self._rate(self.relevant)

    @property
    def assigned_rate(self) -> float | None:
        return self._rate(self.well_assigned)

    @property
    def both_rate(self) -> float | None:
        return self._rate(self.both)

    @property
    def validated(self) -> bool:
        rate = self.both_rate
        return (
            self.planned > 0
            and self.coverage >= COVERAGE_THRESHOLD
            and rate is not None
            and rate >= RATE_THRESHOLD
        )


@dataclass(frozen=True)
class Rejection:
    plan_id: int
    day: date
    title: str
    category: str
    origin: str
    assignee: str
    relevant: bool
    well_assigned: bool
    note: str


def streak(days: list[DayStats]) -> int:
    """Jours validés consécutifs ; `days` du plus récent au plus ancien."""
    rest = list(days)
    while rest and rest[0].reviewed == 0:
        rest.pop(0)
    count = 0
    for d in rest:
        if not d.validated:
            break
        count += 1
    return count


def cost_projection(spent: Decimal, now: datetime) -> Decimal:
    """Dépense du mois extrapolée au mois entier, au prorata des jours écoulés."""
    days_in_month = calendar.monthrange(now.year, now.month)[1]
    elapsed = Decimal(now.day - 1) + Decimal(now.hour * 60 + now.minute) / Decimal(1440)
    if spent <= 0 or elapsed <= 0:
        return Decimal(0)
    return (spent / elapsed * days_in_month).quantize(Decimal("0.01"))


def month_spent(session: Session, now: datetime) -> Decimal:
    """Dépense IA du mois civil (UTC) ; sans importer le moteur IA (séparation web/worker)."""
    start = now.astimezone(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    total = session.scalar(
        select(func.coalesce(func.sum(models.LLMCall.cost_usd), 0)).where(
            models.LLMCall.at >= start
        )
    )
    return Decimal(total or 0)


def _latest_daily_plans(session: Session, limit: int) -> list[models.Plan]:
    """Le plan le plus récent de chaque jour (un plan peut être régénéré)."""
    plans = session.scalars(
        select(models.Plan)
        .where(models.Plan.kind == PlanKind.daily)
        .order_by(models.Plan.period_start.desc(), models.Plan.created_at.desc())
    ).all()
    seen: set[date] = set()
    out: list[models.Plan] = []
    for plan in plans:
        if plan.period_start in seen:
            continue
        seen.add(plan.period_start)
        out.append(plan)
        if len(out) == limit:
            break
    return out


def _planned(plan: models.Plan) -> ColumnElement[bool]:
    """Tâches planifiées du plan : affectées et prévues dans la période (hors backlog)."""
    return and_(
        models.Task.plan_id == plan.id,
        models.Task.assignee_id.is_not(None),
        or_(models.Task.not_before.is_(None), models.Task.not_before <= plan.period_end),
    )


def day_stats(session: Session, limit: int = HISTORY_DAYS) -> list[DayStats]:
    out = []
    for plan in _latest_daily_plans(session, limit):
        rows = session.execute(
            select(models.Task.id, models.TaskReview)
            .outerjoin(models.TaskReview, models.TaskReview.task_id == models.Task.id)
            .where(_planned(plan))
        ).all()
        reviews = [r for _, r in rows if r is not None]
        cost = Decimal(0)
        if plan.llm_call_id is not None:
            call = session.get(models.LLMCall, plan.llm_call_id)
            cost = call.cost_usd if call is not None else Decimal(0)
        out.append(
            DayStats(
                plan_id=plan.id,
                day=plan.period_start,
                planned=len(rows),
                reviewed=len(reviews),
                relevant=sum(r.relevant for r in reviews),
                well_assigned=sum(r.well_assigned for r in reviews),
                both=sum(r.relevant and r.well_assigned for r in reviews),
                cost_usd=cost,
            )
        )
    return out


def rejections(session: Session, plan_ids: list[int]) -> list[Rejection]:
    """Tâches jugées non pertinentes ou mal affectées, du plus récent au plus ancien."""
    if not plan_ids:
        return []
    rows = session.execute(
        select(models.Task, models.TaskReview, models.Plan.period_start, models.Person.name)
        .join(models.TaskReview, models.TaskReview.task_id == models.Task.id)
        .join(models.Plan, models.Plan.id == models.Task.plan_id)
        .outerjoin(models.Person, models.Person.id == models.Task.assignee_id)
        .where(
            models.Task.plan_id.in_(plan_ids),
            or_(models.TaskReview.relevant.is_(False), models.TaskReview.well_assigned.is_(False)),
        )
        .order_by(models.Plan.period_start.desc(), models.Task.id)
    ).all()
    return [
        Rejection(
            plan_id=task.plan_id or 0,
            day=day,
            title=task.title,
            category=task.category.value,
            origin=task.origin.value,
            assignee=name or "—",
            relevant=review.relevant,
            well_assigned=review.well_assigned,
            note=review.note,
        )
        for task, review, day, name in rows
    ]


def rejection_counts(items: list[Rejection]) -> dict[str, Counter[str]]:
    return {
        "category": Counter(r.category for r in items),
        "origin": Counter(r.origin for r in items),
    }
