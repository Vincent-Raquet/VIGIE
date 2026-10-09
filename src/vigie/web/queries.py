"""Lectures en base pour les écrans des plans (aucune écriture ici)."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vigie.db import models
from vigie.db.enums import IncidentStatus, PlanKind, Priority, TaskStatus

PRIORITY_ORDER = {Priority.P1: 0, Priority.P2: 1, Priority.P3: 2, Priority.P4: 3}
OPEN_STATUSES = (
    TaskStatus.todo,
    TaskStatus.in_progress,
    TaskStatus.blocked,
    TaskStatus.pending_done,
)


@dataclass
class TaskView:
    task: models.Task
    incident_ids: list[int]
    comments: list[tuple[str, datetime, str]] = field(default_factory=list)

    @property
    def day(self) -> date | None:
        return self.task.not_before


@dataclass
class PersonCard:
    person: models.Person
    tasks: list[TaskView]
    load_h: float
    capacity_h: float
    summary: str = ""

    @property
    def over(self) -> bool:
        return self.load_h > self.capacity_h


@dataclass
class PlanView:
    plan: models.Plan
    people: list[PersonCard]
    later: list[TaskView]
    backlog: list[TaskView]
    days: list[date]
    by_cell: dict[tuple[int, date], list[TaskView]]
    capacity: dict[tuple[int, date], float]
    load: dict[tuple[int, date], float]

    @property
    def ai(self) -> dict[str, Any]:
        data = self.plan.data.get("ai") if isinstance(self.plan.data, dict) else None
        return data if isinstance(data, dict) else {}

    @property
    def p1_open(self) -> int:
        return sum(
            1
            for card in self.people
            for t in card.tasks
            if t.task.priority is Priority.P1 and t.task.status in OPEN_STATUSES
        )


def latest_plan(session: Session, kind: PlanKind, day: date) -> models.Plan | None:
    """Plan de ce type couvrant `day`, sinon le plus récent antérieur."""
    covering = session.scalar(
        select(models.Plan)
        .where(
            models.Plan.kind == kind, models.Plan.period_start <= day, models.Plan.period_end >= day
        )
        .order_by(models.Plan.created_at.desc(), models.Plan.id.desc())
        .limit(1)
    )
    if covering is not None:
        return covering
    return session.scalar(
        select(models.Plan)
        .where(models.Plan.kind == kind, models.Plan.period_start <= day)
        .order_by(models.Plan.period_start.desc(), models.Plan.id.desc())
        .limit(1)
    )


def _grid(data: dict[str, Any], key: str) -> dict[tuple[int, date], float]:
    out: dict[tuple[int, date], float] = {}
    for pid, per_day in (data.get(key) or {}).items():
        for d, value in (per_day or {}).items():
            out[(int(pid), date.fromisoformat(d))] = float(value)
    return out


def plan_view(session: Session, plan: models.Plan) -> PlanView:
    tasks = session.scalars(select(models.Task).where(models.Task.plan_id == plan.id)).all()
    ids = [t.id for t in tasks]
    links: dict[int, list[int]] = defaultdict(list)
    comments: dict[int, list[tuple[str, datetime, str]]] = defaultdict(list)
    if ids:
        for link in session.scalars(
            select(models.TaskIncident).where(models.TaskIncident.task_id.in_(ids))
        ):
            links[link.task_id].append(link.incident_id)
        rows = session.execute(
            select(models.TaskComment, models.Person.name)
            .join(models.Person, models.Person.id == models.TaskComment.author_id)
            .where(models.TaskComment.task_id.in_(ids))
            .order_by(models.TaskComment.at)
        ).all()
        for comment, author in rows:
            comments[comment.task_id].append((author, comment.at, comment.body))
    views = [TaskView(t, sorted(links[t.id]), comments[t.id]) for t in tasks]
    views.sort(key=lambda v: (PRIORITY_ORDER[v.task.priority], -(v.task.score or 0), v.task.id))

    data = plan.data if isinstance(plan.data, dict) else {}
    capacity = _grid(data, "capacity")
    load = _grid(data, "load")
    days = sorted({d for _, d in capacity}) or [plan.period_start]
    people = {p.id: p for p in session.scalars(select(models.Person).order_by(models.Person.name))}
    summaries = (data.get("ai") or {}).get("per_person") or {}

    by_person: dict[int, list[TaskView]] = defaultdict(list)
    by_cell: dict[tuple[int, date], list[TaskView]] = defaultdict(list)
    later, backlog = [], []
    for v in views:
        pid = v.task.assignee_id
        if pid is None:
            backlog.append(v)
        elif v.day is not None and v.day > plan.period_end:
            later.append(v)
        else:
            by_person[pid].append(v)
            if v.day is not None:
                by_cell[(pid, v.day)].append(v)

    cards = []
    for pid, person in people.items():
        cap = sum(capacity.get((pid, d), 0) for d in days)
        if not by_person.get(pid) and cap == 0:
            continue
        cards.append(
            PersonCard(
                person=person,
                tasks=by_person.get(pid, []),
                load_h=round(sum(load.get((pid, d), 0) for d in days), 2),
                capacity_h=round(cap, 2),
                summary=str(summaries.get(str(pid), "")),
            )
        )
    cards.sort(
        key=lambda c: (
            0 if any(t.task.priority is Priority.P1 for t in c.tasks) else 1,
            c.person.name,
        )
    )
    later.sort(key=lambda v: v.day or date.max)
    return PlanView(plan, cards, later, backlog, days, dict(by_cell), capacity, load)


def new_urgent_incidents(session: Session, since: datetime) -> list[models.Incident]:
    return list(
        session.scalars(
            select(models.Incident)
            .where(
                models.Incident.status == IncidentStatus.open,
                models.Incident.priority.in_([Priority.P1, Priority.P2]),
                models.Incident.created_at >= since,
            )
            .order_by(models.Incident.priority, models.Incident.score.desc())
        )
    )


def failing_sources(session: Session) -> list[models.Source]:
    return [
        s
        for s in session.scalars(select(models.Source).where(models.Source.enabled.is_(True)))
        if s.last_error_at is not None and (s.last_ok_at is None or s.last_error_at > s.last_ok_at)
    ]


def open_p1_count(session: Session) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(models.Incident)
            .where(
                models.Incident.status == IncidentStatus.open,
                models.Incident.priority == Priority.P1,
            )
        )
        or 0
    )


def since_yesterday(now: datetime | None = None) -> datetime:
    return (now or datetime.now(UTC)) - timedelta(days=1)
