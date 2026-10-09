"""Construction des plans quotidien et hebdomadaire (SPEC F8, §7.1).

`build_plan` lit la base et renvoie un `PlanDraft` (aucune écriture) ; `save_plan` l'enregistre
en `draft`, généré par les règles. Les incidents doivent avoir été corrélés et scorés avant
(`run_engine`).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.config import PlansConfig
from vigie.db import models
from vigie.db.enums import (
    Category,
    GeneratedBy,
    IncidentStatus,
    MilestoneStatus,
    PlanKind,
    PlanStatus,
    Priority,
    ProjectStatus,
    TaskOrigin,
    TaskStatus,
)
from vigie.engine.assign import (
    Assigner,
    AssignmentResult,
    Candidate,
    Member,
    MilestoneRisk,
    milestone_at_risk,
)
from vigie.engine.calendar import AbsenceSpan, Availability, days, week_of
from vigie.engine.correlate import correlate
from vigie.engine.scoring import score_incidents
from vigie.engine.settings import ScoringConfig, load_scoring, load_sla_hours

COORDINATOR_ROLE_SKILL = "ingenieur-coordinateur"
OPEN_TASK = (TaskStatus.todo, TaskStatus.in_progress, TaskStatus.blocked)
ABSENCE_HORIZON_DAYS = 35
TITLE_MAX = 120
MILESTONE_CHUNK_H = 4.0


@dataclass(frozen=True)
class IncidentLine:
    id: int
    priority: Priority
    score: float
    category: Category
    company_code: str | None
    asset: str
    title: str
    reason: str
    created_at: datetime


@dataclass(frozen=True)
class SourceDown:
    name: str
    since: datetime | None
    error: str


@dataclass
class PlanDraft:
    kind: PlanKind
    period_start: date
    period_end: date
    generated_at: datetime
    window: list[date]
    members: dict[int, Member]
    result: AssignmentResult
    new_incidents: list[IncidentLine] = field(default_factory=list)
    late: list[Candidate] = field(default_factory=list)
    blocked: list[Candidate] = field(default_factory=list)
    sources_down: list[SourceDown] = field(default_factory=list)
    milestones: list[Candidate] = field(default_factory=list)
    risks: list[MilestoneRisk] = field(default_factory=list)
    open_by_priority: Counter[Priority] = field(default_factory=Counter)
    trends: dict[str, list[tuple[str, int, int]]] = field(default_factory=dict)


def plan_window(kind: PlanKind, day: date) -> list[date]:
    if kind is PlanKind.daily:
        return [day]
    if day.weekday() >= 5:  # week-end : semaine suivante
        day = day + timedelta(days=7 - day.weekday())
    return days(*week_of(day))


# --- Lecture de la base -----------------------------------------------------------------


def load_members(session: Session, start: date) -> list[Member]:
    horizon = start + timedelta(days=ABSENCE_HORIZON_DAYS)
    coordinator_skill = session.scalar(
        select(models.RoleSkill.id).where(models.RoleSkill.name == COORDINATOR_ROLE_SKILL)
    )
    people = session.scalars(
        select(models.Person).where(models.Person.active.is_(True)).order_by(models.Person.id)
    ).all()
    skills: dict[int, dict[str, tuple[int, object]]] = {}
    for s in session.scalars(select(models.PersonSkill)):
        skills.setdefault(s.person_id, {})[s.skill_tag] = (s.level, s.preference)
    absences: dict[int, list[AbsenceSpan]] = {}
    for a in session.scalars(
        select(models.Absence).where(models.Absence.end >= start, models.Absence.start <= horizon)
    ):
        absences.setdefault(a.person_id, []).append(AbsenceSpan(a.start, a.end, a.kind, a.hours))
    return [
        Member(
            id=p.id,
            name=p.name,
            skills=skills.get(p.id, {}),  # type: ignore[arg-type]
            availability=Availability(
                person_id=p.id,
                weekly_pattern=dict(p.weekly_pattern),
                planning_rate=p.planning_rate,
                absences=tuple(absences.get(p.id, [])),
            ),
            is_coordinator=coordinator_skill is not None and p.role_skill_id == coordinator_skill,
        )
        for p in people
    ]


def _open_incidents(
    session: Session,
) -> list[tuple[models.Incident, list[models.Signal]]]:
    rows = session.execute(
        select(models.Incident, models.Signal)
        .join(models.IncidentSignal, models.IncidentSignal.incident_id == models.Incident.id)
        .join(models.Signal, models.Signal.id == models.IncidentSignal.signal_id)
        .where(models.Incident.status == IncidentStatus.open, models.Signal.resolved_at.is_(None))
        .order_by(models.Incident.id, models.Signal.id)
    ).all()
    grouped: dict[int, tuple[models.Incident, list[models.Signal]]] = {}
    for incident, signal in rows:
        grouped.setdefault(incident.id, (incident, []))[1].append(signal)
    return list(grouped.values())


def _skills_for(category: Category, attributes: dict[str, object], cfg: ScoringConfig) -> list[str]:
    skills = list(cfg.category_skill.get(category, []))
    for extra in cfg.extra_skills:
        if extra.category is category and extra.when.holds({"attributes": attributes}):
            skills.extend(s for s in extra.skills if s not in skills)
    return skills


def _title(incident: models.Incident, lead: models.Signal, count: int) -> str:
    prefix = f"{incident.asset} : " if incident.asset else ""
    suffix = f" (+{count - 1} signal(s))" if count > 1 else ""
    text = f"{prefix}{lead.title}"
    if len(text) + len(suffix) > TITLE_MAX:
        text = text[: TITLE_MAX - len(suffix) - 1].rstrip() + "…"
    return text + suffix


def incident_candidates(
    session: Session, cfg: ScoringConfig, window: Sequence[date], tz: ZoneInfo
) -> list[Candidate]:
    sla = load_sla_hours(session)
    out = []
    for incident, signals in _open_incidents(session):
        lead = max(signals, key=lambda s: (s.severity, s.last_seen))
        opened = min(s.first_seen for s in signals)
        due = (opened + timedelta(hours=sla[incident.priority])).astimezone(tz).date()
        out.append(
            Candidate(
                ref=f"incident:{incident.id}",
                title=_title(incident, lead, len(signals)),
                category=incident.category,
                priority=incident.priority,
                score=incident.score,
                estimate_h=cfg.estimate_h(incident.category),
                skills=_skills_for(incident.category, dict(lead.attributes or {}), cfg),
                due=max(due, window[0]),
                incident_ids=[incident.id],
                reason=incident.priority_reason,
                forced=incident.priority_reason.startswith("Override "),
            )
        )
    return out


def milestone_candidates(
    session: Session, kind: PlanKind, window: Sequence[date], plans: PlansConfig
) -> list[Candidate]:
    horizon = window[0] + timedelta(days=plans.milestone_window_days)
    rows = session.scalars(
        select(models.Milestone)
        .join(models.Project, models.Project.id == models.Milestone.project_id)
        .where(
            models.Project.status == ProjectStatus.active,
            models.Milestone.status.in_([MilestoneStatus.planned, MilestoneStatus.in_progress]),
            models.Milestone.remaining_h > 0,
            models.Milestone.due <= horizon,
        )
        .order_by(models.Milestone.due)
    ).all()
    # Tranche par jour de travail, compatible avec la capacité d'un temps partiel (6,4 h).
    chunk = MILESTONE_CHUNK_H
    return [
        Candidate(
            ref=f"milestone:{m.id}",
            title=f"Jalon : {m.title}"[:TITLE_MAX],
            category=Category.project,
            priority=Priority.P2 if m.due <= window[0] + timedelta(days=7) else Priority.P3,
            score=0,
            estimate_h=min(m.remaining_h, chunk),
            skills=list(m.skill_tags),
            due=max(m.due, window[0]),
            milestone_id=m.id,
            preferred_id=m.owner_id,
            reason=f"Échéance {m.due:%d/%m}, {m.remaining_h:g} h restantes",
        )
        for m in rows
    ]


def carried_candidates(
    session: Session, kind: PlanKind, window: Sequence[date]
) -> tuple[list[Candidate], list[Candidate]]:
    """Tâches non terminées du plan précédent de même type (report) ; et les bloquées."""
    previous = session.scalar(
        select(models.Plan)
        .where(models.Plan.kind == kind, models.Plan.period_end < window[0])
        .order_by(models.Plan.period_end.desc(), models.Plan.id.desc())
        .limit(1)
    )
    if previous is None:
        return [], []
    tasks = session.scalars(
        select(models.Task).where(
            models.Task.plan_id == previous.id, models.Task.status.in_(OPEN_TASK)
        )
    ).all()
    links: dict[int, list[int]] = {}
    for link in session.scalars(
        select(models.TaskIncident).where(models.TaskIncident.task_id.in_([t.id for t in tasks]))
    ):
        links.setdefault(link.task_id, []).append(link.incident_id)
    open_ids = set(
        session.scalars(
            select(models.Incident.id).where(models.Incident.status == IncidentStatus.open)
        )
    )
    carried: list[Candidate] = []
    blocked: list[Candidate] = []
    for t in tasks:
        incident_ids = links.get(t.id, [])
        if incident_ids and not set(incident_ids) & open_ids:
            continue  # signaux résolus : clôture proposée (F10), pas de report
        candidate = Candidate(
            ref=f"carry:{t.id}",
            title=t.title,
            category=t.category,
            priority=t.priority,
            score=t.score or 0,
            estimate_h=t.estimate_h,
            skills=[],
            due=t.due,
            incident_ids=incident_ids,
            milestone_id=t.milestone_id,
            preferred_id=t.assignee_id,
            carry_count=t.carry_count + 1,
            reason=t.rationale,
            not_before=t.not_before,
        )
        (blocked if t.status is TaskStatus.blocked else carried).append(candidate)
    return carried, blocked


def sources_down(session: Session) -> list[SourceDown]:
    out = []
    for s in session.scalars(select(models.Source).where(models.Source.enabled.is_(True))):
        failing = s.last_error_at is not None and (
            s.last_ok_at is None or s.last_error_at > s.last_ok_at
        )
        if failing:
            out.append(SourceDown(s.name, s.last_ok_at, s.last_error or ""))
    return out


def _line(incident: models.Incident, lead: models.Signal) -> IncidentLine:
    return IncidentLine(
        incident.id,
        incident.priority,
        incident.score,
        incident.category,
        incident.company_code,
        incident.asset,
        lead.title,
        incident.priority_reason,
        incident.created_at,
    )


def _trends(session: Session, start: date, tz: ZoneInfo) -> dict[str, list[tuple[str, int, int]]]:
    """Signaux apparus cette semaine et la précédente, par source et par société."""
    this_start = datetime.combine(start, datetime.min.time(), tz)
    prev_start = this_start - timedelta(days=7)
    rows = session.execute(
        select(models.Signal.source, models.Signal.company_code, models.Signal.first_seen).where(
            models.Signal.first_seen >= prev_start
        )
    ).all()
    out: dict[str, list[tuple[str, int, int]]] = {}
    for label, index in (("source", 0), ("société", 1)):
        now_c: Counter[str] = Counter()
        prev_c: Counter[str] = Counter()
        for source, company, first_seen in rows:
            key = (source if index == 0 else company) or "sans société"
            (now_c if first_seen >= this_start else prev_c)[key] += 1
        out[label] = [(k, now_c[k], prev_c[k]) for k in sorted(set(now_c) | set(prev_c))]
    return out


def build_plan(
    session: Session,
    kind: PlanKind,
    day: date,
    now: datetime,
    plans: PlansConfig,
    *,
    tz: ZoneInfo,
    country: str = "BE",
) -> PlanDraft:
    cfg = load_scoring(session)
    window = plan_window(kind, day)
    members = load_members(session, window[0])
    carried, blocked = carried_candidates(session, kind, window)
    covered = {i for c in carried + blocked for i in c.incident_ids}
    covered_milestones = {c.milestone_id for c in carried + blocked if c.milestone_id}
    fresh = [
        c
        for c in incident_candidates(session, cfg, window, tz)
        if not set(c.incident_ids) & covered
    ]
    milestones = [
        c
        for c in milestone_candidates(session, kind, window, plans)
        if c.milestone_id not in covered_milestones
    ]
    current = {i: c for c in incident_candidates(session, cfg, window, tz) for i in c.incident_ids}
    for c in carried:
        if not c.skills:
            c.skills = list(cfg.category_skill.get(c.category, []))
        # Un report suit la priorité actuelle de ses incidents (aggravation, override).
        live = [current[i] for i in c.incident_ids if i in current]
        if live:
            top = min(live, key=lambda x: (x.priority.value, -x.score))
            c.priority, c.score, c.reason = top.priority, top.score, top.reason
            c.forced = top.forced
            c.skills = top.skills

    assigner = Assigner(
        members,
        window,
        max_tasks_per_day=plans.max_tasks_per_person_per_day,
        country=country,
        escalate_carry_after=plans.carry_over_escalation_after,
        coordinator_overload_max=plans.coordinator_overload_max,
    )
    result = assigner.run(carried + fresh + milestones)

    since = now - timedelta(days=1 if kind is PlanKind.daily else 7)
    incidents = _open_incidents(session)
    new = sorted(
        (
            _line(i, max(s, key=lambda x: (x.severity, x.last_seen)))
            for i, s in incidents
            if i.priority in (Priority.P1, Priority.P2) and i.created_at >= since
        ),
        key=lambda line: (line.priority.value, -line.score),
    )
    risks = []
    for m in milestone_candidates(session, PlanKind.weekly, window, plans):
        milestone = session.get(models.Milestone, m.milestone_id)
        if milestone is None:  # pragma: no cover - lu juste au-dessus
            continue
        risk = milestone_at_risk(
            milestone.id,
            milestone.title,
            milestone.due,
            milestone.remaining_h,
            milestone.skill_tags,
            members,
            window[0],
            country,
        )
        if risk is not None:
            risks.append(risk)
    return PlanDraft(
        kind=kind,
        period_start=window[0],
        period_end=window[-1],
        generated_at=now,
        window=window,
        members={m.id: m for m in members},
        result=result,
        new_incidents=new,
        late=[c for c in carried if c.due is not None and c.due < window[0]],
        blocked=blocked,
        sources_down=sources_down(session),
        milestones=milestones,
        risks=risks,
        open_by_priority=Counter(i.priority for i, _ in incidents),
        trends=_trends(session, window[0], tz) if kind is PlanKind.weekly else {},
    )


# --- Écriture ---------------------------------------------------------------------------


def run_engine(session: Session, now: datetime) -> None:
    """Corrélation puis score des incidents ouverts (préalable à `build_plan`)."""
    correlate(session, now)
    score_incidents(session, now)


def plan_data(draft: PlanDraft, ai: dict[str, Any] | None = None) -> dict[str, Any]:
    """Données structurées du plan lues par le web (JSON)."""
    return {
        "capacity": {
            str(pid): {d.isoformat(): draft.result.capacity.get((pid, d), 0) for d in draft.window}
            for pid in sorted(draft.members)
        },
        "load": {
            str(pid): {d.isoformat(): draft.result.load.get((pid, d), 0) for d in draft.window}
            for pid in sorted(draft.members)
        },
        "milestones_at_risk": [
            {
                "milestone_id": r.milestone_id,
                "title": r.title,
                "due": r.due.isoformat(),
                "remaining_h": r.remaining_h,
                "capacity_h": r.capacity_h,
            }
            for r in draft.risks
        ],
        "sources_down": [s.name for s in draft.sources_down],
        "ai": ai or {},
    }


def save_plan(
    session: Session,
    draft: PlanDraft,
    summary_md: str,
    *,
    llm_call_id: int | None = None,
    ai: dict[str, Any] | None = None,
) -> models.Plan:
    """Enregistre le brouillon ; `llm_call_id` : plan affiné par l'IA et validé ;
    `ai` : synthèses, risques, escalades, rejets ou raison d'un plan sans IA."""
    plan = models.Plan(
        kind=draft.kind,
        period_start=draft.period_start,
        period_end=draft.period_end,
        status=PlanStatus.draft,
        summary_md=summary_md,
        generated_by=GeneratedBy.llm if llm_call_id is not None else GeneratedBy.rules,
        llm_call_id=llm_call_id,
        created_at=draft.generated_at,
        data=plan_data(draft, ai),
    )
    session.add(plan)
    session.flush()
    groups = (
        (draft.result.assigned, TaskStatus.todo),
        (draft.result.later, TaskStatus.todo),
        (draft.result.backlog, TaskStatus.todo),
    )
    for assignments, status in groups:
        for a in assignments:
            c = a.candidate
            task = models.Task(
                plan_id=plan.id,
                milestone_id=c.milestone_id,
                title=c.title[:TITLE_MAX],
                description=c.reason,
                actions=list(c.actions),
                category=c.category,
                priority=c.priority,
                score=c.score,
                estimate_h=min(c.estimate_h, 16),
                assignee_id=a.person_id,
                due=c.due if c.due is not None else a.day,
                not_before=c.not_before if c.not_before is not None else a.day,
                status=status,
                carry_count=c.carry_count,
                rationale=a.rationale,
                origin=TaskOrigin.llm if c.by_llm else TaskOrigin.engine,
                created_at=draft.generated_at,
            )
            session.add(task)
            session.flush()
            for incident_id in dict.fromkeys(c.incident_ids):
                session.add(models.TaskIncident(task_id=task.id, incident_id=incident_id))
    session.flush()
    return plan


def utc_now() -> datetime:
    return datetime.now(UTC)
