"""Affectation déterministe des tâches (SPEC §7.5).

Candidats d'une tâche : personnes actives ayant **toutes** les compétences requises (niveau
≥ 2 pour P1/P2, ≥ 1 sinon), présentes un jour de la fenêtre avec assez de capacité restante
et moins de `max_tasks_per_day` tâches ce jour-là. Le coordinateur n'est pas un candidat
ordinaire : il est le recours (sauf s'il est le responsable désigné de la tâche).

Tri : jour le plus tôt, responsable désigné, niveau ↓, capacité restante sur la fenêtre ↓,
préférence, équité (charge relative sur la fenêtre).

Sans candidat :
- P1 → coordinateur, même au-delà de sa capacité, marqué *escalade* ; une tâche de suivi
  « Analyse de cause racine » est prévue au prochain jour de présence du spécialiste ;
- P2 → prochain jour de présence du spécialiste si avant l'échéance SLA, sinon coordinateur
  (dans sa capacité), sinon backlog ;
- P3/P4 → coordinateur s'il est compétent et a de la capacité, sinon backlog.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import date

from vigie.db.enums import Category, Priority, SkillPreference
from vigie.engine.calendar import DAY_NAMES_FR, Availability, days
from vigie.engine.rules import PRIORITY_RANK

PREFERENCE_RANK = {SkillPreference.likes: 0, SkillPreference.neutral: 1, SkillPreference.avoid: 2}
FOLLOW_UP_ESTIMATE_H = 1.0
FOLLOW_UP_HORIZON_DAYS = 28


@dataclass(frozen=True)
class Member:
    id: int
    name: str
    skills: dict[str, tuple[int, SkillPreference]]
    availability: Availability
    is_coordinator: bool = False

    def level(self, skills: Sequence[str]) -> int:
        """Niveau sur l'ensemble des compétences requises (le plus faible) ; 0 si l'une manque."""
        if not skills:
            return 1
        return min(self.skills.get(s, (0, SkillPreference.neutral))[0] for s in skills)

    def preference(self, skills: Sequence[str]) -> int:
        ranks = [PREFERENCE_RANK[self.skills[s][1]] for s in skills if s in self.skills]
        return max(ranks, default=PREFERENCE_RANK[SkillPreference.neutral])


@dataclass
class Candidate:
    """Tâche à affecter (incident, jalon, report ou suivi)."""

    ref: str
    title: str
    category: Category
    priority: Priority
    score: float
    estimate_h: float
    skills: list[str]
    due: date | None = None
    incident_ids: list[int] = field(default_factory=list)
    milestone_id: int | None = None
    preferred_id: int | None = None
    carry_count: int = 0
    reason: str = ""
    follow_up: bool = False
    not_before: date | None = None  # suivi prévu chez un spécialiste un jour donné
    forced: bool = False  # priorité imposée par une règle (override) : servie avant le score
    actions: list[str] = field(default_factory=list)  # étapes rédigées par le LLM (validées)
    by_llm: bool = False  # titre, actions ou affectation retenus depuis la proposition du LLM


@dataclass
class Assignment:
    candidate: Candidate
    person_id: int | None
    day: date | None
    rationale: str
    escalation: bool = False


@dataclass
class AssignmentResult:
    assigned: list[Assignment] = field(default_factory=list)
    later: list[Assignment] = field(default_factory=list)  # prévues après la fenêtre
    backlog: list[Assignment] = field(default_factory=list)
    load: dict[tuple[int, date], float] = field(default_factory=dict)
    capacity: dict[tuple[int, date], float] = field(default_factory=dict)


def _num(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".").replace(".", ",")


def min_level(priority: Priority) -> int:
    return 2 if priority in (Priority.P1, Priority.P2) else 1


class Assigner:
    def __init__(
        self,
        members: Sequence[Member],
        window: Sequence[date],
        *,
        max_tasks_per_day: int = 5,
        country: str = "BE",
        escalate_carry_after: int = 3,
        coordinator_overload_max: float = 1.5,
    ) -> None:
        self.overload_max = coordinator_overload_max
        self.members = list(members)
        self.window = sorted(window)
        self.max_tasks = max_tasks_per_day
        self.country = country
        self.escalate_after = escalate_carry_after
        self.coordinator = next((m for m in self.members if m.is_coordinator), None)
        self.result = AssignmentResult()
        self.count: dict[tuple[int, date], int] = {}
        for m in self.members:
            for d in self.window:
                self.result.capacity[(m.id, d)] = m.availability.capacity(d, country)
                self.result.load[(m.id, d)] = 0.0

    # --- Outils -----------------------------------------------------------------------

    def remaining(self, member: Member, day: date) -> float:
        key = (member.id, day)
        return round(self.result.capacity.get(key, 0) - self.result.load.get(key, 0), 2)

    def _fits(self, member: Member, day: date, hours: float) -> bool:
        return (
            member.availability.present(day, self.country)
            and self.remaining(member, day) >= hours
            and self.count.get((member.id, day), 0) < self.max_tasks
        )

    def _remaining_window(self, member: Member) -> float:
        """Capacité restante sur toute la fenêtre : un temps partiel ne voit pas son unique
        jour absorbé par une tâche qu'un temps plein peut prendre."""
        return round(sum(self.remaining(member, d) for d in self.window), 2)

    def _equity(self, member: Member) -> float:
        cap = sum(self.result.capacity.get((member.id, d), 0) for d in self.window)
        load = sum(self.result.load.get((member.id, d), 0) for d in self.window)
        return load / cap if cap else 1.0

    def _book(self, member: Member, day: date, hours: float) -> None:
        key = (member.id, day)
        self.result.load[key] = round(self.result.load.get(key, 0) + hours, 2)
        self.count[key] = self.count.get(key, 0) + 1

    def _qualified(self, task: Candidate) -> list[Member]:
        level = min_level(task.priority)
        return [m for m in self.members if m.level(task.skills) >= level]

    def _why(self, member: Member, day: date, task: Candidate) -> str:
        skills = ", ".join(
            f"{s} niveau {member.skills[s][0]}" for s in task.skills if s in member.skills
        )
        competence = f"compétence {skills}" if skills else "sans compétence requise"
        load = self.result.load.get((member.id, day), 0)
        cap = self.result.capacity.get((member.id, day), 0)
        return (
            f"Assigné à {member.name} : {competence}, présent {DAY_NAMES_FR[day.weekday()]}, "
            f"charge {_num(load)}/{_num(cap)} h"
        )

    # --- Affectation ------------------------------------------------------------------

    def run(self, tasks: Sequence[Candidate]) -> AssignmentResult:
        ordered = sorted(
            tasks,
            # À priorité égale : règle explicite (override) d'abord, puis jalons (capacité
            # réservée, SPEC F3), puis score.
            key=lambda t: (
                PRIORITY_RANK[t.priority],
                not t.forced,
                t.milestone_id is None,
                -t.score,
                t.due or date.max,
                t.ref,
            ),
        )
        for task in ordered:
            self.place(task)
        return self.result

    def place(self, task: Candidate) -> None:
        if task.not_before is not None and self.window and self.window[-1] < task.not_before:
            # Pas encore son jour : reste prévue, sans recours au coordinateur.
            why = task.reason or f"Prévue à partir du {task.not_before:%d/%m}"
            self.result.later.append(Assignment(task, task.preferred_id, task.not_before, why))
            return
        qualified = self._qualified(task)
        ordinary = [m for m in qualified if not m.is_coordinator or m.id == task.preferred_id]
        # P1/P2 : jamais après l'échéance SLA (un P1 n'attend pas le jour du spécialiste).
        # P3/P4 : l'échéance est une cible ; en retard, mieux vaut plus tard que le backlog.
        hard_due = task.due if task.priority in (Priority.P1, Priority.P2) else None
        allowed = [
            d
            for d in self.window
            if (hard_due is None or d <= hard_due)
            and (task.not_before is None or d >= task.not_before)
        ]
        options = [(m, d) for m in ordinary for d in allowed if self._fits(m, d, task.estimate_h)]
        if options:
            member, day = min(
                options,
                key=lambda o: (
                    o[1],
                    o[0].id != task.preferred_id,
                    -o[0].level(task.skills),
                    -self._remaining_window(o[0]),
                    o[0].preference(task.skills),
                    self._equity(o[0]),
                    o[0].id,
                ),
            )
            self._book(member, day, task.estimate_h)
            escalation = task.carry_count > self.escalate_after
            why = self._why(member, day, task)
            if escalation:
                why += f" ; reportée {task.carry_count} fois : escalade vers le coordinateur"
            self.result.assigned.append(Assignment(task, member.id, day, why, escalation))
            return
        self._fallback(task, qualified)

    def _escalation_day(self, c: Member, task: Candidate) -> date | None:
        """Premier jour où le coordinateur, présent, reste sous le plafond d'escalade."""
        allowed = [d for d in self.window if task.due is None or d <= task.due] or self.window[:1]
        for d in allowed:
            cap = self.result.capacity.get((c.id, d), 0)
            load = self.result.load.get((c.id, d), 0)
            if cap > 0 and load + task.estimate_h <= cap * self.overload_max + 1e-9:
                return d
        return None

    def _coordinator_day(self, hours: float) -> date | None:
        """Premier jour où le coordinateur a la capacité (recours ordinaire, P2 à P4)."""
        c = self.coordinator
        if c is None:
            return None
        return next((d for d in self.window if self._fits(c, d, hours)), None)

    def _specialists(self, task: Candidate, qualified: Sequence[Member]) -> list[Member]:
        return sorted(
            (m for m in qualified if not m.is_coordinator),
            key=lambda m: (-m.level(task.skills), m.id),
        )

    def _fallback(self, task: Candidate, qualified: Sequence[Member]) -> None:
        c = self.coordinator
        first = self.window[0] if self.window else None
        if task.priority is Priority.P1 and c is not None:
            day = self._escalation_day(c, task)
            if day is None:
                ceiling = _num(self.overload_max * 100)
                why = (
                    "P1 non couvert : aucun spécialiste disponible et capacité d'escalade du "
                    f"coordinateur atteinte ({ceiling} %) — arbitrage nécessaire"
                )
                self.result.backlog.append(Assignment(task, None, None, why, escalation=True))
                return
            self._book(c, day, task.estimate_h)
            needed = ", ".join(task.skills) or "tous"
            why = f"Escalade : aucun spécialiste ({needed}) disponible ; " + self._why(c, day, task)
            self.result.assigned.append(Assignment(task, c.id, day, why, escalation=True))
            self._follow_up(task, qualified, day)
            return
        if task.priority is Priority.P2 and first is not None:
            for specialist in self._specialists(task, qualified):
                nxt = specialist.availability.next_presence(
                    first, FOLLOW_UP_HORIZON_DAYS, self.country
                )
                if (
                    nxt is not None
                    and (task.due is None or nxt <= task.due)
                    and nxt > self.window[-1]
                ):
                    why = (
                        f"Prévue le {DAY_NAMES_FR[nxt.weekday()]} {nxt:%d/%m} chez "
                        f"{specialist.name} (prochain jour de présence, dans le délai SLA)"
                    )
                    postponed = replace(task, not_before=nxt, preferred_id=specialist.id)
                    self.result.later.append(Assignment(postponed, specialist.id, nxt, why))
                    return
        if c is not None and c.level(task.skills) >= min_level(task.priority):
            day = self._coordinator_day(task.estimate_h)
            if day is not None:
                self._book(c, day, task.estimate_h)
                escalation = task.priority in (Priority.P1, Priority.P2)
                prefix = "Escalade : spécialiste absent ; " if escalation else "Recours : "
                why = prefix + self._why(c, day, task)
                self.result.assigned.append(Assignment(task, c.id, day, why, escalation))
                return
        reason = (
            "aucune personne compétente"
            if not qualified
            else "capacité insuffisante des personnes compétentes"
        )
        self.result.backlog.append(Assignment(task, None, None, f"Non planifiée : {reason}"))

    def _follow_up(self, task: Candidate, qualified: Sequence[Member], escalated_on: date) -> None:
        for specialist in self._specialists(task, qualified):
            nxt = specialist.availability.next_presence(
                escalated_on, FOLLOW_UP_HORIZON_DAYS, self.country
            )
            if nxt is None:
                continue
            follow = Candidate(
                ref=f"followup:{task.ref}",
                title=f"Analyse de cause racine : {task.title}"[:120],
                category=task.category,
                priority=Priority.P3,
                score=task.score,
                estimate_h=FOLLOW_UP_ESTIMATE_H,
                skills=task.skills,
                incident_ids=list(task.incident_ids),
                preferred_id=specialist.id,
                reason=f"Suivi de l'escalade du {escalated_on:%d/%m}",
                follow_up=True,
                not_before=nxt,
            )
            why = (
                f"Suivi chez {specialist.name}, spécialiste, au prochain jour de présence "
                f"({DAY_NAMES_FR[nxt.weekday()]} {nxt:%d/%m})"
            )
            if nxt in self.window and self._fits(specialist, nxt, FOLLOW_UP_ESTIMATE_H):
                self._book(specialist, nxt, FOLLOW_UP_ESTIMATE_H)
                self.result.assigned.append(Assignment(follow, specialist.id, nxt, why))
            else:
                self.result.later.append(Assignment(follow, specialist.id, nxt, why))
            return


def assign(
    tasks: Sequence[Candidate],
    members: Sequence[Member],
    window: Sequence[date],
    *,
    max_tasks_per_day: int = 5,
    country: str = "BE",
    escalate_carry_after: int = 3,
    coordinator_overload_max: float = 1.5,
) -> AssignmentResult:
    return Assigner(
        members,
        window,
        max_tasks_per_day=max_tasks_per_day,
        country=country,
        escalate_carry_after=escalate_carry_after,
        coordinator_overload_max=coordinator_overload_max,
    ).run(tasks)


@dataclass(frozen=True)
class MilestoneRisk:
    milestone_id: int
    title: str
    due: date
    remaining_h: float
    capacity_h: float


def milestone_at_risk(
    milestone_id: int,
    title: str,
    due: date,
    remaining_h: float,
    skills: Sequence[str],
    members: Sequence[Member],
    today: date,
    country: str = "BE",
) -> MilestoneRisk | None:
    """À risque si la charge restante dépasse la capacité des compétents d'ici l'échéance."""
    window = days(today, due) if due >= today else []
    capable = [m for m in members if m.level(skills) >= 1]
    capacity = round(sum(m.availability.capacity(d, country) for m in capable for d in window), 2)
    if remaining_h > capacity:
        return MilestoneRisk(milestone_id, title, due, remaining_h, capacity)
    return None
