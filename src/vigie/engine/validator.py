"""Validation de la proposition du LLM (SPEC §7.6, SECURITY.md C4) : le validateur a le
dernier mot. Chaque élément fautif est rejeté seul, avec un motif ; le reste du plan garde
l'affectation et les textes déterministes.

Règles :
- `ref` connue, ou `new-N` (au plus 5, priorité plafonnée à P3, origine LLM) ;
- réaffectation seulement vers une personne active, compétente (niveau selon la priorité),
  présente un jour de la fenêtre, avec la capacité et le quota de tâches du jour, et dans
  l'échéance SLA pour P1/P2 ;
- priorité jamais abaissée ; incidents et jalon limités à ceux du plan ;
- textes bornés, nettoyés, et **aucun lien** (URL, www, lien Markdown, balise, e-mail).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import date

from vigie.db.enums import Category, Priority
from vigie.engine.assign import Assignment, AssignmentResult, Candidate, Member, min_level
from vigie.engine.llm_schema import MAX_NEW_TASKS, LLMPlan, LLMTask
from vigie.engine.planner import PlanDraft
from vigie.engine.rules import PRIORITY_RANK
from vigie.redact import clean_untrusted

_LINK_RE = re.compile(
    r"(?i)([a-z][a-z0-9+.-]*://|\bwww\.|\]\s*\(|<\s*/?\s*[a-z!]|[\w.+-]+@[\w-]+\.[a-z]{2,})"
)
TITLE_MAX = 120
ACTION_MAX = 200
RATIONALE_MAX = 300
SUMMARY_MAX = 600


def has_link(text: str) -> bool:
    return bool(_LINK_RE.search(text))


@dataclass
class RefinedPlan:
    draft: PlanDraft
    summary_exec: str = ""
    per_person: dict[int, str] = field(default_factory=dict)
    risks: list[tuple[str, str]] = field(default_factory=list)
    escalations: list[tuple[str, str]] = field(default_factory=list)
    rejections: list[str] = field(default_factory=list)

    def ai_data(self, without_ai_reason: str | None) -> dict[str, object]:
        """Contributions de l'IA retenues, pour `plan.data["ai"]` (JSON)."""
        if without_ai_reason is not None:
            return {"by_llm": False, "without_ai_reason": without_ai_reason}
        return {
            "by_llm": True,
            "summary_exec": self.summary_exec,
            "per_person": {str(k): v for k, v in self.per_person.items()},
            "risks": [{"text": t, "severity": s} for t, s in self.risks],
            "escalations": [{"text": t, "to": to} for t, to in self.escalations],
            "rejections": self.rejections,
        }


class _Ledger:
    """Charge et nombre de tâches par personne et par jour, mis à jour par les déplacements."""

    def __init__(self, draft: PlanDraft, max_tasks: int, country: str) -> None:
        self.capacity = dict(draft.result.capacity)
        self.load = dict(draft.result.load)
        self.count: dict[tuple[int, date], int] = {}
        for a in draft.result.assigned:
            if a.person_id is not None and a.day is not None:
                key = (a.person_id, a.day)
                self.count[key] = self.count.get(key, 0) + 1
        self.max_tasks = max_tasks
        self.country = country

    def fits(self, member: Member, day: date, hours: float, *, freed: float = 0.0) -> bool:
        key = (member.id, day)
        remaining = self.capacity.get(key, 0) - self.load.get(key, 0) + freed
        count = self.count.get(key, 0) - (1 if freed else 0)
        return (
            member.availability.present(day, self.country)
            and remaining + 1e-9 >= hours
            and count < self.max_tasks
        )

    def remove(self, person_id: int | None, day: date | None, hours: float) -> None:
        if person_id is None or day is None:
            return
        key = (person_id, day)
        self.load[key] = round(self.load.get(key, 0) - hours, 2)
        self.count[key] = self.count.get(key, 0) - 1

    def add(self, person_id: int, day: date, hours: float) -> None:
        key = (person_id, day)
        self.load[key] = round(self.load.get(key, 0) + hours, 2)
        self.count[key] = self.count.get(key, 0) + 1


class Validator:
    def __init__(
        self, draft: PlanDraft, *, max_tasks_per_day: int = 5, country: str = "BE"
    ) -> None:
        self.draft = draft
        self.ledger = _Ledger(draft, max_tasks_per_day, country)
        self.rejections: list[str] = []
        self.by_ref: dict[str, tuple[str, Assignment]] = {}
        for status, items in (
            ("assigned", draft.result.assigned),
            ("later", draft.result.later),
            ("backlog", draft.result.backlog),
        ):
            for a in items:
                self.by_ref.setdefault(a.candidate.ref, (status, a))
        self.known_incidents = {
            i for _, a in self.by_ref.values() for i in a.candidate.incident_ids
        }

    # --- Textes -------------------------------------------------------------------------

    def _text(self, value: str, limit: int, where: str) -> str | None:
        if has_link(value):
            self.rejections.append(f"{where} : lien ou balise refusé")
            return None
        cleaned = clean_untrusted(value, limit)
        return cleaned or None

    # --- Affectation --------------------------------------------------------------------

    def _move(
        self, a: Assignment, proposal: LLMTask, status: str
    ) -> tuple[int | None, date | None]:
        """Personne et jour retenus pour la tâche (déterministes si la proposition échoue)."""
        c = a.candidate
        target_id = proposal.assignee_id
        if target_id is None or (target_id == a.person_id and status == "assigned"):
            return a.person_id, a.day
        member = self.draft.members.get(target_id)
        where = f"{c.ref} → personne {target_id}"
        if member is None:
            self.rejections.append(f"{where} : personne inconnue")
            return a.person_id, a.day
        if member.level(c.skills) < min_level(c.priority):
            self.rejections.append(f"{where} : compétence insuffisante ({', '.join(c.skills)})")
            return a.person_id, a.day
        hard_due = c.due if c.priority in (Priority.P1, Priority.P2) else None
        days = [
            d
            for d in self.draft.window
            if (hard_due is None or d <= hard_due) and (c.not_before is None or d >= c.not_before)
        ]
        if a.day in days:  # garder le jour proposé si possible
            days.remove(a.day)
            days.insert(0, a.day)
        freed = c.estimate_h if status == "assigned" and a.person_id == member.id else 0.0
        day = next(
            (
                d
                for d in days
                if self.ledger.fits(member, d, c.estimate_h, freed=freed if d == a.day else 0.0)
            ),
            None,
        )
        if day is None:
            self.rejections.append(f"{where} : absent ou sans capacité dans la fenêtre")
            return a.person_id, a.day
        if status == "assigned":
            self.ledger.remove(a.person_id, a.day, c.estimate_h)
        self.ledger.add(member.id, day, c.estimate_h)
        return member.id, day

    # --- Tâches -------------------------------------------------------------------------

    def _refine(self, proposal: LLMTask, absorbed: set[str]) -> tuple[str, Assignment]:
        status, a = self.by_ref[proposal.ref]
        c = a.candidate
        changes: dict[str, object] = {}
        title = self._text(proposal.title, TITLE_MAX, f"{c.ref} titre")
        if title:
            changes["title"] = title
        actions = [
            t
            for n, raw in enumerate(proposal.actions, start=1)
            if (t := self._text(raw, ACTION_MAX, f"{c.ref} action {n}"))
        ]
        if actions:
            changes["actions"] = actions
        if PRIORITY_RANK[proposal.priority] < PRIORITY_RANK[c.priority]:
            changes["priority"] = proposal.priority  # relèvement accepté
        elif proposal.priority is not c.priority:
            self.rejections.append(f"{c.ref} : priorité {proposal.priority} plus basse refusée")
        extra = [i for i in proposal.incident_ids if i not in c.incident_ids]
        unknown = [i for i in extra if i not in self.known_incidents]
        if unknown:
            self.rejections.append(f"{c.ref} : incidents inconnus {unknown} ignorés")
        merged = [i for i in extra if i in self.known_incidents]
        if merged:
            changes["incident_ids"] = [*c.incident_ids, *merged]
            absorbed.update(
                ref
                for ref, (_, other) in self.by_ref.items()
                if ref != c.ref
                and other.candidate.incident_ids
                and set(other.candidate.incident_ids) <= set(merged)
            )
        if proposal.milestone_id not in (None, c.milestone_id):
            self.rejections.append(f"{c.ref} : jalon {proposal.milestone_id} refusé")
        refined = replace(c, **changes, by_llm=bool(changes)) if changes else c  # type: ignore[arg-type]
        person_id, day = self._move(a, proposal, status)
        moved = (person_id, day) != (a.person_id, a.day)
        rationale = a.rationale
        if moved:
            refined = replace(refined, by_llm=True)
            note = self._text(proposal.rationale, RATIONALE_MAX, f"{c.ref} justification") or ""
            who = self.draft.members[person_id].name if person_id in self.draft.members else "—"
            rationale = f"Réaffecté à {who} sur proposition de l'IA, validée : {note}".rstrip(" :")
            status = "assigned"
        return status, replace(
            a, candidate=refined, person_id=person_id, day=day, rationale=rationale
        )

    def _new_task(self, proposal: LLMTask, n: int) -> Assignment | None:
        where = proposal.ref
        if n > MAX_NEW_TASKS:
            self.rejections.append(f"{where} : plus de {MAX_NEW_TASKS} tâches nouvelles")
            return None
        title = self._text(proposal.title, TITLE_MAX, f"{where} titre")
        if title is None:
            return None
        incidents = [i for i in proposal.incident_ids if i in self.known_incidents]
        category = next(
            (
                a.candidate.category
                for _, a in self.by_ref.values()
                if set(a.candidate.incident_ids) & set(incidents)
            ),
            Category.project,
        )
        priority = proposal.priority if PRIORITY_RANK[proposal.priority] >= 3 else Priority.P3
        candidate = Candidate(
            ref=where,
            title=title,
            category=category,
            priority=priority,
            score=0,
            estimate_h=proposal.estimate_h,
            skills=[],
            incident_ids=incidents,
            actions=[
                t
                for k, raw in enumerate(proposal.actions, start=1)
                if (t := self._text(raw, ACTION_MAX, f"{where} action {k}"))
            ],
            by_llm=True,
            reason="Tâche proposée par l'IA",
        )
        member = self.draft.members.get(proposal.assignee_id or -1)
        if member is not None:
            for d in self.draft.window:
                if self.ledger.fits(member, d, candidate.estimate_h):
                    self.ledger.add(member.id, d, candidate.estimate_h)
                    note = self._text(proposal.rationale, RATIONALE_MAX, f"{where} justification")
                    why = (
                        f"Proposée par l'IA, validée : {note}"
                        if note
                        else "Proposée par l'IA, validée"
                    )
                    return Assignment(candidate, member.id, d, why)
        self.rejections.append(f"{where} : personne absente ou sans capacité, tâche en backlog")
        return Assignment(candidate, None, None, "Proposée par l'IA : non planifiée")

    def run(self, plan: LLMPlan) -> RefinedPlan:
        refined: dict[str, tuple[str, Assignment]] = {}
        absorbed: set[str] = set()
        new: list[Assignment] = []
        seen: set[str] = set()
        new_count = 0
        # Les tâches existantes d'abord (P1 → P4) : elles passent avant les nouvelles.
        ordered = sorted(
            plan.tasks,
            key=lambda t: (t.ref.startswith("new-"), PRIORITY_RANK.get(t.priority, 9)),
        )
        for proposal in ordered:
            if proposal.ref in seen:
                self.rejections.append(f"{proposal.ref} : doublon ignoré")
                continue
            seen.add(proposal.ref)
            if proposal.ref.startswith("new-"):
                new_count += 1
                created = self._new_task(proposal, new_count)
                if created is not None:
                    new.append(created)
            elif proposal.ref in self.by_ref:
                refined[proposal.ref] = self._refine(proposal, absorbed)
            else:
                self.rejections.append(f"{proposal.ref} : référence inconnue ignorée")

        result = AssignmentResult(load=self.ledger.load, capacity=self.ledger.capacity)
        buckets = {"assigned": result.assigned, "later": result.later, "backlog": result.backlog}
        for ref, (status, original) in self.by_ref.items():
            if ref in absorbed and ref not in refined:
                self.ledger.remove(
                    original.person_id if status == "assigned" else None,
                    original.day,
                    original.candidate.estimate_h,
                )
                continue  # regroupée dans une autre tâche
            final_status, assignment = refined.get(ref, (status, original))
            buckets[final_status].append(assignment)
        for a in new:
            (result.assigned if a.person_id is not None else result.backlog).append(a)

        draft = replace(self.draft, result=result)
        return RefinedPlan(
            draft=draft,
            summary_exec=self._text(plan.summary_exec, SUMMARY_MAX, "synthèse") or "",
            per_person={
                p.person_id: text
                for p in plan.per_person
                if p.person_id in self.draft.members
                and (text := self._text(p.summary, SUMMARY_MAX, f"synthèse de {p.person_id}"))
            },
            risks=[
                (text, r.severity)
                for r in plan.risks
                if (text := self._text(r.text, RATIONALE_MAX, "risque"))
            ],
            escalations=[
                (text, e.to)
                for e in plan.escalations
                if (text := self._text(e.text, RATIONALE_MAX, "escalade"))
            ],
            rejections=self.rejections,
        )


def validate(
    draft: PlanDraft, plan: LLMPlan, *, max_tasks_per_day: int = 5, country: str = "BE"
) -> RefinedPlan:
    return Validator(draft, max_tasks_per_day=max_tasks_per_day, country=country).run(plan)
