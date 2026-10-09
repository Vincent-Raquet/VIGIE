"""Contexte envoyé au LLM (SPEC §7.6, SECURITY.md C5).

Blocs système du plus stable au plus variable, pour le cache de prompt :
1. instructions + skills de rôle (+ consignes propres au type de plan) — mis en cache ;
2. politique, taxonomie, équipe — mis en cache ;
puis un message utilisateur variable : période, disponibilités, tâches proposées.

Tout ce qui vient des sources est minimisé (champs utiles), nettoyé et masqué
(`clean_untrusted`), sérialisé en JSON trié puis encapsulé dans `<source_data>` ; les
chevrons y sont échappés pour qu'aucune donnée ne puisse fermer le bloc.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.db import models
from vigie.db.enums import PlanKind, Priority
from vigie.engine.assign import Assignment
from vigie.engine.planner import PlanDraft
from vigie.engine.settings import ScoringConfig
from vigie.redact import clean_untrusted

ROLE_SKILLS = ("responsable-informatique", "ingenieur-coordinateur")
MAX_TASKS_SENT = 150
DETAIL_MAX = 300
TITLE_MAX = 200


@dataclass(frozen=True)
class Prompt:
    system: list[dict[str, Any]]
    user: str
    prompt_hash: str


def _prompt(name: str) -> str:
    return (files("vigie.engine") / "prompts" / f"{name}.md").read_text(encoding="utf-8")


def _json(data: Any) -> str:
    """JSON déterministe (cache) dont les chevrons sont échappés (bloc non refermable)."""
    text = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return text.replace("<", "\\u003c").replace(">", "\\u003e")


def _block(text: str, cached: bool) -> dict[str, Any]:
    block: dict[str, Any] = {"type": "text", "text": text}
    if cached:
        block["cache_control"] = {"type": "ephemeral"}
    return block


def instructions_block(session: Session, kind: PlanKind) -> str:
    skills = {
        s.name: s.body_md
        for s in session.scalars(
            select(models.RoleSkill).where(models.RoleSkill.name.in_(ROLE_SKILLS))
        )
    }
    parts = [_prompt("system")]
    for name in ROLE_SKILLS:
        if name in skills:
            parts.append(f'<role_skill name="{name}">\n{skills[name].strip()}\n</role_skill>')
    parts.append(_prompt(kind.value))
    return "\n\n".join(parts)


def organisation_block(session: Session, draft: PlanDraft, cfg: ScoringConfig) -> str:
    axes = [
        {
            "title": a.title,
            "weight": a.weight,
            "categories": sorted(a.categories),
            "keywords": sorted(a.keywords),
            "valid_from": a.valid_from.isoformat() if a.valid_from else None,
            "valid_to": a.valid_to.isoformat() if a.valid_to else None,
        }
        for a in session.scalars(select(models.PolicyAxis).order_by(models.PolicyAxis.title))
    ]
    rules = list(
        session.scalars(
            select(models.PolicyRule.text)
            .where(models.PolicyRule.active.is_(True))
            .order_by(models.PolicyRule.text)
        )
    )
    people = {p.id: p for p in session.scalars(select(models.Person))}
    team = [
        {
            "id": m.id,
            "name": m.name,
            "job_role": people[m.id].job_role if m.id in people else "",
            "coordinator": m.is_coordinator,
            "skills": {tag: [lvl, pref.value] for tag, (lvl, pref) in sorted(m.skills.items())},
            "weekly_pattern": dict(sorted(m.availability.weekly_pattern.items())),
            "planning_rate": m.availability.planning_rate,
            "notes": clean_untrusted(people[m.id].notes, 500) if m.id in people else "",
        }
        for m in sorted(draft.members.values(), key=lambda m: m.id)
    ]
    taxonomy = {c.value: skills for c, skills in sorted(cfg.category_skill.items())}
    return "# Organisation (données de configuration)\n\n" + _json(
        {"policy_axes": axes, "policy_rules": rules, "taxonomy": taxonomy, "team": team}
    )


def _incident_facts(session: Session, ids: set[int], now: datetime) -> dict[int, dict[str, Any]]:
    if not ids:
        return {}
    rows = session.execute(
        select(models.IncidentSignal.incident_id, models.Signal)
        .join(models.Signal, models.Signal.id == models.IncidentSignal.signal_id)
        .where(models.IncidentSignal.incident_id.in_(ids), models.Signal.resolved_at.is_(None))
    ).all()
    out: dict[int, dict[str, Any]] = {}
    for incident_id, s in rows:
        facts = out.setdefault(
            incident_id,
            {"sources": set(), "company": s.company_code, "asset": s.asset, "signals": 0},
        )
        facts["sources"].add(s.source)
        facts["signals"] += 1
        age = (now - s.first_seen).total_seconds() / 86400
        facts["age_days"] = round(max(age, facts.get("age_days", 0)), 1)
        facts["occurrences"] = max(s.occurrences, facts.get("occurrences", 1))
        lead = facts.get("_lead")
        if lead is None or s.severity > lead.severity:
            facts["_lead"] = s
    for facts in out.values():
        lead = facts.pop("_lead")
        facts["sources"] = sorted(facts["sources"])
        facts["severity"] = lead.severity
        facts["detail"] = clean_untrusted(lead.details, DETAIL_MAX)
        facts["asset"] = clean_untrusted(facts["asset"], TITLE_MAX)
    return out


def _task(a: Assignment, status: str, facts: dict[int, dict[str, Any]]) -> dict[str, Any]:
    c = a.candidate
    return {
        "ref": c.ref,
        "status": status,
        "title": clean_untrusted(c.title, TITLE_MAX),
        "category": c.category.value,
        "priority": c.priority.value,
        "priority_reason": clean_untrusted(c.reason, DETAIL_MAX),
        "score": c.score,
        "estimate_h": c.estimate_h,
        "due": c.due.isoformat() if c.due else None,
        "skills": c.skills,
        "incident_ids": c.incident_ids,
        "incidents": [facts[i] for i in c.incident_ids if i in facts],
        "milestone_id": c.milestone_id,
        "carry_count": c.carry_count,
        "proposed_assignee_id": a.person_id,
        "proposed_day": a.day.isoformat() if a.day else None,
        "escalation": a.escalation,
        "engine_rationale": clean_untrusted(a.rationale, DETAIL_MAX),
    }


DETAILED_BACKLOG = (Priority.P1, Priority.P2)


def tasks_payload(session: Session, draft: PlanDraft) -> list[dict[str, Any]]:
    """Détail pour les tâches planifiées, prévues et le backlog P1/P2 ; le reste du backlog
    est résumé par `backlog_summary` (coût : le détail de 150 tâches double le prompt)."""
    groups = (
        ("assigned", draft.result.assigned),
        ("later", draft.result.later),
        ("backlog", [a for a in draft.result.backlog if a.candidate.priority in DETAILED_BACKLOG]),
    )
    ordered = [(status, a) for status, items in groups for a in items]
    ordered.sort(key=lambda sa: (sa[1].candidate.priority.value, -sa[1].candidate.score))
    kept = ordered[:MAX_TASKS_SENT]
    ids = {i for _, a in kept for i in a.candidate.incident_ids}
    facts = _incident_facts(session, ids, draft.generated_at)
    return [_task(a, status, facts) for status, a in kept]


def backlog_summary(draft: PlanDraft) -> dict[str, dict[str, int]]:
    """Backlog P3/P4 non détaillé : nombre de tâches par priorité et catégorie."""
    out: dict[str, dict[str, int]] = {}
    for a in draft.result.backlog:
        c = a.candidate
        if c.priority in DETAILED_BACKLOG:
            continue
        per = out.setdefault(c.priority.value, {})
        per[c.category.value] = per.get(c.category.value, 0) + 1
    return out


def variable_message(session: Session, draft: PlanDraft) -> str:
    availability = {
        str(m.id): {d.isoformat(): draft.result.capacity.get((m.id, d), 0) for d in draft.window}
        for m in sorted(draft.members.values(), key=lambda m: m.id)
    }
    data = {
        "plan": {
            "kind": draft.kind.value,
            "period_start": draft.period_start.isoformat(),
            "period_end": draft.period_end.isoformat(),
        },
        "capacity_hours": availability,
        "tasks": tasks_payload(session, draft),
        "backlog_not_detailed": backlog_summary(draft),
        "milestones_at_risk": [
            {
                "milestone_id": r.milestone_id,
                "title": clean_untrusted(r.title, TITLE_MAX),
                "due": r.due.isoformat(),
                "remaining_h": r.remaining_h,
                "capacity_h": r.capacity_h,
            }
            for r in draft.risks
        ],
        "sources_down": [s.name for s in draft.sources_down],
    }
    return (
        f"Affine le plan {draft.kind.value} du {draft.period_start:%d/%m/%Y} au "
        f"{draft.period_end:%d/%m/%Y} à partir de la proposition ci-dessous.\n\n"
        f"<source_data>\n{_json(data)}\n</source_data>"
    )


def build_prompt(session: Session, draft: PlanDraft, cfg: ScoringConfig) -> Prompt:
    system = [
        _block(instructions_block(session, draft.kind), cached=True),
        _block(organisation_block(session, draft, cfg), cached=True),
    ]
    user = variable_message(session, draft)
    digest = hashlib.sha256(
        json.dumps({"system": system, "user": user}, sort_keys=True).encode()
    ).hexdigest()
    return Prompt(system=system, user=user, prompt_hash=digest)
