"""Messages de diffusion d'un plan (SPEC F9) : un e-mail par personne ayant des tâches,
un récapitulatif au coordinateur, une carte Teams de synthèse.

- Données lues en base (`vigie.planview`) ; textes des sources et de l'IA échappés (HTML)
  et nettoyés (texte brut).
- Liens construits par l'application seulement (`vigie.links`).
- Teams (C13) : résumé chiffré et **un seul** lien vers Vigie, aucun détail de tâche.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.db import models
from vigie.db.enums import PlanKind, PlanStatus, Priority
from vigie.engine.calendar import DAY_NAMES_FR
from vigie.engine.planner import COORDINATOR_ROLE_SKILL
from vigie.links import vigie_link
from vigie.planview import PlanView, TaskView, failing_sources, plan_view
from vigie.redact import clean_untrusted

ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"]),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)
PRIORITY_COLORS = {"P1": "#c0392b", "P2": "#c26a0e", "P3": "#8a7a12", "P4": "#6b7684"}


def _num(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".").replace(".", ",")


_URL_RE = re.compile(r"(?i)\b(https?|ftp|file)://")
_WWW_RE = re.compile(r"(?i)\bwww\.")


def _plain(value: str, limit: int = 400) -> str:
    """Texte non fiable (source, IA) : nettoyé et URL désarmées, pour qu'aucun client de
    messagerie n'en fasse un lien (« https[:]// », « www[.] »). Jinja échappe ensuite le HTML."""
    text = clean_untrusted(value, limit)
    return _WWW_RE.sub("www[.]", _URL_RE.sub(r"\1[:]//", text))


ENV.filters["num"] = _num
ENV.filters["plain"] = _plain
ENV.globals["DAY_NAMES_FR"] = DAY_NAMES_FR
ENV.globals["PRIORITY_COLORS"] = PRIORITY_COLORS


@dataclass(frozen=True)
class Message:
    person_id: int
    to: str
    name: str
    subject: str
    html: str
    text: str
    kind: str = "personnel"  # ou « recapitulatif »


@dataclass
class Bundle:
    plan: models.Plan
    messages: list[Message] = field(default_factory=list)
    recap: Message | None = None
    teams: dict[str, Any] = field(default_factory=dict)


def _period(plan: models.Plan) -> str:
    if plan.kind is PlanKind.daily:
        d = plan.period_start
        return f"du {DAY_NAMES_FR[d.weekday()]} {d:%d/%m}"
    return f"de la semaine du {plan.period_start:%d/%m} au {plan.period_end:%d/%m}"


def _subject(plan: models.Plan, tail: str) -> str:
    draft = "[non validé] " if plan.status is PlanStatus.draft else ""
    return f"[Vigie] {draft}Plan {_period(plan)} — {tail}"


def _page(plan: models.Plan) -> str:
    return "aujourdhui" if plan.kind is PlanKind.daily else "semaine"


def coordinator(session: Session) -> models.Person | None:
    return session.scalar(
        select(models.Person)
        .join(models.RoleSkill, models.RoleSkill.id == models.Person.role_skill_id)
        .where(models.RoleSkill.name == COORDINATOR_ROLE_SKILL, models.Person.active.is_(True))
        .order_by(models.Person.id)
        .limit(1)
    )


def _context(view: PlanView, base_url: str) -> dict[str, Any]:
    plan = view.plan
    return {
        "plan": plan,
        "period": _period(plan),
        "draft": plan.status is PlanStatus.draft,
        "weekly": plan.kind is PlanKind.weekly,
        "ai": view.ai,
        "plan_url": vigie_link(base_url, _page(plan), day=plan.period_start),
        "incident_url": lambda incident_id: vigie_link(
            base_url, "signaux", incident_id=incident_id
        ),
    }


def _by_day(tasks: list[TaskView]) -> list[tuple[date | None, list[TaskView]]]:
    days: dict[date | None, list[TaskView]] = {}
    for t in sorted(tasks, key=lambda t: (t.day or date.max, t.task.priority.value)):
        days.setdefault(t.day, []).append(t)
    return list(days.items())


def build(session: Session, plan: models.Plan, base_url: str) -> Bundle:
    view = plan_view(session, plan)
    ctx = _context(view, base_url)
    bundle = Bundle(plan=plan)

    for card in view.people:
        if not card.tasks:
            continue
        p1 = sum(1 for t in card.tasks if t.task.priority is Priority.P1)
        tail = f"{len(card.tasks)} tâche(s)" + (f" dont {p1} P1" if p1 else "")
        data = {**ctx, "card": card, "days": _by_day(card.tasks)}
        bundle.messages.append(
            Message(
                person_id=card.person.id,
                to=card.person.email,
                name=card.person.name,
                subject=_subject(plan, tail),
                html=ENV.get_template("person.html").render(data),
                text=ENV.get_template("person.txt").render(data),
            )
        )

    lead = coordinator(session)
    if lead is not None:
        escalations = [t for c in view.people for t in c.tasks if "scalade" in t.task.rationale]
        data = {
            **ctx,
            "view": view,
            "escalations": escalations,
            "sources_down": [s.name for s in failing_sources(session)],
            "p1": sum(1 for c in view.people for t in c.tasks if t.task.priority is Priority.P1),
        }
        bundle.recap = Message(
            person_id=lead.id,
            to=lead.email,
            name=lead.name,
            subject=_subject(plan, "récapitulatif"),
            html=ENV.get_template("recap.html").render(data),
            text=ENV.get_template("recap.txt").render(data),
            kind="recapitulatif",
        )

    bundle.teams = teams_card(view, ctx["plan_url"])
    return bundle


def teams_card(view: PlanView, url: str) -> dict[str, Any]:
    """Carte adaptative minimale (C13) : chiffres et un lien vers Vigie, sans détail."""
    plan = view.plan
    tasks = [t for c in view.people for t in c.tasks]
    facts = [
        {"title": "Tâches planifiées", "value": str(len(tasks))},
        {"title": "Dont P1", "value": str(sum(1 for t in tasks if t.task.priority is Priority.P1))},
        {"title": "Personnes", "value": str(sum(1 for c in view.people if c.tasks))},
        {"title": "Non planifiées", "value": str(len(view.backlog))},
    ]
    status = "non validé" if plan.status is PlanStatus.draft else plan.status.value
    title = f"Plan {_period(plan)}"
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {
                "type": "TextBlock",
                "text": title,
                "weight": "Bolder",
                "size": "Medium",
                "wrap": True,
            },
            {"type": "TextBlock", "text": f"Statut : {status}", "isSubtle": True, "wrap": True},
            {"type": "FactSet", "facts": facts},
        ],
        "actions": [{"type": "Action.OpenUrl", "title": "Ouvrir dans Vigie", "url": url}],
    }
    return {
        "type": "message",
        "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}
        ],
    }
