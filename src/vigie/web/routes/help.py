"""Aide en ligne (tous les rôles) : principes, fonctionnement, mode d'emploi.

Les valeurs chiffrées (seuils, SLA, horaires, budget) sont lues dans la configuration et
le barème en vigueur, pour que l'aide ne contredise jamais le comportement réel.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from vigie import rodage
from vigie.ai_models import MODELS, default_model, label_of
from vigie.db.enums import Category
from vigie.engine.settings import load_scoring, load_sla_hours
from vigie.web.auth import User, require_role
from vigie.web.deps import ALL, DB, render

router = APIRouter()
Anyone = Annotated[User, Depends(require_role(*ALL))]

PAGES = {
    "principes": "Principes",
    "fonctionnement": "Fonctionnement",
    "mode-emploi": "Mode d'emploi",
}
WEEKDAYS_FR = {
    "mon": "lundi", "tue": "mardi", "wed": "mercredi", "thu": "jeudi",
    "fri": "vendredi", "sat": "samedi", "sun": "dimanche",
}  # fmt: skip


@router.get("/aide")
def help_index(request: Request, user: Anyone, session: DB) -> Response:
    return render(request, "help/index.html", _context(request, session, None))


@router.get("/aide/{slug}")
def help_page(request: Request, user: Anyone, session: DB, slug: str) -> Response:
    if slug not in PAGES:
        raise HTTPException(status_code=404)
    template = f"help/{slug.replace('-', '_')}.html"
    return render(request, template, _context(request, session, slug))


def _context(request: Request, session: Session, current: str | None) -> dict[str, Any]:
    cfg = request.app.state.cfg
    scoring = load_scoring(session)
    return {
        "pages": PAGES,
        "current": current,
        "cfg": cfg,
        "weekly_day": WEEKDAYS_FR[cfg.plans.weekly_day],
        "scoring": scoring,
        "sla": {p.value: h for p, h in load_sla_hours(session).items()},
        "category_skill": {c.value: s for c, s in scoring.category_skill.items()},
        "estimates": {c.value: scoring.estimate_h(c) for c in Category},
        "sources": sorted(cfg.sources.items()),
        "model": label_of(default_model(session, cfg.llm.model)),
        "models": list(MODELS.values()),
        "rodage": rodage,
    }
