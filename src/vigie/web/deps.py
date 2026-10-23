"""Dépendances communes des routes : base, gabarits, utilisateur, navigation."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from vigie.ai_models import label_of
from vigie.db.enums import AppRole
from vigie.engine.calendar import DAY_NAMES_FR
from vigie.web.auth import User
from vigie.web.security import csrf_token

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
MONTHS_FR = (
    "janvier", "février", "mars", "avril", "mai", "juin",
    "juillet", "août", "septembre", "octobre", "novembre", "décembre",
)  # fmt: skip

ALL = (AppRole.admin, AppRole.manager, AppRole.tech, AppRole.viewer)
STAFF = (AppRole.admin, AppRole.manager, AppRole.tech)
LEADS = (AppRole.admin, AppRole.manager)
ADMIN = (AppRole.admin,)


@dataclass(frozen=True)
class NavItem:
    section: str
    label: str
    path: str
    roles: tuple[AppRole, ...]


NAV = (
    NavItem("Plans", "Aujourd'hui", "/aujourdhui", STAFF),
    NavItem("Plans", "Semaine", "/semaine", ALL),
    NavItem("Plans", "Signaux & incidents", "/signaux", STAFF),
    NavItem("Plans", "Rodage", "/rodage", LEADS),
    NavItem("Plans", "Discussions IA", "/chat", ALL),
    NavItem("Configuration", "Équipe", "/equipe", ADMIN),
    NavItem("Configuration", "Politique", "/politique", LEADS),
    NavItem("Configuration", "Projets", "/projets", LEADS),
    NavItem("Configuration", "Skills de rôle", "/skills", ADMIN),
    NavItem("Configuration", "Sources", "/sources", ADMIN),
    NavItem("Configuration", "Paramètres", "/parametres", ADMIN),
    NavItem("Administration", "Audit & coûts", "/audit", ADMIN),
    NavItem("Aide", "Aide", "/aide", ALL),
)


def nav_for(user: User | None) -> list[NavItem]:
    return [item for item in NAV if user is not None and user.role in item.roles]


def db(request: Request) -> Iterator[Session]:
    with request.app.state.sessionmaker() as session:
        yield session


DB = Annotated[Session, Depends(db)]


def fr_date(d: date, *, weekday: bool = True) -> str:
    day = f"{DAY_NAMES_FR[d.weekday()]} " if weekday else ""
    return f"{day}{d.day} {MONTHS_FR[d.month - 1]} {d.year}"


def fr_num(value: float | int | None, digits: int = 1) -> str:
    if value is None:
        return "—"
    text = f"{value:.{digits}f}".rstrip("0").rstrip(".") if digits else f"{value:.0f}"
    return text.replace(".", ",")


TEMPLATES.env.filters["fr_date"] = fr_date
TEMPLATES.env.filters["fr_num"] = fr_num
TEMPLATES.env.globals["DAY_NAMES_FR"] = DAY_NAMES_FR
TEMPLATES.env.globals["model_label"] = label_of


def render(
    request: Request, name: str, context: dict[str, Any] | None = None, status_code: int = 200
) -> HTMLResponse:
    user: User | None = getattr(request.state, "user", None)
    ctx = {
        "user": user,
        "nav": nav_for(user),
        "path": request.url.path,
        "csrf": csrf_token(request),
        **(context or {}),
    }
    return TEMPLATES.TemplateResponse(request, name, ctx, status_code=status_code)
