"""Routes de l'interface, regroupées par écran (SPEC §9)."""

from __future__ import annotations

from fastapi import FastAPI

from vigie.web.routes import (
    audit,
    plans,
    policy,
    projects,
    settings,
    signals,
    skills,
    sources,
    team,
)

MODULES = (plans, signals, team, policy, projects, skills, sources, settings, audit)


def register(app: FastAPI) -> None:
    for module in MODULES:
        app.include_router(module.router)
