"""Routes de l'interface, regroupées par écran (SPEC §9)."""

from __future__ import annotations

from fastapi import FastAPI

from vigie.web.routes import plans

MODULES = (plans,)


def register(app: FastAPI) -> None:
    for module in MODULES:
        app.include_router(module.router)
