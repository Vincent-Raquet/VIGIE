"""Paramètres (admin) : configuration du worker en lecture seule, pause globale."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response

from vigie.pause import pause_state, set_pause
from vigie.web.auth import User, audit, require_role
from vigie.web.deps import ADMIN, DB, render

router = APIRouter()
Admin = Annotated[User, Depends(require_role(*ADMIN))]


@router.get("/parametres")
def settings(request: Request, user: Admin, session: DB) -> Response:
    cfg = request.app.state.cfg
    return render(
        request,
        "settings.html",
        {
            "cfg": cfg,
            "pause": pause_state(session),
            "sources": {name: src.enabled for name, src in sorted(cfg.sources.items())},
            "flash": request.session.pop("flash", None),
        },
    )


@router.post("/parametres/pause")
def save_pause(
    request: Request,
    user: Admin,
    session: DB,
    collect: Annotated[str, Form(max_length=3)] = "",
    plan: Annotated[str, Form(max_length=3)] = "",
) -> Response:
    state = {"collect": collect == "on", "plan": plan == "on"}
    set_pause(session, **state)
    audit(session, user.email, "pause_set", "setting:pause", **state)
    session.commit()
    request.session["flash"] = (
        "Pause enregistrée : le worker la lit avant chaque collecte et chaque plan."
    )
    return RedirectResponse("/parametres", status_code=303)
