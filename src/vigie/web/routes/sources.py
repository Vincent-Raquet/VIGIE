"""Sources : état de santé et « Tester la connexion » (point B : exécuté par le worker)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import func, select

from vigie.db import models
from vigie.db.enums import JobKind
from vigie.db.jobs import JobPayloadError, new_job_request
from vigie.web.auth import User, audit, require_role
from vigie.web.deps import ADMIN, DB, render

router = APIRouter()
Admin = Annotated[User, Depends(require_role(*ADMIN))]


@router.get("/sources")
def sources(request: Request, user: Admin, session: DB) -> Response:
    rows = session.scalars(select(models.Source).order_by(models.Source.name)).all()
    open_signals = dict(
        session.execute(
            select(models.Signal.source, func.count())
            .where(models.Signal.resolved_at.is_(None))
            .group_by(models.Signal.source)
        ).all()
    )
    jobs: dict[str, models.JobRequest] = {}
    for job in session.scalars(
        select(models.JobRequest)
        .where(models.JobRequest.kind == JobKind.source_test)
        .order_by(models.JobRequest.requested_at.desc())
        .limit(50)
    ):
        jobs.setdefault(str(job.payload.get("source", "")), job)
    return render(
        request,
        "sources.html",
        {
            "sources": rows,
            "open_signals": open_signals,
            "jobs": jobs,
            "configured": sorted(request.app.state.cfg.sources),
            "flash": request.session.pop("flash", None),
        },
    )


@router.post("/sources/{name}/tester")
def test_source(request: Request, user: Admin, session: DB, name: str) -> Response:
    if name not in request.app.state.cfg.sources:
        raise HTTPException(status_code=404, detail="Source inconnue.")
    try:
        job = new_job_request(JobKind.source_test.value, {"source": name}, requested_by=user.email)
    except JobPayloadError:
        raise HTTPException(status_code=422, detail="Nom de source invalide.") from None
    session.add(job)
    audit(session, user.email, "source_test_requested", f"source:{name}")
    session.commit()
    request.session["flash"] = (
        f"Test de {name} demandé : le worker l'exécutera à son prochain passage "
        "(vigie jobs --run-pending)."
    )
    return RedirectResponse("/sources", status_code=303)
