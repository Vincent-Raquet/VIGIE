"""Signaux & incidents : liste filtrée et détail avec raison du score (SPEC §9.3)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import func, select

from vigie.db import models
from vigie.db.enums import IncidentStatus, Priority
from vigie.links import source_link
from vigie.web.auth import User, require_role
from vigie.web.deps import DB, STAFF, render

router = APIRouter()
Staff = Annotated[User, Depends(require_role(*STAFF))]
PAGE_SIZE = 200


@router.get("/signaux")
def incidents(
    request: Request,
    user: Staff,
    session: DB,
    status: Annotated[str, Query(pattern="^(open|resolved|all)$")] = "open",
    # Le formulaire envoie tous ses champs : « toutes » = valeur vide, pas une erreur 422.
    priority_raw: Annotated[str, Query(alias="priority", pattern="^(P[1-4])?$")] = "",
    company: Annotated[str | None, Query(max_length=8)] = None,
    source: Annotated[str | None, Query(max_length=64)] = None,
) -> Response:
    priority = Priority(priority_raw) if priority_raw else None
    query = select(models.Incident)
    if status != "all":
        query = query.where(models.Incident.status == IncidentStatus(status))
    if priority is not None:
        query = query.where(models.Incident.priority == priority)
    if company:
        query = query.where(models.Incident.company_code == company)
    if source:
        query = query.where(
            models.Incident.id.in_(
                select(models.IncidentSignal.incident_id)
                .join(models.Signal, models.Signal.id == models.IncidentSignal.signal_id)
                .where(models.Signal.source == source)
            )
        )
    rows = session.scalars(
        query.order_by(models.Incident.priority, models.Incident.score.desc()).limit(PAGE_SIZE)
    ).all()
    counts = dict(
        session.execute(
            select(models.IncidentSignal.incident_id, func.count())
            .where(models.IncidentSignal.incident_id.in_([i.id for i in rows]))
            .group_by(models.IncidentSignal.incident_id)
        ).all()
    )
    return render(
        request,
        "signals.html",
        {
            "incidents": rows,
            "counts": counts,
            "filters": {
                "status": status,
                "priority": priority,
                "company": company,
                "source": source,
            },
            "priorities": list(Priority),
            "companies": session.scalars(
                select(models.Company.code).order_by(models.Company.code)
            ).all(),
            "sources": session.scalars(
                select(models.Source.name).order_by(models.Source.name)
            ).all(),
            "truncated": len(rows) == PAGE_SIZE,
        },
    )


@router.get("/signaux/incidents/{incident_id}")
def incident_detail(request: Request, user: Staff, session: DB, incident_id: int) -> Response:
    incident = session.get(models.Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident introuvable.")
    signals = session.scalars(
        select(models.Signal)
        .join(models.IncidentSignal, models.IncidentSignal.signal_id == models.Signal.id)
        .where(models.IncidentSignal.incident_id == incident.id)
        .order_by(models.Signal.severity.desc(), models.Signal.first_seen)
    ).all()
    cfg = request.app.state.cfg
    links = {}
    for s in signals:
        settings = cfg.sources.get(s.source)
        base = getattr(settings, "base_url", None) if settings else None
        links[s.id] = source_link(s.source, s.url_template_params or {}, base)
    tasks = session.scalars(
        select(models.Task)
        .join(models.TaskIncident, models.TaskIncident.task_id == models.Task.id)
        .where(models.TaskIncident.incident_id == incident.id)
        .order_by(models.Task.created_at.desc())
        .limit(10)
    ).all()
    return render(
        request,
        "incident.html",
        {"incident": incident, "signals": signals, "links": links, "tasks": tasks},
    )
