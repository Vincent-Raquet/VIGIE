"""Projets et jalons (admin, manager) : frise, charge restante, risques (F3)."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select

from vigie.db import models
from vigie.db.enums import MilestoneStatus, ProjectPriority, ProjectStatus
from vigie.engine.assign import milestone_at_risk
from vigie.engine.planner import load_members
from vigie.web.auth import User, audit, require_role
from vigie.web.deps import DB, LEADS, render
from vigie.web.routes.team import TAG_RE

router = APIRouter()
Lead = Annotated[User, Depends(require_role(*LEADS))]


def _done(request: Request, message: str) -> Response:
    request.session["flash"] = message
    return RedirectResponse("/projets", status_code=303)


def _date(value: str, label: str) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"{label} invalide.") from None


def _person(session: DB, value: str) -> int | None:
    if not value:
        return None
    if not value.isdigit() or session.get(models.Person, int(value)) is None:
        raise HTTPException(status_code=422, detail="Personne inconnue.")
    return int(value)


@router.get("/projets")
def projects(request: Request, user: Lead, session: DB) -> Response:
    today = datetime.now(UTC).date()
    rows = session.scalars(
        select(models.Project).order_by(models.Project.status, models.Project.name)
    ).all()
    milestones = session.scalars(select(models.Milestone).order_by(models.Milestone.due)).all()
    by_project: dict[int, list[models.Milestone]] = {}
    for m in milestones:
        by_project.setdefault(m.project_id, []).append(m)
    members = load_members(session, today)
    risks = {
        m.id: r
        for m in milestones
        if m.status in (MilestoneStatus.planned, MilestoneStatus.in_progress)
        and (
            r := milestone_at_risk(
                m.id, m.title, m.due, m.remaining_h, m.skill_tags, members, today
            )
        )
    }
    companies = {
        (pc.project_id, pc.company_code) for pc in session.scalars(select(models.ProjectCompany))
    }
    axes_links = {(pa.project_id, pa.axis_id) for pa in session.scalars(select(models.ProjectAxis))}
    return render(
        request,
        "projects.html",
        {
            "projects": rows,
            "by_project": by_project,
            "risks": risks,
            "today": today,
            "people": session.scalars(
                select(models.Person)
                .where(models.Person.active.is_(True))
                .order_by(models.Person.name)
            ).all(),
            "all_companies": session.scalars(
                select(models.Company.code).order_by(models.Company.code)
            ).all(),
            "all_axes": session.scalars(
                select(models.PolicyAxis).order_by(models.PolicyAxis.title)
            ).all(),
            "project_companies": companies,
            "project_axes": axes_links,
            "statuses": list(ProjectStatus),
            "priorities": list(ProjectPriority),
            "milestone_statuses": list(MilestoneStatus),
            "flash": request.session.pop("flash", None),
        },
    )


@router.post("/projets")
def save_project(
    request: Request,
    user: Lead,
    session: DB,
    name: Annotated[str, Form(min_length=3, max_length=200)],
    status: Annotated[ProjectStatus, Form()],
    priority: Annotated[ProjectPriority, Form()],
    project_id: Annotated[int, Form()] = 0,
    description: Annotated[str, Form(max_length=2000)] = "",
    sponsor: Annotated[str, Form(max_length=100)] = "",
    owner_id: Annotated[str, Form(max_length=12)] = "",
    start: Annotated[str, Form(max_length=10)] = "",
    end: Annotated[str, Form(max_length=10)] = "",
    companies: Annotated[list[str] | None, Form()] = None,
    axes: Annotated[list[int] | None, Form()] = None,
) -> Response:
    project = session.get(models.Project, project_id) if project_id else None
    if project_id and project is None:
        raise HTTPException(status_code=404, detail="Projet introuvable.")
    clash = session.scalar(
        select(models.Project).where(
            models.Project.name == name.strip(), models.Project.id != project_id
        )
    )
    if clash is not None:
        raise HTTPException(status_code=422, detail="Un projet porte déjà ce nom.")
    known_companies = set(session.scalars(select(models.Company.code)))
    known_axes = set(session.scalars(select(models.PolicyAxis.id)))
    if not set(companies or []) <= known_companies or not set(axes or []) <= known_axes:
        raise HTTPException(status_code=422, detail="Société ou axe inconnu.")
    if project is None:
        project = models.Project(name=name.strip(), status=status, priority=priority)
        session.add(project)
    project.name, project.status, project.priority = name.strip(), status, priority
    project.description, project.sponsor = description.strip(), sponsor.strip()
    project.owner_id = _person(session, owner_id)
    project.start, project.end = _date(start, "Début"), _date(end, "Fin")
    session.flush()
    for link in session.scalars(
        select(models.ProjectCompany).where(models.ProjectCompany.project_id == project.id)
    ):
        session.delete(link)
    for axis_link in session.scalars(
        select(models.ProjectAxis).where(models.ProjectAxis.project_id == project.id)
    ):
        session.delete(axis_link)
    session.flush()
    for code in sorted(set(companies or [])):
        session.add(models.ProjectCompany(project_id=project.id, company_code=code))
    for axis_id in sorted(set(axes or [])):
        session.add(models.ProjectAxis(project_id=project.id, axis_id=axis_id))
    audit(
        session,
        user.email,
        "project_save",
        f"project:{project.id}",
        name=project.name,
        status=status.value,
    )
    session.commit()
    return _done(request, "Projet enregistré.")


@router.post("/projets/jalons")
def save_milestone(
    request: Request,
    user: Lead,
    session: DB,
    project_id: Annotated[int, Form()],
    title: Annotated[str, Form(min_length=3, max_length=200)],
    due: Annotated[date, Form()],
    effort_h: Annotated[float, Form(ge=0, le=1000)],
    remaining_h: Annotated[float, Form(ge=0, le=1000)],
    status: Annotated[MilestoneStatus, Form()],
    milestone_id: Annotated[int, Form()] = 0,
    owner_id: Annotated[str, Form(max_length=12)] = "",
    skill_tags: Annotated[str, Form(max_length=300)] = "",
) -> Response:
    if session.get(models.Project, project_id) is None:
        raise HTTPException(status_code=422, detail="Projet inconnu.")
    tags = sorted({t.strip().lower() for t in skill_tags.split(",") if t.strip()})
    if any(not TAG_RE.match(t) for t in tags) or len(tags) > 10:
        raise HTTPException(status_code=422, detail="Compétences invalides.")
    if remaining_h > effort_h:
        raise HTTPException(status_code=422, detail="Le reste à faire dépasse la charge.")
    milestone = session.get(models.Milestone, milestone_id) if milestone_id else None
    if milestone_id and milestone is None:
        raise HTTPException(status_code=404, detail="Jalon introuvable.")
    if milestone is None:
        milestone = models.Milestone(project_id=project_id, title=title.strip(), due=due)
        session.add(milestone)
    milestone.project_id, milestone.title, milestone.due = project_id, title.strip(), due
    milestone.effort_h, milestone.remaining_h, milestone.status = effort_h, remaining_h, status
    milestone.owner_id = _person(session, owner_id)
    milestone.skill_tags = tags
    session.flush()
    audit(session, user.email, "milestone_save", f"milestone:{milestone.id}", title=milestone.title)
    session.commit()
    return _done(request, "Jalon enregistré.")
