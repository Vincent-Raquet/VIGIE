"""Écrans Aujourd'hui et Semaine, suivi des tâches, validation et publication (F8, F10)."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.db import models
from vigie.db.enums import AppRole, Category, PlanKind, PlanStatus, Priority, TaskOrigin, TaskStatus
from vigie.engine.calendar import week_of
from vigie.planview import (
    TaskView,
    failing_sources,
    latest_plan,
    new_urgent_incidents,
    plan_view,
    since_yesterday,
)
from vigie.web.auth import User, audit, require_role
from vigie.web.deps import ALL, DB, LEADS, STAFF, render

router = APIRouter()

Staff = Annotated[User, Depends(require_role(*STAFF))]
Anyone = Annotated[User, Depends(require_role(*ALL))]
Lead = Annotated[User, Depends(require_role(*LEADS))]

SETTABLE = (
    TaskStatus.todo,
    TaskStatus.in_progress,
    TaskStatus.blocked,
    TaskStatus.done,
    TaskStatus.wont_do,
)
STATUS_LABELS = {
    TaskStatus.todo: "à faire",
    TaskStatus.in_progress: "en cours",
    TaskStatus.blocked: "bloquée",
    TaskStatus.pending_done: "terminée ? (signaux résolus)",
    TaskStatus.done: "terminée",
    TaskStatus.wont_do: "abandonnée",
}
PLAN_STATUS_LABELS = {
    PlanStatus.draft: "brouillon non validé",
    PlanStatus.validated: "validé",
    PlanStatus.published: "publié",
}


def safe_next(value: str | None, default: str) -> str:
    """Redirection interne seulement (pas de redirection ouverte)."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return default


def can_edit(user: User, task: models.Task) -> bool:
    if user.role in (AppRole.admin, AppRole.manager):
        return True
    return (
        user.role is AppRole.tech
        and user.person_id is not None
        and task.assignee_id == user.person_id
    )


def _day(value: str | None) -> date:
    if not value:
        return datetime.now(UTC).date()
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise HTTPException(status_code=422, detail="Date attendue au format AAAA-MM-JJ.") from None


def _context(user: User) -> dict[str, object]:
    return {
        "STATUS_LABELS": STATUS_LABELS,
        "SETTABLE": SETTABLE,
        "PLAN_STATUS_LABELS": PLAN_STATUS_LABELS,
        "can_edit": lambda task: can_edit(user, task),
        "is_lead": user.role in LEADS,
    }


@router.get("/aujourdhui")
def today(
    request: Request, user: Staff, session: DB, day: Annotated[str | None, Query()] = None
) -> Response:
    target = _day(day)
    plan = latest_plan(session, PlanKind.daily, target)
    view = plan_view(session, plan) if plan else None
    return render(
        request,
        "today.html",
        {
            **_context(user),
            "day": target,
            "view": view,
            "plan_review": session.get(models.PlanReview, plan.id) if plan else None,
            "p1_count": view.p1_open if view else 0,
            "new_incidents": new_urgent_incidents(session, since_yesterday()),
            "sources_down": failing_sources(session),
        },
    )


@router.get("/semaine")
def week(
    request: Request, user: Anyone, session: DB, day: Annotated[str | None, Query()] = None
) -> Response:
    target = _day(day)
    plan = latest_plan(session, PlanKind.weekly, week_of(target)[0])
    view = plan_view(session, plan) if plan else None
    people = session.scalars(
        select(models.Person).where(models.Person.active.is_(True)).order_by(models.Person.name)
    ).all()
    return render(
        request,
        "week.html",
        {
            **_context(user),
            "day": target,
            "view": view,
            "people": people,
            "categories": list(Category),
            "priorities": list(Priority),
        },
    )


# --- Tâches -----------------------------------------------------------------------------


def apply_status(
    session: Session, user: User, task: models.Task, status: TaskStatus, reason: str
) -> None:
    """Changement de statut d'une tâche (F10) : partagé par l'UI et l'API."""
    if not can_edit(user, task):
        raise HTTPException(
            status_code=403, detail="Vous ne pouvez modifier que vos propres tâches."
        )
    if status not in SETTABLE:
        raise HTTPException(status_code=422, detail="Statut non modifiable.")
    if status is TaskStatus.wont_do and not reason.strip():
        raise HTTPException(status_code=422, detail="Motif obligatoire pour abandonner une tâche.")
    previous = task.status
    task.status = status
    task.status_reason = reason.strip() if status is TaskStatus.wont_do else ""
    audit(
        session,
        user.email,
        "task_status",
        f"task:{task.id}",
        before=previous.value,
        after=status.value,
    )
    session.commit()


def apply_validate(session: Session, user: User, plan: models.Plan) -> None:
    if plan.status is not PlanStatus.draft:
        raise HTTPException(status_code=409, detail="Ce plan n'est plus un brouillon.")
    plan.status = PlanStatus.validated
    plan.validated_by = user.person_id
    plan.validated_at = datetime.now(UTC)
    audit(session, user.email, "plan_validate", f"plan:{plan.id}")
    session.commit()


def apply_review(
    session: Session,
    user: User,
    task: models.Task,
    relevant: bool,
    well_assigned: bool,
    note: str,
) -> None:
    """Jugement d'une tâche par le coordinateur pendant le rodage (phase 9)."""
    if user.person_id is None:
        raise HTTPException(status_code=403, detail="Revue réservée aux membres de l'équipe.")
    review = session.get(models.TaskReview, task.id)
    if review is None:
        review = models.TaskReview(task_id=task.id, reviewer_id=user.person_id)
        session.add(review)
    review.relevant = relevant
    review.well_assigned = well_assigned
    review.note = note.strip()
    review.reviewer_id = user.person_id
    review.at = datetime.now(UTC)
    # Valeurs seulement : la note reste en base, pas dans le journal d'audit.
    audit(
        session,
        user.email,
        "task_review",
        f"task:{task.id}",
        relevant=relevant,
        well_assigned=well_assigned,
    )
    session.commit()


def apply_plan_review(session: Session, user: User, plan: models.Plan, missing: str) -> None:
    if user.person_id is None:
        raise HTTPException(status_code=403, detail="Revue réservée aux membres de l'équipe.")
    review = session.get(models.PlanReview, plan.id)
    if review is None:
        review = models.PlanReview(plan_id=plan.id, reviewer_id=user.person_id)
        session.add(review)
    review.missing = missing.strip()
    review.reviewer_id = user.person_id
    review.at = datetime.now(UTC)
    audit(session, user.email, "plan_review", f"plan:{plan.id}", missing=bool(review.missing))
    session.commit()


def _task_or_404(session: DB, task_id: int) -> models.Task:
    task = session.get(models.Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Tâche introuvable.")
    return task


def _task_fragment(request: Request, user: User, session: DB, task: models.Task) -> Response:
    plan = session.get(models.Plan, task.plan_id) if task.plan_id else None
    view = plan_view(session, plan) if plan else None
    current = next(
        (t for card in (view.people if view else []) for t in card.tasks if t.task.id == task.id),
        None,
    ) or TaskView(task, [])
    return render(request, "_task.html", {**_context(user), "t": current})


@router.post("/taches/{task_id}/statut")
def set_status(
    request: Request,
    user: Staff,
    session: DB,
    task_id: int,
    status: Annotated[TaskStatus, Form()],
    reason: Annotated[str, Form(max_length=300)] = "",
    next_url: Annotated[str | None, Form(alias="next")] = None,
) -> Response:
    task = _task_or_404(session, task_id)
    apply_status(session, user, task, status, reason)
    if request.headers.get("hx-request"):
        return _task_fragment(request, user, session, task)
    return RedirectResponse(safe_next(next_url, "/aujourdhui"), status_code=303)


@router.post("/taches/{task_id}/commentaires")
def add_comment(
    request: Request,
    user: Staff,
    session: DB,
    task_id: int,
    body: Annotated[str, Form(min_length=1, max_length=2000)],
    next_url: Annotated[str | None, Form(alias="next")] = None,
) -> Response:
    task = _task_or_404(session, task_id)
    # Tout membre de l'équipe peut commenter les tâches qu'il voit déjà (plan d'équipe).
    if user.person_id is None:
        raise HTTPException(status_code=403, detail="Commentaire réservé aux membres de l'équipe.")
    session.add(models.TaskComment(task_id=task.id, author_id=user.person_id, body=body.strip()))
    audit(session, user.email, "task_comment", f"task:{task.id}")
    session.commit()
    if request.headers.get("hx-request"):
        return _task_fragment(request, user, session, task)
    return RedirectResponse(safe_next(next_url, "/aujourdhui"), status_code=303)


YES_NO = {"oui": True, "non": False}


def _yes_no(value: str, field: str) -> bool:
    if value not in YES_NO:
        raise HTTPException(status_code=422, detail=f"{field} : oui ou non.")
    return YES_NO[value]


@router.post("/taches/{task_id}/revue")
def review_task(
    request: Request,
    user: Lead,
    session: DB,
    task_id: int,
    relevant: Annotated[str, Form(max_length=3)],
    well_assigned: Annotated[str, Form(max_length=3)],
    note: Annotated[str, Form(max_length=300)] = "",
    next_url: Annotated[str | None, Form(alias="next")] = None,
) -> Response:
    task = _task_or_404(session, task_id)
    apply_review(
        session,
        user,
        task,
        _yes_no(relevant, "Pertinente"),
        _yes_no(well_assigned, "Bien affectée"),
        note,
    )
    if request.headers.get("hx-request"):
        return _task_fragment(request, user, session, task)
    return RedirectResponse(safe_next(next_url, "/aujourdhui"), status_code=303)


# --- Plans ------------------------------------------------------------------------------


def _plan_or_404(session: DB, plan_id: int) -> models.Plan:
    plan = session.get(models.Plan, plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan introuvable.")
    return plan


@router.post("/plans/{plan_id}/valider")
def validate_plan(
    user: Lead,
    session: DB,
    plan_id: int,
    next_url: Annotated[str | None, Form(alias="next")] = None,
) -> Response:
    apply_validate(session, user, _plan_or_404(session, plan_id))
    return RedirectResponse(safe_next(next_url, "/semaine"), status_code=303)


@router.post("/plans/{plan_id}/revue")
def review_plan(
    user: Lead,
    session: DB,
    plan_id: int,
    missing: Annotated[str, Form(max_length=1000)] = "",
    next_url: Annotated[str | None, Form(alias="next")] = None,
) -> Response:
    apply_plan_review(session, user, _plan_or_404(session, plan_id), missing)
    return RedirectResponse(safe_next(next_url, "/aujourdhui"), status_code=303)


@router.post("/plans/{plan_id}/publier")
def publish_plan(
    user: Lead,
    session: DB,
    plan_id: int,
    next_url: Annotated[str | None, Form(alias="next")] = None,
) -> Response:
    plan = _plan_or_404(session, plan_id)
    if plan.status is PlanStatus.published:
        raise HTTPException(status_code=409, detail="Ce plan est déjà publié.")
    validated = plan.status is PlanStatus.validated
    plan.status = PlanStatus.published
    plan.published_at = datetime.now(UTC)
    audit(session, user.email, "plan_publish", f"plan:{plan.id}", validated=validated)
    session.commit()
    return RedirectResponse(safe_next(next_url, "/semaine"), status_code=303)


@router.post("/plans/{plan_id}/taches")
def create_task(
    user: Lead,
    session: DB,
    plan_id: int,
    title: Annotated[str, Form(min_length=3, max_length=120)],
    category: Annotated[Category, Form()],
    priority: Annotated[Priority, Form()],
    estimate_h: Annotated[float, Form(ge=0.25, le=16)],
    assignee: Annotated[str, Form(alias="assignee_id", max_length=12)] = "",
    day_value: Annotated[str, Form(alias="day", max_length=10)] = "",
    next_url: Annotated[str | None, Form(alias="next")] = None,
) -> Response:
    plan = _plan_or_404(session, plan_id)
    # Champs facultatifs d'un formulaire HTML : chaîne vide = absent.
    try:
        assignee_id = int(assignee) if assignee else None
        day = date.fromisoformat(day_value) if day_value else None
    except ValueError:
        raise HTTPException(status_code=422, detail="Personne ou jour invalide.") from None
    if day is not None and not plan.period_start <= day <= plan.period_end:
        raise HTTPException(status_code=422, detail="Jour hors de la période du plan.")
    if assignee_id is not None:
        person = session.get(models.Person, assignee_id)
        if person is None or not person.active:
            raise HTTPException(status_code=422, detail="Personne inconnue.")
    task = models.Task(
        plan_id=plan.id,
        title=title.strip(),
        category=category,
        priority=priority,
        estimate_h=estimate_h,
        assignee_id=assignee_id,
        due=day,
        not_before=day,
        status=TaskStatus.todo,
        rationale=f"Créée manuellement par {user.name}",
        origin=TaskOrigin.human,
    )
    session.add(task)
    session.flush()
    audit(session, user.email, "task_create", f"task:{task.id}", plan=plan.id)
    session.commit()
    return RedirectResponse(safe_next(next_url, "/semaine"), status_code=303)
