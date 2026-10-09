"""API JSON interne (SPEC §10) : mêmes rôles que l'interface, CSRF sur les mutations,
réponses minimales (pas de détails bruts des sources hors champs utiles)."""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from vigie.db import models
from vigie.db.enums import AppRole, IncidentStatus, JobKind, PlanKind, Priority, TaskStatus
from vigie.db.jobs import JobPayloadError, new_job_request
from vigie.web.auth import User, audit, require_role
from vigie.web.deps import ADMIN, ALL, DB, LEADS, STAFF
from vigie.web.routes.audit import month_start
from vigie.web.routes.plans import apply_status, apply_validate

router = APIRouter(prefix="/api")
Anyone = Annotated[User, Depends(require_role(*ALL))]
Staff = Annotated[User, Depends(require_role(*STAFF))]
Lead = Annotated[User, Depends(require_role(*LEADS))]
Admin = Annotated[User, Depends(require_role(*ADMIN))]
MAX_ROWS = 500


def _plan_json(plan: models.Plan) -> dict[str, Any]:
    return {
        "id": plan.id,
        "kind": plan.kind.value,
        "period_start": plan.period_start.isoformat(),
        "period_end": plan.period_end.isoformat(),
        "status": plan.status.value,
        "generated_by": plan.generated_by.value,
        "created_at": plan.created_at.isoformat(),
        "validated_at": plan.validated_at.isoformat() if plan.validated_at else None,
        "published_at": plan.published_at.isoformat() if plan.published_at else None,
    }


def _visible(user: User, plan: models.Plan) -> bool:
    return user.role is not AppRole.viewer or plan.kind is PlanKind.weekly


@router.get("/plans")
def list_plans(
    user: Anyone,
    session: DB,
    kind: Annotated[PlanKind | None, Query()] = None,
    on: Annotated[date | None, Query(alias="date")] = None,
) -> list[dict[str, Any]]:
    query = select(models.Plan)
    if user.role is AppRole.viewer:
        query = query.where(models.Plan.kind == PlanKind.weekly)
    if kind is not None:
        query = query.where(models.Plan.kind == kind)
    if on is not None:
        query = query.where(models.Plan.period_start <= on, models.Plan.period_end >= on)
    rows = session.scalars(query.order_by(models.Plan.created_at.desc()).limit(50))
    return [_plan_json(p) for p in rows]


@router.get("/plans/{plan_id}")
def get_plan(user: Anyone, session: DB, plan_id: int) -> dict[str, Any]:
    plan = session.get(models.Plan, plan_id)
    if plan is None or not _visible(user, plan):
        raise HTTPException(status_code=404, detail="Plan introuvable.")
    tasks = session.scalars(
        select(models.Task).where(models.Task.plan_id == plan.id).order_by(models.Task.id)
    )
    return {
        **_plan_json(plan),
        "ai": (plan.data or {}).get("ai", {}),
        "tasks": [
            {
                "id": t.id,
                "title": t.title,
                "actions": list(t.actions),
                "category": t.category.value,
                "priority": t.priority.value,
                "estimate_h": t.estimate_h,
                "assignee_id": t.assignee_id,
                "day": t.not_before.isoformat() if t.not_before else None,
                "due": t.due.isoformat() if t.due else None,
                "status": t.status.value,
                "origin": t.origin.value,
                "rationale": t.rationale,
            }
            for t in tasks
        ],
    }


@router.post("/plans/{plan_id}/validate")
def validate(user: Lead, session: DB, plan_id: int) -> dict[str, Any]:
    plan = session.get(models.Plan, plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan introuvable.")
    apply_validate(session, user, plan)
    return _plan_json(plan)


class TaskPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: TaskStatus | None = None
    reason: str = Field("", max_length=300)
    comment: str | None = Field(None, min_length=1, max_length=2000)


@router.patch("/tasks/{task_id}")
def patch_task(user: Staff, session: DB, task_id: int, patch: TaskPatch) -> dict[str, Any]:
    task = session.get(models.Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Tâche introuvable.")
    if patch.status is None and patch.comment is None:
        raise HTTPException(status_code=422, detail="Rien à modifier.")
    if patch.status is not None:
        apply_status(session, user, task, patch.status, patch.reason)
    if patch.comment is not None:
        if user.person_id is None:
            raise HTTPException(
                status_code=403, detail="Commentaire réservé aux membres de l'équipe."
            )
        session.add(
            models.TaskComment(
                task_id=task.id, author_id=user.person_id, body=patch.comment.strip()
            )
        )
        audit(session, user.email, "task_comment", f"task:{task.id}")
        session.commit()
    return {"id": task.id, "status": task.status.value, "status_reason": task.status_reason}


@router.get("/incidents")
def incidents(
    user: Staff,
    session: DB,
    status: Annotated[IncidentStatus | None, Query()] = IncidentStatus.open,
    priority: Annotated[Priority | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_ROWS)] = 200,
) -> list[dict[str, Any]]:
    query = select(models.Incident)
    if status is not None:
        query = query.where(models.Incident.status == status)
    if priority is not None:
        query = query.where(models.Incident.priority == priority)
    rows = session.scalars(
        query.order_by(models.Incident.priority, models.Incident.score.desc()).limit(limit)
    )
    return [
        {
            "id": i.id,
            "priority": i.priority.value,
            "score": i.score,
            "priority_reason": i.priority_reason,
            "category": i.category.value,
            "company": i.company_code,
            "asset": i.asset,
            "status": i.status.value,
            "created_at": i.created_at.isoformat(),
        }
        for i in rows
    ]


@router.get("/signals")
def signals(
    user: Staff,
    session: DB,
    source: Annotated[str | None, Query(max_length=64)] = None,
    open_only: Annotated[bool, Query(alias="open")] = True,
    limit: Annotated[int, Query(ge=1, le=MAX_ROWS)] = 200,
) -> list[dict[str, Any]]:
    query = select(models.Signal)
    if source:
        query = query.where(models.Signal.source == source)
    if open_only:
        query = query.where(models.Signal.resolved_at.is_(None))
    rows = session.scalars(
        query.order_by(models.Signal.severity.desc(), models.Signal.id).limit(limit)
    )
    return [
        {
            "id": s.id,
            "source": s.source,
            "external_id": s.external_id,
            "severity": s.severity,
            "category": s.category.value,
            "company": s.company_code,
            "asset": s.asset,
            "title": s.title,
            "first_seen": s.first_seen.isoformat(),
            "last_seen": s.last_seen.isoformat(),
            "resolved_at": s.resolved_at.isoformat() if s.resolved_at else None,
        }
        for s in rows
    ]


@router.get("/sources")
def sources(user: Admin, session: DB) -> list[dict[str, Any]]:
    return [
        {
            "name": s.name,
            "enabled": s.enabled,
            "last_ok_at": s.last_ok_at.isoformat() if s.last_ok_at else None,
            "last_error_at": s.last_error_at.isoformat() if s.last_error_at else None,
            "last_error": s.last_error,
        }
        for s in session.scalars(select(models.Source).order_by(models.Source.name))
    ]


@router.post("/sources/{name}/test", status_code=202)
def test_source(request: Request, user: Admin, session: DB, name: str) -> dict[str, Any]:
    if name not in request.app.state.cfg.sources:
        raise HTTPException(status_code=404, detail="Source inconnue.")
    try:
        job = new_job_request(JobKind.source_test.value, {"source": name}, requested_by=user.email)
    except JobPayloadError:
        raise HTTPException(status_code=422, detail="Nom de source invalide.") from None
    session.add(job)
    audit(session, user.email, "source_test_requested", f"source:{name}")
    session.commit()
    return {"job_id": job.id, "status": job.status.value}


@router.get("/costs")
def costs(request: Request, user: Admin, session: DB) -> dict[str, Any]:
    start = month_start(datetime.now(UTC))
    calls = session.scalars(select(models.LLMCall).where(models.LLMCall.at >= start)).all()
    spent = sum((c.cost_usd for c in calls), Decimal(0))
    return {
        "month": start.strftime("%Y-%m"),
        "spent_usd": f"{spent:.4f}",
        "budget_usd": f"{float(request.app.state.cfg.llm.monthly_budget_usd):.2f}",
        "calls": len(calls),
        "input_tokens": sum(c.input_tokens for c in calls),
        "cached_tokens": sum(c.cached_tokens for c in calls),
        "output_tokens": sum(c.output_tokens for c in calls),
    }
