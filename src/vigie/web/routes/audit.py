"""Audit & coûts (SPEC F11) : journal paginé et consommation LLM du mois."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy import func, select

from vigie.db import models
from vigie.web.auth import User, require_role
from vigie.web.deps import ADMIN, DB, render

router = APIRouter()
Admin = Annotated[User, Depends(require_role(*ADMIN))]
PAGE_SIZE = 50


def month_start(now: datetime) -> datetime:
    return now.astimezone(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)


@router.get("/audit")
def audit_page(
    request: Request,
    user: Admin,
    session: DB,
    page: Annotated[int, Query(ge=1, le=10_000)] = 1,
    action: Annotated[str | None, Query(max_length=100)] = None,
) -> Response:
    query = select(models.AuditLog)
    if action:
        query = query.where(models.AuditLog.action == action)
    entries = session.scalars(
        query.order_by(models.AuditLog.at.desc(), models.AuditLog.id.desc())
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE + 1)
    ).all()
    start = month_start(datetime.now(UTC))
    calls = session.scalars(
        select(models.LLMCall).where(models.LLMCall.at >= start).order_by(models.LLMCall.at.desc())
    ).all()
    spent = sum((c.cost_usd for c in calls), Decimal(0))
    budget = Decimal(str(request.app.state.cfg.llm.monthly_budget_usd))
    actions = session.scalars(
        select(models.AuditLog.action).distinct().order_by(models.AuditLog.action)
    ).all()
    total_in = sum(c.input_tokens + c.cached_tokens for c in calls)
    return render(
        request,
        "audit.html",
        {
            "entries": entries[:PAGE_SIZE],
            "has_next": len(entries) > PAGE_SIZE,
            "page": page,
            "action": action,
            "actions": actions,
            "calls": calls[:20],
            "calls_count": len(calls),
            "spent": spent,
            "budget": budget,
            "cache_share": (sum(c.cached_tokens for c in calls) * 100 // total_in)
            if total_in
            else None,
            "month": start,
            "total_signals": session.scalar(select(func.count()).select_from(models.Signal)),
        },
    )
