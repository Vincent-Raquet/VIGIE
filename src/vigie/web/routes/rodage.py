"""Rodage (phase 9) : suivi du critère d'acceptation et motifs de rejet des tâches."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from vigie import rodage
from vigie.web.auth import User, require_role
from vigie.web.deps import DB, LEADS, render

router = APIRouter()
Lead = Annotated[User, Depends(require_role(*LEADS))]


@router.get("/rodage")
def rodage_page(request: Request, user: Lead, session: DB) -> Response:
    now = datetime.now(UTC)
    days = rodage.day_stats(session)
    items = rodage.rejections(session, [d.plan_id for d in days])
    spent = rodage.month_spent(session, now)
    llm_days = [d for d in days if d.cost_usd > 0]
    return render(
        request,
        "rodage.html",
        {
            "days": days,
            "streak": rodage.streak(days),
            "target": rodage.STREAK_TARGET,
            "rate_threshold": rodage.RATE_THRESHOLD,
            "coverage_threshold": rodage.COVERAGE_THRESHOLD,
            "rejections": items,
            "counts": rodage.rejection_counts(items),
            "spent": spent,
            "projection": rodage.cost_projection(spent, now),
            "avg_cost": (
                sum((d.cost_usd for d in llm_days), Decimal(0)) / len(llm_days)
                if llm_days
                else None
            ),
            "budget": Decimal(str(request.app.state.cfg.llm.monthly_budget_usd)),
        },
    )
