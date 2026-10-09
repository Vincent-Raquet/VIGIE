"""Purge selon la rétention (SPEC §5.2), exécutée chaque nuit par le worker.

Signaux résolus et incidents résolus : 90 jours. Plans et tâches : 2 ans. `llm_call` et
`audit_log` : 1 an (le trigger d'`audit_log` refuse toute suppression plus récente).
Demandes du web traitées : 30 jours.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, Delete, delete, update
from sqlalchemy.orm import Session

from vigie.db import models
from vigie.db.enums import IncidentStatus, JobStatus

RETENTION_DAYS = {
    "signal": 90,
    "incident": 90,
    "plan": 730,
    "llm_call": 365,
    "audit_log": 366,  # marge d'un jour sur la limite du trigger (365 j)
    "job_request": 30,
}


def purge(session: Session, now: datetime) -> dict[str, int]:
    def before(kind: str) -> datetime:
        return now - timedelta(days=RETENTION_DAYS[kind])

    counts: dict[str, int] = {}

    def run(kind: str, statement: Delete) -> None:
        result = cast(CursorResult[Any], session.execute(statement))
        counts[kind] = result.rowcount or 0

    run(
        "incident",
        delete(models.Incident).where(
            models.Incident.status == IncidentStatus.resolved,
            models.Incident.updated_at < before("incident"),
        ),
    )
    run(
        "signal",
        delete(models.Signal).where(
            models.Signal.resolved_at.is_not(None), models.Signal.resolved_at < before("signal")
        ),
    )
    run("plan", delete(models.Plan).where(models.Plan.period_end < before("plan").date()))
    # Les plans conservés (2 ans) ne doivent plus pointer vers un appel IA purgé (1 an).
    old_calls = models.LLMCall.at < before("llm_call")
    session.execute(
        update(models.Plan)
        .where(
            models.Plan.llm_call_id.in_(
                models.LLMCall.__table__.select()
                .with_only_columns(models.LLMCall.id)
                .where(old_calls)
            )
        )
        .values(llm_call_id=None)
    )
    run("llm_call", delete(models.LLMCall).where(old_calls))
    run("audit_log", delete(models.AuditLog).where(models.AuditLog.at < before("audit_log")))
    run(
        "job_request",
        delete(models.JobRequest).where(
            models.JobRequest.status.in_([JobStatus.done, JobStatus.failed]),
            models.JobRequest.requested_at < before("job_request"),
        ),
    )
    session.flush()
    return counts
