"""Exécution par le worker des demandes faites depuis le web (`job_request`, point B).

Le web n'a ni secret ni accès aux sources : il dépose une demande validée ; le worker,
qui détient les secrets, l'exécute ici et écrit un résultat **sans secret** (état,
version, latence, message d'erreur déjà neutre).
"""

from __future__ import annotations

from collections.abc import Callable, Collection
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.connectors.base import ConnectorConfigError, SourceCallError
from vigie.db import models
from vigie.db.enums import JobKind, JobStatus
from vigie.db.jobs import JobPayloadError, PlanGeneratePayload, validate_payload

MAX_JOBS_PER_RUN = 20


PlanGenerator = Callable[[PlanGeneratePayload], dict[str, Any]]


def run_pending(
    session: Session,
    build_connector: Callable[[str], Any],
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    *,
    kinds: Collection[JobKind] = (JobKind.source_test,),
    generate_plan: PlanGenerator | None = None,
) -> list[models.JobRequest]:
    """Exécute les demandes en attente des types `kinds` (les plus anciennes d'abord).

    Chaque unité systemd ne traite que ses types : `vigie-jobs` (secrets des sources) les
    tests de connexion, `vigie-plan-requests` (clé IA) les générations de plan.
    """
    done: list[models.JobRequest] = []
    for _ in range(MAX_JOBS_PER_RUN):
        job = session.scalars(
            select(models.JobRequest)
            .where(models.JobRequest.status == JobStatus.pending, models.JobRequest.kind.in_(kinds))
            .order_by(models.JobRequest.requested_at, models.JobRequest.id)
            .limit(1)
            .with_for_update(skip_locked=True)
        ).first()
        if job is None:
            break
        # « en cours » visible du web pendant l'exécution (une génération dure des minutes).
        job.status = JobStatus.running
        session.commit()
        try:
            payload = validate_payload(job.kind.value, job.payload)  # revalidé côté worker
            if job.kind is JobKind.source_test:
                job.result = _source_test(payload["source"], build_connector)
            elif job.kind is JobKind.plan_generate and generate_plan is not None:
                job.result = generate_plan(PlanGeneratePayload.model_validate(payload))
            else:
                job.result = {"ok": False, "detail": "type de demande non géré ici"}
            job.status = JobStatus.done if job.result and job.result.get("ok") else JobStatus.failed
        except JobPayloadError:
            job.result = {"ok": False, "detail": "demande invalide"}
            job.status = JobStatus.failed
        job.done_at = now()
        session.commit()
        done.append(job)
    return done


def _source_test(source: str, build_connector: Callable[[str], Any]) -> dict[str, Any]:
    try:
        connector = build_connector(source)
        health = connector.healthcheck()
    except (ConnectorConfigError, SourceCallError, LookupError) as exc:
        return {"ok": False, "detail": str(exc)[:300]}
    except Exception as exc:  # secret absent, CA illisible… : type seulement, pas de contenu
        return {"ok": False, "detail": f"échec ({type(exc).__name__})"}
    return {
        "ok": bool(health.ok),
        "detail": str(health.detail)[:300],
        "version": health.version,
        "latency_ms": health.latency_ms,
    }
