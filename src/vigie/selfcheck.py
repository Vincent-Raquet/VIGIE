"""État de santé de Vigie pour la supervision (SPEC §8) : un fichier par indicateur, lu par
zabbix-agent2 (`vfs.file.contents[/var/lib/vigie/selfcheck/<clé>]`), plus `selfcheck.json`.

Contenu non sensible (âges, compteurs, pourcentages) ; écriture atomique.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime
from decimal import Decimal
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vigie.certs import source_certificates
from vigie.config import VigieConfig
from vigie.db import models
from vigie.db.enums import IncidentStatus, PlanKind, Priority
from vigie.pause import pause_state

_KEY_RE = re.compile(r"^[a-z0-9_.]{1,64}$")


def _hours(now: datetime, then: datetime | None) -> float:
    return -1.0 if then is None else round((now - then).total_seconds() / 3600, 2)


def collect_metrics(session: Session, cfg: VigieConfig, now: datetime) -> dict[str, float | int]:
    metrics: dict[str, float | int] = {}
    for kind in PlanKind:
        last = session.scalar(
            select(func.max(models.Plan.created_at)).where(models.Plan.kind == kind)
        )
        metrics[f"last_{kind.value}_plan_age_h"] = _hours(now, last)
    down = 0
    for name in cfg.enabled_sources():
        source = session.get(models.Source, name)
        last_ok = source.last_ok_at if source else None
        metrics[f"source.{name}.last_ok_age_min"] = (
            -1 if last_ok is None else round((now - last_ok).total_seconds() / 60, 1)
        )
        failing = source is None or (
            source.last_error_at is not None
            and (source.last_ok_at is None or source.last_error_at > source.last_ok_at)
        )
        down += int(failing)
    metrics["sources_down"] = down
    # Certificats d'authentification (Defender) : -1 = illisible ; alerte Zabbix < 30 j.
    for name, days in source_certificates(cfg, now).items():
        metrics[f"cert.{name}.days_left"] = -1 if days is None else days
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    spent = session.scalar(
        select(func.coalesce(func.sum(models.LLMCall.cost_usd), 0)).where(
            models.LLMCall.at >= start
        )
    )
    budget = Decimal(str(cfg.llm.monthly_budget_usd))
    metrics["llm_budget_pct"] = (
        float(round(Decimal(spent or 0) * 100 / budget, 1)) if budget else 0.0
    )
    metrics["open_p1"] = int(
        session.scalar(
            select(func.count())
            .select_from(models.Incident)
            .where(
                models.Incident.status == IncidentStatus.open,
                models.Incident.priority == Priority.P1,
            )
        )
        or 0
    )
    pause = pause_state(session)
    metrics["paused"] = int(cfg.general.paused or pause["collect"] or pause["plan"])
    return metrics


def _atomic_write(path: Path, content: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    Path(tmp).chmod(0o644)
    Path(tmp).replace(path)


def write_metrics(out_dir: Path, metrics: dict[str, float | int]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for key, value in metrics.items():
        if not _KEY_RE.match(key):
            raise ValueError(f"clé d'indicateur invalide : {key!r}")
        _atomic_write(out_dir / key, f"{value}\n")
    _atomic_write(out_dir / "selfcheck.json", json.dumps(metrics, sort_keys=True) + "\n")
