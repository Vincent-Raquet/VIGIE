"""Enregistrement des collectes en base (worker) : signaux, résolution, santé des sources.

Une collecte est un **instantané** des alertes ouvertes : un signal absent de l'instantané
est résolu, sauf si la collecte est tronquée (l'absence ne prouve alors rien). La panne
d'une source est elle-même un signal (SPEC F5), porté par la source interne « vigie ».
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.connectors.base import Signal
from vigie.db import models
from vigie.db.enums import Category
from vigie.engine.normalize import fingerprint, raw_hash
from vigie.redact import clean_untrusted

VIGIE_SOURCE = "vigie"
SOURCE_DOWN_SEVERITY = 4


@dataclass
class SnapshotReport:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    reopened: int = 0
    resolved: int = 0


def ensure_source(
    session: Session,
    name: str,
    *,
    kind: str,
    enabled: bool = True,
    interval_min: int = 15,
    base_url: str = "",
) -> models.Source:
    """Ligne `source` alignée sur la configuration (créée au premier passage)."""
    row = session.get(models.Source, name)
    if row is None:
        row = models.Source(name=name, kind=kind)
        session.add(row)
    row.enabled = enabled
    row.interval_min = interval_min
    row.base_url = base_url
    session.flush()
    return row


def _apply(row: models.Signal, signal: Signal) -> None:
    row.company_code = signal.company_code
    row.asset = signal.asset
    row.category = signal.category
    row.severity = signal.severity
    row.title = signal.title
    row.details = signal.details
    row.url_template_params = dict(signal.url_template_params)
    row.attributes = dict(signal.attributes)
    row.fingerprint = fingerprint(signal)
    row.raw_hash = raw_hash(signal)


def _upsert(
    session: Session,
    existing: dict[str, models.Signal],
    signal: Signal,
    report: SnapshotReport,
) -> None:
    row = existing.get(signal.external_id)
    if row is None:
        row = models.Signal(
            source=signal.source,
            external_id=signal.external_id,
            first_seen=signal.first_seen,
            last_seen=signal.last_seen,
            occurrences=1,
        )
        _apply(row, signal)
        session.add(row)
        existing[signal.external_id] = row
        report.created += 1
        return
    row.last_seen = max(row.last_seen, signal.last_seen)
    if row.resolved_at is not None:
        row.resolved_at = None
        row.first_seen = signal.first_seen  # nouvel épisode : l'âge repart de zéro
        row.occurrences += 1
        report.reopened += 1
    if row.raw_hash != raw_hash(signal):
        _apply(row, signal)
        report.updated += 1
    else:
        report.unchanged += 1


def _existing(session: Session, source: str) -> dict[str, models.Signal]:
    rows = session.scalars(select(models.Signal).where(models.Signal.source == source))
    return {row.external_id: row for row in rows}


def store_snapshot(
    session: Session,
    source: str,
    signals: Iterable[Signal],
    now: datetime,
    *,
    complete: bool = True,
) -> SnapshotReport:
    """Enregistre l'instantané d'une source ; résout les signaux disparus si `complete`."""
    report = SnapshotReport()
    existing = _existing(session, source)
    seen: set[str] = set()
    for signal in signals:
        if signal.source != source:
            raise ValueError(f"signal de {signal.source} dans l'instantané de {source}")
        _upsert(session, existing, signal, report)
        seen.add(signal.external_id)
    if complete:
        for external_id, row in existing.items():
            if external_id not in seen and row.resolved_at is None:
                row.resolved_at = now
                report.resolved += 1
    session.flush()
    return report


def _source_down_id(name: str) -> str:
    return f"source_down:{name}"


def record_success(session: Session, name: str, now: datetime) -> None:
    source = session.get(models.Source, name)
    if source is None:
        raise LookupError(f"source {name} inconnue")
    source.last_ok_at = now
    source.last_error = None
    down = _existing(session, VIGIE_SOURCE).get(_source_down_id(name))
    if down is not None and down.resolved_at is None:
        down.resolved_at = now
    session.flush()


def record_failure(session: Session, name: str, error: str, now: datetime) -> None:
    """Note l'échec et ouvre (ou prolonge) le signal « source injoignable »."""
    source = session.get(models.Source, name)
    if source is None:
        raise LookupError(f"source {name} inconnue")
    message = clean_untrusted(error, 1000)
    source.last_error = message
    source.last_error_at = now
    ensure_source(session, VIGIE_SOURCE, kind="internal")
    existing = _existing(session, VIGIE_SOURCE)
    previous = existing.get(_source_down_id(name))
    since = previous.first_seen if previous and previous.resolved_at is None else now
    last_ok = (
        f"{source.last_ok_at.astimezone(UTC):%Y-%m-%d %H:%M} UTC" if source.last_ok_at else "jamais"
    )
    signal = Signal(
        source=VIGIE_SOURCE,
        external_id=_source_down_id(name),
        company_code=None,
        asset=name,
        category=Category.monitoring,
        severity=SOURCE_DOWN_SEVERITY,
        title=f"Source {name} injoignable",
        details=clean_untrusted(f"{message}\nDernière collecte réussie : {last_ok}", 1000),
        first_seen=since,
        last_seen=now,
        attributes={"kind": "source_down", "source": name},
    )
    _upsert(session, existing, signal, SnapshotReport())
    session.flush()
