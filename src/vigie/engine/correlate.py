"""Corrélation des signaux en incidents (SPEC §7.3).

Un signal ouvert rejoint l'incident ouvert portant sur le **même actif** (nom normalisé) de
la **même société** si le premier signal de cet incident date de 60 min au plus ; sinon il
ouvre un nouvel incident. Un signal sans actif forme un incident à lui seul (clé :
empreinte). Un incident est résolu quand tous ses signaux le sont.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.db import models
from vigie.db.enums import IncidentStatus, Priority
from vigie.engine.normalize import normalize_asset

WINDOW = timedelta(minutes=60)


@dataclass(frozen=True)
class SignalRef:
    id: int
    company_code: str | None
    asset: str
    fingerprint: str
    first_seen: datetime


@dataclass
class OpenIncident:
    key: tuple[str | None, str]
    anchor: datetime  # premier signal de l'incident
    id: int | None = None  # None : à créer
    signal_ids: list[int] = field(default_factory=list)


def correlation_key(signal: SignalRef) -> tuple[str | None, str]:
    asset = normalize_asset(signal.asset)
    if not asset:
        return (signal.company_code, f"fp:{signal.fingerprint}")
    return (signal.company_code, asset)


def group(signals: Sequence[SignalRef], incidents: Sequence[OpenIncident]) -> list[OpenIncident]:
    """Rattache chaque signal (du plus ancien au plus récent) ; renvoie les incidents touchés.

    Fonction pure : `incidents` décrit les incidents ouverts existants (avec leur ancre).
    """
    by_key: dict[tuple[str | None, str], list[OpenIncident]] = {}
    for incident in incidents:
        by_key.setdefault(incident.key, []).append(incident)
    touched: list[OpenIncident] = []
    for signal in sorted(signals, key=lambda s: (s.first_seen, s.id)):
        key = correlation_key(signal)
        candidates = [
            i
            for i in by_key.get(key, [])
            if key[1].startswith("fp:") or abs(signal.first_seen - i.anchor) <= WINDOW
        ]
        if candidates:
            target = min(candidates, key=lambda i: abs(signal.first_seen - i.anchor))
        else:
            target = OpenIncident(key=key, anchor=signal.first_seen)
            by_key.setdefault(key, []).append(target)
        target.signal_ids.append(signal.id)
        if target not in touched:
            touched.append(target)
    return touched


def group_fingerprint(key: tuple[str | None, str], anchor: datetime) -> str:
    raw = f"{key[0] or ''}|{key[1]}|{anchor.isoformat()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _ref(signal: models.Signal) -> SignalRef:
    return SignalRef(
        signal.id, signal.company_code, signal.asset, signal.fingerprint, signal.first_seen
    )


def _incident_key(
    incident: models.Incident, members: Sequence[models.Signal]
) -> tuple[str | None, str]:
    if members:
        return correlation_key(_ref(min(members, key=lambda s: (s.first_seen, s.id))))
    asset = normalize_asset(incident.asset)
    return (incident.company_code, asset or f"fp:{incident.fingerprint_group}")


@dataclass
class CorrelationReport:
    created: int = 0
    attached: int = 0
    resolved: int = 0


def correlate(session: Session, now: datetime) -> CorrelationReport:
    """Applique la corrélation en base : rattachements, nouveaux incidents, résolutions."""
    report = CorrelationReport()
    open_incidents = session.scalars(
        select(models.Incident).where(models.Incident.status == IncidentStatus.open)
    ).all()
    links = session.execute(
        select(models.IncidentSignal.incident_id, models.Signal).join(
            models.Signal, models.Signal.id == models.IncidentSignal.signal_id
        )
    ).all()
    signals_of: dict[int, list[models.Signal]] = {}
    for incident_id, signal in links:
        signals_of.setdefault(incident_id, []).append(signal)

    # 1. Résolution : tous les signaux de l'incident sont résolus.
    still_open: list[models.Incident] = []
    for incident in open_incidents:
        members = signals_of.get(incident.id, [])
        if members and all(s.resolved_at is not None for s in members):
            incident.status = IncidentStatus.resolved
            incident.updated_at = now
            report.resolved += 1
        else:
            still_open.append(incident)

    # 2. Signaux ouverts sans incident ouvert.
    linked_open = {s.id for i in still_open for s in signals_of.get(i.id, [])}
    orphans = session.scalars(
        select(models.Signal).where(models.Signal.resolved_at.is_(None))
    ).all()
    refs = [_ref(s) for s in orphans if s.id not in linked_open]
    existing = [
        OpenIncident(
            key=_incident_key(i, signals_of.get(i.id, [])),
            anchor=min((s.first_seen for s in signals_of.get(i.id, [])), default=i.created_at),
            id=i.id,
        )
        for i in still_open
    ]
    by_signal = {s.id: s for s in orphans}
    for target in group(refs, existing):
        if target.id is None:
            first = by_signal[target.signal_ids[0]]
            incident = models.Incident(
                fingerprint_group=group_fingerprint(target.key, target.anchor),
                category=first.category,
                company_code=first.company_code,
                asset=first.asset,
                score=0,
                priority=Priority.P4,
                status=IncidentStatus.open,
                created_at=now,
                updated_at=now,
            )
            session.add(incident)
            session.flush()
            target.id = incident.id
            report.created += 1
        else:
            report.attached += len(target.signal_ids)
        for signal_id in target.signal_ids:
            session.add(models.IncidentSignal(incident_id=target.id, signal_id=signal_id))
    session.flush()
    return report
