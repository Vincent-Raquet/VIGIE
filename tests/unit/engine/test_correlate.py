from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.collect import ensure_source, store_snapshot
from vigie.connectors.base import Signal
from vigie.db import models
from vigie.db.enums import Category, IncidentStatus
from vigie.engine.correlate import OpenIncident, SignalRef, correlate, correlation_key, group

T0 = datetime(2026, 10, 9, 8, 0, tzinfo=UTC)


def ref(
    i: int, asset: str = "srv-wi-01", minutes: int = 0, company: str | None = "WI"
) -> SignalRef:
    return SignalRef(i, company, asset, f"fp{i}", T0 + timedelta(minutes=minutes))


def test_key_uses_normalized_asset_or_fingerprint() -> None:
    assert correlation_key(ref(1, "SRV-WI-01.corp.example.test")) == ("WI", "srv-wi-01")
    assert correlation_key(ref(2, "")) == ("WI", "fp:fp2")


def test_same_asset_within_window_is_grouped() -> None:
    touched = group([ref(1), ref(2, "SRV-WI-01", 45), ref(3, minutes=61)], [])
    assert [t.signal_ids for t in touched] == [[1, 2], [3]]


def test_window_is_measured_from_the_incident_anchor() -> None:
    touched = group([ref(1), ref(2, minutes=50), ref(3, minutes=100)], [])
    assert [t.signal_ids for t in touched] == [[1, 2], [3]]


def test_company_and_asset_separate_incidents() -> None:
    touched = group([ref(1), ref(2, company="SPL"), ref(3, "srv-wi-02")], [])
    assert len(touched) == 3


def test_signals_without_asset_stay_alone_but_join_their_own_incident() -> None:
    existing = OpenIncident(key=("WI", "fp:fp1"), anchor=T0 - timedelta(days=3), id=7)
    touched = group([ref(1, ""), ref(2, "")], [existing])
    assert existing.signal_ids == [1]
    assert [t.id for t in touched] == [7, None]


def test_existing_incident_is_reused() -> None:
    existing = OpenIncident(key=("WI", "srv-wi-01"), anchor=T0, id=42)
    touched = group([ref(5, minutes=30)], [existing])
    assert touched == [existing] and existing.signal_ids == [5]


# --- En base ----------------------------------------------------------------------


def sig(external_id: str, asset: str, minutes: int = 0, **kw: object) -> Signal:
    base: dict[str, object] = {
        "source": "zabbix",
        "external_id": external_id,
        "company_code": None,
        "asset": asset,
        "category": Category.server,
        "severity": 3,
        "title": f"Problème {external_id}",
        "details": "",
        "first_seen": T0 + timedelta(minutes=minutes),
        "last_seen": T0 + timedelta(minutes=minutes),
    }
    base.update(kw)
    return Signal(**base)  # type: ignore[arg-type]


def incidents(session: Session) -> list[tuple[models.Incident, list[str]]]:
    out = []
    for incident in session.scalars(select(models.Incident).order_by(models.Incident.id)):
        ext = session.scalars(
            select(models.Signal.external_id)
            .join(models.IncidentSignal, models.IncidentSignal.signal_id == models.Signal.id)
            .where(models.IncidentSignal.incident_id == incident.id)
            .order_by(models.Signal.external_id)
        ).all()
        out.append((incident, list(ext)))
    return out


@pytest.mark.db
def test_correlate_in_database(db_session: Session) -> None:
    ensure_source(db_session, "zabbix", kind="zabbix")
    store_snapshot(
        db_session,
        "zabbix",
        [sig("1", "srv-a"), sig("2", "srv-a", 20), sig("3", "srv-b"), sig("4", "")],
        T0,
    )
    first = correlate(db_session, T0)
    assert (first.created, first.resolved) == (3, 0)
    found = incidents(db_session)
    assert [ext for _, ext in found] == [["1", "2"], ["3"], ["4"]]
    assert found[0][0].asset == "srv-a" and found[0][0].status is IncidentStatus.open

    # Second passage : rien de nouveau, idempotent.
    assert correlate(db_session, T0).created == 0

    # Nouveau signal sur srv-a dans la fenêtre → rattaché ; srv-b résolu → incident résolu.
    later = T0 + timedelta(minutes=40)
    store_snapshot(
        db_session,
        "zabbix",
        [sig("1", "srv-a"), sig("2", "srv-a", 20), sig("5", "srv-a", 40), sig("4", "")],
        later,
    )
    report = correlate(db_session, later)
    assert (report.created, report.attached, report.resolved) == (0, 1, 1)
    found = incidents(db_session)
    assert found[0][1] == ["1", "2", "5"]
    assert found[1][0].status is IncidentStatus.resolved
