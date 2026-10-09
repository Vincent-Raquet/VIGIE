"""Enregistrement des collectes : upsert, résolution, réouverture, panne de source."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.collect import (
    VIGIE_SOURCE,
    ensure_source,
    record_failure,
    record_success,
    store_snapshot,
)
from vigie.connectors.base import Signal
from vigie.db import models
from vigie.db.enums import Category

pytestmark = pytest.mark.db

T0 = datetime(2026, 10, 9, 8, 0, tzinfo=UTC)


def sig(external_id: str, title: str = "Disk full", at: datetime = T0, **kw: object) -> Signal:
    base: dict[str, object] = {
        "source": "zabbix",
        "external_id": external_id,
        "company_code": None,
        "asset": "srv-wi-01",
        "category": Category.server,
        "severity": 3,
        "title": title,
        "details": "",
        "first_seen": at - timedelta(hours=1),
        "last_seen": at,
    }
    base.update(kw)
    return Signal(**base)  # type: ignore[arg-type]


@pytest.fixture
def session(db_session: Session) -> Session:
    ensure_source(db_session, "zabbix", kind="zabbix", base_url="https://zabbix.test")
    return db_session


def rows(session: Session, source: str = "zabbix") -> dict[str, models.Signal]:
    found = session.scalars(select(models.Signal).where(models.Signal.source == source))
    return {r.external_id: r for r in found}


def test_ensure_source_is_idempotent(session: Session) -> None:
    ensure_source(session, "zabbix", kind="zabbix", interval_min=5)
    assert session.get(models.Source, "zabbix").interval_min == 5  # type: ignore[union-attr]


def test_snapshot_creates_updates_and_resolves(session: Session) -> None:
    first = store_snapshot(session, "zabbix", [sig("1"), sig("2", "CPU high")], T0)
    assert (first.created, first.resolved) == (2, 0)
    stored = rows(session)
    assert stored["1"].fingerprint and stored["1"].raw_hash
    assert stored["1"].attributes == {}

    later = T0 + timedelta(minutes=15)
    second = store_snapshot(
        session, "zabbix", [sig("1", at=later, details="pire", severity=4)], later
    )
    assert (second.created, second.updated, second.resolved) == (0, 1, 1)
    stored = rows(session)
    assert stored["1"].severity == 4
    assert stored["1"].last_seen == later
    assert stored["2"].resolved_at == later

    third = store_snapshot(
        session, "zabbix", [sig("1", at=later, details="pire", severity=4)], later
    )
    assert third.unchanged == 1


def test_incomplete_snapshot_resolves_nothing(session: Session) -> None:
    store_snapshot(session, "zabbix", [sig("1"), sig("2")], T0)
    report = store_snapshot(session, "zabbix", [sig("1")], T0, complete=False)
    assert report.resolved == 0
    assert rows(session)["2"].resolved_at is None


def test_reappearing_signal_is_reopened(session: Session) -> None:
    store_snapshot(session, "zabbix", [sig("1")], T0)
    store_snapshot(session, "zabbix", [], T0 + timedelta(minutes=15))
    back = T0 + timedelta(hours=2)
    report = store_snapshot(session, "zabbix", [sig("1", at=back)], back)
    row = rows(session)["1"]
    assert report.reopened == 1
    assert (row.resolved_at, row.occurrences) == (None, 2)
    assert row.first_seen == back - timedelta(hours=1)


def test_snapshot_rejects_foreign_signals(session: Session) -> None:
    with pytest.raises(ValueError, match="instantané"):
        store_snapshot(session, "zabbix", [sig("1", source="veeam")], T0)


def test_source_failure_opens_then_success_resolves(session: Session) -> None:
    record_success(session, "zabbix", T0)
    fail_at = T0 + timedelta(minutes=30)
    record_failure(session, "zabbix", "zabbix : HTTP 503 (rpc problem.get)", fail_at)
    record_failure(
        session, "zabbix", "zabbix : HTTP 503 (rpc problem.get)", fail_at + timedelta(minutes=15)
    )
    source = session.get(models.Source, "zabbix")
    assert source is not None and source.last_error and "HTTP 503" in source.last_error
    down = rows(session, VIGIE_SOURCE)["source_down:zabbix"]
    assert (down.category, down.severity, down.resolved_at) == (Category.monitoring, 4, None)
    assert down.first_seen == fail_at  # prolongé, pas recréé
    assert down.attributes == {"kind": "source_down", "source": "zabbix"}
    assert "Dernière collecte réussie : 2026-10-09 08:00 UTC" in down.details

    ok_at = fail_at + timedelta(hours=1)
    record_success(session, "zabbix", ok_at)
    assert rows(session, VIGIE_SOURCE)["source_down:zabbix"].resolved_at == ok_at
    assert source.last_error is None and source.last_ok_at == ok_at


def test_unknown_source(session: Session) -> None:
    with pytest.raises(LookupError):
        record_success(session, "nope", T0)
    with pytest.raises(LookupError):
        record_failure(session, "nope", "x", T0)
