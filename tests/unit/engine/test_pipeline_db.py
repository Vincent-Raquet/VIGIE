"""Collecte des fixtures Zabbix → incidents corrélés et scorés, sur base seedée."""

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.conftest import REPO_ROOT
from vigie.collect import ensure_source, store_snapshot
from vigie.connectors.base import ConnectorContext, fixture_transport
from vigie.connectors.zabbix import ZabbixConnector
from vigie.db import models
from vigie.db.enums import IncidentStatus, Priority
from vigie.engine.correlate import correlate
from vigie.engine.scoring import score_incidents
from vigie.mapping import RuleMapper
from vigie.seed import apply_seed, load_seed_data

pytestmark = pytest.mark.db

NOW = datetime.fromtimestamp(1791563400, UTC)  # 2026-10-09 16:30 UTC
FIXTURES = REPO_ROOT / "tests" / "contract" / "zabbix"


def load_zabbix(session: Session, fixtures: Path = FIXTURES) -> None:
    apply_seed(session, load_seed_data(REPO_ROOT / "config", REPO_ROOT / "roles"))
    ensure_source(session, "zabbix", kind="zabbix")
    connector = ZabbixConnector.from_context(
        ConnectorContext(
            settings={"base_url": "https://zabbix.test"},
            secret=lambda _n: SecretStr("x"),
            transport=fixture_transport(fixtures),
        )
    )
    connector._now = lambda: NOW
    mapper = RuleMapper.from_session(session)
    signals = [connector.to_signal(r, mapper) for r in connector.collect(NOW)]
    store_snapshot(session, "zabbix", signals, NOW)


def test_fixtures_become_scored_incidents(db_session: Session) -> None:
    load_zabbix(db_session)
    report = correlate(db_session, NOW)
    assert score_incidents(db_session, NOW) == report.created
    incidents = db_session.scalars(select(models.Incident)).all()
    assert all(i.status is IncidentStatus.open and i.priority_reason for i in incidents)
    by_priority = Counter(i.priority for i in incidents)
    assert by_priority[Priority.P4] > 0 and by_priority[Priority.P2] > 0
    # Les 3 problèmes Proxmox du même hôte, ouverts en moins d'une heure, forment un incident.
    fwd = [i for i in incidents if i.asset == "FWD-PVE-CLOUD"]
    assert len(fwd) == 1
    # Agrégat Veeam : catégorie backup, bonus de l'axe « Sauvegardes fiables et testées ».
    backup = next(i for i in incidents if i.asset == "WI-backup-01")
    assert "politique +10 (Sauvegardes fiables et testées)" in backup.priority_reason
    # Proxy sans contact : au moins P2 (par le score ou l'override proxy_down).
    proxies = [i for i in incidents if i.asset.startswith("proxy-")]
    assert {i.priority for i in proxies} == {Priority.P2}
