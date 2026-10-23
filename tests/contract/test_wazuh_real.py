"""Wazuh : capture réelle anonymisée (4.14.4, OVA tout-en-un, 2026-10-23) → signaux."""

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr

from tests.conftest import REPO_ROOT
from vigie.connectors.base import ConnectorContext, Signal, fixture_transport
from vigie.connectors.wazuh import WazuhConnector
from vigie.mapping import RuleMapper

FIXTURES = Path(__file__).parent / "wazuh"
NOW = datetime(2026, 10, 23, 14, 10, tzinfo=UTC)  # capture : 2026-10-23 vers 16:08 (UTC+2)
SETTINGS = {"api_url": "https://wazuh.test:55000", "indexer_url": "https://wazuh.test:9200"}


@pytest.fixture(scope="module")
def connector_and_signals(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[WazuhConnector, list[Signal]]:
    d = tmp_path_factory.mktemp("seed")
    shutil.copy(REPO_ROOT / "config" / "companies.example.yaml", d)
    mapper = RuleMapper.from_seed_dir(d)
    ctx = ConnectorContext(
        settings=SETTINGS,
        secret=lambda name: SecretStr("fixture-password"),
        transport=fixture_transport(FIXTURES),
    )
    c = WazuhConnector.from_context(ctx)
    c._now = lambda: NOW
    return c, [c.to_signal(r, mapper) for r in c.collect(NOW)]


def test_real_alerts_by_rule_and_agent(
    connector_and_signals: tuple[WazuhConnector, list[Signal]],
) -> None:
    c, sigs = connector_and_signals
    assert not c.truncated
    # Règle 204 « Agent event queue is flooded » (niveau 12, installation des agents) :
    # écartée par défaut (ignore_rules), sinon elle passerait en P1 (wazuh_level12).
    assert sorted(
        (s.severity, s.attributes["rule_level"], s.asset, s.title) for s in sigs
    ) == sorted(
        (4, 10, a, f"Wazuh — {desc} ({a})")
        for desc, agents in (
            ("Multiple Windows Logon Failures", ("srv-spl-01", "srv-spl-02", "srv-fs-01")),
            ("Multiple Windows audit failure events", ("srv-spl-01", "srv-spl-02")),
            ("Multiple Windows error application events.", ("srv-spl-01", "srv-spl-02")),
            ("Multiple System error events", ("srv-spl-01", "srv-spl-02")),
        )
        for a in agents
    )
    counts = {(s.title, s.attributes["count"]) for s in sigs}
    assert ("Wazuh — Multiple Windows audit failure events (srv-spl-01)", 621) in counts


def test_agents_all_active_and_no_linux_vulnerability(
    connector_and_signals: tuple[WazuhConnector, list[Signal]],
) -> None:
    _, sigs = connector_and_signals
    # 4 agents actifs (manager Amazon Linux et 3 serveurs Windows) : aucun signal d'agent ;
    # vulnérabilités demandées pour le seul agent Linux (le manager) : aucune.
    assert {s.attributes["kind"] for s in sigs} == {"alert"}
    # Agents dans le seul groupe « default » : aucune société (à ranger dans Wazuh).
    assert {s.company_code for s in sigs} == {None}
