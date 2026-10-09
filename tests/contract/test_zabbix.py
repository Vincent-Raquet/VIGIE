"""Zabbix : fixtures réelles anonymisées → signaux attendus (aucun appel réseau)."""

import json
import logging
import shutil
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from tests.conftest import REPO_ROOT
from vigie.connectors.base import (
    MAX_OBJECTS,
    ConnectorConfigError,
    ConnectorContext,
    Signal,
    SourceCallError,
    fixture_transport,
)
from vigie.connectors.zabbix import ZabbixConnector
from vigie.db.enums import Category
from vigie.mapping import RuleMapper

FIXTURES = Path(__file__).parent / "zabbix"
NOW = datetime.fromtimestamp(1791563400, UTC)
STALE_TRIGGERS = {"99954", "99957", "99964", "99968", "99970", "100005", "100021"}


@pytest.fixture(scope="module")
def mapper(tmp_path_factory: pytest.TempPathFactory) -> RuleMapper:
    d = tmp_path_factory.mktemp("seed")
    shutil.copy(REPO_ROOT / "config" / "companies.example.yaml", d)
    return RuleMapper.from_seed_dir(d)


def make(transport: httpx.BaseTransport | None = None, **settings: Any) -> ZabbixConnector:
    ctx = ConnectorContext(
        settings={"base_url": "https://zabbix.test", **settings},
        secret=lambda name: SecretStr("fixture-token"),
        transport=transport or fixture_transport(FIXTURES),
    )
    connector = ZabbixConnector.from_context(ctx)
    connector._now = lambda: NOW
    return connector


def signals(mapper: RuleMapper, connector: ZabbixConnector | None = None) -> dict[str, Signal]:
    c = connector or make()
    return {s.external_id: s for s in (c.to_signal(r, mapper) for r in c.collect(NOW))}


def by_asset(sigs: dict[str, Signal], asset: str) -> list[Signal]:
    return [s for s in sigs.values() if s.asset == asset]


def test_volume_and_stale_problems(mapper: RuleMapper) -> None:
    problems = json.loads((FIXTURES / "problem.get.json").read_text())
    stale = {p["eventid"] for p in problems if p["objectid"] in STALE_TRIGGERS}
    sigs = signals(mapper)
    assert len(problems) == 74
    assert len(sigs) == 46  # 74 - 7 périmés - 24 agrégés + 1 agrégat + 2 proxys
    assert not stale & sigs.keys()


def test_noisy_host_is_aggregated(mapper: RuleMapper) -> None:
    agg = signals(mapper)["host:10959:agg"]
    assert agg.title == "24 problèmes ouverts sur WI-backup-01"
    assert (agg.severity, agg.category, agg.company_code) == (3, Category.backup, "WI")
    assert "- [3] Veeam Backup: Failed session [Host Discovery] (11 fois)" in agg.details
    assert agg.first_seen == datetime.fromtimestamp(1791416179, UTC)
    assert agg.url_template_params == {"hostid": "10959"}
    assert [s.external_id for s in by_asset(signals(mapper), "WI-backup-01")] == [agg.external_id]


def test_aggregation_threshold_is_configurable(mapper: RuleMapper) -> None:
    sigs = signals(mapper, make(aggregate_threshold=30))
    assert len(sigs) == 46 - 1 + 24
    assert "host:10959:agg" not in sigs


def test_severities_and_categories(mapper: RuleMapper) -> None:
    sigs = signals(mapper)
    assert Counter(s.severity for s in sigs.values()) == {2: 24, 3: 15, 4: 7}
    assert Counter(s.category for s in sigs.values()) == {
        Category.server: 30,
        Category.network: 9,
        Category.endpoint: 3,
        Category.monitoring: 3,
        Category.backup: 1,
    }
    vpn = next(s for s in sigs.values() if "IPsec" in s.title)
    assert (vpn.category, vpn.company_code) == (Category.network, "WI")  # tag scope=vpn
    switch = by_asset(sigs, "sw-wi-backup-01")[0]
    assert switch.category is Category.network  # groupes SRV-Veeam + Switchs/WI
    assert by_asset(sigs, "WI-Printer 5")[0].category is Category.endpoint


def test_companies(mapper: RuleMapper) -> None:
    sigs = signals(mapper)
    assert Counter(s.company_code for s in sigs.values()) == {
        "WG": 16,
        "WI": 14,
        "SPL": 12,
        "CC": 1,
        None: 3,
    }
    assert by_asset(sigs, "sw-wg-ot-01")[0].company_code == "WG"  # Switchs/WG-OT
    assert by_asset(sigs, "CC-ap 3")[0].company_code == "CC"
    zabbix = by_asset(sigs, "Zabbix server")[0]
    assert (zabbix.company_code, zabbix.category) == (None, Category.monitoring)


def test_maintenance_lowers_severity(mapper: RuleMapper) -> None:
    hvac = by_asset(signals(mapper), "hvac-wg-01")[0]
    assert hvac.severity == 3  # High (4) abaissé
    assert "En maintenance" in hvac.details


def test_problem_signal_fields(mapper: RuleMapper) -> None:
    s = signals(mapper)["503849434"]
    assert s.source == "zabbix"
    assert s.title == "Interface Fa1/7(): FCS ERRORS"
    assert s.asset == "sw-wg-ot-01"
    assert "Données : #FCS Errors: 13194" in s.details
    assert "Groupes : Switchs/WG-OT, WG-Reseau" in s.details
    assert s.last_seen == NOW
    assert s.first_seen < NOW
    assert s.url_template_params.keys() == {"eventid", "triggerid"}
    named = by_asset(signals(mapper), "srv-wg-04")[0]
    assert named.details.startswith("Hôte : WG-srv-wg-04 - SQL (srv-wg-04)")


def test_offline_proxies(mapper: RuleMapper) -> None:
    sigs = signals(mapper)
    proxies = {k: v for k, v in sigs.items() if k.startswith("proxy:")}
    assert set(proxies) == {"proxy:2", "proxy:3"}  # hors ligne ; muet depuis 30 min
    assert all(
        (p.category, p.severity, p.company_code) == (Category.monitoring, 4, None)
        for p in proxies.values()
    )
    assert signals(mapper, make(proxy_stale_min=60)).keys() & {"proxy:3"} == set()


def test_limits_on_text(mapper: RuleMapper) -> None:
    for s in signals(mapper).values():
        assert len(s.title) <= 300
        assert len(s.details) <= 1000
        assert "\x00" not in s.details


def test_collect_is_deterministic(mapper: RuleMapper) -> None:
    c = make()
    assert [r.external_id for r in c.collect(NOW)] == [r.external_id for r in c.collect(NOW)]


class Spy:
    """Transport qui enregistre les requêtes et délègue au rejeu des fixtures."""

    def __init__(self, directory: Path = FIXTURES) -> None:
        self.inner = fixture_transport(directory)
        self.sent: list[dict[str, Any]] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        request.read()
        self.sent.append(
            {"auth": request.headers.get("Authorization"), **json.loads(request.content)}
        )
        return self.inner.handle_request(request)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)


def test_requests_sent(mapper: RuleMapper) -> None:
    spy = Spy()
    list(make(spy.transport(), min_severity=3).collect(NOW))
    methods = [r["method"] for r in spy.sent]
    assert methods == ["problem.get", "trigger.get", "proxy.get"]
    assert spy.sent[0]["params"]["severities"] == [3, 4, 5]
    assert spy.sent[0]["params"]["limit"] == MAX_OBJECTS + 1
    assert spy.sent[1]["params"]["monitored"] is True
    assert all(r["auth"] == "Bearer fixture-token" for r in spy.sent)


def test_triggers_are_fetched_in_batches(tmp_path: Path, mapper: RuleMapper) -> None:
    problems = [
        {
            "eventid": str(i),
            "objectid": str(i),
            "clock": "1791560000",
            "name": "x",
            "severity": "2",
            "acknowledged": "0",
            "suppressed": "0",
            "opdata": "",
            "tags": [],
        }
        for i in range(1, 1202)
    ]
    (tmp_path / "problem.get.json").write_text(json.dumps(problems))
    (tmp_path / "trigger.get.json").write_text("[]")
    (tmp_path / "proxy.get.json").write_text("[]")
    spy = Spy(tmp_path)
    assert list(make(spy.transport()).collect(NOW)) == []
    batches = [r["params"]["triggerids"] for r in spy.sent if r["method"] == "trigger.get"]
    assert [len(b) for b in batches] == [500, 500, 201]


def test_truncation_is_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    problems = [{"eventid": str(i), "objectid": "1"} for i in range(MAX_OBJECTS + 1)]
    (tmp_path / "problem.get.json").write_text(json.dumps(problems))
    (tmp_path / "trigger.get.json").write_text("[]")
    (tmp_path / "proxy.get.json").write_text("[]")
    with caplog.at_level(logging.WARNING, logger="vigie.connectors"):
        list(make(fixture_transport(tmp_path)).collect(NOW))
    assert "collecte tronquée" in caplog.text


def test_healthcheck() -> None:
    health = make().healthcheck()
    assert (health.ok, health.version, health.detail) == (True, "7.4.0", "")


def test_healthcheck_reports_untested_version_and_failure(tmp_path: Path) -> None:
    (tmp_path / "apiinfo.version.json").write_text('"6.0.30"')
    (tmp_path / "proxy.get.json").write_text("[]")
    health = make(fixture_transport(tmp_path)).healthcheck()
    assert (health.ok, health.detail) == (True, "version non testée")
    (tmp_path / "proxy.get.json").unlink()
    failed = make(fixture_transport(tmp_path)).healthcheck()
    assert not failed.ok
    assert "HTTP 404" in failed.detail


@pytest.mark.parametrize(
    "response",
    [
        {"jsonrpc": "2.0", "error": {"code": -32602, "data": "Not authorised."}, "id": 1},
        {"jsonrpc": "2.0", "result": {"unexpected": True}, "id": 1},
        {"jsonrpc": "2.0", "result": ["not-an-object"], "id": 1},
    ],
)
def test_source_errors(response: dict[str, Any]) -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=response))
    with pytest.raises(SourceCallError):
        list(make(transport).collect(NOW))


@pytest.mark.parametrize(
    "settings",
    [
        {"base_url": "http://zabbix.test"},
        {"min_severity": 9},
        {"unknown": 1},
        {"category_by_group": {"X": "nope"}},
    ],
)
def test_invalid_configuration(settings: dict[str, Any]) -> None:
    with pytest.raises(ConnectorConfigError, match=r"\[sources.zabbix\] invalide"):
        make(**settings)
