"""FortiAnalyzer : fixtures synthétiques (formes des sources publiques) → signaux."""

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from tests.conftest import REPO_ROOT
from vigie.connectors.base import (
    ConnectorConfigError,
    ConnectorContext,
    Signal,
    SourceCallError,
    fixture_transport,
)
from vigie.connectors.fortianalyzer import FortiAnalyzerConnector
from vigie.db.enums import Category
from vigie.engine.rules import strongest
from vigie.engine.settings import DEFAULT_OVERRIDES
from vigie.mapping import RuleMapper

FIXTURES = Path(__file__).parent / "fortianalyzer_synthetic"
NOW = datetime(2026, 10, 12, 8, 30, tzinfo=UTC)


@pytest.fixture(scope="module")
def mapper(tmp_path_factory: pytest.TempPathFactory) -> RuleMapper:
    d = tmp_path_factory.mktemp("seed")
    shutil.copy(REPO_ROOT / "config" / "companies.example.yaml", d)
    return RuleMapper.from_seed_dir(d)


class Spy(httpx.BaseTransport):
    def __init__(self, inner: httpx.BaseTransport) -> None:
        self.inner = inner
        self.bodies: list[dict[str, Any]] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(json.loads(request.content))
        return self.inner.handle_request(request)


def make(transport: httpx.BaseTransport | None = None, **settings: Any) -> FortiAnalyzerConnector:
    ctx = ConnectorContext(
        settings={"base_url": "https://FAZVMSTM25009422", **settings},
        secret=lambda name: SecretStr("fixture-key"),
        transport=transport or fixture_transport(FIXTURES),
    )
    c = FortiAnalyzerConnector.from_context(ctx)
    c._now = lambda: NOW
    c._sleep = lambda s: None
    return c


def signals(mapper: RuleMapper, c: FortiAnalyzerConnector | None = None) -> dict[str, Signal]:
    c = c or make()
    return {s.external_id: s for s in (c.to_signal(r, mapper) for r in c.collect(NOW))}


def by_kind(sigs: dict[str, Signal], *kinds: str) -> list[Signal]:
    return [s for s in sigs.values() if s.attributes.get("kind") in kinds]


def test_alerts_grouped_by_handler_and_device(mapper: RuleMapper) -> None:
    sigs = signals(mapper)
    alerts = {(s.attributes["trigger"], s.asset): s for s in by_kind(sigs, "alert", "vpn_event")}
    assert set(alerts) == {
        ("Default-VPN-Down", "WI-FGT-01"),
        ("Default-IPS-Critical", "SPL-FGT-01"),
        ("Default-Admin-Login-Fail", "WG-FGT-01"),
        ("Default-Conf-Change", "XX-FGT-99"),
    }
    vpn = alerts[("Default-VPN-Down", "WI-FGT-01")]
    assert (vpn.category, vpn.severity, vpn.company_code) == (Category.network, 4, "WI")
    assert vpn.attributes == {"kind": "vpn_event", "trigger": "Default-VPN-Down", "count": 2}
    assert vpn.title == "Default-VPN-Down — WI-FGT-01 (2 alerte(s))" and "4 journaux" in vpn.details
    ips = alerts[("Default-IPS-Critical", "SPL-FGT-01")]
    assert (ips.category, ips.severity, ips.company_code) == (Category.security, 5, "SPL")
    assert "<script>" not in ips.details
    login = alerts[("Default-Admin-Login-Fail", "WG-FGT-01")]
    assert (login.category, login.severity, login.attributes["count"]) == (Category.firewall, 3, 1)
    assert alerts[("Default-Conf-Change", "XX-FGT-99")].company_code is None
    assert vpn.first_seen < vpn.last_seen  # dates des alertes


def test_device_connection_and_ha(mapper: RuleMapper) -> None:
    sigs = signals(mapper)
    [down] = by_kind(sigs, "device_down")
    assert (down.asset, down.category, down.severity, down.company_code) == (
        "SPL-FGT-01",
        Category.firewall,
        4,
        "SPL",
    )
    [ha] = by_kind(sigs, "ha_degraded")
    assert (ha.asset, ha.company_code, ha.attributes["state"]) == ("WG-FGT-01", "WG", "ha_degraded")
    assert "WG-FGT-01B" in ha.details
    # conn_status 0 (inconnu) : aucun signal pour CC-FGT-01.
    assert not [s for s in sigs.values() if s.asset == "CC-FGT-01"]
    # Override firewall_down : P1.
    for s in (down, ha):
        facts = {"category": s.category.value, "attributes": s.attributes}
        rule = strongest(DEFAULT_OVERRIDES, facts)
        assert rule is not None and rule.id == "firewall_down"


def test_requests_sent(mapper: RuleMapper) -> None:
    spy = Spy(fixture_transport(FIXTURES))
    signals(mapper, make(spy))
    urls = [(b["method"], b["params"][0]["url"]) for b in spy.bodies]
    assert urls == [("get", "/eventmgmt/adom/root/alerts"), ("get", "/dvmdb/adom/root/device")]
    alerts = spy.bodies[0]["params"][0]
    assert alerts["time-range"] == {"start": "2026-10-11 10:30:00", "end": "2026-10-12 10:30:00"}
    assert alerts["apiver"] == 3 and alerts["limit"] == 500
    assert all(b["jsonrpc"] == "2.0" and "session" not in b for b in spy.bodies)


def test_vpn_logsearch_when_enabled(mapper: RuleMapper) -> None:
    spy = Spy(fixture_transport(FIXTURES))
    sigs = signals(mapper, make(spy, vpn_logsearch=True))
    [log] = [s for s in sigs.values() if s.external_id.startswith("vpnlog:")]
    assert (log.category, log.severity, log.company_code) == (Category.network, 4, "FWD")
    assert log.title == "Tunnel VPN FWD-WI tombé — FWD-FGT-01 (2 fois)"
    methods = [(b["method"], b["params"][0]["url"]) for b in spy.bodies]
    assert ("add", "/logview/adom/root/logsearch") in methods
    assert ("get", "/logview/adom/root/logsearch/42") in methods


def test_healthcheck(mapper: RuleMapper) -> None:
    health = make().healthcheck()
    assert health.ok and health.version == "v8.0.0-build0105 260420 (GA.F)" and not health.detail


def test_status_code_errors_are_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        status = {"code": -11, "message": "No permission for the resource"}
        return httpx.Response(200, json={"id": body["id"], "result": [{"status": status}]})

    c = make(httpx.MockTransport(handler))
    health = c.healthcheck()
    assert not health.ok and "code -11" in health.detail
    with pytest.raises(SourceCallError, match="code -11"):
        list(c.collect(NOW))


def test_pagination_and_truncation() -> None:
    page = [{"triggername": "t", "devname": "WI-FGT-01", "ackflag": "no"}] * 500
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        item = body["params"][0]
        if item["url"].endswith("/alerts"):
            calls.append(item["offset"])
            data: Any = page
        else:
            data = []
        return httpx.Response(
            200, json={"id": body["id"], "result": [{"status": {"code": 0}, "data": data}]}
        )

    c = make(httpx.MockTransport(handler))
    list(c.collect(NOW))
    assert calls == list(range(0, 5000, 500)) and c.truncated


@pytest.mark.parametrize(
    "bad",
    [
        {"base_url": "http://faz.test"},
        {"adom": "../root"},
        {"proxy": "http://evil.test:3128"},
        {"timezone": "Mars/Olympus"},
        {"api_key": "x"},
    ],
)
def test_invalid_config(bad: dict[str, Any]) -> None:
    with pytest.raises(ConnectorConfigError):
        make(**bad)
