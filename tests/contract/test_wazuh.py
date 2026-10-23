"""Wazuh : fixtures synthétiques (documentation officielle 4.x) → signaux attendus."""

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
from vigie.connectors.wazuh import WazuhConnector, _digest, rule_severity
from vigie.db.enums import Category
from vigie.engine.settings import ScoringConfig
from vigie.mapping import RuleMapper

FIXTURES = Path(__file__).parent / "wazuh_synthetic"
NOW = datetime(2026, 10, 23, 6, 0, tzinfo=UTC)
SETTINGS = {"api_url": "https://wazuh.test:55000", "indexer_url": "https://wazuh.test:9200"}


@pytest.fixture(scope="module")
def mapper(tmp_path_factory: pytest.TempPathFactory) -> RuleMapper:
    d = tmp_path_factory.mktemp("seed")
    shutil.copy(REPO_ROOT / "config" / "companies.example.yaml", d)
    return RuleMapper.from_seed_dir(d)


def make(transport: httpx.BaseTransport | None = None, **settings: Any) -> WazuhConnector:
    ctx = ConnectorContext(
        settings={**SETTINGS, **settings},
        secret=lambda name: SecretStr("fixture-password"),
        transport=transport or fixture_transport(FIXTURES),
    )
    connector = WazuhConnector.from_context(ctx)
    connector._now = lambda: NOW
    return connector


def signals(mapper: RuleMapper, connector: WazuhConnector | None = None) -> dict[str, Signal]:
    c = connector or make()
    return {s.external_id: s for s in (c.to_signal(r, mapper) for r in c.collect(NOW))}


def ids(*parts: tuple[str, str]) -> set[str]:
    return {f"{prefix}:{_digest(key)}" for prefix, key in parts}


def test_expected_signals(mapper: RuleMapper) -> None:
    sigs = signals(mapper)
    assert set(sigs) == ids(
        ("agents:disconnected", "spl"),
        ("agents:never", "cc"),
        ("agents:stale", "fwd"),
        ("alert:5712", "001"),
        ("alert:5712", "010"),
        ("alert:100200", "002"),
        ("cve:CVE-2026-0001", "wi"),
        ("cve:CVE-2026-0001", "spl"),
        ("cve:CVE-2026-0003", "wi"),
    )
    assert all(s.source == "wazuh" for s in sigs.values())


def _one(sigs: dict[str, Signal], prefix: str, key: str) -> Signal:
    return sigs[f"{prefix}:{_digest(key)}"]


def test_alerts(mapper: RuleMapper) -> None:
    sigs = signals(mapper)
    brute = _one(sigs, "alert:5712", "001")
    assert (brute.company_code, brute.severity, brute.category) == ("WI", 4, Category.security)
    assert brute.asset == "srv-wi-01"
    assert brute.attributes == {"kind": "alert", "rule_level": 10, "count": 10}
    assert "Occurrences sur 24 h : 10" in brute.details
    assert brute.last_seen == datetime(2026, 10, 23, 5, 40, 12, tzinfo=UTC)
    assert brute.first_seen == datetime(2026, 10, 22, 8, 0, tzinfo=UTC)
    # Agent rangé dans deux sociétés : aucune n'est choisie au hasard.
    assert _one(sigs, "alert:5712", "010").company_code is None
    # Niveau 13 : sévérité 5 ; texte non fiable nettoyé (balises retirées).
    hostile = _one(sigs, "alert:100200", "002")
    assert (hostile.company_code, hostile.severity) == ("SPL", 5)
    assert "<b>" not in hostile.title and "<b>" not in hostile.details


def test_agents(mapper: RuleMapper) -> None:
    sigs = signals(mapper)
    down = _one(sigs, "agents:disconnected", "spl")
    # srv-wg-01, déconnecté depuis 30 min seulement, n'est pas signalé.
    assert (down.company_code, down.severity, down.category) == ("SPL", 3, Category.monitoring)
    assert down.title == "Wazuh — 2 agents déconnectés"
    assert down.details.index("srv-spl-02") < down.details.index("srv-spl-01")  # plus ancien
    never = _one(sigs, "agents:never", "cc")
    assert (never.company_code, never.severity, never.title) == (
        "CC",
        2,
        "Wazuh — 1 agent jamais connecté",
    )
    stale = _one(sigs, "agents:stale", "fwd")
    assert (stale.company_code, stale.severity) == ("FWD", 1)
    assert "plus de 30 jours" in stale.title
    assert not any("wazuh-manager" in s.details for s in sigs.values())


def test_vulnerabilities_linux_only_per_company(mapper: RuleMapper) -> None:
    sigs = signals(mapper)
    wi = _one(sigs, "cve:CVE-2026-0001", "wi")
    assert (wi.company_code, wi.severity, wi.category) == ("WI", 4, Category.vulnerability)
    assert wi.asset == "2 agents Linux"
    assert "srv-wi-01, srv-wi-02" in wi.details and "openssl" in wi.details
    assert wi.attributes["cvss"] == 9.8
    assert _one(sigs, "cve:CVE-2026-0001", "spl").company_code == "SPL"
    high = _one(sigs, "cve:CVE-2026-0003", "wi")
    assert (high.severity, high.asset) == (3, "srv-wi-01")
    # CVE-2026-0002 (Windows → Defender) et CVE-2026-0004 (agent inconnu) : écartées.
    assert not any("0002" in k or "0004" in k for k in sigs)


def test_vulnerabilities_capped_per_company(mapper: RuleMapper) -> None:
    sigs = signals(mapper, make(max_vulns_per_company=1))
    assert {k.split(":")[1] for k in sigs if k.startswith("cve:")} == {"CVE-2026-0001"}


def test_rule_severity_table() -> None:
    assert [rule_severity(n) for n in (0, 1, 3, 4, 6, 7, 9, 10, 12, 13, 15)] == [
        0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5,
    ]  # fmt: skip


def test_level12_override_sees_the_rule_level(mapper: RuleMapper) -> None:
    rule = {r.id: r for r in ScoringConfig().overrides}["wazuh_level12"]
    sigs = signals(mapper)

    def facts(s: Signal) -> dict[str, Any]:
        return {
            "source": s.source,
            "category": s.category,
            "severity": s.severity,
            "attributes": dict(s.attributes),
        }

    assert rule.matches(facts(_one(sigs, "alert:100200", "002")))
    assert not rule.matches(facts(_one(sigs, "alert:5712", "001")))


def test_queries_sent_to_the_indexer() -> None:
    bodies: dict[str, Any] = {}
    replay = fixture_transport(FIXTURES)

    def handler(request: httpx.Request) -> httpx.Response:
        request.read()
        if request.url.path.endswith("/_search"):
            bodies[request.url.path] = json.loads(request.content)
            assert request.headers["authorization"].startswith("Basic ")
        elif request.url.path != "/security/user/authenticate":
            assert request.headers["authorization"] == "Bearer fixture-jwt"
        return replay.handle_request(request)

    list(make(httpx.MockTransport(handler), min_rule_level=12).collect(NOW))
    alerts = bodies["/wazuh-alerts-4.x-*/_search"]
    assert alerts["size"] == 0
    assert {"range": {"rule.level": {"gte": 12}}} in alerts["query"]["bool"]["filter"]
    assert {"range": {"timestamp": {"gte": "2026-10-22T06:00:00+00:00"}}} in alerts["query"][
        "bool"
    ]["filter"]
    assert alerts["query"]["bool"]["must_not"] == [{"terms": {"rule.id": ["204"]}}]
    vulns = bodies["/wazuh-states-vulnerabilities-*/_search"]
    # Agents Linux seulement (ni 004 ni 007, Windows), manager compris.
    linux = ["000", "001", "002", "003", "005", "006", "008", "009", "010"]
    assert vulns["query"]["bool"]["filter"] == [
        {"terms": {"vulnerability.severity": ["Critical", "High"]}},
        {"terms": {"agent.id": linux}},
    ]


def test_no_linux_agent_no_vulnerability_query() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": "t"}})
        if request.url.path == "/agents":
            item = {
                "id": "001",
                "name": "pc-wi-03",
                "status": "active",
                "os": {"platform": "windows"},
            }
            return httpx.Response(
                200, json={"data": {"affected_items": [item], "total_affected_items": 1}}
            )
        return httpx.Response(200, json={"aggregations": {}})

    assert list(make(httpx.MockTransport(handler)).collect(NOW)) == []
    assert "/wazuh-states-vulnerabilities-*/_search" not in paths


def test_healthcheck() -> None:
    health = make().healthcheck()
    assert (health.ok, health.version, health.detail) == (True, "4.12.0", "")


def test_healthcheck_failure_and_untested_version(tmp_path: Path) -> None:
    for name in ("POST_security_user_authenticate.json", "GET_agents_summary_status.json"):
        shutil.copy(FIXTURES / name, tmp_path)
    shutil.copy(FIXTURES / "POST_wazuh-alerts-4.x-*__search.json", tmp_path)
    (tmp_path / "GET_.json").write_text(json.dumps({"data": {"api_version": "5.0.0"}}))
    assert make(fixture_transport(tmp_path)).healthcheck().detail == "version non testée"
    (tmp_path / "POST_wazuh-alerts-4.x-*__search.json").unlink()
    failed = make(fixture_transport(tmp_path)).healthcheck()
    assert not failed.ok and "HTTP 404" in failed.detail


@pytest.mark.parametrize("response", [{"data": {}}, {"data": {"token": ""}}, ["x"]])
def test_authentication_without_token(response: Any) -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=response))
    with pytest.raises(SourceCallError, match="sans jeton"):
        list(make(transport).collect(NOW))


def test_agents_pagination_and_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    import vigie.connectors.wazuh as wazuh

    monkeypatch.setattr(wazuh, "PAGE_SIZE", 2)
    monkeypatch.setattr(wazuh, "MAX_OBJECTS", 3)
    offsets: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": "t"}})
        offsets.append(request.url.params["offset"])
        start = int(request.url.params["offset"])
        items = [{"id": f"{i:03}", "name": f"a{i}"} for i in range(start, min(start + 2, 10))]
        return httpx.Response(
            200, json={"data": {"affected_items": items, "total_affected_items": 10}}
        )

    c = make(httpx.MockTransport(handler))
    assert [a.id for a in c._agents()] == ["000", "001", "002"]
    assert c.truncated and offsets == ["0", "2"]


def test_truncated_aggregations_and_failed_shards(tmp_path: Path) -> None:
    for f in FIXTURES.glob("*.json"):
        shutil.copy(f, tmp_path)
    path = tmp_path / "POST_wazuh-alerts-4.x-*__search.json"
    data = json.loads(path.read_text())
    data["aggregations"]["rules"]["sum_other_doc_count"] = 4
    path.write_text(json.dumps(data))
    c = make(fixture_transport(tmp_path))
    list(c.collect(NOW))
    assert c.truncated
    data["aggregations"]["rules"]["sum_other_doc_count"] = 0
    data["_shards"]["failed"] = 1
    path.write_text(json.dumps(data))
    c = make(fixture_transport(tmp_path))
    list(c.collect(NOW))
    assert c.truncated
    assert not make().truncated


@pytest.mark.parametrize(
    "settings",
    [
        {"api_url": "http://wazuh.test:55000"},
        {"indexer_url": "https://wazuh.test:9200/wazuh-alerts-*"},
        {"min_rule_level": 0},
        {"vuln_severities": ["Urgent"]},
        {"vuln_severities": []},
        {"alerts_index": "*"},
        {"ca_bundle": "/etc/vigie/ca/wazuh.pem"},
        {"verify_hostname": False},
        {"ignore_rules": ["204; DROP"]},
        {"verify_hostname": False, "api_ca_bundle": "api.pem"},
    ],
)
def test_invalid_configuration(settings: dict[str, Any]) -> None:
    with pytest.raises(ConnectorConfigError, match=r"\[sources.wazuh\] invalide"):
        make(**settings)


def _real(**settings: Any) -> WazuhConnector:
    # Sans transport simulé : clients httpx réels (contexte TLS inspectable), aucun appel.
    ctx = ConnectorContext(
        settings={**SETTINGS, **settings}, secret=lambda name: SecretStr("x"), transport=None
    )
    return WazuhConnector.from_context(ctx)


def _tls(client: Any) -> Any:
    return client._client._transport._pool._ssl_context


def test_pinned_certificates_one_anchor_per_api(tmp_path: Path) -> None:
    from tests.security.test_safeclient import _self_signed

    api, indexer = _self_signed(tmp_path, "api.test"), _self_signed(tmp_path, "indexer.test")
    c = _real(api_ca_bundle=str(api), indexer_ca_bundle=str(indexer), verify_hostname=False)
    for client, name in ((c.manager, "api.test"), (c.indexer, "indexer.test")):
        ctx = _tls(client)
        assert ctx.check_hostname is False
        assert [dict(x[0] for x in ca["subject"])["commonName"] for ca in ctx.get_ca_certs()] == [
            name
        ]


def test_hostname_checked_by_default() -> None:
    c = _real()
    assert _tls(c.manager).check_hostname is True
    assert _tls(c.indexer).check_hostname is True


def test_ignored_rules(mapper: RuleMapper) -> None:
    # Règle 5712 écartée : ni dans la requête (must_not), ni dans les signaux.
    sigs = signals(mapper, make(ignore_rules=["5712"]))
    assert not any(k.startswith("alert:5712:") for k in sigs)
    assert any(k.startswith("alert:100200:") for k in sigs)
    # Liste vide : aucune exclusion, pas de must_not.
    bodies: list[Any] = []
    replay = fixture_transport(FIXTURES)

    def handler(request: httpx.Request) -> httpx.Response:
        request.read()
        if request.url.path.startswith("/wazuh-alerts"):
            bodies.append(json.loads(request.content))
        return replay.handle_request(request)

    list(make(httpx.MockTransport(handler), ignore_rules=[]).collect(NOW))
    assert "must_not" not in bodies[0]["query"]["bool"]
