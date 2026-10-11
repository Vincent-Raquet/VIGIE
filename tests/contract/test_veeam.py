"""Veeam : fixtures synthétiques (modèles du swagger officiel) → signaux attendus."""

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
from vigie.connectors.veeam import VeeamConnector
from vigie.db.enums import Category
from vigie.engine.settings import ScoringConfig
from vigie.mapping import RuleMapper

FIXTURES = Path(__file__).parent / "veeam_synthetic"
NOW = datetime(2026, 10, 11, 6, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def mapper(tmp_path_factory: pytest.TempPathFactory) -> RuleMapper:
    d = tmp_path_factory.mktemp("seed")
    shutil.copy(REPO_ROOT / "config" / "companies.example.yaml", d)
    return RuleMapper.from_seed_dir(d)


def make(transport: httpx.BaseTransport | None = None, **settings: Any) -> VeeamConnector:
    ctx = ConnectorContext(
        settings={"base_url": "https://vbr.test:9419", **settings},
        secret=lambda name: SecretStr("fixture-password"),
        transport=transport or fixture_transport(FIXTURES),
    )
    connector = VeeamConnector.from_context(ctx)
    connector._now = lambda: NOW
    return connector


def signals(mapper: RuleMapper, connector: VeeamConnector | None = None) -> dict[str, Signal]:
    c = connector or make()
    return {s.external_id: s for s in (c.to_signal(r, mapper) for r in c.collect(NOW))}


def job_id(n: int) -> str:
    return f"job:10000000-0000-4000-8000-00000000000{n}"


def test_expected_signals(mapper: RuleMapper) -> None:
    sigs = signals(mapper)
    assert set(sigs) == {
        job_id(1),
        job_id(2),
        job_id(3),
        "repo:20000000-0000-4000-8000-000000000001:capacity",
        "repo:20000000-0000-4000-8000-000000000002:capacity",
        "malware:70000000-0000-4000-8000-000000000001",
    }  # succès récents, job désactivé, dépôt à 40 % et malware « Clean » : aucun signal


def test_failed_critical_job(mapper: RuleMapper) -> None:
    s = signals(mapper)[job_id(1)]
    assert (s.category, s.severity, s.company_code) == (Category.backup, 5, "SPL")
    assert s.title == "Veeam — Sauvegarde en échec : SPL-FS01-Daily"
    assert s.attributes["consecutive_failures"] == 2
    assert s.attributes["asset_critical"] is True
    assert s.attributes["hours_since_last_success"] == 52.5
    assert "failed to connect to host srv-spl-01" in s.details


def test_repeated_warning_and_stale_job(mapper: RuleMapper) -> None:
    sigs = signals(mapper)
    warning, stale = sigs[job_id(2)], sigs[job_id(3)]
    assert (warning.severity, warning.company_code) == (3, "WI")
    assert "Avertissements consécutifs : 2" in warning.details
    assert (stale.severity, stale.company_code) == (3, "WG")
    assert stale.attributes["last_result"] == "Success"
    assert stale.attributes["hours_since_last_success"] == 52.5
    assert stale.attributes["asset_critical"] is False


def test_repositories(mapper: RuleMapper) -> None:
    sigs = signals(mapper)
    wi = sigs["repo:20000000-0000-4000-8000-000000000001:capacity"]
    spl = sigs["repo:20000000-0000-4000-8000-000000000002:capacity"]
    assert (wi.severity, wi.attributes["repo_used_pct"], wi.company_code) == (3, 92.0, None)
    assert (spl.severity, spl.attributes["repo_used_pct"], spl.company_code) == (4, 97.0, "SPL")
    assert "800 Go libres" in wi.details


def test_malware(mapper: RuleMapper) -> None:
    s = signals(mapper)["malware:70000000-0000-4000-8000-000000000001"]
    assert (s.category, s.severity, s.asset) == (Category.security, 5, "srv-wi-02")
    assert s.attributes["kind"] == "malware"


def _facts(s: Signal) -> dict[str, Any]:
    # Faits tels que les voit le moteur (scoring.incident_facts) pour les overrides.
    return {
        "source": s.source,
        "category": s.category,
        "severity": s.severity,
        "attributes": dict(s.attributes),
    }


def test_overrides_see_the_backup_attributes(mapper: RuleMapper) -> None:
    rules = {r.id: r for r in ScoringConfig().overrides}
    sigs = signals(mapper)
    fs01 = _facts(sigs[job_id(1)])
    assert rules["backup_two_failures"].matches(fs01)
    assert rules["backup_no_success_24h"].matches(fs01)
    assert not rules["backup_no_success_24h"].matches(_facts(sigs[job_id(3)]))  # non critique
    repo = _facts(sigs["repo:20000000-0000-4000-8000-000000000002:capacity"])
    assert rules["repo_95"].matches(repo)


def test_healthcheck() -> None:
    health = make().healthcheck()
    assert (health.ok, health.version, health.detail) == (True, "13.0.1.180", "")


def test_healthcheck_failure_and_untested_version(tmp_path: Path) -> None:
    shutil.copy(FIXTURES / "POST_api_oauth2_token.json", tmp_path)
    (tmp_path / "GET_api_v1_serverInfo.json").write_text(
        json.dumps({"buildVersion": "12.3.1.1139"})
    )
    assert make(fixture_transport(tmp_path)).healthcheck().detail == "version non testée"
    (tmp_path / "POST_api_oauth2_token.json").unlink()
    failed = make(fixture_transport(tmp_path)).healthcheck()
    assert not failed.ok and "HTTP 404" in failed.detail


@pytest.mark.parametrize("token_response", [{"token_type": "bearer"}, {"access_token": ""}, ["x"]])
def test_token_without_access_token(token_response: Any) -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=token_response))
    with pytest.raises(SourceCallError, match="access_token"):
        list(make(transport).collect(NOW))


def test_pagination_and_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    import vigie.connectors.veeam as veeam

    monkeypatch.setattr(veeam, "PAGE_SIZE", 2)
    monkeypatch.setattr(veeam, "MAX_OBJECTS", 3)
    seen: list[dict[str, list[str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/oauth2/token":
            return httpx.Response(200, json={"access_token": "t"})
        seen.append({k: [v] for k, v in request.url.params.items()})
        skip = int(request.url.params["skip"])
        data = [{"id": str(i), "name": f"n{i}"} for i in range(skip, min(skip + 2, 10))]
        return httpx.Response(200, json={"data": data, "pagination": {"total": 10}})

    c = make(httpx.MockTransport(handler))
    items = list(c._pages("/api/v1/jobs/states"))
    assert [i["id"] for i in items] == ["0", "1", "2"]
    assert c.truncated
    assert [s["skip"] for s in seen] == [["0"], ["2"]]


@pytest.mark.parametrize(
    "settings",
    [
        {"base_url": "http://vbr.test:9419"},
        {"api_version": "latest"},
        {"interval_min": 1},
        {"instances": []},
    ],
)
def test_invalid_configuration(settings: dict[str, Any]) -> None:
    with pytest.raises(ConnectorConfigError, match=r"\[sources.veeam\] invalide"):
        make(**settings)


def test_healthcheck_without_server_info_access() -> None:
    # Essai réel (VBR 13, rôle Backup Viewer) : serverInfo répond 403, les jobs sont lisibles.
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/oauth2/token":
            return httpx.Response(200, json={"access_token": "t"})
        if path == "/api/v1/serverInfo":
            return httpx.Response(403)
        return httpx.Response(200, json={"data": [], "pagination": {"total": 0, "count": 0}})

    health = make(httpx.MockTransport(handler)).healthcheck()
    assert health.ok and health.version is None
    assert health.detail == "version inconnue (serverInfo refusé au rôle)"


def test_other_errors_still_fail_the_healthcheck() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/oauth2/token":
            return httpx.Response(200, json={"access_token": "t"})
        return httpx.Response(403 if request.url.path == "/api/v1/serverInfo" else 500)

    health = make(httpx.MockTransport(handler)).healthcheck()
    assert not health.ok and "HTTP 500" in health.detail
