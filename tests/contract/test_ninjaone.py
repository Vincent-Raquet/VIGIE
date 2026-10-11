"""NinjaOne : fixtures synthétiques (modèles de la spécification officielle) → signaux."""

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
from vigie.connectors.ninjaone import NinjaOneConnector
from vigie.db.enums import Category
from vigie.mapping import RuleMapper

FIXTURES = Path(__file__).parent / "ninjaone_synthetic"
NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
SETTINGS: dict[str, Any] = {
    "base_url": "https://eu.ninjarmm.com",
    "client_id": "vigie-client",
    "ticket_board_id": 12,
    "ticket_statuses": ["Ouvert", "En attente"],
}


@pytest.fixture(scope="module")
def mapper(tmp_path_factory: pytest.TempPathFactory) -> RuleMapper:
    d = tmp_path_factory.mktemp("seed")
    shutil.copy(REPO_ROOT / "config" / "companies.example.yaml", d)
    return RuleMapper.from_seed_dir(d)


def make(transport: httpx.BaseTransport | None = None, **settings: Any) -> NinjaOneConnector:
    ctx = ConnectorContext(
        settings={**SETTINGS, **settings},
        secret=lambda name: SecretStr("fixture-secret"),
        transport=transport or fixture_transport(FIXTURES),
    )
    c = NinjaOneConnector.from_context(ctx)
    c._now = lambda: NOW
    return c


def signals(mapper: RuleMapper, connector: NinjaOneConnector | None = None) -> dict[str, Signal]:
    c = connector or make()
    return {s.external_id: s for s in (c.to_signal(r, mapper) for r in c.collect(NOW))}


def by_kind(sigs: dict[str, Signal], kind: str) -> list[Signal]:
    return [s for s in sigs.values() if s.attributes.get("kind") == kind]


def test_alerts_single_and_aggregated(mapper: RuleMapper) -> None:
    sigs = signals(mapper)
    single = {s.asset: s for s in by_kind(sigs, "alert")}
    assert set(single) == {"srv-wi-01", "pc-spl-07", "fw-wg-01", "pc-wg-09"}
    disk, av, fw = single["srv-wi-01"], single["pc-spl-07"], single["fw-wg-01"]
    assert disk.severity == 3  # gravité NONE (réel) : sévérité selon le type, espace disque
    assert (disk.category, disk.company_code) == (Category.server, "WI")
    assert (av.category, av.severity, av.company_code) == (Category.security, 5, "SPL")
    assert (fw.category, fw.severity, fw.company_code) == (Category.firewall, 4, "WG")
    assert fw.attributes["offline"] is True
    [group] = by_kind(sigs, "alert_group")
    assert (group.category, group.severity, group.company_code) == (Category.endpoint, 2, "SPL")
    assert group.title == "Redémarrage en attente sur 6 appareil(s)"
    assert group.attributes["count"] == 6


def test_failed_patches_aggregated_per_company(mapper: RuleMapper) -> None:
    patches = {
        (s.attributes["patch_kind"], s.company_code): s for s in by_kind(signals(mapper), "patches")
    }
    assert set(patches) == {("os", "WI"), ("os", "SPL"), ("software", "SPL")}
    wi = patches[("os", "WI")]
    assert (wi.category, wi.severity, wi.attributes["count"]) == (Category.vulnerability, 4, 3)
    assert wi.title == "3 patch(s) OS en échec sur 1 appareil(s)"
    assert "KB" not in wi.title and "srv-wi-01" in wi.details
    assert patches[("software", "SPL")].severity == 2


def test_tickets_filtered_by_status_without_personal_data(mapper: RuleMapper) -> None:
    tickets = {s.attributes["ticket_id"]: s for s in by_kind(signals(mapper), "ticket")}
    assert set(tickets) == {"501", "503"}  # 502 « Fermé » hors des statuts configurés
    t501, t503 = tickets["501"], tickets["503"]
    assert (t501.category, t501.severity, t501.company_code) == (Category.user_support, 3, "SPL")
    assert t501.title == "Ticket n° 501 : Imprimante HS au 2e étage"
    assert t501.asset == "Ticket n° 501" and t501.attributes["status"] == "Ouvert"
    assert (t503.severity, t503.company_code, t503.attributes["status"]) == (2, "WI", "En attente")


def test_board_request_lists_only_allowed_columns() -> None:
    sent: list[httpx.Request] = []
    inner = fixture_transport(FIXTURES)

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return inner.handle_request(request)

    list(make(httpx.MockTransport(handler)).collect(NOW))
    [board] = [r for r in sent if r.url.path.endswith("/run")]
    body = board.read().decode()
    assert '"includeColumns"' in body and "description" not in body and "requester" not in body


def test_no_tickets_without_board(mapper: RuleMapper) -> None:
    sigs = signals(mapper, make(ticket_board_id=0))
    assert not by_kind(sigs, "ticket")


def test_healthcheck() -> None:
    health = make().healthcheck()
    assert (health.ok, health.version) == (True, "API v2")


@pytest.mark.parametrize("token", [{"token_type": "Bearer"}, {"access_token": ""}, ["x"]])
def test_token_without_access_token(token: Any) -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=token))
    with pytest.raises(SourceCallError, match="access_token"):
        list(make(transport).collect(NOW))


@pytest.mark.parametrize(
    "settings",
    [
        {"base_url": "https://evil.example.com"},
        {"scope": "monitoring management"},
        {"proxy": "http://proxy.example.com:3128"},
        {"ticket_statuses": [str(i) for i in range(21)]},
        {"unknown": 1},
    ],
)
def test_invalid_configuration(settings: dict[str, Any]) -> None:
    with pytest.raises(ConnectorConfigError, match=r"\[sources.ninjaone\] invalide"):
        make(**settings)


def test_pagination_and_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    import vigie.connectors.ninjaone as ninja

    monkeypatch.setattr(ninja, "PAGE_SIZE", 2)
    calls: list[tuple[str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path, params = request.url.path, dict(request.url.params)
        calls.append((path, params))
        if path == "/ws/oauth/token":
            return httpx.Response(200, json={"access_token": "t"})
        if path == "/v2/organizations":
            start = int(params.get("after", "0"))
            return httpx.Response(
                200, json=[{"id": i, "name": f"o{i}"} for i in range(start + 1, min(start + 3, 6))]
            )
        if path.endswith("/run"):
            last = int(json.loads(request.content).get("lastCursorId") or 0)
            rows = [{"id": i, "status": "Ouvert"} for i in range(last + 1, min(last + 3, 4))]
            return httpx.Response(
                200,
                json={"data": rows, "metadata": {"lastCursorId": rows[-1]["id"] if rows else None}},
            )
        cursor = params.get("cursor")
        return httpx.Response(
            200,
            json={
                "cursor": {"name": "c2" if not cursor else None},
                "results": [{"id": "p"}, {"id": "q"}] if not cursor else [{"id": "r"}],
            },
        )

    c = make(httpx.MockTransport(handler))
    assert [o["id"] for o in c._by_id("/v2/organizations")] == [1, 2, 3, 4, 5]
    assert [p["id"] for p in c._by_cursor("/v2/queries/os-patches", "FAILED")] == ["p", "q", "r"]
    assert [t["id"] for t in c._tickets()] == [1, 2, 3]
    monkeypatch.setattr(ninja, "MAX_OBJECTS", 3)
    c2 = make(httpx.MockTransport(handler))
    assert len(list(c2._by_id("/v2/organizations"))) == 3 and c2.truncated


def test_ticket_rows_are_stripped_on_receipt(mapper: RuleMapper) -> None:
    # NinjaOne ignore includeColumns : description, demandeur… ne doivent survivre nulle part.
    raw = list(make().collect(NOW))
    tickets = [r for r in raw if r.payload["kind"] == "ticket"]
    assert tickets
    dumped = repr([r.payload["row"] for r in tickets])
    for forbidden in ("Soleil2026", "Jean Dupont", "Technicien Un", "description", "requester"):
        assert forbidden not in dumped
    signals_text = repr([make().to_signal(r, mapper) for r in tickets])
    assert "Soleil2026" not in signals_text and "Dupont" not in signals_text


def test_ticket_company_from_organization_name(mapper: RuleMapper) -> None:
    t503 = next(s for s in by_kind(signals(mapper), "ticket") if s.attributes["ticket_id"] == "503")
    assert t503.company_code == "WI"  # clientId vide, « WallIndustries » → organisation 2


def test_unknown_alert_device_is_read_from_its_details(mapper: RuleMapper) -> None:
    ghost = next(s for s in by_kind(signals(mapper), "alert") if s.asset == "pc-wg-09")
    assert (ghost.company_code, ghost.category, ghost.severity) == ("WG", Category.endpoint, 2)


def test_client_id_read_from_secrets_when_absent_from_config() -> None:
    # Production : client id déposé par vigie-secret (gitleaks le refuse dans le dépôt).
    asked: list[str] = []

    def secret(name: str) -> SecretStr:
        asked.append(name)
        return SecretStr("id-depuis-secret\n" if name == "ninjaone_client_id" else "s")

    settings = {k: v for k, v in SETTINGS.items() if k != "client_id"}
    ctx = ConnectorContext(settings=settings, secret=secret, transport=fixture_transport(FIXTURES))
    c = NinjaOneConnector.from_context(ctx)
    assert asked == ["ninjaone_client_id", "ninjaone_client_secret"]
    assert c._client_id == "id-depuis-secret"


def test_pending_security_patches(mapper: RuleMapper) -> None:
    pending = {
        (s.attributes["patch_kind"], s.company_code): s
        for s in by_kind(signals(mapper), "pending_patch")
    }
    # Définitions antivirus (pas sécurité) et patchs refusés (REJECTED) écartés.
    assert set(pending) == {("os", "SPL"), ("os", "WI"), ("software", "SPL")}
    spl = pending[("os", "SPL")]
    assert (spl.category, spl.severity, spl.attributes["devices"]) == (
        Category.vulnerability,
        4,
        2,
    )
    assert spl.title == "Mise à jour de sécurité 2026-09 non installé sur 2 appareil(s)"
    assert spl.asset == "Patchs OS en attente — Splifar"
    assert spl.attributes["min_age_h"] == 168
    assert spl.attributes["incident_group"] == "ninjaone:pending:os"
    assert "KB5060001" in spl.details and "pc-spl-01, pc-spl-02" in spl.details
    wi = pending[("os", "WI")]
    assert (wi.severity, wi.attributes["status"]) == (3, "MANUAL")
    assert "à approuver" in wi.title
    assert pending[("software", "SPL")].severity == 3
    # Identifiant stable d'une collecte à l'autre : c'est lui qui date l'attente.
    assert {s.external_id for s in pending.values()} == {
        s.external_id for s in by_kind(signals(mapper), "pending_patch")
    }


def test_pending_patches_can_be_disabled(mapper: RuleMapper) -> None:
    assert not by_kind(signals(mapper, make(pending_days=0)), "pending_patch")


@pytest.mark.db
def test_pending_patches_become_one_incident_after_seven_days(
    mapper: RuleMapper, db_session: Any
) -> None:
    from datetime import timedelta

    from vigie.collect import ensure_source, store_snapshot
    from vigie.db import models
    from vigie.engine.correlate import correlate

    for code in ("WI", "SPL"):
        if db_session.get(models.Company, code) is None:
            db_session.add(models.Company(code=code, name=code, criticality=1.0))
    ensure_source(db_session, "ninjaone", kind="ninjaone")
    sigs = by_kind(signals(mapper), "pending_patch")
    store_snapshot(db_session, "ninjaone", sigs, NOW)
    assert correlate(db_session, NOW + timedelta(days=6)).created == 0
    report = correlate(db_session, NOW + timedelta(days=7, minutes=1))
    assert report.created == 3  # OS SPL, OS WI, logiciels SPL : un incident chacun
