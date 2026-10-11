"""NinjaOne : capture réelle anonymisée (eu.ninjarmm.com, scope monitoring, 2026-10-11)."""

import shutil
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr

from tests.conftest import REPO_ROOT
from vigie.connectors.base import ConnectorContext, Signal, fixture_transport
from vigie.connectors.ninjaone import NinjaOneConnector
from vigie.mapping import RuleMapper

FIXTURES = Path(__file__).parent / "ninjaone"
NOW = datetime(2026, 10, 11, 14, 10, tzinfo=UTC)


@pytest.fixture(scope="module")
def sigs(tmp_path_factory: pytest.TempPathFactory) -> list[Signal]:
    d = tmp_path_factory.mktemp("seed")
    shutil.copy(REPO_ROOT / "config" / "companies.example.yaml", d)
    mapper = RuleMapper.from_seed_dir(d)
    ctx = ConnectorContext(
        settings={
            "base_url": "https://eu.ninjarmm.com",
            "client_id": "vigie-client",
            "ticket_board_id": 4,
            "ticket_statuses": ["Nouveau", "Ouvert", "En attente"],
        },
        secret=lambda name: SecretStr("fixture-secret"),
        transport=fixture_transport(FIXTURES),
    )
    c = NinjaOneConnector.from_context(ctx)
    c._now = lambda: NOW
    return [c.to_signal(r, mapper) for r in c.collect(NOW)]


def test_every_alert_and_ticket_is_attached(sigs: list[Signal]) -> None:
    assert Counter((s.attributes["kind"], s.company_code) for s in sigs) == {
        ("ticket", "WI"): 14,
        ("ticket", "WG"): 3,
        ("ticket", "FWD"): 2,
        ("alert", "CC"): 5,
        ("alert", "SPL"): 3,
        ("alert", "WG"): 2,
        ("alert", None): 4,  # organisations hors des 5 sociétés (décision du coordinateur)
        ("alert_group", "SPL"): 2,
        ("alert_group", "WG"): 1,
        ("alert_group", "FWD"): 1,
    }


def test_repetitive_alerts_are_grouped_with_readable_titles(sigs: list[Signal]) -> None:
    groups = sorted(s.title for s in sigs if s.attributes["kind"] == "alert_group")
    assert all(t.startswith(("Espace disque faible sur", "Mémoire saturée sur")) for t in groups)
    single = [s for s in sigs if s.attributes["kind"] == "alert"]
    assert any(": Espace disque faible (C:)" in s.title for s in single)
    assert {s.severity for s in single} <= {2, 3}  # gravité NONE → sévérité selon le type


def test_tickets_carry_no_personal_column(sigs: list[Signal]) -> None:
    tickets = [s for s in sigs if s.attributes["kind"] == "ticket"]
    assert len(tickets) == 19 and {s.severity for s in tickets} == {2}  # priorité NONE
    assert all(s.attributes["status"] == "Ouvert" for s in tickets)
    assert all("Sujet du ticket" in s.title for s in tickets)
