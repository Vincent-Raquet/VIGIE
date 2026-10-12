"""FortiAnalyzer 8.0.0 : capture réelle anonymisée (2026-10-12, 3 FortiGate, ADOM root).

Échantillon : 112 alertes non acquittées de l'Event Monitor (toutes les détections rares,
6 par handler d'usage et par appareil), 3 appareils (`conn_status` 0, sans HA).
"""

import shutil
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr

from tests.conftest import REPO_ROOT
from vigie.connectors.base import ConnectorContext, Signal, fixture_transport
from vigie.connectors.fortianalyzer import FortiAnalyzerConnector
from vigie.db.enums import Category
from vigie.mapping import RuleMapper

FIXTURES = Path(__file__).parent / "fortianalyzer"
NOW = datetime(2026, 10, 12, 19, 0, tzinfo=UTC)


def collect(ignore: list[str]) -> list[Signal]:
    ctx = ConnectorContext(
        settings={"base_url": "https://FAZVMSTM25009422", "ignore_groupby": ignore},
        secret=lambda name: SecretStr("fixture-key"),
        transport=fixture_transport(FIXTURES),
    )
    c = FortiAnalyzerConnector.from_context(ctx)
    c._now = lambda: NOW
    raws = list(c.collect(NOW))
    assert not c.truncated
    return [c.to_signal(r, MAPPER) for r in raws]


@pytest.fixture(scope="module", autouse=True)
def _mapper(tmp_path_factory: pytest.TempPathFactory) -> None:
    global MAPPER
    d = tmp_path_factory.mktemp("seed")
    shutil.copy(REPO_ROOT / "config" / "companies.example.yaml", d)
    MAPPER = RuleMapper.from_seed_dir(d)


MAPPER: RuleMapper


def test_every_signal_attached_and_minimised() -> None:
    sigs = collect(["app:NinjaOne"])
    assert Counter(s.company_code for s in sigs) == {"WI": 5, "SPL": 5, "WG": 6, None: 1}
    for s in sigs:
        assert "user-" not in s.details  # noms d'utilisateurs masqués
        assert "192.0.2." not in s.details  # adresses masquées
        assert len(s.details) <= 1000
    [faz] = [s for s in sigs if s.company_code is None]
    assert (faz.asset, faz.category) == ("FAZVM64-TEST", Category.firewall)
    # conn_status 0 (« inconnu ») partout : aucun signal d'appareil.
    assert not [s for s in sigs if s.attributes.get("kind") in ("device_down", "ha_degraded")]


def test_detections_and_minor_usage() -> None:
    sigs = {(s.attributes["trigger"], s.asset): s for s in collect(["app:NinjaOne"])}
    ioc = sigs[("Compromised Host Detection by IOC", "WG-Forti")]
    assert (ioc.category, ioc.severity, ioc.company_code) == (Category.security, 4, "WG")
    recon = sigs[("Recon Activity Detection By Endpoint", "WI-FORTI")]
    assert (recon.category, recon.severity) == (Category.security, 3)
    exfil = sigs[("Data Exfiltration over Remote Services", "SPL-Forti")]
    assert exfil.category is Category.security
    minor = [s for (t, _), s in sigs.items() if t.startswith(("Risky App", "Risky Destination"))]
    assert minor and {s.severity for s in minor} == {2}
    app = sigs[("Risky App Detection by Source Endpoint", "SPL-Forti")]
    assert "Regroupement : " in app.details


def test_ignored_groupby_removes_ninjaone() -> None:
    def risky(sigs: list[Signal]) -> int:
        return sum(s.attributes["count"] for s in sigs if "Risky App" in s.attributes["trigger"])

    with_ninja, without = collect([]), collect(["app:NinjaOne"])
    # 18 alertes NinjaOne vues par poste et les mêmes 18 vues par menace.
    assert risky(with_ninja) - risky(without) == 36
    assert all("NinjaOne" not in s.details for s in without)
