"""Defender : capture réelle anonymisée (tenant WallIndustries, région UE, 2026-10-11).

Échantillon : 51 appareils (15 par domaine + 6 non intégrés), 133 CVE, 1 incident high.
Le certificat et la clé sont générés par le test (jamais ~/vigie-ca)."""

import shutil
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT
from tests.contract.test_defender import make, write_pair
from vigie.connectors.base import Signal, fixture_transport
from vigie.db.enums import Category
from vigie.mapping import RuleMapper

FIXTURES = Path(__file__).parent / "defender"
NOW = datetime(2026, 10, 11, 19, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def sigs(tmp_path_factory: pytest.TempPathFactory) -> list[Signal]:
    d = tmp_path_factory.mktemp("seed")
    shutil.copy(REPO_ROOT / "config" / "companies.example.yaml", d)
    mapper = RuleMapper.from_seed_dir(d)
    c = make(write_pair(tmp_path_factory.mktemp("cert"), 365), fixture_transport(FIXTURES))
    c._now = lambda: NOW
    out = [c.to_signal(r, mapper) for r in c.collect(NOW)]
    assert not c.truncated
    return out


def kind(sigs: list[Signal], k: str) -> list[Signal]:
    return [s for s in sigs if s.attributes.get("kind") == k]


def test_vulnerabilities_capped_per_company_and_explained(sigs: list[Signal]) -> None:
    vulns = kind(sigs, "vulnerability")
    assert Counter(s.company_code for s in vulns) == {"WI": 10, "SPL": 10, "WG": 10}
    for s in vulns:
        a = s.attributes
        assert s.category == Category.vulnerability and len(s.details) <= 1000
        # Chaque vulnérabilité retenue a une raison : exploitation, sensibilité ou critique.
        assert a["public_exploit"] or a["high_value"] or s.severity >= 4, s.title
        assert "192.0.2" not in s.details and "egc-sa.local" not in s.details
    log4j = next(s for s in vulns if s.attributes["cve"] == "CVE-2021-44228")
    assert (log4j.company_code, log4j.severity, log4j.attributes["exploited"]) == ("WG", 5, True)
    # Exploitée mais High, sur postes : sévérité 3 (P3 au barème), en tête de sa société.
    webp = [s for s in vulns if s.attributes["cve"] == "CVE-2023-4863"]
    assert {s.company_code for s in webp} == {"WI", "SPL", "WG"}
    assert {s.severity for s in webp} == {3}


def test_most_critical_first_within_cap(sigs: list[Signal]) -> None:
    vulns = kind(sigs, "vulnerability")
    by_co: dict[str | None, list[float]] = {}
    for s in vulns:
        by_co.setdefault(s.company_code, []).append(s.attributes["criticity"])
    # Plafond : aucune CVE écartée n'est plus critique que la moins critique retenue.
    assert min(by_co["SPL"]) > 15 and min(by_co["WG"]) > 13 and min(by_co["WI"]) > 13


def test_incident_and_inactive_devices(sigs: list[Signal]) -> None:
    [inc] = kind(sigs, "incident")
    assert inc.severity == 5 and inc.category == Category.security
    assert inc.title == "Incident Defender : Suspicious command in RunMRU registry"
    inactive = {s.company_code: s.attributes["count"] for s in kind(sigs, "inactive")}
    assert inactive == {"SPL": 3, "WG": 2, "WI": 2}
