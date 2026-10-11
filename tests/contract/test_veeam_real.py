"""Veeam : capture réelle anonymisée (VBR 13, rôle Backup Viewer, 2026-10-11) → signaux."""

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr

from tests.conftest import REPO_ROOT
from vigie.connectors.base import ConnectorContext, Signal, fixture_transport
from vigie.connectors.veeam import VeeamConnector
from vigie.mapping import RuleMapper

FIXTURES = Path(__file__).parent / "veeam"
NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)  # capture : 2026-10-11 vers 13:50 (UTC+2)


@pytest.fixture(scope="module")
def sigs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Signal]:
    d = tmp_path_factory.mktemp("seed")
    shutil.copy(REPO_ROOT / "config" / "companies.example.yaml", d)
    mapper = RuleMapper.from_seed_dir(d)
    ctx = ConnectorContext(
        settings={"base_url": "https://vbr.test:9419"},
        secret=lambda name: SecretStr("fixture-password"),
        transport=fixture_transport(FIXTURES),
    )
    c = VeeamConnector.from_context(ctx)
    c._now = lambda: NOW
    return {s.title: s for s in (c.to_signal(r, mapper) for r in c.collect(NOW))}


def test_only_real_backup_problems_are_signalled(sigs: dict[str, Signal]) -> None:
    assert sorted((s.severity, s.company_code, s.title) for s in sigs.values()) == [
        (2, "SPL", "Veeam — Job en avertissement : SPL - Backup vers SPL - SOBR -PVE"),
        (3, None, "Veeam — Rétention en échec : Retention job"),
        (4, "WI", "Veeam — Copie de sauvegarde en échec : WI - Backup Copy vers NAS EXT"),
        (4, "WI", "Veeam — Job en échec : WI - Backup vers WI - SOBR"),
    ]
    # Ignorés : découverte de volumes, test d'identifiants, analyse de conformité (bruit),
    # réplication dont l'échec « (Full) » a été suivi de passages réussis.
    assert not any("Discovery" in t or "Credentials" in t or "REPLICATION" in t for t in sigs)


def test_backup_copy_lists_the_failed_vm(sigs: dict[str, Signal]) -> None:
    s = sigs["Veeam — Copie de sauvegarde en échec : WI - Backup Copy vers NAS EXT"]
    assert "Objets en échec : " in s.details
    assert "Some restore points were not processed" in s.details
    assert s.attributes["consecutive_failures"] >= 1


def test_proxmox_job_without_last_run_is_not_stale(sigs: dict[str, Signal]) -> None:
    # Jobs Proxmox (type Unknown en 13.x) : lastResult seul, pas de lastRun ni de sessions.
    s = sigs["Veeam — Job en échec : WI - Backup vers WI - SOBR"]
    assert s.attributes["last_result"] == "Failed"
    assert s.attributes["consecutive_failures"] == 1
