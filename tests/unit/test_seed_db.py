"""Seed en base : idempotence, --update, rollback (critère d'acceptation de la phase 1)."""

from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from tests.conftest import REPO_ROOT, TEST_DB_URL
from vigie.cli import app
from vigie.db import models
from vigie.seed import CompaniesFile, CompanyIn, RoleSkillIn, SeedData, apply_seed, load_seed_data

pytestmark = pytest.mark.db


@pytest.fixture
def data() -> SeedData:
    return load_seed_data(REPO_ROOT / "config", REPO_ROOT / "roles")


def _count(session: Session, model: type[models.Base]) -> int:
    return session.execute(select(func.count()).select_from(model)).scalar_one()


def test_seed_twice_creates_no_duplicates(db_session: Session, data: SeedData) -> None:
    first = apply_seed(db_session, data)
    assert first.total("created") > 0
    counts = {
        m: _count(db_session, m)
        for m in (
            models.Person,
            models.PersonSkill,
            models.Company,
            models.AssetRule,
            models.Milestone,
            models.RoleSkill,
        )
    }
    second = apply_seed(db_session, data)
    assert second.total("created") == 0
    assert second.total("updated") == 0
    assert second.total("existing") == first.total("created")
    assert counts == {m: _count(db_session, m) for m in counts}
    assert _count(db_session, models.AuditLog) == 2


def test_seed_content(db_session: Session, data: SeedData) -> None:
    apply_seed(db_session, data)
    cedric = db_session.execute(select(models.Person).filter_by(name="Cédric")).scalar_one()
    assert cedric.weekly_pattern == {"thu": 8}
    vincent = db_session.execute(select(models.Person).filter_by(name="Vincent")).scalar_one()
    skill = db_session.get(models.RoleSkill, vincent.role_skill_id)
    assert skill is not None and skill.name == "ingenieur-coordinateur" and skill.version == 1
    milestone = db_session.execute(
        select(models.Milestone).filter_by(title="Bascule en production CC")
    ).scalar_one()
    assert milestone.remaining_h == milestone.effort_h == 8
    sla = db_session.get(models.Setting, "sla_hours")
    assert sla is not None and sla.value["P1"] == 4


def test_existing_rows_are_not_overwritten_without_update(
    db_session: Session, data: SeedData
) -> None:
    apply_seed(db_session, data)
    changed = replace(
        data,
        companies=CompaniesFile(
            companies=[CompanyIn(code="WI", name="WallIndustries", criticality=1.5)],
            asset_rules=[],
        ),
    )
    report = apply_seed(db_session, changed)
    assert report.counts["company"]["existing"] == 1
    assert db_session.get(models.Company, "WI").criticality == 1.0  # type: ignore[union-attr]

    report = apply_seed(db_session, changed, update=True)
    assert report.counts["company"]["updated"] == 1
    assert db_session.get(models.Company, "WI").criticality == 1.5  # type: ignore[union-attr]


def test_update_versions_role_skills(db_session: Session, data: SeedData) -> None:
    apply_seed(db_session, data)
    edited = [
        RoleSkillIn(name=s.name, description=s.description, body_md=s.body_md + "Ajout\n")
        for s in data.role_skills
    ]
    apply_seed(db_session, replace(data, role_skills=edited), update=True)
    skill = db_session.execute(
        select(models.RoleSkill).filter_by(name="responsable-informatique")
    ).scalar_one()
    assert skill.version == 2
    versions = (
        db_session.execute(
            select(models.RoleSkillVersion.version).filter_by(role_skill_id=skill.id)
        )
        .scalars()
        .all()
    )
    assert sorted(versions) == [1, 2]


@pytest.fixture
def test_config(tmp_path: Path, db_engine: Engine) -> Path:
    path = tmp_path / "vigie.toml"
    path.write_text(f'[database]\nurl = "{TEST_DB_URL}"\n')
    return path


def test_cli_dry_run_writes_nothing(test_config: Path, db_engine: Engine) -> None:
    result = CliRunner().invoke(
        app,
        [
            "--config",
            str(test_config),
            "seed",
            "--dry-run",
            "--from",
            str(REPO_ROOT / "config"),
            "--roles",
            str(REPO_ROOT / "roles"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Simulation" in result.output
    assert "données d'exemple" in result.output
    with Session(db_engine) as session:
        assert _count(session, models.Person) == 0


def test_cli_seed_invalid_data(test_config: Path, tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app, ["--config", str(test_config), "seed", "--from", str(tmp_path)]
    )
    assert result.exit_code == 1
    assert "introuvable" in result.output


def test_cli_check_reports_database(test_config: Path) -> None:
    result = CliRunner().invoke(app, ["--config", str(test_config), "check"])
    assert result.exit_code == 0, result.output
    assert "Base : OK (révision 0012, à jour)" in result.output


def test_seed_stores_scoring_setting(db_session: Session, data: SeedData) -> None:
    from vigie.db.enums import Priority
    from vigie.engine.settings import ScoringConfig, load_scoring, load_sla_hours

    apply_seed(db_session, data)
    assert load_scoring(db_session) == ScoringConfig()
    assert load_sla_hours(db_session)[Priority.P1] == 4


def test_seed_without_scoring_file_keeps_defaults(db_session: Session, data: SeedData) -> None:
    from vigie.engine.settings import ScoringConfig, load_scoring

    apply_seed(db_session, replace(data, scoring=None))
    assert load_scoring(db_session) == ScoringConfig()


def test_sync_overrides_keeps_ui_settings(db_session: Session) -> None:
    from vigie.engine.settings import DEFAULT_OVERRIDES, ScoringConfig, load_scoring
    from vigie.seed import load_scoring_file, sync_overrides

    # Barème de prod : seuils réglés depuis l'interface, overrides d'un ancien amorçage.
    old = [r.model_dump(mode="json") for r in DEFAULT_OVERRIDES if r.id != "cert_7d"]
    old[0] = {**old[0], "priority": "P2"}
    stale = {**old[1], "id": "obsolete_rule"}
    db_session.add(
        models.Setting(
            key="scoring",
            value={"thresholds": {"P1": 70, "P2": 40, "P3": 15}, "overrides": [*old, stale]},
        )
    )
    db_session.flush()
    _, scoring = load_scoring_file(REPO_ROOT / "config")
    result = sync_overrides(db_session, scoring, actor="test")
    assert result.added == ["cert_7d"] and result.removed == ["obsolete_rule"]
    assert result.changed == [old[0]["id"]]
    loaded = load_scoring(db_session)
    assert loaded.thresholds == {"P1": 70, "P2": 40, "P3": 15}  # réglage de l'interface gardé
    assert [r.id for r in loaded.overrides] == [r.id for r in scoring.overrides]
    assert db_session.scalars(
        select(models.AuditLog).where(models.AuditLog.action == "scoring_overrides_sync")
    ).first()
    assert not sync_overrides(db_session, scoring).any  # idempotent
    assert ScoringConfig.model_validate(db_session.get(models.Setting, "scoring").value)


def test_cli_overrides_dry_run(test_config: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "--config",
            str(test_config),
            "overrides",
            "--from",
            str(REPO_ROOT / "config"),
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Règles lues dans" in result.output
    assert "Barème déjà à jour." in result.output or "Simulation" in result.output
