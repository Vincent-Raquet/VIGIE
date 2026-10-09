"""Diffusion : allowlist, rodage, canaux, publication, idempotence, simulation, CLI."""

import email
from email import policy
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from tests.webfixtures import person_id
from vigie.cli import app
from vigie.config import GeneralConfig, NotifyConfig, VigieConfig
from vigie.db import models
from vigie.db.enums import PlanStatus
from vigie.notify.dispatch import NotifyError, allowed_recipients, dispatch, select_plan

pytestmark = pytest.mark.db
BASE = "https://vigie.example.test"


def cfg(**notify: Any) -> VigieConfig:
    values = {"mail_enabled": True, "teams_enabled": True, "draft_only": False, **notify}
    return VigieConfig(general=GeneralConfig(base_url=BASE), notify=NotifyConfig(**values))


class FakeMailer:
    def __init__(self, fail_for: str | None = None) -> None:
        self.sent: list[tuple[str, str]] = []
        self.fail_for = fail_for

    def send(self, to: str, name: str, subject: str, html: str) -> None:
        if to == self.fail_for:
            raise RuntimeError("HTTP 503")
        self.sent.append((to, subject))


class FakeTeams:
    def __init__(self, fail: bool = False) -> None:
        self.payloads: list[dict[str, Any]] = []
        self.fail = fail

    def send(self, payload: dict[str, Any]) -> None:
        if self.fail:
            raise RuntimeError("HTTP 500")
        self.payloads.append(payload)


def test_select_plan(plans: dict[str, models.Plan], seeded: Session) -> None:
    assert select_plan(seeded, "latest-daily").id == plans["daily"].id
    assert select_plan(seeded, "latest-weekly").id == plans["weekly"].id
    assert select_plan(seeded, str(plans["daily"].id)).id == plans["daily"].id
    for bad in ("999999", "tous", "1;DROP"):
        with pytest.raises(NotifyError):
            select_plan(seeded, bad)


def test_sends_publishes_and_audits(plans: dict[str, models.Plan], seeded: Session) -> None:
    plan = plans["daily"]
    mailer, teams = FakeMailer(), FakeTeams()
    report = dispatch(seeded, plan, cfg(), mailer=mailer, teams=teams)
    assert report.ok and report.published and report.teams == "envoyé"
    recipients = {to for to, _ in mailer.sent}
    assert recipients <= set(allowed_recipients(seeded))
    lead_email = seeded.get(models.Person, person_id(seeded, "Vincent")).email  # type: ignore[union-attr]
    assert any(s.endswith("récapitulatif") for to, s in mailer.sent if to == lead_email)
    assert plan.status is PlanStatus.published and plan.published_at is not None
    assert "notified_at" in plan.data
    audit = seeded.scalars(
        select(models.AuditLog).where(models.AuditLog.action == "notify_sent")
    ).one()
    assert audit.details["mails"] == len(mailer.sent) and audit.details["teams"] == "envoyé"
    assert "@" not in str(audit.details)  # aucune adresse dans le journal
    with pytest.raises(NotifyError, match="déjà diffusé"):
        dispatch(seeded, plan, cfg(), mailer=mailer, teams=teams)
    assert dispatch(seeded, plan, cfg(), mailer=FakeMailer(), teams=FakeTeams(), force=True).ok


def test_inactive_people_are_never_mailed(plans: dict[str, models.Plan], seeded: Session) -> None:
    gio = seeded.get(models.Person, person_id(seeded, "Giovanni"))
    assert gio is not None
    gio.active = False
    seeded.flush()
    mailer = FakeMailer()
    report = dispatch(seeded, plans["daily"], cfg(), mailer=mailer, teams=FakeTeams())
    assert gio.email not in {to for to, _ in mailer.sent}
    assert report.skipped == 1


def test_draft_only_sends_everything_to_the_coordinator(
    plans: dict[str, models.Plan], seeded: Session
) -> None:
    mailer = FakeMailer()
    dispatch(seeded, plans["daily"], cfg(draft_only=True), mailer=mailer, teams=FakeTeams())
    lead = seeded.get(models.Person, person_id(seeded, "Vincent"))
    assert lead is not None
    assert {to for to, _ in mailer.sent} == {lead.email}
    assert any(s.startswith("[pour Giovanni] [Vigie]") for _, s in mailer.sent)


def test_one_channel_failing_does_not_stop_the_other(
    plans: dict[str, models.Plan], seeded: Session
) -> None:
    gio = seeded.get(models.Person, person_id(seeded, "Giovanni"))
    assert gio is not None
    mailer = FakeMailer(fail_for=gio.email)
    report = dispatch(seeded, plans["daily"], cfg(), mailer=mailer, teams=FakeTeams(fail=True))
    assert not report.ok
    assert report.mails == len(mailer.sent) > 0
    assert report.mail_errors and report.mail_errors[0].startswith("Giovanni : RuntimeError")
    assert report.teams.startswith("erreur")
    assert report.published  # au moins un e-mail est parti


def test_nothing_delivered_nothing_published(
    plans: dict[str, models.Plan], seeded: Session
) -> None:
    plan = plans["weekly"]
    report = dispatch(seeded, plan, cfg(mail_enabled=False), teams=FakeTeams(fail=True))
    assert (
        not report.published and plan.status is PlanStatus.draft and "notified_at" not in plan.data
    )


def test_missing_channels_configuration(plans: dict[str, models.Plan], seeded: Session) -> None:
    with pytest.raises(NotifyError, match="Graph"):
        dispatch(seeded, plans["daily"], cfg(), teams=FakeTeams())
    with pytest.raises(NotifyError, match="Teams"):
        dispatch(seeded, plans["daily"], cfg(), mailer=FakeMailer())


def test_dry_run_writes_files(
    plans: dict[str, models.Plan], seeded: Session, tmp_path: Path
) -> None:
    report = dispatch(seeded, plans["daily"], cfg(mail_sender="itbot@example.be"), out_dir=tmp_path)
    names = sorted(p.name for p in report.written)
    assert "teams.json" in names and any(n.endswith(".eml") for n in names)
    eml = next(p for p in report.written if p.suffix == ".eml")
    parsed = email.message_from_string(eml.read_text(), policy=policy.default)
    assert parsed["From"] == "itbot@example.be"
    assert {part.get_content_type() for part in parsed.iter_parts()} == {"text/plain", "text/html"}
    assert plans["daily"].status is PlanStatus.draft  # simulation : rien n'est publié


def test_cli_notify_dry_run(
    plans: dict[str, models.Plan], seeded: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.conftest import TEST_DB_URL

    config = tmp_path / "vigie.toml"
    config.write_text(f'[database]\nurl = "{TEST_DB_URL}"\n\n[general]\nbase_url = "{BASE}"\n')
    out = tmp_path / "out"
    # La CLI ouvre sa propre connexion : le plan doit être visible hors de la transaction du test.
    monkeypatch.setattr("vigie.cli.make_engine", lambda url: seeded.get_bind())  # type: ignore[arg-type]
    monkeypatch.setattr("sqlalchemy.engine.Connection.dispose", lambda self: None, raising=False)
    result = CliRunner().invoke(
        app,
        [
            "--config",
            str(config),
            "notify",
            "--plan",
            "latest-daily",
            "--dry-run",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Simulation (rodage : tout au coordinateur)" in result.output
    assert (out / "teams.json").exists()
