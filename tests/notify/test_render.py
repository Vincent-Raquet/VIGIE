"""Rendu des messages : contenu, échappement, liens construits par l'application."""

import re

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.webfixtures import person_id
from vigie.db import models
from vigie.notify.render import build

pytestmark = pytest.mark.db
BASE = "https://vigie.example.test"
HREF = re.compile(r'href="([^"]+)"')


def test_one_message_per_person_with_tasks_and_recap(
    plans: dict[str, models.Plan], seeded: Session
) -> None:
    bundle = build(seeded, plans["daily"], BASE)
    names = {m.name for m in bundle.messages}
    assert names and names <= {"Vincent", "Giovanni", "Cédric", "Angelo"}
    emails = {p.email for p in seeded.scalars(select(models.Person))}
    assert all(m.to in emails for m in bundle.messages)
    assert bundle.recap is not None and bundle.recap.name == "Vincent"
    m = bundle.messages[0]
    assert m.subject.startswith("[Vigie] [non validé] Plan du vendredi 09/10 — ")
    assert "Plan non validé" in m.html and "PLAN NON VALIDÉ" in m.text
    assert (
        f"{BASE}/aujourdhui?day=2026-10-09" in m.html
        and f"{BASE}/aujourdhui?day=2026-10-09" in m.text
    )


def test_recap_contains_ai_summary_and_counts(
    plans: dict[str, models.Plan], seeded: Session
) -> None:
    recap = build(seeded, plans["daily"], BASE).recap
    assert recap is not None
    assert "Deux urgences réseau." in recap.html and "Capacité système faible." in recap.html
    assert "Relire et valider dans Vigie" in recap.html
    assert "escalade(s)" in recap.text


def test_weekly_groups_by_day(plans: dict[str, models.Plan], seeded: Session) -> None:
    bundle = build(seeded, plans["weekly"], BASE)
    assert any("Mardi 13/10" in m.html or "Lundi 12/10" in m.html for m in bundle.messages)
    assert bundle.messages[0].subject.startswith(
        "[Vigie] [non validé] Plan de la semaine du 12/10 au 16/10"
    )


def test_untrusted_text_is_escaped_and_never_a_link(
    plans: dict[str, models.Plan], seeded: Session
) -> None:
    task = seeded.scalars(
        select(models.Task).where(
            models.Task.plan_id == plans["daily"].id,
            models.Task.assignee_id == person_id(seeded, "Giovanni"),
        )
    ).first()
    assert task is not None
    task.title = '<a href="https://evil.test">clic</a> voir www.evil.test'
    task.actions = ["Ouvrir https://evil.test/login", "<script>alert(1)</script>"]
    seeded.flush()
    gio = next(m for m in build(seeded, plans["daily"], BASE).messages if m.name == "Giovanni")
    assert "<script>" not in gio.html and 'evil.test"' not in gio.html
    assert "https[:]//evil.test/login" in gio.html and "www[.]evil.test" in gio.html
    assert "https[:]//evil.test/login" in gio.text and "www.evil.test" not in gio.text
    for href in HREF.findall(gio.html):
        assert href.startswith(BASE + "/"), href
    assert not re.search(r"https?://(?!vigie\.example\.test)", gio.text)


def test_teams_card_has_no_detail_and_one_link(
    plans: dict[str, models.Plan], seeded: Session
) -> None:
    payload = build(seeded, plans["daily"], BASE).teams
    card = payload["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard"
    assert card["actions"] == [
        {
            "type": "Action.OpenUrl",
            "title": "Ouvrir dans Vigie",
            "url": f"{BASE}/aujourdhui?day=2026-10-09",
        }
    ]
    text = str(card["body"])
    assert "Statut : non validé" in text
    titles = [
        t.title
        for t in seeded.scalars(select(models.Task).where(models.Task.plan_id == plans["daily"].id))
    ]
    assert not any(title in text for title in titles)


def test_links_require_https() -> None:
    from vigie.links import vigie_link

    with pytest.raises(ValueError):
        vigie_link("http://vigie.test", "semaine")
    with pytest.raises(ValueError):
        vigie_link(BASE, "admin")
    assert vigie_link(BASE + "/", "signaux", incident_id=12) == f"{BASE}/signaux/incidents/12"
