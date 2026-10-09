"""Plans quotidien et hebdomadaire sur les fixtures Zabbix et l'équipe d'exemple."""

from datetime import date, timedelta
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.unit.engine.test_pipeline_db import NOW, load_zabbix
from vigie.config import PlansConfig
from vigie.db import models
from vigie.db.enums import PlanKind, PlanStatus, Priority, TaskStatus
from vigie.engine.planner import build_plan, plan_window, run_engine, save_plan
from vigie.engine.render import render_markdown

pytestmark = pytest.mark.db

TZ = ZoneInfo("Europe/Brussels")
FRIDAY = date(2026, 10, 9)  # jour de la capture des fixtures
TUESDAY = date(2026, 10, 13)


@pytest.fixture
def session(db_session: Session) -> Session:
    load_zabbix(db_session)
    run_engine(db_session, NOW)
    return db_session


def names(session: Session) -> dict[int, str]:
    return {p.id: p.name for p in session.scalars(select(models.Person))}


def test_plan_window() -> None:
    assert plan_window(PlanKind.daily, TUESDAY) == [TUESDAY]
    week = plan_window(PlanKind.weekly, TUESDAY)
    assert (week[0], week[-1], len(week)) == (date(2026, 10, 12), date(2026, 10, 16), 5)
    saturday = date(2026, 10, 17)
    assert plan_window(PlanKind.weekly, saturday)[0] == date(2026, 10, 19)


def test_daily_plan_on_friday(session: Session) -> None:
    draft = build_plan(session, PlanKind.daily, FRIDAY, NOW, PlansConfig(), tz=TZ)
    who = names(session)
    assigned = {who[a.person_id] for a in draft.result.assigned if a.person_id}
    # Vendredi : ni Cédric ni Angelo ; Vincent (coordinateur) et Giovanni seuls.
    assert assigned <= {"Vincent", "Giovanni"}
    p1 = [a for a in draft.result.assigned if a.candidate.priority is Priority.P1]
    assert p1 and all(who[a.person_id] == "Vincent" and a.escalation for a in p1)  # type: ignore[index]
    # Suivi du P1 réseau chez Cédric, le jeudi suivant.
    assert any(
        who[a.person_id] == "Cédric" and a.day == date(2026, 10, 15)  # type: ignore[index]
        for a in draft.result.later
    )
    for (person, day), load in draft.result.load.items():
        if not any(a.escalation for a in draft.result.assigned if a.person_id == person):
            assert load <= draft.result.capacity[(person, day)]
    assert draft.new_incidents and draft.new_incidents[0].priority is Priority.P1

    text = render_markdown(draft)
    assert text.startswith("# Plan quotidien — vendredi 09/10/2026")
    assert "## Tâches du jour" in text and "### Vincent" in text
    assert "## Prévu plus tard" in text
    if any(a.candidate.priority.value in ("P3", "P4") for a in draft.result.backlog):
        assert "tâche(s) P3/P4 non planifiée(s) (voir le plan hebdomadaire)" in text


def test_weekly_plan_spreads_work_over_the_week(session: Session) -> None:
    draft = build_plan(session, PlanKind.weekly, TUESDAY, NOW, PlansConfig(), tz=TZ)
    who = names(session)
    by_person = {who[a.person_id] for a in draft.result.assigned if a.person_id}
    assert {"Cédric", "Angelo", "Giovanni"} <= by_person
    days = {a.day for a in draft.result.assigned}
    assert len(days) >= 3
    text = render_markdown(draft)
    assert text.startswith("# Plan hebdomadaire — semaine du 12/10 au 16/10/2026")
    for section in ("## Synthèse", "## Charge par personne et par jour", "## Jalons de projets"):
        assert section in text
    # Jalons d'exemple dans la fenêtre de 21 jours.
    assert any("Maquette configuration FortiGate CC" in c.title for c in draft.milestones)


def test_save_then_carry_over_next_day(session: Session) -> None:
    first = build_plan(session, PlanKind.daily, FRIDAY, NOW, PlansConfig(), tz=TZ)
    plan = save_plan(session, first, render_markdown(first))
    assert (plan.status, plan.kind) == (PlanStatus.draft, PlanKind.daily)
    tasks = session.scalars(select(models.Task).where(models.Task.plan_id == plan.id)).all()
    total = len(first.result.assigned) + len(first.result.later) + len(first.result.backlog)
    assert len(tasks) == total
    linked = session.scalars(select(models.TaskIncident)).all()
    assert linked

    monday = date(2026, 10, 12)
    later_now = NOW + timedelta(days=3)
    second = build_plan(session, PlanKind.daily, monday, later_now, PlansConfig(), tz=TZ)
    carried = [a for a in second.result.assigned + second.result.backlog if a.candidate.carry_count]
    assert carried and all(a.candidate.ref.startswith("carry:") for a in carried)
    # Pas de doublon : chaque incident n'apparaît qu'une fois.
    refs = [
        i for a in second.result.assigned + second.result.backlog for i in a.candidate.incident_ids
    ]
    assert len(refs) == len(set(refs))


def test_done_tasks_are_not_carried(session: Session) -> None:
    first = build_plan(session, PlanKind.daily, FRIDAY, NOW, PlansConfig(), tz=TZ)
    plan = save_plan(session, first, "")
    for task in session.scalars(select(models.Task).where(models.Task.plan_id == plan.id)):
        task.status = TaskStatus.done
    session.flush()
    second = build_plan(
        session, PlanKind.daily, date(2026, 10, 12), NOW + timedelta(days=3), PlansConfig(), tz=TZ
    )
    assert not [a for a in second.result.assigned if a.candidate.carry_count]


def test_source_down_is_reported(session: Session) -> None:
    from vigie.collect import record_failure

    record_failure(session, "zabbix", "zabbix : HTTP 503 (rpc problem.get)", NOW)
    draft = build_plan(session, PlanKind.daily, FRIDAY, NOW, PlansConfig(), tz=TZ)
    assert [s.name for s in draft.sources_down] == ["zabbix"]
    assert "## Sources en panne" in render_markdown(draft)
