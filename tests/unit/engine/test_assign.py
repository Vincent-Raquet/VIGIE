from dataclasses import replace
from datetime import date

from tests.scenarios.team import FRIDAY, MONDAY, THURSDAY, TUESDAY, WEDNESDAY, WEEK, leave, team
from vigie.db.enums import Category, Priority, SkillPreference
from vigie.engine.assign import Candidate, Member, assign, milestone_at_risk
from vigie.engine.calendar import Availability

TEAM = team()
V, G, C, A = (TEAM[n] for n in ("Vincent", "Giovanni", "Cédric", "Angelo"))


def task(
    ref: str, priority: Priority = Priority.P3, skills: list[str] | None = None, **kw: object
) -> Candidate:
    base: dict[str, object] = {
        "ref": ref,
        "title": f"Tâche {ref}",
        "category": Category.server,
        "priority": priority,
        "score": 20,
        "estimate_h": 1,
        "skills": ["systeme"] if skills is None else skills,
    }
    base.update(kw)
    return Candidate(**base)  # type: ignore[arg-type]


def test_member_level_and_preference() -> None:
    assert V.level(["reseau", "support"]) == 1
    assert G.level(["fortinet"]) == 0
    assert G.level([]) == 1
    picky = replace(
        G, skills={"poste": (3, SkillPreference.likes), "m365": (2, SkillPreference.avoid)}
    )
    assert picky.preference(["poste"]) == 0
    assert picky.preference(["poste", "m365"]) == 2


def test_p1_requires_level_two() -> None:
    # Giovanni a reseau 1 : suffisant pour un P3, pas pour un P1.
    p3 = assign([task("x", skills=["reseau"])], list(TEAM.values()), [MONDAY])
    assert [a.person_id for a in p3.assigned] == [G.id]
    p1 = assign([task("x", Priority.P1, skills=["reseau"])], list(TEAM.values()), [MONDAY])
    assert [(a.person_id, a.escalation) for a in p1.assigned] == [(V.id, True)]


def test_no_competent_person_goes_to_backlog() -> None:
    result = assign([task("x", skills=["sap"])], list(TEAM.values()), WEEK)
    [item] = result.backlog
    assert item.person_id is None
    assert item.rationale == "Non planifiée : aucune personne compétente"


def test_capacity_exhausted_goes_to_backlog() -> None:
    tasks = [task(f"t{i}", skills=["fortinet"], estimate_h=2) for i in range(5)]
    result = assign(tasks, list(TEAM.values()), [MONDAY])
    # Cédric absent lundi ; Vincent (recours) a 4 h : deux tâches, le reste en backlog.
    assert [a.person_id for a in result.assigned] == [V.id, V.id]
    assert all(a.rationale.startswith("Recours : ") for a in result.assigned)
    assert len(result.backlog) == 3
    assert result.backlog[0].rationale.endswith("capacité insuffisante des personnes compétentes")


def test_max_tasks_per_day() -> None:
    tasks = [task(f"t{i}", skills=["support"], estimate_h=0.25) for i in range(7)]
    result = assign(tasks, list(TEAM.values()), [MONDAY], max_tasks_per_day=5)
    assert [a.person_id for a in result.assigned].count(G.id) == 5


def test_preferred_owner_wins_even_if_coordinator() -> None:
    owned = task("m", skills=["backup"], preferred_id=V.id, milestone_id=1)
    result = assign([owned], list(TEAM.values()), [TUESDAY])
    assert [a.person_id for a in result.assigned] == [V.id]


def test_carry_over_escalation_flag() -> None:
    result = assign([task("c", skills=["support"], carry_count=4)], list(TEAM.values()), [MONDAY])
    [a] = result.assigned
    assert a.escalation and "reportée 4 fois : escalade vers le coordinateur" in a.rationale


def test_p2_waits_for_specialist_within_sla() -> None:
    p2 = task("f", Priority.P2, skills=["fortinet"], due=THURSDAY)
    result = assign([p2], list(TEAM.values()), [MONDAY])
    [later] = result.later
    assert (later.person_id, later.day) == (C.id, THURSDAY)
    assert later.rationale.startswith("Prévue le jeudi 15/10 chez Cédric")
    # Échéance avant jeudi : coordinateur.
    urgent = assign([replace(p2, due=TUESDAY)], list(TEAM.values()), [MONDAY])
    assert [(a.person_id, a.escalation) for a in urgent.assigned] == [(V.id, True)]


def test_p1_never_waits_past_its_due_date() -> None:
    window = [TUESDAY, WEDNESDAY, THURSDAY, FRIDAY]
    p1 = task("vpn", Priority.P1, skills=["reseau"], estimate_h=2, due=TUESDAY)
    result = assign([p1], list(TEAM.values()), window)
    # Échéance mardi : escalade au coordinateur, suivi chez Cédric jeudi (dans la fenêtre).
    assert [(a.person_id, a.day, a.escalation) for a in result.assigned] == [
        (V.id, TUESDAY, True),
        (C.id, THURSDAY, False),
    ]
    # Sans échéance, le spécialiste du jeudi est un candidat ordinaire.
    relaxed = assign([replace(p1, due=None)], list(TEAM.values()), window)
    assert [(a.person_id, a.day) for a in relaxed.assigned] == [(C.id, THURSDAY)]


def test_follow_up_booked_in_window_when_escalated() -> None:
    absent = team({"Cédric": [leave(MONDAY, WEDNESDAY)]})
    tasks = [task("vpn", Priority.P1, skills=["reseau"], estimate_h=2)]
    # Fenêtre mardi + jeudi, Cédric en congé mardi seulement → il est candidat jeudi.
    result = assign(tasks, list(absent.values()), [TUESDAY, THURSDAY])
    assert [(a.person_id, a.day) for a in result.assigned] == [(C.id, THURSDAY)]
    # Fenêtre mardi seule : escalade, suivi jeudi hors fenêtre.
    escalated = assign(tasks, list(absent.values()), [TUESDAY])
    assert escalated.assigned[0].person_id == V.id
    assert [(a.person_id, a.day) for a in escalated.later] == [(C.id, THURSDAY)]


def test_follow_up_inside_window_is_booked() -> None:
    tasks = [task("vpn", Priority.P1, skills=["reseau"], estimate_h=7)]  # trop long pour Cédric
    result = assign(tasks, list(TEAM.values()), [TUESDAY, THURSDAY])
    assert [(a.person_id, a.day, a.candidate.follow_up) for a in result.assigned] == [
        (V.id, TUESDAY, False),
        (C.id, THURSDAY, True),
    ]


def test_p1_when_coordinator_absent_still_escalates() -> None:
    away = team({"Vincent": [leave(MONDAY, FRIDAY)]})
    result = assign([task("x", Priority.P1, skills=["fortinet"])], list(away.values()), [MONDAY])
    [a] = result.assigned
    assert (a.person_id, a.day, a.escalation) == (V.id, MONDAY, True)


def test_team_without_coordinator() -> None:
    members = [m for m in TEAM.values() if not m.is_coordinator]
    result = assign([task("x", Priority.P1, skills=["fortinet"])], members, [MONDAY])
    assert result.backlog and not result.assigned


def test_unknown_skill_member_level_zero_and_ordering_by_priority() -> None:
    p4 = task("low", Priority.P4, skills=["support"], estimate_h=6)
    p1 = task("high", Priority.P1, skills=["support"], estimate_h=6, score=90)
    result = assign([p4, p1], list(TEAM.values()), [MONDAY])
    # Le P1 passe d'abord et prend la capacité de Giovanni.
    assert result.assigned[0].candidate.ref == "high"
    assert result.assigned[0].person_id == G.id


def test_milestone_at_risk() -> None:
    members = list(TEAM.values())
    risk = milestone_at_risk(1, "Bascule CC", THURSDAY, 25, ["fortinet"], members, MONDAY)
    assert risk is not None and risk.capacity_h == round(6.4 + 4 * 4, 2)
    assert milestone_at_risk(1, "x", THURSDAY, 5, ["fortinet"], members, MONDAY) is None
    late = milestone_at_risk(1, "x", date(2026, 10, 1), 1, ["fortinet"], members, MONDAY)
    assert late is not None and late.capacity_h == 0


def test_capacity_and_load_are_reported() -> None:
    lone = Member(
        9, "Solo", {"systeme": (3, SkillPreference.neutral)}, Availability(9, {"mon": 8}, 1.0)
    )
    result = assign([task("x", estimate_h=3)], [lone], [MONDAY])
    assert result.capacity[(9, MONDAY)] == 8
    assert result.load[(9, MONDAY)] == 3
