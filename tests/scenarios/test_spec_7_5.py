"""Scénarios d'affectation de la SPEC §7.5 avec l'équipe d'exemple."""

from datetime import date

from tests.scenarios.team import MONDAY, THURSDAY, TUESDAY, WEDNESDAY, WEEK, team
from vigie.db.enums import Category, Priority
from vigie.engine.assign import Candidate, assign

TEAM = team()
VINCENT, GIOVANNI, CEDRIC, ANGELO = (
    TEAM[n].id for n in ("Vincent", "Giovanni", "Cédric", "Angelo")
)


def vpn_down() -> Candidate:
    return Candidate(
        ref="incident:1",
        title="VPN WG ↔ WI down",
        category=Category.network,
        priority=Priority.P1,
        score=70,
        estimate_h=2,
        skills=["reseau"],
        incident_ids=[1],
    )


def veeam_spl(due: date) -> Candidate:
    return Candidate(
        ref="incident:2",
        title="Job Veeam SPL-Daily en échec",
        category=Category.backup,
        priority=Priority.P2,
        score=45,
        estimate_h=1.5,
        skills=["backup"],
        due=due,
        incident_ids=[2],
    )


def test_vpn_down_on_tuesday_escalates_and_plans_root_cause_on_thursday() -> None:
    result = assign([vpn_down()], list(TEAM.values()), [TUESDAY])
    [task] = result.assigned
    assert (task.person_id, task.day, task.escalation) == (VINCENT, TUESDAY, True)
    assert task.rationale.startswith(
        "Escalade : aucun spécialiste (reseau) disponible ; Assigné à Vincent"
    )
    [follow] = result.later
    assert (follow.person_id, follow.day) == (CEDRIC, THURSDAY)
    assert follow.candidate.title == "Analyse de cause racine : VPN WG ↔ WI down"
    assert follow.candidate.priority is Priority.P3


def test_vpn_down_on_thursday_goes_to_cedric() -> None:
    result = assign([vpn_down()], list(TEAM.values()), [THURSDAY])
    [task] = result.assigned
    assert (task.person_id, task.escalation) == (CEDRIC, False)
    assert task.rationale == (
        "Assigné à Cédric : compétence reseau niveau 3, présent jeudi, charge 2/6,4 h"
    )
    assert not result.later


def test_veeam_spl_goes_to_angelo_on_tuesday() -> None:
    result = assign([veeam_spl(WEDNESDAY)], list(TEAM.values()), [TUESDAY])
    assert [(a.person_id, a.escalation) for a in result.assigned] == [(ANGELO, False)]


def test_veeam_spl_goes_to_coordinator_when_angelo_is_absent() -> None:
    result = assign([veeam_spl(THURSDAY)], list(TEAM.values()), [WEDNESDAY])
    [task] = result.assigned
    assert (task.person_id, task.escalation) == (VINCENT, True)
    assert task.rationale.startswith("Escalade : spécialiste absent ; Assigné à Vincent")


def test_tickets_and_patches_go_to_giovanni() -> None:
    tickets = [
        Candidate(
            f"incident:t{i}",
            f"Ticket {i}",
            Category.user_support,
            Priority.P3,
            20,
            0.5,
            ["support"],
        )
        for i in range(8)
    ]
    patches = [
        Candidate(
            f"incident:p{c}",
            f"Postes {c} : patchs manquants",
            Category.vulnerability,
            Priority.P3,
            25,
            3,
            ["patching"],
        )
        for c in ("WI", "SPL", "WG")
    ]
    result = assign(tickets + patches, list(TEAM.values()), WEEK)
    assert {a.person_id for a in result.assigned} == {GIOVANNI}
    assert len(result.assigned) == 11 and not result.backlog
    # Au plus 5 tâches par jour : les tickets débordent sur le mardi.
    per_day: dict[date, int] = {}
    for a in result.assigned:
        assert a.day is not None
        per_day[a.day] = per_day.get(a.day, 0) + 1
    assert max(per_day.values()) <= 5
    assert min(per_day) == MONDAY
