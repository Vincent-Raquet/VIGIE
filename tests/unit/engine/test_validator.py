"""Validateur de la proposition du LLM : rejet élément par élément, jamais du plan entier."""

from datetime import UTC, datetime
from typing import Any

import pytest

from tests.scenarios.team import MONDAY, THURSDAY, TUESDAY, team
from vigie.db.enums import Category, PlanKind, Priority
from vigie.engine.assign import Candidate, assign
from vigie.engine.llm_schema import LLMPlan
from vigie.engine.planner import PlanDraft
from vigie.engine.validator import has_link, validate

TEAM = team()
V, G, C, A = (TEAM[n] for n in ("Vincent", "Giovanni", "Cédric", "Angelo"))
NOW = datetime(2026, 10, 12, 6, 0, tzinfo=UTC)


def cand(ref: str, priority: Priority, skills: list[str], incident: int, **kw: Any) -> Candidate:
    base: dict[str, Any] = {
        "ref": ref,
        "title": f"Titre {ref}",
        "category": Category.server,
        "priority": priority,
        "score": 30,
        "estimate_h": 1,
        "skills": skills,
        "incident_ids": [incident],
    }
    base.update(kw)
    return Candidate(**base)


def draft(window: list[Any] | None = None) -> PlanDraft:
    window = window or [MONDAY]
    tasks = [
        cand("incident:1", Priority.P1, ["reseau"], 1, due=window[0]),
        cand("incident:2", Priority.P3, ["support"], 2),
        cand("incident:3", Priority.P3, ["support"], 3),
        cand("incident:4", Priority.P3, ["sap"], 4),  # backlog : personne compétente
    ]
    result = assign(tasks, list(TEAM.values()), window)
    return PlanDraft(
        kind=PlanKind.daily,
        period_start=window[0],
        period_end=window[-1],
        generated_at=NOW,
        window=window,
        members={m.id: m for m in TEAM.values()},
        result=result,
    )


def task(ref: str, priority: str = "P3", **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ref": ref,
        "title": f"Nouveau titre {ref}",
        "actions": [],
        "priority": priority,
        "assignee_id": None,
        "estimate_h": 1,
        "due": None,
        "incident_ids": [],
        "milestone_id": None,
        "rationale": "",
    }
    base.update(kw)
    return base


def plan(*tasks: dict[str, Any], **kw: Any) -> LLMPlan:
    data: dict[str, Any] = {
        "summary_exec": "Semaine chargée.",
        "per_person": [],
        "tasks": list(tasks),
        "risks": [],
        "escalations": [],
    }
    data.update(kw)
    return LLMPlan.model_validate(data)


def assigned(refined: Any) -> dict[str, Any]:
    return {a.candidate.ref: a for a in refined.draft.result.assigned}


def test_texts_and_actions_are_kept_without_changing_assignment() -> None:
    d = draft()
    before = {a.candidate.ref: (a.person_id, a.day) for a in d.result.assigned}
    out = validate(
        d,
        plan(task("incident:2", actions=["Appeler l'utilisateur", "Vérifier le poste"])),
    )
    got = assigned(out)["incident:2"]
    assert got.candidate.title == "Nouveau titre incident:2"
    assert got.candidate.actions == ["Appeler l'utilisateur", "Vérifier le poste"]
    assert got.candidate.by_llm
    assert {r: (a.person_id, a.day) for r, a in assigned(out).items()} == before
    assert out.summary_exec == "Semaine chargée."
    assert not out.rejections


def test_omitted_tasks_keep_their_deterministic_form() -> None:
    d = draft()
    out = validate(d, plan())
    assert [a.candidate.title for a in out.draft.result.assigned] == [
        a.candidate.title for a in d.result.assigned
    ]
    assert len(out.draft.result.backlog) == 1


def test_valid_reassignment_moves_load() -> None:
    d = draft()
    original = assigned(validate(d, plan()))["incident:3"]
    assert original.person_id == G.id
    out = validate(d, plan(task("incident:3", assignee_id=V.id, rationale="Giovanni chargé")))
    moved = assigned(out)["incident:3"]
    assert (moved.person_id, moved.day) == (V.id, MONDAY)
    assert moved.rationale.startswith("Réaffecté à Vincent sur proposition de l'IA, validée")
    assert out.draft.result.load[(G.id, MONDAY)] == d.result.load[(G.id, MONDAY)] - 1
    assert out.draft.result.load[(V.id, MONDAY)] == d.result.load[(V.id, MONDAY)] + 1


@pytest.mark.parametrize(
    ("proposal", "reason"),
    [
        (task("incident:1", "P1", assignee_id=C.id), "absent ou sans capacité"),  # Cédric : jeudi
        (task("incident:1", "P1", assignee_id=G.id), "compétence insuffisante"),  # reseau 1
        (task("incident:3", assignee_id=999), "personne inconnue"),
    ],
)
def test_invalid_reassignments_are_rejected(proposal: dict[str, Any], reason: str) -> None:
    d = draft()
    before = {a.candidate.ref: a.person_id for a in d.result.assigned}
    out = validate(d, plan(proposal))
    assert {r: a.person_id for r, a in assigned(out).items()} == before
    assert any(reason in r for r in out.rejections)


def test_reassignment_respects_capacity() -> None:
    d = draft()
    big = cand("incident:9", Priority.P3, ["support"], 9, estimate_h=6)
    result = assign([big], list(TEAM.values()), [MONDAY])
    d.result.assigned.extend(result.assigned)
    d.result.load[(G.id, MONDAY)] += 6
    # Vincent n'a que 4 h : une tâche de 6 h ne peut pas lui être confiée.
    out = validate(d, plan(task("incident:9", assignee_id=V.id)))
    assert assigned(out)["incident:9"].person_id == G.id
    assert any("sans capacité" in r for r in out.rejections)


def test_backlog_task_can_be_placed_by_the_llm_if_it_fits() -> None:
    d = draft([MONDAY, THURSDAY])
    # incident:4 exige « sap » : personne n'est compétent, la proposition est refusée.
    out = validate(d, plan(task("incident:4", assignee_id=V.id)))
    assert "incident:4" in {a.candidate.ref for a in out.draft.result.backlog}
    assert any("compétence insuffisante" in r for r in out.rejections)


def test_priority_never_lowered_but_can_be_raised() -> None:
    out = validate(draft(), plan(task("incident:1", "P3"), task("incident:2", "P2")))
    got = assigned(out)
    assert got["incident:1"].candidate.priority is Priority.P1
    assert got["incident:2"].candidate.priority is Priority.P2
    assert any("plus basse refusée" in r for r in out.rejections)


@pytest.mark.parametrize(
    "text",
    [
        "Voir https://evil.test/x",
        "Ouvrir www.evil.test",
        "[cliquer](javascript:alert(1))",
        "<img src=x>",
        "Écrire à attacker@evil.test",
        "ftp://files.test",
    ],
)
def test_links_are_refused_everywhere(text: str) -> None:
    assert has_link(text)
    out = validate(
        draft(),
        plan(
            task("incident:2", title=text, actions=[text, "Redémarrer le service"], rationale=text),
            summary_exec=text,
            per_person=[{"person_id": G.id, "summary": text}],
            risks=[{"text": text, "severity": "high"}],
            escalations=[{"text": text, "to": "manager"}],
        ),
    )
    got = assigned(out)["incident:2"]
    assert got.candidate.title == "Titre incident:2"
    assert got.candidate.actions == ["Redémarrer le service"]
    assert out.summary_exec == "" and out.per_person == {}
    assert out.risks == [] and out.escalations == []
    assert len([r for r in out.rejections if "lien ou balise" in r]) >= 6


def test_plain_text_is_not_a_link() -> None:
    for text in (
        "Redémarrer srv-wi-01.corp",
        "Vérifier le VPN WG ↔ WI (tunnel 2)",
        "C: plein à 95 %",
    ):
        assert not has_link(text)


def test_unknown_refs_duplicates_and_incidents() -> None:
    out = validate(
        draft(),
        plan(
            task("incident:2", incident_ids=[2, 4242]),
            task("incident:2", title="Doublon"),
            task("incident:77"),
        ),
    )
    assert assigned(out)["incident:2"].candidate.incident_ids == [2]
    assert any("incidents inconnus [4242]" in r for r in out.rejections)
    assert any("doublon" in r for r in out.rejections)
    assert any("incident:77 : référence inconnue" in r for r in out.rejections)


def test_merging_absorbs_the_other_task_and_frees_its_load() -> None:
    d = draft()
    out = validate(d, plan(task("incident:2", incident_ids=[2, 3])))
    refs = {a.candidate.ref for a in out.draft.result.assigned}
    assert "incident:3" not in refs
    assert assigned(out)["incident:2"].candidate.incident_ids == [2, 3]
    assert out.draft.result.load[(G.id, MONDAY)] == d.result.load[(G.id, MONDAY)] - 1


def test_milestone_change_refused() -> None:
    out = validate(draft(), plan(task("incident:2", milestone_id=5)))
    assert any("jalon 5 refusé" in r for r in out.rejections)


def test_new_tasks_are_capped() -> None:
    news = [
        task(
            f"new-{i}", "P1", assignee_id=G.id, estimate_h=0.5, incident_ids=[2], title=f"Prépa {i}"
        )
        for i in range(1, 8)
    ]
    out = validate(draft([MONDAY, TUESDAY]), plan(*news))
    created = [
        a
        for a in out.draft.result.assigned + out.draft.result.backlog
        if a.candidate.ref.startswith("new-")
    ]
    assert len(created) == 5
    assert all(a.candidate.priority is Priority.P3 for a in created)
    assert all(a.candidate.category is Category.server for a in created)
    assert any("plus de 5 tâches nouvelles" in r for r in out.rejections)


def test_new_task_without_room_goes_to_backlog() -> None:
    out = validate(draft(), plan(task("new-1", assignee_id=C.id, title="Préparer jeudi")))
    [backlog] = [a for a in out.draft.result.backlog if a.candidate.ref == "new-1"]
    assert backlog.person_id is None and backlog.candidate.category is Category.project
    out2 = validate(draft(), plan(task("new-1", title="https://x.test")))
    assert not [a for a in out2.draft.result.backlog if a.candidate.ref == "new-1"]


def test_per_person_unknown_ids_dropped() -> None:
    out = validate(
        draft(),
        plan(
            per_person=[
                {"person_id": G.id, "summary": "Journée support."},
                {"person_id": 99, "summary": "x"},
            ]
        ),
    )
    assert out.per_person == {G.id: "Journée support."}
