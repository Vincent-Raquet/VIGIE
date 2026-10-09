"""Écrans de configuration : droits par rôle et effets des formulaires."""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.webfixtures import login, person_id
from vigie.db import models
from vigie.db.enums import AbsenceKind, AppRole, MilestoneStatus
from vigie.pause import is_paused, pause_state

pytestmark = pytest.mark.db

PAGES = {
    "/equipe": {AppRole.admin},
    "/equipe/0": {AppRole.admin},
    "/politique": {AppRole.admin, AppRole.manager},
    "/projets": {AppRole.admin, AppRole.manager},
    "/skills": {AppRole.admin},
    "/sources": {AppRole.admin},
    "/parametres": {AppRole.admin},
    "/audit": {AppRole.admin},
    "/signaux": {AppRole.admin, AppRole.manager, AppRole.tech},
}


@pytest.mark.parametrize("role", list(AppRole))
def test_authorization_matrix(client: TestClient, seeded: Session, role: AppRole) -> None:
    login(client, seeded, "Vincent", role)
    for path, allowed in PAGES.items():
        expected = 200 if role in allowed else 403
        assert client.get(path).status_code == expected, (role, path)


def test_mutations_refused_to_other_roles(client: TestClient, seeded: Session) -> None:
    token = login(client, seeded, "Giovanni", AppRole.tech)
    h = {"X-CSRF-Token": token}
    for path in (
        "/equipe/0",
        "/equipe/absences",
        "/politique/regles",
        "/politique/sla",
        "/projets",
        "/projets/jalons",
        "/skills/1",
        "/parametres/pause",
        "/politique/societes/WI",
    ):
        assert client.post(path, headers=h).status_code == 403, path
    token = login(client, seeded, "Vincent", AppRole.manager)
    for path in ("/equipe/0", "/skills/1", "/parametres/pause"):
        assert client.post(path, headers={"X-CSRF-Token": token}).status_code == 403, path


def admin(client: TestClient, seeded: Session) -> dict[str, str]:
    return {"X-CSRF-Token": login(client, seeded, "Vincent", AppRole.admin)}


def person_form(seeded: Session, **overrides: Any) -> dict[str, Any]:
    data = {
        "name": "Sofia", "email": "sofia@example.be", "app_role": "tech", "job_role": "Support",
        "planning_rate": "0,8", "active": "on", "wp_mon": "8", "wp_tue": "4", "skill_support": "2",
        "pref_support": "likes", "skill_reseau": "0", "notes": "Pas de site FWD.",
    }  # fmt: skip
    data.update(overrides)
    return data


def test_create_and_edit_person(client: TestClient, seeded: Session) -> None:
    h = admin(client, seeded)
    r = client.post("/equipe/0", data=person_form(seeded), headers=h)
    assert r.status_code == 303
    sofia = seeded.scalars(select(models.Person).where(models.Person.name == "Sofia")).one()
    assert sofia.weekly_pattern == {"mon": 8.0, "tue": 4.0} and sofia.planning_rate == 0.8
    skills = {
        s.skill_tag: (s.level, s.preference.value)
        for s in seeded.scalars(
            select(models.PersonSkill).where(models.PersonSkill.person_id == sofia.id)
        )
    }
    assert skills == {"support": (2, "likes")}
    r = client.post(
        f"/equipe/{sofia.id}", data=person_form(seeded, skill_support="0", new_tag="sap"), headers=h
    )
    assert r.status_code == 303
    skills = {
        s.skill_tag
        for s in seeded.scalars(
            select(models.PersonSkill).where(models.PersonSkill.person_id == sofia.id)
        )
    }
    assert skills == {"sap"}
    assert "Sofia" in client.get("/equipe").text
    assert "Pas de site FWD." in client.get(f"/equipe/{sofia.id}").text


@pytest.mark.parametrize(
    "bad",
    [
        {"email": "pas-un-email"},
        {"email": "giovanni@example.be"},  # déjà utilisé
        {"planning_rate": "1,5"},
        {"wp_mon": "30"},
        {"app_role": "root"},
        {"skill_support": "7"},
        {"new_tag": "Mauvais Tag"},
        {"name": ""},
    ],
)
def test_person_validation(client: TestClient, seeded: Session, bad: dict[str, str]) -> None:
    assert (
        client.post(
            "/equipe/0", data=person_form(seeded, **bad), headers=admin(client, seeded)
        ).status_code
        == 422
    )


def test_absences(client: TestClient, seeded: Session) -> None:
    h = admin(client, seeded)
    cedric = person_id(seeded, "Cédric")
    data = {
        "person_id": cedric,
        "start": "2099-10-15",
        "end": "2099-10-16",
        "kind": "leave",
        "note": "Congé",
    }
    assert client.post("/equipe/absences", data=data, headers=h).status_code == 303
    absence = seeded.scalars(select(models.Absence)).one()
    assert absence.kind is AbsenceKind.leave
    assert "Congé" in client.get("/equipe").text
    assert (
        client.post("/equipe/absences", data={**data, "end": "2099-10-01"}, headers=h).status_code
        == 422
    )
    assert (
        client.post("/equipe/absences", data={**data, "kind": "extra_day"}, headers=h).status_code
        == 422
    )
    assert (
        client.post(
            "/equipe/absences", data={**data, "kind": "extra_day", "hours": "4"}, headers=h
        ).status_code
        == 303
    )
    absence_id = absence.id
    assert client.post(f"/equipe/absences/{absence_id}/supprimer", headers=h).status_code == 303
    seeded.expire_all()
    assert seeded.get(models.Absence, absence_id) is None
    assert client.post("/equipe/absences/999999/supprimer", headers=h).status_code == 404


def test_policy_axes_rules_companies_sla(client: TestClient, seeded: Session) -> None:
    h = {"X-CSRF-Token": login(client, seeded, "Vincent", AppRole.manager)}
    axis = {
        "title": "Migration M365 SPL",
        "weight": "4",
        "categories": ["m365"],
        "keywords": "exchange, teams",
        "valid_from": "2026-10-01",
        "valid_to": "2027-03-31",
    }
    assert client.post("/politique/axes", data=axis, headers=h).status_code == 303
    row = seeded.scalars(
        select(models.PolicyAxis).where(models.PolicyAxis.title == axis["title"])
    ).one()
    assert (row.weight, row.categories, row.keywords) == (4, ["m365"], ["exchange", "teams"])
    assert (
        client.post(
            "/politique/axes", data={**axis, "axis_id": row.id, "weight": "2"}, headers=h
        ).status_code
        == 303
    )
    seeded.refresh(row)
    assert row.weight == 2
    assert (
        client.post("/politique/axes", data={**axis, "categories": ["nope"]}, headers=h).status_code
        == 422
    )
    assert (
        client.post(
            "/politique/axes", data={**axis, "valid_to": "2026-01-01"}, headers=h
        ).status_code
        == 422
    )
    assert (
        client.post("/politique/axes", data={**axis, "weight": "9"}, headers=h).status_code == 422
    )
    assert client.post(f"/politique/axes/{row.id}/supprimer", headers=h).status_code == 303

    assert (
        client.post(
            "/politique/regles", data={"text": "Pas de patch le vendredi."}, headers=h
        ).status_code
        == 303
    )
    rule = seeded.scalars(
        select(models.PolicyRule).where(models.PolicyRule.text == "Pas de patch le vendredi.")
    ).one()
    assert client.post(f"/politique/regles/{rule.id}/basculer", headers=h).status_code == 303
    seeded.refresh(rule)
    assert (rule.active, rule.version) == (False, 2)

    assert (
        client.post("/politique/societes/WG", data={"criticality": "1.4"}, headers=h).status_code
        == 303
    )
    assert seeded.get(models.Company, "WG").criticality == 1.4  # type: ignore[union-attr]
    assert (
        client.post("/politique/societes/WG", data={"criticality": "3"}, headers=h).status_code
        == 422
    )
    assert (
        client.post(
            "/politique/sla", data={"p1": "2", "p2": "8", "p3": "48", "p4": "120"}, headers=h
        ).status_code
        == 303
    )
    assert seeded.get(models.Setting, "sla_hours").value == {"P1": 2, "P2": 8, "P3": 48, "P4": 120}  # type: ignore[union-attr]
    assert (
        client.post(
            "/politique/sla", data={"p1": "9", "p2": "8", "p3": "48", "p4": "120"}, headers=h
        ).status_code
        == 422
    )
    page = client.get("/politique").text
    assert "sla_save" in page and "company_save" in page  # historique


def test_projects_and_milestones(client: TestClient, seeded: Session) -> None:
    h = admin(client, seeded)
    project = {"name": "Migration M365 SPL", "status": "active", "priority": "high",
               "owner_id": str(person_id(seeded, "Giovanni")), "companies": ["SPL"]}  # fmt: skip
    assert client.post("/projets", data=project, headers=h).status_code == 303
    row = seeded.scalars(select(models.Project).where(models.Project.name == project["name"])).one()
    assert [
        c.company_code
        for c in seeded.scalars(
            select(models.ProjectCompany).where(models.ProjectCompany.project_id == row.id)
        )
    ] == ["SPL"]
    ms = {
        "project_id": row.id,
        "title": "Bascule des boîtes",
        "due": "2099-01-15",
        "effort_h": "400",
        "remaining_h": "400",
        "status": "planned",
        "skill_tags": "m365, support",
    }
    assert client.post("/projets/jalons", data=ms, headers=h).status_code == 303
    m = seeded.scalars(
        select(models.Milestone).where(models.Milestone.title == "Bascule des boîtes")
    ).one()
    assert (m.skill_tags, m.status) == (["m365", "support"], MilestoneStatus.planned)
    assert (
        client.post("/projets/jalons", data={**ms, "remaining_h": "500"}, headers=h).status_code
        == 422
    )
    assert (
        client.post("/projets/jalons", data={**ms, "skill_tags": "Bad Tag"}, headers=h).status_code
        == 422
    )
    assert (
        client.post("/projets", data={**project, "companies": ["XX"]}, headers=h).status_code == 422
    )
    page = client.get("/projets").text
    assert "Bascule des boîtes" in page and "<meter" in page


def test_skill_editor(client: TestClient, seeded: Session) -> None:
    h = admin(client, seeded)
    skill = seeded.scalars(
        select(models.RoleSkill).where(models.RoleSkill.name == "ingenieur-coordinateur")
    ).one()
    page = client.get(f"/skills/{skill.id}").text
    assert "Aperçu" in page and "<h1>" in page  # Markdown rendu
    preview = client.post("/skills/apercu", data={"body_md": "# T\n<script>alert(1)</script> [x](https://evil.test)"},
                          headers={**h, "HX-Request": "true"})  # fmt: skip
    assert (
        "<h1>T</h1>" in preview.text
        and "<script>" not in preview.text
        and "href" not in preview.text
    )
    before = skill.version
    new_body = skill.body_md + "\n## Ajout\nNouvelle consigne.\n"
    r = client.post(
        f"/skills/{skill.id}",
        data={"description": skill.description, "body_md": new_body},
        headers=h,
    )
    assert r.status_code == 303
    seeded.refresh(skill)
    assert skill.version == before + 1
    versions = seeded.scalars(
        select(models.RoleSkillVersion).where(models.RoleSkillVersion.role_skill_id == skill.id)
    ).all()
    assert {v.version for v in versions} == {before, before + 1}
    diff = client.get(f"/skills/{skill.id}", params={"diff": before}).text
    assert '<span class="add">+Nouvelle consigne.</span>' in diff
    export = client.get(f"/skills/{skill.id}/export")
    assert export.headers["content-disposition"].endswith('ingenieur-coordinateur-SKILL.md"')
    assert export.text.startswith("---\nname: ingenieur-coordinateur\n")
    assert client.get(f"/skills/{skill.id}", params={"diff": 99}).status_code == 404


def test_pause(client: TestClient, seeded: Session) -> None:
    h = admin(client, seeded)
    assert not is_paused(seeded, "collect")
    assert client.post("/parametres/pause", data={"collect": "on"}, headers=h).status_code == 303
    assert pause_state(seeded) == {"collect": True, "plan": False}
    assert is_paused(seeded, "collect") and not is_paused(seeded, "plan")
    assert is_paused(seeded, "plan", config_paused=True)
    assert "checked" in client.get("/parametres").text
