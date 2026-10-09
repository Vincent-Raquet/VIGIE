"""Équipe de config/team.example.yaml sous forme de `Member` (scénarios SPEC §7.5)."""

from datetime import date

import yaml

from tests.conftest import REPO_ROOT
from vigie.db.enums import AbsenceKind, SkillPreference
from vigie.engine.assign import Member
from vigie.engine.calendar import AbsenceSpan, Availability

MONDAY = date(2026, 10, 12)
TUESDAY = date(2026, 10, 13)
WEDNESDAY = date(2026, 10, 14)
THURSDAY = date(2026, 10, 15)
FRIDAY = date(2026, 10, 16)
WEEK = [MONDAY, TUESDAY, WEDNESDAY, THURSDAY, FRIDAY]


def team(absences: dict[str, list[AbsenceSpan]] | None = None) -> dict[str, Member]:
    data = yaml.safe_load((REPO_ROOT / "config" / "team.example.yaml").read_text())
    members = {}
    for i, p in enumerate(data["people"], start=1):
        skills = {}
        for tag, value in p["skills"].items():
            if isinstance(value, dict):
                skills[tag] = (value["level"], SkillPreference(value.get("preference", "neutral")))
            else:
                skills[tag] = (value, SkillPreference.neutral)
        members[p["name"]] = Member(
            id=i,
            name=p["name"],
            skills=skills,
            availability=Availability(
                person_id=i,
                weekly_pattern=p["weekly_pattern"],
                planning_rate=p["planning_rate"],
                absences=tuple((absences or {}).get(p["name"], [])),
            ),
            is_coordinator=p.get("role_skill") == "ingenieur-coordinateur",
        )
    return members


def leave(start: date, end: date) -> AbsenceSpan:
    return AbsenceSpan(start, end, AbsenceKind.leave)
