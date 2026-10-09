"""Amorçage de la base depuis `config/` et `roles/` (`vigie seed`).

La base est la source de vérité (SPEC §4) : par défaut le seed crée ce qui manque et ne
modifie jamais l'existant. `update=True` écrase les champs depuis les YAML.
Tout est validé (schémas stricts + références croisées) avant la moindre écriture.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.db import enums, models

SEED_FILES = ("team", "companies", "policy")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_EMAIL_RE = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
_TAG_RE = r"^[a-z0-9_]{1,50}$"

Tag = Annotated[str, Field(pattern=_TAG_RE)]
Hours = Annotated[float, Field(ge=0, le=24)]
Criticality = Annotated[float, Field(ge=0.5, le=1.5)]


class SeedError(Exception):
    """Données d'amorçage absentes ou invalides ; rien n'a été écrit."""


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --- Schémas des fichiers ------------------------------------------------------


class SkillIn(_In):
    level: int = Field(ge=1, le=3)
    preference: enums.SkillPreference = enums.SkillPreference.neutral


class PersonIn(_In):
    name: str = Field(min_length=1, max_length=100)
    email: str = Field(pattern=_EMAIL_RE, max_length=254)
    job_role: str = ""
    app_role: enums.AppRole
    role_skill: str | None = None
    weekly_pattern: dict[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"], Hours] = {}
    planning_rate: float = Field(0.8, gt=0, le=1)
    skills: dict[Tag, Annotated[int, Field(ge=1, le=3)] | SkillIn] = {}
    notes: str = ""

    def skill_items(self) -> list[tuple[str, SkillIn]]:
        return [
            (tag, s if isinstance(s, SkillIn) else SkillIn(level=s))
            for tag, s in self.skills.items()
        ]


class TeamFile(_In):
    people: list[PersonIn]


class CompanyIn(_In):
    code: str = Field(pattern=r"^[A-Z]{2,8}$")
    name: str
    criticality: Criticality = 1.0


class AssetRuleIn(_In):
    source: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    match: enums.MatchType
    pattern: str = Field(min_length=1, max_length=200)
    company: str | None = None
    asset_criticality: Criticality | None = None
    tags: list[Tag] = []

    @model_validator(mode="after")
    def _has_effect(self) -> AssetRuleIn:
        if self.company is None and self.asset_criticality is None:
            raise ValueError("une règle doit porter une société ou une criticité d'actif")
        return self


class CompaniesFile(_In):
    companies: list[CompanyIn]
    asset_rules: list[AssetRuleIn] = []


class AxisIn(_In):
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    weight: int = Field(ge=1, le=5)
    valid_from: date | None = None
    valid_to: date | None = None
    categories: list[enums.Category] = []
    keywords: list[str] = []


class MilestoneIn(_In):
    title: str = Field(min_length=1, max_length=200)
    due: date
    owner: str | None = None
    effort_h: float = Field(0, ge=0)
    remaining_h: float | None = Field(None, ge=0)
    skills: list[Tag] = []
    status: enums.MilestoneStatus = enums.MilestoneStatus.planned
    depends_on: list[str] = []


class ProjectIn(_In):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    sponsor: str = ""
    companies: list[str] = []
    axes: list[str] = []
    owner: str | None = None
    priority: enums.ProjectPriority = enums.ProjectPriority.medium
    status: enums.ProjectStatus = enums.ProjectStatus.proposed
    start: date | None = None
    end: date | None = None
    milestones: list[MilestoneIn] = []


class PolicyFile(_In):
    axes: list[AxisIn] = []
    rules: list[str] = []
    sla_hours: dict[enums.Priority, int] = {}
    projects: list[ProjectIn] = []


class RoleSkillIn(_In):
    name: str = Field(pattern=r"^[a-z0-9-]{1,100}$")
    description: str
    body_md: str


@dataclass
class SeedData:
    team: TeamFile
    companies: CompaniesFile
    policy: PolicyFile
    role_skills: list[RoleSkillIn]
    example_files: list[str] = field(default_factory=list)


@dataclass
class SeedReport:
    counts: dict[str, Counter[str]] = field(default_factory=dict)

    def add(self, entity: str, outcome: str) -> None:
        self.counts.setdefault(entity, Counter())[outcome] += 1

    def total(self, outcome: str) -> int:
        return sum(c[outcome] for c in self.counts.values())


# --- Lecture et validation -------------------------------------------------------


def pick_file(from_dir: Path, stem: str) -> tuple[Path, bool]:
    """`<stem>.yaml` si présent, sinon `<stem>.example.yaml` (données d'exemple)."""
    real = from_dir / f"{stem}.yaml"
    if real.is_file():
        return real, False
    example = from_dir / f"{stem}.example.yaml"
    if example.is_file():
        return example, True
    raise SeedError(f"fichier d'amorçage introuvable : {real} (ni {example.name})")


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SeedError(f"YAML invalide dans {path} : {exc}") from exc
    if not isinstance(data, dict):
        raise SeedError(f"{path} : un dictionnaire YAML est attendu")
    return data


_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n(.*)\Z", re.DOTALL)


def parse_role_skill(path: Path) -> RoleSkillIn:
    text = path.read_text(encoding="utf-8")
    m = _FRONTMATTER_RE.match(text)
    if m is None:
        raise SeedError(f"{path} : frontmatter YAML (--- … ---) attendu")
    try:
        front = yaml.safe_load(m.group(1))
    except yaml.YAMLError as exc:
        raise SeedError(f"{path} : frontmatter invalide : {exc}") from exc
    if not isinstance(front, dict):
        raise SeedError(f"{path} : frontmatter invalide")
    try:
        skill = RoleSkillIn(
            name=front.get("name", ""),
            description=front.get("description", ""),
            body_md=m.group(2).strip() + "\n",
        )
    except ValidationError as exc:
        raise SeedError(f"{path} : {exc}") from exc
    if skill.name != path.parent.name:
        raise SeedError(f"{path} : name={skill.name!r} différent du dossier {path.parent.name!r}")
    return skill


def _validate[T: BaseModel](model: type[T], data: dict[str, Any], path: Path) -> T:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise SeedError(f"{path} invalide :\n{exc}") from exc


def load_seed_data(from_dir: Path, roles_dir: Path) -> SeedData:
    paths = {stem: pick_file(from_dir, stem) for stem in SEED_FILES}
    examples = [path.name for path, is_example in paths.values() if is_example]
    team_path, companies_path, policy_path = (paths[s][0] for s in SEED_FILES)
    data = SeedData(
        team=_validate(TeamFile, _load_yaml(team_path), team_path),
        companies=_validate(CompaniesFile, _load_yaml(companies_path), companies_path),
        policy=_validate(PolicyFile, _load_yaml(policy_path), policy_path),
        role_skills=[parse_role_skill(p) for p in sorted(roles_dir.glob("*/SKILL.md"))],
        example_files=examples,
    )
    check_references(data)
    return data


def _dupes(values: list[str]) -> set[str]:
    return {v for v, n in Counter(values).items() if n > 1}


def check_references(data: SeedData) -> None:
    """Références croisées : toutes les erreurs sont listées d'un coup."""
    errors: list[str] = []
    companies = {c.code for c in data.companies.companies}
    people = {p.name for p in data.team.people}
    skills = {s.name for s in data.role_skills}
    axes = {a.title for a in data.policy.axes}

    for label, values in (
        ("société", [c.code for c in data.companies.companies]),
        ("personne", [p.name for p in data.team.people]),
        ("e-mail", [p.email for p in data.team.people]),
        ("axe", [a.title for a in data.policy.axes]),
        ("règle", data.policy.rules),
        ("projet", [p.name for p in data.policy.projects]),
    ):
        errors += [f"{label} en double : {v}" for v in sorted(_dupes(values))]

    for p in data.team.people:
        if p.role_skill is not None and p.role_skill not in skills:
            errors.append(f"{p.name} : skill de rôle inconnu {p.role_skill!r}")
    for r in data.companies.asset_rules:
        if r.company is not None and r.company not in companies:
            errors.append(f"règle {r.source}/{r.pattern} : société inconnue {r.company!r}")
    for proj in data.policy.projects:
        errors += [
            f"{proj.name} : société inconnue {c!r}" for c in proj.companies if c not in companies
        ]
        errors += [f"{proj.name} : axe inconnu {a!r}" for a in proj.axes if a not in axes]
        if proj.owner is not None and proj.owner not in people:
            errors.append(f"{proj.name} : responsable inconnu {proj.owner!r}")
        titles = {m.title for m in proj.milestones}
        errors += [
            f"{proj.name} : jalon en double {t!r}"
            for t in sorted(_dupes([m.title for m in proj.milestones]))
        ]
        for m in proj.milestones:
            if m.owner is not None and m.owner not in people:
                errors.append(f"{proj.name}/{m.title} : responsable inconnu {m.owner!r}")
            for dep in m.depends_on:
                if dep not in titles or dep == m.title:
                    errors.append(f"{proj.name}/{m.title} : dépendance invalide {dep!r}")
    if errors:
        raise SeedError("références invalides :\n  - " + "\n  - ".join(errors))


# --- Écriture -------------------------------------------------------------------


def _upsert[M: models.Base](
    session: Session,
    report: SeedReport,
    entity: str,
    model: type[M],
    key: dict[str, Any],
    values: dict[str, Any],
    *,
    update: bool,
) -> M:
    obj = session.execute(select(model).filter_by(**key)).scalar_one_or_none()
    if obj is None:
        obj = model(**key, **values)
        session.add(obj)
        session.flush()
        report.add(entity, "created")
    elif update and any(getattr(obj, k) != v for k, v in values.items()):
        for k, v in values.items():
            setattr(obj, k, v)
        session.flush()
        report.add(entity, "updated")
    else:
        report.add(entity, "existing")
    return obj


def _link(session: Session, report: SeedReport, entity: str, obj: models.Base) -> None:
    """Ligne d'association : ajoutée si absente."""
    if session.merge(obj) in session.new:
        report.add(entity, "created")
    else:
        report.add(entity, "existing")


def apply_seed(
    session: Session, data: SeedData, *, update: bool = False, actor: str = "seed"
) -> SeedReport:
    report = SeedReport()
    up = {"update": update}

    skill_ids: dict[str, int] = {}
    for rs in data.role_skills:
        existing = session.execute(
            select(models.RoleSkill).filter_by(name=rs.name)
        ).scalar_one_or_none()
        if existing is None:
            obj = models.RoleSkill(
                name=rs.name,
                description=rs.description,
                body_md=rs.body_md,
                version=1,
                updated_by=actor,
            )
            session.add(obj)
            session.flush()
            session.add(
                models.RoleSkillVersion(
                    role_skill_id=obj.id,
                    version=1,
                    description=rs.description,
                    body_md=rs.body_md,
                    updated_by=actor,
                )
            )
            report.add("role_skill", "created")
        elif update and (existing.body_md, existing.description) != (rs.body_md, rs.description):
            obj = existing
            obj.version += 1
            obj.body_md, obj.description, obj.updated_by = rs.body_md, rs.description, actor
            session.add(
                models.RoleSkillVersion(
                    role_skill_id=obj.id,
                    version=obj.version,
                    description=rs.description,
                    body_md=rs.body_md,
                    updated_by=actor,
                )
            )
            report.add("role_skill", "updated")
        else:
            obj = existing
            report.add("role_skill", "existing")
        skill_ids[rs.name] = obj.id

    for c in data.companies.companies:
        _upsert(
            session,
            report,
            "company",
            models.Company,
            {"code": c.code},
            {"name": c.name, "criticality": c.criticality},
            **up,
        )

    for r in data.companies.asset_rules:
        _upsert(
            session,
            report,
            "asset_rule",
            models.AssetRule,
            {"source": r.source, "match_type": r.match, "pattern": r.pattern},
            {
                "company_code": r.company,
                "asset_criticality": r.asset_criticality,
                "tags": list(r.tags),
            },
            **up,
        )

    person_ids: dict[str, int] = {}
    for p in data.team.people:
        person = _upsert(
            session,
            report,
            "person",
            models.Person,
            {"name": p.name},
            {
                "email": p.email,
                "job_role": p.job_role,
                "app_role": p.app_role,
                "weekly_pattern": dict(p.weekly_pattern),
                "planning_rate": p.planning_rate,
                "notes": p.notes,
                "role_skill_id": skill_ids[p.role_skill] if p.role_skill else None,
            },
            **up,
        )
        person_ids[p.name] = person.id
        for tag, skill in p.skill_items():
            _upsert(
                session,
                report,
                "person_skill",
                models.PersonSkill,
                {"person_id": person.id, "skill_tag": tag},
                {"level": skill.level, "preference": skill.preference},
                **up,
            )

    axis_ids: dict[str, int] = {}
    for a in data.policy.axes:
        axis = _upsert(
            session,
            report,
            "policy_axis",
            models.PolicyAxis,
            {"title": a.title},
            {
                "description": a.description,
                "weight": a.weight,
                "valid_from": a.valid_from,
                "valid_to": a.valid_to,
                "keywords": list(a.keywords),
                "categories": [str(c) for c in a.categories],
            },
            **up,
        )
        axis_ids[a.title] = axis.id

    for text in data.policy.rules:
        _upsert(session, report, "policy_rule", models.PolicyRule, {"text": text}, {}, **up)

    if data.policy.sla_hours:
        _upsert(
            session,
            report,
            "setting",
            models.Setting,
            {"key": "sla_hours"},
            {"value": {str(k): v for k, v in data.policy.sla_hours.items()}},
            **up,
        )

    for proj in data.policy.projects:
        project = _upsert(
            session,
            report,
            "project",
            models.Project,
            {"name": proj.name},
            {
                "description": proj.description,
                "sponsor": proj.sponsor,
                "owner_id": person_ids.get(proj.owner) if proj.owner else None,
                "priority": proj.priority,
                "status": proj.status,
                "start": proj.start,
                "end": proj.end,
            },
            **up,
        )
        for code in proj.companies:
            _link(
                session,
                report,
                "project_company",
                models.ProjectCompany(project_id=project.id, company_code=code),
            )
        for title in proj.axes:
            _link(
                session,
                report,
                "project_axis",
                models.ProjectAxis(project_id=project.id, axis_id=axis_ids[title]),
            )
        milestone_ids: dict[str, int] = {}
        for m in proj.milestones:
            ms = _upsert(
                session,
                report,
                "milestone",
                models.Milestone,
                {"project_id": project.id, "title": m.title},
                {
                    "due": m.due,
                    "owner_id": person_ids.get(m.owner) if m.owner else None,
                    "effort_h": m.effort_h,
                    "remaining_h": m.effort_h if m.remaining_h is None else m.remaining_h,
                    "skill_tags": list(m.skills),
                    "status": m.status,
                },
                **up,
            )
            milestone_ids[m.title] = ms.id
        for m in proj.milestones:
            for dep in m.depends_on:
                _link(
                    session,
                    report,
                    "milestone_dependency",
                    models.MilestoneDependency(
                        milestone_id=milestone_ids[m.title], depends_on_id=milestone_ids[dep]
                    ),
                )

    session.flush()
    session.add(
        models.AuditLog(
            actor=actor,
            action="seed",
            object="config",
            details={
                "update": update,
                "example_files": data.example_files,
                "counts": {k: dict(v) for k, v in sorted(report.counts.items())},
            },
        )
    )
    session.flush()
    return report
