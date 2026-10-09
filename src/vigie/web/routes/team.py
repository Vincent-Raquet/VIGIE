"""Équipe (admin) : personnes, compétences, modèle hebdomadaire, absences (SPEC F1)."""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import FormData

from vigie.db import models
from vigie.db.enums import AbsenceKind, AppRole, SkillPreference
from vigie.engine.calendar import DAY_NAMES_FR, WEEKDAYS
from vigie.engine.settings import load_scoring
from vigie.web.auth import User, audit, require_role
from vigie.web.deps import ADMIN, DB, render

router = APIRouter()
Admin = Annotated[User, Depends(require_role(*ADMIN))]

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[a-z]{2,}$", re.IGNORECASE)
TAG_RE = re.compile(r"^[a-z][a-z0-9_-]{0,49}$")


def skill_tags(session: Session) -> list[str]:
    """Taxonomie (compétences des catégories) + compétences déjà attribuées."""
    cfg = load_scoring(session)
    tags = {t for skills in cfg.category_skill.values() for t in skills}
    tags |= set(session.scalars(select(models.PersonSkill.skill_tag).distinct()))
    return sorted(tags)


@router.get("/equipe")
def team(request: Request, user: Admin, session: DB) -> Response:
    people = session.scalars(
        select(models.Person).order_by(models.Person.active.desc(), models.Person.name)
    ).all()
    skills: dict[tuple[int, str], models.PersonSkill] = {
        (s.person_id, s.skill_tag): s for s in session.scalars(select(models.PersonSkill))
    }
    today = datetime.now(UTC).date()
    absences = session.execute(
        select(models.Absence, models.Person.name)
        .join(models.Person, models.Person.id == models.Absence.person_id)
        .where(models.Absence.end >= today)
        .order_by(models.Absence.start)
    ).all()
    return render(
        request,
        "team.html",
        {
            "people": people,
            "skills": skills,
            "tags": skill_tags(session),
            "absences": absences,
            "kinds": list(AbsenceKind),
            "weekdays": list(zip(WEEKDAYS, DAY_NAMES_FR, strict=True)),
            "flash": request.session.pop("flash", None),
        },
    )


@router.get("/equipe/{person_id:int}")
def person_form(request: Request, user: Admin, session: DB, person_id: int) -> Response:
    person = session.get(models.Person, person_id) if person_id else None
    if person_id and person is None:
        raise HTTPException(status_code=404, detail="Personne introuvable.")
    current = {
        s.skill_tag: s
        for s in session.scalars(
            select(models.PersonSkill).where(models.PersonSkill.person_id == person_id)
        )
    }
    return render(
        request,
        "person.html",
        {
            "person": person,
            "current": current,
            "tags": skill_tags(session),
            "roles": list(AppRole),
            "preferences": list(SkillPreference),
            "weekdays": list(zip(WEEKDAYS, DAY_NAMES_FR, strict=True)),
            "role_skills": session.scalars(
                select(models.RoleSkill).order_by(models.RoleSkill.name)
            ).all(),
        },
    )


def _hours(value: str) -> float:
    hours = float(value.replace(",", ".")) if value.strip() else 0.0
    if not 0 <= hours <= 12:
        raise ValueError
    return hours


def _save_person(session: Session, user: User, person_id: int, form: FormData) -> int:
    def text(name: str, limit: int) -> str:
        value = str(form.get(name) or "").strip()
        if len(value) > limit:
            raise HTTPException(status_code=422, detail=f"Champ {name} trop long.")
        return value

    name, email = text("name", 100), text("email", 254).lower()
    if not name or not EMAIL_RE.match(email):
        raise HTTPException(status_code=422, detail="Nom et e-mail valides obligatoires.")
    try:
        role = AppRole(text("app_role", 20))
        rate = float(text("planning_rate", 6).replace(",", "."))
        pattern = {d: h for d in WEEKDAYS if (h := _hours(text(f"wp_{d}", 5)))}
        if not 0 < rate <= 1:
            raise ValueError
    except ValueError:
        raise HTTPException(status_code=422, detail="Rôle, taux ou heures invalides.") from None
    role_skill = text("role_skill_id", 12)
    duplicate = session.scalar(
        select(models.Person).where(models.Person.email == email, models.Person.id != person_id)
    )
    if duplicate is not None:
        raise HTTPException(status_code=422, detail="Cet e-mail est déjà utilisé.")

    person = session.get(models.Person, person_id) if person_id else None
    if person_id and person is None:
        raise HTTPException(status_code=404, detail="Personne introuvable.")
    if person is None:
        person = models.Person(name=name, email=email, app_role=role)
        session.add(person)
    person.name, person.email, person.app_role = name, email, role
    person.job_role = text("job_role", 200)
    person.notes = text("notes", 2000)
    person.weekly_pattern = pattern
    person.planning_rate = rate
    person.active = form.get("active") == "on"
    person.role_skill_id = int(role_skill) if role_skill.isdigit() else None
    session.flush()

    existing = {
        s.skill_tag: s
        for s in session.scalars(
            select(models.PersonSkill).where(models.PersonSkill.person_id == person.id)
        )
    }
    for tag in skill_tags(session):
        try:
            level = int(text(f"skill_{tag}", 1) or 0)
            pref = SkillPreference(text(f"pref_{tag}", 10) or "neutral")
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Compétence {tag} invalide.") from None
        if not 0 <= level <= 3:
            raise HTTPException(status_code=422, detail=f"Niveau de {tag} hors 0 à 3.")
        if level == 0:
            if tag in existing:
                session.delete(existing[tag])
        elif tag in existing:
            existing[tag].level, existing[tag].preference = level, pref
        else:
            session.add(
                models.PersonSkill(person_id=person.id, skill_tag=tag, level=level, preference=pref)
            )
    new_tag = text("new_tag", 50).lower()
    if new_tag:
        if not TAG_RE.match(new_tag):
            raise HTTPException(status_code=422, detail="Nouvelle compétence invalide.")
        if new_tag not in existing:
            session.add(models.PersonSkill(person_id=person.id, skill_tag=new_tag, level=1))
    audit(session, user.email, "person_save", f"person:{person.id}", name=name, role=role.value)
    session.commit()
    return person.id


@router.post("/equipe/{person_id:int}")
async def save_person(request: Request, user: Admin, session: DB, person_id: int) -> Response:
    form = await request.form()
    await run_in_threadpool(_save_person, session, user, person_id, form)
    request.session["flash"] = "Fiche enregistrée."
    return RedirectResponse("/equipe", status_code=303)


@router.post("/equipe/absences")
def add_absence(
    request: Request,
    user: Admin,
    session: DB,
    person_id: Annotated[int, Form()],
    start: Annotated[date, Form()],
    end: Annotated[date, Form()],
    kind: Annotated[AbsenceKind, Form()],
    hours: Annotated[str, Form(max_length=5)] = "",
    note: Annotated[str, Form(max_length=300)] = "",
) -> Response:
    if session.get(models.Person, person_id) is None:
        raise HTTPException(status_code=422, detail="Personne inconnue.")
    if end < start or (end - start).days > 366:
        raise HTTPException(status_code=422, detail="Période invalide.")
    try:
        extra = _hours(hours) if kind is AbsenceKind.extra_day else None
    except ValueError:
        raise HTTPException(status_code=422, detail="Heures invalides.") from None
    if kind is AbsenceKind.extra_day and not extra:
        raise HTTPException(
            status_code=422, detail="Heures obligatoires pour un jour supplémentaire."
        )
    absence = models.Absence(
        person_id=person_id, start=start, end=end, kind=kind, hours=extra, note=note.strip()
    )
    session.add(absence)
    session.flush()
    audit(
        session,
        user.email,
        "absence_add",
        f"absence:{absence.id}",
        person=person_id,
        kind=kind.value,
    )
    session.commit()
    request.session["flash"] = "Absence enregistrée."
    return RedirectResponse("/equipe", status_code=303)


@router.post("/equipe/absences/{absence_id}/supprimer")
def delete_absence(request: Request, user: Admin, session: DB, absence_id: int) -> Response:
    absence = session.get(models.Absence, absence_id)
    if absence is None:
        raise HTTPException(status_code=404, detail="Absence introuvable.")
    details: dict[str, Any] = {"person": absence.person_id, "start": absence.start.isoformat()}
    session.delete(absence)
    audit(session, user.email, "absence_delete", f"absence:{absence_id}", **details)
    session.commit()
    request.session["flash"] = "Absence supprimée."
    return RedirectResponse("/equipe", status_code=303)
