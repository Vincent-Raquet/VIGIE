"""Politique IT (admin, manager) : axes pondérés, règles, criticité des sociétés, SLA (F2)."""

from __future__ import annotations

from datetime import date
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select

from vigie.db import models
from vigie.db.enums import Category, Priority
from vigie.engine.settings import load_sla_hours
from vigie.web.auth import User, audit, require_role
from vigie.web.deps import DB, LEADS, render

router = APIRouter()
Lead = Annotated[User, Depends(require_role(*LEADS))]
POLICY_ACTIONS = ("axis_save", "axis_delete", "rule_add", "rule_toggle", "company_save", "sla_save")


def _words(value: str, limit: int = 20) -> list[str]:
    items = [w.strip() for w in value.replace(";", ",").split(",") if w.strip()]
    if len(items) > limit or any(len(w) > 60 for w in items):
        raise HTTPException(status_code=422, detail="Liste trop longue.")
    return items


def _done(request: Request, message: str) -> Response:
    request.session["flash"] = message
    return RedirectResponse("/politique", status_code=303)


@router.get("/politique")
def policy(request: Request, user: Lead, session: DB) -> Response:
    history = session.scalars(
        select(models.AuditLog)
        .where(models.AuditLog.action.in_(POLICY_ACTIONS))
        .order_by(models.AuditLog.at.desc())
        .limit(30)
    ).all()
    return render(
        request,
        "policy.html",
        {
            "axes": session.scalars(
                select(models.PolicyAxis).order_by(models.PolicyAxis.weight.desc())
            ).all(),
            "rules": session.scalars(
                select(models.PolicyRule).order_by(models.PolicyRule.id)
            ).all(),
            "companies": session.scalars(
                select(models.Company).order_by(models.Company.code)
            ).all(),
            "sla": load_sla_hours(session),
            "categories": [c.value for c in Category],
            "priorities": list(Priority),
            "history": history,
            "flash": request.session.pop("flash", None),
        },
    )


@router.post("/politique/axes")
def save_axis(
    request: Request,
    user: Lead,
    session: DB,
    title: Annotated[str, Form(min_length=3, max_length=200)],
    weight: Annotated[int, Form(ge=1, le=5)],
    axis_id: Annotated[int, Form()] = 0,
    description: Annotated[str, Form(max_length=1000)] = "",
    categories: Annotated[list[str] | None, Form()] = None,
    keywords: Annotated[str, Form(max_length=600)] = "",
    valid_from: Annotated[str, Form(max_length=10)] = "",
    valid_to: Annotated[str, Form(max_length=10)] = "",
) -> Response:
    cats = categories or []
    if any(c not in {x.value for x in Category} for c in cats):
        raise HTTPException(status_code=422, detail="Catégorie inconnue.")
    try:
        start = date.fromisoformat(valid_from) if valid_from else None
        end = date.fromisoformat(valid_to) if valid_to else None
    except ValueError:
        raise HTTPException(status_code=422, detail="Dates invalides.") from None
    if start and end and end < start:
        raise HTTPException(status_code=422, detail="Fin avant le début.")
    axis = session.get(models.PolicyAxis, axis_id) if axis_id else None
    if axis_id and axis is None:
        raise HTTPException(status_code=404, detail="Axe introuvable.")
    clash = session.scalar(
        select(models.PolicyAxis).where(
            models.PolicyAxis.title == title.strip(), models.PolicyAxis.id != axis_id
        )
    )
    if clash is not None:
        raise HTTPException(status_code=422, detail="Un axe porte déjà ce titre.")
    if axis is None:
        axis = models.PolicyAxis(title=title.strip(), weight=weight)
        session.add(axis)
    axis.title, axis.weight, axis.description = title.strip(), weight, description.strip()
    axis.categories, axis.keywords = cats, _words(keywords)
    axis.valid_from, axis.valid_to = start, end
    session.flush()
    audit(session, user.email, "axis_save", f"axis:{axis.id}", title=axis.title, weight=weight)
    session.commit()
    return _done(request, "Axe enregistré.")


@router.post("/politique/axes/{axis_id}/supprimer")
def delete_axis(request: Request, user: Lead, session: DB, axis_id: int) -> Response:
    axis = session.get(models.PolicyAxis, axis_id)
    if axis is None:
        raise HTTPException(status_code=404, detail="Axe introuvable.")
    title = axis.title
    for link in session.scalars(
        select(models.ProjectAxis).where(models.ProjectAxis.axis_id == axis_id)
    ):
        session.delete(link)
    session.delete(axis)
    audit(session, user.email, "axis_delete", f"axis:{axis_id}", title=title)
    session.commit()
    return _done(request, "Axe supprimé.")


@router.post("/politique/regles")
def add_rule(
    request: Request,
    user: Lead,
    session: DB,
    text: Annotated[str, Form(min_length=5, max_length=500)],
) -> Response:
    if session.scalar(select(models.PolicyRule).where(models.PolicyRule.text == text.strip())):
        raise HTTPException(status_code=422, detail="Cette règle existe déjà.")
    rule = models.PolicyRule(text=text.strip(), active=True)
    session.add(rule)
    session.flush()
    audit(session, user.email, "rule_add", f"rule:{rule.id}")
    session.commit()
    return _done(request, "Règle ajoutée.")


@router.post("/politique/regles/{rule_id}/basculer")
def toggle_rule(request: Request, user: Lead, session: DB, rule_id: int) -> Response:
    rule = session.get(models.PolicyRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Règle introuvable.")
    rule.active = not rule.active
    rule.version += 1
    audit(session, user.email, "rule_toggle", f"rule:{rule.id}", active=rule.active)
    session.commit()
    return _done(request, "Règle mise à jour.")


@router.post("/politique/societes/{code}")
def save_company(
    request: Request,
    user: Lead,
    session: DB,
    code: str,
    criticality: Annotated[float, Form(ge=0.5, le=1.5)],
) -> Response:
    company = session.get(models.Company, code)
    if company is None:
        raise HTTPException(status_code=404, detail="Société inconnue.")
    before = company.criticality
    company.criticality = round(criticality, 2)
    audit(
        session,
        user.email,
        "company_save",
        f"company:{code}",
        before=before,
        after=company.criticality,
    )
    session.commit()
    return _done(request, f"Criticité de {code} enregistrée.")


@router.post("/politique/sla")
def save_sla(
    request: Request,
    user: Lead,
    session: DB,
    p1: Annotated[int, Form(ge=1, le=720)],
    p2: Annotated[int, Form(ge=1, le=720)],
    p3: Annotated[int, Form(ge=1, le=2160)],
    p4: Annotated[int, Form(ge=1, le=4320)],
) -> Response:
    if not p1 <= p2 <= p3 <= p4:
        raise HTTPException(status_code=422, detail="Les SLA doivent croître de P1 à P4.")
    value = {"P1": p1, "P2": p2, "P3": p3, "P4": p4}
    row = session.get(models.Setting, "sla_hours")
    if row is None:
        session.add(models.Setting(key="sla_hours", value=value))
    else:
        row.value = value
    audit(session, user.email, "sla_save", "setting:sla_hours", **value)
    session.commit()
    return _done(request, "SLA enregistrés.")
