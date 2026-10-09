"""Skills de rôle (admin) : éditeur Markdown avec aperçu, versions, diff, export (F4)."""

from __future__ import annotations

import difflib
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from sqlalchemy import select

from vigie.db import models
from vigie.web.auth import User, audit, require_role
from vigie.web.deps import ADMIN, DB, render
from vigie.web.markdown import render_markdown_safe

router = APIRouter()
Admin = Annotated[User, Depends(require_role(*ADMIN))]
MAX_BODY = 50_000


def _skill(session: DB, skill_id: int) -> models.RoleSkill:
    skill = session.get(models.RoleSkill, skill_id)
    if skill is None:
        raise HTTPException(status_code=404, detail="Skill introuvable.")
    return skill


def _versions(session: DB, skill_id: int) -> list[models.RoleSkillVersion]:
    return list(
        session.scalars(
            select(models.RoleSkillVersion)
            .where(models.RoleSkillVersion.role_skill_id == skill_id)
            .order_by(models.RoleSkillVersion.version.desc())
        )
    )


@router.get("/skills")
def skills(request: Request, user: Admin, session: DB) -> Response:
    rows = session.scalars(select(models.RoleSkill).order_by(models.RoleSkill.name)).all()
    users = {
        p.role_skill_id: p.name for p in session.scalars(select(models.Person)) if p.role_skill_id
    }
    return render(
        request,
        "skills.html",
        {"skills": rows, "users": users, "flash": request.session.pop("flash", None)},
    )


@router.get("/skills/{skill_id:int}")
def edit_skill(
    request: Request,
    user: Admin,
    session: DB,
    skill_id: int,
    diff: Annotated[int | None, Query(ge=1)] = None,
) -> Response:
    skill = _skill(session, skill_id)
    versions = _versions(session, skill_id)
    diff_lines: list[tuple[str, str]] = []
    if diff is not None:
        old = next((v for v in versions if v.version == diff), None)
        if old is None:
            raise HTTPException(status_code=404, detail="Version introuvable.")
        for line in difflib.unified_diff(
            old.body_md.splitlines(), skill.body_md.splitlines(),
            f"version {old.version}", f"version {skill.version} (actuelle)", lineterm="",
        ):  # fmt: skip
            kind = "add" if line.startswith("+") else "del" if line.startswith("-") else ""
            diff_lines.append((kind, line))
    return render(
        request,
        "skill_edit.html",
        {
            "skill": skill,
            "versions": versions,
            "preview": render_markdown_safe(skill.body_md),
            "diff": diff,
            "diff_lines": diff_lines,
        },
    )


@router.post("/skills/apercu")
def preview(
    request: Request, user: Admin, body_md: Annotated[str, Form(max_length=MAX_BODY)] = ""
) -> Response:
    return render(request, "_markdown.html", {"html": render_markdown_safe(body_md)})


@router.post("/skills/{skill_id:int}")
def save_skill(
    request: Request,
    user: Admin,
    session: DB,
    skill_id: int,
    description: Annotated[str, Form(max_length=1000)],
    body_md: Annotated[str, Form(min_length=1, max_length=MAX_BODY)],
) -> Response:
    skill = _skill(session, skill_id)
    body = body_md.replace("\r\n", "\n").strip() + "\n"
    if (skill.body_md, skill.description) == (body, description.strip()):
        request.session["flash"] = "Aucune modification."
        return RedirectResponse(f"/skills/{skill.id}", status_code=303)
    skill.version += 1
    skill.body_md, skill.description, skill.updated_by = body, description.strip(), user.email
    session.add(
        models.RoleSkillVersion(
            role_skill_id=skill.id,
            version=skill.version,
            description=skill.description,
            body_md=body,
            updated_by=user.email,
        )
    )
    audit(session, user.email, "role_skill_save", f"role_skill:{skill.name}", version=skill.version)
    session.commit()
    request.session["flash"] = f"Version {skill.version} enregistrée."
    return RedirectResponse("/skills", status_code=303)


@router.get("/skills/{skill_id:int}/export")
def export_skill(user: Admin, session: DB, skill_id: int) -> Response:
    skill = _skill(session, skill_id)
    description = skill.description.replace("\n", " ")
    content = f"---\nname: {skill.name}\ndescription: {description}\n---\n\n{skill.body_md}"
    return PlainTextResponse(
        content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{skill.name}-SKILL.md"'},
    )
