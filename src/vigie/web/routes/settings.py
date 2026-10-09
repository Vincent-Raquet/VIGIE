"""Paramètres (admin) : configuration du worker en lecture seule, pause globale, barème."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import ValidationError
from starlette.datastructures import FormData

from vigie.db import models
from vigie.db.enums import Category
from vigie.engine.settings import ScoringConfig, load_scoring
from vigie.pause import pause_state, set_pause
from vigie.web.auth import User, audit, require_role
from vigie.web.deps import ADMIN, DB, render

router = APIRouter()
Admin = Annotated[User, Depends(require_role(*ADMIN))]


@router.get("/parametres")
def settings(request: Request, user: Admin, session: DB) -> Response:
    cfg = request.app.state.cfg
    return render(
        request,
        "settings.html",
        {
            "cfg": cfg,
            "pause": pause_state(session),
            "sources": {name: src.enabled for name, src in sorted(cfg.sources.items())},
            "scoring": load_scoring(session),
            "categories": [c.value for c in Category],
            "flash": request.session.pop("flash", None),
            "error": request.session.pop("scoring_error", None),
        },
    )


@router.post("/parametres/pause")
def save_pause(
    request: Request,
    user: Admin,
    session: DB,
    collect: Annotated[str, Form(max_length=3)] = "",
    plan: Annotated[str, Form(max_length=3)] = "",
) -> Response:
    state = {"collect": collect == "on", "plan": plan == "on"}
    set_pause(session, **state)
    audit(session, user.email, "pause_set", "setting:pause", **state)
    session.commit()
    request.session["flash"] = (
        "Pause enregistrée : le worker la lit avant chaque collecte et chaque plan."
    )
    return RedirectResponse("/parametres", status_code=303)


# --- Barème (rodage, phase 9) -----------------------------------------------------------
# Champs réglables depuis l'interface ; les règles d'override restent dans scoring.yaml.
# (nom du champ de formulaire, chemin dans setting["scoring"], bornes)
CATEGORY_WEIGHT_KEYS = ("default", *(c.value for c in Category))
SCORING_FIELDS: tuple[tuple[str, tuple[str, ...], float, float], ...] = (
    *((f"thr_{p}", ("thresholds", p), 1, 200) for p in ("P1", "P2", "P3")),
    *((f"sev_{n}", ("severity_weight", str(n)), 0, 100) for n in range(6)),
    *((f"cw_{k}", ("category_weight", k), 0.1, 3) for k in CATEGORY_WEIGHT_KEYS),
    *((f"est_{c.value}", ("default_estimate_h", c.value), 0.25, 16) for c in Category),
    ("age_per_day", ("age_factor_per_day",), 0, 0.2),
    ("age_max_days", ("age_factor_max_days",), 0, 60),
)


def _number(raw: str, low: float, high: float) -> float:
    value = float(raw.replace(",", ".").strip())
    if not low <= value <= high:
        raise ValueError
    return value


def _changes(form: FormData) -> list[tuple[tuple[str, ...], float | None]]:
    """(chemin, valeur) des champs envoyés ; poids de catégorie vide = retiré (défaut)."""
    out: list[tuple[tuple[str, ...], float | None]] = []
    for name, path, low, high in SCORING_FIELDS:
        if name not in form:  # champ absent : valeur inchangée
            continue
        raw = str(form.get(name) or "").strip()
        if not raw:
            if path[0] == "category_weight" and path[1] != "default":
                out.append((path, None))
            continue
        try:
            value = _number(raw, low, high)
        except ValueError:
            raise ValueError(f"{name} : nombre entre {low:g} et {high:g} attendu") from None
        out.append((path, int(value) if path == ("age_factor_max_days",) else value))
    return out


@router.post("/parametres/bareme")
async def save_scoring(request: Request, user: Admin, session: DB) -> Response:
    row = session.get(models.Setting, "scoring")
    raw: dict[str, Any] = dict(row.value) if row is not None else {}
    before = ScoringConfig.model_validate(raw).model_dump(mode="json")
    try:
        updated = json_copy(raw)
        for path, value in _changes(await request.form()):
            target = updated
            for key in path[:-1]:
                current = target.get(key)
                target[key] = current = dict(current) if isinstance(current, dict) else {}
                target = current
            if value is None:
                target.pop(path[-1], None)
            else:
                target[path[-1]] = value
        if "severity_weight" not in raw:  # défauts complets pour le contrôle 0 à 5
            updated["severity_weight"] = {
                **before["severity_weight"],
                **updated.get("severity_weight", {}),
            }
        after = ScoringConfig.model_validate(updated).model_dump(mode="json")
    except (ValueError, ValidationError) as exc:
        message = exc.errors()[0]["msg"] if isinstance(exc, ValidationError) else str(exc)
        request.session["scoring_error"] = f"Barème non enregistré : {message}"
        return RedirectResponse("/parametres#bareme", status_code=303)
    changed = {
        key: {"avant": before[key], "après": after[key]}
        for key in after
        if after[key] != before[key]
    }
    if changed:
        if row is None:
            session.add(models.Setting(key="scoring", value=updated))
        else:
            row.value = updated
        audit(session, user.email, "scoring_save", "setting:scoring", changes=changed)
        session.commit()
    request.session["flash"] = (
        "Barème enregistré : il s'applique au prochain plan." if changed else "Barème inchangé."
    )
    return RedirectResponse("/parametres#bareme", status_code=303)


def json_copy(value: dict[str, Any]) -> dict[str, Any]:
    return {k: dict(v) if isinstance(v, dict) else v for k, v in value.items()}
