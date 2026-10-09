"""Pause globale (SPEC F11) : `[general] paused` dans vigie.toml, ou interrupteur de l'UI
(`setting["pause"] = {"collect": bool, "plan": bool}`), lu par le worker avant d'agir."""

from __future__ import annotations

from typing import Literal

from sqlalchemy.orm import Session

from vigie.db import models

PAUSE_KEY = "pause"
Activity = Literal["collect", "plan"]


def pause_state(session: Session) -> dict[str, bool]:
    row = session.get(models.Setting, PAUSE_KEY)
    value = row.value if row is not None and isinstance(row.value, dict) else {}
    return {"collect": bool(value.get("collect")), "plan": bool(value.get("plan"))}


def is_paused(session: Session, activity: Activity, *, config_paused: bool = False) -> bool:
    return config_paused or pause_state(session)[activity]


def set_pause(session: Session, *, collect: bool, plan: bool) -> None:
    row = session.get(models.Setting, PAUSE_KEY)
    value = {"collect": collect, "plan": plan}
    if row is None:
        session.add(models.Setting(key=PAUSE_KEY, value=value))
    else:
        row.value = value
    session.flush()
