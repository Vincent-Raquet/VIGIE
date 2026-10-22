"""Rendu statique des gabarits Ansible du déploiement, pour les tests de sécurité.

Les variables sont résolues comme le ferait Ansible (defaults → group_vars → vars du rôle),
avec un petit moteur Jinja natif : aucun appel à Ansible, à Docker ni à la VM.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined, Undefined, UndefinedError
from jinja2.nativetypes import NativeEnvironment

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
ROLE = DEPLOY / "roles" / "vigie"
IDS = {"web": "990", "worker": "991", "migrate": "992", "group": "993"}


def native_env() -> NativeEnvironment:
    env = NativeEnvironment(
        loader=FileSystemLoader(ROLE / "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["flatten"] = lambda seq: [x for sub in seq for x in sub]
    env.filters["bool"] = bool
    env.filters["unique"] = lambda seq: list(dict.fromkeys(seq))  # liste, comme Ansible
    env.filters["to_json"] = json.dumps
    env.filters["strftime"] = time.strftime
    return env


def resolve(value: Any, ctx: dict[str, Any], env: NativeEnvironment) -> Any:
    if isinstance(value, str) and "{{" in value:
        result = env.from_string(value).render(ctx)
        if isinstance(result, Undefined):  # Jinja natif renvoie l'objet au lieu de lever
            raise UndefinedError(f"non résolu : {value}")
        return list(result) if isinstance(result, Iterator) else result
    if isinstance(value, list):
        return [resolve(v, ctx, env) for v in value]
    if isinstance(value, dict):
        return {k: resolve(v, ctx, env) for k, v in value.items()}
    return value


def templated(value: Any) -> bool:
    if isinstance(value, str):
        return "{{" in value
    if isinstance(value, list):
        return any(templated(v) for v in value)
    if isinstance(value, dict):
        return any(templated(v) for v in value.values())
    return False


def context(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    env = native_env()
    ctx: dict[str, Any] = {}
    for path in (
        ROLE / "defaults" / "main.yml",
        DEPLOY / "group_vars" / "vigie.yml",
        ROLE / "vars" / "main.yml",
    ):
        ctx.update(yaml.safe_load(path.read_text(encoding="utf-8")))
    ctx.update(overrides or {})
    ctx.update(
        vigie_release="1.0.0-test",
        playbook_dir=str(DEPLOY),
        ansible_managed="test",
        # Faits lus sur la VM par le rôle (getent) : UID des comptes vigie-* et GID de vigie.
        vigie_ids=IDS,
    )
    # Résolution par passes : une variable n'est rendue qu'avec des variables déjà résolues.
    while pending := [k for k, v in ctx.items() if templated(v)]:
        done = {k: v for k, v in ctx.items() if not templated(v)}
        progress = False
        for key in pending:
            try:
                ctx[key] = resolve(ctx[key], done, env)
                progress = True
            except Exception:  # noqa: S112 - variable dépendant d'une autre non résolue
                continue
        assert progress, f"variables non résolues : {pending}"
    return ctx


def render(template: str, ctx: dict[str, Any], role: str = "vigie", **extra: Any) -> str:
    # Rendu texte (pas natif) : le fichier tel qu'il sera écrit sur la VM.
    env = Environment(  # noqa: S701 - fichiers de configuration, pas de HTML
        loader=FileSystemLoader(DEPLOY / "roles" / role / "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["to_json"] = json.dumps
    env.filters["bool"] = bool
    return env.get_template(template).render({**ctx, **extra})


def directives(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith(("#", "[")):
            key, _, value = line.partition("=")
            out.setdefault(key.strip(), []).append(value.strip())
    return out


def task_vars(task_name: str, ctx: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    """Variables passées au gabarit par la tâche du rôle, rendues comme Ansible le ferait :
    le test suit ainsi exactement le rôle (`omit`, absent ici, ferait échouer le rendu)."""
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    task = next(t for t in tasks if t["name"] == task_name)
    return {k: resolve(v, {**ctx, "item": item}, native_env()) for k, v in task["vars"].items()}
