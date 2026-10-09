"""Unités systemd du déploiement (SECURITY.md C7, C8, C10) : rendu statique des gabarits du
rôle Ansible `vigie` et vérification du sandboxing et de la répartition des secrets.

Les variables sont résolues comme le ferait Ansible (defaults → group_vars → vars du rôle),
avec un petit moteur Jinja natif : aucun appel à Ansible ni à la VM.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from jinja2.nativetypes import NativeEnvironment

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
ROLE = DEPLOY / "roles" / "vigie"

SANDBOX = {
    "NoNewPrivileges": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "PrivateTmp": "yes",
    "PrivateDevices": "yes",
    "ProtectKernelTunables": "yes",
    "ProtectKernelModules": "yes",
    "ProtectKernelLogs": "yes",
    "ProtectControlGroups": "yes",
    "RestrictNamespaces": "yes",
    "RestrictSUIDSGID": "yes",
    "LockPersonality": "yes",
    "MemoryDenyWriteExecute": "yes",
    "SystemCallArchitectures": "native",
    "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
    "CapabilityBoundingSet": "",
    "IPAddressDeny": "any",
}
SOURCE_SECRETS = {"zabbix_api_token"}
# Secrets autorisés par unité : tout ce qui n'est pas listé ici est interdit.
ALLOWED = {
    "vigie-web.service": {"web_session_key", "entra_client_secret"},
    "vigie-collect@.service": set(),
    "vigie-plan@.service": {"anthropic_api_key"},
    "vigie-notify@.service": {"graph_certificate", "teams_webhook_url"},
    "vigie-jobs.service": SOURCE_SECRETS,
    "vigie-housekeeping.service": set(),
    "vigie-selfcheck.service": set(),
}
ALL_ON = {
    "vigie_llm_enabled": True,
    "vigie_notify_mail_enabled": True,
    "vigie_notify_teams_enabled": True,
    "vigie_oidc": {"tenant_id": "t", "client_id": "c", "groups": {}},
}


def _env() -> NativeEnvironment:
    env = NativeEnvironment(
        loader=FileSystemLoader(ROLE / "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["flatten"] = lambda seq: [x for sub in seq for x in sub]
    env.filters["bool"] = bool
    env.filters["unique"] = lambda seq: list(dict.fromkeys(seq))  # liste, comme Ansible
    return env


def _resolve(value: Any, ctx: dict[str, Any], env: NativeEnvironment) -> Any:
    if isinstance(value, str) and "{{" in value:
        result = env.from_string(value).render(ctx)
        return list(result) if isinstance(result, Iterator) else result
    if isinstance(value, list):
        return [_resolve(v, ctx, env) for v in value]
    if isinstance(value, dict):
        return {k: _resolve(v, ctx, env) for k, v in value.items()}
    return value


def _templated(value: Any) -> bool:
    if isinstance(value, str):
        return "{{" in value
    if isinstance(value, list):
        return any(_templated(v) for v in value)
    if isinstance(value, dict):
        return any(_templated(v) for v in value.values())
    return False


def _context(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    env = _env()
    ctx: dict[str, Any] = {}
    for path in (
        ROLE / "defaults" / "main.yml",
        DEPLOY / "group_vars" / "vigie.yml",
        ROLE / "vars" / "main.yml",
    ):
        ctx.update(yaml.safe_load(path.read_text(encoding="utf-8")))
    ctx.update(overrides or {})
    ctx.update(vigie_release="1.0.0-test", playbook_dir=str(DEPLOY), ansible_managed="test")
    # Résolution par passes : une variable n'est rendue qu'avec des variables déjà résolues.
    while pending := [k for k, v in ctx.items() if _templated(v)]:
        done = {k: v for k, v in ctx.items() if not _templated(v)}
        progress = False
        for key in pending:
            try:
                ctx[key] = _resolve(ctx[key], done, env)
                progress = True
            except Exception:  # noqa: S112 - variable dépendant d'une autre non résolue
                continue
        assert progress, f"variables non résolues : {pending}"
    return ctx


def _render(template: str, ctx: dict[str, Any], **extra: Any) -> str:
    # Rendu texte (pas natif) : le fichier tel qu'il sera écrit sur la VM.
    env = Environment(  # noqa: S701 - unités systemd, pas de HTML
        loader=FileSystemLoader(ROLE / "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env.get_template(template).render({**ctx, **extra})


def _directives(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith(("#", "[")):
            key, _, value = line.partition("=")
            out.setdefault(key.strip(), []).append(value.strip())
    return out


def _units(ctx: dict[str, Any]) -> dict[str, str]:
    units = {"vigie-web.service": _render("units/vigie-web.service.j2", ctx)}
    for unit in ctx["vigie_worker_units"]:
        params = {
            "unit_credentials": [],
            "unit_proxy": False,
            "unit_ips": [],
            "unit_timeout": "15min",
            **{k: v for k, v in unit.items() if k.startswith("unit_")},
        }
        units[unit["name"]] = _render("units/vigie-worker.service.j2", ctx, **params)
    return units


def _credentials(text: str) -> set[str]:
    return {v.split(":", 1)[0] for v in _directives(text).get("LoadCredentialEncrypted", [])}


@pytest.fixture(params=["config par défaut", "tout activé"])
def ctx(request: pytest.FixtureRequest) -> dict[str, Any]:
    return _context(ALL_ON if request.param == "tout activé" else None)


def test_every_unit_is_listed_and_sandboxed(ctx: dict[str, Any]) -> None:
    units = _units(ctx)
    assert set(units) == set(ALLOWED)
    for name, text in units.items():
        d = _directives(text)
        for key, expected in SANDBOX.items():
            assert key in d, f"{name} : {key} manquant"
            assert d[key][-1] == expected, f"{name} : {key}={d[key][-1]!r}"
        assert d["SystemCallFilter"][0] == "@system-service", name
        assert d["User"] in (["vigie-web"], ["vigie-worker"]), name
        assert "ReadWritePaths" not in d, f"{name} : écriture disque non prévue"
    # Directive placée après le bloc inclus : vérifie qu'aucune ligne n'a été recollée.
    selfcheck = _directives(units["vigie-selfcheck.service"])
    assert selfcheck["StateDirectory"] == ["vigie/selfcheck"]


def test_credentials_are_limited_per_unit(ctx: dict[str, Any]) -> None:
    for name, text in _units(ctx).items():
        creds = _credentials(text)
        assert creds <= ALLOWED[name], f"{name} reçoit {creds - ALLOWED[name]}"
        for value in _directives(text).get("LoadCredentialEncrypted", []):
            cred, _, path = value.partition(":")
            assert path == f"/etc/credstore.encrypted/vigie.{cred}"


def test_web_never_gets_source_or_llm_secrets() -> None:
    text = _units(_context(ALL_ON))["vigie-web.service"]
    assert _credentials(text) == {"web_session_key", "entra_client_secret"}
    d = _directives(text)
    assert d["User"] == ["vigie-web"]
    assert d["IPAddressAllow"] == ["localhost"]
    assert d["Environment"][0] == f"HTTPS_PROXY=http://127.0.0.1:{_context()['squid_web_port']}"


def test_disabled_features_load_no_secret() -> None:
    off = _context(
        {
            "vigie_llm_enabled": False,
            "vigie_notify_mail_enabled": False,
            "vigie_notify_teams_enabled": False,
        }
    )
    units = _units(off)
    assert _credentials(units["vigie-plan@.service"]) == set()
    assert _credentials(units["vigie-notify@.service"]) == set()
    assert "anthropic_api_key" not in off["vigie_required_secrets"]


def test_collect_dropin_gives_only_its_source_secret_and_addresses() -> None:
    ctx = _context()
    for source in ctx["vigie_sources_enabled"]:
        text = _render("units/credentials.conf.j2", ctx, source=source)
        assert _credentials(text) == set(source["secrets"])
        allowed = _directives(text)["IPAddressAllow"][0].split()
        egress = {e["ip"] for e in ctx["vigie_source_egress"] if e["name"] == source["name"]}
        assert set(allowed) == set(ctx["dns_servers"]) | egress


def test_only_internet_units_use_the_worker_proxy(ctx: dict[str, Any]) -> None:
    port = ctx["squid_worker_port"]
    for name, text in _units(ctx).items():
        has_proxy = f"HTTPS_PROXY=http://127.0.0.1:{port}" in text
        assert has_proxy == (name in {"vigie-plan@.service", "vigie-notify@.service"}), name


def test_timers_are_persistent_and_reference_existing_units() -> None:
    ctx = _context()
    services = {u["name"] for u in ctx["vigie_worker_units"]}
    for timer in ctx["vigie_timers"]:
        params = {k: v for k, v in timer.items() if k.startswith("timer_")}
        text = _render("units/timer.j2", ctx, **params)
        unit = _directives(text)["Unit"][0]
        template = re.sub(r"@[^.]+\.", "@.", unit)
        assert template in services, f"{timer['name']} → {unit}"
        if "timer_calendar" in params:
            assert "Persistent=true" in text


def test_secret_script_validates_names_and_never_echoes_values() -> None:
    script = (ROLE / "files" / "vigie-secret").read_text(encoding="utf-8")
    assert "*[!a-z0-9_]*" in script
    assert "systemd-creds encrypt" in script
    assert not re.search(r"echo[^\n]*\$\(cat", script)
    assert "set -x" not in script
