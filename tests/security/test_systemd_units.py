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
from jinja2 import Environment, FileSystemLoader, StrictUndefined, Undefined, UndefinedError
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
# Secrets de sources connus : seuls autorisés pour vigie-jobs (et chacun pour sa collecte).
SOURCE_SECRETS = {
    "zabbix_api_token",
    "veeam_password",
    "ninjaone_client_id",
    "defender_private_key",
    "ninjaone_client_secret",
}
# Secrets autorisés par unité : tout ce qui n'est pas listé ici est interdit.
ALLOWED = {
    "vigie-web.service": {"web_session_key", "entra_client_secret"},
    "vigie-collect@.service": set(),
    "vigie-plan@.service": {"anthropic_api_key"},
    "vigie-notify@.service": {"graph_certificate", "teams_webhook_url"},
    "vigie-jobs.service": SOURCE_SECRETS,
    "vigie-plan-requests.service": {"anthropic_api_key"},
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
        if isinstance(result, Undefined):  # Jinja natif renvoie l'objet au lieu de lever
            raise UndefinedError(f"non résolu : {value}")
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


def _task_vars(task_name: str, ctx: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    """Variables passées au gabarit par la tâche du rôle, rendues comme Ansible le ferait :
    le test suit ainsi exactement le rôle (`omit`, absent ici, ferait échouer le rendu)."""
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    task = next(t for t in tasks if t["name"] == task_name)
    return {k: _resolve(v, {**ctx, "item": item}, _env()) for k, v in task["vars"].items()}


def _units(ctx: dict[str, Any]) -> dict[str, str]:
    units = {"vigie-web.service": _render("units/vigie-web.service.j2", ctx)}
    for unit in ctx["vigie_worker_units"]:
        params = _task_vars("Services du worker", ctx, unit)
        units[unit["name"]] = _render("units/vigie-worker.service.j2", ctx, **params)
    return units


def _timers(ctx: dict[str, Any]) -> dict[str, str]:
    timers = {
        f"vigie-collect@{s['name']}.timer": _render(
            "units/timer.j2", ctx, **_task_vars("Timers de collecte", ctx, s)
        )
        for s in ctx["vigie_sources_enabled"]
    }
    for timer in ctx["vigie_timers"]:
        params = _task_vars("Autres timers", ctx, timer)
        timers[timer["name"]] = _render("units/timer.j2", ctx, **params)
    return timers


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


def test_credentials_are_exact_when_everything_is_enabled() -> None:
    # Égalité (pas seulement inclusion) : un secret manquant ferait échouer l'unité en prod.
    ctx = _context(ALL_ON)
    expected = {**ALLOWED, "vigie-jobs.service": set(ctx["vigie_source_secrets"])}
    for name, text in _units(ctx).items():
        assert _credentials(text) == expected[name], name


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


@pytest.mark.parametrize("veeam_host", ["", "vbr-01.example.test"])
def test_collect_dropin_gives_only_its_source_secret_and_addresses(veeam_host: str) -> None:
    ctx = _context({"vigie_veeam_host": veeam_host, "vigie_ninjaone_enabled": False})
    names = [s["name"] for s in ctx["vigie_sources_enabled"]]
    assert names == (["zabbix", "veeam"] if veeam_host else ["zabbix"])
    for source in ctx["vigie_sources_enabled"]:
        text = _render("units/credentials.conf.j2", ctx, source=source)
        assert _credentials(text) == set(source["secrets"])
        allowed = _directives(text)["IPAddressAllow"][0].split()
        egress = {e["ip"] for e in ctx["vigie_source_egress"] if e["name"] == source["name"]}
        assert set(allowed) == set(ctx["dns_servers"]) | egress
    if veeam_host:
        jobs = _units(ctx)["vigie-jobs.service"]
        assert _credentials(jobs) == {"zabbix_api_token", "veeam_password"}
        assert "10.10.10.27" in _directives(jobs)["IPAddressAllow"][0].split()


def test_ninjaone_source_goes_through_squid_only() -> None:
    ctx = _context({"vigie_ninjaone_enabled": True})
    [source] = [s for s in ctx["vigie_sources_enabled"] if s["name"] == "ninjaone"]
    assert source["secrets"] == ["ninjaone_client_id", "ninjaone_client_secret"]
    assert "client_id" not in source["settings"]  # jamais dans le dépôt
    assert source["settings"]["proxy"] == f"http://127.0.0.1:{ctx['squid_worker_port']}"
    assert "eu.ninjarmm.com" in ctx["squid_worker_domains"]
    text = _render("units/credentials.conf.j2", ctx, source=source)
    assert _credentials(text) == {"ninjaone_client_id", "ninjaone_client_secret"}
    # Aucune IP directe : seulement le DNS (Squid est joint par la boucle locale).
    assert set(_directives(text)["IPAddressAllow"][0].split()) == set(ctx["dns_servers"])
    assert "ninjaone" not in {e["name"] for e in ctx["vigie_source_egress"]}


def test_defender_source_certificate_and_key_only() -> None:
    off = _context()
    assert "defender" not in [s["name"] for s in off["vigie_sources_enabled"]]  # GUID vide
    ctx = _context({"vigie_defender_client_id": "11111111-1111-1111-1111-111111111111"})
    [source] = [s for s in ctx["vigie_sources_enabled"] if s["name"] == "defender"]
    assert source["secrets"] == ["defender_private_key"]  # aucun secret client
    settings = source["settings"]
    assert settings["tenant_id"] == ctx["vigie_oidc"]["tenant_id"]
    assert settings["certificate"] == "/etc/vigie/ca/defender.crt"
    assert "private_key_file" not in settings  # prod : la clé vient de systemd-creds
    assert settings["proxy"] == f"http://127.0.0.1:{ctx['squid_worker_port']}"
    for domain in ("login.microsoftonline.com", "graph.microsoft.com", settings["api_host"]):
        assert domain in ctx["squid_worker_domains"]
    text = _render("units/credentials.conf.j2", ctx, source=source)
    assert _credentials(text) == {"defender_private_key"}
    assert set(_directives(text)["IPAddressAllow"][0].split()) == set(ctx["dns_servers"])
    jobs = _units(ctx)["vigie-jobs.service"]
    assert "defender_private_key" in _credentials(jobs)


def test_plan_requests_never_get_source_secrets() -> None:
    # La génération demandée depuis le web a la clé IA, jamais les secrets des sources ;
    # vigie-jobs garde les secrets des sources, jamais la clé IA.
    units = _units(_context({**ALL_ON, "vigie_veeam_host": "10.10.10.27"}))
    assert _credentials(units["vigie-plan-requests.service"]) == {"anthropic_api_key"}
    assert "--kind plan_generate" in units["vigie-plan-requests.service"]
    assert "anthropic_api_key" not in _credentials(units["vigie-jobs.service"])
    assert "--kind source_test" in units["vigie-jobs.service"]


def test_only_internet_units_use_the_worker_proxy(ctx: dict[str, Any]) -> None:
    port = ctx["squid_worker_port"]
    for name, text in _units(ctx).items():
        has_proxy = f"HTTPS_PROXY=http://127.0.0.1:{port}" in text
        internet = {"vigie-plan@.service", "vigie-notify@.service", "vigie-plan-requests.service"}
        assert has_proxy == (name in internet), name


def test_timers_are_valid_and_reference_existing_units() -> None:
    ctx = _context()
    services = {u["name"] for u in ctx["vigie_worker_units"]}
    for name, text in _timers(ctx).items():
        d = _directives(text)
        assert re.sub(r"@[^.]+\.", "@.", d["Unit"][0]) in services, f"{name} → {d['Unit']}"
        # Exactement un déclencheur, jamais vide (« OnCalendar= » réinitialise le timer).
        triggers = [k for k in ("OnCalendar", "OnUnitActiveSec") if k in d]
        assert len(triggers) == 1, f"{name} : {triggers}"
        assert d[triggers[0]] != [""], f"{name} : {triggers[0]} vide"
        if triggers == ["OnCalendar"]:
            assert d["Persistent"] == ["true"], name


def test_no_unit_has_an_empty_directive(ctx: dict[str, Any]) -> None:
    # Une directive vide réinitialise la valeur (StateDirectory=, OnCalendar=…) : seules
    # les remises à zéro voulues sont permises.
    allowed_empty = {"CapabilityBoundingSet", "AmbientCapabilities"}
    for name, text in {**_units(ctx), **_timers(ctx)}.items():
        for key, values in _directives(text).items():
            assert "" not in values or key in allowed_empty, f"{name} : {key}= vide"


def test_only_selfcheck_relaxes_umask(ctx: dict[str, Any]) -> None:
    for name, text in _units(ctx).items():
        d = _directives(text)
        expected = "0022" if name == "vigie-selfcheck.service" else "0027"
        assert d["UMask"][-1] == expected, name
        assert ("StateDirectory" in d) == (name == "vigie-selfcheck.service"), name


def test_secret_script_validates_names_and_never_echoes_values() -> None:
    script = (ROLE / "files" / "vigie-secret").read_text(encoding="utf-8")
    assert "*[!a-z0-9_]*" in script
    assert "systemd-creds encrypt" in script
    assert not re.search(r"echo[^\n]*\$\(cat", script)
    assert "set -x" not in script
