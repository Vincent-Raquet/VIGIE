"""Vigie en conteneurs (SECURITY.md C6, C7, C8, C10) : rendu statique du compose.yaml, des
unités systemd, de Squid et de nftables du rôle Ansible `vigie`, puis vérification du
durcissement, de la répartition des secrets et des réseaux par service.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.security.deploy_render import DEPLOY, IDS, ROLE, context, directives, render, task_vars
from vigie.config import load_config

# Secrets de sources connus : seuls autorisés pour « jobs » (et chacun pour sa collecte).
SOURCE_SECRETS = {
    "zabbix_api_token",
    "veeam_password",
    "ninjaone_client_id",
    "defender_client_id",
    "defender_private_key",
    "ninjaone_client_secret",
    "fortianalyzer_api_key",
}
LLM = {"anthropic_api_key"}
# Secrets autorisés par service : tout ce qui n'est pas listé ici est interdit. Les services
# de collecte (collect-<source>) ne reçoivent que les secrets de leur source.
ALLOWED: dict[str, set[str]] = {
    "squid": set(),
    "web": {"web_session_key", "entra_client_secret"},
    "chat": LLM,
    "plan": LLM,
    "plan-requests": LLM,
    "notify": {"graph_certificate", "teams_webhook_url"},
    "jobs": SOURCE_SECRETS,
    "housekeeping": set(),
    "selfcheck": set(),
    "migrate": set(),
    "breakglass": set(),
}
# Services qui sortent sur Internet (par Squid, port worker).
INTERNET = {"chat", "plan", "plan-requests", "notify"}
ALL_ON = {
    "vigie_llm_enabled": True,
    "vigie_notify_mail_enabled": True,
    "vigie_notify_teams_enabled": True,
    "vigie_oidc": {"tenant_id": "t", "client_id": "c", "groups": {}},
}


def compose(ctx: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(render("compose.yaml.j2", ctx))
    return data


def services(ctx: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {k: v for k, v in compose(ctx)["services"].items()}


def allowed(name: str, ctx: dict[str, Any]) -> set[str]:
    if name.startswith("collect-"):
        [source] = [s for s in ctx["vigie_sources_enabled"] if f"collect-{s['name']}" == name]
        return set(source["secrets"])
    return ALLOWED[name]


def networks(service: dict[str, Any]) -> set[str]:
    nets = service.get("networks", [])
    return set(nets if isinstance(nets, list) else nets.keys())


@pytest.fixture(params=["config par défaut", "tout activé"])
def ctx(request: pytest.FixtureRequest) -> dict[str, Any]:
    return context(ALL_ON if request.param == "tout activé" else None)


# --- Durcissement --------------------------------------------------------------------------


def test_every_service_is_hardened(ctx: dict[str, Any]) -> None:
    svc = services(ctx)
    expected = set(ALLOWED) | {f"collect-{s['name']}" for s in ctx["vigie_sources_enabled"]}
    assert set(svc) == expected
    for name, s in svc.items():
        assert s["read_only"] is True, name
        assert s["cap_drop"] == ["ALL"], name
        assert "cap_add" not in s, name
        assert "no-new-privileges:true" in s["security_opt"], name
        assert not s.get("privileged"), name
        assert "ports" not in s, f"{name} : seul le proxy d'entrée publie un port"
        for key in ("network_mode", "pid", "ipc", "userns_mode"):
            assert s.get(key) in (None, "none"), f"{name} : {key}={s.get(key)}"
        uid = str(s["user"]).split(":")[0]
        assert uid not in ("0", "root", ""), f"{name} tourne en root"
        assert s["pids_limit"] > 0 and s["mem_limit"], name
        for volume in s.get("volumes", []):
            assert "docker.sock" not in volume, f"{name} : socket Docker montée"


def test_app_services_run_with_the_host_service_accounts(ctx: dict[str, Any]) -> None:
    # UID des comptes vigie-* de l'hôte : l'authentification peer de PostgreSQL (pg_ident)
    # leur donne leur rôle (vigie_web, vigie_worker, vigie_migrate).
    group = IDS["group"]
    for name, s in services(ctx).items():
        if name == "squid":
            assert s["user"] == "13:13"  # compte proxy de l'image Debian
            continue
        account = {"web": "web", "breakglass": "web", "migrate": "migrate"}.get(name, "worker")
        assert s["user"] == f"{IDS[account]}:{group}", name
        assert s["image"] == "vigie:1.0.0-test", name


def test_containers_trust_the_host_certificate_store(ctx: dict[str, Any]) -> None:
    # Certificats internes (Zabbix auto-signé…) ajoutés à l'hôte : [tls] ca_bundle.
    bundle = "/etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro"
    for name, s in services(ctx).items():
        if name != "squid":
            assert bundle in s["volumes"], name


def test_only_selfcheck_writes_to_the_host(ctx: dict[str, Any]) -> None:
    for name, s in services(ctx).items():
        writable = [v for v in s.get("volumes", []) if not v.endswith(":ro")]
        expected = ["/var/lib/vigie/selfcheck:/var/lib/vigie/selfcheck"]
        assert writable == (expected if name == "selfcheck" else []), name


def test_permanent_services_restart_only_on_failure(ctx: dict[str, Any]) -> None:
    # « always » ou « unless-stopped » relanceraient les conteneurs au démarrage du démon,
    # avant que vigie-creds n'ait déchiffré les secrets : vigie-compose.service s'en charge.
    for name, s in services(ctx).items():
        if name in ("squid", "web", "chat"):
            assert s["restart"] == "on-failure", name
            assert "profiles" not in s, name
        else:
            assert "restart" not in s and s["profiles"] == ["tasks"], name


# --- Secrets -------------------------------------------------------------------------------


def test_secrets_are_limited_per_service(ctx: dict[str, Any]) -> None:
    for name, s in services(ctx).items():
        secrets = set(s.get("secrets", []))
        assert secrets <= allowed(name, ctx), f"{name} reçoit {secrets - allowed(name, ctx)}"


def test_secrets_are_exact_when_everything_is_enabled() -> None:
    # Égalité (pas seulement inclusion) : un secret manquant ferait échouer le service en prod.
    ctx = context(ALL_ON)
    for name, s in services(ctx).items():
        expected = set(ctx["vigie_source_secrets"]) if name == "jobs" else allowed(name, ctx)
        assert set(s.get("secrets", [])) == expected, name


def test_secret_files_come_from_the_decrypted_tmpfs() -> None:
    ctx = context(ALL_ON)
    declared = compose(ctx)["secrets"]
    assert set(declared) == set(ctx["vigie_required_secrets"])
    for name, spec in declared.items():
        assert spec == {"file": f"/run/vigie/creds/{name}"}
    for name, s in services(ctx).items():
        env = s.get("environment", {})
        assert env.get("CREDENTIALS_DIRECTORY") == ("/run/secrets" if name != "squid" else None)
        # Jamais de secret dans l'environnement (SECURITY.md C7).
        assert not any(re.search(r"KEY|SECRET|TOKEN|PASSWORD", k) for k in env), env


def test_web_never_gets_source_or_llm_secrets() -> None:
    web = services(context(ALL_ON))["web"]
    assert set(web["secrets"]) == {"web_session_key", "entra_client_secret"}
    assert web["environment"]["HTTPS_PROXY"] == f"http://squid:{context()['squid_web_port']}"


def test_disabled_features_load_no_secret() -> None:
    off = context(
        {
            "vigie_llm_enabled": False,
            "vigie_notify_mail_enabled": False,
            "vigie_notify_teams_enabled": False,
        }
    )
    svc = services(off)
    for name in ("chat", "plan", "plan-requests", "notify"):
        assert svc[name]["secrets"] == [], name
    assert "anthropic_api_key" not in off["vigie_required_secrets"]
    assert off["vigie_permanent_services"] == ["squid", "web"]


def test_plan_requests_never_get_source_secrets() -> None:
    svc = services(context({**ALL_ON, "vigie_veeam_host": "10.10.10.27"}))
    assert set(svc["plan-requests"]["secrets"]) == LLM
    assert svc["plan-requests"]["command"][-1] == "plan_generate"
    assert "anthropic_api_key" not in svc["jobs"]["secrets"]
    assert svc["jobs"]["command"][-1] == "source_test"


def test_creds_unlock_gives_each_secret_to_its_only_reader() -> None:
    ctx = context(ALL_ON)
    script = render("vigie-creds-unlock.j2", ctx)
    unlocks = dict(re.findall(r"^unlock (\w+) (\S+)$", script, flags=re.M))
    assert set(unlocks) == set(ctx["vigie_required_secrets"])
    for name, owner in unlocks.items():
        web = name in ALLOWED["web"]
        assert owner == ("vigie-web" if web else "vigie-worker"), name
    assert "systemd-creds decrypt" in script and "chmod 0400" in script
    assert "set -x" not in script and not re.search(r"\b(echo|cat)\b[^\n]*\$DIR/", script)
    unit = directives(render("units/vigie-creds.service.j2", ctx))
    assert unit["RuntimeDirectory"] == ["vigie/creds"]  # effacé à l'arrêt de l'unité
    assert unit["RuntimeDirectoryMode"] == ["0700"]
    assert unit["PrivateNetwork"] == ["yes"]


def test_secret_script_validates_names_and_never_echoes_values() -> None:
    script = (ROLE / "files" / "vigie-secret").read_text(encoding="utf-8")
    assert "*[!a-z0-9_]*" in script
    assert "systemd-creds encrypt" in script
    assert not re.search(r"echo[^\n]*\$\(cat", script)
    assert "set -x" not in script


# --- Réseaux -------------------------------------------------------------------------------


def test_networks_per_service(ctx: dict[str, Any]) -> None:
    svc = services(ctx)
    direct = {e["name"] for e in ctx["vigie_source_egress"]}
    for name, s in svc.items():
        nets = networks(s)
        if name == "squid":
            assert nets == {"web", "worker", "egress"}
        elif name == "web":
            assert nets == {"web", "edge"}
        elif name.startswith("collect-"):
            source = name.removeprefix("collect-")
            assert nets == {"worker"} | ({f"src_{source}"} if source in direct else set()), name
        elif name == "jobs":
            assert nets == {"worker", "jobs"}
        elif name in ("chat", "plan", "plan-requests", "notify"):
            assert nets == {"worker"}, name
        else:
            assert s["network_mode"] == "none" and not nets, name
    # Seul Squid a un réseau qui sort sur Internet ; web et worker sont internes.
    declared = compose(ctx)["networks"]
    assert declared["web"]["internal"] is True and declared["worker"]["internal"] is True
    assert declared["edge"] == {"external": True}
    for net, spec in declared.items():
        if net not in ("web", "worker", "edge"):
            assert "internal" not in spec, net


def test_web_reached_by_caddy_only_through_a_fixed_address() -> None:
    ctx = context()
    edge = services(ctx)["web"]["networks"]["edge"]
    assert edge == {"ipv4_address": ctx["vigie_web_edge_ip"], "aliases": ["vigie-web"]}
    assert ctx["vigie_web_edge_ip"] != ctx["edge_caddy_ip"]


def test_fixed_subnets_do_not_overlap_each_other_or_the_lan() -> None:
    import ipaddress

    ctx = context()
    subnets = [ipaddress.ip_network(n["subnet"]) for n in ctx["vigie_networks"].values()]
    subnets += [ipaddress.ip_network(e["subnet"]) for e in ctx["vigie_source_egress"]]
    subnets += [ipaddress.ip_network(ctx["vigie_jobs_subnet"])]
    subnets += [ipaddress.ip_network(ctx["edge_subnet"])]
    pool = ipaddress.ip_network(ctx["docker_address_pool"])
    lan = [ipaddress.ip_network(n) for n in ctx["lan_vpn_networks"] + ctx["admin_networks"]]
    lan += [ipaddress.ip_network("10.10.10.0/24")]
    for i, net in enumerate(subnets):
        assert not any(net.overlaps(other) for other in subnets[i + 1 :]), net
        assert not net.overlaps(pool) and not any(net.overlaps(n) for n in lan), net
    for name, spec in ctx["vigie_networks"].items():
        assert ipaddress.ip_address(spec["squid"]) in ipaddress.ip_network(spec["subnet"]), name


def test_only_internet_services_use_the_worker_proxy(ctx: dict[str, Any]) -> None:
    proxy = f"http://squid:{ctx['squid_worker_port']}"
    for name, s in services(ctx).items():
        has_proxy = s.get("environment", {}).get("HTTPS_PROXY") == proxy
        assert has_proxy == (name in INTERNET), name


def test_sources_through_squid_or_direct() -> None:
    ctx = context({"vigie_ninjaone_enabled": True, "vigie_defender_enabled": True})
    by_name = {s["name"]: s for s in ctx["vigie_sources_enabled"]}
    egress = {e["name"] for e in ctx["vigie_source_egress"]}
    for name in ("ninjaone", "defender"):
        assert by_name[name]["settings"]["proxy"] == "http://squid:3128"
        assert "client_id" not in by_name[name]["settings"]  # jamais dans le dépôt
        assert name not in egress
    assert "private_key_file" not in by_name["defender"]["settings"]
    faz = by_name["fortianalyzer"]
    assert (
        "proxy" not in faz["settings"] and faz["settings"]["base_url"] == "https://FAZVMSTM25009422"
    )
    svc = services(ctx)
    faz = ["FAZVMSTM25009422:192.168.240.104"]
    zabbix = ["zabbix.local.wallindustries.be:192.168.250.49"]
    assert svc["collect-fortianalyzer"]["extra_hosts"] == faz
    assert svc["collect-zabbix"]["extra_hosts"] == zabbix
    assert svc["jobs"]["extra_hosts"] == zabbix + faz
    assert "extra_hosts" not in svc["collect-veeam"]  # appelé par son IP
    assert "extra_hosts" not in svc["collect-ninjaone"]  # Squid résout lui-même


def test_squid_listens_per_network_and_filters_by_source() -> None:
    ctx = context()
    conf = render("squid.conf.j2", ctx)
    nets = ctx["vigie_networks"]
    assert f"http_port {nets['worker']['squid']}:{ctx['squid_worker_port']} name=worker" in conf
    assert f"http_port {nets['web']['squid']}:{ctx['squid_web_port']} name=web" in conf
    access = [line for line in conf.splitlines() if line.startswith("http_access")]
    assert access == [
        "http_access deny !CONNECT",
        "http_access deny !Safe_ports",
        "http_access deny !SSL_ports",
        "http_access allow worker_port worker_net worker_domains",
        "http_access allow web_port web_net web_domains",
        "http_access deny all",
    ]
    assert f"acl web_domains dstdomain {' '.join(ctx['squid_web_domains'])}" in conf
    assert ctx["squid_web_domains"] == ["login.microsoftonline.com"]


def test_firewall_lets_each_network_reach_only_its_destinations() -> None:
    ctx = context()
    rules = render("nftables.conf.j2", ctx, role="nftables")
    code = [line for line in rules.splitlines() if not line.lstrip().startswith("#")]
    assert not any("flush" in line for line in code)  # effacerait les règles de Docker
    forward = rules.split("chain forward {", 1)[1].split("chain output {", 1)[0]
    lines = [line.strip() for line in forward.splitlines()]
    squid = ctx["vigie_networks"]["egress"]["squid"]
    assert f"ip saddr {squid} tcp dport 443 accept" in lines
    jobs = ctx["vigie_jobs_subnet"]
    # Réseaux de collecte directe : aucun DNS (noms déclarés dans les conteneurs).
    dns = [line for line in lines if "@dns_servers" in line]
    assert dns == [
        f"ip saddr {squid} ip daddr @dns_servers meta l4proto {{ tcp, udp }} th dport 53 accept"
    ]
    for e in ctx["vigie_source_egress"]:
        rule = f"ip saddr {{ {e['subnet']}, {jobs} }} ip daddr {e['ip']} tcp dport {e['port']}"
        assert any(line.startswith(rule + " accept") for line in lines), e["name"]
    # Toute autre sortie des réseaux de Vigie est rejetée avant l'accès libre des autres ponts.
    vigie_drop = lines.index("ip saddr @vigie_subnets counter drop")
    bridges = next(i for i, line in enumerate(lines) if line.startswith('iifname "br-*"'))
    assert vigie_drop < bridges
    web_drop = lines.index(f"ip saddr {ctx['vigie_web_edge_ip']} counter drop")
    assert web_drop < bridges
    assert "policy drop;" in forward
    assert "ct status dnat ip saddr @lan_vpn_networks accept" in lines


# --- Configuration -------------------------------------------------------------------------


def test_rendered_production_config_is_valid(tmp_path: Path) -> None:
    ctx = context({k: v for k, v in ALL_ON.items() if k != "vigie_oidc"})
    path = tmp_path / "vigie.toml"
    path.write_text(render("vigie.toml.j2", ctx), encoding="utf-8")
    cfg = load_config(path)
    assert cfg.web.host == "0.0.0.0"  # noqa: S104 - dans le conteneur, rien n'est publié
    assert cfg.web.forwarded_allow_ips == [ctx["edge_caddy_ip"]]
    assert cfg.web.dev_login is False
    assert cfg.notify.proxy == "http://squid:3128"
    migrate = tomllib.loads(render("migrate.toml.j2", ctx))
    assert migrate["database"]["url"].endswith("?user=vigie_migrate")


def test_migrate_has_no_network_and_its_own_config() -> None:
    migrate = services(context())["migrate"]
    assert migrate["network_mode"] == "none"
    assert migrate["environment"]["VIGIE_CONFIG"] == "/etc/vigie/migrate.toml"
    assert migrate["command"] == ["migrate"]


# --- Unités et timers ----------------------------------------------------------------------


def task_units(ctx: dict[str, Any]) -> dict[str, str]:
    return {
        t["name"]: render("units/vigie-task.service.j2", ctx, task=t) for t in ctx["vigie_tasks"]
    }


def test_task_units_run_existing_compose_services(ctx: dict[str, Any]) -> None:
    svc = services(ctx)
    for name, text in task_units(ctx).items():
        d = directives(text)
        assert d["Type"] == ["oneshot"], name
        cmd = d["ExecStart"][0].split()
        assert cmd[:6] == [
            "/usr/bin/docker",
            "compose",
            "--project-directory",
            "/srv/vigie",
            "run",
            "--rm",
        ], name
        service = cmd[cmd.index("--name") + 2]
        container = cmd[cmd.index("--name") + 1]
        assert d["ExecStopPost"] == [f"-/usr/bin/docker rm --force {container}"], name
        if "%i" in service:
            for s in ctx["vigie_sources_enabled"]:
                assert service.replace("%i", s["name"]) in svc, name
        else:
            assert service in svc, name


def test_docker_client_units_are_sandboxed(ctx: dict[str, Any]) -> None:
    units = {
        **task_units(ctx),
        "vigie-compose.service": render("units/vigie-compose.service.j2", ctx),
    }
    for name, text in units.items():
        d = directives(text)
        assert d["RestrictAddressFamilies"] == ["AF_UNIX"], name  # socket Docker seulement
        assert d["IPAddressDeny"] == ["any"], name
        assert d["CapabilityBoundingSet"] == [""], name
        assert d["NoNewPrivileges"] == ["yes"] and d["ProtectSystem"] == ["strict"], name
        assert "vigie-creds.service" in d["Requires"][0], name
    compose_unit = directives(units["vigie-compose.service"])
    assert compose_unit["ExecStart"][0].endswith(" ".join(ctx["vigie_permanent_services"]))


def test_timers_are_valid_and_reference_existing_units() -> None:
    ctx = context()
    tasks = {t["name"] for t in ctx["vigie_tasks"]}
    timers = {
        f"vigie-collect@{s['name']}.timer": render(
            "units/timer.j2", ctx, **task_vars("Timers de collecte", ctx, s)
        )
        for s in ctx["vigie_sources_enabled"]
    }
    for timer in ctx["vigie_timers"]:
        timers[timer["name"]] = render(
            "units/timer.j2", ctx, **task_vars("Autres timers", ctx, timer)
        )
    for name, text in timers.items():
        d = directives(text)
        assert re.sub(r"@[^.]+\.", "@.", d["Unit"][0]) in tasks, f"{name} → {d['Unit']}"
        # Exactement un déclencheur, jamais vide (« OnCalendar= » réinitialise le timer).
        triggers = [k for k in ("OnCalendar", "OnUnitActiveSec") if k in d]
        assert len(triggers) == 1, f"{name} : {triggers}"
        assert d[triggers[0]] != [""], f"{name} : {triggers[0]} vide"
        if triggers == ["OnCalendar"]:
            assert d["Persistent"] == ["true"], name


def test_no_unit_has_an_empty_directive(ctx: dict[str, Any]) -> None:
    allowed_empty = {"CapabilityBoundingSet", "AmbientCapabilities"}
    units = {
        **task_units(ctx),
        "vigie-compose.service": render("units/vigie-compose.service.j2", ctx),
        "vigie-creds.service": render("units/vigie-creds.service.j2", ctx),
    }
    for name, text in units.items():
        for key, values in directives(text).items():
            assert "" not in values or key in allowed_empty, f"{name} : {key}= vide"


# --- Proxy d'entrée ------------------------------------------------------------------------


def test_edge_proxy_is_the_only_published_port_and_trusted_by_web() -> None:
    ctx = context()
    facts = {"getent_passwd": {"edge": ["x", "980", "980", "", "/nonexistent", ""]}}
    defaults = yaml.safe_load((DEPLOY / "roles" / "edge" / "defaults" / "main.yml").read_text())
    edge = yaml.safe_load(
        render("compose.yaml.j2", {**ctx, **defaults}, role="edge", ansible_facts=facts)
    )
    caddy = edge["services"]["caddy"]
    assert caddy["ports"] == [f"{ctx['vigie_ip']}:443:443/tcp"]
    assert caddy["user"] == "980:980" and caddy["read_only"] is True
    assert caddy["cap_drop"] == ["ALL"] and caddy["cap_add"] == ["NET_BIND_SERVICE"]
    assert "no-new-privileges:true" in caddy["security_opt"]
    assert caddy["networks"]["edge"]["ipv4_address"] == ctx["edge_caddy_ip"]
    assert edge["networks"]["edge"]["ipam"]["config"] == [{"subnet": ctx["edge_subnet"]}]
    site = render("vigie.caddy.j2", ctx)
    assert f"reverse_proxy vigie-web:{ctx['vigie_web_port']}" in site
    assert "tls internal" in site
    caddyfile = (DEPLOY / "roles" / "edge" / "templates" / "Caddyfile.j2").read_text()
    assert "admin off" in caddyfile


def test_legacy_purge_removes_the_old_ca_private_key() -> None:
    tasks = yaml.safe_load((DEPLOY / "roles" / "legacy" / "tasks" / "main.yml").read_text())
    removed = {
        t["ansible.builtin.file"]["path"]
        for t in tasks
        if t.get("ansible.builtin.file", {}).get("state") == "absent"
        and t.get("when") == "legacy_purge | bool"
    }
    assert {"/var/lib/caddy", "/opt/vigie"} <= removed
