"""Accès entrant à la VM : SSH du traitement invité Veeam limité au serveur VBR (C6, C11)."""

from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from tests.security.deploy_render import DEPLOY
from tests.security.deploy_render import context as _context


def render(role: str, template: str, ctx: dict[str, Any]) -> str:
    env = Environment(  # noqa: S701 - fichiers de configuration, pas de HTML
        loader=FileSystemLoader(DEPLOY / "roles" / role / "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env.get_template(template).render(**ctx)


def test_ssh_open_to_veeam_only_besides_admin_networks() -> None:
    ctx = _context()
    assert ctx["veeam_guest_sources"] == ["10.10.10.27"]
    assert "10.10.10.27" not in " ".join(ctx["admin_networks"])  # pas d'accès administrateur
    rules = render("nftables", "nftables.conf.j2", ctx)
    ssh = [line.strip() for line in rules.splitlines() if "tcp dport 22" in line]
    assert ssh == [
        "tcp dport 22 ip saddr @admin_networks accept",
        'tcp dport 22 ip saddr { 10.10.10.27 } accept comment "Veeam traitement invité"',
    ]
    none = render("nftables", "nftables.conf.j2", {**ctx, "veeam_guest_sources": []})
    assert "Veeam" not in none


def test_veeam_account_only_from_veeam_server() -> None:
    ctx = _context()
    off = render("hardening", "sshd-vigie.conf.j2", {**ctx, "veeam_guest_enabled": False})
    assert "Match User" not in off
    conf = render("hardening", "sshd-vigie.conf.j2", ctx)  # défaut : mot de passe
    from_veeam, elsewhere = conf.split("Match User svcveeam", 2)[1:]
    assert from_veeam.startswith(" Address 10.10.10.27\n")
    assert "PasswordAuthentication yes" in from_veeam and "AllowTcpForwarding no" in from_veeam
    # Depuis toute autre adresse : aucune méthode d'authentification.
    assert "PasswordAuthentication no" in elsewhere and "PubkeyAuthentication no" in elsewhere
    key = render("hardening", "sshd-vigie.conf.j2", {**ctx, "veeam_guest_auth": "key"})
    assert "PasswordAuthentication yes" not in key.split("Match User svcveeam", 1)[1]


def test_native_rules_kept_until_legacy_purge() -> None:
    # Avant la bascule, Caddy natif sert 443 et les unités natives sortent par l'hôte : leurs
    # règles restent jusqu'à legacy_purge (sinon interface coupée et sortie non filtrée).
    ctx = _context()
    assert ctx["legacy_purge"] is False
    kept = render("nftables", "nftables.conf.j2", ctx)
    assert "tcp dport 443 ip saddr @lan_vpn_networks accept" in kept
    assert 'meta skuid "vigie-worker" counter drop' in kept
    assert 'meta skuid "vigie-web" counter drop' in kept
    purged = render("nftables", "nftables.conf.j2", {**ctx, "legacy_purge": True})
    assert "tcp dport 443 ip saddr @lan_vpn_networks" not in purged
    assert 'skuid "vigie-' not in purged
    assert "chain forward" in purged


def test_audit_watches_only_existing_or_created_paths() -> None:
    # auditctl s'arrête au premier chemin absent : les règles suivantes ne seraient pas
    # chargées. Tout chemin surveillé sous /srv ou /etc/docker est créé par hardening avant.
    import yaml

    rules = (DEPLOY / "roles" / "hardening" / "files" / "vigie.rules").read_text()
    watched = [line.split()[1] for line in rules.splitlines() if line.startswith("-w ")]
    tasks = yaml.safe_load((DEPLOY / "roles" / "hardening" / "tasks" / "main.yml").read_text())
    names = [t["name"] for t in tasks]
    created_task = tasks[names.index("Dossiers surveillés par auditd")]
    created = {item["path"] for item in created_task["loop"]}
    assert names.index("Dossiers surveillés par auditd") < names.index("Règles auditd de Vigie")
    for path in watched:
        if path.startswith(("/srv/", "/etc/docker")):
            assert path.rstrip("/") in created, path


def test_rate_limit_never_gates_a_verdict() -> None:
    # « limit rate » est une condition : sur une règle de rejet, il laisse passer ce qui
    # dépasse le débit vers les règles suivantes (constaté le 2026-10-22 : vigie-web sortait
    # par « br-* accept » après 10 SYN). Il ne doit borner que la journalisation.
    ctx = _context()
    for purge in (False, True):
        rules = render("nftables", "nftables.conf.j2", {**ctx, "legacy_purge": purge})
        lines = [line.strip() for line in rules.splitlines()]
        lines = [line for line in lines if line and not line.startswith("#")]
        for i, line in enumerate(lines):
            if "limit rate" in line:
                assert not line.endswith(("drop", "accept", "reject")), line
                assert " log prefix " in line, line
                # Rejet inconditionnel juste après, avec la même condition.
                condition = line.split("limit rate")[0]
                assert lines[i + 1] == f"{condition}counter drop", (line, lines[i + 1])
