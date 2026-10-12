"""Accès entrant à la VM : SSH du traitement invité Veeam limité au serveur VBR (C6, C11)."""

from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from tests.security.test_systemd_units import DEPLOY, _context


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
