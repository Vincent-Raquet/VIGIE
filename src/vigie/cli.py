"""Point d'entrée `vigie`. Les commandes non encore implémentées sortent avec le code 3."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from vigie import __version__
from vigie.config import ConfigError, load_config, resolve_config_path
from vigie.connectors import registry

EXIT_NOT_IMPLEMENTED = 3  # distinct du code 2 de Click (erreur d'usage)

app = typer.Typer(
    name="vigie",
    help="Vigie : veille des systèmes de supervision et plans de tâches de l'équipe IT.",
    no_args_is_help=True,
    add_completion=False,
)


class PlanKind(StrEnum):
    daily = "daily"
    weekly = "weekly"


def _not_implemented(phase: int) -> NoReturn:
    typer.echo(f"Commande non implémentée (phase {phase} de la roadmap).", err=True)
    raise typer.Exit(code=EXIT_NOT_IMPLEMENTED)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"vigie {__version__}")
        raise typer.Exit


@app.callback()
def main(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help="Fichier vigie.toml (défaut : $VIGIE_CONFIG, sinon config/vigie.toml).",
        ),
    ] = None,
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version, is_eager=True, help="Affiche la version."),
    ] = False,
) -> None:
    ctx.obj = {"config": config}


@app.command()
def collect(
    source: Annotated[str, typer.Option("--source", help="Source à collecter (ex. zabbix).")],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="N'écrit rien en base, affiche les signaux.")
    ] = False,
    fixtures: Annotated[
        Path | None,
        typer.Option("--fixtures", help="Rejoue des réponses enregistrées au lieu d'appeler."),
    ] = None,
) -> None:
    """Collecte les alertes d'une source (lecture seule)."""
    _not_implemented(3)


@app.command()
def plan(
    kind: Annotated[PlanKind, typer.Option("--kind", help="Plan quotidien ou hebdomadaire.")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="N'enregistre pas le plan.")] = False,
    no_llm: Annotated[
        bool, typer.Option("--no-llm", help="Plan déterministe seul, sans appel au LLM.")
    ] = False,
) -> None:
    """Génère un plan de tâches."""
    _not_implemented(4)


@app.command()
def notify(
    plan_ref: Annotated[
        str, typer.Option("--plan", help="Identifiant du plan, latest-daily ou latest-weekly.")
    ],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Écrit les messages dans un dossier sans envoyer.")
    ] = False,
) -> None:
    """Diffuse un plan par mail et Teams."""
    _not_implemented(7)


@app.command()
def check(ctx: typer.Context) -> None:
    """Vérifie la configuration (base et sources : phases suivantes)."""
    path = resolve_config_path(ctx.obj["config"])
    try:
        cfg = load_config(path)
    except ConfigError as exc:
        typer.echo(f"ERREUR {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Configuration valide : {path}")
    installed = set(registry.available())
    for name in sorted(cfg.sources):
        state = "activée" if cfg.sources[name].enabled else "désactivée"
        connector = "connecteur installé" if name in installed else "connecteur absent"
        typer.echo(f"  source {name} : {state}, {connector}")


@app.command()
def seed(
    from_dir: Annotated[
        Path, typer.Option("--from", help="Dossier des fichiers d'amorçage.")
    ] = Path("config"),
) -> None:
    """Importe équipe, sociétés, politique, projets et skills de rôle (idempotent)."""
    _not_implemented(1)


@app.command()
def budget() -> None:
    """Affiche la consommation LLM du mois et le budget restant."""
    _not_implemented(5)


@app.command()
def web(
    reload: Annotated[bool, typer.Option("--reload", help="Rechargement auto (dev).")] = False,
    port: Annotated[int, typer.Option("--port", help="Port d'écoute sur 127.0.0.1.")] = 8000,
) -> None:
    """Lance l'application web (127.0.0.1 uniquement)."""
    _not_implemented(6)


@app.command()
def housekeeping() -> None:
    """Purge selon la rétention (SPEC §5.2)."""
    _not_implemented(8)


@app.command()
def selfcheck() -> None:
    """Écrit l'état de santé lu par zabbix-agent2."""
    _not_implemented(8)


@app.command()
def breakglass(
    enable: Annotated[bool, typer.Option("--enable/--disable", help="Active le compte local.")],
    ttl: Annotated[str, typer.Option("--ttl", help="Durée de validité (ex. 1h).")] = "1h",
) -> None:
    """Compte local de secours, désactivé par défaut (SECURITY.md C9)."""
    _not_implemented(6)
