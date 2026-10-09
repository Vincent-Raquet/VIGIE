"""Point d'entrée `vigie`. Les commandes non encore implémentées sortent avec le code 3."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from vigie import __version__
from vigie.config import ConfigError, VigieConfig, load_config, resolve_config_path
from vigie.connectors import registry
from vigie.db.enums import PlanKind
from vigie.db.migrate import current_revision, head_revision
from vigie.db.session import make_engine
from vigie.logs import configure_logging
from vigie.seed import SeedError, apply_seed, load_seed_data

EXIT_NOT_IMPLEMENTED = 3  # distinct du code 2 de Click (erreur d'usage)

app = typer.Typer(
    name="vigie",
    help="Vigie : veille des systèmes de supervision et plans de tâches de l'équipe IT.",
    no_args_is_help=True,
    add_completion=False,
)


def _not_implemented(phase: int) -> NoReturn:
    typer.echo(f"Commande non implémentée (phase {phase} de la roadmap).", err=True)
    raise typer.Exit(code=EXIT_NOT_IMPLEMENTED)


def _config(ctx: typer.Context) -> tuple[Path, VigieConfig]:
    path = resolve_config_path(ctx.obj["config"])
    try:
        return path, load_config(path)
    except ConfigError as exc:
        typer.echo(f"ERREUR {exc}", err=True)
        raise typer.Exit(code=1) from exc


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
    configure_logging(os.environ.get("VIGIE_LOG_LEVEL", "INFO"))
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
    """Vérifie la configuration et la base (sources : phase 3)."""
    path, cfg = _config(ctx)
    typer.echo(f"Configuration valide : {path}")
    installed = set(registry.available())
    for name in sorted(cfg.sources):
        state = "activée" if cfg.sources[name].enabled else "désactivée"
        connector = "connecteur installé" if name in installed else "connecteur absent"
        typer.echo(f"  source {name} : {state}, {connector}")

    engine = make_engine(cfg.database.url)
    try:
        current = current_revision(engine)
    except SQLAlchemyError as exc:
        typer.echo(f"ERREUR base injoignable : {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()
    head = head_revision()
    if current != head:
        typer.echo(
            f"ERREUR base en révision {current}, attendue {head} : uv run alembic upgrade head",
            err=True,
        )
        raise typer.Exit(code=1)
    typer.echo(f"Base : OK (révision {current}, à jour)")


OUTCOME_LABELS = {"created": "créé(s)", "existing": "existant(s)", "updated": "mis à jour"}


@app.command()
def seed(
    ctx: typer.Context,
    from_dir: Annotated[
        Path, typer.Option("--from", help="Dossier des fichiers d'amorçage.")
    ] = Path("config"),
    roles_dir: Annotated[Path, typer.Option("--roles", help="Dossier des skills de rôle.")] = Path(
        "roles"
    ),
    update: Annotated[
        bool, typer.Option("--update", help="Écrase l'existant depuis les fichiers.")
    ] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Valide sans rien écrire.")] = False,
) -> None:
    """Importe équipe, sociétés, politique, projets et skills de rôle (idempotent)."""
    _, cfg = _config(ctx)
    try:
        data = load_seed_data(from_dir, roles_dir)
    except SeedError as exc:
        typer.echo(f"ERREUR {exc}", err=True)
        raise typer.Exit(code=1) from exc
    for name in data.example_files:
        typer.echo(f"Attention : données d'exemple utilisées ({name}).")

    engine = make_engine(cfg.database.url)
    try:
        with Session(engine) as session:
            report = apply_seed(session, data, update=update)
            if dry_run:
                session.rollback()
            else:
                session.commit()
    except SQLAlchemyError as exc:
        typer.echo(f"ERREUR base : {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()

    for entity, counts in sorted(report.counts.items()):
        parts = ", ".join(f"{counts[k]} {label}" for k, label in OUTCOME_LABELS.items())
        typer.echo(f"  {entity} : {parts}")
    if dry_run:
        typer.echo("Simulation : rien n'a été écrit.")


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
