"""Point d'entrée `vigie`. Les commandes non encore implémentées sortent avec le code 3."""

from __future__ import annotations

import os
from collections import Counter
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, NoReturn
from zoneinfo import ZoneInfo

import typer
from pydantic import SecretStr
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from vigie import __version__
from vigie.collect import ensure_source, record_failure, record_success, store_snapshot
from vigie.config import (
    ConfigError,
    SecretError,
    VigieConfig,
    get_secret,
    load_config,
    resolve_config_path,
)
from vigie.connectors import registry
from vigie.connectors.base import (
    ConnectorConfigError,
    ConnectorContext,
    Signal,
    SourceCallError,
    fixture_transport,
)
from vigie.db.enums import PlanKind
from vigie.db.migrate import current_revision, head_revision
from vigie.db.session import make_engine
from vigie.engine.calendar import CalendarError
from vigie.engine.planner import build_plan, run_engine, save_plan
from vigie.engine.render import render_markdown
from vigie.logs import configure_logging
from vigie.mapping import RuleMapper
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


FIXTURE_BASE_URL = "https://fixtures.invalid"


def _build_connector(name: str, cfg: VigieConfig, fixtures: Path | None) -> Any:
    settings: dict[str, Any] = {}
    if name in cfg.sources:
        settings = cfg.sources[name].model_dump()
    elif fixtures is None:
        raise ConnectorConfigError(f"section [sources.{name}] absente de la configuration")
    if fixtures is not None:
        # Rejeu : ni secret ni réseau ; l'allowlist du SafeClient s'applique quand même.
        settings.setdefault("base_url", FIXTURE_BASE_URL)
        context = ConnectorContext(
            settings=settings,
            secret=lambda _name: SecretStr("fixture"),
            transport=fixture_transport(fixtures),
        )
    else:
        context = ConnectorContext(
            settings=settings, secret=get_secret, ca_bundle=cfg.tls.ca_bundle
        )
    connector_cls: Any = registry.load(name)
    return connector_cls.from_context(context)


def _print_signals(signals: list[Signal]) -> None:
    signals = sorted(signals, key=lambda s: (-s.severity, s.company_code or "~", s.asset))
    typer.echo(f"{'SÉV':<4}{'CATÉGORIE':<12}{'SOCIÉTÉ':<9}{'ACTIF':<28}TITRE")
    for s in signals:
        typer.echo(
            f"{s.severity:<4}{s.category.value:<12}{s.company_code or '—':<9}"
            f"{s.asset[:27]:<28}{s.title[:90]}"
        )
    by_severity = Counter(s.severity for s in signals)
    by_company = Counter(s.company_code or "sans société" for s in signals)
    typer.echo(f"\n{len(signals)} signal(s)")
    typer.echo(
        "Par sévérité : "
        + ", ".join(f"{k}={by_severity[k]}" for k in sorted(by_severity, reverse=True))
    )
    typer.echo("Par société : " + ", ".join(f"{k}={n}" for k, n in by_company.most_common()))


@app.command()
def collect(
    ctx: typer.Context,
    source: Annotated[str, typer.Option("--source", help="Source à collecter (ex. zabbix).")],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="N'écrit rien en base, affiche les signaux.")
    ] = False,
    fixtures: Annotated[
        Path | None,
        typer.Option("--fixtures", help="Rejoue des réponses enregistrées au lieu d'appeler."),
    ] = None,
    mapping: Annotated[
        Path,
        typer.Option("--mapping", help="Dossier de companies.yaml (rattachement des sociétés)."),
    ] = Path("config"),
) -> None:
    """Collecte les alertes d'une source (lecture seule) et les enregistre en base."""
    if source not in registry.available():
        typer.echo(f"ERREUR aucun connecteur installé pour la source {source!r}", err=True)
        raise typer.Exit(code=1)
    _, cfg = _config(ctx)
    if dry_run:
        try:
            mapper = RuleMapper.from_seed_dir(mapping)
            connector = _build_connector(source, cfg, fixtures)
            signals = _run(connector, mapper)
        except (ConnectorConfigError, SecretError, SeedError, SourceCallError) as exc:
            typer.echo(f"ERREUR {exc}", err=True)
            raise typer.Exit(code=1) from exc
        _print_signals(signals)
        return
    _collect_to_db(source, cfg, fixtures)


def _run(connector: Any, mapper: RuleMapper) -> list[Signal]:
    since = datetime.now(UTC) - timedelta(minutes=connector.config.interval_min)
    return [connector.to_signal(raw, mapper) for raw in connector.collect(since)]


def _collect_to_db(source: str, cfg: VigieConfig, fixtures: Path | None) -> None:
    settings = cfg.sources.get(source)
    engine = make_engine(cfg.database.url)
    failure: str | None = None
    try:
        with Session(engine) as session:
            ensure_source(
                session,
                source,
                kind=source,
                enabled=settings.enabled if settings else True,
                interval_min=settings.interval_min if settings else 15,
                base_url=str(getattr(settings, "base_url", "") or ""),
            )
            mapper = RuleMapper.from_session(session)
            now = datetime.now(UTC)
            try:
                connector = _build_connector(source, cfg, fixtures)
                signals = _run(connector, mapper)
                complete = not getattr(connector, "truncated", False)
                report = store_snapshot(session, source, signals, now, complete=complete)
                record_success(session, source, now)
            except SourceCallError as exc:
                failure = str(exc)
                record_failure(session, source, failure, now)
            session.commit()
    except (ConnectorConfigError, SecretError) as exc:
        typer.echo(f"ERREUR {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except SQLAlchemyError as exc:
        typer.echo(f"ERREUR base : {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()
    if failure is not None:
        typer.echo(f"ERREUR {failure} (signal « source injoignable » enregistré)", err=True)
        raise typer.Exit(code=1)
    typer.echo(
        f"{source} : {len(signals)} signal(s) — {report.created} nouveau(x), "
        f"{report.updated} mis à jour, {report.reopened} rouvert(s), {report.resolved} résolu(s)"
        + ("" if complete else " ; collecte tronquée : aucune résolution")
    )


@app.command()
def plan(
    ctx: typer.Context,
    kind: Annotated[PlanKind, typer.Option("--kind", help="Plan quotidien ou hebdomadaire.")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="N'enregistre pas le plan.")] = False,
    no_llm: Annotated[
        bool, typer.Option("--no-llm", help="Plan déterministe seul, sans appel au LLM.")
    ] = False,
    day: Annotated[
        str | None,
        typer.Option("--date", help="Jour du plan (AAAA-MM-JJ) ; défaut : aujourd'hui."),
    ] = None,
) -> None:
    """Génère un plan de tâches (brouillon) et l'affiche en Markdown."""
    if not no_llm:
        typer.echo("Raffinement par IA non implémentée (phase 5) : utiliser --no-llm.", err=True)
        raise typer.Exit(code=EXIT_NOT_IMPLEMENTED)
    _, cfg = _config(ctx)
    tz = ZoneInfo(cfg.general.timezone)
    now = datetime.now(UTC)
    try:
        target = date.fromisoformat(day) if day else now.astimezone(tz).date()
    except ValueError as exc:
        raise typer.BadParameter("date attendue au format AAAA-MM-JJ", param_hint="--date") from exc
    engine = make_engine(cfg.database.url)
    try:
        with Session(engine) as session:
            run_engine(session, now)
            draft = build_plan(
                session,
                kind,
                target,
                now,
                cfg.plans,
                tz=tz,
                country=cfg.general.holidays_country,
            )
            markdown = render_markdown(draft)
            plan_id = None
            if dry_run:
                session.rollback()
            else:
                plan_id = save_plan(session, draft, markdown).id
                session.commit()
    except CalendarError as exc:
        typer.echo(f"ERREUR {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except SQLAlchemyError as exc:
        typer.echo(f"ERREUR base : {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()
    typer.echo(markdown)
    if plan_id is None:
        typer.echo("Simulation : rien n'a été écrit.")
    else:
        typer.echo(f"Plan {plan_id} enregistré en brouillon.")


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


def _check_source(name: str, cfg: VigieConfig) -> bool:
    try:
        health = _build_connector(name, cfg, None).healthcheck()
    except (ConnectorConfigError, SecretError, SourceCallError) as exc:
        typer.echo(f"    ERREUR {exc}", err=True)
        return False
    if not health.ok:
        typer.echo(f"    ERREUR {health.detail}", err=True)
        return False
    extra = f", {health.detail}" if health.detail else ""
    typer.echo(f"    OK : version {health.version}, {health.latency_ms} ms{extra}")
    return True


@app.command()
def check(
    ctx: typer.Context,
    sources: Annotated[
        bool,
        typer.Option("--sources", help="Teste aussi la connexion aux sources activées."),
    ] = False,
) -> None:
    """Vérifie la configuration, la base et, avec --sources, la connexion aux sources."""
    path, cfg = _config(ctx)
    typer.echo(f"Configuration valide : {path}")
    installed = set(registry.available())
    failed = False
    for name in sorted(cfg.sources):
        state = "activée" if cfg.sources[name].enabled else "désactivée"
        connector = "connecteur installé" if name in installed else "connecteur absent"
        typer.echo(f"  source {name} : {state}, {connector}")
        if sources and cfg.sources[name].enabled and name in installed:
            failed |= not _check_source(name, cfg)
    if failed:
        raise typer.Exit(code=1)

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
