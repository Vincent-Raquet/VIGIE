"""Point d'entrée `vigie`. Les commandes non encore implémentées sortent avec le code 3."""

from __future__ import annotations

import os
from collections import Counter
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any, NoReturn
from zoneinfo import ZoneInfo

import typer
from pydantic import SecretStr
from sqlalchemy import Engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from vigie import __version__
from vigie.collect import ensure_source, record_failure, record_success, store_snapshot
from vigie.config import (
    ConfigError,
    LLMConfig,
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
from vigie.db import models
from vigie.db.enums import PlanKind
from vigie.db.migrate import current_revision, head_revision
from vigie.db.session import make_engine
from vigie.engine.calendar import CalendarError
from vigie.engine.llm import LLMClient, make_client, month_spend
from vigie.engine.planner import PlanDraft, build_plan, run_engine, save_plan
from vigie.engine.refine import Refinement, deterministic, refine
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


# Point d'injection des tests (faux client, aucun réseau).
llm_client_factory: Callable[[str, LLMConfig], LLMClient] = make_client


def _refine(
    session: Session, engine: Engine, draft: PlanDraft, cfg: VigieConfig, no_llm: bool
) -> tuple[Refinement | None, str]:
    """Raffinement par l'IA, ou raison de s'en passer. L'appel est journalisé dans sa propre
    transaction : son coût compte dans le budget même en simulation."""
    if no_llm:
        return None, ""
    if not cfg.llm.enabled:
        return deterministic(draft, "IA désactivée dans la configuration"), ""
    try:
        key = get_secret("anthropic_api_key")
    except SecretError:
        return deterministic(draft, "clé API Anthropic indisponible"), ""
    client = llm_client_factory(key.get_secret_value(), cfg.llm)
    with Session(engine) as log_session:
        refinement = refine(
            session,
            log_session,
            draft,
            client,
            cfg.llm,
            cfg.plans,
            country=cfg.general.holidays_country,
        )
        note = ""
        if refinement.llm is not None and refinement.llm.call_id is not None:
            call = log_session.get(models.LLMCall, refinement.llm.call_id)
            if call is not None:
                note = (
                    f"Appel IA ({call.model}) : {call.outcome.value}, {call.cost_usd} $, "
                    f"{call.input_tokens} jetons en entrée dont {call.cached_tokens} en cache, "
                    f"{call.output_tokens} en sortie."
                )
        log_session.commit()
    return refinement, note


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
    """Génère un plan de tâches (brouillon), affiné par l'IA sauf --no-llm, et l'affiche."""
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
            refinement, ai_note = _refine(session, engine, draft, cfg, no_llm)
            if refinement is None:
                markdown = render_markdown(draft)
                final, call_id = draft, None
                ai: dict[str, object] = {"by_llm": False, "without_ai_reason": "option --no-llm"}
            else:
                markdown = render_markdown(
                    draft, refinement.plan, without_ai=refinement.without_ai_reason
                )
                final = refinement.plan.draft
                call_id = refinement.llm.call_id if refinement.by_llm and refinement.llm else None
                ai = refinement.plan.ai_data(refinement.without_ai_reason)
            plan_id = None
            if dry_run:
                session.rollback()
            else:
                plan_id = save_plan(session, final, markdown, llm_call_id=call_id, ai=ai).id
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
    if ai_note:
        typer.echo(ai_note)
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
def budget(ctx: typer.Context) -> None:
    """Affiche la consommation LLM du mois et le budget restant."""
    _, cfg = _config(ctx)
    now = datetime.now(UTC)
    engine = make_engine(cfg.database.url)
    try:
        with Session(engine) as session:
            spent = month_spend(session, now)
            start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            rows = session.scalars(select(models.LLMCall).where(models.LLMCall.at >= start)).all()
    except SQLAlchemyError as exc:
        typer.echo(f"ERREUR base : {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()
    limit = Decimal(str(cfg.llm.monthly_budget_usd))
    outcomes = Counter(r.outcome.value for r in rows)
    total_in = sum(r.input_tokens + r.cached_tokens for r in rows)
    cached = sum(r.cached_tokens for r in rows)
    share = f"{cached * 100 // total_in} %" if total_in else "—"
    typer.echo(f"Mois de {now:%m/%Y} : {spent:.4f} $ dépensés sur {limit:.2f} $")
    typer.echo(f"Reste : {max(limit - spent, Decimal(0)):.4f} $")
    detail = ", ".join(f"{k} {v}" for k, v in sorted(outcomes.items())) or "aucun"
    typer.echo(f"Appels : {len(rows)} ({detail})")
    typer.echo(f"Part des jetons d'entrée servis par le cache : {share}")


@app.command()
def web(
    ctx: typer.Context,
    reload: Annotated[bool, typer.Option("--reload", help="Rechargement auto (dev).")] = False,
    port: Annotated[
        int | None, typer.Option("--port", help="Port d'écoute (défaut : [web] port).")
    ] = None,
) -> None:
    """Lance l'application web (127.0.0.1 uniquement)."""
    import uvicorn

    path, cfg = _config(ctx)
    os.environ["VIGIE_CONFIG"] = str(path)  # relu par la fabrique, y compris au rechargement
    try:
        get_secret("web_session_key")
    except SecretError as exc:
        typer.echo(
            f"ERREUR {exc} : créez une clé (ex. `python -c 'import secrets; "
            "print(secrets.token_urlsafe(48))'`) dans .env.local ou systemd-creds.",
            err=True,
        )
        raise typer.Exit(code=1) from exc
    uvicorn.run(
        "vigie.web.app:build_from_env",
        factory=True,
        host=cfg.web.host,
        port=port or cfg.web.port,
        reload=reload,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
        server_header=False,
        log_level="info",
    )


@app.command()
def jobs(
    ctx: typer.Context,
    run_pending: Annotated[
        bool, typer.Option("--run-pending", help="Exécute les demandes du web en attente.")
    ] = False,
) -> None:
    """Demandes déposées par l'interface web (ex. « Tester la connexion »), exécutées ici."""
    from vigie.jobs_runner import run_pending as run

    if not run_pending:
        typer.echo("Rien à faire : utiliser --run-pending.", err=True)
        raise typer.Exit(code=2)
    _, cfg = _config(ctx)
    engine = make_engine(cfg.database.url)
    try:
        with Session(engine) as session:
            done = run(session, lambda name: _build_connector(name, cfg, None))
            session.commit()
    except SQLAlchemyError as exc:
        typer.echo(f"ERREUR base : {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()
    for job in done:
        result = job.result or {}
        typer.echo(
            f"{job.kind.value} {job.payload} : {job.status.value} — {result.get('detail') or 'OK'}"
        )
    typer.echo(f"{len(done)} demande(s) traitée(s).")


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
