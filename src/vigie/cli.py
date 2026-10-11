"""Point d'entrée `vigie` : collecte, plans, diffusion, web, maintenance et administration."""

from __future__ import annotations

import os
import re
from collections import Counter
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any
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
from vigie.db.enums import JobKind, PlanKind
from vigie.db.jobs import PlanGeneratePayload
from vigie.db.migrate import current_revision, head_revision
from vigie.db.session import make_engine
from vigie.engine.calendar import CalendarError
from vigie.engine.llm import LLMClient, make_client, month_spend
from vigie.logs import configure_logging
from vigie.mapping import RuleMapper
from vigie.pause import is_paused
from vigie.planning import PlanPausedError, generate_plan
from vigie.seed import SeedError, apply_seed, load_seed_data

app = typer.Typer(
    name="vigie",
    help="Vigie : veille des systèmes de supervision et plans de tâches de l'équipe IT.",
    no_args_is_help=True,
    add_completion=False,
)


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
            if is_paused(session, "collect", config_paused=cfg.general.paused):
                typer.echo("Collecte en pause (interface ou [general] paused) : rien n'est fait.")
                return
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
    now = datetime.now(UTC)
    try:
        target = (
            date.fromisoformat(day)
            if day
            else now.astimezone(ZoneInfo(cfg.general.timezone)).date()
        )
    except ValueError as exc:
        raise typer.BadParameter("date attendue au format AAAA-MM-JJ", param_hint="--date") from exc
    engine = make_engine(cfg.database.url)
    try:
        result = generate_plan(
            engine,
            cfg,
            kind,
            target,
            now,
            client_factory=lambda key, llm: llm_client_factory(key, llm),
            secret=lambda name: get_secret(name),
            no_llm=no_llm,
            dry_run=dry_run,
        )
    except PlanPausedError:
        typer.echo("Génération des plans en pause (interface ou [general] paused).")
        return
    except CalendarError as exc:
        typer.echo(f"ERREUR {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except SQLAlchemyError as exc:
        typer.echo(f"ERREUR base : {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()
    typer.echo(result.markdown)
    if result.ai_note:
        typer.echo(result.ai_note)
    if result.plan_id is None:
        typer.echo("Simulation : rien n'a été écrit.")
    else:
        typer.echo(f"Plan {result.plan_id} enregistré en brouillon.")


@app.command()
def notify(
    ctx: typer.Context,
    plan_ref: Annotated[
        str, typer.Option("--plan", help="Identifiant du plan, latest-daily ou latest-weekly.")
    ],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Écrit les messages dans un dossier sans envoyer.")
    ] = False,
    out: Annotated[Path, typer.Option("--out", help="Dossier des messages en simulation.")] = Path(
        "notify-out"
    ),
    force: Annotated[bool, typer.Option("--force", help="Renvoie un plan déjà diffusé.")] = False,
) -> None:
    """Diffuse un plan par e-mail (Graph) et Teams ; le plan est alors publié."""
    from vigie.notify.dispatch import NotifyError, dispatch, select_plan

    _, cfg = _config(ctx)
    engine = make_engine(cfg.database.url)
    try:
        with Session(engine) as session:
            if not dry_run and is_paused(session, "plan", config_paused=cfg.general.paused):
                typer.echo("Diffusion en pause (interface ou [general] paused).")
                return
            plan = select_plan(session, plan_ref)
            mailer, teams = (None, None) if dry_run else _notifiers(cfg)
            report = dispatch(
                session,
                plan,
                cfg,
                mailer=mailer,
                teams=teams,
                out_dir=out if dry_run else None,
                force=force,
            )
            session.commit()
    except (NotifyError, SecretError, ValueError) as exc:
        typer.echo(f"ERREUR {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except SQLAlchemyError as exc:
        typer.echo(f"ERREUR base : {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()
    mode = " (rodage : tout au coordinateur)" if cfg.notify.draft_only else ""
    if dry_run:
        typer.echo(
            f"Simulation{mode} : {report.mails} message(s) écrit(s) dans {out}/, teams.json."
        )
        return
    typer.echo(
        f"Plan {report.plan_id}{mode} : {report.mails} e-mail(s) envoyé(s), Teams : {report.teams}"
        + (" ; plan publié." if report.published else ".")
    )
    for error in report.mail_errors:
        typer.echo(f"ERREUR e-mail {error}", err=True)
    if not report.ok:
        raise typer.Exit(code=1)


def _notifiers(cfg: VigieConfig) -> tuple[Any, Any]:
    from vigie.notify.graph_mail import GraphMailer, msal_token_provider
    from vigie.notify.teams_webhook import TeamsWebhook

    n = cfg.notify
    mailer = None
    if n.mail_enabled:
        if not (n.graph_tenant_id and n.graph_client_id and n.mail_sender_id):
            raise ValueError("[notify] graph_tenant_id, graph_client_id et mail_sender_id requis")
        token = msal_token_provider(
            n.graph_tenant_id, n.graph_client_id, get_secret("graph_certificate"), n.proxy
        )
        mailer = GraphMailer(n.mail_sender_id, token, proxy=n.proxy)
    teams = (
        TeamsWebhook(get_secret("teams_webhook_url"), proxy=n.proxy) if n.teams_enabled else None
    )
    return mailer, teams


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
    kinds: Annotated[
        list[JobKind] | None,
        typer.Option(
            "--kind",
            help="Types traités (répétable) ; défaut : source_test. Chaque unité systemd ne "
            "traite que les types dont elle détient les secrets.",
        ),
    ] = None,
) -> None:
    """Demandes déposées par l'interface web (« Tester la connexion », « Générer le plan
    maintenant »), exécutées ici."""
    from vigie.jobs_runner import run_pending as run

    if not run_pending:
        typer.echo("Rien à faire : utiliser --run-pending.", err=True)
        raise typer.Exit(code=2)
    _, cfg = _config(ctx)
    engine = make_engine(cfg.database.url)
    try:
        with Session(engine) as session:
            done = run(
                session,
                lambda name: _build_connector(name, cfg, None),
                kinds=kinds or [JobKind.source_test],
                generate_plan=lambda payload: _plan_job(engine, cfg, payload),
            )
            session.commit()
            # Lu avant la fermeture de la session (l'exécuteur valide après chaque demande).
            lines = [
                f"{job.kind.value} {job.payload} : {job.status.value} — "
                f"{(job.result or {}).get('detail') or 'OK'}"
                for job in done
            ]
    except SQLAlchemyError as exc:
        typer.echo(f"ERREUR base : {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()
    for line in lines:
        typer.echo(line)
    typer.echo(f"{len(lines)} demande(s) traitée(s).")


PLAN_REQUEST_WINDOW_DAYS = 14


def _plan_job(engine: Engine, cfg: VigieConfig, payload: PlanGeneratePayload) -> dict[str, Any]:
    """« Générer le plan maintenant » : résultat sans secret ni contenu du plan."""
    now = datetime.now(UTC)
    target = payload.target()
    today = now.astimezone(ZoneInfo(cfg.general.timezone)).date()
    if abs((target - today).days) > PLAN_REQUEST_WINDOW_DAYS:
        return {"ok": False, "detail": "jour hors de la fenêtre autorisée (± 14 jours)"}
    try:
        result = generate_plan(
            engine,
            cfg,
            PlanKind(payload.kind),
            target,
            now,
            client_factory=lambda key, llm: llm_client_factory(key, llm),
            secret=lambda name: get_secret(name),
            no_llm=not payload.use_llm,
        )
    except PlanPausedError:
        return {"ok": False, "detail": "génération des plans en pause"}
    except CalendarError as exc:
        return {"ok": False, "detail": str(exc)[:300]}
    except Exception as exc:  # erreur base, IA… : type seulement, jamais de contenu
        return {"ok": False, "detail": f"échec ({type(exc).__name__})"}
    by = "affiné par l'IA" if result.by_llm else f"sans IA ({result.without_ai_reason})"
    return {
        "ok": True,
        "plan_id": result.plan_id,
        "by_llm": result.by_llm,
        "outcome": result.outcome,
        "cost_usd": str(result.cost_usd) if result.cost_usd is not None else None,
        "detail": f"plan n° {result.plan_id} {by}"[:300],
    }


@app.command()
def migrate(ctx: typer.Context) -> None:
    """Applique les migrations de la base (en production : en tant que vigie-migrate,
    propriétaire du schéma ; jamais avec un rôle d'exécution)."""
    from alembic import command

    from vigie.db.migrate import alembic_config

    _, cfg = _config(ctx)
    engine = make_engine(cfg.database.url)
    try:
        before = current_revision(engine)
        with engine.begin() as conn:
            command.upgrade(alembic_config(conn), "head")
        current = current_revision(engine)
    except SQLAlchemyError as exc:
        typer.echo(f"ERREUR base : {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()
    if before == current:
        typer.echo(f"Base déjà à jour (révision {current}).")
    else:
        # Repère lu par Ansible (changed_when).
        typer.echo(f"Base migrée : {before or 'vide'} → {current}.")


@app.command()
def housekeeping(ctx: typer.Context) -> None:
    """Purge selon la rétention (SPEC §5.2)."""
    from vigie.housekeeping import purge

    _, cfg = _config(ctx)
    engine = make_engine(cfg.database.url)
    try:
        with Session(engine) as session:
            counts = purge(session, datetime.now(UTC))
            session.commit()
    except SQLAlchemyError as exc:
        typer.echo(f"ERREUR base : {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()
    typer.echo("Purge : " + ", ".join(f"{k} {v}" for k, v in counts.items()))


@app.command()
def selfcheck(
    ctx: typer.Context,
    out: Annotated[Path, typer.Option("--out", help="Dossier lu par zabbix-agent2.")] = Path(
        "/var/lib/vigie/selfcheck"
    ),
) -> None:
    """Écrit l'état de santé lu par zabbix-agent2."""
    from vigie.selfcheck import collect_metrics, write_metrics

    _, cfg = _config(ctx)
    engine = make_engine(cfg.database.url)
    try:
        with Session(engine) as session:
            metrics = collect_metrics(session, cfg, datetime.now(UTC))
    except SQLAlchemyError as exc:
        typer.echo(f"ERREUR base : {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()
    write_metrics(out, metrics)
    typer.echo(f"{len(metrics)} indicateur(s) écrit(s) dans {out}")


@app.command()
def breakglass(
    ctx: typer.Context,
    enable: Annotated[bool, typer.Option("--enable/--disable", help="Active le compte local.")],
    ttl: Annotated[
        str, typer.Option("--ttl", help="Durée de validité (ex. 30m, 1h, max 8h).")
    ] = "1h",
) -> None:
    """Compte local de secours, désactivé par défaut (SECURITY.md C9).

    À lancer sur le serveur, en tant que vigie-web : le mot de passe (usage unique) n'est
    affiché qu'ici, une seule fois.
    """
    from vigie.web.auth import audit, disable_breakglass, enable_breakglass

    match = re.fullmatch(r"([0-9]{1,3})([mh])", ttl)
    minutes = int(match.group(1)) * (60 if match.group(2) == "h" else 1) if match else 0
    if enable and not 5 <= minutes <= 480:
        raise typer.BadParameter("durée entre 5m et 8h (ex. 30m, 1h)", param_hint="--ttl")
    _, cfg = _config(ctx)
    engine = make_engine(cfg.web.database_url or cfg.database.url)
    actor = f"cli:{os.environ.get('SUDO_USER') or os.environ.get('USER') or 'inconnu'}"
    try:
        with Session(engine) as session:
            if enable:
                password = enable_breakglass(session, timedelta(minutes=minutes), datetime.now(UTC))
                audit(session, actor, "breakglass_enable", "setting:breakglass", minutes=minutes)
            else:
                existed = disable_breakglass(session)
                audit(session, actor, "breakglass_disable", "setting:breakglass", existed=existed)
            session.commit()
    except SQLAlchemyError as exc:
        typer.echo(f"ERREUR base : {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        engine.dispose()
    if enable:
        typer.echo(f"Accès de secours actif {minutes} min, usage unique : /breakglass")
        typer.echo(f"Mot de passe : {password}")
    else:
        typer.echo("Accès de secours désactivé.")
