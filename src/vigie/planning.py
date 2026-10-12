"""Génération d'un plan (moteur + raffinement IA), partagée par `vigie plan` et les demandes
du web (`job_request` de type `plan_generate`, exécutées par le worker).

Le coût de l'itération est lu sur le `llm_call` journalisé, même quand l'IA a échoué ou que le
budget l'a refusée (`plan.llm_call_id` n'est renseigné que si l'IA a produit le plan).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from zoneinfo import ZoneInfo

from pydantic import SecretStr
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from vigie.ai_models import resolve_model
from vigie.config import LLMConfig, SecretError, VigieConfig, get_secret
from vigie.db import models
from vigie.db.enums import PlanKind
from vigie.engine.llm import LLMClient
from vigie.engine.planner import PlanDraft, build_plan, run_engine, save_plan
from vigie.engine.refine import Refinement, deterministic, refine
from vigie.engine.render import render_markdown
from vigie.pause import is_paused

ClientFactory = Callable[[str, LLMConfig], LLMClient]
SecretReader = Callable[[str], SecretStr]


class PlanPausedError(Exception):
    """Génération des plans en pause (interface ou [general] paused)."""


@dataclass(frozen=True)
class GeneratedPlan:
    plan_id: int | None  # None en simulation
    markdown: str
    by_llm: bool
    without_ai_reason: str
    call_id: int | None  # appel IA de l'itération (même en échec)
    outcome: str | None
    cost_usd: Decimal | None
    ai_note: str


def _refine(
    session: Session,
    engine: Engine,
    draft: PlanDraft,
    cfg: VigieConfig,
    no_llm: bool,
    client_factory: ClientFactory,
    secret: SecretReader,
) -> tuple[Refinement | None, models.LLMCall | None]:
    """Raffinement par l'IA, ou raison de s'en passer. L'appel est journalisé dans sa propre
    transaction : son coût compte dans le budget même en simulation."""
    if no_llm:
        return None, None
    if not cfg.llm.enabled:
        return deterministic(draft, "IA désactivée dans la configuration"), None
    try:
        key = secret("anthropic_api_key")
    except SecretError:
        return deterministic(draft, "clé API Anthropic indisponible"), None
    client = client_factory(key.get_secret_value(), cfg.llm)
    with Session(engine, expire_on_commit=False) as log_session:
        refinement = refine(
            session,
            log_session,
            draft,
            client,
            cfg.llm,
            cfg.plans,
            country=cfg.general.holidays_country,
        )
        call = None
        if refinement.llm is not None and refinement.llm.call_id is not None:
            call = log_session.get(models.LLMCall, refinement.llm.call_id)
        log_session.commit()
    return refinement, call


def generate_plan(
    engine: Engine,
    cfg: VigieConfig,
    kind: PlanKind,
    target: date,
    now: datetime,
    *,
    client_factory: ClientFactory,
    secret: SecretReader = get_secret,
    no_llm: bool = False,
    dry_run: bool = False,
    model: str | None = None,
) -> GeneratedPlan:
    """Génère (et enregistre en brouillon, sauf simulation) le plan `kind` du jour `target`.

    Lève `PlanPausedError` si la génération est en pause (jamais en simulation),
    `CalendarError` ou une erreur SQLAlchemy sinon. `model` : choix ponctuel parmi les
    modèles proposés (`vigie.ai_models`), sinon le modèle par défaut (Paramètres).
    """
    tz = ZoneInfo(cfg.general.timezone)
    with Session(engine) as session:
        if not dry_run and is_paused(session, "plan", config_paused=cfg.general.paused):
            raise PlanPausedError("génération des plans en pause")
        run_engine(session, now)
        draft = build_plan(
            session, kind, target, now, cfg.plans, tz=tz, country=cfg.general.holidays_country
        )
        llm = cfg.llm.model_copy(update={"model": resolve_model(session, cfg.llm.model, model)})
        run_cfg = cfg.model_copy(update={"llm": llm})
        refinement, call = _refine(session, engine, draft, run_cfg, no_llm, client_factory, secret)
        if refinement is None:
            markdown = render_markdown(draft)
            final, plan_call_id = draft, None
            reason = "option --no-llm"
            ai: dict[str, object] = {"by_llm": False, "without_ai_reason": reason}
            by_llm = False
        else:
            markdown = render_markdown(
                draft, refinement.plan, without_ai=refinement.without_ai_reason
            )
            final = refinement.plan.draft
            by_llm = refinement.by_llm
            plan_call_id = refinement.llm.call_id if by_llm and refinement.llm else None
            reason = refinement.without_ai_reason or ""
            ai = refinement.plan.ai_data(refinement.without_ai_reason)
        plan_id = None
        if dry_run:
            session.rollback()
        else:
            plan_id = save_plan(session, final, markdown, llm_call_id=plan_call_id, ai=ai).id
            session.commit()
    note = ""
    if call is not None:
        note = (
            f"Appel IA ({call.model}) : {call.outcome.value}, {call.cost_usd} $, "
            f"{call.input_tokens} jetons en entrée dont {call.cached_tokens} en cache, "
            f"{call.output_tokens} en sortie."
        )
    return GeneratedPlan(
        plan_id=plan_id,
        markdown=markdown,
        by_llm=by_llm,
        without_ai_reason=reason,
        call_id=call.id if call is not None else None,
        outcome=call.outcome.value if call is not None else None,
        cost_usd=call.cost_usd if call is not None else None,
        ai_note=note,
    )
