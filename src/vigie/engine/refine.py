"""Raffinement d'un plan par le LLM, avec repli déterministe (SPEC §7.6).

Plan déterministe → prompt → appel → validation. Tout échec (IA désactivée, secret absent,
budget, erreur, sortie invalide) rend le plan déterministe, accompagné de la raison qui
sera affichée (« généré sans IA »).
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from vigie.config import LLMConfig, PlansConfig
from vigie.db.enums import LLMOutcome
from vigie.engine.context import build_prompt
from vigie.engine.llm import LLMClient, LLMResult, PlanRefiner
from vigie.engine.planner import PlanDraft
from vigie.engine.settings import load_scoring
from vigie.engine.validator import RefinedPlan, validate


@dataclass(frozen=True)
class Refinement:
    plan: RefinedPlan
    llm: LLMResult | None
    without_ai_reason: str | None  # None : plan affiné par l'IA et validé

    @property
    def by_llm(self) -> bool:
        return self.without_ai_reason is None


def deterministic(draft: PlanDraft, reason: str) -> Refinement:
    return Refinement(RefinedPlan(draft=draft), None, reason)


def refine(
    data_session: Session,
    log_session: Session,
    draft: PlanDraft,
    client: LLMClient,
    llm_cfg: LLMConfig,
    plans: PlansConfig,
    *,
    country: str = "BE",
) -> Refinement:
    """`data_session` lit le contexte ; `log_session` journalise l'appel (validé à part,
    pour que le coût soit compté même si le plan n'est pas enregistré)."""
    prompt = build_prompt(data_session, draft, load_scoring(data_session))
    refiner = PlanRefiner(client, llm_cfg, log_session)
    result = refiner.refine(prompt, draft.kind, draft.generated_at)
    if result.outcome is not LLMOutcome.ok or result.plan is None:
        return Refinement(RefinedPlan(draft=draft), result, result.detail or result.outcome.value)
    refined = validate(
        draft,
        result.plan,
        max_tasks_per_day=plans.max_tasks_per_person_per_day,
        country=country,
    )
    return Refinement(refined, result, None)
