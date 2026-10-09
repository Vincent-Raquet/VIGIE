"""Appel au LLM pour raffiner un plan (SPEC §7.6, SECURITY.md C3).

- Aucun outil : sortie structurée (`output_config.format`) ; le texte rendu est validé par
  `LLMPlan` (Pydantic) puis par `vigie.engine.validator`, jamais exécuté.
- Budget mensuel vérifié **avant** l'appel, sur une estimation pessimiste.
- Chaque appel (ou refus pour budget) est journalisé dans `llm_call` : modèle, jetons, coût,
  hash du prompt, issue — jamais le contenu.
- Le client est injecté : les tests utilisent un faux client, sans réseau.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol

import anthropic
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vigie.config import LLMConfig
from vigie.db import models
from vigie.db.enums import LLMOutcome, PlanKind
from vigie.engine.context import Prompt
from vigie.engine.llm_schema import OUTPUT_SCHEMA, LLMPlan

logger = logging.getLogger("vigie.llm")

FALLBACK_BETA = "server-side-fallback-2026-07-01"
CACHE_WRITE_FACTOR = Decimal("1.25")  # écriture du cache (TTL 5 min)


@dataclass(frozen=True)
class Price:
    """Dollars par million de jetons."""

    input: Decimal
    output: Decimal
    cache_read: Decimal


# Tarifs publics (doc Claude API, 2026-09) ; un modèle inconnu est compté au plus cher.
PRICES: dict[str, Price] = {
    "claude-sonnet-5-5": Price(Decimal(2), Decimal(10), Decimal("0.20")),
    "claude-opus-5-5": Price(Decimal(4), Decimal(20), Decimal("0.20")),
    "claude-haiku-4-5": Price(Decimal(1), Decimal(5), Decimal("0.10")),
}
MOST_EXPENSIVE = Price(Decimal(10), Decimal(50), Decimal("1.00"))


def price_of(model: str) -> Price:
    return PRICES.get(model, MOST_EXPENSIVE)


def usage_cost(model: str, usage: Any) -> Decimal:
    """Coût d'un appel ; avec repli serveur, chaque itération est comptée à son modèle."""
    iterations = getattr(usage, "iterations", None) or []
    parts = [(getattr(it, "model", None) or model, it) for it in iterations] or [(model, usage)]
    total = Decimal(0)
    for name, u in parts:
        p = price_of(name)
        total += (
            Decimal(getattr(u, "input_tokens", 0) or 0) * p.input
            + Decimal(getattr(u, "cache_creation_input_tokens", 0) or 0)
            * p.input
            * CACHE_WRITE_FACTOR
            + Decimal(getattr(u, "cache_read_input_tokens", 0) or 0) * p.cache_read
            + Decimal(getattr(u, "output_tokens", 0) or 0) * p.output
        )
    return (total / Decimal(1_000_000)).quantize(Decimal("0.0001"))


class LLMClient(Protocol):
    """Sous-ensemble du client `anthropic.Anthropic` utilisé ici (injectable en test) :
    seul `client.beta.messages.create(**kwargs)` est appelé."""

    @property
    def beta(self) -> Any: ...


@dataclass(frozen=True)
class LLMResult:
    outcome: LLMOutcome
    plan: LLMPlan | None
    call_id: int | None
    detail: str = ""


def month_spend(session: Session, now: datetime) -> Decimal:
    start = now.astimezone(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    total = session.scalar(
        select(func.coalesce(func.sum(models.LLMCall.cost_usd), 0)).where(
            models.LLMCall.at >= start
        )
    )
    return Decimal(total or 0)


def max_tokens_for(cfg: LLMConfig, kind: PlanKind) -> int:
    return cfg.max_tokens_daily if kind is PlanKind.daily else cfg.max_tokens_weekly


class PlanRefiner:
    def __init__(self, client: LLMClient, cfg: LLMConfig, session: Session) -> None:
        self.client = client
        self.cfg = cfg
        self.session = session

    def _record(
        self,
        prompt: Prompt,
        outcome: LLMOutcome,
        *,
        model: str,
        usage: Any = None,
        error: str | None = None,
        now: datetime,
    ) -> int:
        row = models.LLMCall(
            at=now,
            model=model,
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0)
            + int(getattr(usage, "cache_creation_input_tokens", 0) or 0),
            cached_tokens=int(getattr(usage, "cache_read_input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
            cost_usd=usage_cost(model, usage) if usage is not None else Decimal(0),
            prompt_hash=prompt.prompt_hash,
            outcome=outcome,
            error=error,
        )
        self.session.add(row)
        self.session.flush()
        logger.info(
            "appel LLM",
            extra={
                "model": model,
                "outcome": outcome.value,
                "input_tokens": row.input_tokens,
                "cached_tokens": row.cached_tokens,
                "output_tokens": row.output_tokens,
                "cost_usd": str(row.cost_usd),
            },
        )
        return row.id

    def estimate_max_cost(self, prompt: Prompt, kind: PlanKind) -> Decimal:
        """Majorant : tout le prompt facturé plein tarif (≈ 4 caractères/jeton, ×1,5)."""
        p = price_of(self.cfg.model)
        chars = sum(len(b["text"]) for b in prompt.system) + len(prompt.user)
        input_tokens = Decimal(chars) / 4 * Decimal("1.5")
        output_tokens = Decimal(max_tokens_for(self.cfg, kind))
        return (input_tokens * p.input * CACHE_WRITE_FACTOR + output_tokens * p.output) / Decimal(
            1_000_000
        )

    def refine(self, prompt: Prompt, kind: PlanKind, now: datetime) -> LLMResult:
        spent = month_spend(self.session, now)
        budget = Decimal(str(self.cfg.monthly_budget_usd))
        if spent + self.estimate_max_cost(prompt, kind) > budget:
            detail = f"budget mensuel ({spent:.2f} $ dépensés sur {budget:.2f} $)"
            call_id = self._record(
                prompt, LLMOutcome.budget_exceeded, model=self.cfg.model, error=detail, now=now
            )
            return LLMResult(LLMOutcome.budget_exceeded, None, call_id, detail)

        request: dict[str, Any] = {
            "model": self.cfg.model,
            "max_tokens": max_tokens_for(self.cfg, kind),
            "system": prompt.system,
            "messages": [{"role": "user", "content": prompt.user}],
            "thinking": {"type": "adaptive"},
            "output_config": {
                "effort": self.cfg.effort,
                "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA},
            },
        }
        if self.cfg.fallback:
            request["betas"] = [FALLBACK_BETA]
            request["fallbacks"] = "default"
        try:
            response = self.client.beta.messages.create(**request)
        except anthropic.APIError as exc:
            # Type d'erreur seulement : le message peut citer des extraits de la requête.
            name = type(exc).__name__
            status = getattr(exc, "status_code", None)
            detail = f"{name} (HTTP {status})" if status else name
            call_id = self._record(
                prompt, LLMOutcome.error, model=self.cfg.model, error=detail, now=now
            )
            return LLMResult(LLMOutcome.error, None, call_id, detail)

        model = str(getattr(response, "model", None) or self.cfg.model)
        usage = getattr(response, "usage", None)
        stop = getattr(response, "stop_reason", None)
        if stop != "end_turn":
            detail = f"arrêt « {stop} »"
            call_id = self._record(
                prompt, LLMOutcome.invalid, model=model, usage=usage, error=detail, now=now
            )
            return LLMResult(LLMOutcome.invalid, None, call_id, detail)
        try:
            plan = parse_plan(response)
        except (ValueError, ValidationError) as exc:
            detail = f"sortie invalide ({type(exc).__name__})"
            call_id = self._record(
                prompt, LLMOutcome.invalid, model=model, usage=usage, error=detail, now=now
            )
            return LLMResult(LLMOutcome.invalid, None, call_id, detail)
        call_id = self._record(prompt, LLMOutcome.ok, model=model, usage=usage, now=now)
        return LLMResult(LLMOutcome.ok, plan, call_id)


def parse_plan(response: Any) -> LLMPlan:
    texts = [b.text for b in response.content if getattr(b, "type", None) == "text"]
    if not texts:
        raise ValueError("aucun bloc texte")
    data = json.loads("".join(texts))
    if not isinstance(data, Mapping):
        raise ValueError("objet JSON attendu")
    return LLMPlan.model_validate(data)


def make_client(api_key: str, cfg: LLMConfig) -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=api_key, max_retries=2, timeout=cfg.timeout_s)
