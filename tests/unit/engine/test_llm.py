"""Appel au LLM avec un faux client (aucun réseau) : budget, erreurs, coûts, cache."""

import json
from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import anthropic
import httpx2
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.config import LLMConfig
from vigie.db import models
from vigie.db.enums import LLMOutcome, PlanKind
from vigie.engine.context import Prompt
from vigie.engine.llm import (
    FALLBACK_BETA,
    MOST_EXPENSIVE,
    PlanRefiner,
    month_spend,
    parse_plan,
    price_of,
    usage_cost,
)
from vigie.engine.llm_schema import OUTPUT_SCHEMA

NOW = datetime(2026, 10, 13, 5, 15, tzinfo=UTC)
PROMPT = Prompt(
    system=[{"type": "text", "text": "stable", "cache_control": {"type": "ephemeral"}}],
    user="<source_data>{}</source_data>",
    prompt_hash="a" * 64,
)
VALID = {"summary_exec": "RAS.", "per_person": [], "tasks": [], "risks": [], "escalations": []}


def usage(**kw: int) -> SimpleNamespace:
    base = {
        "input_tokens": 1000,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "output_tokens": 500,
        "iterations": None,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def response(text: str | None = None, stop: str = "end_turn", **kw: Any) -> SimpleNamespace:
    content = [SimpleNamespace(type="thinking", thinking="")]
    if text is not None:
        content.append(SimpleNamespace(type="text", text=text))
    return SimpleNamespace(
        content=content,
        stop_reason=stop,
        model=kw.get("model", "claude-sonnet-5-5"),
        usage=kw.get("usage", usage()),
    )


class FakeClient:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: list[dict[str, Any]] = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def calls(session: Session) -> list[models.LLMCall]:
    return list(session.scalars(select(models.LLMCall).order_by(models.LLMCall.id)))


def test_prices_and_costs() -> None:
    assert price_of("claude-sonnet-5-5").output == Decimal(10)
    assert price_of("modele-inconnu") == MOST_EXPENSIVE
    # 1000 × 2 + 2000 × 2 × 1,25 + 10 000 × 0,20 + 500 × 10 = 14 000 µ$ → 0,014 $
    u = usage(cache_creation_input_tokens=2000, cache_read_input_tokens=10_000)
    assert usage_cost("claude-sonnet-5-5", u) == Decimal("0.0140")
    # Repli serveur : chaque itération à son modèle.
    iters = [
        SimpleNamespace(
            model="claude-sonnet-5-5",
            input_tokens=1000,
            output_tokens=0,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0,
        ),
        SimpleNamespace(
            model="claude-opus-5-5",
            input_tokens=1000,
            output_tokens=1000,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0,
        ),
    ]
    assert usage_cost("claude-opus-5-5", usage(iterations=iters)) == Decimal("0.0260")


def test_parse_plan() -> None:
    assert parse_plan(response(json.dumps(VALID))).summary_exec == "RAS."
    with pytest.raises(ValueError):
        parse_plan(response(None))
    with pytest.raises(ValueError):
        parse_plan(response("[1, 2]"))


@pytest.mark.db
def test_successful_call_request_shape_and_log(db_session: Session) -> None:
    client = FakeClient(response(json.dumps(VALID), usage=usage(cache_read_input_tokens=800)))
    result = PlanRefiner(client, LLMConfig(), db_session).refine(PROMPT, PlanKind.daily, NOW)
    assert result.outcome is LLMOutcome.ok and result.plan is not None
    [sent] = client.calls
    assert sent["model"] == "claude-sonnet-5-5"
    assert sent["max_tokens"] == 8000
    assert sent["system"] == PROMPT.system
    assert sent["output_config"] == {
        "effort": "medium",
        "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA},
    }
    assert sent["thinking"] == {"type": "adaptive"}
    assert sent["betas"] == [FALLBACK_BETA] and sent["fallbacks"] == "default"
    assert "tools" not in sent and "tool_choice" not in sent  # aucun outil (SECURITY C3)
    [row] = calls(db_session)
    assert (row.outcome, row.cached_tokens, row.prompt_hash) == (LLMOutcome.ok, 800, "a" * 64)
    assert row.cost_usd > 0 and row.id == result.call_id


@pytest.mark.db
def test_fallback_can_be_disabled_and_weekly_tokens(db_session: Session) -> None:
    client = FakeClient(response(json.dumps(VALID)))
    PlanRefiner(client, LLMConfig(fallback=False), db_session).refine(PROMPT, PlanKind.weekly, NOW)
    assert "betas" not in client.calls[0] and "fallbacks" not in client.calls[0]
    assert client.calls[0]["max_tokens"] == 16000


@pytest.mark.db
@pytest.mark.parametrize(
    ("result", "outcome", "detail"),
    [
        (response("pas du json"), LLMOutcome.invalid, "sortie invalide"),
        (response(json.dumps({**VALID, "extra": 1})), LLMOutcome.invalid, "sortie invalide"),
        (
            response(json.dumps({**VALID, "summary_exec": "x" * 601})),
            LLMOutcome.invalid,
            "sortie invalide",
        ),
        (response(None, stop="refusal"), LLMOutcome.invalid, "refusal"),
        (response("{", stop="max_tokens"), LLMOutcome.invalid, "max_tokens"),
    ],
)
def test_invalid_outputs(
    db_session: Session, result: Any, outcome: LLMOutcome, detail: str
) -> None:
    out = PlanRefiner(FakeClient(result), LLMConfig(), db_session).refine(
        PROMPT, PlanKind.daily, NOW
    )
    assert (out.outcome, out.plan) == (outcome, None)
    assert detail in out.detail
    assert calls(db_session)[-1].outcome is outcome


def _request() -> httpx2.Request:
    return httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


@pytest.mark.db
@pytest.mark.parametrize(
    "exc",
    [
        anthropic.RateLimitError(
            "secret prompt", response=httpx2.Response(429, request=_request()), body=None
        ),
        anthropic.InternalServerError(
            "secret prompt", response=httpx2.Response(500, request=_request()), body=None
        ),
        anthropic.APIConnectionError(request=_request()),
    ],
)
def test_api_errors_are_recorded_without_content(db_session: Session, exc: Exception) -> None:
    out = PlanRefiner(FakeClient(exc), LLMConfig(), db_session).refine(PROMPT, PlanKind.daily, NOW)
    assert out.outcome is LLMOutcome.error
    row = calls(db_session)[-1]
    assert row.error is not None and "secret" not in row.error
    assert type(exc).__name__ in row.error


@pytest.mark.db
def test_budget_exceeded_means_no_call(db_session: Session) -> None:
    db_session.add(
        models.LLMCall(
            at=NOW,
            model="claude-sonnet-5-5",
            cost_usd=Decimal("29.99"),
            prompt_hash="b" * 64,
            outcome=LLMOutcome.ok,
        )
    )
    db_session.flush()
    assert month_spend(db_session, NOW) == Decimal("29.99")
    client = FakeClient(response(json.dumps(VALID)))
    out = PlanRefiner(client, LLMConfig(), db_session).refine(PROMPT, PlanKind.daily, NOW)
    assert out.outcome is LLMOutcome.budget_exceeded and not client.calls
    assert "29.99 $ dépensés sur 30.00 $" in out.detail


@pytest.mark.db
def test_previous_month_does_not_count(db_session: Session) -> None:
    db_session.add(
        models.LLMCall(
            at=datetime(2026, 9, 30, 23, 0, tzinfo=UTC),
            model="m",
            cost_usd=Decimal(50),
            prompt_hash="c" * 64,
            outcome=LLMOutcome.ok,
        )
    )
    db_session.flush()
    assert month_spend(db_session, NOW) == 0
