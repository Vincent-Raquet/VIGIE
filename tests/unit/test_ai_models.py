"""Modèles d'IA proposés, tarifs et choix (défaut des Paramètres, choix ponctuel)."""

from decimal import Decimal
from typing import get_args

import pytest
from sqlalchemy.orm import Session

from vigie.ai_models import MODELS, SETTING_KEY, default_model, price_of, resolve_model
from vigie.db import models
from vigie.db.jobs import PlanGeneratePayload
from vigie.engine.llm import usage_cost


def test_three_models_with_documented_prices() -> None:
    assert set(MODELS) == {"claude-opus-5-5", "claude-sonnet-5-5", "claude-fable-5-1"}
    assert price_of("claude-fable-5-1").output == Decimal(50)
    assert price_of("claude-opus-5-5").input == Decimal(4)
    assert price_of("modele-inconnu").output == Decimal(50)  # compté au plus cher


def test_job_payload_accepts_exactly_the_proposed_models() -> None:
    annotation = PlanGeneratePayload.model_fields["model"].annotation
    literal = next(a for a in get_args(annotation) if get_args(a))
    assert set(get_args(literal)) == set(MODELS)


def test_cost_follows_the_model() -> None:
    from types import SimpleNamespace

    usage = SimpleNamespace(input_tokens=1_000_000, output_tokens=0, iterations=None)
    assert usage_cost("claude-sonnet-5-5", usage) == Decimal(2)
    assert usage_cost("claude-fable-5-1", usage) == Decimal(10)


@pytest.mark.db
def test_default_and_override(db_session: Session) -> None:
    assert default_model(db_session, "claude-sonnet-5-5") == "claude-sonnet-5-5"
    db_session.add(models.Setting(key=SETTING_KEY, value="claude-opus-5-5"))
    db_session.flush()
    assert default_model(db_session, "claude-sonnet-5-5") == "claude-opus-5-5"
    assert resolve_model(db_session, "claude-sonnet-5-5", "claude-fable-5-1") == "claude-fable-5-1"
    assert resolve_model(db_session, "claude-sonnet-5-5", "gpt-4") == "claude-opus-5-5"
    db_session.get(models.Setting, SETTING_KEY).value = "inconnu"  # type: ignore[union-attr]
    db_session.flush()
    assert default_model(db_session, "claude-sonnet-5-5") == "claude-sonnet-5-5"
