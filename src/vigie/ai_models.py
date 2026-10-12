"""Modèles d'IA proposés (plans et discussion) et leurs tarifs.

Sans dépendance au SDK : le web l'utilise pour afficher et valider le choix (il n'appelle
jamais l'IA). Le modèle par défaut se règle dans Paramètres (setting `llm_model`, admin) ;
à défaut, `[llm] model` de la configuration. Un choix ponctuel est possible pour une
génération de plan ou une question de la discussion, parmi ces seuls modèles.

Tarifs : documentation Claude API (2026-10), dollars par million de jetons ; écriture du
cache facturée 1,25 × l'entrée (TTL 5 min).
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from sqlalchemy.orm import Session

SETTING_KEY = "llm_model"


@dataclass(frozen=True)
class Price:
    """Dollars par million de jetons."""

    input: Decimal
    output: Decimal
    cache_read: Decimal


@dataclass(frozen=True)
class AIModel:
    id: str
    label: str
    hint: str
    price: Price


MODELS: dict[str, AIModel] = {
    m.id: m
    for m in (
        AIModel(
            "claude-sonnet-5-5",
            "Claude Sonnet 5.5",
            "rapide et économique",
            Price(Decimal(2), Decimal(10), Decimal("0.20")),
        ),
        AIModel(
            "claude-opus-5-5",
            "Claude Opus 5.5",
            "raisonnement approfondi",
            Price(Decimal(4), Decimal(20), Decimal("0.20")),
        ),
        AIModel(
            "claude-fable-5-1",
            "Claude Fable 5.1",
            "le plus capable, le plus cher",
            Price(Decimal(10), Decimal(50), Decimal("0.25")),
        ),
    )
}
# Modèle hors liste (configuration ancienne, repli serveur) : compté au plus cher.
MOST_EXPENSIVE = Price(Decimal(10), Decimal(50), Decimal("1.00"))
EXTRA_PRICES: dict[str, Price] = {
    "claude-haiku-4-5": Price(Decimal(1), Decimal(5), Decimal("0.10")),
}


def price_of(model: str) -> Price:
    known = MODELS.get(model)
    return known.price if known else EXTRA_PRICES.get(model, MOST_EXPENSIVE)


def label_of(model: str) -> str:
    known = MODELS.get(model)
    return known.label if known else model


def default_model(session: Session, configured: str) -> str:
    """Modèle par défaut : réglage de l'interface s'il est valide, sinon la configuration."""
    from vigie.db import models

    row = session.get(models.Setting, SETTING_KEY)
    value = row.value if row is not None else None
    return value if isinstance(value, str) and value in MODELS else configured


def resolve_model(session: Session, configured: str, requested: str | None) -> str:
    """Choix ponctuel (s'il fait partie des modèles proposés), sinon le modèle par défaut."""
    if requested and requested in MODELS:
        return requested
    return default_model(session, configured)
