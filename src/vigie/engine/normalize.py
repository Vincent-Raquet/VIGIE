"""Normalisation des signaux (SPEC §7.2) : empreinte de dédoublonnage et hash du brut."""

from __future__ import annotations

import hashlib
import json
import re

from vigie.connectors.base import Signal
from vigie.mapping import normalize as normalize_text

_NUMBER_RE = re.compile(r"\d+(?:[.,]\d+)*")
_SPACES_RE = re.compile(r"\s+")


def normalize_title(title: str) -> str:
    """Titre sans chiffres variables (compteurs, valeurs, dates), casse et accents."""
    return _SPACES_RE.sub(" ", _NUMBER_RE.sub("#", normalize_text(title))).strip()


def normalize_asset(asset: str) -> str:
    """Nom d'hôte comparable entre sources : minuscules, sans accents ni domaine."""
    name = normalize_text(asset)
    if "." in name and not name.replace(".", "").isdigit():
        name = name.split(".", 1)[0]
    return name


def fingerprint(signal: Signal) -> str:
    """sha256(source | société | actif | catégorie | titre normalisé)."""
    parts = (
        signal.source,
        signal.company_code or "",
        normalize_asset(signal.asset),
        signal.category.value,
        normalize_title(signal.title),
    )
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def raw_hash(signal: Signal) -> str:
    """Change dès qu'un champ affiché change : détecte les mises à jour."""
    payload = {
        "title": signal.title,
        "details": signal.details,
        "severity": signal.severity,
        "category": signal.category.value,
        "company": signal.company_code,
        "asset": signal.asset,
        "attributes": dict(signal.attributes),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
