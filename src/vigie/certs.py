"""Expiration des certificats d'authentification des sources (ex. Defender).

Seul le certificat public est lu (`[sources.<nom>] certificate`), jamais la clé privée.
"""

from __future__ import annotations

import math
from datetime import datetime
from pathlib import Path

from vigie.config import VigieConfig

CERT_WARN_DAYS = 30


def certificate_days_left(path: Path, now: datetime) -> int:
    """Jours restants avant expiration du certificat PEM (négatif s'il est expiré)."""
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(path.read_bytes())
    return math.floor((cert.not_valid_after_utc - now).total_seconds() / 86400)


def source_certificates(cfg: VigieConfig, now: datetime) -> dict[str, int | None]:
    """Jours restants par source activée déclarant un `certificate` (None : illisible)."""
    out: dict[str, int | None] = {}
    for name in cfg.enabled_sources():
        path = (cfg.sources[name].model_extra or {}).get("certificate")
        if not path:
            continue
        try:
            out[name] = certificate_days_left(Path(str(path)).expanduser(), now)
        except (OSError, ValueError):
            out[name] = None
    return out
