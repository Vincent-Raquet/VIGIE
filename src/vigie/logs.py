"""Journaux JSON sur stderr (capturés par journald), toujours masqués (SPEC §12, SECURITY C7)."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from vigie.redact import redact

# Attributs standard d'un LogRecord : tout le reste vient de `extra=`.
_STD_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message",
    "asctime",
    "taskName",
}

# Bibliothèques qui journalisent des URL complètes (avec paramètres) en INFO/DEBUG.
NOISY_LOGGERS = ("httpx", "httpcore")


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list | tuple):
        return [_redact_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    return value


class RedactingFilter(logging.Filter):
    """Masque le message formaté et chaque champ `extra` avant toute émission."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        for key, value in list(vars(record).items()):
            if key not in _STD_ATTRS:
                setattr(record, key, _redact_value(value))
        return True


class _VigieHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """Handler installé par Vigie (remplacé, jamais dupliqué, par configure_logging)."""


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "at": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        entry.update({k: v for k, v in vars(record).items() if k not in _STD_ATTRS})
        if record.exc_info:
            entry["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(entry, ensure_ascii=False, default=str)


def configure_logging(level: str = "INFO") -> None:
    level = level.upper() if level.upper() in logging.getLevelNamesMapping() else "INFO"
    handler = _VigieHandler(sys.stderr)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    for existing in [h for h in root.handlers if isinstance(h, _VigieHandler)]:
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    for name in NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
