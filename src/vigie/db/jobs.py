"""Demandes web → worker (`job_request`).

Le payload ne contient **jamais** de secret : uniquement des références (nom de source…).
Chaque `kind` a un schéma strict ; un kind inconnu, un champ en trop ou un payload trop gros
sont refusés avant l'écriture. La base borne aussi la taille (contrainte `payload_size`).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vigie.db.enums import JobKind

if TYPE_CHECKING:
    from vigie.db.models import JobRequest

MAX_PAYLOAD_BYTES = 4096


class JobPayloadError(ValueError):
    """Payload de demande refusé."""


class _Payload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SourceTestPayload(_Payload):
    """« Tester la connexion » : healthcheck en lecture seule d'une source configurée."""

    source: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}(:[a-z0-9][a-z0-9_-]{0,31})?$")


PAYLOAD_SCHEMAS: dict[JobKind, type[_Payload]] = {
    JobKind.source_test: SourceTestPayload,
}


def validate_payload(kind: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    try:
        job_kind = JobKind(kind)
    except ValueError as exc:
        raise JobPayloadError(f"type de demande inconnu : {kind!r}") from exc
    try:
        size = len(json.dumps(payload, ensure_ascii=False).encode())
    except (TypeError, ValueError) as exc:
        raise JobPayloadError("payload non sérialisable en JSON") from exc
    if size > MAX_PAYLOAD_BYTES:
        raise JobPayloadError(f"payload trop volumineux ({size} > {MAX_PAYLOAD_BYTES} octets)")
    try:
        model = PAYLOAD_SCHEMAS[job_kind].model_validate(dict(payload))
    except ValidationError as exc:
        raise JobPayloadError(f"payload invalide pour {job_kind} : {exc}") from exc
    return model.model_dump(mode="json")


def new_job_request(kind: str, payload: Mapping[str, Any], requested_by: str) -> JobRequest:
    """Seul point de création d'une `JobRequest` : valide le payload."""
    from vigie.db.models import JobRequest

    return JobRequest(
        kind=JobKind(kind),
        payload=validate_payload(kind, payload),
        requested_by=requested_by,
    )
