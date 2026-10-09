"""Message Teams par webhook Workflows (SPEC F9, SECURITY.md C13).

L'URL complète (avec signature `sig`) est un secret (`teams_webhook_url`). Un seul appel
autorisé : `POST …/workflows/<id>/triggers/manual/paths/invoke`, avec les seuls paramètres
de requête attendus. Le message ne contient qu'un résumé et un lien vers Vigie.
"""

from __future__ import annotations

import re
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from vigie.connectors.base import AllowedCall, SafeClient, SourceCallError, Transport

PATH_RE = (
    r"^(/powerautomate/automations/direct)?/workflows/[0-9a-f]{32}/triggers/manual/paths/invoke$"
)
QUERY = frozenset({"api-version", "sp", "sv", "sig"})


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Attachment(_Strict):
    contentType: Literal["application/vnd.microsoft.card.adaptive"]  # noqa: N815
    content: dict[str, Any]


class TeamsPayload(_Strict):
    type: Literal["message"]
    attachments: list[Attachment] = Field(min_length=1, max_length=1)


class TeamsError(Exception):
    """Échec d'envoi (message neutre : jamais l'URL ni sa signature)."""


class TeamsWebhook:
    def __init__(
        self,
        url: SecretStr,
        *,
        proxy: str | None = None,
        transport: Transport | None = None,
    ) -> None:
        parts = urlsplit(url.get_secret_value())
        if parts.scheme != "https" or not parts.hostname or not re.match(PATH_RE, parts.path):
            raise TeamsError("URL de webhook Teams invalide (HTTPS Workflows attendu)")
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        if not set(params) <= QUERY:
            raise TeamsError("URL de webhook Teams : paramètres inattendus")
        self.path = parts.path
        self.params = params
        self.client = SafeClient(
            source="teams",
            base_url=f"https://{parts.netloc}",
            allowlist=[
                AllowedCall(
                    method="POST",
                    path=f"^{re.escape(parts.path)}$",  # exactement le chemin du secret
                    query=QUERY,
                    body_schema=TeamsPayload,
                    reason="message de synthèse du plan dans le canal Teams de l'équipe",
                )
            ],
            proxy=proxy,
            transport=transport,
        )

    def send(self, payload: dict[str, Any]) -> None:
        try:
            self.client.post(
                self.path, TeamsPayload.model_validate(payload).model_dump(mode="json"), self.params
            )
        except SourceCallError as exc:
            # Le message de SafeClient ne cite que le chemin, jamais la signature.
            raise TeamsError(str(exc)) from None
