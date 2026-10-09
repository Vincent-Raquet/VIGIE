"""Envoi d'e-mails par Microsoft Graph (SPEC F9, SECURITY.md C13).

- Jeton applicatif par **certificat** (MSAL, client credentials, scope `.default`).
- Un seul appel autorisé : `POST /v1.0/users/{id de la boîte d'envoi}/sendMail`, corps
  validé par schéma strict (un destinataire, HTML) ; Graph limite en plus l'application à
  cette boîte (RBAC for Applications d'Exchange Online).
- Le journal ne contient ni adresse, ni sujet, ni contenu.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from vigie.connectors.base import AllowedCall, SafeClient, SourceCallError, Transport

logger = logging.getLogger("vigie.notify")
GRAPH_URL = "https://graph.microsoft.com"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_GUID = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
_EMAIL = r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class EmailAddress(_Strict):
    address: str = Field(pattern=_EMAIL, max_length=254)
    name: str = Field("", max_length=100)


class Recipient(_Strict):
    emailAddress: EmailAddress  # noqa: N815 - nom imposé par Graph


class Body(_Strict):
    contentType: Literal["HTML"] = "HTML"  # noqa: N815
    content: str = Field(max_length=500_000)


class Message(_Strict):
    subject: str = Field(min_length=1, max_length=255)
    body: Body
    toRecipients: list[Recipient] = Field(min_length=1, max_length=1)  # noqa: N815


class SendMailBody(_Strict):
    message: Message
    saveToSentItems: bool = True  # noqa: N815


class MailError(Exception):
    """Échec d'envoi (message neutre, sans contenu)."""


TokenProvider = Callable[[], str]


def graph_allowlist(sender_id: str) -> list[AllowedCall]:
    if not _GUID.match(sender_id):
        raise ValueError("mail_sender_id : ID d'objet Entra (GUID) attendu")
    return [
        AllowedCall(
            method="POST",
            path=rf"^/v1\.0/users/{re.escape(sender_id)}/sendMail$",
            body_schema=SendMailBody,
            reason="envoi du plan depuis la boîte de Vigie (seule action d'écriture du projet, "
            "hors des systèmes supervisés)",
        )
    ]


def normalize_pem(value: str) -> str:
    """PEM sur une ligne (`.env.local`) : `\\n` littéraux → retours à la ligne."""
    return value.replace("\\n", "\n").strip() + "\n"


def msal_token_provider(
    tenant_id: str, client_id: str, certificate_pem: SecretStr, proxy: str | None = None
) -> TokenProvider:
    """Jeton applicatif Graph par certificat (MSAL met le jeton en cache jusqu'à expiration)."""
    import msal
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    pem = normalize_pem(certificate_pem.get_secret_value())
    cert = x509.load_pem_x509_certificate(pem.encode())
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential={
            "private_key": pem,
            "thumbprint": cert.fingerprint(hashes.SHA1()).hex(),  # noqa: S303 - exigé par Entra
        },
        proxies={"https": proxy} if proxy else None,
    )

    def token() -> str:
        result = app.acquire_token_for_client(scopes=[GRAPH_SCOPE])
        if "access_token" not in result:
            # Code d'erreur seulement : la description peut citer l'application.
            raise MailError(f"jeton Graph refusé ({result.get('error', 'erreur inconnue')})")
        return str(result["access_token"])

    return token


class GraphMailer:
    def __init__(
        self,
        sender_id: str,
        token: TokenProvider,
        *,
        proxy: str | None = None,
        transport: Transport | None = None,
    ) -> None:
        self.path = f"/v1.0/users/{sender_id}/sendMail"
        self.token = token
        self.client = SafeClient(
            source="graph",
            base_url=GRAPH_URL,
            allowlist=graph_allowlist(sender_id),
            proxy=proxy,
            transport=transport,
        )

    def send(self, to: str, name: str, subject: str, html: str) -> None:
        body = SendMailBody(
            message=Message(
                subject=subject[:255],
                body=Body(content=html),
                toRecipients=[Recipient(emailAddress=EmailAddress(address=to, name=name[:100]))],
            )
        )
        self.client.set_auth_header("Authorization", SecretStr(f"Bearer {self.token()}"))
        try:
            self.client.post(self.path, body.model_dump(mode="json"))
        except SourceCallError as exc:
            raise MailError(str(exc).replace("graph :", "Graph :")) from None
