"""En-têtes de sécurité et protection CSRF (SECURITY.md C9).

- Chaque réponse, statiques compris, porte une CSP stricte : aucun script, style ou police
  hors de l'application, aucun cadre, formulaires vers l'application seulement.
- Toute requête mutante (POST, PUT, PATCH, DELETE) doit présenter le jeton CSRF de la
  session, en en-tête `X-CSRF-Token` (htmx) ou en champ de formulaire `csrf_token`.
  La vérification est une dépendance globale de l'application : aucune route ne l'oublie.
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from fastapi import HTTPException, Request

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; object-src 'none'"
)
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "x-csrf-token"

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class SecurityHeaders:
    """Middleware ASGI : ajoute les en-têtes à toutes les réponses HTTP."""

    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        headers = [
            (b"content-security-policy", CSP.encode()),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
            (b"x-content-type-options", b"nosniff"),
            (b"cross-origin-opener-policy", b"same-origin"),
            (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
        ]
        if hsts:
            headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
        self.headers = headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                message["headers"] = [
                    *message.get("headers", []),
                    *((k, v) for k, v in self.headers if k not in existing),
                ]
            await send(message)

        await self.app(scope, receive, with_headers)


def csrf_token(request: Request) -> str:
    """Jeton CSRF de la session (créé au besoin, y compris pour un visiteur anonyme)."""
    token = request.session.get("csrf")
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


async def csrf_protect(request: Request) -> None:
    """Dépendance globale : refuse toute requête mutante sans le bon jeton."""
    if request.method in SAFE_METHODS:
        return
    expected = request.session.get("csrf")
    sent = request.headers.get(CSRF_HEADER)
    if sent is None:
        content_type = request.headers.get("content-type", "")
        if content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
            form = await request.form()  # mis en cache : les routes relisent le même formulaire
            value = form.get(CSRF_FIELD)
            sent = value if isinstance(value, str) else None
    if not isinstance(expected, str) or not sent or not hmac.compare_digest(expected, sent):
        raise HTTPException(status_code=403, detail="Jeton CSRF absent ou invalide.")
