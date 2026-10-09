"""Authentification et rôles (SECURITY.md C9, SPEC §2).

Trois façons d'ouvrir une session, toutes journalisées dans `audit_log` :
- **Entra ID** (OIDC, code + PKCE) : rôle = le plus élevé des groupes mappés dans
  `[web.oidc] groups` ; aucun groupe mappé → accès refusé. Si Entra signale un
  dépassement de groupes (« groups overage »), l'accès est refusé (point M de la roadmap).
- **Développement** : seulement si `VIGIE_ENV=dev`, `[web] dev_login = true` et écoute
  locale. Sinon les routes n'existent pas (404).
- **Bris de glace** : mot de passe à usage unique créé en CLI sur le serveur
  (`vigie breakglass --enable`), haché, expirant ; supprimé dès son utilisation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from fastapi import HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vigie.config import OIDCConfig
from vigie.db import models
from vigie.db.enums import AppRole

ROLE_RANK = {AppRole.admin: 4, AppRole.manager: 3, AppRole.tech: 2, AppRole.viewer: 1}
BREAKGLASS_KEY = "breakglass"
LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


@dataclass(frozen=True)
class User:
    name: str
    email: str
    role: AppRole
    person_id: int | None
    via: str  # entra | dev | breakglass

    def to_session(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "email": self.email,
            "role": self.role.value,
            "person_id": self.person_id,
            "via": self.via,
        }

    @classmethod
    def from_session(cls, data: Mapping[str, Any]) -> User:
        return cls(
            name=str(data["name"]),
            email=str(data["email"]),
            role=AppRole(data["role"]),
            person_id=data.get("person_id"),
            via=str(data["via"]),
        )

    def can(self, *roles: AppRole) -> bool:
        return self.role in roles


class LoginRequiredError(Exception):
    """Aucune session valide : redirection vers /login (HTML) ou 401 (API)."""


def current_user(request: Request, max_age_s: int) -> User | None:
    data = request.session.get("user")
    login_at = request.session.get("login_at")
    if not isinstance(data, dict) or not isinstance(login_at, int | float):
        return None
    if time.time() - login_at > max_age_s:
        request.session.clear()
        return None
    try:
        return User.from_session(data)
    except (KeyError, ValueError):
        request.session.clear()
        return None


def open_session(request: Request, user: User) -> None:
    """Nouvelle session (identifiant et jeton CSRF renouvelés : pas de fixation)."""
    request.session.clear()
    request.session["user"] = user.to_session()
    request.session["login_at"] = int(time.time())
    request.session["csrf"] = secrets.token_urlsafe(32)


def require_role(*roles: AppRole) -> Callable[[Request], User]:
    """Dépendance de route : session valide et rôle autorisé, sinon 401/403."""
    allowed = frozenset(roles)

    def dependency(request: Request) -> User:
        user: User | None = request.state.user
        if user is None:
            raise LoginRequiredError
        if user.role not in allowed:
            raise HTTPException(status_code=403, detail="Accès refusé pour votre rôle.")
        return user

    return dependency


def audit(session: Session, actor: str, action: str, obj: str = "", **details: Any) -> None:
    session.add(
        models.AuditLog(actor=actor[:100], action=action[:100], object=obj[:200], details=details)
    )


def person_for_email(session: Session, email: str) -> models.Person | None:
    return session.scalar(
        select(models.Person).where(func.lower(models.Person.email) == email.lower())
    )


# --- Entra ID --------------------------------------------------------------------------


class OIDCClient(Protocol):
    """Sous-ensemble du client authlib (injectable en test)."""

    async def authorize_redirect(self, request: Request, redirect_uri: str) -> Any: ...

    async def authorize_access_token(self, request: Request) -> dict[str, Any]: ...


class AccessDeniedError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def role_from_groups(claims: Mapping[str, Any], cfg: OIDCConfig) -> AppRole:
    if "_claim_names" in claims and "groups" in claims.get("_claim_names", {}):
        raise AccessDeniedError(
            "trop de groupes dans le jeton Entra : n'émettre que les groupes assignés"
        )
    groups = claims.get("groups") or []
    roles = [cfg.groups[g] for g in groups if isinstance(g, str) and g in cfg.groups]
    if not roles:
        raise AccessDeniedError("aucun groupe SG-Vigie-* attribué à ce compte")
    return max(roles, key=lambda r: ROLE_RANK[r])


def user_from_claims(session: Session, claims: Mapping[str, Any], cfg: OIDCConfig) -> User:
    if claims.get("tid") not in (None, cfg.tenant_id):
        raise AccessDeniedError("locataire Entra inattendu")
    email = str(claims.get("email") or claims.get("preferred_username") or "").strip()
    if not email:
        raise AccessDeniedError("jeton sans adresse e-mail")
    role = role_from_groups(claims, cfg)
    person = person_for_email(session, email)
    if person is not None and not person.active:
        raise AccessDeniedError("personne désactivée dans Vigie")
    name = person.name if person else str(claims.get("name") or email)
    return User(name, email, role, person.id if person else None, "entra")


def make_entra_client(cfg: OIDCConfig, client_secret: str) -> OIDCClient:
    from authlib.integrations.starlette_client import OAuth

    oauth = OAuth()
    oauth.register(
        name="entra",
        client_id=cfg.client_id,
        client_secret=client_secret,
        server_metadata_url=(
            f"https://login.microsoftonline.com/{cfg.tenant_id}/v2.0/.well-known/openid-configuration"
        ),
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
    )
    client: OIDCClient = oauth.create_client("entra")
    return client


# --- Développement ---------------------------------------------------------------------


def dev_login_enabled(dev_login: bool, host: str, env: Mapping[str, str]) -> bool:
    return dev_login and env.get("VIGIE_ENV") == "dev" and host in LOCAL_HOSTS


# --- Bris de glace ---------------------------------------------------------------------


def _hash(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()


def enable_breakglass(session: Session, ttl: timedelta, now: datetime) -> str:
    """Crée le mot de passe de secours (affiché une seule fois par la CLI)."""
    password = secrets.token_urlsafe(18)
    salt = secrets.token_bytes(16)
    value = {
        "salt": salt.hex(),
        "hash": _hash(password, salt),
        "expires_at": (now + ttl).astimezone(UTC).isoformat(),
    }
    row = session.get(models.Setting, BREAKGLASS_KEY)
    if row is None:
        session.add(models.Setting(key=BREAKGLASS_KEY, value=value))
    else:
        row.value = value
    session.flush()
    return password


def disable_breakglass(session: Session) -> bool:
    row = session.get(models.Setting, BREAKGLASS_KEY)
    if row is None:
        return False
    session.delete(row)
    session.flush()
    return True


def breakglass_active(session: Session, now: datetime) -> bool:
    row = session.get(models.Setting, BREAKGLASS_KEY)
    if row is None or not isinstance(row.value, dict):
        return False
    try:
        return datetime.fromisoformat(row.value["expires_at"]) > now
    except (KeyError, ValueError):
        return False


def check_breakglass(session: Session, password: str, now: datetime) -> bool:
    """Vrai si le mot de passe est bon et valide ; le compte est alors consommé."""
    if not breakglass_active(session, now):
        return False
    row = session.get(models.Setting, BREAKGLASS_KEY)
    if row is None:  # pragma: no cover - garanti par breakglass_active
        return False
    expected = row.value.get("hash", "")
    candidate = _hash(password, bytes.fromhex(row.value.get("salt", "")))
    if not hmac.compare_digest(expected, candidate):
        return False
    disable_breakglass(session)
    return True
