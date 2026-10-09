"""Chargement de la configuration non secrète (vigie.toml) et des secrets.

Configuration : `--config`, sinon `$VIGIE_CONFIG`, sinon `./config/vigie.toml`.
Il n'y a volontairement aucun repli implicite sur `/etc/vigie/vigie.toml` : la VM sert
aussi de machine de dev, le dev ne doit jamais lire la configuration de prod par accident.
Les unités systemd positionnent `VIGIE_CONFIG` explicitement.

Secrets (SECURITY.md C7) : lus un par un, à la demande, depuis `$CREDENTIALS_DIRECTORY`
(systemd `LoadCredentialEncrypted=`) ; à défaut, depuis `.env.local` uniquement si
`VIGIE_ENV=dev`. Jamais depuis l'environnement global, jamais affichés.
"""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Mapping
from datetime import time
from pathlib import Path
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from vigie.db.enums import AppRole

DEFAULT_CONFIG_PATH = Path("config/vigie.toml")
DEFAULT_ENV_FILE = Path(".env.local")
ENV_SECRET_PREFIX = "VIGIE_SECRET_"  # noqa: S105 - préfixe de clé, pas un secret

_SECRET_NAME_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_SOURCE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


class ConfigError(Exception):
    """Configuration absente ou invalide."""


class SecretError(Exception):
    """Secret introuvable ou nom invalide. Le message ne contient jamais de valeur."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class GeneralConfig(_Strict):
    timezone: str = "Europe/Brussels"
    base_url: str = "https://vigie.local.wallindustries.be"
    holidays_country: str = "BE"
    paused: bool = False

    @field_validator("timezone")
    @classmethod
    def _known_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"fuseau horaire inconnu : {value}") from exc
        return value


class DatabaseConfig(_Strict):
    # Socket unix + authentification peer : aucun mot de passe en dev.
    url: str = "postgresql+psycopg:///vigie"


class LLMConfig(_Strict):
    enabled: bool = True
    model: str = "claude-sonnet-5-5"
    max_tokens_daily: int = Field(8000, gt=0)
    max_tokens_weekly: int = Field(16000, gt=0)
    monthly_budget_usd: float = Field(30, ge=0)
    send_ticket_text: bool = False
    effort: Literal["low", "medium", "high"] = "medium"
    # Repli serveur si le modèle refuse pour raison de sécurité (fallbacks="default").
    fallback: bool = True
    timeout_s: float = Field(120, gt=0, le=600)


class PlansConfig(_Strict):
    daily_at: time = time(7, 15)
    daily_publish_at: time = time(7, 30)
    weekly_day: Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"] = "mon"
    weekly_at: time = time(6, 30)
    weekly_auto_publish_at: time = time(9, 0)
    max_tasks_per_person_per_day: int = Field(5, gt=0)
    carry_over_escalation_after: int = Field(3, gt=0)
    milestone_window_days: int = Field(21, gt=0)


class NotifyConfig(_Strict):
    mail_sender: str = ""
    teams_enabled: bool = False


class TLSConfig(_Strict):
    ca_bundle: Path | None = None


class OIDCConfig(_Strict):
    """Application Entra ID (non secret ; le secret client est `entra_client_secret`)."""

    tenant_id: str = Field("", pattern=r"^([0-9a-f-]{36})?$")
    client_id: str = Field("", pattern=r"^([0-9a-f-]{36})?$")
    # ID d'objet du groupe Entra → rôle applicatif (SG-Vigie-Admin, -Manager, -Tech, -Viewer).
    groups: dict[str, AppRole] = Field(default_factory=dict)

    @property
    def configured(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.groups)


class WebConfig(_Strict):
    host: str = "127.0.0.1"  # derrière Caddy ; jamais exposé directement
    port: int = Field(8000, ge=1, le=65535)
    # Base de vigie-web (rôle vigie_web en prod) ; défaut : [database] url.
    database_url: str | None = None
    session_hours: int = Field(8, ge=1, le=24)
    # Connexion de développement : exige aussi VIGIE_ENV=dev et une écoute sur 127.0.0.1.
    dev_login: bool = False
    oidc: OIDCConfig = OIDCConfig()


class SourceConfig(BaseModel):
    """Champs communs à toutes les sources.

    Les champs propres à un système (URL, filtres, instances…) restent libres ici et sont
    validés par le modèle de configuration du connecteur lui-même : ajouter une source ne
    demande aucune modification de ce module.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    enabled: bool = False
    interval_min: int = Field(15, ge=1, le=1440)


class VigieConfig(_Strict):
    general: GeneralConfig = GeneralConfig()
    database: DatabaseConfig = DatabaseConfig()
    llm: LLMConfig = LLMConfig()
    plans: PlansConfig = PlansConfig()
    notify: NotifyConfig = NotifyConfig()
    tls: TLSConfig = TLSConfig()
    web: WebConfig = WebConfig()
    sources: dict[str, SourceConfig] = Field(default_factory=dict)

    @field_validator("sources")
    @classmethod
    def _valid_source_names(cls, value: dict[str, SourceConfig]) -> dict[str, SourceConfig]:
        for name in value:
            if not _SOURCE_NAME_RE.match(name):
                raise ValueError(f"nom de source invalide : {name!r}")
        return value

    def enabled_sources(self) -> list[str]:
        return sorted(name for name, src in self.sources.items() if src.enabled)


def resolve_config_path(explicit: Path | None = None, env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    if explicit is not None:
        return explicit
    if env.get("VIGIE_CONFIG"):
        return Path(env["VIGIE_CONFIG"])
    return DEFAULT_CONFIG_PATH


def load_config(path: Path | None = None, env: Mapping[str, str] | None = None) -> VigieConfig:
    resolved = resolve_config_path(path, env)
    try:
        with resolved.open("rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError as exc:
        raise ConfigError(f"fichier de configuration introuvable : {resolved}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"TOML invalide dans {resolved} : {exc}") from exc
    try:
        return VigieConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"configuration invalide dans {resolved} :\n{exc}") from exc


def get_secret(
    name: str,
    *,
    env: Mapping[str, str] | None = None,
    env_file: Path = DEFAULT_ENV_FILE,
) -> SecretStr:
    """Retourne le secret `name` ; lève `SecretError` s'il est introuvable."""
    env = os.environ if env is None else env
    if not _SECRET_NAME_RE.match(name):
        raise SecretError("nom de secret invalide")

    cred_dir = env.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        # Prod : uniquement systemd-creds, pas de repli sur .env.local.
        try:
            value = (Path(cred_dir) / name).read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise SecretError(f"secret {name} absent de CREDENTIALS_DIRECTORY") from exc
        return SecretStr(value.rstrip("\r\n"))

    if env.get("VIGIE_ENV") == "dev":
        key = ENV_SECRET_PREFIX + name.upper()
        values = _read_env_file(env_file)
        if key in values:
            return SecretStr(values[key])
        raise SecretError(f"secret {name} absent de {env_file} ({key})")

    raise SecretError(f"secret {name} indisponible : ni CREDENTIALS_DIRECTORY ni VIGIE_ENV=dev")


def _read_env_file(path: Path) -> dict[str, str]:
    """Analyse minimale KEY=VALUE ; aucune expansion, aucune exécution."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values
