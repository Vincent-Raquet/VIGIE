"""Contrat des connecteurs et `SafeClient` : seul point de sortie réseau vers les sources.

Garantie (CLAUDE.md règle 1, SECURITY.md C2) : un appel absent de l'allowlist du connecteur
lève `ForbiddenCallError` **avant** l'envoi. Les allowlists sont elles-mêmes contrôlées à la
définition (chemins ancrés, aucune méthode d'écriture HTTP, verbes JSON-RPC destructifs
refusés sauf exception justifiée).
"""

from __future__ import annotations

import json
import logging
import re
import ssl
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, NoReturn, Protocol

import httpx
from pydantic import BaseModel, RootModel, SecretStr, ValidationError

from vigie import __version__
from vigie.db.enums import Category

logger = logging.getLogger("vigie.connectors")
# httpx journalise les URL complètes (paramètres compris) en INFO : jamais dans nos journaux.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

CONNECT_TIMEOUT_S = 5.0
READ_TIMEOUT_S = 30.0
MAX_RETRIES = 3
RETRY_BASE_DELAY_S = 0.5
RETRY_STATUSES = frozenset({429, 502, 503, 504})
MAX_RESPONSE_BYTES = 20 * 1024 * 1024
MAX_OBJECTS = 5000

ALLOWED_HTTP_METHODS = frozenset({"GET", "POST"})
_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._~\-/*:,]*$")
_RPC_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]*$")
# Verbes d'action : une méthode JSON-RPC qui en contient un est refusée sauf override justifié.
_DESTRUCTIVE_RPC_RE = re.compile(
    r"(?:^|[._])(?:create|update|delete|remove|set|add|exec|execute|clone|move|mass\w*|"
    r"acknowledge|ack|import|run|start|stop|enable|disable|restart|reboot|install|push|"
    r"replace|purge|reset)(?:$|[._])",
    re.IGNORECASE,
)
_BROAD_REGEX_RE = re.compile(r"(?<!\\)\.[*+]")


# Transport HTTP injectable (rejeu de fixtures, tests) sans importer httpx ailleurs.
Transport = httpx.BaseTransport


class AllowlistDefinitionError(ValueError):
    """Entrée d'allowlist mal formée (erreur de programmation, détectée au chargement)."""


class ForbiddenCallError(Exception):
    """Appel hors allowlist : refusé avant toute émission réseau."""

    def __init__(self, source: str, target: str, reason: str) -> None:
        super().__init__(f"appel interdit vers {source} : {target} ({reason})")
        self.source = source
        self.target = target
        self.reason = reason


class ConnectorConfigError(ValueError):
    """Bloc `[sources.<nom>]` invalide (le message nomme les champs, jamais leurs valeurs)."""


class SourceCallError(Exception):
    """Échec d'un appel autorisé (réseau, HTTP, réponse invalide). Message sans donnée.

    `status` : code HTTP de la réponse quand il y en a une (ex. 403 = droits insuffisants).
    """

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def _check_schema(schema: type[BaseModel] | None, label: str) -> None:
    # Un RootModel (liste de paramètres, ex. FortiAnalyzer) n'a pas de champs propres :
    # ses éléments doivent eux-mêmes être des modèles stricts.
    if schema is None or issubclass(schema, RootModel):
        return
    if schema.model_config.get("extra") != "forbid":
        raise AllowlistDefinitionError(f"{label} doit déclarer extra='forbid'")


@dataclass(frozen=True)
class AllowedCall:
    """Un appel autorisé : REST (`method` + `path`) ou JSON-RPC (`jsonrpc`)."""

    method: str | None = None
    path: str | None = None
    query: frozenset[str] = frozenset()
    body_schema: type[BaseModel] | None = None
    reason: str = ""
    jsonrpc: str | None = None
    params_schema: type[BaseModel] | None = None
    endpoint: str | None = None
    override_reason: str = ""
    # Méthode accessible sans authentification (ex. apiinfo.version de Zabbix, qui refuse
    # toute requête authentifiée) : aucun en-tête d'auth n'est alors envoyé.
    anonymous: bool = False
    # Encodage du corps d'un POST : JSON (défaut) ou formulaire (OAuth2 « password » de Veeam).
    body_format: Literal["json", "form"] = "json"
    _regex: re.Pattern[str] | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "query", frozenset(self.query))
        rest = self.method is not None or self.path is not None
        if rest == (self.jsonrpc is not None):
            raise AllowlistDefinitionError("définir soit method+path, soit jsonrpc")
        if rest:
            self._validate_rest()
        else:
            self._validate_jsonrpc()

    def _validate_rest(self) -> None:
        if self.method not in ALLOWED_HTTP_METHODS:
            raise AllowlistDefinitionError(f"méthode HTTP interdite : {self.method}")
        if self.path is None:
            raise AllowlistDefinitionError("path obligatoire")
        if not (self.path.startswith("^/") and self.path.endswith("$")):
            raise AllowlistDefinitionError(f"chemin non ancré (^/…$) : {self.path}")
        if _BROAD_REGEX_RE.search(self.path):
            raise AllowlistDefinitionError(f"joker trop large (.* ou .+) : {self.path}")
        try:
            object.__setattr__(self, "_regex", re.compile(self.path))
        except re.error as exc:
            raise AllowlistDefinitionError(f"regex invalide : {self.path}") from exc
        if self.method == "POST":
            if self.body_schema is None or not self.reason.strip():
                raise AllowlistDefinitionError(
                    f"POST {self.path} : body_schema et reason (justification) obligatoires"
                )
        elif self.body_schema is not None:
            raise AllowlistDefinitionError(f"GET {self.path} : pas de corps")
        if self.body_format not in ("json", "form"):
            raise AllowlistDefinitionError(f"{self.path} : body_format json ou form")
        _check_schema(self.body_schema, f"body_schema de {self.path}")
        if self.params_schema is not None or self.endpoint is not None:
            raise AllowlistDefinitionError("params_schema/endpoint réservés au JSON-RPC")

    def _validate_jsonrpc(self) -> None:
        name = self.jsonrpc or ""
        if not _RPC_NAME_RE.match(name):
            raise AllowlistDefinitionError(f"nom de méthode JSON-RPC invalide : {name!r}")
        if self.endpoint is None or not _SAFE_PATH_RE.match(self.endpoint):
            raise AllowlistDefinitionError(f"{name} : endpoint (chemin littéral) obligatoire")
        if self.params_schema is None:
            raise AllowlistDefinitionError(f"{name} : params_schema obligatoire")
        _check_schema(self.params_schema, f"params_schema de {name}")
        if _DESTRUCTIVE_RPC_RE.search(name) and not self.override_reason.strip():
            raise AllowlistDefinitionError(
                f"{name} : verbe d'action, override_reason (justification) obligatoire"
            )
        if self.query or self.body_schema is not None:
            raise AllowlistDefinitionError(f"{name} : query/body_schema réservés au REST")

    @property
    def literal_path(self) -> str | None:
        """Chemin exact si l'expression n'a aucune partie variable (sondage des lectures)."""
        if self.path is None:
            return None
        inner = self.path[1:-1].replace("\\.", ".")
        return inner if re.fullmatch(r"/[A-Za-z0-9_./-]*", inner) else None

    def matches_rest(self, method: str, path: str) -> bool:
        return (
            self.method == method and self._regex is not None and bool(self._regex.fullmatch(path))
        )


def _check_path(path: str) -> str | None:
    """Motif de refus du chemin, ou None s'il est acceptable."""
    if not _SAFE_PATH_RE.match(path):
        return "chemin relatif attendu, caractères non autorisés (encodage, requête, schéma…)"
    if "//" in path:
        return "double barre oblique"
    if any(segment in (".", "..") for segment in path.split("/")):
        return "segment . ou .."
    return None


class SafeClient:
    """Client HTTP en lecture seule, borné à l'allowlist d'un connecteur."""

    def __init__(
        self,
        *,
        source: str,
        base_url: str,
        allowlist: Sequence[AllowedCall],
        ca_bundle: Path | None = None,
        proxy: str | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        jsonrpc_version: str | None = "2.0",
        headers: Mapping[str, str] | None = None,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError(f"{source} : HTTPS obligatoire")
        if not allowlist:
            raise ValueError(f"{source} : allowlist vide")
        self.source = source
        self._base_url = base_url.rstrip("/")
        self._allowlist = tuple(allowlist)
        self._sleep = sleep
        self._max_bytes = max_response_bytes
        self._jsonrpc_version = jsonrpc_version
        self._auth_headers: dict[str, SecretStr] = {}
        self._rpc_id = 0
        fixed = dict(headers or {})
        # En-têtes fixes non secrets (ex. x-api-version) ; l'authentification passe par
        # set_auth_header (SecretStr), jamais par ici.
        forbidden = {"authorization", "cookie", "proxy-authorization", "host"}
        if any(name.lower() in forbidden for name in fixed):
            raise ValueError(f"{source} : en-tête réservé dans headers")
        try:
            verify = ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None)
        except (OSError, ssl.SSLError):
            raise SourceCallError(f"{source} : bundle CA illisible ({ca_bundle})") from None
        self._client = httpx.Client(
            timeout=httpx.Timeout(READ_TIMEOUT_S, connect=CONNECT_TIMEOUT_S),
            verify=verify,
            proxy=proxy,
            trust_env=False,
            follow_redirects=False,
            transport=transport,
            headers={
                "Accept": "application/json",
                "User-Agent": f"vigie/{__version__}",
                **fixed,
            },
        )

    # --- API publique ---------------------------------------------------------

    def set_auth_header(self, name: str, value: SecretStr) -> None:
        self._auth_headers[name] = value

    def get(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        call = self._authorize_rest("GET", path, params)
        return self._send("GET", path, params=params, body=None, label=path, call=call)

    def post(self, path: str, json_body: Any, params: Mapping[str, Any] | None = None) -> Any:
        call = self._authorize_rest("POST", path, params)
        if call.body_schema is None:  # impossible : garanti par AllowedCall
            raise AllowlistDefinitionError(f"POST {path} sans body_schema")
        model = self._validated_model(call.body_schema, json_body, f"POST {path}")
        if call.body_format == "form":
            # Formulaire : valeurs en clair au seul moment de l'envoi (SecretStr révélé ici).
            body: Any = {
                k: v.get_secret_value() if isinstance(v, SecretStr) else str(v)
                for k, v in model.model_dump(by_alias=True, exclude_unset=True).items()
            }
        else:
            body = model.model_dump(mode="json", by_alias=True, exclude_unset=True)
        return self._send("POST", path, params=params, body=body, label=path, call=call)

    def jsonrpc(self, method: str, params: Any) -> Any:
        call = next((c for c in self._allowlist if c.jsonrpc == method), None)
        if call is None:
            self._forbid(f"rpc {method}", "méthode JSON-RPC hors allowlist")
        if call.params_schema is None or call.endpoint is None:  # garanti par AllowedCall
            raise AllowlistDefinitionError(f"rpc {method} incomplet")
        validated = self._validated(call.params_schema, params, f"rpc {method}")
        self._rpc_id += 1
        envelope: dict[str, Any] = {"method": method, "params": validated, "id": self._rpc_id}
        if self._jsonrpc_version is not None:
            envelope["jsonrpc"] = self._jsonrpc_version
        data = self._send(
            "POST", call.endpoint, params=None, body=envelope, label=f"rpc {method}", call=call
        )
        if isinstance(data, dict) and "error" in data:
            code = data["error"].get("code") if isinstance(data["error"], dict) else None
            raise SourceCallError(f"{self.source} : erreur JSON-RPC {method} (code {code})")
        if not isinstance(data, dict) or "result" not in data:
            raise SourceCallError(f"{self.source} : réponse JSON-RPC sans result ({method})")
        return data["result"]

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SafeClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- Contrôles avant envoi --------------------------------------------------

    def _forbid(self, target: str, reason: str) -> NoReturn:
        logger.critical(
            "appel interdit", extra={"source": self.source, "target": target, "reason": reason}
        )
        raise ForbiddenCallError(self.source, target, reason)

    def _authorize_rest(
        self, method: str, path: str, params: Mapping[str, Any] | None
    ) -> AllowedCall:
        target = f"{method} {path}"
        problem = _check_path(path)
        if problem is not None:
            self._forbid(target, problem)
        call = next((c for c in self._allowlist if c.matches_rest(method, path)), None)
        if call is None:
            self._forbid(target, "hors allowlist")
        unknown = sorted(set(params or {}) - call.query)
        if unknown:
            self._forbid(target, f"paramètres non autorisés : {', '.join(unknown)}")
        return call

    def _validated_model(self, schema: type[BaseModel], payload: Any, target: str) -> BaseModel:
        try:
            return schema.model_validate(payload)
        except ValidationError as exc:
            fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
            self._forbid(target, f"corps hors schéma ({', '.join(fields)})")

    def _validated(self, schema: type[BaseModel], payload: Any, target: str) -> Any:
        # On envoie la forme re-sérialisée par le schéma, jamais l'objet de l'appelant.
        model = self._validated_model(schema, payload, target)
        return model.model_dump(mode="json", by_alias=True, exclude_unset=True)

    # --- Envoi -------------------------------------------------------------------

    def _send(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None,
        body: Any,
        label: str,
        call: AllowedCall,
    ) -> Any:
        headers = (
            {}
            if call.anonymous
            else {k: v.get_secret_value() for k, v in self._auth_headers.items()}
        )
        form = call.body_format == "form" and body is not None
        request = self._client.build_request(
            method,
            self._base_url + path,
            params=params,
            json=None if form else body,
            data=body if form else None,
            headers=headers,
        )
        log_extra = {
            "source": self.source,
            "method": method,
            "target": label,
            "params": sorted(params or {}),
        }
        for attempt in range(MAX_RETRIES + 1):
            started = time.monotonic()
            try:
                response = self._client.send(request, stream=True)
            except httpx.TransportError as exc:
                logger.warning(
                    "erreur réseau",
                    extra={**log_extra, "error": type(exc).__name__, "attempt": attempt + 1},
                )
                if attempt == MAX_RETRIES:
                    raise SourceCallError(
                        f"{self.source} : {label} injoignable ({type(exc).__name__})"
                    ) from None
                self._sleep(RETRY_BASE_DELAY_S * 2**attempt)
                continue
            try:
                status = response.status_code
                logger.info(
                    "appel source",
                    extra={
                        **log_extra,
                        "status": status,
                        "duration_ms": round((time.monotonic() - started) * 1000),
                        "attempt": attempt + 1,
                    },
                )
                if status in RETRY_STATUSES and attempt < MAX_RETRIES:
                    self._sleep(RETRY_BASE_DELAY_S * 2**attempt)
                    continue
                if 300 <= status < 400:
                    raise SourceCallError(f"{self.source} : redirection refusée ({label})")
                if status >= 400:
                    raise SourceCallError(f"{self.source} : HTTP {status} ({label})", status)
                raw = self._read_limited(response, label)
            finally:
                response.close()
            if not raw.strip():
                return None  # ex. 202/204 sans corps (Graph sendMail, webhook Teams)
            try:
                return json.loads(raw)
            except ValueError:
                raise SourceCallError(f"{self.source} : réponse non JSON ({label})") from None
        raise AssertionError("inaccessible")  # pragma: no cover

    def _read_limited(self, response: httpx.Response, label: str) -> bytes:
        declared = response.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > self._max_bytes:
            raise SourceCallError(f"{self.source} : réponse trop volumineuse ({label})")
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > self._max_bytes:
                raise SourceCallError(f"{self.source} : réponse trop volumineuse ({label})")
            chunks.append(chunk)
        return b"".join(chunks)


def fixture_transport(directory: Path) -> httpx.BaseTransport:
    """Rejoue des réponses enregistrées (`vigie collect --fixtures`, tests de contrat).

    JSON-RPC : `<méthode>.json` contient la valeur de `result` (ex. `problem.get.json`).
    REST : `<MÉTHODE>_<chemin avec / remplacés par _>.json` (ex. `GET_api_v1_jobs.json`).
    Les requêtes passent d'abord par l'allowlist du `SafeClient` : le rejeu ne contourne rien.
    """
    root = directory.resolve()

    def handler(request: httpx.Request) -> httpx.Response:
        envelope: dict[str, Any] | None = None
        if request.method == "POST" and request.content:
            try:
                body = json.loads(request.content)
            except ValueError:
                body = None  # corps de formulaire (jeton OAuth2) : rejeu par le seul chemin
            if isinstance(body, dict) and "method" in body and "id" in body:
                envelope = body
        if envelope is not None:
            name = f"{envelope['method']}.json"
        else:
            name = f"{request.method}_{request.url.path.strip('/').replace('/', '_')}.json"
        path = (root / name).resolve()
        if path.parent != root or not path.is_file():
            return httpx.Response(404)
        data = json.loads(path.read_text(encoding="utf-8"))
        if envelope is not None:
            data = {"jsonrpc": "2.0", "result": data, "id": envelope["id"]}
        return httpx.Response(200, json=data)

    return httpx.MockTransport(handler)


TOKEN_PATHS = frozenset({"/api/oauth2/token", "/ws/oauth/token"})  # Veeam, NinjaOne
FAKE_TOKEN = {
    "access_token": "fixture-access-token",
    "token_type": "bearer",
    "refresh_token": "fixture-refresh-token",
    "expires_in": 900,
}


class RecordingTransport(httpx.BaseTransport):
    """Transport réel (TLS vérifié) qui garde une copie des réponses JSON.

    Outil de capture des fixtures (`scripts/record_fixtures.py`) : placé ici, seul module
    autorisé à importer httpx. Les requêtes passent toujours par l'allowlist du SafeClient.
    """

    def __init__(self, ca_bundle: Path | None, inner: httpx.BaseTransport | None = None) -> None:
        if inner is None:
            verify = ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None)
            inner = httpx.HTTPTransport(verify=verify)
        self._inner = inner
        self.saved: dict[str, Any] = {}
        # Bilan de tous les appels (méthode, chemin, statut, taille), même sans corps.
        self.calls: list[tuple[str, str, int, int]] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self._inner.handle_request(request)
        body = response.read()
        self.calls.append((request.method, request.url.path, response.status_code, len(body)))
        name = f"{request.method}_{request.url.path.strip('/').replace('/', '_')}.json"
        if response.status_code == 200 and body.strip():
            if request.url.path in TOKEN_PATHS:
                self.saved[name] = FAKE_TOKEN  # jamais le vrai jeton
            else:
                self._merge(name, json.loads(body))
        # `body` est déjà décompressé : ne pas transmettre Content-Encoding (sinon httpx
        # décompresse une seconde fois) ni l'ancienne longueur.
        headers = [
            (k, v)
            for k, v in response.headers.multi_items()
            if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")
        ]
        return httpx.Response(response.status_code, headers=headers, content=body, request=request)

    def _merge(self, name: str, data: Any) -> None:
        """Pages successives d'un même chemin cumulées : liste brute (NinjaOne), `data`
        (Veeam, boards NinjaOne) ou `results` (rapports NinjaOne à curseur)."""
        previous = self.saved.get(name)
        if isinstance(previous, list) and isinstance(data, list):
            self.saved[name] = previous + data
            return
        for key in ("data", "results"):
            if (
                isinstance(previous, dict)
                and isinstance(data, dict)
                and isinstance(previous.get(key), list)
                and isinstance(data.get(key), list)
            ):
                merged = previous[key] + data[key]
                self.saved[name] = {**data, key: merged}
                if "pagination" in data:
                    self.saved[name]["pagination"] = {
                        "total": len(merged),
                        "count": len(merged),
                        "skip": 0,
                    }
                return
        self.saved[name] = data


class Bounded[T](Iterator[T]):
    """Itère au plus `max_objects` éléments ; `truncated` indique qu'il en restait."""

    def __init__(self, items: Iterable[T], max_objects: int = MAX_OBJECTS) -> None:
        self._items = iter(items)
        self._max = max_objects
        self.count = 0
        self.truncated = False

    def __next__(self) -> T:
        if self.count >= self._max:
            if not self.truncated:
                for _ in self._items:
                    self.truncated = True
                    logger.warning("collecte tronquée", extra={"max_objects": self._max})
                    break
            raise StopIteration
        item = next(self._items)
        self.count += 1
        return item


def bounded[T](items: Iterable[T], max_objects: int = MAX_OBJECTS) -> Bounded[T]:
    return Bounded(items, max_objects)


# --- Contrat des connecteurs (SPEC §6.1) -----------------------------------------


@dataclass(frozen=True)
class HealthStatus:
    ok: bool
    detail: str = ""
    version: str | None = None
    latency_ms: float | None = None


@dataclass(frozen=True)
class RawSignal:
    """Objet brut de la source, avant normalisation. Données non fiables."""

    external_id: str
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class Signal:
    """Signal normalisé produit par un connecteur (SPEC §5.1, §7.2)."""

    source: str
    external_id: str
    company_code: str | None
    asset: str
    category: Category
    severity: int
    title: str
    details: str
    first_seen: datetime
    last_seen: datetime
    url_template_params: Mapping[str, str] = field(default_factory=dict)
    resolved: bool = False
    # Attributs structurés (ex. kind, maintenance, asset_criticality) : comparés par les
    # règles déclaratives du moteur, jamais interprétés. Valeurs JSON simples uniquement.
    attributes: Mapping[str, str | int | float | bool | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0 <= self.severity <= 5:
            raise ValueError(f"sévérité hors 0 à 5 : {self.severity}")


class CompanyMapper(Protocol):
    """Règles `asset_rule` : rattachement d'un actif à une société et criticité."""

    def company_for(self, source: str, match_type: str, value: str) -> str | None: ...

    def asset_criticality(self, source: str, match_type: str, value: str) -> float | None: ...


@dataclass(frozen=True)
class ConnectorContext:
    """Ce qu'il faut pour construire un connecteur, sans que la CLI connaisse la source.

    `settings` : bloc `[sources.<nom>]` brut, validé par le modèle du connecteur.
    `secret` : fournisseur de secrets (`config.get_secret` ; factice en rejeu de fixtures).
    `transport` : uniquement pour le rejeu (`fixture_transport`) et les tests.
    """

    settings: Mapping[str, Any]
    secret: Callable[[str], SecretStr]
    ca_bundle: Path | None = None
    transport: httpx.BaseTransport | None = None


class Connector(Protocol):
    name: str
    allowlist: Sequence[AllowedCall]

    @classmethod
    def from_context(cls, ctx: ConnectorContext) -> Connector: ...

    def healthcheck(self) -> HealthStatus: ...

    def collect(self, since: datetime) -> Iterable[RawSignal]: ...

    def to_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal: ...
