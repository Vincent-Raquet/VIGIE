"""Connecteur Wazuh 4.12+ (lecture seule). Voir CONNECTORS.md §4.

Deux API, deux clients :
- manager (`:55000`) : JWT obtenu par `POST /security/user/authenticate` (Basic, rôle
  `readonly`), puis inventaire des agents (`GET /agents`) : groupes (société), état de
  connexion, système ;
- indexer (`:9200`, OpenSearch) : `_search` sur les alertes et sur les états de vulnérabilités
  (Basic, rôle `vigie_read`), corps validés par un schéma strict, sans script.

Signaux (instantané, toutes les 15 min) :
- alertes de niveau ≥ `min_rule_level` sur `alert_window_hours`, agrégées par règle et agent ;
- agents déconnectés depuis plus de `disconnected_hours`, jamais connectés, ou abandonnés
  (> `stale_days`), un signal par société et par cas ;
- vulnérabilités Critical/High des agents Linux (Windows → Defender), par CVE et par société.

Les points non confirmés sur l'instance sont marqués `TODO verify` (capture réelle à faire).
"""

from __future__ import annotations

import base64
import hashlib
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)

from vigie.connectors.base import (
    MAX_OBJECTS,
    AllowedCall,
    CompanyMapper,
    ConnectorConfigError,
    ConnectorContext,
    HealthStatus,
    RawSignal,
    SafeClient,
    Signal,
    SourceCallError,
)
from vigie.db.enums import Category, MatchType
from vigie.mapping import companies_for
from vigie.redact import clean_untrusted

SOURCE = "wazuh"
API_PASSWORD_SECRET = "wazuh_api_password"  # noqa: S105 - nom du secret, pas sa valeur
INDEXER_PASSWORD_SECRET = "wazuh_indexer_password"  # noqa: S105 - nom du secret
SUPPORTED_MAJOR = "4"
PAGE_SIZE = 500
TITLE_MAX = 300
DETAILS_MAX = 1000
LISTED = 10
MANAGER_ID = "000"  # le manager lui-même, toujours « active »
# Index (4.8+) : alertes quotidiennes wazuh-alerts-4.x-AAAA.MM.JJ ; états de vulnérabilités
# wazuh-states-vulnerabilities-<cluster>. TODO verify : nom exact sur l'instance (4.12).
ALERTS_INDEX = "/wazuh-alerts-4.x-*/_search"
VULNS_INDEX = "/wazuh-states-vulnerabilities-*/_search"
# Plafonds des agrégations (au-delà : collecte tronquée, rien n'est résolu à tort).
ALERT_RULES = 200
ALERT_AGENTS = 50
VULN_CVES = 500
VULN_AGENTS = 1000
# Systèmes laissés à d'autres sources (Windows → Defender) ; os.platform de /agents.
NON_LINUX_PLATFORMS = frozenset({"windows", "darwin"})
GROUP_DEFAULT = "default"
VULN_SEVERITY = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
MONITORING_SEVERITY = 2  # règles de santé des agents (monitoring_rules)
# Agents : (singulier, pluriel, sévérité). Un agent abandonné est à retirer, pas à dépanner.
AGENT_CASES = {
    "agents_disconnected": ("agent déconnecté", "agents déconnectés", 3),
    "agents_never": ("agent jamais connecté", "agents jamais connectés", 2),
    "agents_stale": (
        "agent abandonné (déconnecté depuis plus de {days} jours)",
        "agents abandonnés (déconnectés depuis plus de {days} jours)",
        1,
    ),
}

# --- Allowlist (CONNECTORS.md §4) -------------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuthenticateRequest(_Strict):
    """Corps vide : les identifiants passent en Basic, rien d'autre n'est accepté."""


# Clés qui feraient exécuter du code (Painless) ou liraient un autre index que celui de l'URL
# (terms lookup `index`, more_like_this, percolate, forme indexée) : refusées partout, en plus
# du rôle vigie_read limité aux deux index.
FORBIDDEN_SEARCH_KEYS = frozenset(
    {
        "script",
        "script_fields",
        "runtime_mappings",
        "scripted_metric",
        "stored_fields",
        "pit",
        "index",
        "_index",
        "more_like_this",
        "percolate",
        "indexed_shape",
    }
)
MAX_SEARCH_SIZE = 500


def _forbidden_keys(value: Any, depth: int = 0) -> set[str]:
    if depth > 20:
        return {"<profondeur>"}
    if isinstance(value, Mapping):
        found = {str(k) for k in value if str(k) in FORBIDDEN_SEARCH_KEYS}
        for v in value.values():
            found |= _forbidden_keys(v, depth + 1)
        return found
    if isinstance(value, list):
        return set().union(*(_forbidden_keys(v, depth + 1) for v in value)) if value else set()
    return set()


class SearchRequest(_Strict):
    """Recherche OpenSearch en lecture : requête, agrégations, tri, champs ; ni script, ni
    pagination par curseur, `size` ≤ 500."""

    size: int = Field(0, ge=0, le=MAX_SEARCH_SIZE)
    query: dict[str, Any]
    aggs: dict[str, Any] | None = None
    sort: list[Any] | None = None
    source: list[str] | Literal[False] | None = Field(None, alias="_source")
    track_total_hits: bool | None = None

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    @model_validator(mode="after")
    def _no_script(self) -> SearchRequest:
        bad = _forbidden_keys(self.query) | _forbidden_keys(self.aggs) | _forbidden_keys(self.sort)
        if bad:
            raise ValueError(f"clés interdites : {', '.join(sorted(bad))}")
        return self


MANAGER_ALLOWLIST: tuple[AllowedCall, ...] = (
    AllowedCall(
        method="POST",
        path=r"^/security/user/authenticate$",
        body_schema=AuthenticateRequest,
        reason="JWT de l'API Wazuh (Basic, rôle readonly) : authentification seule, sans effet",
    ),
    AllowedCall(method="GET", path=r"^/$"),
    AllowedCall(method="GET", path=r"^/agents/summary/status$"),
    AllowedCall(
        method="GET", path=r"^/agents$", query=frozenset({"select", "limit", "offset", "status"})
    ),
)
INDEXER_ALLOWLIST: tuple[AllowedCall, ...] = (
    AllowedCall(
        method="POST",
        path=r"^/wazuh-alerts-4\.x-\*/_search$",
        body_schema=SearchRequest,
        reason="recherche OpenSearch des alertes (lecture, rôle vigie_read), sans script",
    ),
    AllowedCall(
        method="POST",
        path=r"^/wazuh-states-vulnerabilities-\*/_search$",
        body_schema=SearchRequest,
        reason="recherche OpenSearch des vulnérabilités (lecture, rôle vigie_read), sans script",
    ),
)
# Pour les tests génériques des connecteurs enregistrés (une seule liste par connecteur).
ALLOWLIST: tuple[AllowedCall, ...] = MANAGER_ALLOWLIST + INDEXER_ALLOWLIST

# --- Configuration ----------------------------------------------------------------------

VulnSeverity = Literal["Critical", "High", "Medium", "Low"]
DEFAULT_VULN_SEVERITIES: tuple[VulnSeverity, ...] = ("Critical", "High")
_HTTPS_URL = r"^https://[^\s/?#]+(:[0-9]{1,5})?/?$"


class WazuhConfig(_Strict):
    enabled: bool = False
    interval_min: int = Field(15, ge=5, le=1440)
    api_url: str = Field(pattern=_HTTPS_URL)
    indexer_url: str = Field(pattern=_HTTPS_URL)
    username: str = Field("svc-vigie", min_length=1, max_length=128)
    indexer_username: str = Field("svc-vigie", min_length=1, max_length=128)
    # Ancre de chaque API, seule approuvée pour elle : certificat de l'API (auto-signé
    # d'origine) et root-ca.pem de l'installation pour l'indexer.
    api_ca_bundle: Path | None = None
    indexer_ca_bundle: Path | None = None
    # false : certificats épinglés dont le nom ne correspond pas (OVA : localhost, 127.0.0.1) ;
    # exige les deux bundles (SafeClient refuse sinon).
    verify_hostname: bool = True
    min_rule_level: int = Field(10, ge=1, le=16)
    alert_window_hours: int = Field(24, ge=1, le=168)
    disconnected_hours: float = Field(1, gt=0, le=720)
    stale_days: int = Field(30, ge=2, le=365)
    vuln_severities: list[VulnSeverity] = Field(
        default_factory=lambda: list(DEFAULT_VULN_SEVERITIES), min_length=1
    )
    max_vulns_per_company: int = Field(10, ge=1, le=100)
    # Règles (identifiants Wazuh) écartées, et règles de santé des agents ramenées en supervision
    # à sévérité basse, sans attribut rule_level (l'override wazuh_level12 ne les voit pas) :
    # 204 « Agent event queue is flooded » (niveau 12) signale des événements perdus, mais se
    # déclenche surtout à l'installation des agents (capture réelle du 2026-10-23).
    ignore_rules: list[str] = Field(default_factory=list, max_length=100)
    monitoring_rules: list[str] = Field(default_factory=lambda: ["204"], max_length=100)

    @field_validator("ignore_rules", "monitoring_rules")
    @classmethod
    def _rule_ids(cls, value: list[str]) -> list[str]:
        if any(not r.isdigit() or len(r) > 10 for r in value):
            raise ValueError("identifiants de règle numériques attendus")
        return value

    @field_validator("api_ca_bundle", "indexer_ca_bundle")
    @classmethod
    def _expand(cls, value: Path | None) -> Path | None:
        return value.expanduser() if value is not None else None  # « ~/vigie-ca/… » en dev

    @model_validator(mode="after")
    def _pinned(self) -> WazuhConfig:
        pinned = self.api_ca_bundle is not None and self.indexer_ca_bundle is not None
        if not self.verify_hostname and not pinned:
            raise ValueError("verify_hostname = false exige api_ca_bundle et indexer_ca_bundle")
        return self


# --- Utilitaires ------------------------------------------------------------------------


def _dt(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _digest(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode(), usedforsecurity=False).hexdigest()[:12]


def _num(value: float) -> str:
    return f"{value:g}".replace(".", ",")


def rule_severity(level: int) -> int:
    """Niveau de règle Wazuh → sévérité Vigie (tableau de CONNECTORS.md)."""
    if level >= 13:
        return 5
    if level >= 10:
        return 4
    if level >= 7:
        return 3
    if level >= 4:
        return 2
    return 1 if level >= 1 else 0


def _basic(user: str, password: SecretStr) -> SecretStr:
    raw = f"{user}:{password.get_secret_value()}".encode()
    return SecretStr("Basic " + base64.b64encode(raw).decode())


def _buckets(agg: Any) -> list[Mapping[str, Any]]:
    items = agg.get("buckets") if isinstance(agg, Mapping) else None
    return [b for b in items if isinstance(b, Mapping)] if isinstance(items, list) else []


def _top_source(bucket: Mapping[str, Any]) -> Mapping[str, Any]:
    hits = (((bucket.get("last") or {}).get("hits")) or {}).get("hits")
    first = hits[0] if isinstance(hits, list) and hits else {}
    src = first.get("_source") if isinstance(first, Mapping) else None
    return src if isinstance(src, Mapping) else {}


def _get(doc: Mapping[str, Any], dotted: str) -> Any:
    value: Any = doc
    for part in dotted.split("."):
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


@dataclass(frozen=True)
class Agent:
    id: str
    name: str
    status: str
    groups: tuple[str, ...]
    platform: str
    os_name: str
    last_keepalive: datetime | None

    @property
    def group_key(self) -> str:
        """Groupes porteurs de la société (hors `default`) : clé de regroupement des signaux."""
        return ",".join(sorted({g.lower() for g in self.groups} - {GROUP_DEFAULT}))

    @property
    def is_linux(self) -> bool:
        return self.platform.lower() not in NON_LINUX_PLATFORMS

    @classmethod
    def parse(cls, item: Mapping[str, Any]) -> Agent:
        raw_os = item.get("os")
        os_info: Mapping[str, Any] = raw_os if isinstance(raw_os, Mapping) else {}
        groups = item.get("group")
        return cls(
            id=str(item.get("id", "")),
            name=str(item.get("name", "")),
            status=str(item.get("status", "")),
            groups=tuple(str(g) for g in groups) if isinstance(groups, list) else (),
            platform=str(os_info.get("platform", "")),
            os_name=str(os_info.get("name", "")),
            last_keepalive=_dt(item.get("lastKeepAlive")),
        )


def _by_name(item: tuple[str, str]) -> str:
    return item[1].casefold()


def _company(mapping: CompanyMapper, groups: Sequence[str], name: str) -> str | None:
    """Groupe d'agent (hors `default`), puis préfixe du nom ; une seule société sinon rien."""
    named = [g for g in groups if g.lower() != GROUP_DEFAULT]
    companies = companies_for(mapping, SOURCE, MatchType.agent_group, named)
    if not companies and name:
        companies = companies_for(mapping, SOURCE, MatchType.devname_prefix, [name])
    return next(iter(companies)) if len(companies) == 1 else None


@dataclass
class CveGroup:
    cve: str
    severity: str
    cvss: float = 0.0
    published: str = ""
    agents: dict[str, str] = field(default_factory=dict)  # id → nom
    packages: set[str] = field(default_factory=set)
    first_detected: datetime | None = None

    def rank(self) -> tuple[int, float, int]:
        return (VULN_SEVERITY.get(self.severity, 0), self.cvss, len(self.agents))


# --- Connecteur -------------------------------------------------------------------------


class WazuhConnector:
    name = SOURCE
    allowlist = ALLOWLIST

    def __init__(
        self,
        config: WazuhConfig,
        clients: Mapping[str, SafeClient],
        passwords: Mapping[str, SecretStr],
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.config = config
        self.manager = clients["manager"]
        self.indexer = clients["indexer"]
        self._passwords = passwords
        self._now = now
        self._token_ok = False
        self._indexer_ok = False
        # Collecte tronquée : l'absence d'un signal ne prouve pas sa résolution.
        self.truncated = False

    @classmethod
    def from_context(cls, ctx: ConnectorContext) -> WazuhConnector:
        try:
            config = WazuhConfig.model_validate(dict(ctx.settings))
        except ValidationError as exc:
            # Champ fautif, ou message de la règle croisée (verify_hostname) sans champ.
            fields = sorted(
                {".".join(str(p) for p in e["loc"]) or str(e["msg"]) for e in exc.errors()}
            )
            raise ConnectorConfigError(f"[sources.wazuh] invalide : {', '.join(fields)}") from None

        def client(base: str, allowlist: Sequence[AllowedCall], ca: Path | None) -> SafeClient:
            return SafeClient(
                source=SOURCE,
                base_url=base,
                allowlist=allowlist,
                ca_bundle=ca or ctx.ca_bundle,
                transport=ctx.transport,
                check_hostname=config.verify_hostname,
            )

        clients = {
            "manager": client(config.api_url, MANAGER_ALLOWLIST, config.api_ca_bundle),
            "indexer": client(config.indexer_url, INDEXER_ALLOWLIST, config.indexer_ca_bundle),
        }
        passwords = {
            "manager": ctx.secret(API_PASSWORD_SECRET),
            "indexer": ctx.secret(INDEXER_PASSWORD_SECRET),
        }
        return cls(config, clients, passwords)

    # --- Authentification ------------------------------------------------------------

    def _login(self) -> None:
        if self._token_ok:
            return
        self.manager.set_auth_header(
            "Authorization", _basic(self.config.username, self._passwords["manager"])
        )
        data = self.manager.post("/security/user/authenticate", {})
        token = ((data or {}).get("data") or {}).get("token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise SourceCallError(f"{SOURCE} : réponse d'authentification sans jeton")
        # Le JWT remplace l'en-tête Basic : le mot de passe ne part qu'une fois.
        self.manager.set_auth_header("Authorization", SecretStr(f"Bearer {token}"))
        self._token_ok = True

    def _search(self, path: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        if not self._indexer_ok:
            self.indexer.set_auth_header(
                "Authorization", _basic(self.config.indexer_username, self._passwords["indexer"])
            )
            self._indexer_ok = True
        data = self.indexer.post(path, dict(body))
        if not isinstance(data, dict):
            raise SourceCallError(f"{SOURCE} : réponse de recherche inattendue ({path})")
        if (data.get("_shards") or {}).get("failed"):
            self.truncated = True  # résultat partiel : ne rien résoudre
        return data

    def _agents(self) -> Iterator[Agent]:
        self._login()
        offset = 0
        # Champs du schéma Agent (spec 4.14) : un champ inconnu dans select fait échouer l'appel.
        select = "id,name,status,group,lastKeepAlive,os.platform,os.name"
        while True:
            page = self.manager.get(
                "/agents", {"select": select, "limit": PAGE_SIZE, "offset": offset}
            )
            data = page.get("data") if isinstance(page, dict) else None
            items = data.get("affected_items") if isinstance(data, dict) else None
            if not isinstance(items, list):
                raise SourceCallError(f"{SOURCE} : réponse inattendue (/agents)")
            for item in items:
                if offset >= MAX_OBJECTS:
                    self.truncated = True
                    return
                offset += 1
                if isinstance(item, Mapping):
                    yield Agent.parse(item)
            total = data.get("total_affected_items") if isinstance(data, dict) else None
            if not items or len(items) < PAGE_SIZE or (isinstance(total, int) and offset >= total):
                return

    # --- Santé -----------------------------------------------------------------------

    def healthcheck(self) -> HealthStatus:
        started = time.monotonic()
        try:
            self._login()
            info = self.manager.get("/")
            self.manager.get("/agents/summary/status")
            self._search(ALERTS_INDEX, {"size": 0, "query": {"match_all": {}}})
        except SourceCallError as exc:
            return HealthStatus(ok=False, detail=str(exc))
        data = info.get("data") if isinstance(info, dict) else None
        version = str(data.get("api_version", "")) if isinstance(data, dict) else ""
        latency = round((time.monotonic() - started) * 1000, 1)
        detail = "" if version.split(".")[0] == SUPPORTED_MAJOR else "version non testée"
        return HealthStatus(ok=True, detail=detail, version=version or None, latency_ms=latency)

    # --- Collecte --------------------------------------------------------------------

    def collect(self, since: datetime) -> Iterable[RawSignal]:
        """Instantané : `since` est ignoré, chaque collecte relit l'état complet."""
        now = self._now()
        self.truncated = False
        agents = {a.id: a for a in self._agents()}
        out = self._agent_signals(agents, now)
        out += self._alert_signals(agents, now)
        out += self._vuln_signals(agents, now)
        return sorted(out, key=lambda r: r.external_id)

    def _agent_signals(self, agents: Mapping[str, Agent], now: datetime) -> list[RawSignal]:
        threshold = timedelta(hours=self.config.disconnected_hours)
        stale = timedelta(days=self.config.stale_days)
        cases: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for a in agents.values():
            if a.id == MANAGER_ID:
                continue
            if a.status == "never_connected":
                cases[("never", a.group_key)].append(self._agent_ref(a, None))
            elif a.status == "disconnected":
                since = a.last_keepalive  # dernier contact : début de la déconnexion
                if since is None:
                    continue
                age = now - since
                if age >= stale:
                    cases[("stale", a.group_key)].append(self._agent_ref(a, age))
                elif age >= threshold:
                    cases[("disconnected", a.group_key)].append(self._agent_ref(a, age))
        return [
            RawSignal(
                f"agents:{case}:{_digest(key)}",
                {"kind": f"agents_{case}", "agents": items, "at": now},
            )
            for (case, key), items in cases.items()
        ]

    @staticmethod
    def _agent_ref(a: Agent, age: timedelta | None) -> dict[str, Any]:
        return {
            "id": a.id,
            "name": a.name,
            "groups": list(a.groups),
            "os": a.os_name,
            "hours": round(age.total_seconds() / 3600, 1) if age is not None else None,
        }

    def _alert_signals(self, agents: Mapping[str, Agent], now: datetime) -> list[RawSignal]:
        start = now - timedelta(hours=self.config.alert_window_hours)
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"rule.level": {"gte": self.config.min_rule_level}}},
                        {"range": {"timestamp": {"gte": start.isoformat()}}},
                    ],
                    **(
                        {"must_not": [{"terms": {"rule.id": list(self.config.ignore_rules)}}]}
                        if self.config.ignore_rules
                        else {}
                    ),
                }
            },
            "aggs": {
                "rules": {
                    "terms": {"field": "rule.id", "size": ALERT_RULES},
                    "aggs": {
                        "agents": {
                            "terms": {"field": "agent.id", "size": ALERT_AGENTS},
                            "aggs": {
                                "first": {"min": {"field": "timestamp"}},
                                "last": {
                                    "top_hits": {
                                        "size": 1,
                                        "sort": [{"timestamp": {"order": "desc"}}],
                                        "_source": [
                                            "timestamp",
                                            "rule.id",
                                            "rule.level",
                                            "rule.description",
                                            "rule.groups",
                                            "agent.id",
                                            "agent.name",
                                        ],
                                    }
                                },
                            },
                        }
                    },
                }
            },
        }
        data = self._search(ALERTS_INDEX, body)
        rules = (data.get("aggregations") or {}).get("rules")
        if (rules or {}).get("sum_other_doc_count"):
            self.truncated = True
        out: list[RawSignal] = []
        ignored = set(self.config.ignore_rules)
        for rule in _buckets(rules):
            if str(rule.get("key", "")) in ignored:
                continue  # déjà exclue par la requête ; garde-fou si l'index l'a renvoyée
            by_agent = rule.get("agents")
            if (by_agent or {}).get("sum_other_doc_count"):
                self.truncated = True
            for bucket in _buckets(by_agent):
                last = _top_source(bucket)
                agent_id = str(bucket.get("key", ""))
                known = agents.get(agent_id)
                first = (bucket.get("first") or {}).get("value_as_string")
                out.append(
                    RawSignal(
                        f"alert:{rule.get('key')}:{_digest(agent_id)}",
                        {
                            "kind": "alert",
                            "rule_id": str(rule.get("key", "")),
                            "level": int(_get(last, "rule.level") or 0),
                            "description": str(_get(last, "rule.description") or ""),
                            "rule_groups": list(_get(last, "rule.groups") or [])[:LISTED],
                            "agent_id": agent_id,
                            "agent_name": known.name
                            if known
                            else str(_get(last, "agent.name") or ""),
                            "groups": list(known.groups) if known else [],
                            "count": int(bucket.get("doc_count") or 0),
                            "first": first if isinstance(first, str) else None,
                            "last": _get(last, "timestamp"),
                            "at": now,
                        },
                    )
                )
        return out

    def _vuln_signals(self, agents: Mapping[str, Agent], now: datetime) -> list[RawSignal]:
        # Agents Linux seulement, filtrés par l'indexer : les postes Windows (Defender) portent
        # l'essentiel des CVE et satureraient l'agrégation (capture réelle du 2026-10-23).
        linux = sorted(a.id for a in agents.values() if a.is_linux)
        if not linux:
            return []
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"terms": {"vulnerability.severity": list(self.config.vuln_severities)}},
                        {"terms": {"agent.id": linux}},
                    ]
                }
            },
            "aggs": {
                "cves": {
                    "terms": {
                        "field": "vulnerability.id",
                        "size": VULN_CVES,
                        "order": {"cvss": "desc"},
                    },
                    "aggs": {
                        "cvss": {"max": {"field": "vulnerability.score.base"}},
                        "first": {"min": {"field": "vulnerability.detected_at"}},
                        "agents": {"terms": {"field": "agent.id", "size": VULN_AGENTS}},
                        "packages": {"terms": {"field": "package.name", "size": 5}},
                        "last": {
                            "top_hits": {
                                "size": 1,
                                "_source": [
                                    "vulnerability.id",
                                    "vulnerability.severity",
                                    "vulnerability.score.base",
                                    "vulnerability.published_at",
                                ],
                            }
                        },
                    },
                }
            },
        }
        data = self._search(VULNS_INDEX, body)
        cves = (data.get("aggregations") or {}).get("cves")
        if (cves or {}).get("sum_other_doc_count"):
            self.truncated = True
        # Une CVE par groupe d'agents (société) : chaque société reçoit ses CVE les plus graves.
        by_key: dict[str, list[CveGroup]] = defaultdict(list)
        for bucket in _buckets(cves):
            last = _top_source(bucket)
            split: dict[str, CveGroup] = {}
            for b in _buckets(bucket.get("agents")):
                agent = agents.get(str(b.get("key", "")))
                # Agents inconnus du manager (retirés) ou non Linux : écartés.
                if agent is None or not agent.is_linux:
                    continue
                group = split.get(agent.group_key)
                if group is None:
                    group = split[agent.group_key] = CveGroup(
                        cve=str(bucket.get("key", "")),
                        severity=str(_get(last, "vulnerability.severity") or ""),
                        cvss=float((bucket.get("cvss") or {}).get("value") or 0),
                        published=str(_get(last, "vulnerability.published_at") or ""),
                        packages={str(p.get("key")) for p in _buckets(bucket.get("packages"))},
                        first_detected=_dt((bucket.get("first") or {}).get("value_as_string")),
                    )
                group.agents[agent.id] = agent.name
            for key, group in split.items():
                by_key[key].append(group)
        out: list[RawSignal] = []
        for key, groups in by_key.items():
            groups.sort(key=CveGroup.rank, reverse=True)
            if len(groups) > self.config.max_vulns_per_company:
                groups = groups[: self.config.max_vulns_per_company]
            for g in groups:
                out.append(
                    RawSignal(
                        f"cve:{g.cve[:60]}:{_digest(key)}",
                        {
                            "kind": "vulnerability",
                            "cve": g.cve,
                            "severity": g.severity,
                            "cvss": g.cvss,
                            "published": g.published,
                            "packages": sorted(g.packages),
                            "agents": [
                                {"id": i, "name": n, "groups": list(agents[i].groups)}
                                for i, n in sorted(g.agents.items(), key=_by_name)
                            ],
                            "first": g.first_detected,
                            "at": now,
                        },
                    )
                )
        return out

    # --- Normalisation ---------------------------------------------------------------

    def to_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        kind = raw.payload["kind"]
        if kind == "alert":
            return self._alert_signal(raw, mapping)
        if kind == "vulnerability":
            return self._vuln_signal(raw, mapping)
        return self._agents_signal(raw, mapping)

    def _alert_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        agent = clean_untrusted(p["agent_name"], 200)
        description = clean_untrusted(p["description"], 200)
        level = int(p["level"])
        last = _dt(p.get("last")) or p["at"]
        first = _dt(p.get("first")) or last
        lines = [
            f"Règle {clean_untrusted(p['rule_id'], 20)} (niveau {level}) : {description}",
            f"Agent : {agent} ({clean_untrusted(p['agent_id'], 10)})",
            f"Occurrences sur {self.config.alert_window_hours} h : {p['count']}",
            f"Dernière : {last:%d/%m/%Y %H:%M} UTC",
        ]
        if p.get("rule_groups"):
            lines.append("Groupes de règle : " + ", ".join(str(g) for g in p["rule_groups"]))
        health = str(p["rule_id"]) in self.config.monitoring_rules
        if health:
            lines.append("Santé de l'agent : classée en supervision (monitoring_rules)")
        attributes: dict[str, str | int | float | bool | None] = (
            {"kind": "agent_health", "wazuh_level": level, "count": int(p["count"])}
            if health
            else {"kind": "alert", "rule_level": level, "count": int(p["count"])}
        )
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=_company(mapping, p["groups"], p["agent_name"]),
            asset=agent,
            category=Category.monitoring if health else Category.security,
            severity=MONITORING_SEVERITY if health else rule_severity(level),
            title=clean_untrusted(f"Wazuh — {description} ({agent})", TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=first,
            last_seen=last,
            url_template_params={"agent_id": str(p["agent_id"]), "rule_id": str(p["rule_id"])},
            attributes=attributes,
        )

    def _vuln_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        # Une CVE peut toucher plusieurs sociétés : la société n'est renseignée que si tous les
        # agents concernés en partagent une (le regroupement par société se fait au plan).
        p = raw.payload
        cve = clean_untrusted(p["cve"], 40)
        companies = {_company(mapping, a["groups"], a["name"]) for a in p["agents"]}
        names = [clean_untrusted(a["name"], 60) for a in p["agents"]]
        count = len(names)
        severity = VULN_SEVERITY.get(p["severity"], 2)
        lines = [
            f"{cve} — gravité {p['severity']}, CVSS {_num(p['cvss'])}",
            f"Agents Linux concernés ({count}) : "
            + ", ".join(names[:LISTED])
            + (" …" if count > LISTED else ""),
        ]
        if p["packages"]:
            lines.append("Paquets : " + ", ".join(clean_untrusted(x, 60) for x in p["packages"]))
        if p.get("published"):
            lines.append(f"Publiée : {clean_untrusted(p['published'], 30)[:10]}")
        suffix = names[0] if count == 1 else f"{count} agents"
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=next(iter(companies)) if len(companies) == 1 else None,
            asset=names[0] if count == 1 else f"{count} agents Linux",
            category=Category.vulnerability,
            severity=severity,
            title=clean_untrusted(f"Wazuh — {cve} ({p['severity']}) : {suffix}", TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=p.get("first") or p["at"],
            last_seen=p["at"],
            url_template_params={"cve": p["cve"]},
            attributes={
                "kind": "vulnerability",
                "cvss": p["cvss"],
                "vuln_severity": p["severity"],
                "agents": count,
            },
        )

    def _agents_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        kind = p["kind"]
        items = p["agents"]
        one, many, severity = AGENT_CASES[kind]
        companies = {_company(mapping, a["groups"], a["name"]) for a in items}
        lines = []
        for a in sorted(items, key=lambda a: -(a["hours"] or 0))[:LISTED]:
            age = f", {_num(a['hours'])} h" if a["hours"] is not None else ""
            name, os_name = clean_untrusted(a["name"], 60), clean_untrusted(a["os"], 40)
            lines.append(f"- {name} ({os_name}{age})")
        if len(items) > LISTED:
            lines.append(f"… et {len(items) - LISTED} autres")
        count = len(items)
        label = (one if count == 1 else many).format(days=self.config.stale_days)
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=next(iter(companies)) if len(companies) == 1 else None,
            asset=clean_untrusted(items[0]["name"], 60) if count == 1 else f"{count} agents",
            category=Category.monitoring,
            severity=severity,
            title=clean_untrusted(f"Wazuh — {count} {label}", TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=p["at"],
            last_seen=p["at"],
            attributes={"kind": kind, "agents": count},
        )
