"""Connecteur Zabbix 7.4 (lecture seule, JSON-RPC). Voir docs/CONNECTORS.md §1.

Collecte : problèmes ouverts (`problem.get`), rattachés à leur hôte et à ses groupes par
`trigger.get` (le problème ne porte pas l'hôte), et proxys hors ligne (`proxy.get`).
Les hôtes bruyants (beaucoup de problèmes de sévérité ≤ 3) sont agrégés en un seul signal.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, SecretStr, ValidationError

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
    bounded,
)
from vigie.db.enums import Category, MatchType
from vigie.mapping import companies_for, normalize
from vigie.redact import clean_untrusted

SOURCE = "zabbix"
ENDPOINT = "/api_jsonrpc.php"
TOKEN_SECRET = "zabbix_api_token"  # noqa: S105 - nom du secret, pas sa valeur
TRIGGER_BATCH = 500
TITLE_MAX = 300
DETAILS_MAX = 1000
SUPPORTED_MAJOR = "7"

# --- Schémas des paramètres autorisés (allowlist) ------------------------------------
# Champs `output` en Literal : on ne demande que ce qui sert (minimisation, SECURITY.md C5).


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


Severity = Annotated[int, Field(ge=0, le=5)]
NumericId = Annotated[str, Field(pattern=r"^[0-9]{1,20}$")]

ProblemField = Literal[
    "eventid", "objectid", "clock", "name", "severity", "acknowledged", "suppressed", "opdata"
]
HostField = Literal["hostid", "host", "name", "status", "maintenance_status"]
ProxyField = Literal["proxyid", "name", "state", "lastaccess", "operating_mode"]


class ApiInfoVersionParams(RootModel[Annotated[list[int], Field(max_length=0)]]):
    """`apiinfo.version` n'accepte que `[]` et doit partir sans authentification."""


class ProblemGetParams(_Params):
    output: list[ProblemField]
    source: Literal[0]
    object: Literal[0]
    severities: list[Severity] = Field(max_length=6)
    recent: Literal[False]
    selectTags: Literal["extend"]  # noqa: N815 - nom imposé par l'API Zabbix
    selectAcknowledges: Literal["count"]  # noqa: N815
    sortfield: Literal["eventid"]
    sortorder: Literal["ASC", "DESC"]
    limit: int = Field(ge=1, le=MAX_OBJECTS + 1)


class TriggerGetParams(_Params):
    triggerids: list[NumericId] = Field(min_length=1, max_length=TRIGGER_BATCH)
    output: list[Literal["triggerid", "priority"]]
    selectHosts: list[HostField]  # noqa: N815
    selectHostGroups: list[Literal["groupid", "name"]]  # noqa: N815
    monitored: Literal[True]


class ProxyGetParams(_Params):
    output: list[ProxyField]


ALLOWLIST: tuple[AllowedCall, ...] = (
    AllowedCall(
        jsonrpc="apiinfo.version",
        endpoint=ENDPOINT,
        params_schema=ApiInfoVersionParams,
        anonymous=True,
    ),
    AllowedCall(jsonrpc="problem.get", endpoint=ENDPOINT, params_schema=ProblemGetParams),
    AllowedCall(jsonrpc="trigger.get", endpoint=ENDPOINT, params_schema=TriggerGetParams),
    AllowedCall(jsonrpc="proxy.get", endpoint=ENDPOINT, params_schema=ProxyGetParams),
)

# --- Configuration ---------------------------------------------------------------------

# Mot (borné par des séparateurs) présent dans le nom d'un groupe → catégorie.
# Le mot le plus long l'emporte (« Zabbix servers » avant « servers »).
DEFAULT_CATEGORY_BY_GROUP: dict[str, Category] = {
    "Réseau": Category.network,
    "Switchs": Category.network,
    "RUT": Category.network,
    "Serveurs": Category.server,
    "servers": Category.server,
    "Hypervisors": Category.server,
    "hypervisor": Category.server,
    "IDRAC": Category.server,
    "vm": Category.server,
    "SRV-Veeam": Category.backup,
    "Synology-NAS": Category.backup,
    "CAMERAS": Category.endpoint,
    "Printer": Category.endpoint,
    "atelier": Category.endpoint,
    "Zabbix servers": Category.monitoring,
}
# Tag de trigger (tag, valeur) → catégorie ; prioritaire sur les groupes.
TAG_CATEGORY: dict[tuple[str, str], Category] = {
    ("application", "veeam"): Category.backup,
    ("target", "veeam"): Category.backup,
    ("application", "vpn"): Category.network,
    ("scope", "vpn"): Category.network,
    ("class", "network"): Category.network,
    ("component", "network"): Category.network,
    ("class", "os"): Category.server,
    ("class", "hardware"): Category.server,
    ("subclass", "virtualization"): Category.server,
    ("component", "storage"): Category.server,
}
# Plusieurs catégories possibles par les groupes : la plus spécifique d'abord. Le réseau
# passe avant la sauvegarde (un switch du groupe « SRV-Veeam » reste un équipement réseau).
CATEGORY_PRECEDENCE = (
    Category.network,
    Category.backup,
    Category.monitoring,
    Category.endpoint,
    Category.server,
)
DEFAULT_CATEGORY = Category.server


class ZabbixConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    interval_min: int = Field(15, ge=1, le=1440)
    base_url: str = Field(pattern=r"^https://[^\s/?#]+(/[^\s?#]*)?$")
    min_severity: Severity = 2
    aggregate_threshold: int = Field(8, ge=1)
    proxy_stale_min: int = Field(10, ge=1)
    category_by_group: dict[str, Category] = Field(
        default_factory=lambda: dict(DEFAULT_CATEGORY_BY_GROUP)
    )


# --- Connecteur ------------------------------------------------------------------------


def _ts(value: Any) -> datetime:
    return datetime.fromtimestamp(int(value), tz=UTC)


def _token_in(group: str, word: str) -> bool:
    """`word` apparaît dans `group` comme mot entier (bornes : début, fin, séparateur)."""
    g, w = normalize(group), normalize(word)
    start = g.find(w)
    while start != -1:
        end = start + len(w)
        before_ok = start == 0 or not g[start - 1].isalnum()
        after_ok = end == len(g) or not g[end].isalnum()
        if before_ok and after_ok:
            return True
        start = g.find(w, start + 1)
    return False


class ZabbixConnector:
    name = SOURCE
    allowlist = ALLOWLIST

    def __init__(
        self,
        config: ZabbixConfig,
        client: SafeClient,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.config = config
        self.client = client
        self._now = now
        self._group_words = sorted(config.category_by_group.items(), key=lambda kv: -len(kv[0]))

    @classmethod
    def from_context(cls, ctx: ConnectorContext) -> ZabbixConnector:
        try:
            config = ZabbixConfig.model_validate(dict(ctx.settings))
        except ValidationError as exc:
            fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
            raise ConnectorConfigError(f"[sources.zabbix] invalide : {', '.join(fields)}") from None
        token: SecretStr = ctx.secret(TOKEN_SECRET)
        client = SafeClient(
            source=SOURCE,
            base_url=config.base_url,
            allowlist=ALLOWLIST,
            ca_bundle=ctx.ca_bundle,
            transport=ctx.transport,
        )
        client.set_auth_header("Authorization", SecretStr(f"Bearer {token.get_secret_value()}"))
        return cls(config, client)

    # --- Santé -------------------------------------------------------------------------

    def healthcheck(self) -> HealthStatus:
        started = time.monotonic()
        try:
            version = str(self.client.jsonrpc("apiinfo.version", []))
            self.client.jsonrpc("proxy.get", {"output": ["proxyid"]})  # valide le jeton
        except SourceCallError as exc:
            return HealthStatus(ok=False, detail=str(exc))
        latency = round((time.monotonic() - started) * 1000, 1)
        detail = "" if version.split(".")[0] == SUPPORTED_MAJOR else "version non testée"
        return HealthStatus(ok=True, detail=detail, version=version, latency_ms=latency)

    # --- Collecte ----------------------------------------------------------------------

    def collect(self, since: datetime) -> Iterable[RawSignal]:
        """Instantané des problèmes ouverts et des proxys hors ligne.

        `since` est ignoré : un problème résolu disparaît de `problem.get`, et la résolution
        est déduite de cette absence lors de l'enregistrement (phase 4).
        """
        collected_at = self._now()
        problems = self._problems()
        triggers = self._triggers({p["objectid"] for p in problems})

        by_host: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
        for problem in problems:
            trigger = triggers.get(problem["objectid"])
            if trigger is None or not trigger.get("hosts"):
                continue  # trigger, hôte ou item désactivé : problème périmé
            by_host[trigger["hosts"][0]["hostid"]].append((problem, trigger))

        raws: list[RawSignal] = []
        for hostid, items in by_host.items():
            low = [(p, t) for p, t in items if int(p["severity"]) <= 3]
            if len(low) > self.config.aggregate_threshold:
                raws.append(self._aggregate(hostid, low, collected_at))
                items = [(p, t) for p, t in items if int(p["severity"]) > 3]
            raws.extend(
                RawSignal(
                    external_id=p["eventid"],
                    payload={"kind": "problem", "problem": p, "trigger": t, "at": collected_at},
                )
                for p, t in items
            )
        raws.extend(self._stale_proxies(collected_at))
        raws.sort(key=lambda r: r.external_id)
        return raws

    def _problems(self) -> list[dict[str, Any]]:
        result = self.client.jsonrpc(
            "problem.get",
            {
                "output": [
                    "eventid",
                    "objectid",
                    "clock",
                    "name",
                    "severity",
                    "acknowledged",
                    "suppressed",
                    "opdata",
                ],
                "source": 0,
                "object": 0,
                "severities": list(range(self.config.min_severity, 6)),
                "recent": False,
                "selectTags": "extend",
                "selectAcknowledges": "count",
                "sortfield": "eventid",
                "sortorder": "DESC",
                "limit": MAX_OBJECTS + 1,
            },
        )
        return list(bounded(self._list(result, "problem.get")))

    def _triggers(self, triggerids: set[str]) -> dict[str, dict[str, Any]]:
        ids = sorted(triggerids, key=int)
        found: dict[str, dict[str, Any]] = {}
        for start in range(0, len(ids), TRIGGER_BATCH):
            result = self.client.jsonrpc(
                "trigger.get",
                {
                    "triggerids": ids[start : start + TRIGGER_BATCH],
                    "output": ["triggerid", "priority"],
                    "selectHosts": ["hostid", "host", "name", "status", "maintenance_status"],
                    "selectHostGroups": ["groupid", "name"],
                    "monitored": True,
                },
            )
            for trigger in self._list(result, "trigger.get"):
                found[str(trigger["triggerid"])] = trigger
        return found

    def _stale_proxies(self, now: datetime) -> list[RawSignal]:
        result = self.client.jsonrpc(
            "proxy.get", {"output": ["proxyid", "name", "state", "lastaccess", "operating_mode"]}
        )
        stale_after = timedelta(minutes=self.config.proxy_stale_min)
        raws = []
        for proxy in self._list(result, "proxy.get"):
            last = int(proxy.get("lastaccess") or 0)
            offline = str(proxy.get("state")) == "1"
            silent = last > 0 and now - _ts(last) > stale_after
            if offline or silent:
                raws.append(
                    RawSignal(
                        external_id=f"proxy:{proxy['proxyid']}",
                        payload={"kind": "proxy", "proxy": proxy, "at": now},
                    )
                )
        return raws

    @staticmethod
    def _aggregate(
        hostid: str, items: Sequence[tuple[dict[str, Any], dict[str, Any]]], at: datetime
    ) -> RawSignal:
        return RawSignal(
            external_id=f"host:{hostid}:agg",
            payload={
                "kind": "aggregate",
                "problems": [p for p, _ in items],
                "trigger": items[0][1],
                "at": at,
            },
        )

    @staticmethod
    def _list(result: Any, method: str) -> list[dict[str, Any]]:
        if not isinstance(result, list) or not all(isinstance(x, dict) for x in result):
            raise SourceCallError(f"{SOURCE} : réponse inattendue ({method})")
        return result

    # --- Normalisation -----------------------------------------------------------------

    def to_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        payload = raw.payload
        kind = payload["kind"]
        if kind == "proxy":
            return self._proxy_signal(raw, mapping)
        trigger: Mapping[str, Any] = payload["trigger"]
        host: Mapping[str, Any] = trigger["hosts"][0]
        groups = [str(g["name"]) for g in trigger.get("hostgroups", [])]
        problems: list[Mapping[str, Any]] = (
            payload["problems"] if kind == "aggregate" else [payload["problem"]]
        )
        companies = companies_for(mapping, SOURCE, MatchType.hostgroup_prefix, groups)
        in_maintenance = str(host.get("maintenance_status")) == "1" or any(
            str(p.get("suppressed")) == "1" for p in problems
        )
        severity = max(int(p["severity"]) for p in problems)
        if in_maintenance:
            severity = max(1, severity - 1)
        categories = Counter(self._category(p.get("tags", []), groups) for p in problems)
        asset = clean_untrusted(str(host.get("host", "")), 200)
        visible = clean_untrusted(str(host.get("name", "")), 200)

        lines = [f"Hôte : {visible}" + (f" ({asset})" if visible != asset else "")]
        if groups:
            lines.append("Groupes : " + ", ".join(groups))
        if len(companies) > 1:
            lines.append("Sociétés multiples : " + ", ".join(sorted(companies)))
        if in_maintenance:
            lines.append("En maintenance (sévérité abaissée d'un niveau)")
        if kind == "aggregate":
            title = f"{len(problems)} problèmes ouverts sur {visible or asset}"
            by_title = Counter((int(p["severity"]), str(p["name"])) for p in problems)
            ranked = sorted(by_title.items(), key=lambda kv: (-kv[0][0], -kv[1], kv[0][1]))
            lines.append("Principaux :")
            lines.extend(
                f"- [{sev}] {name}" + (f" ({n} fois)" if n > 1 else "")
                for (sev, name), n in ranked[:10]
            )
            params = {"hostid": str(host.get("hostid", ""))}
        else:
            problem = problems[0]
            title = str(problem["name"])
            if problem.get("opdata"):
                lines.append(f"Données : {problem['opdata']}")
            acks = int(problem.get("acknowledges") or 0)
            if str(problem.get("acknowledged")) == "1":
                lines.append(f"Acquitté dans Zabbix ({acks} message(s))")
            params = {"eventid": str(problem["eventid"]), "triggerid": str(problem["objectid"])}

        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=next(iter(companies)) if len(companies) == 1 else None,
            asset=asset,
            category=categories.most_common(1)[0][0],
            severity=severity,
            title=clean_untrusted(title, TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=min(_ts(p["clock"]) for p in problems),
            last_seen=payload["at"],
            url_template_params=params,
        )

    def _proxy_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        proxy: Mapping[str, Any] = raw.payload["proxy"]
        name = clean_untrusted(str(proxy.get("name", "")), 200)
        last = int(proxy.get("lastaccess") or 0)
        seen = _ts(last) if last else raw.payload["at"]
        detail = f"Dernier contact : {seen:%Y-%m-%d %H:%M} UTC" if last else "Jamais contacté"
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=None,
            asset=name,
            category=Category.monitoring,
            severity=4,
            title=f"Proxy Zabbix {name} sans contact",
            details=detail,
            first_seen=seen,
            last_seen=raw.payload["at"],
            url_template_params={"proxyid": str(proxy.get("proxyid", ""))},
        )

    def _category(self, tags: Iterable[Mapping[str, Any]], groups: Sequence[str]) -> Category:
        for tag in tags:
            key = (normalize(str(tag.get("tag", ""))), normalize(str(tag.get("value", ""))))
            if key in TAG_CATEGORY:
                return TAG_CATEGORY[key]
        found: set[Category] = set()
        for group in groups:
            for word, category in self._group_words:
                if _token_in(group, word):
                    found.add(category)
                    break
        return next((c for c in CATEGORY_PRECEDENCE if c in found), DEFAULT_CATEGORY)
