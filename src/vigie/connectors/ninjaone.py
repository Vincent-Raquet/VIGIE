"""Connecteur NinjaOne (API publique v2, lecture seule). Voir docs/CONNECTORS.md §3.

Collecte (instantané, toutes les 15 min) :
- alertes actives (`/v2/alerts`), agrégées par société et type au-delà d'un seuil ;
- patchs OS et logiciels en échec (`/v2/queries/*-patches`), agrégés par société ;
- tickets d'un board (`POST /v2/ticketing/trigger/board/{id}/run`, lecture en POST à
  schéma strict), statuts filtrés localement ; jamais de description ni de demandeur.

Authentification : jeton OAuth2 « client credentials », scope `monitoring` (lecture seule).
Spécification de référence : NinjaOne Public API 2.0 (2.0.9-draft, NinjaRMM-API-v2.yaml).
Les valeurs d'énumération non listées par la spécification sont marquées `TODO verify`.
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

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
from vigie.redact import clean_untrusted

SOURCE = "ninjaone"
CLIENT_SECRET = "ninjaone_client_secret"  # noqa: S105 - nom du secret, pas sa valeur
# Le client id n'est pas secret au sens OAuth, mais ressemble à une clé : hors du dépôt
# (gitleaks), il est lu dans la configuration locale ou, à défaut, dans les secrets.
CLIENT_ID_SECRET = "ninjaone_client_id"  # noqa: S105 - nom du secret, pas sa valeur
TOKEN_PATH = "/ws/oauth/token"  # noqa: S105 - chemin, pas un secret
PAGE_SIZE = 100
TITLE_MAX = 300
DETAILS_MAX = 1000
LISTED_DEVICES = 10
MAX_DEVICE_LOOKUPS = 200  # appareils d'alerte absents des listes d'organisation

# Gravité NinjaOne → 0-5. Capture réelle : toutes les alertes en « NONE » ; la sévérité vient
# alors du type d'alerte (SOURCE_SEVERITY). TODO verify : autres valeurs que NONE.
SEVERITY = {"CRITICAL": 5, "MAJOR": 4, "MODERATE": 3, "MINOR": 2}
DEFAULT_SEVERITY = 2
SOURCE_SEVERITY = {
    "CONDITION_SMART_STATUS_DEGRATED": 4,
    "CONDITION_RAID_HEALTH_STATUS": 4,
    "AV_QUARANTINE_THREAT": 5,
    "BITDEFENDER_DELETE_THREAT": 5,
    "AGENT_OFFLINE": 3,
    "CONDITION_AGENT_DISK_FREE_SPACE": 3,
    "CONDITION_LINUX_DISK_FREE_SPACE": 3,
    "CONDITION_PENDING_REBOOT": 2,
}
SOURCE_LABELS = {
    "CONDITION_AGENT_DISK_FREE_SPACE": "Espace disque faible",
    "CONDITION_LINUX_DISK_FREE_SPACE": "Espace disque faible",
    "CONDITION_AGENT_MEMORY": "Mémoire saturée",
    "CONDITION_AGENT_DISK_IO": "Disque très sollicité",
    "CONDITION_AGENT_CPU": "Processeur saturé",
    "CONDITION_PENDING_REBOOT": "Redémarrage en attente",
    "AGENT_OFFLINE": "Agent hors ligne",
}
# Priorité d'un ticket → sévérité. TODO verify : valeurs de la colonne priority.
# Capture réelle : priorité « NONE » sur tous les tickets ouverts → sévérité normale (2),
# sinon ils ne seraient jamais planifiés.
TICKET_SEVERITY = {"URGENT": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 2}

SERVER_CLASSES = frozenset(
    {
        "WINDOWS_SERVER",
        "LINUX_SERVER",
        "MAC_SERVER",
        "VMWARE_VM_HOST",
        "VMWARE_VM_GUEST",
        "HYPERV_VMM_HOST",
        "HYPERV_VMM_GUEST",
        "NMS_SERVER",
        "NMS_VM_HOST",
    }
)
SECURITY_SOURCES = ("AV_", "BITDEFENDER_", "CONDITION_BITLOCKER", "CONDITION_FILEVAULT")
VULNERABILITY_SOURCES = ("CONDITION_AGENT_CVSS_SCORE", "CONDITION_AGENT_PATCH_LAST_INSTALLED")

# Colonnes de board autorisées : identifiants, état, dates, titre. Jamais la description,
# le demandeur, le contact ni les champs personnalisés (minimisation, SECURITY.md C5).
# TODO verify : noms exacts des colonnes du board (capture réelle).
TicketColumn = Literal[
    "id", "summary", "status", "priority", "severity", "organization", "clientId",
    "type", "createTime", "lastUpdated",
]  # fmt: skip
TICKET_COLUMNS: tuple[TicketColumn, ...] = (
    "id", "summary", "status", "priority", "severity", "organization", "clientId",
    "type", "createTime", "lastUpdated",
)  # fmt: skip

# --- Allowlist (CONNECTORS.md §3) -------------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TokenRequest(_Strict):
    """Jeton client credentials, scope `monitoring` (lecture seule) et rien d'autre."""

    grant_type: Literal["client_credentials"]
    client_id: str = Field(min_length=1, max_length=200)
    client_secret: SecretStr
    scope: Literal["monitoring"]


class BoardRunRequest(_Strict):
    """Lecture d'un board : colonnes choisies dans une liste fermée, pagination seulement.

    Ni filtre, ni recherche, ni tri : le board configuré dans NinjaOne fait la sélection, les
    statuts sont filtrés localement.
    """

    includeColumns: list[TicketColumn] = Field(min_length=1, max_length=len(TICKET_COLUMNS))  # noqa: N815
    pageSize: int = Field(ge=1, le=PAGE_SIZE)  # noqa: N815
    lastCursorId: int | None = Field(None, ge=0)  # noqa: N815


PAGED = frozenset({"pageSize", "after"})
CURSOR = frozenset({"pageSize", "cursor", "status"})
ALLOWLIST: tuple[AllowedCall, ...] = (
    AllowedCall(
        method="POST",
        path=rf"^{TOKEN_PATH}$",
        body_schema=TokenRequest,
        body_format="form",
        anonymous=True,
        reason="jeton OAuth2 client credentials, scope monitoring (lecture seule)",
    ),
    AllowedCall(method="GET", path=r"^/v2/organizations$", query=PAGED),
    # Appareils par organisation : /v2/devices ne renvoie pas les appareils gérés (capture
    # réelle 2026-10-11 : 36 appareils non gérés seulement).
    AllowedCall(method="GET", path=r"^/v2/organization/[0-9]{1,9}/devices$", query=PAGED),
    AllowedCall(method="GET", path=r"^/v2/alerts$"),
    # Détails d'un appareil d'alerte absent des listes d'organisation (capture réelle : les
    # appareils gérés de certaines organisations n'y figurent pas). PATCH reste interdit.
    AllowedCall(method="GET", path=r"^/v2/device/[0-9]{1,9}$"),
    AllowedCall(method="GET", path=r"^/v2/queries/os-patches$", query=CURSOR),
    AllowedCall(method="GET", path=r"^/v2/queries/software-patches$", query=CURSOR),
    AllowedCall(method="GET", path=r"^/v2/ticketing/trigger/boards$"),
    AllowedCall(method="GET", path=r"^/v2/ticketing/statuses$"),
    AllowedCall(
        method="POST",
        path=r"^/v2/ticketing/trigger/board/[0-9]{1,9}/run$",
        body_schema=BoardRunRequest,
        reason="lecture des tickets d'un board (l'API n'offre que POST pour cette liste) ; "
        "colonnes limitées, sans description ni données personnelles",
    ),
)

# --- Configuration ----------------------------------------------------------------------


class NinjaOneConfig(_Strict):
    enabled: bool = False
    interval_min: int = Field(15, ge=5, le=1440)
    base_url: str = Field(pattern=r"^https://(app|eu|ca|oc|us2)\.ninjarmm\.com/?$")
    client_id: str | None = Field(None, min_length=1, max_length=200)
    scope: Literal["monitoring"] = "monitoring"
    ticket_board_id: int = Field(0, ge=0)  # 0 = tickets non collectés
    ticket_statuses: list[str] = Field(default_factory=list, max_length=20)
    aggregate_threshold: int = Field(5, ge=2, le=1000)
    patch_status: str = Field("FAILED", pattern=r"^[A-Z_]{1,30}$")  # TODO verify : valeur
    proxy: str | None = Field(None, pattern=r"^http://127\.0\.0\.1:[0-9]{2,5}$")
    ca_bundle: Path | None = None


# --- Connecteur -------------------------------------------------------------------------


def _ts(value: Any) -> datetime | None:
    """Horodatage NinjaOne (secondes, éventuellement en millisecondes) → datetime UTC."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number > 1e12:  # millisecondes
        number /= 1000
    return datetime.fromtimestamp(number, tz=UTC)


def _text(value: Any) -> str:
    """Valeur de colonne : chaîne directe ou objet {displayName|name|value}."""
    if isinstance(value, Mapping):
        for key in ("displayName", "name", "value"):
            if value.get(key) is not None:
                return str(value[key])
        return ""
    return "" if value is None else str(value)


def _dict(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _device(devices: Mapping[int, Mapping[str, Any]], device_id: Any) -> Mapping[str, Any]:
    return devices.get(device_id, {}) if isinstance(device_id, int) else {}


def _severity(alert: Mapping[str, Any]) -> int:
    explicit = SEVERITY.get(str(alert.get("severity", "")).upper())
    if explicit is not None:
        return explicit
    source = str(alert.get("sourceType", ""))
    if source.startswith(("AV_", "BITDEFENDER_")):
        return 5
    return SOURCE_SEVERITY.get(source, DEFAULT_SEVERITY)


def _int(value: Any) -> int | None:
    """Identifiant numérique, reçu en nombre ou en texte (capture réelle : « 2766 »)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _category(source_type: str, node_class: str) -> Category:
    if source_type.startswith(SECURITY_SOURCES):
        return Category.security
    if source_type in VULNERABILITY_SOURCES:
        return Category.vulnerability
    if node_class == "NMS_FIREWALL":
        return Category.firewall
    if node_class.startswith("NMS_") and node_class not in SERVER_CLASSES:
        return Category.network
    if node_class in SERVER_CLASSES:
        return Category.server
    return Category.endpoint


def _digest(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode(), usedforsecurity=False).hexdigest()[:16]


class NinjaOneConnector:
    name = SOURCE
    allowlist = ALLOWLIST

    def __init__(
        self,
        config: NinjaOneConfig,
        client: SafeClient,
        secret: SecretStr,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        client_id: str | None = None,
    ) -> None:
        self.config = config
        self._client_id = client_id or config.client_id or ""
        self.client = client
        self._secret = secret
        self._now = now
        self._token_ok = False
        self.truncated = False

    @classmethod
    def from_context(cls, ctx: ConnectorContext) -> NinjaOneConnector:
        try:
            config = NinjaOneConfig.model_validate(dict(ctx.settings))
        except ValidationError as exc:
            fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
            raise ConnectorConfigError(
                f"[sources.ninjaone] invalide : {', '.join(fields)}"
            ) from None
        client = SafeClient(
            source=SOURCE,
            base_url=config.base_url,
            allowlist=ALLOWLIST,
            ca_bundle=config.ca_bundle or ctx.ca_bundle,
            proxy=config.proxy,
            transport=ctx.transport,
        )
        client_id = config.client_id or ctx.secret(CLIENT_ID_SECRET).get_secret_value().strip()
        return cls(config, client, ctx.secret(CLIENT_SECRET), client_id=client_id)

    # --- Authentification et pagination ------------------------------------------------

    def _login(self) -> None:
        if self._token_ok:
            return
        data = self.client.post(
            TOKEN_PATH,
            {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._secret,
                "scope": self.config.scope,
            },
        )
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise SourceCallError(f"{SOURCE} : réponse de jeton sans access_token")
        self.client.set_auth_header("Authorization", SecretStr(f"Bearer {token}"))
        self._token_ok = True

    def _bounded(self, items: Iterable[Any], seen: list[int]) -> Iterator[Any]:
        for item in items:
            if seen[0] >= MAX_OBJECTS:
                self.truncated = True
                return
            seen[0] += 1
            yield item

    def _by_id(self, path: str) -> Iterator[Any]:
        """Pagination `pageSize` + `after` (dernier id reçu) : organisations, appareils."""
        self._login()
        seen, after = [0], None
        while True:
            params: dict[str, Any] = {"pageSize": PAGE_SIZE}
            if after is not None:
                params["after"] = after
            page = self.client.get(path, params)
            items = page if isinstance(page, list) else []
            yield from self._bounded(items, seen)
            if self.truncated or len(items) < PAGE_SIZE:
                return
            after = items[-1].get("id") if isinstance(items[-1], dict) else None
            if after is None:
                return

    def _by_cursor(self, path: str, status: str) -> Iterator[Any]:
        """Pagination par curseur nommé (rapports de patchs). TODO verify : sémantique."""
        self._login()
        seen, cursor = [0], None
        while True:
            params: dict[str, Any] = {"pageSize": PAGE_SIZE, "status": status}
            if cursor:
                params["cursor"] = cursor
            page = self.client.get(path, params)
            results = page.get("results", []) if isinstance(page, dict) else []
            yield from self._bounded(results if isinstance(results, list) else [], seen)
            cursor = ((page.get("cursor") or {}).get("name")) if isinstance(page, dict) else None
            if self.truncated or not cursor or len(results) < PAGE_SIZE:
                return

    def _tickets(self) -> Iterator[Mapping[str, Any]]:
        if not self.config.ticket_board_id:
            return
        self._login()
        path = f"/v2/ticketing/trigger/board/{self.config.ticket_board_id}/run"
        seen, last = [0], None
        while True:
            body: dict[str, Any] = {"includeColumns": list(TICKET_COLUMNS), "pageSize": PAGE_SIZE}
            if last is not None:
                body["lastCursorId"] = last
            page = self.client.post(path, body)
            raw_rows = page.get("data", []) if isinstance(page, dict) else []
            # NinjaOne ignore includeColumns (capture réelle) : description, demandeur,
            # technicien… arrivent quand même. On ne garde que les colonnes autorisées,
            # avant tout autre traitement.
            rows = [
                {k: r[k] for k in TICKET_COLUMNS if k in r}
                for r in (raw_rows if isinstance(raw_rows, list) else [])
                if isinstance(r, dict)
            ]
            yield from self._bounded(rows, seen)
            meta = page.get("metadata") if isinstance(page, dict) else None
            last = (meta or {}).get("lastCursorId") if isinstance(meta, dict) else None
            if self.truncated or len(rows) < PAGE_SIZE or not isinstance(last, int):
                return

    # --- Santé -------------------------------------------------------------------------

    def healthcheck(self) -> HealthStatus:
        started = time.monotonic()
        try:
            self._login()
            self.client.get("/v2/organizations", {"pageSize": 1})
        except SourceCallError as exc:
            return HealthStatus(ok=False, detail=str(exc))
        latency = round((time.monotonic() - started) * 1000, 1)
        return HealthStatus(ok=True, detail="", version="API v2", latency_ms=latency)

    # --- Collecte ----------------------------------------------------------------------

    def collect(self, since: datetime) -> Iterable[RawSignal]:
        """Instantané : `since` est ignoré, chaque collecte relit l'état complet."""
        now = self._now()
        self.truncated = False
        orgs = {
            int(o["id"]): str(o.get("name", ""))
            for o in self._by_id("/v2/organizations")
            if isinstance(o, dict) and isinstance(o.get("id"), int)
        }
        devices: dict[int, Mapping[str, Any]] = {}
        for org_id in orgs:
            for d in self._by_id(f"/v2/organization/{org_id}/devices"):
                if isinstance(d, dict) and (dev_id := _int(d.get("id"))) is not None:
                    devices[dev_id] = {"organizationId": org_id, **d}
        out: list[RawSignal] = []
        out.extend(self._alert_signals(orgs, devices, now))
        out.extend(self._patch_signals(orgs, devices, now))
        statuses = {s.casefold() for s in self.config.ticket_statuses}
        for row in self._tickets():
            if not isinstance(row, dict) or row.get("id") is None:
                continue
            if statuses and _text(row.get("status")).casefold() not in statuses:
                continue
            out.append(
                RawSignal(
                    f"ticket:{row['id']}", {"kind": "ticket", "row": row, "orgs": orgs, "at": now}
                )
            )
        return sorted(out, key=lambda r: r.external_id)

    def _device_details(self, dev_id: int, done: int) -> Mapping[str, Any]:
        if done >= MAX_DEVICE_LOOKUPS:
            self.truncated = True
            return {}
        data = self.client.get(f"/v2/device/{dev_id}")
        if not isinstance(data, dict):
            return {}
        keep = ("id", "organizationId", "nodeClass", "systemName", "displayName", "offline")
        return {k: data[k] for k in keep if k in data}

    def _alert_signals(
        self, orgs: Mapping[int, str], devices: Mapping[int, Mapping[str, Any]], now: datetime
    ) -> list[RawSignal]:
        self._login()
        alerts: list[dict[str, Any]] = []
        looked_up: dict[int, Mapping[str, Any]] = {}
        for a in self.client.get("/v2/alerts") or []:
            if not isinstance(a, dict):
                continue
            # L'alerte réelle ne porte que deviceId (en texte) : l'appareil vient de la liste
            # de son organisation, sinon de sa fiche (lecture bornée).
            dev_id = _int(a.get("deviceId"))
            known = _device(devices, dev_id)
            if not known and dev_id is not None and dev_id not in looked_up:
                looked_up[dev_id] = self._device_details(dev_id, len(looked_up))
            device = {**known, **looked_up.get(dev_id or -1, {}), **_dict(a.get("device"))}
            alerts.append({**a, "device": device})
        groups: dict[tuple[int | None, str], list[Mapping[str, Any]]] = defaultdict(list)
        for a in alerts:
            org = _dict(a.get("device")).get("organizationId")
            key = str(a.get("sourceType") or a.get("conditionName") or "alerte")
            groups[(org if isinstance(org, int) else None, key)].append(a)
        out: list[RawSignal] = []
        for (org, key), items in groups.items():
            org_name = orgs.get(org, "") if org is not None else ""
            if len(items) >= self.config.aggregate_threshold:
                out.append(
                    RawSignal(
                        f"alerts:{org}:{_digest(key)}",
                        {"kind": "alert_group", "alerts": items, "org": org,
                         "org_name": org_name, "condition": key, "at": now},
                    )
                )  # fmt: skip
            else:
                out.extend(
                    RawSignal(
                        f"alert:{a.get('uid')}",
                        {"kind": "alert", "alert": a, "org": org, "org_name": org_name, "at": now},
                    )
                    for a in items
                )
        return out

    def _patch_signals(
        self, orgs: Mapping[int, str], devices: Mapping[int, Mapping[str, Any]], now: datetime
    ) -> list[RawSignal]:
        out: list[RawSignal] = []
        for kind, path in (
            ("os", "/v2/queries/os-patches"),
            ("software", "/v2/queries/software-patches"),
        ):
            by_org: dict[int | None, list[Mapping[str, Any]]] = defaultdict(list)
            for patch in self._by_cursor(path, self.config.patch_status):
                if not isinstance(patch, dict):
                    continue
                org = _device(devices, _int(patch.get("deviceId"))).get("organizationId")
                by_org[org if isinstance(org, int) else None].append(patch)
            for org, patches in by_org.items():
                names = sorted(
                    {
                        str(
                            _device(devices, _int(p.get("deviceId"))).get("systemName")
                            or _device(devices, _int(p.get("deviceId"))).get("displayName")
                            or p.get("deviceId")
                        )
                        for p in patches
                    }
                )
                out.append(
                    RawSignal(
                        f"patches:{kind}:{org}",
                        {"kind": "patches", "patch_kind": kind, "patches": patches,
                         "devices": names, "org": org,
                         "org_name": orgs.get(org, "") if org is not None else "", "at": now},
                    )
                )  # fmt: skip
        return out

    # --- Normalisation -----------------------------------------------------------------

    def _company(self, mapping: CompanyMapper, org: Any) -> str | None:
        return mapping.company_for(SOURCE, MatchType.org_id, str(org)) if org is not None else None

    def to_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        kind = raw.payload["kind"]
        if kind == "ticket":
            return self._ticket_signal(raw, mapping)
        if kind == "patches":
            return self._patch_signal(raw, mapping)
        if kind == "alert_group":
            return self._alert_group_signal(raw, mapping)
        return self._alert_signal(raw, mapping)

    def _alert_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        a: Mapping[str, Any] = p["alert"]
        device = _dict(a.get("device"))
        host = clean_untrusted(
            str(device.get("systemName") or device.get("displayName") or ""), 200
        )
        source_type = str(a.get("sourceType", ""))
        node_class = str(device.get("nodeClass", ""))
        # Capture réelle : le sujet n'est souvent que le volume (« C: ») ; on préfixe le type.
        label = SOURCE_LABELS.get(source_type) or str(a.get("conditionName") or source_type)
        subject = str(a.get("subject") or "")
        title = f"{label} ({subject})" if subject and subject not in label else label
        lines = [f"Appareil : {host}", f"Type : {source_type}"]
        if p["org_name"]:
            lines.append(f"Organisation NinjaOne : {p['org_name']}")
        if a.get("message"):
            lines.append(f"Message : {a['message']}")
        created = _ts(a.get("createTime")) or p["at"]
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=self._company(mapping, p["org"]),
            asset=host,
            category=_category(source_type, node_class),
            severity=_severity(a),
            title=clean_untrusted(f"{host} : {title}" if host else title, TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=created,
            last_seen=p["at"],
            url_template_params={"device_id": str(a.get("deviceId", ""))},
            attributes={
                "kind": "alert",
                "source_type": source_type,
                "node_class": node_class,
                "offline": bool(device.get("offline")),
            },
        )

    def _alert_group_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        alerts: Sequence[Mapping[str, Any]] = p["alerts"]
        hosts = sorted(
            {
                str(
                    _dict(a.get("device")).get("systemName")
                    or _dict(a.get("device")).get("displayName")
                    or a.get("deviceId")
                )
                for a in alerts
                if isinstance(a.get("device"), dict) or a.get("deviceId") is not None
            }
        )
        severity = max(_severity(a) for a in alerts)
        first = alerts[0]
        device = _dict(first.get("device"))
        source_type = str(first.get("sourceType", ""))
        condition = clean_untrusted(SOURCE_LABELS.get(p["condition"], p["condition"]), 200)
        lines = [f"Condition : {condition}", f"Appareils : {len(hosts)}"]
        lines.append("Exemples : " + ", ".join(hosts[:LISTED_DEVICES]))
        if p["org_name"]:
            lines.append(f"Organisation NinjaOne : {p['org_name']}")
        firsts = [t for a in alerts if (t := _ts(a.get("createTime"))) is not None]
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=self._company(mapping, p["org"]),
            asset=clean_untrusted(p["org_name"] or "NinjaOne", 200),
            category=_category(source_type, str(device.get("nodeClass", ""))),
            severity=severity,
            title=clean_untrusted(f"{condition} sur {len(hosts)} appareil(s)", TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=min(firsts, default=p["at"]),
            last_seen=p["at"],
            attributes={"kind": "alert_group", "source_type": source_type, "count": len(alerts)},
        )

    def _patch_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        patches: Sequence[Mapping[str, Any]] = p["patches"]
        os_kind = p["patch_kind"] == "os"
        critical = any(
            str(x.get("severity" if os_kind else "impact", "")).upper() == "CRITICAL"
            for x in patches
        )  # TODO verify : valeurs de severity / impact
        label = "OS" if os_kind else "logiciels"
        names = [
            str(x.get("name") if os_kind else x.get("title") or x.get("productIdentifier") or "")
            for x in patches
        ]
        lines = [
            f"Patchs {label} en échec : {len(patches)} sur {len(p['devices'])} appareil(s)",
            "Appareils : " + ", ".join(p["devices"][:LISTED_DEVICES]),
            "Patchs : " + ", ".join(sorted({n for n in names if n})[:LISTED_DEVICES]),
        ]
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=self._company(mapping, p["org"]),
            asset=clean_untrusted(p["org_name"] or "NinjaOne", 200),
            category=Category.vulnerability,
            severity=(4 if critical else 3) if os_kind else (3 if critical else 2),
            title=clean_untrusted(
                f"{len(patches)} patch(s) {label} en échec sur {len(p['devices'])} appareil(s)",
                TITLE_MAX,
            ),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=p["at"],
            last_seen=p["at"],
            attributes={"kind": "patches", "patch_kind": p["patch_kind"], "count": len(patches)},
        )

    def _ticket_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        row: Mapping[str, Any] = p["row"]
        ticket_id = str(row.get("id"))
        status = clean_untrusted(_text(row.get("status")), 60)
        priority = _text(row.get("priority")).upper()
        org = row.get("clientId")
        if org is None and isinstance(row.get("organization"), dict):
            org = row["organization"].get("id")
        if org is None:  # capture réelle : clientId vide, organisation donnée par son nom
            name = _text(row.get("organization")).casefold()
            org = next((i for i, n in p["orgs"].items() if n.casefold() == name), None)
        summary = clean_untrusted(_text(row.get("summary")), 200)
        created = _ts(row.get("createTime")) or p["at"]
        lines = [f"Ticket n° {ticket_id}", f"Statut : {status}"]
        if priority:
            lines.append(f"Priorité : {priority}")
        org_name = _text(row.get("organization")) or (
            p["orgs"].get(org, "") if isinstance(org, int) else ""
        )
        if org_name:
            lines.append(f"Organisation NinjaOne : {clean_untrusted(org_name, 100)}")
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=self._company(mapping, org),
            asset=f"Ticket n° {ticket_id}",
            category=Category.user_support,
            severity=TICKET_SEVERITY.get(priority, 2),
            # Titre rédigé par l'utilisateur : affiché aux techniciens, masqué pour l'IA
            # tant que [llm] send_ticket_text = false (attribut kind = ticket).
            title=clean_untrusted(f"Ticket n° {ticket_id} : {summary}", TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=created,
            last_seen=p["at"],
            url_template_params={"ticket_id": ticket_id},
            attributes={"kind": "ticket", "ticket_id": ticket_id, "status": status},
        )
