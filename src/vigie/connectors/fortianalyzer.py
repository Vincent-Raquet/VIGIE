"""Connecteur FortiAnalyzer 8.0 (JSON-RPC, lecture seule). Voir docs/CONNECTORS.md §2.

Collecte (instantané, toutes les 15 min) :
- alertes de l'Event Monitor des 24 dernières heures, non acquittées, agrégées par event
  handler et par appareil (`get /eventmgmt/adom/{adom}/alerts`) ;
- état des appareils : connexion FortiGate ↔ FAZ et HA (`get /dvmdb/adom/{adom}/device`) ;
- tunnels VPN tombés : alertes VPN de l'Event Monitor ; en option (`vpn_logsearch`), recherche
  dans les journaux d'événements VPN (`add` puis `get` de `/logview/adom/{adom}/logsearch`).

Authentification : clé API d'un administrateur API en lecture seule (`Authorization:
Bearer`), secret `fortianalyzer_api_key`. Chaque réponse JSON-RPC porte un code d'état par
résultat (HTTP 200 même en cas de refus, ex. -11 « No permission ») : il est vérifié.

Sans accès à la référence officielle (FNDN), les URL, paramètres et champs viennent des
sources publiques (implémentations testées sur la 8.0.0 GA) ; ce qui n'est pas confirmé est
marqué `TODO verify` et tranché par la capture (`scripts/record_fixtures.py fortianalyzer`).
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict, Field, RootModel, SecretStr, ValidationError

from vigie.connectors.base import (
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

SOURCE = "fortianalyzer"
ENDPOINT = "/jsonrpc"
KEY_SECRET = "fortianalyzer_api_key"  # noqa: S105 - nom du secret, pas sa valeur
API_VERSION = 3  # TODO verify : apiver des appels eventmgmt/logview en 8.0
PAGE = 500
MAX_ALERTS = 5000
LOG_PAGE = 500
LOGSEARCH_POLLS = 10
TITLE_MAX = 300
DETAILS_MAX = 1000
LISTED = 10
SUPPORTED_MAJOR = 8
ADOM_RE = r"[A-Za-z0-9_-]{1,35}"
TIME_RE = r"^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$"
# Recherche des tunnels tombés (journaux d'événements VPN). TODO verify : syntaxe du filtre.
VPN_DOWN_FILTER = "subtype==vpn and action==tunnel-down"

# --- Allowlist (CONNECTORS.md §2) : méthode JSON-RPC « get » sur des URL listées ---------


class _P(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class TimeRange(_P):
    start: str = Field(pattern=TIME_RE)
    end: str = Field(pattern=TIME_RE)


class StatusGet(_P):
    url: Literal["/sys/status"]


class AlertsGet(_P):
    url: str = Field(pattern=rf"^/eventmgmt/adom/{ADOM_RE}/alerts$")
    apiver: Literal[3]
    limit: int = Field(ge=1, le=2000)
    offset: int = Field(ge=0, le=MAX_ALERTS)
    time_range: TimeRange = Field(alias="time-range")
    time_order: Literal["desc"] = Field(alias="time-order")


# Champs d'appareil lus (minimisation) ; TODO verify : noms des champs HA en 8.0.
DeviceField = Literal[
    "name",
    "hostname",
    "sn",
    "conn_status",
    "ha_mode",
    "ha_group_name",
    "ha_slave",
    "os_ver",
    "mr",
    "patch",
    "platform_str",
]


class DevicesGet(_P):
    url: str = Field(pattern=rf"^/dvmdb/adom/{ADOM_RE}/device$")
    fields: list[DeviceField] = Field(min_length=1, max_length=20)
    loadsub: Literal[0]


class LogsearchResultGet(_P):
    url: str = Field(pattern=rf"^/logview/adom/{ADOM_RE}/logsearch/[0-9]{{1,12}}$")
    apiver: Literal[3]
    offset: int = Field(ge=0, le=MAX_ALERTS)
    limit: int = Field(ge=1, le=1000)


GetItem = StatusGet | AlertsGet | DevicesGet | LogsearchResultGet


class GetParams(RootModel[Annotated[list[GetItem], Field(min_length=1, max_length=1)]]):
    """Un seul objet par appel, d'une des URL ci-dessus (lecture seule)."""


class LogsearchDevice(_P):
    devid: Literal["All_FortiGate"]


class LogsearchAdd(_P):
    url: str = Field(pattern=rf"^/logview/adom/{ADOM_RE}/logsearch$")
    apiver: Literal[3]
    logtype: Literal["event"]
    device: list[LogsearchDevice] = Field(min_length=1, max_length=1)
    filter: Literal["subtype==vpn and action==tunnel-down"]
    time_range: TimeRange = Field(alias="time-range")
    time_order: Literal["desc"] = Field(alias="time-order")


class LogsearchAddParams(
    RootModel[Annotated[list[LogsearchAdd], Field(min_length=1, max_length=1)]]
):
    """Création d'une tâche de recherche : filtre imposé (tunnels VPN tombés), rien d'autre."""


READ_ALLOWLIST: tuple[AllowedCall, ...] = (
    AllowedCall(jsonrpc="get", endpoint=ENDPOINT, params_schema=GetParams),
)
LOGSEARCH_ALLOWLIST: tuple[AllowedCall, ...] = (
    AllowedCall(
        jsonrpc="add",
        endpoint=ENDPOINT,
        params_schema=LogsearchAddParams,
        override_reason=(
            "« add » sur /logview/.../logsearch crée une tâche de recherche temporaire dans les "
            "journaux (sans effet sur la configuration) ; filtre imposé aux tunnels VPN tombés, "
            "seulement si vpn_logsearch = true (l'Event Monitor ne suffit pas)"
        ),
    ),
)
# Pour les tests génériques des connecteurs enregistrés.
ALLOWLIST: tuple[AllowedCall, ...] = READ_ALLOWLIST + LOGSEARCH_ALLOWLIST

# --- Configuration ----------------------------------------------------------------------


class FortiAnalyzerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    interval_min: int = Field(15, ge=5, le=1440)
    # Nom porté par le certificat (le certificat d'usine n'a ni SAN ni IP : entrée DNS ou
    # /etc/hosts vers l'IP du FAZ).
    base_url: str = Field(pattern=r"^https://[A-Za-z0-9.-]{1,253}(:[0-9]{2,5})?/?$")
    adom: str = Field("root", pattern=rf"^{ADOM_RE}$")
    window_hours: int = Field(24, ge=1, le=168)
    timezone: str = "Europe/Brussels"  # fuseau du FAZ pour time-range ; TODO verify
    vpn_logsearch: bool = False
    ca_bundle: str | None = None
    proxy: str | None = Field(None, pattern=r"^http://127\.0\.0\.1:[0-9]{2,5}$")


# --- Connecteur -------------------------------------------------------------------------

SEVERITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "information": 1}
VPN_WORDS = ("vpn", "tunnel", "ipsec")
SECURITY_WORDS = (
    "ips",
    "virus",
    "malware",
    "botnet",
    "attack",
    "intrusion",
    "compromis",
    "ioc",
    "sandbox",
    "ransom",
)


def _first(row: Mapping[str, Any], *keys: str) -> Any:
    """Premier champ présent (noms qui varient selon les versions ; TODO verify)."""
    for key in keys:
        value = row.get(key)
        if value not in (None, "", []):
            return value
    return None


def _text(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return "" if value is None else str(value)


def _when(value: Any) -> datetime | None:
    """Horodatage d'alerte : epoch (s) ou texte « AAAA-MM-JJ hh:mm:ss » (TODO verify)."""
    if isinstance(value, int | float) and not isinstance(value, bool) and value > 0:
        return datetime.fromtimestamp(float(value), UTC)
    if isinstance(value, str):
        if value.isdigit():
            return datetime.fromtimestamp(float(value), UTC)
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _digest(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode(), usedforsecurity=False).hexdigest()[:12]


class FortiAnalyzerConnector:
    name = SOURCE
    allowlist = ALLOWLIST

    def __init__(
        self,
        config: FortiAnalyzerConfig,
        client: SafeClient,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self.client = client
        self._now = now
        self._sleep = sleep
        self.truncated = False

    @classmethod
    def from_context(cls, ctx: ConnectorContext) -> FortiAnalyzerConnector:
        try:
            config = FortiAnalyzerConfig.model_validate(dict(ctx.settings))
            ZoneInfo(config.timezone)
        except (ValidationError, ValueError, KeyError) as exc:
            fields = (
                sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
                if isinstance(exc, ValidationError)
                else ["timezone"]
            )
            raise ConnectorConfigError(
                f"[sources.fortianalyzer] invalide : {', '.join(fields)}"
            ) from None
        from pathlib import Path

        ca = Path(config.ca_bundle).expanduser() if config.ca_bundle else ctx.ca_bundle
        allowlist = READ_ALLOWLIST + (LOGSEARCH_ALLOWLIST if config.vpn_logsearch else ())
        client = SafeClient(
            source=SOURCE,
            base_url=config.base_url.rstrip("/"),
            allowlist=allowlist,
            ca_bundle=ca,
            proxy=config.proxy,
            transport=ctx.transport,
            jsonrpc_version="2.0",
        )
        client.set_auth_header(
            "Authorization",
            SecretStr("Bearer " + ctx.secret(KEY_SECRET).get_secret_value().strip()),
        )
        return cls(config, client)

    # --- Appels ----------------------------------------------------------------------

    def _call(self, method: str, item: Mapping[str, Any]) -> Any:
        result = self.client.jsonrpc(method, [dict(item)])
        entry = result[0] if isinstance(result, list) and result else result
        if not isinstance(entry, dict):
            raise SourceCallError(f"{SOURCE} : réponse inattendue ({item.get('url')})")
        status = entry.get("status")
        code = status.get("code", 0) if isinstance(status, dict) else 0
        if code != 0:
            # -11 : droits du compte API ; -6 : URL inconnue (version).
            raise SourceCallError(f"{SOURCE} : {item.get('url')} refusé (code {code})")
        return entry.get("data")

    def _range(self, now: datetime) -> dict[str, str]:
        tz = ZoneInfo(self.config.timezone)
        start = now - timedelta(hours=self.config.window_hours)
        fmt = "%Y-%m-%d %H:%M:%S"
        return {
            "start": start.astimezone(tz).strftime(fmt),
            "end": now.astimezone(tz).strftime(fmt),
        }

    # --- Santé -------------------------------------------------------------------------

    def healthcheck(self) -> HealthStatus:
        started = time.monotonic()
        try:
            data = self._call("get", {"url": "/sys/status"})
        except SourceCallError as exc:
            return HealthStatus(ok=False, detail=str(exc))
        latency = round((time.monotonic() - started) * 1000, 1)
        data = data if isinstance(data, dict) else {}
        version = str(data.get("Version") or "?").strip()
        major = data.get("Major")
        detail = "" if major == SUPPORTED_MAJOR else f"version {major} non testée (attendue 8.x)"
        if str(data.get("Admin Domain Configuration", "")).lower() == "enabled":
            detail = (
                detail + " ; " if detail else ""
            ) + f"ADOM activés : ADOM lu « {self.config.adom} »"
        return HealthStatus(ok=True, detail=detail, version=version, latency_ms=latency)

    # --- Collecte ----------------------------------------------------------------------

    def collect(self, since: datetime) -> Iterable[RawSignal]:
        """Instantané : `since` est ignoré ; fenêtre glissante de `window_hours`."""
        now = self._now()
        self.truncated = False
        out: list[RawSignal] = []
        out.extend(self._alert_signals(now))
        out.extend(self._device_signals(now))
        if self.config.vpn_logsearch:
            out.extend(self._vpn_log_signals(now))
        return sorted(out, key=lambda r: r.external_id)

    def _alerts(self, now: datetime) -> list[Mapping[str, Any]]:
        rows: list[Mapping[str, Any]] = []
        offset = 0
        url = f"/eventmgmt/adom/{self.config.adom}/alerts"
        while True:
            data = self._call(
                "get",
                {
                    "url": url,
                    "apiver": API_VERSION,
                    "limit": PAGE,
                    "offset": offset,
                    "time-range": self._range(now),
                    "time-order": "desc",
                },
            )
            page = data.get("data", data) if isinstance(data, dict) else data
            page = page if isinstance(page, list) else []
            rows.extend(r for r in page if isinstance(r, dict))
            offset += len(page)
            if len(page) < PAGE:
                return rows
            if offset >= MAX_ALERTS:
                self.truncated = True
                return rows

    def _alert_signals(self, now: datetime) -> list[RawSignal]:
        groups: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
        for alert in self._alerts(now):
            # Non acquittées seulement (TODO verify : champ et valeurs d'acquittement).
            ack = str(_first(alert, "ackflag", "ack_flag", "acknowledged") or "no").lower()
            if ack in ("yes", "1", "true", "acked", "acknowledged"):
                continue
            trigger = _text(_first(alert, "triggername", "trigger_name", "handler")) or "?"
            device = _text(_first(alert, "devname", "devs", "devid", "dev")) or "?"
            groups[(trigger, device)].append(alert)
        return [
            RawSignal(
                f"alert:{_digest(trigger, device)}",
                {
                    "kind": "alert",
                    "trigger": trigger,
                    "device": device,
                    "alerts": alerts,
                    "at": now,
                },
            )
            for (trigger, device), alerts in groups.items()
        ]

    def _device_signals(self, now: datetime) -> list[RawSignal]:
        data = self._call(
            "get",
            {
                "url": f"/dvmdb/adom/{self.config.adom}/device",
                "loadsub": 0,
                "fields": [
                    "name",
                    "hostname",
                    "sn",
                    "conn_status",
                    "ha_mode",
                    "ha_group_name",
                    "ha_slave",
                    "os_ver",
                    "mr",
                    "patch",
                    "platform_str",
                ],
            },
        )
        devices = data if isinstance(data, list) else []
        out: list[RawSignal] = []
        for dev in devices:
            if not isinstance(dev, dict) or not dev.get("name"):
                continue
            name = str(dev["name"])
            # conn_status : 1 connecté, 2 déconnecté, 0 inconnu (ignoré). TODO verify.
            if str(dev.get("conn_status")) in ("2", "down"):
                out.append(
                    RawSignal(
                        f"device:{_digest(name)}:down",
                        {"kind": "device_down", "device": dev, "at": now},
                    )
                )
            raw_members = dev.get("ha_slave")
            members: list[Any] = raw_members if isinstance(raw_members, list) else []
            ha = str(dev.get("ha_mode", "0"))
            down = [
                m
                for m in members
                if isinstance(m, dict) and str(m.get("status", "1")) not in ("1", "up")
            ]
            if ha not in ("0", "standalone", "") and (down or len(members) == 1):
                out.append(
                    RawSignal(
                        f"device:{_digest(name)}:ha",
                        {
                            "kind": "ha_degraded",
                            "device": dev,
                            "members": members,
                            "down": down,
                            "at": now,
                        },
                    )
                )
        return out

    def _vpn_log_signals(self, now: datetime) -> list[RawSignal]:
        adom = self.config.adom
        task = self._call(
            "add",
            {
                "url": f"/logview/adom/{adom}/logsearch",
                "apiver": API_VERSION,
                "logtype": "event",
                "device": [{"devid": "All_FortiGate"}],
                "filter": VPN_DOWN_FILTER,
                "time-range": self._range(now),
                "time-order": "desc",
            },
        )
        tid = task.get("tid") if isinstance(task, dict) else None
        if not isinstance(tid, int):
            raise SourceCallError(f"{SOURCE} : recherche VPN sans identifiant de tâche")
        logs: list[Mapping[str, Any]] = []
        for _ in range(LOGSEARCH_POLLS):
            data = self._call(
                "get",
                {
                    "url": f"/logview/adom/{adom}/logsearch/{tid}",
                    "apiver": API_VERSION,
                    "offset": 0,
                    "limit": LOG_PAGE,
                },
            )
            data = data if isinstance(data, dict) else {}
            # TODO verify : avancement (percentage) et liste des journaux (data).
            if int(data.get("percentage", 100) or 0) >= 100:
                logs = [r for r in data.get("data", []) or [] if isinstance(r, dict)]
                break
            self._sleep(1)
        groups: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
        for log in logs:
            device = _text(_first(log, "devname", "devid")) or "?"
            tunnel = _text(_first(log, "vpntunnel", "tunnelid", "remip")) or "?"
            groups[(device, tunnel)].append(log)
        return [
            RawSignal(
                f"vpnlog:{_digest(device, tunnel)}",
                {"kind": "vpn_log", "device": device, "tunnel": tunnel, "logs": items, "at": now},
            )
            for (device, tunnel), items in groups.items()
        ]

    # --- Normalisation -----------------------------------------------------------------

    def _company(self, mapping: CompanyMapper, device: str) -> str | None:
        return mapping.company_for(SOURCE, MatchType.devname_prefix, device) if device else None

    def to_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        kind = raw.payload["kind"]
        if kind == "alert":
            return self._alert_signal(raw, mapping)
        if kind == "vpn_log":
            return self._vpn_log_signal(raw, mapping)
        return self._device_signal(raw, mapping)

    def _alert_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        alerts: Sequence[Mapping[str, Any]] = p["alerts"]
        trigger = clean_untrusted(p["trigger"], 150)
        device = clean_untrusted(p["device"], 100)
        severities = [
            SEVERITY.get(str(_first(a, "severity", "level") or "").lower(), 3) for a in alerts
        ]
        severity = max(severities, default=3)
        haystack = f"{trigger} {_text(_first(alerts[0], 'subject', 'eventtype'))}".lower()
        vpn = any(w in haystack for w in VPN_WORDS)
        if vpn:
            category = Category.network
        elif any(w in haystack for w in SECURITY_WORDS):
            category = Category.security
        else:
            category = Category.firewall
        times = [
            t for a in alerts if (t := _when(_first(a, "alerttime", "firstlogtime", "lastlogtime")))
        ]
        count = sum(int(_first(a, "logcount", "count") or 1) for a in alerts)
        subjects = sorted(
            {
                clean_untrusted(_text(_first(a, "subject", "eventtype", "extrainfo")), 200)
                for a in alerts
            }
            - {""}
        )
        lines = [
            f"Event handler : {trigger}",
            f"Appareil : {device}",
            f"Alertes non acquittées sur {self.config.window_hours} h : {len(alerts)} "
            f"({count} journaux)",
        ]
        if subjects:
            lines.append("Exemples : " + " ; ".join(subjects[:5]))
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=self._company(mapping, p["device"]),
            asset=device,
            category=category,
            severity=severity,
            title=clean_untrusted(f"{trigger} — {device} ({len(alerts)} alerte(s))", TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=min(times, default=p["at"]),
            last_seen=max(times, default=p["at"]),
            attributes={
                # Événement passé, pas l'état courant du tunnel : pas « vpn_down » (réservé à
                # une panne en cours, override P1 après 30 min).
                "kind": "vpn_event" if vpn else "alert",
                "trigger": trigger,
                "count": len(alerts),
            },
        )

    def _device_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        dev: Mapping[str, Any] = p["device"]
        name = clean_untrusted(str(dev.get("name", "")), 100)
        version = clean_untrusted(_text(dev.get("os_ver")), 20)
        platform = clean_untrusted(_text(dev.get("platform_str")), 60)
        if p["kind"] == "device_down":
            title = f"FortiGate {name} déconnecté du FortiAnalyzer"
            lines = [
                f"Appareil : {name} ({platform}, FortiOS {version})",
                "Le FortiAnalyzer ne reçoit plus ses journaux (connexion perdue).",
            ]
            state, severity = "offline", 4
        else:
            members = ", ".join(
                clean_untrusted(_text(m.get("name") or m.get("sn")), 60) for m in p["members"]
            )
            down = ", ".join(clean_untrusted(_text(m.get("name") or m.get("sn")), 60)
                             for m in p["down"]) or "membre unique"  # fmt: skip
            group = clean_untrusted(_text(dev.get("ha_group_name")), 60)
            title = f"Cluster HA dégradé : {name}"
            lines = [
                f"Cluster {group or name} : membres {members or '?'}",
                f"Membre(s) hors service : {down}",
            ]
            state, severity = "ha_degraded", 4
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=self._company(mapping, str(dev.get("name", ""))),
            asset=name,
            category=Category.firewall,
            severity=severity,
            title=clean_untrusted(title, TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=p["at"],
            last_seen=p["at"],
            # Override firewall_down (P1) : catégorie firewall et état offline / ha_degraded.
            attributes={"kind": p["kind"], "state": state},
        )

    def _vpn_log_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        logs: Sequence[Mapping[str, Any]] = p["logs"]
        device = clean_untrusted(p["device"], 100)
        tunnel = clean_untrusted(p["tunnel"], 100)
        times = [t for log in logs if (t := _when(_first(log, "itime", "date", "eventtime")))]
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=self._company(mapping, p["device"]),
            asset=device,
            category=Category.network,
            severity=4,
            title=clean_untrusted(
                f"Tunnel VPN {tunnel} tombé — {device} ({len(logs)} fois)", TITLE_MAX
            ),
            details=clean_untrusted(
                f"Appareil : {device}\nTunnel : {tunnel}\n"
                f"Événements tunnel-down sur {self.config.window_hours} h : {len(logs)}",
                DETAILS_MAX,
            ),
            first_seen=min(times, default=p["at"]),
            last_seen=max(times, default=p["at"]),
            attributes={"kind": "vpn_event", "tunnel": tunnel, "count": len(logs)},
        )
