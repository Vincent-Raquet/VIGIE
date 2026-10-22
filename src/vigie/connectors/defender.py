"""Connecteur Microsoft Defender (lecture seule). Voir docs/CONNECTORS.md §9.

Sources (application Entra « Vigie Defender », permissions d'application en lecture) :
- Defender for Endpoint, `eu.api.security.microsoft.com` : vulnérabilités (`/api/vulnerabilities`,
  `Vulnerability.Read.All`), correspondance appareil ↔ CVE (`/api/vulnerabilities/
  machinesVulnerabilities`), appareils (`/api/machines`, `Machine.Read.All`) ;
- Microsoft Graph v1.0 : incidents Defender XDR (`/security/incidents`,
  `SecurityIncident.Read.All`).

Authentification : assertion JWT signée par certificat (PS256, `x5t#S256`) échangée contre un
jeton par audience, une fois par collecte. Le POST du jeton passe par le `SafeClient` (allowlist) ;
MSAL n'est pas utilisé ici car il émet ses propres requêtes hors allowlist.

Sélection des vulnérabilités (analyse de criticité) : Critical et High présentes dans le tenant,
appareils Windows seulement (Linux → Wazuh, patchs → NinjaOne), agrégées par domaine et par CVE ;
on garde les exploitées, les critiques à risque élevé (CVSS, EPSS), les nouvelles et celles qui
touchent des équipements sensibles (`deviceValue` High ou serveur), au plus
`max_vulns_per_company` par domaine DNS ou étiquette Defender (≈ société).
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
import uuid
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from vigie.certs import CERT_WARN_DAYS, certificate_days_left
from vigie.connectors.base import (
    LOCAL_PROXY_RE,
    AllowedCall,
    CompanyMapper,
    ConnectorConfigError,
    ConnectorContext,
    HealthStatus,
    RawSignal,
    SafeClient,
    Signal,
    SourceCallError,
    split_link,
)
from vigie.db.enums import Category, MatchType
from vigie.redact import clean_untrusted

SOURCE = "defender"
PRIVATE_KEY_SECRET = "defender_private_key"  # noqa: S105 - nom du secret, pas sa valeur
# Le GUID de l'app ressemble à une clé pour gitleaks (refusé dans le dépôt) : secret en prod.
CLIENT_ID_SECRET = "defender_client_id"  # noqa: S105 - nom du secret, pas sa valeur
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
LOGIN_URL = "https://login.microsoftonline.com"
GRAPH_URL = "https://graph.microsoft.com"
MDE_SCOPE = "https://api.securitycenter.microsoft.com/.default"  # audience exigée par l'API
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
MDE_HOSTS = (
    "api.security.microsoft.com",
    "eu.api.security.microsoft.com",
    "uk.api.security.microsoft.com",
    "us.api.security.microsoft.com",
)
MDE_PAGE = 8000  # $top maximal de /api/vulnerabilities (10 000 pour les autres)
GRAPH_PAGE = 50
MAX_ROWS = 100_000  # garde-fou mémoire (appareil × CVE)
TITLE_MAX = 300
DETAILS_MAX = 1000
LISTED = 10
SEVERITIES = "severity eq 'Critical' or severity eq 'High'"
# /api/vulnerabilities renvoie tout le catalogue (≈ 100 000 CVE, capture 2026-10-11) : seules
# celles présentes dans le tenant (statut ≠ NoActionRequired) sont demandées. Filtre sur le statut
# vérifié sur l'API réelle (`exposedMachines` n'est pas filtrable : HTTP 400).
VULN_FILTER = (
    "(severity eq 'Critical' or severity eq 'High') and "
    "(status eq 'RemediationRequired' or status eq 'PartialException')"
)
# Graph n'a pas de gravité « critical » pour les incidents (low, medium, high, informational) :
# « élevée ou critique » = high.
INCIDENT_FILTER = "status ne 'resolved' and severity eq 'high'"
INCIDENT_FIELDS = (
    "id",
    "displayName",
    "severity",
    "status",
    "classification",
    "determination",
    "createdDateTime",
    "lastUpdateDateTime",
    "incidentWebUrl",
    "priorityScore",
)  # fmt: skip  — jamais assignedTo, description, comments, alerts (données personnelles)
INACTIVE_STATUSES = frozenset({"Inactive", "NoSensorData", "ImpairedCommunication"})

# --- Allowlist (CONNECTORS.md §9) -------------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TokenRequest(_Strict):
    """Jeton client credentials par assertion de certificat, pour l'une des deux audiences."""

    client_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    client_assertion_type: Literal["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]
    client_assertion: SecretStr
    scope: Literal[
        "https://api.securitycenter.microsoft.com/.default", "https://graph.microsoft.com/.default"
    ]
    grant_type: Literal["client_credentials"]


ODATA = frozenset({"$filter", "$top", "$skip"})


def login_allowlist(tenant_id: str) -> tuple[AllowedCall, ...]:
    return (
        AllowedCall(
            method="POST",
            path=rf"^/{tenant_id}/oauth2/v2\.0/token$",
            body_schema=TokenRequest,
            body_format="form",
            anonymous=True,
            reason="jeton Entra (client credentials, certificat) : authentification seule",
        ),
    )


MDE_ALLOWLIST: tuple[AllowedCall, ...] = (
    AllowedCall(method="GET", path=r"^/api/vulnerabilities$", query=ODATA),
    AllowedCall(method="GET", path=r"^/api/vulnerabilities/machinesVulnerabilities$", query=ODATA),
    AllowedCall(method="GET", path=r"^/api/machines$", query=ODATA),
)
GRAPH_ALLOWLIST: tuple[AllowedCall, ...] = (
    AllowedCall(method="GET", path=r"^/v1\.0/security/incidents$", query=ODATA | {"$skiptoken"}),
)
# Pour les tests génériques des connecteurs enregistrés (une seule liste par connecteur).
ALLOWLIST: tuple[AllowedCall, ...] = MDE_ALLOWLIST + GRAPH_ALLOWLIST

# --- Configuration ----------------------------------------------------------------------


class DefenderConfig(_Strict):
    enabled: bool = False
    interval_min: int = Field(60, ge=15, le=1440)
    tenant_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    client_id: str | None = Field(None, pattern=r"^[0-9a-f-]{36}$")  # sinon secret
    api_host: str = Field("eu.api.security.microsoft.com")
    certificate: Path  # certificat public (PEM)
    private_key_file: Path | None = None  # dev seulement ; prod : secret defender_private_key
    os_platform_prefixes: list[str] = Field(default_factory=lambda: ["Windows"], max_length=10)
    inactive_days: int = Field(14, ge=1, le=180)
    new_days: int = Field(14, ge=1, le=90)
    max_vulns_per_company: int = Field(10, ge=1, le=100)
    min_epss: float = Field(0.1, ge=0, le=1)
    proxy: str | None = Field(None, pattern=LOCAL_PROXY_RE)

    @field_validator("certificate", "private_key_file")
    @classmethod
    def _expand(cls, value: Path | None) -> Path | None:
        return value.expanduser() if value is not None else None  # « ~/vigie-ca/… » en dev

    def model_post_init(self, _context: Any) -> None:
        if self.api_host not in MDE_HOSTS:
            raise ValueError(f"api_host : un de {', '.join(MDE_HOSTS)}")


# --- Certificat et assertion -------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def client_assertion(
    cert_pem: bytes, key_pem: bytes, tenant_id: str, client_id: str, now: datetime
) -> str:
    """Assertion JWT PS256 (doc Entra « certificate credentials »)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    cert = x509.load_pem_x509_certificate(cert_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("clé privée RSA attendue")
    header = {
        "alg": "PS256",
        "typ": "JWT",
        "x5t#S256": _b64url(cert.fingerprint(hashes.SHA256())),
    }
    issued = int(now.timestamp())
    claims = {
        "aud": f"{LOGIN_URL}/{tenant_id}/oauth2/v2.0/token",
        "iss": client_id,
        "sub": client_id,
        "jti": str(uuid.uuid4()),
        "nbf": issued,
        "iat": issued,
        "exp": issued + 300,
    }
    signing_input = ".".join(
        _b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims)
    )
    signature = key.sign(
        signing_input.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )
    return f"{signing_input}.{_b64url(signature)}"


# --- Connecteur -------------------------------------------------------------------------


def _dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _sensitive(machine: Mapping[str, Any]) -> bool:
    return (
        str(machine.get("deviceValue", "")).lower() == "high"
        or "server" in str(machine.get("osPlatform", "")).lower()
    )


def _domain(machine: Mapping[str, Any]) -> str:
    """Domaine DNS de l'appareil : seul critère de société fiable dans ce tenant (aucun groupe
    d'appareils ni étiquette, capture 2026-10-11)."""
    return str(machine.get("computerDnsName") or "").lower().partition(".")[2]


def _group_key(machine: Mapping[str, Any]) -> str:
    """Regroupement (≈ société) sans la table de correspondance : la première étiquette
    Defender si l'appareil en a (départage un domaine partagé), sinon le domaine DNS."""
    tags = machine.get("machineTags") or []
    return f"tag:{tags[0]}" if tags else _domain(machine)


def _num(value: float) -> str:
    return f"{value:g}".replace(".", ",")


@dataclass
class CveGroup:
    """Une CVE dans une société : appareils touchés et informations de la vulnérabilité."""

    cve: Mapping[str, Any]
    company: str | None
    machines: dict[str, Mapping[str, Any]] = field(default_factory=dict)
    fix_kbs: set[str] = field(default_factory=set)
    products: set[str] = field(default_factory=set)

    @property
    def exploited(self) -> bool:
        return bool(self.cve.get("exploitVerified") or self.cve.get("exploitInKit"))

    @property
    def public_exploit(self) -> bool:
        return bool(self.cve.get("publicExploit")) or self.exploited

    @property
    def high_value(self) -> bool:
        """Équipement sensible : « valeur élevée » dans Defender, ou serveur."""
        return any(_sensitive(m) for m in self.machines.values())

    def is_new(self, now: datetime, new_days: int) -> bool:
        first = _dt(self.cve.get("firstDetected"))
        return first is not None and now - first <= timedelta(days=new_days)

    def selected(self, now: datetime, new_days: int, min_epss: float) -> bool:
        """Retenue si exploitée, sur équipement sensible, ou critique à EPSS élevé ou nouvelle."""
        critical = str(self.cve.get("severity")) == "Critical"
        epss = float(self.cve.get("epss") or 0)
        return (
            self.public_exploit
            or self.high_value
            or (critical and (epss >= min_epss or self.is_new(now, new_days)))
        )

    def criticity(self, now: datetime, new_days: int) -> float:
        """Score de tri : vulnérabilité, exploitation, sensibilité et étendue."""
        cvss = float(self.cve.get("cvssV3") or 0)
        epss = float(self.cve.get("epss") or 0)
        new = self.is_new(now, new_days)
        return (
            cvss
            + 4 * self.exploited
            + 2 * self.public_exploit
            + 3 * epss
            + 2 * self.high_value
            + 1 * new
            + math.log2(1 + len(self.machines))
        )


class DefenderConnector:
    name = SOURCE
    allowlist = ALLOWLIST

    def __init__(
        self,
        config: DefenderConfig,
        clients: Mapping[str, SafeClient],
        private_key: Callable[[], bytes],
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.config = config
        self.login = clients["login"]
        self.mde = clients["mde"]
        self.graph = clients["graph"]
        self._private_key = private_key
        self._now = now
        self._tokens: set[str] = set()
        self.truncated = False

    @classmethod
    def from_context(cls, ctx: ConnectorContext) -> DefenderConnector:
        try:
            config = DefenderConfig.model_validate(dict(ctx.settings))
        except (ValidationError, ValueError) as exc:
            fields = (
                sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
                if isinstance(exc, ValidationError)
                else [str(exc)]
            )
            raise ConnectorConfigError(
                f"[sources.defender] invalide : {', '.join(fields)}"
            ) from None

        if config.client_id is None:
            client_id = ctx.secret(CLIENT_ID_SECRET).get_secret_value().strip().lower()
            if not GUID.match(client_id):
                raise ConnectorConfigError(f"secret {CLIENT_ID_SECRET} : GUID attendu")
            config = config.model_copy(update={"client_id": client_id})

        def client(base: str, allowlist: Sequence[AllowedCall]) -> SafeClient:
            return SafeClient(
                source=SOURCE,
                base_url=base,
                allowlist=allowlist,
                ca_bundle=ctx.ca_bundle,
                proxy=config.proxy,
                transport=ctx.transport,
            )

        def private_key() -> bytes:
            if config.private_key_file is not None:  # dev : fichier local, jamais affiché
                return config.private_key_file.read_bytes()
            return ctx.secret(PRIVATE_KEY_SECRET).get_secret_value().replace("\\n", "\n").encode()

        clients = {
            "login": client(LOGIN_URL, login_allowlist(config.tenant_id)),
            "mde": client(f"https://{config.api_host}", MDE_ALLOWLIST),
            "graph": client(GRAPH_URL, GRAPH_ALLOWLIST),
        }
        return cls(config, clients, private_key)

    # --- Authentification ------------------------------------------------------------

    def _token(self, client: SafeClient, scope: str) -> None:
        if scope in self._tokens:
            return
        try:
            assertion = client_assertion(
                self.config.certificate.read_bytes(),
                self._private_key(),
                self.config.tenant_id,
                self.config.client_id or "",
                self._now(),
            )
        except (OSError, ValueError) as exc:
            # Message sans contenu : jamais la clé ni le chemin complet du secret.
            raise SourceCallError(
                f"{SOURCE} : certificat ou clé illisible ({type(exc).__name__})"
            ) from None
        data = self.login.post(
            f"/{self.config.tenant_id}/oauth2/v2.0/token",
            {
                "client_id": self.config.client_id or "",
                "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": SecretStr(assertion),
                "scope": scope,
                "grant_type": "client_credentials",
            },
        )
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise SourceCallError(f"{SOURCE} : réponse de jeton sans access_token")
        client.set_auth_header("Authorization", SecretStr(f"Bearer {token}"))
        self._tokens.add(scope)

    def _login(self) -> None:
        """Les deux jetons (capture des fixtures : sondage de chaque lecture)."""
        self._token(self.mde, MDE_SCOPE)
        self._token(self.graph, GRAPH_SCOPE)

    def _mde_rows(self, path: str, odata_filter: str | None, page: int) -> Iterator[Any]:
        self._token(self.mde, MDE_SCOPE)
        skip = 0
        while True:
            params: dict[str, Any] = {"$top": page, "$skip": skip}
            if odata_filter:
                params["$filter"] = odata_filter
            data = self.mde.get(path, params)
            rows = data.get("value", []) if isinstance(data, dict) else []
            if not isinstance(rows, list):
                raise SourceCallError(f"{SOURCE} : réponse inattendue ({path})")
            for row in rows:
                if skip >= MAX_ROWS:
                    self.truncated = True
                    return
                skip += 1
                yield row
            if len(rows) < page:
                return

    def _incidents(self) -> Iterator[Mapping[str, Any]]:
        self._token(self.graph, GRAPH_SCOPE)
        params: dict[str, Any] = {"$filter": INCIDENT_FILTER, "$top": GRAPH_PAGE}
        seen = 0
        while True:
            data = self.graph.get("/v1.0/security/incidents", params)
            rows = data.get("value", []) if isinstance(data, dict) else []
            for row in rows if isinstance(rows, list) else []:
                if isinstance(row, dict):
                    seen += 1
                    # $select n'est pas pris en charge : champs réduits dès réception.
                    yield {k: row[k] for k in INCIDENT_FIELDS if k in row}
            next_link = data.get("@odata.nextLink") if isinstance(data, dict) else None
            if not next_link or seen >= MAX_ROWS:
                return
            host, path, query = split_link(str(next_link))
            if host != "graph.microsoft.com" or path != "/v1.0/security/incidents":
                raise SourceCallError(f"{SOURCE} : lien de pagination inattendu")
            params = dict(query)  # $skiptoken… revérifiés par l'allowlist

    # --- Santé -------------------------------------------------------------------------

    def healthcheck(self) -> HealthStatus:
        started = time.monotonic()
        try:
            self._token(self.mde, MDE_SCOPE)
            self.mde.get("/api/machines", {"$top": 1})
            self._token(self.graph, GRAPH_SCOPE)
            self.graph.get("/v1.0/security/incidents", {"$top": 1})
        except SourceCallError as exc:
            return HealthStatus(ok=False, detail=str(exc))
        latency = round((time.monotonic() - started) * 1000, 1)
        days = self._cert_days()
        detail = (
            f"certificat : {days} j restants" if days is not None and days < CERT_WARN_DAYS else ""
        )
        return HealthStatus(
            ok=True, detail=detail, version="MDE API + Graph v1.0", latency_ms=latency
        )

    def _cert_days(self) -> int | None:
        try:
            return certificate_days_left(self.config.certificate, self._now())
        except (OSError, ValueError):
            return None

    # --- Collecte ----------------------------------------------------------------------

    def collect(self, since: datetime) -> Iterable[RawSignal]:
        now = self._now()
        self.truncated = False
        out: list[RawSignal] = []
        days = self._cert_days()
        if days is not None and days < CERT_WARN_DAYS:
            out.append(RawSignal("certificate", {"kind": "cert_expiry", "days": days, "at": now}))
        machines = {
            str(m["id"]): m
            for m in self._mde_rows("/api/machines", None, 10_000)
            if isinstance(m, dict) and m.get("id")
        }
        out.extend(self._inactive_signals(machines, now))
        out.extend(self._vulnerability_signals(machines, now))
        out.extend(
            RawSignal(f"incident:{inc.get('id')}", {"kind": "incident", "incident": inc, "at": now})
            for inc in self._incidents()
            if inc.get("id") is not None
        )
        return sorted(out, key=lambda r: r.external_id)

    def _windows(self, machine: Mapping[str, Any]) -> bool:
        platform = str(machine.get("osPlatform", ""))
        return any(platform.startswith(p) for p in self.config.os_platform_prefixes)

    def _inactive_signals(
        self, machines: Mapping[str, Mapping[str, Any]], now: datetime
    ) -> list[RawSignal]:
        limit = now - timedelta(days=self.config.inactive_days)
        stale = [
            m
            for m in machines.values()
            if str(m.get("healthStatus", "")) in INACTIVE_STATUSES
            and (seen := _dt(m.get("lastSeen"))) is not None
            and seen < limit
            and str(m.get("onboardingStatus", "Onboarded")) == "Onboarded"
        ]
        by_group: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for m in stale:
            by_group[_group_key(m)].append(m)
        return [
            RawSignal(
                f"inactive:{hashlib.sha1(group.encode(), usedforsecurity=False).hexdigest()[:12]}",
                {"kind": "inactive", "machines": items, "group": group, "at": now},
            )
            for group, items in by_group.items()
        ]

    def _vulnerability_signals(
        self, machines: Mapping[str, Mapping[str, Any]], now: datetime
    ) -> list[RawSignal]:
        cves = {
            str(v["id"]): v
            for v in self._mde_rows("/api/vulnerabilities", VULN_FILTER, MDE_PAGE)
            if isinstance(v, dict)
            and v.get("id")
            and v.get("status", "RemediationRequired")
            in ("RemediationRequired", "PartialException")
        }
        # Société calculée à la normalisation : ici on groupe par appareil d'abord.
        groups: dict[tuple[str, str], CveGroup] = {}
        for row in self._mde_rows(
            "/api/vulnerabilities/machinesVulnerabilities", SEVERITIES, 10_000
        ):
            if not isinstance(row, dict):
                continue
            cve = cves.get(str(row.get("cveId")))
            machine = machines.get(str(row.get("machineId")))
            if cve is None or machine is None or not self._windows(machine):
                continue
            key = (str(row.get("cveId")), _group_key(machine))
            group = groups.setdefault(key, CveGroup(cve=cve, company=None))
            group.machines[str(machine["id"])] = machine
            if row.get("fixingKbId"):
                group.fix_kbs.add(str(row["fixingKbId"]))
            if row.get("productName"):
                group.products.add(str(row["productName"]))
        # Analyse de criticité : seules les vulnérabilités qui comptent, au plus
        # max_vulns_per_company par domaine DNS ou étiquette (≈ société), plus critiques d'abord.
        cfg = self.config
        by_group: dict[str, list[tuple[str, CveGroup]]] = defaultdict(list)
        for (cve_id, grp), g in groups.items():
            if g.selected(now, cfg.new_days, cfg.min_epss):
                by_group[grp].append((cve_id, g))
        out: list[RawSignal] = []
        for grp, items in by_group.items():
            items.sort(key=lambda item: -item[1].criticity(now, cfg.new_days))
            digest = hashlib.sha1(grp.encode(), usedforsecurity=False).hexdigest()[:8]
            out.extend(
                RawSignal(
                    f"cve:{cve_id}:{digest}",
                    {"kind": "vulnerability", "group": g, "domain": grp, "at": now},
                )
                for cve_id, g in items[: cfg.max_vulns_per_company]
            )
        return out

    # --- Normalisation -----------------------------------------------------------------

    def _company(self, mapping: CompanyMapper, machine: Mapping[str, Any]) -> str | None:
        """Étiquette Defender (ex. « FWD », pour départager un domaine partagé), groupe
        d'appareils, domaine DNS (`hostgroup_suffix` sur le nom complet), préfixe du nom."""
        fqdn = str(machine.get("computerDnsName") or "")
        candidates = [(MatchType.agent_group, str(t)) for t in machine.get("machineTags") or []]
        candidates += [
            (MatchType.hostgroup_prefix, str(machine.get("rbacGroupName") or "")),
            (MatchType.hostgroup_suffix, fqdn),
            (MatchType.devname_prefix, fqdn.split(".")[0]),
        ]
        for match, value in candidates:
            if value and (company := mapping.company_for(SOURCE, match, value)) is not None:
                return company
        return None

    def to_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        kind = raw.payload["kind"]
        if kind == "vulnerability":
            return self._vuln_signal(raw, mapping)
        if kind == "incident":
            return self._incident_signal(raw)
        if kind == "inactive":
            return self._inactive_signal(raw, mapping)
        return self._cert_signal(raw)

    def _vuln_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        g: CveGroup = p["group"]
        now: datetime = p["at"]
        companies = {self._company(mapping, m) for m in g.machines.values()}
        company = next(iter(companies)) if len(companies) == 1 else None
        cve_id = str(g.cve.get("id"))
        cvss = float(g.cve.get("cvssV3") or 0)
        epss = float(g.cve.get("epss") or 0)
        severity_name = str(g.cve.get("severity", ""))
        first = _dt(g.cve.get("firstDetected"))
        new = g.is_new(now, self.config.new_days)
        critical = severity_name == "Critical"
        severity = 4 if critical else 3
        if g.exploited and (g.high_value or critical):
            severity = 5
        names = sorted(
            clean_untrusted(str(m.get("computerDnsName") or "").split(".")[0], 60)
            for m in g.machines.values()
        )
        exploit = (
            "exploitée (vérifiée ou en kit)"
            if g.exploited
            else "exploit public connu"
            if g.public_exploit
            else "pas d'exploit connu"
        )
        lines = [
            f"{cve_id} — {severity_name}, CVSS {_num(cvss)}, EPSS {_num(round(epss, 3))}",
            f"Exploitation : {exploit}",
            f"Appareils touchés : {len(g.machines)}"
            + (" (dont équipements sensibles)" if g.high_value else ""),
            "Exemples : " + ", ".join(names[:LISTED]),
        ]
        if g.products:
            lines.append("Logiciels : " + ", ".join(sorted(g.products)[:5]))
        lines.append(
            "Correctif : " + (", ".join(f"KB{k}" for k in sorted(g.fix_kbs)[:5]) if g.fix_kbs
                              else "pas de KB (mise à jour du logiciel)")
        )  # fmt: skip
        if first is not None:
            lines.append(f"Détectée le {first:%d/%m/%Y}" + (" (nouvelle)" if new else ""))
        tag = " [exploitée]" if g.exploited else ""
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=company,
            asset=f"{len(g.machines)} appareil(s)",
            category=Category.vulnerability,
            severity=severity,
            title=clean_untrusted(
                f"{cve_id}{tag} sur {len(g.machines)} appareil(s) — CVSS {_num(cvss)}", TITLE_MAX
            ),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=first or now,
            last_seen=now,
            url_template_params={"cve": cve_id},
            attributes={
                "kind": "vulnerability",
                "cve": cve_id,
                "cvss": cvss,
                "epss": epss,
                "exploited": g.exploited,
                "public_exploit": g.public_exploit,
                "high_value": g.high_value,
                "devices": len(g.machines),
                "fix_available": bool(g.fix_kbs),
                "new": new,
                "criticity": round(g.criticity(now, self.config.new_days), 2),
            },
        )

    def _incident_signal(self, raw: RawSignal) -> Signal:
        p = raw.payload
        inc: Mapping[str, Any] = p["incident"]
        severity = 5 if str(inc.get("severity", "")).lower() == "high" else 3
        title = clean_untrusted(str(inc.get("displayName", "")), 200)
        lines = [
            f"Incident Defender n° {inc.get('id')} — gravité {inc.get('severity')}",
            f"Statut : {inc.get('status')}",
        ]
        if inc.get("determination") and inc.get("determination") != "unknown":
            lines.append(f"Détermination : {inc.get('determination')}")
        created = _dt(inc.get("createdDateTime")) or p["at"]
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=None,  # un incident peut toucher plusieurs sociétés
            asset=f"Incident Defender n° {inc.get('id')}",
            category=Category.security,
            severity=severity,
            title=clean_untrusted(f"Incident Defender : {title}", TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=created,
            last_seen=_dt(inc.get("lastUpdateDateTime")) or p["at"],
            url_template_params={"incident_id": str(inc.get("id"))},
            attributes={"kind": "incident", "incident_severity": str(inc.get("severity"))},
        )

    def _inactive_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        machines: Sequence[Mapping[str, Any]] = p["machines"]
        companies = {self._company(mapping, m) for m in machines}
        names = sorted(
            clean_untrusted(str(m.get("computerDnsName") or "").split(".")[0], 60) for m in machines
        )
        oldest = min(
            (_dt(m.get("lastSeen")) for m in machines), default=None, key=lambda d: d or p["at"]
        )
        lines = [
            f"Appareils inactifs ou sans capteur depuis plus de {self.config.inactive_days} "
            f"jours : {len(machines)}",
            "Exemples : " + ", ".join(names[:LISTED]),
        ]
        if p["group"]:
            lines.append(f"Domaine ou étiquette : {clean_untrusted(p['group'], 100)}")
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=next(iter(companies)) if len(companies) == 1 else None,
            asset=clean_untrusted(p["group"] or "Defender", 200),
            category=Category.monitoring,
            severity=2,
            title=clean_untrusted(
                f"{len(machines)} appareil(s) sans remontée Defender depuis plus de "
                f"{self.config.inactive_days} j",
                TITLE_MAX,
            ),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=oldest or p["at"],
            last_seen=p["at"],
            attributes={"kind": "inactive", "count": len(machines)},
        )

    def _cert_signal(self, raw: RawSignal) -> Signal:
        p = raw.payload
        days = p["days"]
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=None,
            asset="Application Entra « Vigie Defender »",
            category=Category.monitoring,
            severity=4 if days < 7 else 3,
            title=f"Certificat de l'application Vigie Defender : expire dans {days} jour(s)",
            details="Renouveler le certificat (deploy/README.md, source Defender).",
            first_seen=p["at"],
            last_seen=p["at"],
            # Overrides cert_7d / cert_21d du barème.
            attributes={"kind": "cert_expiry", "days_left": days},
        )
