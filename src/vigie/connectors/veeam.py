"""Connecteur Veeam Backup & Replication 13 (lecture seule, API REST). Voir CONNECTORS.md §5.

Collecte (instantané, toutes les 30 min) :
- état des jobs (`/api/v1/jobs/states`) complété par l'historique récent des sessions
  (`/api/v1/sessions`) : dernier succès, échecs consécutifs ;
- remplissage des dépôts (`/api/v1/backupInfrastructure/repositories/states`) ;
- détections de malware (`/api/v1/malwareDetection/events`).

Authentification : jeton OAuth2 « password » demandé à chaque collecte (seul POST autorisé).
Modèles de réponse : swagger officiel 1.1-rev0 (VBR 12.0) ; les écarts propres à 13.x sont
marqués `TODO verify` et seront confirmés par les captures réelles (scripts/record_fixtures.py).
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
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
from vigie.mapping import companies_for, max_criticality
from vigie.redact import clean_untrusted

SOURCE = "veeam"
PASSWORD_SECRET = "veeam_password"  # noqa: S105 - nom du secret, pas sa valeur
SUPPORTED_MAJOR = "13"
PAGE_SIZE = 500
TITLE_MAX = 300
DETAILS_MAX = 1000
# Criticité d'actif (règle asset_rule job_prefix) à partir de laquelle un job est « critique »
# pour l'override backup_no_success_24h.
CRITICAL_ASSET = 1.2
REPO_WARN_PCT = 85.0
REPO_HIGH_PCT = 90.0
REPO_CRITICAL_PCT = 95.0
NO_SUCCESS_HOURS = 24.0
SUCCESS_RESULTS = frozenset({"Success", "Warning"})  # une sauvegarde a bien été produite
MALWARE_SEVERITIES = frozenset({"Suspicious", "Infected"})  # TODO verify : valeurs 13.x
# Sessions qui sont de vraies sauvegardes (capture réelle VBR 13, 2026-10-11). Les autres
# (découverte de volumes, test d'identifiants, analyse de conformité…) sont du bruit.
# TODO verify : type des sessions des jobs Proxmox, absentes de /sessions en 13.x (le job
# n'expose alors que lastResult dans jobs/states).
JOB_SESSION_TYPES = {
    "BackupJob": "Sauvegarde",
    "BackupCopyJob": "Copie de sauvegarde",
    "ReplicaJob": "Réplication",
    "ArchiveBackup": "Déport vers le stockage objet",
    "ConfigurationBackup": "Sauvegarde de la configuration VBR",
    "Retention": "Rétention",
}
# Suffixe d'exécution ajouté au nom de session (« REPLICATION - X (Full) »).
_RUN_SUFFIX = re.compile(
    r"\s*\((?:full|incremental|retry|active full|synthetic full|health check)\)\s*$", re.I
)
MAX_LISTED_OBJECTS = 10

# --- Allowlist (CONNECTORS.md §5) -------------------------------------------------------


class TokenRequest(BaseModel):
    """Jeton OAuth2, grant `password` uniquement (pas de refresh, pas de jeton VBR)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    grant_type: Literal["password"]
    username: str = Field(min_length=1, max_length=256)
    password: SecretStr


PAGED = frozenset({"skip", "limit"})
ALLOWLIST: tuple[AllowedCall, ...] = (
    AllowedCall(
        method="POST",
        path=r"^/api/oauth2/token$",
        body_schema=TokenRequest,
        body_format="form",
        anonymous=True,
        reason="jeton OAuth2 (grant password) : authentification seule, aucun effet sur VBR",
    ),
    AllowedCall(method="GET", path=r"^/api/v1/serverInfo$"),
    AllowedCall(method="GET", path=r"^/api/v1/jobs/states$", query=PAGED),
    AllowedCall(
        method="GET",
        path=r"^/api/v1/sessions$",
        query=PAGED | {"createdAfterFilter", "orderColumn", "orderAsc"},
    ),
    AllowedCall(
        method="GET", path=r"^/api/v1/backupInfrastructure/repositories/states$", query=PAGED
    ),
    AllowedCall(
        method="GET",
        path=r"^/api/v1/malwareDetection/events$",
        # TODO verify : nom du filtre de date en 13.x (absent du swagger 1.1-rev0).
        query=PAGED | {"detectedAfterTimeUtcFilter"},
    ),
)

# --- Configuration ----------------------------------------------------------------------


class VeeamConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    interval_min: int = Field(30, ge=5, le=1440)
    base_url: str = Field(pattern=r"^https://[^\s/?#]+(:[0-9]{1,5})?/?$")
    username: str = Field("svc-vigie", min_length=1, max_length=256)
    # x-api-version : 1.3-rev1 (13.0.1.180), 1.3-rev2 (13.1) ; relu dans /api/v1/serverInfo.
    api_version: str = Field("1.3-rev1", pattern=r"^[0-9]+\.[0-9]+-rev[0-9]+$")
    # Certificat (ou AC) du VBR : remplace le bundle global pour cette source seulement.
    ca_bundle: Path | None = None
    session_window_days: int = Field(7, ge=2, le=30)


# --- Historique des sessions -------------------------------------------------------------


def _result(session: Mapping[str, Any]) -> str:
    return str((session.get("result") or {}).get("result", "None"))


def _split_session_name(name: str) -> tuple[str, str]:
    """`job\\objet (Incremental)` → (`job`, `objet`) ; sessions par VM des copies."""
    job, _, obj = name.partition("\\")
    obj = re.sub(r"\s+backup$", "", _RUN_SUFFIX.sub("", obj).strip(), flags=re.I)
    return _RUN_SUFFIX.sub("", job).strip(), obj


def _leading(results: Sequence[str], value: str) -> int:
    count = 0
    for r in results:
        if r != value:
            break
        count += 1
    return count


@dataclass
class JobHistory:
    """Sessions terminées d'un job, par objet (VM), de la plus récente à la plus ancienne."""

    name: str
    session_type: str
    objects: dict[str, list[Mapping[str, Any]]] = field(default_factory=dict)

    def latest(self) -> dict[str, Mapping[str, Any]]:
        return {obj: items[0] for obj, items in self.objects.items() if items}

    def objects_with(self, result: str) -> list[str]:
        return sorted(o for o, s in self.latest().items() if _result(s) == result)

    def consecutive(self, result: str) -> int:
        return max(
            (_leading([_result(s) for s in items], result) for items in self.objects.values()),
            default=0,
        )

    def last_success(self) -> datetime | None:
        ends = [
            _dt(s.get("endTime"))
            for items in self.objects.values()
            for s in items
            if _result(s) in SUCCESS_RESULTS
        ]
        return max((e for e in ends if e is not None), default=None)

    def worst(self) -> str:
        results = {_result(s) for s in self.latest().values()}
        return next((r for r in ("Failed", "Warning", "Success") if r in results), "None")

    def message(self) -> str:
        """Message de la session la plus récente en échec (ou avertissement)."""
        for result in ("Failed", "Warning"):
            candidates = [s for s in self.latest().values() if _result(s) == result]
            if candidates:
                newest = max(candidates, key=lambda s: str(s.get("creationTime", "")))
                return str((newest.get("result") or {}).get("message", ""))
        return ""


# --- Connecteur -------------------------------------------------------------------------


def _dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _num(value: float) -> str:
    """Nombre lisible en français : 52,5 ; 8000."""
    return f"{value:g}".replace(".", ",")


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class VeeamConnector:
    name = SOURCE
    allowlist = ALLOWLIST

    def __init__(
        self,
        config: VeeamConfig,
        client: SafeClient,
        password: SecretStr,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.config = config
        self.client = client
        self._password = password
        self._now = now
        self._token_ok = False
        # Collecte tronquée : l'absence d'un signal ne prouve pas sa résolution.
        self.truncated = False

    @classmethod
    def from_context(cls, ctx: ConnectorContext) -> VeeamConnector:
        try:
            config = VeeamConfig.model_validate(dict(ctx.settings))
        except ValidationError as exc:
            fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
            raise ConnectorConfigError(f"[sources.veeam] invalide : {', '.join(fields)}") from None
        client = SafeClient(
            source=SOURCE,
            base_url=config.base_url,
            allowlist=ALLOWLIST,
            ca_bundle=config.ca_bundle or ctx.ca_bundle,
            transport=ctx.transport,
            headers={"x-api-version": config.api_version},
        )
        return cls(config, client, ctx.secret(PASSWORD_SECRET))

    # --- Authentification ------------------------------------------------------------

    def _login(self) -> None:
        if self._token_ok:
            return
        data = self.client.post(
            "/api/oauth2/token",
            {
                "grant_type": "password",
                "username": self.config.username,
                "password": self._password,
            },
        )
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise SourceCallError(f"{SOURCE} : réponse de jeton sans access_token")
        self.client.set_auth_header("Authorization", SecretStr(f"Bearer {token}"))
        self._token_ok = True

    def _pages(self, path: str, params: Mapping[str, Any] | None = None) -> Iterator[Any]:
        """Éléments `data` page par page, au plus MAX_OBJECTS (au-delà : `truncated`)."""
        self._login()
        skip = 0
        while True:
            page = self.client.get(path, {**(params or {}), "skip": skip, "limit": PAGE_SIZE})
            items = page.get("data", []) if isinstance(page, dict) else []
            if not isinstance(items, list):
                raise SourceCallError(f"{SOURCE} : réponse inattendue ({path})")
            for item in items:
                if skip >= MAX_OBJECTS:
                    self.truncated = True
                    return
                skip += 1
                yield item
            total = (page.get("pagination") or {}).get("total") if isinstance(page, dict) else None
            if not items or len(items) < PAGE_SIZE or (isinstance(total, int) and skip >= total):
                return

    # --- Santé -----------------------------------------------------------------------

    def healthcheck(self) -> HealthStatus:
        started = time.monotonic()
        try:
            self._login()
            info = self.client.get("/api/v1/serverInfo")
        except SourceCallError as exc:
            if exc.status != 403:
                return HealthStatus(ok=False, detail=str(exc))
            # Backup Viewer n'a pas accès à serverInfo (essai réel, VBR 13) : on valide
            # l'accès par la lecture des jobs, sans version.
            try:
                self.client.get("/api/v1/jobs/states", {"skip": 0, "limit": 1})
            except SourceCallError as inner:
                return HealthStatus(ok=False, detail=str(inner))
            latency = round((time.monotonic() - started) * 1000, 1)
            return HealthStatus(
                ok=True, detail="version inconnue (serverInfo refusé au rôle)", latency_ms=latency
            )
        version = str(info.get("buildVersion", "")) if isinstance(info, dict) else ""
        latency = round((time.monotonic() - started) * 1000, 1)
        detail = "" if version.split(".")[0] == SUPPORTED_MAJOR else "version non testée"
        return HealthStatus(ok=True, detail=detail, version=version, latency_ms=latency)

    # --- Collecte --------------------------------------------------------------------

    def collect(self, since: datetime) -> Iterable[RawSignal]:
        """Instantané : `since` est ignoré, chaque collecte relit l'état complet."""
        now = self._now()
        self.truncated = False
        history = self._job_history(now)
        seen: set[str] = set()
        out: list[RawSignal] = []
        for job in self._pages("/api/v1/jobs/states"):
            if not isinstance(job, dict) or str(job.get("status", "")).lower() == "disabled":
                continue
            key = str(job.get("name", "")).casefold()
            seen.add(key)
            payload = self._job_payload(
                job, str(job.get("lastResult", "None")), history.get(key), now
            )
            if payload is not None:
                out.append(RawSignal(f"job:{job.get('id')}", payload))
        # Jobs connus seulement par leurs sessions (réplications, déports…) : absents de
        # jobs/states en 13.x.
        for key, h in history.items():
            if key in seen:
                continue
            ref = {"name": h.name, "type": h.session_type}
            payload = self._job_payload(ref, h.worst(), h, now, stale_check=False)
            if payload is not None:
                digest = hashlib.sha1(key.encode(), usedforsecurity=False).hexdigest()[:16]
                out.append(RawSignal(f"session-job:{digest}", payload))
        for repo in self._pages("/api/v1/backupInfrastructure/repositories/states"):
            if not isinstance(repo, dict):
                continue
            if repo.get("isOnline") is False:
                out.append(
                    RawSignal(
                        f"repo:{repo.get('id')}:offline",
                        {"kind": "repository_offline", "repo": repo, "at": now},
                    )
                )
            capacity = float(repo.get("capacityGB") or 0)
            used = float(repo.get("usedSpaceGB") or 0)
            pct = round(used / capacity * 100, 1) if capacity > 0 else 0.0
            if pct > REPO_WARN_PCT:
                out.append(
                    RawSignal(
                        f"repo:{repo.get('id')}:capacity",
                        {"kind": "repository", "repo": repo, "used_pct": pct, "at": now},
                    )
                )
        after = _iso(now - timedelta(days=self.config.session_window_days))
        for event in self._pages(
            "/api/v1/malwareDetection/events", {"detectedAfterTimeUtcFilter": after}
        ):
            if isinstance(event, dict) and event.get("severity") in MALWARE_SEVERITIES:
                out.append(
                    RawSignal(
                        f"malware:{event.get('id')}", {"kind": "malware", "event": event, "at": now}
                    )
                )
        return sorted(out, key=lambda r: r.external_id)

    def _job_history(self, now: datetime) -> dict[str, JobHistory]:
        """Sessions de sauvegarde terminées, groupées par job (nom sans suffixe) et par objet.

        Capture réelle (VBR 13) : les copies produisent une session par VM nommée
        `<job>\\<VM> Backup (Incremental)` ; une réplication complète `<job> (Full)`.
        """
        after = _iso(now - timedelta(days=self.config.session_window_days))
        jobs: dict[str, JobHistory] = {}
        for s in self._pages(
            "/api/v1/sessions",
            {"createdAfterFilter": after, "orderColumn": "CreationTime", "orderAsc": "false"},
        ):
            if not isinstance(s, dict) or s.get("state") != "Stopped":
                continue
            session_type = str(s.get("sessionType", ""))
            if session_type not in JOB_SESSION_TYPES:
                continue
            job, obj = _split_session_name(str(s.get("name", "")))
            h = jobs.setdefault(job.casefold(), JobHistory(job, session_type))
            h.objects.setdefault(obj, []).append(s)
        for h in jobs.values():
            for items in h.objects.values():
                items.sort(
                    key=lambda s: _dt(s.get("endTime")) or _dt(s.get("creationTime")) or now,
                    reverse=True,
                )
        return jobs

    def _job_payload(
        self,
        job: Mapping[str, Any],
        last_result: str,
        history: JobHistory | None,
        now: datetime,
        *,
        stale_check: bool = True,
    ) -> dict[str, Any] | None:
        h = history or JobHistory(str(job.get("name", "")), "")
        last_success = h.last_success()
        if last_success is None and last_result in SUCCESS_RESULTS:
            last_success = _dt(job.get("lastRun"))  # historique vide : on se fie à l'état
        window_h = self.config.session_window_days * 24.0
        hours = (
            round((now - last_success).total_seconds() / 3600, 1)
            if last_success is not None
            else window_h  # aucun succès connu dans la fenêtre : au moins sa durée
        )
        # Sans lastRun (jobs Proxmox en 13.x), l'ancienneté n'est pas mesurable.
        stale = stale_check and hours > NO_SUCCESS_HOURS and _dt(job.get("lastRun")) is not None
        if last_result not in ("Failed", "Warning") and not stale:
            return None
        return {
            "kind": "job",
            "job": dict(job),
            "session_type": h.session_type,
            "last_result": last_result,
            "consecutive_failures": max(h.consecutive("Failed"), int(last_result == "Failed")),
            "consecutive_warnings": max(h.consecutive("Warning"), int(last_result == "Warning")),
            "failed_objects": [o for o in h.objects_with("Failed") if o][:MAX_LISTED_OBJECTS],
            "warning_objects": [o for o in h.objects_with("Warning") if o][:MAX_LISTED_OBJECTS],
            "hours_since_last_success": hours,
            "last_message": h.message(),
            "at": now,
        }

    # --- Normalisation ---------------------------------------------------------------

    def to_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        kind = raw.payload["kind"]
        if kind == "repository":
            return self._repo_signal(raw, mapping)
        if kind == "repository_offline":
            return self._repo_offline_signal(raw, mapping)
        if kind == "malware":
            return self._malware_signal(raw, mapping)
        return self._job_signal(raw, mapping)

    def _job_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        job: Mapping[str, Any] = p["job"]
        name = clean_untrusted(str(job.get("name", "")), 200)
        companies = companies_for(mapping, SOURCE, MatchType.job_prefix, [str(job.get("name", ""))])
        criticality = max_criticality(
            mapping, SOURCE, MatchType.job_prefix, [str(job.get("name", ""))]
        )
        critical = criticality is not None and criticality >= CRITICAL_ASSET
        result = p["last_result"]
        label = JOB_SESSION_TYPES.get(str(p.get("session_type", "")), "Job")
        if result == "Failed":
            # Une rétention en échec n'empêche pas les sauvegardes : elle remplit le stockage.
            severity = 3 if p.get("session_type") == "Retention" else 5 if critical else 4
            title = f"Veeam — {label} en échec : {name}"
        elif result == "Warning":
            severity = 3 if p["consecutive_warnings"] >= 2 else 2
            title = f"Veeam — {label} en avertissement : {name}"
        else:
            severity = 4 if critical else 3
            title = (
                f"Veeam — {label} sans succès depuis "
                f"{_num(p['hours_since_last_success'])} h : {name}"
            )
        lines = [
            f"Job : {name}",
            f"Dernier résultat : {result}",
            f"Dernier succès il y a : {_num(p['hours_since_last_success'])} h",
        ]
        if p["consecutive_failures"] >= 2:
            lines.append(f"Échecs consécutifs : {p['consecutive_failures']}")
        if p["consecutive_warnings"] >= 2:
            lines.append(f"Avertissements consécutifs : {p['consecutive_warnings']}")
        for key, text in (("failed_objects", "en échec"), ("warning_objects", "en avertissement")):
            if p.get(key):
                lines.append(f"Objets {text} : " + ", ".join(p[key]))
        if job.get("repositoryName"):
            lines.append(f"Dépôt : {job['repositoryName']}")
        if p.get("last_message"):
            lines.append(f"Message : {p['last_message']}")
        last_run = _dt(job.get("lastRun")) or p["at"]
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=next(iter(companies)) if len(companies) == 1 else None,
            asset=name,
            category=Category.backup,
            severity=severity,
            title=clean_untrusted(title, TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=last_run,
            last_seen=p["at"],
            url_template_params={"job_id": str(job.get("id", ""))},
            attributes={
                "kind": "job",
                "last_result": result,
                "consecutive_failures": p["consecutive_failures"],
                "hours_since_last_success": p["hours_since_last_success"],
                "asset_criticality": criticality,
                "asset_critical": critical,
            },
        )

    def _repo_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        repo: Mapping[str, Any] = p["repo"]
        name = clean_untrusted(str(repo.get("name", "")), 200)
        pct = p["used_pct"]
        companies = companies_for(
            mapping, SOURCE, MatchType.job_prefix, [str(repo.get("name", ""))]
        )
        severity = 4 if pct > REPO_CRITICAL_PCT else 3 if pct > REPO_HIGH_PCT else 2
        used, capacity, free = (
            float(repo.get(k) or 0) for k in ("usedSpaceGB", "capacityGB", "freeGB")
        )
        lines = [
            f"Dépôt : {name}",
            f"Occupation : {_num(pct)} % ({_num(used)} Go sur {_num(capacity)} Go, "
            f"{_num(free)} Go libres)",
        ]
        if repo.get("hostName"):
            lines.append(f"Serveur : {repo['hostName']}")
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=next(iter(companies)) if len(companies) == 1 else None,
            asset=clean_untrusted(str(repo.get("hostName") or repo.get("name", "")), 200),
            category=Category.backup,
            severity=severity,
            title=clean_untrusted(f"Dépôt Veeam rempli à {_num(pct)} % : {name}", TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=p["at"],
            last_seen=p["at"],
            url_template_params={"repository_id": str(repo.get("id", ""))},
            attributes={"kind": "repository", "repo_used_pct": pct},
        )

    def _repo_offline_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        repo: Mapping[str, Any] = p["repo"]
        name = clean_untrusted(str(repo.get("name", "")), 200)
        companies = companies_for(
            mapping, SOURCE, MatchType.job_prefix, [str(repo.get("name", ""))]
        )
        lines = [f"Dépôt : {name}", f"Type : {repo.get('type', '')}"]
        if repo.get("hostName"):
            lines.append(f"Serveur : {repo['hostName']}")
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=next(iter(companies)) if len(companies) == 1 else None,
            asset=clean_untrusted(str(repo.get("hostName") or repo.get("name", "")), 200),
            category=Category.backup,
            severity=4,
            title=clean_untrusted(f"Dépôt Veeam hors ligne : {name}", TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=p["at"],
            last_seen=p["at"],
            url_template_params={"repository_id": str(repo.get("id", ""))},
            attributes={"kind": "repository_offline"},
        )

    def _malware_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal:
        p = raw.payload
        event: Mapping[str, Any] = p["event"]
        raw_machine = event.get("machine")
        machine: Mapping[str, Any] = raw_machine if isinstance(raw_machine, dict) else {}
        host = clean_untrusted(str(machine.get("displayName", "")), 200)
        detected = _dt(event.get("detectionTimeUtc")) or p["at"]
        lines = [
            f"Machine : {host}",
            f"Gravité Veeam : {event.get('severity')}",
            f"Détection : {detected:%d/%m/%Y %H:%M} UTC",
        ]
        if event.get("details"):
            lines.append(f"Détails : {event['details']}")
        return Signal(
            source=SOURCE,
            external_id=raw.external_id,
            company_code=None,
            asset=host,
            category=Category.security,
            severity=5,
            title=clean_untrusted(f"Veeam : malware détecté sur {host}", TITLE_MAX),
            details=clean_untrusted("\n".join(lines), DETAILS_MAX),
            first_seen=detected,
            last_seen=p["at"],
            url_template_params={"event_id": str(event.get("id", ""))},
            attributes={"kind": "malware", "malware_severity": str(event.get("severity"))},
        )
