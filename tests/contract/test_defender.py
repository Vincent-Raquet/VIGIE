"""Defender : fixtures synthétiques (modèles de la documentation officielle) → signaux.

Le certificat et la clé sont générés pour le test (jamais ~/vigie-ca)."""

import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import SecretStr

from tests.conftest import REPO_ROOT
from vigie.connectors.base import (
    ConnectorConfigError,
    ConnectorContext,
    Signal,
    SourceCallError,
    fixture_transport,
)
from vigie.connectors.defender import DefenderConnector
from vigie.db.enums import Category
from vigie.mapping import RuleMapper

FIXTURES = Path(__file__).parent / "defender_synthetic"
NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
TENANT = "00000000-0000-0000-0000-000000000000"


@pytest.fixture(scope="module")
def mapper(tmp_path_factory: pytest.TempPathFactory) -> RuleMapper:
    d = tmp_path_factory.mktemp("seed")
    shutil.copy(REPO_ROOT / "config" / "companies.example.yaml", d)
    return RuleMapper.from_seed_dir(d)


def write_pair(directory: Path, days: int) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vigie-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=days, hours=1))
        .sign(key, hashes.SHA256())
    )
    crt, pem = directory / "defender.crt", directory / "defender.key"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return crt, pem


@pytest.fixture(scope="module")
def pair(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    return write_pair(tmp_path_factory.mktemp("cert"), 365)


class Spy(httpx.BaseTransport):
    def __init__(self, inner: httpx.BaseTransport) -> None:
        self.inner = inner
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.inner.handle_request(request)


def make(
    pair: tuple[Path, Path],
    transport: httpx.BaseTransport | None = None,
    secret_key: bool = False,
    **settings: Any,
) -> DefenderConnector:
    crt, pem = pair
    base: dict[str, Any] = {
        "tenant_id": TENANT,
        "client_id": "11111111-1111-1111-1111-111111111111",
        "certificate": str(crt),
    }
    if not secret_key:
        base["private_key_file"] = str(pem)

    def secret(name: str) -> SecretStr:
        assert name == "defender_private_key"
        return SecretStr(pem.read_text().replace("\n", "\\n"))

    ctx = ConnectorContext(
        settings={**base, **settings},
        secret=secret,
        transport=transport or fixture_transport(FIXTURES),
    )
    c = DefenderConnector.from_context(ctx)
    c._now = lambda: NOW
    return c


def signals(mapper: RuleMapper, c: DefenderConnector) -> dict[str, Signal]:
    return {s.external_id: s for s in (c.to_signal(r, mapper) for r in c.collect(NOW))}


def by_kind(sigs: dict[str, Signal], kind: str) -> list[Signal]:
    return [s for s in sigs.values() if s.attributes.get("kind") == kind]


def test_vulnerabilities_selected_by_criticity(mapper: RuleMapper, pair: tuple[Path, Path]) -> None:
    vulns = by_kind(signals(mapper, make(pair)), "vulnerability")
    got = {(s.attributes["cve"], s.company_code, s.attributes["devices"]) for s in vulns}
    assert got == {
        ("CVE-2026-0001", "WI", 2),  # exploitée : WI - Postes
        ("CVE-2026-0001", "WI", 1),  # WI - Serveurs (équipement sensible)
        ("CVE-2026-0001", "SPL", 2),
        ("CVE-2026-0001", None, 1),  # groupe sans règle : « Sans société »
        ("CVE-2026-0002", "SPL", 2),  # exploit public
        ("CVE-2026-0003", "WI", 1),  # critique et nouvelle
        ("CVE-2026-0004", "WI", 1),  # High, mais sur un serveur à valeur élevée
    }  # 0005 sans critère, 0006 Linux (Wazuh), 0007 en exception : écartées
    one = {(s.attributes["cve"], s.severity) for s in vulns}
    assert one == {
        ("CVE-2026-0001", 5),
        ("CVE-2026-0002", 3),
        ("CVE-2026-0003", 4),
        ("CVE-2026-0004", 3),
    }
    exploited = next(s for s in vulns if s.attributes["devices"] == 2 and s.company_code == "WI")
    assert exploited.category == Category.vulnerability
    assert exploited.title == "CVE-2026-0001 [exploitée] sur 2 appareil(s) — CVSS 9,8"
    assert exploited.attributes["exploited"] and exploited.attributes["fix_available"]
    assert "KB5050001" in exploited.details and "pc-wi-01, pc-wi-02" in exploited.details
    assert "Texte fourni" not in exploited.details  # description éditeur jamais reprise
    assert "192.0.2" not in exploited.details
    new = next(s for s in vulns if s.attributes["cve"] == "CVE-2026-0003")
    assert new.attributes["new"] and "(nouvelle)" in new.details


def test_cap_per_device_group_keeps_most_critical(
    mapper: RuleMapper, pair: tuple[Path, Path]
) -> None:
    vulns = by_kind(signals(mapper, make(pair, max_vulns_per_company=1)), "vulnerability")
    wi_postes = [s for s in vulns if s.company_code == "WI" and "pc-wi-01" in s.details]
    assert [s.attributes["cve"] for s in wi_postes] == ["CVE-2026-0001"]


def test_os_platform_policy_can_include_linux(mapper: RuleMapper, pair: tuple[Path, Path]) -> None:
    c = make(pair, os_platform_prefixes=["Windows", "Linux"])
    cves = {s.attributes["cve"] for s in by_kind(signals(mapper, c), "vulnerability")}
    assert "CVE-2026-0006" in cves


def test_inactive_devices_aggregated(mapper: RuleMapper, pair: tuple[Path, Path]) -> None:
    [inactive] = by_kind(signals(mapper, make(pair)), "inactive")
    assert (inactive.category, inactive.severity, inactive.company_code) == (
        Category.monitoring,
        2,
        "SPL",
    )
    assert inactive.attributes["count"] == 2
    assert "pc-spl-03, pc-spl-04" in inactive.details and "pc-spl-05" not in inactive.details


def test_incidents_minimised(mapper: RuleMapper, pair: tuple[Path, Path]) -> None:
    [inc] = by_kind(signals(mapper, make(pair)), "incident")
    assert (inc.category, inc.severity, inc.company_code) == (Category.security, 5, None)
    assert inc.title.startswith("Incident Defender : Multi-stage incident")
    text = inc.title + inc.details + str(inc.attributes)
    for leak in ("utilisateur@example.com", "note interne", "Admin", "script"):
        assert leak not in text


def test_requests_sent(pair: tuple[Path, Path]) -> None:
    spy = Spy(fixture_transport(FIXTURES))
    list(make(pair, transport=spy).collect(NOW))
    tokens = [r for r in spy.requests if r.method == "POST"]
    assert [r.url.host for r in tokens] == ["login.microsoftonline.com"] * 2  # une par audience
    scopes = {parse_qs(r.content.decode())["scope"][0] for r in tokens}
    assert scopes == {
        "https://api.securitycenter.microsoft.com/.default",
        "https://graph.microsoft.com/.default",
    }
    assert all("client_secret" not in r.content.decode() for r in tokens)
    gets = [r for r in spy.requests if r.method == "GET"]
    assert {r.url.host for r in gets} == {"eu.api.security.microsoft.com", "graph.microsoft.com"}
    assert all(r.headers["Authorization"] == "Bearer fixture-access-token" for r in gets)
    vuln = next(r for r in gets if r.url.path == "/api/vulnerabilities")
    assert vuln.url.params["$filter"] == "severity eq 'Critical' or severity eq 'High'"
    inc = next(r for r in gets if r.url.host == "graph.microsoft.com")
    assert inc.url.params["$filter"] == "status ne 'resolved' and severity eq 'high'"


def test_private_key_from_secret(mapper: RuleMapper, pair: tuple[Path, Path]) -> None:
    assert by_kind(signals(mapper, make(pair, secret_key=True)), "incident")


def test_certificate_expiry_signal_and_health(mapper: RuleMapper, tmp_path: Path) -> None:
    c = make(write_pair(tmp_path, 20))
    [cert] = by_kind(signals(mapper, c), "cert_expiry")
    assert (cert.severity, cert.attributes["days_left"], cert.category) == (
        3,
        20,
        Category.monitoring,
    )
    health = c.healthcheck()
    assert health.ok and health.detail == "certificat : 20 j restants"
    assert not by_kind(signals(mapper, make(write_pair(tmp_path, 200))), "cert_expiry")


def test_unreadable_key_fails_without_content(tmp_path: Path, pair: tuple[Path, Path]) -> None:
    bad = tmp_path / "bad.key"
    bad.write_text("c2VjcmV0LWRlLXRlc3Q=\n")  # pas une clé PEM
    c = make((pair[0], bad))
    with pytest.raises(SourceCallError) as err:
        list(c.collect(NOW))
    assert "c2VjcmV0" not in str(err.value) and "bad.key" not in str(err.value)
    assert not c.healthcheck().ok


def test_foreign_next_link_refused(pair: tuple[Path, Path]) -> None:
    inner = fixture_transport(FIXTURES)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "graph.microsoft.com":
            return httpx.Response(
                200, json={"value": [], "@odata.nextLink": "https://evil.example/v1.0/x"}
            )
        return inner.handle_request(request)

    with pytest.raises(SourceCallError, match="pagination"):
        list(make(pair, transport=httpx.MockTransport(handler))._incidents())


@pytest.mark.parametrize(
    "bad",
    [
        {"api_host": "evil.example"},
        {"tenant_id": "contoso.onmicrosoft.com"},
        {"proxy": "http://proxy.example:3128"},
        {"client_secret": "x"},
    ],
)
def test_invalid_config_rejected(pair: tuple[Path, Path], bad: dict[str, Any]) -> None:
    with pytest.raises(ConnectorConfigError):
        make(pair, **bad)


def test_default_overrides_raise_exploited_vulnerabilities(
    mapper: RuleMapper, pair: tuple[Path, Path]
) -> None:
    from vigie.engine.rules import strongest
    from vigie.engine.settings import DEFAULT_OVERRIDES

    def rule(s: Signal) -> str | None:
        facts = {"source": s.source, "category": s.category.value, "attributes": s.attributes}
        found = strongest(DEFAULT_OVERRIDES, facts)
        return found.id if found else None

    vulns = by_kind(signals(mapper, make(pair)), "vulnerability")
    by_rule = {(s.attributes["cve"], s.attributes["high_value"]): rule(s) for s in vulns}
    assert by_rule[("CVE-2026-0001", True)] == "vuln_exploited_sensitive"  # P1
    assert by_rule[("CVE-2026-0001", False)] == "vuln_exploited"  # P2
    assert by_rule[("CVE-2026-0002", False)] is None  # exploit public seul : barème


def test_graph_next_link_followed(pair: tuple[Path, Path]) -> None:
    inner = fixture_transport(FIXTURES)
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host != "graph.microsoft.com":
            return inner.handle_request(request)
        seen.append(dict(request.url.params.items()))
        if "$skiptoken" in request.url.params:
            return httpx.Response(200, json={"value": [{"id": "2", "assignedTo": "x@y"}]})
        return httpx.Response(
            200,
            json={
                "value": [{"id": "1"}],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/incidents"
                "?$top=50&$skiptoken=abc",
            },
        )

    rows = list(make(pair, transport=httpx.MockTransport(handler))._incidents())
    assert rows == [{"id": "1"}, {"id": "2"}] and seen[1] == {"$top": "50", "$skiptoken": "abc"}
