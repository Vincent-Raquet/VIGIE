"""Defender : lectures prévues et jeton seulement ; aucune action de réponse (SECURITY.md C2)."""

import base64
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from pydantic import SecretStr

from tests.security.helpers import BASE_URL, Recorder, assert_forbidden, trapped_client
from vigie.connectors.base import SafeClient
from vigie.connectors.defender import (
    GRAPH_ALLOWLIST,
    MDE_ALLOWLIST,
    client_assertion,
    login_allowlist,
)

TENANT = "00000000-0000-0000-0000-000000000000"
CLIENT = "11111111-1111-1111-1111-111111111111"
MACHINE = "/api/machines/1e5bc9d7e413ddd7902c2932e418702b84d0cc07"


def keypair() -> tuple[bytes, bytes, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vigie-test")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    pem_cert = cert.public_bytes(serialization.Encoding.PEM)
    pem_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return pem_cert, pem_key, key


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", f"{MACHINE}/isolate"),
        ("POST", f"{MACHINE}/unisolate"),
        ("POST", f"{MACHINE}/runAntiVirusScan"),
        ("POST", f"{MACHINE}/restrictCodeExecution"),
        ("POST", f"{MACHINE}/collectInvestigationPackage"),
        ("POST", f"{MACHINE}/offboard"),
        ("POST", "/api/indicators"),
        ("POST", "/api/alerts/da637/comments"),
        ("POST", "/api/advancedqueries/run"),
        ("GET", MACHINE),
        ("GET", f"{MACHINE}/logonusers"),
        ("GET", "/api/alerts"),
        ("GET", "/api/files/abc/stats"),
        ("GET", "/api/vulnerabilities/CVE-2024-1/machineReferences"),
    ],
)
def test_response_actions_and_unlisted_mde_paths_are_refused(method: str, path: str) -> None:
    client = trapped_client(MDE_ALLOWLIST, source="defender")
    if method == "POST":
        assert_forbidden(lambda: client.post(path, {}))
    else:
        assert_forbidden(lambda: client.get(path))


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/v1.0/security/incidents/29/comments"),
        ("POST", "/v1.0/security/runHuntingQuery"),
        ("GET", "/v1.0/security/alerts_v2"),
        ("GET", "/v1.0/users"),
        ("GET", "/v1.0/security/incidents/29"),
    ],
)
def test_graph_writes_and_unlisted_paths_are_refused(method: str, path: str) -> None:
    client = trapped_client(GRAPH_ALLOWLIST, source="defender")
    if method == "POST":
        assert_forbidden(lambda: client.post(path, {}))
    else:
        assert_forbidden(lambda: client.get(path))


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("PATCH", "/v1.0/security/incidents/29"),
        ("PATCH", "/api/alerts/da637"),
        ("DELETE", "/api/indicators/1"),
    ],
)
def test_updates_of_incidents_alerts_indicators_are_refused(method: str, path: str) -> None:
    for allowlist in (MDE_ALLOWLIST, GRAPH_ALLOWLIST):
        client = trapped_client(allowlist, source="defender")
        assert_forbidden(lambda client=client: client._authorize_rest(method, path, None))


@pytest.mark.parametrize(
    "params",
    [{"$expand": "alerts"}, {"$select": "assignedTo"}, {"$orderby": "id"}, {"api-version": "x"}],
)
def test_unlisted_odata_parameters_are_refused(params: dict[str, Any]) -> None:
    client = trapped_client(GRAPH_ALLOWLIST, source="defender")
    assert_forbidden(lambda: client.get("/v1.0/security/incidents", params))


def _token_body(**over: Any) -> dict[str, Any]:
    return {
        "client_id": CLIENT,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": SecretStr("eyJ.x.y"),
        "scope": "https://api.securitycenter.microsoft.com/.default",
        "grant_type": "client_credentials",
        **over,
    }


@pytest.mark.parametrize(
    "body",
    [
        _token_body(scope="https://management.azure.com/.default"),
        _token_body(scope="https://graph.microsoft.com/User.ReadWrite.All"),
        _token_body(grant_type="password"),
        _token_body(client_secret="x"),
    ],
)
def test_token_request_is_strict(body: dict[str, Any]) -> None:
    client = trapped_client(login_allowlist(TENANT), source="defender")
    assert_forbidden(lambda: client.post(f"/{TENANT}/oauth2/v2.0/token", body))


def test_token_for_another_tenant_is_refused() -> None:
    client = trapped_client(login_allowlist(TENANT), source="defender")
    assert_forbidden(lambda: client.post("/common/oauth2/v2.0/token", _token_body()))


def test_assertion_is_a_valid_ps256_jwt_and_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    cert_pem, key_pem, key = keypair()
    now = datetime.now(UTC)
    jwt = client_assertion(cert_pem, key_pem, TENANT, CLIENT, now)
    head_b64, claims_b64, sig_b64 = jwt.split(".")

    def dec(part: str) -> bytes:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))

    header, claims = json.loads(dec(head_b64)), json.loads(dec(claims_b64))
    cert = x509.load_pem_x509_certificate(cert_pem)
    assert header["alg"] == "PS256" and header["typ"] == "JWT"
    thumb = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).rstrip(b"=").decode()
    assert header["x5t#S256"] == thumb
    assert claims["aud"] == f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    assert claims["iss"] == claims["sub"] == CLIENT and claims["exp"] - claims["nbf"] == 300
    key.public_key().verify(
        dec(sig_b64),
        f"{head_b64}.{claims_b64}".encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    recorder = Recorder(httpx.Response(200, json={"access_token": "t"}))
    client = SafeClient(
        source="defender",
        base_url=BASE_URL,
        allowlist=login_allowlist(TENANT),
        transport=recorder.transport(),
    )
    with caplog.at_level(logging.DEBUG):
        client.post(f"/{TENANT}/oauth2/v2.0/token", _token_body(client_assertion=SecretStr(jwt)))
    sent = parse_qs(recorder.requests[0].content.decode())
    assert sent["client_assertion"] == [jwt] and "Authorization" not in recorder.requests[0].headers
    assert jwt not in caplog.text and claims_b64 not in caplog.text
