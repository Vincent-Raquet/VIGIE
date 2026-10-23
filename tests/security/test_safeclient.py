"""SafeClient : allowlist vérifiée avant l'envoi (SECURITY.md C2, C10)."""

import json
import re
import ssl
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import BaseModel, ConfigDict, Field, RootModel, SecretStr

from tests.security.helpers import BASE_URL, Recorder, assert_forbidden, trapped_client
from vigie.connectors.base import (
    CONNECT_TIMEOUT_S,
    MAX_RETRIES,
    READ_TIMEOUT_S,
    AllowedCall,
    AllowlistDefinitionError,
    SafeClient,
    Signal,
    SourceCallError,
    bounded,
    fixture_transport,
)
from vigie.db.enums import Category


class TokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    grant_type: str = Field(pattern="^password$")
    username: str


class ProblemGetParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recent: bool = False
    severities: list[int] = []


class FazGetItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(pattern=r"^/sys/status$")


class FazGetParams(RootModel[list[FazGetItem]]):
    pass


class Loose(BaseModel):
    pass


ALLOWLIST = [
    AllowedCall(method="GET", path=r"^/api/v1/jobs/states$", query={"limit", "skip"}),
    AllowedCall(method="GET", path=r"^/api/v1/jobs/[0-9a-f-]{36}$"),
    AllowedCall(
        method="POST",
        path=r"^/api/oauth2/token$",
        body_schema=TokenRequest,
        reason="authentification OAuth, sans effet sur la configuration",
    ),
    AllowedCall(jsonrpc="problem.get", endpoint="/api_jsonrpc.php", params_schema=ProblemGetParams),
]


def client(*responses: httpx.Response, **kwargs: Any) -> tuple[SafeClient, Recorder]:
    recorder = Recorder(*responses)
    sleeps: list[float] = kwargs.pop("sleeps", [])
    c = SafeClient(
        source="test",
        base_url=BASE_URL,
        allowlist=ALLOWLIST,
        transport=recorder.transport(),
        sleep=sleeps.append,
        **kwargs,
    )
    return c, recorder


# --- Refus avant émission ---------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/jobs/states/extra",
        "/api/v1/jobs",
        "/api/v1/jobs/1234/stop",
        "/api/v1/jobs/states/../../jobs/1/start",
        "/api/v1/./jobs/states",
        "//evil.test/api/v1/jobs/states",
        "https://evil.test/api/v1/jobs/states",
        "/api/v1/jobs/states?limit=1",
        "/api/v1/jobs/states#x",
        "/api/v1/jobs/st%61tes",
        "/api/v1/jobs/states\n",
        "api/v1/jobs/states",
        "/api/v1/jobs\\states",
    ],
)
def test_get_outside_allowlist_is_refused(path: str) -> None:
    c = trapped_client(ALLOWLIST)
    assert_forbidden(lambda: c.get(path))


def test_post_on_get_only_path_is_refused() -> None:
    c = trapped_client(ALLOWLIST)
    assert_forbidden(lambda: c.post("/api/v1/jobs/states", {}))


def test_destructive_veeam_calls_refused() -> None:
    c = trapped_client(ALLOWLIST)
    job = "/api/v1/jobs/0a1b2c3d-0000-0000-0000-000000000000"
    for action in ("start", "stop", "retry", "disable"):
        assert_forbidden(lambda a=action: c.post(f"{job}/{a}", {}))  # type: ignore[misc]


def test_unlisted_query_param_refused() -> None:
    c = trapped_client(ALLOWLIST)
    err = assert_forbidden(lambda: c.get("/api/v1/jobs/states", {"limit": 1, "action": "x"}))
    assert "action" in err.reason


@pytest.mark.parametrize(
    "body",
    [
        {"grant_type": "password"},  # champ manquant
        {"grant_type": "client_credentials", "username": "svc"},  # valeur hors motif
        {"grant_type": "password", "username": "svc", "scope": "admin"},  # champ en trop
        ["not", "a", "dict"],
    ],
)
def test_post_body_outside_schema_refused(body: Any) -> None:
    c = trapped_client(ALLOWLIST)
    assert_forbidden(lambda: c.post("/api/oauth2/token", body))


@pytest.mark.parametrize("method", ["host.delete", "event.acknowledge", "problem.get.x", "get"])
def test_unlisted_jsonrpc_method_refused(method: str) -> None:
    c = trapped_client(ALLOWLIST)
    assert_forbidden(lambda: c.jsonrpc(method, {}))


def test_jsonrpc_params_outside_schema_refused() -> None:
    c = trapped_client(ALLOWLIST)
    assert_forbidden(lambda: c.jsonrpc("problem.get", {"recent": True, "output": "extend"}))


# --- Allowlists mal formées ---------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"method": "DELETE", "path": r"^/api/v1/jobs$"},
        {"method": "PUT", "path": r"^/api/v1/jobs$"},
        {"method": "PATCH", "path": r"^/api/v1/jobs$"},
        {"method": "get", "path": r"^/api/v1/jobs$"},
        {"method": "GET", "path": r"/api/v1/jobs$"},
        {"method": "GET", "path": r"^/api/v1/jobs"},
        {"method": "GET", "path": r"^api/v1/jobs$"},
        {"method": "GET", "path": r"^/api/.*$"},
        {"method": "GET", "path": r"^/api/.+$"},
        {"method": "GET", "path": r"^/api/v1/(jobs$"},
        {"method": "GET"},
        {"method": "POST", "path": r"^/api/v1/token$"},
        {"method": "POST", "path": r"^/api/v1/token$", "body_schema": TokenRequest},
        {"method": "POST", "path": r"^/x$", "body_schema": Loose, "reason": "x"},
        {"method": "GET", "path": r"^/x$", "body_schema": TokenRequest},
        {"method": "GET", "path": r"^/x$", "jsonrpc": "problem.get"},
        {},
        {"jsonrpc": "problem.get", "endpoint": "/api_jsonrpc.php"},
        {"jsonrpc": "problem.get", "params_schema": ProblemGetParams},
        {"jsonrpc": "problem get", "endpoint": "/x", "params_schema": ProblemGetParams},
        {"jsonrpc": "host.delete", "endpoint": "/x", "params_schema": ProblemGetParams},
        {"jsonrpc": "event.acknowledge", "endpoint": "/x", "params_schema": ProblemGetParams},
        {"jsonrpc": "host.massupdate", "endpoint": "/x", "params_schema": ProblemGetParams},
        {"jsonrpc": "exec", "endpoint": "/x", "params_schema": ProblemGetParams},
        {"jsonrpc": "set", "endpoint": "/x", "params_schema": ProblemGetParams},
        {"jsonrpc": "add", "endpoint": "/x", "params_schema": ProblemGetParams},
        {"jsonrpc": "problem.get", "endpoint": "/x", "params_schema": Loose},
    ],
)
def test_invalid_allowlist_entries_rejected(kwargs: dict[str, Any]) -> None:
    with pytest.raises(AllowlistDefinitionError):
        AllowedCall(**kwargs)


def test_destructive_rpc_allowed_only_with_justification() -> None:
    call = AllowedCall(
        jsonrpc="add",
        endpoint="/jsonrpc",
        params_schema=FazGetParams,
        override_reason="logsearch FAZ : crée une tâche de recherche, sans effet de config",
    )
    assert call.jsonrpc == "add"


def test_client_requires_https_and_allowlist() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        SafeClient(source="t", base_url="http://source.test", allowlist=ALLOWLIST)
    with pytest.raises(ValueError, match="vide"):
        SafeClient(source="t", base_url=BASE_URL, allowlist=[])


# --- Comportement des appels autorisés ----------------------------------------------


def test_allowed_get_returns_json_with_auth_and_params() -> None:
    c, rec = client(httpx.Response(200, json={"data": [1, 2]}))
    c.set_auth_header("Authorization", SecretStr("Bearer fake-token"))
    assert c.get("/api/v1/jobs/states", {"limit": 2}) == {"data": [1, 2]}
    req = rec.requests[0]
    assert req.method == "GET"
    assert str(req.url) == f"{BASE_URL}/api/v1/jobs/states?limit=2"
    assert req.headers["Authorization"] == "Bearer fake-token"


def test_base_url_with_subpath() -> None:
    recorder = Recorder(httpx.Response(200, json={}))
    c = SafeClient(
        source="t",
        base_url=f"{BASE_URL}/zabbix/",
        allowlist=ALLOWLIST,
        transport=recorder.transport(),
    )
    c.get("/api/v1/jobs/states")
    assert recorder.requests[0].url.path == "/zabbix/api/v1/jobs/states"


def test_post_sends_body_reserialized_by_schema() -> None:
    c, rec = client(httpx.Response(200, json={"access_token": "x"}))
    c.post("/api/oauth2/token", {"grant_type": "password", "username": "svc"})
    assert json.loads(rec.requests[0].content) == {"grant_type": "password", "username": "svc"}


def test_jsonrpc_envelope_and_result() -> None:
    c, rec = client(httpx.Response(200, json={"jsonrpc": "2.0", "result": [{"eventid": "1"}]}))
    assert c.jsonrpc("problem.get", {"recent": False, "severities": [4, 5]}) == [{"eventid": "1"}]
    sent = json.loads(rec.requests[0].content)
    assert rec.requests[0].url.path == "/api_jsonrpc.php"
    assert sent == {
        "jsonrpc": "2.0",
        "method": "problem.get",
        "id": 1,
        "params": {"recent": False, "severities": [4, 5]},
    }


def test_jsonrpc_without_version_key() -> None:
    c, rec = client(httpx.Response(200, json={"result": []}), jsonrpc_version=None)
    c.jsonrpc("problem.get", {})
    assert "jsonrpc" not in json.loads(rec.requests[0].content)


@pytest.mark.parametrize(
    "payload", [{"error": {"code": -32602, "message": "secret detail"}}, {"nothing": 1}, [1]]
)
def test_jsonrpc_errors(payload: Any) -> None:
    c, _ = client(httpx.Response(200, json=payload))
    with pytest.raises(SourceCallError) as excinfo:
        c.jsonrpc("problem.get", {})
    assert "secret detail" not in str(excinfo.value)


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirects_are_refused(status: int) -> None:
    c, rec = client(httpx.Response(status, headers={"Location": "https://evil.test/"}))
    with pytest.raises(SourceCallError, match="redirection"):
        c.get("/api/v1/jobs/states")
    assert len(rec.requests) == 1


def test_retries_on_503_then_fails() -> None:
    sleeps: list[float] = []
    responses = [httpx.Response(503) for _ in range(MAX_RETRIES + 1)]
    c, rec = client(*responses, sleeps=sleeps)
    with pytest.raises(SourceCallError, match="HTTP 503"):
        c.get("/api/v1/jobs/states")
    assert len(rec.requests) == MAX_RETRIES + 1
    assert sleeps == [0.5, 1.0, 2.0]


def test_retry_then_success() -> None:
    c, rec = client(httpx.Response(429), httpx.Response(200, json={"ok": True}))
    assert c.get("/api/v1/jobs/states") == {"ok": True}
    assert len(rec.requests) == 2


@pytest.mark.parametrize("status", [400, 401, 403, 404, 500])
def test_no_retry_on_client_errors(status: int) -> None:
    c, rec = client(httpx.Response(status))
    with pytest.raises(SourceCallError, match=f"HTTP {status}"):
        c.get("/api/v1/jobs/states")
    assert len(rec.requests) == 1


def test_network_errors_are_retried_then_reported() -> None:
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        raise httpx.ConnectError("refused", request=request)

    c = SafeClient(
        source="t",
        base_url=BASE_URL,
        allowlist=ALLOWLIST,
        transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
    )
    with pytest.raises(SourceCallError, match="injoignable"):
        c.get("/api/v1/jobs/states")
    assert len(attempts) == MAX_RETRIES + 1


def test_response_size_is_bounded() -> None:
    c, _ = client(httpx.Response(200, content=b"[" + b"1," * 600 + b"1]"), max_response_bytes=1000)
    with pytest.raises(SourceCallError, match="volumineuse"):
        c.get("/api/v1/jobs/states")


def test_declared_size_is_bounded() -> None:
    big = httpx.Response(200, content=b"{}", headers={"Content-Length": "999999999"})
    c, _ = client(big)
    with pytest.raises(SourceCallError, match="volumineuse"):
        c.get("/api/v1/jobs/states")


def test_non_json_response() -> None:
    c, _ = client(httpx.Response(200, content=b"<html>"))
    with pytest.raises(SourceCallError, match="non JSON"):
        c.get("/api/v1/jobs/states")


def test_transport_settings() -> None:
    c = SafeClient(source="t", base_url=BASE_URL, allowlist=ALLOWLIST)
    inner = c._client
    assert inner.timeout.connect == CONNECT_TIMEOUT_S
    assert inner.timeout.read == READ_TIMEOUT_S
    assert inner.follow_redirects is False
    assert inner.trust_env is False
    pool = inner._transport._pool  # type: ignore[attr-defined]
    assert pool._ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert pool._ssl_context.check_hostname is True
    c.close()


def test_environment_proxy_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://evil-proxy.test:3128")
    with SafeClient(source="t", base_url=BASE_URL, allowlist=ALLOWLIST) as c:
        assert c._client._mounts == {}


# --- Pagination bornée et contrat ------------------------------------------------------


def test_bounded_truncates() -> None:
    items = bounded(range(10_000), max_objects=5000)
    assert len(list(items)) == 5000
    assert items.truncated is True


def test_bounded_exact_limit_not_truncated() -> None:
    items = bounded(range(5000), max_objects=5000)
    assert len(list(items)) == 5000
    assert items.truncated is False


def test_signal_severity_range() -> None:
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="sévérité"):
        Signal(
            source="s",
            external_id="1",
            company_code=None,
            asset="a",
            category=Category.server,
            severity=6,
            title="t",
            details="",
            first_seen=now,
            last_seen=now,
        )


# --- Appels anonymes et rejeu de fixtures -------------------------------------------


class EmptyParams(RootModel[list[int]]):
    pass


ANON = [
    AllowedCall(
        jsonrpc="apiinfo.version",
        endpoint="/api_jsonrpc.php",
        params_schema=EmptyParams,
        anonymous=True,
    ),
    AllowedCall(jsonrpc="problem.get", endpoint="/api_jsonrpc.php", params_schema=ProblemGetParams),
    AllowedCall(method="GET", path=r"^/api/v1/jobs$"),
]


def test_anonymous_call_sends_no_auth_header() -> None:
    recorder = Recorder(
        httpx.Response(200, json={"result": "7.4.0"}), httpx.Response(200, json={"result": []})
    )
    c = SafeClient(source="t", base_url=BASE_URL, allowlist=ANON, transport=recorder.transport())
    c.set_auth_header("Authorization", SecretStr("Bearer fake-token"))
    assert c.jsonrpc("apiinfo.version", []) == "7.4.0"
    c.jsonrpc("problem.get", {})
    assert "Authorization" not in recorder.requests[0].headers
    assert json.loads(recorder.requests[0].content)["params"] == []
    assert recorder.requests[1].headers["Authorization"] == "Bearer fake-token"


def test_fixture_replay(tmp_path: Path) -> None:
    (tmp_path / "problem.get.json").write_text('[{"eventid": "7"}]')
    (tmp_path / "GET_api_v1_jobs.json").write_text('{"data": []}')
    c = SafeClient(
        source="t", base_url=BASE_URL, allowlist=ANON, transport=fixture_transport(tmp_path)
    )
    assert c.jsonrpc("problem.get", {}) == [{"eventid": "7"}]
    assert c.get("/api/v1/jobs") == {"data": []}
    with pytest.raises(SourceCallError, match="HTTP 404"):
        c.jsonrpc("apiinfo.version", [])


def test_fixture_replay_still_enforces_allowlist(tmp_path: Path) -> None:
    (tmp_path / "host.delete.json").write_text("[]")
    c = SafeClient(
        source="t", base_url=BASE_URL, allowlist=ANON, transport=fixture_transport(tmp_path)
    )
    assert_forbidden(lambda: c.jsonrpc("host.delete", {}))


def test_unreadable_ca_bundle_is_reported(tmp_path: Path) -> None:
    with pytest.raises(SourceCallError, match="bundle CA illisible"):
        SafeClient(source="t", base_url=BASE_URL, allowlist=ANON, ca_bundle=tmp_path / "absent.pem")


def test_empty_body_returns_none() -> None:
    c, _ = client(httpx.Response(202, content=b""))
    assert c.get("/api/v1/jobs/states") is None


@pytest.mark.parametrize(
    "value", ["Bearer <clé API du FAZ>", "Bearer abc\ndef", "Bearer clé", "Bearer <token>"]
)
def test_invalid_auth_header_is_refused_without_echo(value: str) -> None:
    from vigie.connectors.base import ConnectorConfigError

    client = SafeClient(source="t", base_url="https://source.test", allowlist=ALLOWLIST)
    with pytest.raises(ConnectorConfigError) as exc:
        client.set_auth_header("Authorization", SecretStr(value))
    assert "Authorization" in str(exc.value) and value not in str(exc.value)
    client.set_auth_header("Authorization", SecretStr("Bearer AbC123._~+/=-"))


@pytest.mark.parametrize(
    ("proxy", "ok"),
    [
        ("http://127.0.0.1:3128", True),  # Squid de l'hôte (installation native)
        ("http://squid:3128", True),  # conteneur Squid de compose.yaml
        ("http://squid.evil.test:3128", False),
        ("http://evil.test:3128", False),
        ("https://squid:3128", False),
        ("http://squid:3128/x", False),
    ],
)
def test_source_proxy_is_local_or_the_squid_container(proxy: str, ok: bool) -> None:
    from vigie.connectors.base import LOCAL_PROXY_RE

    assert bool(re.fullmatch(LOCAL_PROXY_RE, proxy)) is ok


def _self_signed(tmp_path: Path, name: str) -> Path:
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / f"{name}.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def test_hostname_check_off_only_with_a_pinned_bundle(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="seulement avec ca_bundle"):
        SafeClient(source="t", base_url=BASE_URL, allowlist=ANON, check_hostname=False)
    pinned = _self_signed(tmp_path, "pinned.test")
    c = SafeClient(
        source="t", base_url=BASE_URL, allowlist=ANON, ca_bundle=pinned, check_hostname=False
    )
    ctx = c._client._transport._pool._ssl_context  # type: ignore[attr-defined]
    assert ctx.verify_mode == ssl.CERT_REQUIRED  # chaîne toujours vérifiée
    assert ctx.check_hostname is False
    assert ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
    # Seul le certificat épinglé est approuvé : aucune autorité du système.
    assert [dict(x[0] for x in ca["subject"])["commonName"] for ca in ctx.get_ca_certs()] == [
        "pinned.test"
    ]
    c.close()
