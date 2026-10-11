"""Veeam : seules les lectures prévues et le jeton passent, aucune action (SECURITY.md C2)."""

import logging
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from pydantic import SecretStr

from tests.security.helpers import BASE_URL, Recorder, assert_forbidden, trapped_client
from vigie.connectors.base import SafeClient
from vigie.connectors.veeam import ALLOWLIST

JOB = "/api/v1/jobs/10000000-0000-4000-8000-000000000001"
TOKEN: dict[str, Any] = {
    "grant_type": "password",
    "username": "svc-vigie",
    "password": SecretStr("s3cret-du-test"),
}


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", f"{JOB}/start"),
        ("POST", f"{JOB}/stop"),
        ("POST", f"{JOB}/retry"),
        ("POST", f"{JOB}/disable"),
        ("POST", f"{JOB}/enable"),
        ("POST", "/api/v1/sessions/40000000-0000-4000-8000-000000000001/stop"),
        ("POST", "/api/v1/jobs"),
        ("POST", "/api/oauth2/logout"),
        ("POST", "/api/v1/malwareDetection/events"),
        ("POST", "/api/v1/backups/1/restorePoints"),
        ("GET", JOB),
        ("GET", "/api/v1/jobs"),
        ("GET", "/api/v1/credentials"),
        ("GET", "/api/v1/backups"),
        ("GET", "/api/v1/jobs/states/../../credentials"),
        ("GET", "/api/v1/jobs/states/"),
    ],
)
def test_actions_and_unlisted_paths_are_refused(method: str, path: str) -> None:
    client = trapped_client(ALLOWLIST, source="veeam")
    if method == "POST":
        assert_forbidden(lambda: client.post(path, {}))
    else:
        assert_forbidden(lambda: client.get(path))


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
def test_write_methods_are_refused(method: str) -> None:
    client = trapped_client(ALLOWLIST, source="veeam")
    assert_forbidden(lambda: client._authorize_rest(method, JOB, None))


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/api/v1/jobs/states", {"nameFilter": "x"}),
        ("/api/v1/sessions", {"jobIdFilter": "x"}),
        ("/api/v1/backupInfrastructure/repositories/states", {"orderColumn": "Name"}),
        ("/api/v1/serverInfo", {"limit": 1}),
    ],
)
def test_unlisted_query_parameters_are_refused(path: str, params: dict[str, Any]) -> None:
    client = trapped_client(ALLOWLIST, source="veeam")
    assert_forbidden(lambda: client.get(path, params))


@pytest.mark.parametrize(
    "body",
    [
        {**TOKEN, "grant_type": "refresh_token"},
        {**TOKEN, "grant_type": "vbr_token"},
        {**TOKEN, "use_short_term_refresh": True},
        {"grant_type": "password", "username": "svc-vigie"},
    ],
)
def test_token_body_outside_schema_is_refused(body: dict[str, Any]) -> None:
    client = trapped_client(ALLOWLIST, source="veeam")
    assert_forbidden(lambda: client.post("/api/oauth2/token", body))


def test_token_is_form_encoded_anonymous_and_password_never_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    recorder = Recorder(
        httpx.Response(200, json={"access_token": "t"}),
        httpx.Response(200, json={"data": [], "pagination": {"total": 0, "count": 0}}),
    )
    client = SafeClient(
        source="veeam",
        base_url=BASE_URL,
        allowlist=ALLOWLIST,
        transport=recorder.transport(),
        headers={"x-api-version": "1.3-rev1"},
    )
    client.set_auth_header("Authorization", SecretStr("Bearer fake-token"))
    with caplog.at_level(logging.DEBUG):
        client.post("/api/oauth2/token", TOKEN)
        client.get("/api/v1/jobs/states", {"skip": 0, "limit": 500})
    token_req, states_req = recorder.requests
    assert token_req.headers["content-type"] == "application/x-www-form-urlencoded"
    assert parse_qs(token_req.content.decode()) == {
        "grant_type": ["password"],
        "username": ["svc-vigie"],
        "password": ["s3cret-du-test"],
    }
    assert "Authorization" not in token_req.headers  # appel anonyme
    assert states_req.headers["Authorization"] == "Bearer fake-token"
    assert all(r.headers["x-api-version"] == "1.3-rev1" for r in recorder.requests)
    assert "s3cret-du-test" not in caplog.text


def test_fixed_headers_cannot_carry_credentials() -> None:
    for name in ("Authorization", "cookie", "Proxy-Authorization"):
        with pytest.raises(ValueError, match="réservé"):
            SafeClient(source="veeam", base_url=BASE_URL, allowlist=ALLOWLIST, headers={name: "x"})
