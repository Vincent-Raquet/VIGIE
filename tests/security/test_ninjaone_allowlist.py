"""NinjaOne : lectures prévues, jeton monitoring et lecture de board seulement (SECURITY.md C2)."""

import logging
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from pydantic import SecretStr

from tests.security.helpers import BASE_URL, Recorder, assert_forbidden, trapped_client
from vigie.connectors.base import SafeClient
from vigie.connectors.ninjaone import ALLOWLIST, TICKET_COLUMNS

TOKEN: dict[str, Any] = {
    "grant_type": "client_credentials",
    "client_id": "vigie-client",
    "client_secret": SecretStr("s3cret-ninja"),
    "scope": "monitoring",
}
BOARD = "/v2/ticketing/trigger/board/12/run"
BOARD_BODY: dict[str, Any] = {"includeColumns": ["id", "summary", "status"], "pageSize": 100}


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/v2/ticketing/ticket"),  # créer un ticket
        ("POST", "/v2/ticketing/ticket/42/comment"),
        ("POST", "/v2/alert/0a1b/reset"),
        ("POST", "/v2/device/7/patch/os/apply"),
        ("POST", "/v2/device/7/patch/software/scan"),
        ("POST", "/v2/device/7/script/run"),
        ("POST", "/v2/organizations"),
        ("POST", "/v2/organization/generate-installer"),
        ("POST", "/v2/backup/integrity-check-jobs"),
        ("POST", "/v2/ticketing/trigger/board/x/run"),
        ("POST", "/v2/ticketing/trigger/board/12/run/../../ticket"),
        ("GET", "/v2/ticketing/ticket/42"),  # corps du ticket : jamais
        ("GET", "/v2/ticketing/ticket/42/log-entry"),
        ("GET", "/v2/organization/1/end-users"),  # données personnelles
        ("GET", "/v2/ticketing/contact/contacts"),
        ("GET", "/v2/device/7/dashboard-url"),
        ("GET", "/v2/backup/jobs"),  # NinjaOne Backup non utilisé
    ],
)
def test_actions_and_unlisted_paths_are_refused(method: str, path: str) -> None:
    client = trapped_client(ALLOWLIST, source="ninjaone")
    if method == "POST":
        assert_forbidden(lambda: client.post(path, {}))
    else:
        assert_forbidden(lambda: client.get(path))


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("PUT", "/v2/ticketing/ticket/42"),
        ("DELETE", "/v2/alert/0a1b"),
        ("PATCH", "/v2/organization/1"),
    ],
)
def test_write_methods_are_refused(method: str, path: str) -> None:
    client = trapped_client(ALLOWLIST, source="ninjaone")
    assert_forbidden(lambda: client._authorize_rest(method, path, None))


@pytest.mark.parametrize(
    "body",
    [
        {**TOKEN, "scope": "monitoring management"},
        {**TOKEN, "scope": "control"},
        {**TOKEN, "grant_type": "authorization_code"},
        {**TOKEN, "redirect_uri": "https://evil.test"},
    ],
)
def test_token_only_with_monitoring_scope(body: dict[str, Any]) -> None:
    client = trapped_client(ALLOWLIST, source="ninjaone")
    assert_forbidden(lambda: client.post("/ws/oauth/token", body))


@pytest.mark.parametrize(
    "body",
    [
        {**BOARD_BODY, "includeColumns": ["id", "description"]},
        {**BOARD_BODY, "includeColumns": ["id", "requester"]},
        {**BOARD_BODY, "includeColumns": ["id", "contact"]},
        {**BOARD_BODY, "filters": [{"field": "status", "operator": "in", "value": "1"}]},
        {**BOARD_BODY, "searchCriteria": "mot de passe"},
        {**BOARD_BODY, "sortBy": [{"field": "id", "direction": "ASC"}]},
        {**BOARD_BODY, "pageSize": 1000},
    ],
)
def test_board_read_is_strictly_limited(body: dict[str, Any]) -> None:
    client = trapped_client(ALLOWLIST, source="ninjaone")
    assert_forbidden(lambda: client.post(BOARD, body))


def test_no_personal_or_free_text_column_is_allowed() -> None:
    assert not {"description", "requester", "contact", "assignedAppUser", "cc"} & set(
        TICKET_COLUMNS
    )


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/v2/alerts", {"df": "org = 1"}),
        ("/v2/organizations", {"of": "1"}),
        ("/v2/queries/os-patches", {"df": "class in (WINDOWS_SERVER)"}),
    ],
)
def test_unlisted_query_parameters_are_refused(path: str, params: dict[str, Any]) -> None:
    client = trapped_client(ALLOWLIST, source="ninjaone")
    assert_forbidden(lambda: client.get(path, params))


def test_allowed_calls_pass_and_secret_is_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    recorder = Recorder(
        httpx.Response(200, json={"access_token": "t"}),
        httpx.Response(200, json=[]),
        httpx.Response(200, json={"data": [], "metadata": {}}),
    )
    client = SafeClient(
        source="ninjaone", base_url=BASE_URL, allowlist=ALLOWLIST, transport=recorder.transport()
    )
    client.set_auth_header("Authorization", SecretStr("Bearer fake"))
    with caplog.at_level(logging.DEBUG):
        client.post("/ws/oauth/token", TOKEN)
        client.get("/v2/alerts")
        client.post(BOARD, BOARD_BODY)
    token_req = recorder.requests[0]
    assert parse_qs(token_req.content.decode())["scope"] == ["monitoring"]
    assert "Authorization" not in token_req.headers
    assert recorder.requests[2].headers["Authorization"] == "Bearer fake"
    assert "s3cret-ninja" not in caplog.text
