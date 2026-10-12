"""FortiAnalyzer : « get » sur les URL listées seulement ; aucune écriture (SECURITY.md C2)."""

import json
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from tests.security.helpers import Recorder, assert_forbidden, trapped_client
from vigie.connectors.base import AllowedCall, AllowlistDefinitionError, ConnectorContext
from vigie.connectors.fortianalyzer import (
    ALLOWLIST,
    READ_ALLOWLIST,
    VPN_DOWN_FILTER,
    FortiAnalyzerConnector,
    GetParams,
)

RANGE = {"start": "2026-10-11 10:00:00", "end": "2026-10-12 10:00:00"}
ALERTS: dict[str, Any] = {
    "url": "/eventmgmt/adom/root/alerts",
    "apiver": 3,
    "limit": 500,
    "offset": 0,
    "time-range": RANGE,
    "time-order": "desc",
}
LOGSEARCH: dict[str, Any] = {
    "url": "/logview/adom/root/logsearch",
    "apiver": 3,
    "logtype": "event",
    "device": [{"devid": "All_FortiGate"}],
    "filter": VPN_DOWN_FILTER,
    "time-range": RANGE,
    "time-order": "desc",
}


@pytest.mark.parametrize(
    ("method", "item"),
    [
        # Écritures et actions : jamais déclarées.
        ("set", {"url": "/cli/global/system/admin/user/svc-vigie", "data": {}}),
        ("update", {"url": "/eventmgmt/adom/root/alerts/ack", "alertid": ["1"]}),
        ("update", {"url": "/eventmgmt/adom/root/alerts/comment", "comment": "x"}),
        ("delete", {"url": "/dvmdb/adom/root/device/FGT-WI-01"}),
        ("delete", {"url": "/logview/adom/root/logsearch/42"}),
        ("exec", {"url": "/sys/reboot"}),
        ("exec", {"url": "/dvm/cmd/del/device"}),
        ("add", {"url": "/dvm/cmd/add/device"}),
        ("add", {"url": "/eventmgmt/adom/root/config/basic-handler"}),
        ("clone", {"url": "/eventmgmt/adom/root/config/basic-handler"}),
        ("move", {"url": "/eventmgmt/adom/root/config/basic-handler"}),
        # Lectures non listées.
        ("get", {"url": "/cli/global/system/admin/user"}),
        ("get", {"url": "/eventmgmt/adom/root/config/basic-handler"}),
        ("get", {"url": "/incidentmgmt/adom/root/incidents"}),
        ("get", {"url": "/logview/adom/root/logfiles/data"}),
        ("get", {"url": "/sys/ha/status"}),
        ("get", {"url": "/dvmdb/adom/root/device/FGT-WI-01"}),
        ("get", {"url": "/dvmdb/adom/../device"}),
    ],
)
def test_writes_and_unlisted_urls_are_refused(method: str, item: dict[str, Any]) -> None:
    client = trapped_client(ALLOWLIST, source="fortianalyzer")
    assert_forbidden(lambda: client.jsonrpc(method, [item]))


@pytest.mark.parametrize(
    "item",
    [
        {**ALERTS, "limit": 5000},  # au-delà de 2000
        {**ALERTS, "filter": "ackflag==yes"},  # paramètre non listé
        {**ALERTS, "url": "/eventmgmt/adom/root/alerts/unack"},
        {"url": "/dvmdb/adom/root/device", "fields": ["name", "psk"], "loadsub": 0},
        {"url": "/dvmdb/adom/root/device", "fields": ["name"], "loadsub": 1},
        {"url": "/sys/status", "data": {"x": 1}},
    ],
)
def test_get_parameters_are_strict(item: dict[str, Any]) -> None:
    client = trapped_client(ALLOWLIST, source="fortianalyzer")
    assert_forbidden(lambda: client.jsonrpc("get", [item]))


def test_one_object_per_call() -> None:
    client = trapped_client(ALLOWLIST, source="fortianalyzer")
    assert_forbidden(lambda: client.jsonrpc("get", [{"url": "/sys/status"}] * 2))
    assert_forbidden(lambda: client.jsonrpc("get", []))


@pytest.mark.parametrize(
    "item",
    [
        {**LOGSEARCH, "filter": "srcip==10.0.0.1"},  # filtre imposé
        {**LOGSEARCH, "logtype": "traffic"},
        {**LOGSEARCH, "device": [{"devid": "FGT-WI-01"}]},
        {**LOGSEARCH, "url": "/logview/adom/root/logfiles/search"},
    ],
)
def test_logsearch_task_is_restricted(item: dict[str, Any]) -> None:
    client = trapped_client(ALLOWLIST, source="fortianalyzer")
    assert_forbidden(lambda: client.jsonrpc("add", [item]))


def test_logsearch_absent_unless_enabled() -> None:
    client = trapped_client(READ_ALLOWLIST, source="fortianalyzer")
    assert_forbidden(lambda: client.jsonrpc("add", [LOGSEARCH]))


def test_add_requires_justification() -> None:
    with pytest.raises(AllowlistDefinitionError):
        AllowedCall(jsonrpc="add", endpoint="/jsonrpc", params_schema=GetParams)


def test_allowed_get_is_sent_reserialized_with_bearer() -> None:
    recorder = Recorder(
        httpx.Response(200, json={"id": 1, "result": [{"status": {"code": 0}, "data": {}}]})
    )
    ctx = ConnectorContext(
        settings={"base_url": "https://faz.test"},
        secret=lambda name: SecretStr("cle-api-de-test"),
        transport=recorder.transport(),
    )
    connector = FortiAnalyzerConnector.from_context(ctx)
    assert connector.healthcheck().ok
    [request] = recorder.requests
    body = json.loads(request.content)
    assert body["method"] == "get" and body["params"] == [{"url": "/sys/status"}]
    assert "session" not in body and request.url.path == "/jsonrpc"
    assert request.headers["Authorization"] == "Bearer cle-api-de-test"
