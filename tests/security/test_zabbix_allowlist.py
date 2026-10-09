"""Zabbix : seules les lectures prévues passent, rien d'autre n'est émis (SECURITY.md C2)."""

import json
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from tests.security.helpers import BASE_URL, Recorder, assert_forbidden, trapped_client
from vigie.connectors.base import SafeClient
from vigie.connectors.zabbix import ALLOWLIST

PROBLEM_PARAMS: dict[str, Any] = {
    "output": ["eventid", "objectid", "clock", "name", "severity"],
    "source": 0,
    "object": 0,
    "severities": [2, 3, 4, 5],
    "recent": False,
    "selectTags": "extend",
    "selectAcknowledges": "count",
    "sortfield": "eventid",
    "sortorder": "DESC",
    "limit": 5001,
}
TRIGGER_PARAMS: dict[str, Any] = {
    "triggerids": ["69814", "95206"],
    "output": ["triggerid", "priority"],
    "selectHosts": ["hostid", "host", "name", "status", "maintenance_status"],
    "selectHostGroups": ["groupid", "name"],
    "monitored": True,
}


@pytest.mark.parametrize(
    "method",
    [
        "host.delete",
        "host.update",
        "host.massupdate",
        "event.acknowledge",
        "problem.acknowledge",
        "script.execute",
        "script.get",
        "user.update",
        "user.login",
        "configuration.import",
        "configuration.export",
        "maintenance.create",
        "trigger.update",
        "item.get",
        "history.get",
        "host.get",
        "token.generate",
        "settings.update",
    ],
)
def test_actions_and_unlisted_reads_are_refused(method: str) -> None:
    client = trapped_client(ALLOWLIST, source="zabbix")
    assert_forbidden(lambda: client.jsonrpc(method, {}))


@pytest.mark.parametrize(
    ("method", "params"),
    [
        ("problem.get", {**PROBLEM_PARAMS, "output": "extend"}),
        ("problem.get", {**PROBLEM_PARAMS, "output": ["eventid", "r_eventid"]}),
        ("problem.get", {**PROBLEM_PARAMS, "selectAcknowledges": "extend"}),
        ("problem.get", {**PROBLEM_PARAMS, "limit": 100000}),
        ("problem.get", {**PROBLEM_PARAMS, "severities": [9]}),
        ("problem.get", {**PROBLEM_PARAMS, "acknowledge": True}),
        ("trigger.get", {**TRIGGER_PARAMS, "triggerids": ["1 OR 1=1"]}),
        ("trigger.get", {**TRIGGER_PARAMS, "triggerids": [str(i) for i in range(501)]}),
        ("trigger.get", {**TRIGGER_PARAMS, "selectHosts": "extend"}),
        ("trigger.get", {**TRIGGER_PARAMS, "selectItems": ["itemid"]}),
        ("trigger.get", {**TRIGGER_PARAMS, "monitored": False}),
        ("proxy.get", {"output": "extend"}),
        ("proxy.get", {"output": ["proxyid", "tls_psk"]}),
        ("apiinfo.version", [1]),
        ("apiinfo.version", {"auth": "x"}),
    ],
)
def test_params_outside_schema_are_refused(method: str, params: Any) -> None:
    client = trapped_client(ALLOWLIST, source="zabbix")
    assert_forbidden(lambda: client.jsonrpc(method, params))


def test_allowed_calls_pass_and_apiinfo_is_anonymous() -> None:
    recorder = Recorder(*(httpx.Response(200, json={"result": []}) for _ in range(4)))
    client = SafeClient(
        source="zabbix", base_url=BASE_URL, allowlist=ALLOWLIST, transport=recorder.transport()
    )
    client.set_auth_header("Authorization", SecretStr("Bearer fake-token"))
    client.jsonrpc("apiinfo.version", [])
    client.jsonrpc("problem.get", PROBLEM_PARAMS)
    client.jsonrpc("trigger.get", TRIGGER_PARAMS)
    client.jsonrpc("proxy.get", {"output": ["proxyid", "name", "state", "lastaccess"]})
    methods = [json.loads(r.content)["method"] for r in recorder.requests]
    assert methods == ["apiinfo.version", "problem.get", "trigger.get", "proxy.get"]
    assert "Authorization" not in recorder.requests[0].headers
    assert all(r.headers["Authorization"] == "Bearer fake-token" for r in recorder.requests[1:])
    assert {r.url.path for r in recorder.requests} == {"/api_jsonrpc.php"}
