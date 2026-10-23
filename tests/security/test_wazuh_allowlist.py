"""Wazuh : seules les lectures prévues et le JWT passent, aucune action (SECURITY.md C2)."""

import base64
import json
import logging
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from tests.security.helpers import Recorder, assert_forbidden, trapped_client
from vigie.connectors.base import ConnectorContext
from vigie.connectors.wazuh import (
    INDEXER_ALLOWLIST,
    MANAGER_ALLOWLIST,
    SearchRequest,
    WazuhConnector,
)

ALERTS = "/wazuh-alerts-4.x-*/_search"
VULNS = "/wazuh-states-vulnerabilities-*/_search"
SEARCH: dict[str, Any] = {"size": 0, "query": {"match_all": {}}}


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/agents"),
        ("POST", "/agents/insert"),
        ("POST", "/agents/001/restart"),
        ("POST", "/groups"),
        ("POST", "/security/user/authenticate/run_as"),
        ("POST", "/security/users"),
        ("POST", "/logtest"),
        ("POST", "/manager/api/config"),
        ("GET", "/agents/001/key"),
        ("GET", "/agents/001/config/agent/client"),
        ("GET", "/security/users"),
        ("GET", "/manager/configuration"),
        ("GET", "/manager/logs"),
        ("GET", "/agents/../security/users"),
        ("GET", "/agents/"),
    ],
)
def test_manager_actions_and_unlisted_paths_are_refused(method: str, path: str) -> None:
    client = trapped_client(MANAGER_ALLOWLIST, source="wazuh")
    if method == "POST":
        assert_forbidden(lambda: client.post(path, {}))
    else:
        assert_forbidden(lambda: client.get(path))


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("DELETE", "/agents"),
        ("PUT", "/agents/restart"),
        ("PUT", "/active-response"),
        ("PUT", "/manager/restart"),
        ("PUT", "/agents/group"),
        ("DELETE", "/security/user/authenticate"),
        ("PUT", "/security/config"),
        ("PUT", "/agents/upgrade"),
        ("PUT", "/cluster/restart"),
        ("PUT", "/"),
        ("PATCH", "/agents"),
    ],
)
def test_manager_write_methods_are_refused(method: str, path: str) -> None:
    client = trapped_client(MANAGER_ALLOWLIST, source="wazuh")
    assert_forbidden(lambda: client._authorize_rest(method, path, None))


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/agents", {"q": "status=active"}),
        ("/agents", {"agents_list": "001"}),
        ("/agents/summary/status", {"limit": 1}),
        ("/", {"pretty": "true"}),
    ],
)
def test_unlisted_query_parameters_are_refused(path: str, params: dict[str, Any]) -> None:
    client = trapped_client(MANAGER_ALLOWLIST, source="wazuh")
    assert_forbidden(lambda: client.get(path, params))


def test_authenticate_accepts_no_body() -> None:
    client = trapped_client(MANAGER_ALLOWLIST, source="wazuh")
    assert_forbidden(lambda: client.post("/security/user/authenticate", {"run_as": True}))
    assert_forbidden(lambda: client.post("/security/user/authenticate", {}, {"raw": "true"}))


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/wazuh-alerts-4.x-*/_delete_by_query"),
        ("POST", "/wazuh-alerts-4.x-*/_update_by_query"),
        ("POST", "/_bulk"),
        ("POST", "/wazuh-alerts-4.x-*/_doc"),
        ("POST", "/wazuh-alerts-4.x-*/_bulk"),
        ("POST", "/wazuh-states-vulnerabilities-*/_doc/1/_update"),
        ("POST", "/_search"),
        ("POST", "/*/_search"),
        ("POST", "/.opendistro_security/_search"),
        ("POST", "/wazuh-archives-4.x-*/_search"),
        ("POST", "/wazuh-alerts-4.x-*/_search/template"),
        ("POST", "/_plugins/_security/api/internalusers"),
        ("POST", "/wazuh-alerts-4.x-*/_close"),
        ("GET", "/_cat/indices"),
        ("GET", "/_plugins/_security/api/roles"),
        ("GET", "/wazuh-alerts-4.x-*/_search"),
    ],
)
def test_indexer_writes_and_other_indices_are_refused(method: str, path: str) -> None:
    client = trapped_client(INDEXER_ALLOWLIST, source="wazuh")
    if method == "POST":
        assert_forbidden(lambda: client.post(path, SEARCH))
    else:
        assert_forbidden(lambda: client.get(path))


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
def test_indexer_write_methods_are_refused(method: str) -> None:
    client = trapped_client(INDEXER_ALLOWLIST, source="wazuh")
    assert_forbidden(lambda: client._authorize_rest(method, "/wazuh-alerts-4.x-*", None))


@pytest.mark.parametrize(
    "body",
    [
        {**SEARCH, "size": 501},
        {"size": 0},
        {**SEARCH, "script_fields": {"x": {"script": "1"}}},
        {"query": {"script": {"script": {"source": "true"}}}},
        {"query": {"bool": {"filter": [{"script": {"script": "doc['x'] > 1"}}]}}},
        {**SEARCH, "aggs": {"x": {"scripted_metric": {"map_script": "state.x = 1"}}}},
        {**SEARCH, "aggs": {"x": {"terms": {"script": {"source": "doc['x']"}}}}},
        {**SEARCH, "sort": [{"_script": {"type": "number", "script": "1"}}]},
        {**SEARCH, "runtime_mappings": {"x": {"type": "long"}}},
        {**SEARCH, "stored_fields": ["*"]},
        {**SEARCH, "pit": {"id": "x"}},
        {**SEARCH, "from": 10000},
        {**SEARCH, "search_after": [1]},
        {**SEARCH, "_source": "*"},
        # Lecture d'un autre index depuis la requête (terms lookup, more_like_this, percolate).
        {"query": {"terms": {"agent.id": {"index": ".opendistro_security", "id": "x"}}}},
        {"query": {"more_like_this": {"like": [{"_index": "wazuh-archives-4.x-x", "_id": "1"}]}}},
        {"query": {"percolate": {"field": "q", "index": "x", "id": "1"}}},
        {"query": {"geo_shape": {"g": {"indexed_shape": {"index": "x", "id": "1"}}}}},
    ],
)
def test_search_bodies_outside_the_schema_are_refused(body: dict[str, Any]) -> None:
    client = trapped_client(INDEXER_ALLOWLIST, source="wazuh")
    assert_forbidden(lambda: client.post(ALERTS, body))
    assert_forbidden(lambda: client.post(VULNS, body))


def test_search_query_parameters_are_refused() -> None:
    client = trapped_client(INDEXER_ALLOWLIST, source="wazuh")
    assert_forbidden(lambda: client.post(ALERTS, SEARCH, {"scroll": "1m"}))
    assert_forbidden(lambda: client.post(ALERTS, SEARCH, {"q": "*"}))


def test_search_schema_accepts_the_connector_queries() -> None:
    SearchRequest.model_validate(
        {**SEARCH, "_source": ["rule.id"], "sort": [{"timestamp": "desc"}], "aggs": {}}
    )


def test_passwords_sent_once_as_basic_and_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    recorder = Recorder(
        httpx.Response(200, json={"data": {"token": "jwt-du-test"}}),
        httpx.Response(200, json={"data": {"affected_items": [], "total_affected_items": 0}}),
        httpx.Response(200, json={"aggregations": {}}),
        httpx.Response(200, json={"aggregations": {}}),
    )
    secrets = {
        "wazuh_api_password": SecretStr("mdp-api-du-test"),
        "wazuh_indexer_password": SecretStr("mdp-indexer-du-test"),
    }
    ctx = ConnectorContext(
        settings={"api_url": "https://wazuh.test:55000", "indexer_url": "https://wazuh.test:9200"},
        secret=lambda name: secrets[name],
        transport=recorder.transport(),
    )
    with caplog.at_level(logging.DEBUG):
        assert list(WazuhConnector.from_context(ctx).collect(None)) == []  # type: ignore[arg-type]
    auth = [r.headers["authorization"] for r in recorder.requests]
    api_basic = "Basic " + base64.b64encode(b"svc-vigie:mdp-api-du-test").decode()
    idx_basic = "Basic " + base64.b64encode(b"svc-vigie:mdp-indexer-du-test").decode()
    assert auth == [api_basic, "Bearer jwt-du-test", idx_basic, idx_basic]
    assert [r.url.port for r in recorder.requests] == [55000, 55000, 9200, 9200]
    assert json.loads(recorder.requests[0].content) == {}
    for text in ("mdp-api-du-test", "mdp-indexer-du-test", "jwt-du-test", api_basic[6:]):
        assert text not in caplog.text
