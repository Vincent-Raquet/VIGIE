"""scripts/record_fixtures.py : jeton jamais enregistré, pages fusionnées, sortie hors dépôt."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import httpx
import pytest

from tests.conftest import REPO_ROOT
from vigie.connectors.base import RecordingTransport


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "record_fixtures", REPO_ROOT / "scripts" / "record_fixtures.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_token_is_replaced_and_pages_are_merged() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/oauth2/token":
            return httpx.Response(200, json={"access_token": "VRAI-JETON-SECRET"})
        skip = int(request.url.params.get("skip", "0"))
        return httpx.Response(200, json={"data": [{"id": skip}], "pagination": {"total": 2}})

    recorder = RecordingTransport(None, inner=httpx.MockTransport(handler))
    with httpx.Client(transport=recorder) as client:
        assert client.post("https://vbr.test/api/oauth2/token").json() == {
            "access_token": "VRAI-JETON-SECRET"
        }  # l'appelant reçoit la vraie réponse…
        client.get("https://vbr.test/api/v1/jobs/states", params={"skip": 0})
        client.get("https://vbr.test/api/v1/jobs/states", params={"skip": 1})
    saved = recorder.saved
    assert "VRAI-JETON-SECRET" not in str(saved)  # … mais seul un jeton factice est gardé
    assert saved["POST_api_oauth2_token.json"]["access_token"] == "fixture-access-token"
    assert saved["GET_api_v1_jobs_states.json"]["data"] == [{"id": 0}, {"id": 1}]


def test_wazuh_jwt_is_replaced() -> None:
    real = {"data": {"token": "eyJ.VRAI-JWT.SECRET"}, "error": 0}
    recorder = RecordingTransport(
        None, inner=httpx.MockTransport(lambda r: httpx.Response(200, json=real))
    )
    with httpx.Client(transport=recorder) as client:
        assert client.post("https://wazuh.test:55000/security/user/authenticate").json() == real
    assert "VRAI-JWT" not in str(recorder.saved)
    assert recorder.saved["POST_security_user_authenticate.json"] == {
        "data": {"token": "fixture-jwt"},
        "error": 0,
    }


@pytest.mark.parametrize(
    ("env", "out", "message"),
    [
        ({}, None, "VIGIE_ENV=dev"),
        ({"VIGIE_ENV": "dev"}, REPO_ROOT / "tests" / "contract" / "veeam", "HORS du dépôt"),
    ],
)
def test_refuses_unsafe_runs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    env: dict[str, str],
    out: Path | None,
    message: str,
) -> None:
    script = _script()
    monkeypatch.delenv("VIGIE_ENV", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    argv = ["record_fixtures.py", "veeam", *(["--out", str(out)] if out else [])]
    monkeypatch.setattr(sys, "argv", argv)
    assert script.main() == 2
    assert message in capsys.readouterr().err


def test_compressed_responses_are_replayed_decoded() -> None:
    # NinjaOne compresse ses réponses (gzip) : la réponse recréée ne doit pas l'être deux fois.
    import gzip

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=gzip.compress(b'[{"id": 1}]'),
            headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
        )

    recorder = RecordingTransport(None, inner=httpx.MockTransport(handler))
    with httpx.Client(transport=recorder) as client:
        assert client.get("https://ninja.test/v2/organizations").json() == [{"id": 1}]
    assert recorder.saved["GET_v2_organizations.json"] == [{"id": 1}]


@pytest.mark.parametrize(
    ("pages", "expected"),
    [
        ([[{"id": 1}], [{"id": 2}]], [{"id": 1}, {"id": 2}]),  # liste brute (NinjaOne)
        (
            [{"cursor": {"name": "c"}, "results": [1]}, {"cursor": {}, "results": [2]}],
            {"cursor": {}, "results": [1, 2]},
        ),  # rapport à curseur (NinjaOne)
        (
            [
                {"data": {"affected_items": [1], "total_affected_items": 2}, "error": 0},
                {"data": {"affected_items": [2], "total_affected_items": 2}, "error": 0},
            ],
            {"data": {"affected_items": [1, 2], "total_affected_items": 2}, "error": 0},
        ),  # agents (Wazuh)
    ],
)
def test_all_page_shapes_are_accumulated(pages: list[object], expected: object) -> None:
    responses = iter(pages)
    recorder = RecordingTransport(
        None, inner=httpx.MockTransport(lambda r: httpx.Response(200, json=next(responses)))
    )
    with httpx.Client(transport=recorder) as client:
        for _ in pages:
            client.get("https://ninja.test/v2/organization/2/devices")
    assert recorder.saved["GET_v2_organization_2_devices.json"] == expected


def test_jsonrpc_results_named_by_method_and_url() -> None:
    from vigie.connectors.base import rpc_fixture_name

    assert rpc_fixture_name({"method": "problem.get", "params": {}}) == "problem.get.json"
    assert (
        rpc_fixture_name({"method": "get", "params": [{"url": "/eventmgmt/adom/root/alerts"}]})
        == "get_eventmgmt_adom_root_alerts.json"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "result": [{"status": {"code": 0}, "data": 1}]})

    recorder = RecordingTransport(None, inner=httpx.MockTransport(handler))
    with httpx.Client(transport=recorder) as client:
        client.post(
            "https://faz.test/jsonrpc",
            json={"id": 1, "method": "get", "params": [{"url": "/sys/status"}]},
        )
    assert recorder.saved == {"get_sys_status.json": [{"status": {"code": 0}, "data": 1}]}


def test_tls_per_origin_follows_the_source_settings(tmp_path: Path) -> None:
    from vigie.connectors.base import tls_by_origin

    settings = {
        "api_url": "https://wazuh.test:55000",
        "indexer_url": "https://wazuh.test:9200",
        "api_ca_bundle": str(tmp_path / "api.pem"),
        "indexer_ca_bundle": str(tmp_path / "idx.pem"),
        "verify_hostname": False,
    }
    assert tls_by_origin(settings) == {
        "wazuh.test:55000": (tmp_path / "api.pem", False),
        "wazuh.test:9200": (tmp_path / "idx.pem", False),
    }
    # Source à un seul hôte et bundle commun : transport par défaut.
    assert tls_by_origin({"base_url": "https://vbr.test:9419", "ca_bundle": "x.pem"}) == {}
    with pytest.raises(ValueError, match="seulement avec un bundle"):
        RecordingTransport(None, tls={"h:1": (None, False)})
