"""Aucun secret, paramètre ni corps dans les journaux (SECURITY.md C7, SPEC §12)."""

import json
import logging
from collections.abc import Iterator

import httpx
import pytest
from pydantic import SecretStr

from tests.security.helpers import BASE_URL, Recorder, trapped_client
from tests.security.test_safeclient import ALLOWLIST
from vigie.connectors.base import ForbiddenCallError, SafeClient, SourceCallError
from vigie.logs import JsonFormatter, RedactingFilter, configure_logging

TOKEN = "fake-token-SHOULD-NOT-LEAK"
PARAM_VALUE = "param-value-should-not-leak"
BODY_VALUE = "body-value-should-not-leak"


class ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def dump(self) -> str:
        formatter = JsonFormatter()
        return "\n".join(formatter.format(r) for r in self.records)


@pytest.fixture
def captured() -> Iterator[ListHandler]:
    """Capture brute (sans filtre) : SafeClient ne doit même pas émettre ces valeurs."""
    configure_logging("DEBUG")
    handler = ListHandler()
    root = logging.getLogger()
    root.addHandler(handler)
    yield handler
    root.removeHandler(handler)


def test_safeclient_logs_contain_no_values(captured: ListHandler) -> None:
    responses = [
        httpx.Response(200, json={"echo": BODY_VALUE}),
        httpx.Response(503),
        httpx.Response(403, json={"detail": BODY_VALUE}),
    ]
    recorder = Recorder(*responses)
    c = SafeClient(
        source="test",
        base_url=BASE_URL,
        allowlist=ALLOWLIST,
        transport=recorder.transport(),
        sleep=lambda _: None,
    )
    c.set_auth_header("Authorization", SecretStr(f"Bearer {TOKEN}"))
    c.get("/api/v1/jobs/states", {"limit": PARAM_VALUE})
    with pytest.raises(SourceCallError):
        c.post("/api/oauth2/token", {"grant_type": "password", "username": BODY_VALUE})
    output = captured.dump()
    assert "appel source" in output
    assert '"limit"' in output  # nom du paramètre : oui
    for leaked in (TOKEN, PARAM_VALUE, BODY_VALUE):
        assert leaked not in output


def test_forbidden_call_logged_critical_without_body(captured: ListHandler) -> None:
    c = trapped_client(ALLOWLIST)
    with pytest.raises(ForbiddenCallError):
        c.post(
            "/api/oauth2/token", {"grant_type": "password", "username": "x", "password": BODY_VALUE}
        )
    critical = [r for r in captured.records if r.levelno == logging.CRITICAL]
    assert len(critical) == 1
    assert BODY_VALUE not in captured.dump()


def test_error_messages_contain_no_values() -> None:
    recorder = Recorder(httpx.Response(401, json={"detail": BODY_VALUE}))
    c = SafeClient(
        source="t", base_url=BASE_URL, allowlist=ALLOWLIST, transport=recorder.transport()
    )
    with pytest.raises(SourceCallError) as excinfo:
        c.get("/api/v1/jobs/states", {"limit": PARAM_VALUE})
    assert PARAM_VALUE not in str(excinfo.value)
    assert BODY_VALUE not in str(excinfo.value)


def test_httpx_url_logging_is_silenced() -> None:
    configure_logging("DEBUG")
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING


def _record(msg: str, **extra: object) -> logging.LogRecord:
    record = logging.LogRecord("vigie.test", logging.INFO, __file__, 1, msg, None, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_redacting_filter_masks_message_and_extra() -> None:
    record = _record(
        "échec password=%s", extra_field=f"token={TOKEN}", nested={"k": [f"Bearer {TOKEN}"]}
    )
    record.args = ("hunter2-secret",)
    RedactingFilter().filter(record)
    rendered = JsonFormatter().format(record)
    assert "hunter2-secret" not in rendered
    assert TOKEN not in rendered
    payload = json.loads(rendered)
    assert payload["msg"] == "échec password=<redacted>"
    assert payload["level"] == "INFO"


def test_exception_text_is_redacted() -> None:
    try:
        raise RuntimeError(f"api_key={TOKEN}")
    except RuntimeError:
        import sys

        record = logging.LogRecord("vigie", logging.ERROR, __file__, 1, "x", None, sys.exc_info())
    assert TOKEN not in JsonFormatter().format(record)


def test_invalid_level_falls_back_to_info() -> None:
    configure_logging("bavard")
    assert logging.getLogger().level == logging.INFO
    configure_logging("debug")
    assert logging.getLogger().level == logging.DEBUG
