"""Graph et Teams : un seul appel autorisé chacun, rien d'autre n'est émis (SECURITY.md C13)."""

import json
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from tests.security.helpers import Recorder, assert_forbidden, trap_transport
from vigie.notify.graph_mail import GraphMailer, MailError, SendMailBody, graph_allowlist
from vigie.notify.teams_webhook import TeamsError, TeamsWebhook

SENDER = "0b6c3a6e-1111-4222-8333-444455556666"
WEBHOOK = (
    "https://prod-12.westeurope.logic.azure.com:443/workflows/0123456789abcdef0123456789abcdef"
    "/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=SECRETSIG"
)


def mailer(transport: httpx.BaseTransport) -> GraphMailer:
    return GraphMailer(SENDER, lambda: "fake-token", transport=transport)


def mail_body(**kw: Any) -> dict[str, Any]:
    body = {
        "message": {
            "subject": "Plan",
            "body": {"contentType": "HTML", "content": "<p>x</p>"},
            "toRecipients": [
                {"emailAddress": {"address": "giovanni@example.be", "name": "Giovanni"}}
            ],
        },
        "saveToSentItems": True,
    }
    body.update(kw)
    return body


def test_graph_allows_only_sendmail_of_the_sender() -> None:
    client = mailer(trap_transport()).client
    for path in (
        "/v1.0/me/sendMail",
        "/v1.0/users/ffffffff-1111-4222-8333-444455556666/sendMail",
        f"/v1.0/users/{SENDER}/messages",
        f"/v1.0/users/{SENDER}/mailFolders/inbox/messages",
        "/v1.0/users",
    ):
        assert_forbidden(lambda p=path: client.post(p, mail_body()))  # type: ignore[misc]
    assert_forbidden(lambda: client.get(f"/v1.0/users/{SENDER}/messages"))


@pytest.mark.parametrize(
    "body",
    [
        mail_body(extra=1),
        {**mail_body(), "message": {**mail_body()["message"], "bccRecipients": []}},
        {**mail_body(), "message": {**mail_body()["message"], "toRecipients": []}},
        {
            **mail_body(),
            "message": {
                **mail_body()["message"],
                "toRecipients": mail_body()["message"]["toRecipients"] * 2,
            },
        },
        {
            **mail_body(),
            "message": {**mail_body()["message"], "body": {"contentType": "Text", "content": "x"}},
        },
    ],
)
def test_graph_body_schema_is_strict(body: dict[str, Any]) -> None:
    client = mailer(trap_transport()).client
    assert_forbidden(lambda: client.post(f"/v1.0/users/{SENDER}/sendMail", body))


def test_graph_allowlist_needs_a_guid() -> None:
    with pytest.raises(ValueError):
        graph_allowlist("itbot@example.be")
    assert SendMailBody.model_json_schema()["additionalProperties"] is False


def test_graph_send_contract() -> None:
    rec = Recorder(httpx.Response(202))
    mailer(rec.transport()).send(
        "giovanni@example.be", "Giovanni", "[Vigie] Plan", "<p>Bonjour</p>"
    )
    [req] = rec.requests
    assert (req.method, req.url.host, req.url.path) == (
        "POST", "graph.microsoft.com", f"/v1.0/users/{SENDER}/sendMail",
    )  # fmt: skip
    assert req.headers["Authorization"] == "Bearer fake-token"
    sent = json.loads(req.content)
    assert sent["message"]["toRecipients"] == [
        {"emailAddress": {"address": "giovanni@example.be", "name": "Giovanni"}}
    ]
    assert sent["message"]["body"] == {"contentType": "HTML", "content": "<p>Bonjour</p>"}


def test_graph_errors_are_neutral() -> None:
    rec = Recorder(httpx.Response(403, json={"error": {"message": "secret detail"}}))
    with pytest.raises(MailError) as excinfo:
        mailer(rec.transport()).send("giovanni@example.be", "G", "S", "<p>x</p>")
    assert "HTTP 403" in str(excinfo.value) and "secret" not in str(excinfo.value)


def test_teams_webhook_contract_and_secrecy() -> None:
    rec = Recorder(httpx.Response(202))
    hook = TeamsWebhook(SecretStr(WEBHOOK), transport=rec.transport())
    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {"type": "AdaptiveCard"},
            }
        ],
    }
    hook.send(payload)
    [req] = rec.requests
    assert req.url.host == "prod-12.westeurope.logic.azure.com"
    assert req.url.path.endswith("/triggers/manual/paths/invoke")
    assert dict(req.url.params)["sig"] == "SECRETSIG"
    assert json.loads(req.content) == payload
    with pytest.raises(TeamsError) as excinfo:
        TeamsWebhook(SecretStr(WEBHOOK), transport=Recorder(httpx.Response(500)).transport()).send(
            payload
        )
    assert "SECRETSIG" not in str(excinfo.value)
    assert_forbidden(
        lambda: hook.client.post(
            hook.path, {"type": "message", "attachments": [], "x": 1}, hook.params
        )
    )
    assert_forbidden(lambda: hook.client.post("/workflows/other", payload, hook.params))


@pytest.mark.parametrize(
    "url",
    [
        WEBHOOK.replace("https://", "http://"),
        WEBHOOK.replace("/workflows/", "/admin/workflows/"),
        WEBHOOK + "&redirect=https://evil.test",
        "https://evil.test/hook",
    ],
)
def test_teams_rejects_unexpected_urls(url: str) -> None:
    with pytest.raises(TeamsError) as excinfo:
        TeamsWebhook(SecretStr(url), transport=trap_transport())
    assert "SECRETSIG" not in str(excinfo.value)


def test_powerplatform_url_format_is_accepted() -> None:
    url = (
        "https://abc.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/"
        "0123456789abcdef0123456789abcdef/triggers/manual/paths/invoke?api-version=1&sp=x&sv=1.0&sig=S"
    )
    TeamsWebhook(SecretStr(url), transport=trap_transport())


def test_pem_on_one_line_is_accepted() -> None:
    from vigie.notify.graph_mail import normalize_pem

    one_line = "-----BEGIN CERTIFICATE-----\\nAAA\\n-----END CERTIFICATE-----"
    expected = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
    assert normalize_pem(one_line) == expected
    assert normalize_pem("a\nb\n") == "a\nb\n"
