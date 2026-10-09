"""Outils réutilisés par les tests d'allowlist de chaque connecteur (skill add-connector)."""

from collections.abc import Callable, Sequence
from typing import Any

import httpx
import pytest

from vigie.connectors.base import AllowedCall, ForbiddenCallError, SafeClient

BASE_URL = "https://source.test"


def trap_transport() -> httpx.MockTransport:
    """Transport qui fait échouer le test si une requête est émise."""

    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail(
            f"requête émise alors qu'elle devait être refusée : {request.method} {request.url.path}"
        )

    return httpx.MockTransport(handler)


def trapped_client(allowlist: Sequence[AllowedCall], source: str = "test") -> SafeClient:
    return SafeClient(
        source=source, base_url=BASE_URL, allowlist=allowlist, transport=trap_transport()
    )


def assert_forbidden(call: Callable[[], Any]) -> ForbiddenCallError:
    """L'appel lève ForbiddenCallError (et, avec trapped_client, n'émet rien)."""
    with pytest.raises(ForbiddenCallError) as excinfo:
        call()
    return excinfo.value


class Recorder:
    """Transport qui enregistre les requêtes et rejoue des réponses."""

    def __init__(self, *responses: httpx.Response) -> None:
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        request.read()
        self.requests.append(request)
        if not self.responses:
            pytest.fail("aucune réponse préparée")
        return self.responses.pop(0)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)
