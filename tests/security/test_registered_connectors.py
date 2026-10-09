"""S'applique automatiquement à chaque connecteur enregistré (entry points vigie.connectors)."""

from importlib.metadata import EntryPoint
from typing import Any

import pytest

from tests.security.helpers import assert_forbidden, trapped_client
from vigie.connectors import registry
from vigie.connectors.base import AllowedCall


def _allowlist(name: str) -> list[AllowedCall]:
    connector: Any = registry.load(name)
    allowlist = getattr(connector, "allowlist", None)
    assert allowlist, f"{name} : allowlist absente ou vide"
    assert all(isinstance(c, AllowedCall) for c in allowlist)
    return list(allowlist)


def check_allowlist_well_formed(name: str) -> None:
    for call in _allowlist(name):
        if call.method == "POST":
            assert call.reason.strip(), f"{name} : POST {call.path} sans justification"


def check_destructive_probes_refused(name: str) -> None:
    client = trapped_client(_allowlist(name), source=name)
    assert_forbidden(lambda: client.post("/__vigie_probe__/delete", {}))
    assert_forbidden(lambda: client.get("/__vigie_probe__"))
    for method in ("host.delete", "event.acknowledge", "exec", "set", "delete"):
        assert_forbidden(lambda m=method: client.jsonrpc(m, {}))  # type: ignore[misc]


@pytest.mark.parametrize("name", registry.available())
def test_allowlist_is_well_formed(name: str) -> None:
    check_allowlist_well_formed(name)


@pytest.mark.parametrize("name", registry.available())
def test_destructive_probes_refused_without_request(name: str) -> None:
    check_destructive_probes_refused(name)


class FakeConnector:
    name = "fake"
    allowlist = (AllowedCall(method="GET", path=r"^/api/v1/items$"),)


def test_checks_apply_to_a_registered_connector(monkeypatch: pytest.MonkeyPatch) -> None:
    ep = EntryPoint(name="fake", value=f"{__name__}:FakeConnector", group="vigie.connectors")
    monkeypatch.setattr(registry, "entry_points", lambda group: [ep])
    assert registry.available() == ["fake"]
    check_allowlist_well_formed("fake")
    check_destructive_probes_refused("fake")


def test_connector_without_allowlist_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    ep = EntryPoint(name="bad", value="vigie.config:VigieConfig", group="vigie.connectors")
    monkeypatch.setattr(registry, "entry_points", lambda group: [ep])
    with pytest.raises(AssertionError, match="allowlist absente"):
        check_allowlist_well_formed("bad")
