from importlib.metadata import EntryPoint

import pytest

from vigie.connectors import registry


def _fake_entry_points(group: str) -> list[EntryPoint]:
    assert group == registry.ENTRY_POINT_GROUP
    return [EntryPoint(name="demo", value="vigie.config:VigieConfig", group=group)]


def test_discovers_registered_connectors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "entry_points", _fake_entry_points)
    assert registry.available() == ["demo"]
    from vigie.config import VigieConfig

    assert registry.load("demo") is VigieConfig


def test_unknown_connector(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "entry_points", _fake_entry_points)
    with pytest.raises(registry.UnknownConnectorError):
        registry.load("absent")
