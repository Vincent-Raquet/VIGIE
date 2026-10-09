"""Découverte des connecteurs par entry points `vigie.connectors` (SPEC §6.1).

Un connecteur s'enregistre dans `pyproject.toml` :

    [project.entry-points."vigie.connectors"]
    zabbix = "vigie.connectors.zabbix:ZabbixConnector"

Le moteur et la CLI ne connaissent les sources que par ce registre ; ajouter un système
ne demande donc ni modification du moteur ni de `config.py`.
"""

from __future__ import annotations

from importlib.metadata import EntryPoint, entry_points

ENTRY_POINT_GROUP = "vigie.connectors"


class UnknownConnectorError(LookupError):
    """Aucun connecteur enregistré sous ce nom."""


def discover() -> dict[str, EntryPoint]:
    """Connecteurs installés, par nom, sans les importer."""
    return {ep.name: ep for ep in entry_points(group=ENTRY_POINT_GROUP)}


def available() -> list[str]:
    return sorted(discover())


def load(name: str) -> object:
    """Importe et retourne la classe du connecteur `name`."""
    try:
        ep = discover()[name]
    except KeyError as exc:
        raise UnknownConnectorError(name) from exc
    return ep.load()
