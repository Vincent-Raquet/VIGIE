"""Liens vers les consoles des sources (SPEC F9, SECURITY.md C4).

Un lien n'est jamais fourni par une source ni par le LLM : il est construit ici à partir
de l'URL de base configurée (HTTPS) et d'identifiants **numériques** validés.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_NUMERIC = re.compile(r"^[0-9]{1,20}$")

# Gabarits par source et par jeu de paramètres. Zabbix 7.4 : TODO verify (CONNECTORS.md §1).
TEMPLATES: dict[str, list[tuple[frozenset[str], str]]] = {
    "zabbix": [
        (
            frozenset({"eventid", "triggerid"}),
            "/tr_events.php?triggerid={triggerid}&eventid={eventid}",
        ),
        (frozenset({"hostid"}), "/zabbix.php?action=problem.view&hostids%5B%5D={hostid}"),
        (frozenset({"proxyid"}), "/zabbix.php?action=proxy.list"),
    ],
}


def source_link(source: str, params: Mapping[str, Any], base_url: str | None) -> str | None:
    if not base_url or not base_url.startswith("https://"):
        return None
    values = {k: str(v) for k, v in params.items()}
    if not all(_NUMERIC.match(v) for v in values.values()):
        return None
    for keys, template in TEMPLATES.get(source, []):
        if keys == frozenset(values):
            return base_url.rstrip("/") + template.format(**values)
    return None
