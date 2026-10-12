"""Enregistre les réponses réelles d'une source pour en faire des fixtures de contrat.

Usage (outil de développement, lancé par le coordinateur, hors du paquet `vigie`) :

    VIGIE_ENV=dev uv run python scripts/record_fixtures.py veeam [--out ~/vigie-raw/veeam]
    VIGIE_ENV=dev uv run python scripts/record_fixtures.py defender

- Passe par le connecteur et son `SafeClient` : l'allowlist s'applique, l'enregistrement est
  en lecture seule comme la collecte (healthcheck puis une collecte complète).
- Secret lu par `get_secret` (`.env.local` en dev) ; jamais écrit ni affiché.
- Écrit les réponses BRUTES hors du dépôt (`--out`, droits 0600) au format de
  `fixture_transport` ; la réponse du jeton est remplacée par un jeton factice.
- Les pages successives d'un même chemin sont fusionnées en une seule réponse.
Ensuite : `scripts/anonymize_fixtures.py OUT tests/contract/<source> --map MAP.json`, relecture
manuelle, README des fixtures, gitleaks.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vigie.config import SecretError, get_secret, load_config, resolve_config_path
from vigie.connectors import registry
from vigie.connectors.base import (
    ConnectorConfigError,
    ConnectorContext,
    RecordingTransport,
    SafeClient,
    SourceCallError,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", help="Nom de la source (ex. veeam).")
    parser.add_argument("--config", type=Path, default=None, help="vigie.toml (défaut habituel).")
    parser.add_argument("--out", type=Path, default=None, help="Dossier de sortie, hors dépôt.")
    args = parser.parse_args()

    if os.environ.get("VIGIE_ENV") != "dev":
        print("ERREUR lancer avec VIGIE_ENV=dev (secret lu dans .env.local)", file=sys.stderr)
        return 2
    out: Path = (args.out or Path.home() / "vigie-raw" / args.source).expanduser().resolve()
    repo = Path(__file__).resolve().parents[1]
    if out.is_relative_to(repo):
        print("ERREUR --out doit être HORS du dépôt (réponses non anonymisées)", file=sys.stderr)
        return 2

    cfg = load_config(resolve_config_path(args.config))
    if args.source not in cfg.sources:
        print(f"ERREUR section [sources.{args.source}] absente", file=sys.stderr)
        return 2
    settings = cfg.sources[args.source].model_dump()
    ca = settings.get("ca_bundle") or cfg.tls.ca_bundle
    transport = RecordingTransport(Path(ca).expanduser() if ca else None)
    context = ConnectorContext(
        settings=settings, secret=get_secret, ca_bundle=cfg.tls.ca_bundle, transport=transport
    )
    try:
        connector: Any = registry.load(args.source).from_context(context)
    except (ConnectorConfigError, SecretError) as exc:
        print(f"ERREUR {exc}", file=sys.stderr)
        return 2

    # 1. Sondage de chaque lecture de l'allowlist (1 élément), pour connaître les droits du compte.
    try:
        if hasattr(connector, "_login"):
            connector._login()
    except SourceCallError as exc:
        print(f"Authentification : ÉCHEC {exc}")
        return 1
    # Un client par hôte (Defender : API Defender et Graph), sinon `client`.
    clients = [
        c
        for c in (getattr(connector, n, None) for n in ("client", "mde", "graph"))
        if isinstance(c, SafeClient)
    ]
    print("Lectures autorisées par l'allowlist :")
    for call in connector.allowlist:
        path = call.literal_path
        if call.method != "GET" or path is None:
            continue
        params: dict[str, int] | None = None
        if {"skip", "limit"} <= call.query:
            params = {"skip": 0, "limit": 1}  # Veeam
        elif "pageSize" in call.query:
            params = {"pageSize": 1}  # NinjaOne
        elif "$top" in call.query:
            params = {"$top": 1}  # OData (Defender, Graph)
        client = next(c for c in clients if call in c._allowlist)
        try:
            client.get(path, params)
            print(f"  OK          GET {path}")
        except SourceCallError as exc:
            print(f"  HTTP {exc.status or '???'}    GET {path}")
    # Les sondes (1 élément) ne servent pas de fixtures pour ce que la collecte relit ; elles
    # restent pour le reste (ex. organisations, boards et statuts NinjaOne).
    probed = {n: v for n, v in transport.saved.items() if not n.startswith("POST_")}
    for name in probed:
        del transport.saved[name]

    # 2. Santé et collecte complète ; ce qui a été lu est enregistré même en cas d'échec.
    health = connector.healthcheck()
    print(f"Santé : {'OK' if health.ok else 'ÉCHEC'} {health.version} {health.detail}".rstrip())
    try:
        raw = list(connector.collect(datetime.now(UTC)))
        print(f"Collecte : {len(raw)} objet(s) signalé(s), tronquée : {connector.truncated}")
    except SourceCallError as exc:
        print(f"Collecte : ÉCHEC {exc} (réponses déjà lues enregistrées quand même)")
    for name, data in probed.items():
        transport.saved.setdefault(name, data)

    # Bilan par famille d'appels (identifiants numériques regroupés) : statuts et réponses vides.
    summary: dict[tuple[str, str, int], list[int]] = {}
    for method, path, status, size in transport.calls:
        family = re.sub(r"/[0-9]+(?=/|$)", "/{id}", path)
        summary.setdefault((method, family, status), []).append(size)
    print("Appels :")
    for (method, family, status), sizes in sorted(summary.items()):
        empty = sum(1 for s in sizes if s == 0)
        print(
            f"  {len(sizes):4d} × {method} {family} → HTTP {status}"
            + (f" ({empty} vides)" if empty else "")
        )

    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, data in sorted(transport.saved.items()):
        path = out / name
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        path.chmod(0o600)
        print(f"  {path}")
    print("Étape suivante : scripts/anonymize_fixtures.py (mapping hors dépôt), puis relecture.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
