"""Anonymise des réponses JSON capturées avant de les committer comme fixtures de contrat.

Usage (outil de développement, hors du paquet `vigie`) :

    uv run python scripts/anonymize_fixtures.py RAW_DIR OUT_DIR --map MAP.json

`MAP.json` (à garder HORS du dépôt : il contient les vrais noms) :

    {"replace": {"vrai-nom": "srv-wi-01", ...}, "domains": ["exemple-interne.be"]}

Traitement de toutes les chaînes (clés comprises) :
- remplacements de `replace`, du plus long au plus court ;
- adresses IPv4 → 192.0.2.0/24 (TEST-NET-1), de façon stable ;
- e-mails → user@example.test ; sous-domaines de `domains` → example.test.
Échoue si un nom de `replace` ou un domaine subsiste dans la sortie : relire ensuite à la main.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


class Anonymizer:
    def __init__(self, replace: dict[str, str], domains: list[str]) -> None:
        self.replace = sorted(replace.items(), key=lambda kv: -len(kv[0]))
        self.domains = domains
        self._domain_re = (
            re.compile(
                r"\b(?:[A-Za-z0-9-]+\.)*(?:" + "|".join(re.escape(d) for d in domains) + r")\b",
                re.IGNORECASE,
            )
            if domains
            else None
        )
        self._ips: dict[str, str] = {}

    def _ip(self, m: re.Match[str]) -> str:
        ip = m.group(0)
        if ip.startswith("192.0.2."):
            return ip
        return self._ips.setdefault(ip, f"192.0.2.{len(self._ips) % 254 + 1}")

    def text(self, value: str) -> str:
        for real, fake in self.replace:
            value = value.replace(real, fake)
        value = _EMAIL_RE.sub("user@example.test", value)
        if self._domain_re is not None:
            value = self._domain_re.sub("example.test", value)
        return _IPV4_RE.sub(self._ip, value)

    def walk(self, data: Any) -> Any:
        if isinstance(data, str):
            return self.text(data)
        if isinstance(data, list):
            return [self.walk(x) for x in data]
        if isinstance(data, dict):
            return {self.text(k): self.walk(v) for k, v in data.items()}
        return data

    def leftovers(self, dumped: str) -> list[str]:
        lowered = dumped.lower()
        found = [real for real, _ in self.replace if real.lower() in lowered]
        found += [d for d in self.domains if d.lower() in lowered]
        return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("raw_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--map", type=Path, required=True, dest="map_path")
    args = parser.parse_args(argv)

    spec = json.loads(args.map_path.read_text(encoding="utf-8"))
    anonymizer = Anonymizer(spec.get("replace", {}), spec.get("domains", []))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    status = 0
    for src in sorted(args.raw_dir.glob("*.json")):
        data = anonymizer.walk(json.loads(src.read_text(encoding="utf-8")))
        dumped = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        left = anonymizer.leftovers(dumped)
        if left:
            print(f"ERREUR {src.name} : noms réels subsistants : {left}", file=sys.stderr)
            status = 1
            continue
        (args.out_dir / src.name).write_text(dumped, encoding="utf-8")
        print(f"{src.name} → {args.out_dir / src.name}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
