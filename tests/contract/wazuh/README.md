# Capture réelle Wazuh 4.14.4 (2026-10-23)

- Instance : OVA tout-en-un, manager 4.14.4 (API `rc2`), indexer sur le même hôte.
- Comptes : `svc-vigie` côté API (rôle `readonly`) et côté indexer (rôle `vigie_read`,
  `indices:data/read/search` sur `wazuh-alerts-4.x-*` et `wazuh-states-vulnerabilities-*`).
- Capture : `VIGIE_ENV=dev uv run python scripts/record_fixtures.py wazuh` (JWT remplacé par
  `fixture-jwt`), puis `scripts/anonymize_fixtures.py` : 3 noms de serveurs et le nom du manager
  remplacés (`srv-spl-01`, `srv-spl-02`, `srv-fs-01`, `wazuh-manager`), aucune IP ni adresse
  dans les réponses ; identifiants de documents OpenSearch conservés (aléatoires).
- Heure de référence des tests : 2026-10-23 14:10 UTC.

Constats :
- 4 agents, tous actifs : le manager (`000`, Amazon Linux, sans groupe) et 3 serveurs Windows,
  tous dans le seul groupe `default` → aucune société.
- Champs d'agent renvoyés : `id`, `name`, `status`, `group`, `lastKeepAlive`, `os`
  (`disconnection_time` n'existe pas) ; `lastKeepAlive` du manager : `9999-12-31T23:59:59+00:00`.
- Alertes : index quotidiens `wazuh-alerts-4.x-AAAA.MM.JJ` (303 shards, 297 sautés),
  `timestamp` au format `2026-10-23T14:07:47.080+0000` ; 5 règles de niveau ≥ 10 sur 24 h
  (60204, 60205, 61061, 61110, et 204 « Agent event queue is flooded », niveau 12, à
  l'installation des agents), 12 couples règle × agent.
- Vulnérabilités : index `wazuh-states-vulnerabilities-wazuh-server` ; sévérités `Critical` et
  `High` ; 1 203 documents Critical/High, tous sur les serveurs Windows (Defender), aucun sur le
  manager. Sans filtre sur les agents Linux, l'agrégation saturait à 500 CVE (collecte
  tronquée) : la requête filtre désormais `agent.id` sur les agents Linux.
