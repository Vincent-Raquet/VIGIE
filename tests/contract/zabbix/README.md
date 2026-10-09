# Fixtures Zabbix 7.4

- `problem.get.json`, `trigger.get.json` : réponses réelles capturées le 2026-10-09 via le MCP
  de développement (74 problèmes de sévérité ≥ 2), anonymisées par
  `scripts/anonymize_fixtures.py` puis relues. Les noms de groupes sont conservés (préfixes
  société, utiles au rattachement) ; les noms d'hôtes, de VM et d'applications sont remplacés.
- Les triggers de 7 problèmes (sessions Veeam anciennes) sont absents de `trigger.get.json` :
  `monitored=true` les écarte côté Zabbix, ce qui teste l'élimination des problèmes périmés.
- Modification synthétique : `hvac-wg-01` (hostid 10756) est mis en maintenance
  (`maintenance_status = 1`), aucun hôte ne l'étant dans l'échantillon.
- `apiinfo.version.json`, `proxy.get.json` : synthétiques, conformes à la documentation 7.4
  (pas d'outil MCP pour ces méthodes). Heure de référence des tests : 1791563400
  (2026-10-09 16:30 UTC) ; proxy-wg-01 hors ligne, proxy-cc-01 muet depuis 30 min,
  proxy-fwd-01 jamais contacté (état inconnu, ignoré).
