# Fixtures synthétiques Wazuh 4.12

Réponses écrites d'après la documentation officielle (spec de l'API du manager 4.14.9,
documents d'exemple de l'indexer), en attendant la capture réelle. Heure de référence des tests : 2026-10-23 06:00 UTC.
Agents génériques (`srv-wi-01`…), aucun nom, IP ni jeton réel.

| Objet | Cas couvert | Signal attendu |
|---|---|---|
| Agent 000 `wazuh-manager` | le manager lui-même | aucun |
| Agents 002, 009 (`spl`) | déconnectés depuis 3 h et 5 h (dernier contact `lastKeepAlive`) | `agents:disconnected` SPL, sévérité 3, 2 agents |
| Agent 003 (`wg`) | déconnecté depuis 30 min | aucun (sous `disconnected_hours`) |
| Agent 004 (`cc`, Windows) | jamais connecté | `agents:never` CC, sévérité 2 |
| Agent 005 (`fwd`) | déconnecté depuis 45 jours | `agents:stale` FWD, sévérité 1 |
| Agent 008 (`default` seul) | aucune société | aucun signal propre |
| Agent 010 (`wi` et `spl`) | deux sociétés | alerte sans société |
| Règle 5712 niveau 10 | brute force SSH sur 001 et 010 | 2 alertes, sévérité 4 |
| Règle 100200 niveau 13 | description hostile (balises, injection) sur 002 | alerte SPL, sévérité 5, override `wazuh_level12` |
| CVE-2026-0001 Critical | agents 001, 006 (WI) et 002 (SPL) | une CVE par société, sévérité 4 |
| CVE-2026-0003 High | agent 001 | WI, sévérité 3 (écartée si `max_vulns_per_company = 1`) |
| CVE-2026-0002 High | agent 007 Windows | aucune (Windows → Defender) |
| CVE-2026-0004 Critical | agent 099 inconnu du manager | aucune |
