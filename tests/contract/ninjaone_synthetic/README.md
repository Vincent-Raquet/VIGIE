# Fixtures de contrat NinjaOne — synthétiques

Construites le 2026-10-11 d'après la spécification officielle NinjaOne Public API 2.0
(2.0.9-draft, `NinjaRMM-API-v2.yaml`), en attendant la capture réelle (`scripts/record_fixtures.py
ninjaone`, puis anonymisation). Heure de référence des tests : 2026-10-11T12:00:00Z.

| Objet | Cas couvert | Signal attendu |
|---|---|---|
| alerte disque sur `srv-wi-01` (MAJOR) | alerte simple, serveur | `server`, sévérité 4, WI |
| 6 × « Redémarrage en attente » (MINOR) sur des postes SPL | agrégation (seuil 5) | 1 signal `endpoint`, sévérité 2, SPL |
| menace antivirus (CRITICAL) sur `pc-spl-07` | sécurité | `security`, sévérité 5, SPL |
| `fw-wg-01` hors ligne (MAJOR, NMS_FIREWALL) | pare-feu | `firewall`, sévérité 4, WG |
| 3 patchs OS en échec sur `srv-wi-01` (dont un CRITICAL), 1 sur `pc-spl-01` | agrégation par société | WI sévérité 4, SPL sévérité 4 |
| 2 patchs logiciels en échec (impact HIGH) sur `pc-spl-02` | logiciels | SPL sévérité 2 |
| tickets 501 (Ouvert, HIGH), 502 (Fermé), 503 (En attente) | filtre de statuts | 501 sévérité 3 SPL, 503 sévérité 2 WI, 502 ignoré |

Les jetons sont factices ; aucun nom réel.
