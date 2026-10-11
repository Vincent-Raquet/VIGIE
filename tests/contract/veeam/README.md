# Fixtures de contrat Veeam B&R

**Synthétiques** (2026-10-11), en attendant les captures réelles (`scripts/record_fixtures.py veeam`,
puis `scripts/anonymize_fixtures.py`). Structure : modèles du swagger officiel 1.1-rev0
(`JobStatesResult`, `SessionsResult`, `RepositoryStatesResult`, `ServerInfoModel`, `TokenModel`) ;
les événements malware suivent le format attendu en 12.1+/13 (`TODO verify` sur capture réelle).

Heure de référence des tests : 2026-10-11T06:00:00Z.

| Objet | Cas couvert | Signal attendu |
|---|---|---|
| `SPL-FS01-Daily` | 2 échecs consécutifs, préfixe `SPL-` critique (1,3) | sévérité 5, `consecutive_failures` 2, société SPL |
| `WI-DC01-Daily` | 2 avertissements consécutifs | sévérité 3 |
| `WG-SQL01-Daily` | dernier succès il y a 52,5 h | sévérité 3, `hours_since_last_success` > 24 |
| `CC-Files-Daily`, `WI-Exchange-Hourly` | succès récent, session en cours ignorée | aucun |
| `FWD-Old-Archive` | job désactivé | aucun |
| `Repo-WI` 92 %, `SPL-Repo` 97 %, `Repo-Archive` 40 % | remplissage | sévérités 3, 4, aucun |
| malware `srv-wi-02` (Suspicious), `srv-wg-01` (Clean) | détection | `security` sévérité 5, aucun |

Les jetons du fichier `POST_api_oauth2_token.json` sont factices.
