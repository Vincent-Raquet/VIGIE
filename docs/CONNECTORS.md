# Vigie — Connecteurs

Chaque connecteur respecte le contrat de `SPEC.md §6.1` et l'allowlist de `SECURITY.md C2`.

## Forme d'une allowlist (`vigie.connectors.base.AllowedCall`)
```python
ALLOWLIST = [
    # REST en lecture ; `query` liste les noms de paramètres acceptés (aucun par défaut)
    AllowedCall(method="GET", path=r"^/api/v1/jobs/states$", query={"limit", "skip"}),
    # POST de lecture : schéma de corps strict (extra="forbid") ET justification obligatoires
    AllowedCall(method="POST", path=r"^/api/oauth2/token$", body_schema=TokenRequest,
                reason="authentification OAuth2, sans effet sur la configuration"),
    # JSON-RPC : nom exact, point d'entrée littéral, schéma des paramètres strict
    AllowedCall(jsonrpc="problem.get", endpoint="/api_jsonrpc.php",
                params_schema=ProblemGetParams),
    # Verbe d'action JSON-RPC : refusé sauf exception documentée
    AllowedCall(jsonrpc="add", endpoint="/jsonrpc", params_schema=LogSearchParams,
                override_reason="logsearch FAZ : crée une tâche de recherche, sans effet de config"),
]
```
Le `SafeClient` refuse les redirections : si une source redirige (HTTP → HTTPS, sous-chemin), corriger `base_url` dans la configuration. Pour un `params_schema` sous forme de liste (FortiAnalyzer), utiliser un `RootModel[list[Item]]` dont `Item` est strict.
Les tests de `tests/security/test_registered_connectors.py` s'appliquent automatiquement à tout connecteur enregistré ; les tests propres à un connecteur utilisent `tests/security/helpers.py` (`trapped_client`, `assert_forbidden`).

> **Règle de vérification** : les endpoints ci-dessous sont la cible fonctionnelle. Avant d'implémenter, Claude Code vérifie chaque endpoint, chaque scope et chaque rôle dans la documentation officielle **de la version installée** et marque `# TODO verify` ce qui ne peut pas être confirmé. Les points d'incertitude connus sont signalés par ⚠️.

## Sévérité normalisée (0–5)
| Vigie | Zabbix | FortiAnalyzer | NinjaOne | Wazuh (niveau) | Veeam |
|---|---|---|---|---|---|
| 5 critique | Disaster (5) | critical | CRITICAL | ≥ 13 | Failed (job critique) |
| 4 haute | High (4) | high | MAJOR | 10–12 | Failed |
| 3 moyenne | Average (3) | medium | MODERATE | 7–9 | Warning répétée (≥ 2) |
| 2 basse | Warning (2) | low | MINOR | 4–6 | Warning |
| 1 info | Information (1) | info | NONE | 1–3 | — |
| 0 non classé | Not classified (0) | — | — | 0 | — |

---

## 1. Zabbix 7.4 — implémenté (`vigie.connectors.zabbix`)
- **Auth** : token API (`Authorization: Bearer`, seule méthode en 7.4) d'un utilisateur `svc-vigie` dans un groupe ayant un rôle de type *User* dont l'accès API est limité par *API methods → Allow list* à `problem.get`, `trigger.get`, `proxy.get`, et permissions **Read** sur les groupes d'hôtes supervisés. Secret : `zabbix_api_token`.
- **Endpoint** : `POST {base}/api_jsonrpc.php` (JSON-RPC 2.0). Certificat vérifié par `[tls] ca_bundle` (AC interne).
- **Allowlist** (paramètres validés par des schémas stricts, champs `output` énumérés) :
  | Méthode | Usage |
  |---|---|
  | `apiinfo.version` | santé ; **appel anonyme** (la doc 7.4 la réserve aux utilisateurs non authentifiés) : `AllowedCall(anonymous=True)` n'envoie pas l'en-tête |
  | `problem.get` | problèmes ouverts : `source=0`, `object=0`, `severities ≥ min_severity`, `recent=false`, `selectTags`, `selectAcknowledges="count"`, borné à 5 000 (+1 pour détecter la troncature) |
  | `trigger.get` | hôte et groupes de chaque problème (`selectHosts`, `selectHostGroups`, `monitored=true`), lots de 500 ids |
  | `proxy.get` | `name`, `state` (0 inconnu, 1 hors ligne, 2 en ligne), `lastaccess` |

  `host.get`, `hostgroup.get`, `event.get`, `item.get`, `maintenance.get` ne sont **pas** nécessaires : `trigger.get` fournit hôte, groupes et `maintenance_status` (vérifié sur l'instance le 2026-10-09).
- **Collecte** : instantané des problèmes ouverts (`since` ignoré ; la résolution se déduit de la disparition, phase 4). Les problèmes dont le trigger, l'hôte ou l'item est désactivé (`monitored=true` ne les renvoie pas) sont écartés comme périmés — sur l'instance, environ la moitié des problèmes de sévérité ≥ 2.
- **Société** : règles `asset_rule` `hostgroup_prefix` sur chaque groupe de l'hôte (préfixe borné par un séparateur, insensible à la casse et aux accents, motif le plus long d'abord : `Switchs/WI`…). Plusieurs sociétés → aucune, mentionnées dans `details`.
- **Catégorie** : tags du problème d'abord (`Application:Veeam`/`target:veeam` → backup, `Application:VPN`/`scope:vpn` → network, `subclass:virtualization`, `class:os` → server…), puis mots des groupes (`category_by_group` dans `[sources.zabbix]`, défauts dans le code : `Réseau`/`Switchs`/`RUT` → network, `Serveurs`/`Hypervisors`/`IDRAC`/`(vm)` → server, `SRV-Veeam`/`Synology-NAS` → backup, `CAMERAS`/`Printer`/`atelier` → endpoint, `Zabbix servers` → monitoring) ; précédence network > backup > monitoring > endpoint > server ; défaut server.
- **Agrégation** : un hôte ayant plus de `aggregate_threshold` (8) problèmes de sévérité ≤ 3 donne un seul signal « N problèmes ouverts sur <hôte> » (`external_id = host:<hostid>:agg`, titres regroupés dans `details`) ; les sévérités 4–5 restent individuelles.
- **Maintenance** : hôte en maintenance ou problème supprimé → sévérité abaissée d'un niveau (min. 1) et mention dans `details`.
- **Proxy** : `state = 1` ou `lastaccess` plus vieux que `proxy_stale_min` (10 min) → signal `monitoring`, sévérité 4, `external_id = proxy:<proxyid>`.
- **external_id** : `eventid`. `url_template_params` : `{eventid, triggerid}`.
- **Lien** : `{base}/tr_events.php?triggerid={triggerid}&eventid={eventid}` — `# TODO verify` en 7.4 (alternative `zabbix.php?action=problem.view&filter_eventids[]={eventid}`).
- **Fixtures** : `tests/contract/zabbix/` (réelles anonymisées, cf. README du dossier).

## 2. FortiAnalyzer
- **Auth** : administrateur API REST `svc-vigie` avec profil **Read-Only** (« Restricted_User » ou profil personnalisé tout en lecture), *Trusted Hosts* limités à l'IP de la VM, clé API (Bearer). ⚠️ Selon la version (7.2/7.4/7.6), l'authentification par clé API ou par session (`sys/login/user`) diffère : vérifier.
- **Endpoint** : `POST {base}/jsonrpc`.
- **Allowlist** (champ `method` JSON-RPC + préfixe `url`) :
  - `get` sur `/sys/status`, `/dvmdb/adom/{adom}/device`, `/eventmgmt/adom/{adom}/alerts`, `/incidentmgmt/adom/{adom}/incidents` (si FortiSOC).
  - Exception documentée : `add` sur `/logview/adom/{adom}/logsearch` (création d'une tâche de recherche, sans effet sur la configuration) et `get` du résultat, `delete` **interdit**. N'activer que si les alertes d'event management ne suffisent pas.
- **Collecte** : alertes d'event management non acquittées des 24 dernières heures ; état des appareils (connexion FortiGate ↔ FAZ, HA) ; VPN : événements `vpn` tunnel-down sur la période.
- **Mapping société** : ADOM ou nom d'appareil (`devname` préfixé).
- **Catégories** : `firewall`, `network` (VPN, SD-WAN), `security` (IPS, AV, botnet).

## 3. NinjaOne
- **Auth** : API client *Client Credentials* dans NinjaOne (Administration → Apps → API), scope **`monitoring`** (lecture). Token sur `POST https://{region}.ninjarmm.com/ws/oauth/token`. ⚠️ La lecture des tickets peut nécessiter le scope `management` : si c'est le cas, créer un client distinct, l'associer à un technicien dont le rôle est limité à la lecture, et s'appuyer sur l'allowlist.
- **Allowlist** (`GET` sauf mention) :
  - `/v2/alerts` — alertes actives (conditions).
  - `/v2/organizations`, `/v2/devices` (champs limités) — mapping organisation → société.
  - `/v2/queries/os-patches` et `/v2/queries/software-patches` (statut `FAILED`/`PENDING` approuvés) — patchs manquants.
  - `/v2/queries/antivirus-threats`, `/v2/queries/antivirus-status`.
  - `/v2/queries/backup/jobs` — si NinjaOne Backup est utilisé.
  - Vulnérabilités : ⚠️ endpoint du module *Vulnerability Management* à confirmer dans la doc API de l'instance.
  - Tickets : `GET /v2/ticketing/trigger/boards`, puis **exception documentée** `POST /v2/ticketing/trigger/board/{id}/run` (la liste des tickets d'un board s'obtient en POST ; corps validé : uniquement `pageSize`, `lastCursorId`, `sortBy`, filtres) ⚠️ vérifier ; `GET /v2/ticketing/ticket/{id}` pour le détail.
- **Collecte** : alertes ouvertes ; tickets ouverts (sujet, statut, priorité, sévérité, organisation, assigné, âge, dernière mise à jour) — **pas le corps** par défaut (`SECURITY.md C5`) ; agrégats patchs/vulnérabilités par société (un signal par société et catégorie, pas un par poste, pour éviter le bruit : « 34 postes WG avec patchs critiques manquants > 14 j »).
- **Catégories** : `user_support` (tickets), `endpoint`, `vulnerability`, `backup`, `server` (selon rôle de l'appareil).
- **Mapping société** : `organizationId` → code société (table `asset_rule`).

## 4. Wazuh (4.x)
- **Deux API** :
  1. Wazuh server API (`https://{manager}:55000`) : JWT via `POST /security/user/authenticate` (exception documentée) avec un utilisateur affecté au rôle **`readonly`**.
     Allowlist `GET` : `/agents` (filtres `status=disconnected,never_connected`), `/agents/summary/status`, `/manager/status`, `/cluster/healthcheck`.
  2. Wazuh indexer (`https://{indexer}:9200`) : utilisateur interne avec rôle personnalisé `vigie_read` (`indices:data/read/search` sur `wazuh-alerts-*` et `wazuh-states-vulnerabilities-*` uniquement).
     Allowlist : `POST /wazuh-alerts-*/_search` et `POST /wazuh-states-vulnerabilities-*/_search` (corps validé : requête, agrégations, `size` ≤ 500). ⚠️ Noms d'index selon version (4.8+ pour les états de vulnérabilités).
- **Collecte** : alertes de niveau ≥ 10 sur les 24 h (agrégées par règle et agent) ; agents déconnectés > 1 h ; vulnérabilités Critical/High agrégées par société.
- **Mapping** : groupe d'agent Wazuh ou préfixe de nom d'agent.
- **Catégories** : `security`, `vulnerability`, `monitoring` (agents).

## 5. Veeam Backup & Replication 13.1 (`src/vigie/connectors/veeam.py`)
- **Auth** : `POST /api/oauth2/token`, corps **form-urlencoded** `grant_type=password`, `username`, `password` (exception documentée, appel anonyme, schéma strict `TokenRequest` : ni `refresh_token`, ni `vbr_token`) ; un jeton par collecte, pas de rafraîchissement. En-tête `x-api-version` sur chaque requête : `1.3-rev1` (13.0.1.180), `1.3-rev2` (13.1). Compte local `svcveeamvigie`, rôle **Backup Viewer** : jeton accordé (essai réel du 2026-10-11 sur le VBR de production, HTTP 200), contrairement à ce qu'annonçait le forum R&D ; l'accès de ce rôle à chacun des 5 GET reste à confirmer par la première capture (`scripts/record_fixtures.py`). Ne jamais élever le rôle sans décision du coordinateur.
- **Allowlist `GET`** (paramètres listés, rien d'autre) : `/api/v1/serverInfo` ; `/api/v1/jobs/states` (`skip`, `limit`) ; `/api/v1/sessions` (`skip`, `limit`, `createdAfterFilter`, `orderColumn`, `orderAsc`) ; `/api/v1/backupInfrastructure/repositories/states` (`skip`, `limit`) ; `/api/v1/malwareDetection/events` (`skip`, `limit`, `detectedAfterTimeUtcFilter` — TODO verify en 13.x).
- **Interdits** (`tests/security/test_veeam_allowlist.py`) : `jobs/{id}/start|stop|retry|disable|enable`, `sessions/{id}/stop`, `POST /api/v1/jobs`, `oauth2/logout`, toute écriture (PUT/DELETE/PATCH), `/api/v1/credentials`, `/api/v1/backups`, paramètres non listés.
- **Signaux** (instantané toutes les 30 min, catégorie `backup` sauf malware) :
  - job (hors désactivés) : dernier résultat Failed → 4 (5 si job critique : `asset_criticality` ≥ 1,2 par règle `job_prefix`) ; Warning → 2 (3 si ≥ 2 de suite) ; aucun succès depuis > 24 h → 3 (4 si critique). Attributs `consecutive_failures`, `hours_since_last_success`, `asset_critical` (overrides `backup_two_failures`, `backup_no_success_24h`) ; historique lu dans les sessions des `session_window_days` derniers jours (TODO verify : la session porte le nom du job) ;
  - dépôt > 85 % → 2, > 90 % → 3, > 95 % → 4, attribut `repo_used_pct` (overrides `repo_90`, `repo_95`) ;
  - détection malware (`Suspicious`, `Infected` ; TODO verify des valeurs en 13.x) → `security`, sévérité 5.
- **Société** : préfixe du nom de job ou de dépôt (`asset_rule` `job_prefix` : `WI-`, `SPL-`…).
- **Certificat** : le VBR présente un certificat auto-signé ; `ca_bundle` propre à la source (`/etc/vigie/ca/veeam.pem`), vérification TLS toujours active ; l'URL utilise le nom porté par le certificat.
- **Un seul serveur VBR** : configuration à plat `[sources.veeam]` (`base_url`, `username`, `api_version`, `ca_bundle`, `session_window_days`) ; un second serveur demanderait une seconde source.
- **Fixtures** : synthétiques d'après le swagger officiel 1.1-rev0 ; captures réelles avec `VIGIE_ENV=dev uv run python scripts/record_fixtures.py veeam` (sortie hors dépôt, jeton remplacé), puis `scripts/anonymize_fixtures.py`.

## 6. Veezo
⚠️ Produit à identifier (question ouverte n° 1 de la SPEC). Le connecteur est créé comme **squelette désactivé** (`enabled=false`), avec healthcheck renvoyant « non configuré ». À compléter avec le skill `add-connector` dès que l'éditeur, la version et la documentation API sont connus.

## 7. Ajouter une source plus tard
Utiliser le skill `.claude/skills/add-connector`. Candidats évoqués : Microsoft 365 (Graph : santé des services, alertes Defender, licences — permissions `ServiceHealth.Read.All`, `SecurityAlert.Read.All`, `Organization.Read.All`, *application*, lecture seule), Synology (DSM API), iDRAC (Redfish GET), certificats (sonde TLS interne).

## 8. Comptes de service — récapitulatif à créer
| Source | Compte | Rôle / scope | Restriction réseau |
|---|---|---|---|
| Zabbix | `svc-vigie` + token | Rôle User, API allowlist `problem.get`, `trigger.get`, `proxy.get`, groupes en Read | — (token) |
| FortiAnalyzer | `svc-vigie` (API admin) | Profil Read-Only | Trusted host = IP VM |
| NinjaOne | API client « Vigie » | `monitoring` (+ `management` seulement si requis pour tickets, technicien RO) | Allowed IP si disponible |
| Wazuh API | `svc-vigie` | Rôle `readonly` | Pare-feu manager |
| Wazuh indexer | `svc-vigie` | `vigie_read` (search sur 2 index) | Pare-feu indexer |
| Veeam B&R 13.1 | `svcveeamvigie` (local) | Backup Viewer (jeton confirmé 2026-10-11 ; GET à confirmer) | Pare-feu Windows : 9419 depuis 192.168.10.17 ; secret `veeam_password` |
| Microsoft Graph | App « Vigie Mail » | `Mail.Send` (app) restreint à `itbot@…` | — |
| Entra SSO | App « Vigie » | OIDC, claims groupes | Accès conditionnel MFA |
| Anthropic | Clé workspace « vigie » | — | Limite de dépense mensuelle |
