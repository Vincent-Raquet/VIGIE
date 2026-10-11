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

## 3. NinjaOne (`src/vigie/connectors/ninjaone.py`)
Référence : spécification officielle NinjaOne Public API 2.0 (2.0.9-draft, `https://app.ninjarmm.com/apidocs/NinjaRMM-API-v2.yaml`), instance **eu.ninjarmm.com**.
- **Auth** : app API « Vigie » en *client credentials* ; `POST /ws/oauth/token` en formulaire (`grant_type=client_credentials`, `client_id`, `client_secret`, **`scope=monitoring`** seul : schéma strict, `management`/`control` refusés avant envoi). La spécification n'indique pas le scope par opération : `monitoring` = lecture seule selon la doc « OAuth token configuration » ; **Confirmé par la capture réelle (2026-10-11)** : toutes les lectures, y compris `board/run`, passent avec `monitoring` seul.
- **Allowlist `GET`** : `/v2/organizations`, `/v2/organization/{id}/devices` (`pageSize`, `after`), `/v2/device/{id}` (fiche d'un appareil d'alerte absent des listes ; `PATCH` interdit) ; `/v2/alerts` (aucun paramètre) ; `/v2/queries/os-patches`, `/v2/queries/software-patches` (`pageSize`, `cursor`, `status`) ; `/v2/ticketing/trigger/boards`, `/v2/ticketing/statuses`.
- **Exception `POST` de lecture** : `/v2/ticketing/trigger/board/{id}/run` (l'API n'offre que POST), corps strict : `includeColumns` choisis dans une liste fermée (`id`, `summary`, `status`, `priority`, `severity`, `organization`, `clientId`, `type`, `createTime`, `lastUpdated` — jamais description, demandeur, contact), `pageSize` ≤ 100, `lastCursorId` ; ni filtre, ni recherche, ni tri (statuts filtrés localement).
- **Interdits** (`tests/security/test_ninjaone_allowlist.py`) : création, modification, commentaire de ticket, `GET /v2/ticketing/ticket/{id}` (corps), journal du ticket, contacts et utilisateurs finaux, reset/suppression d'alerte, scans et installations de patchs, scripts, organisations, installeurs, sauvegardes (NinjaOne Backup non utilisé), toute écriture.
- **Signaux** :
  - alertes : une par alerte ; au-delà de `aggregate_threshold` (5) alertes de même condition dans une organisation → un signal agrégé (nombre, exemples d'appareils). Gravité `CRITICAL/MAJOR/MODERATE/MINOR/NONE` → 5/4/3/2/1 (TODO verify, chaîne libre dans la spécification) ; catégorie : antivirus/BitLocker → `security`, CVSS/patch → `vulnerability`, `NMS_FIREWALL` → `firewall`, autres `NMS_*` → `network`, serveurs → `server`, sinon `endpoint` ;
  - patchs en échec (`patch_status`, `FAILED` par défaut ; TODO verify) agrégés par société et type (OS → 3, 4 si un patch CRITICAL ; logiciels → 2, 3 si CRITICAL) ;
  - tickets du board `ticket_board_id`, statuts `ticket_statuses` (noms affichés) : `user_support`, sévérité selon la priorité ; **titre conservé pour les techniciens mais jamais envoyé à l'IA** tant que `[llm] send_ticket_text = false` (attribut `kind = ticket`, masquage dans `engine/context.py`, testé).
- **Capture réelle (2026-10-11), écarts avec la spécification** : `includeColumns` **ignoré** — le board renvoie description, demandeur, technicien, d'où le filtrage des colonnes **dès réception** (testé) ; `clientId` vide (organisation par son nom) ; alertes sans objet `device` (`deviceId` seul) et gravité/priorité `NONE` (sévérité selon le type : espace disque 3, mémoire/CPU/activité disque 2) ; priorité des tickets `NONE` → sévérité 2. Fixtures : `tests/contract/ninjaone/` (réelles anonymisées) et `ninjaone_synthetic/`.
- **Réseau** : Internet via Squid (`proxy` de la source → port worker 3128 ; `eu.ninjarmm.com` dans `squid_worker_domains`).
- **Mapping société** : id d'organisation → règle `asset_rule` `org_id`.
- **Fixtures** : synthétiques (`tests/contract/ninjaone_synthetic`) ; capture réelle par `scripts/record_fixtures.py ninjaone`, qui relève aussi organisations, boards et statuts.

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
- **Auth** : `POST /api/oauth2/token`, corps **form-urlencoded** `grant_type=password`, `username`, `password` (exception documentée, appel anonyme, schéma strict `TokenRequest` : ni `refresh_token`, ni `vbr_token`) ; un jeton par collecte, pas de rafraîchissement. En-tête `x-api-version` sur chaque requête : `1.3-rev1` (13.0.1.180), `1.3-rev2` (13.1). Compte local `svcveeamvigie`, rôle **Backup Viewer** : jeton accordé (essai réel du 2026-10-11 sur le VBR de production, HTTP 200), contrairement à ce qu'annonçait le forum R&D ; accès confirmé à `jobs/states`, `sessions`, `repositories/states`, `malwareDetection/events` ; **`serverInfo` répond 403** (le healthcheck valide alors l'accès par `jobs/states`, sans version). Ne jamais élever le rôle sans décision du coordinateur.
- **Allowlist `GET`** (paramètres listés, rien d'autre) : `/api/v1/serverInfo` ; `/api/v1/jobs/states` (`skip`, `limit`) ; `/api/v1/sessions` (`skip`, `limit`, `createdAfterFilter`, `orderColumn`, `orderAsc`) ; `/api/v1/backupInfrastructure/repositories/states` (`skip`, `limit`) ; `/api/v1/malwareDetection/events` (`skip`, `limit`, `detectedAfterTimeUtcFilter` — TODO verify en 13.x).
- **Interdits** (`tests/security/test_veeam_allowlist.py`) : `jobs/{id}/start|stop|retry|disable|enable`, `sessions/{id}/stop`, `POST /api/v1/jobs`, `oauth2/logout`, toute écriture (PUT/DELETE/PATCH), `/api/v1/credentials`, `/api/v1/backups`, paramètres non listés.
- **Signaux** (instantané toutes les 30 min, catégorie `backup` sauf malware) :
  - job (hors désactivés) : dernier résultat Failed → 4 (5 si job critique : `asset_criticality` ≥ 1,2 par règle `job_prefix` ; 3 pour la rétention) ; Warning → 2 (3 si ≥ 2 de suite) ; aucun succès depuis > 24 h → 3 (4 si critique, seulement si `lastRun` est connu). Attributs `consecutive_failures`, `hours_since_last_success`, `asset_critical` (overrides `backup_two_failures`, `backup_no_success_24h`) ;
  - historique : sessions des `session_window_days` derniers jours, types de sauvegarde seulement (`JOB_SESSION_TYPES` : sauvegarde, copie, réplication, déport objet, configuration, rétention ; le reste — découverte, tests, conformité — est du bruit) ; regroupées par job (nom sans suffixe `(Full)`…) et par VM (`<job>\<VM> Backup`) ; les jobs absents de `jobs/states` (réplications, déports) sont signalés depuis leurs sessions ;
  - capture réelle VBR 13 (2026-10-11) : statuts `Enabled`/`Stopped`, jobs Proxmox en type `Unknown` sans `lastRun` ni sessions, `jobId` des sessions sans lien avec `jobs/states` — voir `tests/contract/veeam/README.md` ;
  - dépôt hors ligne (`isOnline: false`) → 4 ;
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
| NinjaOne | app API « Vigie » (client credentials) | `monitoring` seul (`management` uniquement sur décision si les tickets l'exigent) | Squid (`eu.ninjarmm.com`) ; secrets `ninjaone_client_id`, `ninjaone_client_secret` |
| Wazuh API | `svc-vigie` | Rôle `readonly` | Pare-feu manager |
| Wazuh indexer | `svc-vigie` | `vigie_read` (search sur 2 index) | Pare-feu indexer |
| Veeam B&R 13.1 | `svcveeamvigie` (local) | Backup Viewer (jeton confirmé 2026-10-11 ; GET à confirmer) | Pare-feu Windows : 9419 depuis 192.168.10.17 ; secret `veeam_password` |
| Microsoft Defender | App Entra « Vigie Defender » (certificat, sans secret client) | Application : `Vulnerability.Read.All`, `Machine.Read.All` (WindowsDefenderATP), `SecurityIncident.Read.All` (Graph) ; `SecurityAlert.Read.All` accordée mais non utilisée | Squid (`login.microsoftonline.com`, `graph.microsoft.com`, `eu.api.security.microsoft.com`) ; secret `defender_private_key` |
| Microsoft Graph | App « Vigie Mail » | `Mail.Send` (app) restreint à `itbot@…` | — |
| Entra SSO | App « Vigie » | OIDC, claims groupes | Accès conditionnel MFA |
| Anthropic | Clé workspace « vigie » | — | Limite de dépense mensuelle |

## 9. Microsoft Defender (`src/vigie/connectors/defender.py`)
Références officielles : *Microsoft Defender for Endpoint API* (« Get all vulnerabilities », « List vulnerabilities by machine and software », « List machines », « Supported Microsoft Defender for Endpoint query parameters », « Exposed APIs » — URL régionales), *Microsoft Graph v1.0 — List incidents*, *Microsoft identity platform — certificate credentials*.
- **Un seul tenant** (celui de la connexion web, `vigie_oidc.tenant_id`), app Entra « Vigie Defender ».
- **Auth par certificat, sans secret client** : assertion JWT PS256 signée par la clé privée (en-tête `x5t#S256`, `aud` = point de jeton, `exp` = +5 min), échangée par `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` (formulaire strict : `client_assertion_type` jwt-bearer, `grant_type=client_credentials`, `scope` = `https://api.securitycenter.microsoft.com/.default` **ou** `https://graph.microsoft.com/.default`, rien d'autre ; tenant fixé dans l'allowlist). Un jeton par audience **et par collecte** (pas de cache disque). MSAL n'est pas utilisé : il émettrait ses propres requêtes hors allowlist.
- **Le même certificat sert en dev et en prod** : certificat public `~/vigie-ca/defender.crt` (dev) copié par Ansible dans `/etc/vigie/ca/defender.crt` ; clé privée `~/vigie-ca/defender.key` lue par le connecteur en dev (`private_key_file`), secret `defender_private_key` (systemd-creds) en prod. Conséquence : une fuite de la clé du poste de dev compromet aussi la prod — protéger `~/vigie-ca` (0700) et renouveler aux deux endroits (`deploy/README.md`). Expiration surveillée : signal `monitoring` sous 30 jours (overrides `cert_21d` → P2, `cert_7d` → P1), avertissement de `vigie check`, indicateur selfcheck `cert.defender.days_left` (alerte Zabbix à créer : `< 30`, `= -1` illisible).
- **Allowlist `GET`** (OData limité à `$filter`, `$top`, `$skip` ; `$skiptoken` pour Graph) :
  - `https://eu.api.security.microsoft.com/api/vulnerabilities` (`$top` ≤ 8000) ;
  - `/api/vulnerabilities/machinesVulnerabilities` (`$top` ≤ 10 000, filtre sur `severity`) ;
  - `/api/machines` (`$top` ≤ 10 000 ; limites 100 appels/min, 1 500/h) ;
  - `https://graph.microsoft.com/v1.0/security/incidents` (`$filter` statut et gravité, `$top` ≤ 50, `@odata.nextLink` suivi seulement vers le même hôte et le même chemin ; `$select` non pris en charge → champs réduits **dès réception**).
  Régions possibles (`api_host`) : `api.`, `eu.`, `uk.`, `us.security.microsoft.com`.
- **Interdits** (`tests/security/test_defender_allowlist.py`) : actions de réponse sur les appareils (`isolate`, `unisolate`, `runAntiVirusScan`, `restrictCodeExecution`, `collectInvestigationPackage`, `offboard`), création d'indicateurs, commentaires et modification d'alertes ou d'incidents (`PATCH`), chasse avancée (`advancedqueries/run`, `runHuntingQuery`), utilisateurs connectés (`logonusers`), fiche d'appareil, fichiers, `$expand`/`$select`/`$orderby`, jeton pour un autre tenant, une autre audience ou avec `client_secret`.
- **Risque à l'échelle du tenant** : les permissions d'application `*.Read.All` donnent la lecture de **tous** les appareils, vulnérabilités et incidents du tenant, toutes sociétés confondues (aucune restriction par groupe d'appareils pour une app). C'est pourquoi la clé n'est jamais copiée ailleurs que dans `~/vigie-ca` et systemd-creds, que seule l'unité `vigie-collect@defender` (et `vigie-jobs` pour le test de connexion) la reçoit, et que l'allowlist ne contient que trois lectures. Aucune permission d'écriture (`Machine.Isolate`, `Ti.ReadWrite`, `SecurityIncident.ReadWrite.All`…) ne doit être accordée.
- **Signaux** :
  - **vulnérabilités** Critical et High, statut `RemediationRequired`/`PartialException`, appareils dont `osPlatform` commence par un préfixe de `os_platform_prefixes` (`Windows` : Linux → Wazuh, correctifs → NinjaOne). Regroupées **par CVE et par groupe d'appareils** (`rbacGroupName`), avec le nombre d'appareils, 10 exemples, les KB correctifs et les logiciels. **Analyse de criticité** : retenue si exploit public, vérifié ou en kit, ou appareil « valeur élevée » (`deviceValue = High`), ou critique avec EPSS ≥ `min_epss` ou détectée depuis moins de `new_days` jours ; triées par un score (CVSS + 4 × exploitée + 2 × exploit public + 3 × EPSS + 2 × équipement sensible + 1 si nouvelle + log₂(1 + appareils)) et limitées à `max_vulns_per_company` par groupe. Sévérité : Critical 4, High 3, **5** si exploitée et (critique ou équipement sensible). Overrides : `vuln_exploited_sensitive` → P1, `vuln_exploited` → P2 ;
  - **incidents** Defender XDR non résolus de gravité `high` (Graph n'a pas de gravité « critical » pour les incidents) → `security`, sévérité 5, sans société (un incident peut en toucher plusieurs) ;
  - **appareils inactifs** (`Inactive`, `NoSensorData`, `ImpairedCommunication`) depuis plus de `inactive_days` jours, agrégés par groupe d'appareils → `monitoring`, sévérité 2.
- **Minimisation** : jamais de noms d'utilisateurs, lignes de commande, chemins de fichiers, IP, description d'éditeur ni commentaires d'incident dans les signaux ; détails tronqués (1 000 caractères), noms d'appareils réduits au nom court.
- **Mapping société** : `hostgroup_prefix` sur le groupe d'appareils Defender, sinon `devname_prefix` sur le nom court, sinon `agent_group` sur une étiquette d'appareil. Règles d'exemple dans `config/companies.example.yaml`, **à confirmer à la capture** (TODO verify : noms réels des groupes d'appareils).
- **Doublons de vulnérabilités** : une source par périmètre (Windows → Defender, Linux → Wazuh, correctifs → NinjaOne), appliqué par chaque connecteur à la collecte (`config/scoring.example.yaml`). Évolution possible : corréler un patch NinjaOne en échec et une CVE Defender par le numéro de KB.
- **TODO verify** (première capture) : valeurs réelles de `healthStatus` et `deviceValue`, présence de `epss`, `exploitInKit` et `firstDetected` sur `/api/vulnerabilities` dans ce tenant, filtre `severity` accepté par `machinesVulnerabilities`, filtre `status ne 'resolved'` accepté par Graph.
- **Fixtures** : synthétiques (`tests/contract/defender_synthetic`, certificat et clé générés par les tests) ; capture réelle : `VIGIE_ENV=dev uv run python scripts/record_fixtures.py defender`.
