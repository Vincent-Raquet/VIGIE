# Vigie — Connecteurs

Chaque connecteur respecte le contrat de `SPEC.md §6.1` et l'allowlist de `SECURITY.md C2`.

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

## 1. Zabbix 7.4
- **Auth** : token API (`Authorization: Bearer`) d'un utilisateur `svc-vigie` dans un groupe ayant un rôle de type *User* avec accès API limité aux méthodes en lecture (Zabbix 7.x : *API methods → Allow list*), et permissions **Read** sur les groupes d'hôtes supervisés.
- **Endpoint** : `POST {base}/api_jsonrpc.php` (JSON-RPC 2.0).
- **Allowlist** : `apiinfo.version`, `problem.get`, `event.get`, `trigger.get`, `host.get`, `hostgroup.get`, `item.get` (champs limités), `proxy.get`, `maintenance.get`.
- **Collecte** :
  - `problem.get` avec `recent=false`, `severities=[2,3,4,5]` (configurable), `selectTags`, `selectAcknowledges` → problèmes ouverts.
  - `host.get` pour résoudre hôte → groupes (mapping société par préfixe : `WI`, `SPL`, `WG`, `CC`, `FWD`) ; mise en cache 1 h.
  - `proxy.get` : proxy sans contact > 10 min → signal `monitoring`.
  - `maintenance.get` : hôtes en maintenance → signaux rétrogradés d'une priorité et marqués.
- **Catégorie** : déduite des tags du trigger (`component:network`, `class:os`…) et des groupes (`*-Réseau` → network, `SRV-Veeam` → backup, `Hypervisors` → server…) ; table dans `config/scoring.example.yaml`.
- **external_id** : `eventid` ; résolution quand le problème disparaît de `problem.get`.
- **Lien** : `{base}/zabbix.php?action=problem.view&filter_eventids[]={eventid}` ⚠️ vérifier le format en 7.4.

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

## 5. Veeam Backup & Replication (12.x / 13)
- **Auth** : `POST {base}:9419/api/oauth2/token` (grant `password`, exception documentée), en-tête `x-api-version` (ex. `1.2-rev0` ⚠️ selon version). Compte local `svc-vigie` avec le rôle **Veeam Backup Viewer** ⚠️ vérifier que ce rôle est accepté par l'API REST de la version installée ; sinon, utiliser le rôle minimal accepté, documenter, et compenser par l'allowlist. Si un serveur Veeam ONE existe, préférer son API (rôle *Read-Only User*).
- **Allowlist `GET`** : `/api/v1/serverInfo`, `/api/v1/jobs/states`, `/api/v1/sessions` (filtres `createdAfterFilter`, `resultFilter`), `/api/v1/backupInfrastructure/repositories/states`, `/api/v1/backups`, `/api/v1/malwareDetection/events` ⚠️ (v12.1+).
- **Interdits explicitement** (test dédié) : tout `POST` sauf token, notamment `/jobs/{id}/start|stop|retry|disable`, `/sessions/{id}/stop`.
- **Collecte** :
  - État de chaque job : dernier résultat, dernière exécution réussie, prochain lancement.
  - Repositories : capacité, espace libre.
  - Détections de malware éventuelles → `security` P1.
- **Règles** : voir SPEC §7.4 (> 24 h sans succès, 2 échecs consécutifs, repository > 90/95 %).
- **Mapping** : préfixe du nom de job (`WI-`, `SPL-`…) ou serveur VBR par société (plusieurs instances = plusieurs entrées de source `veeam:<nom>`).
- Plusieurs serveurs VBR : le connecteur est multi-instance (`[sources.veeam.instances]`).

## 6. Veezo
⚠️ Produit à identifier (question ouverte n° 1 de la SPEC). Le connecteur est créé comme **squelette désactivé** (`enabled=false`), avec healthcheck renvoyant « non configuré ». À compléter avec le skill `add-connector` dès que l'éditeur, la version et la documentation API sont connus.

## 7. Ajouter une source plus tard
Utiliser le skill `.claude/skills/add-connector`. Candidats évoqués : Microsoft 365 (Graph : santé des services, alertes Defender, licences — permissions `ServiceHealth.Read.All`, `SecurityAlert.Read.All`, `Organization.Read.All`, *application*, lecture seule), Synology (DSM API), iDRAC (Redfish GET), certificats (sonde TLS interne).

## 8. Comptes de service — récapitulatif à créer
| Source | Compte | Rôle / scope | Restriction réseau |
|---|---|---|---|
| Zabbix | `svc-vigie` + token | Rôle User, API allowlist `*.get`, groupes en Read | — (token) |
| FortiAnalyzer | `svc-vigie` (API admin) | Profil Read-Only | Trusted host = IP VM |
| NinjaOne | API client « Vigie » | `monitoring` (+ `management` seulement si requis pour tickets, technicien RO) | Allowed IP si disponible |
| Wazuh API | `svc-vigie` | Rôle `readonly` | Pare-feu manager |
| Wazuh indexer | `svc-vigie` | `vigie_read` (search sur 2 index) | Pare-feu indexer |
| Veeam B&R | `svc-vigie` (local) | Backup Viewer (⚠️) | Pare-feu Windows : 9419 depuis IP VM |
| Microsoft Graph | App « Vigie Mail » | `Mail.Send` (app) restreint à `itbot@…` | — |
| Entra SSO | App « Vigie » | OIDC, claims groupes | Accès conditionnel MFA |
| Anthropic | Clé workspace « vigie » | — | Limite de dépense mensuelle |
