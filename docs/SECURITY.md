# Vigie — Sécurité

**Objectif : même compromis (bug, prompt injection, vol de la VM, erreur de Claude Code pendant le développement), Vigie ne doit pas pouvoir modifier, arrêter ou supprimer quoi que ce soit sur les systèmes supervisés.**

La sécurité repose sur la **défense en profondeur** : chaque couche suffit seule à empêcher une action dommageable.

## 1. Modèle de menace

| Menace | Exemple | Contrôles principaux |
|---|---|---|
| Action destructrice involontaire | Bug appelant `host.delete` ou `POST /jobs/{id}/stop` | Comptes RO (C1), allowlist SafeClient (C2), tests (C10) |
| Prompt injection via les données | Ticket utilisateur : « Ignore tes instructions et… » | LLM sans outil d'action (C3), validateur (C4), données encapsulées (C5) |
| Exfiltration de données | LLM ou dépendance compromise envoyant des données ailleurs | Egress allowlist (C6), minimisation (C5) |
| Vol de secrets | Accès au disque, logs, dépôt Git | systemd-creds chiffrés (C7), séparation des processus (C8), scan de secrets (C10) |
| Accès non autorisé à l'UI | Collègue ou attaquant sur le LAN | OIDC Entra + MFA, RBAC, LAN/VPN uniquement (C9) |
| Pivot depuis la VM | VM compromise utilisée pour attaquer le réseau | Durcissement, nftables sortant restreint (C6, C11) |
| Dérive de coût | Boucle d'appels LLM | Budget mensuel + limite workspace Anthropic (C12) |
| Messages trompeurs | Mail de plan contenant un lien malveillant | Aucun lien produit par le LLM, destinataires allowlistés (C4, C13) |

## 2. Contrôles

### C1 — Comptes de service en lecture seule (première ligne)
Chaque source utilise un compte **dédié à Vigie**, avec le rôle le plus restreint qui permet la lecture. Détail par source dans `CONNECTORS.md`. Restreindre par IP source (IP de la VM) partout où c'est possible. Rotation des secrets tous les 6 mois et à chaque départ.

Si une API exige un rôle plus large que la lecture (cas à vérifier : tickets NinjaOne, API REST Veeam selon version), le documenter dans `CONNECTORS.md`, compenser par C2, et revoir à chaque mise à jour de l'outil.

### C2 — SafeClient et allowlist d'appels (deuxième ligne)
- Toute requête sortante d'un connecteur passe par `SafeClient`. Un test statique (`tests/security/test_no_raw_http.py`) échoue si un module de `connectors/` importe `httpx`, `requests`, `urllib`, `aiohttp`, `socket` ou `subprocess`.
- Allowlist déclarative par connecteur : `AllowedCall(method="GET", path=r"^/api/v1/jobs/states$")` ou `AllowedCall(jsonrpc="problem.get")`. Expressions ancrées, pas de jokers larges.
- JSON-RPC (Zabbix, FortiAnalyzer) : seule la méthode explicitement listée est acceptée ; pour Zabbix, uniquement des `*.get` + `apiinfo.version`.
- Les quelques POST de lecture nécessaires (authentification OAuth/JWT, recherche Wazuh Indexer `_search`, exécution de board NinjaOne, logsearch FortiAnalyzer) sont listés nommément avec justification en commentaire, et leurs corps sont validés par schéma.
- Appel refusé → `ForbiddenCallError`, journalisé en `CRITICAL`, signal `monitoring` P1 « Tentative d'appel non autorisé ».
- Contrôles de l'allowlist dès sa définition (`AllowedCall`) : chemins ancrés `^/…$` sans joker large (`.*`, `.+`) ; seules les méthodes HTTP `GET` et `POST` existent (PUT/PATCH/DELETE impossibles à déclarer) ; tout `POST` exige un schéma de corps strict (`extra="forbid"`) **et** une justification (`reason`) ; les méthodes JSON-RPC portant un verbe d'action (`create`, `update`, `delete`, `set`, `add`, `exec`, `acknowledge`, `mass*`…) exigent un `override_reason`.
- Contrôles à l'appel : chemin relatif sans `..`, `//`, encodage `%`, requête ou fragment ; noms de paramètres de requête listés ; le corps envoyé est celui **re-sérialisé par le schéma**, pas celui de l'appelant.
- Transport : HTTPS obligatoire et TLS non désactivable (CA interne configurable) ; **redirections refusées** (une redirection contournerait l'allowlist) ; environnement ignoré (`trust_env=False` : ni proxy ni `.netrc` implicites, proxy uniquement explicite) ; réponse bornée à 20 Mo ; journaux limités à source, méthode, chemin, noms de paramètres, statut et durée.

### C3 — LLM sans capacité d'action
- **Aucun outil** exposé au modèle : la réponse est une sortie structurée (`output_config.format`, schéma JSON du plan), donc purement déclarative ; un test vérifie que la requête ne contient ni `tools` ni `tool_choice`. Pas de MCP, pas d'outil bash, web ou fichier, pas d'Agent SDK en production.
- Budget mensuel vérifié avant chaque appel (majorant pessimiste) ; chaque appel est journalisé dans `llm_call` (modèle servi, jetons, coût, hash du prompt, issue, type d'erreur) — jamais le contenu du prompt ni de la réponse.
- Le contenu des sources ne peut pas refermer `<source_data>` (chevrons échappés dans le JSON) ; le validateur refuse tout lien, balise ou e-mail dans les textes du LLM.
- Le code n'exécute jamais, n'évalue jamais et n'interprète jamais comme commande un texte produit par le LLM.
- **Discussion avec l'IA** (`engine/chat.py`, panneau du plan du jour et de la fiche incident) : même principe, aucun outil ; la sortie structurée contient une réponse en Markdown et au plus 3 **propositions déclaratives** (`incident_priority`, `scoring_override`), validées (incident présent dans le contexte, règle d'override valide) puis enregistrées dans `chat_proposal` sans effet. Seul un **admin** les applique, par un clic, avec trace `chat_proposal_applied` dans `audit_log` ; une priorité appliquée est gardée par le moteur (`incident.manual_priority`) tant que l'incident reste ouvert, avec son propre calcul cité dans la raison. Le web n'a pas la clé : il dépose la question en base (`chat_message` en attente) et le service `vigie-chat` (compte `vigie-worker`, clé Anthropic seule) répond ; un déclencheur PostgreSQL interdit au rôle `vigie_web` d'insérer autre chose qu'une question en attente. Contexte figé à la première question, données dans `<source_data>` (chevrons échappés, tickets masqués, secrets masqués) ; « Réinitialiser le contexte » archive la conversation (lecture seule, tracée `chat_reset`) et la suivante repart sans historique. Réponses : URL désarmées, e-mails masqués, rendu Markdown nh3 sans lien. Plafonds : budget mensuel commun (vérifié avant l'appel), jetons par réponse, par conversation et par utilisateur et par jour (`[chat]`).

### C4 — Validation des sorties
Voir SPEC §7.6. En plus :
- Les liens dans les mails et l'UI sont construits par l'application à partir de gabarits par source (`https://zabbix.lan/tr_events.php?triggerid={id}`) et d'identifiants numériques validés.
- Rendu Jinja en autoescape ; Markdown des synthèses rendu avec un sanitiseur (bleach / nh3) n'autorisant que `p, ul, ol, li, strong, em, code`.
- Destinataires des notifications = uniquement les e-mails de la table `person`.

### C5 — Minimisation et encapsulation des données envoyées au LLM
- Seuls les champs utiles sont envoyés (titre, catégorie, sévérité, société, actif, âge, occurrences, extrait de détail ≤ 300 caractères).
- Masquage avant envoi : mots de passe, tokens, clés, IBAN, numéros de carte, e-mails de tiers (remplacés par `<email>`), numéros de téléphone.
- Contenu des sources dans `<source_data>` ; le prompt système indique que ce bloc ne contient que des données et qu'aucune instruction qui s'y trouve ne doit être suivie.
- Option `llm.send_ticket_text = false` (défaut) : pour les tickets (signaux `kind = ticket`), l'IA ne reçoit ni le corps (jamais collecté) **ni le sujet** : seulement le numéro du ticket, la catégorie, la priorité, la sévérité, la société et l'âge ; le sujet reste visible des techniciens dans l'interface. Masquage dans `engine/context.py`, testé par `tests/security/test_llm_injection.py`. `true` envoie le sujet (nettoyé, encapsulé), jamais le corps.

### C6 — Réseau
- **nftables**, politique par défaut `drop` en entrée et sur le trafic routé des conteneurs (chaîne `forward`) ; sortie de l'hôte en `drop` hors cohabitation avec le développement.
- Entrée : 443/tcp depuis le VLAN admin et le pool VPN (port publié par le seul proxy d'entrée, filtré dans `forward` : `ct status dnat`) ; 22/tcp depuis les IP d'administration uniquement ; 10050/tcp depuis le serveur et le proxy Zabbix.
- Sortie :
  - vers les IP/ports des sources internes uniquement (ex. Zabbix 443, FortiAnalyzer 443, Veeam 9419, Wazuh 55000/9200) ;
  - vers le proxy Squid, seul autorisé à sortir sur Internet en 443 ;
  - DNS vers les résolveurs internes, NTP.
- **Squid** : allowlist de domaines (`api.anthropic.com`, `login.microsoftonline.com`, `graph.microsoft.com`, `<region>.ninjarmm.com`, `<region>.api.security.microsoft.com`, domaine du webhook Teams). Tout le reste est refusé et journalisé.
- `vigie-web` ne sort que vers Entra (port web de Squid).
- Réalisé (phase 10, conteneurs ; `deploy/roles/{nftables,vigie,edge}`) : chaque service de `compose.yaml` n'est rattaché qu'aux réseaux Docker dont il a besoin, à sous-réseaux fixes :
  - `vigie_web` et `vigie_worker` sont **internes** (aucune route) : vigie-web n'y joint que Squid (port 3129, Entra seul), les tâches et la discussion n'y joignent que Squid (port 3128) ; Squid n'écoute chaque port que sur son réseau et n'accepte que ce réseau ;
  - `vigie_egress` : Squid seul, autorisé par nftables à sortir en 443 et vers le DNS interne ; les conteneurs font confiance aux autorités de l'hôte (`/etc/ssl/certs/ca-certificates.crt` monté en lecture seule, dont les certificats internes ajoutés) ;
  - `vigie_src_<source>` : un réseau par source interne, rattaché au seul conteneur de collecte de cette source ; nftables ne le laisse joindre que l'`ip:port` de la source, sans DNS (nom de la source déclaré dans le conteneur, `extra_hosts`) ; `vigie_jobs` (tests de source depuis le web) joint toutes les sources ;
  - `edge` : proxy d'entrée partagé (Caddy) et vigie-web à adresse fixe, qui ne peut ouvrir aucune connexion par ce réseau ; seul Caddy publie un port (443 sur l'IP de la VM) ;
  - migrations, purge, selfcheck et bris de glace : aucun réseau (`network_mode: none`), PostgreSQL par socket unix.
  Tout autre trafic d'un réseau de Vigie est rejeté et journalisé (`nft-vigie-drop`). La table `inet vigie` ne fait jamais `flush ruleset` (elle effacerait les règles de Docker). Les applications futures du serveur sortent librement depuis leurs ponts Docker tant qu'aucune règle ne les restreint. Vérifié par `tests/security/test_compose.py`.

### C7 — Secrets
- Stockés chiffrés avec `systemd-creds` (liés au TPM ou à la clé hôte). `vigie-creds.service` les déchiffre au démarrage en mémoire (`/run/vigie/creds`, tmpfs, 0700 root, effacé à l'arrêt de l'unité), un fichier 0400 par secret appartenant au seul compte qui le lit ; `compose.yaml` ne monte dans chaque conteneur (`/run/secrets`, lu par `$CREDENTIALS_DIRECTORY`) que les secrets de ce service.
- Jamais en variable d'environnement globale, jamais dans `/etc/vigie/vigie.toml`, jamais dans les logs (filtre de journalisation qui masque les motifs sensibles).
- Développement : `.env.local` dans `.gitignore`, valeurs factices dans `.env.example`.
- Pré-commit : `gitleaks` ; CI : `gitleaks` + `pip-audit`.
- Dépôt en production : `sudo vigie-secret set <nom>` (valeur sur l'entrée standard, `systemd-creds encrypt` → `/etc/credstore.encrypted/vigie.<nom>`) ; Ansible ne vérifie que leur présence et n'active les unités qu'une fois tous les secrets requis déposés. Aucun mot de passe de base : authentification peer + `pg_ident`.

### C8 — Séparation des privilèges
- Comptes système distincts : `vigie-web`, `vigie-worker`, `vigie-migrate` (migrations et sauvegardes), sans shell, sans sudo. Chaque conteneur tourne avec l'**UID** de son compte : PostgreSQL (hôte, partagé) l'identifie par l'authentification peer + `pg_ident` sur la socket unix montée ; `pg_hba` n'autorise sur la base `vigie` que ces comptes mappés (et `postgres`). Aucun mot de passe de base.
- Rôles PostgreSQL : `vigie_web` (CRUD sur tables de configuration et `task.status`, lecture du reste, INSERT seul sur `audit_log`), `vigie_worker` (écriture signaux, incidents, plans, `llm_call`), `vigie_migrate` (DDL, utilisé uniquement au déploiement).
- Durcissement de chaque conteneur (`compose.yaml`) : système de fichiers en lecture seule (`/tmp` en tmpfs), `cap_drop: [ALL]`, `no-new-privileges`, profil AppArmor `docker-default`, jamais root, jamais `privileged`, ni socket Docker, ni réseau ou PID de l'hôte, limites de mémoire et de processus ; seul `selfcheck` écrit sur l'hôte (`/var/lib/vigie/selfcheck`, lu par Zabbix). Les unités systemd qui lancent `docker compose` ne parlent qu'à la socket Docker (`RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`, aucune capacité).
- Répartition des secrets (`secrets:` de `compose.yaml`) : `web` → `web_session_key`, `entra_client_secret` ; `collect-<source>` → les seuls secrets de la source ; `plan`, `plan-requests` (« Générer le plan maintenant ») et `chat` (discussion avec l'IA) → `anthropic_api_key` seule, jamais un secret de source ; `notify` → `graph_certificate`, `teams_webhook_url` ; `jobs` (tests de source) → secrets des sources, jamais la clé IA ; housekeeping, selfcheck, migrate, Squid → aucun. Vérifié par `tests/security/test_compose.py` (rendu des gabarits Ansible).
- Tâches ponctuelles : un conteneur éphémère par exécution (`docker compose run --rm`), lancé par un timer systemd ; aucun ordonnanceur ne détient tous les secrets ni la socket Docker.

### C9 — Authentification et autorisation
- OIDC Entra ID (Authorization Code + PKCE), MFA imposé par accès conditionnel sur l'application.
- Rôles depuis les claims de groupes ; vérification côté serveur sur chaque route (décorateur `require_role`), tests d'autorisation par route.
- Sessions : cookie `Secure`, `HttpOnly`, `SameSite=Lax`, durée 8 h ; CSRF sur toutes les requêtes mutantes.
- Compte « bris de glace » local désactivé par défaut, activable uniquement en CLI sur le serveur (`vigie breakglass --enable --ttl 1h`), journalisé.
- En-têtes Caddy (proxy d'entrée partagé, `deploy/roles/edge`, AC interne reprise du Caddy natif) : HSTS, CSP stricte (`default-src 'self'`), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- Accès uniquement depuis le LAN / VPN ; pas de publication Internet.

### C10 — Tests de sécurité obligatoires (`tests/security/`)
- Chaque connecteur : un appel hors allowlist lève `ForbiddenCallError` sans aucune requête émise (transport simulé).
- Analyse statique : pas d'import réseau brut dans `connectors/`, pas d'`eval`, `exec`, `pickle`, `subprocess`, `os.system` dans `src/`.
- Prompt injection : fixtures de tickets malveillants → le plan reste valide, aucune tâche hors périmètre, aucun lien, aucune priorité override abaissée.
- Validateur : assignee inexistant, incident inventé, capacité dépassée → corrigé ou rejeté.
- Autorisation : chaque route testée pour chaque rôle.
- Masquage : un secret présent dans une fixture n'apparaît ni dans le prompt ni dans les logs.

### C11 — Durcissement de l'hôte
- Debian 13 minimale, `unattended-upgrades` (sécurité), redémarrage planifié si nécessaire hors fenêtre de génération.
- SSH : clés uniquement, `PermitRootLogin no`, `AllowUsers deploy`, algorithmes modernes ; `fail2ban` ou `sshguard`. Pendant la cohabitation avec le développement : `PermitRootLogin no` et sshguard appliqués, mais ni `AllowUsers` ni retrait du mot de passe (`ssh_disable_password_auth`) sans décision explicite, pour ne pas couper l'accès.
- `auditd` avec règles sur `/etc/vigie`, `/etc/credstore.encrypted`, `/srv/vigie`, `/srv/edge`, `/etc/docker`, exécutions de `sudo`.
- Docker (dépôt officiel) : `no-new-privileges` par défaut, journaux vers journald, `live-restore`, pas de `userland-proxy`. Le groupe `docker` équivaut à root : **aucun compte humain n'en est membre** ; le développement utilise Docker rootless (`docs/DEV.md`). Images reconstruites à chaque version (`--pull`) et l'image Squid chaque mois : `unattended-upgrades` ne couvre pas les conteneurs.
- AppArmor activé ; chrony ; journald persistant.
- Lynis : score ≥ 80 après déploiement.
- Supervision de la VM par Zabbix (agent2 en mode actif, PSK).

### C12 — Coûts
- Limite de dépense mensuelle sur le workspace Anthropic dédié (filet ultime).
- Garde-fou applicatif avant chaque appel (SPEC §7.6), maximum 3 appels LLM par génération de plan (1 + 2 tentatives).

### C13 — Notifications
- Graph : application avec `Mail.Send` application **limitée** à la boîte `itbot@…` via RBAC for Applications d'Exchange Online (ou Application Access Policy). Authentification par **certificat** (MSAL), secret `graph_certificate`.
- Envoi par `SafeClient` : Graph n'autorise que `POST /v1.0/users/{id de la boîte}/sendMail` (un destinataire, HTML, schéma strict) ; Teams n'autorise que le chemin exact du webhook et ses paramètres `api-version`, `sp`, `sv`, `sig`. Tout autre appel est refusé avant émission (tests).
- Webhook Teams : secret ; le message ne contient que le résumé chiffré et **un seul** lien vers Vigie, aucun détail de tâche.
- Destinataires : personnes **actives** de la table `person` uniquement ; mode rodage `draft_only` (défaut) : tout part au coordinateur.
- Textes des sources et de l'IA dans les messages : échappés et URL désarmées (`https[:]//`, `www[.]`) pour qu'aucun client de messagerie n'en fasse un lien ; les seuls liens sont construits par l'application (`vigie.links`).
- Journal `notify_sent` : canaux, nombres et issue, jamais d'adresse ni de contenu.

## 3. Pendant le développement avec Claude Code

> **Situation actuelle (décision du 2026-10-09)** : le développement se fait **sur la VM cible elle-même** (WI-SRV-VIGIE-01), sous le compte `nadmin` (sudo). Conséquences :
> - aucun secret de production n'est déposé sur la VM tant que Claude Code y travaille ; une clé Anthropic de dev (workspace séparé, faible plafond) sert à la phase 5 ;
> - `.claude/settings.json` doit interdire en plus le déchiffrement des credentials (`systemd-creds decrypt`) et demander confirmation pour `sudo` ;
> - dev (`~/projets/vigie`, conteneur rootless de `nadmin`, bases `vigie_dev`/`vigie_test`, port 8000) et prod (`/srv/vigie`, démon Docker système, base `vigie`) sont cloisonnés ; `nadmin` n'est pas membre du groupe `docker` (qui donnerait root et les secrets déchiffrés de la prod) ; voir `docs/DEV.md` ;
> - la phase 8 doit en tenir compte (SSH pour `nadmin`, sortie Internet de Claude Code via Squid, Ansible en `connection: local`) : à revoir explicitement avant d'y déposer les secrets réels.

- `.claude/settings.json` interdit la lecture des fichiers de secrets et demande confirmation pour `ssh`, `ansible-playbook`, `git push`, `scp`, `curl`/`wget`.
- Les tests n'appellent jamais les vraies sources : fixtures anonymisées uniquement.
- Les comptes de service de production ne sont pas utilisés depuis le poste de développement. Pour enregistrer des fixtures, utiliser un script dédié lancé manuellement par l'humain (`scripts/record_fixtures.py`, passant lui aussi par SafeClient), puis anonymiser.
- Ne pas donner à Claude Code d'accès MCP en écriture aux systèmes supervisés pendant ce projet.

## 4. Procédures
- **Pause d'urgence** : `sudo systemctl stop 'vigie-*.timer'` (et `sudo systemctl stop vigie-compose` pour l'interface et la discussion) ou bouton « Pause » dans l'UI.
- **Compromission suspectée** : arrêter les timers et `vigie-compose`, révoquer dans l'ordre la clé Anthropic, le secret Graph, les tokens des sources ; analyser `audit_log`, journald (dont `journalctl -t vigie-squid`, journal de Squid).
- **Rotation** : `sudo vigie-secret set <nom>` puis `sudo systemctl restart vigie-creds` (redéchiffre et redémarre les services permanents), procédure dans `deploy/README.md`.
