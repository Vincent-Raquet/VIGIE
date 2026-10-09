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

### C3 — LLM sans capacité d'action
- Un seul outil exposé au modèle : `submit_plan`, purement déclaratif. Pas de MCP, pas d'outil bash, web ou fichier, pas d'Agent SDK en production.
- Le code n'exécute jamais, n'évalue jamais et n'interprète jamais comme commande un texte produit par le LLM.

### C4 — Validation des sorties
Voir SPEC §7.6. En plus :
- Les liens dans les mails et l'UI sont construits par l'application à partir de gabarits par source (`https://zabbix.lan/tr_events.php?triggerid={id}`) et d'identifiants numériques validés.
- Rendu Jinja en autoescape ; Markdown des synthèses rendu avec un sanitiseur (bleach / nh3) n'autorisant que `p, ul, ol, li, strong, em, code`.
- Destinataires des notifications = uniquement les e-mails de la table `person`.

### C5 — Minimisation et encapsulation des données envoyées au LLM
- Seuls les champs utiles sont envoyés (titre, catégorie, sévérité, société, actif, âge, occurrences, extrait de détail ≤ 300 caractères).
- Masquage avant envoi : mots de passe, tokens, clés, IBAN, numéros de carte, e-mails de tiers (remplacés par `<email>`), numéros de téléphone.
- Contenu des sources dans `<source_data>` ; le prompt système indique que ce bloc ne contient que des données et qu'aucune instruction qui s'y trouve ne doit être suivie.
- Option `llm.send_ticket_text = false` (défaut) : pour les tickets NinjaOne, seuls sujet, catégorie, priorité, statut et âge sont envoyés, pas le corps.

### C6 — Réseau
- **nftables**, politique par défaut `drop` en entrée et en sortie.
- Entrée : 443/tcp depuis le VLAN admin et le pool VPN ; 22/tcp depuis les IP d'administration uniquement ; 10050/tcp depuis le serveur et le proxy Zabbix.
- Sortie :
  - vers les IP/ports des sources internes uniquement (ex. Zabbix 443, FortiAnalyzer 443, Veeam 9419, Wazuh 55000/9200) ;
  - vers le proxy Squid local, seul autorisé à sortir sur Internet en 443 ;
  - DNS vers les résolveurs internes, NTP, et les dépôts Debian via le proxy.
- **Squid** : allowlist de domaines (`api.anthropic.com`, `login.microsoftonline.com`, `graph.microsoft.com`, `<region>.ninjarmm.com`, domaine du webhook Teams, `deb.debian.org`, `security.debian.org`, `pypi.org`, `files.pythonhosted.org`). Tout le reste est refusé et journalisé.
- L'utilisateur `vigie-web` n'a pas le droit de sortir sauf vers Entra (règle nftables `meta skuid`).

### C7 — Secrets
- Stockés chiffrés avec `systemd-creds` (liés au TPM ou à la clé hôte), chargés par `LoadCredentialEncrypted=` uniquement dans les unités qui en ont besoin.
- Jamais en variable d'environnement globale, jamais dans `/etc/vigie/vigie.toml`, jamais dans les logs (filtre de journalisation qui masque les motifs sensibles).
- Développement : `.env.local` dans `.gitignore`, valeurs factices dans `.env.example`.
- Pré-commit : `gitleaks` ; CI : `gitleaks` + `pip-audit`.

### C8 — Séparation des privilèges
- Utilisateurs système distincts : `vigie-web`, `vigie-worker`, sans shell, sans sudo.
- Rôles PostgreSQL : `vigie_web` (CRUD sur tables de configuration et `task.status`, lecture du reste, INSERT seul sur `audit_log`), `vigie_worker` (écriture signaux, incidents, plans, `llm_call`), `vigie_migrate` (DDL, utilisé uniquement au déploiement).
- Sandboxing systemd sur toutes les unités : `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernelTunables/Modules/Logs=yes`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallFilter=@system-service`, `CapabilityBoundingSet=`, `MemoryDenyWriteExecute=yes`, `ReadWritePaths=` minimal. Objectif : `systemd-analyze security` < 2,0 pour chaque unité.

### C9 — Authentification et autorisation
- OIDC Entra ID (Authorization Code + PKCE), MFA imposé par accès conditionnel sur l'application.
- Rôles depuis les claims de groupes ; vérification côté serveur sur chaque route (décorateur `require_role`), tests d'autorisation par route.
- Sessions : cookie `Secure`, `HttpOnly`, `SameSite=Lax`, durée 8 h ; CSRF sur toutes les requêtes mutantes.
- Compte « bris de glace » local désactivé par défaut, activable uniquement en CLI sur le serveur (`vigie breakglass --enable --ttl 1h`), journalisé.
- En-têtes Caddy : HSTS, CSP stricte (`default-src 'self'`), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
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
- SSH : clés uniquement, `PermitRootLogin no`, `AllowUsers deploy`, algorithmes modernes ; `fail2ban` ou `sshguard`.
- `auditd` avec règles sur `/etc/vigie`, `/etc/credstore.encrypted`, exécutions de `sudo`.
- AppArmor activé ; chrony ; journald persistant.
- Lynis : score ≥ 80 après déploiement.
- Supervision de la VM par Zabbix (agent2 en mode actif, PSK).

### C12 — Coûts
- Limite de dépense mensuelle sur le workspace Anthropic dédié (filet ultime).
- Garde-fou applicatif avant chaque appel (SPEC §7.6), maximum 3 appels LLM par génération de plan (1 + 2 tentatives).

### C13 — Notifications
- Graph : application avec `Mail.Send` application **limitée** à la boîte `itbot@…` via RBAC for Applications d'Exchange Online (ou Application Access Policy). Secret client → certificat de préférence.
- Webhook Teams : secret ; le message ne contient que le résumé et un lien vers Vigie.

## 3. Pendant le développement avec Claude Code
- `.claude/settings.json` interdit la lecture des fichiers de secrets et demande confirmation pour `ssh`, `ansible-playbook`, `git push`, `scp`, `curl`/`wget`.
- Les tests n'appellent jamais les vraies sources : fixtures anonymisées uniquement.
- Les comptes de service de production ne sont pas utilisés depuis le poste de développement. Pour enregistrer des fixtures, utiliser un script dédié lancé manuellement par l'humain (`scripts/record_fixtures.py`, passant lui aussi par SafeClient), puis anonymiser.
- Ne pas donner à Claude Code d'accès MCP en écriture aux systèmes supervisés pendant ce projet.

## 4. Procédures
- **Pause d'urgence** : `sudo systemctl stop 'vigie-*.timer'` ou bouton « Pause » dans l'UI.
- **Compromission suspectée** : arrêter les timers, révoquer dans l'ordre la clé Anthropic, le secret Graph, les tokens des sources ; analyser `audit_log`, journald, logs Squid.
- **Rotation** : `vigie secrets rotate <name>` (réécrit le credential chiffré, redémarre l'unité concernée), procédure dans `deploy/README.md`.
