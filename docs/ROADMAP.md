# Vigie — Roadmap de développement

Chaque phase démarre en **plan mode** dans Claude Code et se termine par : tests + lint + mypy verts, skill `security-review` passé sans point bloquant, commit. Ne pas commencer une phase avant validation humaine de la précédente.

## Phase 0 — Socle du dépôt (½ jour)
- `pyproject.toml` (uv), structure `src/vigie`, ruff, mypy, pytest, pre-commit (ruff, gitleaks), `.gitignore`, `.env.example`.
- `vigie` CLI (Typer) avec sous-commandes vides.
- Configuration (`config.py`) : lecture de `vigie.toml` + secrets depuis `$CREDENTIALS_DIRECTORY` ou `.env.local`.
- PostgreSQL 17 **natif Debian** sur la VM (dev et future prod cohabitent, cf. `docs/DEV.md`) : bases `vigie_dev` et `vigie_test`, authentification peer.
- **Acceptation** : `uv run pytest` passe ; `vigie --help` liste les commandes ; gitleaks actif.

## Phase 1 — Modèle de données et seed (1 jour)
- Modèles SQLAlchemy de SPEC §5, migrations Alembic, trigger append-only sur `audit_log`.
- `vigie seed --from config/` idempotent (équipe, sociétés, règles d'actifs, politique, projets, skills de rôle depuis `roles/`).
- **Acceptation** : seed exécuté deux fois sans doublon ; test qui vérifie qu'un UPDATE sur `audit_log` échoue.

## Phase 2 — SafeClient et garde-fous (1 jour)
- `connectors/base.py` : `SafeClient`, `AllowedCall`, `ForbiddenCallError`, retries, timeouts, pagination bornée, logs masqués.
- `tests/security/` : tests statiques (imports interdits), test allowlist générique, masquage des secrets.
- **Acceptation** : tous les tests de sécurité de `SECURITY.md C10` applicables à ce stade passent.
- Réalisé : `SafeClient`/`AllowedCall` (contrôles à la définition et à l'appel, redirections refusées), `vigie.redact` (masquage), journaux JSON masqués (`vigie.logs`), tests statiques AST, tests appliqués automatiquement à chaque connecteur enregistré.

## Phase 3 — Connecteurs (3–4 jours)
Première livraison : **Zabbix puis Veeam**. Les autres sont ajoutés ensuite un par un, sans toucher au moteur (registre par entry points `vigie.connectors`) : NinjaOne ✅, Microsoft Defender ✅, patchs NinjaOne en attente > 7 jours ✅, FortiAnalyzer ✅ (capture réelle à faire), puis **Wazuh** et squelette **Veezo** (à faire). Pour chacun, suivre le skill `add-connector` :
- vérification de l'API dans la doc de la version ;
- allowlist + test « appel interdit » ;
- fixtures anonymisées + tests de contrat ;
- mapping société et catégorie ;
- `vigie collect --source X --dry-run --fixtures …`.
- **Acceptation** : chaque connecteur produit des signaux corrects sur fixtures ; aucun test n'émet d'appel réseau.
- **Ordre révisé (2026-10-09)** : la phase 3 se clôt avec le **seul connecteur Zabbix** ; les phases 4 à 6 se déroulent sur Zabbix seul ; Veeam puis les autres connecteurs sont ajoutés ensuite (skill `add-connector`, sans toucher au moteur).
- **Veeam B&R 13.1** (branche `connector-veeam`, 2026-10-11) : connecteur en lecture seule (jeton OAuth2 en formulaire, 5 GET), jobs (échecs, avertissements répétés, > 24 h sans succès), dépôts > 85/90/95 %, malware ; `SafeClient` étendu (corps en formulaire, en-têtes fixes non secrets, transport d'enregistrement) ; certificat du VBR approuvé pour cette seule source ; fixtures synthétiques. Jeton accordé à Backup Viewer (2026-10-11). Reste : captures réelles anonymisées (accès du rôle aux 5 GET), mise en service (`vigie_veeam_host`).
- **État au 2026-10-12** (détail : `docs/CONNECTORS.md`) :
  - Veeam B&R 13.1 ✅ en production (capture réelle anonymisée, rôle Backup Viewer) ;
  - NinjaOne ✅ en production (alertes, patchs en échec, tickets ; **patchs de sécurité en attente depuis plus de 7 jours** : un signal par patch daté par Vigie, un incident par société et type, attributs moteur `min_age_h` et `incident_group`) ;
  - Microsoft Defender ✅ en production (vulnérabilités Critical/High Windows avec analyse de criticité, incidents XDR high, appareils inactifs ; certificat, capture réelle anonymisée) ; reste : étiquette « FWD » et appareils « valeur élevée » dans Defender ;
  - FortiAnalyzer 8.0 ✅ connecteur (Event Monitor, appareils et HA, VPN ; JSON-RPC `get` sur URL listées, logsearch optionnel) sur fixtures synthétiques ; reste : capture réelle (`TODO verify` de `CONNECTORS.md` §2) et mise en service ;
  - Wazuh (vulnérabilités Linux, alertes) et Veezo : à faire.
- Réalisé (Zabbix) : connecteur 7.4 (`problem.get` + `trigger.get` + `proxy.get`, `apiinfo.version` anonyme), rattachement société `vigie.mapping.RuleMapper`, agrégation des hôtes bruyants, fixtures réelles anonymisées (`scripts/anonymize_fixtures.py`), rejeu `fixture_transport`, `vigie collect --dry-run [--fixtures]`, `vigie check --sources`. L'enregistrement des signaux en base (fingerprint, résolution) relève de la phase 4.

## Phase 4 — Moteur déterministe (2–3 jours, TDD)
- `normalize`, `correlate`, `scoring`, `rules` (overrides), `assign`, `planner` (quotidien et hebdomadaire), report des tâches, backlog.
- Calendrier : jours de présence, absences, jours fériés BE.
- `vigie plan --kind daily|weekly --no-llm`.
- **Acceptation** : couverture ≥ 90 % sur `engine/` ; scénarios de SPEC §7.5 (VPN un mardi, Veeam SPL, tickets Giovanni) reproduits en tests ; plan lisible en Markdown en sortie CLI.
- Réalisé (sur Zabbix seul) : enregistrement des collectes (`vigie collect`, résolution par instantané, panne de source = signal), corrélation (même actif, 60 min), score calibré + overrides déclaratifs (F, H), compétences multiples (I), calendrier avec fériés belges, affectation (coordinateur en recours, escalade P1 + suivi chez le spécialiste, P2 reportée dans le SLA, `task.not_before`), plans quotidien/hebdomadaire Markdown (`vigie plan --no-llm [--date] [--dry-run]`), reports avec compteur. Couverture `engine/` ≥ 94 % par module.

## Phase 5 — Intégration LLM (1–2 jours)
- `llm.py` : SDK `anthropic`, sortie structurée (aucun outil : le modèle refuse `tool_choice` forcé), prompt caching, budget, retries, journal `llm_call`.
- Prompts dans `engine/prompts/` (système, plan quotidien, plan hebdo), incluant les skills de rôle.
- `validator.py` complet ; repli déterministe.
- Tests avec client Anthropic simulé : sortie valide, invalide, injection, dépassement de budget.
- Utiliser le skill `product-self-knowledge` (claude.ai) ou la doc officielle pour vérifier les paramètres SDK et l'identifiant de modèle.
- **Acceptation** : un plan généré sur fixtures réelles anonymisées coûte < 0,40 $ ; tests d'injection verts.
- Réalisé : sortie structurée sans outil, contexte en blocs cachés (instructions + skills de rôle, organisation) et `<source_data>` non refermable, budget vérifié avant appel, coût par modèle servi (repli serveur), validateur élément par élément (compétences, présence, capacité, priorité jamais abaissée, aucun lien, 5 tâches nouvelles max), repli déterministe, `vigie plan` (IA par défaut, `--no-llm`), `vigie budget`. Mesure réelle (2026-10-09, plan hebdomadaire sur fixtures Zabbix, `claude-sonnet-5-5`, effort `medium`) : 21 400 jetons en entrée, ≈ 5 400 en sortie, **0,099 $** au premier appel, **0,087 $** au second (5 920 jetons servis par le cache), 37 s ; aucune proposition rejetée par le validateur. Critère < 0,40 $ ✅.

## Phase 6 — Application web (3–4 jours)
- **Direction visuelle validée** (2026-10-09) : `docs/ui/maquette.html` (10 écrans, barre latérale, cartes par personne, priorités codées P1–P4, thèmes clair et sombre ; polices IBM Plex à auto-héberger : la maquette les charge depuis Google Fonts, mais aucun CDN n'est permis à l'exécution). La phase 6 l'implémente en Jinja2 + HTMX + Tailwind ; skill `frontend-design` pour les finitions.
- URL : `https://vigie.local.wallindustries.be` (DNS interne, accès LAN/VPN).
- OIDC Entra, RBAC, CSRF, pages de SPEC §9, éditeur des skills de rôle, validation/publication des plans, mise à jour des tâches.
- Tailwind compilé au build ; aucun asset externe.
- **Acceptation** : tests d'autorisation par route et par rôle ; parcours complet sur données de seed ; CSP sans violation dans la console.
- Réalisé : socle FastAPI sécurisé (CSP stricte, CSRF global, session 8 h, en-têtes), connexion Entra (groupes → rôle, refus si aucun groupe ou dépassement), connexion de développement, bris de glace à usage unique ; 10 écrans de SPEC §9 et API §10 ; `job_request` exécutées par `vigie jobs --run-pending` ; pause globale ; htmx et polices vendorisés avec intégrité vérifiée. Connexion Entra réelle et console sans violation CSP confirmées par le coordinateur (2026-10-09).

## Phase 7 — Notifications (½–1 jour)
- Graph `sendMail` (certificat), webhook Teams, gabarits HTML + texte, allowlist destinataires.
- `vigie notify --plan <id> --dry-run` (écrit les messages dans un dossier au lieu d'envoyer).
- **Acceptation** : rendu vérifié dans Outlook et Teams ; aucun lien non construit par l'application.
- Réalisé : `vigie notify --plan <id|latest-daily|latest-weekly> [--dry-run --out DIR] [--force]` ; un e-mail par personne (tâches, actions, liens Vigie) et un récapitulatif au coordinateur (synthèse IA, escalades, risques) ; carte Teams sans détail ; Graph par certificat (MSAL) et webhook via `SafeClient` (un seul appel autorisé chacun) ; destinataires = personnes actives ; mode rodage `draft_only` ; publication du plan à la diffusion, idempotence ; pause respectée. Reste : premier envoi réel (application « Vigie Mail », webhook Teams), reporté à la demande du coordinateur ; e-mail et Teams désactivés d'ici là.

## Phase 8 — Déploiement Debian (1–2 jours)
- Suivre le skill `debian-deploy` : Ansible (rôles `base`, `hardening`, `nftables`, `squid`, `postgresql`, `caddy`, `vigie`, `zabbix_agent`, `backup`).
- Unités et timers systemd de SPEC §8 avec sandboxing (`SECURITY.md C8`).
- Secrets via `systemd-creds`.
- **Acceptation** : `systemd-analyze security` < 2,0 par unité ; Lynis ≥ 80 ; un `curl` vers un domaine non autorisé échoue ; collecte réelle de chaque source OK ; premier plan quotidien reçu par mail.
- Réalisé : production sur la VM de développement (cohabitation, `vigie_dev_on_host`) ; `deploy/` (9 rôles, `ansible-lint` profil production, procédures dans `deploy/README.md`) ; version figée par `deploy/build.sh` (wheel + dépendances à empreintes), venv par version et lien `current` ; migrations en `vigie-migrate` (`vigie migrate`) ; unités sandboxées et timers de SPEC §8, secrets répartis par unité ; `vigie housekeeping`, `vigie selfcheck` (fichiers lus par zabbix-agent2 en PSK), `vigie breakglass` ; Caddy en AC interne (racine à diffuser par GPO) ; sauvegardes `pg_dump` chiffrées par age, emportées par Veeam, script de test de restauration. Appliqué le 2026-10-10 : collecte Zabbix réelle toutes les 15 min (164 signaux), `systemd-analyze security` 1,1 pour chaque unité, Squid refuse `example.com` (403) et laisse passer `api.anthropic.com`, `pg_hba` refuse `nadmin` sur la base `vigie`, idempotence vérifiée (`changed=0`). Correctifs issus de l'application : `force_handlers`, rechargement PostgreSQL d'après les dates des fichiers, redémarrage de `vigie-web` s'il tourne sur une ancienne version, venv installé avec umask 022 (le `UMASK 027` de login.defs touche aussi sudo), timers sans `default(omit)`.
- Ouvert (reporté par le coordinateur) : Lynis 70 avant le durcissement complémentaire (`deploy/README.md` §10), à remesurer, objectif ≥ 80 ; racine Caddy à diffuser par GPO ; hôte Zabbix `WI-SRV-VIGIE-01` (PSK) à déclarer ; test de restauration après la première sauvegarde ; « premier plan reçu par mail » attend l'activation de l'envoi.

## Phase 9 — Rodage (2 semaines)
- Premiers enseignements (2026-10-09, première collecte réelle Zabbix, 165 signaux) : âge ramené à +3 %/jour plafonné à ×1,3 (les problèmes chroniques devenaient P1/P2) ; plafond d'escalade du coordinateur à 150 % de sa capacité, au-delà backlog « P1 non couvert » ; criticité par type d'actif d'après le nom d'hôte (`hostname_contains` : antennes, caméras, iLO, onduleurs) prioritaire sur le groupe ; override `hardware_failure` (SMART, RAID, alimentation, température critique, sévérité ≥ High) ; à priorité égale, P1 imposé par une règle avant P1 de score ; détail envoyé à l'IA limité aux tâches planifiées et au backlog P1/P2 (coût 0,16 $ → 0,05 $).
- Mode « brouillon uniquement » (pas d'envoi aux collègues), revue quotidienne par le coordinateur.
- Ajustement des poids, seuils, catégories et estimations dans `config/scoring.yaml` ; suivi du coût réel.
- **Acceptation** : le coordinateur juge ≥ 80 % des tâches pertinentes et bien affectées sur 5 jours consécutifs → activation de la diffusion à l'équipe.
- Outillage réalisé : jugement de chaque tâche (pertinente, bien affectée, note) et « ce qui manquait » au plan, sur Aujourd'hui (admin, manager ; tables `task_review`, `plan_review`, migration 0009) ; page **Rodage** : jour validé si ≥ 90 % des tâches jugées et ≥ 80 % pertinentes et bien affectées, série de jours consécutifs (un plan du jour pas encore relu ne l'interrompt pas), tâches rejetées par catégorie et origine, coût IA par plan, projection mensuelle ; barème réglable dans Paramètres ; `vigie_notify_draft_only` dans Ansible et procédure « Fin de rodage » (`deploy/README.md` §9). Bouton « Générer maintenant… » sur Aujourd'hui et Semaine (coût de la dernière itération affiché, avec ou sans IA, migration 0010, unité `vigie-plan-requests`). Reste : les 2 semaines de rodage en production.

## Phase 10 — Conteneurisation (Docker)
- Contexte (2026-10-22) : la VM devient un serveur multi-applications en Docker (dont un portail sur 443 vers des applis locales ou d'autres serveurs). Vigie passe entièrement en conteneurs, prod et dev, sans perdre les garanties de `SECURITY.md`.
- Décisions : PostgreSQL **de l'hôte** conservé et partagé (une base et des rôles par application ; conteneurs aux UID des comptes `vigie-*`, peer inchangé) ; proxy d'entrée **Caddy partagé** (projet `edge`, seul à publier 443, AC interne reprise) ; secrets **systemd-creds** conservés (`vigie-creds.service` → `/run/vigie/creds` → `secrets:` par service) ; timers systemd de l'hôte conservés (un conteneur éphémère par tâche) ; réseaux Docker à sous-réseaux fixes filtrés par nftables (`forward`) à la place des règles par uid ; dev en **Docker rootless** de `nadmin` (jamais dans le groupe `docker`).
- Réalisé (branche `feature-docker`) : `[web] forwarded_allow_ips`, `vigie web --host`, connexion de dev en conteneur (`VIGIE_DEV_CONTAINER=1`) ; images `vigie:<version>` (contexte `dist/` seul) et `vigie-squid` ; `compose.yaml` (durcissement, secrets et réseaux par service) ; rôles `docker`, `edge`, `legacy`, refonte de `vigie` et `nftables` (plus de `flush ruleset`) ; `tests/security/test_compose.py` ; `compose.dev.yaml`, `scripts/dev`.
- Appliqué le 2026-10-22 : bascule faite, second passage `changed=0` ; collectes réelles en conteneur (Zabbix 144 signaux, NinjaOne 120, Defender 34, Veeam 11, FortiAnalyzer 9) ; web 200 avec la racine d'AC d'origine ; secrets par conteneur vérifiés ; web sans proxy bloqué, via Squid Entra seul. Corrections issues de la bascule : magasin de certificats de l'hôte monté (Zabbix auto-signé), proxy `squid` accepté par les connecteurs, sources directes sans DNS (`extra_hosts`), dossiers audités créés avant les règles auditd, `NET_BIND_SERVICE` pour Caddy, et **règles nftables `… limit rate … drop`** (le rejet ne valait que sous le débit : défaut aussi présent depuis la phase 8 sur la sortie des comptes natifs) ; journal Ansible `~/.local/state/vigie/ansible.log`. Reste : `legacy_purge: true` après une semaine (vers le 2026-10-29), fusion de `feature-docker`.
- **Acceptation** : tests + lint verts dans le conteneur de dev ; `security-review` ; bascule appliquée avec `changed=0` au second passage ; contrôles de `deploy/README.md` § 7 (sortie web limitée à Entra, `collect-zabbix` limité à sa source, secrets par conteneur, conteneurs en lecture seule et non root) ; collecte réelle de chaque source ; AC interne inchangée.

## Après le rodage (réalisé hors phases)
- **Discussion avec l'IA sur les priorités** ✅ (2026-10-12, migration 0011) : panneau sur le plan du jour et la fiche incident, service `vigie-chat` (clé IA seule, le web n'a pas la clé), sortie structurée sans outil, propositions appliquées par un admin seulement (audit), « Réinitialiser le contexte », plafonds de jetons. Reste : essai en production.
- **Choix du modèle d'IA** ✅ (2026-10-12, migration 0012) : Sonnet 5.5, Opus 5.5 ou Fable 5.1 ; défaut réglé par un admin dans Paramètres (audit `llm_model_set`), choix ponctuel dans « Générer maintenant », `vigie plan --model` et la discussion ; budget décompté au tarif de chaque modèle (`vigie/ai_models.py`).
- **Traitement invité Veeam de la VM** ✅ (SSH depuis 10.10.10.27, compte `svcveeam`, `deploy/README.md` §14) ; reste : mot de passe et identité dans Veeam.

## Points à trancher (relevés en phase 0)
| Réf. | Point | Phase |
|---|---|---|
| B ✅ | « Tester la connexion » d'une source depuis l'UI : `vigie-web` n'a ni secret ni sortie réseau → demande mise en file en base, exécutée par le worker. Table `job_request` (payload strict par kind, sans secret) en phase 1. | 1 ✅ / 6 |
| C ✅ | `vigie secrets set/rotate` nécessite `systemd-creds`, or `subprocess` est interdit dans `src/` → script shell `vigie-secret` installé par le rôle `vigie`. | 8 ✅ |
| D ✅ | Rôle DB `vigie_web` : ajouter UPDATE limité à `plan.status`, `validated_by`, `validated_at`, `published_at` (validation depuis l'UI). | 1 ✅ |
| F ✅ | Calibrage du score : hors override et hors bonus politique, le maximum théorique est ≈ 47 (< seuil P1 60) et un Zabbix *High* standard vaut 10 → P4. `B_policy` non borné. Revoir seuils/poids avant d'écrire les tests de scénarios. | 4 |
| H ✅ | Overrides : préférer des conditions déclaratives (champ, opérateur, valeur) à des expressions `when` interprétées. | 4 |
| I ✅ | `vulnerability` → `patching` (+ `systeme` si serveur) : `category_skill` ne gère qu'une compétence. | 4 |
| K | Skills `frontend-design` (phase 6) et `product-self-knowledge` (phase 5) absents de l'environnement ; `claude-api` utilisé pour la phase 5 ✅. | 5 / 6 |
| N ✅ | Rétention 1 an de `audit_log` (SPEC §5.2) incompatible avec un append-only strict → DELETE autorisé par le trigger uniquement pour les lignes de plus de 365 jours ; `at` forcé à `now()` à l'insertion. | 1 |
| O ✅ | `.gitignore` laissait passer de vrais `config/*.yaml` (e-mails, noms) → ignorés, sauf `*.example.yaml`. | 1 |
| P | **À faire** : SSH ouvert **temporairement** à tout `192.168.0.0/16` (`admin_networks`, décision du 2026-10-12, postes d'administration en DHCP) → réduire aux seuls réseaux d'administration (ex. `192.168.48.0/24`, `192.168.10.0/24`, `192.168.250.0/24`) ; relever le score Lynis (≥ 80) en même temps. | 8 |
| M | OIDC : configurer l'app Entra pour n'émettre que les groupes assignés (éviter le *groups overage* qui imposerait un appel Graph depuis `vigie-web`). | 6 |

## Évolutions envisagées (v2)
- Connecteur Microsoft 365 (santé des services, Defender, licences).
- Vue « charge » prévisionnelle sur 4 semaines.
- Création de tickets NinjaOne à partir des tâches, **avec validation humaine action par action** et compte distinct (nécessite une revue de sécurité dédiée).
