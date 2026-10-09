# Vigie — Spécification fonctionnelle et technique

Version 1.0 — octobre 2026

## 1. Contexte et objectifs

Le service IT gère plusieurs sociétés (WI, SPL, WG, CC, FWD) avec une petite équipe dont deux membres ne sont présents qu'un jour par semaine. Les alertes sont dispersées entre plusieurs outils et le tri quotidien repose sur le coordinateur.

Vigie doit :
1. **Veiller** automatiquement les systèmes de supervision et en extraire des *signaux* normalisés.
2. **Prioriser** ces signaux selon des règles explicites, la criticité des sociétés et des actifs, et la politique IT.
3. **Planifier** : produire un plan quotidien (light) et un plan hebdomadaire (complet), répartissant tâches d'incident et jalons de projets entre les personnes selon compétences et disponibilités.
4. **Diffuser** le plan à chaque personne (mail, Teams) et le rendre consultable dans une application web.
5. **Ne jamais agir** sur les systèmes supervisés.

### Indicateurs de succès
- Plan quotidien disponible à 07:30 les jours ouvrés, ≥ 95 % des jours.
- 100 % des sauvegardes en échec détectées dans le plan du jour suivant.
- Le coordinateur valide le plan hebdomadaire en moins de 15 minutes.
- Coût API Anthropic ≤ 30 $/mois (garde-fou budgétaire).

## 2. Acteurs et rôles applicatifs

| Rôle applicatif | Qui | Droits |
|---|---|---|
| `admin` | Coordinateur | Tout : équipe, politique, projets, skills de rôle, sources, paramètres, validation des plans, audit |
| `manager` | Responsable informatique (peut être la même personne) | Politique, projets, validation et lecture des plans, rapports |
| `tech` | Giovanni, Cédric, Angelo | Lecture de son plan et du plan d'équipe ; mise à jour du statut de ses tâches ; commentaires |
| `viewer` | Direction éventuelle | Lecture des rapports hebdomadaires |

Les rôles sont dérivés de groupes Entra ID (`SG-Vigie-Admin`, `SG-Vigie-Manager`, `SG-Vigie-Tech`, `SG-Vigie-Viewer`).

## 3. Fonctionnalités

### F1 — Équipe : compétences et disponibilités
- Fiche personne : nom, e-mail, rôle métier, rôle applicatif, temps de travail.
- **Compétences** : liste de tags de la taxonomie (§5.3) avec niveau 1 (notions) à 3 (expert), et préférence (aime / neutre / à éviter).
- **Disponibilité** :
  - Modèle hebdomadaire : jours travaillés et heures par jour (ex. Cédric : jeudi 8 h).
  - Exceptions : congés, absences, jours supplémentaires (calendrier).
  - Capacité planifiable = heures disponibles × taux de planification (défaut 80 % ; coordinateur 50 % pour la réserve de coordination).
- Champ libre « consignes » par personne (ex. « pas d'intervention sur site FWD »), transmis au moteur.

### F2 — Politique IT (axes prioritaires)
- Liste d'**axes prioritaires** pondérés (poids 1–5) avec description, période de validité, mots-clés et catégories associées. Exemples : « Sauvegardes fiables et testées », « Réduction des vulnérabilités critiques », « Migration M365 SPL ».
- **Règles de politique** : textes courts injectés dans le contexte du moteur (ex. « Toute vulnérabilité CVSS ≥ 9 exposée Internet est traitée sous 48 h »).
- **Criticité par société** (0,5 à 1,5) et SLA cibles par priorité (globaux, `sla_hours` de la politique).
- Historique des versions de la politique (qui, quand, quoi).

### F3 — Projets transversaux et jalons
- Projet : nom, description, sociétés concernées, sponsor, responsable, axe(s) de politique liés, priorité, statut (proposé, actif, en pause, terminé), dates.
- **Jalons** : titre, échéance, responsable, charge estimée (h), compétences requises, statut, dépendances.
- Le planificateur réserve de la capacité pour les jalons dont l'échéance est proche (fenêtre configurable, défaut 21 jours) et signale les jalons à risque (charge restante > capacité disponible des personnes compétentes avant échéance).

### F4 — Skills de rôle
- Documents Markdown au format SKILL.md (frontmatter `name`, `description` + corps) éditables dans l'UI, versionnés.
- Deux skills fournis : `ingenieur-coordinateur` et `responsable-informatique` (dossier `roles/`).
- Chaque personne peut se voir associer un skill de rôle ; le moteur injecte dans son contexte :
  - le skill `responsable-informatique` pour les arbitrages globaux (priorisation, synthèse hebdomadaire) ;
  - le skill `ingenieur-coordinateur` pour la répartition et les escalades opérationnelles ;
  - les skills éventuels des autres personnes pour décrire leurs attentes.
- Les skills sont aussi exportables pour être réutilisés dans Claude (claude.ai ou Claude Code).

### F5 — Veille des sources
- Sources prévues : Zabbix 7.4, FortiAnalyzer, NinjaOne (alertes, tickets, vulnérabilités/patchs, backup éventuel), Wazuh, Veeam Backup & Replication, Veezo (à préciser), extensibles par plugin (§6.2).
- Chaque source : activation, fréquence de collecte (défaut 15 min, Veeam 30 min), filtres (sévérité minimale, groupes, organisations), mapping vers société, état de santé (dernier succès, dernière erreur, latence, volume).
- La panne d'une source **est elle-même un signal** (catégorie `monitoring`, priorité P2 ; P1 si > 4 h).

### F6 — Normalisation, corrélation et priorisation
Voir §7. Résultat : un ensemble de *signaux* dédupliqués, groupés en *incidents* corrélés, chacun avec un score et une priorité P1–P4 expliquée.

### F7 — Affectation
Voir §7.5. Chaque tâche reçoit un responsable, une estimation, une échéance et une justification lisible (« Assigné à Cédric : compétence réseau niveau 3, présent jeudi, charge 5/6,4 h »).

### F8 — Plans
- **Plan quotidien (light)** : généré à 07:15 les jours ouvrés, pour les personnes présentes ce jour.
  - Nouveautés depuis la veille (signaux P1/P2 nouveaux ou aggravés).
  - Tâches du jour par personne (max 5 par personne, P1 d'abord).
  - Tâches en retard ou bloquées.
  - Sources en panne.
- **Plan hebdomadaire (complet)** : généré le lundi à 06:30 (configurable : vendredi 16:00 pour la semaine suivante).
  - Synthèse exécutive (5 lignes) rédigée dans la perspective du responsable informatique.
  - Tableau par personne et par jour de présence.
  - Jalons de projets de la semaine et jalons à risque.
  - Backlog non planifié faute de capacité, avec recommandation d'arbitrage.
  - Tendances : nombre de signaux par source, société et priorité vs semaine précédente ; taux de succès des sauvegardes ; vulnérabilités critiques ouvertes.
- Cycle de vie d'un plan : `draft` → `validated` (par admin/manager) → `published`. Paramètre `auto_publish_at` (défaut : quotidien publié automatiquement à 07:30 avec la mention « non validé » ; hebdomadaire attend validation jusqu'à 09:00 puis publication auto).
- Report automatique : une tâche non terminée est reconduite dans le plan suivant avec un compteur de reports ; au-delà de 3 reports, escalade vers le coordinateur.

### F9 — Diffusion
- E-mail via Microsoft Graph (`Mail.Send` application, restreint à la boîte `itbot@…` par RBAC for Applications), destinataires uniquement issus de la table `person` (allowlist), un mail par personne + un mail récapitulatif au coordinateur.
- Message dans un canal Teams via un webhook Workflows (URL stockée comme secret).
- Contenu : HTML sobre + version texte ; liens vers Vigie et vers l'objet source (URL construite par l'application à partir d'un gabarit de la source, jamais fournie par le LLM).

### F10 — Suivi des tâches
- Statuts : `todo`, `in_progress`, `blocked`, `done`, `wont_do` (avec motif).
- Mise à jour par la personne assignée dans l'UI (stockée uniquement dans Vigie).
- Clôture automatique proposée quand tous les signaux liés sont résolus côté source (la tâche passe en `done?` en attente de confirmation).
- Création manuelle de tâches par admin/manager.

### F11 — Administration et observabilité
- Journal d'audit (append-only) : connexions, modifications de configuration, validations, appels LLM (modèle, tokens, coût, hash du prompt), appels sources (source, méthode, statut, durée — sans contenu).
- Tableau des coûts LLM (jour, mois, budget restant).
- Interrupteur global « pause » (collecte et/ou génération) et mode `--no-llm`.
- Page santé : services, timers, dernière exécution, file d'erreurs.

## 4. Architecture

```
           ┌──────────────────────────── VM Debian 13 « vigie » ─────────────────────────────┐
 Navigateur│  Caddy :443 ──► vigie-web (uvicorn 127.0.0.1:8080, user vigie-web)              │
 (OIDC     │                    │ lit/écrit app tables (rôle DB vigie_web)                    │
 Entra ID) │                    ▼                                                             │
           │              PostgreSQL 17 (local, socket unix)                                  │
           │                    ▲                                                             │
           │  systemd timers ──► vigie-worker (user vigie-worker, secrets via systemd creds)  │
           │    collect@<source>   ├─ connectors/* ──SafeClient (allowlist RO)──► sources LAN │
           │    plan-daily         ├─ engine/* (normalise, corrèle, score, assigne)           │
           │    plan-weekly        ├─ llm.py ──► squid (egress allowlist) ──► api.anthropic.com│
           │    notify             └─ notify/* ──► squid ──► graph.microsoft.com / webhook    │
           │  zabbix-agent2 (supervision de Vigie elle-même)                                  │
           └──────────────────────────────────────────────────────────────────────────────────┘
```

Composants :
- **vigie-web** : UI + API JSON interne ; aucune connexion sortante hors OIDC (login.microsoftonline.com).
- **vigie-worker** : commandes CLI one-shot lancées par timers systemd (pas de démon permanent) → surface réduite, redémarrage implicite.
- **PostgreSQL** : unique source de vérité ; deux rôles DB (`vigie_web`, `vigie_worker`) + `vigie_migrate` pour Alembic.
- **Squid** : proxy sortant à allowlist de domaines pour les destinations Internet.
- **Caddy** : TLS (certificat interne PKI ou ACME DNS-01), en-têtes de sécurité.

## 5. Modèle de données

### 5.1 Entités principales
| Table | Champs clés |
|---|---|
| `person` | id, name, email, job_role, app_role, weekly_pattern (JSON jour→heures), planning_rate, notes, active, role_skill_id |
| `person_skill` | person_id, skill_tag, level (1–3), preference |
| `absence` | person_id, start, end, kind, note |
| `company` | code (WI…), name, criticality |
| `asset_rule` | company_code, source, match_type (clé `match` dans le YAML : hostgroup_prefix, hostgroup_suffix, org_id, adom, devname_prefix, job_prefix, agent_group), company_code facultatif (règle de criticité seule), pattern, asset_criticality, tags |
| `policy_axis` | id, title, description, weight, valid_from, valid_to, keywords[], categories[] |
| `policy_rule` | id, text, active, version |
| `project` | id, name, description, companies[], sponsor, owner_id, axis_ids[], priority, status, start, end |
| `milestone` | id, project_id, title, due, owner_id, effort_h, remaining_h, skill_tags[], status, depends_on[] |
| `role_skill` | id, name, description, body_md, version, updated_by, updated_at |
| `source` | name, kind, enabled, interval_min, filters (JSON), base_url, last_ok_at, last_error, last_error_at |
| `signal` | id, source, external_id, fingerprint, company_code, asset, category, severity (0–5 normalisé), title, details (tronqué), url_template_params, first_seen, last_seen, resolved_at, occurrences, raw_hash |
| `incident` | id, fingerprint_group, signal_ids[], category, company_code, asset, score, priority, priority_reason, status |
| `task` | id, plan_id, incident_id?, milestone_id?, title, description, actions[], category, priority, score, estimate_h, assignee_id, due, status, carry_count, rationale, origin (engine/llm/human), created_at |
| `plan` | id, kind (daily/weekly), period_start, period_end, status, summary_md, generated_by (rules/llm), llm_call_id, validated_by, validated_at, published_at |
| `llm_call` | id, at, model, input_tokens, cached_tokens, output_tokens, cost_usd, prompt_hash, outcome, error |
| `audit_log` | id, at, actor, action, object, details (JSON) — append-only (trigger DB interdisant UPDATE/DELETE) |
| `setting` | key, value (JSON) |
| `role_skill_version` | role_skill_id, version, description, body_md, updated_by, updated_at (historique F4) |
| `task_comment` | task_id, author_id, at, body (F10) |
| `job_request` | kind (liste fermée), payload (JSON strict par kind, sans secret, ≤ 4 Ko), requested_by, requested_at, status, result, done_at — demandes du web exécutées par le worker |

Les listes de références sont des tables d'association avec clés étrangères : `incident_signal`, `task_incident` (une tâche peut couvrir plusieurs incidents), `project_company`, `project_axis`, `milestone_dependency`. `task.status` inclut `pending_done` (« done? ») et `task.status_reason` porte le motif de `wont_do`. `audit_log` : UPDATE et TRUNCATE interdits, DELETE uniquement au-delà de 365 jours, `at` forcé à `now()`.

### 5.2 Rétention
Signaux résolus : 90 jours. Plans et tâches : 2 ans. `llm_call` et `audit_log` : 1 an. Purge par timer hebdomadaire.

### 5.3 Taxonomie (catégories ↔ compétences)
| Catégorie | Compétence requise | Exemples de signaux |
|---|---|---|
| `network` | `reseau` | VPN down, lien WAN, switch, Wi-Fi, SNMP |
| `firewall` | `fortinet` | HA FortiGate, IPS, règles, licence FortiGuard |
| `security` | `securite` | Wazuh niveau ≥ 10, détection FortiAnalyzer, compte compromis |
| `vulnerability` | `patching` (+ `systeme` si serveur) | CVE NinjaOne/Wazuh, patchs manquants |
| `backup` | `backup` | Job Veeam en échec, repository plein, NinjaOne Backup |
| `server` | `systeme` | Hôte down, disque, CPU, services Windows/Linux, hyperviseur |
| `endpoint` | `poste` | Poste hors ligne, antivirus, disque poste |
| `user_support` | `support` | Tickets utilisateurs |
| `m365` | `m365` | Licences, Exchange, Teams, Intune |
| `monitoring` | `supervision` | Source injoignable, proxy Zabbix down, agent non rapporté |
| `project` | selon jalon | Jalons |

La table de correspondance est configurable (`config/scoring.example.yaml`).

## 6. Connecteurs

### 6.1 Contrat
```python
class Connector(Protocol):
    name: str                       # "zabbix"
    allowlist: list[AllowedCall]    # méthodes autorisées, vérifiées par SafeClient
    def healthcheck(self) -> HealthStatus: ...
    def collect(self, since: datetime) -> Iterable[RawSignal]: ...
    def to_signal(self, raw: RawSignal, mapping: CompanyMapper) -> Signal: ...
```
- `SafeClient` : timeouts (connect 5 s, read 30 s), retries exponentiels (3), pagination bornée (max 5 000 objets / collecte), TLS vérifié (CA interne configurable), journalisation méthode/chemin/statut/durée, refus de toute méthode hors allowlist **avant** l'envoi.
- Les connecteurs sont découverts par entry points `vigie.connectors` → ajouter un système = ajouter un module + config, sans toucher au moteur.

### 6.2 Détail par source
Voir `docs/CONNECTORS.md`.

## 7. Moteur de priorisation et de planification

### 7.1 Pipeline
```
collect → normalize → dedupe (fingerprint) → correlate (incidents) → score → rules (overrides)
       → candidate tasks (incidents + jalons + reports) → assign (déterministe)
       → LLM refine (optionnel) → validate → plan draft → notify/publish
```

### 7.2 Normalisation
- Sévérité normalisée 0–5 (mapping par source dans `CONNECTORS.md`).
- `fingerprint = sha256(source | company | asset | category | titre normalisé sans chiffres variables)`.
- `details` tronqué à 1 000 caractères, nettoyé (caractères de contrôle, balises), secrets masqués (regex : mots de passe, tokens, clés privées, IBAN).

### 7.3 Corrélation
Regrouper en un incident les signaux de sources différentes portant sur le même actif (nom d'hôte normalisé, IP, numéro de série) dans une fenêtre de 60 min. Exemples : Zabbix « host unreachable » + NinjaOne « device offline » + Veeam « job failed » sur le même serveur → un incident `server` avec la sévérité maximale.

### 7.4 Score
```
score = W_sev[severity] × C_company × C_asset × F_age × F_recurrence × W_category + B_policy
```
- `W_sev` = {0:1, 1:4, 2:10, 3:20, 4:35, 5:50} (calibrage 2026-10 : Zabbix *High* sur serveur de prod ≈ 45 → P2, *Average* ≈ 26 → P3, *Warning* ≈ 10 → P4)
- `C_company` ∈ [0,5 ; 1,5], `C_asset` ∈ [0,5 ; 1,5] (prod, cœur réseau, firewall = 1,5 ; poste = 0,8)
- `F_age` = 1 + 0,03 × min(jours ouverts, 10) (×1,3 au plus ; 0,1 avant le rodage 2026-10)
- `F_recurrence` = 1 + 0,05 × min(occurrences sur 7 j, 10)
- `W_category` : backup 1,3 ; security 1,3 ; firewall 1,2 ; autres 1,0
- `B_policy` = Σ (poids de l'axe × 2) pour chaque axe actif correspondant (catégorie ou mot-clé), **plafonné à 20**
- Seuils : P1 ≥ 60 ; P2 ≥ 35 ; P3 ≥ 15 ; P4 sinon.
- `C_asset` : règles `asset_rule` ; une règle sur le nom d'hôte (`hostname_contains`, type d'actif) l'emporte sur les règles de groupe.

**Règles d'override (relèvent la priorité, jamais ne l'abaissent ; raison affichée)** — configurables dans `scoring.yaml` sous forme **déclarative** : `{id, priority, reason, all: [{field, op, value}]}`, champs `source`, `category`, `severity`, `company`, `hours_open`, `attr.<clé>` (attributs fournis par le connecteur), opérateurs `eq ne gt ge lt le in`. Aucune expression n'est évaluée.
- Aucune sauvegarde réussie depuis > 24 h pour un job marqué critique, ou 2 échecs consécutifs.
- Repository de sauvegarde > 90 % (P2) / > 95 % (P1).
- FortiGate hors ligne, HA dégradée, ou VPN site-à-site down > 30 min.
- Zabbix sévérité Disaster.
- Wazuh règle niveau ≥ 12.
- Vulnérabilité CVSS ≥ 9 ou présente au catalogue CISA KEV sur un actif exposé.
- Certificat expirant < 7 j (P2 si < 21 j).
- Source de supervision injoignable > 4 h.

Chaque incident stocke `priority_reason` (lisible : « Override : backup critique sans succès depuis 31 h »).

### 7.5 Affectation (déterministe, toujours exécutée)
1. Compétences requises = taxonomie (§5.3), **toutes** requises si plusieurs (`category_skill` en liste, `extra_skills` conditionnelles : `vulnerability` + `systeme` si `attr.asset_type = server`) ; pour un jalon, ses `skill_tags`.
2. Candidats = personnes actives ayant la compétence (niveau ≥ 2 pour P1/P2, ≥ 1 sinon) **et** présentes dans la fenêtre (jour pour le plan quotidien, semaine pour l'hebdomadaire).
3. Tri : niveau de compétence ↓, capacité restante ↓, préférence, équité (charge relative de la semaine).
4. À priorité égale, une priorité imposée par une règle (override) passe avant une priorité de score. Les P1 escaladés au coordinateur sont plafonnés à 150 % de sa capacité du jour (`coordinator_overload_max`) ; au-delà, backlog « P1 non couvert — arbitrage nécessaire », en tête du récapitulatif. Le coordinateur n'est pas un candidat ordinaire mais le **recours** (sauf s'il est responsable désigné, ex. jalon). Échéance SLA stricte pour P1/P2 (jamais planifiés après), simple cible pour P3/P4. Jalons servis avant les incidents de même priorité (capacité réservée), par tranches de 4 h. Si aucun candidat présent pour un **P1** : affectation au coordinateur (ingénieur système & réseau, polyvalent), marquée `escalade`. Pour un P2 : planifié au prochain jour de présence du spécialiste si l'échéance SLA le permet, sinon coordinateur.
5. Estimation par défaut par catégorie (configurable) ; les jalons utilisent `remaining_h`.
6. Capacité : on n'affecte pas au-delà de la capacité planifiable ; le reste va au **backlog non planifié**, signalé au coordinateur.
7. Exemples avec l'équipe actuelle :
   - VPN WG down un mardi → Cédric absent → coordinateur (escalade), et tâche de suivi « analyse cause racine » planifiée le jour de Cédric.
   - Job Veeam SPL en échec → compétence `backup` : Angelo (si présent ce jour) sinon coordinateur.
   - 8 tickets utilisateurs + 30 postes avec patchs manquants → Giovanni.

### 7.6 Raffinement par LLM (optionnel, activé par défaut)
Rôle du LLM : reformuler les tâches en actions concrètes, regrouper les doublons restants, proposer des ajustements d'affectation justifiés, rédiger les synthèses (par personne et exécutive), signaler les risques. **Il ne décide pas seul** : le validateur a le dernier mot.

**Entrée** (JSON, ~20–60 k tokens) — blocs ordonnés du plus stable au plus variable pour le prompt caching :
1. Instructions système + skills de rôle (`responsable-informatique`, `ingenieur-coordinateur`) — mis en cache.
2. Politique (axes, règles), taxonomie, équipe (compétences, consignes) — mis en cache.
3. Variable : disponibilités de la période, projets/jalons pertinents, incidents scorés (top 150, champs utiles uniquement), tâches reportées, proposition d'affectation déterministe.
Le contenu issu des sources est encapsulé dans `<source_data>…</source_data>` avec l'instruction explicite que ce sont des données.

**Sortie** : **sortie structurée** (`output_config.format`, type `json_schema`), sans aucun outil — `claude-sonnet-5-5` refuse `tool_choice` forcé (400). Pensée adaptative, `effort` configurable (défaut `medium`), repli serveur `fallbacks="default"` en cas de refus de sécurité (coût compté par modèle servi). Schéma :
```json
{
  "summary_exec": "string (≤ 600 caractères)",
  "per_person": [{"person_id": "int", "summary": "string"}],
  "tasks": [{
    "ref": "string (id de tâche candidate ou 'new-N')",
    "title": "string ≤ 120",
    "actions": ["string ≤ 200"],
    "priority": "P1|P2|P3|P4",
    "assignee_id": "int",
    "estimate_h": "number 0.25–16",
    "due": "date ISO",
    "incident_ids": ["int"],
    "milestone_id": "int|null",
    "rationale": "string ≤ 300"
  }],
  "risks": [{"text": "string", "severity": "low|medium|high"}],
  "escalations": [{"text": "string", "to": "coordinator|manager"}]
}
```
**Validation** (`engine/validator.py`) — rejet de l'élément fautif, pas du plan entier :
- `assignee_id` existe, est actif, présent dans la fenêtre, possède la compétence ; sinon on revient à l'affectation déterministe.
- `incident_ids` / `milestone_id` existent ; une tâche `new-N` sans référence est marquée `origin=llm` et non prioritaire au-delà de P3.
- La priorité ne peut pas être **abaissée** sous celle fixée par une règle d'override.
- Capacités respectées ; sinon déplacement vers backlog.
- Textes : longueur bornée, aucun lien, échappement HTML au rendu.
- Échec de l'appel, JSON invalide, budget dépassé → plan déterministe seul, mention « généré sans IA ».

**Coût** : modèle `claude-sonnet-5-5` ; `max_tokens` 8 000 (quotidien) / 16 000 (hebdomadaire) ; garde-fou mensuel (`setting.llm_monthly_budget_usd`, défaut 30) vérifié avant chaque appel à partir de `llm_call`.

## 8. Ordonnancement (timers systemd, heure Europe/Brussels)
| Timer | Fréquence | Commande |
|---|---|---|
| `vigie-collect@<source>.timer` | toutes les 15 min (Veeam 30 min) | `vigie collect --source <source>` |
| `vigie-plan@daily.timer` | lun–ven 07:15 | `vigie plan --kind daily` |
| `vigie-notify@daily.timer` | lun–ven 07:30 | `vigie notify --plan latest-daily` (publié avec la mention « non validé » si besoin) |
| `vigie-plan@weekly.timer` | lun 06:30 | `vigie plan --kind weekly` |
| `vigie-notify@weekly.timer` | lun 09:00 | `vigie notify --plan latest-weekly` (publication auto si non validé à cette heure) |
| `vigie-housekeeping.timer` | quotidien 02:30 | purge rétention, `pg_dump` chiffré |
| `vigie-selfcheck.timer` | toutes les 5 min | écrit l'état pour zabbix-agent2 (âge dernier plan, sources KO, budget) |

Jours fériés belges exclus du plan quotidien (paquet `holidays`, calendrier BE).

## 9. Interface web
URL : `https://vigie.local.wallindustries.be` (LAN/VPN uniquement). Direction visuelle validée : `docs/ui/maquette.html`.

Pages (FR, responsive, utilisable sur mobile) :
1. **Aujourd'hui** — plan du jour : cartes par personne, P1 en tête, nouveautés, sources KO.
2. **Semaine** — vue par personne × jour, jalons, backlog non planifié, bouton « Valider / Publier ».
3. **Signaux & incidents** — filtres source/société/priorité/statut, détail avec raison du score et lien source.
4. **Équipe** — personnes, compétences (matrice), modèle hebdo, absences (calendrier).
5. **Politique** — axes pondérés, règles, criticités sociétés, SLA ; historique.
6. **Projets** — liste, jalons (vue timeline), charge restante, risques.
7. **Skills de rôle** — éditeur Markdown avec aperçu, versions, diff, export.
8. **Sources** — état, dernière collecte, volume, bouton « tester la connexion » (healthcheck lecture seule).
9. **Paramètres** — horaires, auto-publication, budget LLM, modèle, destinataires, pause globale.
10. **Audit & coûts**.

Accessibilité : contrastes AA, navigation clavier. Aucun script ou police chargés depuis un CDN.

Droits par écran (testés) : Aujourd'hui et Signaux — admin, manager, tech ; Semaine — tous (viewer : plans hebdomadaires seulement) ; Politique et Projets — admin, manager ; Équipe, Skills, Sources, Paramètres, Audit — admin. Un `tech` ne modifie que le statut de ses propres tâches ; tout membre de l'équipe peut commenter. Paramètres : configuration du worker en lecture seule, seule la pause globale est modifiable.

## 10. API interne (JSON, sous `/api`, session OIDC + CSRF)
`GET /api/plans?kind=&date=`, `GET /api/plans/{id}`, `POST /api/plans/{id}/validate`, `PATCH /api/tasks/{id}` (statut, commentaire), `CRUD /api/people|absences|axes|rules|projects|milestones|role-skills|companies|asset-rules`, `GET /api/signals`, `GET /api/incidents`, `GET /api/sources`, `POST /api/sources/{name}/test`, `GET /api/costs`, `GET /healthz` (sans auth, sans détail).
Aucun endpoint ne déclenche d'appel en écriture vers une source (il n'en existe pas). Le CRUD de la configuration passe par les formulaires de l'interface (même couche, mêmes contrôles) ; les endpoints JSON correspondants seront ajoutés si un besoin d'intégration apparaît.

## 11. Configuration et secrets
- `/etc/vigie/vigie.toml` (non secret) : URLs des sources, fréquences, filtres, fuseau, modèle, budgets.
- Secrets : `systemd-creds encrypt` → `/etc/credstore.encrypted/vigie.*`, chargés par `LoadCredentialEncrypted=` dans les seules unités qui en ont besoin.
- Amorçage : `vigie seed --from config/` importe équipe, politique, sociétés, règles, skills de rôle (idempotent).

## 12. Exigences non fonctionnelles
- Disponibilité : best effort, mais tout échec de génération est visible (selfcheck → Zabbix).
- Performance : collecte complète < 2 min ; génération du plan < 3 min.
- Sauvegarde : `pg_dump` quotidien chiffré (age) + VM sauvegardée par Veeam ; restauration documentée et testée.
- Journaux : JSON vers journald, rotation par journald ; jamais de secret ni de contenu de ticket en clair dans les logs.
- Qualité : ruff, mypy strict sur tout `src/`, couverture ≥ 80 % global, ≥ 90 % `engine/`.

## 13. Hors périmètre (v1)
- Toute action sur les systèmes supervisés (acquitter, fermer, redémarrer, modifier).
- Création/mise à jour de tickets NinjaOne (envisageable en v2 uniquement avec validation humaine par action et compte dédié distinct).
- Chat conversationnel dans l'application.
- Accès depuis Internet (accès LAN/VPN uniquement).

## 14. Questions ouvertes (à trancher avant la phase 5)
1. **Veezo** : quel produit exactement (éditeur, version, API disponible) ?
2. Jours de présence de Cédric et d'Angelo (exemples actuels : jeudi et mardi).
3. Le « responsable informatique » est-il le coordinateur lui-même ou une autre personne (direction) qui doit recevoir le rapport hebdomadaire ?
4. Versions installées : FortiAnalyzer, Veeam B&R (12.x / 13), Wazuh (4.x), région NinjaOne (eu/app/ca/oc/us2).
5. NinjaOne Backup est-il utilisé en plus de Veeam ?
6. Canal Teams cible et adresse de la boîte d'envoi (`itbot@…`).
7. Certificat TLS pour `vigie.local.wallindustries.be` : PKI interne existante ou ACME DNS-01 (le domaine `wallindustries.be` est public : DNS-01 possible si le fournisseur DNS a une API) ?
