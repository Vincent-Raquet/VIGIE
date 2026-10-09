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
Première livraison : **Zabbix puis Veeam**. Les autres (NinjaOne → FortiAnalyzer → Wazuh → squelette Veezo) sont ajoutés ensuite un par un, sans toucher au moteur (registre par entry points `vigie.connectors`). Pour chacun, suivre le skill `add-connector` :
- vérification de l'API dans la doc de la version ;
- allowlist + test « appel interdit » ;
- fixtures anonymisées + tests de contrat ;
- mapping société et catégorie ;
- `vigie collect --source X --dry-run --fixtures …`.
- **Acceptation** : chaque connecteur produit des signaux corrects sur fixtures ; aucun test n'émet d'appel réseau.

## Phase 4 — Moteur déterministe (2–3 jours, TDD)
- `normalize`, `correlate`, `scoring`, `rules` (overrides), `assign`, `planner` (quotidien et hebdomadaire), report des tâches, backlog.
- Calendrier : jours de présence, absences, jours fériés BE.
- `vigie plan --kind daily|weekly --no-llm`.
- **Acceptation** : couverture ≥ 90 % sur `engine/` ; scénarios de SPEC §7.5 (VPN un mardi, Veeam SPL, tickets Giovanni) reproduits en tests ; plan lisible en Markdown en sortie CLI.

## Phase 5 — Intégration LLM (1–2 jours)
- `llm.py` : SDK `anthropic`, outil forcé `submit_plan`, prompt caching, budget, retries, journal `llm_call`.
- Prompts dans `engine/prompts/` (système, plan quotidien, plan hebdo), incluant les skills de rôle.
- `validator.py` complet ; repli déterministe.
- Tests avec client Anthropic simulé : sortie valide, invalide, injection, dépassement de budget.
- Utiliser le skill `product-self-knowledge` (claude.ai) ou la doc officielle pour vérifier les paramètres SDK et l'identifiant de modèle.
- **Acceptation** : un plan généré sur fixtures réelles anonymisées coûte < 0,40 $ ; tests d'injection verts.

## Phase 6 — Application web (3–4 jours)
- Utiliser le skill `frontend-design` pour la direction visuelle (sobre, dense, lisible, mode sombre).
- OIDC Entra, RBAC, CSRF, pages de SPEC §9, éditeur des skills de rôle, validation/publication des plans, mise à jour des tâches.
- Tailwind compilé au build ; aucun asset externe.
- **Acceptation** : tests d'autorisation par route et par rôle ; parcours complet sur données de seed ; CSP sans violation dans la console.

## Phase 7 — Notifications (½–1 jour)
- Graph `sendMail` (certificat), webhook Teams, gabarits HTML + texte, allowlist destinataires.
- `vigie notify --plan <id> --dry-run` (écrit les messages dans un dossier au lieu d'envoyer).
- **Acceptation** : rendu vérifié dans Outlook et Teams ; aucun lien non construit par l'application.

## Phase 8 — Déploiement Debian (1–2 jours)
- Suivre le skill `debian-deploy` : Ansible (rôles `base`, `hardening`, `nftables`, `squid`, `postgresql`, `caddy`, `vigie`, `zabbix_agent`, `backup`).
- Unités et timers systemd de SPEC §8 avec sandboxing (`SECURITY.md C8`).
- Secrets via `systemd-creds`.
- **Acceptation** : `systemd-analyze security` < 2,0 par unité ; Lynis ≥ 80 ; un `curl` vers un domaine non autorisé échoue ; collecte réelle de chaque source OK ; premier plan quotidien reçu par mail.

## Phase 9 — Rodage (2 semaines)
- Mode « brouillon uniquement » (pas d'envoi aux collègues), revue quotidienne par le coordinateur.
- Ajustement des poids, seuils, catégories et estimations dans `config/scoring.yaml` ; suivi du coût réel.
- **Acceptation** : le coordinateur juge ≥ 80 % des tâches pertinentes et bien affectées sur 5 jours consécutifs → activation de la diffusion à l'équipe.

## Points à trancher (relevés en phase 0)
| Réf. | Point | Phase |
|---|---|---|
| B ✅ | « Tester la connexion » d'une source depuis l'UI : `vigie-web` n'a ni secret ni sortie réseau → demande mise en file en base, exécutée par le worker. Table `job_request` (payload strict par kind, sans secret) en phase 1. | 1 ✅ / 6 |
| C | `vigie secrets set/rotate` nécessite `systemd-creds`, or `subprocess` est interdit dans `src/` → script shell dans `deploy/`. | 8 |
| D ✅ | Rôle DB `vigie_web` : ajouter UPDATE limité à `plan.status`, `validated_by`, `validated_at`, `published_at` (validation depuis l'UI). | 1 ✅ |
| F | Calibrage du score : hors override et hors bonus politique, le maximum théorique est ≈ 47 (< seuil P1 60) et un Zabbix *High* standard vaut 10 → P4. `B_policy` non borné. Revoir seuils/poids avant d'écrire les tests de scénarios. | 4 |
| H | Overrides : préférer des conditions déclaratives (champ, opérateur, valeur) à des expressions `when` interprétées. | 4 |
| I | `vulnerability` → `patching` (+ `systeme` si serveur) : `category_skill` ne gère qu'une compétence. | 4 |
| K | Skills `frontend-design` (phase 6) et `product-self-knowledge` (phase 5) absents de l'environnement ; utiliser `claude-api` pour la phase 5. | 5 / 6 |
| N ✅ | Rétention 1 an de `audit_log` (SPEC §5.2) incompatible avec un append-only strict → DELETE autorisé par le trigger uniquement pour les lignes de plus de 365 jours ; `at` forcé à `now()` à l'insertion. | 1 |
| O ✅ | `.gitignore` laissait passer de vrais `config/*.yaml` (e-mails, noms) → ignorés, sauf `*.example.yaml`. | 1 |
| M | OIDC : configurer l'app Entra pour n'émettre que les groupes assignés (éviter le *groups overage* qui imposerait un appel Graph depuis `vigie-web`). | 6 |

## Évolutions envisagées (v2)
- Connecteur Microsoft 365 (santé des services, Defender, licences).
- Vue « charge » prévisionnelle sur 4 semaines.
- Création de tickets NinjaOne à partir des tâches, **avec validation humaine action par action** et compte distinct (nécessite une revue de sécurité dédiée).
