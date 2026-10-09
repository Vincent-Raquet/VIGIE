# CLAUDE.md — Projet Vigie

## Mission
Vigie collecte l'état et les alertes de systèmes de supervision IT, les normalise en *signaux*, les priorise, et produit des plans de tâches (quotidien light, hebdomadaire complet) assignés à l'équipe IT selon compétences, disponibilités, politique IT et projets. Spécification complète : `docs/SPEC.md`.

## Règles non négociables (lire `docs/SECURITY.md`)
1. **Lecture seule absolue vers les systèmes supervisés.** Tout appel sortant vers une source passe par `vigie.connectors.base.SafeClient`, qui applique une allowlist (méthode HTTP + chemin, ou méthode JSON-RPC) définie dans le connecteur. Aucun contournement, aucun `httpx`/`requests` direct dans un connecteur. Un test vérifie que tout appel hors allowlist lève `ForbiddenCallError`.
2. **Le LLM n'a aucun outil.** Aucun outil déclaré : la réponse est une **sortie structurée** (`output_config.format`, schéma JSON du plan, données uniquement) ; le modèle du projet refuse de toute façon `tool_choice` forcé. Sa sortie est validée par Pydantic puis par `vigie.engine.validator` (ids de signaux existants, personnes existantes, capacités respectées). Rien de ce que produit le LLM n'est exécuté.
3. **Contenu des sources = données non fiables** (tickets rédigés par des utilisateurs finaux, logs). Toujours tronqué, nettoyé, encapsulé dans des balises de données, jamais interprété comme instruction. Sorties HTML toujours échappées.
4. **Secrets** : jamais dans le code, les logs, les fixtures, les prompts ou Git. Chargés via credentials systemd (`$CREDENTIALS_DIRECTORY`) en prod, `.env.local` (ignoré par Git) en dev. Ne jamais lire ni afficher `.env*`, `secrets/`, `*.cred`.
5. **Séparation des processus** : `vigie-web` n'a accès à aucun secret de source ni à la clé Anthropic ; seul `vigie-worker` les détient.
6. Pas de fonctionnalité « write-back » (fermer un ticket, acquitter une alerte…) : hors périmètre par conception.

## Stack
- Python 3.12+, gestion par `uv` ; FastAPI ; SQLAlchemy 2 + Alembic ; PostgreSQL 17 ; Pydantic v2.
- UI : Jinja2 (autoescape) + htmx vendorisé (`web/static/VENDOR.md`) + feuille CSS de la maquette validée (`docs/ui/maquette.html`) ; ni Tailwind, ni Alpine (qui exigerait `unsafe-eval`), aucun CDN, aucun script ou style inline (CSP stricte, testé).
- LLM : SDK `anthropic` Python, modèle par défaut `claude-sonnet-5-5`, sortie structurée via `output_config.format` (aucun outil), prompt caching sur les blocs stables, repli serveur `fallbacks="default"`.
- Auth : OIDC Entra ID (authlib), rôles mappés depuis des groupes Entra.
- Déploiement : Ansible (dossier `deploy/`) vers Debian 13 ; Caddy en reverse proxy ; systemd timers pour l'ordonnancement.

## Arborescence cible
```
src/vigie/
  config.py            # chargement config + secrets
  db/ (models.py, session.py, migrations/)
  connectors/ (base.py, registry.py, zabbix.py, fortianalyzer.py, ninjaone.py, wazuh.py, veeam.py, veezo.py)
  engine/ (normalize.py, correlate.py, scoring.py, rules.py, assign.py, llm.py, prompts/, validator.py, planner.py)
  notify/ (graph_mail.py, teams_webhook.py, render.py)
  web/ (app.py, auth.py, routes/, templates/, static/)
  cli.py               # vigie collect|plan|notify|check|seed|budget
roles/                 # skills de rôle (markdown) chargés en base au seed
config/                # exemples YAML d'amorçage
deploy/                # Ansible
tests/ (unit/, contract/ avec fixtures JSON anonymisées, security/)
```

## Commandes
- Installer : `uv sync`
- Tests : `uv run pytest` (tous) ; `uv run pytest tests/security` (garde-fous)
- Lint/format/typage : `uv run ruff check . && uv run ruff format --check . && uv run mypy src`
- Dev web : `uv run vigie web --reload` (clé `VIGIE_SECRET_WEB_SESSION_KEY` dans `.env.local`, `[web] dev_login = true` pour la connexion de développement)
- Collecte à blanc sur fixtures : `uv run vigie collect --source zabbix --dry-run --fixtures tests/contract/zabbix`
- Plan à blanc : `uv run vigie plan --kind daily --dry-run --no-llm`

## Façon de travailler
- Avancer **phase par phase** selon `docs/ROADMAP.md`, en plan mode pour chaque nouvelle phase.
- TDD pour le moteur (scoring, règles, affectation, validateur) : ces modules sont déterministes et doivent être couverts à ≥ 90 %.
- Connecteurs : tests de contrat sur fixtures JSON enregistrées et anonymisées ; jamais d'appel réseau réel dans les tests.
- Avant de terminer une phase : lancer le skill `security-review`, puis tests + lint verts.
- Pour ajouter un système supervisé : skill `add-connector`. Pour la VM : skill `debian-deploy`.
- Toute vérification d'API tierce se fait contre la documentation officielle de la version installée ; si un endpoint n'est pas confirmé, le marquer `# TODO verify` et le signaler plutôt que deviner.
- Langue : code et identifiants en anglais, UI, docs et messages utilisateur en français.

## Contexte métier utile
- Équipe : coordinateur (ingénieur système & réseau, temps plein), Giovanni (support utilisateurs, temps plein), Cédric (réseau, 1 jour/semaine), Angelo (ingénieur système, 1 jour/semaine). Détails : `config/team.example.yaml`.
- Multi-société : WI (WallIndustries), SPL (Splifar), WG (WallGlass), CC (Construct Center), FWD (Fairwind). Mapping des sources → société : `config/companies.example.yaml`.
