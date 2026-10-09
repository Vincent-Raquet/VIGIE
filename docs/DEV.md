# Vigie — Environnement de développement

Le développement se fait **directement sur la VM cible** WI-SRV-VIGIE-01 (192.168.10.17, Debian 13), sous le compte `nadmin`. Dev et future prod cohabitent sur la même machine ; ce document fixe le cloisonnement et liste les modifications système faites à la main, que le déploiement Ansible (phase 8) devra reprendre ou adopter.

## Cloisonnement dev / prod

| | Dev | Prod (phase 8) |
|---|---|---|
| Code | `~/projets/vigie` (nadmin) | `/opt/vigie/current` (wheel versionné) |
| Utilisateurs | `nadmin` | `vigie-web`, `vigie-worker` (sans shell ni sudo) |
| Bases PostgreSQL | `vigie_dev`, `vigie_test` (rôle `nadmin`, peer) | `vigie` (`vigie_web`, `vigie_worker`, `vigie_migrate`) |
| Configuration | `config/vigie.toml` (ignoré par Git) via `VIGIE_CONFIG` | `/etc/vigie/vigie.toml` via les unités systemd |
| Secrets | `.env.local` (factices) si `VIGIE_ENV=dev` | `systemd-creds`, `$CREDENTIALS_DIRECTORY` |
| Web | `127.0.0.1:8000`, accès par tunnel SSH | `https://vigie.local.wallindustries.be` (Caddy → `127.0.0.1:8080`) |

Règles :
- **Aucun secret de production sur la VM tant que Claude Code y travaille** (cf. `SECURITY.md §3`).
- `config.py` ne lit jamais `/etc/vigie/vigie.toml` implicitement : sans `--config` ni `VIGIE_CONFIG`, c'est `./config/vigie.toml`.
- `.env.local` n'est lu que si `VIGIE_ENV=dev` et si `CREDENTIALS_DIRECTORY` est absent.

## Installation (une fois)

Modifications système (sudo), à reprendre par Ansible :
```bash
sudo apt install -y pipx gitleaks postgresql-17
sudo -u postgres createuser nadmin
sudo -u postgres createdb -O nadmin vigie_dev
sudo -u postgres createdb -O nadmin vigie_test
# Rôles d'exécution (phase 1), sans login ; nadmin membre pour tester les droits en SET ROLE
sudo -u postgres psql -c "CREATE ROLE vigie_web NOLOGIN; CREATE ROLE vigie_worker NOLOGIN; CREATE ROLE vigie_migrate NOLOGIN; GRANT vigie_web, vigie_worker TO nadmin;"
```

Utilisateur `nadmin` (sans sudo) :
```bash
pipx install uv            # uv n'est pas packagé dans Debian 13
cd ~/projets/vigie
uv sync                    # Python 3.13 système (.python-version), identique à la prod
uv run pre-commit install
cp config/vigie.example.toml config/vigie.toml   # puis database.url = postgresql+psycopg:///vigie_dev
cp .env.example .env.local                       # valeurs factices uniquement
uv run alembic upgrade head                      # schéma dans vigie_dev
uv run vigie seed                                # amorçage depuis config/ et roles/
```

## Base de données
- Migrations : `uv run alembic upgrade head` (URL : `-x url=…`, sinon `database.url` de la config). Nouvelle migration : `uv run alembic revision --autogenerate -m "…"`, puis **ajouter les droits** des nouvelles tables (un test vérifie que chaque table est lisible par `vigie_web` et `vigie_worker`).
- Les tests utilisent `vigie_test` (ou `$VIGIE_TEST_DATABASE_URL`) : schéma supprimé puis recréé à chaque session, chaque test dans une transaction annulée.
- Seed : `vigie seed` lit `config/<nom>.yaml`, sinon `<nom>.example.yaml` (avertissement). Il crée ce qui manque sans jamais modifier l'existant ; `--update` écrase depuis les fichiers, `--dry-run` valide sans écrire. Les vrais `config/*.yaml` sont ignorés par Git.

### Propriétaire du schéma
`audit_log` est append-only par triggers, ce qui ne tient **que contre les rôles qui ne possèdent pas la table** : un propriétaire peut désactiver ou supprimer un trigger.
- **En prod, le propriétaire du schéma et de toutes les tables est `vigie_migrate`** (utilisé uniquement par les migrations au déploiement), **jamais un rôle d'exécution** (`vigie_web`, `vigie_worker`). Des tests le vérifient (`tests/security/test_db_grants.py`).
- En dev, `nadmin` possède `vigie_dev` et `vigie_test` : acceptable car aucune donnée réelle n'y est stockée.

Dans `~/.bashrc` :
```bash
export VIGIE_ENV=dev
export VIGIE_CONFIG="$HOME/projets/vigie/config/vigie.toml"
```

## Commandes courantes
```bash
uv run pytest                                          # tous les tests (réseau TCP bloqué)
uv run ruff check . && uv run ruff format --check . && uv run mypy src
uv run vigie --help
uv run vigie check
uv run pre-commit run --all-files                      # ruff, mypy, gitleaks
```

Interface web (à partir de la phase 6), depuis le poste admin :
```bash
ssh -L 8000:127.0.0.1:8000 nadmin@192.168.10.17
# puis http://127.0.0.1:8000
```

## Écarts à reprendre par Ansible (phase 8)

| Écart | Rôle Ansible concerné |
|---|---|
| Paquets `pipx`, `gitleaks`, `postgresql-17` installés à la main | `base`, `postgresql` |
| Cluster PostgreSQL `17/main` par défaut, rôle `nadmin`, bases `vigie_dev` et `vigie_test` | `postgresql` (adopter le cluster existant sans le recréer) |
| `uv` installé via pipx pour `nadmin` | `vigie` (installation de `uv` pour le déploiement) |
| Rôles `vigie_web`, `vigie_worker`, `vigie_migrate` (NOLOGIN) ; `nadmin` membre de `vigie_web` et `vigie_worker` | `postgresql` : passer les rôles en LOGIN (peer + `pg_ident`), **retirer l'appartenance de `nadmin`** (sinon il lit la base de prod en `SET ROLE`) |

Contraintes de la cohabitation à traiter en phase 8 :
- SSH : `AllowUsers` doit inclure `nadmin` (pas seulement `deploy`).
- nftables, sortie par défaut `drop` : Claude Code (utilisateur `nadmin`) doit pouvoir joindre `api.anthropic.com`, PyPI et le dépôt Git via Squid.
- Ansible s'exécute sur la VM elle-même (`connection: local`) ou depuis le poste admin.
- Décider du sort des bases `vigie_dev` et `vigie_test` (conservées, pas exposées).

## MCP de développement (Claude Code)
Claude Code accède aux MCP Zabbix et Veeam pour vérifier les API et capturer des fixtures (phase 3). Les droits sont limités côté serveur MCP ; Claude Code n'appelle que des outils de lecture, et chaque appel reste soumis aux permissions Claude Code.

- `.mcp.json` (racine, **ignoré par Git** : adresses internes) déclare les deux serveurs en transport HTTP natif, sans `npx` ni `mcp-remote`. Les jetons y sont référencés par `${ZABBIX_MCP_TOKEN}` et `${VEEAM_MCP_TOKEN}`.
- Jetons : `~/.config/vigie/mcp-tokens.sh` (droits 600, dossier 700), chargé par `~/.bashrc`. Y coller les valeurs **sans** le préfixe `Bearer `, puis relancer Claude Code depuis un nouveau shell et approuver les serveurs du projet.
- Rotation : régénérer le jeton côté serveur MCP, remplacer la valeur dans le fichier, relancer Claude Code.
- Les jetons sont présents dans l'environnement du shell de Claude Code : `.claude/settings.json` doit interdire `Read(~/.config/vigie/**)` et toute commande les mentionnant.
- **Zabbix** (2026-10-09) : passé en **HTTPS** (adresse interne, cf. `claude mcp list`) et déclaré hors de `.mcp.json` (portée locale/utilisateur de Claude Code : `claude mcp list`). Son certificat est **auto-signé** : Node refuse la connexion (`DEPTH_ZERO_SELF_SIGNED_CERT`) de façon intermittente. Correction : certificat émis par l'AC interne, et `export NODE_EXTRA_CA_CERTS=/chemin/ac-interne.pem` dans `~/.bashrc`. **Jamais** `NODE_TLS_REJECT_UNAUTHORIZED=0` (coupe la vérification TLS de toutes les connexions de Claude Code).
- ⚠️ **Veeam** reste en **HTTP clair** (jeton et données en clair sur le LAN) : reverse proxy TLS à prévoir.
- Limites du MCP Zabbix : réponses tronquées (≈ 75 objets, marqueur `_truncated`) ; pas d'outil pour `proxy.get` ni `apiinfo.version` ; réponses préfixées d'un avertissement « données non fiables » à retirer avant traitement.

### Capturer des fixtures de contrat
1. Interroger le MCP (sortie volumineuse → fichier) et extraire le JSON dans le scratchpad, **hors du dépôt**.
2. Écrire un fichier de correspondance (vrais noms → noms génériques, domaines internes), lui aussi hors du dépôt.
3. `uv run python scripts/anonymize_fixtures.py BRUT/ tests/contract/<source>/ --map correspondance.json` (échoue si un nom réel subsiste).
4. Relire les chaînes produites (hôtes, titres, tags), documenter les modifications synthétiques dans le `README.md` du dossier, puis `gitleaks` avant commit.

## Interface web en développement
1. `.env.local` : `VIGIE_SECRET_WEB_SESSION_KEY=<python -c "import secrets; print(secrets.token_urlsafe(48))">` ; pour Entra, `VIGIE_SECRET_ENTRA_CLIENT_SECRET=…`.
2. `config/vigie.toml` : `[web] dev_login = true` et, pour Entra, `[web.oidc]` (tenant, client, groupes). L'URI de redirection `http://localhost:8000/auth/callback` doit être déclarée dans l'application Entra (plus `https://vigie.local.wallindustries.be/auth/callback` pour la prod).
3. `uv run vigie web --reload`, puis http://localhost:8000. La connexion de développement n'existe que si `VIGIE_ENV=dev`, `dev_login = true` et écoute sur 127.0.0.1.
4. « Tester la connexion » d'une source dépose une demande : `uv run vigie jobs --run-pending` l'exécute (rôle du worker).
