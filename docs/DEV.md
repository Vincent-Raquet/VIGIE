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
| Web | `127.0.0.1:8000`, accès par tunnel SSH | `127.0.0.1:8080` derrière Caddy |

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
```

Utilisateur `nadmin` (sans sudo) :
```bash
pipx install uv            # uv n'est pas packagé dans Debian 13
cd ~/projets/vigie
uv sync                    # Python 3.13 système (.python-version), identique à la prod
uv run pre-commit install
cp config/vigie.example.toml config/vigie.toml   # puis database.url = postgresql+psycopg:///vigie_dev
cp .env.example .env.local                       # valeurs factices uniquement
```

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

Contraintes de la cohabitation à traiter en phase 8 :
- SSH : `AllowUsers` doit inclure `nadmin` (pas seulement `deploy`).
- nftables, sortie par défaut `drop` : Claude Code (utilisateur `nadmin`) doit pouvoir joindre `api.anthropic.com`, PyPI et le dépôt Git via Squid.
- Ansible s'exécute sur la VM elle-même (`connection: local`) ou depuis le poste admin.
- Décider du sort des bases `vigie_dev` et `vigie_test` (conservées, pas exposées).
