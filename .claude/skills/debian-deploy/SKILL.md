---
name: debian-deploy
description: Provisionnement, durcissement et déploiement de Vigie sur la VM Debian 13 via Ansible (dossier deploy/), Vigie tournant en conteneurs Docker. Utilise ce skill pour tout travail sur les rôles Ansible, Docker et compose.yaml, les images, les unités et timers systemd, nftables, Squid, le proxy d'entrée Caddy partagé, PostgreSQL, systemd-creds, zabbix-agent2, la sauvegarde de la base, ou quand l'utilisateur parle d'installer, configurer, mettre à jour ou durcir le serveur Vigie, même sans citer Ansible.
---

# Déployer Vigie sur Debian 13

La VM est entièrement configurée par Ansible depuis le poste de l'administrateur : jamais de modification manuelle non reportée dans le code, pour que la machine soit reconstructible et auditable. Toute commande qui touche la VM réelle (`ansible-playbook`, `ssh`, `scp`) demande confirmation à l'utilisateur — `.claude/settings.json` l'impose aussi.

## Structure
```
deploy/
  inventory/hosts.yml           # connexion locale (la VM elle-même)
  group_vars/vigie.yml          # variables non secrètes (IPs sources + sous-réseaux Docker, domaines egress, horaires)
  site.yml
  build.sh                      # dist/ : wheel + requirements.txt à empreintes + release.txt
  docker/vigie/Dockerfile       # image vigie:<release> (contexte = dist/ seul, jamais le dépôt)
  docker/squid/Dockerfile       # image vigie-squid:<AAAAMM>
  roles/
    base/ hardening/            # paquets, locale, journald, unattended-upgrades ; sshd, auditd, AppArmor, sysctl
    postgresql/                 # PG 17 de l'HÔTE, partagé entre applications ; peer + pg_ident par UID
    nftables/                   # table inet vigie seulement (jamais flush ruleset) ; chaîne forward par sous-réseau
    docker/                     # docker-ce officiel, daemon.json ; paquets rootless pour les comptes de dev
    legacy/                     # retrait de l'installation native (legacy_purge)
    edge/                       # Caddy partagé (projet compose /srv/edge), seul à publier 443, sites/*.caddy
    vigie/                      # comptes, images, compose.yaml, squid.conf, vigie-creds, unités de tâches, timers
    zabbix_agent/ backup/       # agent2 PSK (lit /var/lib/vigie/selfcheck) ; pg_dump chiffré age
  README.md                     # procédures : premier déploiement, bascule, mise à jour, secrets, restauration
```

## Règles
1. **Idempotence** : deux exécutions successives → `changed=0`. Tester avec `--check --diff` avant d'appliquer.
2. **Secrets** : jamais dans le dépôt, même chiffrés avec ansible-vault, sauf accord explicite de l'utilisateur. L'utilisateur les dépose par `sudo vigie-secret set <name>` (stdin → `systemd-creds encrypt`). Le rôle vérifie leur présence ; `vigie-creds.service` les déchiffre dans `/run/vigie/creds` (tmpfs, 0400, propriétaire = compte du conteneur lecteur) ; `compose.yaml` ne monte dans chaque service que ses secrets (`secrets:` → `/run/secrets`, `CREDENTIALS_DIRECTORY`) :
   - `web` : `web_session_key`, `entra_client_secret` ; aucun secret de source ni clé IA.
   - `collect-<source>` : uniquement les secrets de la source.
   - `plan`, `plan-requests`, `chat` : `anthropic_api_key`.
   - `notify` : `graph_certificate`, `teams_webhook_url`.
   - `jobs` : secrets des sources ; jamais la clé IA.
3. **Conteneurs** (`tests/security/test_compose.py`) : `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, `user:` = UID du compte `vigie-*` de l'hôte (jamais root), limites mémoire/PID, ni `privileged`, ni socket Docker, ni réseau/PID de l'hôte, aucun port publié (seul Caddy d'`edge` publie 443). Volumes en lecture seule sauf `/var/lib/vigie/selfcheck` pour `selfcheck`. Aucun compte humain dans le groupe `docker` ; le dev utilise Docker rootless.
4. **Réseau** : un réseau Docker par besoin, à sous-réseau fixe dans 172.30.0.0/16 (`vigie_web` et `vigie_worker` internes ; `vigie_egress` pour Squid seul ; `vigie_src_<source>` pour la seule collecte de la source ; `edge` pour Caddy et web à IP fixe). nftables (`forward`) n'autorise que Squid → 443/DNS et chaque `src_<source>` → son `ip:port`/DNS ; tout autre trafic de `@vigie_subnets` est rejeté. Une nouvelle source interne = une entrée `vigie_source_egress` avec son `subnet`.
5. **Unités et timers** : les timers gardent leur nom et `OnCalendar` en heure locale, `Persistent=true`, `RandomizedDelaySec` court pour la collecte. Ils déclenchent `vigie-*.service` (gabarit `vigie-task.service.j2`) : `docker compose run --rm --name <conteneur> <service>`, `ExecStopPost` qui supprime le conteneur, client sandboxé (`RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`). Les services permanents (`squid`, `web`, `chat`) : `restart: on-failure` et `vigie-compose.service` (après `vigie-creds`).
6. **Mises à jour** : `deploy/build.sh` puis playbook : image `vigie:<release>` construite avec `--pull`, migration par `docker compose run --rm migrate` (compte `vigie-migrate`, sans réseau), recréation des services permanents, 3 images gardées. Retour arrière : étiquette précédente. Lancer le playbook au moins une fois par mois (image Squid reconstruite).

## Vérifications de fin de déploiement (à exécuter et rapporter)
- `deploy/README.md` § 7 : conteneurs en lecture seule, sans capacité, non root (`docker inspect`) ; secrets par conteneur (noms seulement) ; web ne joint qu'Entra via Squid ; `example.com` refusé (403) ; `api.anthropic.com` accepté depuis `chat`.
- `lynis audit system` ≥ 80 ; `nft list table inet vigie` conforme.
- `vigie check` (dans un conteneur `plan`) : base OK, chaque source `healthcheck` OK, timers actifs (`systemctl list-timers 'vigie-*'`).
- Zabbix reçoit les items de selfcheck.
- Restauration du `pg_dump` testée sur une base temporaire.
