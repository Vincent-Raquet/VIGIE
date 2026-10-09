---
name: debian-deploy
description: Provisionnement, durcissement et déploiement de Vigie sur la VM Debian 13 via Ansible (dossier deploy/). Utilise ce skill pour tout travail sur les rôles Ansible, les unités et timers systemd, nftables, Squid, Caddy, PostgreSQL, systemd-creds, zabbix-agent2, la sauvegarde de la base, ou quand l'utilisateur parle d'installer, configurer, mettre à jour ou durcir le serveur Vigie, même sans citer Ansible.
---

# Déployer Vigie sur Debian 13

La VM est entièrement configurée par Ansible depuis le poste de l'administrateur : jamais de modification manuelle non reportée dans le code, pour que la machine soit reconstructible et auditable. Toute commande qui touche la VM réelle (`ansible-playbook`, `ssh`, `scp`) demande confirmation à l'utilisateur — `.claude/settings.json` l'impose aussi.

## Structure attendue
```
deploy/
  inventory/hosts.yml          # vigie ansible_host=<IP> ansible_user=deploy
  group_vars/vigie.yml          # variables non secrètes (IPs sources, domaines egress, horaires)
  site.yml
  roles/
    base/          # paquets, locale fr_BE, fuseau Europe/Brussels, chrony, journald persistant, unattended-upgrades
    hardening/     # sshd, sshguard, auditd (+ règles), AppArmor, sysctl, umask, désactivation services inutiles
    nftables/      # politique drop in/out, règles SECURITY.md C6, ensembles d'IP des sources
    squid/         # proxy sortant à allowlist de domaines, logs
    postgresql/    # PG 17, rôles vigie_web / vigie_worker / vigie_migrate, pg_hba en socket unix
    caddy/         # TLS (PKI interne ou ACME DNS-01), en-têtes de sécurité, reverse proxy 127.0.0.1:8080
    vigie/         # utilisateurs système, uv, venv /opt/vigie, migrations, unités et timers, credentials
    zabbix_agent/  # agent2 actif + PSK, UserParameters de selfcheck
    backup/        # pg_dump chiffré (age) quotidien, rétention 14 jours
  README.md        # procédures : premier déploiement, mise à jour, rotation de secrets, restauration
```

## Règles
1. **Idempotence** : deux exécutions successives → `changed=0`. Tester avec `--check --diff` avant d'appliquer.
2. **Secrets** : jamais dans le dépôt, même chiffrés avec ansible-vault, sauf accord explicite de l'utilisateur. Procédure par défaut : l'utilisateur dépose les valeurs sur la VM via `vigie secrets set <name>` (lecture sur stdin, `systemd-creds encrypt --name=<name> - /etc/credstore.encrypted/vigie.<name>`). Le rôle Ansible vérifie seulement leur présence.
3. **Unités systemd** : chaque service et chaque `vigie-*@.service` déclenché par timer reçoit le sandboxing de `SECURITY.md C8`, `User=` dédié, `LoadCredentialEncrypted=` limité aux secrets nécessaires :
   - `vigie-web.service` : `oidc_client_secret`, `session_key`, `db_web_password` ; aucun secret de source.
   - `vigie-collect@.service` : uniquement le secret de la source `%i` (via un drop-in par source).
   - `vigie-plan@.service` : `anthropic_api_key`, `db_worker_password`.
   - `vigie-notify.service` : `graph_cert`, `teams_webhook_url`.
   Ajouter `Environment=HTTPS_PROXY=http://127.0.0.1:3128` pour les unités qui sortent sur Internet.
4. **Timers** : `OnCalendar` en heure locale (`Mon..Fri 07:15 Europe/Brussels`), `Persistent=true`, `RandomizedDelaySec` court pour la collecte.
5. **nftables sortant** : règle `meta skuid vigie-web` n'autorisant que le proxy Squid ; Squid n'autorise pour ce client que `login.microsoftonline.com`.
6. **Mises à jour de l'application** : build d'un wheel versionné en local, copie, `uv pip install` dans un nouveau venv, migration Alembic avec `vigie_migrate`, bascule de lien symbolique `/opt/vigie/current`, redémarrage, et retour arrière possible en rebasculant le lien.

## Vérifications de fin de déploiement (à exécuter et rapporter)
- `systemd-analyze security <unité>` < 2,0 pour chaque unité Vigie.
- `lynis audit system` ≥ 80.
- `nft list ruleset` conforme ; `curl -x http://127.0.0.1:3128 https://example.com` refusé ; `api.anthropic.com` accepté.
- `vigie check` : base OK, chaque source `healthcheck` OK, timers actifs (`systemctl list-timers 'vigie-*'`).
- Zabbix reçoit les items de selfcheck.
- Restauration du `pg_dump` testée sur une base temporaire.
