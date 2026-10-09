# Déploiement de Vigie (Debian 13)

La production tourne sur **WI-SRV-VIGIE-01**, la même VM que le développement (cohabitation :
`vigie_dev_on_host: true`). Tout est décrit ici par Ansible : aucune modification manuelle
non reportée dans le code. Le playbook s'exécute **sur la VM elle-même** (`connection: local`).

| Élément | Production | Développement |
|---|---|---|
| Code | `/opt/vigie/releases/<version>`, lien `/opt/vigie/current` | `~/projets/vigie` |
| Base | `vigie` (rôles `vigie_web`, `vigie_worker`, `vigie_migrate`, peer) | `vigie_dev` |
| Configuration | `/etc/vigie/vigie.toml` (gabarit Ansible) | `config/vigie.toml` |
| Secrets | `/etc/credstore.encrypted/vigie.<nom>` (systemd-creds) | `.env.local` |
| Web | Caddy `https://vigie.local.wallindustries.be` → `127.0.0.1:8080` | `127.0.0.1:8000` |

## 1. Premier déploiement

1. **Relire `group_vars/vigie.yml`**, en particulier `admin_networks` (accès SSH : une erreur
   coupe l'accès), `vigie_oidc` (reprendre `tenant_id`, `client_id` et les groupes de
   `config/vigie.toml`) et `backup_age_recipient` (voir § 5).
2. Construire la version : `deploy/build.sh` (wheel + dépendances figées avec empreintes dans
   `dist/`, numéro dans `dist/release.txt`).
3. Simulation puis application :
   ```sh
   cd deploy
   uv run ansible-playbook site.yml --check --diff -K
   uv run ansible-playbook site.yml -K
   ```
   `-K` demande le mot de passe sudo (ne jamais le stocker ni ajouter de `NOPASSWD`).
   En simulation sur une VM vierge, les tâches qui dépendent d'un paquet ou d'un compte
   pas encore créé échouent et sont marquées `...ignoring` : c'est attendu ; seules les
   erreurs non ignorées comptent.
   Au premier passage, les unités Vigie ne sont **pas** activées : le playbook liste les
   secrets manquants.
4. Déposer les secrets (§ 2), mettre `vigie_run_seed: true` le temps d'un passage (équipe,
   sociétés, politique et skills de rôle depuis `config/*.yaml` et `roles/`), relancer le
   playbook, puis remettre `vigie_run_seed: false`.
5. Relancer une seconde fois : le récapitulatif doit afficher **`changed=0`** (idempotence).
6. Contrôles de fin (§ 7).

Les réglages faits en développement dans l'interface (barème, règles d'actifs ajoutées pendant
le rodage) vivent dans la base `vigie_dev` : les reprendre dans l'interface de production
(`Paramètres`) ou les ajouter aux fichiers d'amorçage.

## 2. Secrets

Jamais dans le dépôt, ni dans les journaux, ni dans la sortie d'Ansible. La valeur est lue
sur l'entrée standard et chiffrée par la clé de la machine :

```sh
sudo vigie-secret set zabbix_api_token          # coller, puis Ctrl-D
python3 -c 'import secrets; print(secrets.token_urlsafe(48), end="")' | sudo vigie-secret set web_session_key
sudo vigie-secret set graph_certificate < vigie-mail.pem
sudo vigie-secret list
sudo vigie-secret rm teams_webhook_url
```

| Secret | Unité(s) | Requis si |
|---|---|---|
| `web_session_key` | vigie-web | toujours |
| `entra_client_secret` | vigie-web | `vigie_oidc.client_id` renseigné |
| `anthropic_api_key` | vigie-plan@ | `vigie_llm_enabled` |
| `zabbix_api_token` | vigie-collect@zabbix, vigie-jobs | source zabbix active |
| `graph_certificate` | vigie-notify@ | `vigie_notify_mail_enabled` |
| `teams_webhook_url` | vigie-notify@ | `vigie_notify_teams_enabled` |

**Rotation** : `vigie-secret set <nom>` avec la nouvelle valeur, puis
`sudo systemctl restart vigie-web` (les tâches planifiées relisent le secret à chaque
exécution). Révoquer ensuite l'ancienne valeur à la source.

## 3. Mise à jour de l'application

```sh
git pull && deploy/build.sh
cd deploy && uv run ansible-playbook site.yml --check --diff -K && uv run ansible-playbook site.yml -K
```

Le playbook installe la nouvelle version dans son propre venv (dépendances vérifiées par
empreinte), applique les migrations en `vigie-migrate`, bascule `/opt/vigie/current` et
redémarre `vigie-web`. Les trois dernières versions sont gardées.

**Retour arrière** (si la migration ne l'empêche pas) :
```sh
sudo ln -sfn /opt/vigie/releases/<version précédente> /opt/vigie/current
sudo systemctl restart vigie-web
```

## 4. Unités et horaires

| Unité | Compte | Déclenchement |
|---|---|---|
| `vigie-web.service` | vigie-web | permanent |
| `vigie-collect@<source>.timer` | vigie-worker | toutes les `interval_min` (zabbix : 15 min) |
| `vigie-plan@daily.timer` / `@weekly` | vigie-worker | lun–ven 07:15 / lun 06:30 |
| `vigie-notify@daily.timer` / `@weekly` | vigie-worker | 07:30 / lun 09:00 — **arrêtés** tant que la diffusion est désactivée |
| `vigie-jobs.timer` | vigie-worker | chaque minute (« Tester la connexion » du web) |
| `vigie-housekeeping.timer` | vigie-worker | 02:30 (rétention SPEC §5.2) |
| `vigie-selfcheck.timer` | vigie-worker | 5 min (état lu par l'agent Zabbix) |
| `vigie-backup.timer` | root → vigie-migrate | 02:45 |

Commandes utiles :
```sh
systemctl list-timers 'vigie-*'
journalctl -u 'vigie-collect@zabbix' -n 50
sudo systemctl start vigie-plan@daily          # plan immédiat
sudo -u vigie-worker VIGIE_CONFIG=/etc/vigie/vigie.toml /opt/vigie/current/bin/vigie budget
```

**Accès de secours** (Entra indisponible) : mot de passe à usage unique, affiché une fois.
```sh
sudo -u vigie-web VIGIE_CONFIG=/etc/vigie/vigie.toml /opt/vigie/current/bin/vigie breakglass --enable --ttl 30m
sudo -u vigie-web VIGIE_CONFIG=/etc/vigie/vigie.toml /opt/vigie/current/bin/vigie breakglass --disable
```

## 5. Sauvegardes et restauration

`pg_dump -Fc` chiffré par **age** avec une clé publique ; la clé privée n'est **jamais** sur
la VM (coffre de l'équipe). Les fichiers `/var/backups/vigie/vigie-*.dump.age` (14 jours)
sont emportés par le job Veeam de la VM.

Générer la paire de clés une fois, hors VM : `age-keygen -o vigie-backup.key` ; reporter la
ligne `public key: age1…` dans `backup_age_recipient`.

**Test de restauration** (à faire au déploiement puis chaque trimestre) : copier
temporairement la clé privée sur la VM, puis
```sh
sudo vigie-restore-test /root/vigie-backup.key && sudo shred -u /root/vigie-backup.key
```
Le script restaure la dernière sauvegarde dans une base temporaire, compte quelques tables
et supprime la base.

**Restauration réelle** : arrêter les timers et `vigie-web`, puis
```sh
age -d -i vigie-backup.key vigie-AAAAMMJJ-HHMMSS.dump.age \
  | sudo -u vigie-migrate pg_restore --clean --if-exists --no-owner -d vigie
```

## 6. Certificat HTTPS (AC interne de Caddy)

Caddy émet le certificat de `vigie.local.wallindustries.be` avec sa propre AC. Après le
premier démarrage, la racine est copiée dans `/etc/vigie/caddy-root-ca.crt` (relancer le
playbook si elle n'y est pas encore) : la distribuer par **GPO** (Configuration ordinateur →
Paramètres Windows → Paramètres de sécurité → Stratégies de clé publique → Autorités de
certification racines de confiance). L'entrée DNS interne doit pointer vers `vigie_ip`.

## 7. Contrôles de fin de déploiement

```sh
systemd-analyze security vigie-web.service vigie-plan@daily.service vigie-collect@zabbix.service  # < 2,0
sudo lynis audit system                                         # indice ≥ 80
sudo nft list ruleset
sudo -u vigie-worker curl -sx http://127.0.0.1:3128 https://example.com -o /dev/null -w '%{http_code}\n'      # refusé (403)
sudo -u vigie-worker curl -sx http://127.0.0.1:3128 https://api.anthropic.com -o /dev/null -w '%{http_code}\n' # accepté
sudo systemctl start vigie-collect@zabbix && journalctl -u vigie-collect@zabbix -n 20   # collecte réelle
systemctl list-timers 'vigie-*'
ls -l /var/lib/vigie/selfcheck/
```
Dans Zabbix : hôte `WI-SRV-VIGIE-01`, chiffrement PSK (identité `vigie-01`, clé :
`sudo cat /etc/zabbix/vigie.psk`, à saisir dans l'interface puis à ne pas recopier
ailleurs), items `vfs.file.contents[/var/lib/vigie/selfcheck/<clé>]`.

## 8. Quand le développement quittera la VM

Passer `vigie_dev_on_host: false` : la sortie réseau passe en `drop` pour tous les comptes
(seuls restent DNS, NTP, apt en root, Squid et l'agent Zabbix). Supprimer ensuite
`~/projets/vigie`, `.env.local` et les bases `vigie_dev` / `vigie_test`, et envisager
`ssh_disable_password_auth: true` après avoir vérifié l'accès par clé.
