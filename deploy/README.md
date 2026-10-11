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
| `veeam_password` | vigie-collect@veeam, vigie-jobs | `vigie_veeam_host` renseigné (§11) |
| `ninjaone_client_secret` | vigie-collect@ninjaone, vigie-jobs | `vigie_ninjaone_client_id` renseigné (§12) |

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
| `vigie-jobs.timer` | vigie-worker | chaque minute (« Tester la connexion » du web ; secrets des sources) |
| `vigie-plan-requests.timer` | vigie-worker | chaque minute (« Générer le plan maintenant » du web ; clé IA) |
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

## 9. Fin de rodage (phase 9) : activer la diffusion à l'équipe

Pendant le rodage, le coordinateur juge chaque tâche du plan quotidien sur « Aujourd'hui »
(pertinente, bien affectée) ; la page **Plans › Rodage** compte les jours validés
(≥ 90 % des tâches jugées, ≥ 80 % pertinentes et bien affectées). Le barème se règle dans
**Paramètres › Barème** (effet au plan suivant).

Quand la page Rodage affiche « Critère atteint » (5 jours ouvrés consécutifs) :
1. Déposer le certificat de l'application « Vigie Mail » : `sudo vigie-secret set graph_certificate < vigie-mail.pem`.
2. `group_vars/vigie.yml` : `vigie_notify_mail_enabled: true`, puis
   `vigie_notify_draft_only: false` (les messages partent alors à chaque personne).
   Conseil : un premier passage avec `draft_only` encore à `true` pour vérifier l'envoi
   réel au seul coordinateur.
3. `uv run ansible-playbook site.yml -K` : les timers `vigie-notify@daily/weekly` s'activent.

## 10. Lynis : suggestions volontairement écartées

Indice après le premier déploiement : 70 ; les corrections suivantes sont dans les rôles
(`hardening`, `squid`) : modules noyau inutiles bloqués, sysctl du profil Lynis, login.defs
(umask 027, âge et hachage des mots de passe), passwdqc, pam-tmpdir, comptabilité des
processus, sysstat, debsums, needrestart (liste seule), rkhunter, bannières, SSH
(`MaxAuthTries 3`, `LogLevel VERBOSE`), Squid (`Safe_ports`, `reply_body_max_size`,
`squid.conf` en 0640).

Écartées, avec la raison :
| Suggestion | Raison |
|---|---|
| Permissions 600 sur `postgresql.conf`, `pg_ctl.conf`, `start.conf` (DBS-1828) | `pg_wrapper` (psql, pg_dump) lit ces fichiers pour trouver le cluster : la sauvegarde en `vigie-migrate` casserait. Aucun secret dedans (authentification peer). |
| `AllowTcpForwarding no`, `MaxSessions 2` | Tunnel SSH du développement ; appliqués automatiquement avec `vigie_dev_on_host: false`. |
| Port SSH non standard | Sécurité par l'obscurité ; SSH déjà limité à `admin_networks` par nftables. |
| Mot de passe GRUB (BOOT-5122) | Console de la VM protégée par l'hyperviseur. |
| `/home`, `/var`, `/tmp` sur partitions séparées | Partitionnement fixé à l'installation de la VM. |
| fail2ban | sshguard en place. |
| apt-listbugs | Peut bloquer les mises à jour non interactives. |
| Journaux vers un hôte externe, AIDE | Prévu avec l'agent Wazuh (connecteur à venir). |

## 11. Source Veeam B&R (10.10.10.27, API REST 9419)

Prérequis côté VBR : compte local `svcveeamvigie` (rôle Backup Viewer, jeton confirmé le 2026-10-11),
pare-feu Windows ouvrant 9419/tcp depuis `vigie_ip` (192.168.10.17).

1. **Certificat du VBR** (auto-signé) : le récupérer, puis comparer son empreinte avec celle
   affichée sur le serveur (`certlm.msc` ou
   `Get-ChildItem Cert:\LocalMachine\My | Format-List Subject,Thumbprint,DnsNameList`) :
   ```sh
   mkdir -p ~/vigie-ca && openssl s_client -connect 10.10.10.27:9419 </dev/null 2>/dev/null \
     | openssl x509 > ~/vigie-ca/veeam.pem
   openssl x509 -in ~/vigie-ca/veeam.pem -noout -subject -ext subjectAltName -fingerprint -sha1
   ```
   Le nom DNS du certificat (`VBR` ci-dessous) est la valeur de `vigie_veeam_host` ; il doit
   résoudre vers 10.10.10.27 par le DNS interne.
2. **Le rôle est-il accepté par l'API ?** Test du jeton, TLS vérifié avec ce certificat ; le
   mot de passe est lu au clavier, passé par l'entrée standard (absent de la liste des
   processus) et n'est écrit nulle part :
   ```sh
   VBR=nom-du-certificat; read -rs VPW && printf '%s' "$VPW" | curl -s -o /dev/null \
     -w '%{http_code}\n' --cacert ~/vigie-ca/veeam.pem --resolve "$VBR:9419:10.10.10.27" \
     "https://$VBR:9419/api/oauth2/token" -H 'x-api-version: 1.3-rev1' \
     --data-urlencode grant_type=password --data-urlencode username=svcveeamvigie \
     --data-urlencode password@-; unset VPW
   ```
   `200` : on continue. `400`/`401`/`403` : s'arrêter et décider du rôle (voir
   `docs/CONNECTORS.md` §5) — ne pas passer le compte en Backup Administrator par défaut.
3. **Dev** : dans `config/vigie.toml`, `[sources.veeam]` (voir `config/vigie.example.toml`) avec
   `enabled = true`, `base_url = "https://<nom du certificat>:9419"`,
   `ca_bundle = "/home/nadmin/vigie-ca/veeam.pem"` ; dans `.env.local` :
   `VIGIE_SECRET_VEEAM_PASSWORD=…`. Puis :
   ```sh
   VIGIE_ENV=dev uv run vigie check --sources
   VIGIE_ENV=dev uv run python scripts/record_fixtures.py veeam      # captures hors dépôt
   VIGIE_ENV=dev uv run vigie collect --source veeam --dry-run        # collecte réelle à blanc
   ```
4. **Production** : `vigie_veeam_host: <nom du certificat>` dans `group_vars/vigie.yml`,
   `sudo vigie-secret set veeam_password`, puis le playbook (certificat copié dans
   `/etc/vigie/ca/veeam.pem`, règle nftables et timer `vigie-collect@veeam` toutes les 30 min).
   Vérifier avec « Tester la connexion » (page Sources) : le build affiché donne
   `api_version` (13.0.1 → `1.3-rev1`, 13.1 → `1.3-rev2`).

## 12. Source NinjaOne (eu.ninjarmm.com, via Squid)

1. **Jeton** (scope `monitoring`, lecture seule) : le secret client est lu au clavier, passé
   par l'entrée standard, jamais affiché ni écrit :
   ```sh
   read -rp "Client ID : " CID; read -rsp "Client secret : " CS; echo
   printf '%s' "$CS" | curl -s -o /dev/null -w 'HTTP %{http_code}\n' \
     https://eu.ninjarmm.com/ws/oauth/token --data-urlencode grant_type=client_credentials \
     --data-urlencode "client_id=$CID" --data-urlencode client_secret@- --data-urlencode scope=monitoring
   unset CS
   ```
2. **Dev** : `[sources.ninjaone]` dans `config/vigie.toml` (modèle : `config/vigie.example.toml`,
   `client_id`, `ticket_board_id = 0` pour commencer) et `VIGIE_SECRET_NINJAONE_CLIENT_SECRET=…`
   dans `.env.local`, puis `VIGIE_ENV=dev uv run python scripts/record_fixtures.py ninjaone`
   (capture hors dépôt ; relève organisations, boards et statuts).
3. **Correspondance** : ids d'organisation → sociétés dans `config/companies.yaml` (règles
   `org_id`), id du board et statuts à traiter dans la configuration.
4. **Production** : `vigie_ninjaone_client_id`, `vigie_ninjaone_board_id`,
   `vigie_ninjaone_statuses` dans `group_vars/vigie.yml` ; `sudo vigie-secret set
   ninjaone_client_secret` ; playbook (Squid autorise `eu.ninjarmm.com` au worker, timer
   `vigie-collect@ninjaone` toutes les 15 min).
