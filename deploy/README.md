# Déploiement de Vigie (Debian 13)

La production tourne sur **WI-SRV-VIGIE-01**, la même VM que le développement (cohabitation :
`vigie_dev_on_host: true`). Depuis la phase 10, Vigie tourne **en conteneurs Docker** sur un
hôte durci par Ansible (PostgreSQL de l'hôte partagé, proxy d'entrée Caddy partagé avec les
futures applications). Tout est décrit ici par Ansible : aucune modification manuelle non
reportée dans le code. Le playbook s'exécute **sur la VM elle-même** (`connection: local`).

| Élément | Production | Développement |
|---|---|---|
| Code | image `vigie:<version>` (projet compose `/srv/vigie`) | `~/projets/vigie`, conteneur rootless (`scripts/dev`) |
| Base | `vigie` sur le PostgreSQL de l'hôte (rôles `vigie_web`, `vigie_worker`, `vigie_migrate`, peer par UID) | `vigie_dev` |
| Configuration | `/etc/vigie/vigie.toml` (gabarit Ansible), montée en lecture seule | `config/vigie.toml` |
| Secrets | `/etc/credstore.encrypted/vigie.<nom>` (systemd-creds) → `/run/secrets` du seul conteneur concerné | `.env.local` |
| Web | proxy d'entrée `edge` (Caddy, `/srv/edge`) `https://vigie.local.wallindustries.be` → `vigie-web:8080` (réseau Docker `edge`) | `127.0.0.1:8000` |

Rôles, dans l'ordre : `base`, `hardening`, `postgresql`, `nftables`, `docker` (Docker Engine
du dépôt officiel, Docker rootless pour les comptes de dev), `legacy` (retrait de l'ancienne
installation native), `edge` (proxy d'entrée partagé), `vigie`, `zabbix_agent`, `backup`.

## 1. Premier déploiement

1. **Relire `group_vars/vigie.yml`**, en particulier `admin_networks` (accès SSH : une erreur
   coupe l'accès), `vigie_oidc` (reprendre `tenant_id`, `client_id` et les groupes de
   `config/vigie.toml`), `backup_age_recipient` (voir § 5) et les sous-réseaux Docker
   (`vigie_networks`, `vigie_source_egress[].subnet`, `edge_subnet`, `docker_address_pool`),
   qui ne doivent chevaucher aucun réseau de l'entreprise.
2. Construire la version : `deploy/build.sh` (wheel + dépendances figées avec empreintes dans
   `dist/`, numéro dans `dist/release.txt`). Le playbook en fait l'image `vigie:<version>` :
   le contexte de construction ne contient que `dist/`, jamais le dépôt.
3. Simulation puis application :
   ```sh
   cd deploy
   uv run ansible-playbook site.yml --check --diff -K
   uv run ansible-playbook site.yml -K
   ```
   `-K` demande le mot de passe sudo (ne jamais le stocker ni ajouter de `NOPASSWD`).
   En simulation sur une VM vierge, les tâches qui dépendent de Docker ou d'un compte pas
   encore créés échouent : c'est attendu, seule l'application compte.
   Au premier passage, les services Vigie ne sont **pas** activés : le playbook liste les
   secrets manquants.
4. Déposer les secrets (§ 2), mettre `vigie_run_seed: true` le temps d'un passage (équipe,
   sociétés, politique et skills de rôle depuis `config/*.yaml` et `roles/`), relancer le
   playbook, puis remettre `vigie_run_seed: false`.
5. Relancer une seconde fois : le récapitulatif doit afficher **`changed=0`** (idempotence).
6. Contrôles de fin (§ 7).

Les réglages faits en développement dans l'interface (barème, règles d'actifs ajoutées pendant
le rodage) vivent dans la base `vigie_dev` : les reprendre dans l'interface de production
(`Paramètres`) ou les ajouter aux fichiers d'amorçage.

### Bascule depuis l'installation native (phase 8 → phase 10, une fois)

Fenêtre de 15 à 30 min, interface indisponible pendant la construction de l'image.
1. `deploy/build.sh`, puis simulation (`--check --diff`) : relire le diff de nftables
   (plus de `flush ruleset`, nouvelle chaîne `forward`).
2. Application du playbook. Il installe Docker, arrête `vigie-web`, `vigie-chat`, Caddy et
   Squid natifs (rôle `legacy`), reprend l'AC interne de Caddy dans `/srv/edge/data` (même
   racine : rien à rediffuser par GPO), construit les images, applique les migrations dans un
   conteneur et réécrit les timers pour lancer des conteneurs.
3. Contrôles de fin (§ 7).
4. **Retour arrière** (si la bascule échoue) : `/opt/vigie/current` est toujours là.
   ```sh
   sudo systemctl stop vigie-compose 'vigie-*.timer'
   cd /srv/edge && sudo docker compose down
   git checkout <commit d'avant la phase 10> && cd deploy && uv run ansible-playbook site.yml -K
   ```
5. Une semaine plus tard, `legacy_purge: true` (`group_vars/vigie.yml`) le temps d'un passage :
   suppression des paquets `caddy` et `squid`, de `/opt/vigie` et de l'ancienne AC de Caddy, et
   des règles nftables de l'installation native (443 en entrée, sorties par compte `vigie-*`).
   Laisser ensuite `legacy_purge: true`.

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

| Secret | Service(s) de `compose.yaml` | Requis si |
|---|---|---|
| `web_session_key` | web | toujours |
| `entra_client_secret` | web | `vigie_oidc.client_id` renseigné |
| `anthropic_api_key` | plan, plan-requests, chat | `vigie_llm_enabled` |
| `zabbix_api_token` | collect-zabbix, jobs | source zabbix active |
| `graph_certificate` | notify | `vigie_notify_mail_enabled` |
| `teams_webhook_url` | notify | `vigie_notify_teams_enabled` |
| `veeam_password` | collect-veeam, jobs | `vigie_veeam_host` renseigné (§11) |
| `ninjaone_client_id`, `ninjaone_client_secret` | collect-ninjaone, jobs | `vigie_ninjaone_enabled: true` (§12) |
| `fortianalyzer_api_key` | collect-fortianalyzer, jobs | `vigie_fortianalyzer_enabled: true` (§15) |
| `defender_client_id`, `defender_private_key` | collect-defender, jobs | `vigie_defender_enabled: true` (§13) |
| `wazuh_api_password`, `wazuh_indexer_password` | collect-wazuh, jobs | `vigie_wazuh_enabled: true` (§17) |

Au démarrage, `vigie-creds.service` déchiffre les secrets dans `/run/vigie/creds` (mémoire,
0700 root, un fichier 0400 par secret au nom du compte qui le lit) ; chaque conteneur ne
reçoit dans `/run/secrets` que les siens.

**Rotation** : `vigie-secret set <nom>` avec la nouvelle valeur, puis
`sudo systemctl restart vigie-creds` (redéchiffre et redémarre l'interface, la discussion et
Squid ; les tâches planifiées lisent le secret à chaque exécution). Révoquer ensuite
l'ancienne valeur à la source.

## 3. Mise à jour de l'application

```sh
git pull && deploy/build.sh
cd deploy && uv run ansible-playbook site.yml --check --diff -K && uv run ansible-playbook site.yml -K
```

Le playbook construit l'image `vigie:<version>` (image Python de base tirée à jour,
dépendances vérifiées par empreinte), applique les migrations dans le conteneur `migrate`
(compte `vigie-migrate`, sans réseau) et recrée l'interface et la discussion sur la nouvelle
image. Les tâches planifiées prennent la nouvelle image à leur exécution suivante. Les trois
dernières images sont gardées. L'image Squid est reconstruite (paquets Debian à jour) au
premier passage de chaque mois : **lancer le playbook au moins une fois par mois**, même sans
nouvelle version, et `deploy/build.sh` + playbook pour rafraîchir l'image Python.

**Règles de priorité (overrides)** : `vigie seed` ne réécrit pas le barème existant, et
`seed --update` réécrirait aussi l'équipe et les sociétés. Après une mise à jour qui modifie
les overrides de `config/scoring.example.yaml` (copié dans `/etc/vigie/seed`) :
```sh
cd /srv/vigie
sudo docker compose run --rm migrate overrides --from /etc/vigie/seed --dry-run
sudo docker compose run --rm migrate overrides --from /etc/vigie/seed
```
Seules les règles d'override changent ; les réglages de la page Barème sont conservés
(journal d'audit `scoring_overrides_sync`).

**Retour arrière** (si la migration ne l'empêche pas) : remettre l'étiquette précédente
(`sudo docker image ls vigie`) dans `/srv/vigie/compose.yaml` et relancer les services, ou
plus simplement revenir au commit précédent et relancer `deploy/build.sh` + playbook.
```sh
sudo sed -i 's|image: vigie:.*|image: vigie:<version précédente>|' /srv/vigie/compose.yaml
sudo systemctl restart vigie-compose
```
Le playbook suivant réécrira `compose.yaml` d'après `dist/release.txt`.

## 4. Services, tâches et horaires

| Unité (hôte) | Conteneur (service compose, compte) | Déclenchement |
|---|---|---|
| `vigie-creds.service` | — (déchiffre les secrets dans `/run/vigie/creds`) | démarrage |
| `vigie-compose.service` | `squid` (proxy), `web` (vigie-web), `chat` (vigie-worker, si `vigie_llm_enabled`) | permanent |
| `vigie-collect@<source>.timer` | `collect-<source>` (vigie-worker) | toutes les `interval_min` (zabbix : 15 min) |
| `vigie-plan@daily.timer` / `@weekly` | `plan` (vigie-worker) | lun–ven 07:15 / lun 06:30 |
| `vigie-notify@daily.timer` / `@weekly` | `notify` (vigie-worker) | 07:30 / lun 09:00 — **arrêtés** tant que la diffusion est désactivée |
| `vigie-jobs.timer` | `jobs` (vigie-worker) | chaque minute (« Tester la connexion » du web ; secrets des sources) |
| `vigie-plan-requests.timer` | `plan-requests` (vigie-worker) | chaque minute (« Générer le plan maintenant » du web ; clé IA) |
| `vigie-housekeeping.timer` | `housekeeping` (vigie-worker, sans réseau) | 02:30 (rétention SPEC §5.2) |
| `vigie-selfcheck.timer` | `selfcheck` (vigie-worker, sans réseau) | 5 min (état lu par l'agent Zabbix) |
| `vigie-backup.timer` | — (root → vigie-migrate, sur l'hôte) | 02:45 |

Chaque tâche est un conteneur éphémère (`docker compose run --rm`) qui ne reçoit que ses
secrets et ses réseaux. Journaux : journald (`journalctl -u vigie-collect@zabbix` pour l'unité,
`journalctl -t <conteneur>` pour la sortie du conteneur (`vigie-web-1`, `vigie-collect-zabbix`…), `-t vigie-squid`, `-t edge-caddy`).

Commandes utiles :
```sh
systemctl list-timers 'vigie-*'
journalctl -u 'vigie-collect@zabbix' -n 50
sudo systemctl start vigie-plan@daily          # plan immédiat
cd /srv/vigie && sudo docker compose ps
sudo docker compose --project-directory /srv/vigie run --rm plan budget
```

**Accès de secours** (Entra indisponible) : mot de passe à usage unique, affiché une fois.
```sh
cd /srv/vigie
sudo docker compose run --rm breakglass breakglass --enable --ttl 30m
sudo docker compose run --rm breakglass breakglass --disable
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

**Restauration réelle** : arrêter les timers et `vigie-compose`, puis
```sh
age -d -i vigie-backup.key vigie-AAAAMMJJ-HHMMSS.dump.age \
  | sudo -u vigie-migrate pg_restore --clean --if-exists --no-owner -d vigie
```

## 6. Certificat HTTPS (AC interne de Caddy, proxy d'entrée partagé)

Le proxy d'entrée (`/srv/edge`, projet compose `edge`, seul conteneur qui publie un port :
443 sur `vigie_ip`) émet le certificat de `vigie.local.wallindustries.be` avec sa propre AC,
reprise de l'ancien Caddy natif. La racine est copiée dans `/srv/edge/root-ca.crt` : la
distribuer par **GPO** (Configuration ordinateur → Paramètres Windows → Paramètres de
sécurité → Stratégies de clé publique → Autorités de certification racines de confiance).
L'entrée DNS interne doit pointer vers `vigie_ip`.

**Ajouter une application** derrière ce proxy : déposer son fichier de site dans
`/srv/edge/sites/<appli>.caddy` (par son rôle Ansible, comme `vigie.caddy`), rattacher son
service web au réseau Docker externe `edge`, puis redémarrer Caddy
(`cd /srv/edge && sudo docker compose restart`). Le portail suivra le même modèle ; pour une
application d'un autre serveur, `reverse_proxy https://<serveur>` dans son fichier de site.

## 7. Contrôles de fin de déploiement

```sh
sudo lynis audit system                                         # indice ≥ 80
sudo nft list table inet vigie
cd /srv/vigie
sudo docker compose ps                                          # squid, web, chat : running
# Sortie : web n'atteint que Entra par Squid, rien en direct.
sudo docker compose exec web python -c "import urllib.request as u; print(u.urlopen('https://login.microsoftonline.com', timeout=10).status)"   # 200
sudo docker compose exec web python -c "import urllib.request as u; u.urlopen('https://example.com', timeout=10)"                                  # 403 (Squid)
sudo docker compose exec chat python -c "import urllib.request as u; u.urlopen('https://api.anthropic.com', timeout=10)"                           # réponse HTTP (404/401), pas 403
# Secrets : noms seulement, jamais les valeurs.
sudo docker compose exec web ls /run/secrets                   # web_session_key, entra_client_secret
# (jamais `run` pour web : son adresse fixe sur « edge » est prise par le conteneur en marche)
sudo docker inspect --format '{{.Name}} ro={{.HostConfig.ReadonlyRootfs}} caps={{.HostConfig.CapDrop}} user={{.Config.User}}' $(sudo docker ps -q)
sudo systemctl start vigie-collect@zabbix && journalctl -u vigie-collect@zabbix -n 20   # collecte réelle
systemctl list-timers 'vigie-*'
ls -l /var/lib/vigie/selfcheck/
# Interface : 200 pour /healthz, 303 vers /login pour les écrans (dont /aide)
curl -s -o /dev/null -w '%{http_code}\n' --cacert /srv/edge/root-ca.crt https://vigie.local.wallindustries.be/healthz
curl -s -o /dev/null -w '%{http_code}\n' --cacert /srv/edge/root-ca.crt https://vigie.local.wallindustries.be/aide
```
Dans Zabbix : hôte `WI-SRV-VIGIE-01`, chiffrement PSK (identité `vigie-01`, clé :
`sudo cat /etc/zabbix/vigie.psk`, à saisir dans l'interface puis à ne pas recopier
ailleurs), items `vfs.file.contents[/var/lib/vigie/selfcheck/<clé>]`.

## 8. Quand le développement quittera la VM

Passer `vigie_dev_on_host: false` : la sortie de l'hôte passe en `drop` (seuls restent DNS,
NTP, apt et images Docker en root, et l'agent Zabbix ; les conteneurs restent régis par la
chaîne `forward`) et plus aucun compte n'a Docker rootless. Supprimer ensuite
`~/projets/vigie`, `.env.local`, les bases `vigie_dev` / `vigie_test` et le Docker rootless
de `nadmin` (`dockerd-rootless-setuptool.sh uninstall`), et envisager
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
4. Annoncer à l'équipe l'aide en ligne, en particulier **Aide › Mode d'emploi** (`/aide/mode-emploi`) : lire son plan, mettre à jour ses tâches, commenter.

## 10. Lynis : suggestions volontairement écartées

Indice après le premier déploiement : 70 ; les corrections suivantes sont dans les rôles
(`hardening`, Squid du rôle `vigie`) : modules noyau inutiles bloqués, sysctl du profil Lynis, login.defs
(umask 027, âge et hachage des mots de passe), passwdqc, pam-tmpdir, comptabilité des
processus, sysstat, debsums, needrestart (liste seule), rkhunter, bannières, SSH
(`MaxAuthTries 3`, `LogLevel VERBOSE`), Squid (`Safe_ports`, `reply_body_max_size`,
`squid.conf` lisible par le seul conteneur Squid, en lecture seule).

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
| Journaux vers un hôte externe, AIDE | Prévu avec l'agent Wazuh (connecteur prêt, §17 ; agent sur la VM à installer). |

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
4. **Production** : `vigie_ninjaone_enabled: true`, `vigie_ninjaone_board_id`,
   `vigie_ninjaone_statuses` dans `group_vars/vigie.yml` ; `sudo vigie-secret set
   ninjaone_client_id` et `sudo vigie-secret set ninjaone_client_secret` (le client id
   ressemble à une clé : gitleaks le refuse dans le dépôt) ; playbook (Squid autorise `eu.ninjarmm.com` au worker, timer
   `vigie-collect@ninjaone` toutes les 15 min).

## 13. Source Microsoft Defender (vulnérabilités, incidents, appareils inactifs)

App Entra « Vigie Defender » (tenant de `vigie_oidc`), permissions d'**application** accordées
par un administrateur : `WindowsDefenderATP` → `Vulnerability.Read.All`, `Machine.Read.All` ;
`Microsoft Graph` → `SecurityIncident.Read.All` (et `SecurityAlert.Read.All`, non utilisée).
Authentification par **certificat**, aucun secret client. **Le même certificat sert en dev et en
prod** (`docs/CONNECTORS.md` §9) : `~/vigie-ca/defender.crt` (public) et `~/vigie-ca/defender.key`
(privée, 0600, dossier 0700).

1. **Dev** : `[sources.defender]` dans `config/vigie.toml` (modèle : `config/vigie.example.toml`,
   `tenant_id`, `client_id`, `certificate` et `private_key_file` vers `~/vigie-ca`), puis
   `VIGIE_ENV=dev uv run vigie check --sources` et
   `VIGIE_ENV=dev uv run python scripts/record_fixtures.py defender` (capture hors dépôt,
   `~/vigie-raw/defender`).
2. **Correspondance** : domaine DNS → société (`config/companies.example.yaml`, règles
   `hostgroup_suffix` de la source `defender`) ; étiquette Defender « FWD » pour les appareils
   Fairwind du domaine partagé `fleurinvest.fleurus.be`.
3. **Production** :
   ```sh
   printf '%s' "<GUID de l'app>" | sudo vigie-secret set defender_client_id
   sudo vigie-secret set defender_private_key < ~/vigie-ca/defender.key
   ```
   (le GUID ressemble à une clé : gitleaks le refuse dans le dépôt), puis
   `vigie_defender_enabled: true` dans `group_vars/vigie.yml` et le playbook : il copie `vigie_defender_cert_file` (défaut `~/vigie-ca/defender.crt`) dans
   `/etc/vigie/ca/defender.crt`, autorise `eu.api.security.microsoft.com` dans Squid et active
   `vigie-collect@defender` (toutes les 60 min).
4. **Surveillance de l'expiration** : `vigie check` avertit sous 30 jours ; selfcheck
   `/var/lib/vigie/selfcheck/cert.defender.days_left` (item Zabbix
   `vfs.file.contents[/var/lib/vigie/selfcheck/cert.defender.days_left]`, déclencheurs
   `< 30` avertissement, `< 7` haute, `= -1` certificat illisible) ; signal Vigie
   « Certificat de l'application Vigie Defender » (P2 sous 21 jours, P1 sous 7).

### Renouvellement du certificat (aux deux endroits)
Entra accepte plusieurs certificats sur l'app : on ajoute le nouveau avant de retirer l'ancien,
sans interruption.
```sh
cd ~/vigie-ca && umask 077
openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes -subj "/CN=Vigie Defender" \
  -keyout defender.key.new -out defender.crt.new
```
1. Entra → app « Vigie Defender » → *Certificats et secrets* → *Certificats* → téléverser
   `defender.crt.new` (jamais la clé).
2. Bascule **dev** : `mv defender.key.new defender.key && mv defender.crt.new defender.crt`,
   puis `VIGIE_ENV=dev uv run vigie check --sources` (OK, nouveau nombre de jours).
3. Bascule **prod**, coup sur coup (entre les deux, une collecte peut échouer sans dommage) :
   `sudo vigie-secret set defender_private_key < ~/vigie-ca/defender.key`, puis le playbook
   (nouveau certificat dans `/etc/vigie/ca/defender.crt`) ; vérifier avec « Tester la
   connexion » (page Sources, exécuté par `vigie-jobs` qui reçoit le secret).
4. Entra : supprimer l'ancien certificat. En cas de fuite de la clé : supprimer d'abord le
   certificat compromis dans Entra (coupe dev **et** prod), puis refaire 1 à 3.


## 14. Sauvegarde Veeam de cette VM : traitement invité (SSH depuis 10.10.10.27)

Le traitement invité de Veeam se connecte en SSH à la VM, y dépose un composant et l'exécute
avec les droits root. Sans règle, nftables ignore la connexion (erreur Veeam « Socket error
10022 » au bout de 2 minutes). Variables (`group_vars/vigie.yml`) :
- `veeam_guest_sources` (défaut `[10.10.10.27]`) : SSH ouvert à ces seules adresses (règle
  nftables distincte de `admin_networks`), exemptées de sshguard ;
- `veeam_guest_enabled`, `veeam_guest_user` (`svcveeam`), `veeam_guest_auth` (`password`
  par défaut, ou `key` avec `veeam_guest_pubkey`) : compte avec sudo sans mot de passe
  (exigé par Veeam, tracé par auditd), **connexion acceptée depuis `veeam_guest_sources`
  seulement** (bloc `Match` de sshd : depuis toute autre adresse, aucune méthode
  d'authentification) ; ni redirection de ports ni X11. Le serveur Veeam lit déjà tout le
  disque de la VM : ce compte élargit peu sa portée, mais son mot de passe ne doit exister que
  dans Veeam.

1. Lancer le playbook (compte créé verrouillé, sans mot de passe).
2. Déposer le mot de passe sur la VM (jamais dans le dépôt ; politique passwdqc) :
   ```sh
   sudo passwd svcveeam
   ```
3. Veeam : *Credentials & Passwords* → *Add* → *Linux account (user name and password)* :
   `svcveeam`, ce mot de passe, cocher *Elevate account privileges automatically*, décocher
   *Use su if sudo fails*. Dans le job : *Guest Processing* → *Credentials* → cette identité
   pour la VM Vigie, puis *Test Now*.
4. Vérifier côté VM : `journalctl -u ssh` montre la connexion de `svcveeam` depuis 10.10.10.27.

La base est aussi sauvegardée chaque nuit par `pg_dump` chiffré (§5) : le traitement invité
apporte la cohérence applicative de l'image, pas la seule copie de la base.

## 15. Source FortiAnalyzer 8.0 (192.168.240.104, JSON-RPC)

Le certificat d'usine du FAZ ne porte que son n° de série (`CN=FAZVMSTM25009422`, ni SAN ni
IP) : Vigie l'appelle par ce nom, que `compose.yaml` déclare dans les conteneurs `collect-fortianalyzer` et `jobs` (`extra_hosts`)
(`vigie_fortianalyzer_ip`, `vigie_fortianalyzer_name`), et n'approuve que ce certificat.

1. **Certificat** (public), exporté et vérifié sur la VM :
   ```sh
   openssl s_client -connect 192.168.240.104:443 </dev/null 2>/dev/null | openssl x509 > ~/vigie-ca/fortianalyzer.pem
   openssl x509 -in ~/vigie-ca/fortianalyzer.pem -noout -fingerprint -sha256
   # attendu : C0:39:80:86:7C:DF:99:D8:28:B5:63:92:5E:60:3F:C3:FC:15:85:78:EC:B9:C0:D1:26:54:1C:25:4C:57:0C:58
   ```
2. **Dev** : `[sources.fortianalyzer]` dans `config/vigie.toml` (modèle : `config/vigie.example.toml`,
   `enabled = true`, `ca_bundle = "~/vigie-ca/fortianalyzer.pem"`), clé dans `.env.local`
   (`VIGIE_SECRET_FORTIANALYZER_API_KEY=…`), puis `VIGIE_ENV=dev uv run vigie check --sources` et
   `VIGIE_ENV=dev uv run python scripts/record_fixtures.py fortianalyzer`.
3. **Production** : `printf '%s' "<clé API>" | sudo vigie-secret set fortianalyzer_api_key`,
   puis le playbook (réseau `vigie_src_fortianalyzer` vers 192.168.240.104:443 seulement, `extra_hosts`, certificat
   dans `/etc/vigie/ca/fortianalyzer.pem`, timer `vigie-collect@fortianalyzer` toutes les 15 min).
4. **Renouvellement du certificat du FAZ** (nouvelle VM, nouveau certificat) : refaire 1, vérifier
   l'empreinte sur la console du FAZ, relancer le playbook.


## 16. Renuméroter les réseaux Docker (passage à 10.10.100.0/22)

Les réseaux Docker à sous-réseau fixe (edge, vigie_*, sources) et `docker0` ne peuvent pas
changer de plage en place : il faut arrêter les projets compose, supprimer les réseaux,
puis relancer les playbooks, qui les recréent avec le plan d'adressage de
`group_vars/vigie.yml`. Coupure de Vigie **et** de Portal : environ 15 minutes.

1. **Avant** : vérifier que `10.10.100.0/22` n'est routé nulle part dans l'entreprise, et
   noter les timers actifs (les `vigie-notify@*` sont volontairement arrêtés pendant le
   rodage : ne relancer que ceux de la liste) :
   ```sh
   systemctl list-timers 'vigie-*' --no-legend | awk '{print $NF}' | tee ~/timers-actifs.txt
   ```
2. **Arrêt** (Portal, Vigie, puis le proxy d'entrée, propriétaire du réseau `edge`) :
   ```sh
   sudo systemctl stop $(cat ~/timers-actifs.txt)
   sudo systemctl stop portal-compose vigie-compose
   sudo docker compose --project-directory /srv/portal down
   sudo docker compose --project-directory /srv/vigie down
   sudo docker compose --project-directory /srv/edge down
   sudo docker network ls          # plus aucun réseau edge / vigie_* ; sinon docker network rm
   ```
3. **Vigie** (le rôle docker pose `bip` et le pool, puis redémarre le démon ; nftables,
   edge et vigie suivent avec les nouvelles plages) :
   ```sh
   cd ~/projets/vigie/deploy
   uv run --group deploy ansible-playbook site.yml --check --diff -K
   uv run --group deploy ansible-playbook site.yml -K
   ```
4. **Portal** (adresses edge de `deploy/ansible/group_vars/portal.yml`, déjà alignées) :
   ```sh
   cd ~/projets/portal && deploy/build.sh
   cd deploy/ansible && uv run --group deploy ansible-playbook site.yml -K
   ```
5. **Contrôles** :
   ```sh
   ip -4 -o addr | grep -E 'docker0|br-'      # 10.10.100.x uniquement, plus de 172.x
   sudo nft list set inet vigie vigie_subnets  # sous-réseaux 10.10.100.x
   sudo systemctl start $(cat ~/timers-actifs.txt)
   systemctl list-timers 'vigie-*'
   ```
   Puis Vigie et Portal dans le navigateur, un « Tester la connexion » par source dans
   Vigie, et `journalctl -t vigie-squid -n 20` (Squid accepte bien les nouveaux réseaux).

Retour arrière : revenir au commit précédent de `group_vars/vigie.yml` (et de
`portal.yml`) et refaire la même procédure.

## 17. Source Wazuh 4.12+ (192.168.240.148, API 55000 et indexer 9200)

Installation tout-en-un `wazuh.egc-sa.local` : Vigie appelle le manager et l'indexer par ce nom,
que `compose.yaml` déclare dans les conteneurs `collect-wazuh` et `jobs` (`extra_hosts`), et
n'approuve que les certificats épinglés (étape 3). Le réseau `vigie_src_wazuh` (10.10.100.192/28) ne sort
que vers 192.168.240.148, ports 55000 et 9200 (`port: [55000, 9200]` dans `vigie_source_egress`).

1. **Comptes** (lecture seule) :
   - API : utilisateur `svc-vigie` lié au rôle prédéfini `readonly` (Server management →
     Security → Users), rien d'autre ;
   - indexer : utilisateur interne `svc-vigie` et rôle `vigie_read`, sans permission de cluster
     (Indexer management → Security), par exemple :
     ```yaml
     vigie_read:
       index_permissions:
         - index_patterns: ["wazuh-alerts-4.x-*", "wazuh-states-vulnerabilities-*"]
           allowed_actions: ["indices:data/read/search"]
     ```
     rôle mappé au seul utilisateur `svc-vigie`. Ne jamais lui donner `readall`, ni l'accès aux
     archives (`wazuh-archives-*`, journaux complets).
     Si la recherche répond 403 malgré ce rôle, ajouter la seule permission de cluster
     `cluster_composite_ops_ro` (lecture), comme dans l'exemple de la documentation Wazuh.
2. **Indexer joignable** (serveur Wazuh) : il n'écoute d'usine que sur `127.0.0.1`. Étendre la
   seule couche HTTP (le transport reste local : pas de contrôles de démarrage « production »)
   dans `/etc/wazuh-indexer/opensearch.yml`, après sauvegarde :
   ```yaml
   http.host: ["127.0.0.1", "192.168.240.148"]
   ```
   puis `sudo systemctl restart wazuh-indexer` et `sudo ss -ltnp | grep 9200`. Réserver le port
   9200 à Vigie (192.168.10.17) dans le pare-feu du serveur Wazuh (ou de l'hyperviseur).
   Retour arrière : retirer la ligne et redémarrer.
3. **Certificats épinglés** (publics, sur la machine qui lance Ansible, hors dépôt) : la clé de
   l'AC de l'OVA n'existe plus, ses certificats ne portent pas le nom du serveur (API :
   `localhost` ; indexer : `127.0.0.1`) et `root-ca.pem`, sans extension *Key Usage*, est refusé
   par le mode X.509 strict. Chaque API n'approuve que son propre certificat, sans contrôle du nom :
   ```sh
   cd ~/vigie-ca   # root-ca.pem du serveur (/etc/wazuh-indexer/certs/) copié dans wazuh.pem
   openssl s_client -connect 192.168.240.148:55000 </dev/null 2>/dev/null | openssl x509 > wazuh-api.pem
   openssl s_client -connect 192.168.240.148:9200  </dev/null 2>/dev/null | openssl x509 > wazuh-indexer.pem
   openssl verify -CAfile wazuh.pem wazuh-indexer.pem          # attendu : OK
   openssl x509 -in wazuh-api.pem -noout -fingerprint -sha256  # comparer avec le serveur :
   #   sudo openssl x509 -in /var/ossec/api/configuration/ssl/server.crt -noout -fingerprint -sha256
   ```
   Le certificat de l'API expire le 2027-03-13 (celui de l'indexer en 2036) : à son
   renouvellement, refaire cette étape et relancer le playbook.
4. **Dev** : `[sources.wazuh]` dans `config/vigie.toml` (modèle : `config/vigie.example.toml`,
   `enabled = true`, `api_ca_bundle`, `indexer_ca_bundle`, `verify_hostname = false`), mots de passe dans `.env.local`
   (`VIGIE_SECRET_WAZUH_API_PASSWORD=…`, `VIGIE_SECRET_WAZUH_INDEXER_PASSWORD=…`), puis
   `VIGIE_ENV=dev uv run vigie check --sources` et
   `VIGIE_ENV=dev uv run python scripts/record_fixtures.py wazuh` (le JWT n'est jamais enregistré).
5. **Production** : `sudo vigie-secret set wazuh_api_password` et
   `sudo vigie-secret set wazuh_indexer_password`, `vigie_wazuh_enabled: true` dans
   `group_vars/vigie.yml`, puis le playbook (certificats dans `/etc/vigie/ca/wazuh-api.pem` et `wazuh-indexer.pem`, timer
   `vigie-collect@wazuh` toutes les 15 min).

## 18. Squid ne redémarre plus (« Address already in use »)

Symptôme : `vigie-squid-1` arrêté, le playbook échoue sur « Services permanents à jour » avec
`failed to set up container networking: Address already in use` ; connexion Entra, IA,
NinjaOne et Defender coupées. Cause (incident du 2026-10-23) : les IP fixes de Squid (`.34`,
`.66`, `.50`) étaient les premières adresses distribuées par Docker ; pendant un arrêt de
Squid, `web` ou `chat` les ont reçues. Depuis, chaque réseau a une plage automatique
(`range` de `vigie_networks`, `ip_range` de `compose.yaml`) qui exclut les IP fixes
(`tests/security/test_compose.py`). Une plage ne change pas en place : recréer les réseaux
de Vigie (coupure de Vigie seul, quelques minutes ; `edge` et Portal ne sont pas touchés) :
```sh
systemctl list-timers 'vigie-*' --no-legend | awk '{print $NF}' | tee ~/timers-actifs.txt
sudo systemctl stop $(cat ~/timers-actifs.txt)
sudo systemctl stop vigie-compose
sudo docker compose --project-directory /srv/vigie down
sudo docker network ls | grep vigie_     # plus aucun réseau vigie_* ; sinon docker network rm
cd ~/projets/vigie/deploy && uv run --group deploy ansible-playbook site.yml -K
sudo systemctl start $(cat ~/timers-actifs.txt)
sudo docker ps --format '{{.Names}} {{.Status}}' | grep vigie   # squid, web, chat « Up »
```

