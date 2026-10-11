# Fixtures de contrat Veeam B&R — capture réelle anonymisée

Capturées le 2026-10-11 vers 13:50 (UTC+2) sur le VBR de production (13.x), compte
`svcveeamvigie` (rôle **Backup Viewer**), avec `scripts/record_fixtures.py veeam` ; réduites et
anonymisées hors dépôt (table de correspondance dans `~/vigie-raw/`, jamais committée), puis
passées par `scripts/anonymize_fixtures.py` et relues.

Réduction : sessions des seuls types de sauvegarde (`JOB_SESSION_TYPES`) limitées aux 3
dernières par job et par VM, plus un exemple de chaque type de bruit (découverte, test
d'identifiants, analyse de conformité…) ; 322 sessions sur 1 357. Descriptions vidées, chemins
des dépôts remplacés par `/backups`, `initiatedBy` → `svc-backup`, noms de VM et de serveurs →
`vm-<société>-NN`, `srv-<société>-NN`, `backup-host-*` ; « NAS TCA » → « NAS EXT » ; domaines
internes → `example.test` ; adresses IPv4 → 192.0.2.0/24. Les noms de sociétés (WI, SPL, WG,
Wasabi par société) sont conservés : ils sont publics dans le dépôt.
`POST_api_oauth2_token.json` : jeton factice. `GET /api/v1/serverInfo` répond 403 au rôle
Backup Viewer : pas de fichier.

Constats (VBR 13.x, différences avec le swagger 1.1-rev0) :
- `jobs/states` : statuts `Enabled` / `Stopped` ; jobs Proxmox en type `Unknown`, sans
  `lastRun` ; les réplications n'y figurent pas (sessions seulement) ;
- `sessions` : `jobId` présent mais sans lien avec les ids de `jobs/states` ; les copies
  produisent une session par VM nommée `<job>\<VM> Backup (Incremental)` ; les réplications
  complètes `<job> (Full)` ;
- aucun événement malware sur la période (filtre `detectedAfterTimeUtcFilter` accepté).

Heure de référence des tests : 2026-10-11T12:00:00Z.
