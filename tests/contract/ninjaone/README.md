# Fixtures de contrat NinjaOne — capture réelle anonymisée

Capturées le 2026-10-11 vers 16:06 (UTC+2) sur l'instance eu.ninjarmm.com, app API « Vigie »
(client credentials, **scope `monitoring` seul**), avec `scripts/record_fixtures.py ninjaone` ;
réduites et anonymisées hors dépôt (table de correspondance dans `~/vigie-raw/`, jamais committée),
passées par `scripts/anonymize_fixtures.py` puis relues.

Réduction et anonymisation :
- tickets : lignes réduites aux colonnes autorisées (`TICKET_COLUMNS`), **sujets remplacés**
  (« Sujet du ticket NN ») ; métadonnées du board limitées à `lastCursorId` ;
- appareils : seuls ceux cités par les alertes (+ 3 par organisation), champs utiles seulement ;
  noms (souvent nominatifs) → `pc-<société>-NN` ;
- organisations : noms des 5 sociétés conservés (publics), autres → « Organisation NN » ;
- domaines internes → `example.test`, IPv4 → 192.0.2.0/24 ; jeton factice.

Constats (différences avec la spécification 2.0.9-draft) :
- `includeColumns` est **ignoré** : le board renvoie description, demandeur, technicien… (filtrés
  à la réception par le connecteur) ; `clientId` vide, organisation donnée par son nom ;
- alertes : `deviceId` seul (pas d'objet `device`), gravité et priorité `NONE` ;
- listes d'appareils paginées (`pageSize`/`after`) ; aucun patch en échec à la date de capture ;
- lecture du board (`POST …/board/4/run`) acceptée avec le scope `monitoring`.

Heure de référence des tests : 2026-10-11T14:10:00Z.
