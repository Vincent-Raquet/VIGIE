---
name: add-connector
description: Procédure pour ajouter ou modifier un connecteur de source de supervision dans Vigie (Zabbix, FortiAnalyzer, NinjaOne, Wazuh, Veeam, Veezo, Microsoft 365, Synology, iDRAC ou tout nouveau système). Utilise ce skill dès qu'il s'agit de créer un fichier dans src/vigie/connectors/, de toucher à une allowlist d'appels, d'ajouter des fixtures de contrat, de mapper des alertes vers des signaux, ou quand l'utilisateur dit « ajoute la source X », « intègre l'API de Y », « collecte les alertes de Z ».
---

# Ajouter un connecteur Vigie

Un connecteur transforme l'état d'un système supervisé en `Signal` normalisés, **en lecture seule**. La sécurité du projet repose sur le fait qu'aucun connecteur ne puisse émettre un appel modifiant le système cible ; c'est pourquoi la procédure commence par l'allowlist et ses tests, avant toute logique métier.

## Étapes

1. **Lire** `docs/CONNECTORS.md` (section de la source si elle existe) et `docs/SECURITY.md` §C1–C2.

2. **Vérifier l'API dans la documentation officielle de la version installée** (demander la version à l'utilisateur si elle n'est pas dans `CONNECTORS.md`). Pour chaque endpoint envisagé, noter : méthode, chemin, paramètres, pagination, rôle/scope minimal requis. Si un point ne peut être confirmé, écrire `# TODO verify: <quoi>` et le signaler dans le résumé de fin — ne pas deviner.

3. **Écrire l'allowlist d'abord** dans `src/vigie/connectors/<name>.py` :
   ```python
   ALLOWLIST = [
       AllowedCall(method="GET", path=r"^/api/v1/jobs/states$", query={"limit", "skip"}),
       # POST de lecture : schéma strict (extra="forbid") et justification obligatoires
       AllowedCall(method="POST", path=r"^/api/oauth2/token$", body_schema=TokenRequest,
                   reason="authentification OAuth2, sans effet sur la configuration"),
       AllowedCall(jsonrpc="problem.get", endpoint="/api_jsonrpc.php",
                   params_schema=ProblemGetParams),
   ]
   ```
   `AllowedCall` refuse à la définition : chemin non ancré (`^/…$`) ou joker large, PUT/PATCH/DELETE, POST sans `body_schema` ou sans `reason`, verbe JSON-RPC d'action sans `override_reason`. Forme complète : `docs/CONNECTORS.md`.

4. **Écrire les tests de sécurité** dans `tests/security/test_<name>_allowlist.py`, avec `tests/security/helpers.py` (`trapped_client`, `assert_forbidden`). Les tests génériques de `test_registered_connectors.py` s'appliquent en plus automatiquement dès l'enregistrement de l'entry point :
   - un appel représentatif d'une action destructrice de ce système (ex. `jobs/{id}/stop`, `host.delete`, `tickets PUT`) lève `ForbiddenCallError` **sans** requête émise (transport simulé qui échoue si appelé) ;
   - les appels de l'allowlist passent.

5. **Fixtures** dans `tests/contract/<name>/` : réponses JSON réalistes **anonymisées** (noms d'hôtes génériques `srv-wi-01`, IP en 192.0.2.0/24, aucun e-mail réel, aucun token). Si l'utilisateur fournit de vraies réponses, les anonymiser avant de les committer.

6. **Implémenter** `healthcheck()`, `collect(since)`, `to_signal()` :
   - uniquement via `self.client` (`SafeClient`) ;
   - sévérité normalisée selon le tableau de `CONNECTORS.md` ;
   - catégorie selon la taxonomie de `SPEC.md §5.3` ;
   - société via `CompanyMapper` (règles `asset_rule`), jamais en dur ;
   - `details` court, sans secret ; `external_id` stable ; agrégation quand le volume est élevé (un signal par société et type plutôt qu'un par poste).

7. **Tests de contrat** `tests/contract/test_<name>.py` : fixtures → signaux attendus (nombre, sévérités, catégories, sociétés, résolution).

8. **Enregistrer** le connecteur (entry point `vigie.connectors` dans `pyproject.toml`), ajouter sa section dans `config/vigie.example.toml` (désactivé par défaut) et la ligne du compte de service dans `CONNECTORS.md §8`.

9. **Vérifier** : `uv run pytest tests/security tests/contract -k <name>`, `uv run vigie collect --source <name> --dry-run --fixtures tests/contract/<name>`, ruff, mypy.

10. **Résumé de fin** à l'utilisateur : endpoints utilisés, compte et rôle à créer côté système cible, points `TODO verify`, éventuelles exceptions POST et leur justification.

## Pièges fréquents
- Un endpoint de « liste » en `POST` (NinjaOne boards, recherche OpenSearch) : autorisé seulement avec un schéma de corps strict.
- Ne pas récupérer de champs inutiles (corps de ticket, données personnelles) : la minimisation protège aussi le coût LLM.
- Ne jamais utiliser `httpx`/`requests` directement : le test statique échouera, et c'est voulu.
