---
name: security-review
description: Revue de sécurité de Vigie à exécuter avant de clore chaque phase de la roadmap, avant chaque déploiement, et après toute modification d'un connecteur, de l'intégration LLM, de l'authentification, des notifications ou du déploiement. Utilise ce skill aussi quand l'utilisateur demande « est-ce sûr ? », « vérifie la sécurité », « relis avant de commit » ou parle de prompt injection, de secrets ou de droits.
---

# Revue de sécurité Vigie

Le but est de prouver, par des vérifications concrètes, que les garanties de `docs/SECURITY.md` tiennent toujours. Lire ce document d'abord. Produire un rapport court : ✅ conforme, ⚠️ à améliorer, ❌ bloquant (empêche de clore la phase), avec fichier et ligne.

## Vérifications

### 1. Lecture seule (C1, C2)
- `rg -n "httpx|requests|urllib|aiohttp|socket|subprocess" src/vigie/connectors` → seul `base.py` peut importer `httpx`.
- Pour chaque connecteur : allowlist ancrée ; tout `POST`/`PUT`/`DELETE`/`PATCH` justifié en commentaire avec schéma de corps ; test « appel interdit » présent.
- Aucune fonction nommée ou se comportant comme une action (`ack`, `close`, `start`, `stop`, `update`, `delete`, `create`) dans `connectors/`.

### 2. LLM (C3, C4, C5)
- `llm.py` n'expose que l'outil `submit_plan` ; `tool_choice` forcé ; aucun autre outil, aucun MCP.
- Les données sources passent par la fonction de masquage puis sont encapsulées dans `<source_data>`.
- `validator.py` couvre : assignee, références, présence, compétence, capacité, override non abaissé, longueurs, absence de liens.
- Aucun texte du LLM n'est passé à `eval`, à un shell, à une requête SQL brute, ni rendu sans échappement (`|safe` interdit sauf sortie du sanitiseur).

### 3. Secrets (C7)
- `gitleaks detect` propre ; aucun secret dans `tests/`, `config/`, `deploy/`.
- Les logs ne contiennent ni tokens ni corps de réponses (vérifier le filtre de journalisation et ses tests).

### 4. Web (C9)
- Chaque route a un contrôle de rôle et un test par rôle ; CSRF sur les méthodes mutantes ; cookies `Secure/HttpOnly/SameSite`.
- CSP sans `unsafe-inline` pour les scripts ; aucun asset externe.

### 5. Dépendances
- `uv run pip-audit` sans vulnérabilité haute non justifiée ; versions verrouillées dans `uv.lock`.

### 6. Déploiement (si concerné)
- Durcissement des conteneurs, répartition des secrets et réseaux par service (`compose.yaml`) conformes au skill `debian-deploy` ; nftables (chaîne `forward`) et Squid conformes à C6.

### 7. Tests
- `uv run pytest tests/security` vert ; ajouter un test pour toute faille corrigée pendant la revue.

Terminer par la liste des ❌ à corriger avant de continuer. Ne jamais marquer la phase comme terminée s'il reste un ❌.
