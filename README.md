# Vigie — pack de spécifications pour Claude Code

Vigie est l'assistant de pilotage IT de l'équipe. Il fait la veille des systèmes de supervision (Zabbix, FortiAnalyzer, NinjaOne, Wazuh, Veeam, Veezo…), priorise les problèmes, et produit chaque jour (version light) et chaque semaine (version complète) un plan de tâches réparti entre les membres de l'équipe selon leurs compétences, leur disponibilité, la politique IT et les projets en cours.

**Principe directeur : Vigie observe et propose, il n'agit jamais sur les systèmes supervisés.**

## Contenu du pack

| Fichier | Rôle |
|---|---|
| `CLAUDE.md` | Mémoire projet lue automatiquement par Claude Code (règles, stack, commandes) |
| `docs/SPEC.md` | Spécification fonctionnelle et technique complète |
| `docs/SECURITY.md` | Modèle de menace et contrôles de sécurité (non négociables) |
| `docs/CONNECTORS.md` | Spécification de chaque connecteur (auth, comptes, endpoints autorisés, mapping) |
| `docs/ROADMAP.md` | Phases de développement avec critères d'acceptation |
| `.claude/settings.json` | Permissions Claude Code (accès secrets interdits, actions sensibles soumises à confirmation) |
| `.claude/skills/add-connector/` | Skill de dev : ajouter un nouveau système supervisé |
| `.claude/skills/debian-deploy/` | Skill de dev : provisionner et durcir la VM Debian via Ansible |
| `.claude/skills/security-review/` | Skill de dev : revue de sécurité avant chaque merge/déploiement |
| `roles/ingenieur-coordinateur/SKILL.md` | Skill de rôle « Ingénieur système & réseau, coordinateur » (contenu métier injecté dans le moteur) |
| `roles/responsable-informatique/SKILL.md` | Skill de rôle « Responsable informatique / CIO » (arbitrage, politique, reporting) |
| `config/*.example.yaml` | Données d'amorçage : équipe, politique, sociétés, règles de scoring |

## Démarrage avec Claude Code

1. Crée un dépôt Git vide et copie-y tout le contenu de ce pack.
2. Ouvre Claude Code à la racine du dépôt.
3. Premier message conseillé :

   > Lis CLAUDE.md puis docs/ROADMAP.md. Passe en plan mode et propose le plan détaillé de la phase 0. N'écris aucun code avant que j'aie validé le plan.

4. Avance phase par phase. À la fin de chaque phase : `/security-review` (skill fourni), tests verts, puis commit.
5. Avant la phase de déploiement, réponds aux questions ouvertes en fin de `docs/SPEC.md`.

## Ce que tu dois préparer de ton côté

- La VM Debian 13 (2 vCPU, 4 Go RAM, 40 Go disque recommandés ; la VM actuelle WI-SRV-VIGIE-01 a 1 vCPU, 4 Go, 30 Go et sert aussi au développement, cf. `docs/DEV.md`), IP fixe dans le VLAN d'admin, accès SSH par clé pour le compte de déploiement.
- Les comptes de service **en lecture seule** listés dans `docs/CONNECTORS.md`.
- Une clé API Anthropic dans un workspace dédié avec une limite de dépense.
- Une app registration Entra ID (connexion SSO + envoi de mail restreint à une boîte `itbot@…`).
