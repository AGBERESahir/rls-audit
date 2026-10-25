# rls-audit

Repère les tables Supabase / PostgreSQL **sans RLS** ou **sans politique**, soit dans un fichier SQL, soit en direct dans ta base.

Sur Supabase, une table sans Row Level Security (RLS) est lisible et modifiable par **n'importe qui possède ta clé `anon`**, c'est-à-dire par tout visiteur de ton site. C'est l'erreur de sécurité la plus courante et la plus grave. Cet outil la détecte en quelques secondes.

Deux façons de l'utiliser :

| Méthode | Quand | Fichier |
|---|---|---|
| Audit d'un fichier SQL | Avant de déployer : schéma, migration | `rls-audit.js` (Node 18+, sans dépendance) |
| Audit en direct | Sur la vraie base, telle qu'elle est maintenant | `rls-audit.sql` (à coller dans Supabase) |

## 1. Auditer des fichiers SQL

```bash
npx github:AGBERESahir/rls-audit schema.sql
# un dossier de migrations entier (lu dans l'ordre alphabétique)
npx github:AGBERESahir/rls-audit supabase/migrations
# ou, depuis une copie locale
node rls-audit.js schema.sql
```

Les instructions sont **rejouées dans l'ordre**, comme le ferait PostgreSQL : une table créée puis supprimée par une migration ultérieure n'est pas signalée, et une RLS désactivée après coup est détectée.

Un exemple à essayer tout de suite : `npm run exemple` (le fichier est dans [`exemple/schema-risque.sql`](exemple/schema-risque.sql)).

```text
🟢 profiles : RLS activée, 1 politique(s).
🔴 messages : RLS non activée : la table est lisible et modifiable par tout porteur de la clé anon.
🔴 notes : RLS non activée alors que 1 politique(s) existent : elles n'ont aucun effet.
🟠 notes : politique « tout le monde » : ALL autorisé sans condition (true).
🟠 vide : RLS activée mais aucune politique : personne n'a accès (sauf la clé service_role).
🟠 posts : politique « ecrit anon » : INSERT ouvert au rôle anon (visiteurs non connectés).
🟡 posts : politique « p2 » : écris (select auth.uid()) plutôt que auth.uid() pour de meilleures performances.
🟠 vue stats : sans security_invoker = true : la vue s'exécute avec les droits de son propriétaire et contourne la RLS.
🟠 fonction secret : SECURITY DEFINER sans SET search_path : risque de détournement de schéma.

1 fichier(s), 2 critique(s), 6 important(s), 4 info(s).
```

### Options

| Option | Effet |
|---|---|
| `<fichier.sql ou dossier>` | Un ou plusieurs fichiers, ou des dossiers (récursif, ordre alphabétique). |
| `--schema=NOM` | Audite aussi ce schéma, en plus de `public`. Répétable. |
| `--strict` | Le code de sortie est `1` aussi pour les alertes 🟠. |
| `--json` | Sortie JSON pour les scripts et la CI. |
| `-h`, `--help` | Affiche l'aide. |

### Lire les résultats

| Pastille | Signification | Action |
|---|---|---|
| 🔴 **critique** | RLS non activée (table ouverte à tous), ou politiques écrites sur une table dont la RLS est désactivée (elles ne servent à rien). | **À corriger immédiatement** : `alter table ... enable row level security;` puis écrire les politiques. |
| 🟠 **important** | RLS sans aucune politique ; écriture autorisée sans condition (`true`) ou au rôle `anon` ; vue sans `security_invoker` ; fonction `SECURITY DEFINER` sans `search_path`. | À examiner : parfois voulu, rarement anodin. |
| 🟡 **info** | Politique sans clause `TO` ; `auth.uid()` non enveloppé dans `(select ...)` ; colonne `user_id` filtrée sans index ; lecture ouverte à tous. | Améliorations de sécurité ou de performance. |
| 🟢 | RLS activée et au moins une politique, sans alerte critique ni importante. | Vérifier que la politique est bien celle voulue. |

**Code de sortie** : `1` s'il y a au moins une alerte 🔴 (ou 🟠 avec `--strict`), `0` sinon. Tu peux donc l'ajouter à une CI ou à un script de déploiement :

```bash
node rls-audit.js supabase/migrations || { echo "RLS manquante"; exit 1; }
```

> Le 🟢 dit qu'une politique existe, pas qu'elle protège les bonnes lignes. Une politique `using (user_id is not null)` donne un 🟢 alors que tout utilisateur connecté lit toutes les lignes. Relis toujours les politiques à la main.

## 2. Auditer la base en direct

1. Ouvre ton projet Supabase, puis **SQL Editor**.
2. Colle le contenu de [`rls-audit.sql`](rls-audit.sql).
3. Exécute les requêtes **une par une** (l'éditeur n'affiche que le résultat de la dernière).

Chaque requête doit renvoyer **0 ligne**. Une ligne affichée est un point à examiner.

| N° | Niveau | Ce qu'elle liste |
|---|---|---|
| 1 | 🔴 | Tables de `public` **sans RLS** |
| 2 | 🔴 | Politiques **sans effet** car la RLS est désactivée sur la table |
| 3 | 🟠 | Tables avec RLS mais **sans aucune politique** |
| 4 | 🟠 | Politiques d'écriture sans condition (`true`) ou ouvertes au rôle `anon` |
| 5 | 🟠 | **Vues** sans `security_invoker = true` (PostgreSQL 15+) |
| 6 | 🟠 | Fonctions **`SECURITY DEFINER`** sans `search_path` fixé |
| 7 | 🟠 | **Buckets de stockage publics** (fichiers lisibles par tous) |
| 8 | 🟡 | Politiques sans clause `TO` (donc valables aussi pour `anon`) |
| 9 | 🟡 | `auth.uid()` non enveloppé dans `(select auth.uid())` |
| 10 | 🟡 | Colonne `user_id` **sans index** |

Les requêtes ne font que **lire** le catalogue PostgreSQL : elles ne modifient rien. Elles ont été testées sur PostgreSQL 16 avec un schéma imitant Supabase.

## Ce que l'analyse des fichiers comprend

Les commentaires (`--` et `/* */`), les chaînes et les corps de fonction `$$ ... $$` sont ignorés. Les instructions reconnues :

- `CREATE TABLE [IF NOT EXISTS]` et `DROP TABLE`
- `ALTER TABLE ... ENABLE | DISABLE | FORCE ROW LEVEL SECURITY`
- `CREATE POLICY` (commande, rôles `TO`, `USING`, `WITH CHECK`) et `DROP POLICY`
- `CREATE INDEX` (pour le contrôle de `user_id`)
- `CREATE VIEW` et `CREATE FUNCTION` (pour `security_invoker` et `SECURITY DEFINER`)

Les noms entre guillemets et les préfixes de schéma sont acceptés.

## Limites à connaître

- **Il lit du texte, il n'exécute rien.** Une table créée depuis le tableau de bord Supabase, par un outil de migration ou par du SQL dynamique n'apparaît pas dans le fichier. Pour l'état réel de la base, utilise `rls-audit.sql`.
- **Il ne juge pas le sens des politiques.** Il détecte les cas évidents (`true`, rôle `anon`), pas une condition qui filtre mal.
- **Il ne regarde pas** les droits `GRANT` accordés aux rôles, ni `ALTER TABLE ... RENAME`, ni les politiques créées dans des fonctions.
- Les noms sont comparés en minuscules.

## Pour aller plus loin

- Commence par ce principe : **RLS activée sur toute table du schéma `public`**, puis des politiques écrites par opération (`select`, `insert`, `update`, `delete`) et limitées au rôle `authenticated`.
- Identifie le propriétaire avec `(select auth.uid())` et indexe la colonne utilisée (`user_id`).
- La clé `service_role` ne doit jamais se retrouver dans le code du navigateur : [secret-guard](https://github.com/AGBERESahir/secret-guard) bloque ce genre de commit.

## Tests

```bash
npm test
```

14 tests : des tests unitaires (découpage SQL, chaque contrôle) et des tests de bout en bout qui lancent la commande. Ils utilisent le lanceur de tests intégré à Node (18 ou plus), sans dépendance. Les tests sont exécutés automatiquement sur GitHub (Node 18, 20 et 22) à chaque push.

## Licence

MIT, voir [LICENSE](LICENSE).
