# rls-audit

Repère les tables Supabase / PostgreSQL **sans RLS** ou **sans politique**, soit dans un fichier SQL, soit en direct dans ta base.

Sur Supabase, une table sans Row Level Security (RLS) est lisible et modifiable par **n'importe qui possède ta clé `anon`**, c'est-à-dire par tout visiteur de ton site. C'est l'erreur de sécurité la plus courante et la plus grave. Cet outil la détecte en quelques secondes.

Deux façons de l'utiliser :

| Méthode | Quand | Fichier |
|---|---|---|
| Audit d'un fichier SQL | Avant de déployer : schéma, migration | `rls-audit.js` (Node 18+, sans dépendance) |
| Audit en direct | Sur la vraie base, telle qu'elle est maintenant | `rls-audit.sql` (à coller dans Supabase) |

## 1. Auditer un fichier SQL

```bash
npx github:AGBERESahir/rls-audit schema.sql
# ou, depuis une copie locale
node rls-audit.js schema.sql
```

Exemple, avec ce `schema.sql` :

```sql
create table public.profiles (id uuid primary key, nom text);
alter table public.profiles enable row level security;
create policy "lecture" on public.profiles for select using (true);

create table notes (id bigint primary key, user_id uuid);
alter table notes enable row level security;

create table paiements (id bigint primary key);
```

Résultat :

```text
🟢 profiles : RLS activée, politique(s) présente(s)
🟠 notes : RLS activée mais aucune politique (personne n’a accès)
🔴 paiements : RLS non activée (accessible à tout porteur de la clé anon)
```

| Pastille | Signification | Action |
|---|---|---|
| 🔴 | RLS non activée : table ouverte à tous. | **À corriger immédiatement** : `alter table ... enable row level security;` puis écrire les politiques. |
| 🟠 | RLS activée mais aucune politique : la table est verrouillée, personne (hors `service_role`) ne peut lire ni écrire. | Écrire les politiques voulues, ou laisser tel quel si la table n'est utilisée que côté serveur. |
| 🟢 | RLS activée et au moins une politique. | Vérifier que la politique est bien celle voulue (voir ci-dessous). |

**Code de sortie** : `1` si au moins une table est en 🔴, `0` sinon. Les 🟠 ne font pas échouer la commande. Tu peux donc l'ajouter à une CI ou à un script de déploiement :

```bash
node rls-audit.js supabase/schema.sql || { echo "RLS manquante"; exit 1; }
```

> Dans l'exemple, `profiles` est en vert mais sa politique est `using (true)` : tout le monde peut lire. Le 🟢 dit seulement qu'une politique existe, pas qu'elle est correcte. L'audit en direct ci-dessous la signale.

## 2. Auditer la base en direct

1. Ouvre ton projet Supabase, puis **SQL Editor**.
2. Colle le contenu de [`rls-audit.sql`](rls-audit.sql).
3. Exécute les trois requêtes. Si l'éditeur n'affiche que le résultat de la dernière, lance-les **une par une**.

| Requête | Ce qu'elle liste | Résultat attendu |
|---|---|---|
| 1 | Tables du schéma `public` **sans RLS** | Aucune ligne |
| 2 | Tables avec RLS mais **sans aucune politique** | Aucune ligne, sauf tables volontairement réservées au serveur |
| 3 | Politiques d'écriture trop permissives (`using (true)` ou `with check (true)`) sur autre chose que `SELECT` | Aucune ligne, sauf cas voulu |

Les requêtes ne font que **lire** le catalogue PostgreSQL (`pg_tables`, `pg_policies`) : elles ne modifient rien.

## Ce que l'analyse du fichier SQL comprend

Le script repère trois instructions, en ignorant les commentaires (`--` et `/* */`) :

- `CREATE TABLE [IF NOT EXISTS] nom`
- `ALTER TABLE [ONLY] nom ENABLE ROW LEVEL SECURITY`
- `CREATE POLICY ... ON nom`

Les noms entre guillemets et le préfixe `public.` sont acceptés.

## Limites à connaître

- **Il lit du texte, il n'exécute rien.** Une table créée depuis le tableau de bord Supabase, par un outil de migration ou par du SQL dynamique n'apparaît pas dans le fichier. Pour l'état réel de la base, utilise `rls-audit.sql`.
- **Schéma `public` uniquement.** Les tables écrites avec un autre schéma (`auth.`, `storage.`, un schéma à toi) ne sont pas gérées correctement par le script.
- **Il ne juge pas le contenu des politiques.** Il vérifie leur présence. Une politique `using (true)` sur des données privées donne un 🟢. Pour ça, la requête 3 de `rls-audit.sql` aide, mais seulement pour les écritures et seulement pour la valeur littérale `true`.
- **Il ne regarde pas** `FORCE ROW LEVEL SECURITY`, les vues (qui doivent être en `security_invoker`), les fonctions `SECURITY DEFINER`, ni les droits (`GRANT`) accordés aux rôles.
- Les noms sont comparés en minuscules : deux tables qui ne diffèrent que par la casse seraient confondues.

## Pour aller plus loin

- Commence par ce principe : **RLS activée sur toute table du schéma `public`**, puis des politiques écrites par opération (`select`, `insert`, `update`, `delete`) et limitées au rôle `authenticated`.
- Identifie le propriétaire avec `(select auth.uid())` et indexe la colonne utilisée (`user_id`).
- La clé `service_role` ne doit jamais se retrouver dans le code du navigateur : [secret-guard](https://github.com/AGBERESahir/secret-guard) bloque ce genre de commit.

## Licence

MIT, voir [LICENSE](LICENSE).
