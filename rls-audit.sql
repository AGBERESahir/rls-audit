-- rls-audit : audit EN DIRECT du schéma public d'un projet Supabase / PostgreSQL.
-- À coller dans l'éditeur SQL de Supabase (lecture seule : aucune requête ne modifie la base).
-- Chaque requête doit renvoyer 0 ligne ; chaque ligne affichée est un point à examiner.

-- 1. 🔴 CRITIQUE : tables sans RLS (lisibles et modifiables avec la clé anon)
select schemaname, tablename
from pg_tables
where schemaname = 'public' and rowsecurity = false
order by tablename;

-- 2. 🔴 CRITIQUE : politiques qui n'ont aucun effet car la RLS est désactivée sur la table
select p.tablename, p.policyname
from pg_policies p
join pg_tables t on t.schemaname = p.schemaname and t.tablename = p.tablename
where p.schemaname = 'public' and t.rowsecurity = false
order by p.tablename, p.policyname;

-- 3. 🟠 IMPORTANT : tables avec RLS mais sans aucune politique (personne n'y accède, sauf service_role)
select t.tablename
from pg_tables t
left join pg_policies p on p.schemaname = t.schemaname and p.tablename = t.tablename
where t.schemaname = 'public' and t.rowsecurity = true
group by t.tablename
having count(p.policyname) = 0
order by t.tablename;

-- 4. 🟠 IMPORTANT : écriture sans condition ou ouverte au rôle anon
select tablename, policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public'
  and cmd <> 'SELECT'
  and (
    trim(both '() ' from coalesce(qual, '')) = 'true'
    or trim(both '() ' from coalesce(with_check, '')) = 'true'
    or 'anon' = any (roles)
  )
order by tablename, policyname;

-- 5. 🟠 IMPORTANT : vues qui contournent la RLS (sans security_invoker = true, Postgres 15+)
select n.nspname as schema, c.relname as vue
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'v'
  and n.nspname = 'public'
  and not coalesce(c.reloptions::text, '') ilike '%security_invoker=true%'
order by c.relname;

-- 6. 🟠 IMPORTANT : fonctions SECURITY DEFINER sans search_path fixé
select n.nspname as schema, p.proname as fonction
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
  and p.prosecdef
  and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) as reglage where reglage like 'search_path=%')
order by p.proname;

-- 7. 🟠 IMPORTANT : buckets de stockage publics (tout le monde peut lire les fichiers)
select id as bucket, public
from storage.buckets
where public = true
order by id;

-- 8. 🟡 INFO : politiques qui s'appliquent à tous les rôles (aucune clause TO), donc aussi à anon
select tablename, policyname, cmd
from pg_policies
where schemaname = 'public' and (roles is null or roles = '{public}')
order by tablename, policyname;

-- 9. 🟡 INFO : auth.uid() non enveloppé dans (select auth.uid()), recalculé à chaque ligne
select tablename, policyname, cmd
from pg_policies
where schemaname = 'public'
  and (qual ilike '%auth.uid()%' or with_check ilike '%auth.uid()%')
  and not (coalesce(qual, '') || coalesce(with_check, '')) ~* '\(\s*select\s+auth\.uid\(\)(\s+as\s+\w+)?\s*\)'
order by tablename, policyname;

-- 10. 🟡 INFO : colonne user_id sans index (les politiques qui la filtrent ralentiront avec le volume)
select c.table_name, c.column_name
from information_schema.columns c
join information_schema.tables tb on tb.table_schema = c.table_schema and tb.table_name = c.table_name
where c.table_schema = 'public' and c.column_name = 'user_id' and tb.table_type = 'BASE TABLE'
  and not exists (
    select 1
    from pg_index i
    join pg_class t on t.oid = i.indrelid
    join pg_namespace n on n.oid = t.relnamespace
    join pg_attribute a on a.attrelid = t.oid and a.attnum = any (i.indkey)
    where n.nspname = 'public' and t.relname = c.table_name and a.attname = 'user_id'
  )
order by c.table_name;
