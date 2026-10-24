-- À coller dans l’éditeur SQL de Supabase : audit en direct du schéma public.

-- 1. Tables sans RLS (à corriger en priorité)
select schemaname, tablename
from pg_tables
where schemaname = 'public' and rowsecurity = false
order by tablename;

-- 2. Tables avec RLS mais sans aucune politique (personne n’y accède)
select t.tablename
from pg_tables t
left join pg_policies p on p.schemaname = t.schemaname and p.tablename = t.tablename
where t.schemaname = 'public' and t.rowsecurity = true
group by t.tablename
having count(p.policyname) = 0
order by t.tablename;

-- 3. Politiques trop permissives (using true) sur autre chose que de la lecture
select tablename, policyname, cmd, qual
from pg_policies
where schemaname = 'public' and cmd <> 'SELECT' and (qual = 'true' or with_check = 'true');
