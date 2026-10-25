-- profils : OK
create table public.profiles (id uuid primary key, user_id uuid references auth.users, nom text);
alter table public.profiles enable row level security;
create index on public.profiles (user_id);
create policy "lire son profil" on public.profiles for select to authenticated using ((select auth.uid()) = user_id);

create table messages (id bigint primary key, user_id uuid, texte text);  -- pas de RLS
create table notes (id bigint primary key, user_id uuid);
create policy "tout le monde" on notes for all using (true);           /* politique inutile sans RLS */
create table temp_a_supprimer (id int);
drop table temp_a_supprimer;
create table vide (id int);
alter table vide enable row level security;
create table posts (id int, user_id uuid);
alter table posts enable row level security;
create policy "ecrit anon" on posts for insert to anon with check (true);
create policy p2 on posts for select using (auth.uid() = user_id);
create view public.stats as select count(*) from posts;
create function public.secret() returns int language plpgsql security definer as $$ begin perform 1; return 1; end; $$;
create table auth_interne.x (id int);
