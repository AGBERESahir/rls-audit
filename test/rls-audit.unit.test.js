const test = require('node:test');
const assert = require('node:assert');
const { decouper, analyser, evaluer } = require('../rls-audit.js');

const audit = sql => evaluer(analyser(sql));
const niveaux = (t, objet) => t.filter(x => x.objet === objet).map(x => x.niveau);

test('découpe sans casser les corps de fonction ni les commentaires', () => {
  const s = decouper("select 1; -- commentaire ; piège\ncreate function f() returns int as $$ begin return 1; end; $$ language plpgsql; /* a;b */ select 2;");
  assert.strictEqual(s.length, 3);
  assert.match(s[1], /return 1; end;/);
});

test('table sans RLS : critique', () => {
  assert.deepStrictEqual(niveaux(audit('create table public.a (id int);'), 'a'), ['critique']);
});

test('table supprimée ensuite : aucune alerte', () => {
  assert.deepStrictEqual(audit('create table a (id int); drop table if exists a;'), []);
});

test('politique sur une table sans RLS : critique (sans effet)', () => {
  const t = audit('create table a (id int); create policy p on a for select using (true);');
  assert.ok(t.some(x => x.niveau === 'critique' && /aucun effet/.test(x.message)));
});

test('RLS sans politique : important', () => {
  const t = audit('create table a (id int); alter table a enable row level security;');
  assert.deepStrictEqual(niveaux(t, 'a'), ['important']);
});

test('écriture ouverte à anon ou sans condition : important', () => {
  const t = audit(`create table a (id int); alter table a enable row level security;
    create policy p on a for insert to anon with check (true);`);
  assert.strictEqual(t.filter(x => x.niveau === 'important').length, 2);
});

test('table correcte : verte, même avec un index nommé ou non', () => {
  const t = audit(`create table a (id int, user_id uuid); alter table a enable row level security;
    create index on a (user_id);
    create policy p on a for select to authenticated using ((select auth.uid()) = user_id);`);
  assert.deepStrictEqual(niveaux(t, 'a'), ['ok']);
});

test('vue sans security_invoker et fonction definer sans search_path : important', () => {
  const t = audit(`create view v as select 1;
    create function f() returns int language sql security definer as $$ select 1 $$;`);
  assert.deepStrictEqual(t.map(x => x.niveau), ['important', 'important']);
});

test('les schémas non audités sont ignorés', () => {
  assert.deepStrictEqual(audit('create table interne.a (id int);'), []);
});
