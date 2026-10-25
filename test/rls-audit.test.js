'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const SCRIPT = path.join(__dirname, '..', 'rls-audit.js');

function audit(sql) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rls-audit-'));
  const file = path.join(dir, 'schema.sql');
  fs.writeFileSync(file, sql);
  const r = spawnSync(process.execPath, [SCRIPT, file], { encoding: 'utf8' });
  fs.rmSync(dir, { recursive: true, force: true });
  return r;
}

test('table sans RLS : signalée en rouge, code de sortie 1', () => {
  const r = audit('create table paiements (id bigint primary key);');
  assert.strictEqual(r.status, 1);
  assert.match(r.stdout, /🔴 paiements/);
});

test('RLS activée sans politique : orange, code de sortie 0', () => {
  const r = audit('create table notes (id bigint);\nalter table notes enable row level security;');
  assert.strictEqual(r.status, 0);
  assert.match(r.stdout, /🟠 notes/);
});

test('RLS et politique présentes : vert, préfixe public. accepté', () => {
  const r = audit(`create table public.profiles (id uuid);
alter table public.profiles enable row level security;
create policy "lecture" on public.profiles for select using (true);`);
  assert.strictEqual(r.status, 0);
  assert.match(r.stdout, /🟢 profiles/);
});

test('les commentaires SQL sont ignorés', () => {
  const r = audit('-- create table fantome (id int);\n/* create table autre (id int); */\ncreate table reel (id int);');
  assert.doesNotMatch(r.stdout, /fantome|autre/);
  assert.match(r.stdout, /reel/);
});

test('plusieurs tables : une seule en rouge suffit pour échouer', () => {
  const r = audit(`create table a (id int);
alter table a enable row level security;
create policy p on a for select using (true);
create table b (id int);`);
  assert.strictEqual(r.status, 1);
  assert.match(r.stdout, /🟢 a /);
  assert.match(r.stdout, /🔴 b /);
});
