#!/usr/bin/env node
// rls-audit : analyse un fichier SQL (schema.sql, migration) et signale les tables sans RLS ou sans politique.
// Usage : node dev/rls-audit.js schema.sql
const fs = require('fs');
const file = process.argv[2];
if (!file || !fs.existsSync(file)) {
  console.error('Usage : node dev/rls-audit.js <fichier.sql>');
  process.exit(1);
}
const sql = fs.readFileSync(file, 'utf8').replace(/--.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
const ident = '(?:"?public"?\\.)?"?([a-z0-9_]+)"?';
const all = (re) => [...sql.matchAll(new RegExp(re, 'gi'))].map(m => m[1].toLowerCase());

const tables = [...new Set(all('create\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?' + ident))];
const rls = new Set(all('alter\\s+table\\s+(?:only\\s+)?' + ident + '\\s+enable\\s+row\\s+level\\s+security'));
const policies = new Set(all('create\\s+policy\\s+[^;]*?\\son\\s+' + ident));

let critical = 0;
for (const t of tables) {
  if (!rls.has(t)) { console.log(`🔴 ${t} : RLS non activée (accessible à tout porteur de la clé anon)`); critical++; }
  else if (!policies.has(t)) console.log(`🟠 ${t} : RLS activée mais aucune politique (personne n’a accès)`);
  else console.log(`🟢 ${t} : RLS activée, politique(s) présente(s)`);
}
if (!tables.length) console.log('Aucune instruction CREATE TABLE trouvée.');
process.exit(critical ? 1 : 0);
