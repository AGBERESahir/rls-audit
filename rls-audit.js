#!/usr/bin/env node
// rls-audit : analyse des fichiers SQL (schema.sql, dossier de migrations) et signale les risques RLS.
// Voir README.md pour toutes les options et la liste des contrôles.
const fs = require('fs');
const path = require('path');

const AIDE = `rls-audit : audit des politiques RLS (Row Level Security) dans des fichiers SQL.

Usage :
  rls-audit <fichier.sql | dossier> [autres fichiers ...] [options]

Les fichiers d'un dossier sont lus dans l'ordre alphabétique, comme des migrations.

Options :
  --schema=NOM   Audite aussi ce schéma (en plus de public). Répétable.
  --strict       Code de sortie 1 aussi pour les alertes « important » (🟠)
  --json         Sortie JSON (pour les scripts et la CI)
  -h, --help     Affiche cette aide

Code de sortie : 1 s'il y a au moins une alerte critique (🔴), sinon 0.`;

const ICONES = { critique: '🔴', important: '🟠', info: '🟡', ok: '🟢' };
const ID = '(?:"?([a-z0-9_]+)"?\\s*\\.\\s*)?"?([a-z0-9_]+)"?';
const NOM_POLITIQUE = '("[^"]+"|[a-z0-9_]+)';

// Découpe le SQL en instructions, en retirant les commentaires et en respectant
// les chaînes, les identifiants entre guillemets et les corps de fonction $$ ... $$.
function decouper(sql) {
  const instructions = [];
  let cur = '', i = 0;
  const n = sql.length;
  while (i < n) {
    const c = sql[i], d = sql[i + 1];
    if (c === '-' && d === '-') { while (i < n && sql[i] !== '\n') i++; continue; }
    if (c === '/' && d === '*') { const j = sql.indexOf('*/', i + 2); i = j < 0 ? n : j + 2; cur += ' '; continue; }
    if (c === "'" || c === '"') {
      let j = i + 1;
      while (j < n) { if (sql[j] === c) { if (sql[j + 1] === c) { j += 2; continue; } break; } j++; }
      cur += sql.slice(i, j + 1); i = j + 1; continue;
    }
    if (c === '$') {
      const m = /^\$([A-Za-z_]*)\$/.exec(sql.slice(i, i + 40));
      if (m) {
        const fin = sql.indexOf(m[0], i + m[0].length);
        const j = fin < 0 ? n : fin + m[0].length;
        cur += sql.slice(i, j); i = j; continue;
      }
    }
    if (c === ';') { if (cur.trim()) instructions.push(cur.trim()); cur = ''; i++; continue; }
    cur += c; i++;
  }
  if (cur.trim()) instructions.push(cur.trim());
  return instructions;
}

// Contenu entre parenthèses équilibrées qui suit le mot-clé repéré par `re` (qui finit sur « ( »).
function entreParentheses(texte, re) {
  const m = re.exec(texte);
  if (!m) return null;
  let profondeur = 1, i = m.index + m[0].length;
  const debut = i;
  while (i < texte.length && profondeur) { if (texte[i] === '(') profondeur++; else if (texte[i] === ')') profondeur--; i++; }
  return texte.slice(debut, i - 1).trim();
}

const cle = (schema, nom) => `${(schema || 'public').toLowerCase()}.${nom.toLowerCase()}`;
const sansGuillemets = s => s.replace(/^"|"$/g, '').toLowerCase();

// Rejoue les instructions dans l'ordre pour reconstituer l'état final du schéma.
function analyser(sql) {
  const tables = new Map(), vues = [], fonctions = [], index = [];
  const rx = (motif) => new RegExp(motif, 'i');
  for (const st of decouper(sql)) {
    let m;
    if ((m = rx('^create\\s+(?:unlogged\\s+)?table\\s+(?:if\\s+not\\s+exists\\s+)?' + ID).exec(st))) {
      const k = cle(m[1], m[2]);
      if (!tables.has(k)) tables.set(k, { schema: (m[1] || 'public').toLowerCase(), nom: m[2].toLowerCase(), rls: false, force: false, politiques: [] });
    } else if ((m = rx('^alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?' + ID + '\\s+(enable|disable|force|no\\s+force)\\s+row\\s+level\\s+security').exec(st))) {
      const t = tables.get(cle(m[1], m[2]));
      const action = m[3].toLowerCase().replace(/\s+/g, ' ');
      if (t) { if (action === 'enable') t.rls = true; else if (action === 'disable') t.rls = false; else t.force = action === 'force'; }
    } else if ((m = rx('^drop\\s+table\\s+(?:if\\s+exists\\s+)?(.+?)(?:\\s+(?:cascade|restrict))?$').exec(st))) {
      for (const part of m[1].split(',')) {
        const id = rx('^\\s*' + ID + '\\s*$').exec(part);
        if (id) tables.delete(cle(id[1], id[2]));
      }
    } else if ((m = rx('^create\\s+policy\\s+' + NOM_POLITIQUE + '\\s+on\\s+' + ID + '([\\s\\S]*)$').exec(st))) {
      const t = tables.get(cle(m[2], m[3]));
      if (!t) continue;
      const reste = m[4];
      const roles = /\bto\s+([\s\S]+?)(?=\s+(?:using|with\s+check)\b|$)/i.exec(reste);
      t.politiques.push({
        nom: sansGuillemets(m[1]),
        cmd: ((/\bfor\s+(all|select|insert|update|delete)\b/i.exec(reste) || [])[1] || 'all').toLowerCase(),
        roles: roles ? roles[1].toLowerCase().split(',').map(r => r.trim()) : null,
        using: entreParentheses(reste, /\busing\s*\(/i),
        check: entreParentheses(reste, /\bwith\s+check\s*\(/i),
      });
    } else if ((m = rx('^drop\\s+policy\\s+(?:if\\s+exists\\s+)?' + NOM_POLITIQUE + '\\s+on\\s+' + ID).exec(st))) {
      const t = tables.get(cle(m[2], m[3]));
      if (t) t.politiques = t.politiques.filter(p => p.nom !== sansGuillemets(m[1]));
    } else if ((m = rx('^create\\s+(?:unique\\s+)?index\\s+(?:concurrently\\s+)?(?:if\\s+not\\s+exists\\s+)?(?:(?!on\\s)\\S+\\s+)?on\\s+(?:only\\s+)?' + ID + '[^(]*\\(([\\s\\S]*)\\)').exec(st))) {
      index.push({ table: cle(m[1], m[2]), colonnes: m[3].toLowerCase() });
    } else if ((m = rx('^create\\s+(?:or\\s+replace\\s+)?(?:recursive\\s+)?view\\s+' + ID).exec(st))) {
      vues.push({ schema: (m[1] || 'public').toLowerCase(), nom: m[2].toLowerCase(), invoker: /security_invoker\s*=\s*(true|on|1)/i.test(st) });
    } else if ((m = rx('^create\\s+(?:or\\s+replace\\s+)?function\\s+' + ID).exec(st))) {
      fonctions.push({ schema: (m[1] || 'public').toLowerCase(), nom: m[2].toLowerCase(),
        definer: /security\s+definer/i.test(st), searchPath: /set\s+search_path/i.test(st) });
    }
  }
  return { tables, vues, fonctions, index };
}

const toujoursVrai = e => e !== null && /^\(*\s*true\s*\)*$/i.test(e);

function evaluer(etat, schemas = ['public']) {
  const trouvailles = [];
  const ajouter = (niveau, objet, message) => trouvailles.push({ niveau, objet, message });
  for (const t of etat.tables.values()) {
    if (!schemas.includes(t.schema)) continue;
    const objet = t.schema === 'public' ? t.nom : `${t.schema}.${t.nom}`;
    const avant = trouvailles.length;
    if (!t.rls && !t.politiques.length) ajouter('critique', objet, 'RLS non activée : la table est lisible et modifiable par tout porteur de la clé anon.');
    else if (!t.rls) ajouter('critique', objet, `RLS non activée alors que ${t.politiques.length} politique(s) existent : elles n'ont aucun effet.`);
    else if (!t.politiques.length) ajouter('important', objet, 'RLS activée mais aucune politique : personne n\'a accès (sauf la clé service_role).');

    for (const p of t.politiques) {
      const ecriture = p.cmd !== 'select';
      const large = toujoursVrai(p.using) || toujoursVrai(p.check);
      if (ecriture && large) ajouter('important', objet, `politique « ${p.nom} » : ${p.cmd.toUpperCase()} autorisé sans condition (true).`);
      if (ecriture && p.roles && p.roles.includes('anon')) ajouter('important', objet, `politique « ${p.nom} » : ${p.cmd.toUpperCase()} ouvert au rôle anon (visiteurs non connectés).`);
      if (p.cmd === 'select' && large) ajouter('info', objet, `politique « ${p.nom} » : lecture ouverte à tous (voulu pour une table publique ?).`);
      if (!p.roles) ajouter('info', objet, `politique « ${p.nom} » sans clause TO : s'applique à tous les rôles, dont anon. Préfère TO authenticated.`);
      const expr = `${p.using || ''} ${p.check || ''}`;
      if (/auth\.uid\(\)/i.test(expr) && !/\(\s*select\s+auth\.uid\(\)\s*\)/i.test(expr)) {
        ajouter('info', objet, `politique « ${p.nom} » : écris (select auth.uid()) plutôt que auth.uid() pour de meilleures performances.`);
      }
      if (/\buser_id\b/i.test(expr) && !etat.index.some(i => i.table === cle(t.schema, t.nom) && /\buser_id\b/.test(i.colonnes))) {
        ajouter('info', objet, `politique « ${p.nom} » filtre sur user_id sans index sur cette colonne : les requêtes ralentiront avec le volume.`);
      }
    }
    // une table sans alerte critique ni importante reste verte ; les remarques 🟡 s'affichent en dessous
    if (!trouvailles.slice(avant).some(x => x.niveau === 'critique' || x.niveau === 'important')) {
      trouvailles.splice(avant, 0, { niveau: 'ok', objet, message: `RLS activée, ${t.politiques.length} politique(s).` });
    }
  }
  for (const v of etat.vues) {
    if (schemas.includes(v.schema) && !v.invoker) ajouter('important', `vue ${v.nom}`, 'sans security_invoker = true : la vue s\'exécute avec les droits de son propriétaire et contourne la RLS.');
  }
  for (const f of etat.fonctions) {
    if (schemas.includes(f.schema) && f.definer && !f.searchPath) ajouter('important', `fonction ${f.nom}`, 'SECURITY DEFINER sans SET search_path : risque de détournement de schéma.');
  }
  return trouvailles;
}

function fichiersSql(entree) {
  if (fs.statSync(entree).isFile()) return [entree];
  return fs.readdirSync(entree, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)).flatMap(e =>
    e.isDirectory() ? fichiersSql(path.join(entree, e.name)) : /\.sql$/i.test(e.name) ? [path.join(entree, e.name)] : []);
}

function main(argv) {
  if (argv.includes('-h') || argv.includes('--help')) { console.log(AIDE); return 0; }
  const schemas = ['public', ...argv.filter(a => a.startsWith('--schema=')).map(a => a.split('=')[1].toLowerCase())];
  const entrees = argv.filter(a => !a.startsWith('-'));
  if (!entrees.length) { console.error('Usage : rls-audit <fichier.sql | dossier> [options]   (--help pour l\'aide)'); return 1; }
  for (const e of entrees) if (!fs.existsSync(e)) { console.error(`Introuvable : ${e}`); return 1; }

  const fichiers = entrees.flatMap(fichiersSql);
  const etat = analyser(fichiers.map(f => fs.readFileSync(f, 'utf8')).join(';\n'));
  const trouvailles = evaluer(etat, schemas);
  const compte = n => trouvailles.filter(t => t.niveau === n).length;

  if (argv.includes('--json')) {
    console.log(JSON.stringify({ fichiers, tables: [...etat.tables.values()].filter(t => schemas.includes(t.schema)).length, trouvailles }, null, 2));
  } else {
    if (!etat.tables.size) console.log('Aucune instruction CREATE TABLE trouvée.');
    for (const t of trouvailles) console.log(`${ICONES[t.niveau]} ${t.objet} : ${t.message}`);
    console.log(`\n${fichiers.length} fichier(s), ${compte('critique')} critique(s), ${compte('important')} important(s), ${compte('info')} info(s).`);
  }
  return compte('critique') || (argv.includes('--strict') && compte('important')) ? 1 : 0;
}

module.exports = { decouper, analyser, evaluer };
if (require.main === module) process.exit(main(process.argv.slice(2)));
