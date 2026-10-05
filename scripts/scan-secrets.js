'use strict';
// يفشل إذا ظهر في أي ملف متتبَّع نمط مفتاح خاص أو مادة سرية أو ملف مفتاح. يُشغَّل في كل workflow.
const fs = require('fs'), path = require('path');
const root = path.join(__dirname, '..');
const SKIP = new Set(['.git', 'node_modules', 'dist']);
const BAD_NAMES = /\.(pem|key|p12|pfx|jks|keystore)$/i;
const BAD_CONTENT = [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, /"d"\s*:\s*"[A-Za-z0-9_-]{20,}"/, /\bghp_[A-Za-z0-9]{20,}/, /\bgithub_pat_[A-Za-z0-9_]{20,}/, /\bAKIA[0-9A-Z]{16}\b/];
const hits = [];
(function walk(d) {
  for (const n of fs.readdirSync(d)) {
    if (SKIP.has(n)) continue;
    const p = path.join(d, n), rel = path.relative(root, p);
    if (fs.statSync(p).isDirectory()) { walk(p); continue; }
    if (BAD_NAMES.test(n)) { hits.push(rel + ' (اسم ملف مفتاح)'); continue; }
    if (rel === path.join('tests', 'control.test.js') || rel === path.join('scripts', 'scan-secrets.js')) continue; // الأنماط نفسها مذكورة هنا
    const s = fs.readFileSync(p, 'utf8');
    for (const re of BAD_CONTENT) if (re.test(s)) hits.push(rel + ' (' + re.source.slice(0, 30) + ')');
  }
})(root);
if (hits.length) { console.error('✖ مادة سرية محتملة في المستودع:\n - ' + hits.join('\n - ')); process.exit(1); }
console.log('فحص الأسرار: نظيف ✔');
