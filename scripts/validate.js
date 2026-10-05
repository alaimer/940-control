'use strict';
// node scripts/validate.js [control.json]  → يخرج 1 مع قائمة أخطاء إن كان المصدر غير صالح. لا يحتاج أسرارًا.
const fs = require('fs'), path = require('path');
const { validateControl } = require('./lib');
const file = process.argv[2] || path.join(__dirname, '..', 'control.json');
let c;
try { c = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { console.error('تعذّرت قراءة JSON:', e.message); process.exit(1); }
const errs = validateControl(c, new Date());
if (errs.length) { console.error('control.json غير صالح:\n - ' + errs.join('\n - ')); process.exit(1); }
console.log('control.json صالح ✔');
