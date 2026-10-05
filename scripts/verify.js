'use strict';
// node scripts/verify.js manifest.json [--min-sequence N]  → يتحقق من التوقيع بكل المفاتيح العامة في keys/public ويعرض ملخصًا.
const fs = require('fs'), path = require('path');
const { verifyEnvelope } = require('./crypto');
const { validateControl, PLATFORMS } = require('./lib');

const file = process.argv[2];
if (!file) { console.error('الاستعمال: node scripts/verify.js <manifest.json> [--min-sequence N]'); process.exit(1); }
const i = process.argv.indexOf('--min-sequence'), minSeq = i > 0 ? Number(process.argv[i + 1]) : 0;
const dir = path.join(__dirname, '..', 'keys', 'public');
const keys = {};
for (const f of fs.existsSync(dir) ? fs.readdirSync(dir) : []) {
  const m = /^([a-z0-9_-]{1,16})\.jwk\.json$/.exec(f);
  if (m) keys[m[1]] = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
}
if (!Object.keys(keys).length) { console.error('لا توجد مفاتيح عامة في keys/public'); process.exit(1); }
try {
  const { payload, kid } = verifyEnvelope(JSON.parse(fs.readFileSync(file, 'utf8')), keys);
  if (!Number.isInteger(payload.sequence) || payload.sequence < minSeq) throw new Error(`sequence=${payload.sequence} أقل من الأدنى ${minSeq}`);
  // إعادة فحص بنية المحتوى الموقَّع بنفس قواعد المصدر (بدون شرط until المستقبلي لأنه قد يمضي)
  if (payload.issuer !== 'alaimer/940-control') throw new Error('issuer غير متوقع');
  if (typeof payload.issuedAt !== 'string' || isNaN(Date.parse(payload.issuedAt))) throw new Error('issuedAt غير صالح');
  const probe = JSON.parse(JSON.stringify(payload)); if (probe.maintenance) probe.maintenance.until = null;
  delete probe.issuer; delete probe.sequence; delete probe.issuedAt; // حقول الغلاف الموقَّع وليست من المصدر
  const errs = validateControl(probe, new Date());
  if (errs.length) throw new Error('المحتوى الموقَّع مخالف للـschema: ' + errs.join('; '));
  console.log(`التوقيع صحيح ✔ kid=${kid} sequence=${payload.sequence} issuedAt=${payload.issuedAt} offlineGraceDays=${payload.offlineGraceDays}`);
  for (const p of PLATFORMS) console.log(`  ${p}: latest=${payload.platforms[p].latest} minimum=${payload.platforms[p].minimum} overrides=${Object.keys(payload.platforms[p].overrides).length}`);
  console.log('  maintenance:', payload.maintenance.enabled ? 'ON' : 'off');
} catch (e) { console.error('فشل التحقق:', e.message); process.exit(1); }
