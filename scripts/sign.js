'use strict';
// node scripts/sign.js --kid k1 --sequence N --out dist/manifest.json
// المفتاح الخاص يُقرأ من متغير البيئة CONTROL_PRIVATE_KEY فقط (PEM). لا يُقرأ من ملف ولا يُطبع ولا يُكتب في أي مكان.
const fs = require('fs'), path = require('path');
const { validateControl, buildPayload } = require('./lib');
const { signEnvelope, verifyEnvelope } = require('./crypto');

function arg(n, d) { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : d; }
const kid = arg('kid', 'k1'), seq = Number(arg('sequence')), out = arg('out', path.join('dist', 'manifest.json'));
const src = arg('control', path.join(__dirname, '..', 'control.json'));
if (!Number.isInteger(seq) || seq < 1) { console.error('--sequence مطلوب (عدد صحيح ≥ 1)'); process.exit(1); }
const pem = process.env.CONTROL_PRIVATE_KEY;
if (!pem || !/BEGIN (EC )?PRIVATE KEY/.test(pem)) { console.error('CONTROL_PRIVATE_KEY غير مضبوط أو ليس PEM'); process.exit(1); }

const c = JSON.parse(fs.readFileSync(src, 'utf8'));
const errs = validateControl(c, new Date());
if (errs.length) { console.error('control.json غير صالح:\n - ' + errs.join('\n - ')); process.exit(1); }

const payload = buildPayload(c, { sequence: seq, issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') });
const env = signEnvelope(payload, pem, kid);

// تحقق ذاتي فوري بالمفتاح العام المنشور (keys/public/<kid>.jwk.json) قبل أي كتابة
const kp = path.join(__dirname, '..', 'keys', 'public', kid + '.jwk.json');
if (!fs.existsSync(kp)) { console.error('المفتاح العام غير موجود: ' + kp + ' (ولّد المفاتيح أولًا — انظر keys/README.md)'); process.exit(1); }
verifyEnvelope(env, { [kid]: JSON.parse(fs.readFileSync(kp, 'utf8')) });

fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify(env) + '\n');
console.log(`وُقّع بنجاح: kid=${kid} sequence=${seq} → ${out}`);
