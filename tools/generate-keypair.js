'use strict';
// أداة يشغّلها المالك على جهازه الشخصي فقط (ليس في CI ولا في بيئة سحابية):
//   node tools/generate-keypair.js --kid k1 --out-dir "D:\\secure\\940-keys"
// تكتب المفتاح الخاص PEM في مجلد خارج أي مستودع git (بصلاحيات 600 حيث أمكن)، وتطبع المفتاح العام JWK لنسخه إلى keys/public/<kid>.jwk.json.
// لا تُرسل شيئًا عبر الشبكة، ولا تطبع المفتاح الخاص على الشاشة.
const crypto = require('crypto'), fs = require('fs'), path = require('path');
function arg(n) { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : null; }
const kid = arg('kid'), dir = arg('out-dir');
if (!kid || !/^[a-z0-9_-]{1,16}$/.test(kid) || !dir) { console.error('الاستعمال: node tools/generate-keypair.js --kid k1 --out-dir <مجلد آمن خارج أي مستودع>'); process.exit(1); }
const abs = path.resolve(dir);
for (let d = abs; ; d = path.dirname(d)) { // يرفض الكتابة داخل مستودع git
  if (fs.existsSync(path.join(d, '.git'))) { console.error('✖ المجلد داخل مستودع git: ' + d + '\n  اختر مجلدًا خارج أي مستودع.'); process.exit(1); }
  if (path.dirname(d) === d) break;
}
fs.mkdirSync(abs, { recursive: true });
const target = path.join(abs, kid + '.private.pem');
if (fs.existsSync(target)) { console.error('✖ الملف موجود مسبقًا ولن يُستبدل: ' + target); process.exit(1); }
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
fs.writeFileSync(target, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
const jwk = publicKey.export({ format: 'jwk' });
const pub = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
const fp = crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
console.log('تم إنشاء المفتاح الخاص في: ' + target + '  (لا ترفعه لأي مكان، ولا تضعه في git)');
console.log('\nالمفتاح العام (انسخه إلى keys/public/' + kid + '.jwk.json):\n' + JSON.stringify(pub, null, 2));
console.log('\nبصمة المفتاح العام SHA-256 (للتوثيق): ' + fp);
