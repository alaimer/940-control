'use strict';
// اختبارات 940-control (node:test، بلا اعتماديات). المفاتيح هنا مؤقتة ومولَّدة في الذاكرة للاختبار فقط ولا تُستخدم في أي نشر.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto'), fs = require('fs'), os = require('os'), path = require('path');
const { spawnSync } = require('child_process');
const L = require('../scripts/lib');
const { signEnvelope, verifyEnvelope } = require('../scripts/crypto');
const ROOT = path.join(__dirname, '..');

const gen = () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const j = publicKey.export({ format: 'jwk' });
  return { pem: privateKey.export({ type: 'pkcs8', format: 'pem' }), jwk: { kty: j.kty, crv: j.crv, x: j.x, y: j.y } };
};
const base = () => JSON.parse(fs.readFileSync(path.join(ROOT, 'control.json'), 'utf8'));
const NOW = new Date('2026-10-06T08:00:00Z');
const withDl = (c) => { c.platforms.android.download = { url: 'https://github.com/alaimer/940-control/releases/download/v1.13.3/app-release.apk' }; c.platforms.windows.download = { url: 'https://github.com/alaimer/940-control/releases/download/v1.13.3/Operations940-Setup-1.13.3.exe' }; return c; };
const errsOf = (c, now = NOW) => L.validateControl(c, now);

// ---------- semver ----------
test('semver: مقارنة رقمية لا نصية', () => {
  assert.equal(L.cmpSemver('1.13.10', '1.13.9'), 1);
  assert.equal(L.cmpSemver('1.13.9', '1.13.10'), -1);
  assert.equal(L.cmpSemver('1.13.3', '1.13.3'), 0);
  assert.equal(L.cmpSemver('1.2.0', '1.10.0'), -1);
  assert.equal(L.cmpSemver('2.0.0', '1.99.99'), 1);
});
test('semver: يرفض الصيغ الشاذة', () => {
  for (const bad of ['v1.0.0', '1.0', '1.0.0.0', '01.0.0', '1.0.0-beta', '1.0.0+x', '', ' 1.0.0', '1.0.0 ', '١.٠.٠', '1.-1.0', null, undefined, 5, '1.0.1e3'])
    assert.equal(L.parseSemver(bad), null, 'يجب رفض: ' + String(bad));
});

// ---------- روابط التنزيل ----------
test('روابط: المسموح', () => {
  const ok = [
    ['https://github.com/alaimer/940-control/releases/download/v1.13.3/app-release.apk', 'android'],
    ['https://github.com/alaimer/940-control/releases/download/v1.13.3/Operations940-Setup-1.13.3.exe', 'windows'],
    ['https://ars.gov.sa/downloads/940.apk', 'android'],
    ['https://updates.ars.gov.sa/940/Setup.exe', 'windows'],
    ['https://a.b.ars.gov.sa/x.EXE', 'windows']
  ];
  for (const [u, p] of ok) assert.equal(L.checkDownloadUrl(u, p), null, u);
});
test('روابط: المرفوض', () => {
  const bad = [
    ['http://ars.gov.sa/x.apk', 'android'],
    ['https://evil.com/x.apk', 'android'],
    ['https://ars.gov.sa.evil.com/x.apk', 'android'],
    ['https://evilars.gov.sa/x.apk', 'android'],
    ['https://notars.gov.sa/x.apk', 'android'],
    ['https://ars.gov.sa@evil.com/x.apk', 'android'],
    ['https://user:pw@ars.gov.sa/x.apk', 'android'],
    ['https://ars.gov.sa:8443/x.apk', 'android'],
    ['https://ars.gov.sa/x.apk?x=1', 'android'],
    ['https://ars.gov.sa/x.apk#f', 'android'],
    ['https://ars.gov.sa/x.exe', 'android'],
    ['https://ars.gov.sa/x.apk', 'windows'],
    ['https://github.com/evil/940-control/releases/download/v1/x.apk', 'android'],
    ['https://github.com/alaimer/940-control/raw/main/x.apk', 'android'],
    ['https://github.com/alaimer/940-control/releases/download/../../../../evil/x.apk', 'android'],
    ['https://github.com/alaimer/940-control/releases/download/v1/%2e%2e/x.apk', 'android'],
    ['https://raw.githubusercontent.com/alaimer/940-control/main/x.apk', 'android'],
    ['javascript:alert(1)', 'android'],
    ['data:text/html,x', 'android'],
    ['file:///etc/passwd', 'android'],
    ['//ars.gov.sa/x.apk', 'android'],
    ['https://xn--ars-gov-sa-9ib.com/x.apk', 'android'],
    ['https://ars.gov.sa/x.apk\n', 'android'],
    ['', 'android'], [null, 'android'], [undefined, 'android'], [5, 'android'],
    ['https://' + 'a'.repeat(450) + '.ars.gov.sa/x.apk', 'android']
  ];
  for (const [u, p] of bad) assert.notEqual(L.checkDownloadUrl(u, p), null, 'يجب رفض: ' + String(u));
});

// ---------- control.json ----------
test('أول manifest: كل شيء active بلا أي override ولا صيانة', () => {
  const c = base();
  assert.deepEqual(errsOf(c), []);
  assert.equal(c.maintenance.enabled, false);
  for (const p of L.PLATFORMS) { assert.deepEqual(c.platforms[p].overrides, {}); assert.equal(c.platforms[p].latest, c.platforms[p].minimum); }
  const pl = L.buildPayload(c, { sequence: 1, issuedAt: '2026-10-06T08:00:00Z' });
  assert.equal(pl.offlineGraceDays, 3);
  assert.equal(pl.maintenance.enabled, false);
  for (const p of L.PLATFORMS) assert.deepEqual(pl.platforms[p].overrides, {});
});
test('schema: حقول ناقصة أو زائدة أو بأنواع خاطئة تُرفض', () => {
  const mut = (f) => { const c = base(); f(c); return errsOf(c); };
  assert.ok(mut((c) => { c.schemaVersion = 2; }).length);
  assert.ok(mut((c) => { c.kind = 'x'; }).length);
  assert.ok(mut((c) => { c.extra = 1; }).length);
  assert.ok(mut((c) => { delete c.maintenance; }).length);
  assert.ok(mut((c) => { delete c.platforms.android; }).length);
  assert.ok(mut((c) => { c.platforms.mac = c.platforms.android; }).length);
  assert.ok(mut((c) => { c.platforms.android.latest = '1.13'; }).length);
  assert.ok(mut((c) => { c.platforms.android.minimum = '1.14.0'; }).length, 'minimum أعلى من latest');
  assert.ok(mut((c) => { c.maintenance.enabled = 'yes'; }).length);
  assert.ok(mut((c) => { c.platforms.android.overrides = []; }).length);
  assert.ok(mut((c) => { c.platforms.android.overrides = { 'x.y.z': { status: 'blocked', message: 'm' } }; }).length);
  assert.ok(mut((c) => { c.platforms.android.overrides = { '1.13.1': { status: 'banned', message: 'm' } }; }).length);
  assert.ok(mut((c) => { c.platforms.android.overrides = { '1.13.1': { status: 'blocked', message: 'm', x: 1 } }; }).length);
  assert.ok(errsOf([]).length && errsOf(null).length && errsOf('x').length);
});
test('offlineGraceDays: 1..7 فقط', () => {
  for (const ok of [undefined, 1, 3, 7]) { const c = base(); if (ok !== undefined) c.offlineGraceDays = ok; assert.deepEqual(errsOf(c), []); }
  for (const bad of [0, 8, 14, 3.5, -1, '3', null, NaN]) { const c = base(); c.offlineGraceDays = bad; assert.ok(errsOf(c).length, 'يجب رفض ' + String(bad)); }
  const c = base(); c.offlineGraceDays = 7; assert.equal(L.buildPayload(c, { sequence: 1, issuedAt: 'x' }).offlineGraceDays, 7);
});
test('أمان: ممنوع إيقاف أو إجبار تحديث أحدث إصدار', () => {
  for (const st of ['blocked', 'force_update']) { const c = base(); c.platforms.android.overrides = { '1.13.2': { status: st, message: 'm' } }; assert.ok(errsOf(c).some((e) => /أحدث إصدار/.test(e)), st); }
  const c = base(); c.platforms.android.overrides = { '1.13.2': { status: 'update_available' } }; // مسموح نظريًا لكنه يحتاج رابط تنزيل
  assert.ok(errsOf(c).some((e) => /download/.test(e)));
});
test('إيقاف إصدار قديم: يتطلب رسالة، ولا يتطلب رابط تنزيل', () => {
  let c = withDl(base()); c.platforms.android.latest = '1.13.3'; c.platforms.android.minimum = '1.13.3'; c.platforms.android.overrides = { '1.13.2': { status: 'blocked', message: 'تم إيقاف هذا الإصدار' } };
  assert.deepEqual(errsOf(c), []);
  c.platforms.android.overrides['1.13.2'].message = '  '; assert.ok(errsOf(c).length);
  delete c.platforms.android.overrides['1.13.2'].message; assert.ok(errsOf(c).length);
});
test('latest > minimum يتطلب رابط تنزيل صالحًا', () => {
  const c = base(); c.platforms.windows.latest = '1.13.3';
  assert.ok(errsOf(c).some((e) => /download/.test(e)));
  withDl(c); assert.deepEqual(errsOf(c), []);
  c.platforms.windows.download.url = 'https://evil.com/Setup.exe'; assert.ok(errsOf(c).some((e) => /القائمة البيضاء/.test(e)));
  c.platforms.windows.download.url = 'https://ars.gov.sa/Setup.exe'; c.platforms.windows.download.sha256 = 'ABC'; assert.ok(errsOf(c).some((e) => /sha256/.test(e)));
  c.platforms.windows.download.sha256 = 'a'.repeat(64); assert.deepEqual(errsOf(c), []);
});
test('رسائل: طول ومحارف تحكم واتجاه مخفي', () => {
  const m = (msg) => { const c = base(); c.maintenance = { enabled: true, message: msg, until: '2026-10-06T10:00:00Z' }; return errsOf(c); };
  assert.deepEqual(m('صيانة مجدولة، نعود قريبًا.'), []);
  assert.deepEqual(m('<b>نص</b> & "اقتباس"'), [], 'HTML يُسمح به كنص لأن التطبيق يعرضه textContent فقط');
  assert.ok(m('').length && m('   ').length, 'رسالة الصيانة مطلوبة');
  assert.ok(m('x'.repeat(501)).length);
  assert.ok(m('a\u0000b').length && m('a\u001bb').length && m('a‮b').length && m('a⁦b').length && m('a b').length);
});
test('maintenance.until: صيغة وحدود وانتهاء', () => {
  const m = (enabled, until) => { const c = base(); c.maintenance = { enabled, message: enabled ? 'صيانة' : '', until }; return errsOf(c); };
  assert.deepEqual(m(true, '2026-10-06T12:00:00Z'), []);
  assert.deepEqual(m(true, null), []);
  assert.ok(m(true, '2026-10-06T07:00:00Z').length, 'منتهٍ');
  assert.ok(m(true, '2026-12-31T00:00:00Z').length, 'أبعد من 30 يومًا');
  assert.ok(m(true, '2026-10-06 12:00').length && m(true, '2026-10-06T12:00:00+03:00').length && m(true, 'غدًا').length && m(true, 12345).length && m(true, '2026-13-45T25:61:61Z').length);
  assert.deepEqual(m(false, '2020-01-01T00:00:00Z'), [], 'until قديم مع enabled=false لا يضر');
});

// ---------- التوقيع ----------
const sample = (seq = 1) => L.buildPayload(base(), { sequence: seq, issuedAt: '2026-10-06T08:00:00Z' });
test('توقيع صحيح يُقبل ويعيد الـpayload نفسه', () => {
  const k = gen(), env = signEnvelope(sample(7), k.pem, 'k1');
  const r = verifyEnvelope(env, { k1: k.jwk });
  assert.equal(r.kid, 'k1'); assert.equal(r.payload.sequence, 7); assert.deepEqual(r.payload, sample(7));
  assert.equal(Buffer.from(env.sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64').length, 64, 'P1363 = 64 بايت');
});
test('عبث: تعديل payload أو sig أو kid يفشل', () => {
  const k = gen(), k2 = gen(), env = signEnvelope(sample(1), k.pem, 'k1');
  const keys = { k1: k.jwk, k2: k2.jwk };
  const evil = JSON.parse(Buffer.from(env.payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()); evil.platforms.android.overrides = { '1.13.2': { status: 'blocked', message: 'x' } };
  assert.throws(() => verifyEnvelope({ ...env, payload: L.b64u.enc(Buffer.from(JSON.stringify(evil))) }, keys), /التوقيع/);
  const flip = Buffer.from(L.b64u.dec(env.sig)); flip[10] ^= 1;
  assert.throws(() => verifyEnvelope({ ...env, sig: L.b64u.enc(flip) }, keys), /التوقيع/);
  assert.throws(() => verifyEnvelope({ ...env, kid: 'k2' }, keys), /التوقيع/, 'تبديل kid لمفتاح موثوق آخر');
  assert.throws(() => verifyEnvelope({ ...env, kid: 'k9' }, keys), /غير موثوق/);
  assert.throws(() => verifyEnvelope({ ...env, kid: '__proto__' }, keys), /غير موثوق/);
  assert.throws(() => verifyEnvelope({ ...env, kid: 'constructor' }, keys), /غير موثوق/);
});
test('توقيع بمفتاح غير موثوق (مهاجم) يُرفض', () => {
  const trusted = gen(), attacker = gen();
  const env = signEnvelope(sample(1), attacker.pem, 'k1');
  assert.throws(() => verifyEnvelope(env, { k1: trusted.jwk }), /التوقيع/);
});
test('مغلّف تالف أو ناقص أو نصوص عشوائية تُرفض بلا استثناءات غريبة', () => {
  const k = gen(), env = signEnvelope(sample(1), k.pem, 'k1'), keys = { k1: k.jwk };
  for (const bad of [null, undefined, 5, 'x', [], {}, { v: 2, kid: 'k1', payload: env.payload, sig: env.sig }, { ...env, payload: 5 }, { ...env, sig: null }, { ...env, payload: '***' }, { ...env, sig: '***' }, { ...env, sig: 'AAAA' }, { ...env, sig: '' }, { ...env, payload: '' }])
    assert.throws(() => verifyEnvelope(bad, keys), Error, String(JSON.stringify(bad)).slice(0, 60));
});
test('payload موقَّع لكنه ليس JSON: يفشل التحليل بعد التحقق (لا قبله)', () => {
  const k = gen(), bytes = Buffer.from('not json'), sig = crypto.sign('sha256', bytes, { key: crypto.createPrivateKey(k.pem), dsaEncoding: 'ieee-p1363' });
  assert.throws(() => verifyEnvelope({ v: 1, kid: 'k1', payload: L.b64u.enc(bytes), sig: L.b64u.enc(sig) }, { k1: k.jwk }), SyntaxError);
});
test('مفتاح عام يحوي d (خاص) يُرفض، ومفتاح خاص غير P-256 يُرفض للتوقيع', () => {
  const k = gen(), env = signEnvelope(sample(1), k.pem, 'k1');
  const priv = crypto.createPrivateKey(k.pem).export({ format: 'jwk' });
  assert.throws(() => verifyEnvelope(env, { k1: { ...k.jwk, d: priv.d } }), /خاص/);
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.throws(() => signEnvelope(sample(1), rsa, 'k1'), /P-256/);
  const p384 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.throws(() => signEnvelope(sample(1), p384, 'k1'), /P-256/);
  assert.throws(() => signEnvelope(sample(1), k.pem, 'K 1'), /kid/);
});
test('تدوير المفاتيح: توقيع k2 يُقبل عند وجوده في القائمة، ولا يُقبل إن أُزيل', () => {
  const a = gen(), b = gen();
  const env = signEnvelope(sample(3), b.pem, 'k2');
  assert.equal(verifyEnvelope(env, { k1: a.jwk, k2: b.jwk }).kid, 'k2');
  assert.throws(() => verifyEnvelope(env, { k1: a.jwk }), /غير موثوق/);
});

// ---------- CLI من البداية للنهاية (نسخة مؤقتة؛ المفتاح الخاص يمر عبر متغير بيئة فقط ولا يُكتب على القرص) ----------
function tmpRepo() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), '940c-'));
  fs.cpSync(path.join(ROOT, 'scripts'), path.join(d, 'scripts'), { recursive: true });
  fs.copyFileSync(path.join(ROOT, 'control.json'), path.join(d, 'control.json'));
  fs.mkdirSync(path.join(d, 'keys', 'public'), { recursive: true });
  return d;
}
const run = (d, script, args, env = {}) => spawnSync(process.execPath, [path.join(d, 'scripts', script), ...args], { cwd: d, env: { ...process.env, ...env }, encoding: 'utf8' });
test('CLI: توقيع ← تحقق ← عبث ← sequence', () => {
  const d = tmpRepo(), k = gen();
  fs.writeFileSync(path.join(d, 'keys', 'public', 'k1.jwk.json'), JSON.stringify(k.jwk));
  let r = run(d, 'sign.js', ['--kid', 'k1', '--sequence', '50', '--out', 'dist/manifest.json'], { CONTROL_PRIVATE_KEY: k.pem });
  assert.equal(r.status, 0, r.stderr);
  r = run(d, 'verify.js', ['dist/manifest.json', '--min-sequence', '50']); assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /sequence=50/);
  r = run(d, 'verify.js', ['dist/manifest.json', '--min-sequence', '51']); assert.notEqual(r.status, 0); assert.match(r.stderr, /sequence/);
  const env = JSON.parse(fs.readFileSync(path.join(d, 'dist', 'manifest.json'), 'utf8')); env.sig = env.sig.slice(0, -2) + (env.sig.endsWith('AA') ? 'BB' : 'AA');
  fs.writeFileSync(path.join(d, 'dist', 'bad.json'), JSON.stringify(env));
  r = run(d, 'verify.js', ['dist/bad.json']); assert.notEqual(r.status, 0);
  fs.rmSync(d, { recursive: true, force: true });
});
test('CLI: لا يوقّع بلا مفتاح بيئة، ولا بلا مفتاح عام منشور، ولا بمصدر غير صالح، ولا بمفتاح لا يطابق العام', () => {
  const d = tmpRepo(), k = gen(), other = gen();
  assert.notEqual(run(d, 'sign.js', ['--sequence', '1']).status, 0);
  assert.notEqual(run(d, 'sign.js', ['--sequence', '1'], { CONTROL_PRIVATE_KEY: k.pem }).status, 0, 'لا مفتاح عام');
  fs.writeFileSync(path.join(d, 'keys', 'public', 'k1.jwk.json'), JSON.stringify(other.jwk));
  const r = run(d, 'sign.js', ['--sequence', '1', '--out', 'dist/m.json'], { CONTROL_PRIVATE_KEY: k.pem });
  assert.notEqual(r.status, 0, 'مفتاح خاص لا يطابق العام المنشور');
  assert.ok(!fs.existsSync(path.join(d, 'dist', 'm.json')), 'لا يُكتب شيء عند الفشل');
  fs.writeFileSync(path.join(d, 'keys', 'public', 'k1.jwk.json'), JSON.stringify(k.jwk));
  const c = JSON.parse(fs.readFileSync(path.join(d, 'control.json'), 'utf8')); c.platforms.android.minimum = '9.9.9'; fs.writeFileSync(path.join(d, 'control.json'), JSON.stringify(c));
  assert.notEqual(run(d, 'sign.js', ['--sequence', '1', '--out', 'dist/m.json'], { CONTROL_PRIVATE_KEY: k.pem }).status, 0);
  assert.notEqual(run(d, 'sign.js', ['--sequence', '0'], { CONTROL_PRIVATE_KEY: k.pem }).status, 0);
  fs.rmSync(d, { recursive: true, force: true });
});
test('CLI: المفتاح الخاص لا يظهر في أي مخرجات', () => {
  const d = tmpRepo(), k = gen();
  fs.writeFileSync(path.join(d, 'keys', 'public', 'k1.jwk.json'), JSON.stringify(k.jwk));
  const r = run(d, 'sign.js', ['--sequence', '2', '--out', 'dist/manifest.json'], { CONTROL_PRIVATE_KEY: k.pem });
  const body = k.pem.split('\n').filter((l) => l && !l.startsWith('-----'))[0];
  assert.ok(!r.stdout.includes(body) && !r.stderr.includes(body));
  assert.ok(!fs.readFileSync(path.join(d, 'dist', 'manifest.json'), 'utf8').includes(body));
  fs.rmSync(d, { recursive: true, force: true });
});

// ---------- أداة توليد المفاتيح (على جهاز المالك) ----------
test('generate-keypair: يكتب الخاص بصلاحية 600 خارج git، يطبع العام بلا d، ويرفض داخل مستودع أو الاستبدال', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), '940k-'));
  const run2 = (dir) => spawnSync(process.execPath, [path.join(ROOT, 'tools', 'generate-keypair.js'), '--kid', 'k9', '--out-dir', dir], { encoding: 'utf8' });
  let r = run2(out); assert.equal(r.status, 0, r.stderr);
  const f = path.join(out, 'k9.private.pem');
  assert.ok(fs.existsSync(f));
  if (process.platform !== 'win32') assert.equal(fs.statSync(f).mode & 0o777, 0o600);
  assert.match(r.stdout, /"kty": "EC"/); assert.match(r.stdout, /"crv": "P-256"/); assert.ok(!/"d"/.test(r.stdout));
  const body = fs.readFileSync(f, 'utf8').split('\n').filter((l) => l && !l.startsWith('-----'))[0];
  assert.ok(!r.stdout.includes(body), 'المفتاح الخاص لا يُطبع');
  assert.notEqual(run2(out).status, 0, 'لا استبدال');
  assert.notEqual(run2(path.join(ROOT, 'keys')).status, 0, 'يرفض الكتابة داخل مستودع git');
  assert.notEqual(spawnSync(process.execPath, [path.join(ROOT, 'tools', 'generate-keypair.js'), '--kid', 'BAD KID', '--out-dir', out]).status, 0);
  fs.rmSync(out, { recursive: true, force: true });
});

// ---------- فحص الأسرار ----------
test('scan-secrets: نظيف على المستودع، ويكشف مفتاحًا خاصًا وملف مفتاح وتوكن', () => {
  assert.equal(spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'scan-secrets.js')], { encoding: 'utf8' }).status, 0);
  const d = tmpRepo();
  const scan = () => spawnSync(process.execPath, [path.join(d, 'scripts', 'scan-secrets.js')], { cwd: d, encoding: 'utf8' }).status;
  assert.equal(scan(), 0);
  fs.writeFileSync(path.join(d, 'note.txt'), '-----BEGIN ' + 'PRIVATE KEY-----\nabc\n'); assert.equal(scan(), 1); fs.rmSync(path.join(d, 'note.txt'));
  fs.writeFileSync(path.join(d, 'k1.pem'), 'x'); assert.equal(scan(), 1); fs.rmSync(path.join(d, 'k1.pem'));
  fs.writeFileSync(path.join(d, 'keys', 'public', 'k1.jwk.json'), '{"kty":"EC","crv":"P-256","x":"a","y":"b","d":"' + 'A'.repeat(43) + '"}'); assert.equal(scan(), 1); fs.rmSync(path.join(d, 'keys', 'public', 'k1.jwk.json'));
  fs.writeFileSync(path.join(d, 'n.md'), 'token ghp_' + 'a'.repeat(30)); assert.equal(scan(), 1);
  fs.rmSync(d, { recursive: true, force: true });
});

// ---------- لا مفاتيح خاصة في المستودع ----------
test('المستودع: لا ملفات مفاتيح، ولا يوجد مفتاح عام مزيَّف (تُنشأ المفاتيح العامة من المالك)', () => {
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.name === '.git' || e.name === 'node_modules' ? [] : e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
  const files = walk(ROOT);
  assert.ok(!files.some((f) => /\.(pem|key|p12|pfx|jks|keystore)$/i.test(f)));
  for (const f of files.filter((f) => /keys[\\/]public[\\/].*\.jwk\.json$/.test(f))) assert.ok(!('d' in JSON.parse(fs.readFileSync(f, 'utf8'))), f);
});
