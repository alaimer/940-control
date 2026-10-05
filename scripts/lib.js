'use strict';
// المكتبة المشتركة: base64url، semver صارم، قائمة الروابط البيضاء، والتحقق من control.json.
// بلا أي اعتماديات خارجية (سلسلة توريد صغيرة). هذا الملف هو المرجع الملزِم؛ schema/control.schema.json وصف هيكلي فقط.

const STATUSES = ['active', 'update_available', 'force_update', 'blocked'];
const PLATFORMS = ['android', 'windows'];
const EXT = { android: '.apk', windows: '.exe' };
const MAX_MESSAGE = 500;
const GRACE_MIN_DAYS = 1, GRACE_MAX_DAYS = 7, GRACE_DEFAULT_DAYS = 3; // الحد الأقصى ثابت أيضًا داخل التطبيق ولا يتجاوزه الـmanifest
const MAX_UNTIL_AHEAD_MS = 30 * 24 * 3600 * 1000; // حماية من خطأ كتابة (مثل سنة 2062)

const b64u = {
  enc: (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => {
    if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('base64url غير صالح');
    return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  }
};

// ===== semver صارم: X.Y.Z أرقام فقط (بلا v ولا pre-release ولا أصفار بادئة) والمقارنة رقمية لا نصية =====
const SEMVER = /^(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})$/;
function parseSemver(s) {
  const m = typeof s === 'string' ? SEMVER.exec(s) : null;
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}
function cmpSemver(a, b) {
  const x = parseSemver(a), y = parseSemver(b);
  if (!x || !y) throw new Error('semver غير صالح');
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}

// ===== قائمة الروابط البيضاء (HTTPS فقط، تحقق صارم عبر URL لا عبر تعابير نصية) =====
// مطابقة لما اعتمدته للتطبيق: github.com/alaimer/940-control/releases/download/ و ars.gov.sa ونطاقاتها الفرعية.
function checkDownloadUrl(raw, platform) {
  let u;
  try { u = new URL(raw); } catch (e) { return 'رابط غير صالح'; }
  if (typeof raw !== 'string' || raw.length > 400) return 'رابط طويل جدًا';
  if (/[\s\u0000-\u001f\u007f]/.test(raw)) return 'الرابط يحوي محارف غير مسموحة';
  if (/%2e|%2f|%5c/i.test(raw)) return 'مسار مشبوه (ترميز نقاط أو فواصل)'; // URL يطبّع %2e%2e قبل فحص المسار، فنفحص النص الخام
  if (u.protocol !== 'https:') return 'HTTPS فقط';
  if (u.username || u.password) return 'ممنوع وجود بيانات اعتماد في الرابط';
  if (u.port) return 'ممنوع تحديد منفذ';
  if (u.search || u.hash) return 'ممنوع query أو fragment';
  const host = u.hostname.toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(host) || host.includes('xn--')) return 'اسم المضيف يجب أن يكون ASCII عاديًا';
  const okGithub = host === 'github.com' && u.pathname.startsWith('/alaimer/940-control/releases/download/');
  const okArs = host === 'ars.gov.sa' || host.endsWith('.ars.gov.sa');
  if (!okGithub && !okArs) return 'المضيف أو المسار خارج القائمة البيضاء';
  if (u.pathname.includes('..') || u.pathname.includes('//') || /%2e|%2f|%5c/i.test(u.pathname)) return 'مسار مشبوه';
  if (!u.pathname.toLowerCase().endsWith(EXT[platform])) return 'امتداد الملف يجب أن يكون ' + EXT[platform];
  return null;
}

const CTL_RE = new RegExp('[\\u0000-\\u0008\\u000b\\u000c\\u000e-\\u001f\\u007f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069]'); // تحكم + فواصل أسطر Unicode + اتجاه ثنائي مخادع
const hasCtl = (s) => CTL_RE.test(s);
const ISO_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const isPlain = (o) => o !== null && typeof o === 'object' && !Array.isArray(o);
function onlyKeys(o, allowed, path, errs) {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) errs.push(`${path}: حقل غير معروف «${k}»`);
}
function checkMessage(m, path, errs) {
  if (m === undefined) return;
  if (typeof m !== 'string') { errs.push(`${path}: يجب أن تكون نصًا`); return; }
  if (m.length > MAX_MESSAGE) errs.push(`${path}: أطول من ${MAX_MESSAGE} حرفًا`);
  if (hasCtl(m)) errs.push(`${path}: محارف تحكم أو اتجاه مخفية غير مسموحة`);
}

// يتحقق من control.json (المصدر الذي يحرره المالك) ويعيد قائمة أخطاء (فارغة = صالح). now: Date لاختبار maintenance.until
function validateControl(c, now = new Date()) {
  const errs = [];
  if (!isPlain(c)) return ['الجذر يجب أن يكون كائنًا'];
  onlyKeys(c, ['schemaVersion', 'kind', 'offlineGraceDays', 'maintenance', 'platforms'], 'control', errs);
  if (c.schemaVersion !== 1) errs.push('schemaVersion يجب أن يكون 1');
  if (c.kind !== 'version-control') errs.push('kind يجب أن يكون "version-control"');
  if (c.offlineGraceDays !== undefined) {
    if (!Number.isInteger(c.offlineGraceDays) || c.offlineGraceDays < GRACE_MIN_DAYS || c.offlineGraceDays > GRACE_MAX_DAYS) {
      errs.push(`offlineGraceDays يجب أن يكون عددًا صحيحًا بين ${GRACE_MIN_DAYS} و${GRACE_MAX_DAYS}`);
    }
  }
  // الصيانة
  const mt = c.maintenance;
  if (!isPlain(mt)) errs.push('maintenance مطلوب ككائن');
  else {
    onlyKeys(mt, ['enabled', 'message', 'until'], 'maintenance', errs);
    if (typeof mt.enabled !== 'boolean') errs.push('maintenance.enabled يجب أن يكون true/false');
    checkMessage(mt.message, 'maintenance.message', errs);
    if (mt.enabled === true && !(typeof mt.message === 'string' && mt.message.trim())) errs.push('maintenance.message مطلوبة عند تفعيل الصيانة');
    if (mt.until !== undefined && mt.until !== null) {
      if (typeof mt.until !== 'string' || !ISO_Z.test(mt.until) || isNaN(Date.parse(mt.until))) errs.push('maintenance.until يجب أن يكون UTC بصيغة YYYY-MM-DDTHH:MM:SSZ أو null');
      else if (mt.enabled === true) {
        const t = Date.parse(mt.until);
        if (t <= now.getTime()) errs.push('maintenance.until منتهٍ أصلًا (يجب أن يكون في المستقبل)');
        if (t - now.getTime() > MAX_UNTIL_AHEAD_MS) errs.push('maintenance.until أبعد من 30 يومًا (احتمال خطأ كتابة)');
      }
    }
  }
  // المنصات
  if (!isPlain(c.platforms)) { errs.push('platforms مطلوب ككائن'); return errs; }
  onlyKeys(c.platforms, PLATFORMS, 'platforms', errs);
  for (const p of PLATFORMS) {
    const pl = c.platforms[p], path = `platforms.${p}`;
    if (!isPlain(pl)) { errs.push(`${path}: مطلوب`); continue; }
    onlyKeys(pl, ['latest', 'minimum', 'download', 'overrides'], path, errs);
    const okL = parseSemver(pl.latest), okM = parseSemver(pl.minimum);
    if (!okL) errs.push(`${path}.latest: semver غير صالح`);
    if (!okM) errs.push(`${path}.minimum: semver غير صالح`);
    if (okL && okM && cmpSemver(pl.minimum, pl.latest) > 0) errs.push(`${path}: minimum أعلى من latest`);
    const ov = pl.overrides === undefined ? {} : pl.overrides;
    if (!isPlain(ov)) { errs.push(`${path}.overrides: يجب أن يكون كائنًا`); continue; }
    let needsDownload = okL && okM && cmpSemver(pl.latest, pl.minimum) > 0;
    for (const [ver, o] of Object.entries(ov)) {
      const op = `${path}.overrides["${ver}"]`;
      if (!parseSemver(ver)) { errs.push(`${op}: مفتاح semver غير صالح`); continue; }
      if (!isPlain(o)) { errs.push(`${op}: يجب أن يكون كائنًا`); continue; }
      onlyKeys(o, ['status', 'message'], op, errs);
      if (!STATUSES.includes(o.status)) errs.push(`${op}.status: يجب أن يكون أحد ${STATUSES.join(' | ')}`);
      checkMessage(o.message, `${op}.message`, errs);
      if (o.status === 'blocked' && !(typeof o.message === 'string' && o.message.trim())) errs.push(`${op}.message: مطلوبة للإيقاف`);
      if (okL && ver === pl.latest && (o.status === 'blocked' || o.status === 'force_update')) errs.push(`${op}: ممنوع إيقاف/إجبار تحديث أحدث إصدار (${pl.latest})`);
      if (o.status === 'update_available' || o.status === 'force_update') needsDownload = true;
    }
    if (pl.download !== undefined) {
      if (!isPlain(pl.download)) errs.push(`${path}.download: يجب أن يكون كائنًا`);
      else {
        onlyKeys(pl.download, ['url', 'sha256'], `${path}.download`, errs);
        const why = checkDownloadUrl(pl.download.url, p);
        if (why) errs.push(`${path}.download.url: ${why}`);
        if (pl.download.sha256 !== undefined && !/^[0-9a-f]{64}$/.test(pl.download.sha256)) errs.push(`${path}.download.sha256: يجب أن يكون 64 خانة hex صغيرة`);
      }
    } else if (needsDownload) errs.push(`${path}.download: مطلوب لأن التحديث ممكن (latest > minimum أو override بتحديث)`);
  }
  return errs;
}

// يبني الـpayload الموقَّع بترتيب مفاتيح ثابت (لا يُوقَّع إلا بعد نجاح التحقق)
function buildPayload(c, { sequence, issuedAt }) {
  const pl = {};
  for (const p of PLATFORMS) {
    const s = c.platforms[p], o = { latest: s.latest, minimum: s.minimum };
    if (s.download) { o.download = { url: s.download.url }; if (s.download.sha256) o.download.sha256 = s.download.sha256; }
    o.overrides = {};
    for (const v of Object.keys(s.overrides || {}).sort((a, b) => cmpSemver(a, b))) {
      o.overrides[v] = { status: s.overrides[v].status, message: s.overrides[v].message || '' };
    }
    pl[p] = o;
  }
  return {
    schemaVersion: 1, kind: 'version-control', issuer: 'alaimer/940-control',
    sequence, issuedAt,
    offlineGraceDays: c.offlineGraceDays === undefined ? GRACE_DEFAULT_DAYS : c.offlineGraceDays,
    maintenance: { enabled: c.maintenance.enabled, message: c.maintenance.message || '', until: c.maintenance.until || null },
    platforms: pl
  };
}

module.exports = { STATUSES, PLATFORMS, GRACE_MIN_DAYS, GRACE_MAX_DAYS, GRACE_DEFAULT_DAYS, b64u, parseSemver, cmpSemver, checkDownloadUrl, validateControl, buildPayload };
