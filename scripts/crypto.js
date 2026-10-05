'use strict';
// التوقيع والتحقق: ECDSA P-256 + SHA-256، التوقيع بصيغة IEEE-P1363 (r||s، 64 بايت) وهي صيغة WebCrypto مباشرة.
// الصيغة (envelope): {"v":1,"kid":"k1","payload":"<base64url لبايتات JSON>","sig":"<base64url>"}
// التوقيع على بايتات الـpayload المفكوكة نفسها (لا توحيد نصّي)، ولا يُحلَّل JSON إلا بعد نجاح التحقق.
const crypto = require('crypto');
const { b64u, buildPayload } = require('./lib');

function signEnvelope(payloadObj, privateKeyPem, kid) {
  if (!/^[a-z0-9_-]{1,16}$/.test(kid)) throw new Error('kid غير صالح');
  const bytes = Buffer.from(JSON.stringify(payloadObj), 'utf8');
  const key = crypto.createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails.namedCurve !== 'prime256v1') throw new Error('المفتاح الخاص يجب أن يكون EC P-256');
  const sig = crypto.sign('sha256', bytes, { key, dsaEncoding: 'ieee-p1363' });
  return { v: 1, kid, payload: b64u.enc(bytes), sig: b64u.enc(sig) };
}

// keys: { kid: JWK } (مفاتيح عامة فقط). يعيد { payload, bytes, kid } أو يرمي خطأ.
function verifyEnvelope(env, keys) {
  if (!env || typeof env !== 'object' || env.v !== 1 || typeof env.kid !== 'string' || typeof env.payload !== 'string' || typeof env.sig !== 'string') throw new Error('مغلّف غير صالح');
  const jwk = Object.prototype.hasOwnProperty.call(keys, env.kid) ? keys[env.kid] : null;
  if (!jwk) throw new Error('kid غير موثوق: ' + env.kid);
  if (jwk.d) throw new Error('المفتاح المُعطى يحوي جزءًا خاصًا (d)! يجب أن يكون عامًا فقط');
  const pub = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const bytes = b64u.dec(env.payload), sig = b64u.dec(env.sig);
  if (sig.length !== 64) throw new Error('طول التوقيع غير صحيح');
  if (!crypto.verify('sha256', bytes, { key: pub, dsaEncoding: 'ieee-p1363' }, sig)) throw new Error('التوقيع غير صحيح');
  return { payload: JSON.parse(bytes.toString('utf8')), bytes, kid: env.kid };
}

module.exports = { signEnvelope, verifyEnvelope, buildPayload };
