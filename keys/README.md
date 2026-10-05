# المفاتيح العامة

هنا **المفاتيح العامة فقط** بصيغة JWK (`kty, crv, x, y`) بالأسماء `k1.jwk.json` و`k2.jwk.json`. أي ملف يحوي الحقل `d` (جزء خاص) يُرفض من `verify` ومن فحص الأسرار.

## إنشاء المفاتيح (إجراء يدوي من المالك، على جهازك الشخصي)
```
node tools/generate-keypair.js --kid k1 --out-dir "<مجلد آمن خارج أي مستودع>"
node tools/generate-keypair.js --kid k2 --out-dir "<مكان آمن مختلف>"
```
1. الأداة تكتب `k1.private.pem` / `k2.private.pem` في المجلد الذي تحدده (وترفض الكتابة داخل مستودع git)، وتطبع المفتاح العام وبصمته.
2. انسخ كل مفتاح عام إلى `keys/public/<kid>.jwk.json` (ملفان) واعمل commit لهما.
3. **k1:** أضف محتوى `k1.private.pem` كاملًا Secret باسم `CONTROL_K1_PRIVATE` في Settings ← Environments ← `publish`، ثم احذف نسخته من الجهاز أو احفظه مشفرًا.
4. **k2:** لا يُرفع. احفظه مشفرًا في مكانين منفصلين.
5. أنشئ البيئة `publish` مع **Required reviewers = أنت**، وفعّل Pages من فرع `gh-pages` (المجلد الجذر) بعد أول نشر.
