# FALX V2 — Security Policy
**Lead Architect & Owner: FT-1**

---

## تقرير الثغرات الأمنية

هذا مشروع خاص. للإبلاغ عن ثغرة أمنية، تواصل مباشرة مع **FT-1**.

لا تفتح Issue عام لأي ثغرة أمنية.

---

## نموذج التهديد (Threat Model)

### الأصول المحمية
| الأصل | المستوى | الوصف |
|---|---|---|
| BPF Maps | حرج | قراءة/كتابة غير مصرح بها تؤثر مباشرة على قرارات الحجب |
| JWT Private Key | حرج | تسريبه يسمح بانتحال هوية أي مستخدم |
| Auth Database | عالي | يحتوي على hashes كلمات المرور + TOTP secrets |
| Audit Log | متوسط | التلاعب به يخفي النشاط الضار |
| Failsafe State | عالي | التلاعب به قد يوقف أو يفعّل وضع الطوارئ |

### المهاجمون المفترضون
1. **مهاجم شبكي خارجي**: يحاول تجاوز XDP blocklist
2. **مستخدم غير مصرح داخلي**: يحاول رفع صلاحياته
3. **خدمة AI مخترقة**: ترسل verdicts ضارة عبر IPC
4. **DoS**: يحاول تعطيل قاطع الدائرة أو استنزاف BPF maps

---

## ضمانات الأمان المُطبَّقة

### طبقة XDP (النواة)
- ✅ جميع عمليات الذاكرة محمية بـ BPF verifier
- ✅ LRU maps تمنع استنزاف الذاكرة
- ✅ Circuit breaker يُسقط تلقائياً عند الفيضان
- ✅ Rate limiting على مستوى مصدر IP
- ✅ XSK_MAP محمي بصلاحيات kernel

### طبقة Control Plane
- ✅ كل كتابة BPF map مقيّدة بـ Token Bucket (10,000 op/sec)
- ✅ Atomic batch writes مع rollback عند الفشل
- ✅ Deduplication cache يمنع الكتابات المكررة
- ✅ Capacity guard يوقف الكتابة عند 95% امتلاء
- ✅ Audit trail لكل تغيير في الخرائط

### طبقة المصادقة
- ✅ **Argon2id** لتشفير كلمات المرور (64 MiB، 3 iterations)
- ✅ **RS256** للـ JWT (4096-bit RSA key)
- ✅ **TOTP** (RFC 6238) للمصادقة الثنائية
- ✅ Replay prevention لرموز TOTP
- ✅ Refresh token rotation على كل استخدام
- ✅ Inactivity timeout (25 دقيقة)
- ✅ Account lockout بعد 5 محاولات فاشلة
- ✅ Login rate limiting (10 req/min per IP)
- ✅ Constant-time password comparison

### طبقة IPC (AI Engine)
- ✅ Unix domain socket (لا شبكة خارجية)
- ✅ SO_PEERCRED التحقق من UID عند الاتصال
- ✅ Rate limiting على MapUpdateReq
- ✅ CRC32 لكل frame
- ✅ Max payload 1 MiB

### طبقة SOC Backend
- ✅ RBAC دقيق على كل endpoint
- ✅ Security headers (HSTS, CSP, X-Frame-Options...)
- ✅ CORS محدود بـ allowlist
- ✅ Input validation + size limits (1 MiB max)
- ✅ JWT verification على كل request

---

## متطلبات النشر الآمن

### TLS
```bash
# إنشاء شهادة self-signed (للتطوير فقط)
openssl req -x509 -newkey rsa:4096 -keyout server.key \
    -out server.crt -days 365 -nodes \
    -subj "/CN=soc.falx.local"
sudo install -m600 server.key /etc/falx/tls/
sudo install -m644 server.crt /etc/falx/tls/

# للإنتاج: استخدم Let's Encrypt أو شهادة مؤسسية
```

### Secrets Rotation
```bash
# تجديد JWT keys (يُبطل جميع الجلسات النشطة)
sudo rm /etc/falx/keys/jwt_*.pem
sudo systemctl restart falx-soc
# سيتم توليد مفاتيح جديدة تلقائياً عند الإقلاع

# تغيير كلمة admin
curl -X PUT https://soc.falx.local/api/v1/auth/me/password \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"old_password":"current","new_password":"NewSecure123!"}'
```

### Audit Log Monitoring
```bash
# مراقبة الأحداث الحرجة
tail -f /var/log/falx/audit.jsonl | jq 'select(.action | test("login|block|circuit"))'

# البحث عن محاولات فاشلة
jq 'select(.success==false)' /var/log/falx/audit.jsonl

# تصدير لـ SIEM
journalctl -u falxd -u falx-soc --output=json | \
    nc siem.company.local 5140
```

---

## إجراء الفحص الأمني

```bash
# تشغيل فحص الأمان الكامل
sudo bash scripts/security_audit.sh

# تشغيل اختبارات الـ chaos
go test ./tests/ -run TestChaos -v

# فحص الثغرات في التبعيات
cd control-plane && govulncheck ./...
cd soc-backend   && govulncheck ./...
```

---

## إعدادات مُوصى بها للإنتاج

```toml
# /etc/falx/falx.toml
[general]
log_level = "warn"   # لا debug في الإنتاج

[maps]
map_write_rate_limit_rps = 5000   # أقل من الافتراضي

[failsafe]
pps_threshold = 500000    # عتبة أكثر حذراً
cooldown_secs = 60        # cooldown أطول
```

```nginx
# إضافة OCSP Stapling في nginx.conf
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
```
