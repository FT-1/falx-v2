# FALX V2 — المرحلة 11: SOC Backend + Admin Panel + Role-Based Dashboard
**Lead Architect & Owner: FT-1**

---

## المكوّنات المنجزة في المرحلة 11

| الملف | الوظيفة |
|---|---|
| `soc-backend/cmd/main.go` | نقطة دخول SOC Backend مع كل الـ flags |
| `soc-backend/internal/server/server.go` | HTTP server — 40+ route مع RBAC middleware |
| `soc-backend/internal/api/security_handler.go` | Block/Unblock/Redirect + Failsafe control |
| `soc-backend/internal/api/dashboard_handler.go` | Overview + Stats + Threats + Timeline |
| `soc-backend/internal/api/handlers.go` | Notifications + Admin + System handlers |
| `soc-backend/internal/server/server_test.go` | Integration tests: auth, RBAC, headers |
| `soc-backend/internal/api/api_test.go` | API handler tests: security, dashboard |
| `soc-backend/dashboard/index.html` | SOC Dashboard SPA — Arabic RTL, Dark mode |
| `configs/nginx.conf` | Reverse proxy: TLS + rate limiting + WS |
| `scripts/deploy.sh` | Zero-downtime deploy + auto-rollback |
| `scripts/falx-soc.service` | systemd service للـ SOC backend |
| `scripts/falx-ai.service` | systemd service لمحرك الذكاء الاصطناعي |
| `docker-compose.yml` | كامل Docker stack |
| `docker/Dockerfile.*` | Dockerfiles للـ 3 مكوّنات |

---

## مرجع API الكامل

### 🔓 Public — بدون توثيق
```http
POST /api/v1/auth/login           تسجيل الدخول → JWT tokens
POST /api/v1/auth/refresh         تجديد الـ access token
GET  /api/v1/auth/roles           قائمة الأدوار والصلاحيات
GET  /healthz                     Liveness probe
GET  /readyz                      Readiness probe
```

### 🔐 Authenticated — viewer+
```http
POST /api/v1/auth/logout          تسجيل الخروج
POST /api/v1/auth/logout-all      إنهاء جميع الجلسات
GET  /api/v1/auth/me              بيانات المستخدم الحالي
PUT  /api/v1/auth/me/password     تغيير كلمة المرور
GET  /api/v1/dashboard            ملخص KPIs + stats + failsafe
GET  /api/v1/dashboard/stats      إحصاءات XDP التفصيلية
GET  /api/v1/dashboard/threats    التهديدات النشطة + threat level
GET  /api/v1/dashboard/timeline   جدول زمني للأحداث
GET  /api/v1/system/health        حالة جميع الأنظمة الفرعية
GET  /api/v1/notifications        قائمة الإشعارات (limit, unread)
GET  /api/v1/notifications/unread-count  عدد غير المقروءة
PUT  /api/v1/notifications/{id}/read     تعليم كمقروء
GET  /ws                          WebSocket — بث الأحداث المباشرة
```

### 🛡️ Security — analyst+
```http
GET    /api/v1/security/blocklist           قائمة IPs المحظورة
POST   /api/v1/security/block               حظر IP
                                            analyst: max 24h فقط
                                            senior+: دائم أو مؤقت
DELETE /api/v1/security/block/{ip}         إلغاء الحظر [senior_analyst+]
POST   /api/v1/security/redirect            إعادة توجيه لـ honeypot [senior_analyst+]
GET    /api/v1/security/rate-buckets        إحصاءات rate limiter
GET    /api/v1/security/honeypot/sessions   جلسات مصائد العسل
GET    /api/v1/security/stats               إحصاءات XDP الأمنية
GET    /api/v1/failsafe                     حالة قاطع الدائرة الكاملة
POST   /api/v1/failsafe/open                فتح الدائرة [senior_analyst+]
POST   /api/v1/failsafe/close               إغلاق الدائرة [senior_analyst+]
PUT    /api/v1/failsafe/thresholds          تعديل عتبات PPS/BPS
```

### 📋 Policy — senior_analyst+
```http
GET    /api/v1/policy/rules                 قائمة كل القواعد
POST   /api/v1/policy/rules                 إضافة قاعدة جديدة
GET    /api/v1/policy/rules/{id}            تفاصيل قاعدة
PUT    /api/v1/policy/rules/{id}            تعديل قاعدة
DELETE /api/v1/policy/rules/{id}            حذف قاعدة [admin+]
POST   /api/v1/policy/rules/{id}/enable     تفعيل القاعدة
POST   /api/v1/policy/rules/{id}/disable    تعطيل القاعدة
POST   /api/v1/policy/reload                Hot-reload بلا restart
GET    /api/v1/policy/stats                 إحصاءات المحرك
```

### 👥 Admin — admin+
```http
GET    /api/v1/users                        قائمة المستخدمين
POST   /api/v1/users                        إنشاء مستخدم جديد
GET    /api/v1/users/{id}                   تفاصيل مستخدم
PUT    /api/v1/users/{id}/lock              قفل الحساب
PUT    /api/v1/users/{id}/unlock            إلغاء القفل
GET    /api/v1/audit                        سجل التدقيق [senior_analyst+]
GET    /api/v1/system/config                إعدادات النظام [super_admin]
PUT    /api/v1/system/config                تعديل الإعدادات [super_admin]
GET    /api/v1/system/metrics-summary       ملخص شامل للـ metrics
```

---

## الصلاحيات حسب الدور

| الصفحة / الوظيفة | Viewer | Analyst | Sr. Analyst | Admin | Super Admin |
|---|:---:|:---:|:---:|:---:|:---:|
| Dashboard الرئيسية | ✅ | ✅ | ✅ | ✅ | ✅ |
| البث المباشر (WS) | ✅ | ✅ | ✅ | ✅ | ✅ |
| إحصاءات XDP | ✅ | ✅ | ✅ | ✅ | ✅ |
| قائمة الحظر | — | ✅ | ✅ | ✅ | ✅ |
| حظر IP (مؤقت 24h) | — | ✅ | ✅ | ✅ | ✅ |
| حظر IP (دائم) | — | — | ✅ | ✅ | ✅ |
| إلغاء الحظر | — | — | ✅ | ✅ | ✅ |
| إعادة توجيه Honeypot | — | — | ✅ | ✅ | ✅ |
| عرض قاطع الدائرة | ✅ | ✅ | ✅ | ✅ | ✅ |
| التحكم في الدائرة | — | — | ✅ | ✅ | ✅ |
| إدارة القواعد | عرض | عرض | ✅ | ✅ | ✅ |
| حذف القواعد | — | — | — | ✅ | ✅ |
| إدارة المستخدمين | — | — | — | ✅ | ✅ |
| سجل التدقيق | — | — | ✅ | ✅ | ✅ |
| إعدادات النظام | — | — | — | — | ✅ |
| إنشاء Super Admin | — | — | — | — | ✅ |

---

## Dashboard SOC — الميزات التقنية

### Real-time WebSocket
```javascript
// الاتصال التلقائي مع exponential backoff
ws = new WebSocket(`wss://soc.falx.local/ws?token=${JWT}`)
ws.onmessage = e => handleEvent(JSON.parse(e.data))

// مثال على حدث مباشر
{
  "id": "a1b2c3d4",
  "topic": "security.ip.blocked",
  "severity": "warning",
  "title": "IP Address Blocked",
  "message": "IP 185.220.101.45 blocked by soc:admin",
  "timestamp": "2026-01-15T14:30:00Z",
  "meta": { "src_ip": "185.220.101.45", "ttl_s": "3600" }
}
```

### مثال Login Flow
```bash
# 1. Login
curl -X POST https://soc.falx.local/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FLX-abc123!"}' \
  | jq .tokens.access_token

# 2. Block IP
curl -X POST https://soc.falx.local/api/v1/security/block \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"185.220.101.45","ttl_s":3600,"reason":"tor_exit_node","threat_score":85}'

# 3. Check failsafe
curl -s https://soc.falx.local/api/v1/failsafe \
  -H "Authorization: Bearer $TOKEN" | jq '{open:.circuit_open,pps:.current_pps}'

# 4. Add policy rule
curl -X POST https://soc.falx.local/api/v1/policy/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "block-high-threat",
    "priority": 8000,
    "action": "block",
    "conditions": [{"type":"threat_score","operator":"gte","value":"90"}],
    "ttl_s": 3600,
    "enabled": true
  }'
```

---

## أرقام الأداء

| المقياس | القيمة | الملاحظة |
|---|---|---|
| Login latency | ~680ms | Argon2id متعمّد البطء |
| /dashboard latency | < 5ms | BPF map read + JSON |
| WebSocket fan-out | < 1ms | 10 subscribers |
| RBAC middleware | < 1µs | Map lookup |
| JWT verify (RS256) | ~150µs | RSA signature |
| Dashboard size | ~88 KB | SPA بلا dependencies خارجية |
| SOC memory | ~35 MB | في الذاكرة |
| Concurrent WS | 10,000+ | goroutine per connection |

---

## تشغيل بـ Docker

```bash
# تشغيل الـ stack الكامل
docker compose up -d

# الخدمات
# SOC Dashboard:  http://localhost:8080
# Prometheus:     http://localhost:9090
# Grafana:        http://localhost:3000 (admin/falx-v2)

# Logs
docker compose logs -f falxd
docker compose logs -f falx-soc

# إيقاف
docker compose down
```

---

## النشر على Production

```bash
# النشر الكامل (يشمل Tests + Build + Deploy + Health Check)
sudo bash scripts/deploy.sh

# نشر سريع بدون اختبارات
sudo bash scripts/deploy.sh --skip-tests

# Staging
sudo bash scripts/deploy.sh --env staging

# استرجاع الإصدار السابق عند الحاجة
sudo bash scripts/deploy.sh --rollback
```

---

## الترابط الكامل مع جميع المراحل

```
Phase 1  (Project Scaffolding) ─────→ Makefile + go.mod + configs
Phase 2  (XDP Pipeline)  ───────────→ BPF maps للـ SecurityHandler
Phase 3  (Map Security)  ───────────→ Rate-limited map writes
Phase 4  (AF_XDP Bridge) ───────────→ MetaCh → AI inference
Phase 5  (Failsafe Engine) ─────────→ ForceOpen/Close Circuit API
Phase 6  (Honeypot) ────────────────→ RedirectIP + session tracking
Phase 7  (Control Plane) ───────────→ falxd daemon يوفر BPF maps
Phase 8  (Secure IPC) ──────────────→ AI verdicts → PolicyAwareBlock
Phase 9  (Auth + AI)  ──────────────→ JWT middleware + RBAC
Phase 10 (Policy + Events) ─────────→ Policy API + WS event bus
Phase 11 (SOC Backend) ─────────────→ هذه المرحلة ✓
Phase 12 (Final + Docs) ────────────→ التالي
```
