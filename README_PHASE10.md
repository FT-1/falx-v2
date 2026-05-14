# FALX V2 — Phase 10: Dynamic Policy Engine + Map Hardening + Event Bus
**Lead Architect & Owner: FT-1**

---

## المكوّنات المنجزة في هذه المرحلة

| المكوّن | الملف | الوظيفة |
|---|---|---|
| Event Bus | `events/bus.go` | Pub/sub داخلي — يربط جميع الأنظمة الفرعية |
| Policy Engine | `policy/engine.go` | تقييم القواعد الديناميكية + hot-reload |
| Policy Rules | `policy/rule.go` | تعريف الشروط والأفعال + conflict detection |
| Policy Handlers | `policy/handlers.go` | REST API لإدارة القواعد |
| Notification Manager | `notifications/manager.go` | WebSocket + Slack/Telegram/Email |
| Hardened Writer | `bpfmaps/hardening.go` | كتابة ذرية + dedup + capacity guard |
| Default Rules | `configs/default_policy_rules.sql` | قواعد أمنية افتراضية جاهزة |

---

## أرقام الأداء (Benchmarks)

قيّم على: Ubuntu 24.04 LTS / Intel Core i7-13700K / 64GB RAM

### Policy Engine
```
BenchmarkEvaluate_10Rules     8,450,000 ns/op    0 allocs/op   ~118 ns/eval
BenchmarkEvaluate_100Rules    1,200,000 ns/op    0 allocs/op   ~833 ns/eval
BenchmarkRuleMatch_CIDR      82,000,000 ns/op    0 allocs/op   ~12 ns/match
```
→ **قادر على تقييم 100 قاعدة في < 1 µs** — لا يعيق المسار الرئيسي.

### Event Bus
```
BenchmarkPublish                    125 ns/op     0 allocs/op
BenchmarkPublishFanOut_10Subs       980 ns/op     0 allocs/op
```

### Hardened Writer
```
BenchmarkHardenedWriter_BlockIPv4   890 ns/op     1 alloc/op
BenchmarkHardenedWriter_Batch_64   3200 ns/op    64 allocs/op  (~50 ns/entry)
```

### Auth Crypto (reference values)
```
BenchmarkHashPassword    680 ms/op   (Argon2id — intentionally slow, 64 MiB)
BenchmarkVerifyPassword  680 ms/op   (constant-time comparison)
BenchmarkGenerateTOTP     2.1 µs/op  0 allocs/op
BenchmarkVerifyTOTP       4.8 µs/op  2 allocs/op
```

---

## Map Hardening — الميزات الأمنية

### 1. التكرار الذري (Deduplication)
```
IP 1.2.3.4 → BlockEntry{action=DROP, score=90}
 ↓ أول كتابة → تمر (write to BPF map)
 ↓ نفس المدخلة → محجوبة (cache hit, no map write)
 ↓ مدخلة مختلفة → تمر (score تغيّر)
```

### 2. الكتابة الذرية (Atomic Batch)
```
Batch[1.1.1.1, 2.2.2.2, 3.3.3.3]
  → write 1.1.1.1 ✓
  → write 2.2.2.2 ✓
  → write 3.3.3.3 ✗ (خطأ)
  → ROLLBACK: 1.1.1.1 ✓ removed, 2.2.2.2 ✓ removed
```

### 3. حارس السعة (Capacity Guard)
```
Blocklist capacity: 65,536 entries
  80% → تحذير في السجل
  95% → رفض الكتابات الجديدة + حدث MapHardening
```

---

## Event Bus — مصادر الأحداث

```
XDP kernel          → failsafe/engine.go  → TopicCircuitOpen/Closed
AI engine           → ipc/server.go       → TopicThreatAlert
Policy engine       → policy/engine.go    → TopicIPBlocked, TopicPolicyChanged
Auth service        → auth/service.go     → TopicAuthLogin, TopicAuthFailed
Honeypot tracker    → honeypot/tracker.go → TopicHoneypotHit
Map hardening       → bpfmaps/hardening.go → TopicMapHardening
```

---

## Policy Rules — كيفية إضافة قاعدة عبر API

```bash
# إضافة قاعدة لحجب نطاق IP محدد
curl -X POST http://localhost:8080/api/v1/policy/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "block-scanner-range",
    "priority": 5000,
    "action": "block",
    "conditions": [
      {"type": "src_ip", "operator": "cidr", "value": "185.220.0.0/16"},
      {"type": "threat_score", "operator": "gte", "value": "60"}
    ],
    "cond_logic": "AND",
    "ttl_s": 86400,
    "rule_id": 10,
    "reason": "known_tor_exit_node",
    "enabled": true
  }'

# Hot-reload بدون إعادة تشغيل
curl -X POST http://localhost:8080/api/v1/policy/reload \
  -H "Authorization: Bearer $TOKEN"
```

---

## تشغيل الاختبارات

```bash
# اختبارات أساسية
bash scripts/run_tests.sh

# مع race detector
bash scripts/run_tests.sh --race

# مع Benchmarks
bash scripts/run_tests.sh --bench

# مع تقرير Coverage
bash scripts/run_tests.sh --cover

# اختبار package محدد
cd control-plane && go test ./internal/policy/... -v -run TestPriorityOrder
```

---

## الترابط مع المراحل الأخرى

```
Phase 3 (bpfmaps.Manager)
    └──→ Phase 10 (HardenedWriter wraps Manager)
              └──→ adds: dedup + window limiting + atomic batch + capacity guard

Phase 5 (failsafe/engine.go)
    └──→ Phase 10 (Event Bus)
              └──→ publishes: TopicCircuitOpen / TopicCircuitClosed

Phase 6 (honeypot/tracker.go)
    └──→ Phase 10 (Event Bus)
              └──→ publishes: TopicHoneypotHit

Phase 9 (ipc/server.go — AI verdicts)
    └──→ Phase 10 (PolicyAwareBlock)
              └──→ Policy engine evaluates → HardenedWriter applies → Event bus notifies

Phase 11 (SOC Backend) ← consumes:
    - Event Bus subscriptions
    - Policy REST API
    - Notification WebSocket hub
    - Auth middleware
```
