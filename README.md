<div align="center">

```
███████╗ █████╗ ██╗     ██╗  ██╗    ██╗   ██╗██████╗
██╔════╝██╔══██╗██║     ╚██╗██╔╝    ██║   ██║╚════██╗
█████╗  ███████║██║      ╚███╔╝     ██║   ██║ █████╔╝
██╔══╝  ██╔══██║██║      ██╔██╗     ╚██╗ ██╔╝██╔═══╝
██║     ██║  ██║███████╗██╔╝ ██╗     ╚████╔╝ ███████╗
╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝      ╚═══╝  ╚══════╝
```

**Hybrid XDP/AI Intrusion Prevention System**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-nightly-orange.svg)](https://www.rust-lang.org)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8.svg)](https://golang.org)
[![C++](https://img.shields.io/badge/C++-20-blue.svg)](https://isocpp.org)
[![Kernel](https://img.shields.io/badge/Kernel-≥5.15-green.svg)](https://kernel.org)
[![XDP](https://img.shields.io/badge/XDP-native%2Fskb-yellow.svg)](https://ebpf.io)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-orange.svg)](https://ubuntu.com)

*Lead Architect & Owner: **FT-1***

</div>

---

## ما هو FALX V2؟

FALX V2 هو نظام منع تسلل **(IPS)** هجين عالي الأداء يعمل في قلب Linux kernel. يجمع بين:

- **XDP سرعة الأجهزة** — قرارات حجب في < 1 µs مباشرة من driver النواة، قبل أن تصل الحزمة لـ TCP/IP stack
- **ذكاء اصطناعي في User-space** — تحليل عميق (SYN Flood, Port Scan, C2 Beacon, Amplification) بدون تأثير على throughput
- **منصة أمنية مؤسسية** — Multi-user RBAC، JWT RS256، TOTP 2FA، Audit trail كامل
- **SOC Dashboard متكامل** — Real-time WebSocket، Arabic RTL، 40+ API endpoint

### لماذا FALX V2 مختلف؟

| الميزة | FALX V2 | Snort 3 | Suricata |
|---|:---:|:---:|:---:|
| Throughput | **> 10 Gbps** | ~3 Gbps | ~5 Gbps |
| Decision latency | **< 1 µs** | ~50 µs | ~30 µs |
| Memory footprint | **~80 MB** | ~500 MB | ~300 MB |
| AI Integration | **Native** | Plugin | Plugin |
| Zero-copy path | **AF_XDP** | ❌ | ❌ |
| Circuit Breaker | **Autonomous** | Manual | Manual |
| SOC Dashboard | **Built-in** | ❌ | ❌ |

---

## المعمارية

```
┌─────────────────────────────────────────────────────────────────┐
│                    Network Interface (NIC)                       │
│            Intel i40e / Mellanox mlx5 / ixgbe                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │ Every packet
                           ▼
┌──────────────────── XDP Data Plane ─────────────────────────────┐
│  (Rust/Aya — runs inside Linux kernel at driver level)          │
│                                                                  │
│  Packet ──► Parser ──► Blocklist ──► Rate Limiter ──► Failsafe  │
│              L2/L3/L4    LRU Hash     Token Bucket   Circuit CB  │
│                             │              │              │       │
│                         XDP_DROP      XDP_DROP       XDP_DROP    │
│                                                                  │
│              XDP_PASS ──────────────────────────────────────►   │
│              XDP_REDIRECT ──────────────────► Honeypot (XDP_TX) │
└──────────────────────────┬──────────────────────────────────────┘
                           │ AF_XDP Zero-Copy (UMEM)
                           ▼
┌──────────────── Control Plane (Go/falxd) ───────────────────────┐
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ BPF Maps │  │ AF_XDP   │  │ Failsafe │  │   Honeypot    │  │
│  │ Manager  │  │ Bridge   │  │ Engine   │  │   Manager     │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───────────────┘  │
│       │              │ PacketMeta  │ Events                      │
│       └──────────────┴─────────────┘                            │
│                        │                                         │
│              ┌──────── Event Bus ────────┐                       │
│              │  Policy Engine            │                       │
│              │  Notifications Manager    │                       │
│              │  Prometheus Collector     │                       │
│              └───────────────────────────┘                      │
└──────────────────────────┬──────────────────────────────────────┘
                           │ IPC — FLX2 Protocol (Unix Socket)
                           ▼
┌──────────────── AI Inference Engine (C++) ──────────────────────┐
│  Feature Extraction → Heuristic Scoring → ONNX Model            │
│  SYN Flood │ Port Scan │ Brute Force │ Amplification │ C2 Beacon │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP/WS/gRPC
                           ▼
┌──────────────── SOC Backend (Go) ───────────────────────────────┐
│  REST API (40+ routes) │ WebSocket Real-time │ JWT RBAC         │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Dashboard (Arabic RTL SPA)                   │  │
│  │  Block IPs │ Policies │ Users │ Audit │ Failsafe Control  │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## هيكل الملفات

```
falx-v2/
├── ebpf-kern/          # XDP kernel program (Rust/Aya)
│   └── src/
│       ├── main.rs     # Entry point + XDP pipeline
│       ├── parser.rs   # Bounds-checked L2/L3/L4 parser
│       ├── maps.rs     # 6 BPF map declarations
│       ├── types.rs    # ABI contract (shared with Go/Rust)
│       └── honeypot.rs # Silent redirect via XDP_TX
├── ebpf-user/          # BPF loader (Rust/Aya)
├── control-plane/      # falxd daemon (Go 1.22) — 50+ files
│   └── internal/
│       ├── auth/       # JWT RS256 + Argon2id + TOTP + RBAC
│       ├── bpfmaps/    # Map manager + Rate limiter + Audit
│       ├── afxdp/      # Zero-copy bridge (UMEM + rings)
│       ├── failsafe/   # Circuit breaker (4 algorithms)
│       ├── honeypot/   # Manager + Tracker
│       ├── ipc/        # FLX2 protocol server (Unix socket)
│       ├── policy/     # Dynamic rule engine (SQLite)
│       └── events/     # Event bus (pub/sub)
├── soc-backend/        # HTTP/WS server + Dashboard (Go)
│   └── dashboard/      # Arabic RTL SPA (single HTML file)
├── ai-inference/       # AI engine (C++20 + CMake)
│   └── src/
│       ├── inference_engine.cpp  # 5 heuristic algorithms
│       ├── ipc_client.cpp        # FLX2 Unix socket client
│       └── ipc_protocol.hpp      # Binary frame protocol
├── configs/            # falx.toml, nginx.conf, seccomp, SQL
├── docker/             # Dockerfiles + Grafana + Prometheus
│   ├── Dockerfile.falxd  # Multi-stage: Rust/eBPF + Go
│   ├── Dockerfile.soc    # Go SOC backend
│   └── Dockerfile.ai     # C++20 multi-stage build
├── scripts/            # setup, deploy, audit, package, tests
└── tests/              # Load + Chaos tests
```

---

## التثبيت والبناء

### المتطلبات

| المتطلب | الحد الأدنى | ملاحظة |
|---|---|---|
| Ubuntu | 22.04 LTS / 24.04 LTS | OS آخر غير مدعوم |
| Linux Kernel | ≥ 5.15 | 6.x موصى به |
| RAM | 8 GB | 16 GB للإنتاج |
| NIC | تدعم XDP | Intel i40e / Mellanox mlx5 / ixgbe |
| Go | 1.22+ | لـ control-plane و soc-backend |
| Rust | nightly | لـ eBPF kernel program |
| CMake | ≥ 3.20 | لـ AI engine |

---

### البناء من المصدر على Ubuntu (خطوة بخطوة)

```bash
# ══════════════════════════════════════════════════════════════
# الخطوة 1: حزم النظام
# ══════════════════════════════════════════════════════════════
sudo apt-get update && sudo apt-get install -y \
  build-essential cmake pkg-config git curl wget jq zip \
  clang llvm libelf-dev linux-headers-$(uname -r) \
  libbpf-dev bpftool sqlite3 libsqlite3-dev \
  nlohmann-json3-dev libspdlog-dev libfmt-dev \
  ca-certificates openssl

# ══════════════════════════════════════════════════════════════
# الخطوة 2: BPF filesystem (مطلوب لـ BPF map pinning)
# ══════════════════════════════════════════════════════════════
sudo mount -t bpf bpffs /sys/fs/bpf 2>/dev/null || true
grep -q 'bpffs' /etc/fstab || \
  echo 'bpffs /sys/fs/bpf bpf defaults 0 0' | sudo tee -a /etc/fstab

# تحقق
mount | grep bpf    # يجب أن يظهر: bpffs on /sys/fs/bpf type bpf

# ══════════════════════════════════════════════════════════════
# الخطوة 3: Go 1.22
# ══════════════════════════════════════════════════════════════
GO_VER=1.22.5
curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" \
  | sudo tar -C /usr/local -xz
export PATH="$PATH:/usr/local/go/bin"
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
go version    # يجب: go version go1.22.x linux/amd64

# ══════════════════════════════════════════════════════════════
# الخطوة 4: Rust + eBPF toolchain
# ══════════════════════════════════════════════════════════════
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

rustup toolchain install nightly --component rust-src
rustup target add bpfel-unknown-none
cargo install bpf-linker

rustup show    # تحقق أن nightly + bpfel-unknown-none مثبّتَين

# ══════════════════════════════════════════════════════════════
# الخطوة 5: تثبيت Go dependencies
# ══════════════════════════════════════════════════════════════
cd control-plane && go mod tidy && go mod download && cd ..
cd soc-backend   && go mod tidy && go mod download && cd ..

# ══════════════════════════════════════════════════════════════
# الخطوة 6: بناء eBPF kernel program (Rust → .bpf.o)
# ══════════════════════════════════════════════════════════════
cargo +nightly build \
  --manifest-path ebpf-kern/Cargo.toml \
  --target bpfel-unknown-none \
  -Z build-std=core \
  --release

# ══════════════════════════════════════════════════════════════
# الخطوة 7: بناء BPF loader (Rust user-space)
# ══════════════════════════════════════════════════════════════
cargo build --manifest-path ebpf-user/Cargo.toml --release

# ══════════════════════════════════════════════════════════════
# الخطوة 8: بناء Control Plane (Go — falxd daemon)
# ══════════════════════════════════════════════════════════════
mkdir -p bin
cd control-plane
go build \
  -ldflags "-s -w -X main.Version=0.1.0 -X main.BuildTime=$(date -u +%Y%m%dT%H%M%SZ)" \
  -o ../bin/falxd \
  ./cmd/falxd/
cd ..

# ══════════════════════════════════════════════════════════════
# الخطوة 9: بناء AI Inference Engine (C++20 + CMake)
# ══════════════════════════════════════════════════════════════
cmake \
  -S ai-inference \
  -B ai-inference/build \
  -DCMAKE_BUILD_TYPE=Release

cmake --build ai-inference/build --parallel $(nproc)
cp ai-inference/build/falx-ai bin/

# ══════════════════════════════════════════════════════════════
# الخطوة 10: بناء SOC Backend (Go)
# ══════════════════════════════════════════════════════════════
cd soc-backend
go build -ldflags "-s -w" -o ../bin/falx-soc ./cmd/
cd ..

# ══════════════════════════════════════════════════════════════
# تحقق نهائي
# ══════════════════════════════════════════════════════════════
ls -lh bin/
# يجب أن ترى:
#   falxd      (Go control plane daemon)
#   falx-user  (Rust BPF loader)
#   falx-ai    (C++ inference engine)
#   falx-soc   (Go SOC backend)
```

---

### الإعداد والتشغيل

```bash
# ── إعداد المجلدات والإعدادات ─────────────────────────────────
sudo install -d -m 750 \
  /etc/falx/keys  /etc/falx/tls \
  /var/log/falx   /var/lib/falx \
  /var/run/falx   /opt/falx/models

sudo cp configs/falx.toml          /etc/falx/falx.toml
sudo cp configs/honeypot.toml      /etc/falx/honeypot.toml
sudo cp configs/notifications.toml /etc/falx/notifications.toml
sudo chmod 640 /etc/falx/*.toml

# ── ضبط الواجهة الشبكية ───────────────────────────────────────
ip link show   # اعرف اسم واجهتك: eth0, ens3, enp3s0 ...
sudo nano /etc/falx/falx.toml
# غيّر:   iface = "eth0"    →    iface = "<اسم واجهتك>"
# للـ VM: mode = "native"   →    mode = "skb"

# ── تهيئة قاعدة بيانات القواعد ───────────────────────────────
sqlite3 /var/lib/falx/policy.db < configs/default_policy_rules.sql

# ── تثبيت الـ binaries ────────────────────────────────────────
sudo install -m 755 bin/falxd     /usr/local/bin/falxd
sudo install -m 755 bin/falx-user /usr/local/bin/falx-user
sudo install -m 755 bin/falx-ai   /usr/local/bin/falx-ai
sudo install -m 755 bin/falx-soc  /usr/local/bin/falx-soc

# ── تثبيت systemd services ────────────────────────────────────
sudo cp scripts/falxd.service    /etc/systemd/system/
sudo cp scripts/falx-soc.service /etc/systemd/system/
sudo cp scripts/falx-ai.service  /etc/systemd/system/
sudo systemctl daemon-reload

# ── تشغيل ─────────────────────────────────────────────────────
sudo systemctl enable --now falxd
sudo systemctl enable --now falx-soc
sudo systemctl enable --now falx-ai   # اختياري — يتطلب ONNX model

# ── مراقبة ────────────────────────────────────────────────────
sudo journalctl -fu falxd    # Control plane logs
sudo journalctl -fu falx-soc # SOC backend logs

# ── كلمة مرور admin الافتراضية ────────────────────────────────
sudo journalctl -u falx-soc | grep "DEFAULT ADMIN"
# DEFAULT ADMIN CREATED — username=admin temp_password=FLX-XXXXXXXX!
```

---

## النشر بـ Docker

> **XDP modes في Docker:**
> - `native`: يتطلب NIC فيزيائية مربوطة لـ hardware queue — لا يعمل داخل Docker بشكل كامل.
> - `skb`: يعمل داخل Docker via generic XDP. **استخدمه للاختبار والتطوير.**
> - للإنتاج على bare-metal: استخدم systemd services (الأسلوب أعلاه).

```bash
# ── 1. ضبط متغيرات البيئة ─────────────────────────────────────
export GRAFANA_PASS=$(openssl rand -base64 24)   # إلزامي — لا يوجد default
export FALX_IFACE=eth0                           # اسم واجهتك الشبكية
export FALX_XDP_MODE=skb                         # skb للـ Docker، native للـ bare-metal
export FALX_VERSION=$(git describe --tags --always 2>/dev/null || echo 0.1.0)
export FALX_BUILD_TIME=$(date -u +%Y%m%dT%H%M%SZ)

# ── 2. بناء وتشغيل الـ stack ──────────────────────────────────
docker compose up -d --build

# ── 3. مراقبة الـ logs ────────────────────────────────────────
docker compose logs -f falxd     # Control plane + XDP loader
docker compose logs -f falx-soc  # SOC backend + API
docker compose logs -f falx-ai   # AI inference engine

# ── 4. التحقق من الصحة ────────────────────────────────────────
docker compose ps
# NAME                  STATUS            PORTS
# falx-control-plane    healthy           (network_mode: host)
# falx-soc-backend      healthy           0.0.0.0:8080->8080/tcp
# falx-ai-engine        healthy           -
# falx-prometheus       running           0.0.0.0:9091->9090/tcp
# falx-grafana          running           0.0.0.0:3000->3000/tcp

# ── 5. الخدمات ────────────────────────────────────────────────
# SOC Dashboard: http://localhost:8080
# Prometheus:    http://localhost:9091
# Grafana:       http://localhost:3000   (user: admin / pass: $GRAFANA_PASS)

# ── بناء بنسخة محددة (للـ CI/CD) ─────────────────────────────
docker compose build \
  --build-arg VERSION=1.0.0 \
  --build-arg BUILD_TIME=$(date -u +%Y%m%dT%H%M%SZ) \
  falxd

# ── إيقاف الـ stack ───────────────────────────────────────────
docker compose down          # يحفظ الـ volumes
docker compose down -v       # يحذف الـ volumes (تحذير: حذف البيانات)
```

### متطلبات Docker الحرجة

| المتطلب | القيمة | السبب |
|---|---|---|
| `privileged: true` | required | BPF program loading + XDP attachment |
| `network_mode: host` | required | XDP يربط مباشرة لـ NIC من الـ host |
| `ulimits.memlock: -1` | required | AF_XDP UMEM يستدعي `mlock()` — يفشل بـ `EPERM` بدونه |
| `cap_add: NET_RAW` | required | XDP socket creation (kernel < 5.19) |
| `cap_add: BPF` | required | BPF syscall access |
| `cap_add: SYS_ADMIN` | required | BPF program loading |
| `/sys/fs/bpf:/sys/fs/bpf` | required | BPF map pinning |

---

## الاستخدام

### Dashboard

```
افتح: http://localhost:8080

الدخول الأول:
  Username: admin
  Password: (راجع: journalctl -u falx-soc | grep "DEFAULT ADMIN")

يُنصح بتغيير كلمة المرور فوراً عبر: الإعدادات → Change Password
```

### REST API

```bash
# ── المصادقة ──────────────────────────────────────────────────
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"YOUR_PASSWORD"}' \
    | jq -r .tokens.access_token)

# ── حظر IP (دائم) ──────────────────────────────────────────────
curl -s -X POST http://localhost:8080/api/v1/security/block \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"ip":"1.2.3.4","ttl_s":0,"reason":"known_attacker","threat_score":95}'

# ── حظر مؤقت (ساعة) ───────────────────────────────────────────
curl -s -X POST http://localhost:8080/api/v1/security/block \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"ip":"5.6.7.8","ttl_s":3600,"reason":"port_scan"}'

# ── إلغاء الحظر ───────────────────────────────────────────────
curl -s -X DELETE http://localhost:8080/api/v1/security/block/1.2.3.4 \
    -H "Authorization: Bearer $TOKEN"

# ── XDP stats ─────────────────────────────────────────────────
curl -s http://localhost:8080/api/v1/security/stats \
    -H "Authorization: Bearer $TOKEN" | jq .xdp

# ── حالة قاطع الدائرة ─────────────────────────────────────────
curl -s http://localhost:8080/api/v1/failsafe \
    -H "Authorization: Bearer $TOKEN" | jq

# ── فتح قاطع الدائرة يدوياً ───────────────────────────────────
curl -s -X POST http://localhost:8080/api/v1/failsafe/open \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"reason":"manual_test"}'

# ── إضافة قاعدة أمان ───────────────────────────────────────────
curl -s -X POST http://localhost:8080/api/v1/policy/rules \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name":       "block-critical-threat",
      "priority":   9000,
      "action":     "block",
      "conditions": [{"type":"threat_score","operator":"gte","value":"90"}],
      "enabled":    true
    }'

# ── Health Check ───────────────────────────────────────────────
curl -s http://localhost:8080/healthz | jq
# {"status":"ok","uptime":"5m23s","timestamp":"2024-..."}
```

---

## الأدوار والصلاحيات (RBAC)

| الدور | Block IP | Block Temp | Policies | Users | Failsafe | Audit |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Viewer** | ❌ | ❌ | عرض | ❌ | عرض | ❌ |
| **Analyst** | ❌ | ✅ (24h) | عرض | ❌ | عرض | ❌ |
| **Senior Analyst** | ✅ | ✅ | إدارة | ❌ | تحكم | ✅ |
| **Admin** | ✅ | ✅ | إدارة | ✅ | تحكم | ✅ |
| **Super Admin** | ✅ | ✅ | إدارة | ✅ + تعيين أدوار | كامل | ✅ |

---

## الاختبار

```bash
# اختبارات الوحدة (Go)
bash scripts/run_tests.sh

# مع race detector (إلزامي قبل الإنتاج)
bash scripts/run_tests.sh --race

# Benchmarks
bash scripts/run_tests.sh --bench

# فحص الأمان الشامل
sudo bash scripts/security_audit.sh

# ABI verification: تحقق أن Rust structs ↔ Go structs متطابقة حجماً
bash scripts/verify_abi.sh

# Load test (يتطلب falxd يعمل)
go test ./tests/ -run TestLoad -v -timeout 60s

# Chaos test (يتطلب صلاحيات root)
sudo go test ./tests/ -run TestChaos -v -timeout 120s
```

---

## الأداء

```
XDP Throughput:      > 10 Gbps  (native mode, Intel i40e)
Decision Latency:    < 1 µs     (XDP_DROP path)
Blocklist Lookup:    O(1)       (BPF LRU Hash Map)
Policy Evaluation:   > 1,000,000 rules/sec (50 rules, no alloc)
Event Bus:           > 500,000  pub/sec
JWT Validation:      > 10,000   req/sec (RS256 cached)
AI Inference:        ~200 µs    (heuristic, no ONNX model)
Memory:              ~80 MB     (all subsystems running)
```

---

## الأمان

| الآلية | التفاصيل |
|---|---|
| **Argon2id** | كلمات المرور — 64 MiB، 3 iterations، salt عشوائي |
| **JWT RS256** | 4096-bit RSA asymmetric signing — الـ private key يبقى في auth service فقط |
| **TOTP 2FA** | RFC 6238 مع replay prevention (30s window) |
| **Refresh token rotation** | كل استخدام يُبطل التوكن القديم ويُصدر جديداً |
| **Account lockout** | بعد 5 محاولات فاشلة — يتطلب admin لإلغاء القفل |
| **SO_PEERCRED** | التحقق من هوية AI engine قبل قبول أوامر الحجب |
| **Seccomp profile** | يقيّد syscalls لـ falxd للحد الأدنى المطلوب |
| **Rate limiting** | حماية BPF maps من الـ flood (10,000 ops/sec per type) |
| **Audit trail** | كل عملية حساسة مسجّلة في `/var/log/falx/audit.jsonl` |
| **RBAC** | 5 أدوار، 25+ صلاحية، تحقق في كل API request |

راجع [SECURITY.md](SECURITY.md) للتفاصيل الكاملة ونموذج التهديد.

---

## استكشاف الأخطاء

### falxd لا يبدأ

```bash
sudo journalctl -u falxd -n 50 --no-pager

# الأخطاء الشائعة وحلولها:
```

| الخطأ | السبب | الحل |
|---|---|---|
| `Failed to load BPF object` | kernel < 5.15 أو CAP_BPF مفقود | `uname -r` — تحقق ≥ 5.15 |
| `interface not found` | اسم الواجهة في falx.toml خاطئ | `ip link show` ثم صحّح `iface` |
| `BPF filesystem not mounted` | `/sys/fs/bpf` غير موجود | `sudo mount -t bpf bpffs /sys/fs/bpf` |
| `cannot open pinned map` | ebpf-user لم يُشغَّل بعد | تأكد من تسلسل: `falx-user` قبل `falxd` |
| `permission denied` on UMEM | `RLIMIT_MEMLOCK` محدود | `ulimit -l unlimited` أو أضف systemd `LimitMEMLOCK=infinity` |

### XDP native mode فاشل

```bash
# تحقق من دعم الـ driver
ethtool -i eth0 | grep driver
# i40e, mlx5_core, ixgbe, bnxt_en  → native ✅
# virtio_net, e1000, vmxnet3        → يحتاج skb mode ⚠️

# التبديل لـ skb mode
sudo sed -i 's/mode = "native"/mode = "skb"/' /etc/falx/falx.toml
sudo systemctl restart falxd
```

### AF_XDP UMEM فاشل في Docker

```bash
# العرض في الـ logs:
# "mlock: operation not permitted" أو "EPERM"

# الحل: تأكد من وجود هذا في docker-compose.yml
# ulimits:
#   memlock:
#     soft: -1
#     hard: -1

# أو شغّل يدوياً:
docker run --ulimit memlock=-1:-1 ...
```

### SOC Backend لا يتصل بـ falxd

```bash
# تحقق من Unix socket
ls -la /var/run/falx/
# يجب أن يظهر: ipc.sock, ai.sock

# تحقق من الصلاحيات
sudo journalctl -u falx-soc | grep "connection refused"
# إذا ظهر → تأكد أن falxd يعمل أولاً
```

### مشكلة صلاحيات BPF

```bash
# إضافة capabilities بدون تشغيل كـ root
sudo setcap cap_bpf,cap_net_admin,cap_net_raw,cap_sys_admin+ep /usr/local/bin/falxd

# تحقق
getcap /usr/local/bin/falxd
```

### التحقق من BPF maps مباشرة

```bash
# عرض الـ maps المحمّلة
sudo bpftool map show | grep falx

# البحث عن IP في blocklist
sudo bpftool map lookup \
    pinned /sys/fs/bpf/falx/blocklist_v4 \
    key hex $(printf '%02x %02x %02x %02x' 1 2 3 4)   # 1.2.3.4

# عرض Failsafe state
sudo bpftool map dump pinned /sys/fs/bpf/falx/failsafe_state

# عرض XDP stats
sudo bpftool map dump pinned /sys/fs/bpf/falx/xdp_stats
```

---

## النشر على Production

```bash
# ── النشر التلقائي (zero-downtime rolling update) ──────────────
sudo bash scripts/deploy.sh

# ── استرجاع إصدار سابق عند المشكلة ───────────────────────────
sudo bash scripts/deploy.sh --rollback

# ── إعداد TLS (Let's Encrypt) ─────────────────────────────────
sudo certbot certonly --standalone -d soc.yourdomain.com
sudo cp /etc/letsencrypt/live/soc.yourdomain.com/fullchain.pem /etc/falx/tls/server.crt
sudo cp /etc/letsencrypt/live/soc.yourdomain.com/privkey.pem   /etc/falx/tls/server.key
sudo chmod 600 /etc/falx/tls/server.key

# ── Nginx Reverse Proxy ────────────────────────────────────────
sudo cp configs/nginx.conf /etc/nginx/sites-available/falx
sudo sed -i 's/soc.falx.local/soc.yourdomain.com/' /etc/nginx/sites-available/falx
sudo ln -sf /etc/nginx/sites-available/falx /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### ONNX Model للـ AI engine (اختياري)

```bash
# ضع الـ model في:
sudo mkdir -p /opt/falx/models
sudo cp your_model.onnx /opt/falx/models/threat_classifier.onnx

# أو في Docker:
# falx-models volume يُماب على /opt/falx/models
docker cp your_model.onnx falx-ai-engine:/opt/falx/models/
docker restart falx-ai-engine
```

---

## إنشاء حزمة للتوزيع

```bash
# حزمة قياسية (بدون docs)
bash scripts/package.sh --version=1.0.0

# حزمة شاملة مع الوثائق
bash scripts/package.sh --version=1.0.0 --with-docs

# حزمة في مجلد مخصص
bash scripts/package.sh --version=1.0.0 --output=/tmp

# الناتج:
# FALX-V2-1.0.0-20240101-FT1.zip
# FALX-V2-1.0.0-20240101-MANIFEST.txt  (SHA256 + MD5 + file list)
```

---

## الوثائق

| الملف | الوصف |
|---|---|
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | دليل تشغيل Ubuntu المفصّل خطوة بخطوة |
| [SECURITY.md](SECURITY.md) | سياسة الأمان ونموذج التهديد الكامل |
| [CHANGELOG.md](CHANGELOG.md) | تاريخ الإصدارات وأرقام الأداء |
| [FINAL_REVIEW.md](FINAL_REVIEW.md) | مراجعة شاملة وسجل كل الإصلاحات |

---

## الترخيص

[MIT License](LICENSE) — Copyright (c) 2024 FT-1

---

<div align="center">

**FALX V2** — *"الكود الغبي السريع في النواة + الذكاء خارج النواة = الأمان الحقيقي"*

**Lead Architect & Owner: FT-1**

</div>
