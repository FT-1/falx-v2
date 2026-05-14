# FALX V2 — دليل التشغيل الكامل على Ubuntu
**Lead Architect & Owner: FT-1**

---

## متطلبات النظام

### الأجهزة
```
CPU:  x86-64 مع Intel VT-x أو AMD-V
RAM:  8 GB minimum (16 GB للإنتاج)
NIC:  بطاقة تدعم XDP native:
      ✅ Intel: i40e (X710), ixgbe (82599), igb (I350), i210
      ✅ Mellanox: mlx5_core (ConnectX-4+)
      ✅ Broadcom: bnxt_en
      ⚠️  غيرها: تعمل بـ --mode=skb (أبطأ)
DISK: 20 GB حرة
```

### النظام
```bash
# تحقق من إصدار الـ kernel (يجب >= 5.15)
uname -r
# مثال: 6.8.0-45-generic ✅

# Ubuntu 22.04 LTS أو 24.04 LTS موصى بهما
lsb_release -a
```

---

## الخطوة 1: تثبيت المتطلبات

```bash
# 1. نسخ المشروع
git clone https://github.com/ft-1/falx-v2.git
cd falx-v2

# 2. تشغيل سكربت الإعداد (يثبت كل شيء تلقائياً)
sudo bash scripts/setup.sh

# أو يدوياً:
# ─── System packages ───────────────────────────────
sudo apt-get update
sudo apt-get install -y \
    build-essential curl git pkg-config \
    llvm clang libelf-dev linux-headers-$(uname -r) \
    libbpf-dev bpftool sqlite3 libsqlite3-dev \
    cmake ninja-build protobuf-compiler \
    libprotobuf-dev libgrpc++-dev protobuf-compiler-grpc

# ─── Rust ──────────────────────────────────────────
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --default-toolchain nightly
source ~/.cargo/env

rustup target add bpfel-unknown-none
rustup component add rust-src --toolchain nightly
cargo install bpf-linker

# ─── Go ────────────────────────────────────────────
wget https://golang.org/dl/go1.22.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# ─── BPF Filesystem ────────────────────────────────
sudo mount -t bpf bpf /sys/fs/bpf
echo "bpf /sys/fs/bpf bpf defaults 0 0" | sudo tee -a /etc/fstab

# ─── Directories ───────────────────────────────────
sudo mkdir -p /etc/falx/{keys,tls,dashboard} \
              /var/log/falx \
              /var/lib/falx/{models} \
              /var/run/falx \
              /sys/fs/bpf/falx \
              /opt/falx/releases
```

---

## الخطوة 2: البناء (Build)

```bash
cd falx-v2

# تحقق من المتطلبات
make check-deps

# بناء كامل (eBPF + Control Plane + SOC + AI)
make all

# أو بناء سريع (بدون AI engine)
make dev

# التحقق من نجاح البناء
ls -la dist/
# يجب أن ترى: falxd  falx-soc  falx-ai
```

### إذا فشل بناء eBPF:
```bash
# تأكد من nightly toolchain
rustup show
cargo +nightly build --target bpfel-unknown-none \
    -Z build-std=core 2>&1 | head -20

# إذا فشل bpf-linker:
cargo install bpf-linker --force
```

---

## الخطوة 3: الإعداد الأولي

```bash
# نسخ الإعدادات الافتراضية
sudo cp configs/falx.toml         /etc/falx/falx.toml
sudo cp configs/honeypot.toml     /etc/falx/honeypot.toml
sudo cp configs/notifications.toml /etc/falx/notifications.toml
sudo chmod 640 /etc/falx/*.toml

# ضبط اسم الواجهة الشبكية
ip link show  # لمعرفة اسم واجهتك (eth0, ens3, enp3s0, إلخ)

sudo nano /etc/falx/falx.toml
# غيّر السطر التالي:
#   iface = "eth0"   →   iface = "enp3s0"  (اسم واجهتك)

# إعداد قاعدة بيانات القواعد الافتراضية
sqlite3 /var/lib/falx/policy.db < configs/default_policy_rules.sql

# تثبيت Dashboard
sudo mkdir -p /etc/falx/dashboard
sudo cp soc-backend/dashboard/index.html /etc/falx/dashboard/

# تثبيت systemd services
sudo cp scripts/falxd.service    /etc/systemd/system/
sudo cp scripts/falx-soc.service /etc/systemd/system/
sudo cp scripts/falx-ai.service  /etc/systemd/system/
sudo systemctl daemon-reload

# تثبيت binaries
sudo install -m755 dist/falxd    /usr/local/bin/falxd
sudo install -m755 dist/falx-soc /usr/local/bin/falx-soc
sudo install -m755 dist/falx-ai  /usr/local/bin/falx-ai
```

---

## الخطوة 4: التشغيل

```bash
# ─── تشغيل falxd (eBPF loader + Control Plane) ───────────
sudo systemctl enable --now falxd
sudo systemctl status falxd

# تحقق من تحميل XDP
sudo bpftool prog show | grep falx_xdp
sudo bpftool map show  | grep falx

# ─── تشغيل SOC Backend ───────────────────────────────────
sudo systemctl enable --now falx-soc
sudo systemctl status falx-soc

# ─── تشغيل AI Engine (اختياري) ──────────────────────────
sudo systemctl enable --now falx-ai
sudo systemctl status falx-ai

# ─── مراقبة السجلات ──────────────────────────────────────
sudo journalctl -fu falxd    # Control plane logs
sudo journalctl -fu falx-soc # SOC backend logs
sudo journalctl -fu falx-ai  # AI engine logs
```

### الحصول على كلمة مرور admin الافتراضية:
```bash
sudo journalctl -u falx-soc | grep "DEFAULT ADMIN"
# ستظهر:
# DEFAULT ADMIN CREATED — username=admin temp_password=FLX-XXXXXXXX!
```

---

## الخطوة 5: التحقق والاختبار

### اختبار أساسي:
```bash
# ─── Health Check ─────────────────────────────────────────
curl -s http://localhost:8080/healthz | jq
# {"status":"ok","uptime":"...","timestamp":"..."}

# ─── تسجيل الدخول ─────────────────────────────────────────
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"YOUR_TEMP_PASSWORD"}' \
    | jq -r .tokens.access_token)

echo "Token: ${TOKEN:0:20}..."

# ─── XDP Stats ───────────────────────────────────────────
curl -s http://localhost:8080/api/v1/security/stats \
    -H "Authorization: Bearer $TOKEN" | jq .xdp

# ─── Failsafe Status ─────────────────────────────────────
curl -s http://localhost:8080/api/v1/failsafe \
    -H "Authorization: Bearer $TOKEN" | jq

# ─── Policy Stats ────────────────────────────────────────
curl -s http://localhost:8080/api/v1/policy/stats \
    -H "Authorization: Bearer $TOKEN" | jq
```

### اختبار حظر IP:
```bash
# حظر IP تجريبي
curl -X POST http://localhost:8080/api/v1/security/block \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"ip":"192.168.99.1","ttl_s":60,"reason":"test_block","threat_score":90}'

# تحقق من الإضافة
sudo bpftool map lookup \
    pinned /sys/fs/bpf/falx/blocklist_v4 \
    key hex c0 a8 63 01  # 192.168.99.1

# إلغاء الحظر
curl -X DELETE http://localhost:8080/api/v1/security/block/192.168.99.1 \
    -H "Authorization: Bearer $TOKEN"
```

### اختبار قاطع الدائرة:
```bash
# ─── اختبار الفتح اليدوي ──────────────────────────────────
curl -X POST http://localhost:8080/api/v1/failsafe/open \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"reason":"circuit_test"}'

# تحقق من الحالة
curl -s http://localhost:8080/api/v1/failsafe \
    -H "Authorization: Bearer $TOKEN" | jq .circuit_open
# true

# تحقق من XDP map مباشرة
sudo bpftool map lookup pinned /sys/fs/bpf/falx/failsafe_state key 0

# إغلاق الدائرة
curl -X POST http://localhost:8080/api/v1/failsafe/close \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{}'

# ─── اختبار الفتح التلقائي (DDoS simulation) ──────────────
# لاختبار threshold تلقائياً على نظام حقيقي:
# hping3 -S --flood -p 80 <target_ip>  ← من جهاز آخر
# راقب: journalctl -fu falxd | grep "CIRCUIT BREAKER"
```

### اختبار Policy Engine:
```bash
# إضافة قاعدة
curl -X POST http://localhost:8080/api/v1/policy/rules \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "test-block-port-22",
        "priority": 5000,
        "action": "rate_limit",
        "conditions": [{"type":"dst_port","operator":"eq","value":"22"}],
        "enabled": true,
        "reason": "ssh_rate_limit"
    }'

# تحقق من القواعد
curl -s http://localhost:8080/api/v1/policy/rules \
    -H "Authorization: Bearer $TOKEN" | jq '.rules[] | .name'

# Hot-reload
curl -X POST http://localhost:8080/api/v1/policy/reload \
    -H "Authorization: Bearer $TOKEN"
```

### فتح Dashboard:
```bash
# افتح المتصفح
xdg-open http://localhost:8080
# أو
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):8080"
```

---

## الخطوة 6: اختبارات الأداء

```bash
# ─── تشغيل كل الاختبارات ──────────────────────────────────
cd falx-v2
bash scripts/run_tests.sh

# مع race detector
bash scripts/run_tests.sh --race

# مع Benchmarks (يأخذ وقتاً)
bash scripts/run_tests.sh --bench

# ─── فحص الأمان ───────────────────────────────────────────
sudo bash scripts/security_audit.sh

# ─── ABI Verification ─────────────────────────────────────
bash scripts/verify_abi.sh
```

---

## الخطوة 7: النشر بـ Docker

```bash
# ─── الطريقة السريعة ────────────────────────────────────────
export GRAFANA_PASS=$(openssl rand -base64 24)
export FALX_IFACE=eth0          # غيّرها لواجهتك الفعلية
export FALX_VERSION=$(git describe --tags --always 2>/dev/null || echo 0.1.0)
export FALX_BUILD_TIME=$(date -u +%Y%m%dT%H%M%SZ)

docker compose up -d --build

# ─── مراقبة الـ logs ──────────────────────────────────────────
docker compose logs -f falxd
docker compose logs -f falx-soc
docker compose logs -f falx-ai

# ─── التحقق من الصحة ─────────────────────────────────────────
docker compose ps
# يجب أن تكون كل الخدمات healthy

# ─── لبناء بنسخة محددة (CI/CD) ───────────────────────────────
docker compose build \
    --build-arg VERSION=1.0.0 \
    --build-arg BUILD_TIME=$(date -u +%Y%m%dT%H%M%SZ) \
    falxd

# ─── إيقاف الـ stack ──────────────────────────────────────────
docker compose down

# إيقاف مع حذف الـ volumes (تحذير: يحذف البيانات)
docker compose down -v

# ─── ملاحظات مهمة ─────────────────────────────────────────────
# 1. falxd يتطلب privileged: true + network_mode: host → XDP native لا يعمل في Docker
#    استخدم mode = "skb" في falx.toml عند التشغيل بـ Docker
# 2. GRAFANA_PASS يجب تعيينه — لا يوجد default (يفشل البناء عمداً)
# 3. الـ volumes محفوظة بين إعادات التشغيل (falx-data, falx-logs, falx-keys)
```

---

## الخطوة 8: الإنتاج (Physical Host)

```bash
# ─── تشغيل النشر الكامل ───────────────────────────────────
sudo bash scripts/deploy.sh

# ─── إعداد TLS (للإنتاج) ──────────────────────────────────
sudo mkdir -p /etc/falx/tls
# شهادة Let's Encrypt:
sudo certbot certonly --standalone -d soc.yourdomain.com
sudo cp /etc/letsencrypt/live/soc.yourdomain.com/fullchain.pem /etc/falx/tls/server.crt
sudo cp /etc/letsencrypt/live/soc.yourdomain.com/privkey.pem   /etc/falx/tls/server.key
sudo chmod 600 /etc/falx/tls/server.key

# ─── إعداد Nginx ──────────────────────────────────────────
sudo cp configs/nginx.conf /etc/nginx/sites-available/falx
sudo sed -i 's/soc.falx.local/soc.yourdomain.com/' /etc/nginx/sites-available/falx
sudo ln -s /etc/nginx/sites-available/falx /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# ─── استرجاع عند المشكلة ──────────────────────────────────
sudo bash scripts/deploy.sh --rollback
```

---

## استكشاف الأخطاء

### falxd لا يبدأ:
```bash
sudo journalctl -u falxd -n 50 --no-pager

# أخطاء شائعة:
# "Failed to load BPF object" → kernel قديم أو CAP_BPF مفقود
# "interface not found" → اسم الواجهة في falx.toml خاطئ
# "BPF filesystem not mounted" → mount /sys/fs/bpf أولاً
```

### XDP native mode فاشل:
```bash
# تحقق من دعم الـ driver
ethtool -i eth0 | grep driver
# i40e, mlx5_core, ixgbe → native ✅
# virtio_net, e1000 → يحتاج skb mode

# التبديل لـ skb mode
sudo nano /etc/falx/falx.toml
# mode = "skb"
sudo systemctl restart falxd
```

### مشكلة صلاحيات BPF:
```bash
# تحقق من capabilities
sudo getcap /usr/local/bin/falxd

# إضافة capabilities بدون root
sudo setcap cap_bpf,cap_net_admin,cap_net_raw,cap_sys_admin+ep /usr/local/bin/falxd
```
