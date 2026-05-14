# FALX V2 — Hybrid eBPF/XDP IPS

> **Project**: FALX V2  Lead Architect & Owner: **FT-1**
> **Status**: Production-grade  License: Proprietary
> **Target**: Ubuntu 22.04 LTS / 24.04 LTS  •  Linux kernel ≥ 5.15

A high-performance, defense-in-depth **Intrusion Prevention System** that
combines **kernel-side XDP** (line-rate packet drop) with a **user-space AI
inference engine** (deep verdicts) and a **multi-user SOC dashboard**
(RBAC + JWT + audit). Designed to survive volumetric DDoS via an
**autonomous failsafe circuit breaker** that bypasses the AI path under
flood, keeping the kernel datapath functional even when the control plane
is degraded.

---

## Table of Contents

1. [Highlights](#highlights)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [Installation on Ubuntu](#installation-on-ubuntu)
5. [Docker Deployment](#docker-deployment)
6. [Configuration](#configuration)
7. [REST & WebSocket API](#rest--websocket-api)
8. [Security Model](#security-model)
9. [Failsafe / Circuit Breaker](#failsafe--circuit-breaker)
10. [Observability](#observability)
11. [Troubleshooting](#troubleshooting)
12. [Known Limitations](#known-limitations)
13. [Project Structure](#project-structure)
14. [Build from Source](#build-from-source)

---

## Highlights

| Property | Value |
|---|---|
| **Datapath** | eBPF/XDP — line rate, &lt;1 µs avg packet decision @ 10 Gbps |
| **AI bypass** | Zero-copy AF_XDP → ONNX inference (C++20) |
| **Failsafe** | XDP autonomously opens circuit on PPS/BPS threshold breach |
| **RBAC** | 5 roles · 25+ fine-grained permissions · enforced in middleware |
| **Authentication** | RS256 JWT (15 min access · 7 day refresh) + TOTP 2FA |
| **Password hashing** | Argon2id (memory-hard) + constant-time compare |
| **Audit** | Every block / unblock / login / config change → JSONL log |
| **Observability** | Prometheus `/metrics` · structured zap logs · live WebSocket |
| **Map pinning** | All 9 BPF maps pinned to `/sys/fs/bpf/falx/` → control-plane survives daemon restart |

---

## Architecture

```
                ┌─────────────────────────────────────────────────────────────┐
                │                       SOC Dashboard                         │
                │              (React-style SPA  +  WebSocket)                │
                └────────────────────────────┬────────────────────────────────┘
                                             │  HTTPS / Bearer JWT
                                             ▼
                  ┌──────────────────────────────────────────────────┐
                  │              soc-backend (Go)                    │
                  │  REST API · RBAC · audit · event bus · gRPC       │
                  └────────────┬──────────────────────┬──────────────┘
                               │ pinned BPF maps     │ gRPC
                               ▼                      ▼
   ┌──────────────────────────────────────┐    ┌─────────────────────────┐
   │           falxd (Go control plane)   │    │  falx-ai (C++/ONNX)     │
   │                                       │    │  - feature extraction   │
   │  - Map manager + hardening            │    │  - deep verdicts        │
   │  - Failsafe engine (4 detectors)      │◄──►│  - threat scoring       │
   │  - Honeypot manager + rotation        │ ipc│                          │
   │  - AF_XDP bridge → AI                 │unix└─────────────────────────┘
   │  - Policy engine (hot reload)         │
   │  - Prometheus exporter                │
   └────────────┬──────────────────────────┘
                │ pins maps · loads program
                ▼
   ┌──────────────────────────────────────────────────────────────┐
   │           Linux kernel — XDP program (Rust / Aya)            │
   │  parse → stats → failsafe? → blocklist? → rate limit? → PASS │
   │  AUTONOMOUS circuit breaker (per-packet, lock-free)          │
   └──────────────────────────────────────────────────────────────┘
                              ▲
                              │
                           NIC (XDP-native or generic SKB)
```

### Critical safety property

The XDP program in the kernel maintains its **own** copy of the failsafe
counters (`current_pps`, `current_bps`). If the Go control plane
crashes, hangs, or is starved of CPU, the kernel program will still trip
the circuit breaker autonomously when PPS or BPS exceeds the configured
thresholds — **defense in depth across two layers**.

---

## Quick Start

```bash
# 1. Clone + build
git clone https://example.com/falx-v2.git && cd falx-v2

# 2. Install all deps + build (Ubuntu 22.04/24.04, requires sudo)
sudo bash scripts/setup.sh

# 3. Start the daemon
sudo systemctl enable --now falxd

# 4. Open the SOC dashboard
xdg-open http://localhost:8080
```

Default admin credentials are printed once on first start. Change them
immediately via the dashboard.

---

## Installation on Ubuntu

Tested on Ubuntu 22.04 LTS (kernel 5.15+) and 24.04 LTS / Noble
(kernel 6.8+). The setup script is idempotent.

### Step 1 — System packages

```bash
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    build-essential curl wget git pkg-config \
    llvm clang libelf-dev libbpf-dev \
    linux-headers-$(uname -r) linux-tools-common linux-tools-$(uname -r) \
    sqlite3 libsqlite3-dev \
    cmake ninja-build \
    protobuf-compiler libprotobuf-dev libgrpc++-dev protobuf-compiler-grpc \
    ca-certificates make jq
```

> On Ubuntu 24.04 **Noble**, `bpftool` is a virtual package — install
> `linux-tools-$(uname -r)` instead. The setup script handles this
> automatically.

### Step 2 — Mount BPF filesystem

```bash
sudo mount -t bpf bpf /sys/fs/bpf
# Persist across reboots:
echo "bpf /sys/fs/bpf bpf defaults 0 0" | sudo tee -a /etc/fstab
```

### Step 3 — Go 1.22

```bash
curl -L https://go.dev/dl/go1.22.5.linux-amd64.tar.gz -o /tmp/go.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/golang.sh
source /etc/profile.d/golang.sh
go version          # → go1.22.x
```

### Step 4 — Rust nightly + BPF tooling

```bash
# Install rustup with nightly as default
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --default-toolchain nightly
source "$HOME/.cargo/env"

# Add rust-src so cargo can build core from source (-Z build-std)
rustup component add rust-src --toolchain nightly

# bpfel-unknown-none is a Tier-3 target — DO NOT use `rustup target add`.
# The Makefile already uses `-Z build-std=core`, which builds core from
# source for the BPF target without requiring a prebuilt artifact.

cargo install bpf-linker
```

### Step 5 — Build everything

```bash
cd ~/FALX-V2          # or wherever you cloned the repo
make all              # ≈ 5–10 minutes the first time

# Outputs:
ls -la dist/          # falxd  falx-soc  falx-ai
ls -la build/ebpf/    # falx.bpf.o (the XDP program object)
```

### Step 6 — Install and run as a system service

```bash
sudo make install                       # → /usr/local/bin + /etc/falx/
sudo nano /etc/falx/falx.toml           # set [general].iface = "eth0" (or your NIC)
sudo systemctl enable --now falxd
sudo journalctl -fu falxd               # tail logs
```

**Verify** the XDP program is attached:

```bash
sudo bpftool prog show     # look for "falx_xdp" of type xdp
sudo bpftool map list      # 9 pinned maps under /sys/fs/bpf/falx
```

---

## Docker Deployment

### Prerequisites

- Docker 24+ with Compose v2 plugin
- Linux host with kernel 5.15+ and BPF filesystem mounted on the host
- For native XDP: a real NIC (not a Docker bridge). Use `FALX_XDP_MODE=skb`
  inside a containerised test environment.

### One-command stack

```bash
export GRAFANA_PASS='a-strong-password'    # mandatory — no insecure default
export FALX_IFACE=eth0                     # NIC to attach to
export FALX_XDP_MODE=skb                   # use "native" only on bare metal

docker compose up -d --build
```

What you get:

| Service | URL | Notes |
|---|---|---|
| `falxd` | host network | XDP attached to `$FALX_IFACE` |
| `falx-soc` | http://localhost:8080 | SOC dashboard + REST API |
| `falx-ai` | unix socket | AI inference engine |
| Prometheus | http://localhost:9091 | metrics (port-shifted to avoid conflict) |
| Grafana | http://localhost:3000 | dashboards (admin / $GRAFANA_PASS) |

### Why falxd needs `privileged: true` and `network_mode: host`

XDP must attach to the **host's** network device queue. A Docker bridge
network creates a virtual veth pair — XDP cannot attach there at native
speed. AF_XDP additionally requires:

- `ulimits.memlock: -1`  → UMEM `mlock()` calls fail with EPERM otherwise
- `CAP_NET_RAW`  → AF_XDP socket creation (older kernels)
- `CAP_BPF` + `CAP_SYS_ADMIN` + `CAP_NET_ADMIN`  → program load + map ops
- `/sys/fs/bpf` mounted into the container so pinned maps survive

### Stopping and cleanup

```bash
docker compose down                # stop containers
docker compose down -v             # also delete volumes (DB, logs, keys)
```

---

## Configuration

Primary config: `/etc/falx/falx.toml`. Live-reload via:

```bash
sudo kill -SIGHUP $(pidof falxd)   # rereads only thresholds (failsafe)
```

Other config:
- `/etc/falx/honeypot.toml`  → honeypot pool definitions
- `/etc/falx/notifications.toml`  → SOC notification channels (Slack / email / webhook)

### Key knobs

```toml
[general]
iface     = "eth0"          # NIC to attach XDP
pin_path  = "/sys/fs/bpf/falx"

[xdp]
mode      = "native"        # native | skb | offload

[failsafe]
pps_threshold = 1_000_000   # autonomous trip if exceeded for N consecutive ticks
bps_threshold = 8_000_000_000
cooldown_secs = 30          # base cooldown; exponential up to MaxCooldown

[afxdp]
queue_id   = 0
umem_size  = 4096           # frames
frame_size = 2048           # bytes (page-aligned)

[metrics]
prometheus_addr = "0.0.0.0:9090"
```

---

## REST & WebSocket API

All endpoints are under `/api/v1/`. Authentication: `Authorization: Bearer <JWT>`.

| Method | Path | Permission | Description |
|---|---|---|---|
| POST | `/auth/login` | public | Login → returns access + refresh token |
| POST | `/auth/refresh` | public | Rotate refresh token (single use) |
| POST | `/auth/logout` | authed | Revoke current session |
| GET | `/auth/roles` | authed | List role definitions |
| GET | `/users` | `user:list` | List users (admin+) |
| POST | `/users` | `user:create` | Create user (admin+) |
| PUT | `/users/{id}/lock` | `user:create` | Lock account |
| PUT | `/users/{id}/unlock` | `user:create` | Unlock account |
| GET | `/audit` | `audit:read` | Audit trail |
| GET | `/security/blocklist` | `telemetry:read` | List blocked IPs |
| POST | `/security/block` | `ip:block_temp` | Block an IP (TTL ≤ 24h for analyst) |
| DELETE | `/security/block/{ip}` | `ip:block` | Unblock |
| POST | `/security/redirect` | `ip:block` | Redirect to honeypot |
| GET | `/security/stats` | `telemetry:read` | XDP stats (aggregated) |
| GET | `/failsafe` | `failsafe:view` | Current circuit state |
| POST | `/failsafe/open` | `failsafe:control` | **Emergency**: force circuit OPEN |
| POST | `/failsafe/close` | `failsafe:control` | Force circuit CLOSED |
| PUT | `/failsafe/thresholds` | `failsafe:control` | Update PPS/BPS thresholds |
| GET | `/policy/rules` | `policy:read` | List rules |
| POST | `/policy/rules` | `policy:create` | Create rule |
| POST | `/policy/reload` | `policy:create` | Hot-reload from disk |
| GET | `/system/health` | `system:health` | Subsystem health |
| GET | `/system/metrics-summary` | `user:list` | XDP + Failsafe summary |
| WS | `/ws` | authed | Live event stream (alerts, transitions) |

Unauthenticated: `/healthz`, `/readyz`, `/metrics`.

---

## Security Model

### Authentication
- **RS256 JWT** signed with 4096-bit RSA. Private key kept on disk
  `0600 falx:falx`; public key may be shared with external services.
- **Refresh token rotation**: every refresh issues a new opaque token and
  revokes the prior session in a single atomic operation (SEC-FIX-004 —
  OWASP A07:2021 mitigated).
- **TOTP 2FA**: optional per-user, RFC 6238.

### Authorization
- **RBAC** with 5 roles: `super_admin` > `admin` > `senior_analyst` > `analyst` > `viewer`.
- Permission checks happen in middleware **before** the handler.
- `analyst` can only block with `ttl ≤ 24h` (`ip:block_temp` permission).

### Session safety
- **Inactivity timeout** (25 min) enforced server-side — JWT expiry alone is
  not sufficient because revocation needs to be immediate.
- **Login rate limit** 10 attempts/min per IP, with sliding TTL eviction
  to prevent unbounded memory growth.
- **Account lockout** after 5 failed attempts.

### Audit
- Every state-changing operation (block, unblock, login, password change,
  policy mutation, circuit override) writes a JSONL entry to
  `/var/log/falx/audit.jsonl` with actor, IP, user agent, success flag,
  and reason.

### IPC hardening
- Unix socket at `/var/run/falx/ai.sock` (mode `0600`).
- **SO_PEERCRED** verification of every connection (UID allow-list).
- **Symlink-safe** stale-socket cleanup — refuses to bind if the path is
  a symlink or non-socket file (I2 mitigation).
- **CIDR deny-list** on map updates from AI peer — refuses to block
  loopback, link-local, multicast, broadcast (I4 mitigation).
- **CRC32-framed protocol** with per-connection sequence numbers; bounded
  message size (1 MiB).

### Container security
- Non-root users per service: `falx:1000`, `falxsoc:1001`, `falxai:1002`.
- Read-only root filesystems where possible; minimal capability sets.
- Multi-stage builds — final image carries only runtime libs.

---

## Failsafe / Circuit Breaker

A **three-state machine** running in the control plane, mirrored by an
autonomous detector inside the XDP program:

```
        ┌──────────┐  pps/bps > threshold     ┌────────┐
        │  CLOSED  │ ──── for N ticks ──────► │  OPEN  │
        │ (normal) │                          │(drops) │
        └──────────┘ ◄─── stable for K ticks  └────┬───┘
              ▲                                    │ cooldown
              │                                    ▼
              │                            ┌────────────┐
              └────────────────────────────│ HALF_OPEN  │
                  no detector fires        │  (probe)   │
                                           └────────────┘
```

Key correctness properties (after audit fixes F1–F14):

| # | Fix | Effect |
|---|---|---|
| F1 | Dedicated `overrideThresholdUpdate` kind | Threshold update no longer causes a spurious circuit close |
| F2 | Non-blocking override channel sends | `ForceOpen`/`ForceClose` return `ErrEngineBusy` instead of blocking when engine is stalled |
| F3 | `events.Bus` publish on every transition | SOC dashboards receive `CircuitOpen`/`CircuitClosed` events |
| F6 | Encapsulated `ResetTripCount()` | Engine no longer reaches into private CB fields |
| F8 | Capped exponential backoff multiplier | `Duration` overflow at trips≈40 eliminated |
| F9 | `ResetViolation` → set to 0 (not decrement) | Hysteresis now actually trips during sustained moderate floods |
| F10 | `bpfWriteFailures` atomic counter | Kernel/CP divergence becomes visible to operators |
| F14 | `defer recover` around tick + override | A detector panic no longer kills the entire failsafe goroutine |

Manual override (SOC operator):

```bash
curl -X POST -H "Authorization: Bearer $JWT" \
     -d '{"reason":"investigating-flood"}' \
     https://localhost:8080/api/v1/failsafe/open
```

---

## Observability

### Prometheus metrics

```
falx_xdp_rx_packets_total         counter   total packets received
falx_xdp_dropped_total            counter   total drops (blocklist + ratelimit + failsafe)
falx_xdp_passed_total             counter   passed to network stack
falx_xdp_redirected_total         counter   redirected to honeypot
falx_failsafe_circuit_open        gauge     1 if open, 0 if closed
falx_failsafe_trip_count          counter   cumulative trips
falx_failsafe_bpf_write_failures  counter   kernel/CP divergence indicator (should be 0)
falx_rate_limit_drops_total       counter   token-bucket drops
falx_blocklist_v4_size            gauge     current blocked IPs
falx_afxdp_meta_chan_len          gauge     CP→AI queue fill
```

### Logs

`falxd` writes structured JSON via zap to stdout. `journalctl -fu falxd`
or pipe to Loki/ELK for aggregation.

`audit.jsonl` is a strict append-only line-delimited JSON file —
trivially fed to a SIEM.

### Health endpoints (no auth)

- `GET /healthz` → liveness (returns `{status:"ok", uptime, version}`)
- `GET /readyz`  → readiness (returns subsystem health; 503 if BPF maps unreachable)

---

## Troubleshooting

### Build issues

| Symptom | Cause | Fix |
|---|---|---|
| `error: toolchain 'nightly' has no prebuilt artifacts available for target 'bpfel-unknown-none'` | Tier-3 target — `rustup target add` cannot install it | Don't add the target; build uses `-Z build-std=core`. Ensure `rust-src` is installed: `rustup component add rust-src --toolchain nightly` |
| `error[E0152]: duplicate lang item in crate core: sized` | Stale `target/` from a different toolchain | `cd ebpf-user && cargo clean && cargo build --release` |
| `Package 'bpftool' has no installation candidate` (Ubuntu 24.04) | Virtual package | `apt install linux-tools-common linux-tools-$(uname -r)` |
| `CMake Error … Findnlohmann_json.cmake` | System lib lacks CMake config | The build automatically falls back to FetchContent — make sure CMake ≥ 3.20 |

### Runtime issues

| Symptom | Cause | Fix |
|---|---|---|
| `Failed to attach XDP to 'eth0'. Try --mode skb if native is unsupported.` | NIC driver lacks native XDP | Set `[xdp].mode = "skb"` in `falx.toml` |
| `UMEM registration failed: EPERM` | `memlock` ulimit too low | `systemctl edit falxd` add `LimitMEMLOCK=infinity`, restart |
| `BPF verifier rejected the program` | Kernel < 5.15 or program too complex | Upgrade kernel: `apt install linux-image-generic-hwe-22.04` |
| `bpfel-unknown-none has no prebuilt artifacts` | Used `rustup target add` on Tier-3 target | Skip that command — `-Z build-std=core` covers it |
| `Circuit breaker stays open forever` | `bpfWriteFailures` counter > 0 | Check `/metrics`; investigate divergence; manually close via `POST /failsafe/close` |

### Diagnostic commands

```bash
# XDP program attached?
sudo bpftool prog show

# Maps pinned correctly?
ls -la /sys/fs/bpf/falx/

# Live BPF map stats
sudo bpftool map dump pinned /sys/fs/bpf/falx/xdp_stats

# Tail the daemon
sudo journalctl -fu falxd

# Pull a debug dump (SIGUSR1)
sudo kill -SIGUSR1 $(pidof falxd)
```

---

## Known Limitations

These items are tracked from the production audit (Phases 1–11). Each has
a `// AUDIT-FX-NN` marker in the source where applicable.

### High-impact (will be addressed in Phase 12)

- **AF_XDP frame lifecycle (AFX-5)**: under sustained burst, the bridge
  may push the same frame to FILL ring while a `PacketMeta.UMEMOffset`
  reference is still live. Mitigation today: AI engine copies
  `PayloadSample` and does not dereference `UMEMOffset`.
- **AF_XDP memory barriers (AFX-4)**: producer/consumer ring updates use
  Go atomics, which provide sequential consistency to other Go code but
  do not emit hardware `smp_wmb` for the kernel. Works on x86 (strong
  ordering) but may drop frames on ARM64.
- **IPC message integrity (IPC-12)**: protocol uses CRC32 (not HMAC) for
  framing. A peer that passes UID check can still inject crafted frames.
  Acceptable today because IPC is `0600 falx:falx` — only the falx user
  can speak it.

### Medium-impact (operational)

- **Threshold persistence (FS-15)**: operator-changed failsafe thresholds
  are pushed to the BPF map but not persisted to disk. Daemon restart
  reloads defaults from `falx.toml`. Workaround: edit the toml and SIGHUP.
- **HALF-OPEN probe (FS-11)**: while the circuit is in HALF-OPEN, the
  kernel still drops packets, so the "probe" measures zero traffic and
  always concludes the flood has cleared. Under a continuing flood, the
  circuit will close briefly (~1 tick) and immediately re-trip; visible
  as flapping in the `trip_count` metric.

### Low-impact (defensive)

- Bias-free random char mapping in refresh-token encoder relies on
  `256 % 64 == 0` (mathematically OK, but brittle to alphabet changes).
- TTL semantics: kernel reads `expire_at` as Unix seconds; if the kernel
  reads `bpf_ktime_get_ns()/1e9` (monotonic since boot), values differ by
  uptime. Current code uses absolute timestamps from the control plane,
  which matches the documented contract.

---

## Project Structure

```
falx-v2/
├── ebpf-kern/                # Rust eBPF kernel program (no_std, Aya)
│   └── src/
│       ├── main.rs           # XDP entry → process_packet pipeline
│       ├── types.rs          # ABI-stable structs (mirrored 3-way)
│       ├── maps.rs           # BPF map declarations
│       ├── parser.rs         # Bounds-checked packet parser
│       └── honeypot.rs       # Silent honeypot redirect
├── ebpf-user/                # Rust user-space loader (Aya)
│   └── src/
│       ├── loader.rs         # Load+pin 9 maps, attach XDP
│       └── main.rs           # falx-user CLI
├── control-plane/            # Go daemon (falxd)
│   ├── cmd/falxd/            # main + daemon orchestrator
│   ├── pkg/                  # Public API: auth, bpfmaps, events, notifications, policy
│   └── internal/             # Private: afxdp, failsafe, honeypot, ipc, metrics, subsys
├── soc-backend/              # Go SOC backend + dashboard
│   ├── cmd/                  # main
│   └── internal/             # api handlers, server
├── ai-inference/             # C++20 AI engine (CMake)
│   └── src/                  # main, inference_engine, ipc_client
├── docker/                   # Dockerfile.{falxd,soc,ai} + prometheus.yml
├── scripts/                  # setup.sh, package.sh, falxd.service
├── tests/                    # Integration + chaos + load tests
├── configs/                  # falx.toml, honeypot.toml, notifications.toml
├── docker-compose.yml        # Full-stack deployment
├── Makefile                  # Build orchestrator
├── go.work                   # Multi-module workspace
└── rust-toolchain.toml       # Pinned to nightly + rust-src
```

---

## Build from Source

```bash
make help                  # list all targets
make all                   # full build (10 min cold)
make dev                   # eBPF + control plane only (fast iteration)
make test                  # all Go + Rust tests
make lint                  # clippy + golangci-lint + clang-tidy
make fmt                   # rustfmt + gofmt
make clean                 # nuke build artifacts
sudo make install          # install to /usr/local/bin + /etc/falx
sudo make uninstall        # remove all installed files
```

---

## License & Attribution

Proprietary — © FT-1. All rights reserved.

This project depends on:
- [Aya](https://aya-rs.dev/) — Rust eBPF library
- [cilium/ebpf](https://github.com/cilium/ebpf) — Go eBPF library
- [asavie/xdp](https://github.com/asavie/xdp) — Go AF_XDP socket
- [gorilla/mux](https://github.com/gorilla/mux) — HTTP routing
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) — JWT
- [ONNX Runtime](https://onnxruntime.ai/) — AI inference
- [Prometheus](https://prometheus.io/) — metrics

---

**FALX V2 — Architect & Owner: FT-1**
