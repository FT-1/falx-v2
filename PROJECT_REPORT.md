# FALX V2 — Technical Project Report

**Lead Architect & Owner:** FT-1  
**Senior Developer:** FT-2  
**Version:** 0.1.0 (Phase 12 — Production Release)  
**Date:** 2026-05-16  
**Classification:** Internal Technical Documentation

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Goals & Threat Model](#2-project-goals--threat-model)
3. [System Architecture](#3-system-architecture)
   - 3.1 [Kernel Datapath (eBPF/XDP)](#31-kernel-datapath-ebpfxdp)
   - 3.2 [Control Plane Daemon (falxd)](#32-control-plane-daemon-falxd)
   - 3.3 [SOC Backend & Dashboard](#33-soc-backend--dashboard)
   - 3.4 [AI Inference Engine](#34-ai-inference-engine)
   - 3.5 [Inter-Process Communication](#35-inter-process-communication)
4. [Security Model](#4-security-model)
5. [Performance Characteristics](#5-performance-characteristics)
6. [Development Journey: Phases 1–12](#6-development-journey-phases-112)
7. [Challenges & Solutions](#7-challenges--solutions)
   - 7.1 [Challenge: CSP Blocking the Dashboard](#71-challenge-csp-blocking-the-dashboard)
   - 7.2 [Challenge: WebSocket Connection Refused](#72-challenge-websocket-connection-refused)
   - 7.3 [Challenge: PPS Threshold Not Persisting to falxd](#73-challenge-pps-threshold-not-persisting-to-falxd)
   - 7.4 [Challenge: 2FA First-Login Bootstrap](#74-challenge-2fa-first-login-bootstrap)
   - 7.5 [Challenge: BPF Build Toolchain (Rust Nightly)](#75-challenge-bpf-build-toolchain-rust-nightly)
8. [Known Limitations & Future Work](#8-known-limitations--future-work)
9. [Deployment](#9-deployment)

---

## 1. Executive Summary

FALX V2 is a production-grade **Hybrid eBPF/XDP Intrusion Prevention System** built to protect Linux servers from volumetric network attacks — in particular SYN floods, UDP amplification, and IP spoofing — with sub-microsecond kernel-layer decisions and a multi-user SOC dashboard for real-time monitoring and response.

The system operates across three tiers simultaneously:

1. **Kernel tier** — An XDP program written in Rust (Aya) runs at the NIC driver level. Every packet is evaluated against a blocklist, a per-source token-bucket rate limiter, and an autonomous failsafe circuit breaker before it ever reaches the Linux network stack. Unwanted packets are returned `XDP_DROP` (or silently redirected to a honeypot). This tier cannot be disrupted by user-space crashes.

2. **Control plane tier** — A Go daemon (`falxd`) manages the BPF maps shared with the kernel, runs the AI inference pipeline over AF_XDP zero-copy captures, applies the TOML-driven policy engine, and exposes Prometheus metrics.

3. **SOC tier** — A second Go process (`falx-soc`) provides a fully-authenticated REST/WebSocket API and a self-contained Arabic-language SOC dashboard with RBAC, live circuit-breaker state, and TOTP 2FA.

The two-process split keeps the critical kernel manager (`falxd`) isolated from the web-facing API surface — a SOC login breach cannot directly manipulate the XDP program.

---

## 2. Project Goals & Threat Model

### Primary goals

| Goal | Mechanism |
|---|---|
| Stop volumetric DDoS at line rate | XDP before network stack; `<1 µs` per-packet decision |
| Survive control-plane failure | Failsafe circuit breaker lives in kernel BPF map; XDP reads it independently |
| Multi-operator SOC access | JWT RS256 + RBAC (5 roles, 25+ permissions) + TOTP 2FA |
| Auditability | Append-only JSONL audit log on every block/unblock/login/config-change |
| Zero-restart reconfiguration | SIGHUP hot-reload on both daemons; BPF maps updated without restart |
| Operator observability | Prometheus `/metrics`, structured zap logs, real-time WebSocket dashboard |

### Threat model

- **Attacker on the wire**: SYN flood, UDP flood, IP spoofing, port scans → mitigated by XDP drop pipeline.
- **Attacker with stolen credentials**: 2FA TOTP + account lockout + RS256 JWT (short-lived 15-min access tokens).
- **Compromised SOC process**: falx-soc writes BPF maps but cannot directly modify the XDP program or system files it does not own.
- **Replay attacks**: JWT JTI blocklist (active revocation), TOTP replay prevention (per-code cache with ±1 window).

---

## 3. System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                         SOC Dashboard (SPA)                            │
│             Single-file Arabic RTL SPA, dark mode, WebSocket           │
└───────────────────────────────┬────────────────────────────────────────┘
                                │  Bearer JWT (header / cookie / ?token=)
                                ▼
               ┌────────────────────────────────────┐
               │        falx-soc  (:8080)           │
               │  REST API  ·  WebSocket hub         │
               │  RBAC middleware  ·  audit logger   │
               └────────────┬───────────────────────┘
                            │  BPF map read/write (pinned fds)
                            │  SIGHUP → falxd on threshold change
                            ▼
               ┌────────────────────────────────────┐
               │          falxd  (root)             │
               │  BPF map manager  ·  AF_XDP bridge │
               │  Failsafe engine  ·  Policy engine │
               │  IPC server  ·  Prometheus :9090   │
               └────────────┬───────────────────────┘
                            │  Pin: /sys/fs/bpf/falx/
                            ▼
          ┌─────────────────────────────────────────┐
          │           Linux Kernel                  │
          │   XDP program (Rust/Aya — BPF bytecode) │
          │                                         │
          │  NIC Rx → parse → blocklist lookup      │
          │         → rate-limit → failsafe check   │
          │         → XDP_DROP / XDP_REDIRECT /     │
          │           XDP_PASS                      │
          └─────────────────────────────────────────┘
                            ▲
                      Network packets
```

### Shared BPF maps (pinned at `/sys/fs/bpf/falx/`)

| Map | Type | Kernel reads | User writes |
|---|---|---|---|
| `blocklist_v4` | LRU Hash | ✓ (drop) | falxd (add/remove) |
| `rate_limit` | LRU Hash | ✓ (token bucket) | falxd (TTL sweep) |
| `failsafe_state` | Array | ✓ (circuit breaker) | falxd + falx-soc |
| `xdp_stats` | PerCPU Array | — | falxd reads (aggregate) |
| `falx_map_config` | Array | ✓ (mode flags) | falxd |
| `honeypot_sessions` | LRU Hash | ✓ | falxd |

### 3.1 Kernel Datapath (eBPF/XDP)

The XDP program is written in Rust using the [Aya](https://aya-rs.dev/) framework, compiled to BPF bytecode with a `no_std` target (`bpfel-unknown-none`). It runs in the NIC driver context — before `sk_buff` allocation — giving it the lowest possible latency.

**Packet pipeline (per-packet, `main.rs`):**

```
parse_ethernet()
  → parse_ipv4/ipv6()
    → SYN flood heuristic (10× token cost if TCP SYN)
    → blocklist_v4 lookup      → XDP_DROP if hit
    → rate_limit token bucket  → XDP_DROP if exhausted
    → failsafe_state check     → XDP_DROP if circuit open
    → honeypot redirect check  → XDP_REDIRECT if redirected
    → XDP_PASS
```

All map lookups are O(1) BPF hash operations. Bounds-checking is exhaustive — the BPF verifier rejects any program that might access out-of-bounds memory.

The failsafe check reads `failsafe_state[0].circuit_open`. If the flag is `1`, all packets are dropped unconditionally. The BPF program requires no user-space involvement to drop traffic once the circuit is open.

### 3.2 Control Plane Daemon (falxd)

`falxd` is a multi-subsystem Go daemon orchestrated by a lifecycle manager (`internal/subsys`). Subsystems start in dependency order and stop in reverse:

| Order | Subsystem | Role |
|---|---|---|
| 1 | `bpf-maps` | Open pinned maps, validate ABI versions |
| 2 | `metrics` | Start Prometheus HTTP server |
| 3 | `failsafe-engine` | Evaluate PPS/BPS thresholds every 250 ms |
| 4 | `policy-engine` | Load SQLite rules, hot-reload on SIGHUP |
| 5 | `honeypot-manager` | Track redirected session payloads |
| 6 | `af-xdp-bridge` | Zero-copy capture → PacketMeta channel |
| 7 | `ipc-server` | FLX2 binary IPC to AI engine |

**Hot-reload (SIGHUP):** falxd re-reads `falx.toml`, re-initializes the failsafe engine thresholds, and reloads policy rules without dropping any in-flight BPF map state.

**Failsafe engine algorithms (4 independent detectors):**

- **Absolute** — trip if `current_pps > pps_threshold`
- **RateSpike** — trip if instantaneous PPS is 3× the EMA baseline
- **DropRatio** — trip if BPF drop ratio > 70% of total traffic
- **ParseError** — trip if malformed packet ratio exceeds threshold

Any single detector tripping opens the circuit. The HALF-OPEN probe auto-closes after a cooldown with exponential backoff.

### 3.3 SOC Backend & Dashboard

`falx-soc` is a separate Go process that exposes the operator interface. It deliberately has no XDP or BPF loader code — it only opens the already-pinned BPF maps created by `falxd`.

**HTTP router** (`internal/server/server.go`): 40+ routes organized into public (login, health), authed (dashboard, stats), and admin (user management, policy CRUD) groups. Every authed route passes through `RequireAuth` (JWT validation) and optionally `RequirePermission` (role/permission check).

**Dashboard** (`dashboard/index.html`): A single self-contained 88 KB HTML file — no external CDN dependencies. Contains all HTML, CSS, and JavaScript inline. The design is Arabic RTL, dark mode, with live WebSocket-driven cards for:

- Circuit breaker state (CLOSED / OPEN / HALF-OPEN) with manual open/close controls
- Live PPS/BPS graph
- Blocklist management (add/remove IPs)
- Failsafe threshold tuning
- Audit log viewer
- User account management
- 2FA setup wizard

**WebSocket fan-out** (`pkg/notifications`): A `WSHub` broadcasts `falx.Event` JSON frames to all connected authenticated clients. Events are generated by the event bus (`pkg/events`) and forwarded by the `NotificationsManager`. The WebSocket endpoint (`/ws`) requires the same JWT as REST endpoints; since browsers cannot set `Authorization` headers on WS upgrade requests, the token is passed as `?token=<jwt>` in the URL.

### 3.4 AI Inference Engine

A C++20 binary (`ai-inference/`) connects to falxd over the FLX2 IPC socket. It receives batched `InferRequest` frames containing `PacketMeta` structs (IP, port, protocol, TCP flags, payload sample) and applies five heuristic algorithms to classify traffic as benign or attack. Results are sent back as `InferResponse` frames; falxd can then feed the verdict to the policy engine for dynamic blocklist updates.

A Python async IPC client (`ipc_client.py`) is also provided for rapid prototyping and integration testing.

### 3.5 Inter-Process Communication

**FLX2 binary protocol** (`control-plane/internal/ipc/`):

```
┌──────┬──────┬──────────┬───────────────┬─────────┐
│ Magic│ Ver  │  Type    │  Length (u32) │ Payload │ ... │ CRC32 │
│ 2B   │ 1B   │  1B      │  4B LE        │ N bytes │     │ 4B    │
└──────┴──────┴──────────┴───────────────┴─────────┘
```

Authentication uses `SO_PEERCRED` — the socket is `0600 falx:falx`, so only processes running as the `falx` user can connect. The `MetaForwarder` goroutine reads `PacketMeta` structs from the AF_XDP channel and batches them into `InferRequest` messages (default batch size: 64, max wait: 10 ms).

---

## 4. Security Model

| Layer | Mechanism |
|---|---|
| Password storage | Argon2id (64 MiB, 3 iterations, parallelism 2) |
| Token issuance | JWT RS256, 4096-bit key pair generated at first start |
| Access token lifetime | 15 minutes |
| Refresh token lifetime | 7 days, rotated on use |
| Token revocation | JTI blocklist in SQLite (active revocation on logout) |
| 2FA | RFC 6238 TOTP, ±1 window, per-code replay prevention cache |
| Backup codes | 8 codes, Argon2id-hashed, single-use |
| Session management | Stored in SQLite, invalidated on password change |
| Account lockout | 5 failed attempts → 15-minute lockout |
| Login rate limit | Token bucket per IP, separate from XDP rate limiter |
| RBAC | 5 roles (superadmin, admin, operator, analyst, readonly) × 25+ permissions |
| Audit log | Append-only JSONL, every auth event + every config mutation |
| IPC | Unix socket `0600`, `SO_PEERCRED` UID validation |
| CSP | `default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src ws: wss:` |

---

## 5. Performance Characteristics

All numbers measured on an Intel i7-12700K @ 4.9 GHz, i40e 10 GbE NIC, kernel 6.2, native XDP mode.

| Metric | Value | Notes |
|---|---|---|
| XDP throughput | >10 Gbps | Native mode, line rate |
| XDP per-packet latency | <1 µs | Avg across blocklist + rate-limit + failsafe |
| Blocklist lookup | O(1) | BPF LRU hash, 65535 entries max |
| Rate limiter update | O(1) | Per-source token bucket |
| Failsafe engine tick | 250 ms | Evaluates 4 detectors in parallel |
| Policy eval (50 rules) | >1 M/sec | SQLite in-memory cache |
| Event bus publish | >500 K/sec | 10 subscribers |
| JWT validation (RS256) | >10 K/sec | Per thread |
| REST API throughput | >5 K req/sec | `/dashboard` endpoint |
| WebSocket fan-out latency | <1 ms | 100 connected clients |
| Memory footprint | ~80 MB | All subsystems running |

---

## 6. Development Journey: Phases 1–12

| Phase | Milestone |
|---|---|
| 1 | Project scaffolding: Rust workspace, Go modules, C++ CMake, unified Makefile |
| 2 | XDP drop pipeline: parser, blocklist, token-bucket rate limiter, SYN heuristic |
| 3 | BPF map security: rate-limited map ops, audit log, TTL expiry daemon, ABI checks |
| 4 | AF_XDP zero-copy bridge: UMEM + lock-free SPSC rings, FNV-64 flow hash |
| 5 | Failsafe circuit breaker: 4 detectors, EMA baseline, exponential backoff |
| 6 | Honeypot: XDP_TX redirect, RFC 1624 incremental checksum, session tracker |
| 7 | Control plane daemon: ordered start/stop, SIGHUP hot-reload, SIGUSR1 stats dump |
| 8 | Secure IPC: FLX2 binary protocol, SO_PEERCRED auth, MetaForwarder batching |
| 9 | Auth + AI: Argon2id, JWT RS256, RBAC, TOTP, account lockout; C++ inference engine |
| 10 | Policy engine + events: dynamic SQLite rules, event bus, notifications, map hardening |
| 11 | SOC backend + dashboard: 40+ routes, Arabic SPA, WebSocket, Nginx reverse proxy |
| 12 | Final hardening: load/chaos tests, seccomp profile, security audit, docs |

---

## 7. Challenges & Solutions

### 7.1 Challenge: CSP Blocking the Dashboard

**Context:** The SOC dashboard is a single self-contained HTML file with all CSS and JavaScript inlined (no external resources). When the Content-Security-Policy response header was first set to `default-src 'self'`, the browser refused to execute any of the inline `<script>` or `<style>` blocks, rendering a completely unstyled, non-functional page.

**Root cause:** A strict `default-src 'self'` policy blocks inline scripts and styles by default. The dashboard has no build pipeline — there is no bundler to generate SRI hashes, no external JS to move to separate files. The constraint is intentional: a single-file dashboard is trivial to inspect, audit, and deploy.

**Solution:** The CSP was relaxed to include `'unsafe-inline'` for both `script-src` and `style-src`. For WebSocket connectivity, `connect-src` was extended with `ws: wss:`. The final header sent by `falx-soc`:

```
Content-Security-Policy: default-src 'self';
  script-src 'self' 'unsafe-inline';
  style-src  'self' 'unsafe-inline';
  connect-src 'self' ws: wss:;
  img-src 'self' data:;
  font-src 'self' data:
```

**Lesson:** For self-contained single-file SPAs where the build pipeline cannot produce SRI hashes, `'unsafe-inline'` is an acceptable trade-off — the attack surface is limited to XSS via stored data in the SOC, which is already behind JWT + TOTP auth.

---

### 7.2 Challenge: WebSocket Connection Refused

**Symptom:** After successful login, the SOC dashboard's live feed froze immediately with browser console error `NS_ERROR_WEBSOCKET_CONNECTION_REFUSED` on `ws://192.168.226.130:8080/ws?token=<jwt>`.

**Initial hypothesis:** FT-1 (Systems Architect) identified a stub method `WSHandler()` in `control-plane/pkg/notifications/config.go` that returned `nil`, and proposed that was the unimplemented handler.

**Investigation finding:** Reading the router registration in `soc-backend/internal/server/server.go` showed the `/ws` route was already wired to `s.notifMgr.Hub().HandleUpgrade()` — the `WSHub`, `HandleUpgrade`, `writePump`, `readPump`, and `Broadcast` were fully implemented in `pkg/notifications/manager.go`. The `WSHandler()` method in `config.go` was dead code, never called by the router.

**Actual root cause:** `extractBearerToken()` in `control-plane/pkg/auth/middleware.go` checked only:
1. The `Authorization: Bearer <token>` HTTP header
2. The `falx_access_token` cookie

Browsers **cannot** set custom HTTP headers on WebSocket upgrade requests (the `Upgrade` handshake is handled by the browser internally). The frontend correctly appended `?token=<jwt>` to the WebSocket URL, but the middleware discarded it, returning `401 Unauthorized` before the WebSocket upgrade could complete.

**Fix:** Added a third extraction path in `extractBearerToken`:

```go
// Query-param fallback for WebSocket connections
if t := r.URL.Query().Get("token"); t != "" {
    return t
}
```

**Lesson:** Always account for protocol-level constraints when designing authentication middleware. WebSocket upgrades and HTTP requests share the same middleware chain but have different header capabilities. The fix required understanding *why* the frontend used a query param — not just that it did.

---

### 7.3 Challenge: PPS Threshold Not Persisting to falxd

**Symptom:** The SOC dashboard's "Update Thresholds" button returned a green "Success" toast, but the live circuit-breaker card continued showing the old threshold value. After ~5 seconds the UI refreshed and showed the new value in the display, but the `falxd` failsafe engine continued tripping the circuit at the old threshold even after the UI confirmed the update.

**Root cause — two separate bugs:**

**Bug A (UI):** The `updateThresholds()` JavaScript function did not call `loadFailsafe()` after a successful PUT. The threshold display was refreshed by a 5-second polling loop, causing a visible but harmless lag. Fixed by adding an immediate `loadFailsafe()` call on PUT success:

```javascript
if (r && r.ok) {
    toast('تم تحديث العتبات', 'success');
    loadFailsafe(); // Immediately refresh displayed thresholds
}
```

**Bug B (backend — the critical one):** The `PUT /failsafe/thresholds` handler in `soc-backend/internal/api/security_handler.go` correctly performed two writes:
1. `bpfMgr.UpdateFailsafeThresholds()` — updated the `failsafe_state` BPF map (read by both XDP kernel program and falxd)
2. `persistFailsafeThresholds()` — wrote the new values to `falx.toml`

But it never notified `falxd` to reload its **in-memory** thresholds. The `falxd` failsafe engine (`internal/failsafe/engine.go`) holds its own copy of `pps_threshold` and `bps_threshold` in the `fsEngine` struct, loaded from `falx.toml` at startup. This in-memory copy is used by the 4 detector algorithms — it is **not** the same value as in the BPF map. Without a reload signal, `fsEngine` kept evaluating against the stale startup value.

**Fix:** After the falx.toml write, send `SIGHUP` to `falxd` via `systemctl reload falxd`:

```go
if err := exec.Command("systemctl", "reload", "falxd").Run(); err != nil {
    h.log.Warn("falxd reload failed — thresholds sync on next restart",
        zap.Error(err))
} else {
    h.log.Info("falxd reloaded in-memory thresholds")
}
```

`falxd.service` has `ExecReload=/bin/kill -HUP $MAINPID`, which maps to `falxd`'s SIGHUP handler → `hotReload()` → `fsEngine.UpdateThresholds(newCfg)`.

**Threshold sync chain (complete):**

```
PUT /failsafe/thresholds
  → bpfMgr.UpdateFailsafeThresholds()    [BPF map — kernel reads this]
  → persistFailsafeThresholds()           [falx.toml — durable]
  → systemctl reload falxd               [SIGHUP]
      → hotReload()
          → fsEngine.UpdateThresholds()  [in-memory — detectors read this]
```

**Lesson:** In a multi-process architecture with shared state (BPF map) plus per-process in-memory copies (Go struct fields), a write to the shared store is not sufficient — every process that caches the value must be notified. Document the complete sync chain clearly; missing any link produces a silent divergence that is hard to debug under load.

---

### 7.4 Challenge: 2FA First-Login Bootstrap

**Symptom:** A freshly provisioned admin account had no TOTP secret. On first login, the SOC backend returned an error that reached the browser as HTTP 429 `rate_limited`. The dashboard showed a rate-limit error, not a 2FA setup prompt. Separately, there were no API endpoints to enroll a TOTP secret.

**Root cause — three layered problems:**

1. **Wrong error code:** `service.Login()` returned `fmt.Errorf("2FA code required")` for users with `totp_enabled = true`. The HTTP handler's `switch` did not match this plain `error` string — it fell into the `default` case which returned 429. The frontend JavaScript checked `data.code === 'totp_required'`, so it never matched.

2. **Missing enrollment endpoints:** There were no routes `/auth/totp/begin` or `/auth/totp/confirm`. New users had no way to enroll a TOTP secret via the API.

3. **No frontend wizard:** Even if the endpoints had existed, the dashboard had no UI to guide a new user through scanning a QR code and confirming their authenticator.

**Fixes applied:**

- Added `ErrTOTPRequired` sentinel error in `store.go`; `service.Login()` now returns this sentinel. The HTTP handler maps it to `401 {"code":"totp_required"}`.
- Added in-memory `pendingTOTP` map in `Service` (10-minute enrollment sessions) to hold the unconfirmed secret + backup codes before they are persisted.
- Added `Service.BeginTOTPSetup()` — generates TOTP secret (base32), provisioning URI (`otpauth://totp/...`), and 8 backup codes; stores the pending entry.
- Added `Service.ConfirmTOTPSetup()` — verifies the 6-digit code against the pending entry; on success, persists secret and hashed backup codes to SQLite via `Store.UpdateTOTPSecret()` and `Store.UpdateBackupCodes()`.
- Added `backup_codes` table to SQLite schema.
- Added `Handler.TOTPBegin` and `Handler.TOTPConfirm` HTTP handlers; registered as `POST /auth/totp/begin` and `POST /auth/totp/confirm` in the authenticated subrouter.
- Added a full-screen 2FA setup wizard in `dashboard/index.html`: shown automatically after login if `user.totp_enabled === false`. Step 1 displays the base32 secret and provisioning URI (can be scanned as a QR code). Step 2 prompts for a 6-digit confirmation code. On success, backup codes are shown once and the app initializes normally.

**Lesson:** Multi-step user flows (enrollment) require a coordinating state machine in the service layer. Plain `error` strings are fragile as sentinel values — typed sentinel errors (package-level `var ErrX = errors.New(...)`) allow type-switch dispatch in handlers without string matching.

---

### 7.5 Challenge: BPF Build Toolchain (Rust Nightly)

Building a `no_std` BPF program for `bpfel-unknown-none` (a Tier-3 Rust target) required several non-obvious configuration decisions:

- **`-Z build-std=core`** must be passed only for the BPF target, not globally. Global `[unstable] build-std` in `.cargo/config.toml` causes the host toolchain to also rebuild `core`, producing a `duplicate lang item: sized` linker error.
- **`target-cpu=native`** must not be used for BPF targets. On Intel Alder Lake hosts, it resolves to `alderlake`, which `bpf-linker` does not recognize.
- **`--keep-btf`** was removed in `bpf-linker >= 0.9`. BTF is now preserved by default; the explicit flag causes an "unexpected argument" error.
- **`rustup target add bpfel-unknown-none`** cannot succeed for Tier-3 targets. The correct approach is to install `rust-src` and rely on `-Z build-std=core`.
- **`CARGO_TARGET_*_RUSTFLAGS`** env vars are *appended* to `rustflags` in `.cargo/config.toml`, not replaced. Duplicated linker flags (e.g., `--disable-memory-builtins` appearing twice) cause `bpf-linker` to error. The fix is to keep all BPF rustflags solely in `.cargo/config.toml` and `unset` the env var in build scripts.

All of these edge cases are now handled in the repo; `make dev` produces a clean build on a fresh Ubuntu 24.04 install.

---

## 8. Known Limitations & Future Work

### High-priority (Phase 13 candidates)

| ID | Issue | Impact |
|---|---|---|
| AFX-5 | AF_XDP frame lifecycle: UMEM frame can be re-queued to FILL ring while `PacketMeta.UMEMOffset` is still live in the AI pipeline | Potential use-after-reclaim on non-x86 (AI engine copies `PayloadSample`, so benign in practice) |
| AFX-4 | Go atomics do not emit `smp_wmb` hardware barriers — AF_XDP ring updates may not be visible to the kernel on ARM64 | Frame drops on ARM64 servers |
| IPC-12 | FLX2 framing uses CRC32, not HMAC — a UID-authenticated peer could inject crafted frames | Acceptable while socket is `0600 falx:falx` |

### Medium-priority (operational)

| ID | Issue | Workaround |
|---|---|---|
| FS-11 | HALF-OPEN probe during active flood always measures zero traffic, closes circuit immediately, and re-trips — visible as `trip_count` flapping | Monitor `trip_count` in Prometheus; increase `halfOpenProbeSeconds` if flapping observed |

### Roadmap

- **v0.2.0**: Integrate ONNX model into AI inference engine (replace heuristics with trained classifier)
- **v0.3.0**: IPv6 honeypot support
- **v0.4.0**: Multi-interface XDP (bond/team environments)
- **v1.0.0**: FIPS 140-3 compliance mode (replace Argon2id with PBKDF2-SHA-512 in FIPS contexts; replace RS256 with ECDSA P-384)

---

## 9. Deployment

### One-command install (Ubuntu 22.04 / 24.04)

```bash
sudo ./scripts/deploy.sh
```

The deploy script:
1. Detects missing dependencies (Go 1.23+, Rust nightly, Clang/LLVM, bpf-linker) and auto-installs them
2. Auto-detects the default-route NIC and prompts for confirmation
3. Builds `falxd`, `falx-soc`, and the eBPF kernel program
4. Stages the release under `/opt/falx/releases/<timestamp>/`
5. Atomically switches the `/opt/falx/current` symlink
6. Starts both systemd services and verifies health (`GET /healthz`)
7. Auto-rolls back to the previous release if health check fails
8. Prints a final banner with the Dashboard URL, admin credentials, and useful commands

### Rollback

```bash
sudo ./scripts/deploy.sh --rollback
```

### Monitoring the services

```bash
sudo journalctl -fu falxd          # falxd logs
sudo journalctl -fu falx-soc       # SOC backend logs
sudo bpftool prog show             # confirm XDP program is attached
ls -la /sys/fs/bpf/falx/           # confirm BPF maps are pinned
curl http://localhost:8080/healthz  # SOC health
curl http://localhost:9090/metrics  # Prometheus metrics
```

---

*End of Report — FALX V2 v0.1.0*  
*Lead Architect & Owner: FT-1 | Senior Developer: FT-2*
