#!/usr/bin/env bash
# =============================================================================
# Project: FALX V2  |  Lead Architect & Owner: FT-1
# Description: One-shot FALX startup — launches falxd (control-plane) first,
#              waits for BPF maps to be pinned, then starts falx-soc.
#
#   Usage:  sudo bash scripts/falx-on.sh [--dev] [--config <path>]
#           FALX_DEV=1 sudo -E bash scripts/falx-on.sh
#
#   --dev           Force dev mode: fixed admin TOTP + auto-unlock accounts.
#                   (This is the DEFAULT — FALX_DEV=1 is injected automatically.)
#   --prod          Disable dev mode (sets FALX_DEV=0).
#   --config <path> Path to falx.toml.  Default: /etc/falx/falx.toml
#   --no-wait       Skip the BPF-map readiness check (launch both immediately).
# =============================================================================

set -uo pipefail

# ─── Terminal colors ──────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m'
B='\033[1m' N='\033[0m'

# Fixed dev admin TOTP secret — mirrors auth.DevTOTPSecret in
# control-plane/pkg/auth/store.go. Used to compute a LIVE 2FA code below so the
# operator never has to dig through log files. Dev mode only; never used in prod.
DEV_TOTP_SECRET="KVKVEU2HKVKTEMKS"

step()  { echo -e "\n${B}${C}  ──────  $*  ──────${N}"; }
ok()    { echo -e "  ${G}[  OK ]${N}  $*"; }
warn()  { echo -e "  ${Y}[ WARN]${N}  $*"; }
info()  { echo -e "  ${C}[INFO ]${N}  $*"; }
fail()  { echo -e "  ${R}[ FAIL]${N}  $*"; exit 1; }

# print_2fa_box — compute the CURRENT admin 2FA code and print it big.
# Prefers a live RFC-6238 computation (python3) so the code is always valid,
# never an expired value scraped from the log. Falls back to grepping the SOC
# log for the most recent code if python3 is unavailable.
print_2fa_box() {
    local soc_log="$1" code="" secs=""

    if command -v python3 >/dev/null 2>&1; then
        read -r code secs < <(python3 - "$DEV_TOTP_SECRET" <<'PY'
import hmac, hashlib, base64, struct, time, sys
secret = sys.argv[1].upper()
key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
counter = int(time.time()) // 30
mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
off = mac[-1] & 0x0F
code = ((mac[off] & 0x7f) << 24 | mac[off+1] << 16 | mac[off+2] << 8 | mac[off+3]) % 10**6
print("%06d %d" % (code, 30 - (int(time.time()) % 30)))
PY
)
    fi

    # Fallback: scrape the most recent 6-digit code from the SOC log.
    if [[ -z "$code" && -f "$soc_log" ]]; then
        code=$(grep -aoE '"code":[ ]*"[0-9]{6}"|2FA Token[^0-9]*[0-9]{6}' "$soc_log" 2>/dev/null \
               | grep -oE '[0-9]{6}' | tail -1)
        secs="?"
    fi

    [[ -z "$code" ]] && { warn "Could not determine 2FA code — check ${soc_log}"; return; }

    echo ""
    echo -e "${B}${Y}  ╔══════════════════════════════════════════════════════════╗${N}"
    echo -e "${B}${Y}  ║                                                          ║${N}"
    printf  "${B}${Y}  ║        🔐  ADMIN 2FA CODE  →   ${G}%-6s${Y}                   ║${N}\n" "$code"
    echo -e "${B}${Y}  ║            user: ${G}admin${Y}      valid: ${G}${secs}s${Y}                       ║${N}"
    echo -e "${B}${Y}  ║                                                          ║${N}"
    echo -e "${B}${Y}  ╚══════════════════════════════════════════════════════════╝${N}"
    echo ""
}

[[ $EUID -ne 0 ]] && { echo -e "${R}Run as root:${N}  sudo bash scripts/falx-on.sh"; exit 1; }

# ─── Args ─────────────────────────────────────────────────────────────────────
# Dev mode is ON by default — the `falx-on` command is the demo/dev launcher.
# Override with --prod or FALX_DEV=0 for a production-style start.
DEV_MODE="${FALX_DEV:-1}"
FALX_CONF="${FALX_CONF:-/etc/falx/falx.toml}"
NO_WAIT=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dev)         DEV_MODE=1; shift ;;
        --prod)        DEV_MODE=0; shift ;;
        --config)      FALX_CONF="$2"; shift 2 ;;
        --config=*)    FALX_CONF="${1#*=}"; shift ;;
        --no-wait)     NO_WAIT=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ─── Resolve paths ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"

FALXD_BIN="${DIST_DIR}/falxd"
SOC_BIN="${DIST_DIR}/falx-soc"

# falx-user is the Rust XDP loader: it attaches the eBPF program to the NIC and
# pins the LIVE maps. `make dev` places it under build/user/, not dist/, so
# search the known locations. Without it, no XDP program is attached and every
# counter reads zero — this is the #1 cause of a "dead" dashboard.
FALX_USER_BIN=""
for cand in "${DIST_DIR}/falx-user" "${REPO_ROOT}/build/user/falx-user" \
            "${REPO_ROOT}/build/falx-user" "${REPO_ROOT}/target/release/falx-user"; do
    [[ -x "$cand" ]] && { FALX_USER_BIN="$cand"; break; }
done

[[ -x "$FALXD_BIN" ]] || fail "falxd binary not found at ${FALXD_BIN}. Run: make build"
[[ -x "$SOC_BIN"   ]] || fail "falx-soc binary not found at ${SOC_BIN}. Run: make build-soc"
[[ -n "$FALX_USER_BIN" ]] || fail "falx-user (XDP loader) binary not found. Run: make build-user
       Without it the XDP program is never attached and all counters stay zero."

BPF_PIN_DIR="/sys/fs/bpf/falx"
BPF_STATS_PIN="${BPF_PIN_DIR}/xdp_stats"

echo -e "\n${B}  FALX V2  —  Starting Up${N}$([ "$DEV_MODE" = "1" ] && echo "  ${Y}[DEV MODE]${N}" || true)\n"

# ─── Preflight: ensure nothing is already running ────────────────────────────
step "Preflight checks"

for proc in falx-user falxd falx-soc; do
    if pgrep -x "$proc" >/dev/null 2>&1; then
        warn "${proc} is already running (PID $(pgrep -x "$proc" | head -1))"
        warn "Run 'sudo bash scripts/falx-off.sh' first to do a clean restart."
        exit 1
    fi
done
ok "No stale FALX processes"

# ─── Data-access preflight (run as root) ─────────────────────────────────────
# Both daemons run as root here (this script is invoked via sudo), so they have
# the privileges to read pinned BPF maps and write the SQLite databases. This
# step removes the *other* common failure mode: state files left owned by a
# non-root user from an earlier `make dev` run, which a root service can still
# write — but a later non-root run could not. We normalise ownership/mode and
# guarantee the dirs + bpffs mount exist so auth.db / soc.db / policy.db writes
# (user add/delete) and map reads never hit "permission denied".
step "Preparing runtime state (root)"

for d in /var/lib/falx /var/log/falx /run/falx /etc/falx; do
    mkdir -p "$d" 2>/dev/null || true
done
chown -R root:root /var/lib/falx /var/log/falx /run/falx 2>/dev/null || true
chmod 750 /var/lib/falx 2>/dev/null || true
# SQLite needs to create -wal/-shm siblings in the dir; keep DB files root-owned.
for db in /var/lib/falx/auth.db /var/lib/falx/soc.db /var/lib/falx/policy.db; do
    [[ -e "$db" ]] && { chown root:root "$db" 2>/dev/null || true; chmod 640 "$db" 2>/dev/null || true; }
done
ok "State dirs ready, DB ownership normalised to root"

if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
    if mount -t bpf bpf /sys/fs/bpf 2>/dev/null; then
        ok "Mounted bpffs at /sys/fs/bpf"
    else
        warn "Could not mount bpffs — falxd will attempt it on startup"
    fi
else
    ok "bpffs already mounted at /sys/fs/bpf"
fi

# ─── 1. Start falx-user (XDP loader) ─────────────────────────────────────────
# CRITICAL ORDERING: the loader runs FIRST. It attaches the eBPF/XDP program to
# the NIC and pins the LIVE maps under /sys/fs/bpf/falx/. falxd and falx-soc then
# OPEN those existing pins, so all three processes share the one kernel map
# instance the datapath actually writes to. If falxd started first it would
# create empty placeholder maps and read zeros forever (the dual-instance bug).
step "Starting falx-user (XDP loader)"

USER_LOG="/var/log/falx/falx-user.log"
mkdir -p "$(dirname "$USER_LOG")" 2>/dev/null || true

setsid "$FALX_USER_BIN" --config "$FALX_CONF" >> "$USER_LOG" 2>&1 &
FALX_USER_PID=$!
ok "falx-user started (PID ${FALX_USER_PID}), logging → ${USER_LOG}"

# ─── 2. Wait for BPF maps to be pinned by the loader ─────────────────────────
step "Waiting for BPF maps to be pinned"

if [[ "$NO_WAIT" == true ]]; then
    info "--no-wait: skipping readiness check"
else
    MAX_WAIT=20   # seconds — XDP attach + pin can take a moment on first load
    ELAPSED=0
    while [[ ! -e "$BPF_STATS_PIN" ]]; do
        # Check that the loader is still alive (XDP attach can fail on some NICs)
        if ! kill -0 "$FALX_USER_PID" 2>/dev/null; then
            fail "falx-user exited before pinning maps — XDP attach likely failed.
       Check ${USER_LOG} (interface/mode in ${FALX_CONF})."
        fi
        if [[ $ELAPSED -ge $MAX_WAIT ]]; then
            fail "BPF maps not pinned after ${MAX_WAIT}s. Check ${USER_LOG}."
        fi
        info "Waiting for ${BPF_STATS_PIN} … (${ELAPSED}s)"
        sleep 1
        (( ELAPSED++ )) || true
    done
    ok "XDP attached, live BPF maps pinned (${ELAPSED}s)"
fi

# ─── 3. Start falxd (control-plane: failsafe, AF_XDP, metrics) ───────────────
# Opens the live maps the loader just pinned (never creates its own now).
step "Starting falxd"

FALXD_LOG="/var/log/falx/falxd.log"
mkdir -p "$(dirname "$FALXD_LOG")" 2>/dev/null || true

FALXD_ARGS=(--config "$FALX_CONF")

# setsid → new session so the daemon survives this script (and the terminal) exiting.
setsid "$FALXD_BIN" "${FALXD_ARGS[@]}" >> "$FALXD_LOG" 2>&1 &
FALXD_PID=$!
ok "falxd started (PID ${FALXD_PID}), logging → ${FALXD_LOG}"

# Give falxd a moment to open the maps before the SOC backend attaches too.
sleep 1

# ─── 4. Start falx-soc (SOC HTTP/WS backend) ─────────────────────────────────
step "Starting falx-soc"

SOC_LOG="/var/log/falx/falx-soc.log"
mkdir -p "$(dirname "$SOC_LOG")" 2>/dev/null || true

if [[ "$DEV_MODE" == "1" ]]; then
    info "Dev mode enabled — fixed admin TOTP active"
    FALX_DEV=1 setsid "$SOC_BIN" >> "$SOC_LOG" 2>&1 &
else
    setsid "$SOC_BIN" >> "$SOC_LOG" 2>&1 &
fi
SOC_PID=$!
ok "falx-soc started (PID ${SOC_PID}), logging → ${SOC_LOG}"

# ─── 5. Quick health check ────────────────────────────────────────────────────
step "Health check"

sleep 2

ALIVE=true
if ! kill -0 "$FALX_USER_PID" 2>/dev/null; then
    warn "falx-user (PID ${FALX_USER_PID}) has already exited — check ${USER_LOG}"
    warn "Without it the XDP program is detached and counters will read zero."
    ALIVE=false
fi
if ! kill -0 "$FALXD_PID" 2>/dev/null; then
    warn "falxd (PID ${FALXD_PID}) has already exited — check ${FALXD_LOG}"
    ALIVE=false
fi
if ! kill -0 "$SOC_PID" 2>/dev/null; then
    warn "falx-soc (PID ${SOC_PID}) has already exited — check ${SOC_LOG}"
    ALIVE=false
fi

if [[ "$ALIVE" == true ]]; then
    echo -e "\n${G}${B}  FALX is running.${N}"
    echo -e "  falx-user PID ${B}${FALX_USER_PID}${N}   ${C}tail -f ${USER_LOG}${N}   (XDP datapath)"
    echo -e "  falxd     PID ${B}${FALXD_PID}${N}   ${C}tail -f ${FALXD_LOG}${N}"
    echo -e "  falx-soc  PID ${B}${SOC_PID}${N}   ${C}tail -f ${SOC_LOG}${N}"
    if [[ "$DEV_MODE" == "1" ]]; then
        print_2fa_box "$SOC_LOG"
    fi
    echo ""
else
    echo -e "\n${R}${B}  One or more services failed to start. Check logs above.${N}\n"
    exit 1
fi
