#!/usr/bin/env bash
# =============================================================================
# Project: FALX V2  |  Lead Architect & Owner: FT-1
# Description: Zero-touch production installer / deployment script.
#
#   One-line bootstrap (fresh machine — installs ALL dependencies):
#     curl -sSL https://your-server/deploy.sh | sudo bash
#
#   From a cloned repository:
#     sudo bash scripts/deploy.sh              # Full install + deploy
#     sudo bash scripts/deploy.sh --skip-tests # Skip test suite
#     sudo bash scripts/deploy.sh --rollback   # Roll back to previous release
#     sudo bash scripts/deploy.sh --no-deps    # Skip dep-check (already installed)
#
# =============================================================================

set -euo pipefail

# ─── Terminal colors ──────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m'
B='\033[1m' M='\033[0;35m' N='\033[0m'

step()   { echo -e "\n${B}${C}  ══════  $*  ══════${N}"; }
info()   { echo -e "  ${C}[INFO]${N}   $*"; }
ok()     { echo -e "  ${G}[  OK ]${N}  $*"; }
warn()   { echo -e "  ${Y}[ WARN]${N}  $*"; }
fail()   { echo -e "  ${R}[ FAIL]${N}  $*"; exit 1; }
banner() { echo -e "\n${B}${G}$*${N}"; }

# ─── Arguments ────────────────────────────────────────────────────────────────
DEPLOY_ENV="production"
SKIP_TESTS=false
ROLLBACK=false
NO_DEPS=false
VERSION="$(date +%Y%m%d%H%M%S)"
REPO_URL="${FALX_REPO_URL:-}"   # Set to git URL when piped from curl

for arg in "$@"; do case $arg in
    --env=*)      DEPLOY_ENV="${arg#*=}" ;;
    --skip-tests) SKIP_TESTS=true ;;
    --rollback)   ROLLBACK=true ;;
    --no-deps)    NO_DEPS=true ;;
    --version=*)  VERSION="${arg#*=}" ;;
esac done

[[ $EUID -ne 0 ]] && fail "Run as root:  sudo bash scripts/deploy.sh"

# ─── Welcome banner ───────────────────────────────────────────────────────────
echo ""
echo -e "${B}${M}  ╔══════════════════════════════════════════════════════════╗${N}"
echo -e "${B}${M}  ║   ⚡  FALX V2  —  Hybrid eBPF/XDP IPS                   ║${N}"
echo -e "${B}${M}  ║   Lead Architect: FT-1  |  Deploying v${VERSION}${N}${B}${M}  ║${N}"
echo -e "${B}${M}  ╚══════════════════════════════════════════════════════════╝${N}"
echo ""

# ─── Rollback ─────────────────────────────────────────────────────────────────
if [[ "$ROLLBACK" == true ]]; then
    step "ROLLBACK"
    PREV=$(ls -1t /opt/falx/releases/ 2>/dev/null | sed -n '2p')
    [[ -z "$PREV" ]] && fail "No previous release found in /opt/falx/releases/"
    info "Rolling back to: $PREV"
    ln -sfn "/opt/falx/releases/$PREV" /opt/falx/current
    systemctl restart falxd falx-soc 2>/dev/null || true
    ok "Rollback complete → $PREV"
    exit 0
fi

# ─── Detect script location (repo vs pipe-from-curl) ─────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || echo "/tmp")"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd 2>/dev/null || echo "/tmp/falx-v2")"

# If piped from curl, BASH_SOURCE[0] is /dev/stdin — clone the repo first.
if [[ ! -f "$ROOT_DIR/Makefile" ]]; then
    step "Clone Repository"
    if [[ -z "$REPO_URL" ]]; then
        fail "Cannot find FALX V2 source tree. Set FALX_REPO_URL=<git-url> or run from a cloned directory."
    fi
    CLONE_DIR="/opt/falx-src"
    [[ -d "$CLONE_DIR" ]] && info "Updating existing clone at $CLONE_DIR" || true
    git clone --depth 1 "$REPO_URL" "$CLONE_DIR" 2>/dev/null \
        || git -C "$CLONE_DIR" pull --ff-only 2>/dev/null \
        || true
    ROOT_DIR="$CLONE_DIR"
    SCRIPT_DIR="$CLONE_DIR/scripts"
    ok "Source at: $ROOT_DIR"
fi

# ─── 0. Dependency Bootstrap ──────────────────────────────────────────────────
# Runs automatically on first install or when tools are missing.
# Skip with --no-deps if everything is already installed.
# ─────────────────────────────────────────────────────────────────────────────
need_install=false
command -v go    &>/dev/null || need_install=true
command -v cargo &>/dev/null || need_install=true
command -v clang &>/dev/null || need_install=true

if [[ "$NO_DEPS" == false && ("$need_install" == true) ]]; then
    step "Dependency Bootstrap  (first-time install)"
    info "Missing tools detected — installing all required dependencies."
    info "This takes 5–15 minutes the first time."

    # ── System packages ───────────────────────────────────────────────────────
    info "Installing system packages..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        build-essential curl wget git pkg-config \
        llvm clang libelf-dev libbpf-dev \
        linux-headers-"$(uname -r)" \
        linux-tools-common linux-tools-"$(uname -r)" \
        sqlite3 libsqlite3-dev \
        cmake ninja-build \
        protobuf-compiler libprotobuf-dev \
        libgrpc++-dev protobuf-compiler-grpc \
        ca-certificates make jq lsb-release \
        2>/dev/null || true
    ok "System packages ready"

    # ── Rust toolchain ────────────────────────────────────────────────────────
    if ! command -v cargo &>/dev/null; then
        info "Installing Rust nightly toolchain..."
        export CARGO_HOME="/root/.cargo"
        export RUSTUP_HOME="/root/.rustup"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --profile minimal --default-toolchain nightly \
                        --no-modify-path 2>&1 | tail -4
        source "/root/.cargo/env" 2>/dev/null || true
        ok "Rust installed: $(rustc --version 2>/dev/null || echo '?')"
    else
        info "Rust present: $(rustc --version 2>/dev/null || echo '?')"
        rustup update nightly --no-self-update 2>/dev/null || true
    fi
    # Always ensure these components are present
    source "/root/.cargo/env" 2>/dev/null || true
    rustup component add rust-src  --toolchain nightly 2>/dev/null || true
    cargo install bpf-linker 2>/dev/null || true
    ok "Rust BPF tooling ready"

    # ── Go toolchain ──────────────────────────────────────────────────────────
    GO_WANT="1.23.4"
    GO_ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    need_go=false
    if ! command -v go &>/dev/null; then
        need_go=true
    else
        cur=$(go version | awk '{print $3}' | tr -d 'go')
        # Simple version compare: 1.22 < 1.23 needs upgrade
        [[ "$(printf '%s\n' 1.23 "$cur" | sort -V | head -1)" != "1.23" ]] && need_go=true || true
    fi

    if [[ "$need_go" == true ]]; then
        info "Installing Go $GO_WANT..."
        GO_TGZ="go${GO_WANT}.linux-${GO_ARCH}.tar.gz"
        wget -q "https://golang.org/dl/${GO_TGZ}" -O "/tmp/${GO_TGZ}"
        rm -rf /usr/local/go
        tar -C /usr/local -xzf "/tmp/${GO_TGZ}"
        rm -f "/tmp/${GO_TGZ}"
        ln -sf /usr/local/go/bin/go    /usr/local/bin/go
        ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
        ok "Go $GO_WANT installed"
    else
        info "Go present: $(go version)"
    fi

    # ── BPF filesystem ────────────────────────────────────────────────────────
    if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
        mount -t bpf bpf /sys/fs/bpf
        ok "BPF filesystem mounted"
    else
        info "BPF filesystem already mounted"
    fi
    if ! grep -q '/sys/fs/bpf' /etc/fstab 2>/dev/null; then
        echo "bpf /sys/fs/bpf bpf defaults 0 0" >> /etc/fstab
    fi

    # ── Kernel tuning ─────────────────────────────────────────────────────────
    cat > /etc/sysctl.d/99-falx.conf << 'EOF'
net.core.rmem_max        = 134217728
net.core.wmem_max        = 134217728
net.core.bpf_jit_enable  = 1
net.core.bpf_jit_harden  = 1
fs.file-max              = 2097152
EOF
    sysctl -p /etc/sysctl.d/99-falx.conf --quiet 2>/dev/null || true
    ok "Kernel settings applied"

elif [[ "$NO_DEPS" == false ]]; then
    info "All build tools already installed — skipping bootstrap (use --no-deps to silence this check)"
fi

# Ensure cargo is on PATH for the build steps below
export CARGO_HOME="${CARGO_HOME:-/root/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/root/.rustup}"
[[ -f "$CARGO_HOME/env" ]] && source "$CARGO_HOME/env" || true

# ─── 1. Tests ─────────────────────────────────────────────────────────────────
if [[ "$SKIP_TESTS" == false ]]; then
    step "Test Suite"
    cd "$ROOT_DIR"
    if [[ -f scripts/run_tests.sh ]]; then
        bash scripts/run_tests.sh --race || fail "Tests failed — deploy aborted"
        ok "All tests passed"
    else
        warn "run_tests.sh not found — skipping test suite"
    fi
fi

# ─── 2. Build ─────────────────────────────────────────────────────────────────
step "Build"
cd "$ROOT_DIR"
info "Building FALX V2 (eBPF kernel + control-plane + SOC backend)..."
make dev 2>&1 | grep -E '^\[|^make|OK|FAIL|Error|error' | tail -15
ok "Build complete"

# ─── 3. Create Release Directory ──────────────────────────────────────────────
step "Staging Release $VERSION"
REL="/opt/falx/releases/$VERSION"
mkdir -p "$REL/bin" "$REL/bpf" "$REL/dashboard"

DIST="$ROOT_DIR/dist"
for bin in falxd falx-soc falx-ai; do
    [[ -f "$DIST/$bin" ]] && install -m755 "$DIST/$bin" "$REL/bin/$bin" && info "→ $bin"
done
FALX_USER_SRC="$ROOT_DIR/build/user/falx-user"
[[ -f "$FALX_USER_SRC" ]] && install -m755 "$FALX_USER_SRC" "$REL/bin/falx-user" && info "→ falx-user"
[[ -f "$ROOT_DIR/build/ebpf/falx.bpf.o" ]] && cp "$ROOT_DIR/build/ebpf/falx.bpf.o" "$REL/bpf/"
[[ -d "$ROOT_DIR/soc-backend/dashboard"  ]] && cp -r "$ROOT_DIR/soc-backend/dashboard/." "$REL/dashboard/"

cat > "$REL/RELEASE" << EOF
version=$VERSION
env=$DEPLOY_ENV
deployed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
git=$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)
architect=FT-1
EOF
ok "Release staged: $REL"

# ─── 4. Configs (first-run only) ──────────────────────────────────────────────
step "Config"
mkdir -p /etc/falx /etc/falx/keys /etc/falx/dashboard /var/log/falx /var/lib/falx /var/run/falx
for f in falx.toml honeypot.toml notifications.toml; do
    [[ ! -f "/etc/falx/$f" && -f "$ROOT_DIR/configs/$f" ]] && \
        install -m640 "$ROOT_DIR/configs/$f" "/etc/falx/$f" && info "Installed: /etc/falx/$f"
done

# ─── 4b. Interface wizard ────────────────────────────────────────────────────
# Auto-detects the NIC carrying the default route and asks for a single [Y/n].
# Fully non-interactive (CI / piped) when stdin is not a tty.
step "Network Interface Setup"
FALX_CONF=/etc/falx/falx.toml

if [[ ! -f "$FALX_CONF" ]]; then
    warn "$FALX_CONF missing — interface prompt skipped"
elif [[ ! -t 0 || ! -t 1 ]]; then
    info "Non-interactive mode — keeping existing interface config"
    info "  Edit $FALX_CONF to change interface, then: sudo systemctl reload falxd"
else
    CURRENT_IFACE=$(grep -E '^iface[[:space:]]*=' "$FALX_CONF" 2>/dev/null | head -1 \
                    | sed -E 's/.*"([^"]+)".*/\1/' || echo "eth0")
    CURRENT_MODE=$(grep  -E '^mode[[:space:]]*='  "$FALX_CONF" 2>/dev/null | head -1 \
                    | sed -E 's/.*"([^"]+)".*/\1/' || echo "skb")

    AUTODETECT_IFACE=$(ip route get 8.8.8.8 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}')
    AUTODETECT_IP=""
    if [[ -n "$AUTODETECT_IFACE" ]]; then
        AUTODETECT_IP=$(ip -4 -o addr show dev "$AUTODETECT_IFACE" 2>/dev/null \
            | awk '{print $4}' | cut -d/ -f1 | head -1)
    fi

    if [[ -n "$CURRENT_IFACE" && "$CURRENT_IFACE" != "eth0" ]]; then
        DEFAULT_IFACE="$CURRENT_IFACE"
    else
        DEFAULT_IFACE="${AUTODETECT_IFACE:-eth0}"
    fi

    AVAIL_IFACES=$(ip -br link show 2>/dev/null | awk '$1 != "lo" {print $1}' \
                   | sed 's/@.*//' | tr '\n' '  ')

    echo ""
    echo -e "  ${B}Available interfaces:${N}  ${AVAIL_IFACES}"
    if [[ -n "$AUTODETECT_IFACE" ]]; then
        echo -e "  ${G}Auto-detected:${N}         ${AUTODETECT_IFACE}${AUTODETECT_IP:+  (IP: $AUTODETECT_IP)}"
    fi
    echo -e "  ${C}Current config:${N}        iface=${CURRENT_IFACE}  mode=${CURRENT_MODE}"
    echo ""

    # Single [Y/n] to accept the auto-detected interface
    if [[ "$DEFAULT_IFACE" == "$CURRENT_IFACE" ]]; then
        info "Interface already configured: ${CURRENT_IFACE} — no change needed"
        NEW_IFACE="$CURRENT_IFACE"
        NEW_MODE="$CURRENT_MODE"
    else
        read -rp "  Use interface ${B}${DEFAULT_IFACE}${N} with mode ${B}skb${N}? [Y/n]: " CONFIRM
        CONFIRM=${CONFIRM:-Y}
        if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
            NEW_IFACE="$DEFAULT_IFACE"
            NEW_MODE="skb"
        else
            read -rp "  Enter interface name [${CURRENT_IFACE}]: " NEW_IFACE
            NEW_IFACE=${NEW_IFACE:-$CURRENT_IFACE}
            read -rp "  XDP mode (native/skb/offload) [${CURRENT_MODE}]: " NEW_MODE
            NEW_MODE=${NEW_MODE:-$CURRENT_MODE}
        fi
    fi

    if ! ip link show "$NEW_IFACE" >/dev/null 2>&1; then
        warn "Interface '$NEW_IFACE' not found — keeping '$CURRENT_IFACE'"
        NEW_IFACE=$CURRENT_IFACE
    fi

    case "$NEW_MODE" in
        native|skb|offload) ;;
        *) warn "Invalid mode '$NEW_MODE' — defaulting to 'skb'"; NEW_MODE=skb ;;
    esac

    if [[ "$NEW_IFACE" != "$CURRENT_IFACE" || "$NEW_MODE" != "$CURRENT_MODE" ]]; then
        sed -i.bak \
            -e "s|^iface[[:space:]]*=[[:space:]]*\"[^\"]*\"|iface     = \"$NEW_IFACE\"|" \
            -e "s|^mode[[:space:]]*=[[:space:]]*\"[^\"]*\"|mode = \"$NEW_MODE\"|"  \
            "$FALX_CONF"
        ok "Interface: ${NEW_IFACE}  mode: ${NEW_MODE}  (backup: ${FALX_CONF}.bak)"
    else
        info "$FALX_CONF unchanged"
    fi
fi

# ─── 5. Atomic Switchover ─────────────────────────────────────────────────────
step "Atomic Switchover"
PREV_REL=""
[[ -L /opt/falx/current ]] && PREV_REL=$(readlink /opt/falx/current) || true

for bin in falxd falx-user falx-soc falx-ai; do
    [[ -f "$REL/bin/$bin" ]] && \
        cp "/usr/local/bin/$bin" "/usr/local/bin/$bin.prev" 2>/dev/null || true
    [[ -f "$REL/bin/$bin" ]] && install -m755 "$REL/bin/$bin" "/usr/local/bin/$bin"
done
[[ -d "$REL/dashboard" ]] && cp -r "$REL/dashboard/." /etc/falx/dashboard/

for svc in falx-user.service falxd.service falx-soc.service falx-ai.service; do
    if [[ -f "$SCRIPT_DIR/$svc" ]]; then
        install -m644 "$SCRIPT_DIR/$svc" "/etc/systemd/system/$svc" && info "Unit: $svc"
    fi
done
systemctl daemon-reload
ln -sfn "$REL" /opt/falx/current
ok "Active release → $VERSION"

# ─── 6. Start / Restart Services ─────────────────────────────────────────────
step "Services"
for svc in falxd falx-soc; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        info "Restarting $svc..."
        systemctl restart "$svc"
    else
        info "Starting $svc..."
        systemctl enable --now "$svc" 2>/dev/null || true
    fi
done
sleep 4

# ─── 7. Health Check ─────────────────────────────────────────────────────────
step "Health Check"
HEALTHY=false
for i in $(seq 1 12); do
    if curl -sf http://localhost:8080/healthz >/dev/null 2>&1; then
        HEALTHY=true; break
    fi
    info "Waiting for SOC backend ($i/12)..."; sleep 3
done

if [[ "$HEALTHY" == false ]]; then
    warn "Health check failed — rolling back to previous release..."
    [[ -n "$PREV_REL" ]] && ln -sfn "$PREV_REL" /opt/falx/current && \
        systemctl restart falxd falx-soc 2>/dev/null || true
    fail "Deploy failed. Check logs:  sudo journalctl -u falxd -n 50"
fi
ok "SOC backend is healthy"

# ─── 7b. Seed policy rules ────────────────────────────────────────────────────
if [[ -f "$ROOT_DIR/configs/default_policy_rules.sql" ]]; then
    for attempt in 1 2 3 4 5; do
        if sqlite3 /var/lib/falx/policy.db \
            < "$ROOT_DIR/configs/default_policy_rules.sql" 2>/dev/null; then
            ok "Default policy rules seeded"; break
        fi
        sleep 1
    done
fi

# ─── 8. Cleanup Old Releases ─────────────────────────────────────────────────
ls -1t /opt/falx/releases/ 2>/dev/null | tail -n +6 | while read -r r; do
    rm -rf "/opt/falx/releases/$r" && info "Removed old release: $r"
done

# ─── Read default admin credentials from service log ─────────────────────────
ADMIN_PASS="(see: sudo journalctl -u falx-soc -n 50 | grep 'DEFAULT ADMIN')"
ADMIN_PASS_LINE=$(journalctl -u falx-soc --no-pager -n 100 2>/dev/null \
    | grep -o 'temp_password=[^ ]*' | head -1 | cut -d= -f2 || true)
[[ -n "$ADMIN_PASS_LINE" ]] && ADMIN_PASS="$ADMIN_PASS_LINE"

# Derive dashboard URL from the auto-detected IP (or hostname)
DASH_IP="$AUTODETECT_IP"
[[ -z "$DASH_IP" ]] && DASH_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -z "$DASH_IP" ]] && DASH_IP="localhost"
DASH_URL="http://${DASH_IP}:8080"

# ─── Final Banner ─────────────────────────────────────────────────────────────
echo ""
echo -e "${B}${G}  ╔══════════════════════════════════════════════════════════════╗${N}"
echo -e "${B}${G}  ║                                                              ║${N}"
echo -e "${B}${G}  ║   ⚡  FALX V2  —  Deployment Successful!                    ║${N}"
echo -e "${B}${G}  ║                                                              ║${N}"
echo -e "${B}${G}  ╠══════════════════════════════════════════════════════════════╣${N}"
echo -e "${B}${G}  ║${N}                                                              ${B}${G}║${N}"
echo -e "${B}${G}  ║${N}  🌐  ${B}Dashboard URL:${N}   ${C}${DASH_URL}${N}                          ${B}${G}║${N}"
echo -e "${B}${G}  ║${N}  👤  ${B}Admin user:${N}      ${Y}admin${N}                                   ${B}${G}║${N}"
echo -e "${B}${G}  ║${N}  🔑  ${B}Admin password:${N}  ${Y}${ADMIN_PASS}${N}   ${B}${G}║${N}"
echo -e "${B}${G}  ║${N}  🔒  ${B}2FA setup:${N}       Required on first login                   ${B}${G}║${N}"
echo -e "${B}${G}  ║${N}                                                              ${B}${G}║${N}"
echo -e "${B}${G}  ╠══════════════════════════════════════════════════════════════╣${N}"
echo -e "${B}${G}  ║${N}  📊  Prometheus:   ${C}http://${DASH_IP}:9090/metrics${N}           ${B}${G}║${N}"
echo -e "${B}${G}  ║${N}  ❤️   Health:       ${C}${DASH_URL}/healthz${N}           ${B}${G}║${N}"
echo -e "${B}${G}  ║${N}  📝  Logs:         ${C}sudo journalctl -fu falxd${N}              ${B}${G}║${N}"
echo -e "${B}${G}  ║${N}  ↩️   Rollback:     ${C}sudo bash scripts/deploy.sh --rollback${N}${B}${G}║${N}"
echo -e "${B}${G}  ║${N}                                                              ${B}${G}║${N}"
echo -e "${B}${G}  ║${N}  ⚠️   ${R}Change the admin password immediately!${N}               ${B}${G}║${N}"
echo -e "${B}${G}  ║${N}  ⚠️   ${Y}Enable 2FA for all operator accounts.${N}                ${B}${G}║${N}"
echo -e "${B}${G}  ║${N}                                                              ${B}${G}║${N}"
echo -e "${B}${G}  ╚══════════════════════════════════════════════════════════════╝${N}"
echo ""
echo -e "  Version: ${G}${VERSION}${N}  |  Env: ${DEPLOY_ENV}  |  ${B}Architect: FT-1${N}"
echo ""
