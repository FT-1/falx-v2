#!/usr/bin/env bash
# =============================================================================
# Project: FALX V2
# Lead Architect & Owner: FT-1
# Description: Environment setup script (scripts/setup.sh).
#              Installs all build-time and runtime dependencies for FALX V2.
#              Tested on Ubuntu 22.04 LTS / 24.04 LTS.
#              Run once on a fresh machine: sudo bash scripts/setup.sh
# =============================================================================

set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_error() { echo -e "${RED}[ERROR]${RESET} $*"; }
log_step()  { echo -e "\n${BOLD}══ $* ══${RESET}"; }

# ─── Root check ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root: sudo bash $0"
    exit 1
fi

UBUNTU_VER=$(lsb_release -rs 2>/dev/null || echo "unknown")
log_info "FALX V2 Setup | Ubuntu $UBUNTU_VER | Architect: FT-1"

# ─── Step 1: System packages ──────────────────────────────────────────────────
log_step "System Packages"
apt-get update -qq
apt-get install -y --no-install-recommends \
    build-essential \
    curl wget git \
    pkg-config \
    llvm clang \
    libelf-dev \
    linux-headers-$(uname -r) \
    libbpf-dev \
    bpftool \
    sqlite3 libsqlite3-dev \
    cmake ninja-build \
    protobuf-compiler \
    libprotobuf-dev \
    libgrpc++-dev \
    protobuf-compiler-grpc \
    ca-certificates \
    make \
    jq \
    2>/dev/null
log_ok "System packages installed"

# ─── Step 2: Rust toolchain ───────────────────────────────────────────────────
log_step "Rust Toolchain"
if ! command -v cargo &>/dev/null; then
    log_info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain nightly
    source "$HOME/.cargo/env"
    log_ok "Rust installed"
else
    log_info "Rust already installed: $(rustc --version)"
    rustup update nightly --no-self-update 2>/dev/null || true
fi

# BPF target and tools
log_info "Adding BPF target..."
rustup target add bpfel-unknown-none 2>/dev/null || true
rustup component add rust-src --toolchain nightly 2>/dev/null || true

log_info "Installing bpf-linker..."
cargo install bpf-linker 2>/dev/null \
    && log_ok "bpf-linker installed" \
    || log_warn "bpf-linker install failed (may already be installed)"

# ─── Step 3: Go toolchain ─────────────────────────────────────────────────────
log_step "Go Toolchain"
GO_VERSION="1.22.5"
GO_ARCH=$(dpkg --print-architecture | sed 's/arm64/arm64/;s/amd64/amd64/')

if ! command -v go &>/dev/null || [[ "$(go version | awk '{print $3}' | tr -d 'go')" < "1.22" ]]; then
    log_info "Installing Go $GO_VERSION..."
    GO_TGZ="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    wget -q "https://golang.org/dl/${GO_TGZ}" -O "/tmp/${GO_TGZ}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TGZ}"
    rm "/tmp/${GO_TGZ}"
    ln -sf /usr/local/go/bin/go   /usr/local/bin/go
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
    log_ok "Go $GO_VERSION installed"
else
    log_info "Go already installed: $(go version)"
fi

# Go tools
log_info "Installing Go development tools..."
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest        2>/dev/null || true
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest       2>/dev/null || true
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest 2>/dev/null || true
log_ok "Go tools installed"

# ─── Step 4: Python ───────────────────────────────────────────────────────────
log_step "Python Environment"
apt-get install -y python3 python3-pip python3-venv --no-install-recommends
log_info "Creating Python virtualenv..."
python3 -m venv /opt/falx-ai-venv
/opt/falx-ai-venv/bin/pip install --upgrade pip -q
/opt/falx-ai-venv/bin/pip install \
    grpcio grpcio-tools protobuf \
    onnxruntime numpy scipy \
    asyncio-rlock structlog \
    prometheus-client \
    -q
log_ok "Python venv ready at /opt/falx-ai-venv"

# ─── Step 5: BPF filesystem ───────────────────────────────────────────────────
log_step "BPF Filesystem"
if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpf /sys/fs/bpf
    log_ok "BPF filesystem mounted"
else
    log_info "BPF filesystem already mounted"
fi

# Persist across reboots
if ! grep -q '/sys/fs/bpf' /etc/fstab; then
    echo "bpf /sys/fs/bpf bpf defaults 0 0" >> /etc/fstab
    log_ok "BPF filesystem added to /etc/fstab"
fi

# ─── Step 6: Directory structure ─────────────────────────────────────────────
log_step "FALX V2 Directory Structure"
install -d -m 750 /etc/falx
install -d -m 750 /etc/falx/keys
install -d -m 750 /var/log/falx
install -d -m 750 /var/lib/falx
install -d -m 750 /var/run/falx
install -d -m 700 /sys/fs/bpf/falx

# Install default configs if not present
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_SRC="${SCRIPT_DIR}/../configs"
if [[ -f "${CONFIG_SRC}/falx.toml" && ! -f /etc/falx/falx.toml ]]; then
    install -m 640 "${CONFIG_SRC}/falx.toml"         /etc/falx/falx.toml
    install -m 640 "${CONFIG_SRC}/honeypot.toml"     /etc/falx/honeypot.toml
    install -m 640 "${CONFIG_SRC}/notifications.toml" /etc/falx/notifications.toml
    log_ok "Default configs installed to /etc/falx/"
fi

# Seed default policy rules
if [[ -f "${CONFIG_SRC}/default_policy_rules.sql" && ! -f /var/lib/falx/policy.db ]]; then
    sqlite3 /var/lib/falx/policy.db \
        < "${CONFIG_SRC}/default_policy_rules.sql" \
        && log_ok "Default policy rules seeded" \
        || log_warn "Policy rule seeding failed"
fi

log_ok "Directory structure ready"

# ─── Step 7: Kernel settings ─────────────────────────────────────────────────
log_step "Kernel Settings"
cat > /etc/sysctl.d/99-falx.conf << 'EOF'
# FALX V2 Kernel Tuning
# Increase socket buffers for AF_XDP
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 67108864
# Allow BPF JIT
net.core.bpf_jit_enable = 1
net.core.bpf_jit_harden = 1
# Increase file descriptor limits for BPF maps
fs.file-max = 2097152
# Locked memory for UMEM (AF_XDP requires MAP_LOCKED)
# Applied per-service via systemd LimitMEMLOCK=infinity
EOF
sysctl -p /etc/sysctl.d/99-falx.conf --quiet
log_ok "Kernel settings applied"

# ─── Step 8: Build FALX V2 ───────────────────────────────────────────────────
log_step "Build FALX V2"
PROJECT_ROOT="${SCRIPT_DIR}/.."
cd "$PROJECT_ROOT"

log_info "Running: make deps check-deps"
if make deps check-deps 2>&1 | tail -5; then
    log_ok "Dependencies verified"
else
    log_warn "Dependency check warnings (review above)"
fi

log_info "Running: make dev  (data plane + control plane)"
if make dev 2>&1 | tail -10; then
    log_ok "FALX V2 dev build complete"
else
    log_error "Build failed — check output above"
    exit 1
fi

# ─── Step 9: systemd service ──────────────────────────────────────────────────
log_step "systemd Service"
if [[ -f "${SCRIPT_DIR}/falxd.service" ]]; then
    install -m 644 "${SCRIPT_DIR}/falxd.service" /etc/systemd/system/falxd.service
    systemctl daemon-reload
    log_ok "falxd.service installed"
    log_info "To start: systemctl enable --now falxd"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  FALX V2 Setup Complete | Lead Architect: FT-1        ${RESET}"
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${RESET}"
echo ""
echo "  Next steps:"
echo "  1. Review /etc/falx/falx.toml and set your interface name"
echo "  2. sudo systemctl enable --now falxd"
echo "  3. sudo systemctl enable --now falx-ai  (optional)"
echo "  4. Open http://localhost:9090/metrics   (Prometheus)"
echo "  5. Open http://localhost:8080           (SOC Dashboard)"
echo ""
echo "  Logs:   journalctl -fu falxd"
echo "  Status: systemctl status falxd"
echo ""
