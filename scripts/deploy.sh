#!/usr/bin/env bash
# =============================================================================
# Project: FALX V2
# Lead Architect & Owner: FT-1
# Description: deploy.sh — automated zero-downtime production deployment.
#   Usage:
#     sudo bash scripts/deploy.sh                    # Full deploy
#     sudo bash scripts/deploy.sh --skip-tests       # Skip test suite
#     sudo bash scripts/deploy.sh --rollback         # Roll back to previous
#     sudo bash scripts/deploy.sh --env staging      # Staging environment
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOY_ENV="production"
SKIP_TESTS=false
ROLLBACK=false
VERSION="$(date +%Y%m%d%H%M%S)"

for arg in "$@"; do case $arg in
    --env=*)      DEPLOY_ENV="${arg#*=}" ;;
    --skip-tests) SKIP_TESTS=true ;;
    --rollback)   ROLLBACK=true ;;
    --version=*)  VERSION="${arg#*=}" ;;
esac done

R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m' B='\033[1m' N='\033[0m'
step()  { echo -e "\n${B}${C}══ $* ══${N}"; }
info()  { echo -e "${C}[INFO]${N}  $*"; }
ok()    { echo -e "${G}[OK]${N}    $*"; }
warn()  { echo -e "${Y}[WARN]${N}  $*"; }
fail()  { echo -e "${R}[FAIL]${N}  $*"; exit 1; }

[[ $EUID -ne 0 ]] && fail "Must run as root (sudo)"

# ─── Rollback ─────────────────────────────────────────────────────────────────
if [[ "$ROLLBACK" == true ]]; then
    step "ROLLBACK"
    PREV=$(ls -1t /opt/falx/releases/ 2>/dev/null | sed -n '2p')
    [[ -z "$PREV" ]] && fail "No previous release found"
    info "Rolling back to: $PREV"
    ln -sfn "/opt/falx/releases/$PREV" /opt/falx/current
    systemctl restart falxd falx-soc 2>/dev/null || true
    ok "Rollback complete → $PREV"
    exit 0
fi

echo -e "\n${B}${G}══ FALX V2 Deploy | Env=$DEPLOY_ENV | v$VERSION | FT-1 ══${N}\n"

# ─── 1. Tests ─────────────────────────────────────────────────────────────────
if [[ "$SKIP_TESTS" == false ]]; then
    step "Test Suite"
    cd "$ROOT_DIR"
    bash scripts/run_tests.sh --race || fail "Tests failed — deploy aborted"
    ok "All tests passed"
fi

# ─── 2. Build ─────────────────────────────────────────────────────────────────
step "Build"
cd "$ROOT_DIR"
make dev 2>&1 | tail -8
ok "Build complete"

# ─── 3. Create Release Directory ──────────────────────────────────────────────
step "Release $VERSION"
REL="/opt/falx/releases/$VERSION"
mkdir -p "$REL/bin" "$REL/bpf" "$REL/dashboard"

DIST="$ROOT_DIR/dist"
for bin in falxd falx-soc falx-ai; do
    [[ -f "$DIST/$bin" ]] && install -m755 "$DIST/$bin" "$REL/bin/$bin" && info "→ $bin"
done
[[ -f "$ROOT_DIR/build/ebpf/falx.bpf.o" ]] && cp "$ROOT_DIR/build/ebpf/falx.bpf.o" "$REL/bpf/"
[[ -d "$ROOT_DIR/soc-backend/dashboard" ]]   && cp -r "$ROOT_DIR/soc-backend/dashboard/." "$REL/dashboard/"

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
[[ ! -f /var/lib/falx/policy.db && -f "$ROOT_DIR/configs/default_policy_rules.sql" ]] && \
    sqlite3 /var/lib/falx/policy.db < "$ROOT_DIR/configs/default_policy_rules.sql" && \
    ok "Policy DB seeded"

# ─── 4b. Interface & XDP mode (interactive) ───────────────────────────────────
# Patch /etc/falx/falx.toml's iface= and mode= to match the operator's NIC.
# Skipped when stdin is not a tty (CI / piped input) so non-interactive
# deploys reuse whatever is in the existing falx.toml.
step "Interface & XDP mode"
FALX_CONF=/etc/falx/falx.toml
if [[ ! -f "$FALX_CONF" ]]; then
    warn "$FALX_CONF missing — interface prompt skipped (will be created on first daemon start with defaults)"
elif [[ ! -t 0 || ! -t 1 ]]; then
    info "Non-interactive run — leaving $FALX_CONF unchanged"
    info "  To set iface/mode manually: edit $FALX_CONF before 'systemctl start falxd'"
else
    CURRENT_IFACE=$(grep -E '^iface[[:space:]]*=' "$FALX_CONF" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    CURRENT_MODE=$(grep -E '^mode[[:space:]]*='  "$FALX_CONF" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    AVAIL_IFACES=$(ip -br link show 2>/dev/null | awk '$1 != "lo" {print $1}' | sed 's/@.*//' | tr '\n' ' ')

    info "Detected interfaces: ${AVAIL_IFACES:-<none>}"
    info "Current config:      iface=$CURRENT_IFACE  mode=$CURRENT_MODE"
    read -rp "  Network interface for XDP attach [$CURRENT_IFACE]: " NEW_IFACE
    NEW_IFACE=${NEW_IFACE:-$CURRENT_IFACE}
    if ! ip link show "$NEW_IFACE" >/dev/null 2>&1; then
        warn "Interface '$NEW_IFACE' not found on this host — keeping '$CURRENT_IFACE'"
        NEW_IFACE=$CURRENT_IFACE
    fi

    read -rp "  XDP mode (native/skb/offload) [$CURRENT_MODE]: " NEW_MODE
    NEW_MODE=${NEW_MODE:-$CURRENT_MODE}
    case "$NEW_MODE" in
        native|skb|offload) ;;
        *) warn "Invalid mode '$NEW_MODE' — keeping '$CURRENT_MODE'"; NEW_MODE=$CURRENT_MODE ;;
    esac

    if [[ "$NEW_IFACE" != "$CURRENT_IFACE" || "$NEW_MODE" != "$CURRENT_MODE" ]]; then
        # sed -i.bak leaves a .bak alongside the patched file for one-step rollback.
        sed -i.bak \
            -e "s|^iface[[:space:]]*=[[:space:]]*\"[^\"]*\"|iface     = \"$NEW_IFACE\"|" \
            -e "s|^mode[[:space:]]*=[[:space:]]*\"[^\"]*\"|mode = \"$NEW_MODE\"|"  \
            "$FALX_CONF"
        ok "Patched $FALX_CONF: iface=$NEW_IFACE  mode=$NEW_MODE  (backup: ${FALX_CONF}.bak)"
    else
        info "$FALX_CONF unchanged"
    fi
fi

# ─── 5. Atomic Switchover ─────────────────────────────────────────────────────
step "Switchover"
PREV_REL=""
[[ -L /opt/falx/current ]] && PREV_REL=$(readlink /opt/falx/current)

for bin in falxd falx-soc falx-ai; do
    [[ -f "$REL/bin/$bin" ]] && \
        cp "/usr/local/bin/$bin" "/usr/local/bin/$bin.prev" 2>/dev/null || true
    [[ -f "$REL/bin/$bin" ]] && install -m755 "$REL/bin/$bin" "/usr/local/bin/$bin"
done
[[ -d "$REL/dashboard" ]] && cp -r "$REL/dashboard/." /etc/falx/dashboard/

# Install systemd units
for svc in falxd.service falx-soc.service falx-ai.service; do
    [[ -f "$SCRIPT_DIR/$svc" && ! -f "/etc/systemd/system/$svc" ]] && \
        install -m644 "$SCRIPT_DIR/$svc" "/etc/systemd/system/$svc" && info "Installed: $svc"
done
systemctl daemon-reload

ln -sfn "$REL" /opt/falx/current
ok "Current → $VERSION"

# ─── 6. Service Restart ───────────────────────────────────────────────────────
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
sleep 3

# ─── 7. Health Check ──────────────────────────────────────────────────────────
step "Health Check"
for i in $(seq 1 10); do
    if curl -sf http://localhost:8080/healthz >/dev/null 2>&1; then
        ok "SOC backend healthy"; break
    fi
    info "Waiting ($i/10)..."; sleep 3
    if [[ $i -eq 10 ]]; then
        warn "Health check failed — rolling back..."
        [[ -n "$PREV_REL" ]] && ln -sfn "$PREV_REL" /opt/falx/current && \
            systemctl restart falxd falx-soc 2>/dev/null || true
        fail "Deploy failed. Logs: journalctl -u falxd -n 50"
    fi
done

# ─── 8. Cleanup ───────────────────────────────────────────────────────────────
ls -1t /opt/falx/releases/ | tail -n +6 | while read r; do
    rm -rf "/opt/falx/releases/$r" && info "Removed old release: $r"
done

# ─── Done ─────────────────────────────────────────────────────────────────────
echo -e "\n${B}${G}══ DEPLOY SUCCESS ══${N}"
echo -e "  Version:   ${G}$VERSION${N} ($DEPLOY_ENV)"
echo -e "  Dashboard: ${C}https://soc.falx.local${N}"
echo -e "  Health:    ${C}http://localhost:8080/healthz${N}"
echo -e "  Metrics:   ${C}http://localhost:9090/metrics${N}"
echo -e "  Rollback:  sudo bash scripts/deploy.sh --rollback\n"
