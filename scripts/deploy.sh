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
# falx-user lives under build/user/, not dist/ — without this it never gets
# installed and falxd is left looking at a stale /usr/local/bin/falx-user (or
# nothing). That's why the loader hash on the running system could lag the
# source tree by an arbitrary amount.
FALX_USER_SRC="$ROOT_DIR/build/user/falx-user"
[[ -f "$FALX_USER_SRC" ]] && install -m755 "$FALX_USER_SRC" "$REL/bin/falx-user" && info "→ falx-user"
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
# NOTE: policy DB seeding moved to step 7b (after services start). The `rules`
# table is created by falxd's migrate() on startup, so seeding from this stage
# was always failing with "no such table: rules".

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

    # Auto-detect the NIC that carries the default route, with its IPv4 address.
    # `ip route get 8.8.8.8` resolves through the routing table even without any
    # external connectivity (it's a kernel-only operation, no packet sent), so it
    # works on disconnected lab VMs too.
    AUTODETECT_IFACE=$(ip route get 8.8.8.8 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
    AUTODETECT_IP=""
    if [[ -n "$AUTODETECT_IFACE" ]]; then
        AUTODETECT_IP=$(ip -4 -o addr show dev "$AUTODETECT_IFACE" 2>/dev/null \
            | awk '{print $4}' | cut -d/ -f1 | head -1)
    fi

    # Prompt default precedence:
    #   1. The interface already in falx.toml (operator's deliberate choice).
    #   2. The auto-detected default-route interface (sensible for fresh installs).
    #   3. Hard fallback "eth0" if neither is available.
    # The stock falx.toml ships with iface="eth0", so treat that as "not yet set"
    # and prefer auto-detection over the placeholder.
    if [[ -n "$CURRENT_IFACE" && "$CURRENT_IFACE" != "eth0" ]]; then
        DEFAULT_IFACE="$CURRENT_IFACE"
    else
        DEFAULT_IFACE="${AUTODETECT_IFACE:-eth0}"
    fi

    info "Available interfaces: ${AVAIL_IFACES:-<none>}"
    if [[ -n "$AUTODETECT_IFACE" ]]; then
        info "Default route via:    $AUTODETECT_IFACE${AUTODETECT_IP:+  (ip=$AUTODETECT_IP)}"
    fi
    info "Current config:       iface=$CURRENT_IFACE  mode=$CURRENT_MODE"
    read -rp "  Network interface for XDP attach [$DEFAULT_IFACE]: " NEW_IFACE
    NEW_IFACE=${NEW_IFACE:-$DEFAULT_IFACE}
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

for bin in falxd falx-user falx-soc falx-ai; do
    [[ -f "$REL/bin/$bin" ]] && \
        cp "/usr/local/bin/$bin" "/usr/local/bin/$bin.prev" 2>/dev/null || true
    [[ -f "$REL/bin/$bin" ]] && install -m755 "$REL/bin/$bin" "/usr/local/bin/$bin"
done
[[ -d "$REL/dashboard" ]] && cp -r "$REL/dashboard/." /etc/falx/dashboard/

# Install systemd units. falx-user.service MUST be installed too — falxd has
# Requires=falx-user.service and won't start without it.
# IMPORTANT: refresh unit files on every deploy (the `! -f` guard from the old
# version meant operators got stuck on the first-installed unit forever).
for svc in falx-user.service falxd.service falx-soc.service falx-ai.service; do
    if [[ -f "$SCRIPT_DIR/$svc" ]]; then
        install -m644 "$SCRIPT_DIR/$svc" "/etc/systemd/system/$svc" && info "Installed: $svc"
    fi
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

# ─── 7b. Seed default policy rules (after daemon migrate()) ───────────────────
# falxd creates the `rules` table on startup via policy.Engine.migrate(). We
# seed the default rules AFTER the health check passes so the table is
# guaranteed to exist. INSERT OR IGNORE in the SQL file makes re-runs a no-op.
if [[ -f "$ROOT_DIR/configs/default_policy_rules.sql" ]]; then
    step "Policy rules"
    SEEDED=false
    for attempt in 1 2 3 4 5; do
        if sqlite3 /var/lib/falx/policy.db < "$ROOT_DIR/configs/default_policy_rules.sql" 2>/dev/null; then
            ok "Default policy rules seeded (attempt $attempt)"
            SEEDED=true; break
        fi
        sleep 1
    done
    $SEEDED || warn "Default policy rules NOT seeded — falxd may still be migrating. \
Re-run manually: sudo sqlite3 /var/lib/falx/policy.db < configs/default_policy_rules.sql"
fi

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
