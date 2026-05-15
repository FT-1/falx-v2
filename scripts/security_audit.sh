#!/usr/bin/env bash
# =============================================================================
# Project: FALX V2
# Lead Architect & Owner: FT-1
# Description: Security audit script (scripts/security_audit.sh).
#              Validates the security posture of a FALX V2 deployment.
#              Run before going to production: sudo bash scripts/security_audit.sh
# =============================================================================

set -euo pipefail

R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m' B='\033[1m' N='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${G}[PASS]${N} $*"; ((PASS++)); }
warn()  { echo -e "${Y}[WARN]${N} $*"; ((WARN++)); }
fail()  { echo -e "${R}[FAIL]${N} $*"; ((FAIL++)); }
check() { echo -e "\n${B}── $* ──${N}"; }

echo -e "\n${B}${C}FALX V2 Security Audit | Architect: FT-1${N}\n"

# ─── 1. File Permissions ──────────────────────────────────────────────────────
check "File Permissions"

for f in /etc/falx/falx.toml /etc/falx/honeypot.toml /etc/falx/notifications.toml; do
    if [[ -f "$f" ]]; then
        perms=$(stat -c "%a" "$f")
        if [[ "$perms" =~ ^6[04][04]$ ]]; then
            pass "$f: $perms (owner read-only)"
        else
            warn "$f: $perms (should be 640 or 600)"
        fi
    fi
done

for f in /etc/falx/keys/jwt_private.pem; do
    if [[ -f "$f" ]]; then
        perms=$(stat -c "%a" "$f")
        if [[ "$perms" == "600" ]]; then
            pass "$f: 600 (owner-only)"
        else
            fail "$f: $perms (MUST be 600 — private key exposed!)"
        fi
    fi
done

for f in /var/lib/falx/auth.db /var/lib/falx/policy.db; do
    if [[ -f "$f" ]]; then
        perms=$(stat -c "%a" "$f")
        if [[ "$perms" =~ ^6 ]]; then
            pass "$f: $perms"
        else
            warn "$f: $perms (should be 600 or 640)"
        fi
    fi
done

# ─── 2. BPF Map Security ──────────────────────────────────────────────────────
check "BPF Map Security"

if [[ -d /sys/fs/bpf/falx ]]; then
    pass "BPF pin directory exists: /sys/fs/bpf/falx"
    for map in blocklist_v4 blocklist_v6 config failsafe_state; do
        if [[ -f "/sys/fs/bpf/falx/$map" ]]; then
            pass "BPF map pinned: $map"
        else
            warn "BPF map not pinned: $map (falxd may not be running)"
        fi
    done
else
    warn "BPF pin directory missing — is falxd running?"
fi

# Check BPF JIT hardening
if [[ -f /proc/sys/net/core/bpf_jit_harden ]]; then
    jit_harden=$(cat /proc/sys/net/core/bpf_jit_harden)
    if [[ "$jit_harden" -ge 1 ]]; then
        pass "BPF JIT hardening enabled (level=$jit_harden)"
    else
        warn "BPF JIT hardening disabled — enable: sysctl net.core.bpf_jit_harden=1"
    fi
fi

# ─── 3. Network Security ──────────────────────────────────────────────────────
check "Network Security"

# Check if SOC backend is binding to all interfaces unnecessarily
if ss -tlnp 2>/dev/null | grep -q ":8080.*0.0.0.0"; then
    warn "SOC backend binding to 0.0.0.0:8080 — consider binding to 127.0.0.1 behind nginx"
else
    pass "SOC backend network binding OK"
fi

# Check nginx TLS
if command -v nginx &>/dev/null; then
    if nginx -t 2>/dev/null; then
        pass "Nginx config valid"
    else
        fail "Nginx config invalid"
    fi
fi

# Check open ports
EXPECTED_PORTS=(8080 50051 50052 9090)
for port in "${EXPECTED_PORTS[@]}"; do
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        pass "Port $port listening"
    fi
done

# ─── 4. Authentication Configuration ─────────────────────────────────────────
check "Authentication Configuration"

# Check JWT key length
if [[ -f /etc/falx/keys/jwt_private.pem ]]; then
    key_bits=$(openssl rsa -in /etc/falx/keys/jwt_private.pem -text -noout 2>/dev/null \
        | grep "Private-Key" | grep -o "[0-9]*" | head -1)
    if [[ "${key_bits:-0}" -ge 4096 ]]; then
        pass "JWT RSA key: ${key_bits} bits (strong)"
    elif [[ "${key_bits:-0}" -ge 2048 ]]; then
        warn "JWT RSA key: ${key_bits} bits (minimum — upgrade to 4096)"
    else
        fail "JWT RSA key: ${key_bits} bits (too weak!)"
    fi
fi

# Check default admin password
if command -v sqlite3 &>/dev/null && [[ -f /var/lib/falx/auth.db ]]; then
    admin_locked=$(sqlite3 /var/lib/falx/auth.db \
        "SELECT locked FROM users WHERE username='admin' LIMIT 1;" 2>/dev/null || echo "unknown")
    if [[ "$admin_locked" == "0" ]]; then
        warn "Default 'admin' account is active — ensure password has been changed"
    fi
fi

# ─── 5. systemd Service Hardening ─────────────────────────────────────────────
check "systemd Service Hardening"

for svc in falxd falx-soc; do
    if systemctl is-enabled "$svc" &>/dev/null; then
        # Check critical hardening options
        unit_file=$(systemctl show -p FragmentPath "$svc" 2>/dev/null | cut -d= -f2)
        if [[ -f "$unit_file" ]]; then
            grep -q "NoNewPrivileges"     "$unit_file" && pass "$svc: NoNewPrivileges" || warn "$svc: NoNewPrivileges missing"
            grep -q "ProtectSystem"       "$unit_file" && pass "$svc: ProtectSystem"   || warn "$svc: ProtectSystem missing"
            grep -q "PrivateTmp"          "$unit_file" && pass "$svc: PrivateTmp"      || warn "$svc: PrivateTmp missing"
        fi
    else
        warn "Service $svc not enabled"
    fi
done

# ─── 6. Kernel Parameters ─────────────────────────────────────────────────────
check "Kernel Security Parameters"

declare -A KERNEL_CHECKS=(
    ["net.core.bpf_jit_enable"]="1"
    ["net.core.bpf_jit_harden"]="1"
)

for param in "${!KERNEL_CHECKS[@]}"; do
    expected="${KERNEL_CHECKS[$param]}"
    actual=$(sysctl -n "$param" 2>/dev/null || echo "unavailable")
    if [[ "$actual" == "$expected" ]]; then
        pass "$param = $actual"
    else
        warn "$param = $actual (expected $expected)"
    fi
done

# ─── 7. Audit Log ─────────────────────────────────────────────────────────────
check "Audit Logging"

AUDIT_LOG="/var/log/falx/audit.jsonl"
if [[ -f "$AUDIT_LOG" ]]; then
    lines=$(wc -l < "$AUDIT_LOG")
    perms=$(stat -c "%a" "$AUDIT_LOG")
    pass "Audit log exists: $AUDIT_LOG ($lines entries, perms=$perms)"
    if [[ "$perms" != "600" && "$perms" != "640" ]]; then
        warn "Audit log permissions $perms — should be 600 or 640"
    fi
else
    warn "Audit log not found: $AUDIT_LOG (is falxd running?)"
fi

# ─── 8. TLS Certificate ───────────────────────────────────────────────────────
check "TLS Certificate"

TLS_CERT="/etc/falx/tls/server.crt"
if [[ -f "$TLS_CERT" ]]; then
    expiry=$(openssl x509 -enddate -noout -in "$TLS_CERT" 2>/dev/null | cut -d= -f2)
    expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
    now_ts=$(date +%s)
    days_left=$(( (expiry_ts - now_ts) / 86400 ))
    if [[ $days_left -gt 30 ]]; then
        pass "TLS cert valid for $days_left days (expires: $expiry)"
    elif [[ $days_left -gt 0 ]]; then
        warn "TLS cert expires in $days_left days — renew soon!"
    else
        fail "TLS cert EXPIRED ($expiry)"
    fi
else
    warn "TLS certificate not found at $TLS_CERT — set up TLS before production"
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${B}════════════════════════════════════════${N}"
echo -e "  ${G}PASS: $PASS${N}   ${Y}WARN: $WARN${N}   ${R}FAIL: $FAIL${N}"
echo -e "${B}════════════════════════════════════════${N}"

SCORE=$(( PASS * 100 / (PASS + WARN + FAIL) ))
if   [[ $FAIL -gt 0 ]];    then echo -e "${R}Security posture: CRITICAL ($SCORE%)${N}"
elif [[ $WARN -gt 5 ]];    then echo -e "${Y}Security posture: NEEDS ATTENTION ($SCORE%)${N}"
elif [[ $WARN -gt 0 ]];    then echo -e "${Y}Security posture: GOOD ($SCORE%) — fix warnings${N}"
else                             echo -e "${G}Security posture: EXCELLENT ($SCORE%)${N}"; fi
echo ""
