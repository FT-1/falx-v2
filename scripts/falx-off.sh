#!/usr/bin/env bash
# =============================================================================
# Project: FALX V2  |  Lead Architect & Owner: FT-1
# Description: Full FALX teardown — detach XDP, kill daemons, clean BPF maps,
#              bounce the NIC so networking is fully restored.
#
#   Usage:  sudo bash scripts/falx-off.sh [--iface <NIC>] [--no-bounce]
#
#   --iface <NIC>   Override the interface to detach XDP from.
#                   Default: auto-detected from falx.toml → ip route fallback.
#   --no-bounce     Skip the NIC down/up cycle (useful on remote servers where
#                   a bounce may briefly drop the SSH session).
# =============================================================================

set -uo pipefail

# ─── Terminal colors ──────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m'
B='\033[1m' N='\033[0m'

step()  { echo -e "\n${B}${C}  ──────  $*  ──────${N}"; }
ok()    { echo -e "  ${G}[  OK ]${N}  $*"; }
warn()  { echo -e "  ${Y}[ WARN]${N}  $*"; }
info()  { echo -e "  ${C}[INFO ]${N}  $*"; }

[[ $EUID -ne 0 ]] && { echo -e "${R}Run as root:${N}  sudo bash scripts/falx-off.sh"; exit 1; }

# ─── Args ─────────────────────────────────────────────────────────────────────
IFACE_OVERRIDE=""
NO_BOUNCE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface)    IFACE_OVERRIDE="$2"; shift 2 ;;
        --iface=*)  IFACE_OVERRIDE="${1#*=}"; shift ;;
        --no-bounce) NO_BOUNCE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ─── Resolve NIC ──────────────────────────────────────────────────────────────
FALX_CONF="${FALX_CONF:-/etc/falx/falx.toml}"

if [[ -n "$IFACE_OVERRIDE" ]]; then
    IFACE="$IFACE_OVERRIDE"
elif [[ -f "$FALX_CONF" ]]; then
    IFACE=$(grep -E '^iface[[:space:]]*=' "$FALX_CONF" 2>/dev/null | head -1 \
            | sed -E 's/.*"([^"]+)".*/\1/' || true)
    IFACE="${IFACE:-}"
fi

if [[ -z "${IFACE:-}" ]]; then
    IFACE=$(ip route get 8.8.8.8 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}')
fi
IFACE="${IFACE:-eth0}"

echo -e "\n${B}  FALX V2  —  Full Teardown${N}  (interface: ${B}${IFACE}${N})\n"

# ─── 1. Kill FALX daemons ─────────────────────────────────────────────────────
step "Stopping FALX daemons"

for proc in falxd falx-soc falx-user falx-ai; do
    if pgrep -x "$proc" >/dev/null 2>&1; then
        kill -9 $(pgrep -x "$proc") 2>/dev/null || true
        ok "Killed $proc"
    else
        info "$proc not running"
    fi
done

# Give OS a moment to release file descriptors / BPF references
sleep 0.5

# ─── 2. Detach XDP program ───────────────────────────────────────────────────
step "Detaching XDP from ${IFACE}"

if ip link show "$IFACE" >/dev/null 2>&1; then
    # Try native mode first, then skb — both are no-ops if nothing is attached
    ip link set dev "$IFACE" xdp off 2>/dev/null || true
    ip link set dev "$IFACE" xdpoffload off 2>/dev/null || true
    ok "XDP detached from ${IFACE}"
else
    warn "Interface ${IFACE} not found — skipping XDP detach"
fi

# ─── 3. Clean pinned BPF maps ────────────────────────────────────────────────
step "Cleaning pinned BPF maps"

BPF_PIN_DIR="/sys/fs/bpf/falx"
if [[ -d "$BPF_PIN_DIR" ]]; then
    # Remove files first, then the directory (rmdir is safer than rm -rf on bpffs)
    find "$BPF_PIN_DIR" -type f -delete 2>/dev/null || true
    find "$BPF_PIN_DIR" -mindepth 1 -type d | sort -r | xargs rmdir 2>/dev/null || true
    rmdir "$BPF_PIN_DIR" 2>/dev/null || true
    ok "Removed ${BPF_PIN_DIR}"
else
    info "${BPF_PIN_DIR} already absent"
fi

# ─── 4. Bounce NIC ───────────────────────────────────────────────────────────
step "Restoring network interface"

if [[ "$NO_BOUNCE" == true ]]; then
    warn "Skipping NIC bounce (--no-bounce). Run manually if traffic is still blocked:"
    warn "  sudo ip link set dev ${IFACE} down && sudo ip link set dev ${IFACE} up"
else
    if ip link show "$IFACE" >/dev/null 2>&1; then
        ip link set dev "$IFACE" down
        sleep 0.3
        ip link set dev "$IFACE" up
        ok "NIC ${IFACE} bounced"

        # Re-acquire an IP so the internet comes back with no extra commands.
        # Try the available DHCP mechanism in order of preference.
        if command -v dhclient >/dev/null 2>&1; then
            dhclient -r "$IFACE" 2>/dev/null || true   # release any stale lease
            dhclient "$IFACE"    2>/dev/null || true
            ok "DHCP lease renewed via dhclient"
        elif command -v dhcpcd >/dev/null 2>&1; then
            dhcpcd -n "$IFACE" 2>/dev/null || true
            ok "DHCP lease renewed via dhcpcd"
        elif command -v nmcli >/dev/null 2>&1; then
            nmcli device connect "$IFACE" 2>/dev/null || true
            ok "Interface reconnected via NetworkManager"
        elif command -v networkctl >/dev/null 2>&1; then
            networkctl reconfigure "$IFACE" 2>/dev/null || true
            ok "Interface reconfigured via systemd-networkd"
        else
            warn "No DHCP client found — run manually if offline:  sudo dhclient ${IFACE}"
        fi

        # Wait briefly for an IPv4 address to confirm connectivity is back.
        for _ in 1 2 3 4 5 6; do
            CUR_IP=$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
            [[ -n "$CUR_IP" ]] && break
            sleep 0.5
        done
        if [[ -n "${CUR_IP:-}" ]]; then
            ok "Networking restored — ${IFACE} has IP ${B}${CUR_IP}${N}"
        else
            warn "${IFACE} has no IPv4 yet — give it a few seconds or check your DHCP server"
        fi
    else
        warn "Interface ${IFACE} not found — skipping bounce"
    fi
fi

echo -e "\n${G}${B}  FALX fully stopped. XDP detached. BPF maps cleared. Internet restored.${N}\n"
