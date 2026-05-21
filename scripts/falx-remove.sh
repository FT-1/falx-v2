#!/usr/bin/env bash
# =============================================================================
# Project: FALX V2  |  Lead Architect & Owner: FT-1
# Description: falx-remove — full uninstall. Returns the server to a clean state:
#                1. Stops everything cleanly (delegates to falx-off: kill -9,
#                   detach XDP, clean bpffs, restore networking).
#                2. Removes the 4 global commands from /usr/local/bin.
#                3. Removes installed binaries + systemd units (if deploy.sh ran).
#                4. Deletes runtime state: /var/lib/falx (DATABASES), logs,
#                   /etc/falx, /opt/falx, /run/falx, sysctl + fstab entries.
#
#   The git source tree you are standing in is NOT deleted — only installed
#   system artifacts are removed.
#
#   Usage:
#     sudo bash scripts/falx-remove.sh           # asks for confirmation
#     sudo bash scripts/falx-remove.sh --yes     # non-interactive
#     sudo bash scripts/falx-remove.sh --keep-db # remove all EXCEPT databases
# =============================================================================

set -uo pipefail

R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m' B='\033[1m' N='\033[0m'
step()  { echo -e "\n${B}${C}  ══════  $*  ══════${N}"; }
info()  { echo -e "  ${C}[INFO]${N}   $*"; }
ok()    { echo -e "  ${G}[  OK ]${N}  $*"; }
warn()  { echo -e "  ${Y}[ WARN]${N}  $*"; }

[[ $EUID -ne 0 ]] && { echo -e "${R}Run as root:${N}  sudo bash scripts/falx-remove.sh"; exit 1; }

ASSUME_YES=false
KEEP_DB=false
for a in "$@"; do case "$a" in
    --yes|-y)  ASSUME_YES=true ;;
    --keep-db) KEEP_DB=true ;;
    *) echo "Unknown option: $a"; exit 1 ;;
esac done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="/usr/local/bin"

echo -e "\n${B}${R}  FALX V2 — Full Uninstall${N}"
echo -e "  This stops all services, detaches XDP, removes the global commands,"
echo -e "  systemd units, and ${B}deletes /var/lib/falx (databases & users)${N}."
echo -e "  The source repo at ${REPO_ROOT} is left untouched."

if [[ "$ASSUME_YES" != true ]]; then
    echo ""
    read -rp "  Type ${B}REMOVE${N} to confirm full uninstall: " CONFIRM
    [[ "$CONFIRM" == "REMOVE" ]] || { echo -e "  ${Y}Aborted — nothing changed.${N}\n"; exit 0; }
fi

# ─── 1. Stop everything cleanly (reuse falx-off) ─────────────────────────────
step "Stopping FALX and restoring networking"
if [[ -f "${SCRIPT_DIR}/falx-off.sh" ]]; then
    bash "${SCRIPT_DIR}/falx-off.sh" || warn "falx-off reported issues — continuing teardown"
else
    # Fallback: kill directly if falx-off.sh is gone.
    for p in falx-soc falxd falx-user falx-ai; do
        pgrep -x "$p" >/dev/null 2>&1 && kill -9 "$(pgrep -x "$p")" 2>/dev/null || true
    done
    warn "falx-off.sh not found — killed processes directly (XDP/NIC not restored)"
fi

# ─── 2. systemd units ─────────────────────────────────────────────────────────
step "Removing systemd units"
UNITS=(falxd.service falx-soc.service falx-user.service falx-ai.service)
removed_unit=false
for u in "${UNITS[@]}"; do
    if [[ -f "/etc/systemd/system/$u" ]]; then
        systemctl disable --now "$u" 2>/dev/null || true
        rm -f "/etc/systemd/system/$u"
        removed_unit=true
        ok "Removed unit: $u"
    fi
done
$removed_unit && systemctl daemon-reload 2>/dev/null || info "No systemd units installed"

# ─── 3. Global commands + installed binaries ─────────────────────────────────
step "Removing global commands and binaries"
for c in falx-install falx-on falx-off falx-remove; do
    [[ -e "${BIN_DIR}/${c}" ]] && rm -f "${BIN_DIR}/${c}" && ok "Unlinked ${c}"
done
for binf in falxd falx-soc falx-user falx-ai falxd.prev falx-soc.prev falx-user.prev falx-ai.prev; do
    [[ -e "${BIN_DIR}/${binf}" ]] && rm -f "${BIN_DIR}/${binf}" && info "Removed ${BIN_DIR}/${binf}"
done

# ─── 4. Runtime state, configs, logs ─────────────────────────────────────────
step "Cleaning runtime state"
TARGETS=(/var/log/falx /run/falx /etc/falx /opt/falx /opt/falx-src)
if [[ "$KEEP_DB" == true ]]; then
    info "--keep-db: preserving /var/lib/falx (databases)"
else
    TARGETS+=(/var/lib/falx)
fi
for d in "${TARGETS[@]}"; do
    [[ -e "$d" ]] && rm -rf "$d" && ok "Removed $d"
done

# Kernel tuning + bpffs fstab entry added by the installer.
[[ -f /etc/sysctl.d/99-falx.conf ]] && rm -f /etc/sysctl.d/99-falx.conf && ok "Removed sysctl tuning"
if grep -q '/sys/fs/bpf' /etc/fstab 2>/dev/null; then
    sed -i.bak '/bpf \/sys\/fs\/bpf bpf defaults 0 0/d' /etc/fstab 2>/dev/null \
        && ok "Removed bpffs fstab entry (backup: /etc/fstab.bak)" || true
fi

# Remove the pinned-map directory if anything survived the teardown.
[[ -d /sys/fs/bpf/falx ]] && { find /sys/fs/bpf/falx -type f -delete 2>/dev/null; rmdir /sys/fs/bpf/falx 2>/dev/null; } || true

echo ""
echo -e "${B}${G}  FALX V2 fully removed. Server is back to a clean state.${N}"
echo -e "  Source repo preserved at: ${B}${REPO_ROOT}${N}"
echo -e "  To reinstall:  ${C}sudo bash ${REPO_ROOT}/scripts/falx-install.sh${N}\n"
