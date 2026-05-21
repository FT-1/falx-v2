#!/usr/bin/env bash
# =============================================================================
# Project: FALX V2  |  Lead Architect & Owner: FT-1
# Description: Bootstrap entrypoint. This is the SINGLE command you run on a
#              fresh machine after cloning the repo. It hands off to
#              falx-install.sh, which installs every dependency (Go, Python3,
#              Rust + bpf-linker, clang/libbpf, …), builds all components, and
#              links the 4 global commands:
#
#                  falx-install · falx-on · falx-off · falx-remove
#
#   Run once (does everything):
#     sudo bash scripts/install-commands.sh
#
#   Just (re)link the commands without rebuilding:
#     sudo bash scripts/install-commands.sh --link-only
#
#   Uninstall everything:
#     sudo bash scripts/install-commands.sh --uninstall   (→ falx-remove.sh)
# =============================================================================

set -uo pipefail

R='\033[0;31m' N='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ $EUID -ne 0 ]] && { echo -e "${R}Run as root:${N}  sudo bash scripts/install-commands.sh"; exit 1; }

# --uninstall is a friendly alias for the full remover.
if [[ "${1:-}" == "--uninstall" ]]; then
    exec bash "${SCRIPT_DIR}/falx-remove.sh" "${@:2}"
fi

# Everything else (full install, or --link-only / --no-deps) is handled by the
# installer, which is also the global `falx-install` command.
exec bash "${SCRIPT_DIR}/falx-install.sh" "$@"
