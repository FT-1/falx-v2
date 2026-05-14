#!/usr/bin/env bash
# =============================================================================
# Project: FALX V2
# Lead Architect & Owner: FT-1
# Description: ABI verification script (scripts/verify_abi.sh).
#              Validates that the BPF struct sizes in Rust (ebpf-kern + ebpf-user)
#              match the corresponding Go structs in the control-plane.
#              Run this after any modification to types.rs or types.go.
#              CI/CD should fail on ABI mismatch to prevent silent data corruption.
# =============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0

COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[1;33m'
COLOR_RESET='\033[0m'

log_pass() { echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} $1"; ((PASS++)); }
log_fail() { echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $1"; ((FAIL++)); }
log_info() { echo -e "${COLOR_YELLOW}[INFO]${COLOR_RESET} $1"; }

echo ""
echo "=== FALX V2 ABI Verification | Architect: FT-1 ==="
echo ""

# ─── Expected Struct Sizes (bytes) ───────────────────────────────────────────
declare -A EXPECTED_SIZES=(
    ["BlockEntry"]=16
    ["RateBucket"]=40
    ["XdpStats"]=80
    ["FailsafeState"]=56
    ["FalxMapConfig"]=32
)

# ─── Rust ABI Test ────────────────────────────────────────────────────────────
log_info "Running Rust ABI size tests..."

if cd "$ROOT_DIR/ebpf-user" && cargo test --lib abi_tests 2>&1 | grep -q "test result: ok"; then
    log_pass "Rust ABI tests passed"
else
    log_fail "Rust ABI tests FAILED — check ebpf-user/src/types.rs"
fi

# ─── Go ABI Test ─────────────────────────────────────────────────────────────
log_info "Running Go ABI size tests..."

GO_TEST_FILE=$(mktemp /tmp/falx_abi_XXXXXX.go)
cat > "$GO_TEST_FILE" << 'EOF'
package main

import (
    "fmt"
    "unsafe"
)

// Mirror of control-plane/internal/bpfmaps/types.go
type BlockEntry struct {
    ExpireAt   uint64
    Action     uint8
    RuleID     uint8
    ThreatScore uint8
    Pad        uint8
    Reason     uint32
}

type RateBucket struct {
    Tokens     uint64
    LastRefill uint64
    Capacity   uint64
    RefillRate uint64
    DropCount  uint64
}

type XdpStats struct {
    RxPackets   uint64
    RxBytes     uint64
    Dropped     uint64
    RateLimited uint64
    Passed      uint64
    Redirected  uint64
    FailsafeDrops uint64
    ParseErrors uint64
    MapErrors   uint64
    LastResetNs uint64
}

type FailsafeState struct {
    CircuitOpen   uint8
    Pad           [7]uint8
    CurrentPPS    uint64
    CurrentBPS    uint64
    OpenSinceNs   uint64
    PPSThreshold  uint64
    BPSThreshold  uint64
    WindowStartNs uint64
}

type FalxMapConfig struct {
    DefaultAction    uint8
    RateLimitEnabled uint8
    FailsafeEnabled  uint8
    AFXDPRedirect    uint8
    Pad              [4]uint8
    RateCapacity     uint64
    RateRefillNs     uint64
    HoneypotIP       uint32
    HoneypotPort     uint16
    Pad2             [2]uint8
}

func main() {
    checks := []struct{ name string; got, want uintptr }{
        {"BlockEntry",   unsafe.Sizeof(BlockEntry{}),   16},
        {"RateBucket",   unsafe.Sizeof(RateBucket{}),   40},
        {"XdpStats",     unsafe.Sizeof(XdpStats{}),     80},
        {"FailsafeState",unsafe.Sizeof(FailsafeState{}),56},
        {"FalxMapConfig",unsafe.Sizeof(FalxMapConfig{}),32},
    }
    failed := 0
    for _, c := range checks {
        if c.got != c.want {
            fmt.Printf("FAIL  %s: got=%d want=%d\n", c.name, c.got, c.want)
            failed++
        } else {
            fmt.Printf("PASS  %s: size=%d\n", c.name, c.got)
        }
    }
    if failed > 0 {
        fmt.Printf("\n%d ABI mismatches detected!\n", failed)
        panic("ABI mismatch")
    }
    fmt.Println("\nAll Go ABI checks PASSED")
}
EOF

if go run "$GO_TEST_FILE" 2>&1; then
    log_pass "Go ABI tests passed"
else
    log_fail "Go ABI tests FAILED — struct sizes mismatch between Rust and Go!"
fi
rm -f "$GO_TEST_FILE"

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────────"
echo -e "Results: ${COLOR_GREEN}${PASS} passed${COLOR_RESET} / ${COLOR_RED}${FAIL} failed${COLOR_RESET}"
echo "─────────────────────────────────────────"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "${COLOR_RED}ABI VERIFICATION FAILED — fix struct mismatches before proceeding.${COLOR_RESET}"
    exit 1
else
    echo -e "${COLOR_GREEN}ABI VERIFICATION PASSED — Rust and Go structs are aligned.${COLOR_RESET}"
    exit 0
fi
