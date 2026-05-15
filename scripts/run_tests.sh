#!/usr/bin/env bash
# =============================================================================
# Project: FALX V2
# Lead Architect & Owner: FT-1
# Description: Test runner (scripts/run_tests.sh).
#              Runs all unit tests, integration tests, and benchmarks
#              across all FALX V2 subsystems. Generates coverage report.
#              Usage: bash scripts/run_tests.sh [--bench] [--cover] [--race]
# =============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
CP_DIR="$ROOT_DIR/control-plane"
RUST_USER="$ROOT_DIR/ebpf-user"

# ─── Parse flags ──────────────────────────────────────────────────────────────
RUN_BENCH=false
RUN_COVER=false
RUN_RACE=false
VERBOSE=false

for arg in "$@"; do
    case $arg in
        --bench)  RUN_BENCH=true ;;
        --cover)  RUN_COVER=true ;;
        --race)   RUN_RACE=true  ;;
        -v|--verbose) VERBOSE=true ;;
    esac
done

# ─── Colors ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

log_step()  { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }
log_ok()    { echo -e "${GREEN}[PASS]${RESET} $*"; }
log_fail()  { echo -e "${RED}[FAIL]${RESET} $*"; }
log_info()  { echo -e "${CYAN}[INFO]${RESET} $*"; }
log_bench() { echo -e "${YELLOW}[BENCH]${RESET} $*"; }

PASS=0; FAIL=0

run_test() {
    local name="$1"; shift
    if "$@" 2>&1; then
        log_ok "$name"
        ((PASS++))
    else
        log_fail "$name"
        ((FAIL++))
    fi
}

# ─── Go Build Flags ───────────────────────────────────────────────────────────
GO_FLAGS="-timeout 120s"
[[ "$VERBOSE"   == true ]] && GO_FLAGS="$GO_FLAGS -v"
[[ "$RUN_RACE"  == true ]] && GO_FLAGS="$GO_FLAGS -race"

COVER_FLAGS=""
if [[ "$RUN_COVER" == true ]]; then
    COVER_DIR="$ROOT_DIR/build/coverage"
    mkdir -p "$COVER_DIR"
    COVER_FLAGS="-coverprofile=$COVER_DIR/coverage.out -covermode=atomic"
fi

# ─── Go Tests ─────────────────────────────────────────────────────────────────
log_step "Go Tests — Control Plane"

PACKAGES=(
    "./internal/auth/..."
    "./internal/events/..."
    "./internal/policy/..."
    "./internal/bpfmaps/..."
    "./internal/metrics/..."
    "./internal/failsafe/..."
    "./internal/notifications/..."
)

for pkg in "${PACKAGES[@]}"; do
    pkg_name=$(echo "$pkg" | sed 's|./internal/||;s|/\.\.\.$||')
    run_test "Go: $pkg_name" \
        go test $GO_FLAGS $COVER_FLAGS \
        -count=1 \
        "$pkg" \
        2>/dev/null || true
done

# ─── Coverage Report ──────────────────────────────────────────────────────────
if [[ "$RUN_COVER" == true && -f "$COVER_DIR/coverage.out" ]]; then
    log_step "Coverage Report"
    go tool cover -func="$COVER_DIR/coverage.out" | tail -1
    go tool cover -html="$COVER_DIR/coverage.out" \
        -o "$COVER_DIR/coverage.html" 2>/dev/null || true
    log_ok "Coverage HTML: $COVER_DIR/coverage.html"
fi

# ─── Rust Tests ───────────────────────────────────────────────────────────────
log_step "Rust Tests — ebpf-user"
if command -v cargo &>/dev/null; then
    run_test "Rust: ABI size checks" \
        bash -c "cd '$RUST_USER' && cargo test --lib abi_tests 2>&1"
    run_test "Rust: unit tests" \
        bash -c "cd '$RUST_USER' && cargo test 2>&1"
else
    log_info "cargo not found — skipping Rust tests"
fi

# ─── Benchmarks ───────────────────────────────────────────────────────────────
if [[ "$RUN_BENCH" == true ]]; then
    log_step "Benchmarks"
    BENCH_PACKAGES=(
        "./internal/auth/..."
        "./internal/events/..."
        "./internal/policy/..."
        "./internal/bpfmaps/..."
    )
    for pkg in "${BENCH_PACKAGES[@]}"; do
        pkg_name=$(echo "$pkg" | sed 's|./internal/||;s|/\.\.\.$||')
        log_bench "Benchmarking: $pkg_name"
        go test $GO_FLAGS \
            -bench=. \
            -benchmem \
            -benchtime=3s \
            -run='^$' \
            "$pkg" 2>/dev/null || true
    done
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════${RESET}"
echo -e "  Tests: ${GREEN}${PASS} passed${RESET} / ${RED}${FAIL} failed${RESET}"
echo -e "${BOLD}═══════════════════════════════════════${RESET}"

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}Some tests FAILED${RESET}"
    exit 1
else
    echo -e "${GREEN}All tests PASSED${RESET}"
    exit 0
fi
