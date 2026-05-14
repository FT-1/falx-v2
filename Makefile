# =============================================================================
# Project: FALX V2
# Lead Architect & Owner: FT-1
# Description: Master Makefile - Orchestrates all build targets across all
#              subsystems (eBPF/Rust, Go, C++, Python). Single entry point
#              for the entire build pipeline.
# =============================================================================

# ─── Global Variables ────────────────────────────────────────────────────────
PROJECT_NAME    := falx-v2
VERSION         := 0.1.0
KERNEL_MIN      := 5.15

# Toolchain
CARGO           := cargo
GO              := go
CMAKE           := cmake
PYTHON          := python3
CLANG           := clang
LLC             := llc
RUSTUP          := rustup

# Directories
ROOT_DIR        := $(shell pwd)
BUILD_DIR       := $(ROOT_DIR)/build
DIST_DIR        := $(ROOT_DIR)/dist
EBPF_KERN_DIR   := $(ROOT_DIR)/ebpf-kern
EBPF_USER_DIR   := $(ROOT_DIR)/ebpf-user
CP_DIR          := $(ROOT_DIR)/control-plane
AI_DIR          := $(ROOT_DIR)/ai-inference
SOC_DIR         := $(ROOT_DIR)/soc-backend
SCRIPTS_DIR     := $(ROOT_DIR)/scripts
CONFIGS_DIR     := $(ROOT_DIR)/configs

# Build targets
FALXD_BIN       := $(DIST_DIR)/falxd
AI_BIN          := $(DIST_DIR)/falx-ai
SOC_BIN         := $(DIST_DIR)/falx-soc

# Colors for terminal output
RED             := \033[0;31m
GREEN           := \033[0;32m
YELLOW          := \033[1;33m
CYAN            := \033[0;36m
BOLD            := \033[1m
RESET           := \033[0m

# ─── Phony Targets ───────────────────────────────────────────────────────────
.PHONY: all clean deps check-deps \
        build-ebpf build-user build-control-plane build-ai build-soc \
        install uninstall \
        test test-ebpf test-go test-ai \
        lint lint-rust lint-go lint-cpp \
        fmt fmt-rust fmt-go \
        docker-build docker-push \
        release dev

# ─── Default Target ──────────────────────────────────────────────────────────
all: check-deps build-ebpf build-user build-control-plane build-ai build-soc
	@echo "$(GREEN)$(BOLD)[FALX V2] Full build complete. Version: $(VERSION)$(RESET)"

# ─── Development Target (faster rebuild) ─────────────────────────────────────
dev: build-ebpf build-user build-control-plane
	@echo "$(CYAN)[FALX V2] Dev build complete (AI/SOC skipped)$(RESET)"

# ─── Release Target ──────────────────────────────────────────────────────────
release: clean all
	@mkdir -p $(DIST_DIR)
	@echo "$(GREEN)[FALX V2] Release $(VERSION) packaged in $(DIST_DIR)$(RESET)"

# ─── Dependency Checking ─────────────────────────────────────────────────────
check-deps:
	@echo "$(CYAN)[FALX V2] Checking build dependencies...$(RESET)"
	@command -v $(CARGO)   >/dev/null 2>&1 || (echo "$(RED)[ERROR] cargo not found. Install Rust toolchain.$(RESET)"; exit 1)
	@command -v $(GO)      >/dev/null 2>&1 || (echo "$(RED)[ERROR] go not found. Install Go >= 1.22.$(RESET)"; exit 1)
	@command -v $(CLANG)   >/dev/null 2>&1 || (echo "$(RED)[ERROR] clang not found. Install LLVM/Clang.$(RESET)"; exit 1)
	@command -v $(CMAKE)   >/dev/null 2>&1 || (echo "$(RED)[ERROR] cmake not found. Install CMake >= 3.20.$(RESET)"; exit 1)
	@command -v $(PYTHON)  >/dev/null 2>&1 || (echo "$(RED)[ERROR] python3 not found.$(RESET)"; exit 1)
	@command -v bpftool    >/dev/null 2>&1 || (echo "$(YELLOW)[WARN] bpftool not found. Some features may be limited.$(RESET)")
	@$(RUSTUP) component list --toolchain nightly --installed | grep -q "rust-src" || \
		(echo "$(YELLOW)[INFO] Installing rust-src for nightly...$(RESET)" && \
		 $(RUSTUP) component add rust-src --toolchain nightly)
	@echo "$(GREEN)[INFO] bpfel-unknown-none is Tier 3 — no prebuilt artifacts.$(RESET)"
	@echo "$(GREEN)[INFO] Build uses -Z build-std=core (no rustup target add needed).$(RESET)"
	@echo "$(GREEN)[OK] All required dependencies found.$(RESET)"

# ─── Dependency Installation ─────────────────────────────────────────────────
deps: deps-rust deps-go deps-python
	@echo "$(GREEN)[FALX V2] All dependencies installed.$(RESET)"

deps-rust:
	@echo "$(CYAN)[RUST] Installing Rust dependencies...$(RESET)"
	@$(RUSTUP) toolchain install nightly --component rust-src
	@# bpfel-unknown-none is Tier 3 — no prebuilt artifacts in rustup.
	@# The build uses -Z build-std=core (builds core from source) so no
	@# rustup target add is needed. rust-src component (above) is sufficient.
	@cargo install bpf-linker 2>/dev/null || true

deps-go:
	@echo "$(CYAN)[GO] Downloading Go modules...$(RESET)"
	@cd $(CP_DIR)  && $(GO) mod download
	@cd $(SOC_DIR) && $(GO) mod download

deps-python:
	@echo "$(CYAN)[PYTHON] Installing Python dependencies...$(RESET)"
	@$(PYTHON) -m pip install -r $(AI_DIR)/requirements.txt --quiet

# ─── eBPF Kernel Program (Rust/Aya) ──────────────────────────────────────────
build-ebpf:
	@echo "$(CYAN)[eBPF] Building kernel-side XDP program...$(RESET)"
	@mkdir -p $(BUILD_DIR)/ebpf
	@cd $(EBPF_KERN_DIR) && \
		CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS="-C panic=abort" \
		$(CARGO) build \
			--target bpfel-unknown-none \
			-Z build-std=core \
			--release 2>&1
	@cp $(EBPF_KERN_DIR)/target/bpfel-unknown-none/release/falx-kern \
		$(BUILD_DIR)/ebpf/falx.bpf.o 2>/dev/null || true
	@echo "$(GREEN)[OK] eBPF kernel program built.$(RESET)"

# ─── eBPF User-space Loader (Rust/Aya) ───────────────────────────────────────
build-user:
	@echo "$(CYAN)[USER] Building eBPF user-space loader...$(RESET)"
	@mkdir -p $(BUILD_DIR)/user
	@# Clean stale artifacts to prevent duplicate lang-item errors when the
	@# active toolchain differs from what produced the cached .rmeta files.
	@cd $(EBPF_USER_DIR) && $(CARGO) clean -q
	@cd $(EBPF_USER_DIR) && $(CARGO) build --release
	@cp $(EBPF_USER_DIR)/target/release/falx-user \
		$(BUILD_DIR)/user/falx-user 2>/dev/null || true
	@echo "$(GREEN)[OK] User-space loader built.$(RESET)"

# ─── Control Plane (Go) ──────────────────────────────────────────────────────
build-control-plane:
	@echo "$(CYAN)[GO] Building control plane daemon (falxd)...$(RESET)"
	@mkdir -p $(DIST_DIR)
	@cd $(CP_DIR) && \
		CGO_ENABLED=0 \
		GOOS=linux \
		GOARCH=amd64 \
		$(GO) build \
			-ldflags="-s -w -X main.Version=$(VERSION) -X main.BuildTime=$(shell date -u +%Y%m%d%H%M%S)" \
			-o $(FALXD_BIN) \
			./cmd/falxd/...
	@echo "$(GREEN)[OK] Control plane built: $(FALXD_BIN)$(RESET)"

# ─── AI Inference Engine (C++/Python) ────────────────────────────────────────
build-ai:
	@echo "$(CYAN)[AI] Building AI inference engine...$(RESET)"
	@mkdir -p $(BUILD_DIR)/ai
	@cd $(AI_DIR) && \
		$(CMAKE) -B $(BUILD_DIR)/ai \
			-DCMAKE_BUILD_TYPE=Release \
			-DCMAKE_EXPORT_COMPILE_COMMANDS=ON && \
		$(CMAKE) --build $(BUILD_DIR)/ai --parallel $(shell nproc)
	@cp $(BUILD_DIR)/ai/falx-ai $(AI_BIN) 2>/dev/null || true
	@echo "$(GREEN)[OK] AI inference engine built.$(RESET)"

# ─── SOC Backend (Go gRPC/WebSocket) ─────────────────────────────────────────
build-soc:
	@echo "$(CYAN)[SOC] Building SOC backend...$(RESET)"
	@mkdir -p $(DIST_DIR)
	@cd $(SOC_DIR) && \
		CGO_ENABLED=0 \
		GOOS=linux \
		GOARCH=amd64 \
		$(GO) build \
			-ldflags="-s -w -X main.Version=$(VERSION)" \
			-o $(SOC_BIN) \
			./cmd/...
	@echo "$(GREEN)[OK] SOC backend built: $(SOC_BIN)$(RESET)"

# ─── Protobuf Generation ──────────────────────────────────────────────────────
proto:
	@echo "$(CYAN)[PROTO] Generating protobuf stubs...$(RESET)"
	@command -v protoc >/dev/null 2>&1 || (echo "$(RED)[ERROR] protoc not found.$(RESET)"; exit 1)
	@protoc \
		--go_out=$(CP_DIR) \
		--go-grpc_out=$(CP_DIR) \
		--python_out=$(AI_DIR) \
		--proto_path=$(ROOT_DIR)/ipc/proto \
		$(ROOT_DIR)/ipc/proto/*.proto
	@echo "$(GREEN)[OK] Protobuf stubs generated.$(RESET)"

# ─── Testing ─────────────────────────────────────────────────────────────────
test: test-go test-rust
	@echo "$(GREEN)[FALX V2] All tests passed.$(RESET)"

test-rust:
	@echo "$(CYAN)[TEST] Running Rust tests...$(RESET)"
	@cd $(EBPF_USER_DIR) && $(CARGO) test

test-go:
	@echo "$(CYAN)[TEST] Running Go tests...$(RESET)"
	@cd $(CP_DIR) && $(GO) test ./... -v -race -timeout 120s
	@cd $(SOC_DIR) && $(GO) test ./... -v -race -timeout 60s

# ─── Linting & Formatting ────────────────────────────────────────────────────
lint: lint-rust lint-go lint-cpp

lint-rust:
	@cd $(EBPF_USER_DIR) && $(CARGO) clippy -- -D warnings

lint-go:
	@command -v golangci-lint >/dev/null 2>&1 && \
		cd $(CP_DIR) && golangci-lint run ./... || \
		echo "$(YELLOW)[WARN] golangci-lint not installed, skipping.$(RESET)"

lint-cpp:
	@command -v clang-tidy >/dev/null 2>&1 && \
		find $(AI_DIR)/src -name '*.cpp' -exec clang-tidy {} \; || \
		echo "$(YELLOW)[WARN] clang-tidy not installed, skipping.$(RESET)"

fmt: fmt-rust fmt-go

fmt-rust:
	@cd $(EBPF_KERN_DIR) && $(CARGO) fmt
	@cd $(EBPF_USER_DIR) && $(CARGO) fmt

fmt-go:
	@$(GO) fmt $(CP_DIR)/...
	@$(GO) fmt $(SOC_DIR)/...

# ─── Install / Uninstall ──────────────────────────────────────────────────────
# install does NOT depend on `all` — building requires cargo/go in the caller's
# PATH which sudo strips. The expected workflow is:
#   1) make all              (as regular user, builds with cargo/go in PATH)
#   2) sudo make install     (as root, only copies pre-built binaries)
install:
	@# Pre-flight: refuse to run if the binaries haven't been built yet.
	@if [ ! -f $(FALXD_BIN) ]; then \
		echo "$(RED)[ERROR] $(FALXD_BIN) not found.$(RESET)"; \
		echo "$(YELLOW)        Run 'make all' as your regular user FIRST,$(RESET)"; \
		echo "$(YELLOW)        THEN re-run 'sudo make install'.$(RESET)"; \
		exit 1; \
	fi
	@echo "$(CYAN)[INSTALL] Installing FALX V2 system components...$(RESET)"
	@install -Dm755 $(FALXD_BIN) /usr/local/bin/falxd
	@install -Dm755 $(AI_BIN)   /usr/local/bin/falx-ai   2>/dev/null || true
	@install -Dm755 $(SOC_BIN)  /usr/local/bin/falx-soc  2>/dev/null || true
	@install -Dm644 $(CONFIGS_DIR)/falx.toml /etc/falx/falx.toml
	@install -Dm644 $(SCRIPTS_DIR)/falxd.service /etc/systemd/system/falxd.service
	@systemctl daemon-reload
	@echo "$(GREEN)[OK] FALX V2 installed. Run: systemctl enable --now falxd$(RESET)"

uninstall:
	@systemctl stop falxd 2>/dev/null || true
	@systemctl disable falxd 2>/dev/null || true
	@rm -f /usr/local/bin/falxd /usr/local/bin/falx-ai /usr/local/bin/falx-soc
	@rm -f /etc/systemd/system/falxd.service
	@rm -rf /etc/falx/
	@systemctl daemon-reload
	@echo "$(GREEN)[OK] FALX V2 uninstalled.$(RESET)"

# ─── Clean ───────────────────────────────────────────────────────────────────
clean:
	@echo "$(CYAN)[CLEAN] Removing build artifacts...$(RESET)"
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@cd $(EBPF_KERN_DIR) && $(CARGO) clean 2>/dev/null || true
	@cd $(EBPF_USER_DIR) && $(CARGO) clean 2>/dev/null || true
	@echo "$(GREEN)[OK] Clean complete.$(RESET)"

# ─── Help ────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "$(BOLD)FALX V2 - Hybrid IPS Build System$(RESET)"
	@echo "Lead Architect: FT-1 | Version: $(VERSION)"
	@echo ""
	@echo "$(BOLD)Targets:$(RESET)"
	@echo "  make all              - Full production build"
	@echo "  make dev              - Fast dev build (skip AI/SOC)"
	@echo "  make release          - Clean + full build"
	@echo "  make deps             - Install all dependencies"
	@echo "  make check-deps       - Verify required tools"
	@echo "  make build-ebpf       - Build eBPF kernel program"
	@echo "  make build-user       - Build eBPF user-space loader"
	@echo "  make build-control-plane - Build Go falxd daemon"
	@echo "  make build-ai         - Build C++ AI inference engine"
	@echo "  make build-soc        - Build SOC gRPC/WS backend"
	@echo "  make proto            - Regenerate protobuf stubs"
	@echo "  make test             - Run all tests"
	@echo "  make lint             - Run all linters"
	@echo "  make fmt              - Format all source files"
	@echo "  make install          - Install to system (needs root)"
	@echo "  make uninstall        - Remove from system (needs root)"
	@echo "  make clean            - Remove all build artifacts"
	@echo ""
