#!/usr/bin/env bash
# =============================================================================
# Project: FALX V2
# Lead Architect & Owner: FT-1
# Description: package.sh — Creates a clean, distributable ZIP of FALX V2.
#              Excludes all build artifacts, secrets, IDE files, and binaries.
#              Output: FALX-V2-{VERSION}-{DATE}.zip
#
# Usage:
#   bash scripts/package.sh                  # Standard packaging
#   bash scripts/package.sh --with-docs      # Include all .md documentation
#   bash scripts/package.sh --version=1.0.0  # Custom version tag
#   bash scripts/package.sh --output=/tmp    # Custom output directory
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

VERSION="0.1.0"
DATE=$(date +%Y%m%d)
WITH_DOCS=false
OUTPUT_DIR="$ROOT_DIR"

R='\033[0;31m' G='\033[0;32m' C='\033[0;36m' B='\033[1m' N='\033[0m'

for arg in "$@"; do case $arg in
    --with-docs)    WITH_DOCS=true ;;
    --version=*)    VERSION="${arg#*=}" ;;
    --output=*)     OUTPUT_DIR="${arg#*=}" ;;
esac done

ZIP_NAME="FALX-V2-${VERSION}-${DATE}-FT1.zip"
ZIP_PATH="$OUTPUT_DIR/$ZIP_NAME"

echo -e "\n${B}${C}FALX V2 Packager | v$VERSION | FT-1${N}\n"

# ─── Pre-checks ───────────────────────────────────────────────────────────────
command -v zip >/dev/null 2>&1 || { echo -e "${R}[ERROR]${N} 'zip' not found. Install: apt install zip"; exit 1; }

# Ensure git working directory is clean before packaging (no uncommitted changes)
if git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if ! git -C "$ROOT_DIR" diff --quiet || ! git -C "$ROOT_DIR" diff --cached --quiet; then
        echo -e "${R}[ERROR]${N} Git working directory is not clean. Commit or stash your changes before packaging."
        echo -e "        Run: git status"
        exit 1
    fi
    echo -e "${G}[OK]${N} Git working directory is clean"
fi

# ─── Exclusion patterns ───────────────────────────────────────────────────────
EXCLUDES=(
    # Build artifacts
    "*/target/*"
    "*/build/*"
    "*/dist/*"
    "*/__pycache__/*"
    "*.pyc"
    # Rust
    "*/Cargo.lock"
    # Go
    "*/go.sum"
    "*/vendor/*"
    # Node (should not exist in this project, but guard against accidental inclusion)
    "*/node_modules/*"
    # BPF objects
    "*.bpf.o"
    # Secrets (NEVER package these)
    "*.pem"
    "*.key"
    "*.crt"
    "*.p12"
    "*/.env*"
    # Databases
    "*.db"
    "*.sqlite"
    "*.sqlite3"
    "*.db-shm"
    "*.db-wal"
    # Runtime sockets (never package live socket files)
    "*.sock"
    # Logs
    "*.log"
    "*.jsonl"
    # IDE
    "*/.idea/*"
    "*/.vscode/*"
    "*.swp"
    "*~"
    # Git (entire .git directory — history must never be distributed)
    "*/.git"
    "*/.git/*"
    "*.gitkeep"
    # OS
    "*/.DS_Store"
    "*/Thumbs.db"
    # Test cache
    "*/coverage.out"
    "*/coverage.html"
    # Compiled binaries
    "*/bin/falxd"
    "*/bin/falx-soc"
    "*/bin/falx-ai"
    "*/bin/falx-user"
    # Previous zips / manifests
    "*.zip"
    "*.tar.gz"
    "FALX-V2-*-MANIFEST.txt"
)

# When --with-docs is NOT set, skip heavyweight docs
if [[ "$WITH_DOCS" == "false" ]]; then
    EXCLUDES+=("*/docs/*")
fi

# ─── Build exclusion arguments ────────────────────────────────────────────────
EXCLUDE_ARGS=()
for pattern in "${EXCLUDES[@]}"; do
    EXCLUDE_ARGS+=("-x" "$pattern")
done

# ─── Create ZIP ───────────────────────────────────────────────────────────────
echo -e "${C}[1/4]${N} Creating archive: $ZIP_NAME"
rm -f "$ZIP_PATH"

cd "$(dirname "$ROOT_DIR")"
PROJECT_DIR=$(basename "$ROOT_DIR")

zip -r "$ZIP_PATH" "$PROJECT_DIR/" \
    "${EXCLUDE_ARGS[@]}" \
    2>/dev/null

# ─── Verify contents ──────────────────────────────────────────────────────────
echo -e "${C}[2/4]${N} Verifying contents..."
FILE_COUNT=$(unzip -l "$ZIP_PATH" | grep -c '\.' || true)
ZIP_SIZE=$(du -sh "$ZIP_PATH" | cut -f1)

# Check no secrets leaked
echo -e "${C}[3/4]${N} Security check (no secrets in archive)..."
SECRETS_FOUND=0
for pattern in "*.pem" "*.key" "*.env" "password" "secret"; do
    if unzip -l "$ZIP_PATH" | grep -qi "$pattern" 2>/dev/null; then
        echo -e "${R}[WARN]${N} Potential secret found matching: $pattern"
        SECRETS_FOUND=1
    fi
done
if [[ $SECRETS_FOUND -eq 0 ]]; then
    echo -e "${G}[OK]${N} No secrets found in archive"
fi

# ─── Generate manifest ────────────────────────────────────────────────────────
echo -e "${C}[4/4]${N} Generating manifest..."
MANIFEST="$OUTPUT_DIR/FALX-V2-${VERSION}-${DATE}-MANIFEST.txt"
cat > "$MANIFEST" << EOF
FALX V2 — Package Manifest
Lead Architect & Owner: FT-1
Version: $VERSION
Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Archive: $ZIP_NAME

Contents:
$(unzip -l "$ZIP_PATH" | grep -v "^Archive:" | tail -n +4 | head -n -2)

Checksums:
SHA256: $(sha256sum "$ZIP_PATH" | cut -d' ' -f1)
MD5:    $(md5sum "$ZIP_PATH" | cut -d' ' -f1)

File count: $FILE_COUNT
Archive size: $ZIP_SIZE
EOF

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${B}${G}══════════════════════════════════════════${N}"
echo -e "${B}${G}  FALX V2 Package Created Successfully    ${N}"
echo -e "${B}${G}══════════════════════════════════════════${N}"
echo ""
echo -e "  Archive:    ${C}$ZIP_PATH${N}"
echo -e "  Size:       ${G}$ZIP_SIZE${N}"
echo -e "  Files:      $FILE_COUNT"
echo -e "  Manifest:   $MANIFEST"
echo ""
echo -e "  SHA256: $(sha256sum "$ZIP_PATH" | cut -d' ' -f1)"
echo ""
echo -e "  To extract: unzip ${ZIP_NAME}"
echo -e "  To verify:  sha256sum -c <(echo \"\$(head -1 MANIFEST | awk '{print \$2}')  ${ZIP_NAME}\")"
echo ""
