#!/bin/bash
# Apply fuzzing patches to Commonware monorepo
# Usage: ./setup.sh [pull|clean|reset] [--no-test] [--help]

set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMONWARE_PATH="$REPO_DIR/../.."

# Show help
show_help() {
    cat << EOF
Usage: ./setup.sh [OPTIONS]

Apply fuzzing patches to Commonware submodule.

OPTIONS:
    pull            Clean monorepo and pull latest from origin/main
    clean           Restore monorepo to clean state before patching
    reset           Restore monorepo to clean state and exit (skip patching)
    --no-test       Skip running tests after patching
    -h, --help      Show this help message

EXAMPLES:
    ./setup.sh                  # Apply patches and run tests
    ./setup.sh pull             # Pull latest, clean, patch, and test
    ./setup.sh clean            # Clean and apply patches
    ./setup.sh reset            # Clean monorepo and exit
    ./setup.sh --no-test        # Apply patches without testing
    ./setup.sh clean --no-test  # Clean, patch, skip tests
EOF
    exit 0
}

# Parse args
[[ "$*" == *--help* ]] || [[ "$*" == *-h* ]] && show_help
[[ "$*" == *--no-test* ]] && RUN_TESTS=0 || RUN_TESTS=1
[[ "$*" == *pull* ]] && PULL=1 || PULL=0
[[ "$*" == *clean* ]] && CLEAN=1 || CLEAN=0
[[ "$*" == *reset* ]] && RESET=1 || RESET=0

# Pull latest if requested
if [[ $PULL -eq 1 ]] && [[ -e "$COMMONWARE_PATH/.git" ]]; then
    echo "Cleaning and pulling latest..."
    TOOL_PATH=$(realpath --relative-to="$COMMONWARE_PATH" "$REPO_DIR")
    git -C "$COMMONWARE_PATH" restore . ":!$TOOL_PATH"
    git -C "$COMMONWARE_PATH" clean -fd -e "$TOOL_PATH"
    git -C "$COMMONWARE_PATH" pull origin main
    echo "✓ Pulled latest from origin/main"
fi

# Reset monorepo if requested (skip patching)
if [[ $RESET -eq 1 ]] && [[ -e "$COMMONWARE_PATH/.git" ]]; then
    echo "Resetting monorepo (excluding insitu-fuzz)..."
    TOOL_PATH=$(realpath --relative-to="$COMMONWARE_PATH" "$REPO_DIR")
    git -C "$COMMONWARE_PATH" restore . ":!$TOOL_PATH"
    git -C "$COMMONWARE_PATH" clean -fd -e "$TOOL_PATH"
    echo "✓ Monorepo reset"
    exit 0
fi

# Clean monorepo if requested
if [[ $CLEAN -eq 1 ]] && [[ -e "$COMMONWARE_PATH/.git" ]]; then
    echo "Restoring monorepo to clean state..."
    TOOL_PATH=$(realpath --relative-to="$COMMONWARE_PATH" "$REPO_DIR")
    git -C "$COMMONWARE_PATH" restore . ":!$TOOL_PATH"
    git -C "$COMMONWARE_PATH" clean -fd -e "$TOOL_PATH"
    echo "✓ Monorepo cleaned"
fi

# Apply patches
echo "Applying patches..."
if ! git -C "$COMMONWARE_PATH" diff --quiet --exit-code 2>/dev/null && [[ -e "$COMMONWARE_PATH/.git" ]]; then
    echo "❌ Error: Monorepo has uncommitted changes - patches may fail or create duplicates. Run './setup.sh clean' to reset."
    exit
fi

# Copy raw replacement files from patches/raw/
find "$REPO_DIR/patches/raw" -type f -print0 2>/dev/null | while IFS= read -r -d '' src; do
    rel="${src#$REPO_DIR/patches/raw/}"
    dest="$COMMONWARE_PATH/$rel"
    mkdir -p "$(dirname "$dest")"
    diff_lines=$(diff "$dest" "$src" 2>/dev/null | grep -c '^[<>]' | tr -d '\n' || echo "new")
    cp "$src" "$dest"
    [[ "$diff_lines" == "0" ]] && echo "⊙ $rel" || printf "✓ %s \033[33m(%s lines)\033[0m\n" "$rel" "$diff_lines"
done

# Apply .patch files
for p in "$REPO_DIR/patches"/*.patch; do
    [[ -f "$p" ]] || continue
    name=$(basename "$p")
    if out=$(cd "$COMMONWARE_PATH" && patch -p1 --forward < "$p" 2>&1); then
        echo "✓ $name"
    elif echo "$out" | grep -q "previously applied"; then
        echo "⊙ $name"
    else
        echo "Error: $name failed"; echo "$out"; exit 1
    fi
done

# Delete any redundant .rej or .orig files leftover from failed patch attempts.
find "$COMMONWARE_PATH/" -name "*.orig" -delete 2>/dev/null
find "$COMMONWARE_PATH/" -name "*.rej" -delete 2>/dev/null

# Fail fast if message counts are missing or empty (needed before patching)
MSG_COUNTS="$REPO_DIR/tools/message_counts.json"
if [ ! -s "$MSG_COUNTS" ] || ! grep -q '"messages"' "$MSG_COUNTS"; then
    echo "❌ Critical: message_counts.json is missing/empty. This file lists fuzzable tests and their message counts."
    echo "Generate it with: bash \"$REPO_DIR/tools/message_counts.sh\" --all"
    exit 1
fi

# Apply test patches (adds #[fuzzable_test] attributes and generates harness)
echo ""
echo "Patching tests..."
if ! bash "$REPO_DIR/scripts/patch_tests.sh"; then
    echo "Error: Test patching failed"
    exit 1
fi

# Test
[[ $RUN_TESTS -eq 0 ]] && echo "Tests skipped" && exit 0
if ! "$REPO_DIR/fuzz.sh" test; then
    echo "Error: Tests failed"
    exit 1
fi
echo "✓ Tests passed"
