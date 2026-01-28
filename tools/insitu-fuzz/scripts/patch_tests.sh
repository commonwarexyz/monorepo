#!/bin/bash
# Complete patching workflow for fuzzing support
# Step 1: Bulk text replacements with sed (cfg, pub mod, features)
# Step 2: Add #[fuzzable_test] attributes to monorepo tests
# Step 3: Generate test registry from patched tests
# Step 4: Cargo fmt
#
# Usage:
#   ./scripts/patch_tests.sh        # Patch all tests (default)
#   ./scripts/patch_tests.sh 20     # Patch top 20 tests

set -e

if [[ "$OSTYPE" == "darwin"* ]]; then
    SED_INPLACE=(-i '')
else
    SED_INPLACE=(-i)
fi

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
SCRIPT_DIR="$REPO_ROOT/scripts"
MONOREPO="$REPO_ROOT/../.."
TOOLS_DIR="$REPO_ROOT/tools"
FUZZ_DIR="$REPO_ROOT/fuzz"

# Crates to patch (core crates + examples)
CORE_CRATES="broadcast collector consensus p2p resolver runtime macros"
CORE_CRATES_NO_MACROS="broadcast collector consensus p2p resolver runtime"
EXAMPLE_CRATES=$(cd "$MONOREPO" && ls -d examples/*/ 2>/dev/null || true)
ALL_CRATES="$CORE_CRATES $EXAMPLE_CRATES"
ALL_CRATES_NO_MACROS="$CORE_CRATES_NO_MACROS $EXAMPLE_CRATES"

MSG_COUNTS_FILE="$TOOLS_DIR/message_counts.json"
[ ! -f "$MSG_COUNTS_FILE" ] && echo "❌ message_counts.json not found. Run: bash tools/message_counts.sh" && exit 1

MONOREPO_COMMIT=$(cd "$MONOREPO" && git rev-parse HEAD)
EXPECTED_COMMIT=$(head -1 "$MSG_COUNTS_FILE" | grep -o '"commit":"[^"]*"' | cut -d'"' -f4)
if [ -n "$EXPECTED_COMMIT" ] && [ "$MONOREPO_COMMIT" != "$EXPECTED_COMMIT" ]; then
    echo "⚠️  Commit mismatch (current: ${MONOREPO_COMMIT:0:8}, expected: ${EXPECTED_COMMIT:0:8}). Regenerate with: bash tools/message_counts.sh"
    echo "Continuing anyway..."
fi

echo "Applying bulk patches..."

# Replace all #[cfg(test)] with fuzzing-aware version (only in crates with fuzzed tests)
for crate in $ALL_CRATES; do
  if [ -d "$MONOREPO/$crate" ]; then
    find "$MONOREPO/$crate" -name "*.rs" -type f -exec sed "${SED_INPLACE[@]}" \
      's/#\[cfg(test)\]/#[cfg(any(test, feature = "fuzzing"))]/g' {} +
  fi
done

# Replace #[cfg(feature = "mocks")] to include fuzzing (only in crates with fuzzed tests)
for crate in $ALL_CRATES; do
  if [ -d "$MONOREPO/$crate" ]; then
    find "$MONOREPO/$crate" -name "*.rs" -type f -exec sed "${SED_INPLACE[@]}" \
      's/#\[cfg(feature = "mocks")\]/#[cfg(any(feature = "mocks", feature = "fuzzing"))]/g' {} +
  fi
done

# Make test/mock modules public (only in crates with fuzzed tests)
for crate in $ALL_CRATES; do
  if [ -d "$MONOREPO/$crate" ]; then
    find "$MONOREPO/$crate" -name "*.rs" -type f | while read -r file; do
      # Use sed with two separate passes
      sed "${SED_INPLACE[@]}" -e '
        /cfg(any(test, feature = "fuzzing"))/{
          n
          s/^[[:space:]]*mod tests[[:space:]]/    pub mod tests /
          s/^[[:space:]]*mod test[[:space:]]/    pub mod test /
          s/^[[:space:]]*mod mocks[[:space:]]/    pub mod mocks /
        }
      ' "$file"
    done
  fi
done

# Add fuzzing feature to Cargo.toml files
# Automatically propagate to p2p if the crate depends on it (for monorepo runs)
for crate in $ALL_CRATES_NO_MACROS; do
  toml="$MONOREPO/$crate/Cargo.toml"
  if [ -f "$toml" ]; then
    if ! grep -q "fuzzing" "$toml"; then
      # Check if this crate depends on commonware-p2p
      if [ "$crate" != "p2p" ] && grep -q "commonware-p2p" "$toml"; then
        # Propagate to p2p so hooks work when running tests from monorepo
        if grep -q "\[features\]" "$toml"; then
          sed "${SED_INPLACE[@]}" '/\[features\]/a\
fuzzing = ["commonware-p2p/fuzzing", "commonware-runtime/fuzzing"]
' "$toml"
        else
          echo -e "\n[features]\nfuzzing = [\"commonware-p2p/fuzzing\", \"commonware-runtime/fuzzing\"]" >> "$toml"
        fi
      else
        # No p2p dependency, just add empty feature
        if grep -q "\[features\]" "$toml"; then
          sed "${SED_INPLACE[@]}" '/\[features\]/a\
fuzzing = []
' "$toml"
        else
          echo -e "\n[features]\nfuzzing = []" >> "$toml"
        fi
      fi
    fi
  fi
done

# Add test-only dependencies (like rstest) to fuzzing feature
# When fuzzing makes tests public, dev-dependencies must be available in lib builds
for crate in $ALL_CRATES_NO_MACROS; do
  toml="$MONOREPO/$crate/Cargo.toml"
  [ ! -f "$toml" ] && continue

  # Skip if rstest not used or already configured
  grep -q "rstest.workspace = true" "$toml" || continue
  grep -B100 "\[dev-dependencies\]" "$toml" | grep -q "rstest.*optional = true" && continue

  # Add rstest as optional dependency (just before [dev-dependencies] section)
  sed "${SED_INPLACE[@]}" "/\[dev-dependencies\]/i\\
rstest = { workspace = true, optional = true }\\
" "$toml"

  # Add dep:rstest to fuzzing feature
  if grep -q "^fuzzing = \[\]" "$toml"; then
    sed "${SED_INPLACE[@]}" 's/^fuzzing = \[\]/fuzzing = ["dep:rstest"]/' "$toml"
  elif grep -q "^fuzzing = \[" "$toml"; then
    sed "${SED_INPLACE[@]}" 's/^\(fuzzing = \[.*\)\(\]\)/\1, "dep:rstest"\2/' "$toml"
  fi
done

# Special cases: make nested test parent modules public
simplex_mod="$MONOREPO/consensus/src/simplex/mod.rs"
if [ -f "$simplex_mod" ]; then
  sed "${SED_INPLACE[@]}" 's/^\([[:space:]]*\)mod actors;/\1pub mod actors;/' "$simplex_mod"
fi
simulated_mod="$MONOREPO/p2p/src/simulated/mod.rs"
if [ -f "$simulated_mod" ]; then
  sed "${SED_INPLACE[@]}" 's/^\([[:space:]]*\)mod network;/\1pub mod network;/' "$simulated_mod"
fi
resolver_p2p_mod="$MONOREPO/resolver/src/p2p/mod.rs"
if [ -f "$resolver_p2p_mod" ]; then
  sed "${SED_INPLACE[@]}" 's/^mod fetcher;/pub mod fetcher;/' "$resolver_p2p_mod"
fi
runtime_network_mod="$MONOREPO/runtime/src/network/mod.rs"
if [ -f "$runtime_network_mod" ]; then
  sed "${SED_INPLACE[@]}" 's/^pub(crate) mod audited;/pub mod audited;/' "$runtime_network_mod"
  sed "${SED_INPLACE[@]}" 's/^pub(crate) mod deterministic;/pub mod deterministic;/' "$runtime_network_mod"
  sed "${SED_INPLACE[@]}" 's/^pub(crate) mod metered;/pub mod metered;/' "$runtime_network_mod"
fi

# Remove cdylib crate-type from all crates on macOS (causes linker errors with fuzzing symbols)
if [[ "$OSTYPE" == "darwin"* ]]; then
  for crate in consensus cryptography runtime storage utils; do
    toml="$MONOREPO/$crate/Cargo.toml"
    if [ -f "$toml" ]; then
      sed "${SED_INPLACE[@]}" 's/crate-type = \["rlib", "cdylib"\]/crate-type = ["rlib"]/' "$toml"
    fi
  done
fi

# Add [lib] section to binary-only example crates that have a lib.rs from patches/raw
# This enables importing their test modules into the fuzzing harness
for example_dir in $EXAMPLE_CRATES; do
  toml="$MONOREPO/${example_dir}Cargo.toml"
  lib_rs="$MONOREPO/${example_dir}src/lib.rs"

  # Skip if no Cargo.toml or no lib.rs (lib.rs comes from patches/raw)
  [ ! -f "$toml" ] && continue
  [ ! -f "$lib_rs" ] && continue

  # Skip if already has [lib] section
  grep -q "^\[lib\]" "$toml" && continue

  # Skip if doesn't have [[bin]] (not a binary crate)
  grep -q "^\[\[bin\]\]" "$toml" || continue

  # Extract crate name and convert to lib name (dashes to underscores)
  crate_name=$(grep -E '^name\s*=' "$toml" | head -1 | sed 's/.*"\(.*\)".*/\1/' | tr '-' '_')

  # Insert [lib] section before first [[bin]] only
  first_bin_line=$(grep -n '^\[\[bin\]\]' "$toml" | head -1 | cut -d: -f1)
  sed "${SED_INPLACE[@]}" "${first_bin_line}i\\
[lib]\\
name = \"${crate_name}\"\\
path = \"src/lib.rs\"\\
" "$toml"

  echo "✓ Added [lib] section to ${example_dir}Cargo.toml"
done

echo "✓ Bulk patches applied"
echo
echo "---"
echo

# Step 2: Add #[fuzzable_test] attributes to monorepo tests
echo "Adding #[fuzzable_test] attributes..."
echo
PATCHED_FILE=$(mktemp)
SKIPPED_FILE=$(mktemp)
trap "rm -f $PATCHED_FILE $SKIPPED_FILE" EXIT

PATCH_ARGS=""
[ -n "$1" ] && PATCH_ARGS="-n $1"

if ! python3 "$SCRIPT_DIR/patch_tests.py" $PATCH_ARGS --output "$PATCHED_FILE" --skipped "$SKIPPED_FILE"; then
  echo "Error: Failed to patch monorepo tests"
  exit 1
fi
echo

# Step 3: Generate test registry from patched tests
echo "Generating test registry..."
if ! python3 "$SCRIPT_DIR/gen_test_registry.py" --tests "$PATCHED_FILE" --skipped "$SKIPPED_FILE"; then
  echo "Error: Failed to generate test registry"
  exit 1
fi
echo
echo "✓ All patching complete!"

# Step 4: Cargo fmt (format only insitu-fuzz, not monorepo)
cd "$REPO_ROOT"
cargo fmt --manifest-path Cargo.toml
cargo fmt --manifest-path fuzz/Cargo.toml
