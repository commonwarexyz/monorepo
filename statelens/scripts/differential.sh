#!/usr/bin/env bash
# Differential test of the TSS prefixes against the marshal scenario prefixes
# (statelens/differential/README.md).
#
# Builds nothing in this checkout: it adds a detached git worktree of HEAD under
# a scratch directory, copies statelens/ and consensus/fuzz/marshal/ into it (so
# the uncommitted visibility change and the test crate are present), checks the
# fuzz package there (clippy, rustfmt, nextest), builds the differential tests
# and runs each one twice (canonical, control) in its own process with the
# [statelens-reach] lines captured, runs the reach-check validator over them,
# prints a table, and removes the worktree with its target directory. The logs
# stay in the run's directory, which the last lines print.
#
# Exit code 0 when the differential passed; 1 when it failed, with `(FAILED)`,
# `(NOT CAUGHT)` or `(ERROR)` beside the verdict of each failing row; 2 when the
# run could not start (too little disk, a test listing other than the expected
# one); a failing build or check exits with that command's code.
#
#   DIFFERENTIAL_SCRATCH=<dir>  where each run's directory run.XXXXXX, with the
#                               worktree and the logs, goes
#                               (default: $TMPDIR/statelens-differential)
#   SKIP_FUZZ_CHECKS=1          skip the fuzz package's clippy, rustfmt and tests
#   DIFFERENTIAL_RUSTFMT=<tc>   the rustfmt toolchain (default: nightly-2026-06-21)
set -euo pipefail

REPO=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
SCRATCH=${DIFFERENTIAL_SCRATCH:-${TMPDIR:-/tmp}/statelens-differential}
MIN_FREE_KB=$((25 * 1024 * 1024))
FUZZ_PACKAGE=commonware-consensus-fuzz-marshal
MANIFEST=statelens/differential/Cargo.toml
CARDS=statelens/differential/cards
MODULES=statelens/differential/src/cards
RUSTFMT_TOOLCHAIN=${DIFFERENTIAL_RUSTFMT:-nightly-2026-06-21}
SKIP_FUZZ_CHECKS=${SKIP_FUZZ_CHECKS:-0}
TOUCHED=(
  consensus/fuzz/marshal/src/scenarios/mod.rs
  consensus/fuzz/marshal/src/scenarios/scenarios.rs
  consensus/fuzz/marshal/src/scenarios/environment.rs
  consensus/fuzz/marshal/src/scenarios/harness.rs
  consensus/fuzz/marshal/src/scenarios/recording_resolver.rs
  consensus/fuzz/marshal/src/marshal/end_to_end/mod.rs
  consensus/fuzz/marshal/src/marshal/end_to_end/app.rs
  consensus/fuzz/marshal/src/marshal/end_to_end/twins/mod.rs
  consensus/fuzz/marshal/src/marshal/end_to_end/twins/stack.rs
)
# The tests of src/tests.rs; a listing that differs is an error, so no test is skipped.
EXPECTED_TESTS=(
  ts9001_deferred_n4f0c4 ts9001_deferred_n4f1c3 ts9001_inline_n4f0c4 ts9001_inline_n4f1c3
  ts9002_deferred_n4f0c4 ts9002_deferred_n4f1c3 ts9002_inline_n4f0c4 ts9002_inline_n4f1c3
  ts9003_deferred_n4f0c4 ts9003_deferred_n4f1c3
  ts9004_inline_n4f0c4 ts9004_inline_n4f1c3
  ts9005_deferred_n4f0c4 ts9005_deferred_n4f1c3 ts9005_inline_n4f0c4 ts9005_inline_n4f1c3
  ts9006_deferred_n4f0c4 ts9006_deferred_n4f1c3 ts9006_inline_n4f0c4 ts9006_inline_n4f1c3
  ts9007_deferred_n4f0c4 ts9007_deferred_n4f1c3 ts9007_inline_n4f0c4 ts9007_inline_n4f1c3
  neg_ts9001_dropped_arm neg_ts9001_notarization_to_c neg_ts9002_armed_garbage
  neg_ts9002_stale_handoff_read neg_ts9005_swapped_arm_verify neg_ts9007_finalization_to_c
)
# A verdict the validator computed from a replay, annotated or not.
VERDICT_SHAPE='^(REACHED|UNVERIFIED|PARTIAL|UNREACHED) [0-9]+/[0-9]+( \(.*\))?$'

step() {
  echo
  echo "== $1 ($(date +%T), +${SECONDS}s)"
}

cleanup() {
  cd "$REPO"
  if [ -d "$WT" ]; then
    git worktree remove --force "$WT" 2>/dev/null || rm -rf "$WT"
  fi
  git worktree prune
}

mkdir -p "$SCRATCH"
avail=$(df -Pk "$SCRATCH" | awk 'NR == 2 { print $4 }')
if [ "$avail" -lt "$MIN_FREE_KB" ]; then
  echo "differential: $((avail / 1024 / 1024)) GB free under $SCRATCH; 25 GB needed" >&2
  exit 2
fi

# One directory per run: concurrent runs share nothing, and cleanup removes only
# what this run created.
RUN=$(mktemp -d "$SCRATCH/run.XXXXXX")
WT=$RUN/wt-diff
LOGS=$RUN/logs
mkdir "$LOGS"
step "worktree at $WT"
trap cleanup EXIT
git -C "$REPO" worktree add --detach "$WT" HEAD
rsync -a --delete --exclude target --exclude .ruff_cache --exclude campaign \
  --exclude extract --exclude __pycache__ --exclude Cargo.lock \
  "$REPO/statelens/" "$WT/statelens/"
rsync -a --delete --exclude corpus --exclude artifacts --exclude coverage \
  --exclude target "$REPO/consensus/fuzz/marshal/" "$WT/consensus/fuzz/marshal/"
# The crate's own lockfile starts from the root's, so cached versions are reused.
cp "$REPO/Cargo.lock" "$WT/$(dirname "$MANIFEST")/Cargo.lock"
export CARGO_TARGET_DIR="$WT/target-differential"
ulimit -n 65536 || true
cd "$WT"

if [ "$SKIP_FUZZ_CHECKS" != 1 ]; then
  step "step 1: clippy of $FUZZ_PACKAGE"
  cargo +stable clippy -p "$FUZZ_PACKAGE" --all-targets -- -D warnings 2>&1 | tail -2
  step "step 1: rustfmt check of the touched files"
  rustfmt "+$RUSTFMT_TOOLCHAIN" --edition 2024 --check "${TOUCHED[@]}"
  step "step 1: tests of $FUZZ_PACKAGE"
  cargo +stable nextest run -p "$FUZZ_PACKAGE" 2>&1 | tail -2
fi

step "build the differential tests"
rustfmt "+$RUSTFMT_TOOLCHAIN" --edition 2024 --check "$(dirname "$MANIFEST")/src/lib.rs"
cargo +stable test --manifest-path "$MANIFEST" --lib --no-run 2>&1 | tail -2
tests=$(cargo +stable test -q --manifest-path "$MANIFEST" --lib -- --list 2>/dev/null \
  | sed -n 's/^tests::\([a-z0-9_]*\): test$/\1/p')
if ! diff <(printf '%s\n' "${EXPECTED_TESTS[@]}" | sort) <(printf '%s\n' $tests | sort) \
  >"$LOGS/tests.diff"; then
  echo "differential: the crate lists other tests than the ${#EXPECTED_TESTS[@]} expected" \
    "(< expected, > listed):" >&2
  cat "$LOGS/tests.diff" >&2
  exit 2
fi

# Runs one test in its own process, with the reach lines on stderr captured.
replay() {
  local name=$1 mode=$2 code=0
  local vars=(STATELENS_REACH=1)
  if [ "$mode" = control ]; then
    vars+=(STATELENS_REACH_CONTROL=1)
  else
    vars+=(DIFFERENTIAL_DIGESTS="$LOGS")
  fi
  env "${vars[@]}" cargo +stable test -q --manifest-path "$MANIFEST" --lib -- \
    --exact "tests::$name" --nocapture --test-threads=1 \
    >"$LOGS/$name.$mode.out" 2>"$LOGS/$name.$mode.log" || code=$?
  echo "$code"
}

step "replays and verdicts"
failed=0
rows=()
for name in $tests; do
  number=$(sed -n 's/.*ts\([0-9]\{4\}\).*/\1/p' <<<"$name")
  card=$CARDS/TS-$number.md
  module=$MODULES/ts$number.rs
  canonical=$(replay "$name" canonical)
  equal=$(sed -n 's/.*digest-equal=\([a-z]*\).*/\1/p' "$LOGS/$name.canonical.out" | head -1)
  equal=${equal:-none}
  # Every test gets the control replay, so a negative control's verdict can
  # be REACHED and the check below is live.
  control=$(replay "$name" control)
  args=(--card "$card" --module "$module" \
    --canonical "$LOGS/$name.canonical.log" --canonical-code "$canonical" \
    --control "$LOGS/$name.control.log" --control-code "$control")
  # Exit 1 is the validator's for every verdict but REACHED, so the shape of the
  # verdict, not the exit code, tells a computed verdict from a traceback or an
  # abort.
  python3 statelens/scripts/statelens.py reach-verdict "${args[@]}" \
    >"$LOGS/$name.verdict" 2>&1 || true
  verdict=$(head -1 "$LOGS/$name.verdict")
  case $name in
    neg_*)
      # A wrong prefix must show: unequal digests or a verdict other than
      # REACHED, from a replay that ran to its digest line (the negative tests
      # assert nothing, so exit 0) and a verdict the validator computed.
      # Anything else is an error of the run, not a caught control. REACHED
      # counts annotated or not: an annotation is informational, never a
      # rejected witness.
      if [ "$canonical" != 0 ] || [[ $equal != true && $equal != false ]] \
        || ! [[ $verdict =~ $VERDICT_SHAPE ]]; then
        failed=1
        verdict="$verdict (ERROR)"
      elif [ "$equal" = true ] && [[ $verdict =~ ^REACHED\ [0-9]+/[0-9]+ ]]; then
        failed=1
        verdict="$verdict (NOT CAUGHT)"
      fi
      ;;
    *)
      if [ "$canonical" != 0 ] || [ "$equal" != true ] \
        || ! [[ $verdict =~ ^REACHED\ [0-9]+/[0-9]+$ ]]; then
        failed=1
        verdict="$verdict (FAILED)"
      fi
      ;;
  esac
  rows+=("| $name | $equal (exit $canonical) | $verdict |")
  echo "$name: digest-equal=$equal exit=$canonical verdict=$verdict"
done

step "result"
echo "| test | digest equal | verdict |"
echo "|---|---|---|"
printf '%s\n' ${rows[@]+"${rows[@]}"}
echo
echo "logs: $LOGS (per test: <name>.<canonical|control>.{out,log}, <name>.verdict, <name>.{a,b}.digest)"
if [ "$failed" != 0 ]; then
  echo "differential: FAILED"
  exit 1
fi
echo "differential: PASSED (+${SECONDS}s)"
