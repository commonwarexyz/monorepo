#!/usr/bin/env bash
# The shipped-code measurement (finish-A, task 4): the code commonware-codec
# and commonware-storage compile from sandblaster's emitted and lowered
# copies, against the original Commonware functions, in one binary. Writes
# sandblaster/bench/shipped-harness/REPORT.md.
#
#   sandblaster/bench/shipped-harness/run.sh --codec-out DIR --storage-out DIR [--rounds N] [--out DIR]
#
# --codec-out / --storage-out: the OUT_DIR of a verified build of each crate
# (`cargo test -p commonware-codec`, `cargo test -p commonware-storage`): the
# emitted `varint.rs` and the lowered `mmr-lowered__merkle__mmr__iterator.rs`
# the crates compile.
#
# 1. prepare.py: the subjects' copies of the two crates (gen/): the original
#    code (the merge base of the sandblaster branch) twice, `orig` and the A/A
#    control `aa`, and the shipped code (`shipped`: this worktree's crates
#    with those OUT_DIR files included as the crates include them).
# 2. Per binary (layout `default`, layout `align`: every function and
#    non-fallthrough block aligned to 64 bytes; profile `release`, Commonware's
#    overflow checks on, and `release-nooc`, default layout): samecode.py (the
#    identity check, following calls into each subject's own copies), the
#    differential check, then the timings (>= 21 interleaved rounds, medians),
#    the load average before and after.
# 3. report.py writes REPORT.md from the results.
#
# Every cargo and benchmark process goes through $HEAVY when it is set (the
# machine-wide admission wrapper); never run this script itself under it.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../../.." && pwd)
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$repo/target/shipped}
H=${HEAVY:-}
rounds=31 out="" codec_out="" storage_out=""
while [ $# -gt 0 ]; do
    case $1 in
    --rounds) rounds=$2; shift ;;
    --out) out=$2; shift ;;
    --codec-out) codec_out=$2; shift ;;
    --storage-out) storage_out=$2; shift ;;
    *) echo "usage: $0 --codec-out DIR --storage-out DIR [--rounds N (>= 21)] [--out DIR]" >&2; exit 2 ;;
    esac
    shift
done
[ -n "$codec_out" ] && [ -n "$storage_out" ] || { echo "--codec-out and --storage-out are required" >&2; exit 2; }
[ "$rounds" -ge 21 ] || { echo "the protocol needs at least 21 rounds" >&2; exit 2; }
out=${out:-$here/results}
rm -rf "$out"; mkdir -p "$out"
log() { echo "[shipped] $*" | tee -a "$out/run.log"; }
load() { sysctl -n vm.loadavg 2> /dev/null | tr -d '{}' | xargs || uptime | sed 's/.*load averages*: //'; }
t0=$(date +%s)
log "out: $out; load: $(load); rounds: $rounds"

# ---- 1. the subjects' crate copies (the monorepo's lock: the same versions of every dependency)
python3 "$here/prepare.py" --codec-out "$codec_out" --storage-out "$storage_out" | tee "$out/sources.txt"
cp "$repo/Cargo.lock" "$here/Cargo.lock"

# ---- 2. one binary per layout / profile
binaries="default:release align:release default:release-nooc"
cd "$here"
for b in $binaries; do
    layout=${b%%:*} profile=${b#*:}
    case $layout in
    default) flags="" ;;
    align) flags="-C llvm-args=-align-all-functions=6 -C llvm-args=-align-all-nofallthru-blocks=6" ;;
    esac
    tag=$layout-$profile
    log "[$tag] building"
    RUSTFLAGS="$flags" $H cargo build -q --profile "$profile" --bin shipped-bench
    bin=$out/shipped-bench-$tag
    cp "$CARGO_TARGET_DIR/$profile/shipped-bench" "$bin"
    python3 "$repo/sandblaster/bench/opt-corpus/samecode.py" "$bin" --crates subj_orig,subj_aa,subj_shipped \
        --family subj_orig=sbx_ship_orig_codec+sbx_ship_orig_storage \
        --family subj_aa=sbx_ship_aa_codec+sbx_ship_aa_storage \
        --family subj_shipped=sbx_ship_shipped_codec+sbx_ship_shipped_storage \
        --ignore-panic-locations > "$out/samecode-$tag.json"
    python3 "$repo/sandblaster/bench/opt-corpus/samecode.py" "$bin" --crates subj_orig,subj_aa,subj_shipped \
        --family subj_orig=sbx_ship_orig_codec+sbx_ship_orig_storage \
        --family subj_aa=sbx_ship_aa_codec+sbx_ship_aa_storage \
        --family subj_shipped=sbx_ship_shipped_codec+sbx_ship_shipped_storage \
        --ignore-panic-locations --data-blind > "$out/samecode-blind-$tag.json"
    $H "$bin" check > "$out/check-$tag.txt" || { cat "$out/check-$tag.txt"; log "FAIL: [$tag] the differential check"; exit 1; }
    before=$(load)
    $H "$bin" bench --rounds "$rounds" --json "$out/bench-$tag.json" | tee "$out/bench-$tag.md"
    after=$(load)
    echo "{\"before\": \"$before\", \"after\": \"$after\"}" > "$out/load-$tag.json"
    log "[$tag] load before: $before; after: $after"
    rm -f "$bin"
done

# ---- 3. the report
python3 "$here/report.py" --results "$out" --rounds "$rounds" > "$here/REPORT.md"
log "wrote sandblaster/bench/shipped-harness/REPORT.md; done in $(( $(date +%s) - t0 )) s"
