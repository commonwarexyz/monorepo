#!/usr/bin/env bash
# The measurement harness (README.md): the original crates at a given commit
# against the worktree's own crates, in one binary, for pilots.
#
#   sandblaster/bench/shipped-harness/run.sh [--probe DIR] [--base REV] [--out-dir CRATE=DIR]...
#       [--only F,..] [--rounds N] [--binaries LAYOUT:PROFILE,..] [--out DIR]
#
# --probe: a probe directory (probes/README; default probes/commonware, the
#   whole verified surface). --base: the original code's commit (default: the
#   merge base of main and HEAD). --out-dir CRATE=DIR: the OUT_DIR of a build
#   of CRATE, for a worktree source that includes build output (codec's
#   varint module: `cargo build -p commonware-codec`, then its
#   `target/<profile>/build/commonware-codec-*/out`). --only: a subset of the
#   probe's rows. --binaries: default
#   `default:release,align:release,default:release-nooc`.
#
# 1. prepare.py: the subjects' copies of the probe's crates (gen/): the code
#    at the base commit twice, `orig` and the A/A control `aa`, and the
#    worktree's (`wt`).
# 2. Per binary (layout `default`, layout `align`: every function and
#    non-fallthrough block aligned to 64 bytes; profile `release`,
#    Commonware's overflow checks on, and `release-nooc`): samecode.py (the
#    machine-code identity check, following calls into each subject's own
#    copies; and its data-blind variant), the differential check, then the
#    timings (>= 21 interleaved rounds, medians), the load average before and
#    after.
# 3. report.py writes REPORT.md into the output directory.
#
# Every cargo and benchmark process goes through $HEAVY when it is set (a
# machine-wide admission wrapper); never run this script itself under it.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../../.." && pwd)
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$repo/target/bench-harness}
H=${HEAVY:-}
rounds=31 out="" probe=$here/probes/commonware base="" only="" binaries="default:release,align:release,default:release-nooc"
outdirs=()
while [ $# -gt 0 ]; do
    case $1 in
    --rounds) rounds=$2; shift ;;
    --out) out=$2; shift ;;
    --probe) probe=$(cd -- "$2" && pwd); shift ;;
    --base) base=$2; shift ;;
    --out-dir) outdirs+=(--out-dir "$2"); shift ;;
    --only) only=$2; shift ;;
    --binaries) binaries=$2; shift ;;
    *) echo "usage: $0 [--probe DIR] [--base REV] [--out-dir CRATE=DIR]... [--only F,..] [--rounds N (>= 21)] [--binaries LAYOUT:PROFILE,..] [--out DIR]" >&2; exit 2 ;;
    esac
    shift
done
[ "$rounds" -ge 21 ] || { echo "the protocol needs at least 21 rounds" >&2; exit 2; }
out=${out:-$here/results}
rm -rf "$out"; mkdir -p "$out"
log() { echo "[harness] $*" | tee -a "$out/run.log"; }
load() { sysctl -n vm.loadavg 2> /dev/null | tr -d '{}' | xargs || uptime | sed 's/.*load averages*: //'; }
t0=$(date +%s)
log "out: $out; probe: $probe; load: $(load); rounds: $rounds"

# ---- 1. the subjects' crate copies (the monorepo's lock: the same versions of every dependency)
python3 "$here/prepare.py" --probe "$probe" ${base:+--base "$base"} ${outdirs[@]+"${outdirs[@]}"} | tee "$out/sources.txt"
cp "$repo/Cargo.lock" "$here/Cargo.lock"
crates=$(cat "$probe/crates")
fam() { local s=$1 m=""; for c in $crates; do m="${m:+$m+}sbx_${s}_$c"; done; echo "subj_$s=$m"; }
only_args=()
[ -n "$only" ] && only_args=(--only "$only")

# ---- 2. one binary per layout / profile
cd "$here"
for b in ${binaries//,/ }; do
    layout=${b%%:*} profile=${b#*:}
    case $layout in
    default) flags="" ;;
    align) flags="-C llvm-args=-align-all-functions=6 -C llvm-args=-align-all-nofallthru-blocks=6" ;;
    *) echo "unknown layout $layout" >&2; exit 2 ;;
    esac
    tag=$layout-$profile
    log "[$tag] building"
    RUSTFLAGS="$flags" $H cargo build -q --profile "$profile" --bin bench-harness
    bin=$out/bench-harness-$tag
    cp "$CARGO_TARGET_DIR/$profile/bench-harness" "$bin"
    for mode in exact blind; do
        extra=()
        [ $mode = blind ] && extra=(--data-blind)
        python3 "$here/samecode.py" "$bin" --crates subj_orig,subj_aa,subj_wt \
            --family "$(fam orig)" --family "$(fam aa)" --family "$(fam wt)" \
            --ignore-panic-locations ${extra[@]+"${extra[@]}"} > "$out/samecode-${mode}-$tag.json"
    done
    $H "$bin" check ${only_args[@]+"${only_args[@]}"} > "$out/check-$tag.txt" || { cat "$out/check-$tag.txt"; log "FAIL: [$tag] the differential check"; exit 1; }
    before=$(load)
    $H "$bin" bench --rounds "$rounds" --json "$out/bench-$tag.json" ${only_args[@]+"${only_args[@]}"} | tee "$out/bench-$tag.md"
    after=$(load)
    echo "{\"before\": \"$before\", \"after\": \"$after\"}" > "$out/load-$tag.json"
    log "[$tag] load before: $before; after: $after"
    rm -f "$bin"
done

# ---- 3. the report
python3 "$here/report.py" --results "$out" --rounds "$rounds" > "$out/REPORT.md"
log "wrote $out/REPORT.md; done in $(( $(date +%s) - t0 )) s"
