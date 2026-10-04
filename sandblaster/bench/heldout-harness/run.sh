#!/usr/bin/env bash
# The held-out evaluation (fairness audit of 2026-10-02, evaluation protocol;
# plan step 8): the one script that produces sandblaster/bench/heldout-v2/REPORT.md
# (held-out v2, the held-out set; the default) and sandblaster/bench/heldout/REPORT.md
# (held-out v1, development data since 2026-10-02: `--set v1`).
#
#   sandblaster/bench/heldout-harness/run.sh [--set v1|v2] [--rounds N] [--out DIR] [--no-align] [--no-nooc]
#
# 1. Gates: G6 (the held-out set, the corpus and the references are frozen)
#    and the fair-baseline rule for this harness (one profile, one binary,
#    the identity check, an A/A subject, the rustc subject built from the
#    frozen source).
# 2. Extracts rustc's MIR of H1 (v2: h1v2/h1.sbmir via extract-v2/; v1:
#    h1/h1.sbmir via extract/; the frozen file as module `h1`), builds the
#    front end's `heldout_eval` example and runs the exec-only optimizer
#    (always on; OptOptions::default with only `exclude_user_rewrites` set;
#    no profile) on every H1 function and every H2 function (evaluate.py
#    --set). It writes the optimized subject's lowered copies (v2: gen/v2/h1.rs,
#    gen/v2/h2_opt.rs; v1: gen/h1.rs, gen/h2_opt.rs) and the rustc subject's H2
#    text (v2: gen/v2/h2_source.rs, by evaluate.py; v1: gen/h2_source.rs).
# 3. Per binary (layout `default`, layout `align`: every function and
#    non-fallthrough block aligned to 64 bytes; profile `release`, Commonware's
#    overflow checks on, and `release-nooc`, default layout): samecode.py (the
#    identity check, rows with identical code are `=`), the differential
#    check, then the timings (>= 21 interleaved rounds, medians) of the set's
#    functions (`--set`), the load average before and after.
# 4. report.py writes the set's REPORT.md from the results (v2:
#    results/v2/; v1: results/latest/).
#
# Held-out v1 is development data since 2026-10-02 (heldout/README.md): this
# script runs it (`--set v1`) as a development-set regression check, and the
# report says so. The protocol is unchanged; the held-out evaluation is
# held-out v2 (sandblaster/bench/heldout-v2/, the default), whose results
# nobody reads while building optimizer passes (protocol item 3).
#
# Every cargo and benchmark process goes through $HEAVY when it is set (the
# machine-wide admission wrapper); never run this script itself under it.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../../.." && pwd)
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$repo/target/heldout}
H=${HEAVY:-}
rounds=31 out="" align=1 nooc=1 set=v2
while [ $# -gt 0 ]; do
    case $1 in
    --set) set=$2; shift ;;
    --rounds) rounds=$2; shift ;;
    --out) out=$2; shift ;;
    --no-align) align=0 ;;
    --no-nooc) nooc=0 ;;
    *) echo "usage: $0 [--set v1|v2] [--rounds N (>= 21)] [--out DIR] [--no-align] [--no-nooc]" >&2; exit 2 ;;
    esac
    shift
done
[ "$rounds" -ge 21 ] || { echo "the held-out protocol needs at least 21 rounds" >&2; exit 2; }
# per set: the results directory, the report, the H1 extraction crate and MIR
case $set in
v1) results=$here/results/latest report=sandblaster/bench/heldout/REPORT.md xpkg=heldout_h1_mir xdir=extract h1mir=h1/h1.sbmir prevname=heldout-previous-eval.json ;;
v2) results=$here/results/v2 report=sandblaster/bench/heldout-v2/REPORT.md xpkg=heldout_h1v2_mir xdir=extract-v2 h1mir=h1v2/h1.sbmir prevname=heldout-v2-previous-eval.json ;;
*) echo "--set v1 or v2" >&2; exit 2 ;;
esac
out=${out:-$results}
# the previous run's records, for the report's "change since the previous run"
prev=$CARGO_TARGET_DIR/$prevname
mkdir -p "$CARGO_TARGET_DIR"; rm -f "$prev"
[ -f "$out/eval.json" ] && cp "$out/eval.json" "$prev"
rm -rf "$out"; mkdir -p "$out"
work=$CARGO_TARGET_DIR/heldout-eval-work-$set
log() { echo "[heldout] $*" | tee -a "$out/run.log"; }
load() { sysctl -n vm.loadavg 2> /dev/null | tr -d '{}' | xargs || uptime | sed 's/.*load averages*: //'; }
t0=$(date +%s)
log "set: $set; out: $out; load: $(load); rounds: $rounds"

# ---- 1. gates
bash "$repo/sandblaster/tools/gates/g6.sh" | tee "$out/g6.txt" || { log "FAIL: G6 (a frozen held-out, corpus or reference file changed)"; exit 1; }
bash "$repo/sandblaster/tools/gates/fair-baseline.sh" --heldout "$here" | tee "$out/fair-baseline.txt" || { log "FAIL: the fair-baseline rule"; exit 1; }

# ---- 2. the optimizer on the held-out set
(cd "$repo" && SBMIR_TARGET_DIR=$CARGO_TARGET_DIR/mirx $H "$repo/sandblaster/mirx/extract.sh" $xpkg h1 sandblaster/bench/heldout-harness/$h1mir \
    --manifest sandblaster/bench/heldout-harness/$xdir/Cargo.toml) > "$out/extract.log" 2>&1 || { cat "$out/extract.log"; log "FAIL: MIR extraction of H1"; exit 1; }
(cd "$repo" && $H cargo build --release -q -p sandblaster-front --example heldout_eval)
# H2's source text for the rustc subject (v2: evaluate.py writes gen/v2/h2_source.rs from the sample)
[ $set = v1 ] && python3 "$here/items.py" "$repo/utils/src/rng.rs" mix64 --label utils/src/rng.rs > "$here/gen/h2_source.rs"
python3 "$here/evaluate.py" --set $set --work "$work" --eval "$CARGO_TARGET_DIR/release/examples/heldout_eval" ${H:+--heavy "$H"} | tee "$out/evaluate.txt"
cp "$work/eval.json" "$out/eval.json"
log "optimizer: $(python3 -c "import json,sys; r=json.load(open(sys.argv[1])); fs=r['h1']+r['h2']; print(sum(f['changed'] for f in fs), 'of', len(fs), 'functions changed')" "$out/eval.json")"

# ---- 3. one binary per layout / profile
binaries="default:release"
[ $align = 1 ] && binaries="$binaries align:release"
[ $nooc = 1 ] && binaries="$binaries default:release-nooc"
cd "$here"
for b in $binaries; do
    layout=${b%%:*} profile=${b#*:}
    case $layout in
    default) flags="" ;;
    align) flags="-C llvm-args=-align-all-functions=6 -C llvm-args=-align-all-nofallthru-blocks=6" ;;
    esac
    tag=$layout-$profile
    log "[$tag] building"
    RUSTFLAGS="$flags" $H cargo build -q --profile "$profile"
    bin=$out/heldout-bench-$tag
    cp "$CARGO_TARGET_DIR/$profile/heldout-bench" "$bin"
    python3 "$repo/sandblaster/bench/opt-corpus/samecode.py" "$bin" --crates subj_rustc,subj_rustc_aa,subj_opt --ignore-panic-locations > "$out/samecode-$tag.json"
    python3 "$repo/sandblaster/bench/opt-corpus/samecode.py" "$bin" --crates subj_rustc,subj_rustc_aa,subj_opt --ignore-panic-locations --data-blind > "$out/samecode-blind-$tag.json"
    $H "$bin" check --set $set > "$out/check-$tag.txt" || { cat "$out/check-$tag.txt"; log "FAIL: [$tag] the differential check"; exit 1; }
    before=$(load)
    $H "$bin" bench --set $set --rounds "$rounds" --json "$out/bench-$tag.json" | tee "$out/bench-$tag.md"
    after=$(load)
    echo "{\"before\": \"$before\", \"after\": \"$after\"}" > "$out/load-$tag.json"
    log "[$tag] load before: $before; after: $after"
    rm -f "$bin"
done

# ---- 4. the report
python3 "$here/report.py" --set $set --results "$out" --rounds "$rounds" --previous "$prev" > "$repo/$report"
log "wrote $report; done in $(( $(date +%s) - t0 )) s"
