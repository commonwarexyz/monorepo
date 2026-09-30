#!/usr/bin/env bash
# The general optimizer corpus harness (docs/optimizer-plan.md O1).
#
#   bench/opt-corpus/run.sh [--quick] [--rounds N] [--only P1,P7] [--no-x86]
#                           [--layouts default,align] [--align] [--record] [--composition] [--out DIR]
#
# Three subjects per program in one binary: the corpus as emitted now
# (`cgen`), as emitted at plan O1 (`cgen_o1`, the frozen baselines/o1-gen.rs)
# and the ideal. A milestone's gain is `O1 / current` within one binary, in
# every layout: a gain read across binaries mixes in code placement (adding
# `cgen_o1` at O2 moved P20's unchanged code by +17% in the default layout).
#
# --layouts: the aarch64 code placements to build, each a separate binary
#   (default: both). `default` is plain `--release`; `align` aligns every
#   function and non-fallthrough block to 64 bytes. gains.md judges each gain
#   by its smallest value over the layouts. --align = --layouts align.
# --record: re-record the P15-P20 rows of recorded.tsv (the O1 emission / ideal
#   of the default layout) and the harness composition they belong to. Needs a
#   full run (no --quick, no --only) that includes the default layout.
# --composition: only compare the harness composition with recorded.tsv's
#   (exit 0 when they match, 3 when not); builds and runs nothing.
#
# Composition. What is linked into the binary moves code (placement), so the
# recorded P15-P20 rows are comparable only within one harness composition:
# the sha256 of every harness source that is compiled in, the frozen O1
# emission and `rustc -vV` (not the current emission, which changes by design:
# the in-binary O1 subject absorbs that). A run whose composition differs from
# recorded.tsv's still runs and reports everything, then fails (exit 3) until
# the rows are re-recorded with --record.
#
# 1. Emits the corpus (sandblaster/front/tests/opt_corpus/dsl) for
#    aarch64 and x86_64 with the front end's stage emitter
#    (`cargo run -p sandblaster-front --example stage_emit`: proofs, optimizer,
#    printer and round trip, header `STATUS: STAGE OUTPUT` — the corpus is a
#    toolchain test program, not a crate verdict, DESIGN.md §15.8) with
#    SANDBLASTER_STRICT_OPT=1 (an optimizer warning fails the run: gate G2).
# 2. aarch64 (this machine), per layout: checks (the ideal and the O1 emission
#    against the current emission), must-reject self-test, then the three-subject
#    timings (rotating rounds); P18 again under `overflow-checks = true`
#    (profile release-oc); E0 (`opt-corpus e0`, P18's kernel, plan O2).
# 3. x86_64: x86_64-apple-darwin builds at x86-64 and x86-64-v3 whose checks run
#    under Rosetta 2 (when it can execute them), and a compile-only
#    x86_64-unknown-linux-gnu build at x86-64-v4 (no Linux linker here: the
#    objects are generated, the link is stubbed).
#
# Every cargo and benchmark process goes through $HEAVY when it is set (the
# machine-wide admission wrapper); never run this script itself under it.
# Results: $OUT (default target/opt/opt-corpus/<date>): gen_*.rs, logs,
# bench-aarch64-<layout>[-oc].json/md, samecode-<layout>[-oc].json, e0-<layout>[-oc].md,
# gains.md, summary.md.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../../.." && pwd)
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$repo/target/opt}
H=${HEAVY:-}
quick="" rounds=3 only="" x86=1 out="" layouts="default,align" record=0 composition_only=0
while [ $# -gt 0 ]; do
    case $1 in
    --quick) quick=quick ;;
    --rounds) rounds=$2; shift ;;
    --only) only=$2; shift ;;
    --no-x86) x86=0 ;;
    --layouts) layouts=$2; shift ;;
    --align) layouts=align ;;
    --record) record=1 ;;
    --composition) composition_only=1 ;;
    --out) out=$2; shift ;;
    *) echo "usage: $0 [--quick] [--rounds N] [--only P1,P7] [--no-x86] [--layouts default,align] [--align] [--record] [--composition] [--out DIR]" >&2; exit 2 ;;
    esac
    shift
done
for l in ${layouts//,/ }; do
    case $l in default | align) ;; *) echo "unknown layout $l (default, align)" >&2; exit 2 ;; esac
done
if [ $record = 1 ] && { [ -n "$quick" ] || [ -n "$only" ] || [[ ",$layouts," != *",default,"* ]] || [ "$rounds" -lt 3 ]; }; then
    echo "--record needs a full run (no --quick or --only, >= 3 rounds) that includes the default layout" >&2
    exit 2
fi
out=${out:-$CARGO_TARGET_DIR/opt-corpus/$(date +%Y%m%d-%H%M%S)}
dsl=$repo/sandblaster/front/tests/opt_corpus/dsl/mod.rs
jobs=${CARGO_BUILD_JOBS:-4}
log() { echo "[opt-corpus] $*" | tee -a "$out/summary.md"; }
load() { uptime | sed 's/.*load averages*: //'; }
t0=$(date +%s)
# the harness composition (see above)
composition() {
    (cd "$here" && cat Cargo.toml Cargo.lock src/main.rs cgen/Cargo.toml cgen/build.rs cgen/src/lib.rs \
        cgen_o1/Cargo.toml cgen_o1/build.rs cgen_o1/src/lib.rs ideal/Cargo.toml ideal/src/*.rs baselines/o1-gen.rs
        rustc -vV) | shasum -a 256 | cut -d' ' -f1
}
comp=$(composition)
rec_comp=$(sed -n 's/^# composition \([0-9a-f]\{64\}\)\( .*\)*$/\1/p' "$here/recorded.tsv")
[ "$(grep -cE '^# composition ([0-9a-f]{64}|unrecorded)( |$)' "$here/recorded.tsv")" = 1 ] || { echo "recorded.tsv must have exactly one '# composition <sha256>' line" >&2; exit 2; }
if [ $composition_only = 1 ]; then
    echo "harness composition $comp; recorded.tsv: ${rec_comp:-unrecorded}"
    [ "$comp" = "$rec_comp" ] && exit 0 || exit 3
fi
mkdir -p "$out"
stale=0
log "out: $out; load: $(load); layouts: $layouts"
if [ "$comp" = "$rec_comp" ]; then
    log "harness composition ${comp:0:16}: the recorded P15-P20 rows belong to it"
else
    stale=1
    log "STALE: harness composition ${comp:0:16} differs from recorded.tsv's (${rec_comp:-unrecorded}): the recorded P15-P20 rows are not comparable (re-record with --record)"
fi
(cd "$here/baselines" && shasum -a 256 -c SHA256SUMS) > "$out/baselines.txt" || { cat "$out/baselines.txt"; log "FAIL: a frozen corpus baseline changed"; exit 1; }
(cd "$repo" && $H cargo build -q -j "$jobs" -p sandblaster-front --example stage_emit)
emitter=$CARGO_TARGET_DIR/debug/examples/stage_emit
for t in aarch64 x86_64; do
    if ! SANDBLASTER_STRICT_OPT=1 $H "$emitter" "$dsl" --target $t > "$out/gen_$t.rs" 2> "$out/emit_$t.log"; then
        cat "$out/emit_$t.log" >&2
        log "FAIL: emit for $t (strict)"
        exit 1
    fi
    if grep -q 'warning' "$out/emit_$t.log"; then
        log "FAIL: optimizer warnings in the strict corpus build for $t (gate G2)"
        exit 1
    fi
    log "emitted $t: $(shasum -a 256 "$out/gen_$t.rs" | cut -c1-16) ($(wc -l < "$out/gen_$t.rs") lines)"
done
# the emitted corpus is target-independent: the two files differ at most in the header
if ! diff -q <(tail -n +2 "$out/gen_aarch64.rs") <(tail -n +2 "$out/gen_x86_64.rs") > /dev/null; then
    log "note: the aarch64 and x86_64 corpus emissions differ"
fi

# ---- aarch64, one binary per layout
cd "$here"
for layout in ${layouts//,/ }; do
    case $layout in
    default) atd=$CARGO_TARGET_DIR aflags="" ;;
    align) atd=$CARGO_TARGET_DIR/opt-corpus-aligned aflags="-C llvm-args=-align-all-functions=6 -C llvm-args=-align-all-nofallthru-blocks=6" ;;
    esac
    log "aarch64 [$layout]: building"
    RUSTFLAGS="$aflags" CARGO_TARGET_DIR=$atd OPT_CORPUS_GENERATED_RS=$out/gen_aarch64.rs $H cargo build -q -j "$jobs" --release
    RUSTFLAGS="$aflags" CARGO_TARGET_DIR=$atd OPT_CORPUS_GENERATED_RS=$out/gen_aarch64.rs $H cargo build -q -j "$jobs" --profile release-oc
    bin=$atd/release/opt-corpus
    binoc=$atd/release-oc/opt-corpus
    python3 "$here/samecode.py" "$bin" > "$out/samecode-$layout.json"
    python3 "$here/samecode.py" "$binoc" > "$out/samecode-$layout-oc.json"
    $H "$bin" check | tee "$out/check-aarch64-$layout.txt"
    $H "$bin" check-reject | tee "$out/check-reject-aarch64-$layout.txt"
    log "aarch64 [$layout] bench: load before $(load)"
    args=(bench --rounds "$rounds" --json "$out/bench-aarch64-$layout.json")
    [ -n "$quick" ] && args+=(quick)
    [ -n "$only" ] && args+=(--only "$only")
    $H "$bin" "${args[@]}" | tee "$out/bench-aarch64-$layout.md"
    log "aarch64 [$layout] bench: load after $(load)"
    if [ -z "$only" ] || [[ ",$only," == *",P18,"* ]]; then
        ocargs=(bench --rounds "$rounds" --only P18 --json "$out/bench-aarch64-$layout-oc.json")
        [ -n "$quick" ] && ocargs+=(quick)
        $H "$binoc" "${ocargs[@]}" | tee "$out/bench-aarch64-$layout-oc.md"
        e0args=(e0 --rounds "$rounds")
        [ -n "$quick" ] && e0args+=(quick)
        $H "$binoc" "${e0args[@]}" --json "$out/e0-$layout-oc.json" | tee "$out/e0-$layout-oc.md"
        $H "$bin" "${e0args[@]}" --json "$out/e0-$layout.json" | tee "$out/e0-$layout.md"
    fi
done

# ---- gains: O1 / current per layout; rows whose two emissions compiled to the same machine
# code (samecode.py) measure code placement alone: their spread is the binary's noise floor
python3 - "$out" ${layouts//,/ } > "$out/gains.md" << 'EOF'
import json, os, sys
out, layouts = sys.argv[1], sys.argv[2:]
rows, same = {}, {}
for l in layouts:
    for suffix in ("", "-oc"):
        p = os.path.join(out, f"bench-aarch64-{l}{suffix}.json")
        if not os.path.exists(p):
            continue
        sc = json.load(open(os.path.join(out, f"samecode-{l}{suffix}.json")))
        for r in json.load(open(p))["rows"]:
            key = (r["program"], r["input"])
            rows.setdefault(key, {})[l] = r
            same.setdefault(key, {})[l] = sc.get(r["function"].split(" ")[0])
print("## Gains over the O1 emission, one binary per layout\n")
print("`O1 / current` per layout: > 1 means the current emission is faster. `=` marks a row whose current and O1 emissions compiled to the same machine code in that binary (`samecode.py`): its value is code placement alone. `judged` is the smallest value over the layouts, for rows whose code differs; a gain counts only if it clears the identical-code spread below in every layout.\n")
hdr = " | ".join(f"O1 / current [{l}]" for l in layouts)
rat = " | ".join(f"current / ideal [{l}]" for l in layouts)
print(f"| program | input | {hdr} | judged gain | {rat} |")
print("| --- | --- |" + " ---: |" * (2 * len(layouts) + 1))
spread = {l: [] for l in layouts}
fmt = lambda x, d=3: "—" if x is None else f"{x:.{d}f}"
for key, by in rows.items():
    cells, differs = [], []
    for l in layouts:
        if l not in by:
            cells.append("—")
            continue
        g = by[l]["gain"]
        if same[key].get(l):
            spread[l].append(g)
            cells.append(f"= {g:.3f}")
        else:
            differs.append(g)
            cells.append(f"{g:.3f}")
    cells.append(fmt(min(differs)) if differs else "identical code")
    cells += [fmt(by[l]["ratio"] if l in by else None, 2) for l in layouts]
    print(f"| {key[0]} | {key[1]} | " + " | ".join(cells) + " |")
print()
for l in layouts:
    v = spread[l]
    if v:
        print(f"- identical-code spread [{l}]: {len(v)} rows, O1 / current {min(v):.3f} .. {max(v):.3f} (median {sorted(v)[len(v) // 2]:.3f})")
EOF
cat "$out/gains.md"

# ---- re-record the P15-P20 rows of recorded.tsv (--record)
if [ $record = 1 ]; then
    python3 - "$here/recorded.tsv" "$out/bench-aarch64-default.json" "$out/bench-aarch64-default-oc.json" "$comp" "$(date +%Y-%m-%d)" "$(load)" << 'EOF'
import json, re, sys
path, js, jsoc, comp, day, load = sys.argv[1:]
new = {}
for p in (js, jsoc):
    for r in json.load(open(p))["rows"]:
        if r["program"] in ("P15", "P16", "P17", "P18", "P20"):
            new[(r["program"], r["input"])] = (r["o1_ns"], r["ideal_ns"])
old = open(path).read()
with open(path.replace("recorded.tsv", "recorded-history.tsv"), "a") as h:
    h.write(f"# ---- replaced on {day} by composition {comp}\n" + old)
lines, seen = [], set()
for l in old.split("\n"):
    if re.match(r"^# composition ([0-9a-f]{64}|unrecorded)( |$)", l):
        lines.append(f"# composition {comp} (P15-P20 rows: the O1 emission, default layout, run.sh --record {day}, load {load})")
        continue
    f = l.split("\t")
    if len(f) >= 4 and (f[0], f[1]) in new:
        g, i = new[(f[0], f[1])]
        lines.append(f"{f[0]}\t{f[1]}\t{g:.2f}\t{i:.2f}\tO1 emission, composition {comp[:12]}, {day}")
        seen.add((f[0], f[1]))
    else:
        lines.append(l)
missing = set(new) - seen
assert not missing, f"rows not in recorded.tsv: {missing}"
open(path, "w").write("\n".join(lines))
print(f"recorded {len(seen)} P15-P20 rows for composition {comp[:16]}")
EOF
    log "recorded the P15-P20 rows of recorded.tsv for composition ${comp:0:16} (previous file appended to recorded-history.tsv)"
    stale=0
fi

# ---- x86_64
if [ $x86 = 1 ]; then
    for cpu in x86-64 x86-64-v3; do
        td=$CARGO_TARGET_DIR/opt-corpus-x86/$cpu
        RUSTFLAGS="-C target-cpu=$cpu" OPT_CORPUS_GENERATED_RS=$out/gen_x86_64.rs CARGO_TARGET_DIR=$td $H cargo build -q -j "$jobs" --release --target x86_64-apple-darwin
        xbin=$td/x86_64-apple-darwin/release/opt-corpus
        log "built x86_64-apple-darwin target-cpu=$cpu: $(file -b "$xbin" | cut -c1-40)"
        if arch -x86_64 /usr/bin/true 2> /dev/null; then
            if $H arch -x86_64 "$xbin" check > "$out/check-x86_64-$cpu.txt" 2>&1; then
                log "x86_64 ($cpu, Rosetta 2) checks: $(grep -c 'agree' "$out/check-x86_64-$cpu.txt") passed lines"
            else
                log "x86_64 ($cpu, Rosetta 2) checks did not run to completion (see check-x86_64-$cpu.txt; Rosetta may lack the instructions)"
            fi
        fi
    done
    # compile-only: Linux at the AVX-512 level (objects generated, link stubbed)
    td=$CARGO_TARGET_DIR/opt-corpus-x86/linux-v4
    RUSTFLAGS="-C target-cpu=x86-64-v4" OPT_CORPUS_GENERATED_RS=$out/gen_x86_64.rs CARGO_TARGET_DIR=$td \
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$here/nolink.sh" \
        $H cargo rustc -q -j "$jobs" --release --target x86_64-unknown-linux-gnu --bin opt-corpus -- --emit=obj,link
    log "compiled x86_64-unknown-linux-gnu target-cpu=x86-64-v4: $(ls "$td"/x86_64-unknown-linux-gnu/release/deps/*.o 2> /dev/null | wc -l | tr -d ' ') object file(s)"
fi
log "done in $(( $(date +%s) - t0 )) s"
if [ $stale = 1 ]; then
    log "FAIL: the harness composition changed since the recorded P15-P20 rows were taken; every result above is valid, but re-record them (run.sh --record) before comparing with recorded values"
    exit 3
fi
