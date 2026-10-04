#!/usr/bin/env bash
# Self-test of G6 (sandblaster/tools/gates/g6.sh) on a scratch copy of the
# files it reads: every way of changing a frozen file must fail the check
# (the negative twins), and `--record` must refuse (exit 1, frozen.sha256
# byte-identical) instead of re-baselining it. Only genuinely new files may
# be recorded. No cargo; runs in a few seconds.
#
#   sandblaster/tools/gates/g6-selftest.sh
#   G6_UNDER_TEST=<g6.sh> G6_FROZEN_UNDER_TEST=<frozen.sha256> sandblaster/tools/gates/g6-selftest.sh
#                  (another version of the gate, e.g. to show an old one fails)
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/g6-selftest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
corpus=sandblaster/front/tests/opt_corpus
qmdb=sandblaster/fixtures/qmdb
fresh() {
    rm -rf "$tmp/r"
    mkdir -p "$tmp/r/sandblaster/tools/gates" "$tmp/r/sandblaster/fixtures" "$tmp/r/sandblaster/bench/opt-corpus/ideal" "$tmp/r/$(dirname $corpus)"
    cp "$gates/common.sh" "$tmp/r/sandblaster/tools/gates/"
    cp "${G6_UNDER_TEST:-$gates/g6.sh}" "$tmp/r/sandblaster/tools/gates/g6.sh"
    cp "${G6_FROZEN_UNDER_TEST:-$gates/frozen.sha256}" "$tmp/r/sandblaster/tools/gates/frozen.sha256"
    cp -R "$repo/$qmdb" "$tmp/r/sandblaster/fixtures/"
    cp -R "$repo/sandblaster/bench/opt-corpus/baselines" "$tmp/r/sandblaster/bench/opt-corpus/"
    cp -R "$repo/sandblaster/bench/opt-corpus/ideal/src" "$tmp/r/sandblaster/bench/opt-corpus/ideal/"
    cp -R "$repo/$corpus" "$tmp/r/$corpus"
    if [ -d "$repo/sandblaster/bench/heldout" ]; then cp -R "$repo/sandblaster/bench/heldout" "$tmp/r/sandblaster/bench/"; fi
    if [ -d "$repo/sandblaster/bench/heldout-v2" ]; then cp -R "$repo/sandblaster/bench/heldout-v2" "$tmp/r/sandblaster/bench/"; fi
}
g6() { (cd "$tmp/r" && bash sandblaster/tools/gates/g6.sh "$@") > "$tmp/log" 2>&1; }
fails=0
ok() { say "ok: $*"; }
bad() { say "FAIL: $*"; sed 's/^/    /' "$tmp/log"; fails=$((fails + 1)); }
# expect_refused NAME: the check fails, --record refuses and leaves frozen.sha256
# unchanged, and the check still fails afterwards
expect_refused() {
    local before
    before=$(shasum -a 256 < "$tmp/r/sandblaster/tools/gates/frozen.sha256")
    if g6; then bad "$1: the check passed"; return; fi
    if g6 --record; then bad "$1: --record succeeded"; return; fi
    [ "$(shasum -a 256 < "$tmp/r/sandblaster/tools/gates/frozen.sha256")" = "$before" ] || { bad "$1: --record rewrote frozen.sha256"; return; }
    if g6; then bad "$1: the check passes after --record"; return; fi
    ok "$1: check fails, --record refuses, frozen.sha256 unchanged"
}
edit() { sed -i.bak "$1" "$tmp/r/$2" && rm "$tmp/r/$2.bak"; }

fresh
g6 && ok "the repository's state passes" || bad "the repository's state fails the check"
g6 --record && ok "--record on the recorded state succeeds" || bad "--record on the recorded state refused"

# the QMDB sources (pinned in g6.sh)
fresh; echo '// drift' >> "$tmp/r/$qmdb/sandblaster/codec.rs"
expect_refused "a changed QMDB source"
fresh; rm "$tmp/r/$qmdb/sandblaster/merkle.rs"
expect_refused "a deleted QMDB source"
fresh; echo 'pub fn x() {}' > "$tmp/r/$qmdb/sandblaster/spec/extra.rs"
expect_refused "a new file among the QMDB sources"
fresh; echo '# re-accepted' >> "$tmp/r/$qmdb/sandblaster/SPEC.lock"
g6 && ok "a re-accepted QMDB lock is not a source change" || bad "a re-accepted QMDB lock fails the check"
fresh; shasum -a 256 "$tmp/r/$qmdb/sandblaster/codec.rs" | sed "s| $tmp/r/| |" >> "$tmp/r/sandblaster/tools/gates/frozen.sha256"
if g6; then bad "QMDB sources listed in frozen.sha256: the check passed"; else ok "QMDB sources listed in frozen.sha256 fail the check"; fi

# the corpus
fresh; edit 's/0x2D/0x2B/; s/0x002D/0x002B/' "$corpus/dsl/p17_gf16_mul.rs"
expect_refused "a changed corpus program"
fresh; edit 's/bit_length_go(64, x, 0)/bit_length_go(63, x, 0)/' "$corpus/dsl/mod.rs"
expect_refused "a changed frozen P1-P14 region"
fresh; echo '// drift' >> "$tmp/r/$corpus/must_reject.rs"
expect_refused "a changed must-reject variant"
fresh; edit 's/bit_length_go(63, x, 0)/bit_length_go(64, x, 0)/' "$corpus/conv_pairs.rs"
expect_refused "a conversion mutant turned into its control"

# the corpus harness: the frozen O1 emission and the hand-written references (J15)
fresh; echo '// drift' >> "$tmp/r/sandblaster/bench/opt-corpus/baselines/o1-gen.rs"
expect_refused "a changed corpus baseline"
fresh; rm "$tmp/r/sandblaster/bench/opt-corpus/baselines/o1-gen.rs"
expect_refused "a deleted corpus baseline"
fresh; edit 's/#\[inline(never)\]//' "sandblaster/bench/opt-corpus/ideal/src/lib.rs"; echo '// drift' >> "$tmp/r/sandblaster/bench/opt-corpus/ideal/src/lib.rs"
expect_refused "an edited hand-written reference (ideal/)"

# the QMDB fixture data and the profile/timing split (J8)
fresh; f=$(ls "$tmp/r/$qmdb/fixtures-n32" | grep '^[0-9]' | sed -n 1p); edit 's/"expected": *true/"expected": false/' "$qmdb/fixtures-n32/$f"; echo ' ' >> "$tmp/r/$qmdb/fixtures-n32/$f"
expect_refused "an edited QMDB fixture"
fresh; cp "$tmp/r/$qmdb/fixtures-n32/$f" "$tmp/r/$qmdb/fixtures-n32/999-added.json"
expect_refused "a fixture added to a frozen QMDB corpus"
fresh; rm "$tmp/r/$qmdb/fixtures/$(ls "$tmp/r/$qmdb/fixtures" | sed -n 1p)"
expect_refused "a fixture removed from a frozen QMDB corpus"
fresh; t=$(sed -n '/^\.\./{p;q;}' "$tmp/r/$qmdb/splits/n32-timed.txt"); echo "$t" >> "$tmp/r/$qmdb/splits/n32-profile.txt"
expect_refused "a timed fixture moved into the profile half"

# the one legitimate use: new files are appended, nothing else changes
# (after absorbing whatever the repository has not recorded yet)
fresh
g6 --record || bad "--record on the repository's state refused"
printf '//! P99: a new program.\nuse sandblaster::prelude::*;\npub fn p99(x: u64) -> u64 {\n    x\n}\n' > "$tmp/r/$corpus/dsl/p99_new.rs"
before=$(cat "$tmp/r/sandblaster/tools/gates/frozen.sha256")
if g6 && grep -q 'p99_new.rs is not recorded yet' "$tmp/log"; then ok "a new corpus program passes the check with a note"; else bad "a new corpus program"; fi
if g6 --record; then
    after=$(cat "$tmp/r/sandblaster/tools/gates/frozen.sha256")
    new=$(diff <(echo "$before") <(echo "$after") | grep '^>' || true)
    if [ "${after:0:${#before}}" = "$before" ] && [ "$(echo "$new" | wc -l | tr -d ' ')" = 1 ] && echo "$new" | grep -q " $corpus/dsl/p99_new.rs\$"; then
        ok "--record appends exactly the new program"
    else
        bad "--record changed more than the new program: $new"
    fi
    g6 && ok "the check passes after recording it" || bad "the check fails after recording the new program"
    echo '// drift' >> "$tmp/r/$corpus/dsl/p99_new.rs"
    expect_refused "a recorded new program changed afterwards"
else
    bad "--record refused a new corpus program"
fi
# the held-out manifest: committed and recorded before measuring, then frozen
fresh
g6 --record > /dev/null 2>&1 || true
mkdir -p "$tmp/r/sandblaster/bench/heldout"
printf '# held-out manifest (self-test)\nseed = 1\n' > "$tmp/r/sandblaster/bench/heldout/selftest-new.toml"
if g6 && grep -q 'heldout/selftest-new.toml is not recorded yet' "$tmp/log"; then ok "a new held-out manifest passes the check with a note"; else bad "a new held-out manifest"; fi
if g6 --record && g6; then
    echo 'seed = 2' >> "$tmp/r/sandblaster/bench/heldout/selftest-new.toml"
    expect_refused "a recorded held-out manifest changed afterwards"
else
    bad "--record refused a new held-out manifest"
fi
# the held-out report is generated (bench/heldout-harness/run.sh rewrites it on
# every run), and Python writes caches beside its scripts: --record freezes
# neither, so a regenerated report never fails the next run's G6
fresh
mkdir -p "$tmp/r/sandblaster/bench/heldout/h2/__pycache__"
printf 'report 1\n' > "$tmp/r/sandblaster/bench/heldout/REPORT.md"
printf 'cache\n' > "$tmp/r/sandblaster/bench/heldout/h2/__pycache__/x.pyc"
if g6 --record && ! grep -qE 'heldout/REPORT\.md|__pycache__' "$tmp/r/sandblaster/tools/gates/frozen.sha256"; then
    printf 'report 2\n' > "$tmp/r/sandblaster/bench/heldout/REPORT.md"
    rm -rf "$tmp/r/sandblaster/bench/heldout/h2/__pycache__"
    g6 && ok "the generated held-out report and Python caches are never frozen" || bad "a regenerated held-out report fails G6"
else
    bad "--record froze the generated held-out report or a Python cache"
fi

# held-out v2 (frozen before the reader and optimizer work): its rule, seed
# and blind set cannot be edited or removed once recorded, and its generated
# report is never frozen. v2 FILE: a fresh copy with held-out v2 recorded (a
# placeholder rule and manifest stand in when the repository has none yet)
v2_rule=sandblaster/bench/heldout-v2/h2/RULE.md
v2_manifest=sandblaster/bench/heldout-v2/manifest.toml
v2() {
    fresh
    mkdir -p "$tmp/r/$(dirname $v2_rule)"
    [ -f "$tmp/r/$v2_rule" ] || printf '# rule (self-test)\nseed = 1\n' > "$tmp/r/$v2_rule"
    [ -f "$tmp/r/$v2_manifest" ] || printf 'seed = "1"\n' > "$tmp/r/$v2_manifest"
    g6 --record > /dev/null 2>&1
}
if v2 && g6; then
    echo 'seed = 2' >> "$tmp/r/$v2_rule"
    expect_refused "an edited held-out v2 rule"
    v2; edit 's/seed/Seed/' "$v2_manifest"
    expect_refused "an edited held-out v2 manifest"
    v2; rm "$tmp/r/$v2_rule"
    expect_refused "a removed held-out v2 rule"
    v2; printf 'report 1\n' > "$tmp/r/sandblaster/bench/heldout-v2/REPORT.md"
    if g6 --record && ! grep -q 'heldout-v2/REPORT\.md' "$tmp/r/sandblaster/tools/gates/frozen.sha256"; then
        printf 'report 2\n' > "$tmp/r/sandblaster/bench/heldout-v2/REPORT.md"
        g6 && ok "the generated held-out v2 report is never frozen" || bad "a regenerated held-out v2 report fails G6"
    else
        bad "--record froze the generated held-out v2 report"
    fi
else
    bad "--record refused the held-out v2 files"
fi

[ $fails = 0 ] && say "pass: G6 detects every change and --record only appends"
exit $((fails > 0))
