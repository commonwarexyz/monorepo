#!/usr/bin/env bash
# G6 zero source change (docs/optimizer-plan.md §0.4), ported from the
# toolchain's previous repository and extended by the fairness audit
# (2026-10-02, J10/J15): what the optimizer is measured on cannot be edited
# to fit the optimizer.
#
#   sandblaster/tools/gates/g6.sh            check
#   sandblaster/tools/gates/g6.sh --record   add new frozen files to
#                                            frozen.sha256 (additions only)
#
# Frozen:
# * the QMDB fixture's DSL sources (sandblaster/fixtures/qmdb/sandblaster/,
#   every file but the SPEC*.lock files, which `sandblaster spec --accept`
#   rewrites): pinned below, in this script, never in frozen.sha256. Only a
#   deliberate, reviewed edit of this script can change them (never an
#   optimizer change: G6 forbids changing the program to fit the optimizer);
# * frozen.sha256: the corpus (the frozen P1-P14 region of dsl/mod.rs, every
#   program file, the must-reject candidates and conversion pairs), the
#   corpus harness's frozen O1 emission (bench/opt-corpus/baselines) and its
#   hand-written references (bench/opt-corpus/ideal/src, J15), the QMDB
#   fixture data (proof fixtures, test vectors, the baseline loader and the
#   Bend corpus: one `#tree` entry per directory), the QMDB profile/timing
#   split (fixtures/qmdb/splits, J8) and the held-out evaluation's files
#   (sandblaster/bench/heldout/, v1, now development but still frozen, and
#   sandblaster/bench/heldout-v2/, frozen before any reader or optimizer
#   work: each manifest is committed and recorded here before anything is
#   measured on it), except a generated REPORT.md, which
#   bench/heldout-harness/run.sh rewrites on every run, and Python caches
#   (`__pycache__/`): freezing either would fail the next run's G6.
#
# Entry kinds in frozen.sha256: `<sum>  <file>`, `<sum>  <file>#frozen-prefix`
# (the part of the corpus root above its `// ---- additions` line) and
# `<sum>  <dir>#tree` (the sum of the sorted per-file sums of a directory).
#
# --record never changes or drops an entry: it refuses (exit 1, the file
# untouched) when any pinned or recorded file changed or is missing, and
# otherwise only appends the files not yet recorded. g6-selftest.sh checks
# all of this on a scratch copy. No cargo.
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
cd "$repo"
corpus=sandblaster/front/tests/opt_corpus
qmdb=sandblaster/fixtures/qmdb
heldout=sandblaster/bench/heldout
heldout2=sandblaster/bench/heldout-v2
frozen=$gates/frozen.sha256
QMDB_SOURCES='857a529aca08725e547904d8a554af18d2cbbbddc8215117c7f3b650af6fc778  sandblaster/fixtures/qmdb/sandblaster/LAWS.rs
63c1523e74ac4d052756fdb52a9f1ea7447588fa617ad570b32e08e6a8fc50ae  sandblaster/fixtures/qmdb/sandblaster/MODEL.rs
a2092f62131f06956e9adde343f0aedad69ce801ca5e6aa5e22ac3ec6243aef3  sandblaster/fixtures/qmdb/sandblaster/PROOF.rs
7645ab1c22a3cddd2c2557a7f77002cb8761745cb80582e972797bccd5bc0858  sandblaster/fixtures/qmdb/sandblaster/codec.rs
d5383f0d3a2b5e93f56d8509916c35f8d411cb1f55c8f9434315ecc6f2d5abbd  sandblaster/fixtures/qmdb/sandblaster/config.rs
5926989495d362db1216442153a79ee5ec6497b716772fb48996bf7885bd63fb  sandblaster/fixtures/qmdb/sandblaster/config_n1.rs
ebe3fe52fd2d4c73101b41f741e1eb3fd253c11b3e25a320fe070da3f382e085  sandblaster/fixtures/qmdb/sandblaster/merkle.rs
39e403fe5cddaca18f52f5e149cbfb39506c8f9b0063f929e9d057f4f194c23e  sandblaster/fixtures/qmdb/sandblaster/mod.rs
b6d86f92d237c20ab6dc9bce53f386bfd057e1cee7714e9405ca4481caff224b  sandblaster/fixtures/qmdb/sandblaster/n1.rs
8d79f036a75fd4e682acfbf97d3b2013628730c8d27d1e777312f40a8e16393f  sandblaster/fixtures/qmdb/sandblaster/sha256.rs
0fe27e75774f767489dc3fa1ed27711db375959b9d5cb1ed48d661b724b7d0f9  sandblaster/fixtures/qmdb/sandblaster/spec/codec.rs
dc8dabfd5d517145715fc69174f7ed5ac300aed7da10c7d11e665bee817bc5c5  sandblaster/fixtures/qmdb/sandblaster/spec/config.rs
7c5a68974097877102c0cdb2b2295d0f5fd8599e08a303315a96922c06532b7e  sandblaster/fixtures/qmdb/sandblaster/spec/config_n1.rs
3d99c76f28860d0a5373c996210610180a5c809aff33294189a2b1c6acf4926d  sandblaster/fixtures/qmdb/sandblaster/spec/db.rs
abe0e80e45d00126baaefb81f65002a1ef63cdf5dab474a305db797b95363f3e  sandblaster/fixtures/qmdb/sandblaster/spec/mod.rs
f2d34415588f950a092791c1d5ed4ea43914b2dd42368f4753bf996747523f80  sandblaster/fixtures/qmdb/sandblaster/spec/proof.rs
4249c1096d05fb6c01d94356819e571c1ae5ede1cfddbb180d0253a814656d2d  sandblaster/fixtures/qmdb/sandblaster/spec/sha256.rs
74d541e0fc7b48dfe08cf435201a9663b9e8852b43338c5899a5122b3a8a671e  sandblaster/fixtures/qmdb/sandblaster/spec/tree.rs
0637b6689ea131f056d4b7de98ef214d65c73bcc1b2abbbec2b254796cd38460  sandblaster/fixtures/qmdb/sandblaster/verifier.rs'
prefix() { sed '/^\/\/ ---- additions/,$d' "$1" | shasum -a 256 | cut -d' ' -f1; }
tree() { (cd "$1" && find . -type f ! -name .DS_Store -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256) | shasum -a 256 | cut -d' ' -f1; }
# the sum of an entry (file, #frozen-prefix or #tree), empty when it is missing
sum_of() {
    case $1 in
    *#frozen-prefix) [ -f "${1%#*}" ] && prefix "${1%#*}" ;;
    *#tree) [ -d "${1%#tree}" ] && tree "${1%#tree}" ;;
    *) [ -f "$1" ] && shasum -a 256 "$1" | cut -d' ' -f1 ;;
    esac
    return 0
}
# every entry G6 freezes besides the QMDB sources (what --record may add)
list() {
    ls "$corpus"/dsl/p*.rs
    ls "$corpus"/must_reject.rs "$corpus"/must_reject_controls.rs "$corpus"/conv_pairs.rs 2> /dev/null || true
    ls sandblaster/bench/opt-corpus/baselines/* 2> /dev/null | grep -v -e SHA256SUMS -e README || true
    ls sandblaster/bench/opt-corpus/ideal/src/*.rs 2> /dev/null || true
    for d in fixtures fixtures-n1 fixtures-n32 vectors baseline; do
        [ -d "$qmdb/$d" ] && echo "$qmdb/$d#tree"
    done
    ls "$qmdb"/splits/* 2> /dev/null || true
    # the held-out evaluations, v1 and v2: manifest.toml, h1/ and h2/ (every file)
    for h in "$heldout" "$heldout2"; do
        [ -d "$h" ] && find "$h" -type f ! -name .DS_Store ! -path "$h/REPORT.md" ! -path '*/__pycache__/*' | LC_ALL=C sort
    done
    return 0
}
# whether frozen.sha256 has an entry for exactly this path
recorded() { awk -v p="$1" '$2 == p { found = 1 } END { exit !found }' "$frozen"; }
fail=0
# 1. the QMDB sources: exactly the pinned files, each with its pinned sum
while read -r sum path; do
    [ -f "$path" ] || { say "FAIL: $path is missing"; fail=1; continue; }
    [ "$(shasum -a 256 "$path" | cut -d' ' -f1)" = "$sum" ] || { say "FAIL: $path changed (the QMDB sources are pinned in g6.sh)"; fail=1; }
done <<< "$QMDB_SOURCES"
while read -r f; do
    grep -q " $f\$" <<< "$QMDB_SOURCES" || { say "FAIL: $f is not a pinned QMDB source"; fail=1; }
done < <(find "$qmdb/sandblaster" -type f ! -name '*.lock' ! -name .DS_Store | LC_ALL=C sort)
if grep -q " $qmdb/sandblaster/" "$frozen"; then
    say "FAIL: frozen.sha256 lists QMDB sources (they are pinned in g6.sh only)"; fail=1
fi
# 2. every recorded entry
while read -r sum path; do
    got=$(sum_of "$path")
    [ -n "$got" ] || { say "FAIL: ${path%#*} is missing"; fail=1; continue; }
    if [ "$got" != "$sum" ]; then
        case $path in
        *#frozen-prefix) say "FAIL: the frozen P1-P14 region of ${path%#*} changed" ;;
        *#tree) say "FAIL: ${path%#tree}/ changed (a file was edited, added or removed)" ;;
        *) say "FAIL: $path changed" ;;
        esac
        fail=1
    fi
done < "$frozen"
grep -q '#frozen-prefix$' "$frozen" || { say "FAIL: frozen.sha256 has no frozen-prefix entry"; fail=1; }
if [ "${1:-}" = --record ]; then
    if [ $fail != 0 ]; then
        say "refusing to record: --record only adds entries, and the state above is not the recorded one (frozen.sha256 unchanged)"
        exit 1
    fi
    added=0
    while read -r f; do
        recorded "$f" && continue
        echo "$(sum_of "$f")  $f" >> "$frozen"
        say "recorded $f"
        added=$((added + 1))
    done < <(list)
    say "recorded $added new entr$([ $added = 1 ] && echo y || echo ies); $(wc -l < "$frozen" | tr -d ' ') in frozen.sha256"
    exit 0
fi
# additions only: a frozen file not yet recorded is new (record it)
while read -r f; do
    recorded "$f" || say "note: $f is not recorded yet (sandblaster/tools/gates/g6.sh --record)"
done < <(list)
[ $fail = 0 ] && say "pass: $(wc -l <<< "$QMDB_SOURCES" | tr -d ' ') pinned QMDB sources and $(wc -l < "$frozen" | tr -d ' ') frozen files, trees and regions unchanged"
exit $fail
