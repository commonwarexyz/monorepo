#!/usr/bin/env bash
# The fair-baseline rule of a benchmark harness (fairness audit of
# 2026-10-02, guards list): a speedup is read against a subject compiled the
# same way, in the same binary.
#
#   sandblaster/tools/gates/fair-baseline.sh [HARNESS_DIR]   (default: sandblaster/bench/opt-corpus)
#   sandblaster/tools/gates/fair-baseline.sh --heldout [DIR] (default: sandblaster/bench/heldout-harness)
#   sandblaster/tools/gates/fair-baseline.sh --selftest      (the negative twins of both)
#
# Checked on the harness's sources (no cargo):
# 1. one profile for every subject: no per-package profile override
#    (`[profile.<p>.package.<crate>]`) and no `profile.<p>.build-override`
#    in the harness's Cargo.toml (opt-level, overflow-checks, codegen-units,
#    LTO and debug-assertions are then the same for all subjects), and no
#    subject's build script passing its own codegen flags
#    (`cargo:rustc-flags`, `cargo::rustc-flags`, `-C` in `rustc-link-arg`);
# 2. one binary: the harness's package depends on every subject crate of the
#    workspace (each is linked into the binary that times them);
# 3. the identity check: the runner invokes `samecode.py` on each binary it
#    times (rows whose subjects compiled to the same machine code are
#    placement noise, printed `=`): a `python3 … samecode.py` command line,
#    not a comment or a string that names the script.
# The corpus harness has no rustc subject (its baseline is the frozen O1
# emission, compiled in the same binary). The held-out harness (`--heldout`,
# plan step 8) has one, and must also have:
# 4. one crate source: every subject package compiles the same `[lib] path`
#    (the package's feature selects the module, J11);
# 5. an A/A subject: a second package with the rustc subject's lib path and
#    features (`<rustc subject>_aa`), linked into the same binary;
# 6. the rustc subject built from the frozen source: under the `source`
#    feature, H1 is `#[path]`-included from `heldout/h1/src/lib.rs`, a file
#    G6 has recorded (frozen.sha256, unchanged); any hand-written variants a
#    subject uses would be in the shared source, so both subjects get them;
# 7. the runner refuses fewer than 21 rounds and runs the differential check
#    before it times anything (`rounds >= 21` outside a string, and
#    `if !check(&cases)` within the 8 lines before each `bench(&cases`, in
#    code: comments are not read).
# These are text checks, so comments never count: a comment that names the
# identity check or the round floor satisfies nothing (each has a twin in
# --selftest).
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
# `$1` without shell comments (a `#` at the start of a line or after
# whitespace, to the end of the line)
shell_code() { sed -E 's/(^|[[:space:]])#.*$//' "$1"; }
# `$1` without Rust comments (one-line `/* .. */` blocks and `//` to the end
# of the line)
rust_code() { sed -E 's#/\*([^*]|\*+[^*/])*\*+/##g; s#//.*$##' "$1"; }
# whether the shell script `$1` runs samecode.py (a python3 command line)
runs_samecode() { shell_code "$1" 2> /dev/null | grep -qE '(^|[[:space:];|&(])python3?[[:space:]]+"?[^[:space:]"]*samecode\.py'; }
check() {
    local dir=$1 fail=0
    local toml=$dir/Cargo.toml
    [ -f "$toml" ] || { say "FAIL: $toml is missing"; return 1; }
    if grep -nE '^\[profile\.[A-Za-z0-9_-]+\.(package|build-override)' "$toml"; then
        say "FAIL: $toml overrides the profile per package or for build scripts: the subjects would not be compiled alike"
        fail=1
    fi
    local b
    for b in "$dir"/*/build.rs "$dir"/build.rs; do
        [ -f "$b" ] || continue
        if grep -nE 'rustc-flags|rustc-link-arg[^"]*-C' "$b"; then
            say "FAIL: $b passes its own codegen flags"
            fail=1
        fi
    done
    # every workspace member but the harness itself is a dependency of the harness
    local members m
    members=$(sed -n '/^\[workspace\]/,/^\[/p' "$toml" | sed -n 's/^members *= *\[\(.*\)\]/\1/p' | tr -d '" ' | tr ',' '\n' | grep -v '^\.$' || true)
    [ -n "$members" ] || { say "FAIL: $toml lists no subject crates (workspace members)"; fail=1; }
    for m in $members; do
        if ! sed -n '/^\[dependencies\]/,/^\[/p' "$toml" | grep -qE "^$m *= *\{ *path *= *\"$m\""; then
            say "FAIL: subject crate $m is not linked into the harness binary (one binary for every subject)"
            fail=1
        fi
    done
    if ! runs_samecode "$dir/run.sh"; then
        say "FAIL: $dir/run.sh does not run the machine-code identity check (no \`python3 … samecode.py\` command outside comments)"
        fail=1
    fi
    [ $fail = 0 ] && say "pass: $dir: one profile, one binary ($(echo $members | wc -w | tr -d ' ') subject crates), identity check run"
    return $fail
}
# the held-out harness: rules 1-3, then 4-7
heldout_check() {
    local dir=$1 fail=0
    check "$dir" || fail=1
    local toml=$dir/Cargo.toml lib="" rustc_feat="" p f l feat
    local members
    members=$(sed -n '/^\[workspace\]/,/^\[/p' "$toml" | sed -n 's/^members *= *\[\(.*\)\]/\1/p' | tr -d '" ' | tr ',' '\n' | grep -v '^\.$' || true)
    for p in $members; do
        f=$dir/$p/Cargo.toml
        [ -f "$f" ] || { say "FAIL: subject $p has no Cargo.toml"; fail=1; continue; }
        l=$(sed -n '/^\[lib\]/,/^\[/p' "$f" | sed -n 's/^path *= *"\(.*\)"/\1/p')
        [ -n "$l" ] || { say "FAIL: subject $p names no [lib] path (one crate source for every subject)"; fail=1; continue; }
        if [ -z "$lib" ]; then lib=$l; elif [ "$l" != "$lib" ]; then say "FAIL: subject $p compiles $l, not $lib (one crate source for every subject)"; fail=1; fi
    done
    [ -f "$dir/subj_rustc/Cargo.toml" ] || { say "FAIL: no rustc subject (subj_rustc)"; fail=1; }
    if [ -f "$dir/subj_rustc/Cargo.toml" ]; then
        rustc_feat=$(sed -n 's/^default *= *\(.*\)/\1/p' "$dir/subj_rustc/Cargo.toml")
        if ! grep -qx 'subj_rustc_aa' <<< "$members"; then
            say "FAIL: no A/A subject (subj_rustc_aa) in the binary"; fail=1
        elif [ "$(sed -n 's/^default *= *\(.*\)/\1/p' "$dir/subj_rustc_aa/Cargo.toml")" != "$rustc_feat" ]; then
            say "FAIL: the A/A subject is not built like the rustc subject (default features differ)"; fail=1
        fi
        [ "$rustc_feat" = '["source"]' ] || { say "FAIL: the rustc subject does not build the \`source\` module"; fail=1; }
    fi
    # rule 6: H1 of the rustc subject is the frozen file
    local src=$dir/subj_rustc/$lib frozen_h1=sandblaster/bench/heldout/h1/src/lib.rs hp
    if [ -f "$src" ]; then
        hp=$(awk '/feature = "source", not\(feature = "optimized"\)/ { s = 1; next } s && /#\[path/ { print; exit }' "$src" | sed -n 's/.*#\[path *= *"\(.*\)"\].*/\1/p')
        case $hp in
        */heldout/h1/src/lib.rs) ;;
        *) say "FAIL: the rustc subject's H1 is \`${hp:-nothing}\`, not the frozen heldout/h1/src/lib.rs"; fail=1 ;;
        esac
        if ! awk -v p="$frozen_h1" '$2 == p { found = 1 } END { exit !found }' "$gates/frozen.sha256" \
            || [ "$(awk -v p="$frozen_h1" '$2 == p { print $1 }' "$gates/frozen.sha256")" != "$(shasum -a 256 "$repo/$frozen_h1" | cut -d' ' -f1)" ]; then
            say "FAIL: $frozen_h1 is not recorded by G6, or changed"; fail=1
        fi
    else
        say "FAIL: the subjects' crate source $lib is missing"; fail=1
    fi
    # rule 7 (in code: comments stripped, and the floor outside a string literal)
    if ! rust_code "$dir/src/main.rs" 2> /dev/null | grep -qE '^[^"]*rounds >= 21'; then
        say "FAIL: the runner does not refuse fewer than 21 rounds"; fail=1
    fi
    # (every `bench(&cases` call has its own `if !check(&cases)` in the 8 lines
    # before it: a check elsewhere, such as the `check` subcommand's, does not count)
    if ! rust_code "$dir/src/main.rs" 2> /dev/null | awk '/if !check\(&cases\)/ { c = NR } /bench\(&cases/ { if (c && NR - c <= 8) ok = 1; else bad = 1 } END { exit !(ok && !bad) }'; then
        say "FAIL: the runner does not run the differential check before timing"; fail=1
    fi
    [ $fail = 0 ] && say "pass: $dir: one crate source ($lib), an A/A subject, the rustc subject from the frozen source, >= 21 rounds after the differential check"
    return $fail
}
if [ "${1:-}" = --selftest ]; then
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/fair-baseline.XXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    src=$repo/sandblaster/bench/opt-corpus
    fresh() {
        rm -rf "$tmp/h"; mkdir -p "$tmp/h"
        cp "$src/Cargo.toml" "$src/run.sh" "$tmp/h/"
        for d in cgen cgen_o1 ideal; do mkdir -p "$tmp/h/$d"; [ -f "$src/$d/build.rs" ] && cp "$src/$d/build.rs" "$tmp/h/$d/"; done
        return 0
    }
    fails=0
    expect() { # expect pass|fail NAME
        if check "$tmp/h" > "$tmp/log" 2>&1; then got=pass; else got=fail; fi
        if [ "$got" = "$1" ]; then say "ok: $2 ($1)"; else say "FAIL: $2: expected $1, got $got"; sed 's/^/    /' "$tmp/log"; fails=$((fails + 1)); fi
    }
    fresh; expect pass "the corpus harness"
    fresh; printf '\n[profile.release.package.cgen]\nopt-level = 1\n' >> "$tmp/h/Cargo.toml"; expect fail "a subject compiled at another opt-level"
    fresh; printf '\n[profile.release.package.ideal]\noverflow-checks = false\n' >> "$tmp/h/Cargo.toml"; expect fail "a subject compiled without overflow checks"
    fresh; printf 'fn main() { println!("cargo:rustc-flags=-C target-cpu=native"); }\n' > "$tmp/h/cgen/build.rs"; expect fail "a subject with its own codegen flags"
    fresh; sed -i.bak '/^cgen_o1 = /d' "$tmp/h/Cargo.toml"; rm "$tmp/h/Cargo.toml.bak"; expect fail "a subject timed from another binary"
    fresh; sed -i.bak 's/samecode\.py/nothing.py/g' "$tmp/h/run.sh"; rm "$tmp/h/run.sh.bak"; expect fail "a runner without the identity check"
    fresh; sed -i.bak '/python3 .*samecode\.py/d' "$tmp/h/run.sh"; rm "$tmp/h/run.sh.bak"; expect fail "a runner that names the identity check only in comments and strings"
    # the held-out harness and its twins
    hsrc=$repo/sandblaster/bench/heldout-harness
    hfresh() {
        rm -rf "$tmp/h"; mkdir -p "$tmp/h/src" "$tmp/h/subject"
        cp "$hsrc/Cargo.toml" "$hsrc/run.sh" "$tmp/h/"
        cp "$hsrc/src/main.rs" "$tmp/h/src/"
        cp "$hsrc/subject/lib.rs" "$tmp/h/subject/"
        for d in subj_rustc subj_rustc_aa subj_opt; do mkdir -p "$tmp/h/$d"; cp "$hsrc/$d/Cargo.toml" "$tmp/h/$d/"; done
        return 0
    }
    hexpect() { # hexpect pass|fail NAME
        if heldout_check "$tmp/h" > "$tmp/log" 2>&1; then got=pass; else got=fail; fi
        if [ "$got" = "$1" ]; then say "ok: $2 ($1)"; else say "FAIL: $2: expected $1, got $got"; sed 's/^/    /' "$tmp/log"; fails=$((fails + 1)); fi
    }
    hfresh; hexpect pass "the held-out harness"
    hfresh; sed -i.bak 's/, "subj_rustc_aa"//; /^subj_rustc_aa = /d' "$tmp/h/Cargo.toml"; rm "$tmp/h/Cargo.toml.bak"; hexpect fail "no A/A subject"
    hfresh; sed -i.bak 's/^default = .*/default = ["optimized"]/' "$tmp/h/subj_rustc_aa/Cargo.toml"; rm "$tmp/h/subj_rustc_aa/Cargo.toml.bak"; hexpect fail "an A/A subject built from the optimized module"
    hfresh; sed -i.bak 's|^path = .*|path = "../orig/lib.rs"|' "$tmp/h/subj_rustc/Cargo.toml"; rm "$tmp/h/subj_rustc/Cargo.toml.bak"; hexpect fail "a rustc subject from another crate source"
    hfresh; sed -i.bak 's|../../heldout/h1/src/lib.rs|../trimmed/h1.rs|' "$tmp/h/subject/lib.rs"; rm "$tmp/h/subject/lib.rs.bak"; hexpect fail "a rustc subject from a hand-trimmed copy"
    hfresh; sed -i.bak 's/rounds >= 21/rounds >= 3/' "$tmp/h/src/main.rs"; rm "$tmp/h/src/main.rs.bak"; hexpect fail "a runner that accepts 3 rounds"
    hfresh; sed -i.bak 's/if !check(&cases)/if false/' "$tmp/h/src/main.rs"; rm "$tmp/h/src/main.rs.bak"; hexpect fail "a runner that times before the differential check"
    hfresh; sed -i.bak 's/samecode\.py/nothing.py/g' "$tmp/h/run.sh"; rm "$tmp/h/run.sh.bak"; hexpect fail "a held-out runner without the identity check"
    hfresh; sed -i.bak '/python3 .*samecode\.py/d' "$tmp/h/run.sh"; rm "$tmp/h/run.sh.bak"; hexpect fail "a held-out runner that names the identity check only in a comment"
    hfresh; perl -0pi -e 's|assert!\(rounds >= 21, |// the protocol: rounds >= 21\n            assert!(rounds >= 3, |' "$tmp/h/src/main.rs"; hexpect fail "a runner that states the 21-round floor only in a comment"
    hfresh; perl -0pi -e 's|assert!\(rounds >= 21, |assert!(rounds >= 3, /* rounds >= 21 */ |' "$tmp/h/src/main.rs"; hexpect fail "a runner that states the 21-round floor only in a block comment"
    hfresh; perl -0pi -e 's|assert!\(rounds >= 21, "|assert!(rounds >= 3, "rounds >= 21: |' "$tmp/h/src/main.rs"; hexpect fail "a runner that states the 21-round floor only in a message"
    hfresh; perl -0pi -e 's|if !check\(&cases\) \{\n(\s*)eprintln!\("the differential check failed: nothing timed"\);\n\s*std::process::exit\(1\);\n\s*\}\n(\s*)bench\(&cases|// if !check(&cases) used to run here\n$2bench(&cases|' "$tmp/h/src/main.rs"
    if grep -q 'used to run here' "$tmp/h/src/main.rs"; then hexpect fail "a runner whose check before timing is only a comment (the \`check\` subcommand's own check does not count)"; else say "FAIL: a twin's edit did not apply (src/main.rs changed shape; update the twin)"; fails=$((fails + 1)); fi
    [ $fails = 0 ] && say "pass: the fair-baseline check refuses every twin"
    exit $((fails > 0))
fi
if [ "${1:-}" = --heldout ]; then
    heldout_check "${2:-$repo/sandblaster/bench/heldout-harness}"
    exit $?
fi
check "${1:-$repo/sandblaster/bench/opt-corpus}"
