#!/usr/bin/env bash
# Extracts rustc's MIR of one module of a monorepo crate into a checked-in
# .sbmir file (sandblaster/front/src/mir, `docs/mir-lift.md` §20).
#
#   sandblaster/mirx/extract.sh <package> <module>[,<module>..] <out.sbmir> [--exclude T,..] [--stub out.rs=src.rs,..]
#       [--stubs crate:out.rs=src.rs;crate2:..] [--instance Trait=path::Type,..] [--skip-traits T,..]
#       [--inject name=file.rs,..] [--items 'mod=Item,..;mod2=..'] [--skip-fns T::m,..]
#       [--manifest path/Cargo.toml] [--target <triple>] [--mir-opt-level N] [--rustflags '<flags>']
#       [--features f,..] [--no-default-features] [--profile <name>]
#
#   sandblaster/mirx/extract.sh commonware-codec varint codec/sandblaster/varint/varint.sbmir \
#       --exclude u128,i128 --stub varint.rs=codec/sandblaster/varint/varint.rs
#
# It builds the driver with the pinned nightly of rust-toolchain.toml (the
# nightly of the stable release the workspace builds with; rustc-dev) and runs
# `cargo check` of the package with it as RUSTC_WORKSPACE_WRAPPER, in its own
# target directory (SBMIR_TARGET_DIR, default target/sandblaster-mirx): the
# host's build script is replaced by a stub (`--stub`: what `compile_module`
# emits, the source minus its leading `//!` lines) because the real one runs
# the verifier with the stable toolchain. Nothing of the workspace build is
# touched; the output is deterministic for the same sources and compiler.
#
# * --stubs: the build scripts of workspace crates the package depends on that
#   verify with sandblaster (commonware-codec's `varint.rs`), stubbed likewise;
# * --instance: open traits read at one instance (SEMANTICS.md §19.6);
# * --skip-traits: impls of these traits are not extracted (host code);
# * --inject: a DSL module compiled as `mod name;` of the crate root (the
#   verifier's `instances.rs`);
# * --items: in the named modules, only the functions of these items (the
#   lift's `items = ..`); --skip-fns: these functions are not extracted (the
#   lift's `unverified_fns = ..`);
# * --manifest: the package is in another workspace than the monorepo's (the
#   toolchain's own test fixtures, sandblaster/front/tests/mir_fixtures);
# * --target: extract for another target than the host (`x86_64-apple-darwin`
#   for x86 SIMD code on an aarch64 host); the `.sbmir` records the target and
#   the build refuses MIR of another architecture than its own.
# * --mir-opt-level: rustc's MIR optimization level for the extracted crate
#   (`-Zmir-opt-level`, default 1: what `cargo check` runs); the `.sbmir`
#   records it and the build refuses an extraction at another level
#   (`docs/mir-lift.md` §20.1).
# * --rustflags: extra rustc flags for the extracted crate, for a negative
#   twin only (a window extraction made under other flags than its main
#   extraction); the `.sbmir` records them, `(rustflags "..")`, the build
#   refuses a main extraction with any, and a window extraction must record
#   its main extraction's.
# * --features, --no-default-features, --profile: the extracted crate's
#   Cargo features and the profile it is checked with (Cargo's options,
#   passed on; `cargo check`'s default profile is `dev`). mirx records the
#   session's whole cfg set, `(cfg ..)`, read from rustc (the features, the
#   target's cfgs, the profile's `debug_assertions` and `panic`, every
#   `--cfg`): a window extraction must record its main extraction's, and a
#   build that knows its own configuration (a build script) refuses an
#   extraction made under another (`mir::load`), so extract with the
#   features and profile of the build that verifies the module. (`--profile
#   test` checks the crate in test mode, `cfg(test)`, which no build script
#   sees: such an extraction is refused by every build. A build whose
#   rustflags set `-C debug-assertions`, `-C opt-level`, `-O`,
#   `-C overflow-checks`, a `-Z` option or an `@file` is refused too: a
#   build script cannot see the configuration they make. A profile's
#   `panic` reaches no build script: it is assumed to be the extraction's,
#   kernel/AUDIT.md §21.1.)
#
# Rustflags are never inherited: a body compiled under other flags (another
# `--cfg`, `-C target-feature`, a `-Z` pass) is another program, and the
# window rule's verdicts are carried to the main extraction by source
# position (docs/mir-lift.md §20.10, the review's F2). So a non-empty
# `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS` or
# `CARGO_TARGET_<triple>_RUSTFLAGS` in the environment is refused, and the
# extraction runs with `CARGO_ENCODED_RUSTFLAGS` set (empty, or the
# `--rustflags`), which overrides every other source of rustflags, Cargo's
# configuration files included; mirx records what it was
# (`SBMIR_RUSTFLAGS`).
#
#   sandblaster/mirx/extract.sh commonware-storage merkle::position,merkle::location,merkle::mmr,merkle::hasher,merkle::proof \
#       storage/sandblaster/verifier/verifier.sbmir \
#       --stubs 'commonware_codec:varint.rs=codec/sandblaster/varint/varint.rs' \
#       --instance 'Family=merkle::mmr::Family,..' --skip-traits Debug,Display,Hash \
#       --inject instances=storage/sandblaster/verifier/instances.rs --items '..' --skip-fns '..'
#   (the full command, and the MMR's, are in the README)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
pkg="$1"; module="$2"; out="$3"; shift 3
exclude=""; stub=""; stubs=""; instance=""; skip=""; inject=""; items=""; skipfns=""; manifest="$root/Cargo.toml"; target=""; level=1; rustflags=""; cargo_opts=()
while [ $# -gt 0 ]; do
  case "$1" in
    --exclude) exclude="$2"; shift 2 ;;
    --stub) stub="$2"; shift 2 ;;
    --stubs) stubs="$2"; shift 2 ;;
    --instance) instance="$2"; shift 2 ;;
    --skip-traits) skip="$2"; shift 2 ;;
    --inject) inject="$2"; shift 2 ;;
    --items) items="$2"; shift 2 ;;
    --skip-fns) skipfns="$2"; shift 2 ;;
    --manifest) manifest="$2"; case "$manifest" in /*) ;; *) manifest="$root/$manifest" ;; esac; shift 2 ;;
    --target) target="$2"; shift 2 ;;
    --mir-opt-level) level="$2"; shift 2 ;;
    --rustflags) rustflags="$2"; shift 2 ;;
    --features) cargo_opts+=(--features "$2"); shift 2 ;;
    --no-default-features) cargo_opts+=(--no-default-features); shift ;;
    --profile) cargo_opts+=(--profile "$2"); shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
# no inherited rustflags (above)
for v in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS $(env | sed -n 's/^\(CARGO_TARGET_[A-Z0-9_]*_RUSTFLAGS\)=.*/\1/p'); do
  if [ -n "$(printenv "$v" || true)" ]; then
    echo "extract.sh: $v is set ($(printenv "$v")): an extraction is compiled with no inherited rustflags (a body compiled under other flags is another program; docs/mir-lift.md §20.1). Unset it; a negative twin passes its flags with --rustflags." >&2
    exit 2
  fi
done
toolchain="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$root/sandblaster/mirx/rust-toolchain.toml")"
tdir="${SBMIR_TARGET_DIR:-$root/target/sandblaster-mirx}"
( cd "$root/sandblaster/mirx" && CARGO_TARGET_DIR="$tdir/driver" cargo +"$toolchain" build --release -q )
abs_stub=""
IFS=',' read -ra pairs <<< "$stub"
for p in "${pairs[@]:-}"; do
  [ -z "$p" ] && continue
  o="${p%%=*}"; s="${p#*=}"
  case "$s" in /*) ;; *) s="$root/$s" ;; esac
  abs_stub="${abs_stub:+$abs_stub,}$o=$s"
done
# `a=b,..` pairs with the right-hand paths made absolute
absify() {
  local res="" p o s
  IFS=',' read -ra ps <<< "$1"
  for p in "${ps[@]:-}"; do
    [ -z "$p" ] && continue
    o="${p%%=*}"; s="${p#*=}"
    case "$s" in /*) ;; *) s="$root/$s" ;; esac
    res="${res:+$res,}$o=$s"
  done
  echo "$res"
}
abs_stubs=""
IFS=';' read -ra centries <<< "$stubs"
for e in "${centries[@]:-}"; do
  [ -z "$e" ] && continue
  abs_stubs="${abs_stubs:+$abs_stubs;}${e%%:*}:$(absify "${e#*:}")"
done
abs_inject="$(absify "$inject")"
case "$out" in /*) ;; *) out="$root/$out" ;; esac
crate="${pkg//-/_}"
# the crate's library is re-checked each time (its MIR is what is printed)
touch "$(cargo metadata --no-deps --format-version 1 --manifest-path "$manifest" | python3 -c "import json,sys; d=json.load(sys.stdin); print([t['src_path'] for p in d['packages'] if p['name']=='$pkg' for t in p['targets'] if 'lib' in t['kind']][0])")"
cd "$root"
if [ -n "$skip" ]; then export SBMIR_SKIP_TRAITS="$skip"; fi
RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER="$tdir/driver/release/sandblaster-mirx" \
SBMIR_CRATE="$crate" SBMIR_MODULE="$module" SBMIR_OUT="$out" SBMIR_EXCLUDE="$exclude" SBMIR_STUB="$abs_stub" \
SBMIR_STUBS="$abs_stubs" SBMIR_INSTANCE="$instance" SBMIR_INJECT="$abs_inject" \
SBMIR_ITEMS="$items" SBMIR_SKIP_FNS="$skipfns" SBMIR_MIR_OPT_LEVEL="$level" \
SBMIR_RUSTFLAGS="$rustflags" CARGO_ENCODED_RUSTFLAGS="$(printf '%s' "$rustflags" | tr ' ' '\037')" \
CARGO_TARGET_DIR="$tdir/check" cargo +"$toolchain" check -q --manifest-path "$manifest" -p "$pkg" ${target:+--target "$target"} ${cargo_opts[@]+"${cargo_opts[@]}"}
echo "wrote $out"
