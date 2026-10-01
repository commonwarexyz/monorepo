#!/usr/bin/env bash
# Extracts rustc's MIR of one module of a monorepo crate into a checked-in
# .sbmir file (sandblaster/front/src/mir, `docs/mir-lift.md` §20).
#
#   sandblaster/mirx/extract.sh <package> <module>[,<module>..] <out.sbmir> [--exclude T,..] [--stub out.rs=src.rs,..]
#       [--stubs crate:out.rs=src.rs;crate2:..] [--instance Trait=path::Type,..] [--skip-traits T,..]
#       [--inject name=file.rs,..] [--replace src.rs=text.rs,..] [--items 'mod=Item,..;mod2=..'] [--skip-fns T::m,..]
#       [--manifest path/Cargo.toml]
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
#   `#[lift(opt)]` alternatives, in the crate's context);
# * --replace: compile a source as if it had another file's text (the lifted
#   round trip's copy of a rewritten file, DESIGN.md §2.1); its SHA-256 is
#   that text's;
# * --items: in the named modules, only the functions of these items (the
#   lift's `items = ..`); --skip-fns: these functions are not extracted (the
#   lift's `unverified_fns = ..`);
# * --manifest: the package is in another workspace than the monorepo's (the
#   toolchain's own test fixtures, sandblaster/front/tests/mir_fixtures).
#
#   sandblaster/mirx/extract.sh commonware-storage merkle::position,merkle::location,merkle::mmr,opt \
#       storage/sandblaster/mmr/mmr.sbmir \
#       --stub mmr-lowered__merkle__mmr__iterator.rs=storage/src/merkle/mmr/iterator.rs \
#       --stubs 'commonware_codec:varint.rs=codec/sandblaster/varint/varint.rs' \
#       --instance Family=merkle::mmr::Family,Graftable=merkle::mmr::Family \
#       --skip-traits Debug,Display,Hash --inject opt=storage/sandblaster/mmr/opt.rs
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
pkg="$1"; module="$2"; out="$3"; shift 3
exclude=""; stub=""; stubs=""; instance=""; skip=""; inject=""; replace=""; items=""; skipfns=""; manifest="$root/Cargo.toml"
while [ $# -gt 0 ]; do
  case "$1" in
    --exclude) exclude="$2"; shift 2 ;;
    --stub) stub="$2"; shift 2 ;;
    --stubs) stubs="$2"; shift 2 ;;
    --instance) instance="$2"; shift 2 ;;
    --skip-traits) skip="$2"; shift 2 ;;
    --inject) inject="$2"; shift 2 ;;
    --replace) replace="$2"; shift 2 ;;
    --items) items="$2"; shift 2 ;;
    --skip-fns) skipfns="$2"; shift 2 ;;
    --manifest) manifest="$2"; case "$manifest" in /*) ;; *) manifest="$root/$manifest" ;; esac; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
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
# `a=b,..` pairs with the right-hand paths made absolute (both, with `both`)
absify() {
  local res="" p o s
  IFS=',' read -ra ps <<< "$1"
  for p in "${ps[@]:-}"; do
    [ -z "$p" ] && continue
    o="${p%%=*}"; s="${p#*=}"
    case "$s" in /*) ;; *) s="$root/$s" ;; esac
    if [ "${2:-}" = both ]; then case "$o" in /*) ;; *) o="$root/$o" ;; esac; fi
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
abs_replace="$(absify "$replace" both)"
case "$out" in /*) ;; *) out="$root/$out" ;; esac
crate="${pkg//-/_}"
# the crate's library is re-checked each time (its MIR is what is printed)
touch "$(cargo metadata --no-deps --format-version 1 --manifest-path "$manifest" | python3 -c "import json,sys; d=json.load(sys.stdin); print([t['src_path'] for p in d['packages'] if p['name']=='$pkg' for t in p['targets'] if 'lib' in t['kind']][0])")"
cd "$root"
if [ -n "$skip" ]; then export SBMIR_SKIP_TRAITS="$skip"; fi
RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER="$tdir/driver/release/sandblaster-mirx" \
SBMIR_CRATE="$crate" SBMIR_MODULE="$module" SBMIR_OUT="$out" SBMIR_EXCLUDE="$exclude" SBMIR_STUB="$abs_stub" \
SBMIR_STUBS="$abs_stubs" SBMIR_INSTANCE="$instance" SBMIR_INJECT="$abs_inject" SBMIR_REPLACE="$abs_replace" \
SBMIR_ITEMS="$items" SBMIR_SKIP_FNS="$skipfns" \
CARGO_TARGET_DIR="$tdir/check" cargo +"$toolchain" check -q --manifest-path "$manifest" -p "$pkg"
echo "wrote $out"
