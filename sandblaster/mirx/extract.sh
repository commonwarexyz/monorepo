#!/usr/bin/env bash
# Extracts rustc's MIR of one module of a monorepo crate into a checked-in
# .sbmir file (sandblaster/front/src/mir, `docs/mir-lift.md` §20).
#
#   sandblaster/mirx/extract.sh <package> <module> <out.sbmir> [--exclude T,..] [--stub out.rs=src.rs,..]
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
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
pkg="$1"; module="$2"; out="$3"; shift 3
exclude=""; stub=""
while [ $# -gt 0 ]; do
  case "$1" in
    --exclude) exclude="$2"; shift 2 ;;
    --stub) stub="$2"; shift 2 ;;
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
case "$out" in /*) ;; *) out="$root/$out" ;; esac
crate="${pkg//-/_}"
# the crate's library is re-checked each time (its MIR is what is printed)
touch "$(cargo metadata --no-deps --format-version 1 --manifest-path "$root/Cargo.toml" | python3 -c "import json,sys; d=json.load(sys.stdin); print([t['src_path'] for p in d['packages'] if p['name']=='$pkg' for t in p['targets'] if 'lib' in t['kind']][0])")"
cd "$root"
RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER="$tdir/driver/release/sandblaster-mirx" \
SBMIR_CRATE="$crate" SBMIR_MODULE="$module" SBMIR_OUT="$out" SBMIR_EXCLUDE="$exclude" SBMIR_STUB="$abs_stub" \
CARGO_TARGET_DIR="$tdir/check" cargo +"$toolchain" check -q -p "$pkg"
echo "wrote $out"
