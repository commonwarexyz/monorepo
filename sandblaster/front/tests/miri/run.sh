#!/bin/sh
# The Miri gate of the narrow reading of existing `unsafe`
# (docs/DESIGN-UNSAFE-SIMD.md risk 1, amendments A-S1 and A-process;
# docs/mir-lift.md §20.10). Run it at every toolchain bump, with the
# re-extraction of every `.sbmir` (`front/tests/mir_fixtures/extract.py`),
# and whenever the window rule (`mir/window.rs`) or L's pointer constructs
# (`mir/literal.rs`, `mir/literal.core`, `mir/ptr.rs`) change.
#
#   sh sandblaster/front/tests/miri/run.sh [--engines]
#
# 1. The positive pointer fixtures (`mir_fixtures/sd_ptr`, the same source
#    the reading verifies) run clean under Stacked Borrows and under Tree
#    Borrows.
# 2. Every twin whose refusal is about undefined behaviour (bounds,
#    aliasing, a store through a shared formation, a base that lives in a
#    local used or dead inside the window: `mir_fixtures/sd_ptr_local`) is
#    reported as undefined behaviour by at least one of the two models.
# 3. With `--engines`, the real engine functions this host reaches:
#    Commonware's NEON Reed–Solomon engine as shipped (`mul`, `fft`, `ifft`:
#    `mul_neon`, `fftb_128`, `ifftb_128` and their loops) against its naive
#    engine, under both models (`engines/`: a harness crate outside
#    Commonware's sources, with a `cpufeatures` whose Miri support detects
#    the build's static features; the published one detects none under
#    Miri, so `Neon::new()` would refuse). Slow: the dependency's build
#    script verifies `commonware-codec`'s varint module first.
#
# Exit status 0 only when all of it holds. The toolchain is the extractor's
# pinned nightly (`sandblaster/mirx/rust-toolchain.toml`), with Miri.
#
# A clean run with `--engines` records what it ran on in `GATE.txt` beside
# this script: the toolchain and the SHA-256 of every file it covered (the
# fixtures, the harnesses, the `cpufeatures` patch, Commonware's NEON
# engine). `tests/unsafe_simd.rs` fails when the pinned toolchain or one of
# those files is not what the record names, so a toolchain bump, or a
# change to a covered file, needs this gate run again.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
toolchain=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$root/sandblaster/mirx/rust-toolchain.toml")
models="stacked tree"
flags() { if [ "$1" = tree ]; then echo "-Zmiri-tree-borrows"; else echo ""; fi; }
fail=0

for m in $models; do
  out=$(cd "$here" && MIRIFLAGS="$(flags $m)" cargo "+$toolchain" miri test --test positive 2>&1)
  if [ $? = 0 ]; then
    echo "positive fixtures [$m]: clean ($(echo "$out" | grep -c ' \.\.\. ok$') tests)"
  else
    echo "positive fixtures [$m]: FAILED"; echo "$out" | tail -40; fail=1
  fi
done

# (the `sd_ptr_local` twins: bases that live in a local of the forming
# function and the window rule's other siblings, stage soundness-fixes)
twins="ub_load_past_end ub_offset_past_end ub_store_through_shared ub_alias ub_two_formations
  ub_local_write ub_local_shared ub_local_scope ub_local_from_mut ub_local_raw_deref ub_param_by_value
  ub_param_by_value_mut ub_local_raw_write ub_raw_scope ub_struct_field ub_tuple_field ub_nested_array
  ub_boxed ub_vec_slice ub_temporary ub_temporary_mut ub_closure_write ub_two_pointers
  ub_shared_then_mut ub_reborrow_moved ub_after_loop ub_after_call ub_loop_scope"
for t in $twins; do
  seen=""
  for m in $models; do
    out=$(cd "$here" && MIRIFLAGS="$(flags $m)" cargo "+$toolchain" miri test --test twins -- --exact "$t" 2>&1)
    if echo "$out" | grep -q "Undefined Behavior"; then seen="$seen $m"; fi
  done
  if [ -n "$seen" ]; then
    echo "$t: undefined behaviour under$seen"
  else
    echo "$t: NOT reported by either model"; fail=1
  fi
done

if [ "${1:-}" = "--engines" ]; then
  for m in $models; do
    out=$(cd "$here/engines" && MIRIFLAGS="$(flags $m)" cargo "+$toolchain" miri test 2>&1)
    if [ $? = 0 ]; then
      echo "NEON engine against the naive one [$m]: clean ($(echo "$out" | grep -c ' \.\.\. ok$') tests)"
    else
      echo "NEON engine against the naive one [$m]: FAILED"; echo "$out" | tail -40; fail=1
    fi
  done
fi

if [ "$fail" = 0 ] && [ "${1:-}" = "--engines" ]; then
  {
    echo "# The Miri gate's last clean run, written by run.sh --engines (Stacked and"
    echo "# Tree Borrows: the positive fixtures and the NEON engine clean, every"
    echo "# twin reported). tests/unsafe_simd.rs checks it against the pinned"
    echo "# toolchain and the files below."
    echo "toolchain $toolchain"
    while read -r f; do
      echo "sha256 $(shasum -a 256 "$root/$f" | cut -d' ' -f1) $f"
    done <<EOF
sandblaster/front/tests/mir_fixtures/sd_ptr/src/a.rs
sandblaster/front/tests/mir_fixtures/sd_ptr_twins/src/a.rs
sandblaster/front/tests/mir_fixtures/sd_ptr_local/src/a.rs
sandblaster/front/tests/miri/src/lib.rs
sandblaster/front/tests/miri/tests/positive.rs
sandblaster/front/tests/miri/tests/twins.rs
sandblaster/front/tests/miri/engines/tests/neon.rs
sandblaster/front/tests/miri/engines/cpufeatures-static/src/miri.rs
cryptography/src/reed_solomon/engine/engine_neon.rs
EOF
  } > "$here/GATE.txt"
  echo "recorded in $here/GATE.txt"
fi

exit $fail
