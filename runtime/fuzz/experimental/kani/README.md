# commonware-runtime Kani proofs

Proof harnesses for the I/O buffers of the `commonware-runtime` crate and for the page size of
its page cache, checked with [Kani](https://github.com/model-checking/kani), a bounded model
checker for Rust. A harness that passes holds for every input inside its stated bounds, not
for a sample. Kani also checks every pointer use, allocation and deallocation of the code a
harness reaches, so the `unsafe` code behind the buffer handles is checked for memory safety
on those paths. The harnesses are run by hand or by a scheduled job, not by CI.

The harnesses call only the public API of `commonware-runtime`. They do not call, import or
copy private code; the private implementation behind each public call runs and is checked
for the inputs the harnesses use, but no private function is proven over its own domain. What
that leaves out is listed under "Not covered".

`kani/` is its own workspace with its own `Cargo.lock`. It is not a member of the repository
workspace, so `cargo` commands run for the repository workspace do not build or run it, and
the repository `Cargo.lock` does not name it. Every module and every dependency is behind
`cfg(kani)`: under a plain `cargo build` the package is empty.

## How Kani harnesses are marked

Three marks agree, so that a person or a script can find the Kani harnesses and run them
without any libFuzzer target:

1. **The path and the package name.** The package is `<crate>/fuzz/experimental/kani/` and
   its name ends with `-kani`.
2. **A marker in the manifest.** `Cargo.toml` has the table `[package.metadata.kani]`, with
   the Kani release as `version` and the number of harnesses as `harnesses`. A libFuzzer
   package has `cargo-fuzz = true` instead, and never this table.
3. **The harness names.** The name of every harness starts with `kani_`.

List the harnesses of this package:

```bash
RUSTFLAGS="--cap-lints=warn" cargo kani --manifest-path runtime/fuzz/experimental/kani/Cargo.toml list
```

## Installing Kani

Kani is not a dependency of the repository. The harnesses are written for Kani 0.68.0 (the
`version` of the marker). Both commands install into the home directory: the two binaries in
`~/.cargo/bin`, the Kani bundle in `~/.kani`, and the compiler Kani uses as a `rustup`
toolchain.

```bash
cargo install --locked kani-verifier --version 0.68.0
cargo kani setup
```

## Running

Run from the repository root and pass the manifest:

```bash
RUSTFLAGS="--cap-lints=warn" cargo kani --manifest-path runtime/fuzz/experimental/kani/Cargo.toml
```

`RUSTFLAGS="--cap-lints=warn"` is required. The repository workspace denies warnings, and
under Kani's compiler `commonware-utils`, a dependency of `commonware-runtime`, gets a
future-incompatibility warning (Kani's standard library defines its own `assert!`, which then
is not local to the crate). Without the flag the build stops with "trailing semicolon in macro
used in expression position". The flag only turns lints of the code under proof into
warnings; it does not change what Kani checks.

A passing run exits with status 0 and ends with:

```text
Complete - 10 successfully verified harnesses, 0 failures, 10 total.
```

Check two more things, because the exit status does not cover them:

1. **The count.** The total equals `harnesses` in the marker. A harness that is no longer
   compiled is missing from the run without any error.
2. **The cover checks.** Every line `** n of m cover properties satisfied` has `n` equal to
   `m`. Kani reports a harness as `SUCCESSFUL` also when a cover check is unsatisfied, and
   then the harness may prove less than it says.

A harness that runs out of time is printed as `VERIFICATION:- FAILED` with the line
`CBMC timed out`: that is no answer, not a failed check. A failed check prints
`Failed Checks:` with the assertion.

Useful options:

| Option | Effect |
| ------ | ------ |
| `--harness p5_iobufs::kani_p5_split_to --exact` | Run one harness (the name with its module). |
| `-j 1` | Run one harness at a time (each harness runs one solver process). |
| `-Z unstable-options --harness-timeout 20m` | Stop each harness after this time. |
| `-Z unstable-options --export-json results.json` | Write the result of every harness and every check to a file. |
| `-Z concrete-playback --concrete-playback=print` | Print a unit test with the input of each failed check and of each satisfied cover check. |
| `--features consistency` | Also assert the implementation-consistency checks (see below). |

Kani has no `--locked` option. Check the lock file before a run with
`cargo metadata --locked --manifest-path runtime/fuzz/experimental/kani/Cargo.toml --format-version 1`.

## Proofs

Each proof states contracts that the documentation of `commonware-runtime` gives, or the
documentation of the `bytes` trait (`Buf`, `BufMut`) that a buffer implements. The quoted
sentences, the bounds and what is left unasserted are in the header of each module in `src/`.

| Module | Harnesses | What is proven |
| ------ | --------- | -------------- |
| `p1_iobuf_lifecycle` | `kani_p1_lifecycle`, `kani_p1_clone_shares` | For every capacity up to 4 bytes, every content and every slice: `IoBufMut::with_capacity` gives that capacity, `freeze` and `slice` keep the bytes, `IoBuf::try_into_mut` succeeds exactly when no other handle shares the allocation and then gives a nonempty buffer its full capacity back. A clone shares the allocation until it is dropped. |
| `p2_iobuf_split` | `kani_p2_split_to` | For every content up to 4 bytes and every index: `IoBuf::split_to` gives the bytes before and after the index; the halves share the allocation exactly when both are nonempty. |
| `p3_iobuf_large_spare` | `kani_p3_freeze_large_spare` | For every capacity from 128 KiB + 3 to 2^41 bytes: a buffer whose spare capacity or size is too large for the compact owner word freezes and converts back; a nonempty one gets its full capacity back. |
| `p4_iobufmut_cursor` | `kani_p4_advance_copy_write` | For every capacity up to 4 bytes: `advance`, `copy_to_slice` and a following write move the read cursor and the write position of `IoBufMut` as the `bytes` traits and the type's docs say. |
| `p5_iobufs` | `kani_p5_append_prepend`, `kani_p5_many_chunks`, `kani_p5_split_to`, `kani_p5_coalesce` | `IoBufs`, one concrete shape per harness with every content: after `append`, `prepend` and `split_to` (at every index), the length, the count of nonempty chunks and the chunks in order match a byte model, up to 5 chunks; an empty buffer adds no chunk; `coalesce` gives all the bytes in one buffer. |
| `p6_page_size` | `kani_p6_page_size_valid` | For every valid physical page size (a power of two above 12 bytes whose logical size fits a `u16`): `buffer::paged::page_size` returns, and the logical size plus the 12-byte CRC record is the physical size. |

### Contract and consistency

The default build asserts the quoted contracts. It is the gate: a failure is a difference
between the code and a quoted contract. Some harnesses also hold checks that are stronger than
the documentation, for example the capacity of a buffer made by `copy_from_slice`. They are
asserted only with `--features consistency`. A valid change of the implementation may fail
them, so a failure there is a reason to look, not a defect.

### Limits

- A proof holds inside its bounds: the sizes and loop bounds in the module header.
- `usize` is 64 bits, as on the machine that runs Kani. Nothing here speaks for 32-bit
  targets.
- Only buffers in native heap storage are covered (made by `IoBufMut`, `copy_from_slice` or
  a freeze of those). Buffers that hold `Bytes` or a `'static` slice are not.
- Kani runs code as sequential code: it does not check races between threads.
- A proof is as sound as Kani, CBMC and the solver.

## Not covered

Decision, 2026-11-24: the harnesses use the public API only, with no change to production
code and no copy of private code. These properties need more than that, or are out of Kani's
reach today:

| Property | Why it is not covered |
| -------- | --------------------- |
| The packing of the owner word of a heap buffer (size, alignment and spare capacity in one word, both the 64-bit and the 32-bit layout), the recovery of the allocation base from a view, and the free with the original layout (`src/iobuf/owner.rs`) | Private code. Reached here only through the public handles, for the sizes the harnesses use. |
| The refcount ceiling of shared buffers (`owner.rs`, the abort above `isize::MAX` references) | Private code, and the ceiling cannot be reached through the public API within a proof. |
| The promotion race: two threads that clone or slice the same frozen buffer at once | Concurrency; Kani runs threads as sequential code. The loom tests in `owner.rs` cover it. |
| Buffers that hold `Bytes` (`From<Bytes>`, `From<BytesMut>`) | `Bytes` is too slow for the solver at useful sizes. |
| Panics on invalid input: `IoBuf::split_to` and `IoBufs::split_to` past the length, `advance` and `copy_to_slice` past the remaining bytes, writes past the capacity, `page_size` of an invalid size | A proof that EVERY invalid input panics needs a `should_panic` harness whose cover after the call is unreachable. The scheduled runner counts an unreachable cover as a failure, so these wait for a change of its pass rule. |
| The page cache itself (`buffer::paged::CacheRef`: `offset_to_page`, `cache`, the cached reads) | Kani 0.68.0 cannot compile it: building a harness that calls `CacheRef::new` stops with an internal compiler error (an assertion in the intrinsics code of `kani-compiler`), and the hash map it creates seeds itself through `getentropy`, a foreign function Kani does not support. |
| The page cache's index and offset math (`locate`, `read_at`, the hint index, the physical page offset, the read-range check) and the choice between the two CRC slots of a page footer | Private code. The footer proof also needs a stub of the CRC function, whose implementation uses hardware instructions. |
| The page writer, reader and replay (`buffer::paged::{Writer, Append, Replay, Sealed}`) | Async code. |
| `IoBufs` shapes other than the four fixed ones (other buffer lengths and call orders) | With the buffer lengths symbolic (up to 2 bytes each), the proofs gave no answer within 8 minutes; each harness fixes one shape. |
| `IoBufsMut` and `IoBufsBuilder` | Not in this proof set. |

## Changing the harnesses

- Name a new harness `kani_...` and raise `harnesses` in `Cargo.toml`.
- Put the quoted contract above the assertion, with the file and the item it belongs to (no
  line numbers). A check with no quote goes behind the `consistency!` macro. A quoted test
  supports what it asserts and no more.
- Keep `IoBufs` inputs to one concrete shape per harness (fixed buffer lengths and call
  order); check a new harness alone with `--harness ... --exact` and a `--harness-timeout`.
- Give every result arm a `kani::cover!` check, so that an arm that is no longer reached is
  seen.
- Before writing a domain, list each division, unchecked arithmetic operation, `assert!`,
  `expect` and `unwrap` on the path, and keep the harness inside the conditions that rule
  them out.

### The lock file

`Cargo.lock` also records the repository crates that the harnesses depend on. When their
versions or dependencies change, refresh the lock and commit it:

```bash
cargo metadata --manifest-path runtime/fuzz/experimental/kani/Cargo.toml --format-version 1 > /dev/null
```
