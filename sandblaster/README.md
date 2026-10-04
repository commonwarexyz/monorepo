# sandblaster

**Bend 2's "everything is proven" discipline, as fast as Rust (faster is the goal: not yet shown on held-out code).**

sandblaster is a DSL embedded in Rust. You write ordinary-looking Rust — a
restricted, provable subset — plus Bend-style laws and Verus-style inline
proofs. `cargo build` elaborates every function into a small dependently typed
kernel, which must check that

* every function terminates and never panics (no overflow, division by zero,
  out-of-bounds access or bad shift is reachable),
* every contract (`#[requires]` / `#[ensures]`) and every law in `LAWS.rs` is
  proven, and
* every optimization the compiler performed — symbolic-execution
  specialization, proven hardware variants (e.g. ARMv8 SHA-256 instructions),
  proven removal of bounds checks — is equal to the original code,

and only then emits Rust for `rustc`. If anything is unproven, the build
fails. There is no flag to skip proofs and no flag to skip optimization.

```text
sandblaster source (Rust syntax) ──syn──▶ front end ──▶ elaborator ──▶ kernel (TRUSTED)
                                                          │               ▲
                                   automation (untrusted) ┘   optimizer ──┘ (every result checked)
                                                                   │
                        canonical Rust ◀── round-trip check ◀── codegen
```

## Results: the QMDB verifier

The first program ported is [`qmdb-bend2`](https://github.com/patrick-ogrady/qmdb-bend2),
a Bend 2 verifier for Commonware QMDB current-membership proofs (MMR, SHA-256,
activity bitmap). Its DSL sources, laws, proofs and fixtures are kept here as a
test fixture of the toolchain ([`fixtures/qmdb/`](fixtures/qmdb/)); the
numbers below were measured on the full port (with its baseline, oracle and
benchmark crates) before the toolchain moved into the monorepo:

* The verified build of the port is **VERIFIED + OPTIMIZED**: 747 obligations and all
  **9 laws** (one-to-one with the Bend `LAWS.bend`) proven, 123 kernel-checked
  definitions, `compress_sha2 ≡ compress` (ARMv8 SHA2 intrinsics vs FIPS 180-4)
  proven by the kernel's word-algebra rule in 18 ms, 48 functions specialized,
  every emitted definition round-tripped against the verified core — in about
  6 s.
* The generated crate passes every test of the reference port (all fixtures,
  the 27 `tests.ts` mutation cases, prefixes/extensions/bit flips, robustness
  runs, 4500 Bend-oracle differential cases, SHA-256 known answers).

Per-`verify` time, geometric mean over the 29 accepting fixtures (Apple M5 Pro;
N = 1; a development-set measurement, on the program the optimizer was
developed against; taken before the fairness audit split the QMDB fixtures,
when the optimizer's profile was recorded on the same fixtures that were
timed, and not re-timed since):

| implementation | ns / verify |
| --- | ---: |
| **sandblaster (generated, verified, optimized)** | **289** |
| **the same sources compiled by rustc**, hand-multiversioned on `compress_sha2` (the fair rustc baseline) | 318–325 |
| Commonware native verifier (verify only) — a different program: the generic verifier | 430 |
| Commonware native verifier (decode + verify) — a different program: the generic verifier | 463 |
| Bend 2, native C | 21,630 |
| Bend 2, JavaScript | 248,056 |

Both sandblaster rows use `compress_sha2`, a **hand-written** ARMv8 SHA-2
kernel proven equal to the portable FIPS 180-4 `compress`; its speed is not
the optimizer's. The optimizer's own share is the first row against the
second (289 vs 318–325 ns; at N = 32, 0.88–1.00× of the same baseline). The
Commonware rows compare a different program: the port is fixed-shape, with
one hand-made hash function per message length. Without hardware SHA (the
sources compiled by rustc with the portable `compress`) a verify takes
1,932 ns: that gap is the hand-written kernel's, not the optimizer's.
"Faster than rustc" is a goal with development-set evidence only.

**Held-out evaluation** (`bench/heldout-v2/REPORT.md`; held-out v2, frozen
before the reader and optimizer work it judges): on 30 functions written
blind from an idiom list, timed against rustc on the unmodified source in
one binary with an A/A control, the optimizer-only geomean is **1.007**
(default layout; **1.002** aligned; 0.999 without overflow checks), with
**0 of 30 functions changed**: the optimized subject is the source compiled
again, so the numbers are placement noise (the A/A control spreads
0.87–1.19). 9 functions are refused by the MIR reader, 11 by exec-only
elaboration, and of the 10 that reach the optimizer none yields a cheaper
printable residual. The monorepo half, H2-v2, is empty: the frozen sampling
rule probed all 869 candidates and accepted none (most are too small for
its size criterion). On code it was not built for, the optimizer does
nothing yet; the numbers above are the development set (DESIGN.md, North
star). Held-out v1 (`bench/heldout/REPORT.md`) is development data now: the
three rewrites stage finish-A lets through there are not faster: one
compiles to rustc's own machine code, one measures 1.00, and `read_u32_le`,
for which the cost model predicted 0.70, measures 1.07–1.12.

**The shipped verified code** (`bench/shipped-harness/REPORT.md`): what
commonware-codec and commonware-storage compile from sandblaster's emitted
and lowered copies (codec's varint, storage's MMR and the verifier's first
set), timed against the original Commonware functions in one binary, is the
original code: 28 of 33 functions compile to identical machine code and the
other 5 differ only in the addresses of each copy's constant data, exactly
as the A/A pair does; geomean 1.003 (default) / 1.002 (aligned).

**Verified Commonware code in this tree.** Three modules are verified by
their crate's `build.rs`, each with an accepted specification lock and
every §15 gate enforced (a failed proof or gate fails the crate's build):

| module | mode | lifted functions with a kernel-checked MIR theorem | lock root |
| --- | --- | ---: | --- |
| commonware-codec's varint (`codec/sandblaster/varint`) | module (`compile_module`) | 63 of 63 | `f0021c19…` |
| commonware-storage's MMR position and peak arithmetic (`storage/sandblaster/mmr`) | in place (`compile_lifted`) | 69 of 69 | `1d8d5969…` |
| the first set of storage's Merkle proof verifier (`storage/sandblaster/verifier`: `hasher.rs` at `Standard<Sha256>`, `proof.rs`'s subtree reconstruction): 8 laws, 2,642 obligations | in place (`compile_lifted`) | 69 of 69 | `3e969a79…` |

## What the code looks like

Exec code is plain Rust with contracts where needed (`fixtures/qmdb/sandblaster/merkle.rs`):

```rust
pub fn bag_prefix(n: usize, xs: &[Digest], acc: Digest) -> Option<Digest> {
    if n == 0 {
        return fold_back_join(&acc, fold_back(xs));
    }
    match xs {
        [] => None,
        [head, tail @ ..] => bag_prefix(n - 1, tail, fold(&acc, head)),
    }
}
```

Laws are human-owned claims (`fixtures/qmdb/sandblaster/LAWS.rs`, like Bend's `LAWS.bend`):

```rust
/// The production peak bagger composes across any partition of its
/// left-folded prefix.
#[law]
fn bag_prefix_partition(xs: &[Digest], ys: &[Digest], n: usize, acc: Digest) {
    requires((xs.len() as Int) + (ys.len() as Int) <= ISIZE_MAX);
    requires((xs.len() as Int) + (n as Int) <= (usize::MAX as Int));
    ensures(
        merkle::bag_prefix(xs.len() + n, seq::append(xs, ys), acc)
            == match merkle::bag_prefix(xs.len(), xs, acc) {
                None => None,
                Some(next) => merkle::bag_prefix(n, ys, next),
            }
    );
}
```

Proofs are scripts checked by the kernel (`fixtures/qmdb/sandblaster/PROOF.rs`, like
Bend's `PROOF.bend`) — induction is a recursive call, `auto` closes the rest:

```rust
#[proof]
fn bag_prefix_partition(xs: &[Digest], ys: &[Digest], n: usize, acc: Digest) {
    match xs {
        [] => {}
        [head, tail @ ..] => {
            bag_prefix_order(tail.len() + n, *head, seq::append(tail, ys), acc);
            bag_prefix_order(tail.len(), *head, tail, acc);
            bag_prefix_partition(tail, ys, n, merkle::fold(&acc, head));
            // ... two `assert`s that auto proves
        }
    }
}
```

Hardware kernels are written with `core::arch` intrinsics and marked
`#[implements(crate::sha256::compress)]`; the kernel proves them equal to the
portable function against formal instruction models that were themselves
validated against the real instructions (10⁷ random cases per model on this
machine). Only proven, evidence-backed variants are dispatched.

## Layout

| Path | What |
| --- | --- |
| [`DESIGN.md`](DESIGN.md) | the normative design (subset, ghost language, core calculus, elaboration, automation, optimizer, hardware, storage/networking/concurrency stretch goal) |
| [`SEMANTICS.md`](SEMANTICS.md) | the elaboration semantics of the subset (part of the trusted base) |
| [`kernel/`](kernel) | `sandblaster-kernel`, the trusted kernel ([`AUDIT.md`](kernel/AUDIT.md) walks through every rule) |
| [`front/`](front) | `sandblaster-front`: loader, resolver, typechecker, subset validator, elaborator, `auto`, optimizer, codegen, round trip |
| [`targets/`](targets) | `sandblaster-targets`: intrinsic models (Rust + kernel core text) with hardware-validation evidence |
| [`sandblaster/`](sandblaster) | `sandblaster`, the facade: erasing macros, `proof!`, `sandblaster::build::compile` |
| [`cli/`](cli) | `sandblaster-cli`, binary `sandblaster`: `sandblaster check \| emit \| report \| spec \| coverage \| eval` (every verdict command runs the §15 gates) |
| [`macros/`](macros), [`memguard/`](memguard), [`rulegen/`](rulegen) | erasing proc macros; the allocation cap; offline rule discovery for the optimizer |
| [`fixtures/qmdb/`](fixtures/qmdb) | the QMDB port's DSL sources, laws, proofs, locks and fixtures (a test fixture of the toolchain's suites) |
| [`bench/opt-corpus/`](bench/opt-corpus) | the optimizer corpus harness |
| [`bench/heldout-v2/`](bench/heldout-v2), [`bench/heldout/`](bench/heldout) | the held-out evaluation (v2, frozen) and its retired predecessor (v1, development data now) |
| [`bench/heldout-harness/`](bench/heldout-harness), [`bench/shipped-harness/`](bench/shipped-harness) | the fair harnesses: the optimizer against rustc on held-out code; the shipped verified code against the original Commonware functions |
| [`tools/gates/`](tools/gates) | the optimizer fairness gates (G6 frozen inputs, fair baseline) |
| [`mirx/`](mirx) | the MIR extractor (a rustc driver on a pinned nightly) |
| [`docs/`](docs) | the proof guide, the optimizer design and plan, the QMDB specification design |

## Using it

A sandblaster crate keeps its DSL sources in `sandblaster/` and lets `build.rs`
verify and generate the shipped code:

```toml
# Cargo.toml
[build-dependencies]
sandblaster = { workspace = true, features = ["build"] }
```

```rust
// build.rs
fn main() { sandblaster::build::compile("sandblaster/mod.rs"); }

// src/lib.rs  (nothing else is allowed here)
include!(concat!(env!("OUT_DIR"), "/sandblaster.rs"));
```

```sh
cargo check -p commonware-codec                                            # codec's build.rs verifies varint
cargo run -p sandblaster-cli -- check sandblaster/fixtures/qmdb/sandblaster  # verification summary
cargo run -p sandblaster-cli -- emit  sandblaster/fixtures/qmdb/sandblaster  # print the generated Rust
```

## Trusted computing base

The kernel (with its word normalizer, linear-arithmetic certificate checker and
fixed axiom list), the elaboration semantics of the canonical dialect
(SEMANTICS.md), the kernel prelude definitions, the intrinsic models and the
generated dispatch/load glue, and `rustc`/LLVM. Automation, the optimizer and
the printer are untrusted: everything they produce is checked. See DESIGN.md
§1.1 and the kernel's AUDIT.md.

## Status

See DESIGN.md §12 for the phase log. The storage / networking / concurrency
extension (journal → QMDB, p2p → Simplex, with zero overhead versus
Commonware) is designed in DESIGN.md §13; its first milestone (E0) is
Commonware's metadata store end to end.
