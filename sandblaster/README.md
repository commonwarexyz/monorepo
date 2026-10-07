# sandblaster

**Prove the complex Rust you already have, SIMD included, against short
laws a human reviewed.**

Humans review the laws. Agents write the proofs. A small dependently typed
kernel checks them, on the code rustc compiles.
sandblaster reads existing Rust as it is: the item skeleton from the
source, every function body from rustc's own MIR. Nothing is generated,
rewritten or printed for rustc. `cargo build` fails unless

* every verified function terminates within its stated preconditions and
  panics exactly where its laws say (a panic contract, `panics_when(p)`:
  it panics if and only if `p`); without one it never panics there (no
  overflow, division by zero, out-of-bounds access or bad shift is
  reachable). Two limits: an overflow panic is rustc's overflow check, so
  it holds in a build with overflow checks on (every profile of this
  workspace; a downstream default release profile wraps instead), and the
  buffer traits are modeled without a capacity (a write into a `&mut [u8]`
  too short for it panics inside `bytes`, outside the verified code),
* every contract and every law in `LAWS.rs` is proven,
* every function's kernel theorem ties rustc's MIR of it to the reading the
  laws are about, and that reading agrees with rustc on generated inputs,
  and
* the §15 gates pass: the laws pin the behavior down (determinacy, known
  answers, law rules) and the specification equals the accepted
  `SPEC.lock`.

There is no flag to skip a proof or a gate. Spec mutation (does every
vocabulary function have known answers that pin it down?) is a review tool
an author or reviewer runs on demand, `sandblaster mutate <root>`, not part
of the build.

```text
Rust source + rustc's MIR ──lift──▶ front end ──▶ elaborator ──▶ kernel (TRUSTED)
LAWS.rs, PROOF.rs ──syn──┘                          │              ▲
                               automation (untrusted) ┘  theorem gate (L = S per function)
                                                        │
                       §15 gates, SPEC.lock, lift conformance ──▶ verdict
```

**The prover and the verifier are the product.** sandblaster writes no new
optimized code. It proves the code a crate already has, as written, meets
its laws, or equals a short reference stated in the laws file (for
hardware-specific code, usually the crate's own portable version: a SIMD
engine equal to its scalar engine). A later change to the code whose lock
diff is empty needs no correctness review. sandblaster used to include a
proven auto-optimizer. On code it was not
built for it changed nothing (about 1.00× against rustc, held-out and on
real Commonware code), so it was removed along with the code printer and
the QMDB fixture (2026-10-05; DESIGN.md, North star and §19); the pilots
that would have had agents write and verify faster versions of Commonware
functions were dropped on 2026-10-06. The hardware
instruction semantics stay first-class: the intrinsic models
(`sandblaster/targets`: NEON, SHA-2/3, SSE to AVX-512, SHA-NI, GFNI), each
validated natively against the hardware, are what proofs over SIMD code
are about (DESIGN.md §9); reading `core::arch` calls from MIR (C8) is the
first priority.

## Verified Commonware code in this tree

Three modules are verified by their crate's `build.rs`, each with an
accepted specification lock and every §15 gate enforced:

| module | mode | MIR theorems | lock root |
| --- | --- | ---: | --- |
| commonware-codec's varint (`codec/sandblaster/varint`): 16 laws | module (`compile_module`) | 63 of 63 | `9532b20c…` |
| commonware-storage's MMR position and peak arithmetic (`storage/sandblaster/mmr`): 11 laws | in place (`compile_lifted`) | 69 of 69 | `0c1fbaeb…` |
| storage's Merkle proof verifier, set 1 (`storage/sandblaster/verifier`: `hasher.rs` at `Standard<Sha256>`, `proof.rs`'s subtree reconstruction): 8 laws | in place (`compile_lifted`) | 69 of 69 | `12015876…` |

```rust
// storage/build.rs
fn main() {
    sandblaster::build::compile_lifted("sandblaster/mmr/mod.rs", "mmr");
    sandblaster::build::compile_lifted("sandblaster/verifier/mod.rs", "verifier");
}
```

```sh
cargo test -p commonware-codec                       # verifies the varint (about 5.5 min)
cargo test -p commonware-storage --lib               # verifies the MMR and the verifier (about 19 min cold)
cargo run -p sandblaster-cli -- spec storage/sandblaster/mmr     # the spec sheet and the lock status
cargo run -p sandblaster-cli -- mutate storage/sandblaster/mmr   # on demand: vocabulary the known answers miss
```

## Layout

| path | what |
| --- | --- |
| [`DESIGN.md`](DESIGN.md) | the design: the model (laws, references, code), the trusted base, the §15 gates, proof techniques, roadmap, what was removed |
| [`SEMANTICS.md`](SEMANTICS.md) | the elaboration semantics (trusted; hashed into every lock) |
| [`kernel/`](kernel) | `sandblaster-kernel`, the trusted kernel; [`AUDIT.md`](kernel/AUDIT.md) walks through every rule |
| [`front/`](front) | `sandblaster-front`: front end, elaborator, `auto`, the lift and the MIR reading, the §15 gates, the lock, the counterexample engine, conformance |
| [`sandblaster/`](sandblaster) | the facade: erasing macros, `proof!`, `sandblaster::build::{compile_module, compile_lifted}` |
| [`cli/`](cli) | binary `sandblaster`: `check \| report \| spec \| coverage \| mutate \| eval \| conform` |
| [`mirx/`](mirx) | the MIR extractor (a rustc driver on a pinned nightly) |
| [`macros/`](macros), [`memguard/`](memguard) | erasing proc macros; the allocation cap |

Documents in [`docs/`](docs):

| document | what |
| --- | --- |
| [`PROOF-GUIDE.md`](docs/PROOF-GUIDE.md) | how to write laws and proofs that check |
| [`mir-lift.md`](docs/mir-lift.md) | reading bodies from rustc's MIR (its §20 is normative until it joins SEMANTICS.md) |
| [`checked-structuring.md`](docs/checked-structuring.md) | the literal reading L, the structured reading S and the theorem between them |

## Trusted computing base

The kernel (with its word normalizer, linear-arithmetic certificate checker
and fixed axiom list), the elaboration semantics (SEMANTICS.md), the kernel
prelude definitions, the lift (the literal reading of rustc's MIR, each
function's theorem statement and its check, the item skeleton, the buffer
and host models), and rustc/LLVM. Automation, the structured MIR reading and
its proof walker are untrusted: everything they produce is checked. See
DESIGN.md §1.1 and the kernel's AUDIT.md.

## Status

Panic contracts landed on 2026-10-05: a documented panic is a law, proven
of rustc's MIR in both directions (DESIGN.md §16.5). The storage roots'
laws state their documented panics (the MMR 18, the Merkle proof verifier
13), each proven; varint's functions do not panic on their own (a write
into a `&mut [u8]` too short for it panics inside `bytes`, outside the
verified code). An overflow panic holds in a build with overflow checks
on, as every profile of this workspace sets them. Verified code is safe
Rust, for good: `unsafe` is out of scope (no memory model for raw
pointers, no unsafe standard-library APIs). The work now is the prover and
the verifier on complex existing code, SIMD first: reading `core::arch`
intrinsic calls from MIR onto the retained models, lockstep and
coupled-loop proofs between code and its reference (a SIMD engine against
its scalar engine), bit-trick automation, and per-function checking
(DESIGN.md §16–§18).
