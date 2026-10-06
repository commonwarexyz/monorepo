# sandblaster

**Write very complex, very optimized Rust and know it is right.**

Humans review short laws. Agents write the code and the proofs. A small
dependently typed kernel checks them, on the code rustc compiles.
sandblaster reads existing Rust as it is: the item skeleton from the
source, every function body from rustc's own MIR. Nothing is generated,
rewritten or printed for rustc. `cargo build` fails unless

* every verified function terminates and never panics within its stated
  preconditions (no overflow, division by zero, out-of-bounds access or bad
  shift is reachable),
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

**Optimized code is the crate's own Rust.** An agent writes the fast
version in the host crate and proves it meets the same laws, or equals a
short reference stated in the laws file. If the lock diff is empty, there is
nothing to review for correctness; the reviewer reads the benchmark.
sandblaster used to include a proven auto-optimizer. On code it was not
built for it changed nothing (about 1.00× against rustc, held-out and on
real Commonware code), so it was removed along with the code printer and
the QMDB fixture (2026-10-05; DESIGN.md, North star and §19). The hardware
instruction semantics stay first-class: the intrinsic models
(`sandblaster/targets`: NEON, SHA-2/3, SSE to AVX-512, SHA-NI, GFNI), each
validated natively against the hardware, are what proofs over SIMD code
are about (DESIGN.md §9); reading `core::arch` calls from MIR is the next
step (C8).

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
| [`DESIGN.md`](DESIGN.md) | the design: the model (laws, references, implementation), the trusted base, the §15 gates, proof techniques, roadmap, what was removed |
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

The work now is proof techniques and laws for complex optimized code:
panic contracts, lockstep and coupled-loop proofs between an implementation
and its reference, bit-trick automation, and per-function checking, driven
by pilots on real Commonware hot paths (DESIGN.md §16–§18).
