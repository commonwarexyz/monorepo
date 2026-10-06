# sandblaster — design (v3)

*Formerly rustoleum. v3 (2026-10-05) is the refocus: the toolchain no longer
optimizes, prints or ships code. It proves that the optimized Rust a crate
already contains meets short laws a human reviewed.*

This document is the contract for everyone working on sandblaster. Section
numbers are stable anchors: code comments, `SEMANTICS.md`, the docs and the
lock headers cite them, so sections that were removed keep a short stub that
says what happened and where the old text lives (§19). Where this document
summarizes, the module docs it names hold the detail. Where the code and this
document disagree, the code is the fact and this document has a bug.

| document | what it is |
| --- | --- |
| `DESIGN.md` (this) | the design: model, architecture, gates, roadmap |
| `SEMANTICS.md` | the elaboration semantics of the exec subset and the ghost language: normative, trusted, hashed into every `SPEC.lock`; its stale parts are listed in §19 |
| `docs/PROOF-GUIDE.md` | how to write laws and proofs that check, with the closers and their failure modes |
| `docs/mir-lift.md` | reading function bodies from rustc's MIR; its §20 is the normative reading until it joins SEMANTICS.md |
| `docs/checked-structuring.md` | the literal reading L, the structured reading S and the kernel theorem between them |
| `kernel/AUDIT.md` | every kernel rule with its code location, justification and tests; the lift's trusted files (§21) |

---------------------------------------------------------------------------

## North star

AI agents write most code now. Writing code is cheap; trusting it is not.
sandblaster's pitch:

> **Write very complex, very optimized Rust and know it is right.** Humans
> review short laws. Agents write the code and the proofs. A small kernel
> checks them, on the code rustc compiles.

### The model: three layers

| layer | written by | read by | what it is |
| --- | --- | --- | --- |
| **Laws** | agent drafts, human approves | the human | `LAWS.rs`: the laws, the vocabulary they use with known answers (`#[example]`), the contract of every function host code can call, type invariants. All of it, and nothing else, is in `SPEC.lock`. |
| **Reference** | depends on its kind (below) | the human, when it is on the surface | what defines behavior: the laws' vocabulary, a reference spec in `LAWS.rs`, or the original code kept as ghost code |
| **Implementation** | agent | nobody has to | the crate's own Rust, verified as written from rustc's MIR, plus the proofs (`PROOF.rs`) that tie it to the laws |

**Optimized code is the crate's own Rust.** Speed comes from code an agent
writes directly in the host crate. Nothing in the toolchain derives,
rewrites, lowers or prints code for rustc. The build reads the item skeleton
from the source and every function body from rustc's MIR. A trusted literal
reading L of the MIR is tied by one kernel theorem per function to the
structured reading S that the laws and proofs are about (§1.1 item 8). What
rustc compiles is what was proven.

**Laws are the only human surface.** A reviewer reads `LAWS.rs` and its
vocabulary, never the code or the proofs. A law states what callers
observe, never how it is computed (§15.1). The lock (§15.6) hashes exactly
the review surface, so a proof refactor or an optimization that keeps the
surface leaves the lock unchanged. **An optimization PR whose lock diff is
empty needs no correctness review**: the build proved the new code meets
the old laws. The reviewer reads the benchmark.

**References and "implementation equals reference" are laws.** Determinacy
(§15.5) forces something in the laws file to define each host-callable
function completely. That something is the reference. It comes in four
kinds:

| kind | when to use it | on the surface? | example |
| --- | --- | --- | --- |
| **the laws' vocabulary** (a characterization) | the laws alone determine the function | yes: it is the vocabulary | `to_nearest_size` is the largest valid size at most `size`; varint `write` appends `varint(x)` and `read` is its canonical left inverse |
| **a reference spec in `LAWS.rs`** | callers depend on incidental behavior (which error, how much input is read, side outputs) and no short characterization exists | yes, read in full | the verifier's `rebuild` (about 40 lines), which `reconstruct_digest`'s contract equates it with |
| **a pinned original** (not built, C2) | existing code has no laws, and "behaves exactly like the code that shipped" is the guarantee wanted | yes, as one item, reviewed for provenance, not content | Reed–Solomon `Scalar::mul` defining `Neon::mul` (pilot C) |
| **a proof copy** (not built, C2) | the laws determine the function, but their proofs follow the original's structure and one equivalence lemma is cheaper | no: a proof internal cannot weaken anything | the varint byte loop under a word-at-a-time `read` |

Prefer the first kind: a characterization frees the implementation
completely. Use the second only for behavior callers rely on that no short
law states, written as a recursive definition for a reader, never in the
shape of the fast algorithm. The third is for legacy code, to be replaced
by laws later; it locks in the original's bugs, which is its honest cost.
The fourth is the agent's cost decision. **The rule: the laws file is the
definition; the implementation is free.** The code still defines behavior
where no law reaches, inside internal functions, which callers can observe
only through host-callable functions, whose behavior the laws file pins.

For a function `f` with precondition `pre_f`, a declared panic condition
`panic_f` and a reference `R`, "implementation equals reference" is:

| | statement | status |
| --- | --- | --- |
| E1, the value | `∀x. pre_f(x) → S_f(x) = R(x)`: a kernel lemma over S (for a characterization, the laws themselves) | built |
| E2, the code | `L::thm::f`: on every `x` with `pre_f(x)` rustc's MIR terminates without panic and returns `S_f(x)`, final `&mut` values included | built, every build |
| E3, the panics | `∀x. ¬pre_f(x) ∧ panic_f(x) →` the MIR panics on `x` | not built (C1, §18) |
| E4, the rest | neither: nothing is promised; the record lists the precondition as a host obligation | built |

A function without a precondition (all of varint's boundary, most of the
MMR) gets "equal on every input of its type" from E1 and E2. Inside the
domain there is no panic to compare: verified code cannot panic there, and
a defensive `assert!` is proven never to fire.

### What a green build means

For every function read from the verified files: the MIR rustc compiles
terminates without panic on every input that satisfies the function's
declared precondition, with the value of its structured reading; every law
holds of these functions; every host-callable function is determined by the
laws file (§15.5); the laws file equals the accepted lock. All of this rests
on the trusted base of §1.1.

It does **not** mean anything about inputs outside the precondition (until
panic contracts, C1); that the laws say what the author meant (that is the
reviewer's reading, helped by known answers and the on-demand spec-mutation
tool, §15.7); or that the code is fast (only a benchmark says that, §17).

### Honest evidence

* **The auto-optimizer did not pay.** About 41k lines of proven
  compositional symbolic execution, cost model, multiversioning and
  lowering. On the frozen held-out set it changed 0 of 30 functions
  (geomean 1.007, A/A control spread 0.87–1.19: placement noise). On the
  shipped Commonware modules (varint, MMR, verifier) 28 of 33 functions
  compiled to identical machine code and the rest differed only in data
  addresses (geomean 1.003). On its own development set (QMDB) it measured
  0.88–1.00×. rustc and LLVM already compile this code well, and every
  line of the optimizer and of its shipping layer (lowered copies, IDE
  twins, the round trip, shipped-code theorems) cost review, trusted base
  and build time. It was removed (§19).
* **The one big win was agent-written.** The six-probe `to_nearest_size`
  (2026-10-01), written by an agent and proven equal to the binary search,
  was reported as about 40× faster, but without an A/A control. It is a
  hypothesis until pilot A measures it (§18).
* **Hardware first, not yet on MIR.** About 23.6k lines of SIMD
  instruction models (x86 to AVX-512, NEON, SHA-2) served the dialect and
  the code the toolchain printed; no verified Commonware module used one
  yet. They are **kept** (user decision, 2026-10-05): very optimized code
  uses SIMD and other intrinsics, and proofs over it need the instruction
  semantics, validated natively (§9). What the models do not reach yet is
  code verified as written: reading `core::arch` calls from MIR is C8.
  Commonware's fastest SIMD (the SHA-256 pair and x16 kernels) is inline
  assembly, which MIR cannot read.
* **Proof size plans were optimistic.** QMDB planned about 1.1k proof lines
  and built 15.4k, for prover gaps (symbolic powers of two, `&`/`|` with no
  arithmetic meaning, arrays expanded byte by byte). Optimized code hits
  those gaps hardest; closing them is the main work (§16).
* **Gates were not at agent speed.** Spec mutation as a build gate made the
  cold storage build take 8 h 11 min; without it the same build takes
  19 min. Mutation is now a tool you run when you want it (§15.7).

Every speed claim cites an A/A-controlled benchmark of the new code
against the code it replaces, on a stated input distribution (§17).

### Why sandblaster, against its rivals

| | Rust | Verus | Lean | Bend 2 | sandblaster |
| --- | --- | --- | --- | --- | --- |
| Agents already write it well | yes | Rust plus proof code | partly | new language | yes: it is Rust |
| Verifies existing crates in place | — | inside `verus!` blocks | no | no | yes, from rustc's MIR |
| What a human reads | code | code, invariants, triggers, ghost code | proofs | laws | laws only |
| Hand-optimized code | unchecked | proven, proof code beside it | n/a | own runtime | proven as written against the laws or a reference |
| Guards against weak or gamed laws | — | no | no | no | yes: determinacy, law rules, known answers, lock diffs |
| Trusted base | rustc | Z3 plus Verus | small kernel | a TypeScript checker | small kernel; solvers and search never trusted |

Verus is the competitor to beat on "verified Rust, short specs", and it
will likely win on bit-trick proof size today (Z3 bit-blasting). The
comparison of §17 decides with data.

### Principles

1. **Proofs are agent artifacts.** Their cost is agent time, check time and
   churn when code changes. A prover gap that bloats proofs is fixed in the
   prover, never by reshaping the code.
2. **Verify the code as written.** Existing code is read as it is; where the
   reading cannot express something yet, the reading grows.
3. **The laws file is the definition; the implementation is free.** Laws
   characterize; references are short and written for a reader; equivalence
   is a law or a lemma.
4. **Measure before proving.** A body is optimized only after an
   unverified prototype wins on a stated distribution; proofs are never
   spent on non-wins.
5. **Gates are mandatory; review tools are on demand.** No flag skips a
   proof or a §15 gate. Spec mutation and LR8 run when an author or
   reviewer asks (`sandblaster mutate`).
6. **The trusted base grows only locally.** No kernel change. New
   constructs enter L's reading one at a time, each with a conformance test
   against rustc and fault injection.

---------------------------------------------------------------------------

## 0. Summary

1. Verified code is ordinary Rust in an ordinary crate. The item skeleton
   is read from the source; function bodies from rustc's MIR (`mirx`).
2. Each body has a literal reading L (trusted, construct by construct) and
   a structured reading S (untrusted, readable). A kernel theorem per
   function ties L to S. S is code in the exec subset (§3).
3. S, the laws and the proofs are elaborated into a small dependently typed
   core calculus (§5): MLTT with two sorts, inductive types, equality,
   irrelevance and machine integers. Elaboration is the formal semantics
   (SEMANTICS.md).
4. A small trusted kernel checks the core. Untrusted automation builds the
   proofs (Lean's architecture).
5. The §15 gates make sure the laws pin the behavior down (determinacy,
   known answers, law rules) and that the specification equals the
   accepted `SPEC.lock`.
6. `cargo build` runs it all from `build.rs`. Anything unproven fails the
   build. There is no flag to skip a proof or a gate.

| System | Relation |
| --- | --- |
| Verus | Inline proofs in Rust, Z3 trusted. sandblaster: own proof-term kernel, no SMT in the TCB, Bend-style laws, §15 gates against weak laws, code read from MIR. |
| Creusot / Prusti | Contracts on Rust, external provers. Same differences. |
| Aeneas / hax | Safe Rust to Lean/F*/Coq. sandblaster keeps the prover in-process (`cargo build` is the gate) and reads rustc's own MIR. |
| fiat-crypto / Jasmin | Verified fast code against a simple reference: the same line, for hand-optimized Rust. |
| Kani | Bounded model checking; no unbounded laws. |
| Bend 2 | The model for laws and proofs (`LAWS.rs`, `PROOF.rs`, proof by computation, induction by recursion). |
| K framework | Semantics first: elaborator = semantics, kernel evaluator = reference interpreter, differential tests against native code. |
| Lean | Proof-term kernel plus untrusted tactics. |

---------------------------------------------------------------------------

## 1. Architecture

```
 Rust source + rustc's MIR (.sbmir)      LAWS.rs, PROOF.rs (ghost Rust syntax)
        │ skeleton (lift) + bodies (S)            │ syn
        ▼                                         ▼
 front end: load → resolve → typecheck → subset validation → HIR
        │
        ▼
 elaborator: HIR → core, obligations proven by auto / scripts ──► kernel (TRUSTED)
        │                                                          ▲
        ▼                                                          │
 theorem gate: L (literal MIR reading) computes S, per function ───┘
        │
        ▼
 §15 gates, SPEC.lock, lift conformance → verdict; rustc compiles the source as written
```

### 1.1 Trusted computing base

Every lock header lists items 1–7 in words (`surface::TCB`); item 8, the
lift, is not listed there yet (§19, stale text).

1. **`sandblaster-kernel`**: checker, evaluator, conversion, termination,
   linear-arithmetic certificate checker, the word normalizer `bvnorm`
   (§9.8), the fixed axiom list, bignum `Int`, the section abstraction and
   the closed evaluator (§15). 9.9k code lines (AUDIT.md §1); its logic
   does not change. No `unsafe`.
2. **The elaboration semantics of the exec subset** (`SEMANTICS.md`): the
   core term for a function means what its source says. For lifted Rust
   the source is S, tied to rustc's MIR by item 8. A crate written in
   sandblaster's own dialect gets a verdict and no code
   (`DIALECT_VERIFIED`). Mitigation: the differential fuzzer of the subset
   against rustc (`tests/redteam_fidelity.rs`), §10.3.
3. **The prelude definitions** (`kernel/prelude/*.core`): the meaning of
   `List`, `Slice`, `Array`, `Option`, tuples and every whitelisted method.
   Prelude lemmas are checked, not trusted.
4. **The target semantics library** (`sandblaster/targets`, §9): the
   intrinsic models as core-text definitions (`targets/core/*.core`, loaded
   for the build target's architecture), each a lane-level transcription of
   the vendor pseudocode (Arm ARM, Intel SDM; `targets/MODELS.md` is
   normative). Mitigation: each model exists twice, as executable Rust and
   as core text; the executable model is compared with the real
   instruction on this CPU (10^7 random inputs plus corners and every
   immediate per model for `validated` evidence), the core text with the
   executable model by kernel evaluation, and the records
   (`targets/evidence/<arch>.json`) are pinned per model in every lock
   that uses it (`target-model:` items). x86 evidence is recorded data
   from x86 hosts; aarch64 is re-validated on this machine.
5. **rustc/LLVM.**
6. **The elaboration of the ghost language** (SEMANTICS.md §13): the kernel
   statement of a spec item, law, contract or invariant means what its
   source says; and `Env::abstract_section` (§15.5), which defines "fully
   specified". Mitigation: the de-elaborated statements on the spec sheet.
7. **Assumptions**: `num-bigint`/`num-integer`; the rustc that compiled the
   kernel; `syn` agreeing with rustc on the subset; the §3.7 stack
   assumption; host code calls a `#[target_feature]` function only on a
   CPU with those features; a process free of undefined behavior (host `unsafe`,
   `transmute` and C externs can forge any value, including values of
   invariant types).
8. **The lift** (`#[lift(mir = "m.sbmir", ..)] mod m;`, SEMANTICS.md §19,
   `docs/mir-lift.md` §20): the exec items the lift produces from a Rust
   file mean what rustc compiles from it. Its parts:
   * **The bodies: the literal reading L of rustc's MIR**, one kernel
     definition per MIR instance, one arm per basic block, a table-driven
     translation of a fixed set of MIR constructs. rustc has already
     expanded macros and lowered `?`, closures, operators, iterators and
     loops. Files: the generator `mir/literal.rs` (1,297 code lines) and its
     library `literal.core` (186); the theorem statement `mir/stmt.rs`
     (213); the parse `mir/ir.rs` and `sexp.rs` (482, 131); names and load
     checks `mir/mod.rs` (531); the printer `mirx` (1,122: a rustc driver on
     the pinned nightly of the stable release; its output is checked in
     with the sources' SHA-256). Then the gate's trusted check
     `mir/gate.rs` (159, plus about 27 at its call site
     `driver::gates::theorem_gate`): L enters the kernel only through it,
     and a function is accepted only when its MIR instance is that
     function, the kernel holds `L::thm::f` with a type α-equal to
     `stmt.rs`'s statement generated afresh, reaching only definitions of
     the elaboration, of L's library or of its own extraction, and every
     module type its MIR reaches is declared alike by the MIR and the
     subset. Then the elaborator's precondition check (39: a function read
     from MIR is elaborated only when each precondition is α-equal to its
     declared contract's clause) and the lift glue (about 260). **About
     4.45k code lines in all** (re-counted after the removal; 4.55k
     before it).
   * **The theorem.** S (`mir/read.rs` 2,975, steered by `mir/cfg.rs` 298)
     is untrusted. Every build checks, per lifted function,
     `L::thm::f : Π x̄ (pre). Σ k. Π n (k ≤ len n). run n b0 (Some init(x̄))
     = Some(erase(S_f x̄))` (total correctness, final `&mut` referents
     included), proven by the untrusted walker (`mir/simproof.rs`,
     `mir/checked.rs`) and checked by the kernel. Today: varint 63 of 63,
     MMR 69 of 69, verifier 69 of 69.
   * **The item skeleton**: `front/src/lift.rs` and `lift_open.rs`
     (`macro_rules!` expansion of item macros, inline modules, sealed-trait
     monomorphization, state passing in signatures, struct and enum
     declarations, derived `Default`, the attachments, in-place children,
     open traits at a declared instance, operator and conversion impls as
     methods, host models).
   * **The expression reading** of the ghost language and of the bodies
     that are not exec code (constant initializers, host-model functions).
   * **The lift prelude** (`front/lift/prelude.rs`), **the buffer model**
     (`front/lift/model.rs`: a `BufMut` is the bytes put so far, a `Buf`
     the bytes not yet read) and **the host models** (`#[lift(host)]`).
   The skeleton, expression reading, prelude and model are about 5.2k code
   lines.
   **Mitigations.** The **lift conformance check** (`front/src/conform.rs`,
   whose module docs are the full description) runs in every build after
   the gates: every lifted function is evaluated by the kernel and the
   original is compiled by the build's rustc (overflow checks on) and run
   on deterministic, coverage-driven inputs; outputs, errors and buffer
   states must agree, or the build fails with the input. L itself is also
   run and compared with rustc (the first 64 inputs per function). It is a
   test, not a proof. Fault injection (`tests/fault_injection.rs`) shows
   that a mutated MIR construct of each kind, and both historical
   structuring bugs, break a theorem. `tests/literal.rs` checks each
   construct of L against rustc's semantics with negative twins. Every
   construct the lift does not know is refused. AUDIT.md §21 has the
   file-by-file accounting.

**Not trusted:** parsing, name resolution, surface typing, obligation
generation (a missing obligation is caught because the kernel needs the
proof slot; this does not cover §15 *statements*, hence item 6),
automation, scripts, the reference evaluator, diagnostics, the structured
reading S and its walker, the verdict cache (its entries are replays the
kernel re-checks or exact repeats, §2.1), the conformance check (it can only
fail a build), the counterexample engine.

### 1.2 Crates

```
sandblaster/          (in the Commonware monorepo)
  kernel/             sandblaster-kernel. TRUSTED. term.rs value.rs api.rs (frozen interfaces),
                      bigint, eval, conv, check, inductive, recursion, prim, linarith, bvnorm,
                      axioms, section, closed, core text syntax, prelude/*.core.
  front/              sandblaster-front. loader, resolver, typechecker, HIR, subset validation,
                      builtins, elaborator, auto, scripts, lemma and proof libraries (lemmas/,
                      stdlib/), the lift and the MIR reading with the theorem gate, the §15
                      gates and the lock, the counterexample engine, conformance, driver.
  macros/             sandblaster-macros: proc macros that erase ghost annotations.
  sandblaster/        the facade: macros, `proof!` (expands to nothing), feature "build":
                      `sandblaster::build::{compile_module, compile_lifted}`; the toolchain identity.
  cli/                binary `sandblaster`: check | report | spec | coverage | mutate | eval | conform.
  mirx/               sandblaster-mirx (own workspace, pinned nightly): rustc's MIR to `.sbmir`.
  targets/            sandblaster-targets. TRUSTED (item 4). The intrinsic models: executable Rust
                      (src/aarch64, src/x86_64) and core text (core/*.core), MODELS.md, the hardware
                      differential harness (src/hw, src/diff), the evidence records and their tool
                      (`sandblaster-targets-evidence`), the kernel cross-checks (feature `kernel`).
  memguard/           process-wide allocation cap (resource safety, not TCB).
  bench/shipped-harness/  the measurement harness for pilots (own workspace; §17).
```

Shipped code has **no runtime dependency** on sandblaster.

---------------------------------------------------------------------------

## 2. Project layout of a verified crate

The laws, proofs, MIR and lock live beside `src/`:

```
host/
  Cargo.toml          [build-dependencies] sandblaster = { features = ["build"] }
  build.rs            sandblaster::build::compile_lifted("sandblaster/mmr/mod.rs", "mmr")
  src/…               ordinary host code; the verified files among them, declared `mod m;`
  sandblaster/mmr/
    mod.rs            DSL root: `#[lift(in_place, mir = "mmr.sbmir", ..)] #[path = "../../src/…"] mod m;`
                      `#[cfg(sandblaster)] #[path = "LAWS.rs"] mod laws;`  (and PROOF.rs)
    LAWS.rs           the human-owned claims (Bend's LAWS.bend)
    PROOF.rs          the proofs (Bend's PROOF.bend)
    mmr.sbmir         rustc's MIR of the lifted files (checked in; `mirx/extract.sh`)
    SPEC.lock         the accepted specification surface (§15.6)
```

* `#[cfg(sandblaster)]` items are **ghost**: never compiled by rustc; the
  checker treats `cfg(sandblaster)` as true. `#![forbid(unsafe_code)]` is
  required at the DSL root.
* Target information comes from `CARGO_CFG_TARGET_*`, never from the host.
* A crate written entirely in sandblaster's own dialect (no `#[lift]`) can
  be checked (`sandblaster check`): it gets a verdict and no code.

### 2.1 Build modes, re-runs and the verdict cache

**In place** (`compile_lifted(root, name)`, `driver::in_place`; storage's
MMR and Merkle proof verifier). The DSL root lifts the crate's own files by
path (`#[lift(in_place, ..)] #[path = "../../src/x.rs"] mod x;`, SEMANTICS.md
§19.5). The host declares each such module `mod m;` with no `#[path]`, so
rustc compiles exactly the files the verifier read. The build runs the
proofs, every §15 gate, the theorem gate and the conformance check, then
writes a record `OUT_DIR/<name>-verified.txt`: the verified items, the
preconditions host callers must meet (host obligations), and every item
left out. This is the mode the model is built for.

**Module mode** (`compile_module(root, module_file)`; codec's varint). One
pure file becomes a verified module: a lifted copy of it is emitted to
`OUT_DIR/<out>.rs` byte for byte after a status header, and the host's module
file is exactly `include!(concat!(env!("OUT_DIR"), "/<out>.rs"))` plus the
source's leading `//!` lines. The checks that the module file holds nothing
else and that no other file under `src/` names the output are textual: they
catch mistakes, not a host that hides an include on purpose. Moving varint
in place is a lock change and a user decision (§18, decision 5).

Both modes have no options, fail with exit 1 on any error, and have **no
development build**: a crate whose lock is not accepted does not build;
`sandblaster check` and `sandblaster spec` say what is missing.

**Bodies from MIR** (`#[lift(mir = "m.sbmir", ..)]`, required). `mirx`
extracts the MIR into a checked-in `.sbmir` that names its sources by
SHA-256; the build refuses a stale file, a file without overflow checks and
MIR of another rustc release. An in-place crate is extracted as a whole;
open traits at the instances the declarations name, given as type aliases
(`storage/sandblaster/verifier/instances.rs`, injected with `--inject`);
only the lifted items (`--items`, `--skip-fns`). Re-extracting after an edit
takes about 8 s (81 s cold).

**Re-runs and the verdict key** (`driver::cache::verifier_context`). The
build script watches every file it read that exists. A stored verdict is
reused when the key matches: the **toolchain identity** (a hash, computed by
the facade's `build.rs`, of every input of the sandblaster crates that can
change a verdict, including `SEMANTICS.md` and the proof libraries, but not
tests or documents nothing includes), the third-party lock entries, the
rustc, host and flags that built the toolchain, the build's `rustc -vV`,
every `SANDBLASTER_*` variable but the resource and cache settings, the
target, the root, the edition, and the content of every file the front end
read (sources, MIR, laws, proofs, the lock). In place, the key also covers
the conformance check's **host inputs** (`conform::host_inputs`: the host's
`src/`, manifests, lock, features, path dependencies, cargo configuration).
It does not cover the profile, the optimization level or the target
directory, so `cargo build`, `cargo test` and a dependent's build share one
verdict. Output is deterministic: the same inputs give byte-identical
reports and emitted files.

**The verdict cache** (`driver::cache`). Without a match in `OUT_DIR`, the
verdict is looked up under the same key in a content-addressed cache shared
by all builds (`SANDBLASTER_CACHE_DIR`, default `~/.cache/sandblaster`;
`SANDBLASTER_CACHE=off` disables it). Entries carry per-payload SHA-256s and
an HMAC-SHA-256 under a secret kept outside the cache; an edited, truncated
or forged entry is rejected and the module re-verified. A hit replays what
the same toolchain computed for byte-identical inputs, so it cannot turn a
failure into a pass. On a miss, parts keep their own caches: the theorem
gate's verdicts (replayed through the kernel) and the conformance pass,
whose key covers only what the check reads, so editing a law, a proof or
the lock does not re-run it. The spec-mutation tool caches per-mutant
verdicts the same way (§15.8). The cache is per module today; per-function
checking is C6 (§18).

---------------------------------------------------------------------------

## 3. The exec subset (code that runs)

The exec subset is the language of the structured reading S and of
sandblaster's own dialect. The checker **rejects** anything not listed.
Lifted Rust is wider than this subset: the lift and the MIR reading
translate it (SEMANTICS.md §19, `docs/mir-lift.md` §20).

### 3.1 Items

* `mod name;`, ghost `#[cfg(sandblaster)] #[path = "X.rs"] mod m;`; `use`
  with explicit paths (no globs but `use sandblaster::prelude::*;`).
* `const NAME: T = expr;` (evaluated by the kernel); non-generic type
  aliases.
* `struct` and `enum` with exec-typed fields, no recursive user types,
  type parameters bounded by `Copy` only, lifetimes; derives `Clone, Copy,
  PartialEq, Eq, Debug` (every user type derives `Clone, Copy`).
* `fn` (free or in inherent `impl`; receivers `self`, `&self`), type
  parameters with `Copy`. No `async`, `extern`, `unsafe`, variadics,
  `impl Trait`, user const generics. `#[target_feature]` functions and
  `core::arch` intrinsics are supported (§9); `#[implements]` is refused.
* **The verified boundary.** In the dialect it is exactly the DSL root's
  `pub use` list (no `pub mod` at the root): boundary functions are
  monomorphic and have no `Irr` binders (no `requires`, no depth bound, no
  ghost parameter), and no slice element type mentions a type parameter.
  In place, every host-callable function is on the boundary (§15.5), and
  its precondition and depth bound are host obligations listed in the
  record.
* Attributes: derives, `#[inline]`, `#[must_use]`, doc comments, the
  sandblaster annotations (§4), `#[allow(..)]` of lints only.
* Rejected: traits and trait impls other than derives, `static`, macros
  other than `proof!` and `unreachable!()`, closures, fn pointers, `dyn`,
  heap types, floats, `char`/`str`, signed integers, `i128`/`u128`, raw
  pointers, `&mut` (except the local `copy_from_slice` statement), interior
  mutability, `loop`/`break`/`continue`, `return`/`?` inside loops, `?` on
  anything but `Option`.

### 3.2 Types

`bool`, `u8`..`u64`, `usize` (64-bit), `()`, tuples (≤ 12), `[T; N]`, `&[T]`,
`&T` (a value), `Option<T>`, user types, type parameters. **Zero-sized
element types are rejected in slices**: Rust bounds `len · size_of::<T>()`
by `isize::MAX`, so the model's length bound would be false for them.

### 3.3 Expressions and statements

* Literals, arrays (`[a, b]`, `[v; N]`), tuples, struct literals (with
  `..base`), constructors; paths to locals, constants, functions.
* Unsigned arithmetic `+ - *` (proof: no overflow), `/ %` (proof: divisor ≠
  0), `& | ^`, `<< >>` (proof: amount < width), comparisons, compound
  assignment. `bool`: short-circuit `&& ||` (the right operand is
  elaborated under the path condition), `== != & | ^ !`. `==` on types with
  derived `PartialEq`, arrays and slices of them. `as` between unsigned
  types (narrowing truncates) and `bool as uN`.
* Indexing `a[i]` (proof `i < len`), ranges `&s[a..b]` and friends (proof
  `a ≤ b ≤ len`), field access, calls (proof: the callee's `requires`),
  whitelisted methods (§3.4).
* `if`/`else`, `if let`, `match` with guards; patterns: bindings, literals,
  ranges, tuples, structs, variants, `&p`, slice patterns, or-patterns. **An
  identifier pattern whose name resolves to a constant, unit struct or unit
  variant anywhere in scope is an error** (rustc and a naive resolver
  disagree on it).
* `let` (with patterns), `let mut`, `let P = e else { return ..; }` and
  `else { unreachable!() }`; assignment to locals, array elements and fields
  of locals; `copy_from_slice` on `let mut` array locals.
* Loops `for i in a..b`, `for i in a..=b`, `while c` (needs `decreases`);
  normative desugaring in §7.4. `return` and `?` outside loops.
  `unreachable!()` (obligation: the path condition is contradictory).
  `proof! { .. }` statements (§4.3).

### 3.4 Method whitelist

Each method has a prelude **definition** (trusted) and prelude **facts**
added at call sites like user `ensures`.

* Integers: `wrapping_*`, `checked_*` (→ `Option`), `saturating_*`,
  `rotate_left/right`, `count_ones`, `leading_zeros`, `trailing_zeros`,
  `swap_bytes`, `to_be_bytes`, `to_le_bytes`, `from_be_bytes`,
  `from_le_bytes`, `min`, `max`, `pow` (proof: no overflow),
  `is_power_of_two`, `abs_diff`, `div_ceil` (proof: divisor ≠ 0).
* Slices: `len`, `is_empty`, `first`, `last`, `get`, `split_at` (proof),
  `split_at_checked`, `split_first`, `split_last`, `split_first_chunk`,
  `split_last_chunk`, `first_chunk`, `as_chunks` (with their length facts).
* Arrays: `len`, indexing, `as_slice()`, `&a[..]`, equality. `Option`:
  `is_some`, `is_none`, `unwrap_or` (no `unwrap`/`expect`).

### 3.5 Semantic model (summary; SEMANTICS.md is normative)

| Rust | Core |
| --- | --- |
| `u8..u64`, `usize` | `IntTy(U8..Usize)` |
| `bool` | builtin `Bool` (ctor 0 = false) |
| `()`, tuples, `Option<T>` | prelude inductives |
| user struct / enum | user inductive (one ctor for a struct; eta, §5.4) |
| `&[T]` | `Slice(T) := Σ(n : Usize). Σ(l : List T). .SliceOk(n, l)` with `SliceOk(n, l) := len l = to_int n ∧ to_int n ≤ ISIZE_MAX` (irrelevant) |
| `[T; N]` | `Array(T, N) := Σ(l : List T). .(len l = N)` (array eta, §5.9) |
| `&T` | `T` |
| `a + b`, `a << s`, `s[i]` | checked primitives with proof slots (`add_w(a, b; p)`, ..., `slice_index(s, i; p)`) |
| `a[i] = v`, `let mut`, assignment | functional update, SSA renaming |
| `if`, `&&`, `||`, `match` | dependent matches with path equations |
| loops | recursive helper definitions with measures (§7.4) |
| `?`, `return` | control-flow conversion into nested matches |

Preconditions are irrelevant arguments; every call supplies proofs.
Out-of-domain operations never happen in a verified program; in the model
they are stuck terms.

### 3.6 Typing rules (must agree with rustc)

Integer literals are typed from their expected type or suffix, else
rejected. The operand of `as` has no expected type, except that a bare
literal takes the target type; an unsuffixed literal rustc would default to
`i32` is rejected. No implicit conversions except auto-ref/deref of
receivers and arguments and `&[T; N] → &[T]`. Rust's lexical scoping.

### 3.7 Recursion, termination and stack depth

* Every recursive function needs a measure (inferred or `#[decreases(e)]`).
* It must be **tail recursive** (elaborated as a loop) or **depth-bounded**:
  `#[decreases(e, max = C)]` with `C ≤ 4096`, the obligation `e ≤ C` proven
  at every outside call, and stack use as an obligation: every call tree
  with non-tail recursion satisfies `depth × frame + max callee stack ≤
  1 MiB`, `frame = 2 × (parameters + result + locals + one temporary per
  expression) + 256 bytes`. **The stack assumption** (TCB item 7): this
  frame model bounds the compiled frames and the thread has at least 2 MiB.
  Non-tail recursion with an unbounded measure is rejected.

---------------------------------------------------------------------------

## 4. Ghost language (specs, proofs, laws)

Ghost code is never compiled by rustc. It is parsed by `syn`.
`docs/PROOF-GUIDE.md` teaches it; this section defines it.

### 4.1 Ghost types and spec expressions

* `Int` (exact integers), `Nat` (`Int` with `0 ≤ n` as a fact at binders and
  an obligation at construction; `a - b` needs `b ≤ a`), `Seq<T>` (the
  prelude `List`, unbounded: `len`, `get`, `take`, `skip`, `chunks_exact`,
  `flatten`, slice patterns, `seq![..]`), `Prop` (a `#[spec] fn .. -> Prop`
  defines a proposition). Every exec type is a ghost type; slices and arrays
  coerce to `Seq` (§15.3). Ghost function values `fn(A, ..) -> B` and
  lambdas `|x: A| e` exist for generic laws (the `spec_fn` of §13.2).
* Exec expressions are spec expressions. In spec items, **spec closure**
  (§15.1) allows only established exec functions.
* In proposition position (`requires`, `ensures`, `assert`, `invariant`,
  law bodies): `==`/`!=` are propositional; `p && q` is the dependent
  conjunction (the left conjunct is a fact while elaborating the right);
  `||`, `!`, `implies`, `iff`, `forall(|x: T| p)`, `exists(|x: T| p)`; a
  `bool` `b` means `b == true`; `eqb(a, b)` is boolean equality.
* `x as Int`; `Int` has exact `+ - *` and comparisons; `/` and `%` need
  provably non-negative operands and a non-zero divisor (else
  `div_euclid`/`rem_euclid`); `Int as uN` truncates. Unsuffixed ghost
  literals default to `Nat`. Ghost code accepts `b".."` and `hex!("..")`.

### 4.2 Contracts on exec functions

`#[requires(p)]` (several are conjoined, each its own irrelevant binder),
`#[ensures(|ret| p)]`, `#[decreases(e)]` / `#[decreases(e, max = C)]`.
Measures are inferred for slice-pattern recursion and for `n − k` under a
path condition. For lifted functions, contracts are attached from the laws
file or a proof file with `#[lift_attach(path)]` (§15.6). Every
function-like item normalizes to `FnDef { requires, ensures, decreases,
body }`.

### 4.3 `proof!` blocks inside exec code

`proof! { stmts }` is a statement anywhere in an exec body; it adds facts for
later obligations. As the first statement of a loop body it may declare
`invariant(p);` and `decreases(e);`. Lifted loops take their invariants from
loop attachments (`#[lift_attach(f, loop_nr = k)]`, §16.2).

### 4.4 Script statements (in `proof!`, `#[lemma]`, `#[proof]`, `#[law]`)

| statement | meaning |
| --- | --- |
| `assert(p);` / `assert(p, { steps });` | prove `p` (by `auto` or the steps), add it as a fact |
| `lemma(args);` / `let h = lemma(args);` | apply a lemma or law; its `requires` proven by `auto`, its `ensures` a fact |
| `apply(lemma);` | the same with arguments inferred by matching `requires` against the facts (and `ensures` against the goal); no match or an ambiguous one is an error listing the candidates |
| `#[induction(x)]`, `ih(args);` | induction on a structurally smaller `x`; `ih` is the termination-checked recursive application |
| `follows();` | the goal follows from the facts by the automation's general reasoning; must be last. An empty body or a block without a closing statement means the same but warns |
| `by_arithmetic();` | arithmetic and equality only: the crate's functions are unknown, no case analysis on program values. Terminal |
| `by_unfolding(f, g, ..);` | like `by_arithmetic`, with exactly the named definitions unfolded. Terminal |
| `by_contradiction();` | the facts alone derive `Empty`. Terminal |
| `by_computation();` | evaluation and conversion alone; on failure both sides are shown. Terminal |
| `by_cases(x);`, `by_cases(k, lo..hi);`, `cases(k in a..b) { .. }` | split on a `bool`/`Option`/enum, or enumerate an integer range (≤ 256 cases) |
| `calc! { e0 == e1 by { .. }; <= e2; }` | a chain of `==`/`<=`/`<` links combined by transitivity |
| `match e { .. }`, `if c { .. } else { .. }` | case analysis with the case equation as a fact; a variable scrutinee refines goal and facts (§7.6). Terminal |
| `witness(e..);`, `unfold(f);`, `rewrite(h);`, `rewrite_rev(h);`, `exact(term);` | instantiate an `exists`; unfold the written applications of `f`; rewrite the goal with an equation; close it with a term |
| `bv();` | close a word equation by `BvRefl` (§9.8); a goal with a variable shift, `/` or `%` goes to linear arithmetic with the shift and `pow2` rules |
| `let x = e;`, `show();`, `todo();` | ghost let; print goal and facts; leave the goal open (the build fails) |

At the end of a script, `auto` must close the goal. `docs/PROOF-GUIDE.md`
has the failure modes and when to use which closer.

### 4.5 Ghost items

`#[spec] fn` (spec functions, also every `fn` of a `#[spec]` module),
`#[lemma] fn` (`requires(..); ensures(..);` then steps), `#[law] fn` in
`LAWS.rs` (a claim, no proof), `#[proof] fn` in `PROOF.rs` (same name and
parameters as its law). A law without a proof is an open claim and fails
the build. Laws and proofs pair by name crate-wide; a proof's recursive
calls are induction hypotheses. Library lemmas are addressable as
`sandblaster::lemmas::<name>` and the proof library as `front/stdlib`
(`bits`, `folds`, `seqs`, `sha256`, `bridges`).

---------------------------------------------------------------------------

## 5. Core calculus (the kernel)

The Rust types are in `kernel/src/{term,value,api}.rs` (frozen). This
section gives the rules; `kernel/AUDIT.md` gives each rule's code, set-model
justification and tests.

### 5.1 Syntax

See `term.rs`. De Bruijn indices in terms, levels in values. Every binder
(Π, λ, let, Σ second component, match-arm fields, motives) carries a
relevance. Integer literals are bignums; machine literals lie in `[0, 2^w)`.

### 5.2 Sorts and formation

* `Type : Kind`; `Kind` has no type. `Π(x :r A). B` has sort `max(s1, s2)`;
  `B = Kind` is ill-formed, so `Π(T : Type). B` (sort `Kind`) never appears
  inside `Eq`. `Σ` and `Eq(A, a, b)` live in `Type`.
* Inductive parameters may have type `T : Type` or `T : Kind`; every
  constructor field type is `: Type` and never `Type` itself (Hurkens).
* Match motives may compute a `Type` (large elimination); transport motives
  are `: Type`.
* Consistency: MLTT with one universe plus large elimination and UIP, in
  the set model. No impredicativity, no `Type : Type`.

### 5.3 Relevance (complete)

* `App { rel }` must match the relevance of the function type's Π.
* **Irrelevant positions** (exactly): the argument of an `Irr` application;
  primitive proof slots; `Rec.proof`; the second component of an `Irr` Σ
  pair; the value of an `Irr` let; `Transport.eq`; `Absurd.proof`; `Irr`
  constructor fields.
* **Every type position is relevant**, including the domain of an `Irr`
  binder and the second component type of an `Irr` Σ.
* **Resurrection**: entering an irrelevant position at depth d makes the
  irrelevant variables bound outside it (levels < d) usable; binders
  introduced inside keep their status. `snd` of an `Irr` Σ is allowed only
  in an irrelevant position entered after every free variable of the pair
  was bound. Elsewhere irrelevant variables are not usable. (A single
  "irrelevant mode" flag admitted a closed proof of `Empty`: AUDIT.md §4.)
* **Irrelevant data must be propositions** where conversion relies on proof
  irrelevance: `Irr` Σ components and `Irr` constructor fields pass a
  conservative `is_prop`. `Irr` Π domains may hold data.
* Conversion skips exactly the irrelevant positions and compares `Irr` Σ
  types fully. Evaluation never inspects irrelevant terms.
* Must-accept: `λG. refl(Bool, G true@Irr) : Π(G : Π(h :Irr Bool). Bool).
  Eq(Bool, G true@Irr, G false@Irr)`. Must-reject: `λ(h :Irr Bool). let x :
  Bool = h; x`; `(λ(x : Bool). x) true@Irr`; the `Array(T,3) ≡ Array(T,4)`
  confusion.

### 5.4 Inductive types

`InductiveDecl { name, params, ctors }`; only direct recursive fields
(strict positivity by syntax); builtins `Bool`, `Empty`, everything else
from the prelude. `match scrut as y return P with arms`, ι-reduction as
usual. **Eta for structs**: a non-recursive single-constructor inductive is
convertible with its projections' rebuild (irrelevant fields skipped).

### 5.5 Equality

`refl(A, a) : Eq(A, a, a)`; `transport(A, a, b, e, y.P, v) : P[b]` with `e`
irrelevant, reducing to `v` iff `a ≡ b`. Symmetry, congruence and
no-confusion are prelude lemmas.

### 5.6 Definitions, recursion, termination, unfolding

`DefDecl { name, kind, ty, body, recursion, arity }`:

* `Recursion::None`; `Structural { param }` (every `Rec` passes a recursive
  field of a match on the parameter); `Measure { measure }` (every
  `Rec(args; p)` carries a proof that the measure decreases and stays
  non-negative, checked in the call-site context). No mutual recursion.
* **Unfolding policy:**
  - non-recursive, non-intrinsic globals unfold on demand;
  - a recursive global applied to all arguments unfolds iff weak-head
    evaluation of its body (sub-budget 2^20 steps, only the global under
    speculation folded) does not reach a match or checked primitive on a
    neutral; otherwise it is a neutral head;
  - **opaque** definitions never unfold in checking mode; `Delta`
    (`unfold(f)`) exposes their defining equation. Sound: opacity only loses
    completeness. The elaborator makes loop-containing functions, buffer
    builders and codec readers opaque, so proofs use their `ensures`.
    `eval_opaque` takes the set to keep folded: `sandblaster eval` and
    the mutation engine pass the empty set (transparent evaluation), the
    walker passes S's opaque definitions;
  - `DefKind::Intrinsic` globals unfold only on closed arguments;
    `BvRefl` evaluates transparently (it unfolds intrinsics on symbolic
    data and opaque definitions);
  - budget exhaustion is an error, never "convertible".
* `Delta(g; args) : Eq(R, g args, body[args])`; `Unfold` casts between a
  propositional `g args` and its body.

### 5.7 Primitives

`PrimOp` in `term.rs`. A primitive computes on literals in its domain and is
stuck otherwise; checked shifts evaluate like wrapping ones. `Int` is exact
up to an implementation limit (4096 bits), beyond which evaluation fails
(never wraps). A fixed list of sound simplifications on neutrals (`x+0 → x`,
literal operands move right, `(x+c)−c → x`, byte-conversion round trips, ...)
is in AUDIT.md §7.

### 5.8 Linear arithmetic certificates

`Linarith { hyps, goal, cert }`: hypotheses and goal are comparisons of
machine or `Int` terms; linearization over ℤ treats literals, checked
`add`/`sub`, multiplication by a literal and same-or-wider casts exactly, and
introduces fresh atoms with defining constraints for division and remainder
by a literal, shifts by a literal, low masks, truncating casts and wrapping
arithmetic; anything else is an atom with its range. The certificate
assigns exact rationals to the constraints and is accepted iff their
combination has zero atom coefficients and a positive constant. A failed
hint is re-searched by an untrusted simplex whose output passes the same
check.

### 5.9 Checking and conversion

Bidirectional checking with NbE. Eta for functions, Σ, structs and
fixed-length arrays (literal `N ≤ 256`, by introducing array variables
eta-expanded). Conversion memos are scoped to one top-level call, keep
their keys alive, and include the comparison mode.

### 5.10 Axioms

A fixed list of schemas in `axioms.rs`, instantiated per width and literal,
each justified in the set model and tested exhaustively over `U8` and `U16`
and at `U64` boundaries: bounds of `and`/`or`/`xor`/`shr`, `min`/`max`/
saturating definitions, `rotr_rotl`, `mul_mono`, `div`/`rem` against
`IDiv`/`IMod`, `rem_lt`, and the bit-count definitions `count_ones_def`,
`leading_zeros_def`, `trailing_zeros_def` (sums over bits). There are no
user axioms. Add a schema only with a justification and tests.

### 5.11 API

`api.rs`: `add_inductive`, `add_def`, `infer`, `check`, `eval`,
`eval_opaque`, `quote`, `conv`, `alpha_eq_relevant` (the theorem gate's
statement comparison), `abstract_occurrences`, `linearize`, `refs_closure`,
`abstract_section`, `eval_closed`. `check_residual_equal` and
`conv_opaque` remain in the frozen kernel but have no caller since the
printer's removal (§8.3). `Term::Erased` is rejected by every checking
entry point.

### 5.12 Core text syntax

A textual syntax for core terms with a parser and printer that round-trip
(`kernel/CORE_SYNTAX.md`), used by the prelude, tests and diagnostics.

---------------------------------------------------------------------------

## 6. Prelude ("Base")

* **Definitions** (trusted, `kernel/prelude/*.core`): `Unit`, `Option`,
  tuples, `List`, `Either`, the logical connectives, `seq::*`, `SliceOk`,
  `Slice`, `Array`, byte conversions (`from_be_bytes := from_le_bytes ∘
  rev`), and the meaning of every §3.4 method.
* **Lemmas** (checked, `front/lemmas/*.core`): lengths, `take`/`drop`,
  extensionality, the method facts.
* **Builtin table** (`front/src/builtins.rs`): `Builtin` ↔ prelude global ↔
  Rust spelling. Hashed into every lock (`builtins`), with
  `elab/semantics.rs` and the surface table of the intrinsics
  `front/src/intrinsics.rs` (§9).

---------------------------------------------------------------------------

## 7. Elaboration

### 7.1 Global order

Collect all items (prelude, DSL and ghost modules, the lift's items),
resolve, reject reference cycles other than self-recursion, elaborate in
dependency order, adding each definition to the kernel immediately. Laws
after everything they mention; proofs after their laws. Loop helpers are
numbered deterministically in source order.

### 7.2 Proof context, facts, obligations

* Facts are context entries (`Irr` lets and binders). Each partial
  operation, call precondition, invariant, measure, contract and law is an
  **obligation** (`prover::ObligationKind`) handed to the prover chain; the
  returned term is re-checked by the kernel and placed in the proof slot.
* The elaborator–automation contract is `prover::{Goal, FactRef, Hint,
  AutoFailure, Prover}`: a goal carries its context, facts, target and
  hints; a failure carries the goal, facts, stuck terms and what was tried.
* Branches are dependent matches whose arms receive the path equation as an
  `Irr` binder.
* A lemma's `requires` are relevant hypotheses. A proof valid only in an
  irrelevant position of an information-free proposition (equations and
  their combinations) is promoted (`eq::promote`); `∨` and `∃` need a
  relevant proof.

### 7.3 Exec functions

`f : Π(T..)(x : ⟦A⟧)..(h :Irr ⟦P⟧).. ⟦R⟧`. The body: SSA for assignment,
early `return`/`?` move the rest into the non-returning branch, or-patterns
with guards expand to consecutive arms, every partial operation gets a
proof. `f::ensures : Π(..)(h : P..). Q[x, f x h]` is proven by walking the
body; recursive calls use `f::ensures` as the induction hypothesis; a call
of an opaque `g` in `Q` brings `g::ensures`.

### 7.4 Loops (normative desugaring)

`for i in a..b { B }` ≡ `if a < b { loop#k(a, mutated.., read..) } else {
mutated.. }`; the helper requires `a ≤ i < b`, the user invariants and the
facts in scope about read variables; its body is `B` then `if i + 1 < b {
rec(i + 1, ..) } else { mutated' }`; measure `b − i`. `a..=b` adds a `done`
flag (no overflow at `MAX`). `while c { B }` with `decreases(e)` likewise,
ensuring `¬c`. Invariant entry, preservation and exit are obligations. The
helper's `ensures` (`Inv` at exit) is bound after the loop as a fact.

### 7.5 Patterns

Nested patterns compile to single-level matches with first-match semantics;
integer patterns to comparisons; guards to an `if` falling through.

### 7.6 Refinement for Σ-typed and struct variables

A match on a variable of slice, array or struct type η-expands it in goal
and facts, generalizes, and rebuilds the pieces per arm, so every arm's goal
mentions the constructor form and computes.

### 7.7 Derived `PartialEq`

Structural `T::eq` with `eq_sound` and `eq_complete`, registered with
automation.

---------------------------------------------------------------------------

## 8. Automation

### 8.1 `auto` (untrusted, proof-producing)

Input: a goal and a budget. Output: a kernel term or an `AutoFailure`. Steps
iterated to a fixpoint within the budget: normalize; close by conversion or
a fact; split goal connectives; saturate facts (conjunctions, injectivity,
`eq_sound`, method facts, registered rules); contradictions (constructor
clash, `Empty`, linarith infeasibility, `¬P` with `P` provable); rewrite
with facts about stuck terms; instantiate axioms for `min`, `max`,
saturating ops, `div`, `rem`, shifts, `and`, `or`, casts, `count_ones` and
products (`mul_mono`), and library lemmas for complements and exponents;
decide stuck comparisons by linarith; arithmetic congruence; `Delta`
unfolding that unblocks a match; bounded case splits and enumeration of
small integer ranges; `BvRefl`; linarith search producing a §5.8
certificate. `#[bridges]` lemmas (`front/stdlib/bridges.rs`) are rules of
every proof. Every search is deterministic and bounded by steps; the
wall-clock deadline and memory cap are safety nets that fail the build,
never decide a proof.

### 8.2 Optimizer (removed)

The always-on optimizer (symbolic-execution specialization, loop
summaries, multiversioning, e-graph, bounds-check elimination, the
panic-explicit reading of unverified code) was removed on 2026-10-05.
§19 says why and where it lives.

### 8.3 Code printer and round trip (removed)

The canonical code printer, generated-mode elaboration, the lifted round
trip and the shipped-code theorems (`L::shipped`, `L::pshipped`) were
removed with the optimizer. The kernel entry points they used
(`check_residual_equal`, `conv_opaque`) stay in the frozen kernel, unused.

---------------------------------------------------------------------------

## 9. Hardware and word algebra

**Hardware semantics are first-class** (user decision, 2026-10-05: "don't we
want to retain the hardware code so our proofs work over it?"). Very
optimized code uses SIMD and other intrinsics; proofs over it need the
instruction semantics. The removal of 2026-10-05 took them out with the
optimizer and the same day's stage "retain-hardware" restored them from
`4a0e5a23fc`, without the optimizer-only parts.

* **The models** (`sandblaster/targets`, TCB item 4): every modeled
  intrinsic twice, as executable Rust (the reference compared with the
  hardware) and as a core-text `def[intrinsic]` global (what proofs are
  about): aarch64 NEON, SHA-2, SHA-3/SHA-512 (58 models); x86 SSE2 to
  SSE4.1, SHA-NI, AVX/AVX2, AVX-512F/BW/VL/DQ/IFMA/VBMI/VBMI2/VPOPCNTDQ/
  BITALG, GFNI (113 models). `MODELS.md` states each model's lane-level
  semantics. Loads and stores are modeled on typed arrays.
* **Validation, natively.** `tests/aarch64_hardware.rs` runs every aarch64
  model against the real instruction on this CPU (random, corner and every
  immediate; `--ignored` runs the 10^7-per-model campaign);
  `tests/kernel_crosscheck.rs` evaluates every core-text model in the
  kernel against its executable model; `tests/consistency.rs` checks the
  SHA models against FIPS 180-4. The records (`evidence/<arch>.json`,
  `sandblaster-targets-evidence --check`) are fail-closed per model (a
  current failure on any CPU, a stale source or core hash: not validated).
  x86 evidence is recorded data (Zen 5 native, Rosetta 2); x86 hardware
  tests run only on x86.
* **The front end.** `core::arch::<arch>` paths resolve against the
  surface table `front/src/intrinsics.rs`; vector types (`uint32x4_t`,
  `__m128i`, …) are `Ty::Vector`, kernel `Array(lane, lanes)` with lane 0
  lowest; an intrinsic call elaborates to its model, immediates first, each
  with a range proof (SEMANTICS.md §15). `#[target_feature(enable = "..")]`
  is read with rustc's implication closure (`target::feature_closure`), and
  every intrinsic call's features must be in the calling function's own
  closure (static target features do not count); calling a
  `#[target_feature]` function needs its features too. The model loader
  (`elab/semantics.rs`) reads `targets/core/<arch>.core`; when the file is
  missing, hardware functions are deferred, never trusted.
* **The lock.** A header's `target <arch>` line is the hash of that
  architecture's core files; every model a crate's code uses is a
  `target-model:<arch>:<name>` item: the executable model's source hash, the
  core hash, the evidence record and the fail-closed verdict.
* **Not restored** (optimizer or native-dialect authoring only): the cost
  and tuning tables, multiversioning and dispatch generation, `#[implements]`
  variants and `VariantEquiv`, the lane lemmas `front/lemmas/lanes`, the
  `sandblaster::arch` load/store helpers. `#[implements]` and
  `sandblaster::arch` are refused (`target::NO_VARIANTS`,
  `target::NO_ARCH_HELPERS`). Pointer-taking loads and stores cannot be
  called from the dialect.
* **Not yet:** code verified as written. The lift's L does not read
  `core::arch` calls from MIR yet; that is capability C8 (§16.4, §18).
  `elab/semantics.rs` loads only `<arch>.core`, so the x86 AVX models
  (`x86_64_avx.core`) are validated and hashed into the header but not
  loaded for elaboration (the file is hashed into the lock's `builtins`
  line; loading them is part of C8).

### 9.8 Word algebra: `BvRefl` and `bvnorm` (TCB)

`BvRefl { ty, lhs, rhs } : Eq(ty, lhs, rhs)` is accepted iff the two sides
are equal modulo word algebra, decided by one bottom-up pass over both DAGs
with hash-consing and union-find (intrinsics unfolded, arrays
eta-expanded, results memoized). Rules, in order per node:

1. Constant-fold total primitives; reduce shift and rotation amounts mod w.
2. `not(x) → x ^ ALL_ONES`.
3. **GF(2)-linear xor sets** of `(atom, rotation, mask)` terms: rotations
   and shifts distribute over xor; group by `(atom, rotation)`, xor the
   masks, drop zero masks.
4. `and`/`or` sets: sorted, idempotent, absorbing constants.
5. Pure bitwise subterms with ≤ 4 atoms → a truth-table canonical form
   (SHA-2's Ch and Maj forms coincide).
6. **Sums** (`wadd`, `wsub`, `wneg`, `wmul` by a literal, `wshl` as `2^k`)
   → constant plus a coefficient map mod 2^w; truncation passes through.
7. **Bit-slice concatenation** with tracked known-zero masks: `|`, `^`, `+`
   merge disjoint segments, adjacent segments of one atom merge (the four
   bytes of `x` in order are `x`; `(x >> 2) | (x << 30)` is `rotr(x, 2)`).

**Tripwire**: before accepting, both sides are evaluated on 32 random
valuations plus corner values; any mismatch rejects. Tested exhaustively
over U8 and U16 for 2-atom expressions from generators aimed at known
traps. It decides equalities only: no comparisons, symbolic shift amounts,
products of variables or carries across masks (§16.3). Long term: prove
the normalizer by reflection, making `BvRefl` ordinary conversion.

---------------------------------------------------------------------------

## 10. Build integration, CLI, validation

### 10.1 Build

`sandblaster::build::compile_lifted(root, name)` and
`compile_module(root, module_file)` (§2.1) read `CARGO_MANIFEST_DIR` and
`CARGO_CFG_*`, run the **crate path** (`driver::build_crate`: proofs, law
non-vacuity audit, the five §15.8 gates, the theorem gate, the conformance
check), write the record or the module only with a crate verdict (the
report always), print `cargo::rerun-if-changed` for every file read that
exists, and exit 1 with diagnostics on failure. Neither takes options.

### 10.2 CLI

`cli/src/main.rs`'s module docs are the reference.

| command | what it does | states a verdict? |
| --- | --- | --- |
| `check <dir>` | the crate path; writes nothing; one line per gate | yes |
| `report <dir>` | the crate path; the JSON report | yes |
| `spec <dir>` | the crate path, then the spec sheet and the lock status | yes |
| `spec --accept [ITEM…]` | every gate but the lock, then writes the lock (the only writer) | writes the lock |
| `spec --accept --equivalent-only` | after a toolchain change: the header, and items kernel-proven equivalent | writes the lock |
| `spec --preview <file>` | writes the lock `--accept` would write, elsewhere; needs the proofs, not the gates | no |
| `spec --diff <rev>` | classifies each changed item: strengthened, weakened, equivalent, unrelated | no |
| `coverage <dir>` | the crate path, then an exploration run of the counterexample engine (§15.9), bounded by `--mutants-max`, `--time-budget` | yes (for the crate path) |
| `mutate <dir>` | the spec-mutation tool (§15.7): every spec mutant of the review surface; exit 1 on a survivor or an incomplete run | no |
| `eval <dir> <fn> <args>` | the reference semantics: kernel evaluation | no |
| `conform <dir> ..` | the lift conformance check of in-place modules alone | no |

Only a crate verdict prints `VERIFIED` or makes a verdict command exit 0.

### 10.3 Validation of the TCB (not optional in CI)

* **The subset**: per construct, programs whose kernel evaluation is
  compared with rustc's build of the same source on many inputs
  (`tests/redteam_fidelity.rs`, `tests/elab_constructs.rs`).
* **The lift**: the theorem gate, the conformance check against rustc,
  fault injection, `tests/literal.rs` (§1.1 item 8).
* **The kernel**: the adversarial suite (proofs of `Empty`, relevance
  breaks, non-terminating recursion, forged certificates, memo address
  reuse, unsound `bvnorm` candidates), AUDIT.md §18.

### 10.4 Diagnostics

`file:line:col: error[kind]: message`, the goal and facts in Rust-like
syntax, and what automation tried; also as JSON. Generated definitions
(`f::ensures`, loop helpers, `L::thm::f`) map back to the source span that
produced them.

---------------------------------------------------------------------------

## 11. The QMDB port (removed)

The QMDB port in sandblaster's own dialect (`fixtures/qmdb`) and its design
(`docs/qmdb-spec-design.md`) were removed on 2026-10-05 (§19). The suites use
the three verified roots as their large examples
(`front/tests/verified_roots.rs`); the draft QMDB laws remain as a law-rule
fixture (`front/tests/samples/qmdb_laws_draft/LAWS.rs`).

## 12. Implementation plan (removed)

The phase plan is in git history. Current work: §18.

## 13. Storage, networking and concurrency (parked)

The design for async actors, effect models, crash consistency and Simplex
(stretch goal, written when sandblaster printed the verified code) is
parked; its text is §13 of DESIGN.md at `4a0e5a23fc`. Two of its pieces are
live: §13.2's ghost function values (`spec_fn`, now §4.1, with the fold
library `front/stdlib/folds.rs`) and opaque definitions (§5.6). If it
returns, it returns as Rust verified as written, like everything else.

## 14. QMDB-full (removed)

In git history (§19).

---------------------------------------------------------------------------

## 15. Specifications: making the laws pin the code down

Audience: engineers for whom a bug is a failure. A proof that code meets
its laws is worth only as much as the laws. §15 makes sure that:

1. an engineer states what the code must do, as laws over a readable
   vocabulary, as contracts, or as types with invariants;
2. the build fails unless the code provably does exactly that; and
3. the build fails if the specification does not pin the behavior down:
   every implementation satisfying it is observationally equal to this one
   (`obs_eq`, §15.5) on every input of its domain.

**Mandatory, with one exception.** Every §15 gate runs in every build of
every crate; no profile, attribute, `cfg`, feature, environment variable or
build option relaxes one (§15.8). The exception, since 2026-10-05: **spec
mutation and the law-sensitivity rule LR8 are an on-demand tool**
(`sandblaster mutate`, §15.7), never a gate.

### 15.1 Spec functions and laws

`#[spec] fn` is the language for *what* code means: pure, total
(measure-checked), over `Int`, `Nat`, `Seq<T>` and exec types, with no
performance concerns; evaluated by the kernel for examples; erased from the
build.

* **Spec closure (normative).** `Refs*(t)` is the least set of globals in
  relevant positions of `t`, closed under bodies and types. A function is
  **established** when it is fully specified (§15.5) in an earlier section
  at an identity or injective view, or, for a lifted function, when a
  laws-file contract states `ret == E` with `E` spec-closed and free of the
  function. A spec item (spec fn, constant, view, invariant, example, ...)
  is **spec-closed** when every exec global in its `Refs*` (not descending
  into established functions) is established. Anything else is
  `error[spec-depends-on-impl]`: otherwise `#[spec] fn s(x) { f(x) }` would
  make any `f` "meet its spec".
* **Fuel.** A spec fn that returns a default when fuel runs out needs a
  `#[fuel_sufficient]` lemma over its domain, or measure recursion.
* **Mirrors.** A spec fn whose body equals an exec function's (after δ of
  non-recursive helpers) needs `#[mirrors_impl(justification = "..")]` plus
  independent examples, else `error[spec-mirrors-impl]`.

**Writing laws for optimized code** (guidance; the rules below enforce
part of it):

1. State what callers observe, never how it is computed. Characterize by
   uniqueness (the largest, the inverse), by an independent standard
   (FIPS 180-4, LEB128), or by round trip plus canonicity.
2. Keep the vocabulary mathematical (`Int`, `Nat`, `Seq`, textbook
   recursion), with known answers from an independent source and both
   outcomes of every `bool`.
3. Specify stateful types through a view (the abstract value), never
   through private fields (views on lifted types: C7).
4. Both directions; security laws in extraction form.
5. Pin incidental behavior with the shortest reference spec that states it.
6. Every documented panic of a host-callable function becomes a panic
   contract (C1).
7. Draft a small set and let §15 say what is missing: an unproven
   `complete_p` names the gap, the engine gives two implementations that
   meet every law and differ on an input, and `sandblaster mutate` finds
   vocabulary the known answers do not pin. A long list "to be safe" costs
   review and says no more than a short complete one.

**Law rules (normative).** A law is read *instead of* the implementation,
so its statement must mean something without it. The rules apply to
`#[law]` items (lemmas in `PROOF.rs` are unrestricted), are checked on the
de-elaborated statement (§15.6), and fail closed: a rule that cannot decide
a law reports a finding.

1. **LR1 Vocabulary** (error `law-mentions-internal`). A law mentions only
   spec items, exec types through their views, and exported functions (the
   root `pub use` list and `pub` methods of exported types; in place, the
   host-callable functions). Not an internal function, not a plain `fn` of
   a ghost module, directly or through a spec item's `Refs*`. Internal
   functions are specified where they are defined and connected by lemmas.
2. **LR2 Closure** (error `spec-depends-on-impl`): a law is a spec item that
   may also reach the exported functions it constrains.
3. **LR3 State it over the spec** (warning `law-bypasses-refinement`): a
   law over an exported `f` with `#[refines(s)]` should be stated over `s`.
4. **LR4 No closed disjuncts; extraction form** (error
   `vacuous-reduction`). Every disjunct of a conclusion and conjunct of a
   hypothesis mentions a binder. A `#[reduces_to(a)]` law concludes
   `P ∨ B(t̄)` with `a` an `#[assumption]`, `B` a `bool` spec fn (the break
   predicate, e.g. `collision`) and `t̄` computed from the binders: an
   explicit collision, never `exists x ≠ y. sha256(x) == sha256(y)`, which
   pigeonhole proves. A break predicate that ignores its arguments or
   follows from the hypotheses is an error, and so is a guarantee `P` that
   follows from the hypotheses alone.
5. **LR5 Mirrors against every function** (error `spec-mirrors-impl`): the
   mirrors check compares each spec fn with every exec function, by the
   lock's canonical hashes.
6. **LR6 Laws that restate** (on the statement with non-recursive spec fns
   unfolded). (a) **Echo** (error `law-restates-impl`): proven by
   unfolding each mentioned function at most once with propositional
   reasoning and congruence only. A round trip through code without
   arithmetic is an echo; specify such a codec by its wire format and make
   the round trip a lemma. An intentionally definitional law carries
   `#[definitional(reason = "..")]` and never counts as a guarantee. (b)
   **Resemblance** (warning): a ≥ 12-node subterm α-equal to a subterm of
   an exec body.
7. **LR7 Corollaries** (warning `law-corollary`): a law whose proof uses
   only other laws and propositional steps; demote it or mark it
   `#[corollary]`.
8. **LR8 Sensitivity** (warning `law-insensitive`, **on demand only**:
   reported by `sandblaster mutate`, never by a build). Per law, the spec
   mutants in its `Refs*` for which the engine finds a definite
   counterexample; a law that kills none says nothing about its
   definitions.
9. **LR9 Readable** (error `law-undocumented`): every law has a doc comment
   whose first sentence states the guarantee in words; every
   `#[reduces_to]` names an `#[assumption]`. The spec sheet prints the
   table *law | guarantee | assumes*.
10. **LR10 Both directions** (warning `one-directional-laws`): a `bool`
    exported function mentioned only in hypotheses, or only in
    conclusions, is reported.

### 15.2 Refinement signatures

`#[refines(s)]` on a function `f` generates the lemma (`Refines`)
`f::refines : Π x̄ (h̄ :Irr Req_f x̄). obs_eq(α(f x̄ h̄), s(α x̄))`, where `α` is
each type's abstraction (identity, the type-directed view coercion, a
`#[view]`, or the simulation form of `#[represents]`); `#[refines(s(e..))]`
maps arguments explicitly. It is proven like `ensures` and is a fact at
every call. It discharges §15.5 for `f` only if every output type has an
identity view, a proven `view_inj`, or is `Abstract` (§15.3). A boundary
function's spec is total on its input type (a standard with a smaller
domain is a total spec plus a law relating it to the standard); internal
functions may use `#[refines(s, domain = P)]`. A mutating method is
written state-passing, `fn m(self, ..) -> (Self, R)`, post-state first.
What ships is what was proven: a lifted function ships as rustc compiles
it, and its theorem ties that MIR to the reading the refinement is about.

### 15.3 Types that carry invariants and meaning

All zero-cost: proof components are `Irr`; the representation is the plain
Rust type.

* **Invariants are part of the kernel type.** `#[invariant(p)]` on `S`
  makes the constructor carry `inv :Irr Eq(Bool, p̂(fields), true)`; every
  construction proves it (`TypeInvariant`), every match yields it as a
  fact. No code path forms an invalid `S`. Refinement newtypes are the
  one-field case (`#[invariant(self.0 < MAX_LOCATION)] pub struct
  Location(u64);`).
* **Visibility.** A type with an invariant, a representation relation or a
  non-identity view has only private fields, so host code cannot forge
  values. No ghost fields; ghost parameters (`#[ghost] x: T`) are allowed
  and make a function non-boundary.
* **Views** `#[view(spec::T)]` (structural, injective), `#[view(|s| e)]`,
  or the type-directed coercion (`&[T] ↦ Seq<α(T)>`, `uN ↦ uN | Nat | Int`,
  componentwise for `Option` and tuples, an invariant newtype to its
  field). Views are surface items.
* **Representation relations** `#[represents(|s: &S, a: spec::A| P)]` for
  state that is not computable from the representation; then `S` must be
  `Abstract`: private fields, no exported constructor, no derived `Debug`,
  `PartialEq` only through the view, and every boundary function over `S`
  refines through `α_S`.
* **Index spaces as distinct types** (`Position`, `Location`, `Height`):
  mixing them is a type error. **Evidence types**: invariant types whose
  invariant is a certified property, constructed only where it is proven
  ("parse, don't validate", enforced by proof).
* When a type gains an invariant, the lock diff reports every law over it
  as weakened.

### 15.4 Traits with laws; determined traits

Designed, not built (the subset has no traits): static traits declare laws
every impl proves; `#[determined]` makes "all implementations agree" a
trait obligation; law-carrying traits are sealed and boundary functions are
never generic over them. Lifted Rust's sealed traits are monomorphized by
the lift instead (§1.1 item 8).

### 15.5 Determinacy

Every **host-callable** function and every exec function mentioned in a law
or a host-callable function's contract must be **determined** by the
specification: by `#[refines]` with determinacy, or by a kernel-checked
obligation per section.

* **Host-callable (normative).** In the dialect: the root `pub use` list and
  the `pub` methods of the types it reaches. In place, every function host
  code can name: every non-private function (free, method, trait-impl
  method, an impl on a primitive lifted as a free function such as
  `u64__from__Position`, associated constants as constant functions); every
  private function of a module that has a **host child module** (a child
  the lift leaves out, other than `#[cfg(test)]`; Rust lets descendants call
  private items, so `mmr/mod.rs`, with children `batch`, `mem`, `proof`, …,
  exposes all its private functions); and every private function that the
  module's own left-out code calls by name (`validate::left_out_callers`;
  the verifier's `reconstruct_digest` and its helpers are host-callable this
  way). Loop helpers stay internal. A host-callable function's
  precondition and depth bound are host obligations listed in the record,
  and only the laws file may state them (§15.6).
* **Sections are computed, never declared**: the strongly connected
  components of "law or contract mentions exec function", without functions
  determined by `#[refines]`, ordered dependencies first.
  `#[section(with = [..])]` only merges sections (always sound).
* **Published functions** `P(R)`: the members referenced from outside `R`.
  **Hypotheses** `H(R)`: the laws mentioning `R` (never a `#[definitional]`
  one), plus the contracts, refinement lemmas and invariants of `R`'s
  functions, re-elaborated with `R` abstracted.
* **Statement.** For each `p ∈ P(R)`, the kernel's `Env::abstract_section`
  (TCB) builds (`Completeness`)

      complete_p(R) : Π(F₁' : T₁)…(Fₖ' : Tₖ[F'₍<ₖ₎]). Π(e : Ens[F']). Π(l : L̂[F']).
                      Π(x̄ : Ā_p)(h̄ :Irr Req_p[F'](x̄)). obs_eq(F_p' x̄ h̄, f_p x̄ h̄)

  replacing every relevant occurrence of a member by a variable, λ-lifting
  spec definitions that reach `R`, and refusing any other global outside
  `R` that reaches it ("establish it earlier or merge it in": inlining an
  outside exec function would turn its implementation into a
  specification). It says: every implementation satisfying the
  specification agrees with this one on every valid input. It is one lemma
  per `p`, printed on the spec sheet and hashed into the lock; proven by
  `auto` or `#[proof(complete = path)]`.
* **Observational equality** `obs_eq_A(a, b)`: `Eq` at identity views; `Eq`
  of views through an injective view or on an `Abstract` type; pointwise for
  function-typed outputs; componentwise for state-passing tuples.
* **Well-founded relative completeness.** `Deps(R)` (computed) are the exec
  globals in `H(R)`'s `Refs*` outside `R`. `R` is fully specified iff every
  `complete_p(R)` checks and every dependency is fully specified in an
  earlier section or is a trusted primitive. Without well-foundedness, the
  single law `f(x) == g(x)` would "determine" `f` given `g` and `g` given
  `f`; here they form one section and the obligation fails, as it should.
* **Discharges by `auto`**: refinement through views; exact
  characterizations of boolean functions (`f(x) == true ↔ P(x)`);
  extensionality of the lift prelude's `Ordering` enums; recursive
  equations by induction.
* **Domain.** Determinacy is over inputs satisfying `requires`. Every such
  `requires` must survive the non-vacuity refuter and be met by an example.

### 15.6 The specification surface and `SPEC.lock`

The build computes every statement item and checks all of them. The
**review surface**, which `SPEC.lock` holds, is only what a reviewer must
read to trust the crate (`crate::surface`, *What is locked*):

1. **Roots**: every law, boundary signature, type and constant, contract,
   computed section, vector file and `#[assumption]`.
2. **Vocabulary**: the closure of the roots under statement dependencies
   (spec fns, constants, types, views, contracts, invariants they mention).
3. **Known answers** of the vocabulary (`#[example]`s, vector files,
   `#[mirrors_impl]`, `#[fuel_sufficient]` lemmas), closed to a fixpoint.

Everything else is a **proof internal** and never locked: helper spec fns
only proofs use and their examples, contracts and invariants no statement
mentions, lemmas and proofs. Varint's lock went from 360 items to 116 when
the 244 proof internals left.

**A lifted crate's lock is its laws file (normative).** A lifted function's
**contract**, the locked statement and its §15.5 hypothesis, is the
`ensures` that `LAWS.rs` attaches, alone. An `ensures` attached from a proof
file is a **proof-internal summary**: proven, a fact at every call, never
locked, never a determinacy hypothesis. Nothing a proof file defines may
appear in a locked statement (`surface::proof_file_errors`). On a locked
item, only the laws file may attach a precondition, a depth bound or an
invariant (`surface::attached_proof_file_errors`). Attachments name their
target by full path (`crate::m::S::f`; an impl on a primitive by its lifted
name, `crate::merkle::position::u64__from__Position`). The source text a lock
item hashes is the statement's own tokens (`hir::Attached`,
`hir::FnDef::sig_text`, `hir::Example::text`), so moving text changes no
hash and editing a statement changes exactly its item. **A proof refactor
never changes the lock; a change of a law, its vocabulary, a known answer
or a boundary signature always does.**

* **The lock** (checked in beside the DSL root; `SPEC.lock`, or
  `SPEC.<stem>.lock` for a root not named `mod.rs`/`lib.rs`) is a sorted
  text file with one entry per surface item: key, kind, the rendered
  statement and a Merkle hash `H(i) = hash(kind, path, canon(stmt),
  src(stmt), ⟨(g, Hdep g) | g ∈ Refs₁(stmt)⟩)` (`canon`: de Bruijn, no
  names, irrelevant subterms erased, globals by path). The header records
  the format, the kernel, prelude, `SEMANTICS.md`, builtins and lift hashes,
  the target with the hash of its target-model core files (§9), the TCB
  items 1–7, and every
  section (`R`, `P`, `Deps`, the hash of `complete_p`).
* **Enforcement.** The entries must equal the computed surface exactly; a
  missing lock or any added, removed or changed item is `error[spec-lock]`
  naming each item. Only `sandblaster spec --accept` writes the lock, and
  only after every other gate passed, so every specification change is a
  reviewable diff. `spec --diff <rev>` classifies each change in the kernel
  (strengthened, weakened, equivalent, unrelated); after a toolchain change,
  `--accept --equivalent-only` re-accepts only the header and items proven
  equivalent.
* **Reviewing.** `sandblaster spec` prints the spec sheet: per section the
  source, a fully parenthesized de-elaborated statement and the kernel
  statement. An empty lock diff means no correctness review (North star).
  For a new surface: read the vocabulary and the provenance of its known
  answers (an answer derived from the definition counts for nothing); read
  each law's first sentence and de-elaborated form, and ask the four
  questions of `docs/PROOF-GUIDE.md` §0; run `sandblaster mutate` and read
  the survivors and each law's kill set; check the record's host
  obligations against the documentation.

### 15.7 Validating the specification itself

A proven implementation of a wrong spec is wrong, so the spec gets its own
checks.

* **Known answers** (gate). `#[example(e)]` (a closed `bool` spec
  expression) is a kernel lemma, checked by conversion or the kernel's
  closed evaluator `Env::eval_closed` (TCB). `#[examples(file = ..)]` binds
  vector records to a checker's parameters; vector files are surface items
  with a content hash and a provenance (`independent`, `production`,
  `self`); self-derived vectors do not count. An exhausted budget is an
  error, never a skip.
* **Coverage** (gate). Every spec fn is exercised by an example; a `bool`,
  `Option` or `Result` spec has each outcome at least once; functions of a
  law-only section have examples on the function itself; every public
  invariant type has an example built through the public API.
* **Non-vacuity** (build). Laws and `requires` must not be refuted by the
  bounded refuter; implication antecedents must be satisfiable.
* **Spec mutation (an on-demand tool, not a gate).** The engine's operators
  (§15.9) applied to the spec fns and spec constants of the review surface
  should each be killed by a known answer or by a definite counterexample
  to a law. A survivor is a vocabulary function the known answers do not
  pin down; the tool reports the input where it differs and the
  `#[example]` to add (`error[spec-mutant-survived]`). LR8 comes from the
  same run. Authors and reviewers run `sandblaster mutate <root>`
  (`driver::stage::mutate`); exit 1 when a mutant survives or the run is
  incomplete. **No build runs it**, and its findings never decide a verdict
  or a lock. Why: what binds the code to the locked statements (the proofs,
  determinacy, the examples gate) does not depend on it, and as a gate it
  made the cold storage build take 8 h 11 min instead of 19 min.
* **Not built:** the ghost-language differential (compiling quantifier-free
  spec fns natively to compare with kernel evaluation, a mitigation for TCB
  item 6) and behavior snapshots (§15.13).

### 15.8 The gates, with no opt-out

`driver::build_crate`, the **crate path**, is the only producer of a
`CrateVerdict` (private fields) and of the lock-accept permit. It runs, in
order:

1. **the proofs**: every definition kernel-checked, every obligation and
   law proven, the law non-vacuity audit, the resource gate;
2. **the five gates**: **boundary** (`validate::spec15_gate`: the
   boundary's shape, every host-callable function determined), **examples**
   (`examples::spec15_gate_s1`: known answers, coverage, spec closure,
   mirrors), **sections** (`complete::spec15_gate_s3`: every `complete_p`
   proven, sections well-founded), **law rules** (`law_rules::
   spec15_gate_laws`: LR1–LR10 but LR8), **lock** (`lock::enforce`);
3. **the theorem gate** of every function read from MIR, **the lift
   conformance check**, and the resource gate again.

Every path that writes crate output (record, module, lock) or states a
verdict (`compile_module`, `compile_lifted`, `check`, `report`, `spec`,
`spec --accept`, `coverage`) goes through it. Stage APIs (`driver::stage`,
`eval`, `spec --diff`, `spec --preview`, `mutate`, `conform`) never state a
verdict; their reports say `PROOFS CHECKED (stage run, no crate verdict …)`.
Outcomes are decided by step budgets only; wall-clock deadlines and memory
limits are safety nets whose trip fails the build as a resource failure.

**The spec-mutation tool** (review mode of the engine; `sandblaster
mutate`). It runs every spec mutant of the review surface with fixed
options (`MutateOptions::gate`: no cap, no deadline; the
`SANDBLASTER_MUTANTS_*` variables shape only `coverage`'s exploration run).
A mutant's re-check elaborates only its spec closure and the `bool`
checkers of the laws in that closure (`elab::order::filter_closure`), never
the proofs. Known answers run nearest first and stop at the first kill;
then the distinguishing search. Batches run on up to four threads. With the
verdict cache, each mutant's verdict is stored under a key covering
everything its re-check reads, so a re-run after an edit runs only the
mutants the edit can affect; resource outcomes are never stored.

**Would-be escape hatches, and how each is closed:**

| escape hatch | closed by |
| --- | --- |
| a flag, attribute, env var, feature or profile that skips a gate | none exists; resource settings only change limits |
| running out of budget | a failed obligation, never a pass |
| deleting `SPEC.lock` | a missing lock is an error; only `spec --accept` writes one |
| a spec that calls the implementation | spec closure (§15.1) |
| a spec that copies the implementation | mirrors (LR5), with justification and independent examples |
| laws that do not pin behavior down | determinacy (§15.5) for every host-callable function |
| circular "relative" completeness | computed, well-founded sections |
| a lossy view hiding wrong output | determinacy through views needs `view_inj` or `Abstract` |
| a precondition that excludes the interesting inputs | non-vacuity, met by an example; in place it is a listed host obligation |
| a law that restates the code | LR1, LR5, LR6 |
| a definitional law as the only spec | never a section hypothesis |
| a security law satisfied by the existence of collisions | LR4 |
| forging an invariant value | `Irr` constructor fields, private fields |
| shipping code other than what was proven | rustc compiles the verified file; its MIR is tied to the proven reading by a theorem per function |
| user axioms | none |
| a stage API used as a verdict | only the crate path makes a verdict or the accept permit |
| a vocabulary function the known answers do not pin | the spec-mutation tool, on demand; what binds code to statements is unchanged |
| an unvalidated or edited hardware model | per-model evidence, fail-closed verdicts, `target-model:` lock items (§9) |
| a hardware variant chosen at run time | `#[implements]` and dispatch are refused; a `#[target_feature]` function is called only by code with its features |

### 15.9 The counterexample engine (untrusted, diagnostic)

It never makes anything pass. It explains failures and gaps by refuting:

1. **Mutants**: operator replacement, constant perturbation, condition
   negation, check deletion, return-value replacement, off-by-one bounds,
   argument swaps, on the typed HIR, printed as source diffs.
2. **Re-verification** of only what depends on the mutated item, bounded.
3. **Distinguishing input**: for a survivor, an input where mutant and
   original differ, by kernel evaluation. Found: a **definite
   counterexample** (`error[spec-incomplete]` with the diff, the input and
   both outputs). Not found: "possibly equivalent", never an error.

Mutants killed by safety obligations or budget are reported apart and never
count as killed by the specification. **Which spec functions the tool
mutates**: the review surface only. A proof internal is not mutated (the
report lists it): whatever it is, the locked statements are proven from it
or the build fails, and demanding known answers for it would make agents
restate proof helpers from their own definitions. Implementation mutants
run only in `coverage`, and only produce findings when a section is not
fully specified.

### 15.10 Reporting

`sandblaster-report.json` (deterministic) and the spec sheet give, per
function: safety obligations and how they were discharged, the laws and
refinements, the section and its status, examples and outcome coverage,
and the TCB and assumptions. The report's `gates` section lists each gate
(ran, errors, warnings, a note) and the SHA-256 of an emitted file (module
mode). Wall-clock times are in `sandblaster-timing.json`, never in the
report. Diagnostics: `error[refines]` (a definite counterexample),
`error[refines-unproven]` (the stuck goal), `error[spec-incomplete]`,
`error[spec-lock]` (old and new statement, classified),
`error[law-mentions-internal]`, `error[law-restates-impl]` (with the
unfolding), `error[vacuous-reduction]`; in rustc's layout and as JSON.
`sandblaster mutate` prints its own run: counts, each survivor with its
input and the example to add, each law's kills, an incomplete run.

### 15.11 QMDB to fully specified (removed)

With the fixture (§11, §19).

### 15.12 Status

S0–S5 landed (2026-09): the §15 interface, spec functions and refinement,
invariants and views, computed sections with `complete_p`, the law rules,
the counterexample engine, the crate path with every gate on and no
transitional mode. On 2026-10-05 spec mutation and LR8 left the gates for
the on-demand tool. Three Commonware roots verify with accepted locks:

| root | mode | laws file | MIR theorems | lock root |
| --- | --- | --- | ---: | --- |
| codec varint (`codec/sandblaster/varint`) | module | 171 lines: 16 laws, 0 attachments | 63 of 63 | `9532b20c…` (116 items) |
| storage MMR (`storage/sandblaster/mmr`) | in place | 922 lines: 11 laws, 89 attachments | 69 of 69 | `0c1fbaeb…` (208 items) |
| storage verifier, set 1 (`storage/sandblaster/verifier`) | in place | 1,022 lines: 8 laws, 87 attachments | 69 of 69 | `12015876…` (272 items) |

Build times after the refocus: codec 5.5 min for the whole `cargo test`
(elaboration 287 s, gates 5.7 s); storage cold 19 min for build and tests
(MMR elaboration 546 s, verifier 336 s).

### 15.13 Beyond functional correctness (designed, staged)

Each becomes mandatory in the release that lands it.

* **Panic contracts** (C1, first): §16.5.
* **Behavior snapshots and the unconstrained-behavior report**: the code's
  outputs on a deterministic input set, locked, so a behavior change no law
  covers shows up concretely in the lock diff. Not built.
* **Canonical codecs**: round trip and uniqueness laws for every boundary
  decoder, or `#[malleable(reason)]`.
* **Resource bounds**: `#[cost(steps <= e)]`, a derived ghost cost function,
  a polynomial `steps` bound on every boundary function.
* **Secrets**: `Secret<T>` with data-independent operations only;
  `declassify(e, "reason")` as a surface item.
* **Assumptions**: `#[assumption(class = .., cite = "..")]` items, security
  laws in extraction form with `#[reduces_to(..)]` (built, LR4).
* **Later**: compatibility against the previous release's lock
  (`#[compat(..)]`), post-link stack analysis, an independent re-check of
  the exported kernel environment.

---------------------------------------------------------------------------

## 16. Proof techniques for optimized code

None of these needs a kernel change. Every new step is untrusted search
producing a kernel-checked term, or a checker written in the kernel's
language whose soundness the kernel checks (reflection). The only trusted
growth is in L's reading of new constructs and in host or hardware models,
each local and covered by conformance against rustc (and, for hardware
models, by native validation, §9).

| technique | today | gap | closing it (capability, §18) |
| --- | --- | --- | --- |
| summary-preserving replacement | works: `PROOF.rs` summaries, `opaque()` | none for pilot A | — |
| characterization (laws determine `f`) | works: uniqueness lemmas, `complete_p` | `complete_p` not reused as a step | a step that instantiates it |
| lockstep, implementation against reference | DSL only (`elab/lockstep.rs`); the walker relates L to S | two MIR-read functions | C3 |
| coupled loops (product programs) | — | missing | C5 |
| loops with invariants | loop attachments, loop lemmas, fuel functions | iterator adapters; fold matching | per-adapter models; fold matching |
| bit tricks | `bvnorm`, K1 bit-count axioms, `stdlib::bits`, proof by computation | symbolic shifts and masks, carries, `u128` | C4, then C11 |
| SIMD lanes | models retained and validated (§9); dialect code proven over them | reading `core::arch` from MIR (S and L), loads, dispatch | C8 |
| `unsafe` | refused | unchecked APIs; raw pointers | C9, C10 (gated) |
| panics outside the domain | — (the gate's panic statement was removed; it seeds C1) | panic contracts | C1 |
| proof reuse and stability | per-module verdicts; theorem and mutant caches | per-function checking; cross-root reuse | C6, C7 |

### 16.1 Relational and equivalence proofs

From cheapest to most expensive.

* **(a) Summary-preserving replacement (works).** Law proofs use a
  function's proof-internal summary (an `ensures` attached in `PROOF.rs`;
  with `opaque()` the only thing callers see). Replace the body, prove the
  same summary for the new body, and every law proof stays. Example: the
  six-probe `to_nearest_size` of `7e9851b3ba` proved the same `ensures` as
  today's binary search, with one search invariant per helper and about
  200 proof lines for 37 code lines.
* **(b) Characterization (works).** When the laws determine `f`, any body
  meeting them equals `f`: `to_nearest_size_by_search` proved fast ==
  original because both are `mmr_size` of the largest leaf count that fits
  (about 30 lines). No reference is needed.
* **(c) Lockstep (DSL only today).** `elab/lockstep.rs` walks an exec body
  and a `#[model]` spec together: tests split with their path equations,
  contradicting arms close at once, calls meet calls, leftover equations go
  to the prover. Nothing relates two MIR-read functions, so the verifier
  tied `reconstruct_digest` to `rebuild` with hand-written step lemmas.
  C3 extends it to lifted functions and pinned originals: the core tool for
  "branchless rewrite of a branchy function" or "table instead of
  computation".
* **(d) Coupled loops (missing).** Optimized loops rarely step in line
  with the original (unrolled by `k`, 16 lanes per step, a word against a
  byte at a time, early exit against a full scan). C5: a coupling
  attachment names both loops, the step ratio and an invariant over both
  programs' variables; the toolchain builds the product lemma by measure
  recursion on the implementation's loop, advancing the reference `k`
  steps per step and finishing with the reference's own loop lemma.
* **(e) Intermediate closed forms (works, costly).** When the two sides
  share no structure, prove each equal to a closed form or
  characterization. The cost is set by the arithmetic and bit automation.
* **(f) Finite-domain computation (works, clumsy).** `position_to_location`
  (three Newton steps, justified in its own comments by testing about 300k
  behavior classes) is proven complete by reducing every input to a class
  and checking all classes by kernel computation, in 32 separate lemmas:
  about 820 proof lines for about 20 code lines. C4 adds one
  `by_enumeration` step over a bounded domain and promotes the reduction
  lemmas to the library.

### 16.2 Loops with invariants

Loop attachments in `PROOF.rs` (`#[lift_attach(f, loop_nr = k)]` with
`invariant`, `decreases`, `at_start!`, `at_end!`, `after_loop!`); without one
the reader guesses a measure and the elaborator proves it. The reader turns
loops into tail-recursive or `while` helpers; on the MIR side each loop gets
a kernel lemma by measure recursion reusing S's decrease proof, and nested
loops get fuel functions (`docs/checked-structuring.md` §5.12). Gaps:
relational invariants (§16.1 d); iterator adapters (`chunks_exact`, `zip`,
`enumerate`, `rev`, `step_by`, `windows` are refused; each needs a model in
both readings with a test, a negative twin and a conformance case, +20–40
trusted lines each); fold matching against `front/stdlib/folds.rs`; early
exits ("the first index where `P` holds").

### 16.3 Bit tricks

Today: `BvRefl` decides word equalities (§9.8; it proved ARMv8 SHA-2
`compress` equal to FIPS 180-4 in 18 ms); `count_ones`, `leading_zeros` and
`trailing_zeros` are kernel-defined sums over bits; `linarith` decides
linear integer arithmetic; `front/stdlib/bits.rs` proves `pow2`,
`popcount`, alignment and zero-count facts one bit at a time; proof by
computation covers finite domains. Missing, with evidence: symbolic shift
amounts (the verifier proves `1 << b == 2^b` by 64 cases); masks and shifts
as arithmetic for symbolic `k` (`x & (2^k − 1) == x % 2^k`, `x >> k == x /
2^k`, disjoint `|` as `+`); popcount across a split; `u128` (L reads it as
unmodeled, so widening multiplies get no theorem). In order: a bridge
library registered as `auto` rules (C4); `by_enumeration` (C4); `u128` as a
pair of `u64` in L's library and the lift prelude, conformance-tested (C4,
+100–200 trusted lines); later, only if a spike shows it pays,
bit-blasting: an untrusted SAT solver's LRAT certificate checked by a
checker written in the kernel's language with a kernel-checked soundness
proof (C11). That would match Verus's `by (bit_vector)` without new trust.

### 16.4 SIMD lanes

The models are retained and validated (§9), and dialect code is proven over
them today (`front/tests/hardware.rs`: a NEON function's contract proven
over `vdupq_n_u32`, `vaddq_u32` and `vgetq_lane_u32`, the models pinned in
the lock). Code verified as written needs **C8: reading `core::arch`
intrinsic calls in host Rust from MIR onto the retained models**, in both
readings:

* **S** (the structured reading, untrusted). The lift reads the source
  through the front end, which already resolves `core::arch`, types vector
  values and elaborates intrinsic calls to the models. Missing: lifted
  modules with `#[target_feature]` functions end to end (attachments,
  contracts over vector values), `unsafe` blocks around value-only
  intrinsics in code older than Rust 1.86, and loads (below).
* **L** (the literal reading, trusted). `mirx` must print a call to a
  `core::arch` function as an intrinsic leaf (its stdarch path, its const
  generic immediates: rustc has already turned legacy immediate arguments
  into const generics) and print vector types (`#[repr(simd)]` structs);
  `mir/ir.rs` parses them; the L generator reads a vector local as the
  model's `Array(lane, lanes)` and an intrinsic call as an application of
  the model global, with the immediates' range proofs, and reads a call
  whose model is missing as unmodeled (no theorem); `stmt.rs` and the gate
  accept model globals in what an `L::thm` may reach; the feature rule is
  checked on MIR (the function's `#[target_feature]` set, which `mirx`
  prints, covers each model's features). Trusted: +150–300 lines of L and
  `mirx`.
* **Loads and stores** take raw pointers. First slice: read
  `vld1q_u8(a.as_ptr())` and `vld1q_u8(s.as_ptr().add(i))` patterns as the
  array model applied to the addressed sub-array, with the bounds as an
  obligation (+50–100 trusted lines); general pointers need C10.
  `transmute` between a vector and an array of the same lanes reads as the
  identity on `Array(lane, lanes)`.
* **The walker and the theorem gate** treat model applications as opaque
  leaves equal on both sides; lane-wise proofs use `bvnorm` per lane.
* **Dispatch.** A `#[target_feature]` function called from code without the
  feature (behind `is_aarch64_feature_detected!`) reads the detection as an
  unknown boolean; every branch is proven equal to the reference.
* **Conformance.** The lift conformance check runs the intrinsic code
  natively (NEON on this machine; SSE/AVX2 under Rosetta 2; AVX-512 only on
  x86 hosts).
* **The AVX models.** Loading `x86_64_avx.core` for elaboration changes
  `elab/semantics.rs`, hashed into the lock's `builtins` line: four varint
  item hashes are restated (not their statements) at that acceptance.

Estimate: a first slice (value-only NEON intrinsics in a `#[target_feature]`
function, no loads, no dispatch) 8–12 agent-days; with array loads,
dispatch, x86 and tests 18–30 agent-days. Commonware's intrinsic code is the
Reed–Solomon engines and curve25519's backends (pilot C); the SHA-256
kernels are inline assembly, out of scope for any MIR-level tool. A cheaper
first step is SWAR in safe Rust (eight byte lanes in a `u64`, pilot B).

### 16.5 Panics outside the domain, and `unsafe`

**Panic contracts (C1).** `PeakIterator::to_nearest_size` asserts `size <=
MAX_NODES` and a host test checks the panic; the precondition excludes
those inputs, so a new body without the `assert!` would verify and the host
would silently get a wrong size. Plan: split L's failure outcome into
**Panic** (a failed `Assert`, a diverging call) and **Stuck** (fuel, UB, an
unmodeled construct), +60–120 trusted lines in L, `stmt.rs` and `gate.rs`;
`panics_when(..)` contracts in the laws file, locked like preconditions,
with the obligation `∀x. panics_when(x) → ∃k. run k b0 init(x) = Panic`
proven by the walker along the guard's path; the record states three
regions per host-callable function (domain, panic region, the rest).
**C1 is seeded from the gate's panic statement removed with the optimizer**
(user decision, 2026-10-05; all at `4a0e5a23fc`): `mir/stmt.rs`'s
`statement_panic` (the `Option`-valued statement: where the reading is
`None`, the literal run returns no value), `mir/gate.rs`'s
`Ledger::accept_shipped_panic` with its checks `panic_exact` (no fault, no
loop, no self-call, every block read as panicking diverges) and
`must_diverge`, and `same_telescope_option`, and the walker's panic mode
(`mir/simproof.rs`, `mir/checked.rs`: `L::pthm`, `L::plem`). C1 restores
them from git, drops the optimizer's panic-explicit readings as the subject
(the subject becomes the laws file's `panics_when`), and replaces the
"nothing but a panic is `None`" restriction by the Panic/Stuck split. Total equivalence on every input,
including where the original loops or returns garbage, is not offered: it
would oblige an optimization to reproduce undocumented misbehavior.

**`unsafe` (gated on a user decision).** Level (a), C9: unsafe standard
library APIs as leaves (`get_unchecked`, `unwrap_unchecked`, ...), each
transcribing its documented safety precondition, so the obligation is the
bounds check the safe version performs at run time (5–15 trusted lines
each). Level (b), C10: a memory model for raw pointers (allocations with
provenance, bounds-checked access, byte-level casts) with a syntactic
no-aliasing rule stated plainly, +1,000–1,500 trusted lines; only if a
pilot shows (a) and a shim are not enough.

### 16.6 Proof reuse and stability

Verdicts are cached per module, so any edit to a verified file re-runs its
module's elaboration (about 4 minutes for the MMR). Law proofs mostly go
through summaries, which is why (a) above is cheap; moving all three modules
from the source reading to MIR changed 0 law lines and one proof lemma. The
MMR and verifier roots both prove `position.rs`, `location.rs` and
`mmr/mod.rs`. Closing: **summary discipline** (law proofs use summaries,
never bodies; a lint warns); **per-function checking** keyed by the
function's reading, its callees' summaries and its proof text (target: a
one-function edit to feedback in ≤ 60 s; the trust argument is the verdict
cache's); **cross-root reuse** (a root imports another's locked contracts);
**library promotion** (a lemma used twice moves to `front/stdlib`). Churn is
measured, not assumed (§17).

---------------------------------------------------------------------------

## 17. The agent workflow and what we measure

**The loop.** (0) Pick a hot function by profile; if it is not verified,
verify it as written first. (1) Prototype the optimized body unverified and
measure it; go on only if it wins on a stated distribution (the pilot-B
prototypes show why: a "fast" `pos_to_height` ran at 0.70–0.73×, a fast
varint lost on 9–10-byte values). (2) Choose the reference: usually keep the
summary or prove the laws. (3) Edit the host file in place; keep the
signature, the documented panics and their messages; keep new helpers
private and out of modules with host children. (4) Re-extract the MIR of
every root that records the edited file. (5) Differential check,
implementation against reference, natively on the conformance inputs
(seconds; to build, C2). (6) Prove: safety (mostly automatic), the MIR
theorem (automatic; a failure is a toolchain bug, not the agent's), the
summary or equivalence lemma, the panic contract. (7) Full build: a pure
optimization leaves the lock diff empty. (8) Report the speedup, proof
lines, check times, agent time and every toolchain gap met, each fixed
generically.

**Feedback** the agent gets, as text and JSON: a counterexample (input and
both outputs); an unproven obligation (goal, facts, what was tried); a
failed lockstep (where the sides diverge, the equation left); a failed MIR
theorem (the path of splits, both sides); a failed panic contract.

**Measured per pilot.** Speedup over the original with
`bench/shipped-harness` (`run.sh --probe <dir> --base <rev>`: the crates at
the base commit against the worktree's own, in one binary): every
subject compiled alike from one source, an A/A copy of the original, three
builds (default, 64-byte aligned, no overflow checks), the machine-code
identity check, at least 21 interleaved rounds, medians and p10–p90, a
frozen input distribution including a realistic one, and the end-to-end
effect on that workload. Also: human review (lock-diff items, reviewer
minutes, reviewed lines per verified line); agent effort (wall clock,
tokens, failed attempts, toolchain fixes counted apart); proof lines per
implementation line; kernel and build times; churn under three to five
realistic follow-up edits; each toolchain gap with its trusted-base delta.

| measure | today | target |
| --- | --- | --- |
| MIR extraction after an edit | 8 s (81 s cold) | same |
| differential check | not built | ≤ 30 s |
| proof feedback after a one-function edit | whole root: about 231 s (MMR), about 10 s (verifier), several minutes (varint) | ≤ 60 s |
| cold verified build of storage | 19 min (8 h 11 min with mutation as a gate) | ≤ 15 min |
| kernel time of one MIR theorem | 0.001–0.66 s | ≤ 1 s |
| proof lines per implementation line | about 5:1 (six-probe search), about 40:1 (Newton) | ≤ 5:1 without loops, ≤ 10:1 with; above 20:1 is a toolchain gap |
| lock diff of a pure optimization | — | 0 items |
| law-proof lines changed by an implementation-only change | 0 (the MIR move) | 0 |

**Against Verus.** Same component (pilot A: `to_nearest_size` and
`is_valid_size` with the six-probe search, against the same laws), same
agent model, same time box. Measure specification lines, proof annotation
lines, verification time, time to green, tokens and added trust; record
whether Verus needed host-code changes, whether its specification
determines the function, and churn. If Verus wins clearly on time to green
and proof size even after C4, that is a strategic finding for the user.

---------------------------------------------------------------------------

## 18. Roadmap

**Done (2026-10-05):** the removal (§19); spec mutation off the build path;
the three roots re-verified with header-only lock re-accepts; the hardware
semantics restored (§9; another header-only re-accept); the measurement
harness restored for pilots (§17).

**Pilot A: MMR `to_nearest_size` and `is_valid_size`.** Replace the binary
search in `storage/src/merkle/mmr/iterator.rs` by the six-probe search
(private helpers in `iterator.rs`, whose only child is `tests`);
`is_valid_size` becomes `size <= MAX_NODES && to_nearest_size(size) ==
size`. Proof: summary-preserving (§16.1 a) and characterization (b); no law
changes. Builds C1 for `to_nearest_size`'s panic. **Exit:** the lock diff is
the one panic contract; 0 law and law-proof lines changed; ≤ 300 new proof
lines; ≤ 1 agent-day to green (excluding C1); MMR check time within 10% of
today; a speedup measured by §17 (target ≥ 10× on a uniform distribution of
bit lengths, the realistic one reported beside it). Then the Verus
comparison.

**Capabilities, in order** (agent-days are focused agent work with tests):

| # | capability | forcing example | trusted base | agent-days |
| --- | --- | --- | --- | ---: |
| C1 | panic contracts (Panic/Stuck split, `panics_when`), seeded from the gate's panic statement at `4a0e5a23fc` (§16.5) | pilot A | +60–120 | 5–8 |
| C2 | pinned originals and proof copies (`#[lift(reference)]` via `mirx --inject`, provenance check, native differential check) | pilots B, C | one item kind | 3–5 |
| C3 | lockstep for lifted functions | pilot B, verifier | none | 5–8 |
| C4 | bit bridge library, `by_enumeration`, `u128` as pairs | pilot B | `u128`: +100–200 | 9–16 |
| C5 | coupled loops | pilot B | none | 8–15 |
| C6 | per-function checking, summary lint, library spec mutation once per version | every pilot's loop time | small | 11–21 |
| C7 | contract schemas (one reviewed line generates a newtype's routine contracts), views on lifted types, host-callable by name, cross-root reuse | review cost; a representation change of `PeakIterator` | +150–350 | 13–23 |
| C8 | reading `core::arch` intrinsic calls in host Rust from MIR (S and L) onto the retained models; array loads, dispatch (§16.4) | pilot C | +200–400 (models already item 4) | 8–12 first slice; 18–30 in all |
| C9 | (gated) unsafe standard-library leaves | unchecked indexing | +100–200 | 3–5 |
| C10 | (gated, only if needed) raw-pointer memory model | pilot C without a shim | +1,000–1,500 | 20–40 |
| C11 | (research) bit-blasting with a checked certificate checker | after C4, if bit proofs still dominate | none | 5 spike, then 20–40 |

**Pilot B: a harder safe case.** Criteria: safe Rust, a real hot path with a
measured win on a realistic distribution, laws already complete, at least
two capabilities pilot A did not need. On preliminary, unverified,
A/A-controlled prototype numbers (the pilot-B stage's
`recovery/refocus/pilotB`, outside the repository), codec's varint
on one 64-bit word fits best: encode 1.04–2.90× across five distributions
and decode 1.02–1.44×, but 0.72× and 0.88× on 9–10-byte values, so the fast
path must be guarded or fixed. Its 16 laws are complete and short, and its
proof is the largest of the three modules. It needs C3 or C5 and C4; decode
also needs a decision on `Buf::chunk` (a prefix of the remaining bytes whose
length depends on segmentation: the model must state that nondeterminism).
**Exit:** lock diff empty; equivalence proof ≤ 10× the implementation's
lines; ≤ 5 agent-days once its capabilities exist; every gap fixed
generically.

**Pilot C (gated): SIMD against a scalar reference.** Reed–Solomon
`Neon::mul` against `Scalar::mul` (the crate already treats the scalar
engine as the reference). Needs C8, `u128` and a proof that the NEON tables
are the nibble split of the scalar ones. 15–25 agent-days after decision 1
(the models are retained, so decision 2 is taken).

**Decisions for the user:** (1) proof-justified `unsafe` in shipped
Commonware code; (2) restoring SIMD models: **taken** (2026-10-05, kept and
first-class, §9); (3) whether
"behaves exactly like the code at revision R" is an acceptable law for
existing code (pinned originals); (4) the `Buf::chunk` buffer model; (5)
when to move varint in place (a lock change: `Decoder::new`/`feed` become
host-callable and need contracts); (6) whether a kernel change is ever on
the table (this design assumes not); (7) **taken** (2026-10-05): the
hardware parts of `intrinsics.rs` and `elab/semantics.rs` stay (§9).

**Stop rules.** If after C3–C5 the pilots still need more than 20 proof
lines per implementation line, or more than two agent-weeks for a function
the size of pilot B's, verified optimization pays only for a handful of very
hot functions: stop adding capabilities and report. Expect most value from
verifying existing optimized code and a few agent optimizations in
genuinely naive spots, not broad speedups. Keep a running count of trusted
lines per stage. If contract schemas and views do not shrink in-place laws
files, the review surface grows with every verified file: measure reviewed
lines per verified line on every pilot.

---------------------------------------------------------------------------

## 19. What was removed, and where it lives

On 2026-10-05 the toolchain was cut back to what this model needs (about
178k lines in the refocus' first pass, then 41k more). Everything removed is
in git:

* **Commit `4a0e5a23fc`** (branch `sandblaster`, 2026-10-04) is the last
  commit with all of it.
* **`refs/parked/auto-optimizer-2026-10-05`** (a stash commit on top of
  `4a0e5a23fc`) holds later, unvalidated optimizer work (proven checks and
  loops, benchmark updates) that was never committed.
* The step-by-step removal log is `recovery/refocus/REMOVAL-LOG.md`, kept
  outside the repository beside the worktree.

| removed | where it was at `4a0e5a23fc` | why |
| --- | --- | --- |
| the auto-optimizer (symbolic-execution specialization, cost model, tuning, profiles, e-graph, panic-explicit readings) | `front/src/opt/`, `docs/optimizer-design.md`, `docs/optimizer-plan.md` | 1.00× on held-out and shipped code (North star) |
| the shipping layer: `#[lift(opt)]`, `#[rewrite]`, `#[specialize]`, lowering, lowered copies and declarations, IDE twins, the lifted round trip, `L::shipped`/`L::pshipped`, relocation, fail-closed stubs | `front/src/driver/lowered.rs`, `lower.rs`, `roundtrip.rs`, `relocate.rs`, `mir/gate.rs`, `mir/stmt.rs` | it shipped optimizer output real code never got |
| the canonical code printer, crate mode, `sandblaster emit`, `profile` | `front/src/canon.rs`, `driver.rs` | nothing is printed for rustc |
| the hardware parts that served only the optimizer or native-dialect authoring: tuning tables, `#[implements]`, `VariantEquiv` variants, multiversioning and dispatch, the lane lemmas, `sandblaster::arch` | `targets/evidence/tuning-*`, `targets/src/evidence/tuning.rs`, `front/lemmas/lanes/`, `sandblaster/src/arch/` | the models themselves are kept (§9) |
| benchmarks, held-out sets, fairness gates, `rulegen`, the optimizer corpus | `bench/` (`shipped-harness` and `samecode.py` are back, repurposed for pilots, §17), `rulegen/`, `front/tests/fairness_*` | they judged the optimizer |
| the QMDB port and its design | `fixtures/qmdb/`, `docs/qmdb-spec-design.md` | a dialect crate; the verified roots replace it as large examples |
| spec mutation as a gate | `driver::gates` | now the on-demand tool (§15.7) |
| the development build `compile_lifted_pending_gates` | removed earlier, in `4a0e5a23fc` itself | no transitional mode |

Kept on purpose: the kernel, unchanged (including the unused
`check_residual_equal`); `mirx --inject`; `elab/lockstep.rs`; the
counterexample engine; the conformance check and its input generator; the
proof libraries; `front/src/refute.rs` (counterexamples for failed
obligations, called from `elab/obl.rs`; moved out of the optimizer, its
module docs still describe the optimizer's residuals).

**Stale text kept for the locks.** `SEMANTICS.md` is hashed into every
lock's `semantics` line, so it is fixed at the next lock acceptance, not
before. Stale today:

1. The introduction cites the QMDB port and `tests/elab_qmdb.rs` as
   validation (removed).
2. §3.1 "Proven arithmetic in generated code" (the printer's `__rt::chk`
   helpers, generated mode, the round trip; `__rt` is no longer reserved by
   the front end): the whole section.
3. §6 "their terms are what the code generator prints"; §7 "`canon::
   expand_or_arms`, shared with the printer" (now `elab/pat.rs`, no
   printer); §9 "tail recursion is printed as a loop by the code
   generator" and "the emitted code" in the stack assumption.
4. §12.1 "the clone equality proofs of the optimizer rely on that" and
   "in generated mode (the round trip, DESIGN.md §8.3)".
5. §13.6 "the round trip's generated mode builds the same constructor with
   `Erased` proofs" and "the printer omits ghost parameters ...; the round
   trip's lowered calls lack them".
6. The obligation kinds list (at the end of §13.5; the contents line calls
   it §14, which has no heading) includes `VariantEquiv`, which nothing
   produces now.
7. §18's "Optimizer clones (DESIGN.md §9.3)" deviation.
8. §19's body rewrites (§19.1's `?`/`unwrap` rewrites, §19.3 in exec code,
   §19.7's templates and `front/lift/combinators.rs`, §19.8's body
   rewriting, §19.9's loop desugaring): retired since bodies are read from
   MIR; `docs/mir-lift.md` §20 replaces them.
9. §19.5's `compile_lifted_pending_gates` development build (deleted).
10. The lock header's TCB text (`surface::TCB`, code, not SEMANTICS.md)
    still says "canonical dialect" in items 2 and 7 (it means the exec
    subset now) and does not list item 8, the lift.

At the same acceptance: fold `docs/mir-lift.md` §20 into SEMANTICS.md §19.
(The hardware parts of `intrinsics.rs` and `elab/semantics.rs` stay: §9.)
