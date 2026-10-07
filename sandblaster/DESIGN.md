# sandblaster — design (v3)

*Formerly rustoleum. v3 (2026-10-05) is the refocus: the toolchain no longer
optimizes, prints or ships code. It proves that the Rust a crate already
contains, including SIMD and other hardware-specific code, meets short laws
a human reviewed. Since 2026-10-06 the prover and the verifier are the whole
product: the optimization pilots were dropped and no new optimized code is
written.*

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

AI agents write most code now. Writing code is cheap; trusting it is not,
and the code that most needs trust already exists: complex, hand-optimized,
often SIMD or otherwise hardware-specific. sandblaster's pitch:

> **Prove the complex Rust you already have, SIMD included, against short
> laws a human reviewed.** Humans review the laws. Agents write the proofs.
> A small kernel checks them, on the code rustc compiles.

**The prover and the verifier are the product.** sandblaster writes no new
optimized code and plans none. The auto-optimizer was removed on 2026-10-05
(Honest evidence, below), and on 2026-10-06 the pilots that would have had
agents write faster versions of Commonware functions and verify them were
dropped (user direction, verbatim: "focus on improving the prover/verifier
(especially covering SIMD code)...remove all new optimizations"). What
grows is what the prover can read and prove of existing code: SIMD
intrinsics read from MIR (C8, §16.4), bit tricks (C4), loops that do not
step in line with their reference (C5), and the time a proof takes to check
(C6).

### The model: three layers

| layer | written by | read by | what it is |
| --- | --- | --- | --- |
| **Laws** | agent drafts, human approves | the human | `LAWS.rs`: the laws, the vocabulary they use with known answers (`#[example]`), the contract of every function host code can call, type invariants. All of it, and nothing else, is in `SPEC.lock`. |
| **Reference** | depends on its kind (below) | the human, when it is on the surface | what defines behavior: the laws' vocabulary, a reference spec in `LAWS.rs`, or the original code kept as ghost code |
| **Implementation** | the crate's authors (code); agent (proofs) | nobody has to | the crate's own Rust, verified as written from rustc's MIR, plus the proofs (`PROOF.rs`) that tie it to the laws |

**The code is the crate's own Rust, verified as written.** Nothing in the
toolchain derives, rewrites, lowers or prints code for rustc. The build reads the item skeleton
from the source and every function body from rustc's MIR. A trusted literal
reading L of the MIR is tied by one kernel theorem per function to the
structured reading S that the laws and proofs are about (§1.1 item 8). What
rustc compiles is what was proven.

**Laws are the only human surface.** A reviewer reads `LAWS.rs` and its
vocabulary, never the code or the proofs. A law states what callers
observe, never how it is computed (§15.1). The lock (§15.6) hashes exactly
the review surface, so a proof refactor, or a change to the code that keeps
the surface, leaves the lock unchanged. **A code change whose lock diff is
empty needs no correctness review**: the build proved the changed code meets
the old laws.

**References and "implementation equals reference" are laws.** Determinacy
(§15.5) forces something in the laws file to define each host-callable
function completely. That something is the reference. For hardware-specific
code the natural reference is usually the crate's own portable version: a
SIMD engine is proven equal to the scalar engine beside it. It comes in four
kinds:

| kind | when to use it | on the surface? | example |
| --- | --- | --- | --- |
| **the laws' vocabulary** (a characterization) | the laws alone determine the function | yes: it is the vocabulary | `to_nearest_size` is the largest valid size at most `size`; varint `write` appends `varint(x)` and `read` is its canonical left inverse |
| **a reference spec in `LAWS.rs`** | callers depend on incidental behavior (which error, how much input is read, side outputs) and no short characterization exists | yes, read in full | the verifier's `rebuild` (about 40 lines), which `reconstruct_digest`'s contract equates it with |
| **a pinned original** (not built, C2) | existing code has no laws, and "behaves exactly like the code that shipped" is the guarantee wanted | yes, as one item, reviewed for provenance, not content | Reed–Solomon `Scalar::mul` defining the existing `Neon::mul` (§18) |
| **a proof copy** (not built, C2) | the laws determine the function, but their proofs follow the original's structure and one equivalence lemma is cheaper | no: a proof internal cannot weaken anything | a scalar loop as the proof route to a SIMD engine's laws |

Prefer the first kind: a characterization frees the implementation
completely. Use the second only for behavior callers rely on that no short
law states, written as a recursive definition for a reader, never in the
shape of the fast algorithm. The third is for legacy code, to be replaced
by laws later; it locks in the original's bugs, which is its honest cost.
The fourth is the agent's cost decision. **The rule: the laws file is the
definition; the implementation is free.** The code still defines behavior
where no law reaches, inside internal functions, which callers can observe
only through host-callable functions, whose behavior the laws file pins.

For a function `f` with precondition `pre_f` (its `requires`, host
obligations), a declared panic condition `panic_f` (its panic contract
`panics_when(p)`, §16.5; `false` when it has none) and a reference `R`,
"implementation equals reference" is:

| | statement | status |
| --- | --- | --- |
| E1, the value | `∀x. pre_f(x) ∧ ¬panic_f(x) → S_f(x) = R(x)`: a kernel lemma over S (for a characterization, the laws themselves) | built |
| E2, the code | `L::thm::f`: on every `x` with `pre_f(x) ∧ ¬panic_f(x)` rustc's MIR terminates without panic and returns `S_f(x)`, final `&mut` values included | built, every build |
| E3, the panics | `L::pthm::f`: on every `x` with `pre_f(x) ∧ panic_f(x)` rustc's MIR panics (a panic, never a loop, an abort or undefined behaviour) | built (C1), every build of a function with a panic contract |
| E4, the rest | `¬pre_f(x)`: nothing is promised; the record lists the precondition as a host obligation | built |

E2 and E3 together: on its domain the function panics exactly when its
laws say. A function without a precondition or a panic contract (all of
varint's boundary, most of the MMR) gets "equal on every input of its type"
from E1 and E2: verified code without a panic contract cannot panic in its
domain, and a defensive `assert!` is proven never to fire. Two limits: the
host code it calls through the buffer traits is modeled without a capacity
(a `BufMut` is the bytes put so far), so a write into a `&mut [u8]` too
short for it panics inside `bytes`, outside the verified code; and an
overflow panic is rustc's overflow check, so it is a panic only in a build
with overflow checks on (§1.1 item 7). A documented
panic is a panic contract, so the laws say when the code panics, and a new
body that drops the `assert!` fails E3.

### What a green build means

For every function read from the verified files: the MIR rustc compiles
terminates without panic on every input that satisfies the function's
declared precondition and not its panic condition, with the value of its
structured reading, and panics on every such input that satisfies its panic
condition; every law holds of these functions; every host-callable function
is determined by the laws file (§15.5); the laws file equals the accepted
lock. All of this rests on the trusted base of §1.1.

It does **not** mean anything about inputs outside the precondition; about
a build without overflow checks, where an overflow wraps instead of
panicking (§1.1 item 7); about the host code the verified functions call
through the buffer traits, modeled without a capacity (a write into a
`&mut [u8]` too short for it panics inside `bytes`); that
the laws say what the author meant (that is the reviewer's reading, helped
by known answers and the on-demand spec-mutation tool, §15.7); or anything
about speed.

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
* **The one big win was agent-written, and never measured fairly.** The
  six-probe `to_nearest_size` (2026-10-01), written by an agent and proven
  equal to the binary search, was reported as about 40× faster, but
  without an A/A control. Measuring it was pilot A, dropped on 2026-10-06
  with every other plan for new optimized code, so the claim stays
  unconfirmed. What it does show is that the proof techniques of §16.1
  (a) and (b) work. Unverified, A/A-controlled prototypes of the dropped
  pilot B were mixed: a word-at-a-time varint encoded 1.04–2.90× faster
  across five distributions but ran at 0.72× and 0.88× on 9–10-byte
  values, and a "fast" `pos_to_height` ran at 0.70–0.73×
  (`recovery/refocus/pilotB`, outside the repository).
* **Hardware first, now on MIR (first slice).** About 23.6k lines of SIMD
  instruction models (x86 to AVX-512, NEON, SHA-2) served the dialect and
  the code the toolchain printed. They are **kept** (user decision,
  2026-10-05): very optimized code uses SIMD and other intrinsics, and
  proofs over it need the instruction semantics, validated natively (§9).
  Since 2026-10-06 safe `core::arch` code is read from MIR onto them (C8's
  first slice, §16.4): a NEON nibble multiply (the shape of Reed–Solomon's
  `mul_128`) verifies in place against scalar reference laws, with the
  lift conformance check running it natively, and an SSSE3 PSHUFB
  counterpart reads onto the x86 models.

  No Commonware SIMD module is verified yet. Its SIMD engines are
  `unsafe` throughout: raw-pointer loads and stores, and `unsafe` blocks
  that rustc forces around value intrinsics in inlined helpers. The user
  decided on 2026-10-06 ("We need to support this.", decision 9): they are
  verified **as written**, through a narrow, proof-checked reading of their
  existing `unsafe` (every pointer access proven in bounds, aliasing
  checked, CPU features established; `docs/DESIGN-UNSAFE-SIMD.md`, C10).
  No engine is split or rewritten, and sandblaster never adds `unsafe`.
  The reading is designed and reviewed; its first stage (a union
  soundness fix and the MIR optimization-level pin it needs) and its
  second, the reading itself (2026-10-07: L's memory model of raw
  pointers, the window rule, the feature binding, the `IterMut` model, the
  structured reading and the walker's support; `docs/mir-lift.md` §20.10),
  are built: a fixture of `mul_neon`'s shape, its `IterMut` loop over
  64-byte chunks with four loads and four stores through
  `as_mut_ptr().add(16 * k)`, gets every theorem, the loop's lemma
  included, and runs clean under Miri's two aliasing models, as does
  Commonware's NEON engine (`mul`, `fft`, `ifft`) through a harness. Its
  per-vector laws are proven; the laws of a whole chunk and of the slice
  wait for a prover step (64-lane goals exceed the automation's read-back
  bound). The engines themselves need C4 first: `mul_128` loads its table
  rows through `u128` bases.

  The C8 survey (`recovery/prover-simd/SIMD-SURVEY.md`, outside the
  repository) found none of Commonware's SIMD functions readable as
  written today, and three of curve25519's AVX-512 helpers readable
  after C8's second slice. Commonware's fastest SIMD (the SHA-256 pair
  and x16 kernels) is inline assembly, which MIR cannot read.
* **Proof size plans were optimistic.** QMDB planned about 1.1k proof lines
  and built 15.4k, for prover gaps (symbolic powers of two, `&`/`|` with no
  arithmetic meaning, arrays expanded byte by byte). Complex existing code
  (bit tricks, SIMD lanes) hits those gaps hardest; closing them is the
  main work (§16).
* **Gates were not at agent speed.** Spec mutation as a build gate made the
  cold storage build take 8 h 11 min; without it the same build takes
  19 min. Mutation is now a tool you run when you want it (§15.7).

sandblaster makes no speed claims. It does not change what rustc compiles;
the speed of verified code is its authors' business.

### Why sandblaster, against its rivals

| | Rust | Verus | Lean | Bend 2 | sandblaster |
| --- | --- | --- | --- | --- | --- |
| Agents already write it well | yes | Rust plus proof code | partly | new language | yes: it is Rust |
| Verifies existing crates in place | — | inside `verus!` blocks | no | no | yes, from rustc's MIR |
| What a human reads | code | code, invariants, triggers, ghost code | proofs | laws | laws only |
| Existing hand-optimized and SIMD code | unchecked | proven, proof code beside it | n/a | own runtime | proven as written from MIR against the laws or a reference (intrinsics from MIR: C8) |
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
4. **No new optimized code.** sandblaster verifies the code a crate has.
   It does not generate, rewrite or propose faster code, and its roadmap
   is prover and verifier capability, not speed. It never adds `unsafe`
   to shipped code; the `unsafe` already there is verified as written,
   through a narrow reading, or not at all (§2, decision 9): code is not
   split or rewritten to make it verifiable.
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
| fiat-crypto / Jasmin | Verified fast code against a simple reference: the same relation, for existing hand-optimized Rust read from MIR. |
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
   CPU with those features, and the binary runs only on a CPU with its
   target's statically enabled features (the narrow reading of existing
   `unsafe` counts them as facts once bound to the build's own, §20.10 of
   `docs/mir-lift.md`); a process free of undefined behavior (host `unsafe`,
   `transmute` and C externs can forge any value, including values of
   invariant types); and **overflow checks on** in the build that compiles
   the verified files. The MIR is extracted with them and L reads
   `RuntimeChecks(overflow)` as true; the build refuses an extraction
   without them, but cannot see the profile that compiles the crate
   (`cfg(overflow_checks)` is unstable, and Cargo does not pass a profile's
   `overflow-checks` to build scripts). A panic contract whose panic is an
   overflow or underflow (13 of the MMR's 18: the position and location
   arithmetic and `children`; all 13 of the verifier's) holds only with
   them. Every profile of this workspace sets them; a downstream crate's
   default release profile does not, and there that code wraps instead of
   panicking. (The value theorems carry over: where they hold no checked
   operation overflows, so a build without the checks computes the same
   values.)
8. **The lift** (`#[lift(mir = "m.sbmir", ..)] mod m;`, SEMANTICS.md §19,
   `docs/mir-lift.md` §20): the exec items the lift produces from a Rust
   file mean what rustc compiles from it. Its parts:
   * **The bodies: the literal reading L of rustc's MIR**, one kernel
     definition per MIR instance, one arm per basic block, a table-driven
     translation of a fixed set of MIR constructs. rustc has already
     expanded macros and lowered `?`, closures, operators, iterators and
     loops. A run's outcome is `Ret(v)`, `Panic` or `Stuck`
     (`mir::Res`, C1): `Panic` only where the MIR certainly panics (a
     failed `Assert`, a block every path of which ends in a call of a panic
     function, a callee's panic, an index leaf past the end), `Stuck` for
     everything else that gives no value (out of fuel, undefined
     behaviour, an unmodeled construct; `docs/mir-lift.md` §20.4). Files:
     the generator `mir/literal.rs` (1,788 code lines; 1,739 before stage
     neon-mul, 1,476 before the narrow reading of existing `unsafe`, 1,436
     before C8, 1,297 before C1) and its library `literal.core` (315; 298;
     203; 186); its reading of
     `core::arch` code `mir/arch.rs` (115; 111, C8: a vector type as its
     model representation, an intrinsic call as its validated target
     model, `docs/mir-lift.md` §20.9); the narrow reading's tables
     `mir/ptr.rs` (422; 414 before stage neon-mul's `u128`: the admitted
     pointer helpers by exact path and signature, the plain byte views, the admitted loads and stores with
     their alignment, the pure-reinterpretation check) and its window rule
     `mir/window.rs` (415: W0–W4 on the unoptimized extraction, the
     verdicts carried to L by source span and kind; §20.10); the theorem
     statements `mir/stmt.rs` (240; 213); the parse `mir/ir.rs` and
     `sexp.rs` (700; 659 before stage neon-mul, 611 before the narrow reading, 529 before the union
     fix and the optimization-level record of 2026-10-06, 482 before C8,
     131); names and load checks `mir/mod.rs` (638; 635 before stage neon-mul,
     572 before the narrow reading's feature binding (A-S3), window verdicts and `IterMut`
     models, 542 before the optimization-level check and the window
     extraction's load, 531 before C8, the check that the MIR is of the
     build's architecture included); the build's codegen flags in
     `target.rs` (29, A-S3); the printer `mirx` (1,254; 1,215 before the
     narrow reading's records, 1,208 before it pinned and recorded the MIR
     optimization level, 1,122 before C8: a rustc driver on the pinned
     nightly of the stable release; its output is checked in with the
     sources' SHA-256, the target it was built for and its optimization
     level). Then the gate's
     trusted check `mir/gate.rs` (176; 159, plus about 30 at its call site
     `driver::gates::theorem_gate`): L enters the kernel only through it,
     and a function is accepted only when its MIR instance is that
     function, the kernel holds `L::thm::f` (and, with a panic contract,
     listed as the function declares it, `L::pthm::f`) with a type α-equal
     to `stmt.rs`'s statement generated
     afresh, reaching only definitions of the elaboration, of L's library or
     of its own extraction, and every module type its MIR reaches is
     declared alike by the MIR and the subset. Then the elaborator's
     precondition check (39: a function read from MIR is elaborated only
     when each precondition, a panic contract's no-panic clause included,
     is α-equal to its declared contract's clause) and the lift glue (about
     350, the panic contract's attachment and no-panic clause and the
     window extraction's declaration included).
     **About 6.69k code lines in all** (6.57k before stage neon-mul,
     2026-10-07, which added 118: in L a `u128` held as its two words, the
     code step `PRange` with `split_at_mut`'s model, `Len`, the referent's
     type after the `Deref` of a `&mut`, `ptr.rs`'s `u128` byte views, the
     parse's fusion of rustc's fake raw borrow with its metadata, and one
     line of the printer; 5.16k before the narrow reading of
     existing `unsafe`, stage "unsafe-reading", 2026-10-07, which added
     about 1,410: `mir/ptr.rs` 414, `mir/window.rs` 415, in `literal.rs`
     the pointer type, formations, moves, casts, loads and stores, the
     refusal of library `unsafe fn` calls, the static facts and the
     `IterMut` model (+263), in `literal.core` the memory model (+95), the
     parse (+48), the load checks (+63), `arch.rs` (+4), `target.rs` (+29),
     the printer (+39) and the lift glue (≈ +40), `docs/mir-lift.md`
     §20.10; and in the ghost language, item 6, the admitted loads' and
     stores' types from their models in ghost code; 5.01k before the first
     stage of the narrow `unsafe` reading, 2026-10-06, which added about 150: the
     refusal of every access to a union's fields in the parse, about 80,
     and the MIR optimization level pinned, recorded and checked with the
     window extraction's declaration, load and check, about 70; 4.69k
     before C8's first slice,
     which added about 325: `mir/arch.rs`, the vector type and the call in
     L, their parse, the target check, the printer's vector types and
     intrinsic leaves, the lift's kept `#[target_feature]`; and 10 in the
     ghost language's elaboration, item 6, for the lane view of vectors;
     4.45k before C1, which added about 237: the outcome split and
     `must_panic` with its tables of panic functions and message
     constructors in L, the `Assert` kinds that panic, the panic statement,
     the gate's second theorem, the glue).
   * **The theorem.** S (`mir/read.rs` 3,989, steered by `mir/cfg.rs` 299)
     is untrusted. Every build checks, per lifted function,
     `L::thm::f : Π x̄ (pre). Σ k. Π n (k ≤ len n). run n b0 (Ret init(x̄))
     = Ret(erase(S_f x̄))` (total correctness, final `&mut` referents
     included), and per panic contract `L::pthm::f : Π x̄ (pre with P for
     Not(P)). Σ k. Π n (k ≤ len n). run n b0 (Ret init(x̄)) = Panic`, proven
     by the untrusted walker (`mir/simproof.rs`, `mir/checked.rs`; a panic
     theorem by its panic mode) and checked by the kernel. Today: varint 63
     of 63 (no function of varint panics on its own; a write into a
     too-short `&mut [u8]` panics inside `bytes`), MMR 69 of 69 with 18 panic
     theorems, verifier 69 of 69 with 13, the Reed–Solomon engine multiply
     (`cryptography/sandblaster/rs_engine`, not yet locked) 5 of 5, none
     of which panics.
   * **The item skeleton**: `front/src/lift.rs` and `lift_open.rs`
     (`macro_rules!` expansion of item macros, inline modules, sealed-trait
     monomorphization, state passing in signatures, struct and enum
     declarations, derived `Default`, the attachments (element attachments
     of a loop's body on one element included), in-place children, open
     traits at one declared instance or read at each of several, operator
     and conversion impls as methods, host models).
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
   run and compared with rustc (the first 64 inputs per function), and on
   inputs sought inside each panic contract's panic region rustc must
   panic and L give `Panic` (a contract compared on no input fails). It
   is a test, not a proof. Fault injection (`tests/fault_injection.rs`) shows
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
* **Never add `unsafe`; verify the `unsafe` already there, narrowly**
  (user decisions: 2026-10-05, proof-justified `unsafe` in shipped
  Commonware code? "then remove it"; refined 2026-10-06 for Commonware's
  SIMD engines, "We need to support this."). sandblaster never adds
  `unsafe` to shipped code, and no code is split or rewritten to avoid
  it. Existing `unsafe` is verified as written through a narrow reading
  (`docs/DESIGN-UNSAFE-SIMD.md`, roadmap C10): raw pointers formed from
  references to slices, arrays and plain integers, pointer offsets,
  vector loads and stores through them, and calls into `#[target_feature]`
  code, each access proven in bounds (L reads an out-of-bounds access as
  stuck, so the theorem excludes it), its aliasing checked by a trusted
  static window rule, its CPU features established. Everything else
  `unsafe` stays refused: raw dereferences, `ptr::read`/`write`,
  `get_unchecked`, `from_raw_parts`, a crate's own `transmute`, union
  field reads,
  `static mut`, FFI, assembly, a general memory model for raw pointers.
  **Until that reading lands, the front end refuses every `unsafe`** as
  before: the DSL root forbids `unsafe_code`; the lift refuses an `unsafe`
  block in a body it reads and any `unsafe` written in a body read from
  MIR, even around an operation L reads; typeck refuses `unsafe fn`,
  resolve `unsafe impl`; and L reads raw pointers, raw borrows'
  dereferences, transmutes other than its few modeled ones and (since
  2026-10-06, wherever they occur, followed library MIR included) every
  access to a union's fields as stuck. Code with `unsafe` outside the
  reading stays unverified host code (its undefined behavior is the
  assumption of §1.1 item 7). The DSL root's `#![forbid(unsafe_code)]`
  stays for the ghost files when the reading lands.
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
preconditions host callers must meet (host obligations), the panic
contracts (proven: where each function panics), and every item left out.
This is the mode the model is built for.

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
`#[ensures(|ret| p)]`, `#[decreases(e)]` / `#[decreases(e, max = C)]`, and
for a lifted function read from MIR the **panic contract**
`panics_when(p);` (laws file only, §16.5): on its domain the function
panics exactly when the proposition `p` holds; its no-panic clause `!(p)`
is its last precondition, so its `ensures` hold where it does not panic.
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
* **Code verified as written** (C8's first slice, 2026-10-06; §16.4,
  `docs/mir-lift.md` §20.9): safe `core::arch` code read from MIR in both
  readings — a vector type as its model representation, an intrinsic call
  as its validated model (L, `mir/arch.rs`), the same call in the subset
  (S) — with the feature rule checked on MIR, pointer loads and stores and
  runtime feature detection refused.
* **Not yet:** `elab/semantics.rs` loads only `<arch>.core`, so the x86
  AVX models (`x86_64_avx.core`) are validated and hashed into the header
  but not loaded for elaboration (the file is hashed into the lock's
  `builtins` line; loading them is a lock change): AVX2 and AVX-512 calls
  read from MIR are refused. Intrinsics the surface table `intrinsics.rs`
  does not list (`_mm_set1_epi8`, `_mm_srli_epi64`) are refused by S; it is
  hashed into the `builtins` line too.

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

**Writing laws for complex code** (guidance; the rules below enforce
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
* **Domain.** Determinacy is over inputs satisfying `requires`, a panic
  contract's no-panic clause included. On the rest of its domain a function
  with a panic contract panics, which the panic contract states and its
  panic theorem proves (E3), so the documented panics are part of what is
  pinned: every host-callable function's behaviour on its domain is fully
  determined, value or panic. Every such `requires` must survive the
  non-vacuity refuter and be met by an example.

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
invariant (`surface::attached_proof_file_errors`); a panic contract only
the laws file states at all (the lift refuses one from a proof file). Attachments name their
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
| a documented panic that a new body drops, or a precondition that hides where the code panics | the panic contract (§16.5): a panic theorem for every documented panic, refused when the code returns, loops or aborts there |
| a loop, an abort or undefined behaviour passed off as a panic | L reads `Panic` only for a failed `Assert`, a call of a panic function on every path, a callee's panic, an index leaf; everything else is `Stuck` (§1.1 item 8) |

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
the on-demand tool, and panic contracts (C1, §16.5) landed and were
applied: the MMR's and the verifier's laws state every documented panic
of their host-callable functions (18 and 13 panic contracts: position and
location arithmetic, `to_nearest_size`, `PeakIterator::new` and
`Family::peaks`, `children`, `chunk_peaks`), each with its panic theorem;
varint's functions do not panic on their own (a write into a `&mut [u8]`
too short for it panics inside `bytes`). Three Commonware roots verify; their
locks were accepted before the panic contracts, whose lock changes wait
for review:

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

* **Panic contracts** (C1): built, §16.5.
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

## 16. Proof techniques for complex and SIMD code

None of these needs a kernel change. Every new step is untrusted search
producing a kernel-checked term, or a checker written in the kernel's
language whose soundness the kernel checks (reflection). The only trusted
growth is in L's reading of new constructs and in host or hardware models,
each local and covered by conformance against rustc (and, for hardware
models, by native validation, §9).

| technique | today | gap | closing it (capability, §18) |
| --- | --- | --- | --- |
| summary-preserving replacement | works: `PROOF.rs` summaries, `opaque()` | none | — |
| characterization (laws determine `f`) | works: uniqueness lemmas, `complete_p` | `complete_p` not reused as a step | a step that instantiates it |
| lockstep, implementation against reference | DSL only (`elab/lockstep.rs`); the walker relates L to S | two MIR-read functions | C3 |
| coupled loops (product programs) | — | missing | C5 |
| loops with invariants | loop attachments, loop lemmas, fuel functions | iterator adapters; fold matching | per-adapter models; fold matching |
| bit tricks | `bvnorm`, K1 bit-count axioms, `stdlib::bits`, proof by computation; shifts by a variable amount (`lemmas/bits_shift.core`, §16.3) | leading zeros as bounds (a case per value), carries, popcount across a split, `u128` | C4, then C11 |
| SIMD lanes | models retained and validated (§9); safe `core::arch` code read from MIR (S and L) onto them and proven lane by lane against scalar references (C8's first slice); ghost lane indexing `v[i]` and lane steps; the lane closer: a vector equation split into lanes, each decided by a case analysis on its table lookups' index tests (`auto::lanes`, §16.4) | AVX models not loaded; runtime dispatch; `u128` table rows (C4) | C8 (second slice) |
| documented panics | built and applied: panic contracts (`panics_when`, the panic theorem; §16.5); panic lemmas restate a condition in the code's terms | a panic reached only after many loop iterations (the panic walk's fuel bound); panics inside lifted callees' loops | a panic loop lemma, when a verified function needs one |
| `unsafe` | never added; every `unsafe` refused today, every union field access stuck (§2, §16.5) | existing SIMD `unsafe` read narrowly: pointers formed from references, offsets, vector loads and stores, `#[target_feature]` calls, each access proven in bounds (`docs/DESIGN-UNSAFE-SIMD.md`) | C10 (first stage built: the union fix, the optimization-level pin, the window extraction) |
| proof reuse and stability | per-module verdicts; theorem and mutant caches | per-function checking; cross-root reuse | C6, C7 |

### 16.1 Relational and equivalence proofs

From cheapest to most expensive.

* **(a) Summary-preserving replacement (works).** Law proofs use a
  function's proof-internal summary (an `ensures` attached in `PROOF.rs`;
  with `opaque()` the only thing callers see). When the code changes, prove
  the same summary for the changed body, and every law proof stays.
  Example (an experiment, never shipped): the six-probe `to_nearest_size`
  of `7e9851b3ba` proved the same `ensures` as today's binary search, with one search invariant per helper and about
  200 proof lines for 37 code lines.
* **(b) Characterization (works).** When the laws determine `f`, any body
  meeting them equals `f`: `to_nearest_size_by_search` proved the six-probe
  version equal to the binary search because both are `mmr_size` of the largest leaf count that fits
  (about 30 lines). No reference is needed.
* **(c) Lockstep (DSL only today).** `elab/lockstep.rs` walks an exec body
  and a `#[model]` spec together: tests split with their path equations,
  contradicting arms close at once, calls meet calls, leftover equations go
  to the prover. Nothing relates two MIR-read functions, so the verifier
  ties `reconstruct_digest` to `rebuild` with a hand-written step lemma
  (`rebuild_step`; its five case lemmas went when the search learned to
  align the code's terms with the law's, 2026-10-06).
  C3 extends it to lifted functions and pinned originals: the core tool for
  existing branch-free code against a branchy reference, or a table
  against the computation it caches.
* **(d) Coupled loops (missing).** Fast existing loops rarely step in
  line with their reference (unrolled by `k`, 16 lanes per step against
  one, a word against a byte at a time, early exit against a full scan);
  a SIMD engine's loop against its scalar engine's is the standard case. C5: a coupling
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
computation covers finite domains. Shifts by a variable amount (C4, built
2026-10-06): `front/lemmas/bits_shift.core` (generated by
`auto::bitlib`, each lemma enumerating the amount once, in the library)
states for `u8`–`u64` that `1 << s` is `2^s`, `x << s` (checked or
wrapping) is `x · 2^s` when that fits, `MAX >> s` is `2^(w − s) − 1` with
`w − s` trailing zeros in its complement, `2^e` has `e` trailing zeros,
`(a + b) · 2^e` distributes, and shifts of ordered values are ordered;
`auto` instantiates them at the shift atoms of a goal (`auto::arith`), next
to `bits_pow2.core`'s `x >> s == x / 2^s`. The storage proofs' 64-case
ladders (`shl_one`, `wshl_one`, `wshl_exact`, `mask_facts`, `tz_pow2`,
`chunk_facts`) are gone; where a large goal needs a shift fact at once
(the MMR's `new_pos`, the verifier's `children` entry facts) the proof
names the library lemma (`bits::shl_one_u64(h)`): `auto` finds the
instance by itself, but in `new_pos` that search took about 20 s more.
Missing, with evidence: leading zeros as bounds
(`2^(w−1−lz) ≤ x < 2^(w−lz)`: the MMR's `lz_bits_chain` and varint's
`lz_bits_*` prove it a case per value, 176 cases); masks for a symbolic `k`
(`x & (2^k − 1) == x % 2^k`) and disjoint `|` as `+`; popcount across a
split; `u128` (L reads it as unmodeled, so widening multiplies get no
theorem). In order: the rest of the bridge library registered as `auto`
rules (C4); `by_enumeration` (C4); `u128` as a
pair of `u64` in L's library and the lift prelude, conformance-tested (C4,
+100–200 trusted lines); later, only if a spike shows it pays,
bit-blasting: an untrusted SAT solver's LRAT certificate checked by a
checker written in the kernel's language with a kernel-checked soundness
proof (C11). That would match Verus's `by (bit_vector)` without new trust.

### 16.4 SIMD lanes

The models are retained and validated (§9). **C8's first slice is built
(2026-10-06; `docs/mir-lift.md` §20.9 is normative): safe `core::arch`
code is read from rustc's MIR onto the retained models, in both
readings.**

* **The extraction** (`mirx`) records the target (MIR of another
  architecture is refused at load), each function's target features
  (rustc's codegen set), `core::arch` vector types (`#[repr(simd)]` structs
  of core's `core_arch`, by public path, with rustc's lanes) and intrinsic
  calls as leaves (public path, const generic immediates by value, the
  intrinsic's features, its safety and pointer use), never followed into
  stdarch's bodies; `std_detect` calls are leaves too.
* **L** (trusted, `mir/arch.rs` with one arm of `literal.rs`): a vector is
  the front end's model representation (`intrinsics::VecTy`; the bits must
  agree with rustc's layout), an intrinsic call is its core model's global
  applied to the immediates (each with its range proofs) and the arguments
  — only for a declared-safe, pointer-free intrinsic whose model has its
  exact path, is validated (the fail-closed evidence verdict) and is the
  library's loaded `def[intrinsic]`, in a body compiled with every feature
  the intrinsic and its model need, with immediates in range and arguments
  of the model's types. Anything else is stuck (no theorem), named.
* **S** (untrusted, `read.rs`): the same call in the subset, which the
  front end elaborates to the same model (an intrinsic without a loaded
  model makes the function deferred, never trusted). The lift keeps the
  function's `#[target_feature]` (the dialect's feature rule is rustc's:
  statically enabled features do not count for a safe call in Rust 1.98
  either) and its `use core::arch::..` items.
* **The walker and the theorem gate** needed nothing new: a model
  application is a neutral head on symbolic arguments, the same term on
  both sides, and the models are defined before L is loaded, so the
  gate's check 3 accepts them.
* **Laws over vectors**: in ghost code a vector is the array of its lanes
  (and back), so a law states a vector function lane by lane against a
  scalar reference (`mul_nibbles(x, lo, hi) == mul_lanes(x, lo, hi)`).
  `bv()` proves such laws when the reference has the model's shape at
  each lane's conditions (NEON TBL). Where it has another (PSHUFB's model
  tests bit 7 in a plain `if`, the elaborated reference's `if` carries its
  path equation; a reference that reads `t[x & 15]` directly where TBL
  tests `x & 15 < 16`), the first slice's proof enumerated one lane's 256
  index bytes in a lemma (about 25 proof lines for one PSHUFB); since
  2026-10-07 the lane closer below proves it with `unfold(f); follows();`.
* **Lanes in proofs** (the prover track, 2026-10-06). Ghost code
  indexes a vector: `v[i]` is lane `i` of its model's `Array(lane, n)`,
  lane 0 first (through the lane view above; exec code still reads a lane
  with the lane intrinsic). A model is a `def[intrinsic]`, folded on
  symbolic data (§5.6), so its lane `k` was reached only by `BvRefl`;
  `auto` now unfolds a model read at a literal lane once (`Delta`, in the
  target and in facts, `auto::lanes`): the models are lane-wise maps, so
  the lane is the scalar operation (`vaddq_u32(a, b)[2]` is `a[2] +w b[2]`)
  for linear arithmetic and the bit lemmas, and a symbolic lane `i < n` is
  split into the literal ones. Nibble splits (`x & 15`, `x >> 4`), lane
  sums exact under lane bounds, carry splits and the x86 byte lanes of a
  32-bit sum are proven this way (`front/tests/hardware.rs`). A table
  lookup's lane (`vqtbl1q_u8`: the dependent `if k < 16 as .h then t[k]
  else 0`) used to read back with an `Erased` placeholder after a step
  inside it: the arm's index proof, carried along the step's equation,
  read the unfolded vector back as an untyped pair. The read-back now gives
  a transport's endpoints its type (`auto::util::kernel_friendly`), so the
  step is taken; a step whose result still reads back with a hidden proof
  is not taken, and one step is tried per model application, not per lane
  read.
* **The lane closer** (C8's second slice, 2026-10-07; `auto::lanes`,
  untrusted). An equation between two vectors of which one is made by
  the models is proven lane by lane, with no search: the models of both
  sides unfolded at once (their bodies, equated with the folded sides by
  `BvRefl`), so each side is the vector of its lanes; arrays the sides
  read that are not variables (a table row `lut.lo[0]`) generalized to
  variables, which the kernel introduces as their lanes (§5.9); each
  lane's reads of vector lanes abstracted, so the sixteen lanes of a
  lane-wise computation are one shape, proven once as a function of its
  inputs, checked by the kernel when built, and applied to each lane's; a
  shape decided by a case analysis on its conditions (a table lookup's
  index test: `x & 15 < 16` decided by linear arithmetic and rewritten,
  PSHUFB's bit 7 of a symbolic byte split), each condition generalized
  where the lane tests it with the dependent match's path equation as the
  motive's equation binder, so the arm's index proof keeps its type; a
  lane with no condition left closes by conversion, `BvRefl`, or
  (bounded) the search on the lane; the lanes joined by one congruence
  step each and `array::ext`. The kernel checks the result like any
  proof. It is off where the search does not use `BvRefl` by itself: the
  law rules' echo prover (LR6 (a) runs without it, so a law that restates
  one model's lanes is not counted an echo, as before) and the
  completeness discharges. Measured: a whole TBL vector law about 0.25M
  steps of search; one product vector of Reed–Solomon's `mul_128` shape
  (sixteen elements, four lookups each) 1.0M and a 0.9M check (one lane
  shape; sixteen lanes one by one cost 3.5M and a 6.9M check, and the
  plain search 12.7M for one lane). The x86 fixture's 256-case PSHUFB
  lemma and its sixteen moves are gone (`unfold(f); follows();` for each
  of its three laws); the unsafe-reading stage's four quarter laws of a
  64-byte chunk now prove with `follows()`. Fixture:
  `mir_fixtures/sd_neon_mul128` (`mul_128` and `muladd_128` as the engine
  writes them, rows `[u8; 16]` where the engine's are `u128`, loaded
  through `ptr::from_ref(..).cast()`), verified in place with native
  conformance; its twins (a shift by 3, two rows swapped) refused by the
  same laws (`front/tests/simd.rs`). Record:
  `docs/DESIGN-UNSAFE-SIMD.md`, stage "table-lookup-lanes".
* **Conformance** runs `#[target_feature]` code natively (the harness
  transmutes lane arrays and calls the original in `unsafe`): the NEON
  fixture compared 1,201 inputs on 4 functions, the literal reading on
  193, with 0 mismatches, on this machine. x86 code is compared on x86
  hosts only.
* **Feature detection**: a statically enabled feature's detection is the
  constant `true` in the MIR (read as such); a runtime detection (a call
  into `std_detect`, cpufeatures' atomic) is refused by both readings. In
  safe Rust a runtime detection cannot guard a call of a
  `#[target_feature]` function (the call needs `unsafe`), so every real
  dispatcher is `unsafe` today; the planned reading (an unknown boolean
  fixed for the run; the function read twice, the two structured readings
  proven equal) waits for a function that needs it.
* **Loads and stores** take raw pointers and need `unsafe`: read in
  crate code by the narrow reading of existing `unsafe` (built 2026-10-07,
  `docs/mir-lift.md` §20.10), refused anywhere else. Decided 2026-10-06 (decision 9,
  "We need to support this."): Commonware's engines are verified as
  written through a narrow reading of their existing `unsafe`
  (`docs/DESIGN-UNSAFE-SIMD.md`, with its amendments; C10), not split and
  not rewritten. A pointer is formed from a reference (its base is the
  referent: a chunk `[u8; 64]`, a table row `u128`), offset within the
  base, and read or written by an admitted unaligned load or store, whose
  validated model applies to the base's bytes; anything out of bounds, a
  store through a shared formation, or a pointer that escapes is stuck in
  L, so a function's theorem proves every access in bounds; a trusted
  static check (the window rule) refuses a pointer whose base anything
  else touches while it is in use; features come from the static target
  set or a declared `requires_features`. The window rule reads an
  unoptimized extraction of the same module (`window_mir = ".."`,
  `docs/mir-lift.md` §20.1), because the MIR the readings read (level 1)
  has already merged and dropped locals and assignments. Built so far
  (stage "prepare"): the refusal of every access to a union's fields
  (a latent soundness bug of the current lift: followed library MIR
  reaches `MaybeUninit` and `LazyLock`'s `Data`), the optimization level
  pinned and recorded by mirx and checked at load, and the window
  extraction's declaration and check. Estimated, with the critique's
  fixes: about 510–775 trusted lines for the reading, plus the mutable
  iterator models it promotes to trusted (`IterMut`, `Zip`), and 14–26
  agent-days for the reading before the first engine.
* Trusted: about 325 code lines of L, the parse, names, printer and lift
  glue, and 10 in the ghost language's elaboration (the lane view), against
  the 150–300 planned.

**What Commonware's code needs** (the C8 survey, measured on rustc's MIR
of the four intrinsic modules: 563 intrinsic call sites of 62
intrinsics). None of its SIMD functions is readable as written today:

* **`unsafe` around value intrinsics.** rustc refuses
  `#[inline(always)]` together with `#[target_feature]`, and a statically
  enabled feature does not make a call safe. So the inlined helpers wrap
  their value intrinsics in `unsafe` (curve25519's NEON backend, the
  Reed–Solomon `mul_128`s). The narrow reading admits these calls; their
  obligation is that the features are available.
* **Raw-pointer loads and stores** (155 call sites; C10).
* **SHA-256 is inline assembly**, as is curve25519's `mul19`. Assembly
  is out of scope for any MIR-level tool.
* **Missing or unloaded models.** 15 of the 62 intrinsics are read today
  (validated and loaded). 17 have validated AVX models that are not
  loaded. 17 have no model.
* **Reader gaps unrelated to SIMD:**
  * `core::array::from_fn`, whose MIR builds a `MaybeUninit` array (14
    roots);
  * closures passed as values;
  * `&mut` slices of arrays and `ShardsRefMut` (every Reed–Solomon
    transform).

**Next** (C8's second slice):

1. Done (2026-10-07): the lane closer above (the PSHUFB lemma's 256 cases
   became `follows()`).
2. `core::array::from_fn` and `<[T; N]>::map` as modeled leaves in both
   readings.
3. Loading the AVX models (`x86_64_avx.core`: a lock change of every
   `builtins` line, four varint item hashes restated) with their surface
   entries.

With these, curve25519's AVX-512 `add_raw`, `sub_raw` and `reduce_regs`
are readable as written (verified on an AVX-512 host).

The rest needs the narrow reading of existing `unsafe` (C10), as written:

* **Reed–Solomon's NEON `mul_128`/`muladd_128`.** Every model they call
  is validated and loaded today.
* **The SSSE3 engine.** It needs `_mm_set1_epi8` and `_mm_srli_epi64`,
  with x86 evidence.
* **curve25519's NEON helpers**, including `mul_regs` and `square_regs`.
  They need 10 NEON lane-map models (`vshl_n_u32` first, 90 call sites).

SWAR code in safe Rust (eight byte lanes in a `u64`), where it exists,
needs no intrinsic reading, only the bit automation (C4).

### 16.5 Panic contracts (C1, built), and `unsafe`: never added, existing read narrowly

**Panic contracts.** `PeakIterator::to_nearest_size` asserts `size <=
MAX_NODES` and a host test checks the panic. With the precondition `size
<= MAX_NODES` alone, a new body without the `assert!` would verify and the
host would silently get a wrong size. A **panic contract** makes the
documented panic part of the laws (C1, 2026-10-05; `docs/mir-lift.md`
§20.4–§20.6 is normative):

```rust
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::to_nearest_size)]
fn to_nearest_size_contract() {
    panics_when((size.0 as Int) > crate::laws::max_nodes());
}
```

* **Semantics.** `panics_when(p)`, `p` a proposition over the parameters
  (the rules of a `requires`), attached in the laws file to a lifted
  function read from MIR (never from a proof file: it is locked; at most
  one per function: join conditions with `||`). On the function's domain,
  where its `requires` hold, it panics **if and only if** `p` holds.
  * With `requires`: preconditions stay host obligations (E4: outside
    them nothing is promised); the panic contract covers the rest of the
    domain, splitting it into the panic region (`p`) and the value region
    (`!p`).
  * With `ensures`: they hold where it does not panic. The no-panic clause
    `!(p)` is the function's last precondition, so `f::ensures`, every
    law's use of `f` and every caller in the module work under it; a
    caller proves it like any precondition, or propagates the panic with a
    panic contract of its own.
  * With determinacy (§15.5): `complete_p` is over the value region; the
    panic region is pinned by the panic contract itself. So a
    host-callable function's behaviour on its domain is fully determined,
    and a reviewer reads exactly when it panics.
  * Locked (§15.6): the function's kernel type carries `Not(P)`, its
    source text `panics_when(p)`; the spec sheet prints `panics_when p`;
    the record lists it ("panics when"), never as a host obligation.
* **The theorems** (§1.1 item 8). E2, `L::thm::f`, holds on the value
  region (its preconditions include `Not(P)`). E3, the panic theorem
  `L::pthm::f : Π x̄ (pre with P for Not(P)). Σ k. Π n ≥ k. run n b0
  (Ret init(x̄)) = Panic`, holds on the panic region. Both are checked by
  the gate (`mir/gate.rs`) against statements generated afresh
  (`stmt::statement`, `stmt::statement_panic`).
* **The literal reading's split** (trusted, construct by construct, each
  with a test and its negative twin in `tests/literal.rs`): a run's outcome
  is `Ret(v)`, `Panic` or `Stuck`. `Panic` comes only from a terminator: a
  failed `Assert` of a kind whose failure panics (overflow, bounds,
  division or remainder by zero; any other kind, whose failure aborts, is
  `Stuck`), a block every path of which ends in a call of a panic
  function (`literal::must_panic`, the table `PANIC_FNS`; on the way only
  a panic message's construction and steps that cannot be undefined
  behaviour), a callee's panic, and core's `Index::index` by a range past
  the end. Out of fuel (a loop that does not end), undefined behaviour
  (`Assume`, an unchecked operation, `unreachable`), an abort
  (`process::abort`, the aborting `panic_nounwind*`) and an unmodeled
  construct are `Stuck`: never a panic. Value theorems are unchanged (the value outcome is the same
  constructor's). The lift conformance check runs each panic region
  against rustc too (in place): it generates inputs inside the panic
  condition on purpose, rustc must panic and L give `Panic` on each, and a
  panic contract compared on no input fails the check (which also catches
  a condition that never holds on the domain, whose panic theorem would be
  vacuous).
* **Overflow checks.** An overflow or underflow panic is rustc's overflow
  check (`Assert` of kind overflow): the 12 position and location
  operators and `children` (13 of the MMR's 18 contracts, all 13 of the
  verifier's) panic only in a build with overflow checks on. The MIR is
  extracted with them and every profile of this workspace sets them; a
  downstream crate's default release profile does not, and there these
  functions wrap instead of panicking. It is an assumption of §1.1 item 7,
  stated on every panic contract of the record; the `assert!`-based
  contracts (`to_nearest_size`, `PeakIterator::new`, `Family::peaks`,
  `chunk_peaks`) hold in any profile.
* **Too wide or too narrow.** A `p` that holds where the code returns,
  loops or aborts has no panic theorem (the panic walk names the path it
  cannot refute); a `p` that misses a panic leaves the structured
  reading's obligation at that panic (`unreachable!()`, an overflow)
  unproven, so the function has no definition and no theorem. Either way
  the build is refused (`tests/panic_contracts.rs`). A `p` that never
  holds on the domain proves vacuously; the conformance check refuses it
  (no input inside it).
* **Proving it** (untrusted): the walker's panic mode drives the literal
  side alone from the entry under the preconditions and `P`, deciding each
  test by the facts or splitting on it, unfolding callees' runs, and
  refuting every outcome but `Panic` (a disjunctive `P` split where a path
  needs it); a loop header costs one of 64 units of fuel and the walk
  follows at most 48 split tests or loop iterations on one path, so a
  panic reached only after many loop iterations is not proven yet (a
  panic loop lemma, when a verified function needs one). The walk's arithmetic is
  linear in the literal reading's terms; where the laws' vocabulary is not
  (`2^h` against `1 << h`, `size > MAX_NODES` against `leading_zeros`), a
  **panic lemma** of the proof file restates the condition in the code's
  terms (`panic_lemma(path);` in the function's attachment: the walk
  applies it to the function's parameters and hypotheses and uses its
  `ensures` as facts; `docs/mir-lift.md` §20.6). The no-panic clause is
  a fact and a goal like any precondition: `auto` reads `!(a || b)` as
  `!a` and `!b` and a negated comparison as the comparison's other value
  (`auto::facts`, `prover_gaps` test 8), and a domain written
  `implies(a <= b, q)` gives `q` under the clause `!(a > b)` (an
  implication whose premise is a comparison of the same operands, proven
  by linear arithmetic: `prover_gaps` test 10).
* **Seeded** from the panic statement removed with the optimizer
  (`4a0e5a23fc`): `stmt::statement_panic` is restored with the panic
  contract as its subject; `Ledger::accept_shipped_panic`'s checks became
  the outcome split (`panic_exact`/`must_diverge` are now
  `literal::must_panic`, decided in L itself, and `same_telescope_option`
  is the panic statement's construction from `S_f`'s own telescope); the
  walker's panic mode is `Walker::panic_walk`.

Total equivalence on every input, including where the original loops or
returns garbage, is not offered: it would oblige every change to the code
to reproduce undocumented misbehavior.

**`unsafe`: never added; existing `unsafe` verified narrowly** (user
decisions 2026-10-05, "then remove it", and 2026-10-06, "We need to
support this."). sandblaster never adds `unsafe` to shipped code, and it
does not split or rewrite code to make it verifiable. The `unsafe` already
in Commonware's SIMD engines is verified as written, through the narrow
reading of `docs/DESIGN-UNSAFE-SIMD.md` (C10; §2 lists what it admits):
each pointer access is read by L with a bounds test, so the function's
theorem, which excludes `Stuck`, proves every access in bounds on its
domain; the window rule and the feature rule are its trusted checks.
There is still no general memory model for raw pointers and no capability
for unsafe standard-library APIs (`get_unchecked`, `from_raw_parts`, ...);
every `unsafe` outside the narrow reading stays refused, and code that
uses it stays unverified host code outside the verified files. A new kind
of `unsafe` needs its own user decision. Until the reading lands, the
front end refuses every `unsafe` (§2).

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

**The loop.** (0) Pick existing code to verify: a module's host-callable
functions, hardware-specific code first wherever the prover can read it.
(1) Draft the laws with known answers and let §15 say what is missing
(determinacy, the counterexample engine, `sandblaster mutate`). (2) Choose
the reference: usually the laws' vocabulary; for a SIMD engine, the crate's
scalar engine (a pinned original, C2, until laws state it). (3) Extract the
MIR of every root that records the file. (4) Differential check, code
against reference, natively on the conformance inputs (seconds; to build,
C2). (5) Prove: safety (mostly automatic), the MIR theorem (automatic; a
failure is a toolchain bug, not the agent's), the laws, the panic
contracts. (6) Full build; a human reviews the lock diff. (7) Report proof
lines, check times, agent time and every toolchain gap met, each fixed
generically in the prover, never by reshaping the code (principle 1).

**Feedback** the agent gets, as text and JSON: a counterexample (input and
both outputs); an unproven obligation (goal, facts, what was tried); a
failed lockstep (where the sides diverge, the equation left); a failed MIR
theorem (the path of splits, both sides); a failed panic contract.

**Measured per verified module.** Human review (lock-diff items, reviewer
minutes, reviewed lines per verified line); agent effort (wall clock,
tokens, failed attempts, toolchain fixes counted apart); proof lines per
code line; kernel and build times; churn under three to five realistic
follow-up edits of the host code; each toolchain gap with its trusted-base
delta. Speed is not measured: verification does not change what rustc
compiles.

| measure | today | target |
| --- | --- | --- |
| MIR extraction after an edit | 8 s (81 s cold) | same |
| differential check | not built | ≤ 30 s |
| proof feedback after a one-function edit | whole root: about 231 s (MMR), about 10 s (verifier), several minutes (varint) | ≤ 60 s |
| cold verified build of storage | 19 min (8 h 11 min with mutation as a gate) | ≤ 15 min |
| kernel time of one MIR theorem | 0.001–0.66 s | ≤ 1 s |
| proof lines per code line | about 5:1 (the six-probe experiment), about 40:1 (Newton) | ≤ 5:1 without loops, ≤ 10:1 with; above 20:1 is a toolchain gap |
| lock diff of a code change that keeps the laws | — | 0 items |
| law-proof lines changed by a code-only change | 0 (the MIR move) | 0 |

**Against Verus.** Same existing component (the MMR's `to_nearest_size`
and `is_valid_size` as written; once C8 exists, a SIMD function such as a
Reed–Solomon NEON `mul`), against the same laws, same agent model, same
time box. Measure specification lines, proof annotation lines,
verification time, time to green, tokens and added trust; record whether
Verus needed host-code changes, whether its specification determines the
function, and churn. If Verus wins clearly on time to green and proof size
even after C4, that is a strategic finding for the user.

---------------------------------------------------------------------------

## 18. Roadmap

**Done (2026-10-05):** the removal (§19); spec mutation off the build path;
the three roots re-verified with header-only lock re-accepts; the hardware
semantics restored (§9; another header-only re-accept); **C1, panic contracts** (§16.5: the
Panic/Stuck split of L, `panics_when`, the panic theorem and its gate
check, the walker's panic mode; +about 230 trusted lines, more than the
+60–120 planned: the tables of panic functions and message constructors
and `must_panic`'s checks are most of it); **C1 applied** to the three
roots (the MMR's 18 and the verifier's 13 documented panics stated and
proven; varint's functions do not panic on their own; no trusted line: the walk splits
disjunctions and takes panic lemmas, `auto` reads negated disjunctions;
the two storage locks' changes wait for review).

**2026-10-06:** the optimization pilots were dropped (A: a faster MMR
search; B: a word-at-a-time varint; C: a SIMD engine planned as a port),
with their measurement harness `bench/shipped-harness`. The roadmap is
prover and verifier capability on existing code, SIMD first. The same day
**C8's first slice** landed (§16.4, `docs/mir-lift.md` §20.9): safe
`core::arch` code read from MIR in both readings onto the validated
models; a NEON nibble multiply verified in place against scalar
references with native conformance, an SSSE3 counterpart on the x86
models, the twins refused (+about 335 trusted lines, item 8 and item 6).
Also that day, **decision (9) was taken**: Commonware's `unsafe` SIMD
engines are verified as written, through a narrow, proof-checked reading
of their existing `unsafe` (C10, `docs/DESIGN-UNSAFE-SIMD.md` with its
adversarial critique `docs/UNSAFE-SIMD-CRITIQUE.md`); no split, no
rewrite, no `unsafe` added. Its first stage ("prepare") is built: every
access to a union's fields is refused in both readings (a latent
soundness bug: followed library MIR reaches `MaybeUninit` and
`LazyLock`'s `Data`; no shipped function accessed one, and the three
roots' theorems and locks are unchanged), and mirx pins and records the
MIR optimization level, the build refuses another than 1, and an
unoptimized window extraction (`window_mir = ".."`) is declared and
checked for the window rule (level 0 for every reading was measured and
refused: the structured reading lost six MMR functions and the
verifier's `Subtree` code). +about 150 trusted lines (item 8).

**Capabilities, in order** (agent-days are focused agent work with tests):

| # | capability | forcing example | trusted base | agent-days |
| --- | --- | --- | --- | ---: |
| C1 | **done** (2026-10-05): panic contracts (Panic/Stuck split, `panics_when`), seeded from the gate's panic statement at `4a0e5a23fc` (§16.5) | the MMR's and the verifier's documented panics | +about 230 | — |
| C2 | pinned originals and proof copies (`#[lift(reference)]` via `mirx --inject`, provenance check, native differential check) | Reed–Solomon `Scalar::mul` as the SIMD engines' reference | one item kind | 3–5 |
| C3 | lockstep for lifted functions | the verifier (`reconstruct_digest` against `rebuild`); a SIMD engine against its scalar engine | none | 5–8 |
| C4 | bit bridge library, `by_enumeration`, `u128` as pairs | `position_to_location`, the verifier's shifts, Reed–Solomon's `u128` | `u128`: +100–200 | 9–16 |
| C5 | coupled loops | a SIMD engine's loop against its scalar loop | none | 8–15 |
| C6 | per-function checking, summary lint, library spec mutation once per version | every root's check time | small | 11–21 |
| C7 | contract schemas (one reviewed line generates a newtype's routine contracts), views on lifted types, host-callable by name, cross-root reuse | review cost; a representation change of `PeakIterator` | +150–350 | 13–23 |
| C8 | **first slice done** (2026-10-06): `core::arch` value intrinsic calls read from MIR (S and L) onto the retained models, the feature rule on MIR, laws over vector lanes. **Second slice, first item done** (2026-10-07): the lane closer (untrusted). Next: `core::array::from_fn`/`map` leaves, the AVX models loaded with their surface entries; the missing NEON and SSE models (§16.4; loads, stores and the `unsafe` around them are C10) | Reed–Solomon's NEON and x86 engines, curve25519's backends | +about 335 so far (models already item 4) | second slice 7–13 |
| C10 | **decided 2026-10-06** (decision 9): the narrow reading of existing `unsafe` SIMD (`docs/DESIGN-UNSAFE-SIMD.md` and its amendments): raw pointers formed from references, offsets, vector loads and stores, `#[target_feature]` calls; bounds in L, the window rule on an unoptimized extraction, static features and `requires_features`; the two-model Miri cross-check over the real engine functions and an independent review land with the reading. **First stage done** (2026-10-06): the union fix, the optimization-level pin and check, the window extraction. **Second stage done** (2026-10-07, `docs/mir-lift.md` §20.10): the reading (L's memory model, the window rule W0–W4 with the `&mut` parameters it reaches, the feature binding A-S3, pure reinterpretation A-S9, `IterMut` A-S4; S and the walker's read-back rewrite and sharing abstraction), the Miri gate over the fixtures and, through a harness, the real NEON engine; `Zip`, `requires_features`, `u128` bases (C4, `mul_128`'s table rows) and the independent review not yet. Not a general memory model (the old C10, a +1.0–1.5k raw-pointer memory model, left the roadmap with decision 1) | Reed–Solomon's four engines as written: `<Neon as Engine>::mul` first | about 510–775 plus the mutable iterator models (+about 150 so far) | the reading 14–26; NEON `mul` 8–13 after it; all four engines 48–87 |
| C11 | (research) bit-blasting with a checked certificate checker | after C4, if bit proofs still dominate | none | 5 spike, then 20–40 |

**Order.** SIMD first: C8's first slice (done: value-only NEON and SSSE3
intrinsics in `#[target_feature]` functions, read from MIR in both
readings, proven on fixtures), then its second slice (the lane-split
closer first: done 2026-10-07) and C10 (the narrow reading of the engines' existing
`unsafe`: fixtures and twins first, then mirx and the parse, L's pointer
values, the window rule, features, S and the walker), then C4 (`u128`)
and C2, C3 and C5 as the first target needs them. C6 runs alongside:
check time limits every target.

**First target: Commonware's SIMD as written.** Reed–Solomon's
`Neon::mul` against `Scalar::mul`. The crate already treats the scalar
engine as the reference; the x86 engines can be checked the same way on
x86 hosts. It needs:

* C8;
* C10, the narrow reading of the engine's existing `unsafe`;
* `u128` (C4), as a value with its byte view;
* the mutable iterator models (`IterMut`, then `Zip` for the transforms),
  trusted under C10 with a stated disjointness property;
* C2, or laws for `Scalar::mul`;
* a proof that the NEON tables are the nibble split of the scalar ones
  (first a hypothesis of the law, later the verified table initializers).

The engine is `unsafe` throughout, and it is verified **as written**
(decision 9): `engine_neon.rs` has 13 `unsafe` (`unsafe fn mul_neon`,
raw-pointer loads and stores, and `unsafe` blocks around value
intrinsics, which rustc forces on `#[inline(always)]` helpers, §16.4),
all within the narrow reading: measured on the engines' MIR, they use no
unsafe operation besides pointer formations from references, offsets,
casts, the admitted loads and stores, and `#[target_feature]` calls.
Nothing is split or rewritten.

* `mul_128`'s arithmetic needs no new model: every intrinsic it calls is
  validated and loaded; its 8 table loads read 16 bytes of a `u128` each.
* `mul_neon`'s 4 loads and 4 stores per chunk stay within the chunk's 64
  bytes, through one pointer formed from the chunk's `&mut`.
* The transforms also need subslice codes and the engine's
  `ShardsRefMut`.

The reading takes 14–26 agent-days, then `<Neon as Engine>::mul` 8–13
(at the edge of the stop rule below, reported if it goes over), `fft`
and `ifft` 10–18 more. Measured by the C8 survey, the only Commonware
SIMD functions readable without the reading are three of curve25519's
AVX-512 helpers (`add_raw`, `sub_raw`, `reduce_regs`), after C8's second
slice, on an AVX-512 host.

**Second target: existing bit-level code.** `position_to_location`'s
Newton steps (about 820 proof lines for about 20 code lines, §16.1 f) and
the verifier's 64-case `1 << b` lemmas (§16.3). C4 should shrink both;
measured as proof lines and check time before and after, with no change to
the code.

**Decisions for the user:** (1) proof-justified `unsafe` in shipped
Commonware code: **taken** (2026-10-05: "then remove it"; a general
unsafe/raw-pointer capability left the roadmap, §16.5), **refined**
2026-10-06 by (9): sandblaster never adds `unsafe`; the `unsafe` already
in Commonware's SIMD engines is verified through the narrow reading
(C10), and every other `unsafe` stays refused; (2) restoring SIMD models: **taken** (2026-10-05,
kept and first-class, §9); (3) whether
"behaves exactly like the code at revision R" is an acceptable law for
existing code (pinned originals); (4) the `Buf::chunk` buffer model; (5)
when to move varint in place (a lock change: `Decoder::new`/`feed` become
host-callable and need contracts); (6) whether a kernel change is ever on
the table (this design assumes not); (7) **taken** (2026-10-05): the
hardware parts of `intrinsics.rs` and `elab/semantics.rs` stay (§9); (8)
**taken** (2026-10-06): no new optimized code, the pilots are dropped
(North star); (9) **taken** (2026-10-06, verbatim: "We need to support
this."): Commonware's existing `unsafe` SIMD (the Reed–Solomon NEON,
SSSE3, AVX2 and AVX-512 engines' raw-pointer loads and stores) is verified
as written, through a narrow, proof-checked reading that proves every
access in bounds (C10, `docs/DESIGN-UNSAFE-SIMD.md`); no engine is split
or rewritten, and sandblaster never adds `unsafe`.

**Stop rules.** If after C3–C5 a verified function still needs more than 20
proof lines per code line, or the first target more than two agent-weeks
once C8 exists, report to the user before adding capabilities: the gap is
in the prover, and that is a strategic finding. Keep a running count of
trusted lines per stage. If contract schemas and views do not shrink
in-place laws files, the review surface grows with every verified file:
measure reviewed lines per verified line on every module.

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
| benchmarks, held-out sets, fairness gates, `rulegen`, the optimizer corpus | `bench/`, `rulegen/`, `front/tests/fairness_*` (`bench/shipped-harness` and `samecode.py` came back for the pilots on 2026-10-05 and left with them on 2026-10-06, last at `081c5da718`) | they judged the optimizer, then the pilots |
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

At the same acceptance: fold `docs/mir-lift.md` §20 into SEMANTICS.md §19
(§20.9's `core::arch` reading included), and add to SEMANTICS.md §13 the
ghost language's lane view of vectors (a vector coerces to the array of
its lanes and back; `==` on vectors in ghost code), built on 2026-10-06.
(The hardware parts of `intrinsics.rs` and `elab/semantics.rs` stay: §9.)
