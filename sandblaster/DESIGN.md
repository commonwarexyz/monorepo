# sandblaster — design (v2)

*The project was formerly called rustoleum; it moved into the Commonware
monorepo as `sandblaster/`.*

> Bend 2's laws and proof discipline, Verus-style inline proofs, K-style
> semantics-first tooling, first-class hardware acceleration, and Rust's
> speed. Every piece of code that lives is proven, or the crate does not
> compile. Every optimization is proven, and the optimizer always runs.

This document is the contract for everyone implementing sandblaster. Where it is
precise, follow it exactly. Where it says "implementation choice", pick the
simplest thing that satisfies the stated invariants and document it in the
module docs. v1 (`docs/DESIGN-v1.md`), the six adversarial reviews of v1
(`docs/review-1.md`) and the per-phase reports stayed in the project's
previous repository and are not part of the monorepo.

---------------------------------------------------------------------------

## North star: the agentic era

AI agents write most code now. The scarce resource is no longer writing code
but trusting it. sandblaster exists to win that world, against Rust, Verus, Lean
and Bend, with one pitch:

> **Make your Rust safer and faster. State short laws instead of writing
> Verus-style proof code; agents write the proofs and a small kernel checks
> them; proven compositional symbolic execution then makes the code faster
> than rustc alone.**

It augments existing Rust: the critical, pure parts of a crate become verified
modules with the same API, and the rest of the crate stays as it is.

**Who does what.**

* **The human** states and approves *what* the code must do in one place: the
  **laws**, plus the few vocabulary definitions they need (for QMDB: what a
  database is, its root, what "current" means). On a change, the human reviews
  the lock diff (§15.6): which laws changed, which behavior snapshots changed,
  and which behaviors no law forces. Code and proofs are readable, but nobody
  is required to read them.
* **The code is the definition.** Existing code as written (or, for new code,
  the obvious version) defines every behavior the laws leave open (free design
  choices). There is no separate spec
  of the implementation and no refinement proof, except where the fast
  algorithm is genuinely different and no optimizer could derive it (limb
  arithmetic, FFT, Montgomery form): only there does a simple reference sit next
  to the laws, with the fast code proven equal to it. No external test vectors
  are assumed: this is for new code (vectors are a bonus when matching an
  existing system).
* **Nothing is silently unconstrained.** The mutation engine (§15.9) runs on the
  code and reports every behavior no law forces; the human either adds a law or
  accepts it as a free choice. **Behavior snapshots** — the code's outputs on a
  deterministic, coverage-driven input set — are locked, so a behavior change no
  law covers still shows up concretely in the diff.
* **The agent** writes the code and all proofs. Proofs are machine artifacts:
  judged by what they cost to produce and maintain, not by how they read.
* **The toolchain** checks everything on every edit, fast, and gives the agent
  precise, structured feedback (goals, counterexamples) until the build is
  green. It also makes the code fast, with proofs, so the agent never
  hand-optimizes.

**Why each rival falls short, and where sandblaster wins.**

| | Rust | Verus | Lean | Bend 2 | sandblaster |
| --- | --- | --- | --- | --- | --- |
| Agents already write it well | yes (largest corpus) | Rust plus proof code | partly | new language | yes: it is Rust |
| Augments existing Rust crates | — | yes, in place | no | no | yes: verified modules inside the crate |
| What a human writes and reads | code only | code plus invariants, triggers, ghost code, lemma calls | proofs | laws | laws only |
| Catches an agent's logic bugs | no (memory safety only) | yes | yes | yes | yes: every live function proven |
| Makes the code faster | — | no (compiled as written) | no | own runtime | yes: proven compositional symbolic execution, fueled by laws, plus proven SIMD |
| Protects against weak or gamed laws | — | no | no | no (laws may restate code or say little) | yes: §15 determinacy, mutation, unconstrained-behavior report, lock diffs |
| Trusted base | rustc | Z3 plus Verus | small kernel | a TypeScript checker | small kernel; solvers and AI search, never trusted |

The moat is the combination: agents write the *obvious* code in the language
they know best; the kernel proves it meets laws that §15 forces to pin the
behaviour down; the proven optimizer (compositional symbolic execution) and
hardware kernels make it faster than rustc alone; the human reviews a law diff.
Against Verus specifically: humans read laws, not proof code; no trusted SMT;
and verification makes the code faster instead of merely costing nothing.

**Principles that follow.**

1. **Proofs are agent artifacts.** Readability of proofs is nice to have, not
   a goal. Size matters only as cost: agent time and tokens, check time, and
   how much proof breaks when code changes.
2. **Verify the code as written; the toolchain adapts to real Rust.** Existing
   code is lifted as-is — never rewritten or simplified to suit the prover;
   where the subset cannot express something yet (trait generics, `&mut self`,
   buffer traits), the toolchain grows to cover it. For new code, agents
   should write the obvious version and let the optimizer own speed: a
   performance gap is an optimizer gap. (Lesson from QMDB: pairing
   hand-optimized code with a separate spec needed a 10–15k-line refinement
   proof; laws proven directly about the code avoid the second program.)
3. **Proven laws and lemmas are the optimizer's fuel.** rustc and LLVM know
   only the language; our optimizer also knows kernel-checked theorems about
   the program, so every law and lemma is a sound fact or rewrite it may use:
   invariant and bound facts drop checks (O6 facts), associativity and
   commutativity turn folds into lane or thread reductions (O11/O13/O14),
   round trip and canonicity delete or shortcut encode/decode, determinacy and
   idempotence allow memoizing equal calls. Human laws often double as fuel;
   agents add **optimization lemmas** — proven, so they need no human review:
   they can make code faster, never wrong. Write the obvious code, prove a
   lemma, get better-than-compiler speed.
4. **The agent loop is the product.** Per-function incremental checking in
   seconds, cached; goals and failures as structured data an agent can act on
   (LSP/MCP), with concrete counterexamples (§15.9); automation that saves
   agent effort (including solvers whose proofs are reconstructed and
   kernel-checked).
5. **Gates run at agent speed.** Every §15 check stays mandatory, but results
   are content-addressed and incremental: spec mutation reruns only for what
   changed; a green edit re-checks in seconds, not minutes.
6. **The human surface is small and exact.** The laws are short, condensed
   statements of correctness (never restatements of code); the lock diff says
   exactly which guarantees, snapshots and unconstrained behaviors changed.

**How we measure it.** The metrics that decide priorities:

* human surface: lines of laws and vocabulary, the unconstrained-behavior
  report, and the size of a typical lock diff;
* agent time-to-green and tokens for a task;
* incremental check time after an edit, and full-build time;
* proof churn: proof lines that must change for a realistic code change;
* runtime speed against hand-written Rust and Commonware (the QMDB regression
  gate, §8.2).

**How we prove the claim.** An agentic benchmark: the same tasks given to
agents in Rust, Lean, Bend and sandblaster, measuring bugs caught, time to
green, speed of the result and the human review load.

---------------------------------------------------------------------------

## 0. Summary

1. The surface language **is Rust syntax** (parsed with `syn`), restricted to a
   subset with a clean mathematical meaning: pure, total, first-order, no
   traits, no heap, no interior mutability, unsigned machine integers whose
   partial operations (overflow, division by zero, out-of-bounds, shift width)
   must be proven unreachable.
2. The subset is **elaborated into a small dependently typed core calculus**
   (MLTT with two sorts, inductive types, equality, irrelevance, machine
   integers). Elaboration *is* the formal semantics of the subset (the K idea:
   define the language once, derive the tools from it).
3. A **small trusted kernel** type-checks the core. A well-typed definition
   terminates, never reaches a partial operation outside its domain (each
   carries a proof), and satisfies every contract and law (each is a checked
   proof term). Untrusted automation constructs the proofs (Lean/Bend
   architecture).
4. The **optimizer always runs** (untrusted): symbolic execution in the
   kernel's evaluator produces residual straight-line code (unrolled, constant
   folded), proven bounds checks are dropped, whole call trees are
   multiversioned per hardware target. Every optimized definition is
   kernel-checked equal to the original; the emitted Rust is a canonical
   dialect that is re-elaborated and compared with the verified core before
   `rustc` sees it.
5. **Hardware is first-class** (§9): lane types, target intrinsics with formal
   models (NEON/SHA2 on aarch64, SSE/SHA-NI/AVX2/AVX-512 on x86_64), proven
   hardware kernels, target dispatch, and representation refinement for
   numbers laid out for SIMD.
6. `cargo build` runs everything from `build.rs`. If anything is unproven, the
   build fails. There is no flag to skip proofs and no flag to skip
   optimization.

| System | Relation |
| --- | --- |
| Verus | Inline proofs in Rust, SMT (Z3) trusted, exec code compiled as written. sandblaster: own proof-term kernel, no SMT in the TCB, Bend-style laws, mandatory proof of all live code, mandatory proven optimization, proven hardware kernels. |
| Creusot / Prusti | Contracts on Rust, external provers. Same differences. |
| Aeneas / hax | Safe Rust → Lean/F*/Coq. sandblaster keeps the prover in-process (`cargo build` is the gate) and uses the model to optimize. |
| fiat-crypto / Jasmin | Verified fast crypto code. §9.6 representation refinement and §9.3 proven kernels follow that line inside a general language. |
| Halide / ISPC | Algorithm vs schedule; SPMD lanes. §9.1/§9.4. |
| Kani | Bounded model checking; no unbounded laws. |
| Bend 2 | Model for laws/proofs (`LAWS.rs` claims, `PROOF.rs` proofs, proof by computation, rewriting, induction by recursion). |
| K framework | Model for semantics first: elaborator = semantics, kernel evaluator = reference interpreter, symbolic execution drives optimization, differential tests against native code. |
| Lean | Proof-term kernel + untrusted tactics. sandblaster follows that architecture but ships Rust. |

---------------------------------------------------------------------------

## 1. Architecture

```
 sandblaster source (Rust syntax)
        │ syn
        ▼
 front end: load → resolve → surface typecheck → subset validation → HIR
        │
        ▼
 elaborator: HIR → core (+ obligations proven by auto / scripts) ──► kernel (TRUSTED)
        │                                                             ▲
        ▼                                                             │
 optimizer: specialization, multiversioning, bounds-check elim. ──────┘ (candidates checked)
        │
        ▼
 codegen: canonical Rust dialect → re-elaborate (generated mode) → α-compare with optimized core
        │
        ▼
 OUT_DIR/sandblaster.rs ──include!──► rustc / LLVM
```

### 1.1 Trusted computing base

1. `sandblaster-kernel`: checker, evaluator, conversion, termination,
   linear-arithmetic certificate checker, the word normalizer `bvnorm`
   (§9.8), the fixed axiom list, bignum `Int`, and the §15 section
   abstraction and closed evaluator. About 9.8k code lines today (bvnorm ≈
   2k, §15 ≈ 0.6k); budget 10k. Heavily tested, no `unsafe`.
2. The **elaboration semantics of the canonical dialect** (§8.3): the claim
   that the core produced for a function in the canonical dialect denotes
   what `rustc` compiles. The canonical dialect leaves `rustc` no freedom
   (absolute paths, fresh local names, suffixed literals, UFCS method calls,
   explicit references, expanded or-patterns, desugared guards), so the
   trusted meaning covers a small language. Mitigations: `SEMANTICS.md`,
   per-construct differential corpus, debug-profile oracle (§10.3).
3. The **prelude definitions** (core text, `sandblaster/kernel/prelude/*.core`):
   the meaning of `List`, `Slice`, `Array`, `Option`, tuples and every
   whitelisted method. (Prelude *lemmas* are checked, not trusted.)
4. The **target semantics library** (§9.2) — intrinsic models, load/store
   helpers — and the generated **dispatch glue** (§9.3).
5. `rustc`/LLVM.
6. The **elaboration of the ghost language** (SEMANTICS.md §13): the claim
   that the kernel statement of a spec item, law, contract or invariant means
   what its source text says; and the kernel's section abstraction
   `Env::abstract_section` (§15.5), which defines what "fully specified"
   states. Mitigations: the de-elaborated form on the spec sheet and the
   ghost-language differential (§15.7).
7. **Assumptions**: `num-bigint`/`num-integer`; the `rustc` that compiled the
   kernel; `syn` agreeing with `rustc` on the canonical dialect; the §3.7
   stack assumption; runtime feature detection; a process free of undefined
   behaviour (host `unsafe`, `transmute` and C externs can forge any value,
   including values of invariant and evidence types). The report, the spec
   sheet and `SPEC.lock` carry this list.
8. **The lift** (lifted modules, `#[lift] mod m;`, §2.1, SEMANTICS.md §19):
   the claim that the exec items the lift produces from an existing Rust
   file mean what `rustc` compiles from that file. The proofs are about
   the lift's reading; the emitted code is the file as-is, so a misreading
   would make a proven law false of the shipped code. Three parts:
   * **the reading** — `sandblaster/front/src/lift.rs`: `macro_rules!`
     expansion, flattening of inline modules, sealed-trait
     monomorphization, state passing for `&mut self` and buffers, the
     rewrite table (`?`, `map_err`, `unwrap`, `checked_*().unwrap()`,
     `&a[..=j]`, loops as helpers, `T::SIZE`, `const` asserts), signed
     integers as their two's complement bits, the dropped items — and its
     prelude (`lift/prelude.rs`: `Result`, `TryGetError`, `iN_shr`,
     `iN_neg`, the prelude iterators; `elab/lift.core`: `div_ceil`);
     **and its extension for in-place crates** — `src/lift_open.rs`
     (SEMANTICS.md §19.5–§19.9: in-place sources and children, open traits
     erased at their declared instance, operator/comparison/conversion,
     `Deref`, `Default` and `Iterator` impls as methods, auto-deref,
     `impl Iterator` returns, `for`/`while` loops with control flow as
     helpers, assertion macros as obligations, inlined closures) and the
     core-method templates `lift/combinators.rs` (core's `Option`, `Result`
     and integer methods transcribed; each is compared with core natively by
     `tests/lift_open.rs`);
   * **the buffer model** — `lift/model.rs`: a `BufMut` is the bytes put so
     far, a `Buf` the bytes not yet read; the host assumption is that the
     caller's buffer behaves so (true of `Vec<u8>`, `BytesMut`, `Bytes`,
     `&[u8]` and chains of them; a `BufMut` out of capacity panics in host
     code);
   * **the host models** — each `#[lift(host)]` module (for varint,
     `crate::Error`) as the proofs see the host items the source names,
     and the host traits the lift knows (`Buf`, `BufMut`, `Read`, `Write`,
     `EncodeSize`, `FixedSize`: commonware-codec's signatures). The
     emitted module's tail makes rustc check every modeled variant and
     every `SIZE` the lift read against the real host (§2.1).

   **and the lowered declaration** (§2.1 "Compiling the optimized
   output"): the reading of `mod m { //! docs include!(concat!(env!(
   "OUT_DIR"), "/<name>-lowered__<path>")); }` (and its IDE twin
   `#[cfg(rust_analyzer)] mod m;`) as `mod m;` — `lift_open.rs`
   `lowered_include`/`ide_twin` and its use in `loader.rs::add_lifted`
   (≈ 75 code lines) — plus the in-place emission argument: the copy rustc
   compiles is the lowering's text (`driver::lowered`, the same argument as
   an emitted lifted module) behind a header of comments
   (`driver::in_place::lowered_copies`), and the build's declaration check
   makes the include name that copy (textual, like module mode's scan).

   About 6.5k code lines today (`lift.rs` 4.0k, of which the macro
   expander ≈ 0.3k; `lift_open.rs` 2.1k; templates 125, prelude 134,
   model 54, `lift.core` 24; the lowered declaration ≈ 75): **over the 4k
   budget** since the in-place extension (the MMR track) — named here as
   new trust; shrinking it (or moving readings into checked templates) is
   open work.
   **The MIR path** (`#[lift(mir = "m.sbmir")]`, `docs/mir-lift.md` §20,
   `sandblaster/front/src/mir`) replaces the reading of *bodies*: rustc's
   own monomorphized MIR (macros expanded, `?`, closures, operators,
   iterators and constants already lowered by the compiler) is read by a
   translation over a fixed set of MIR constructs that does not grow with
   surface features — `mir/read.rs` and the names in `mir/mod.rs` (≈ 2.8k
   code lines) plus the printer `sandblaster/mirx` (≈ 1.1k: a rustc driver
   on the pinned nightly of the stable release, whose output is checked in
   with the sources' SHA-256). For such a module the source lift keeps only
   the item skeleton (names, signatures and state passing, sealed
   families, attachments) and the ghost language; its body rewrites are not
   used. commonware-codec's varint is verified this way with its laws and
   proofs unchanged, and commonware-storage's MMR in place (with its
   `#[rewrite]` alternatives and the lifted round trip of its lowered copy,
   whose bodies are rustc's MIR of the copy) with its laws unchanged, and
   the first set of its Merkle proof verifier (`hasher.rs` at
   `Standard<Sha256>`, `Subtree::reconstruct_digest`) with its laws and
   proofs unchanged. Every exec module of the repository now reads its
   bodies from MIR; the plan to retire the source lift's body reading, with
   the list of its readings no module uses any more, is in
   `docs/mir-lift.md` §6.
   **Mitigation: the lift conformance check** (`sandblaster/front/src/conform.rs`;
   its module docs are the full description), which every module-mode build of a lifted module
   (and every `compile_lifted` build of an in-place one, §2.1)
   runs after the gates and before it emits: every lifted exec function is
   evaluated by the kernel and the original is compiled by the build's
   `rustc` (overflow checks on) and run, on deterministic, seeded,
   coverage-driven inputs from the parameter types; outputs, errors and
   buffer states must agree, or the build fails with the input. The
   harness links the buffer model in Rust (`lift/conform_bytes.rs`), which
   the varint pilot's `vshim` compares with the real `bytes` crate. It is a
   test, not a proof: a misreading on inputs it never generates stays
   possible. The lift records every exec function it produces for the
   check (`lift::ConformEntry`: free functions, inherent methods, trait
   methods — sealed traits, operator/comparison/conversion impls on
   structs and on primitives, `Deref`, `Iterator`, derived `Default`) or
   an explicit exclusion the check reports with its reason
   (`lift::ConformSkip`: loop helpers and `impl Trait` returns, compared
   through their callers; functions with preconditions, compared through
   their callers; associated constants lifted as constant functions).
   Combinator templates (`lift/combinators.rs`) and inlined closures are
   not functions of their own: they are compared inside every function
   that uses them. Its negative twins (`tests/lift_conformance.rs`: a wrong
   rewrite rule behind the lift's test hook is caught) show it catches the
   kind of misreading the rewrite table risks. Further mitigations:
   SEMANTICS.md §19, the refusal of every construct the lift does not know,
   `tests/aug_int_toolchain.rs` and `tests/lift.rs` (kernel against rustc
   for signed operations and `div_ceil`). Audit notes: AUDIT.md §21.

Not trusted: parsing, name resolution, surface typing, the elaborator's
obligation generation for exec code (a missing obligation is caught because
the kernel requires the proof slot; this backstop does not cover the
*statements* of §15 items, hence item 6), automation, scripts, optimizer,
codegen printer, the front end's reference evaluator, diagnostics, the lift
conformance check (a mitigation: it can only fail a build; its shims
decide what it compares against, so a wrong shim could hide a misreading,
never create one).

### 1.2 Crates

```
sandblaster/          (in the Commonware monorepo; one crate per directory)
  kernel/             sandblaster-kernel. TRUSTED. term.rs value.rs api.rs (frozen interfaces),
                      bigint, eval, conv, check, inductive, recursion, prim, linarith, bvnorm,
                      axioms, core text syntax (parser + printer), prelude/*.core.
  front/              sandblaster-front. loader, resolver, surface types, HIR, subset validation,
                      builtins table, elaborator, auto, scripts, prelude lemmas, optimizer,
                      codegen (canonical printer), round trip, driver, diagnostics.
  macros/             sandblaster-macros. proc macros erasing ghost annotations (baseline builds only).
  sandblaster/        sandblaster (the facade): macros, `proof!` (expands to nothing), feature
                      "build": `sandblaster::build::compile`.
  cli/                sandblaster-cli, binary `sandblaster`: `sandblaster check|eval|emit|report <crate-dir>`.
  targets/            sandblaster-targets. TRUSTED (models). Executable intrinsic models, registry,
                      hardware evidence, core-text transcriptions (§9.2).
  memguard/           sandblaster-memguard. process-wide allocation cap (resource safety, not TCB).
  rulegen/            sandblaster-rulegen. offline rule discovery for the optimizer's aegraph.
  fixtures/qmdb/      the QMDB port's DSL sources, laws, proofs, locks and fixtures (§11), kept as
                      a test fixture of the toolchain's own suites.
  bench/opt-corpus/   the optimizer corpus harness.
```

The shipped code has **no runtime dependency** on sandblaster.

---------------------------------------------------------------------------

## 2. Project layout of a sandblaster crate

```
qmdb/
  Cargo.toml          [build-dependencies] sandblaster = { features = ["build"] }
  build.rs            fn main() { sandblaster::build::compile("sandblaster/mod.rs") }
  src/lib.rs          include!(concat!(env!("OUT_DIR"), "/sandblaster.rs"));   (nothing else)
  sandblaster/
    mod.rs            DSL crate root: `mod sha256; mod codec; ...`,
                      `#[cfg(sandblaster)] #[path = "LAWS.rs"] mod laws;`
                      `#[cfg(sandblaster)] #[path = "PROOF.rs"] mod proof;`
    sha256.rs codec.rs merkle.rs verifier.rs
    LAWS.rs           human-owned claims (Bend's LAWS.bend)
    PROOF.rs          proofs of every law (Bend's PROOF.bend)
```

* `build.rs` refuses to build unless `src/lib.rs` is exactly the `include!`
  line (plus comments), so host code cannot live next to generated code.
* Generated code shape (no inner attributes: it is `include!`d):
  ```rust
  #[cfg(not(target_pointer_width = "64"))] compile_error!("sandblaster requires a 64-bit target");
  #[deny(unsafe_code, overflowing_literals, unconditional_recursion)] #[allow(arithmetic_overflow, unconditional_panic, /* dead-code, unused-*, style lints, clippy::all */)]
  mod __sandblaster { /* every DSL module; items pub(crate) or narrower unless boundary */ }
  pub use __sandblaster::{/* boundary items: pub items reachable from the DSL root */};
  ```
  `#[allow(unsafe_code)]` appears only on generated functions that contain
  proven-unchecked operations, `unsafe fn`s (functions with non-trivial
  `requires`, §3.1), dispatchers and load/store helpers. `#![forbid(unsafe_code)]`
  is a **source** rule (checked by the front end, protects baseline builds),
  never emitted.
* `#[cfg(sandblaster)]` items/modules are **ghost**: never compiled by rustc; the
  checker treats `cfg(sandblaster)` as true.
* Target information comes from `CARGO_CFG_TARGET_ARCH`,
  `CARGO_CFG_TARGET_FEATURE`, `CARGO_CFG_TARGET_ENDIAN`,
  `CARGO_CFG_TARGET_POINTER_WIDTH` (never from the host).
* On success `build.rs` writes `OUT_DIR/sandblaster.rs` and
  `OUT_DIR/sandblaster-report.json` (definitions, obligations by kind, automated
  vs hinted, laws, specializations with reasons, variants and model-validation
  evidence, TCB list). On failure it prints diagnostics and exits non-zero.
* The **baseline crate** (benchmarks/differential tests only) includes the raw
  DSL sources with `#[path = "../sandblaster/mod.rs"] mod raw;`, depends on
  `sandblaster` for the erasing macros, and its `build.rs` emits
  `cargo::rustc-check-cfg=cfg(sandblaster)`.

### 2.1 Module mode: a verified module inside an ordinary crate

Crate mode (above) makes the whole crate generated code. **Module mode**
augments an existing crate instead: one critical, pure part becomes a
verified module with the same API, and the rest of the crate stays ordinary,
unverified Rust that calls it.

```
host/
  Cargo.toml              [build-dependencies] sandblaster = { features = ["build"] }
  build.rs                sandblaster::build::compile_module("sandblaster/varint/mod.rs", "src/verified/varint.rs");
  src/lib.rs, src/…       ordinary host code (`mod verified;` …)
  src/verified/varint.rs  include!(concat!(env!("OUT_DIR"), "/varint.rs"));   (nothing else)
  sandblaster/varint/       DSL root, laws, proofs, SPEC.lock (outside src/)
```

* `compile_module(root, module_file)` runs **the crate path unchanged**
  (proofs, law audit, every §15.8 gate, optimizer, printer, round trip,
  emission-chain check) and writes `OUT_DIR/<out>.rs`, `<out>-report.json`
  and `<out>-timing.json`, where `<out>` is the module file's stem. It has no
  options; any failure exits 1 and the host crate does not build.
* Checks before verification: the module file (under `src/`, not the crate
  root) is exactly the `include!` line plus comments — nothing shares the
  module with the generated code (no `use`, attribute or item: a glob import
  could shadow a primitive type or add trait methods); no other file under
  `src/` mentions `"/<out>.rs"`; the DSL root is not under `src/`. A
  module file that includes an unverified file, adds content or names
  another output is rejected. (The scan is textual: it catches mistakes, not
  a host that deliberately hides an include, e.g. `#[path]` outside `src/` or
  a split literal; host code is unverified by definition.)
* **The boundary** is the DSL root's `pub use` list, exactly as in crate
  mode (§3.1, §15.8: monomorphic, no `Irr` binders). The emitted file is the
  crate-mode print, round-tripped, then **relocated**
  (`sandblaster_front::relocate`): every `crate::` path head becomes `self::`
  or `super::` repeated by the number of enclosing `mod` blocks, so paths are
  position independent (the host can mount the module anywhere, and no host
  item can stand in for a generated one); every `pub(crate)` becomes
  `pub(self)` / `pub(in super::…)`, visible exactly within the file, so host
  code reaches only the top-level `pub use` exports and
  `SANDBLASTER_SPEC_ROOT` — never an internal item, a private field or the
  `__rt` / `__arch` / `__dispatch` glue (rustc E0603); the guard's
  `compile_error!` is qualified (`::core::compile_error!`), so a host
  `macro_rules!` cannot shadow any macro of the file; and each top-level
  item gets a lint `allow` (the host's lint levels apply to the included
  file: a `warnings = "deny"` host using part of the boundary would
  otherwise fail on the unused exports). The relocation refuses anything
  position-dependent (`$`, out-of-line `mod x;`, macros outside the
  dialect's list, relative paths that would leave the file) and is checked:
  the spliced text is re-tokenized and must equal the token-level rewrite.
  Its meaning argument (names resolve to the same items; lint levels are
  semantics-free) belongs to the printer's trusted argument (§8.3, TCB
  item 2); the round trip checked the crate-rooted print.
* What host code can still do is what Rust allows any module of a crate:
  add trait implementations (including `Drop`) to boundary types — a
  conflicting definition is a compile error, and a `Drop` can only make a
  call diverge or panic, never change a result — and name its dependencies
  (`::core`, `::std` are trusted as in crate mode, where the generated
  crate's `Cargo.toml` names them). A host `#![forbid(unsafe_code)]` rejects
  modules with proven unchecked operations (use `deny`).
* **Re-runs.** The `src/` scan makes the build script re-run on any host
  edit. Only paths that exist are watched: cargo re-runs a build script on
  every invocation while a watched path is missing (the lift prelude's
  source-map paths are virtual; a lock not accepted yet is noticed through
  the watched root directory), so an unchanged host crate and its
  dependents do not rebuild. A verdict is reused when the verdict key
  matches — the **verifier context** (`driver::cache::verifier_context`:
  the **toolchain identity**, a content hash computed by the facade's
  `build.rs` over the files of every sandblaster crate the build script
  links, including the data read at run time such as `targets/core` and
  `targets/evidence`, the lock entries of every third-party crate, and the
  `rustc`, host and `RUSTFLAGS` that compiled them; the toolchain's
  overflow checks and test hooks; the build's `rustc -vV`; every
  `SANDBLASTER_*` variable but the resource and cache settings), the
  target, the root, the module file, the host edition and the content of
  every file the front end read (sources, data files, the lock, the
  profile) — and `OUT_DIR/<out>.rs` still has the recorded hash. The key
  does not depend on the build-script binary, the host crate's features,
  the profile or the target directory, so `cargo build`, `cargo test`, a
  release build and a dependent crate's build of the same module share one
  verdict (the optimization level and `debug_assertions` cannot change a
  stored verdict: the toolchain is deterministic integer code and never
  branches on `cfg(debug_assertions)`, so they can only add a failure,
  which stores nothing). Verification output is deterministic: identical
  inputs give byte-identical emitted code, report and lift conformance key
  (no paths of `OUT_DIR`, no times; a replayed conformance pass reproduces
  its report). The module checks and the front end run on every build.
* **The verdict cache** (`driver::cache`; crate mode too). Without a
  matching key in `OUT_DIR` (a new target directory, `cargo clean`, an
  undone edit) the verdict is looked up under the same key in a
  content-addressed cache shared by all target directories and builds
  (`SANDBLASTER_CACHE_DIR`, default `~/.cache/sandblaster`; `SANDBLASTER_CACHE=off`
  disables it; neither is part of any key). Entries carry per-payload
  SHA-256s and an HMAC-SHA-256 under a secret kept outside the cache
  (`SANDBLASTER_CACHE_KEY`, or a 0600 key file in `~/.config/sandblaster`): an
  edited, truncated, misfiled or forged entry is rejected and the module
  re-verified. Only verdicts are stored; a hit replays what the same
  toolchain computed for byte-identical inputs, so it cannot turn a failure
  into a pass. On a miss the spec-mutation gate still reuses the verdicts of
  the spec mutants whose inputs did not change (§15.8, *Gate mode*).
* Several verified modules in one crate: one `compile_module` call per
  module file, each with its own output name (a repeated name fails).
* The lock is the root's, as in crate mode (`sandblaster spec <root> --accept`).
* **Lifted modules** (`#[lift] mod m;`, SEMANTICS.md §19): a DSL crate
  whose code is existing Rust copied verbatim emits **that file** (as-is,
  or with cheaper checked residuals lowered into it, below). The proofs are
  about the lift's reading of it; its printed lifted items are state passing
  over the buffer model, not the host's `Buf`/`BufMut` code, so they are
  never emitted. After every proof and every §15.8 gate passed (the same
  seal as the printed verdict) **and the lift conformance check passed** (§1.1
  item 8: the lifted model against `rustc`'s build of the source on generated
  inputs; `OUT_DIR/<out>-conformance/`, cached by content hash, a cached
  pass replaying its recorded report) the emitted file is a header (status
  `VERIFIED + LIFTED AS-IS`, or `VERIFIED + LIFTED + OPTIMIZED` with the
  rewritten functions listed,
  the boundary, what is not verified — `#[lift(unverified = ..)]`
  instances and the items the lift dropped — the host models and the
  `SPEC.lock` root), then the source **byte for byte after its leading
  `//!` lines**, then the rustc-checked host facts (SEMANTICS.md §19.2).
  An `include!`d file cannot carry inner docs, so the module file carries
  them: it must be exactly the source's leading `//!` lines plus the
  `include!` line (plus `//` comments) — module file plus emitted body is
  the original file. Exactly one lifted exec module is emitted (the others
  are `#[lift(host)]` models); a source with an inner attribute after its
  docs is refused; crate mode (`compile`) refuses a lifted crate (the source
  names host items through `crate::`). `driver::lifted` has the details.
* **Bodies from rustc's MIR** (`#[lift(mir = "m.sbmir", ..)]`, SEMANTICS.md
  §20). The module's function bodies are read from rustc's MIR, extracted
  by `sandblaster/mirx/extract.sh` (a rustc driver on the nightly of the
  stable release the workspace builds with) into a checked-in `.sbmir`
  file that names its sources by SHA-256; the build refuses a stale file,
  a file extracted without overflow checks, and MIR of another rustc
  release. The emitted file (still the source byte for byte) says so in
  its header. The lift conformance check compares the read functions with
  the build's rustc exactly as for the source lift. An in-place crate is
  extracted as a whole (its `#[lift(opt)]` alternatives compiled in the
  crate's context); the lifted round trip of a rewritten file reads rustc's
  MIR of the copy it checks (`<stem>.roundtrip__<module>.sbmir`, extracted
  from the copy the build writes to `OUT_DIR/<name>-roundtrip__<module>.rs`;
  a stale one fails the round trip, so a host compiling that lowered copy
  fails its build until it is extracted again; `docs/mir-lift.md` §20.1).
  Open traits are extracted at the instances the declarations name, given as
  type aliases rustc resolves (`storage/sandblaster/verifier/instances.rs`:
  `Standard<Sha256>`, SHA-256's `Digest`, the element iterator), and only
  the items the lift lifts are extracted (`--items`, `--skip-fns`).
* **The optimizer on lifted modules** (`driver::lowered`, `crate::lower`).
  The optimizer is always on here too: it runs on the lifted meaning like on
  any crate (summaries, Σ2 loop summaries, facts from proven laws, the
  aegraph) and every function gets its kernel-checked residual. A source
  function — top level, or an associated function of an impl, without a
  receiver, with plain parameters and at most one buffer state (`buf: &mut
  impl BufMut` without a result, or `buf: &mut impl Buf` with or without
  one) — is **rewritten in place** when a replacement is ≥ 3% cheaper under
  the portable cost model: its signature text stays, its body becomes the
  call of the replacement, and the replacement is appended to the file as
  private helpers. There are three kinds of replacement:
  * **its residual**, **lowered** — printed by `crate::lower` (untrusted) as
    plain Rust in the source's dialect: a `BufMut` state as
    `buf.put_u8(..)`/`buf.put_slice(..)` calls on the original parameter, a
    `Buf` state as `buf.try_get_u8()` calls with the result as the value,
    each state value used once and in order (the driver keeps the buffer
    model's operations folded for this, `drive::KEPT_LIFT_MODEL`);
  * for a **generic function over one sealed trait** (`fn size<T:
    UPrim>(value: T)`), one lowered residual per verified instance and a
    **per-type dispatch the lift reads**: a sealed trait
    `__sandblaster_dispatch_UPrim`, declared next to `UPrim` and made its
    supertrait (so every `T: UPrim` has it), with one method per rewritten
    function, implemented for every impl type of `UPrim` (the lift records
    them, `LiftFacts::sealed_impls`): a verified instance calls its residual,
    a type declared `#[lift(unverified = ..)]` calls a renamed copy of the
    original generic code (`__sandblaster_orig_<f>`), so an unverified
    instance keeps its original code. The body becomes the method call on
    the by-value parameter of type `T`, which the lift reads, per instance,
    as that impl's method. All verified instances must qualify, or none is
    rewritten. (Not yet: a generic function with a buffer state, or without
    a by-value parameter of its type — FRICTION, listed.)
  * an **optimization alternative** named by a **`#[rewrite]` lemma**
    `f(x̄) == g(x̄)` (proven like any lemma, so it needs no review — North
    star principle 3): `g` is a function of a `#[lift(opt)]` module of the
    DSL root, written by the agent in the host's dialect over the original
    API (verified and lifted like any code, never emitted as a module), and
    `g`'s own text — with the alternatives it calls, renamed, private — is
    the replacement. The link is a new kernel-checked definition
    `<f>::rewrite_equiv : Π x̄ (h̄ : Req_f). Eq(R, f x̄ h̄, g x̄ h̄)` whose
    proof is the lemma applied to the binders: the kernel checks that the
    lemma states exactly that (the alternative takes the source function's
    parameters and preconditions). This is how a faster algorithm that no
    optimizer derives (a closed form of a bit walk, a narrower search)
    enters code that is verified as written. (`#[lift(opt)]` lifts its
    module exactly like `#[lift]`; SEMANTICS.md §19 gets that sentence at
    the next lock acceptance — the file is part of the lock's `semantics`
    hash.)

  The cost model prices the source as rustc compiles it: the buffer model's
  operations as calls and the lift prelude's functions (`crate::__lift::*`:
  signed shifts and negation, core's methods) as one operation, never their
  model bodies (so a residual that only "improves" the model is not
  emitted); a loop at its literal trip count, `decreases(.., max = N)` or 16
  iterations, with its loop-carried chain on the critical path. The
  **lifted round trip** accepts a rewrite: the source (with the dispatch
  declarations) plus, per rewritten function, a copy
  `__sandblaster_check__f` with the same signature text and the new body
  plus the helpers and dispatch impls is read back by the same front end
  and lift as the source, its new items are elaborated in generated mode
  against the verified environment, every printed helper must equal its
  residual and every copied alternative its verified definition in all
  relevant positions (`alpha_eq_relevant`, as §8.3, modulo only `let x = v;
  x` ≡ `v`, the lift's reading of a last state update, and for readers the
  reader normal form: a pure read — the buffer model's `try_get_u8` of a
  pure read, or a field of one — bound by `let` is substituted, a tuple of
  one is projected, and a constructor over pure reads is pushed into the
  tails of a `let`/`match`; β, η for the one-constructor tuple and a pure
  total term read once or twice), and every copy and dispatch method must
  have the source function's type and be exactly the delegation `λ x̄. r x̄`
  to its replacement (per instance; for a reader, the lift's
  `let (s, r) = f(..); buf = s; (buf, r)` is the call by η). The rewritten
  function in the emitted file is the copy's text under the source name
  (token-identical signature tail and body, no self-reference), so it means
  its replacement, which the kernel-checked link (`Link::Conversion`,
  `r_f::equiv` or `<f>::rewrite_equiv`) proves equal to `f`. A function
  that fails keeps its source text (the rest is checked again; a second
  failure lowers nothing), and with no cheaper printable replacement the
  file is the source as-is, so the optimizer never makes a lifted module
  slower. The build summary (header and warning line) counts the functions
  that kept their source text by reason (not specialized, residual not 3%
  cheaper, methods, other state passing, …); the report lists each
  function's full reason. The lowered text gets its meaning exactly like
  the source, by the lift (SEMANTICS.md §19); nothing new is trusted: the
  printer writes only what the lift already reads (suffixed literals, locals `l<k>_<name>`,
  plain operators — a checked operator of the residual prints as Rust's
  operator, which agrees with it because the residual's proof slot shows it
  does not overflow —, `as` casts, builtin methods as method calls, calls by
  name, constructors, `if`, `match`, `let`, blocks, the buffer calls, a
  sealed trait and its impls) plus the semantics-free attributes
  `#[inline(always)]`, `#[doc(hidden)]` and `#[allow(..)]`, and a construct
  it gets wrong is a round-trip failure, never a different program. Not
  built yet: lowering of `&mut self` state passing and of residuals with
  loops or recursion (an alternative may have loops: its text is copied,
  not printed — but loop helpers are not yet matched by the round trip, so
  write alternatives loop-free), and the lift conformance check of the
  alternatives' texts.
* **In place.** When the verified code is the crate's own files (not a
  copy), a DSL root inside the crate lifts them by path (`#[lift(in_place,
  ..)] #[path = "../../src/x.rs"] mod x;`, SEMANTICS.md §19.5) and the
  host's `build.rs` calls `sandblaster::build::compile_lifted(root, name)`:
  the build verifies the files rustc compiles and writes a record
  (`OUT_DIR/<name>-verified.txt`: verified items, preconditions host callers
  must meet, every item left out) instead of emitting a module. The order
  is the same as for an emitted lifted module — proofs, every §15.8 gate,
  the lift conformance check of every in-place module, then the record.
  The optimizer runs once every proof checked and lowers each host file as
  above. **Compiling the optimized output** (`driver::in_place`): every
  build writes the lowered copy of **every** in-place file
  (`OUT_DIR/<name>-lowered__<path under src/, `/` as `__`>`, index
  `<name>-lowered.txt`) — the lowering's text exactly as the lifted round
  trip checked it, or the source byte for byte when nothing is cheaper —
  and a host compiles it by changing one declaration, the **lowered
  declaration**:

  ```rust
  #[cfg(rust_analyzer)]
  pub mod iterator;                       // the IDE twin (optional): rust-analyzer analyzes iterator.rs
  #[cfg(not(rust_analyzer))]
  pub mod iterator {
      //! (the leading `//!` lines of iterator.rs, checked equal)
      include!(concat!(env!("OUT_DIR"), "/mmr-lowered__merkle__mmr__iterator.rs"));
  }
  ```

  rustc cannot take a `#[path]` from `OUT_DIR`, so the module includes its
  copy. The lift reads the lowered declaration (and its IDE twin) exactly
  as `mod iterator;` (`lift::open::lowered_include`): the verified source
  stays `iterator.rs` as written. Any other inline module that includes
  something is refused (by the lift in a lifted file, by the build in the
  declaring file), as is a copy name other than this build's, docs other
  than the source's (an `include!`d file cannot carry inner docs), a
  source whose meaning depends on its file (`file!`, `line!`, `column!`,
  `include*!`, an out-of-line `mod`, an inner attribute), and any other
  mention of the build's copies under `src/` (a stale declaration, a copy
  included twice). **Fail closed:** a failed build (a proof, the
  emission chain) writes every copy as a `::core::compile_error!` stub, so
  rustc never compiles a stale, missing or unchecked copy; when the host
  compiles a copy, a rewrite of that file rejected by the lifted round
  trip, a failed lowering or an optimizer that did not run fails the build
  (a function whose replacement is not cheaper keeps its verified source
  text — not a fallback). Each copy's header says what it is: the status
  (a pending-gates build says `NOT VERIFIED — DEVELOPMENT BUILD: PROOFS
  CHECKED, §15 GATES PENDING` and that the rewrites rest on the
  kernel-checked links and the lifted round trip, which ran), whether
  rustc compiles it, the rewritten functions and the source's SHA-256.
  **Edits of a copy** (an IDE's go-to-definition lands in it): the build
  script watches each copy and the facade writes it read-only with a fixed
  old modification time (2000-01-01), so the watch alone never re-runs the
  script, while any edit does, and the re-run rewrites the copy from the
  verified source before rustc compiles it (cargo re-runs a build script
  when a watched file is newer than its last run; a file the script wrote
  itself would otherwise re-run it on every build). A reused verdict needs
  every copy as written (the key file records their digest). **In an
  IDE:** rust-analyzer runs build scripts and expands the include, so
  names from the module resolve and navigation lands in the read-only copy
  (whose header says to edit the source); with the IDE twin, rust-analyzer
  (which sets `cfg(rust_analyzer)`) analyzes `iterator.rs` itself, so
  editing it keeps completion and types — without the twin it reports
  `iterator.rs` as a file outside the module tree. The build declares
  `cfg(rust_analyzer)` to rustc's cfg check and warns if a build sets it
  (that build compiles the source as written: verified, not optimized).
  Panic locations and `line!`-style debugging in the compiled module
  point into the copy. **The conformance harness of in-place modules**
  compiles a copy of the host crate (without its build script) with the
  harness added to each in-place file, and drives every function at the
  declared instances (open traits included) against the kernel's
  evaluation (`crate::conform::check_in_place`, `docs/mir-lift.md` §5):
  the MMR passes (0 mismatches); the verifier's set 1 has no value
  mismatch but 16 `reconstruct_digest` inputs exhaust the kernel's step
  budget, so the check does not pass for it yet and `compile_lifted`
  would issue no verdict for that crate until it does. commonware-storage's MMR position arithmetic is the first
  in-place crate (`storage/sandblaster/mmr`); the first set of its Merkle
  proof verifier (`hasher.rs` at `Standard<Sha256>`, `proof.rs`'s subtree
  reconstruction; SEMANTICS.md §19.10) is the second
  (`storage/sandblaster/verifier`).
* **Development aid, to be removed before any landing:
  `sandblaster::build::compile_lifted_pending_gates(root, name)`.** While an
  in-place crate's specification lock is not accepted, it checks every
  proof and law (a failure fails the build) and runs the §15.8 gates but
  only reports their findings. It is an opt-out of §15.8 (which allows
  none), so it is bounded to be unmistakable: it never yields a verdict,
  an accept permit or a verdict key, even when everything passed; it
  writes `OUT_DIR/<name>-pending.txt` whose first line is `NOT VERIFIED —
  DEVELOPMENT BUILD: PROOFS CHECKED, §15 GATES PENDING`, replaces
  `<name>-verified.txt` with a `NOT VERIFIED` stub, sets the report's
  `status` to the same line and warns on every build. The lift conformance
  check runs only after every gate passed and is reported as not run
  otherwise. It exists only because the lock now holds just the review
  surface and the MMR crate's gates are not all green yet; once its lock
  is accepted the host switches to `compile_lifted` and this entry point
  is deleted.

---------------------------------------------------------------------------

## 3. The exec subset (code that runs)

The checker **rejects** anything not listed here.

### 3.1 Items

* `mod name;` (`name.rs` beside `mod.rs`, or `name/mod.rs`), ghost
  `#[cfg(sandblaster)] #[path = "X.rs"] mod m;`.
* `use` with explicit paths (`crate::`, `super::`, `self::`, renames, groups).
  No globs except `use sandblaster::prelude::*;`, `use core::arch::aarch64::*;`
  and `use core::arch::x86_64::*;` (resolved against the target library).
* `const NAME: T = expr;` (evaluated by the kernel at check time).
* Non-generic type aliases (`pub type Digest = [u8; 32];`), expanded in HIR.
* `struct` (named, tuple, unit) and `enum` (unit/tuple/struct variants); fields
  of exec types; no recursive user types; generic type parameters with bound
  `Copy` only; lifetimes. Derives: `Clone, Copy, PartialEq, Eq, Debug` (all
  user types must derive `Clone, Copy`).
* `fn` (free or in inherent `impl Type {}`; receivers `self`, `&self`),
  generic type parameters with `Copy` bound, `#[target_feature(enable = "..")]`
  (§9.3; never together with `#[inline(always)]`). No `async`, `extern`,
  `unsafe`, variadics, `impl Trait`, user const generics (reserved).
* **Verified boundary:** every function reachable without `unsafe` from
  non-generated code must be total (no `requires`). Enforced by codegen:
  non-boundary items are private to `__sandblaster`; functions with non-trivial
  `requires` are emitted as `unsafe fn` with a `# Safety` doc stating the
  precondition, and every verified call site wraps the call in `unsafe {}`
  with a `SAFETY:` comment naming the discharged obligation. A `pub` function
  reachable from the DSL root whose kernel type has any `Irr` binder (a
  `requires`, the `h_depth` hypothesis of `#[decreases(e, max = C)]`, a ghost
  parameter) is a front-end error. So is a `pub` generic function reachable
  from the root in which a type parameter occurs inside a slice element type:
  `rustc` instantiates exported generics at host call sites, where the §3.2
  zero-sized-type rule is never checked (and, once traits land, where unlawful
  impls could be supplied, §15.4). The boundary is exactly the DSL root's
  `pub use` list (§15.8): `pub mod` is not allowed at the root, and boundary
  functions are monomorphic.
* Attributes: `#[derive(..)]` (above), `#[inline]`, `#[inline(always)]` (not
  on `#[target_feature]` fns), `#[must_use]`, doc comments,
  `#[target_feature]`, sandblaster annotations (§4), and `#[allow(..)]`
  restricted to `dead_code`, `unused_*`, `non_snake_case`,
  `non_camel_case_types`, `non_upper_case_globals`, `clippy::*`.
  `#![forbid(unsafe_code)]` is required at the DSL root.
* Rejected: traits and trait impls (other than derives), `static`, macros other
  than `proof!` and `unreachable!()`, closures, fn pointers, `dyn`,
  `Box/Vec/String`/collections, floats, `char/str`, signed integers (reserved;
  exception: literal `i32` const-generic immediates of intrinsics, §9.2),
  `i128/u128` (exception: the restricted widening multiply, §9.6), raw
  pointers, `&mut` (except the whitelisted local `copy_from_slice` statement),
  interior mutability, `loop/break/continue`, labels, `return`/`?` inside
  loops, `?` on anything but `Option`.

### 3.2 Types

`bool`, `u8`, `u16`, `u32`, `u64`, `usize` (64-bit), `()`, tuples (≤ 12), `[T; N]`
(N a literal or const), `&[T]`, `&T` (shared references are values), `Option<T>`,
user structs/enums, type parameters; lifetimes accepted and ignored. Hardware
types: §9.2.

**Zero-sized element types are rejected in slices** (`&[()]`, `&[[T; 0]]`,
`&[S]` for a struct/enum/tuple all of whose fields are zero-sized): Rust only
bounds `len · size_of::<T>()` by `isize::MAX`, so the model's slice-length
bound would be false for them.

### 3.3 Expressions and statements

* Literals (typing: 3.6), `true/false`, `()`, array literals `[a, b]`,
  `[v; N]`, tuples, struct literals (incl. `..base`), constructors, `Some/None`.
* Paths to locals, consts, functions, associated functions, `u32::MAX`-style
  constants.
* Unary `!` (bool / bitwise), `*` (identity), `&` (identity; array→slice
  unsizing where a slice is expected).
* Unsigned integer binary ops: `+ - *` (proof: no overflow/underflow), `/ %`
  (proof: divisor ≠ 0), `& | ^`, `<< >>` (proof: shift < bit width),
  comparisons. Compound assignments likewise.
* `bool`: `&& ||` (**short-circuit**: `a && b` ≡ `if a { b } else { false }`,
  `a || b` ≡ `if a { true } else { b }`; the right operand is elaborated under
  the path condition), `== != & | ^ !`.
* `==`/`!=` on types with derived `PartialEq` (structural, §7.7), arrays and
  slices of such types.
* `as` between unsigned integer types and `bool as uN` (widening exact,
  narrowing truncates mod 2^w).
* Indexing `a[i]` (proof `i < len`), ranges `&s[a..b]`, `&s[a..]`, `&s[..b]`,
  `&s[..]` (proof `a ≤ b ≤ len`), field access.
* Calls (proof: callee `requires`), whitelisted methods (§3.4), intrinsics
  (§9.2) inside functions whose feature set covers them (§9.3).
* `if`/`else`, `if let`, `match` with guards; patterns: `_`, bindings (`x`,
  `mut x`, `x @ p`), literals, ranges `a..=b`, tuples, structs, tuple structs,
  variants, `Some/None`, `&p`, slice patterns (`[]`, `[a, b]`, `[h, t @ ..]`,
  `[a, b, rest @ ..]`, `[init @ .., last]`, `[first, .., last]`), or-patterns.
  **An identifier pattern whose name resolves to a const, unit struct or unit
  variant anywhere in scope (including ghost items and the prelude) is an
  error** (rustc and a naive resolver disagree on such patterns).
* Blocks; `let` (type annotation, patterns), `let mut`; `let P = e else {
  return ..; };` and `let P = e else { unreachable!() };` (obligation: the else
  path is contradictory); assignment to locals, array elements (`a[i] = v`),
  fields of locals; `local.copy_from_slice(src)` and
  `local[a..b].copy_from_slice(src)` on `let mut` array locals (obligations
  `a ≤ b ≤ N`, `b − a = src.len()`).
* Loops: `for i in a..b`, `for i in a..=b` (integer ranges; `i` immutable),
  `while cond` (needs `decreases`). No `return`/`?`/`break`/`continue` inside.
  Desugaring is normative (§7.4).
* `return e` and `?` outside loops.
* `unreachable!()` (obligation: the path condition is contradictory).
* `proof! { ... }` statements (§4.3).

### 3.4 Method whitelist (exec)

Each method has a prelude **definition** (its meaning, TCB) and prelude
**facts** that the elaborator adds at call sites like user `ensures`.

* Integers: `wrapping_add/sub/mul/neg/shl/shr`, `checked_add/sub/mul/div`
  (→ `Option`), `saturating_add/sub/mul`, `rotate_left/right`, `count_ones`,
  `leading_zeros`, `trailing_zeros`, `swap_bytes`, `to_be_bytes`,
  `to_le_bytes`, `uN::from_be_bytes`, `uN::from_le_bytes`, `min`, `max`,
  `pow` (proof: no overflow), `is_power_of_two`, `abs_diff`, `div_ceil`
  (proof: divisor ≠ 0).
* Slices: `len`, `is_empty`, `first`, `last`, `get(i)`, `split_at(mid)`
  (proof `mid ≤ len`), `split_at_checked`, `split_first`, `split_last`,
  `split_first_chunk::<N>()`, `split_last_chunk::<N>()`, `first_chunk::<N>()`,
  `as_chunks::<N>()` (N > 0). Facts include: `split_at(_checked)` on
  `Some((a, b))`: `a.len() == mid ∧ b.len() == s.len() − mid ∧ append(a, b) == s`;
  `as_chunks::<N>`: `c.len()·N + r.len() == s.len() ∧ r.len() < N`; lengths of
  the rest for the `split_*`/`first_*` family.
* Arrays: `len`, indexing, `as_slice()`, `&a[..]`, equality.
* `Option`: `is_some`, `is_none`, `unwrap_or`; `?`, `match`, `let .. else`
  otherwise (`unwrap/expect` are not allowed).

### 3.5 Semantic model (summary; SEMANTICS.md is normative)

| Rust | Core |
| --- | --- |
| `u8..u64, usize` | `IntTy(U8..Usize)` |
| `bool` | builtin `Bool` (ctor 0 = false, 1 = true) |
| `()`, tuples, `Option<T>` | prelude inductives |
| user struct / enum | user inductive (one ctor for a struct; eta, §5.4) |
| `&[T]` | `Slice(T) := Σ(n : Usize). Σ(l : List T). .SliceOk(n, l)` with `SliceOk(n, l) := len l = to_int n ∧ to_int n ≤ ISIZE_MAX` (irrelevant) |
| `[T; N]` | `Array(T, N) := Σ(l : List T). .(len l = N)` (array eta, §5.9) |
| `&T` | `T` |
| `a + b` | `add_w(a, b; proof)` |
| `a << s` | checked `shl_w(a, s; proof s < w)` (evaluates as the wrapping shift) |
| `s.len()` | `fst s` (exact `usize`, O(1)) |
| `s[i]` | `slice_index(s, i; proof i < fst s)` |
| `a[i] = v` | `a := array_set(a, i, v; proof i < N)` |
| `if`, `&&`, `||`, `match` | dependent matches with path-condition equations |
| `let mut`, assignment | SSA renaming |
| loops | recursive helper definitions with measures (§7.4) |
| `?`, `return` | control-flow conversion into nested matches |
| intrinsic call | `Intrinsic` global applied to its arguments (§9.2) |

Preconditions become irrelevant arguments; every call supplies proofs.
Out-of-domain operations never happen in a verified program; in the model
they are stuck terms (consistent with any total extension).

### 3.6 Typing rules (must agree with rustc)

* Integer literals are typed bidirectionally from their expected type or
  suffix. Otherwise: reject ("annotate this literal").
* The operand of `as` has **no** expected type, except that a syntactically
  bare literal takes the target type. Any other unsuffixed literal inside an
  `as` operand, or as the right operand of `<<`/`>>`, is rejected unless its
  type is fixed by unification with a typed operand (rustc would default it to
  `i32`).
* No implicit conversions except auto-ref/deref of `&T`/`T` in receivers and
  arguments and `&[T; N] → &[T]` unsizing where a slice is expected.
* Method resolution: whitelist + user inherent methods + target intrinsics.
* Name resolution: Rust lexical scoping; locals shadow items in the value
  namespace; the canonical printer makes every resolution explicit (§8.3).

### 3.7 Recursion, termination and stack depth

* Every recursive exec function needs a measure (inferred or
  `#[decreases(e)]`, §4.2).
* **Stack depth:** a recursive exec function must be either
  (a) **tail recursive** — codegen emits a loop (mandatory, §8.3), or
  (b) **depth-bounded** — `#[decreases(e, max = C)]` with `C ≤ 4096`; the
  obligation `e ≤ C` is proven at every call site from outside the function,
  and **stack use is an obligation**: every call tree containing non-tail
  recursion must satisfy `depth × frame + max callee stack ≤ 1 MiB`, where
  `frame = 2 × (parameters + result + locals + one temporary per expression) +
  256 bytes` (plus memory-resident values of callees that may be inlined); a
  frame depending on a type parameter is rejected under recursion. This is an
  engineering bound (it assumes optimized frames are bounded by their
  aggregate slots and that the thread has ≥ 2 MiB of stack), recorded in the
  TCB list. (Phase 4 red team RG-2/S1: depth alone admitted verified programs
  that overflowed the stack.)
  Non-tail recursion with an unbounded measure is rejected.

---------------------------------------------------------------------------

## 4. Ghost language (specs, proofs, laws)

Ghost code is never compiled by rustc. It is parsed by `syn`.

### 4.1 Ghost types and spec expressions

Ghost-only types: `Int` (mathematical integers, arbitrary precision), `Prop` (a
`#[spec] fn .. -> Prop` defines a proposition, like Bend's `-> Type`). Every
exec type is a ghost type.

* All exec expressions are spec expressions (calls to exec functions allowed;
  their `requires` become obligations in the spec context). In spec items
  (§15.1: spec fns, spec constants, views, representation relations,
  invariants, examples) such references are subject to **spec closure**: only
  established (fully specified) exec functions may be referenced.
* In a **proposition position** (`requires`, `ensures`, `assert`, `invariant`,
  law bodies, `-> Prop` bodies): `a == b`, `a != b` are propositional equality /
  disequality; `p && q` is the **dependent** conjunction `Σ(h : p). q` (the
  left conjunct is a fact while elaborating the right, so `off <= len &&
  len - off >= 64` works); `p || q`, `!p` are ∨ and ¬; a `bool` expression `b`
  used as a proposition means `b == true`.
* **Operands** of a propositional `==` are expression positions:
  `(a == b) == false` means `Eq(Bool, eq(a, b), false)`. `eqb(a, b)` is sugar
  for boolean equality.
* `implies(p, q)`, `iff(p, q)`, `forall(|x: T, y: U| p)`, `exists(|x: T| p)`.
* `x as Int`; `Int` supports `+ - *` (exact) and comparisons. `/` and `%` on
  `Int` require provably non-negative operands (then truncating and Euclidean
  division agree) and a non-zero divisor; use `div_euclid`/`rem_euclid`
  otherwise. `Int as uN` truncates mod 2^N, exactly like exec `as`.
* `Nat`: an `Int` with the type bound `0 ≤ n` (a fact at every binder, an
  obligation at every construction); `a - b` needs `b ≤ a`; `saturating_sub`
  mirrors Bend's `Nat.sub`. Unsuffixed literals in ghost code are inferred from
  use, defaulting to `Nat`.
* `Seq<T>`: the prelude `List`, unbounded (no `ISIZE_MAX`): `len() -> Nat`,
  `get`, `take`, `skip`, indexing by `Nat`, `chunks_exact::<N>()` (drops the
  remainder), `flatten`, `to_array::<N>()`, `Seq::repeat`, slice patterns
  `[]`/`[h, t @ ..]`, and `seq![..a, x, ..b]`. Exec slices and arrays coerce
  to `Seq` (§15.3). Ghost code accepts `b".."` and `hex!("..")` (whitespace
  groups allowed), typed `[u8; N]`.
* Ghost sequence helpers from the prelude: `seq::append`, `seq::cons`,
  `seq::take`, `seq::drop`, `seq::len(xs) -> Int`, …; operations that build a
  `Slice` require the `ISIZE_MAX` bound.

### 4.2 Contracts on exec functions

```rust
#[requires(off <= msg.len() && msg.len() - off >= 64)]
#[ensures(|ret: [u32; 8]| true)]
#[decreases(n, max = 64)]
fn f(..) -> .. { .. }
```

`#[requires(p)]` (several are conjoined, each a separate irrelevant binder),
`#[ensures(|ret| p)]` (or `#[ensures(p)]` for unit return), `#[decreases(e)]`
/ `#[decreases(e, max = C)]`. Measures are inferred for slice-pattern
recursion (`len`) and for a parameter `n` recursed on as `n − k` under a path
condition implying `n ≥ k`. `#[implements(path)]` marks a hardware variant
(§9.3). `#[specialize]` requires successful specialization (§8.2).

The front end normalizes every function-like item (exec fn, spec fn, lemma,
law, proof) to one form: `FnDef { requires: Vec<Expr>, ensures: Option<(Pat,
Expr)>, decreases: Option<(Expr, Option<u64>)>, body }`.

### 4.3 `proof!` blocks inside exec code

`proof! { stmts }` may appear as a statement anywhere in an exec body; its
statements run in the proof context at that point and add facts for later
obligations. As the **first statement** of a loop body it may declare
`invariant(p);` (several) and `decreases(e);`.

### 4.4 Script statements (in `proof!`, `#[lemma]`, `#[proof]`, `#[law]`)

| Statement | Meaning |
| --- | --- |
| `assert(p);` | prove `p` with `auto`, add it as a fact |
| `assert(p, { steps });` | prove `p` with the nested steps, add it |
| `lemma(args);` / `let h = lemma(args);` | apply a lemma/law; `requires` proven by auto; `ensures` becomes a fact. (A recursive call by the proof's own name still acts as the induction hypothesis; `ih` is preferred.) |
| `apply(lemma);` / `let h = apply(lemma);` | apply a lemma/law with arguments inferred by matching its `requires` against the facts (and `ensures` against the goal), unfolding transparent functions; the call is then checked as if written out. No match or an ambiguous match is an error listing the candidates. `apply` on the enclosing proof is rejected (use `ih`). |
| `#[induction(x)]` on a lemma/proof, `ih(args);` | the proof recurses on a structurally smaller `x` (slice tail from a `match`, or `x - k`); `ih` is the recursive application, termination-checked. `#[induction]` without `ih`, or `ih` elsewhere, is an error. |
| `follows();` | the remaining goal follows from the facts in scope (`requires`, earlier asserts and lemma results, case equations) by the automation's general reasoning (arithmetic, equalities, unfolding transparent definitions, bounded case splits, prelude lemmas); must be last in its block. Checked like every obligation: the build fails if the prover finds no proof, and the kernel re-checks the proof (the search is deterministic and bounded). An empty proof body, arm or branch (or an `if` without `else`) means the same but warns; so does a block that ends after other statements without a closing statement, and a `calc!` link without `by`, unless the goal left there is closed by conversion or is a fact in scope. (Replaces `by_auto();`, now an error listing the closing statements; `follows_from_facts();` is an error suggesting `follows();`.) |
| `by_arithmetic();` | the goal follows from the facts by arithmetic and equality reasoning only: linear arithmetic, the §8.1 step-7 axioms, the built-in theory of built-in operations (prelude rules), congruence, constructor clashes. The crate's functions, with or without parameters, are unknown (no unfolding, by evaluation or `Delta`; `const` items are values), no case analysis on program values (`bool`/`Option`/enum scrutinees, matches), no instantiation of quantified facts. Integer reasoning is complete linear *integer* arithmetic: it may internally split on arithmetic atoms (integer cuts `a < c ∨ a ≥ c`, `a ≠ b` as `a < b ∨ a > b`), which is arithmetic, not case analysis. Checked by the prover restricted this way on a view of the goal whose functions are variables; on failure the diagnostic says it needs more than arithmetic and names the unknown functions. Terminal. |
| `by_unfolding(f, g, ..);` | like `by_arithmetic();`, but exactly the named definitions (transparent or opaque) are unfolded; the functions they call stay unknown, like every other function (in the view a named definition calls the variables of its callees: a non-recursive transparent one is a `let` of its body, a recursive or opaque one a variable with its defining equation, used like `Delta`). States which definitions the step depends on. Terminal. |
| `by_contradiction();` | the facts in scope are contradictory (this case cannot happen): the prover must derive `Empty` from them alone (the goal is not used); the goal is then `absurd`. Terminal. |
| `by_computation();` | the goal (an equation or `bool`) holds by evaluation and conversion alone, no search; on failure both evaluated sides are shown. Terminal. |
| `by_cases(x);` `by_cases(a, b, ..);` `by_cases(k, lo..hi);` (inside `proof!{}` also `by_cases(k in lo..hi);`) | split on every constructor of a `bool`/`Option`/enum, or enumerate an integer range (≤ 256 cases); the statements after it run in each case, then auto. `cases` is an alias. |
| `calc! { e0 == e1 by { steps }; == e2; <= e3; }` | chain of `==`/`<=`/`<` links, each proven by its block or auto (a link without `by` warns unless it is closed by conversion or is a fact), combined by transitivity; as the last statement it must prove the goal, otherwise its result becomes a fact. |
| `match e { pat => { steps } .. }` | case analysis with the equation `e == pat` as a fact; if `e` is a variable (including a slice/array/struct variable, §7.6), the goal and facts are refined. Terminal. |
| `if c { steps } else { steps }` | case split on a bool. Terminal. |
| `cases(k in a..b) { steps }` (inside `proof!{}`; in ghost fn bodies, where this is not Rust syntax, write `cases(k, a..b, { steps })`) | finite enumeration of an integer whose range auto can prove (≤ 256 cases); each case closed by evaluation + steps + auto. Terminal. |
| `witness(e1, .., en);` | instantiate an `exists` goal |
| `unfold(f);` | unfold the applications of `f` written in the goal term (a transparent non-recursive `f` by conversion, a recursive or opaque one by `Delta`); the rest of the goal stays folded, and with no application the goal is unchanged (a warning) |
| `rewrite(h);` `rewrite_rev(h);` `rewrite(h, \|x\| p);` | rewrite the goal with an equation (optionally with an explicit motive, like Bend's `%e : P`) |
| `exact(term);` | close the goal with a term (spec expression / lemma application) |
| `bv();` | close an equality goal with `BvRefl` (word algebra, §9.8); a goal with a shift by a variable amount, `/` or `%` goes to linear arithmetic with the built-in shift and `pow2` rules, using only the facts that bound its shift amounts and `pow2` exponents (`s < 8`), so it is still a word identity |
| `let x = e;` | ghost let |
| `show();` | print goal and facts as a warning (Bend's `?name`) |
| `todo();` | leave the goal open (the build fails, printing the goal) |

At the end of a script, `auto` must close the goal.

### 4.5 Ghost items

```rust
// spec/proof.rs: spec functions live in the ghost `spec` module (no attribute needed there)
pub fn layout(t: Peak, k: Nat) -> Layout { .. }
// PROOF.rs: proof-local spec functions and lemmas
#[spec]  fn honest(db: Db, i: Nat, n: Nat, k: Nat) -> Proof { .. }
#[lemma] fn and_left(a: bool, b: bool) { requires(a && b); ensures(a); }
```

`LAWS.rs` (claims, no proofs):

```rust
/// Complete: every current update of a well-formed database has a proof
/// that verifies against the database's root.
#[law]
fn current_updates_have_proofs(db: Db, loc: Nat, key: Digest, value: Digest) {
    requires(db.well_formed() && db.is_current(loc, update(key, value)));
    ensures(exists(|p: Proof| p.location == loc && verify(db.root(), key, value, encode(p))));
}
```

(QMDB as built: the honest prover is a proof-local `#[spec]` in `PROOF.rs`,
given to `witness(..)`, so it stays off the surface.)

`PROOF.rs` (one `#[proof]` per law, same name and parameters):

```rust
#[proof]
fn current_updates_have_proofs(db: Db, loc: Nat, key: Digest, value: Digest) { /* steps */ }
```

A `#[law]` without a proof is an **open claim** (build fails). A law may carry
its proof inline after `requires/ensures`. Laws and proofs pair by name,
crate-wide; inside `PROOF.rs` a law's name resolves to its `#[proof]` item,
and a proof's recursive calls are induction hypotheses. Prelude lemmas are
addressable from ghost code as `sandblaster::lemmas::<name>` (glob import
allowed). `#[rewrite]` on a law `f(xs) ==
g(xs)` lets the optimizer use it (later milestone).

---------------------------------------------------------------------------

## 5. Core calculus (the kernel)

The Rust types are in `sandblaster/kernel/src/{term,value,api}.rs`
(frozen; changes need a design note). This section gives their rules.

### 5.1 Syntax

See `term.rs`. De Bruijn indices in terms, levels in values. Every binder
(Π, λ, let, Σ second component, match-arm fields, motives) carries a
relevance. Integer literals are arbitrary-precision (`BigInt`); machine
literals must be in `[0, 2^w)`.

### 5.2 Sorts and formation

* `Type : Kind`; `Kind` has no type and may only appear as the type of a type.
* `Π(x :r A). B` is well-formed if `A : s1` and `B : s2` (sorts), and has sort
  `max(s1, s2)`. `B = Kind` is ill-formed (so no `A → Kind`); `Π(T : Type). B`
  has sort `Kind` and can therefore never appear inside `Eq`.
* `Σ(x : A). B` requires `A, B : Type` (Σ lives in `Type`).
* Inductive parameters may have any type `T` with `T : Type` or `T : Kind`
  (e.g. `T : Type`). **Every constructor field type must be `: Type`**, and may
  not be `Type` itself (no `box(X : Type)`: Hurkens' paradox).
  `D(params) : Type`.
* `Eq(A, a, b) : Type` requires `A : Type`.
* Match motives `y. P` require `Γ, y : D(ps) ⊢ P : s` for a sort `s` (large
  elimination: a match may compute a `Type`). Transport motives require
  `P : Type`.
* Consistency: MLTT with one universe (`Type`) plus large elimination and UIP,
  set-theoretic model. No impredicativity, no `Type : Type`, no `Kind : Kind`.

### 5.3 Relevance (complete table)

* Every binder carries `r`. `App { rel }` is well-typed only if `rel` equals
  the relevance of the function type's Π; neutral spines take relevance from
  the type.
* **Irrelevant positions** (exactly): the argument of an `Irr` application;
  prim proof slots; `Rec.proof`; the second component of a pair whose Σ has
  `snd_rel = Irr`; the value of an `Irr` let; `Transport.eq`; `Absurd.proof`;
  `Irr` constructor fields.
* **Every type position is relevant**: Π/Σ domains and codomains (including the
  domain of an `Irr` binder and the second component *type* of an `Irr` Σ),
  motives, `Eq`'s type, `Transport`'s type and motive, `Absurd`'s type, let
  types.
* **Resurrection (Pfenning/Agda):** entering an irrelevant position at context
  depth d makes the irrelevant variables bound *outside* it (levels < d)
  usable; binders, lets and match fields introduced *inside* it keep their
  irrelevant status (a nested irrelevant position resurrects again). `snd` of
  an `Irr` Σ is allowed only in an irrelevant position entered after every free
  variable of the pair was bound. Elsewhere, irrelevant variables are **not**
  usable (an irrelevant variable may appear in a type only inside a nested
  irrelevant sub-position). (Phase 4 red team: a single "irrelevant mode" flag
  that resurrected inner binders admitted a closed proof of `Empty`; see
  `docs/review-3-redteam.md` R1 and the kernel's AUDIT.md §4.)
* **Irrelevant data must be propositions** where conversion relies on proof
  irrelevance: the second component type of an `Irr` Σ and every `Irr`
  constructor field must satisfy a conservative `is_prop` (Eq; Π into a
  proposition; Σ of propositions; non-recursive inductives with 0 constructors
  or 1 constructor of propositional fields). `Irr` Π domains may hold data (the
  relevance discipline alone justifies skipping them).
* `Snd` of an `Irr` Σ may only occur in irrelevant positions.
* Conversion skips exactly: `Irr` application arguments, `Irr` pair
  components (and `Snd` of `Irr` Σ), prim proof slots, `Rec` proofs,
  `Transport.eq`, `Absurd.proof`, `Irr` ctor fields. It compares Irr-Σ
  **types** fully.
* Evaluation never inspects irrelevant terms.
* Termination checking, linarith and all other checks apply unchanged inside
  irrelevant positions.
* Must-accept: `λG. refl(Bool, G true@Irr) : Π(G : Π(h :Irr Bool). Bool).
  Eq(Bool, G true@Irr, G false@Irr)`. Must-reject: `λ(h :Irr Bool). let x
  : Bool = h; x`; `(λ(x : Bool). x) true@Irr`; the `Array(T,3) ≡ Array(T,4)`
  confusion; the Irr-domain `G0` exploit (`docs/review-1.md`).

### 5.4 Inductive types

`InductiveDecl { name, params, ctors }` (`term.rs`); constructor fields may be
`Irr`. Only direct recursive fields `D(params)` (strict positivity by syntax).
Builtins: `Bool`, `Empty`. Everything else is declared by the prelude through
the same API.

`match scrut as y return P with arms`: arm k binds the fields of ctor k and has
type `P[y := c_k(ps; fields)]`; result `P[y := scrut]`; ι: `match c_k(..) →
arm_k(..)`.

**Eta for structs:** for a non-recursive inductive with exactly one
constructor, conversion equates a neutral `s` with `c(ps; π₁ s, .., πₙ s)` where
`πᵢ s := match s { c(xs) => xᵢ }` (irrelevant fields skipped).

### 5.5 Equality

`refl(A, a) : Eq(A, a, a)`. `transport(A, a, b, e, y.P, v) : P[b]` with `e`
irrelevant, `P : Type`, `v : P[a]`; reduces to `v` iff `a ≡ b`. Symmetry,
transitivity, congruence and no-confusion are derived in the prelude.

### 5.6 Definitions, recursion, termination, unfolding

`DefDecl { name, kind, ty, body, recursion, arity }`:

* `Recursion::None`: no `Rec` in the body.
* `Recursion::Structural { param }`: `param` has a recursive inductive type
  (`List`); every `Rec` passes at `param` a variable bound as a recursive field
  of a match whose scrutinee is the parameter variable or (transitively) such a
  field variable.
* `Recursion::Measure { measure }`: every `Rec(args; p)` carries
  `p : Σ(_ : 0 ≤ m[args]). m[args] < m[params]` (for unsigned measures only
  the second component), stated as `Eq(Bool, cmp(..), true)` facts and checked
  in the call-site context (path conditions available).
* No mutual recursion; `Global(g)` may not occur in `g`'s own body; `Rec` is
  neutral while the body is checked and evaluates as `g args` only after
  `add_def` commits `g`.
* **Unfolding policy:**
  - non-recursive, non-intrinsic globals unfold on demand;
  - a recursive global applied to all arguments unfolds iff weak-head
    evaluation of its body (sub-budget 2^20 steps; **only the global under
    speculation is folded** — other recursive helpers evaluate normally, so a
    head test like `lt(len l, N)` computes on concrete data) does **not**
    reach a match or checked prim whose scrutinee/operand is neutral;
    otherwise the application is the neutral `Head::Global`;
  - **opaque** definitions (`DefDecl.opaque = true`, surface `#[opaque]`) never
    unfold in checking-mode evaluation/conversion; `Delta` (script
    `reveal(f)` / `unfold(f)`) exposes their defining equation. Sound: opacity
    only loses completeness. Hashes, CRC, codecs and large step functions are
    opaque in proofs by default and used through their `ensures`, so symbolic
    SHA-256 is never unrolled during proof search (the elaborator marks
    loop-containing functions, buffer builders and codec readers — a `&[u8]`
    parameter with an `Option<(T, &[u8])>` result — opaque); script steps
    (`unfold`, `rewrite`, `witness`, `match`/`if` on non-variable scrutinees)
    operate on goal *terms* rather than evaluated values; the optimizer evaluates
    them transparently (`eval_opaque` with an empty opaque set);
  - `DefKind::Intrinsic` globals unfold **only when every relevant argument is
    a closed value** (literals and constructors/arrays of literals); otherwise
    they are neutral heads. `BvRefl` (and only it) evaluates **transparently**:
    it unfolds intrinsics on symbolic data and opaque definitions (sound —
    opacity only loses completeness); this is how `VariantEquiv` is proven;
  - recursion that inspects its own recursive result computes on ground
    (fully concrete) arguments; in checking mode a closed recursive call whose
    one-level speculation exceeds the sub-budget stays folded;
  - budget exhaustion is an error (never "convertible").
* `Delta(g; args) : Eq(R, g args, body[args][Rec(a') := g a'])` when `R : Type`;
  `Unfold(g; args; dir; v)` casts between `g args` and the body when `g`
  returns a proposition.

### 5.7 Primitives

See `PrimOp` in `term.rs`. An op computes when its relevant arguments are
literals and (for checked ops) they are in the domain; otherwise it is stuck.
Checked `Shl/Shr` evaluate exactly like `WShl/WShr`. `Int` arithmetic is exact
(bignum); an implementation limit (e.g. 4096 bits) exceeded is
`EvalError::IntOverflow` (never wraparound).

Sound simplifications on neutrals (checked and wrapping forms; wrapping
constants reduced mod 2^w; produced literals always in range):
`x+0 → x`, `0+x → x`, `x−0 → x`, `x·1 → x`, `1·x → x`, `x·0 → 0`, literal
operands of commutative ops move right, `(x+c1)+c2 → x+(c1+c2)`, `(x+c)−c →
x`, `eq(x+c, 0) → false`, `lt(0, x+c) → true`, `le(1, x+c) → true` for a
checked add with literal `c > 0`, `to_int(lit) → lit`, widening casts
collapse, `index(take/drop/slice(l, a, ..), i) → index(l, a+i)` for literal
offsets, `from_le_bytes([cast_u8(x), cast_u8(x>>8), ..]) → x`,
`cast_u8(wshr(from_le_bytes(bs), 8k)) → bs[k]`.

### 5.8 Linear arithmetic certificates

`Linarith { hyps: [(proof, stated)], goal, cert }`:

1. Each `stated` prop must be convertible with the inferred type of `proof`.
   Linearization uses the **stated** form.
2. Hypothesis forms: `Eq(Bool, cmp_w(a, b), true|false)` for `cmp ∈ {eq, lt, le,
   gt, ge, ne}` except `ne … true` and `eq … false` (disjunctive);
   `Eq(IntTy w, a, b)`. Goal forms: the same, plus `ne … true` / `eq … false`
   (their negation is an equality), plus `Empty`. An equality goal needs two
   certificates (≤ and ≥; `cert` is their concatenation).
3. Linearization over ℤ (each encoding is a true definitional fact): literals;
   checked `add/sub`; `mul` by a literal; `Int` `iadd/isub/ineg`, `imul` by a
   literal; `to_int`, `of_int`, widening **and equal-width** casts (`u64 ↔
   usize`) are transparent; **div/rem by a literal `k > 0`**, `wshr`/`shr` by a
   literal `s`, `and` with a literal mask `2^k − 1`, truncating casts,
   `wshl`/`shl` by a literal, and `wadd/wsub/wmul-by-literal` introduce fresh
   atoms with their defining constraints (`a = k·q + r, 0 ≤ r ≤ k−1`;
   `wadd(a,b) = a + b − 2^w·c, 0 ≤ c ≤ 1`; …); every other term is an **atom**,
   identified up to conversion. Machine-typed atoms get `0 ≤ a ≤ 2^w − 1`;
   `seq::len` atoms get `0 ≤ a`.
4. Constraints are normalized to `e ≤ 0` / `e = 0` (strict `e < 0` becomes
   `e + 1 ≤ 0`). The goal is negated. The constraint order is canonical and
   exposed through `Env::linearize` (hypotheses in order, negated goal, then
   implicit constraints in atom-creation order).
5. `cert` assigns an exact (bignum) rational to each constraint (nonnegative
   for `≤`). Accept iff Σ cᵢ·eᵢ has all atom coefficients 0 and a positive
   constant. The certificate is a **hint**: if it fails (e.g. after
   substitution changed atom order), the kernel re-searches with an
   (untrusted) simplex whose output goes through the same exact check; a
   hypothesis may also be justified by a context assumption of the stated
   type (relevance-respecting), which is stable under substitution.

### 5.9 Checking and conversion

Bidirectional checking with NbE. Eta for functions, Σ (including `(fst p, _) ≡
p` for Irr Σ), structs (§5.4) and **fixed-length arrays** (literal `N ≤ 256`),
realized by introducing every kernel-created variable of type `Array(T, N)`
in eta-expanded form `([index(fst x, 0), .., index(fst x, N−1)], snd x)`
(checker binders, conversion under binders, `Env::ctx_venv`,
`Env::fresh_var`); sound by extensionality of fixed-length lists. **Conversion memo:** scoped to one top-level `conv` call;
stores `Rc` clones of both compared values (no address reuse while the memo
lives); records completed positive results (and, for `BvRefl`, failures); the
key includes the comparison mode. Conversion never calls term-returning
normalization; values are never quoted without sharing during conversion.

### 5.10 Axioms

A fixed list of schemas in `axioms.rs` (instantiated per width `w` and, where
needed, per literal `k < w`), each justified in the set model and tested
exhaustively over `U8` and `U16` and at `U64` boundaries:
`and_le_left/right`; `or_ge_left/right`; `or_le_add`; `xor_le_or`; `shr_le:
wshr(a, s) ≤ a`; `min_def`, `max_def`, `sat_sub_def`, `sat_add_def`
(implications from the comparison); `count_ones_le: count_ones(a) ≤ w`
(derivable from `count_ones_def`; retired after O12); `rotr_rotl`;
`int_to_sat_def`; `mul_mono: 0 ≤ a ≤ A ∧ 0 ≤ b ≤ B → a·b ≤ A·B`;
`div_def/rem_def` linking checked `div/rem` to `IDiv/IMod`; `rem_lt: b ≠ 0 →
rem(a, b) < b`; and the bit-count definitions `count_ones_def`,
`leading_zeros_def`, `trailing_zeros_def` (sums in `Int` of the bits / of one
comparison per candidate count; also tested at 10^7 random values per width
and against mutations). The former `leading/trailing_zeros_le/lt` are checked
lemmas (`lemmas/bits.core`); retired schemas keep their ids. Many facts are covered by §5.8's linearization; add axioms
only with justification and tests.

### 5.11 API

See `api.rs`. Entry points: `add_inductive`, `add_def` (checks and commits),
`infer`, `check`, `eval`, `eval_opaque` (optimizer), `quote` (with sharing),
`conv`, `check_residual_equal` (codegen-only: a fully proof-annotated,
straight-line candidate is checked at the reference's type and convertible
with the reference; never added to the environment), `alpha_eq_relevant`
(round trip), `abstract_occurrences` (automation), `linearize` (automation).
`Term::Erased` is only a placeholder in terms compared by
`alpha_eq_relevant`; every checking entry point rejects it.

### 5.12 Core text syntax

A textual syntax for core terms with a parser (named binders → de Bruijn) and a
printer (round-trips), used by prelude definitions, kernel tests, automation
tests and diagnostics. Implementation choice of concrete syntax; it must cover
every `Term` constructor and declarations (`inductive`, `def` with recursion
mode and kind).

---------------------------------------------------------------------------

## 6. Prelude ("Base")

* **Definitions** (trusted): `sandblaster/kernel/prelude/*.core` in core
  text, owned and tested by the kernel crate: `Unit`, `Option`, tuples,
  `List`, `Either`, `Not/And/Or/Iff/Exists`, `seq::*` (`len : List T → Int`
  structural, `index`, `update`, `take`, `drop`, `append`, `rev`, `replicate`,
  `split_first_chunk`, `as_chunks`, list equality), `SliceOk`, `Slice`,
  `Array`, integer byte conversions (`from_le_bytes`, and `from_be_bytes :=
  from_le_bytes ∘ rev`, so byte-reversal plus a little-endian read is
  `from_be_bytes` by definition), and the meaning of every §3.4 method.
  Conventions: list functions take and return `Int`; slice methods work on the
  `usize` length `fst s` and obtain `of_int`/range proofs from `SliceOk`.
* **Lemmas** (checked, untrusted; `sandblaster/front/lemmas/*.core`,
  loaded after the definitions): `len_append`, `len_take`, `index_update_*`,
  `take_drop_append`, `array_eta`, `slice_eta`, `list_ext`/`array_ext`,
  `is_empty(s) = true ↔ s = &[]`, bool lemmas, the §3.4 method facts. Core text
  for the MVP, surface ghost syntax once the elaborator runs.
* **Builtin table** (`sandblaster-front/src/builtins.rs`), shared by method
  resolution, elaboration, the optimizer's opaque set and codegen printing:
  `Builtin` enum ↔ prelude `GlobalId` ↔ canonical Rust spelling.

---------------------------------------------------------------------------

## 7. Elaboration

### 7.1 Global order

Collect all items (prelude, DSL modules, ghost modules, target library),
resolve, build the reference graph, reject cycles other than self-recursion,
elaborate in dependency order, adding each definition to the kernel `Env`
immediately. Laws after everything they mention; proofs after their laws.
Global names: `GlobalName::{Item(Path), LoopHelper{parent, k}, Ensures(..),
Eq(Path), EqSound(Path), Variant{..}, Prelude(..)}`; loop helpers are numbered
deterministically in source order.

### 7.2 Proof context, facts, obligations

* **Facts are context entries** (`Irr` lets / `Irr` λ binders), so shifting and
  match refinement need no special code.
* Elaborator ↔ automation contract (`sandblaster-front/src/prover.rs`):
  ```rust
  pub enum ObligationKind { Overflow, Underflow, DivZero, ShiftWidth, IndexBounds, SliceRange,
      CalleeRequires(GlobalId), Unreachable, InvariantEntry, InvariantPreserve, Termination,
      StackDepth, Ensures, LawGoal, Assert, VariantEquiv, WellFormed,
      Refines, TypeInvariant, InvariantExit, ViewInjective, Example, Completeness }
  pub enum FactOrigin { Requires, PathCond, LetDef, Invariant, CalleeEnsures(GlobalId),
      MethodFact(Builtin), Assert, TypeBound, InductionHyp }
  pub struct FactRef { pub lvl: Lvl, pub origin: FactOrigin, pub span: Span }
  pub enum Hint { Lemma(Tm), Rewrite { eq: Tm, rev: bool, motive: Option<Tm> }, Witness(Vec<Tm>),
      Unfold(GlobalId), Cases { var: Lvl, lo: BigInt, hi: BigInt }, Exact(Tm), Bv }
  pub struct Goal { pub id: ObligationId, pub kind: ObligationKind, pub span: Span, pub ctx: Ctx,
      pub facts: Vec<FactRef>, pub target: V, pub hints: Vec<Hint> }
  pub struct AutoFailure { pub goal: String, pub facts: Vec<String>, pub stuck: Vec<String>,
      pub tried: Vec<String> }
  pub trait Prover { fn prove(&mut self, env: &Env, g: &Goal, b: &mut Budget) -> Result<Tm, AutoFailure>; }
  ```
  The prover is called synchronously; the returned term is closed in `g.ctx`.
  The kernel helper `abstract_occurrences` and one dependent-match builder are
  shared so every component generates identical shapes.
* Dependent match idiom: `match c as y return Π(e :Irr Eq(D, c, y)). R with
  arms` applied to `refl`; each arm receives the path equation as an `Irr`
  binder.

### 7.3 Exec functions

For `fn f<T..>(x: A..) -> R` with requires `P₁..Pₙ` and ensures `Q`:

* `f : Π(T : Type).. Π(x : ⟦A⟧).. Π(h₁ :Irr ⟦P₁⟧)..Π(hₙ :Irr ⟦Pₙ⟧[h₁..]). ⟦R⟧`.
* Body: SSA for `let mut`/assignment (joins produce tuples of the assigned
  variables; original names recorded for codegen); early `return`/`?` move the
  rest of the block into the non-returning branch; `&&`/`||` short-circuit;
  or-patterns with guards are expanded into consecutive arms `p₁ if g => e;
  p₂ if g => e; …` (rustc semantics) before pattern compilation; every partial
  operation gets its proof from the prover.
* `f::ensures : Π(T..)(x..)(h : P..). Q[x, f x h]` (hypotheses relevant:
  lemma-like definitions are only used in irrelevant positions), proven by
  walking the body: at each tail value `v` the prover proves `Q[x, v]` in that
  branch's context; branches combine with the same dependent matches; `Delta`
  unfolds recursive `f`; recursive calls get facts from recursive calls to
  `f::ensures`.

### 7.4 Loops (normative desugaring)

`for i in a..b { B }` ≡ `if a < b { f::loop#k(a, mutated.., read..) } else {
mutated.. }`; the helper has parameters `i`, all variables mutated in the loop
and all variables read; requires: `a ≤ i < b`, user invariants, and all facts
in scope at the loop head about read variables; body: `B`, then `if i + 1 < b
{ rec(i + 1, ..) } else { mutated' }`; measure `b − i`; ensures: user
invariants. **Nothing** is asserted after the loop about `a` and `b`. `a..=b`
adds a `done: bool` parameter mirroring `RangeInclusive` (measure `(b − i) +
(done ? 0 : 1)`; no overflow at `b = MAX`). `while c { B }` with
`decreases(e)`: helper with requires = invariants (+ read facts), body `if c {
B; rec(..) } else { .. }`, ensures = invariants ∧ ¬c. Invariant entry and
preservation are obligations.

The helper's ensures is a lemma `f::loop#k::ensures : Π(params)(h :
requires). Inv[i := b][M := ret]` (for `a..=b` at `done`; for `while`, also
`¬c`). It is proven by walking the helper body: `ObligationKind::InvariantExit`
at the exit branch, the induction hypothesis at `rec`. The call site binds it
as an `Irr` fact, so the invariants hold after the loop. The helper returns
immediately when the range is empty, so the fact holds whenever `a ≤ b` and
survives the `if a < b` join. (SEMANTICS.md §18 is updated; the phase-2
implementation provided no post-loop facts.)

### 7.5 Patterns

Nested patterns compile to nested single-level core matches with first-match
semantics. Integer literal/range patterns compile to comparisons. Guards
compile to an `if` falling through to the remaining arms (after or-pattern
expansion). Slice patterns match on the list inside the slice.

### 7.6 Refinement for Σ-typed and struct variables

A match (exec or script) whose scrutinee is a **variable** `s` of slice, array
or struct type η-expands `s` in the goal and facts, generalizes over the list
component (with its dependent irrelevant proof), matches on it, and rebuilds
the pieces in each arm (e.g. the tail slice `(n − 1, t, p')` with `p'` from
`len t < len (Cons h t) ≤ MAX`). Every arm's goal then mentions the
constructor form and computes.

### 7.7 Derived `PartialEq`

For a user type deriving `PartialEq`, define `T::eq` structurally and prove
`T::eq_sound : eq(a, b) = true → a = b` and `T::eq_complete`. Arrays and
slices use prelude list equality with its lemmas. These are registered with
automation.

---------------------------------------------------------------------------

## 8. Automation, optimization, codegen

### 8.1 `auto` (untrusted, proof-producing)

Input: `Goal` (context, facts, target, hints), budget. Output: a kernel term or
an `AutoFailure`. Steps iterated to a fixpoint within the budget:

1. Normalize target and facts (unfolding policy).
2. Close by conversion (`refl`), by a fact, `Unit`.
3. Goal connectives: split ∧ (dependent), intro →/∀, ∨ by trying each side,
   `exists` by unification against facts (or `Witness` hints).
4. Fact saturation: split ∧ and short-circuit-`&&` facts (`match a {false =>
   false, true => b} == true` ⇒ `a == true`, `b == true`), `!b == true` ⇒ `b ==
   false`, constructor injectivity, `eq_sound` lemmas, method facts, registered
   simp lemmas.
5. Contradictions: constructor clash, `Empty` fact, linarith infeasibility;
   for a fact `¬P`, try to prove `P` (bounded) and derive `Empty`;
   `¬Eq(IntTy, a, b)` becomes the case split `a < b ∨ a > b` when needed.
6. Rewriting with facts `t == v` where `t` is stuck (via transport and
   `abstract_occurrences`), then renormalize.
7. **Axiom instantiation** for atoms headed by `min, max, sat_sub, sat_add,
   div, rem, wshr, wshl, and, or, cast, count_ones`; piecewise ones become case
   splits on their comparison.
8. **Arithmetic decision** of stuck comparisons in target and facts by
   linarith, rewriting them to `true`/`false`.
9. **Arithmetic congruence:** when an equality fails to convert only because
   integer arguments of the same head differ, prove each argument equality by
   linarith and close by congruence; normalize maximal machine-integer
   subterms to canonical linear forms.
10. `Delta` unfolding of stuck recursive applications when that unblocks a
    match whose scrutinee then becomes decidable.
11. Case split (bounded depth) on stuck `Bool`/inductive scrutinees in target
    or facts, with equations; **finite enumeration** of an integer variable
    whose proven range has ≤ 64 values when that makes the goal compute.
12. `BvRefl` for equalities of machine-integer/array terms that are
    convertible modulo word algebra.
13. linarith search (Fourier–Motzkin or simplex; exact rationals) producing a
    §5.8 certificate.

### 8.2 Optimizer (always runs, untrusted, results kernel-checked)

"Always on" means every exec function goes through the optimizer on every build, and there is no flag to disable it. Each function gets exactly one result, `Specialized { link, rung }` or `Unspecialized(reason)`, recorded in the report. If the untrusted optimizer fails, runs out of budget, or produces a candidate the kernel rejects, the build **emits a warning** and uses the next weaker candidate, and finally the proven unspecialized definition. Soundness never depends on the optimizer. The test suite runs with `SANDBLASTER_STRICT_OPT=1`, which turns such warnings into errors. A residual whose obligations the provers do not re-prove, with no counterexample found by a bounded search, is a proven fallback recorded in the report, not a warning (the proof search is incomplete); a counterexample, a type error or a kernel rejection is an optimizer fault. `#[specialize]` turns a failure to specialize that function into a build error that prints the first failed step. `#[specialize(loop_free)]` also requires a residual without loops. Use both on hot paths.

1. **Summaries, bottom-up.**
   * In callee-first order, each function `f` gets one summary:
     - a residual `r_f`;
     - its **link** to `f`;
     - exported fact lemmas (`Π x̄ h̄. P(x̄, f x̄ h̄)`);
     - an all-path decision tree;
     - a parallel skeleton;
     - a cost per variant set.
   * Callers use a callee's summary and never re-drive its body. They either keep the call, inline `r_f` through its link, or instantiate its tree.
   * Driving runs once per function, on the portable meaning. Only selection (item 6) and tier-0 re-specialization of clones run per variant set.
2. **Tier 0 (straight-line).**
   * Array parameters `[T; N]` (literal N ≤ 256) are spine-expanded (§5.9).
   * Summarized callees, builtin exec methods and intrinsics (§5.6) are opaque heads unless their residual is below the inline threshold.
   * A **stuck-free** value is residualized with sharing, its proof slots are re-proven, and it is admitted with `check_residual_equal` (link: conversion). Stuck-free means it contains only primitives, constructors, literals, lets, `index(fst p, lit)`, opaque calls and neutral intrinsic applications.
3. **Tier 1 (driving).** Otherwise a driver (online partial evaluation on `eval_opaque`) builds a process graph:
   * **Entry.** Arrays and non-recursive single-constructor parameters are η-expanded. `requires` clauses become facts.
   * **Unfolding** is the driver's choice, justified by `Delta`.
     - A recursive application unfolds when its measure evaluates to a literal or its structural argument is a closed spine, within the unroll budget.
     - It also unfolds while a homeomorphic-embedding whistle stays silent.
     - Otherwise the driver generalizes (most specific generalization) and folds. Candidate invariants are kept only if they are proven at entry and on every back-edge.
     - A back-edge folds only into the nearest unfolding of the **same** global, so there is no mutual recursion. The residual keeps the source measure.
   * **Stuck matches.** A stuck match on a neutral scrutinee is handled in one of four ways:
     - **reused**, from an earlier split;
     - **pruned**, by linarith on the path facts;
     - **merged** into a select, when both arms are total, cheap and free of partial operations. On `Secret` data the merge is mandatory and goes through the `ct_select` template;
     - **split** into a residual match whose arms carry their path equation.

     `ne … true` and `eq … false` facts are split on demand and never given to linarith.
   * **Callee results.** A match on a summarized callee's result is pushed into the callee's leaves (case-of-case), and leaves that the continuation's facts contradict are pruned. A call with static arguments or branch-deciding facts gets a polyvariant specialization, at most 8 per callee.
   * **At stuck points** the driver consults three summarizers:
     - **Loops.** One-iteration symbolic execution gives recurrence classes, and closed forms are synthesized from traces. The rungs, strongest first, are: closed form, early exit, idle skip, set-bit iteration, residual loop.
       As built: a user loop or `for`-loop helper with a literal trip count (2–64) and machine-integer state goes to the loop summarizer first. Traces start from the checked-in `PROFILE.json` (written by `sandblaster profile`). A closed form is proven by K+1 per-literal lemmas and emitted as an inlined helper with a stable summary lemma (QMDB `shape`: `rung = ClosedForm`). Early exit (with an idle skip at entry only) and set-bit iteration are the certified fallbacks. A summary's facts become kernel-checked fact lemmas (`<f>::fact#k`) that callers' decisions and re-proofs use. A callee's early-return check that those facts decide is dropped at the call through a guard helper `g__g<n>` with its own equality lemma.
     - **Sequences.** A normal form over take/drop/append/update/replicate/`copy_range` with clamped `Int` lengths. Consumers are driven over segments, and unread segments, dead initialization and copies disappear.
       As built: pieces `Seg`/`Elem`/`Rep`, each rewrite an instance of a `lemmas/seq.core` lemma. A call on an assembled buffer becomes the callee on a sub-slice, or a per-shape helper `f__seg<k>` driven like any function and linked by its own lemma. A piece the facts do not decide becomes the residual's own length test. QMDB's 62-digest peak buffer is gone. Not built yet: the SP1/SP2 templates, known-zero propagation and the scan demand.
     - **Algebra.** `bvnorm`; GF(2)-linear maps lowered to table or affine forms; reflective RingRefl; implementations that refine one spec; `#[rewrite]` laws.
4. **Admission by lemma.**
   * A residual with control flow or recursion is committed with `add_def` (kernel-checked, recursion mode included) together with `r_f::equiv : Π x̄ (h̄ :Irr Req_f). Eq(R, r_f x̄ h̄, f x̄ h̄)` (link: lemma).
   * The lemma is built from the process graph:
     - `Delta` for each unfolding;
     - dependent matches with path equations for each split;
     - transport along `Linarith` certificates for each prune or refinement;
     - lemma instances for each summary, fact or law;
     - `Rec`, with the source measure's decrease proof, for each fold;
     - `BvRefl` for word leaves, at most 2·10^5 canonical entries per call;
     - for a literal fuel K, K+1 non-recursive per-literal lemmas.
   * Bit-count facts come from the definitional axioms of §5.10.
   * New helpers carry their own lemmas. Every function that replaces a source function has a plain equality to it.
   * Code that changes representation (lazy reduction, SIMD limb layouts) exists only in helpers inside a region whose boundary function is plainly equal.
   * `check_residual_equal` is unchanged.
5. **Residual code.**
   * Lets are scoped to arms.
   * A partial operation is placed only where the path facts imply its domain, checked at extraction. Its proof slot is re-proven by `elab::generated::resume`.
   * Arithmetic whose overflow freedom is not locally provable is emitted in wrapping form and justified by the link.
   * An array value that evaluation produced as an element spine prints as the buffer it was built as when that is clearly better: a zeroed local filled by `copy_from_slice` from an array variable's range, an integer's `to_be_bytes`/`to_le_bytes`, and single stores. It elaborates back to the same spine, so the link is unchanged.
   * Printing follows §8.3, with checked arithmetic printed through `__rt::chk`.
6. **Selection.**
   * Per variant set, the candidates are:
     - the ladder rungs;
     - straight-line alternatives from an acyclic e-graph over kernel-checked rules and `bvnorm` classes;
     - feature-gated lowerings.
   * A target cost model ranks them. Its inputs are latency/throughput tables, a critical-path weight, trip counts, branch probabilities from the checked-in `PROFILE.json`, and code size. x86 constants come from host-kit tuning evidence, which changes choices only.
   * A candidate replaces the next rung only if it is ≥ 3% cheaper. The top three are kept, and at most two retries follow a proof failure.
   * As built (plan O8): tables per level (x86 v1, v3-scalar, v4; aarch64) and microarchitecture, in milli-cycles, measured where a committed tuning file (`sandblaster/targets/evidence/tuning-*.json`: Zen 5, M5) supplies them and hypotheses otherwise; cost `(critical path + Σ throughput)/2`, the worst over a set's microarchitectures. The aegraph runs on straight-line tier-0 residuals, matches kernel-checked rules (`lemmas/rules/*.core`, written by the offline `sandblaster-rulegen`) modulo `bvnorm`, and admits a rewrite by a transport-chain lemma (rung `Rewritten`; corpus P3 becomes `count_ones`). The loop summarizer orders its rungs by cost. The tuning hash and `PROFILE.json` key the proof cache.
7. **Multiversioning** (§9.3).
   * Whole call trees are cloned per hardware variant set, selected per set, and dispatched once at the boundary. A residual's clone is linked by `clone_equiv`.
   * Feature-only sets (x86 `popcnt, lzcnt, bmi1, bmi2`; aarch64 `cssc`) use only primitives and need no model evidence. They are dispatched only after a known-answer self-test.
   * As built (plan O8): x86 `v3_scalar`, `v4` (with the SHA-NI variant) and SHA-NI combined with `v3_scalar`, at most four sets, cloned from the bit-sensitive functions to the boundary and kept only where a clone is ≥ 3% cheaper; no aarch64 `cssc` set (rustc 1.98.1 rejects the feature, decision D2). The run-time detection of every set is `features && kat_<set>()`, cached, so the self-test (§15.13) runs once per process and the hot path is unchanged; a statically enabled set has no run-time decision.
8. **Proven bounds-check elimination** (unconditional). Every index or range operation in the optimized core carries a checked proof, so codegen prints `get_unchecked` forms (§8.3).
9. **Parallelism** (§9.4, §13.4).
   * Independent work is mapped innermost first to ILP (fusion, k ≤ k_sat), then lanes, then threads. Independent work here means antichains, maps, reductions with proven `Assoc`/`Id`, searches, trees, and state-decoupled recursions.
   * Lanes use the lane functor: one lanewise lemma per intrinsic model.
   * Threads need an execution context:
     - opt-in `f_with(exec, …)` entry points whose kernel meaning ignores the context;
     - fixed templates that validate tile indices and combine in index order, so the executor itself is untrusted;
     - a guard between two proven-equal versions.
   * Work below the thread threshold never gets threads.
10. **Determinism and budgets.**
    * All budgets count steps or nodes. Maps are ordered, seeds are content hashes, and costs are fixed-point.
    * The wall-clock deadlines of the optimizer's searches (the driver's run, the proof builder, each decision) and the memory limits are the §15.8 safety nets, set well above these budgets. A search they stop would fall back to a weaker candidate, so a trip is never a result: it fails the build with `error[resource]` (`driver::resource_gate`, after elaboration and again after the optimizer), and nothing is emitted.
    * The output is a function of the source, the variant set, the options, `PROFILE.json`, the tuning evidence and the optimizer version.
    * A content-addressed cache under `target/` holds hints only, and the kernel re-checks every hit.

Full design, research and judges' scores: `docs/optimizer-design.md`; milestones O1–O20: `docs/optimizer-plan.md`.

### 8.3 Codegen and round trip

* The printer emits a **canonical dialect** from the optimized core / HIR (not
  from source text): absolute paths (`crate::…`, `::core::option::Option::None`),
  every local renamed to a fresh non-colliding name (original name kept as a
  suffix), every literal suffixed, methods in UFCS (`<u32>::rotate_right(x,
  7u32)`, `<[u8]>::len(s)`), explicit `&`/`*` and reference patterns,
  or-patterns expanded, guards desugared, `&&`/`||` printed only from the
  canonical short-circuit shape, loops printed from loop helpers in their
  canonical `for`/`while` shape, tail-recursive functions printed as a
  canonical `loop { … continue … return … }` (the only place `loop`/`continue`
  appear), index operations as `unsafe { *<[T]>::get_unchecked(s, i) }` (and
  range/array forms) with `// SAFETY:` naming the obligation, calls to
  `requires`-functions in `unsafe {}` blocks, intrinsic calls, load/store
  helpers, dispatchers, and constant vectors (as `const` items).
* **Round trip:** parse the printed file, elaborate it in *generated mode* (the
  canonical dialect plus `get_unchecked`, `unsafe fn`, canonical `loop`,
  intrinsic calls; proof slots are `Erased`), and require every re-elaborated
  definition (including loop helpers and variants, matched by deterministic
  names) to be **α-equivalent in all relevant positions**
  (`alpha_eq_relevant`) to the optimized core definition. This is syntactic:
  hoisting an unchecked read out of its guard, dropping or duplicating an
  operation, or any evaluation-level rewrite fails it. Because the relevant
  structure is identical, the kernel-checked proofs of the optimized core
  justify every unchecked operation in the printed code. Trusted glue
  (dispatchers, load/store helpers) is emitted from fixed templates and
  excluded from the round trip.
* A round-trip mismatch is a build error (a printer or elaborator bug).

---------------------------------------------------------------------------

## 9. Hardware, SIMD and number layout (first-class)

The fastest production code in `~/code/monorepo` is hardware-shaped:
interleaved SHA2/SHA-NI kernels for the fixed MMR node shapes (72-byte `pos ‖
left ‖ right`, 64-byte `left ‖ right`) with fixed padding blocks, AVX-512
16-lane multi-buffer SHA-256, NEON/AVX2/SSSE3 Reed–Solomon engines,
NEON/AVX-512 curve25519. sandblaster must reach that level **with proofs**, so
the machine is part of the semantics from day one. Measured on this machine
(Apple M5 Pro, rustc 1.98.1 -O3; `docs/review-1.md`): one 64-byte SHA-256
(two blocks) takes 305 ns looped portable, 208 ns specialized/unrolled
portable, **49 ns with ARMv8 SHA2 intrinsics** — hardware is the main path,
not an afterthought.

### 9.1 Three levels of description

1. **Meaning** — numbers are mathematical (`Int`, ℤ/2^w, ℤ/p via spec
   functions, bit-vectors); algorithms are written over them (portable,
   scalar, the reference).
2. **Data parallelism** — `Lanes<T, N>`: portable vectors, semantics `Array(T,
   N)` with lane-wise operations (wrapping `+`, `^ & | !`, rotates, shifts,
   comparisons → masks, `select`, `shuffle::<IDX>`, `splat`,
   `from_array/to_array`, horizontal reductions). Lowered per function feature
   set to NEON / AVX2 / AVX-512 or to scalar loops.
3. **Machine** — target intrinsics with formal models (§9.2).

Every step down a level is a **refinement proven by the kernel**: a hardware
kernel equals its portable reference (§9.3); a `Lanes` lowering equals the
lane semantics; a number layout represents the mathematical value (§9.6).

### 9.2 Target semantics library (TCB)

`sandblaster/targets/` holds, per intrinsic, an executable Rust reference
model (`src/{aarch64,x86_64}/`), its registry entry (features, Rust path,
immediate ranges; `src/registry.rs`), its hardware-validation evidence
(`evidence/<arch>.json`, keyed by a hash of the model source), and — from phase
3 — its core-text transcription (`core/<arch>.core`), a `DefKind::Intrinsic`
global whose body is the same **lane-level** transcription of the vendor
pseudocode (Arm ARM, Intel SDM). The front end loads the core text; a test
cross-checks the core-text model (kernel evaluator) against the executable
model on random inputs, so the chain hardware ↔ Rust model ↔ kernel model is
tested end to end. `MODELS.md` there is the normative math.

* **Vector representation.** NEON typed vectors (`uint32x4_t`, `uint8x16_t`,
  `uint64x2_t`, `uint8x8_t`, `uint32x2_t`) are `Array(T, N)` of lanes, lane 0 at
  the lowest address. x86 `__m128i/__m256i/__m512i` are canonically
  `Array(U8, 16/32/64)` little-endian, with typed views `view_u32(v)[i] =
  from_le_bytes(v[4i..4i+4])` (the §5.7 byte simplifications keep chains of
  `epi32` operations as clean `u32` terms). Masks: `Array(Bool, N)`; AVX-512
  `__mmask8/16` are `u8/u16` with bit i for lane i. The kernel has no
  u128/u256; bit-level pseudocode such as Arm `ROL(Y:X, 32)` is transcribed at
  lane level: `(X', Y') = ([Y3, X0, X1, X2], [X3, Y0, Y1, Y2])`.
* **Immediates** are literal arguments; stdarch's `const IMM: i32` generics are
  allowed as literals (range-checked like rustc). Vector constants come from
  prelude constructors over unsigned arrays (`m128i_from_u32x4([u32; 4])`,
  printed as `const` loads).
* **Loads/stores** are generated helpers (trusted glue):
  `#[target_feature(enable = F)] #[inline] fn load_u8x16(a: &[u8; 16]) ->
  uint8x16_t { unsafe { vld1q_u8(a.as_ptr()) } }`, unaligned only, so call sites
  are safe and rustc re-checks the feature rule. User code never touches raw
  pointers.
* **Initial coverage:** aarch64: `vld1q_u8/u32`, `vld1_u8`, `vst1q_u8/u32`,
  `vrev32q_u8`, `vreinterpretq_{u32_u8,u8_u32}`, `vaddq_u32`, `veorq`, `vandq`,
  `vorrq`, `vshlq_n/vshrq_n`, `vextq`, `vdupq_n_u32`, `vgetq_lane/vsetq_lane`,
  SHA2 `vsha256hq_u32`, `vsha256h2q_u32`, `vsha256su0q_u32`,
  `vsha256su1q_u32` (note: `vsha256h2q_u32(efgh, abcd, wk)` takes the
  **pre-update** `abcd`, argument order reversed w.r.t. the pseudocode);
  x86_64: `_mm_loadu/_mm_storeu_si128`, `_mm_shuffle_epi8`,
  `_mm_shuffle_epi32::<imm>`, `_mm_alignr_epi8::<imm>`,
  `_mm_blend_epi16::<imm>`, `_mm_add_epi32`, SHA-NI `_mm_sha256rnds2_epu32`,
  `_mm_sha256msg1_epu32`, `_mm_sha256msg2_epu32`; AVX2/AVX-512 integer lane
  ops (for `Lanes` lowering and 16-lane multi-buffer SHA-256, later).
  Semantics of the SHA instructions are spelled out in `docs/review-1.md`
  (hardware lens) and must be transcribed from the vendor pseudocode.
* **Validation (fail closed):** for each model, an executable Rust version is
  generated and compared against the real intrinsic on ≥ 10^7 random inputs
  plus corner values (0, ~0, 0x8000_0000, single-bit words), every immediate
  tested exhaustively; a sample is cross-checked against the kernel evaluator.
  Evidence (hash of the model × hardware) is recorded in the repo; the
  dispatcher never selects a variant whose models lack evidence for that
  architecture. On this machine: aarch64 NEON/SHA2 validated natively; x86
  SSE ≤ 4.2/AES/PCLMUL under Rosetta; SHA-NI and AVX-512 need real x86
  hardware (CI). Constant-folding a model at compile time is safe even for an
  unvalidated model (the proof is about the model); only instructions that
  remain in emitted code need evidence.
* Out of scope for v1: SVE/SME (unstable/absent intrinsics; this M5 has no
  FEAT_SME_FA64, so NEON/SHA2 are illegal in streaming mode), big-endian
  targets (variants are gated `#[cfg(target_endian = "little")]`).

### 9.3 Target features, variants, dispatch

* **Feature set** of a function = the implication closure (rustc's table:
  `sha2 → neon`, `sha3 → sha2`, `aes → neon`, `sha → sse2`, `avx2 → avx →
  sse4.2 → …`) of **its own** `#[target_feature]` attribute. Static target
  features do not count (rustc 1.98 requires the attribute for safe intrinsic
  calls). Intrinsics may only be called where their features are in the set;
  calling a feature function from a function without those features is
  allowed only in generated dispatch glue.
* **Variants:** `#[implements(crate::sha256::compress)]` on a
  `#[target_feature]` function marks it as an implementation of a portable
  function with the same signature. Obligation (`VariantEquiv`,
  kernel-checked): `∀ x. requires_portable(x) → variant(x) == portable(x)`,
  proven by symbolic execution of both sides (intrinsics unfolded, array eta)
  and `BvRefl` (§9.8), whole-function or compositionally (a lemma per 4-round
  group, `vsha256hq(abcd, efgh, wk) == pack_abcd(rounds4(unpack(abcd, efgh),
  wk))`, keeps terms small).
* **Multiversioned call trees:** the optimizer clones each call chain that
  reaches a function with variants (fixed-shape hashes → merkle → verify) once
  per variant set, attaches the feature attribute to every clone, specializes
  per variant (so constant padding blocks reach the intrinsic models), and
  dispatches **once at the boundary** (`verify` → `verify__sha2` /
  `verify__shani` / `verify__portable`). Each clone is equal to the portable
  one by the same conversion argument.
* **Dispatch glue** (trusted, templated): features statically enabled in
  `CARGO_CFG_TARGET_FEATURE` → a direct `cfg`'d call (on `aarch64-apple-darwin`
  `sha2` is static, so dispatch is free); otherwise runtime detection
  (`std::arch::is_aarch64_feature_detected!`/`is_x86_feature_detected!`) cached
  in an atomic state enum whose zero value means "uninitialized → detect" and
  never selects a variant by default. Variants are gated by
  `#[cfg(target_arch)]` and `#[cfg(target_endian = "little")]`. `no_std`: only
  static paths.

### 9.4 Lane lifting and call fusion (later milestone, designed now)

* **Call fusion:** independent calls `(f(a), f(b))` in one block become a fused
  straight-line body (proof: by computation); LLVM interleaves them. This is
  the monorepo's `hash_pair_72/64` (two latency-bound SHA streams).
* **Lane lifting (SPMD):** `f_xN : Lanes-of-A → Lanes-of-B` with `∀ i < N.
  f_xN(xs)[i] == f(xs[i])`. Uniform control flow lifts lane-wise. Data-dependent
  branches evaluate both arms and `select`; lifting happens **before**
  bounds-check elimination, inactive lanes use masked/total accesses (never
  `get_unchecked` justified by an arm's path condition), totalization is
  transitive through callees, loops in arms run `while any(active)` with frozen
  inactive state (measure Σ active_i·m_i), non-tail recursion is rejected,
  enums get a structure-of-arrays tag + payload layout. A per-target cost model
  decides (e.g. on this M5 a 4-lane NEON SHA-256 loses to the SHA2
  instructions; on AVX-512 x86 a 16-lane software SHA wins for batches ≥ 7).
  Codegen patterns: ≤ 3-atom truth tables → `vpternlogd imm` (0x96 xor3, 0xca
  Ch, 0xe8 Maj), rotations → `vprord`.

### 9.5 Specializing hardware kernels

Partial evaluation keeps intrinsics opaque on symbolic data and evaluates
their models on closed data. Preconditions: intrinsics opaque unless constant
(§5.6); array eta (§5.9); padding blocks built from literals at constant
indices (type-level length, never `msg.len()` of a slice); dispatch happens
before specialization (§9.3); `K` is a `const`; vector literals printable.
Then for a 64-byte message the padding block's schedule (`sha256su0/su1`
outputs) and every `W + K` vector fold to constants. For 72/73-byte messages
the second block has symbolic `W0/W1`, so only ≈ 2 of 12 schedule steps and a
few `W + K` fold; mixed vectors stay intrinsic calls. (The monorepo x86 tail0
already uses a precomputed `FINAL_64_WK`; the aarch64 tail0 and both tail8
kernels recompute the schedule.) Expected: 1.2–1.4× single-stream vs the `sha2`
crate's aarch64 backend at 64/72/73 bytes (block-buffer/finalize overhead
removed, schedule off the critical path); 0–20% vs the monorepo aarch64 tail0
on 64-byte pairs (once call fusion exists); ≤ 5% at 72/73 bytes. Measure,
don't assume (§11.4).

### 9.6 Numbers laid out for SIMD (representation refinement)

The spec of arithmetic is mathematical (`Int`, ℤ/p); a **layout** is a
refinement: `decode : Repr → Int` (e.g. 5 limbs of radix 2^51 in `u64` lanes,
10 limbs of radix 2^25.5 in `u32` lanes of a NEON register, a bit-sliced layout
of 64 instances), per-limb bound invariants, and operations whose correctness
is `inv(a) ∧ inv(b) → inv(op a b) ∧ decode(op a b) ≡ spec(decode a, decode b)
(mod p)`. Bounds are tracked by linarith (+ `mul_mono`); carries are placed
where the bound analysis says a lane could otherwise overflow (lazy
reduction), which is what makes limb arithmetic lane-parallel. This is
fiat-crypto's bound-driven synthesis combined with Halide's algorithm/schedule
split, targeting SIMD layouts.

**v1 mechanisms (so this is not an afterthought):** bignum `Int` in the kernel
(done in §5.1); a `RingRefl`/`linear_combination` certificate (planned kernel
extension: `Eq(Int, a, b)` accepted when `a − b − Σ cᵢ·(lhsᵢ − rhsᵢ)` normalizes
to 0 as a polynomial over ℤ with atoms; congruence mod p by an explicit
witness) reusing bvnorm's sum machinery; a widening multiply (`mul_wide_u64(a,
b) -> (u64, u64)` prim, printed as `(a as u128) * (b as u128)`), NEON
`vmull_u32/vmlal_u32` and AVX-512 IFMA models; `#[view(decode)]` and
`#[invariant(inv)]` on repr types (§15.3), with `#[refines(spec::op)]` on each
operation against a spec over canonical residues, so `≡ (mod p)` becomes `==`
on views (`#[refines]` on a type is an error). v2: carry-placement
and layout synthesis for field arithmetic (curve25519, Reed–Solomon kernels).

### 9.7 What QMDB uses

* `sha256::compress(state: [u32; 8], block: &[u8; 64]) -> [u32; 8]` — portable
  reference (FIPS 180-4 formulation), fixed-size inputs (no slice + offset).
* `sha256::compress_sha2` — `#[target_feature(enable = "sha2")]`,
  `#[implements(compress)]`, aarch64 SHA2 intrinsics, proven.
* `sha256::compress_shani` — `#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]`,
  `#[implements(compress)]`, proven; compiled for `x86_64-apple-darwin`; not
  dispatched until its models have x86 evidence.
* Fixed-shape hash wrappers (leaf 73 B, node 72 B, fold 64 B, graft 33 B,
  seal 40/48 B, canonical 64/104 B, chunk 1 B) specialized per variant, with
  `verify` multiversioned and dispatched once.
* Single-proof verification is a dependent hash chain: lanes/fusion only pay
  off for a batch API (`verify_many`, later).

### 9.8 Word algebra: `BvRefl` and `bvnorm` (TCB)

`BvRefl { ty, lhs, rhs } : Eq(ty, lhs, rhs)` is accepted iff `lhs` and `rhs` are
equal modulo word algebra, decided by one **bottom-up pass over both DAGs** in
topological order with hash-consing: every node is normalized with its
children replaced by class ids (union-find), its canonical key is interned to a
class id, atoms are ordered by class id; the two roots must land in the same
class. Intrinsics are unfolded, arrays eta-expanded. Successes and failures are
memoized. Rules (exact identities; applied in this order per node):

1. Constant-fold every total primitive; reduce shift/rotation amounts mod w
   (`rotr(x, 0) → x`, `rotl(x, k) → rotr(x, w − k)`).
2. `not(x) → x ^ ALL_ONES`.
3. **GF(2)-linear xor sets:** an xor node is a set of terms `(atom, rotation r,
   mask m)` plus a constant; `rotr(x, r)` contributes `(x, r, ~0)`,
   `wshr(x, s)` contributes `(x, s, ~0 >> s)` expressed as a rotation plus
   mask, `wshl(x, s)` `(x, w − s, ~0 << s)`; rotations/shifts distribute over
   xor (shifting constants too); group by `(atom, r)`, xor the masks, drop zero
   masks. (Shifts do **not** distribute over `not` except through rule 2.)
4. `and`/`or` sets: sorted by class id, idempotent, `x & 0 = 0`, `x & ~0 = x`,
   `x | 0 = x`, `x | ~0 = ~0`.
5. Pure bitwise subterms (`and/or/xor` after rule 2, no shifts, constants only
   0/~0) with ≤ 4 distinct atoms → a truth-table canonical form (e.g. Ch:
   `(e & f) ^ (!e & g)` ≡ `((f ^ g) & e) ^ g`; Maj: xor-of-ands ≡ `(x & y) | ((x
   | y) & z)`).
6. **Sums:** `wadd/wsub/wneg`, `wmul` by a literal, `wshl(x, k)` as coefficient
   `2^k` → canonical sum (constant + map class id → coefficient mod 2^w),
   flattened through child sums. `wshr`, `rotr` and zero-extension never enter
   or distribute over sums; truncation passes through sums (ring
   homomorphism).
7. **Bit-slice concatenation:** a word is an ordered list of segments
   `(hi, lo, atom, offset)` and constant segments; known-zero masks are
   tracked (`cast_u8_u32(x)` has mask 0xFF, `<< k` shifts the mask, …);
   `|`, `^` or `+` merge into a concatenation only when the masks are provably
   disjoint; adjacent segments of the same atom at consecutive offsets merge
   (so the four bytes of `x` in order become `x`, and `(x >> 2) | (x << 30)`
   becomes `rotr(x, 2)`).

**Tripwire:** before accepting, the kernel evaluates both sides on 32
pseudo-random valuations of the free atoms plus corner values (0, ~0, 1,
0x80…0) and rejects on any mismatch. **Testing:** exhaustive over U8 and U16
for 2-atom expressions from generators targeting known traps (`not` under
shifts, overlapping `|`/`^`, casts around sums), structured random tests at
u32/u64 with every shift amount. Expected cost for SHA-256 compress
equivalence: ≈ 16k canonical entries (portable) and ≈ 30–35k (Arm/Intel):
milliseconds. Long term: prove the normalizer by reflection (a prelude
function over an expression AST with `eval(norm e) = eval e`), making
`BvRefl` ordinary conversion.

---------------------------------------------------------------------------

## 10. Build integration, CLI, validation

### 10.1 Build

`sandblaster::build::compile(root)` — reads `CARGO_MANIFEST_DIR` and the
`CARGO_CFG_*` target variables, checks `src/lib.rs`, runs the **crate path**
(`driver::build_crate`: proofs, law audit, every §15.8 gate, optimizer,
printer, round trip, emission-chain check), writes `OUT_DIR/sandblaster.rs`
only for a crate verdict (always the report), prints
`cargo::rerun-if-changed` for every file read that exists (and the root's
lock once it exists; its directory is watched), and
exits 1 with diagnostics on failure. It takes no options.

`sandblaster::build::compile_module(root, module_file)` (module mode, §2.1) is
the same crate path for one verified module of an ordinary crate: it checks
the host's module file (exactly the `include!` of `OUT_DIR/<out>.rs`) and
that nothing else under `src/` includes the output, runs every proof and
gate, relocates the verdict's file (checked) and writes `OUT_DIR/<out>.rs`
and `<out>-report.json`; failures fail the host build. It takes no options
either.

### 10.2 CLI

`sandblaster check <dir>` runs the same crate path as the build and writes
nothing: a summary with each gate's outcome and the hash of the file the
build would emit; it is how a developer sees every gate's errors. `emit`
(the generated Rust), `report` (the JSON report), `spec` (the spec sheet),
`spec --accept` (every gate but the lock, then writes the lock) and
`coverage` (the gates, then an exploration run of the counterexample engine)
run it too. Only a crate verdict prints `VERIFIED` or exits 0. Two commands
are stage tools and never state a verdict: `sandblaster eval <dir> <fn>
<args-json>` (reference semantics: kernel evaluator; prints a value) and
`sandblaster spec --diff <rev>` (prints classifications).

### 10.3 Validation of the TCB (not optional in CI)

* **Differential corpus:** per construct of the canonical dialect, programs
  whose kernel evaluation is compared with the compiled Rust on many inputs.
* **Debug-profile oracle:** fixtures and fuzz inputs run against the *debug*
  build of the generated code and of the baseline (overflow checks and
  `get_unchecked` precondition checks abort loudly) and against the kernel
  evaluator. Any divergence or abort is a bug.
* **Target models:** §9.2 validation.
* **Kernel adversarial suite:** attempts to prove `Empty`, break relevance,
  sneak non-terminating recursion, forge certificates, exploit the memo
  (address reuse), exploit `bvnorm` (the unsound candidate rules listed in
  `docs/review-1.md` must be rejected).

### 10.4 Diagnostics

`file:line:col: error[kind]: message`, the goal and facts pretty-printed in
Rust-like syntax, and what automation tried. Spans are
`Span { file: FileId, lo: (u32, u32), hi: (u32, u32) }`; generated definitions
(`f::ensures`, loop helpers, variants) map back to the source span that
produced them.

---------------------------------------------------------------------------

## 11. The QMDB port

Source: `patrick-ogrady/qmdb-bend2` (Bend 2). Target: `qmdb/`.

### 11.1 API

```rust
pub type Digest = [u8; 32];
pub fn verify(root: &[u8], key: &[u8], value: &[u8], proof: &[u8]) -> bool;
pub fn verify_fixed(root: &Digest, key: &Digest, value: &Digest, proof: &[u8]) -> bool;
```

### 11.2 Porting rules

* Every Bend `Nat.sub` not dominated by a guard becomes `saturating_sub`
  (Bend's `Nat.sub` truncates; this matches exactly and has no obligation).
* Every Bend `Nat` gets the narrowest unsigned type: uint-decoded fields
  (`location`, `leaves`, `inactive`, `count`) are `u32` (the cap is exactly
  `u32::MAX`); shape fields are narrow (`height, before, after: u32`; widths and
  positions `u64`); arithmetic widens with `as u64`, so implicit type bounds
  discharge overflow obligations without extra `requires`.
* Spec functions are independent descriptions: they never call exec functions
  or read exec constants (§15.1 spec closure). A formula that a law and the
  code both need (`required_digests`) is written once in `spec::`, and the
  refinement proof connects it to the code; convertibility is not a goal. A
  spec that is α-equivalent to the code is reported (`spec-mirrors-impl`).
* Prefer `for` loops with literal bounds and `match` over nested `if`s so
  obligations stay linear; tail recursion where Bend recurses on lists (e.g.
  `fold_back` via `[init @ .., last]`); depth-bounded non-tail recursion only
  with a literal `max` (e.g. `path` with `height ≤ 64`, guarded by a defensive
  check returning `None` for impossible heights).
* Branch-free, fixed-size hash wrappers so specialization applies (§9.7).

### 11.3 Laws (LAWS.rs)

As built (2026-09-26, §15 S5): `sandblaster/fixtures/qmdb/sandblaster/LAWS.rs` holds the five laws
of `docs/qmdb-spec-design.md` verbatim, over `spec::` items only, and
`spec/tree.rs` the two tree laws they rest on; `PROOF.rs` proves them and the
refinements R1–R12 (about 15,400 lines, far above the 1,100 estimated; see
the design's "As built" section). Both instances build with every §15 gate
on. The 13 legacy laws are gone; `qmdb/README.md` maps each to where its
claim lives now. History: until S5 the laws were a one-to-one
transliteration of `LAWS.bend`. An audit (`docs/qmdb-spec-design.md` §1) found that 11 of its 13 laws and all 4
spec items restate the code or are representation noise, the rest are facts
about internal functions, and one-token bugs (a dropped graft, an MSB-first
activity bit, `MAX_LEAVES = 2^32`, `MAX_DIGESTS = 64`, swapped `fold`
arguments) pass all of them. They are replaced in §15 S5 by the five laws of
`docs/qmdb-spec-design.md`, over `spec::` items only — **complete** (honest
proofs from any database verify), **sound** (an accepted update is current at
the proof's location, or the walked trees contain an explicit SHA-256
collision), **unique** (one root and location admit one verifying proof, or a
collision), **canonical** (no malleable encodings), **bounded** (proof size) —
with `verify` and `verify_fixed` `#[refines(spec::proof::verify)]`. Bend's
laws survive only as `PROOF.rs` lemmas where proofs need them (the bagging
split behind R9). In addition, every exec function is proven total
and panic-free, and the hardware compression functions are proven equal to
the portable reference.

### 11.4 Tests, tools, benchmarks

* Host tests (normal Rust, outside the verified crate): every fixture and every
  mutation case from `tests.ts`, SHA-256 known-answer vectors from
  `hash_tests.bend`, hardware-vs-portable compress on random inputs — for both
  instances (`qmdb/fixtures` at N = 1, `qmdb/fixtures-n32` at N = 32).
* Differential test: kernel evaluator vs native on every fixture; debug-profile
  oracle.
* CLI `qmdb-cli run <fixture.json> [index]` with `run.ts`'s exit contract.
* Benchmarks: sandblaster (optimized, hardware) vs baseline (raw source, rustc)
  vs Commonware's verifier (sha2 soft/hw) vs the monorepo SIMD kernels
  (`hash_pair_72/64`) on node shapes vs Bend 2 (JS via bun, native C). Per hash
  and per verify, cold and hot, code size.
* **Production domain** (2026-09-24; `docs/prod-domain-plan.md`,
  `docs/prod-domain-reports.md`): the Bend limits D1 (2^32 leaves) and D2
  (N = 1) are gone. One set of sources builds two verified crates, `qmdb`
  (N = 32, production) and `qmdb-n1` (N = 1, the Bend configuration), from a
  per-crate `config` module (§14.2 `Config`); locations and leaf counts are
  canonical u64 ≤ 2^62, digests ≤ 122, 63-width shape search, 62 peaks.
  Both verified (887 obligations, 13 laws); 0 disagreements with Commonware
  over 12,776 corpus checks, 1.5M fuzz checks and 5M differential cases.
  Measured (qmdb/BENCHMARKS.md): on 20 production N = 32 workloads plus 18
  deep proofs (2^40, 2^62 − 1 including the 122-digest maximal proof, 2^62)
  the generated verifier takes 0.65–0.77× the time of Commonware's
  constant-N decode+verify and 0.88–1.00× the time of hand-written
  multiversioned code. At N = 1 it is 1.54× faster than Commonware
  (3fbd2e0e) but 8.5% slower than the pre-H1 code (≈ 24 ns per verify, from
  the 63-width `shape` search and the 62-entry peak buffer). Follow-up: a
  constant-time `shape` (leading-zeros/popcount lemmas, §14.3(6)) and
  copy-free bagging.

---------------------------------------------------------------------------

## 12. Implementation plan

**Phase 0 (done before fan-out):** this document; frozen `term.rs`,
`value.rs`, `api.rs`.

**Phase 1 (parallel):**
1. Kernel: all of §5 incl. bignum, core text syntax, prelude definitions
   (`.core`), linarith, axioms, adversarial suite. (`bvnorm` may land in phase
   3, behind the frozen `BvRefl` term.)
2. Native QMDB port in the subset (portable + `compress_sha2` intrinsics +
   `compress_shani` compile-only), host tests, CLI, benchmark harness,
   obligation inventory, exact `LAWS.rs` text and `PROOF.rs` skeleton.
3. Front end: loader, resolver, HIR (`hir.rs`), subset validator (run on the
   native port as it lands), builtins table, spans/diagnostics, canonical
   printer from HIR, macros crate, facade, `build.rs` skeleton (validate +
   print, no proofs yet).
4. Target semantics: executable Rust reference models of every needed
   intrinsic transcribed from vendor pseudocode, differential tests against
   hardware and evidence records; transcription to core text once the core
   syntax exists.

**Phase 1 — done** (reports in `docs/phase1-reports.md`): kernel (7.8k
lines, adversarial suite), front end (loader → resolver → typeck → validate →
HIR → canonical printer, `build.rs`/CLI in unverified mode), native QMDB port
(all fixtures, `tests.ts` mutations, KATs, Bend differential corpora;
`verify_sha2` estimate 315 ns vs Commonware 463 ns vs Bend 2 C 21.6 µs),
target models (23 aarch64 models hardware-validated, SSE under Rosetta,
SHA-NI pending hardware).

**Phase 2 (parallel):** (a) elaborator (HIR → core per §3.5/§7, obligations
through `prover.rs`, loops, `ensures`, derived `PartialEq`, spec/law/script
elaboration, verified `build.rs` pipeline, SEMANTICS.md); (b) `auto` + certificate
search + prelude lemmas (`sandblaster/front/lemmas/*.core`); (c) kernel
follow-ups: opaque definitions, `bvnorm` (§9.8) with tripwire and trap
tests; (d) target models → core text (`sandblaster/targets/core/`) with
kernel-vs-executable cross-checks. Goal: kernel-checked portable QMDB (all
obligations discharged).

**Phase 2 — done** (reports in `docs/phase2-reports.md`): elaborator (all 520
obligations of QMDB's portable exec code proven and kernel-checked; kernel
evaluation of `verify` agrees with native on all 32 fixtures; verified
`build.rs` pipeline; SEMANTICS.md), `auto` + lemma library, kernel opaque
definitions and `bvnorm` (ARMv8-shaped compress ≡ FIPS compress by `BvRefl`
in ~10 ms), all 38 target models in core text with kernel cross-checks.

**Phase 3 — done** (reports in `docs/phase3-reports.md`): `cargo build -p
qmdb` is VERIFIED + OPTIMIZED — 747 obligations and all 9 laws proven, 123
kernel-checked definitions, `compress_sha2 ≡ compress` proven by `BvRefl`
(18 ms) and statically dispatched, 48 functions specialized, 115 definitions
round-tripped, 6.2 s; the generated crate passes every baseline test suite;
generated `verify` ≈ 291 ns vs Commonware 465 ns. Kernel fixes and
`sandblaster/kernel/AUDIT.md`.

**Phase 4:** red team (kernel, fidelity, optimizer/codegen, proof-gate
integrity, differential fuzzing against Commonware), fixes, docs.

**Phase 4:** red team (kernel, fidelity, optimizer, hardware), fixes,
SEMANTICS.md, README, benchmarks and report.

Deferred until QMDB is green: dead-branch elimination, `#[rewrite]`, lane
lifting and call fusion, representation synthesis, user generics beyond `Copy`
parameters, advanced patterns beyond what QMDB needs.

---------------------------------------------------------------------------

## 13. Storage, networking and concurrency (stretch goal, designed now)

Goal: implement and prove real Commonware systems in sandblaster —
**journal → QMDB** and **p2p → Simplex** — with **zero runtime overhead**
relative to the hand-optimized Commonware code. Grounding:
`docs/effects-maps.md` (six maps of `~/code/monorepo` and prior art); review:
`docs/review-2-effects.md` (three adversarial lenses; this section is the
revised design).

### 13.1 Architecture: direct style in and out; the step function exists only in the proof

* Authors write actors the way Commonware does: `async fn`s over a runtime
  context `E: Storage + Clock + Network + Spawner + …`, `.await` on runtime
  calls, `select_loop!`/`select!`, mailboxes, `try_join!`.
* The elaborator derives, per async body, a **first-order interaction model**
  (defunctionalized: states are resume points + live variables, like rustc's
  async lowering) with **two kinds of transitions**: *yields* (awaits; the
  scheduler interleaves only there) and *synchronous effects* inside a segment
  (`Clock::current`, rng draws, `Sender::send`, mailbox `enqueue`, lock
  critical sections, §13.4). `step : (Resume, Response) → (Resume', Seq<SyncEff>,
  Option<AsyncEff>) | Return(v)`. Every segment is total sandblaster code, so the
  kernel only sees total functions over inductive data: **no kernel change in
  kind** (no coinduction, no async, no closures in the core).
* The derived items are nameable: `model!(path::f)::{Resume, step, pending,
  measure}` (`GlobalName::AsyncModel`). `measure : Resume → Int` is derived
  from `decreases` clauses of loops that span awaits, so non-actor async
  functions (e.g. recovery) run to completion by measure recursion; actor loops
  (`select_loop!`) get fuel.
* **Reduction theorem** (prelude, proven once, parametric in `step`): in a
  segment whose *IO shape* is "receive-like effects (responses, clock, rng,
  `try_recv`) before send-like effects (sends, enqueues)", sends are left
  movers, receives right movers, and effects on privately owned resources
  (§13.4) commute both ways; such a segment is one atomic system step. The
  elaborator checks the IO shape on the derived model.
* **Ghost state in exec and async bodies:** `#[ghost] let mut snap = ..;`
  lives in the live variables of the model, is erased by codegen, excluded from
  the §8.3 round trip, and volatile under crash — used for linearization
  points and abstraction snapshots.
* Codegen emits the **same direct-style async Rust**; the printer preserves
  source **binding and scope structure** inside async bodies (assignment stays
  assignment, scopes stay scopes) because rustc's coroutine layout depends on
  it (SSA-printing grew a probe future from 8195 to 12291 bytes); the round
  trip compares a binding/scope skeleton in addition to relevant structure.
* Runtime trait methods are **effects with trusted specs** (§13.3), validated
  with recorded evidence like intrinsics (§9.2). No new trusted *code* is
  emitted.

### 13.2 Language extensions (exec subset)

| Extension | Model (kernel) | Emitted Rust | Rules |
| --- | --- | --- | --- |
| `async fn`, `.await` | interaction model (§13.1) | unchanged | awaits on whitelisted effects / verified async fns / combinators below |
| `select!` / `select_loop!` / `Clock::timeout` / `Handle<T>` arms | nondeterministic choice among ready arms (bias is a refinement) | unchanged | **ownership-based cancellation rule**: a future may be dropped (lost arm, abort, `try_join!` error, timeout) only if every handle it owns or mutably borrows is dead afterwards in the model — Sink/Stream become poisoned, storage operations become *detached* (§13.3); signal arms only where control provably leaves the loop |
| `try_join!`, `try_join_all`, `join!`, abortable pools | **interleaving product** of the branches' models (a finite map of sub-machines); first `Err` detaches the siblings | unchanged | disjoint `&mut` splits (`split_at_mut`, `chunks_mut`) are separation: each branch owns its part; backward functions compose at join. Reads on one blob commute (read/write footprint modes) |
| owned non-`Copy` types, moves, `Box<T>`, `mem::{take, replace, swap}`, `Arc::make_mut`, `Arc::try_unwrap/into_inner`, `Weak::upgrade` | values; `Box` is identity; uniqueness-dependent calls are value-preserving oracles | unchanged | rustc guarantees uniqueness; lint on by-value async `self` above a size threshold (suggest `Box`: 18× measured) |
| `&mut` params, `&mut self`, **returned `&mut`** (`entry().or_insert_with`, `get_mut`, `iter_mut`, `last_mut`, …) | Aeneas state passing; returned borrows get **backward functions** applied where the borrow ends (rustc NLL delimits it), including through `?` | unchanged (in place) | the canonical dialect hoists calls with `&mut` operands out of assignment/index/receiver operands **in rustc's evaluation order** (RHS first for assignment and primitive `op=`, place first for overloaded `op=`) |
| **effect handles are linear** (`Blob`, `Sink`, `Stream`, `Signal`, `Receiver`, `Sender`, `oneshot::Sender`, `Handle`, `AbortOnDrop`, `SyncTicket`, and types containing them) | a handle is a resource; `drop(x)` is the effect (close / poison / cancel / release) | unchanged (explicit `drop` compiles to the same code) | no `Clone` of `Blob` in verified code; temporaries, `let _ =`, overwrite of a live handle and conditional moves are rejected; drop order at abort follows rustc's (edition 2024), differentially tested |
| **partition ownership tokens** | ghost token per storage partition, minted at init, owned by exactly one actor | erased | a name is opened only by the token holder and never while another handle is live; `try_join!` needs distinct tokens; a *fault* consumes the token |
| **shared state**: `Arc<Mutex<T>>`, `Arc<RwLock<T>>`, atomics | each critical section is one atomic transition on a ghost heap cell with a declared **lock invariant**; per-actor proofs use rely/guarantee over the cell | unchanged | no guard held across `.await` (syntactic + `!Send`); linearizability makes "interleaving at yields and critical-section boundaries" exact |
| collections `Vec`, `VecDeque`, `BTreeMap`, `BTreeSet`, `HashMap`, `HashSet` | comparator-parametric `Seq`/`FMap`/`FSet` (core text); relational specs for unspecified behaviour: `sort_unstable` ties, `binary_search` among duplicates (some matching index), **hash iteration = `perm(oracle, keys)`** quantified like the scheduler | std, unchanged | key types need lawful `Ord`/`Eq`/`Hash` (`Ord` total, `cmp == Equal ⇔` kernel equality, `Hash` consistent with `Eq`); derived impls discharge them |
| `#[derive(PartialOrd, Ord, Hash)]` | trusted lexicographic semantics (field order, variant index, arrays/slices), differentially tested | unchanged | user `impl`s must prove the laws |
| traits with laws (static dispatch only) | exec: monomorphized per instance; ghost generics: dictionary passing (curried Π binders), so generic lemmas are proven once | unchanged generics | no `dyn`; associated types/consts allowed |
| ghost `spec_fn(A..) -> B` types and predicate parameters | Π types | erased | for generic theorems (e.g. the crash-lift theorem) |
| closures passed to whitelisted adapters (`map/filter/fold/any/all/retain/sort_by_key/…`) | inlined at the call site | unchanged | `Fn` only (pure) for key/comparator adapters; non-escaping |
| `offload(strategy, f, args)` (CPU offload, e.g. batch signature verification) | returns `f(args)`; cancel-safe future | unchanged | `f` verified pure, moved args |
| `Receiver::try_recv`, parametric actor families (per-peer instances), dynamic spawn of verified actors | mailbox model; indexed actor sets | unchanged | needed by p2p (E6) |
| **`#[trusted_extern]` pure functions** (blst, crc-fast CRC32C, chacha20poly1305, sha2 `compress256`, ed25519) | core-text model; validation evidence keyed by model hash; fail closed | direct call | reference-model functions (CRC, FIPS compress, RFC 8439) are differentially tested against the executable model; signatures expose only the abstract interface used by §13.6 (named assumption), never a byte-level axiom |
| `Result<T, E>`, `?` on `Result`, signed integers | prelude inductive; `Int`-backed two's complement | unchanged | error classification §13.3 |

### 13.3 Effect models (trusted specs, validated)

World state and specs in core text (`sandblaster/kernel/prelude/effects/*.core`),
transcribed from the Commonware contracts (runtime/src/lib.rs) and shown to be
a **proven superset** of the deterministic runtime's executable reference
(runtime/src/storage/{memory,faulty}.rs) and of named real-filesystem
assumptions:

* **Storage/Blob: crash over the invocation/response history.** Every
  operation that has been *invoked* and is not covered by a completed sync of
  its generation contributes a crash set — including **in-flight** operations
  and **detached** ones (futures dropped by abort, `try_join!` error or
  timeout: they keep running until crash or exit). Crash sets: write → any
  subset of its bytes, durable length anywhere in `[durable_len, max_end]`,
  zero-filled; resize → any length between old and new; `remove(p, None)` → any
  subset of `p`'s blobs removed; `remove(p, Some(n))` → removed or not;
  `open`-create → absent or present with a torn header (handled by
  `header.rs`); `start_sync` → a cut whose success is undetermined until its
  ticket resolves; failed operations → the same sets as unsynced ones.
  `write_at(.., SYNC)` makes only its own range durable. Named real-FS
  assumptions: zero-fill (no stale blocks; ext4 `data=ordered`/XFS), no damage
  to neighbouring sectors, honest flushes; macOS tokio `sync` is `fsync`
  without `F_FULLFSYNC` (documented per backend).
* **Split-phase durability:** `start_sync(blob)` returns a linear
  `SyncTicket`; acceptance snapshots every write that completed before the
  call; awaiting the ticket merges that snapshot into durable; later writes
  stay in the unsynced relation. Tickets are cancel-safe, movable through
  mailboxes/oneshots, joinable; "a flush/resize waits for any outstanding
  ticket" is an obligation. Durability facts travel with tickets across actors.
* **Open/reopen:** `open` yields `live ∈ crash(state)` (covers memory.rs's
  durable-image reopen and tokio's page-cache reopen) with `durable`
  unchanged; "readable ⇒ durable" holds only for the first open after runtime
  start. `scan` returns a permutation of the name set.
* **Errors:** *semantic* errors (`PartitionMissing`, `BlobInsufficientLength`,
  version mismatch, …) are deterministic functions of the world and modeled
  exactly; where a backend masks faults (tokio maps every `remove_file` error
  to `BlobMissing`) the model says "absent ∨ fault" (and the upstream mapping
  should be fixed); *faults* consume the partition's ownership token, making
  "error = crash" a checked rule.
* **Clock:** `current()` is an arbitrary `SystemTime` (signed seconds +
  nanoseconds) per read; the prelude provides checked conversions and deadline
  arithmetic (the panicking helpers are not whitelisted). A sleep/timeout
  resolves at some later step and implies **nothing** about later `current()`
  reads in the safety model; timing hypotheses live only in the liveness layer.
* **Randomness:** oracle argument.
* **Mailboxes:** bounded ready queue + the verified overflow `Policy`'s state;
  `enqueue` returns `Ok | Backoff | Closed` and never waits; **`Ok` means
  accepted, not delivered** (dropping the receiver drains); FIFO is derived per
  policy as a lemma (a reordering/coalescing policy does not have it);
  `try_recv` is `Some` iff the ready queue is non-empty at that instant.
* **Network:** byte streams (`Sink`/`Stream`: ordered, may fail; errors and
  dropped futures poison the endpoint, a prefix may have been delivered) and
  the authenticated p2p service as a **sent-set** adversary (any previously
  sent message may be delivered any number of times in any order); channel
  authenticity is a named assumption.
* **Spawner/supervision/abort:** abort is a possible transition at every
  await point of every task; parent exit aborts children; `stop` completes when
  all stop guards are dropped (the `select_loop!` signal drops when the loop
  breaks — post-loop exit code is best effort in the model unless the verified
  `select_loop!` variant that keeps the guard alive is used).
* **Metrics** are ghost.

**Validation (fail closed, evidence keyed by model hash):** checkers are
**verified executable code**, not kernel evaluation: e.g. `crash_member(d:
&DiskModel, img: &DiskImage) -> bool` written in the exec subset with a
reflection law `crash_member(d, img) == true ⇔ exists(|o| crash_image(d, o) ==
img)`, emitted into a test-support crate and run natively inside the monorepo's
crash tests, fuzz targets and the deterministic runtime; an **adversarial model
storage backend** (driven by `ScriptedRng`) produces crash images FaultyStorage
cannot (partial `remove_dir_all`, trailing zeros, in-flight/detached writes) so
validation covers the model rather than just faulty.rs; real backends (tokio,
io_uring) are exercised with crash emulation before their evidence is
recorded. The claim is "tested by a checker proven equivalent to the spec".

### 13.4 Concurrency model

* Interleaving happens at **yields and critical-section boundaries**; every
  synchronous effect comes with a stated **mover** classification (left/right/
  both/non-mover) proven against its spec, so the §13.1 reduction theorem
  applies. This — not an assertion — justifies atomic segments on tokio's
  multi-threaded executor.
* Private resources (partitions via ownership tokens, linear handles) are what
  make most storage effects both-movers; shared state goes through locks
  (linearizable cells with invariants).
* The scheduler, clock, rng, hash iteration order and crash oracles are
  universally quantified; `select!` bias and real scheduling are refinements.
* `try_join!` is interleaving with detach-on-error (never "sequential"): e.g.
  a Merkle sync finishing before the journal's leaves the Merkle ahead after a
  crash, and recovery must handle it (Commonware's `Recovery::prepare`
  rewinds; an `align`-style check would be proven wrong).
* Data parallelism (`Strategy` fold/map/join) is specified as its sequential
  meaning with purity/associativity obligations.

### 13.5 Crash consistency

Every storage-owning component exposes its recovery as a (derived-model)
async function with a measure. Laws are stated over **prefix-closed
invocation histories** and **effect-step cuts**, with oracles as finite
sequences (`CrashOracle = Seq<Seq<bool>>`, `faults: Seq<Fault>`, defaulting when
exhausted) and named probabilistic assumptions as **hypotheses**:

```rust
#[law]
fn crash_atomic(ops: Seq<MOp>, k: Int, faults: Seq<Fault>, o: CrashOracle) {
    requires(0 <= k);
    ensures({
        let w = sim::run(model!(meta::api), World::fresh(), ops, faults, k);
        implies(crc_faithful(w.disk, o),
            match sim::run_total(model!(meta::init), crash_image(w.disk, o)) {
                Done(Ok(m)) => m.map == synced_map(ops, w) || m.map == inflight_map(ops, w),
                _ => false,
            })
    });
}
```

* `crc_faithful(d, o)`: every image blob/page whose CRC validates equals some
  version written with that CRC (the named 2^-32 assumption); `no_forgery(tr)`
  is the signature analogue (§13.6). Reported, never kernel axioms.
* **Idempotent recovery:** a second cut/oracle inside recovery recovers the
  same abstract state.
* `sim` is a generic driver in core text, parametric in `step` (legal in the
  kernel today).
* "Error = crash" is enforced by token consumption (§13.3).

### 13.6 Distributed protocols (Simplex)

* **Spec:** finalized blocks form one chain; at most one finalized block per
  view.
* **Protocol model (ghost), parametric in `n, f`:** every model law takes
  `(n: Int, f: Int)` with `requires(n >= 3*f + 1 && 0 <= f)`; `honest:
  FMap<u32, LocalState>` with `dom(honest) = range(n)`; `corrupted ⊆ range(n)`,
  `|corrupted| ≤ f`; `sent: FMap<Subject, FSet<u32>>` (signers per subject —
  no set comprehension or image cardinality needed); views are `Int` in the
  model (exec `u64` view arithmetic is proven overflow-free separately).
  Transitions: `HonestStep(i, ev)`, `Crash(i)` (nondeterministic restore from a
  log between the synced log and the written log, including a torn prefix of
  the dirty section), `Adversary` (corrupted signers add attestations).
  Signature unforgeability and `BatchSound` (optimistic aggregate
  verification: `Ok(cert)` ⇒ all aggregated attestations ∈ `sent`; failure
  results only report honest-sent attestations as verified — with the
  2^-λ failure probability over drawn scalars reported) are **named model
  assumptions**, entering theorems as hypotheses (`no_forgery(trace)`), never
  byte-level axioms.
* **Quorum lemma** from the prelude card library (`card(A∪B) + card(A∩B) =
  card A + card B`, `A ⊆ B → card A ≤ card B`, `card(range(n)) = n`, pigeonhole
  `card X > card Y → ∃x ∈ X. x ∉ Y`).
* **Invariants are stated in history terms** (over `sent` and the durable log,
  not volatile counters such as `last_finalized_i`).
* **Crash lifting theorem** (generic, proven once with `spec_fn`/predicate
  parameters): `init_inv ∧ step_inv ∧ restore_closed(inv, recover) ∧
  durable_before_send(step) → inv` holds under crash–restart, where
  `restore_closed` (the replay lemma) must be proven per protocol.
* **Implementation refinement:** `R(i, c, w, g)` relates the voter's derived
  model state `c`, the world `w` and the abstract state `g`, with the
  linearization point at the segment after the journal sync response (the
  abstract `HonestStep` fires there; earlier transitions stutter), using ghost
  snapshots (§13.1).
* Liveness deferred.

### 13.7 Zero-overhead contract and overhead ledger

The contract is **parity**: emitted code is the direct-style code a Commonware
engineer writes. Proof-enabled speedups are real but small (O(n) checks such
as `is_sorted` asserts and per-position validation in `read_many`; decode
without re-validation of CRC-validated pages under the named CRC assumption);
the design does not promise more. Actor fusion is dropped (it would put
pairing-bound verification back on the voter's timeout-critical loop to save
a ~1 µs mailbox hop). The **overhead ledger** tracks every gap found in review
until closed:

| Gap (review 2) | Closed by |
| --- | --- |
| shared lock-protected state (page cache, QMDB bitmap, compact merkle, rate limiters) | lock/atomic construct (§13.2); page cache/buffer pool as trusted library objects with validated specs where needed |
| hot external kernels (blst, crc-fast, ChaCha20-Poly1305, SHA-NI, AVX-512 x16) | `#[trusted_extern]` + x86 evidence as part of acceptance |
| by-value ownership passing without `Box` (18×) | `Box`, `Arc::make_mut`, lint |
| blocking commits (no `start_sync`) | `SyncTicket` |
| no in-task concurrency (io_uring depth, pools, send batching) | interleaving product, `try_recv`, actor families |
| per-vote signature verification | `BatchSound` + `offload` |
| double hash lookups, stable sorts | returned `&mut` (backward functions), relational specs |
| future size inflation from SSA printing | binding/scope-preserving printer |

Acceptance (not optional): benchmarks against the monorepo's own
implementations on **x86_64 Linux (tokio, io_uring)** and aarch64 macOS —
warm-cache random reads, commit throughput with pipelined `start_sync`,
QMDB update/commit/prove, certificate CPU with optimistic assembly, p2p
small-message throughput, actor future sizes (`size_of_val`), peak buffer-pool
occupancy — plus byte-identical `StorageConformance` digests. Parity or better.

### 13.8 Validation against Commonware (K-style)

Byte-for-byte conformance hashes; the monorepo's fuzz oracles and invariant
checkers run against sandblaster implementations (and, where written as
verified exec checkers with reflection laws, are proven equivalent to the
specs); differential tracing under the deterministic runtime (same seeds,
scripted RNG; compare `storage_audit()`, audited sends, application outputs);
existing Byzantine harnesses (Disrupter, Twins, scripted mocks) drive the
sandblaster voter unchanged.

### 13.9 Kernel and automation work this needs (feeds §5/§8)

* **`#[opaque]` definitions** (a `DefDecl` flag): neutral in checking-mode
  conversion and evaluation unless revealed (`reveal(f)` generalizes `Delta`
  to non-recursive opaque globals). Sound (opacity only loses completeness).
  Hashes, CRC, codecs and large step functions are opaque in proofs by
  default and used through their `ensures` — otherwise symbolic SHA-256 gets
  unrolled in every normalization.
* `auto`: trigger-based instantiation of ∀-facts (E-matching), registered
  conditional simp sets for `seq::*`, `fset::*`, `fmap::*`, an extensionality
  step for `FSet/FMap/Seq`, nonnegativity of `card` atoms in linarith,
  `instantiate(h, args)` script sugar.
* Comparator-parametric `FSet/FMap` in core text with the card library.

### 13.10 Milestones (re-staged)

* **E0 — Metadata, end to end (first).** Port `storage/src/metadata`
  (~600 production lines: two-slot CRC32C design, delta writes, SYNC-range
  writes, `try_join_all` of disjoint writes, resize-not-durable-until-sync,
  `normalize`, a pinned `StorageConformance` hash). Language slice: async/await
  on Blob effects incl. `try_join_all` with a range-disjointness obligation,
  `&mut self`, `BTreeMap<U64, Vec<u8>>`/`BTreeSet` with derived `Ord`,
  `Result`, linear handles, ownership tokens. Proofs: refinement of
  put/get/remove/clear to an `FMap`; `crash_atomic` with `crc_faithful` at
  every effect step; init idempotence under a nested crash; totality (the
  version-overflow `expect` discharged by a stated bound). Zero overhead:
  byte-identical conformance hash; put+sync throughput/latency parity vs
  `commonware_storage::metadata` on deterministic and tokio runtimes; CRC32C
  via ARMv8 `crc32c*` / SSE4.2 `_mm_crc32_u64` intrinsics proven equal to the
  bitwise spec with `bv()`. Validation: the reflected `crash_member` checker
  inside metadata's crash tests. Calibration: ~600 exec lines, 3–6k proof lines.
* **E1 — automation** (§13.9), card library, codec laws (bounded decoding,
  round trip, injectivity for domain separation).
* **E2 — contiguous fixed journal** on verified Metadata (page cache as a
  trusted transparent read-through object first, or verified with the lock
  construct), crash safety + idempotent recovery, `SyncTicket` pipelining.
* **E3 — QMDB:** variable journal, authenticated journal (MMR over ops, reusing
  SHA-256/MMR code and hardware kernels), `any`/`current`, the **completeness
  law** (every active key's proof verifies under the already-verified
  `verify`), then MMB and grafting.
* **E4 — Simplex protocol safety** (ghost), in parallel from day one.
* **E5 — voter implementation** refining E4, **including
  `segmented::variable` crash safety** (the voter's journal), composed via the
  crash-lifting theorem; batcher/resolver liveness-only at first.
* **E6 — p2p:** framing/codec, handshake state machine (crypto via
  `#[trusted_extern]` + named assumptions), bounded per-peer buffers,
  actor families.
* **E7 (optional) — liveness.**

Scale: budget proof ≈ **5–10× exec lines** (Dafny/Z3 systems report 5–10×,
Verdi ~100×; sandblaster has no SMT). Each target is written fresh in
sandblaster's style; porting the existing 60–80k-line async modules line for
line is not the plan.

---------------------------------------------------------------------------

## 14. QMDB-full: a generic verifier with `sol` parity

The first port (§11) verifies one configuration inherited from the Bend
example (Current unordered, fixed 32/32, MMR, SHA-256, 1-byte chunks, single
operation, u32-capped fields). The goal now is a sandblaster verifier that
accepts **any QMDB proof** that `~/code/monorepo/sol` (and Commonware's Rust
verifiers) accept, over Commonware's **native wire encodings**, while staying at
least as fast as Commonware on production configurations. Grounding:
`docs/qmdb-full-maps.md` (three maps: sol, Commonware Rust at HEAD, oracles).

### 14.1 Feature matrix

* **Variants:** Any (ordered, unordered), Current (ordered, unordered),
  Immutable, Keyless. Any/Immutable/Keyless verification treats operations as
  opaque bytes; Current adds activity chunks, grafting, the canonical root and
  exclusion.
* **Families:** MMR and MMB (leaves up to 2^62 / 2^62+30), inactive-peak
  prefixes, backward peak bagging, pending (MMB) and partial chunks, grafting
  at any height.
* **Hashers:** SHA-256 and Keccak-256 (Blake3 optional), each with portable and
  hardware variants (§9).
* **Chunk sizes:** any power of two (production N = 32; grafting height
  G = log2(8N) folded at compile time), plus a dynamic-N entry point matching
  Commonware's `dynamic::OperationProof`.
* **Schemas:** fixed (K, V sizes) and variable (varint-prefixed fields),
  ordered (next-key) and unordered.
* **Proof kinds:** single operation, contiguous range, sparse multi-proof,
  Current ops-multi via `OpsRootWitness`, ordered exclusion (interval,
  single-key, empty-commit), and the sync-side entry points
  (`verify_proof_and_extract_digests`, pinned nodes).
* **Inputs:** proof bytes as `&[u8]` decoded canonically and exactly inside the
  DSL; operations as typed fixed-size arrays or one `&[u8]` concatenation of
  canonical encodings parsed and hashed in place.

### 14.2 Structure: generic definition, proven specialization

* One generic core parameterized by a compile-time `Config { Family, Hasher,
  N, Schema, Variant }` (static traits with laws, §14.3). Per-proof data
  (leaves, inactive peaks, locations, counts, digests, chunk bytes, op bytes,
  variable lengths) stays runtime.
* Heap-free: the peak layout ("Blueprint") is computed by iterating peaks once
  and validating the digest count up front; digests are consumed in layout
  order with a bounded DFS (depth ≤ 63) over stack buffers (≤ 64 peaks);
  multi-proofs compute each element's required positions into a bounded
  buffer, sort and deduplicate with a proven bounded sort, and reconstruct
  shared ancestors once (sol's approach, fewer hashes than Commonware's
  per-element reconstruction, same accept set).
* Every hash preimage length is pinned per instance (leaf 8 + OP_SIZE for fixed
  schemas, node 72, fold 64, root 40/48, grafted leaf N + 32, chunk digest N,
  canonical root 64/96/104/136) and specialized with folded padding on top of
  the proven hardware compression (§9); variable schemas use a multi-part
  hashing kernel over borrowed slices, proven equal to hashing the
  concatenation.
* Instances are produced by the always-on optimizer; the **specialization law**
  (`instance(x) == generic(Config, x)`) is kernel-checked per instance, so
  laws are proven once, generically. Several instances coexist in one crate
  with stable names; a runtime `Config` entry point dispatches to instances
  (with a generic fallback).
* The current port becomes the instance `Config{MMR, Sha256, N=1, Current,
  Unordered, Fixed{32,32}}` and its fixtures stay as a regression set.

### 14.3 Language extensions this requires

1. **User const generics** with const arithmetic in array lengths
   (`[u8; 1 + K + V]`) and const-evaluated branches (so preimage lengths and
   padding fold at compile time).
2. **Static-dispatch traits with laws** (§13.2), associated consts/types
   (`MAX_LEAVES`, `PendingChunk`, schema tags), monomorphized in exec code;
   ghost generics by dictionary passing so laws are proven once.
3. **Bounded stack collections** (`BoundedVec<T, CAP>` = array + length with a
   proven `len ≤ CAP` invariant) replacing Commonware's `Vec`/`BTreeSet`/
   `BTreeMap` on the verification path; a proven bounded sort/dedup.
4. **Multi-part hashing** over borrowed slices (SHA-256 and Keccak-256),
   proven equal to hashing the concatenation, with compile-time selection of
   the fixed-length kernels when the preimage length is constant.
5. **Keccak-f[1600]**: portable reference plus an aarch64 `sha3`-extension
   variant (EOR3/RAX1/XAR/BCAX; statically available on Apple) proven by
   `BvRefl`; x86 variants later.
6. **u64 arithmetic** to 2^62+30 with overflow obligations (MMB positions
   `2p − log2(p+1) + …`), `log2`/`popcount`/`trailing_zeros` lemmas; byte-string
   lexicographic order with a proven total order and cyclic interval
   membership (exclusion); canonical decoding combinators (varints with
   minimality, tags, bounded vectors, family-dependent zero-width fields,
   trailing-byte rejection); re-encoding of typed operations for exclusion.

### 14.4 Laws

Generalize the five spec laws of the Current MMR cell (§11.3, §15.11: complete,
sound, unique, canonical, bounded, with the two tree laws) from one cell to the
Blueprint layout, and add: geometry and position laws (leaf/MMB positions, peak shapes, no
overflow); fold, layout and exact digest consumption; graftable chunks,
presence rules, canonical root composition and the zero-chunk identity; codec
canonicality and exact consumption; exclusion soundness (cyclic interval);
multi-proof exactness; and per-instance specialization. SHA-256/Keccak
conformance and Commonware interop remain tested properties (§14.5) unless
proven (SHA-256 against FIPS as in `bend-collections` is a later option).

### 14.5 Oracles and differential testing

A new standalone workspace `qmdb/oracle` pinned at Commonware HEAD (verification
formats are unchanged since the fixture revision) that ports `sol/fuzz`'s
generators to native wire bytes: G1 materialized databases (≤ ~1M leaves;
replayed histories with repeated keys, deletes, commits; floors at 0, aligned,
unaligned, leaves − 1), G2 synthetic deep trees built with Commonware's own
`reconstruct_root` (leaves near 2^32, 2^40, 2^62, MMB MAX), G3 persistent
lifecycle databases in the deterministic runtime for all variants (checked
against `storage/conformance.toml`), the size schedule around chunk-width
multiples, a pairwise covering array over the matrix (full cross product for
production N = 32 SHA-256), and the mutation operators listed in the maps. Each
case compares verdicts across every sandblaster instance, the generic entry point,
the multiversion clones, the baseline and Commonware; any panic or
disagreement fails. A deterministic corpus (2–5k fixtures) is checked in and
also run through the kernel evaluator; million-case fuzzing runs outside CI.
Optional Solidity tier via an in-process EVM on post-decode semantic cases.

The first instances are checked this way: `qmdb/oracle/check.sh` runs both
verified builds serially and compares 16 entry points (the generated
`verify`/`verify_fixed` and their `[portable]`/`[sha2]` clones per instance,
and the rustc-compiled sources) with Commonware over `corpus/` (4680) and
`corpus-instance/` (970 deep fixtures, 2^32 − 1 … 2^62). Every instance is
checked over Commonware's whole decode domain; **there is no documented-domain
category**. Each instance's capabilities (chunk size, `MAX_LEAVES`, digest
bound 122) are read from the compiled code and checked against its
declaration before any fixture is evaluated; generated files from the wrong
root are refused at build time. A seeded-bug self-test (8 bugs, including
u32-capped fields, a 64-digest bound and N = 1 decoding of N = 32 proofs)
must be caught by the corpora.

### 14.6 Benchmarks (the headline replaces the Bend-configuration row)

Production Current, N = 32, SHA-256, fixed 32/32, ordered and unordered, MMR
and MMB, n ∈ {10k, 100k, 1M, 5M, 10M} plus synthetic 2^32 / 2^62 depths:
single-op (grafted, pending, partial chunk targets), exclusion, ranges
{2…5000}, multi-proofs {3, 10, 100}, ops-level proofs for any/immutable/
keyless; Commonware decode+verify and verify-only for both the constant-N and
dynamic-N APIs; sandblaster specialized instance and generic entry point;
compression counts, code size, machine load. First rows, for the specialized
N = 32 instance before the generic entry point exists: qmdb/BENCHMARKS.md
"Production domain". Targets per instance: generated median ≤ Commonware's
constant-N decode+verify, and within +2% of hand-written specialized code.

### 14.7 Milestones

* **F0** (parallel): `qmdb/oracle` generators + corpus + differential harness
  against the existing instance (host code). Done; since hand-off H1 against
  both instances over Commonware's full domain.
* **F1**: language extensions 14.3 (1)–(4), (6); Keccak (5).
* **F2**: generic Merkle core (MMR/MMB, Blueprint, bounded DFS, exact
  consumption) + plain-operation variants (Any/Immutable/Keyless) with laws.
* **F3**: Current (grafting, pending/partial, canonical root, OpsRootWitness,
  ops-multi, exclusion) with laws.
* **F4**: multi-proofs, sync-side entry points, dynamic-N dispatch.
* **F5**: instances, specialization laws, optimizer/hardware paths for both
  hashers, differential sweep, benchmarks, red team.

---------------------------------------------------------------------------

## 15. Correct by construction: specifications in the type system

Audience: engineers writing production code where a bug is a failure, who
will go the extra mile for assurance. Principle: **the signature is the
specification.** Safety already lives in the types (every operation carries
its obligations, §7). §15 puts functional correctness there too, so that:

1. an engineer states *what* a section of code must do — as a readable
   reference specification, as types with invariants and meanings, or as laws;
2. the build fails unless the code provably does exactly that; and
3. the build fails if the specification does not pin the behaviour down:
   every implementation satisfying it is observationally equal to this one
   (`obs_eq`, §15.5) on every input of the public domain.

**What a green build means** (printed by the report and the spec sheet): for
every boundary function, the dispatched code is equal, by a kernel-checked
emission chain (§15.2), to a source definition that is `obs_eq` to the
function the locked specification surface (§15.6) determines, relative to a
well-founded chain of fully specified sections (§15.5), within the TCB of
§1.1. It does not mean the specification says what its author intended;
§15.7 checks that, and nothing else can.

**All of §15 is mandatory for every sandblaster crate.** There is no profile,
attribute, `cfg`, feature, environment variable or `sandblaster::build` option
that relaxes it — like proofs of safety (§7) and the optimizer (§8). §15.8
lists the would-be escape hatches and how each is closed.

A true but incomplete law is the gap this closes: QMDB's nine laws are all in
the soundness direction, so a wrong SHA-256 round constant or a `verify` that
rejects everything would still verify today. Adversarial review of this
section: `docs/review-4-spec.md`.

### 15.1 Spec functions: the reference semantics

`#[spec] fn` (ghost; §4.5) is the language for writing down *what* code
means: pure, total (measure-checked), over `Int`, `Nat`, `Seq<T>`, `Map`,
`Set` (§4.1) and exec types, with no performance considerations. It is a
transliteration of the standard (FIPS 180-4 pseudo-code, the MMR definition,
the original Bend program). Spec functions live in modules declared
`#[cfg(sandblaster)] #[spec] #[path = "spec/mod.rs"] mod spec;` (`cfg` first;
every `fn` in a `#[spec]` module is a spec fn), are evaluated by the kernel
for `#[example]` (§15.7), and are erased from the build.

* **Spec closure (normative).** `Refs*(t)` is the least set of globals that
  contains those in relevant positions of `t` and is closed under the bodies
  and types of its members (opaque bodies, loop helpers, `::ensures` and
  prelude definitions included). A function is **established** when it is
  fully specified (§15.5) in an earlier section with an identity or injective
  view. A spec item (spec fn, spec constant, view, representation relation,
  invariant, evidence proposition, example) is **spec-closed** when every
  exec global in its `Refs*`, not descending into established functions, is
  established. Referring to any other exec function or exec constant is
  `error[spec-depends-on-impl]`; the diagnostic suggests transcribing the
  definition into `spec::`. (Otherwise `#[spec] fn s(x) { f(x) }` with
  `#[refines(s)] fn f` would make any `f` "refine its spec".) Laws and
  contracts mention the functions they constrain directly; §15.5 governs
  those occurrences.
* **Fuel.** A spec fn that returns a default when a fuel argument runs out
  (Bend-style `peaks(32, ..)`) needs a proven `#[fuel_sufficient]` lemma over
  its declared domain, or measure recursion.
* **Mirrors.** A spec fn whose kernel body is `alpha_eq_relevant` (after δ of
  non-recursive helpers) to the body of the exec function refining it needs
  `#[mirrors_impl(justification = "..")]` plus an independent law or example
  set (§15.7); without them it is `error[spec-mirrors-impl]`. Tiny functions
  legitimately coincide with their spec; the attribute makes that a visible,
  locked claim.
* **Laws state guarantees, not code (normative).** A law is a claim that a reviewer reads *instead of* the implementation, so its statement must mean something without it. The rules below apply to `#[law]` items and to the laws of law-carrying traits (§15.4). Lemmas in `PROOF.rs` are not surface items and are unrestricted. The elaborator checks each rule on the de-elaborated statement (§15.6) and reports it at the item's span.

  1. **LR1 Vocabulary.** *Hard:* `error[law-mentions-internal]`.
     - The statement of a law (binder types, `requires`, `ensures`, `#[reduces_to]`) may mention only:
       - spec items (§15.6);
       - exec types, through their views;
       - exported functions, meaning the root `pub use` list and the `pub` methods of exported types (and of any type reachable from them through public signatures, which §15.8 requires to be exported).
     - Any other exec function or exec constant is an error, and so is a plain `fn` of a ghost module (`LAWS.rs`, `PROOF.rs`), which is neither a spec item nor exported. This holds whether it appears directly or through the `Refs*` of a spec item (not descending into exported functions).
     - An internal function is specified where it is defined, by `#[refines(spec::…)]` or `#[ensures]`, and connected to the laws by lemmas.
     - A trait law may mention its own trait's items.
     - The diagnostic suggests `#[refines]` on the function, or moving the claim to a `#[lemma]` in `PROOF.rs`.
     - Consequence: laws create §15.5 sections only through exported functions.
  2. **LR2 Closure.** *Hard:* `error[spec-depends-on-impl]`. For spec closure, a law is a spec item whose relevant positions may also contain the exported functions it constrains. Reaching any other exec global is the error of §15.1.
  3. **LR3 State it over the spec.** *Warning:* `warning[law-bypasses-refinement]`. A law that mentions an exported `f` carrying `#[refines(s)]` is reported, with the suggestion to state it over `s`. The two are equivalent once `f::refines` is proven. The spec form does not tie the guarantee to `f`'s signature and adds no determinacy obligation.
  4. **LR4 No closed disjuncts; extraction form.** *Hard:* `error[vacuous-reduction]`.
     - In a law or contract, every disjunct of a conclusion and every conjunct of a hypothesis must mention a binder of the statement. A closed subformula there is either provable (so the law is vacuous) or refutable (so it is dead weight).
     - A law tagged `#[reduces_to(a)]` must conclude `P ∨ B(t̄)`, where:
       - `a` names an `#[assumption]` item;
       - `B` is a `bool`-valued spec fn (the break predicate, e.g. `spec::sha256::collision`);
       - `t̄` are spec-closed terms computed from the binders.
     - An `exists` or a `Prop` in the break disjunct is an error.
     - Example: `collision(clash(p.tree(op), db.tree()))` is accepted. `exists x ≠ y. sha256(x) == sha256(y)` is rejected, because pigeonhole proves it.
     - Vacuity: a break predicate that ignores its arguments, or one that bounded `auto` proves from the hypotheses (`requires ⇒ B(t̄)`: the law then holds of any specification), is an error; so is a guarantee `P` that bounded `auto` proves from the hypotheses alone (the break, and the assumption, are dead).
  5. **LR5 Mirrors against every function.** *Hard:* `error[spec-mirrors-impl]`.
     - The mirrors check compares each spec fn with every exec function of the crate, not only the one refining it.
     - Bodies are compared as kernel terms, after δ-unfolding of non-recursive helpers on both sides, modulo the type-directed view coercions. Matching uses the `SPEC.lock` canonical hashes, so it is linear in the number of functions.
     - A match needs `#[mirrors_impl(of = path, justification = "..")]` plus independent examples.
     - Expected QMDB hits: the FIPS helpers `ch`, `maj`, `Σ` and `σ`, with CAVP as the independent examples.
  6. **LR6 Laws that restate.** Let `U` be the law's statement with its non-recursive spec fns δ-unfolded.
     - **(a) Echo.** *Hard:* `error[law-restates-impl]`.
       - Trigger: `U` is proven by unfolding each function it mentions (spec or exported) at most once, using only propositional reasoning and congruence. No induction, no lemma, no arithmetic beyond evaluation, and a fixed budget.
       - The diagnostic prints the unfolding that proves it. A recursive or opaque proposition stays unknown (it has no defining equation to unfold by); a law the check cannot decide (its statement does not re-elaborate, the view cannot be built) is reported as a finding, never passed.
       - Consequence: a round trip through code without arithmetic (a tag byte, a copy) is an echo. Such a codec is specified by its wire format (`#[refines]` against the format transcribed into `spec::`, determined at once), and its round trip is a lemma.
       - A law that is intentionally definitional carries `#[definitional(reason = "..")]`. It is printed under its own heading on the spec sheet and never counted as a guarantee.
     - **(b) Resemblance.** *Warning:* `warning[law-resembles-impl]`. A subterm of `U` of at least 12 kernel nodes that is `alpha_eq_relevant` (modulo views) to a subterm of an exec body is reported, with both spans.
  7. **LR7 Corollaries.** *Warning:* `warning[law-corollary]`.
     - Trigger: the law's `#[proof]` uses only other laws plus propositional or congruence steps, with no unfolding, no induction and no other lemma.
     - Suggested fix: demote it to a lemma, or mark it `#[corollary]` so it is printed under the law it follows from.
  8. **LR8 Sensitivity.** *Warning, S4:* `warning[law-insensitive]`.
     - The §15.9 engine applies spec-mutation operators to the spec fns in a law's `Refs*`.
     - Per law, it records the mutants for which it finds a definite counterexample to the mutated law. The spec sheet prints each law's kill set.
     - A law that kills no mutant says nothing about the definitions it uses and is reported.
     - Like §15.9, this is untrusted and diagnostic only.
  9. **LR9 Readable.** *Hard:* `error[law-undocumented]`.
     - Every law has a doc comment whose first sentence states the guarantee in words: at least three words, a code span counting as one and at least one outside code spans (the sentence does not end at `i.e.`, `e.g.` and similar abbreviations).
     - Every `#[reduces_to]` names an `#[assumption]` item.
     - `sandblaster spec` generates the table *law | guarantee | assumes* for the spec sheet and the report.
  10. **LR10 Both directions.** *Warning:* `warning[one-directional-laws]`. Trigger: the laws mention a `bool`-valued exported function, or its refinement target, only in hypotheses (soundness only) or only in conclusions (completeness only). The report then says that nothing states when the function is true, or when it is false.

### 15.2 Refinement signatures: functional specs as types

```rust
#[refines(spec::sha256::compress)]
pub fn compress(state: [u32; 8], block: &[u8; 64]) -> [u32; 8] { .. }

#[refines(spec::codec::uint)]           // Option<(u64, &[u8])> ↦ Option<(Nat, Seq<u8>)>
pub fn uint(xs: &[u8]) -> Option<(u64, &[u8])> { .. }

impl Mmr {
    #[refines(spec::mmr::push)]         // spec: (spec::Mmr, Digest) -> (spec::Mmr, Nat)
    pub fn push(self, leaf: Digest) -> (Mmr, Position) { .. }
}
```

`#[refines(s)]` applies to functions only; types use `#[view]`,
`#[represents]` and `#[invariant]`. On a function `f` it generates the lemma
(`ObligationKind::Refines`)

    f::refines : Π x̄ (h̄ :Irr Req_f x̄). obs_eq(α(f x̄ h̄), s(α x̄))

where `α` is each type's abstraction: identity, the type-directed view
coercion, a `#[view]`, or, for a type with `#[represents]`, the simulation
form of §15.3. `#[refines(s(e₁, …, eₙ))]` gives an explicit argument map
(ghost expressions over the parameters). The lemma is proven like `ensures`
(auto, loop invariants in the body, or a `#[proof(refines = path::f)]` item in
`PROOF.rs`) and is a fact at every call site. A function with both
`#[ensures]` and `#[refines]` gets their conjunction.

* **Determinacy.** `#[refines]` discharges §15.5 for `f` **only if** every
  output type (the result and a returned `Self`) has an identity view, has a
  proven `view_inj` (`ObligationKind::ViewInjective`), or is `Abstract`
  (§15.3). Otherwise the report says "refines `s` up to `view(T)`" and §15.5
  applies.
* **State passing.** Until `&mut` lands (§13.2), a mutating method is written
  `fn m(self, ..) -> (Self, R)` and refines `s : (V, ..) -> (V, R')`, with the
  post-state first. A later `&mut self` method refines the same spec
  unchanged. A function returning `&mut` needs pointwise refinement of its
  backward function.
* **Total at the boundary.** The spec of a boundary function is total on the
  function's input type. A standard with a smaller domain (FIPS 180-4 stops at
  2^64 − 1 bits) is written as a total spec plus a locked law relating it to
  the standard on that domain (`hash_total_is_fips`). Internal functions may
  use `#[refines(s, domain = P)]` (`P ∧ Req_s → …`); the spec sheet prints
  `WHEN P`.
* **Emission chain (normative).** Every emitted function `e` for a source
  function `f` carries a kernel-checked equality to `f`: conversion for
  specialization residuals (`check_residual_equal`), `clone_equiv` for
  multiversion clones, `variant_equiv` for hardware variants, the §14.2
  specialization law, or a lemma for any later transformation (`#[rewrite]`,
  call fusion, lane lifting, dead-branch elimination). A transformation whose
  link is not proven is never emitted: the optimizer falls back to the proven
  form (a warning; an error under `SANDBLASTER_STRICT_OPT` and for
  `#[specialize]`). Today a multiversion clone without `clone_equiv` is still
  emitted with a warning (`opt/multiversion.rs`); S3 closes that. The spec
  sheet prints, per dispatched entry point, the chain *instruction model →
  variant → portable → spec*. `#[refines]` on an `#[implements]` variant is
  rejected: variants inherit through `VariantEquiv`.
* **Generics.** A generic `f` refines a generic spec at the identity on its
  type parameters. The elaborator also proves `f::natural` (commutation with
  `α` at instantiation) by induction on the body, so refinements compose
  through views at instantiated types.

### 15.3 Types that carry invariants and meaning

All of these are zero-cost: proof components are `Irr` (§5.3) and erased by
codegen, and the exec representation is the plain Rust type.

* **Invariants are part of the kernel type (normative).** `#[invariant(p)]`
  on a struct `S` (several are conjoined) elaborates to
  `inductive S(ps) := S(f̄, inv :Irr Eq(Bool, p̂(f̄), true))`, where `p̂` is a
  `bool`-valued, spec-closed expression over the fields (`self.f` is
  rewritten to the field binder). A `Prop` invariant is accepted only if it
  passes the kernel's `is_prop`; the front end checks this first and gives a
  readable error. `exists` is encoded as `¬¬∃` and reported, because its
  consequences are usable only for decidable goals. Bare `self` and methods
  of `S` in `p` are rejected. Every constructor application must supply `inv`
  (`ObligationKind::TypeInvariant`): literal, tuple-struct call, `..base`
  update, SSA field assignment, pattern rebuild. So no code path can form an
  invalid value of type `S`; the invariant can be broken only in unpacked
  local fields. A match or projection on `S` yields `p̂(f̄) = true` as a fact
  (`FactOrigin::TypeBound`). Refinement newtypes are the one-field case:
  `#[invariant(self.0 < MAX_LOCATION)] pub struct Location(u64);`.
  Constructors are hand-written: `pub fn new(x) -> Option<Self>`, plus
  `#[requires(..)] pub(crate) fn at(x) -> Self` for verified callers.
* **Visibility.** A type with an invariant, a representation relation or a
  non-identity view has only private fields (no `pub`, `pub(crate)` or
  `pub(super)`). Given the kernel encoding, this is hygiene inside the crate
  and the soundness condition at the boundary: host code cannot forge values.
  Ghost code may read private fields anywhere in the crate.
* **No ghost fields.** Exec types have no ghost fields: an `Irr` constructor
  field must be a proposition, and a relevant ghost field would change the
  constructor and fail the round trip. Ghost *parameters* are allowed:
  `#[ghost] x: T` on an exec function parameter is an `Irr` Π binder (it may
  hold data, §5.3). It is not printed and makes the function non-boundary.
* **Views (abstraction functions).** Three forms:
  - `#[view(spec::T)]`, structural: every field maps to the same-named field
    of `spec::T`, so the view is injective by construction;
  - `#[view(|s| e)]`, a spec-closed expression;
  - no attribute: the type-directed coercion. `&T ↦ α(T)`,
    `&[T] ↦ Seq<α(T)>`, `[T; N] ↦ [α(T); N]` or `Seq<α(T)>`,
    `uN ↦ uN | Nat | Int`, `Option`/tuples/`Result` componentwise, and a
    newtype with an invariant ↦ its field.
  Views are surface items (printed and locked). There are no `View` trait
  impls.
* **Representation relations.** Use these when the abstract state is not
  computable from the representation (a streaming hasher's absorbed bytes):
  `#[represents(|s: &S, a: spec::A| P)]`. `#[refines(spec::m)]` on a method
  of `S` then means:
  - a constructor-like method establishes `P(ret, spec::m(..))`;
  - an `S → S` method preserves it: `P(self, a) → P(ret, spec::m(a, ..))`;
  - a method with a non-`S` result `r` refines through it:
    `P(self, a) → obs_eq(r, spec::m(a, ..))`.
  `S` must be `Abstract`.
* **Abstract(T)** holds when every field is private; no constructor is
  exported; `PartialEq` is not derived, or `T::eq a b = eqb(α a, α b)` is
  proven; `Debug` is not derived; and every boundary function taking or
  returning `T` refines through `α_T`. The alternative for a public
  representation is `view_inj_T : Π a b. α a = α b → a = b`.
* **Index spaces as distinct types.** `Position`, `Location`, `Height`, … are
  separate newtypes with invariants and no implicit conversion. Conversions
  are inherent methods with `#[refines]` (`Location::position(self) ->
  Position` with `#[refines(spec::mmr::leaf_position)]`). Mixing index spaces
  — a classic MMR/bitmap bug class — is a type error.
* **Evidence types (typestate)** are invariant types whose invariant is the
  certified property, with private fields and constructors only in the module
  that proves them:
  `#[invariant(spec::verifier::verify(*self.root, *self.key, *self.value,
  self.proof))] pub struct VerifiedMembership<'a> { root: &'a Digest, key: &'a
  Digest, value: &'a Digest, proof: &'a [u8] }`.
  Store the witness, which keeps the invariant decidable, or accept the `¬¬∃`
  encoding. The invariant's free variables are the fields, type parameters,
  consts and spec-closed pure globals: never effect state, `&mut` places or
  lock contents. Evidence about mutable state (§13) must be branded (a
  lifetime brand, or a ghost version the predicate mentions) and is not
  `Copy`. Downstream code relies on the property without re-checking
  ("parse, don't validate", enforced by proof).
* Laws and lemmas quantifying over an invariant type gain the invariant as a
  hypothesis. When a type gains an invariant, the lock diff reports every such
  item as WEAKENED (§15.6).

### 15.4 Traits with laws; determined traits

Static traits (§13.2, §14.3) declare laws; every impl proves them; generic
code is proven once against the laws. `#[determined]` on a trait makes the
determinacy theorem (§15.5) a trait-level obligation: all implementations
agree (e.g. `trait Hasher { law hash(m) == spec::hash(Self::ALG, m) }`).
Traits that are genuinely parameters (MMR vs MMB) are not determined; their
instances are.

Law-carrying traits (and the lawful `Ord`/`Eq`/`Hash` bounds of §13.2) are
emitted **sealed** (a private supertrait). No boundary function or type is
generic over them, and closures or `impl Fn` never appear at the boundary.
Export monomorphic instances (§14.2) instead.

### 15.5 Determinacy

Every function exported from the crate (the root `pub use` list, §15.8), and
every exec function mentioned in a law or in an exported function's contract,
must be **determined** by the specification: immediately by `#[refines]`
with determinacy (§15.2), otherwise by a kernel-checked obligation per
section.

* **Sections are computed, never declared.** They are the strongly connected
  components of the graph "law or contract mentions exec function",
  restricted to functions not determined by `#[refines]`, ordered by a
  well-founded order ≺ (dependencies first). `#[section(with = [..])]` on a
  function only merges sections (always sound: completeness of a larger
  section implies it for each part with the rest fixed); it never removes a
  dependency.
* **Published functions.** `P(R)` = the functions of `R` referenced from
  outside `R`: other code, the surface (contracts included, also those of
  `R`'s own functions: a merge never unpublishes), or the boundary. Only the
  published functions of a fully specified section are determined; the
  others are fixed only relative to them.
* **Hypotheses.** `H(R)` = the laws mentioning `R` (never a
  `#[definitional]` law, which restates a definition and is not a
  guarantee), plus the `ensures`, refinement lemmas and type invariants of
  `R`'s functions, each re-elaborated with `R` abstracted. A hypothesis that
  mentions `R` but did not verify blocks the section.
* **Statement.** For each `p ∈ P(R)`, `Env::abstract_section` (kernel,
  additive, TCB) builds (`ObligationKind::Completeness`)

      complete_p(R) : Π(F₁' : T₁)(F₂' : T₂[F'₍<₂₎])…(Fₖ' : Tₖ[F'₍<ₖ₎]).
                      Π(e : Ens[F']). Π(l : L̂[F']).
                      Π(x̄ : Ā_p)(h̄ :Irr Req_p[F'](x̄)). obs_eq(F_p' x̄ h̄, f_p x̄ h̄)

  When `Req_p` mentions `R`, the requires is split into two binders — the
  abstracted one for `F_p'` and the real one for `f_p` — so the claim is
  agreement on inputs valid for both; every member used in such a requires
  must itself be published with a view-free `obs_eq` (its own `complete_q`
  then forces `F_q' = q`, so both binders range over the same inputs).
  To build it, `abstract_section`:
  - replaces every relevant occurrence of `g ∈ R` by the variable `F_g'`,
    with the requires telescope ordered by the requires-reference DAG;
  - λ-lifts **spec** definitions outside `R` whose bodies reach `R` (a spec
    function means its body). Any other global outside `R` and the stop set
    that reaches `R` — an exec caller, a loop helper, a lemma, an `::ensures`
    — is an error ("establish it in an earlier section or merge it into this
    one"): an exec function outside the section may take any value in the
    set-model argument, so inlining its body would turn its implementation
    into a specification of the member;
  - re-proves the proof slots of re-elaborated laws with auto;
  - generates the conclusion itself from the types;
  - rejects the statement unless `Refs*(complete_p(R)) ∩ R = ∅`.
  The statement may be `Kind`-sorted (generic sections). It is one lemma per
  `p`, never a Σ. It is printed on the spec sheet and hashed into
  `SPEC.lock`. Proof: auto, or `#[proof(complete = path)]` in `PROOF.rs`.
  Because the real functions satisfy their hypotheses, `complete_p(R)` says
  every implementation satisfying the specification agrees with this one on
  every valid input. It is sound in the set model (exec functions are pure
  and total; an `Irr` Π domain behaves as a squash, so `f'` applied to any
  requires proof gives convertible results).
* **Observational equality.** `obs_eq_A(a, b)` is:
  - `Eq(A, a, b)` for types with an identity view;
  - `Eq(V, α a, α b)` through a view that is injective or on an `Abstract`
    type;
  - pointwise for function-typed outputs (backward functions, `spec_fn`;
    there is no funext);
  - componentwise for state-passing tuples;
  - pointwise in explicit oracle and scheduler arguments for §13 models.
* **Relative completeness is well-founded.** `Deps(R)` = the exec globals in
  `Refs*(H(R)) \ R`, computed, never declared. `R` is **fully specified**
  iff every `complete_p(R)` is kernel-checked; every dependency is fully
  specified in a section `S ≺ R`, or is a trusted primitive (prelude,
  intrinsic model, `#[trusted_extern]`); and dependencies occur in `H(R)`
  only in `obs_eq`-respecting positions. Meta-theorem (set model): any
  interpretation of the exec globals that satisfies every `H(S)` agrees with
  the real one on every `P(S)` up to `obs_eq`, by ≺-induction. Without
  well-foundedness it fails: from the single law `f(x) == g(x)`, `f` is
  determined given `g` and `g` given `f`, yet neither is determined — here
  they form one section and the obligation (correctly) fails.
* **Abstractability.** A hypothesis whose *statement* depends on the
  definition of a function in `R` (a proof slot proven by unfolding it) is
  re-proven in the abstracted context: a law is re-elaborated with `R`
  abstracted and the earlier hypotheses as facts, and handed to the kernel
  as a restatement. If that fails it is rejected, with a diagnostic that
  locates each failing slot and names the proposition it needs (the
  explicit hypothesis to add, or a law to place before it).
* **Discharges (by `auto`):** refinement (transitivity through views; the
  refinement hypothesis of a member rewrites it first, which keeps large
  sections easy); exact characterizations of boolean functions
  `f(x) == true ↔ P(x)` (split on both results); recursive equations
  (induction with `ih`).
* **Domain.** Determinacy is over inputs satisfying `requires`. Every
  `requires` of a function in a section, and of every `#[refines]` target,
  must not be refuted by the §10 non-vacuity refuter and must be met by an
  example (§15.7). Boundary functions have no `Irr` binders at all (§3.1): no
  `requires`, no `#[decreases(.., max)]` depth hypothesis, no ghost
  parameters.

### 15.6 The specification surface and `SPEC.lock`

The build computes every statement item of the crate (spec fns and spec
constants, views, representation relations, invariants, evidence types,
laws, contracts, boundary signatures and types, `#[trusted_extern]`s,
`#[mirrors_impl]` justifications, target-intrinsic models with their
evidence, `#[example]`s, vector files, computed sections with their
`complete_p` statements) and checks all of them. The **specification
surface** — what `SPEC.lock` holds — is only what a reviewer must read to
trust the crate, the **review surface**, defined deterministically
(`crate::surface`, *What is locked*):

1. **Roots**: every law; every boundary signature, boundary type and
   boundary constant; every `#[refines]` contract; every trusted extern and
   target model; every computed section; every vector file; every
   `#[assumption]`.
2. **Vocabulary**: the closure of the roots under statement dependencies
   (the Merkle `Refs₁` and explicit dependencies below): the spec fns, spec
   constants, spec types, views, representation relations, contracts,
   types and constants the statements mention — and the invariant of every
   type on the surface (a type and its invariant are one component).
3. **Known answers of the vocabulary**: the `#[example]`s, vector files and
   `#[mirrors_impl]` of every spec fn, spec constant or function on it, and
   every `#[fuel_sufficient]` lemma about one of its spec fns; closed again,
   to a fixpoint.

Everything else is a **proof internal** and never locked: helper spec fns
that only proofs use and their examples, invariants (e.g. `#[lift_attach]`
ones) of types no statement mentions, contracts of functions no statement
mentions, lemmas and proofs. A proof refactor therefore never changes the
lock; a change of a law, of its vocabulary, of a known answer of the
vocabulary or of a boundary signature always does. The kept set is closed
under dependencies, so no kept item's hash depends on an internal. Proof
internals still pass every gate (spec closure, examples and coverage, spec
mutation): they leave the lock, not the build. (Behavior snapshots and the
unconstrained-behavior report, once implemented, are roots.) The varint
pilot's lock went from 360 items to 116: the 244 proof internals left are
63 spec fns no statement uses (57 PROOF.rs helpers, 6 lift-model functions)
with 174 examples, 3 `#[lift_attach]` invariants and 4 internal types; no
kept entry changed. There are no user axioms (§5.10 is fixed).

* `sandblaster spec` prints the spec sheet: per section, the source text, a
  de-elaborated fully parenthesized form of each statement (explicit binder
  types and casts), and the kernel statement, and the number of proof
  internals left out. `sandblaster spec --preview <file>` writes the lock
  `--accept` would write to another file (a review aid; it needs the proofs,
  not the gates, and never writes a lock).
* `SPEC.lock` (checked in, in the DSL root directory; one lock per root:
  `SPEC.lock` for a root named `mod.rs` or `lib.rs`, `SPEC.<stem>.lock`
  otherwise, so `sandblaster/fixtures/qmdb/sandblaster/mod.rs` and `n1.rs` have `SPEC.lock` and
  `SPEC.n1.lock`) is a sorted text file
  with one entry per surface item: key, kind, the rendered statement (for PR
  review) and a Merkle hash
  `H(i) = hash(kind, path, canon(stmt), src(stmt), ⟨(path g, Hdep g) | g ∈ Refs₁(stmt)⟩)`.
  `canon` uses de Bruijn indices, drops binder names, replaces irrelevant
  subterms by `•`, names globals by stable path, and is memoized by sharing.
  `Hdep(g)` is `H(g)` for a surface item; the hash of its spec surface for an
  established exec function; the file hash for prelude and builtin globals;
  and an error for any other exec global. The header records the lock
  format, the kernel, prelude, SEMANTICS, builtins and target-model hashes,
  and every section (`R`, `P`, `Deps`, `H(complete_p)`).
* **Enforcement.** The set of entries must equal the computed surface
  exactly; a missing lock, or any added, removed or changed item, is
  `error[spec-lock]` naming each item (the lock gate of every build).
  Only `sandblaster spec --accept [ITEM…]` writes the lock (never `build.rs`,
  never an environment variable), and only after every other gate passed
  (`lock::accept` takes the permit of the crate path with
  `LockUse::Accepting`), so every spec change is a visible, reviewable diff
  of `SPEC.lock`. Adding a trusted item or changing model evidence is a lock
  mismatch like any other.
* `sandblaster spec --diff <rev>` elaborates old and new in separate
  environments over the same Merkle dependencies. Per changed item it makes a
  bounded kernel attempt at old ⇒ new and new ⇒ old: *strengthened*,
  *weakened*, *equivalent*, or *unrelated*. After a toolchain upgrade,
  `--accept --equivalent-only` re-accepts only items whose new statement is
  kernel-proven equivalent to the old one.
* The generated crate exports `pub const SANDBLASTER_SPEC_ROOT: [u8; 32]` (the
  lock's Merkle root). A consumer can pin the exact specification it
  reviewed: `const _: () = assert!(eq(&qmdb::SANDBLASTER_SPEC_ROOT, &REVIEWED));`.
* Implementation changes that leave the surface untouched need no
  correctness review: the proofs either go through or the build fails.

### 15.7 Validating the specification itself

A proven implementation of a wrong spec is wrong, so specs get their own
checks:

* **Known-answer examples.** `#[example(e)]` (a closed `bool` spec
  expression) becomes a kernel lemma `s::example#k`, checked by conversion or
  by the kernel's closed evaluator `Env::eval_closed` (TCB) when the
  unfolding policy keeps the term folded; the front end's reference evaluator
  is only a diagnostic. `#[examples(file = "..", format = "cavp" | "json")]`
  on a ghost checker fn binds record fields to parameters by name. Files are
  surface items, with a content hash and a provenance (`independent`,
  `production` or `self`); self-derived vectors do not count. An exhausted
  budget is an error, never a skip. The same vectors run natively against the
  generated code as generated host tests. Because the implementation provably
  equals the spec, examples on the spec cover the implementation too.
* **Coverage.** Every spec fn is exercised by an example; a
  `bool`/`Option`/`Result` spec has each outcome at least once; the report
  lists spec branches no example reaches; functions of a law-only section
  have examples evaluated on the function itself; a function refined through
  a non-identity view has examples on the exec function, through the view;
  every public invariant or evidence type has an example built through the
  public API.
* **Two independent descriptions.** Algebraic laws are proven about the spec
  as well as the code; boundary decoders state canonicality (`Codec`,
  §15.13).
* **Non-vacuity** (§10) for laws and `requires` (§15.5), plus satisfiable
  implication antecedents (bounded, untrusted).
* **Ghost-language differential.** Quantifier-free spec fns, contracts and
  law bodies over exec types are compiled natively through an erasing
  lowering and compared with kernel evaluation on random and boundary inputs
  (the §10.3 harness), because elaboration of the ghost language is TCB for
  the meaning of specs (§1.1 item 6).
* **Spec mutation.** The §15.9 operators applied to spec fns must be killed
  by examples or the oracle; a surviving spec mutant is an error.
* **External differential evidence**: the oracle (§14.5, `qmdb/oracle`)
  compares the spec's behaviour against production Commonware on generated
  and fuzzed corpora; disagreements are spec bugs (or production bugs).

### 15.8 Mandatory, with no opt-out

Every sandblaster crate must satisfy, as build errors:

* every boundary function fully specified (`#[refines]` with determinacy, or
  §15.5), every section well-founded, every `complete_p` kernel-checked;
* a boundary that is exactly the root's `pub use` list (no `pub mod` at the
  root), with boundary functions that are monomorphic, have no `Irr` binders,
  and are not generic over law-carrying traits;
* spec closure and mirrors (§15.1), examples, coverage and spec mutation
  (§15.7), and the lock (§15.6);
* the emission chain for every dispatched function (§15.2);
* deterministic outcomes: proofs and the emitted code are decided by step
  budgets only. The wall-clock deadline and memory limits (§8.1, memguard)
  are safety nets set well above the budgets; hitting one is reported as a
  resource failure of the build, never as a proof result, and the report
  records the hash of the emitted file;
* `#[trusted_extern]` only for §13 runtime primitives, with a contract,
  `justification = ".."` and a lock entry; target intrinsics dispatched only
  with validated evidence;
* the staged concerns of §15.13, each fail-closed from the release that lands
  it (e.g. the mandatory `secrets(..)` declaration).

`sandblaster::build::compile` takes no options.

**Where the gates run.** Enforcement is attached to the crate verdict.
`driver::build_crate` — the crate path — runs, in order: the proofs (every
definition kernel-checked, every obligation and law proven, the law
non-vacuity audit, the resource gate); then the six gates: the boundary
(`validate::spec15_gate`), examples, coverage and spec closure
(`examples::spec15_gate_s1`), sections (`complete::spec15_gate_s3`), the law
rules (`law_rules::spec15_gate_laws`), the lock (`lock::enforce`) and spec
mutation (`mutate::spec15_gate_mutants` on the engine's gate mode); then the
optimizer, the printer, the round trip, the emission-chain cross-check and
the resource gate again. Spec mutation, by far the most expensive, runs
once the other gates passed (when one failed the crate has failed; the
report says the mutation gate did not run). The boundary gate runs here,
not in the front end's `validate()`: the front end serves the toolchain's
stage tests too, whose small programs export `pub fn`s at their root.
Every path that writes crate output (`OUT_DIR/sandblaster.rs`, the lock),
states a crate verdict (`sandblaster::build::compile`, the CLI's `check`,
`emit`, `report`, `spec`, `spec --accept`, `coverage`) or runs from a
`build.rs` goes through it. The report records each gate's outcome and the
SHA-256 of the emitted file.

**Gate mode of the counterexample engine.** The spec-mutation gate runs
every spec mutant, with no cap, no deadline and no environment variable
(the `SANDBLASTER_MUTANTS_*` variables shape only `sandblaster coverage`'s
exploration run), on the build's own elaboration as the baseline. Only an
example (vector records included) or a definite counterexample to a law can
kill a spec mutant (§15.7), so a mutant's re-check elaborates only its spec
closure — the mutated spec item and the spec functions that use it, with
their examples — and the `bool` checkers of the laws in its closure, never
proofs or the implementation. Its known answers run one per elaboration,
stopping at the first kill: the `#[example]`s nearest the mutated item
first, then the smallest vector file (stopping at its first failing
record); then the distinguishing search — a survivor without a
distinguishing input is possibly equivalent, which passes, so the larger
vector files run only for a survivor with a witness. Batches run on up to
four threads (a resource setting; verdicts are per mutant).
**Incremental spec mutation**: with the verdict cache (§2.1), a spec
mutant's verdict is stored under a key that covers everything its re-check
reads — the toolchain, the gate options, the mutant (item, operator, site,
diff), its plan (closure, known answers, observation points) and a
position-independent fingerprint (HIR without spans, indices replaced by
paths) of every item reachable from its clones, law checkers and compared
functions — so an edit re-runs exactly the mutants whose statement or code,
or the code of something they read, changed. Resource outcomes (not run,
killed only by budget) are never stored; a stored outcome restores the
verdict, its witnesses and its LR8 records, so the report is the same as a
cold run's. The hit and miss counts are in `<out>-timing.json`, never in
the report.
Implementation mutants run only when a section is not fully specified: when
every `complete_p` is proven no implementation mutant has an observation
point (§15.9), so none can produce a finding.

The would-be escape hatches, and how each is closed:

| Escape hatch | Closed by |
| --- | --- |
| an attribute, flag, env var, feature or profile to skip §15 | none exists; `SANDBLASTER_MEM_LIMIT_GB` and the goal timeout only change resource limits and `SANDBLASTER_STRICT_OPT` only makes the optimizer stricter — none can turn a failure into a pass |
| running out of budget | a failed obligation, never a pass or a skip |
| delete `SPEC.lock` and rebuild | a missing lock is an error; only `sandblaster spec --accept` writes it |
| a spec that calls the implementation or reads its constants | spec closure (§15.1) |
| a spec that is a copy of the implementation | `#[mirrors_impl(justification)]` plus independent laws or examples, on the surface and in the lock |
| laws that don't pin behaviour down | determinacy (§15.5) for every exported function |
| circular "relative" completeness | computed, well-founded sections (§15.5) |
| a lossy view hiding wrong output | determinacy through views needs `view_inj` or `Abstract(T)` (§15.2) |
| a precondition that excludes the interesting inputs | boundary functions have no preconditions; internal ones must be non-vacuous and met by examples (§15.5) |
| `pub` helpers exported without a spec | the boundary is the root `pub use` list, and every entry needs a spec; every host-callable function (a `pub` method of a type an exported function returns included) must be determined, and such a type must be in the list |
| a law that restates a definition as the only "spec" | a `#[definitional]` law is never a hypothesis of a section (§15.5), so it determines nothing |
| a law over a copy of the code in a plain `fn` of `LAWS.rs` | LR1: such a function is not law vocabulary |
| a check that cannot decide a law | the law rules fail closed: an undecided law rule is a finding (LR4, LR6 (a)) |
| host instantiation of exported generics (ZSTs, unlawful impls) | boundary functions are monomorphic; law traits are sealed (§3.1, §15.4) |
| forging an invariant or evidence value | invariants are `Irr` constructor fields, fields private (§15.3) |
| an optimizer transformation without proof | never emitted (emission chain, §15.2) |
| user axioms | none; assumptions such as collision resistance are explicit hypotheses (§15.13) |
| unverified Rust inside the crate | `src/lib.rs` may contain only the `include!` line (checked); other crates meet it only at the §10 boundary |
| `todo()`, open goals, unproven closers | build errors (as today) |
| the toolchain's stage APIs (verify, optimize, print, evaluate a module without the gates: `driver::stage`, `stage_emit`, `sandblaster eval`, `spec --diff`) | only `driver::build_crate` makes a `CrateVerdict` (private fields, no other constructor) or the accept permit; only a verdict prints `STATUS: VERIFIED + OPTIMIZED`, reports `VERIFIED`, writes `OUT_DIR/sandblaster.rs` or makes a CLI command exit 0 on a verdict, and only the permit lets `lock::accept` compute the lock `spec --accept` writes. Stage output carries `STATUS: STAGE OUTPUT (not a crate verdict: the §15 gates did not run)`, stage reports `PROOFS CHECKED (stage run, no crate verdict …)`, and every consumer of crate output (the `include!` glue of the bench, oracle and host-kit crates, `asmcheck`) accepts only a verdict's header; the optimizer corpus's own harness (`cgen`) accepts only the corpus root's stage output. `lock::preview_accept` computes the text of a lock and writes nothing (a lock never makes a crate pass: the build compares it and runs every gate). The phase-1 opt-in `SANDBLASTER_PHASE1_UNVERIFIED` is gone |
| a consumer override that accepts test or stage output (`QMDB_ALLOW_TEST_ONLY`, `generate.sh`'s exec-only mode) | removed: the consumers accept only a crate verdict, and `generate.sh` only runs the build; the red-team differential harness that forces portable dispatch rewrites the status to `STATUS: MODIFIED FOR TESTING (…)`, which nothing accepts |
| capping or timing out the spec-mutation gate (`SANDBLASTER_MUTANTS_MAX`, `--mutants-max`, `--time-budget`, `SANDBLASTER_MUTANTS_TIME_BUDGET`) | the gate's options are fixed (`MutateOptions::gate`: every spec mutant, no deadline); those caps shape only `sandblaster coverage`'s exploration report, and a capped or stopped run is `error[mutation-incomplete]` anyway |
| a gate placed where some path skips it (e.g. the boundary rules inside the front end's `validate()`, which the stage tests also call) | every gate runs in the crate path, so it applies wherever a verdict is stated; stage paths state none |
| laws that restate the code | LR1 (laws mention only spec items and exported functions), LR5 (mirrors against every function), LR6 (echo) |
| a security law satisfied by the mere existence of collisions | LR4 (extraction form) |
| a security law whose break predicate follows from its hypotheses | LR4 (vacuity: bounded `auto` on `requires ⇒ B(t̄)`) |

Adoption follows from this: there is no transitional mode. A crate
(including `qmdb`) switches to the §15 toolchain in the same change that
makes it fully specified (§15.12).

### 15.9 The counterexample engine (untrusted, diagnostic)

A completeness obligation that is not proven already fails the build. The
engine explains why, by trying to refute it:

1. **Mutants.** Operator replacement (arithmetic, bitwise, comparison,
   boolean), constant perturbation (±1, bit flips, zero), condition negation,
   guard/check deletion, return-value replacement, loop-bound and index
   off-by-one, argument swaps — on the section's typed HIR, printed back as
   source diffs.
2. **Incremental re-verification** of only the laws and obligations that
   depend on the mutated function (bounded budget).
3. **Distinguishing input.** For each surviving mutant, search for an input
   where mutant and original differ (examples, boundary values, random
   inputs; kernel `eval_closed` for small inputs, native generated code for
   speed). Found ⇒ a **definite counterexample**, reported as
   `error[spec-incomplete]` with the diff, the input and both outputs; not
   found ⇒ "possibly equivalent mutant" (listed, never an error).

The engine never makes anything pass. Mutants killed by their own safety
obligations or by budget exhaustion are reported separately and never count
as killed by the specification. The engine runs mutants in sequential
batches and re-elaborates from scratch every N mutants or at a memguard
soft-limit fraction (the kernel `Env` has no removal). A definite
counterexample may be emitted as a kernel-checked refutation of
`complete_p(R)`.

### 15.10 Reporting

`sandblaster-report.json` and `sandblaster coverage` add, per function: safety
obligations and how they were discharged; the spec it refines or the laws
that mention it; its section and status (**fully specified**, or — in a
failed build — **partially constrained** with surviving mutants or
**unspecified**); mutation kill rates against proofs and (optionally) tests;
example counts and outcome coverage; the spec sheet. Per boundary function
it also reports the emission chain and the TCB and assumptions statement of
§1.1. Diagnostics follow four fixed shapes: `error[refines]` (a definite
counterexample, localized), `error[refines-unproven]` (the stuck goal and a
suggestion), `error[spec-incomplete]` (the mutant diff, the input and both
outputs), and `error[spec-lock]` (old and new statement with their
classification). They are rendered in rustc's layout and also written as
JSON for editor integration.
Law diagnostics: `error[law-mentions-internal]` (naming the function and
suggesting `#[refines]`), `error[law-restates-impl]` (with the unfolding that
proves the law), `error[vacuous-reduction]` (with the closed subformula).
The report's `gates` section lists each gate (ran, errors, warnings, a
one-line note), the spec-mutation gate's counts and law sensitivity, the
emission-chain findings and `emitted.sha256`, the hash of the generated
file; `sandblaster check` prints the same, one line per gate. Wall-clock
times (the gates', the mutation gate's and its batches) are in
`sandblaster-timing.json`, never in the deterministic report.

### 15.11 QMDB to fully specified

Prerequisite: the production domain (full u64 locations up to the MMR
maximum, production chunk size N = 32) replaces the Bend limits D1/D2
(`qmdb/README.md`); §15 specifies that verifier, not the Bend-limited one.

* `spec::sha256` = FIPS 180-4 (`spec/sha256.rs`, section by section, with
  named step functions such as `rounds(t, v, w)`). `hash_total` extends it
  with ℓ mod 2^64, and the law `hash_total_is_fips` relates the two on
  ℓ < 2^64. `compress` `#[refines(spec::sha256::compress)]` by `bv()`.
  `hash` `#[refines(spec::sha256::hash_total)]` by the padding lemma, block
  induction and post-loop facts. The fixed-size wrappers refine it through
  view coercion. CAVP vectors are `#[examples]`. The streaming hasher uses
  `#[represents]`.
* `codec`: spec decoders transliterated from Commonware's codec, a spec
  encoder, and the canonicality law (decoder ⇔ encoder); `#[refines]` on each
  decoder; Commonware fixtures as examples.
* Index spaces: `Location`, `Position`, `Height` invariant newtypes;
  `verify_member -> Option<VerifiedMembership>` evidence (witness stored).
* `merkle`, `verifier`: the reference semantics (the Bend original, widened
  to Commonware's production domain) transliterated into `spec::` functions
  over unbounded `Seq`/`Nat`, with no representability hypotheses. Code
  `#[refines]` them, with explicit `domain =` on internal helpers whose
  defensive checks exceed the reference. The laws are replaced by the five
  laws of `docs/qmdb-spec-design.md` (complete, sound, unique, canonical,
  bounded) over `spec::` items only (§15.1 LR1–LR10); `verify` and
  `verify_fixed` `#[refines(spec::proof::verify)]`.
* The boundary becomes the root `pub use` list (`verify`, `verify_fixed`,
  `verify_member`, `VerifiedMembership`, `Digest`, `Location`, `Position`).
* For the generic QMDB-full verifier (§14): the same, per instance and
  generically via sealed traits with laws. Fuel-bounded specs need
  `#[fuel_sufficient]` for 2^62 leaves. Examples cover each instance.

As built (S5, 2026-09-26; details in `docs/qmdb-spec-design.md`, "As
built"): `spec/` has `sha256`, `tree`, `db`, `proof`, `codec` and a config
per instance; `verify`, `verify_fixed`, `compress` and the nine fixed-size
hashes carry `#[refines]`; the five laws and two tree laws are proven for
N = 32 and N = 1; Commonware's known answers and roots and the CAVP vectors
are kernel-checked examples; both roots have an accepted lock. Not built
from the list above: `hash_total` and the general `hash` (deleted, since
nothing called it), the index-space newtypes and `verify_member` (the
boundary is still `verify`, `verify_fixed`, `Digest`), `#[represents]`, and
`domain =` (the helpers' defensive checks are proven dead instead). The
coverage gate exempts a break predicate (`collision`, the last disjunct of a
`#[reduces_to]` law) from needing a `true` example.

### 15.12 Plan

* **S0**: post-loop facts (§7.4); the live boundary fixes (§3.1: no `Irr`
  binders, no generic slice parameters at the boundary); `#[refines]` on
  types becomes an error; the §15 interface commit (HIR fields, annotations,
  erasing macros, additive `ObligationKind`s); kernel `abstract_section`,
  `refs_closure` and `eval_closed`.
* **Law rules (§15.1 LR1–LR10):** LR1–LR7, LR9 and LR10 landed in S3
  (`elab::law_rules`; LR6's echo check runs `auto` without arithmetic in the
  restricted view of the closing statements); LR8 in S4. Like every §15.8
  check they are errors for every crate with no exemption: each build
  records the findings (report `law_rules`, the sheet's law table) and the
  gate `law_rules::spec15_gate_laws` reports them; the crate path calls it
  on every build (S5).
* **S1**: `#[spec]` modules, spec closure, `Seq`/`Nat`, view coercion, and
  `#[refines]` (views, `represents`, state passing, `domain`, explicit call
  form, `#[proof(refines = ..)]`); examples as kernel lemmas; the spec sheet
  and a Merkle `SPEC.lock` (+ `--accept`, `--diff`).
* **S2**: invariants as `Irr` constructor fields, visibility and
  `Abstract(T)`, `ViewInjective`, evidence types, ghost parameters.
* **S3**: computed sections, `complete_p(R)` via `abstract_section`, `auto`
  support, the emission chain; `#[determined]` and sealed law traits once
  static traits land.
* **S4**: counterexample engine, `sandblaster coverage`, spec mutation.
  Landed as `mutate` (§15.9 steps 1–3 with sequential, memory-adapted
  batches; §15.7 spec mutation; LR8): recorded by `sandblaster coverage`, and
  enforced by the gate `mutate::spec15_gate_mutants`, which the crate path
  calls with the other gates on the engine's gate mode (a run that did not
  finish is `error[mutation-incomplete]`, never a pass). Verdicts come from the underlying failure (never from a
  clone's placeholder or a blocked record); a law or refinement proof
  failure is a specification kill only with a definite counterexample
  (otherwise "killed by proofs"); constants used at type level are not
  mutated. The kernel-checked refutation of `complete_p` covers `bool`
  results that conversion evaluates. Not yet: the native evaluation path
  and the test kill rates (the report says so).
* **S5**: QMDB fully specified; the §15.8 gates switched on in the same
  change (no transitional flag). Landed in the toolchain as the crate path
  `driver::build_crate` (every gate, then optimizer, round trip, emission
  chain; the only producer of a `CrateVerdict` and of the lock-accept
  permit), with the stage APIs in `driver::stage` (header
  `STATUS: STAGE OUTPUT`, rejected by every consumer of crate output), one
  lock per root, the engine's gate mode (every spec mutant; known answers
  nearest first, one per elaboration, stopping at the first kill; a filtered
  elaboration of only the mutant's spec closure and law checkers, on up to
  four threads; measured on the S1 SHA-256 sample: 1526 spec mutants in
  about 50 s wall clock (160 s of CPU), complete and deterministic) and a read-only emission-chain cross-check. Red team:
  try to write a wrong implementation, a wrong spec edit, or any bypass that
  still builds.
* Later (§15.13): `Codec`, `Secret<T>` (before E6), `#[cost]`, hardware
  self-test, assumptions.

### 15.13 Beyond functional correctness (designed now, staged)

Type-level features for failure classes a functional spec does not cover.
Each becomes mandatory (fail-closed) in the release that lands it.

* **Canonical codecs.** `Codec` (a static trait with laws, §14.3): round trip
  `decode(encode(x) ++ r) == Some((x, r))` and uniqueness
  `decode(b) == Some((x, r)) → b == encode(x) ++ r`. Every boundary decoder
  of `&[u8]` implements it or carries `#[malleable(reason)]` (a surface
  item).
* **Resource bounds.** `#[cost(steps <= e, compress <= e')]`. The elaborator
  derives a ghost `f::cost_r` from the body (loop iterations and recursive
  calls charge `steps`; `#[charges(r, k)]` on a function charges `r`), and the
  bound is proven like `ensures`. Every boundary function has a `steps` bound
  polynomial in its input lengths (denial of service by attacker-sized
  inputs becomes a proof obligation).
* **Secrets.** `Secret<T>` (unsigned integers and arrays of them) with a
  whitelist of data-independent operations: wrapping arithmetic, bitwise ops,
  rotates, shifts by public amounts, `ct_eq`/`ct_lt -> SecretMask`,
  `select`. There is no branching, indexing, division, loop bound or `as` to
  public types on a secret. `declassify(e, "reason")` is a surface item. A
  second check on the optimized core flags secret-dependent control flow,
  indices and variable-latency intrinsics.
  `#![cfg_attr(sandblaster, sandblaster::secrets(none | ..))]` is a mandatory
  declaration, and `Secret<T>` must land before E6.
* **Assumptions.** `#[assumption(class = computational | statistical |
  environmental, cite = "..")]` items have no logical content. Security laws
  are stated in extraction form (an accepting input outside the spec yields an
  explicit collision) and tagged `#[reduces_to(..)]`. The spec sheet lists
  security claims with their assumptions.
* **Hardware self-test.** The dispatch glue runs a known-answer test of each
  selected variant against the portable reference once, and falls back to
  portable on mismatch.
* **Later:** `#[compat(equivalent | strengthen_only | weaken_only)]` against
  the previous release's locked statements; post-link stack analysis and
  `#[stack(max = N)]`; LLVM/Cranelift differential testing, and binary
  lifting of straight-line residuals checked by `BvRefl`;
  `cfg(sandblaster_hardened)` canary emission; bvnorm rewrite traces; an
  independent re-check of the exported kernel environment.
