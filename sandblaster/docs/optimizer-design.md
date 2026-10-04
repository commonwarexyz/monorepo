# sandblaster optimizer v3: compositional symbolic execution with proven summaries

Status: design, 2026-09-24. This document replaces DESIGN.md §8.2. The proposed
normative text is in Appendix A. The implementation plan is in
`docs/optimizer-plan.md`.

**Scope.** This was read-only design work. The only files written are this
document and the plan. The sources read were:

- rust-bend at `81b9c2f` plus its working tree:
  - `DESIGN.md` §1.1, §3.7, §5, §7.4, §8, §9, §13.2–13.4, §15;
  - `sandblaster/front/src/opt/*`, `auto/*`, `canon.rs`, `roundtrip.rs`, `elab/{generated,semantics}.rs`;
  - `sandblaster/kernel/src/{api,alpha,axioms,eval,term,recursion}.rs` and `bvnorm/`;
  - the prelude and lemma `.core` files;
  - `sandblaster/fixtures/qmdb/sandblaster/{merkle,codec,verifier,LAWS}.rs` and `qmdb/BENCHMARKS.md`.
- Commonware:
  - `~/code/monorepo` at HEAD `86b7ee8674`. For every cited path this is identical to the pin `6e15fe7c`, except one line in `storage/src/merkle/persisted/full.rs`.
  - PR #4811 (VROOM BLS) at `5a68b8f417`, checked out in `~/code/monorepo-blst-vendor-simd`.

**How to read numbers.**

- **measured**: from the research runs of this workflow on an Apple M5 Pro,
  release builds, run under the machine-wide admission wrapper and recorded
  with the load average.
- **projected**: estimated from measured parts.
- **x86 numbers**: hypotheses until the AVX-512 host kit (§19) has run.
- **candidate numbers**: measurements of hand-written candidates, i.e. the
  code the optimizer is designed to emit. They are not measurements of
  emitted code. Every acceptance gate in the plan measures emitted code.
  Outside the sections that say so, each such number is tagged inline
  *(hand-written candidate)* or *(third-party code)*, and an emitted figure
  *(emitted)* (fairness audit of 2026-10-02, J18). Numbers measured on
  QMDB, the corpus, codec or storage are **development-set** numbers: the
  optimizer was built on those programs, so they are regression evidence,
  not evidence of generality (DESIGN.md §8.2 item 11).

The scratch artifacts cited lived in a session scratch directory outside
the repository (`optdesign/`), written `$O` below. That directory was
ephemeral; plan milestone O1 imports it into the repository.

---

## 1. Verdict

1. **Build one compositional driver, not a set of passes.** The driver is an
   online partial evaluator (a positive supercompiler) running on the kernel's
   NbE evaluator. It works bottom-up over the call graph and produces one
   **summary** per function:
   - a residual definition;
   - a kernel-checked lemma `residual = source`;
   - an all-path decision tree for callers;
   - derived fact lemmas;
   - a parallel skeleton;
   - a cost per variant set.

   Callers use a callee's summary and never re-drive its body. Where driving
   gets stuck, it hands the site to one of three summarizers:
   - Σ2, loops: recurrences to closed forms;
   - Σ3, sequences: fusion and demand;
   - Σ4, algebra: word, GF(2), ring and refinement.

   Σ5 maps independent work onto hardware (ILP, lanes, threads). Selection
   happens per variant set against a per-target cost model. Each function has
   a certified fallback ladder that ends at the proven source.
2. **Soundness never depends on the optimizer.**
   - Every emitted function that replaces a source function carries a *plain*
     kernel-checked equality to it.
   - The frozen `check_residual_equal` API is unchanged and remains the fast
     path.
   - New results are admitted through the existing `add_def`, as an ordinary
     definition plus an equality lemma. The DESIGN §15.2 emission chain already
     admits "a lemma for any later transformation".
3. **One kernel addition: K1.** K1 is three definitional axiom schemas stating
   `count_ones`, `leading_zeros` and `trailing_zeros` as `Int` sums of
   summands that the kernel already decides (§11.4).
   - It is about 60 lines, and five existing bound schemas retire into checked
     lemmas, so net kernel growth is about 40 lines.
   - The kernel is at 9,808 of its 10,000 code lines (`AUDIT.md`), so this is
     the only kernel change the design can afford.
   - RingRefl is reflective: a checked prelude-lemma normalizer. `u128` is a
     prelude type over `Int`. The GF(2^16) lowering uses linear extensionality
     plus enumeration. Nothing else touches the kernel.
4. **QMDB's u64-domain regression is recovered with zero source changes.** The
   mechanisms and their measured candidates (*hand-written candidates*, on
   QMDB: the development set, not evidence of generality):

   | Hot spot | Mechanism | Measured before | Measured candidate |
   | --- | --- | ---: | ---: |
   | `merkle::shape` | Σ2 closed form `h = 63 − lz(L ⊕ t)` plus popcounts; per-literal induction | 24.8 / 46.0 / 61.5 ns (N=1, N=32 fixtures, uniform) | 2.33 / 2.26 / 2.30 ns |
   | peak buffer (`reconstruct_finish`) | Σ3: the `copy_range` chain over `[Z; 62]` normalizes to `B ++ [d] ++ A`, and the consumers are driven over the three segments | 89.2 ns | 73.1 ns |
   | varint readers (`parse`) | Σ1 static-measure unrolling; `location`'s `≤ 2^62` pushed into the leaves prunes the 10th byte; readers inlined into `parse` | 6.46 ns | 1.46 ns |
   | **whole N=1 `verify`** | all three (S+F+V) | **309.8 ns** (pre-H1 284.0) | **269.4 ns** (0.948× pre-H1) |

   The acceptance gate for emitted code is **≤ 275 ns**, measured with a
   same-binary A/B.
5. **Parallelism is automatic.** The source stays sequential. One
   deterministic decision procedure maps independent work innermost-first:
   - **ILP interleave**: static per target;
   - **SIMD lanes**, vertical or horizontal: static per target;
   - **threads**: only through a caller-supplied execution context, only above
     measured thresholds, and behind a guard between two proven-equal versions.

   The executor is not trusted. The templates validate tile indices, and
   parametricity does the rest (§14.4). So any `commonware_parallel::Strategy`
   is safe, including Commonware's deterministic `Sequential`.
6. **Both AVX-512 and aarch64 are primary targets.**
   - **AVX-512** (F/BW/VL/CD/DQ/VBMI/VBMI2/IFMA/GFNI/VPOPCNTDQ/VAES/VPCLMULQDQ,
     plus SHA-NI and BMI/LZCNT): variants are generated and proven now against
     models transcribed from the Intel SDM pseudocode, compile-only on this Mac.
     Dispatch waits for evidence from the host kit.
   - **aarch64** (NEON/SHA2/SHA3/SHA512, and CSSC when rustc exposes it):
     variants are validated and benchmarked locally in every milestone.

---

## 2. Where we start

### 2.1 What the optimizer does today

The optimizer is `sandblaster/front/src/opt/`, about 3k lines.

- **Specialization is straight-line only.**
  - `symex::symex` evaluates `f x̄` with `eval_opaque`.
  - `analyze` (symex.rs:189-285) accepts only *stuck-free* value DAGs: no
    `Elim::Match` on a neutral and no stuck recursive global.
  - `residual::build` turns the DAG into straight-line HIR.
  - `check_residual_equal` (alpha.rs:270-290) admits it by transparent
    conversion. That check forbids relevant `Match`, `Rec` and `Absurd`.
- Everything else is printed from the source HIR, with `get_unchecked` where
  proofs allow.
- In practice this is total unrolling, constant folding, CSE and folding of
  intrinsic models. Its measured share (development set, `qmdb/BENCHMARKS.md`):
  against the same QMDB source compiled by rustc with the same hand-written
  `compress_sha2` kernel, generated code is 0.88–1.00× at N=32 (geomean 0.95
  production, 0.96 deep) and 289 ns vs 318–325 ns at N=1 (timed before the
  fairness audit's profile split, J8, with the profile recorded on the timed
  fixtures; not re-timed since).
- The often-quoted 0.65–0.77× Commonware at N=32 is **not** the optimizer's
  number: it measures the QMDB port (a different, fixed-shape program with
  one hand-made hash function per message length, a hand-written ARMv8
  `compress_sha2` and constant N) plus the optimizer, against Commonware's
  generic verifier.
- It is also why every control function is a transliteration of the source.
  **51 of 111** QMDB functions are specialized.

Why the hot spots stay unspecialized (`$O/explore.txt`):

| Cause | Functions |
| --- | --- |
| first branch is a symbolic comparison | `shape` (`leaves > MAX_LEAVES`), `root`, `verify`, `read_partial`, `byte`, `digest`, `hash`, `fold_back`, … |
| match on a bool/`Option` parameter | `reconstruct_finish` (peak), `uint64_finish`, `graft`, `canonical`, `verify_parsed`, … |
| field projection of a struct parameter (no struct η at entry) | `active`, `verifier::reconstruct` |
| stuck self-recursion | `uint64_go`, `shape_go`, `bag_prefix`, `fold_back_go`, `path`; `sha256::equal` (`seq::eq` on neutrals) |
| match on the result of an opaque call | `location`, `parse`, `verify_decoded` |

Structural gaps: no path-sensitive evaluation (arms of a stuck match are
closures that are never evaluated), no summaries, no residual control flow, no
lemma admission for specializations, no loop transformations, no call-site
specialization, array-only entry η, no bit-count characterization in the kernel
(which is why `shape_closed_form`, `LAWS.rs:49`, is deferred), a node-count-only
cost model, and `#[rewrite]` laws that were parsed (`resolve.rs:70,93`) but never
consumed. (Since then one consumer exists: the lowering of lifted modules,
`driver::lowered`, takes the user-supplied `#[lift(opt)]` alternative a
`#[rewrite]` lemma names. That is user code, not optimizer output: it is
recorded as `LowerOrigin::UserRewrite` and counted apart from the
optimizer's residuals, whose outcome is still recorded; it is never counted
in "faster than rustc" claims and is not allowed on benchmark-target
functions; `OptOptions::exclude_user_rewrites` builds without it for
evaluation. DESIGN.md principle 3, §2.1.)

### 2.2 The regression

Widening QMDB to Commonware's u64 domain made N=1 `verify` +8.5% slower (about
24 ns, `qmdb/BENCHMARKS.md`, same-binary A/B against pre-H1). The anatomy run
(`$O/run3_verify.txt`, load about 6–8) measured 309.8 ns for H2 against 284.0 ns
for pre-H1.

| Hot spot | pre-H1 | H2 | Δ | Cause |
| --- | ---: | ---: | ---: | --- |
| `shape` | 11.2 | 24.8 | +13.6 | 63-width search (was 32). A non-peak width is 5 instructions of a serial chain; a peak about 30 (NEON popcount on every peak). The x86-64-v4 loop branches per width. |
| `reconstruct_finish` | 83.6 | 89.2 | +5.6 | `[[0u8;32];62]`: `bzero` of 1984 B plus two `memcpy`. On x86: 62 ymm (v4/SPR) or 31 zmm (znver4) stores. |
| `parse` | 3.9 | 6.5 | +2.5 | 10-byte u64 varint; 3 out-of-line reader calls returning `Option<(u64,&[u8])>` through memory |

**Trace replay** (the same hash kernels with every decision precomputed) gives
275.1 ns. H2 spends 50.4 ns of non-hash overhead; S+F+V spends 12.7 ns.
**LLVM does not recover any of this:**
- no LoopIdiomRecognize shape matches the search;
- dead-store elimination cannot trim a fixed memset against variable-length
  copies;
- the "only `[0, nb+1+na)` is read" fact exists only in the proof.

### 2.3 The general corpus

`$O/corpus/dsl/mod.rs` holds 14 programs written the natural way. It passes
`sandblaster check` (128 obligations). The optimizer specializes none of its
loops.

Measured on aarch64 (`$O/run_corpus1.txt`), in ns per call:

| Program | Pattern | Generated | Ideal | Transformation |
| --- | --- | ---: | ---: | --- |
| P1 | shift until zero, with fuel | 9.96 | 0.97 | `64 − clz` |
| P2 | descending search, early exit | 4.24 | 0.59 | highest set bit |
| P3 | 64-step bit sum | 4.59 | 0.51 | `count_ones` idiom |
| P4 | binary-decomposition search (MMR/Fenwick/buddy) | 32.98 | 1.73 | `clz(n^i)` + popcount |
| P5 / P5b | leb128 / 4 varints + `?` | 1.13 / 3.57 | 1.13 / 1.21 | unroll + inline in context |
| P6 | divide-by-128 loop | 2.28 | 0.52 | `(bitlen+6)/7` |
| P7 | 2 KiB zeroed buffer + copies + fold | 21.09 / 84.82 | 2.13 / 38.43 | build/fold fusion |
| P8 | build a 65-entry table, read one | 11.77 | 10.57 | compute only what is read |
| P9 | min/max scan (**control**) | 1.47 | 1.49 | LLVM vectorizes |
| P10 | `checked_add` that never fails | 4.96 / 1006 | 1.57 / 231.6 | check elimination, then vectorize |
| P11 | shift until one | 10.41 | 0.51 | `ctz` |
| P12 | byte search, early exit | 2.45 / 28.82 | 1.27 / 4.12 | word-at-a-time / SIMD |
| P13 | masked 64-bit loop | 9.01 | 0.68 | shift + popcount |
| P14 | arithmetic series (**control**) | 0.72 | 0.52 | LLVM closes it |

On x86-64-v4 no generated corpus function contains `lzcnt`, `tzcnt` or
`popcnt`. The P10 ideal uses ymm (v4) or zmm (znver4) registers; the generated
code is scalar.

---

## 3. Requirements and invariants

1. **Soundness.** The following are all untrusted:
   - the driver, the summarizers, the e-graph, the cost model and the proof builder;
   - traces, profiles, tuning evidence and the cache.

   An emitted function is justified only by kernel-checked terms. **Emission
   chain:** every emitted function that *replaces* a source function carries a
   plain equality to it. The accepted forms are:
   - conversion (tier 0);
   - `Link::Lemma` (new);
   - `clone_equiv`;
   - `variant_equiv`.

   Every *new helper* the optimizer emits carries its own lemma, and that lemma
   is used inside the equality proof of a replacing function. Whole-program
   equality follows by induction over the acyclic emitted call graph,
   instantiating callee lemmas pointwise at each call site. No function
   extensionality is needed. An unproven link is never emitted.
2. **Fallback ladder.** From strongest to weakest:
   1. closed form (Σ2);
   2. structural rewrite: early exit, idle skip, fusion;
   3. residual with control flow (Σ1);
   4. straight-line residual (tier 0);
   5. source.

   Each rung is certified independently. A failure is a warning, and an error
   under `SANDBLASTER_STRICT_OPT=1` or `#[specialize]`. One kind of failure is
   not a fault: a residual (or helper) whose obligations the provers do not
   re-prove. The residual is equal to the source, so each obligation should
   hold; the provers may simply not find the proof (the driver decided a test
   with its own procedure and the residual no longer prints it). A bounded
   counterexample search (`opt/refute.rs`: values for the obligation's
   context, every hypothesis and the goal evaluated by the kernel) tells the
   cases apart. No counterexample: a proven fallback, recorded in the report
   (`rejected_by: "not re-proven"`), with no warning. A counterexample: the
   residual performs an operation outside its domain on some input, which is
   an optimizer fault (R3, R12, R14). The search draws its values so the
   hypotheses can hold: besides a fixed pool of boundary values, every
   integer literal of the hypotheses and the goal (with `c - 1` and `c + 1`)
   is a candidate scalar, and the small ones candidate slice lengths, so a
   helper behind `#[requires(xs.len() >= 8)]` or `#[requires(k == 12345)]`
   is refuted as well. A type error, a proof the kernel
   rejects, or any other diagnostic is a fault too. So is a term the
   Σ1 proof builder builds that the kernel finds ill-typed (a motive whose
   abstraction kept no proof of unknown type: `rejected_by: "proof builder:
   ill-typed term"`, R16); the builder giving up (a budget, a leaf it cannot
   close, a proof of unknown type that breaks a motive) is not. Either way the residual
   is refused and the source is printed. Likewise a segment helper (Σ3) that
   cannot be built is recorded and its caller driven again with the call
   kept, as for fold helpers and loops; only a helper lemma the kernel
   rejects is a fault. The segment proof builder checks each leaf proof, and
   each `linarith` claim whose certificate it leaves to the kernel, before
   the lemma is committed: a proof the kernel refuses there is a proof not
   found. (Must-reject runs, whose builder trusts its claims, skip the
   check, so the kernel judges the lemma.)
3. **Always on.** There is no disable flag. Extraction is gated by a 3%
   profitability threshold, so "no gain" keeps the source print and the
   controls P9/P14 cannot regress.
4. **Zero overhead.** Emitted code must be no slower than hand-optimized code
   for the same algorithm. For threads this means Commonware's own entry
   points are called with the same or better partitions.
5. **Determinism.** Output is a pure function of:
   - the source closure;
   - the variant set;
   - `OptOptions`;
   - the checked-in `PROFILE.json` and tuning evidence;
   - the optimizer version.

   No decision reads wall-clock time or available memory. All maps are ordered.
   Seeds are content hashes. Cost comparisons use fixed-point integers.
6. **Bounded.** Every budget counts steps or nodes (§18). Memory is therefore a
   function of the budgets. `sandblaster-memguard` only aborts; it never feeds a
   decision.
7. **Hardware first-class.** Variant sets are chosen per target. AVX-512 and
   aarch64 are both primary targets.
8. **Workload source code is not edited.** `git diff --exit-code sandblaster/fixtures/qmdb/sandblaster`
   must be empty at every acceptance gate.
9. **The TCB budget holds.** The kernel stays at or below 10k code lines. This
   rules out native RingRefl, packed-array evaluators, new bvnorm rules and a
   `U128` `Width`.

---

## 4. Architecture

```
elaborated, verified crate (Env + HIR)
  │
  ├─ 1. variants: VariantEquiv (BvRefl, or the lane functor)          [variant.rs]
  ├─ 2. multiversion clone trees per variant set + clone_equiv        [multiversion.rs, mirror.rs]
  │
  ├─ 3. SUMMARY PASS, callees first; each fn is driven ONCE on its portable meaning
  │      tier 0: symex → analyze → residual::build → check_residual_equal     (unchanged fast path)
  │      tier 1: Σ1 driver ── at stuck points ──► Σ2 loops │ Σ3 sequences │ Σ4 algebra
  │      admit:  add_def(residual, helpers) + add_def(residual::equiv)        (proof builder)
  │      record: Summary { residual, link, tree, facts, skeleton, candidates }
  │
  ├─ 4. SELECTION PER VARIANT SET: candidate rungs + aegraph alternatives + feature-gated
  │      lowerings, ranked by the target cost model (+ PROFILE.json, tuning evidence);
  │      proofs of lowering-specific candidates are built only for the winner
  ├─ 5. PARALLEL PASS: Σ5 skeletons → decision procedure → fused kernels (conversion),
  │      lane-lifted kernels (lane functor), guarded thread regions (par templates)
  ├─ 6. print view: residual bodies under source names, helpers as private items,
  │      clones of residuals per set (clone_equiv), dead-helper elimination
  ├─ 7. evidence gate (unchanged) + known-answer self-test for feature-only sets
  └─ 8. canonical printer (DESIGN §8.3 + checked-arithmetic helpers) → round trip (unchanged mechanism)
```

**Driving is shared across variant sets.**
- A summary is computed once per source function.
- The residual of a clone `f__S` is the residual of `f` with its callees renamed
  to their `S` clones. It is linked by `trans(clone_equiv(r_S, r), r::equiv,
  sym(clone_equiv(f_S, f)))`; the clone equivalences are the existing `mirror`
  machinery.
- Per set, only three things differ: selection among candidates (a closed form
  is cheaper everywhere, but a set-bit loop or `pext` may win on some sets),
  feature-gated lowerings, and tier-0 re-specialization of clones whose leaves
  call intrinsic variants, so that constant padding still reaches the models.
  That last step is today's mechanism.
- Compile time therefore grows with the number of variant sets only in
  extraction and in tier 0.

**Hook points in existing code.**
- `specialize_one` (opt/mod.rs:890-980) becomes `summarize_one`. The tier-0 path
  is kept verbatim. When `analyze` rejects (909-912), `drive::run` is called.
- `Outcome::Specialized` (103-110) gains `link: Link { Conversion | Lemma(GlobalId) }`,
  `rung: Rung`, `helpers: Vec<ItemId>` and `candidates: Vec<CandidateReport>`.
- The residual item keeps its `Recursion` and bounded `decreases` instead of
  being forced to `Recursion::None` (935-936).
- The print view (729-761) maps `targets[item] = (g, compare)`. For
  lemma-admitted residuals, `compare` is the residual global, which may now
  contain `Match` and `Rec`; `alpha_eq_relevant` already handles every term.
- `mirror.rs` becomes the shared proof builder in `opt/proof/`.
- The symex opaque callback (897-900) consults summaries. A specialized callee is
  unfolded from its **residual** through its link, not from its original
  definition.

---

## 5. Data structures (untrusted, `sandblaster/front/src/opt/`)

```rust
// opt/summary.rs
pub struct SummaryKey { pub source: GlobalId, pub sig: StaticSigId }       // variant set applied at selection
pub struct Summary {
    pub key: SummaryKey,
    pub residual: Option<Residual>,          // None: the source is already the best form
    pub tree: PathTree,                      // all-path summary instantiated by callers
    pub facts: Vec<FactLemma>,               // Π x̄ h̄. P(x̄, f x̄ h̄), kernel-checked (ranges, bit facts)
    pub loop_: Option<LoopSummary>,          // Σ2 result for loop heads
    pub seg_out: Option<SegTemplate>,        // e.g. "returns drop(input, k)" for readers
    pub skeleton: Option<ParSkeleton>,       // Σ5
    pub candidates: Vec<Candidate>,          // rungs + alternatives, each with its (lazy) proof plan
    pub cost: BTreeMap<VariantSetId, CostVec>,
}
pub struct Residual { pub def: GlobalId, pub helpers: Vec<(GlobalId, GlobalId)>, pub link: Link }
pub enum Link { Conversion, Lemma(GlobalId) }  // Lemma: Π x̄ (h̄ :Irr Req). Eq(R, res x̄ h̄, f x̄ h̄)
pub enum Rung { ClosedForm, EarlyExit, SkipIdle, SetBits, Fused, Driven, StraightLine }

pub enum StaticArg { Dyn, Lit(Width, BigInt), Ctor { ind: IndId, ctor: u32, args: Vec<StaticArg> },
                     Array(Vec<StaticArg>), SliceLen(u64), Segs(SegShape) }
pub struct StaticSig { pub args: Vec<StaticArg>, pub facts: Vec<LinFact> } // facts kept only if they decide a branch

// opt/drive/tree.rs — guards partition Req_f
pub enum PathTree {
    Leaf(SymId),
    If { cond: SymId, t: Box<PathTree>, f: Box<PathTree> },
    Match { scrut: SymId, ind: IndId, arms: Vec<(u32, Vec<VarId>, PathTree)> },
    Let { var: VarId, val: SymId, body: Box<PathTree> },
    Call { callee: SummaryKey, args: Vec<SymId>, bind: VarId, body: Box<PathTree> },
    Loop { helper: GlobalId, args: Vec<SymId>, bind: VarId, body: Box<PathTree> },
}

// opt/drive/process.rs — the process graph is also the proof log
pub struct Config { pub value: V, pub facts: FactSet, pub fold_stack: Vec<(GlobalId, ProcId)>, pub depth: u32 }
pub enum Step {
    Eval,                                              // β/ι/δ(non-rec)/prim: conversion
    Unfold { g: GlobalId, args: Vec<V> },             // Delta(g; ā)
    Split { scrut: V, ind: IndId },                    // residual match; arms carry the path equation
    Prune { cond: V, value: bool, cert: LinProof },    // decided from facts
    Reuse { scrut: V, ctor: u32, eq: FactRef },        // decided by an earlier split
    Refine { var: V, lit: V, cert: LinProof },         // fact proves var = literal
    Merge { cond: V, secret: bool },                   // select (ct_select if secret)
    Apply { key: SummaryKey, args: Vec<V> },           // callee summary / fact lemma / #[rewrite] law
    CaseOfCase { outer: ProcId },                      // commuting conversion
    Specialize { key: SummaryKey },                    // polyvariant callee specialization
    Fold { ancestor: ProcId, subst: Vec<V>, measure: LinProof }, // → residual recursion; proof: Rec
    Generalize { vars: Vec<(VarId, V)>, carried: Vec<FactLemmaId> },
    Word { lhs: V, rhs: V },                           // BvRefl leaf (capped)
    Summarize(SummarizerResult),                       // Σ2/Σ3/Σ4 result with its own lemma
}
pub struct FactSet {
    pub lin: Vec<LinFact>,                 // hypothesis forms linarith accepts (DESIGN §5.8.2), with proofs
    pub ctor: BTreeMap<ClassKey, (u32, FactRef)>, // decision cache: scrutinee class → constructor
    pub bits: BTreeMap<ClassKey, KnownBits>,
    pub pending: Vec<DisjFact>,            // ne…true / eq…false: split on demand, never given to linarith
}
```

`SymId` nodes extend the residual node language `N` (residual.rs:118-136) with:

- `If`, `Match`, `SelfCall` and `HelperCall`;
- `SubSlice(base, lo, hi)`;
- `ElemRead(base, idx: SymId)`: a read at a symbolic index whose proof is
  re-proven in its own scope;
- `Enum(item, ctor, args)`;
- `WrapPrim`: residual total arithmetic, justified by the link.

---

## 6. Σ1: the driver

### 6.1 Evaluation and entry

- The driver evaluates `f x̄` with `Env::eval_opaque`. The opaque set is:
  - every user global that has a summary;
  - every recursive global on the fold stack.
- Unfolding is **the driver's decision**, not the kernel policy's. To unfold a
  folded application `g ā`, the driver instantiates `global_body(g)` and logs
  `Step::Unfold`, whose proof is `Delta(g; ā)`. The DESIGN §5.6 checking-mode policy,
  which keeps `uint64_go(10, xs, 0, 0)` folded, therefore does not change.
- **Entry η.**
  - Fixed arrays (≤ 256) are expanded as today.
  - Non-recursive single-constructor parameters (structs, tuples) become
    `Ctor(proj_1 p, …)`. Struct η is part of conversion (DESIGN §5.9), so no proof term
    is needed. This unblocks `active` and `verifier::reconstruct`.
  - `Option`, `bool` and slices stay neutral and are split on demand.
- `requires` binders become facts.

### 6.2 Unfolding control

A folded recursive `g ā` is unfolded when one of the following holds. All of
them are bounded by the unroll budget: at most `unroll_nodes` = 4096 residual
nodes per chain, within the per-function node budget.

- **Static measure:** `g`'s measure (`Recursion::Measure`, or `decreases(e, max
  = C)`) evaluates to a literal. Examples: `uint64_go(10,…)`, `uint_go(5,…)`,
  and fixed-trip loops with branches.
- **Static structure:** the structural argument is a closed spine. That covers
  an η-expanded array, and a slice of known length with symbolic elements. It
  applies to `seq::eq` over two 32-byte digests and to 5×5 limb loops.
- **Silent whistle:** the measure is symbolic and the new configuration does not
  homeomorphically embed an ancestor of the same global on the fold stack.
  Embedding is checked on a bounded skeleton key: variables become type
  placeholders and literals become width classes.

If the unroll budget predicts an explosion (the branching product exceeds it),
the driver keeps the loop head and hands it to Σ2 (§7). `shape_go`'s 63
data-dependent peaks are the example.

**Unroll or keep** (as built; fairness audit of 2026-10-02, J7). A user
recursion with a literal trip count goes to Σ2 first; when Σ2 fails, whether
the driver unrolls it (per-level helpers or in place) or keeps the loop is
the cost model's decision (`drive::unroll_pays`), formerly a fixed limit of
10 trips (the length of a LEB128 `u64`, chosen on the corpus' varint
decoder). Unrolling removes each iteration's loop overhead (one branch and
one ALU operation, as the model prices a loop iteration) and nothing else,
so it pays when that is ≥ 3% of an iteration (the selection gate; the trip
distribution cancels out), and the unrolled copies (trip count × the body's
HIR nodes) must fit the residual budget (`max_residual_nodes`, 4096). On the
development set this changes the decision for the 64-trip corpus loops P1,
P2, P4 and P11 (now "unroll" if Σ2 failed), which Σ2 summarizes first, so no
emitted code changes; the 10- and 5-trip varint readers and `shape_go` keep
their old decisions.

### 6.3 Stuck matches

When evaluation stops at `Elim::Match` on a neutral scrutinee `c`, the driver
tries, in order:

1. **Reuse.** An earlier split on a convertible scrutinee fixes the
   constructor: hash-consed by value identity, else `conv_opaque`. The proof is a
   transport along the stored path equation.
2. **Prune.** `c` is a comparison, or a `Bool` built from comparisons, and
   `linarith(facts ⊢ c)` or `linarith(facts ⊢ ¬c)` succeeds. The driver uses
   `Env::linearize` plus the untrusted simplex, as auto's step 8 does. The
   facts include, besides the path's, the invariants (§15 S2 `#[invariant]`)
   of the values `c` mentions: for `x : S` of a struct with an invariant,
   the instances `S::inv#k x` that the elaborator gives every such value
   (`opt::facts::invariant_facts`). The proof builder replays the decision
   with the same facts.
3. **Merge (if-conversion).** Both arms must be total, cheap (≤ 8 nodes each),
   non-recursive and free of partial operations. The driver emits a
   select-shaped residual.
   - On `Secret` data the merge is **mandatory**, and it is emitted through the
     `ct_select` template, which has an optimization barrier. An emitted
     `if c {a} else {b}` is never relied on to stay branch-free, because LLVM
     may reintroduce the branch.
4. **Split.** Keep a residual `match c { … }`.
   - Each arm is driven with the constructor's fields (`Ev::arm_fields`,
     eval.rs:1388).
   - The path fact `c = Ctor_k(fields)` is added.
   - Linear consequences go to `FactSet.lin`. `Option`/slice outcomes go to the
     decision cache.

**Fact normalization.** linarith rejects `ne … true` and `eq … false`
hypotheses, because they are disjunctive (DESIGN §5.8.2). The driver never passes them
to linarith. It keeps them in `FactSet.pending` and splits them on demand:
- `ne(a, b) = true` becomes a Bool split on `lt(a, b)`: one arm gets
  `a + 1 ≤ b`, the other `b + 1 ≤ a`. The equality case is contradicted by
  transport plus constructor clash.
- For an unsigned `a ≠ 0`, only `a ≥ 1` survives.

This is what makes `h < 2 ∧ h ≠ 0 ⊢ h = 1` provable (§12.3).

### 6.4 Summaries at call sites (the compositional part)

A call `g ā` where `g` has a summary is never re-driven. The cost model picks
one of three forms:
- **keep the call**, with `g`'s fact lemmas available;
- **inline** `g`'s residual through its link, when the call ABI dominates, as with
  `Option<(u64,&[u8])>` returned through memory;
- **instantiate `g`'s path tree** at `ā` (`Step::Apply`) and continue driving
  the caller through it.

**Case-of-case.** `match (g ā) { arms }` over an instantiated tree pushes the
caller's match into every leaf.
- Constructor leaves ι-reduce.
- Leaves whose facts contradict the caller's continuation are pruned.
- The proof is the commuting conversion: a dependent match on the inner
  scrutinee whose arms are `refl` after ι.
- This deletes the 10th varint byte in `location` and fuses `?` chains (P5b).

This is K's "compiling by proving" (step compression and branch lifting),
made proof-producing. The guards of a summary are the path conditions of the
all-path rules, and for loops the circularities are induction hypotheses.

**Loop calls go to Σ2 first.** A call of a user loop (a tail-recursive user
function, or the helper generated for a `for` loop) whose measure is a
literal between 2 and 64, and whose dynamic arguments are all machine
integers, goes to Σ2 (§7) first (`loopsum::candidate`). A loop that Σ2
cannot summarize is recorded as failed. The caller is then driven again, and
the loop is kept (long trip counts), split into per-level helpers (§6.5) or
unrolled, as before. A generated loop helper inside a polyvariant
specialization is unrolled there, never summarized. The report's `rung` for
the function is the loop's rung (`ClosedForm`, `EarlyExit`, `SetBits`), and
the reason names the summary lemma (`crate::merkle::shape_go::summary` for
QMDB).

**Output facts.** Callee fact lemmas enter the caller's `FactSet` at the call.
Examples:
- `shape` exports `height ≤ 62`, `before + after ≤ 61` and `index < width`,
  each proven from its closed form;
- the readers export `value < 2^(7·bytes)`.

As built (O6, `opt/facts.rs`, `opt/loopsum/facts.rs`):
- A driven function whose residual summarizes a loop with exported facts
  gets one kernel-checked lemma per fact:
  `<f>::fact#k : Π x̄ (v : S) (.e : Eq(R, f x̄, Some(v))) h̄. Eq(Bool, P_k(v), true)`.
  It is proven from the loop's fact chain (§7.5) by unfolding `f` and
  splitting on its tests.
- QMDB's `shape` exports five: `height ≤ 62`, `width ≤ 2^62`,
  `index < width`, `height + before ≤ 62` and `before + after ≤ 61`. The
  bound on `before + after` needs the bit-library family `popcnt(x) ≤ k when
  x < 2^k` (`PopcntLe`).
- **Import.** A split on a kept call of such an `f` has the path equation
  `Eq(R, f ā, Some(v))`. The driver's decisions, and the proof builder's
  replay of them, get `fact#k ā v e` as `let` facts of the child state, so
  no new binders appear.
- `auto` uses the lemmas as forward rules on path equations
  (`auto::lemmas::LemmaDb`), and the elaborator adds them in match arms (a
  hook in `dep_match` that does nothing unless facts are registered). So
  the residual's obligations re-prove with the same facts. The registries
  are emptied when `opt::optimize` starts and when it returns.

**Guard specialization** (O6, `opt/guardspec.rs`). This is the certified
fallback when facts cannot reach a callee's tests by unfolding (the
callee's residual cannot be printed, or the trial below drops it).
- Take a kept call `g ā` in tail position whose path has imported facts.
  The driver looks at the early-return guards of `g`'s body: boolean tests
  with a constant exit arm such as `None`.
- A guard the caller's facts decide in the continuing direction (linear
  arithmetic, then `auto` with case splits) is removed. The call becomes a
  call of the guard helper `g__g<n>`: `g`'s source without those
  `if c { return …; }` statements, with `!c` added to its `requires`.
- The helper is elaborated like any exec function and linked by the
  kernel-checked `<g__g<n>>::equiv : Π x̄ h̄ h̄g. Eq(R, g__g<n> x̄ h̄ h̄g, g x̄ h̄)`.
  At the call site the proof builder rewrites the source's call through
  that lemma and proves the new `requires` from the facts
  (`Step::GuardSpec`).
- If the Σ3 leaf hook (§8.2) rewrites or demand-splits that same kept call,
  the `GuardSpec` step is dropped. A leaf is never rewritten twice.
- On QMDB it does not fire. The `nb + na ≥ 62` check of
  `reconstruct_finish` tests the lengths of slices from `list_take`. Their
  counts come from saturating subtraction, `min` and bool-to-int casts,
  and linear arithmetic over `shape`'s facts does not decide that. The
  check is still in the emitted `reconstruct_finish`.

**Fact-directed unfolding is a trial.** A kept call whose arguments the
imported facts are about is unfolded (through its summary's link, or its
source) so the facts reach its tests. The unfolding is kept only when the
subtree it opens decides something the kept call could not: a test pruned
or reused, a checked call decided, a guard specialized, a split merged, a
leaf rewritten by the segment normal form. Otherwise the driver drops the
subtree and keeps the call. Decisions inside a trial are speculative and get
an eighth of the usual step cap. On QMDB, `reconstruct` still unfolds
`reconstruct_shape` and `reconstruct_checked` (the height check is pruned),
but keeps its call of `reconstruct_finish`: pasting that residual in decided
nothing and cost about 7 s of re-proof per caller. Right after the O6/O7
merge, when this unfolding was unconditional, the optimizer took about 5×
the G9 baseline. With the trial rule and the prover speedups made at the
same time, it is back under 1.5× (`docs/opt-o6-o7-reports.md`).

### 6.5 Polyvariant call-site specialization

- **Trigger.** A call `g ā` with some non-`Dyn` `StaticArg` (literals,
  constructors, segment shapes).
- **Result.** The driver creates `g_σ`, memoized on `(g, canonical σ)`. Facts
  enter σ only if they decide a branch of `g` (demand-driven generalization).
- **Lemma.** `Π dyn̄ h̄. g_σ dyn̄ = g(statics, dyn̄)`.
- **Budget.** At most 8 specializations per callee and 64 per crate, and a
  specialization is created only when its estimated gain is ≥ 5% of the
  caller's cost.
- **Uses:**
  - `shape_go(63, t, L, 2^62, 0, 0, 0, None)`;
  - consumers over segment lists (§8.2);
  - constant multipliers (curve25519 `mul(x, A24)`: 7.7 → 5.0 ns measured
    *(hand-written candidate)*);
  - sparse operands (BLS `mul_by_014`);
  - fixed-(k, m) Reed–Solomon block encoders.

### 6.6 Folding and generalization

**Folding.** A fold to an ancestor configuration with substitution θ becomes a
residual self-call, or a call of a new residual loop helper.

- **No mutual recursion.** The kernel has none (DESIGN §5.6), so a back-edge may target
  only the nearest enclosing unfolding of the **same** global inside the
  current residual function's subgraph.
- **Out-of-scope back-edge.** A back-edge to an ancestor above that subgraph
  is refused: the driver generalizes at that ancestor instead.
- **Measure.** The residual reuses the source measure at the fold target. The
  proof is `Rec(θ; p)`, where `p` is the decrease proof built from path facts
  (mirror's `rec(ā; p)`, mirror.rs:239-241).

**Generalization.** When the whistle blows, the driver computes the most
specific generalization (anti-unification) of the two configurations and
restarts from `let x̄ = ā in C_gen`. This is justified by ζ-conversion.

**Carried invariants (Houdini).** The candidate invariants over the generalized
variables are:
- range facts;
- linear relations fitted exactly on up to 64 traces;
- bit-shape facts (`w & (w−1) == 0`, `w == 1 << (f−1)`, `r == L & mask(f)`,
  `s + r == L`);
- the facts in scope at the loop head.

A candidate survives only if it is proven at entry and preserved along every
back-edge; the driver iterates to a fixpoint. Survivors become `requires` of
the residual function and `Irr` binders of its lemma. This is how P10's
`acc + len·(2^32−1) ≤ 2^64−1` prunes the `None` arm of `checked_add`.

### 6.7 Residualization and printing

- **Process graph to HIR:**
  - a split becomes `match`/`if`;
  - a self-fold in tail position becomes a self-call, printed as the canonical
    `loop { … continue … }`;
  - a non-tail fold becomes a recursive call carrying the source's
    `decreases(.., max)`;
  - generalization becomes a `let`;
  - a merge becomes a select or `ct_select`.
- **Scoped emission.**
  - Lets are bound inside arms.
  - Hash-consing is per scope; a node is lifted only when it is *total* and
    used by both arms.
  - **A partial operation is never hoisted above its guard.** A `Partial` node
    (index, `split_at`, division by a non-literal, a checked arithmetic kept
    checked) may be placed only where a linarith query shows that the path
    facts imply its domain condition. The query runs at extraction time, so a
    pruned guard can never strand an unchecked read.
- **Elaboration.** The residual HIR goes through `elab::generated::resume`
  (elab/generated.rs:240-261). Proof slots are re-proven there, and the kernel
  checks the recursion mode. An obligation that is not re-proven is searched
  for a counterexample (§3 item 2).
- **Unsized values.** A slice result is never a local: the straight-line
  printer binds its reference (`let s: &[T] = f(..)`), as rustc requires.
- **Hardware vectors.** A lane array where an intrinsic, a helper or a call
  takes a vector (the driver evaluates `load_u32x4(&[1, 2, 3, 4])` to its
  lanes) is printed through its load helper, in both printers.
- **Assembled arrays** (`opt/residual/assemble.rs`, both printers). Symbolic
  execution turns a message built as `let mut m = [0u8; 40];
  m[0..8].copy_from_slice(&n.to_be_bytes()); m[8..40].copy_from_slice(&d)`
  into a spine of 40 element values. Printed as an array literal, that is 40
  byte stores and 32 byte loads, which LLVM does not merge. The printers find
  the runs in the spine and print the buffer as it was built: a zeroed local,
  `copy_from_slice` from `&d` or `&d[lo..hi]` (consecutive reads of an array
  variable), from `x.to_be_bytes()` / `x.to_le_bytes()` (the bytes of one
  integer in order), a store for any other element, nothing for zeros.
  - The block is used only with a copy of at least 4 elements, at least two
    pieces and at most one statement per 4 elements. Arrays made only of
    integer bytes, or of one sub-array, stay literals: LLVM already turns them
    into byte reversals and vector loads.
  - An array passed to an intrinsic or a load/store helper stays a literal
    unless it has integer bytes: the local then never reaches memory (LLVM
    builds the vector with `rev` + `fmov` + one load instead of per-byte
    shifts).
  - A copy source must be an array *variable* (a parameter or a match field).
    The kernel eta-expands array variables (DESIGN §5.9), so the block
    evaluates to the same spine and the link (conversion or the equality
    lemma) is unchanged. An array returned by a call is not eta-expanded; a
    copy from it would stay a stuck `append` and fail the link, so its reads
    stay elements.
  - Measured on QMDB N=1 `verify` (same binary, *emitted*, development
    set): 0.8878 → 0.8737 of H2. A micro-benchmark of one QMDB message shape
    (a 40/48-byte seal message built from an integer and a digest; *(hand-
    written candidate)*, not a measurement of the class) builds the message
    4.6× faster.
- **Ghost arguments.** A kept call of a function with `#[ghost]` parameters
  passes their values: the components of the call's ghost bundle, printed as
  ghost `Int` expressions (`x as Int + 5`), elaborated with the residual and
  erased from the printed code with the parameters.
- **Wrapping arithmetic.** When overflow freedom is not locally re-provable
  (symbolic shift amounts in closed forms, for example), the arithmetic is
  emitted in total form (`wrapping_*`) and justified by the link. That costs
  nothing at run time.
- Printing follows DESIGN §8.3, plus the checked-arithmetic helpers (§11.5) and
  `#[inline]` on residual helpers below the inline threshold. `#[inline]` is a
  semantics-free attribute and is ignored by the round trip.

---

## 7. Σ2: loop summaries

### 7.1 One iteration on symbolic state

Take a loop head `h(s̄)` with measure `m`: a loop helper, a tail-recursive
function, or a stuck `Loop` configuration. The driver runs **one iteration** on
a fully symbolic state with the fact `m ≥ 1`. The result is a set of guarded
transformers `(φ_π, τ_π)`: each path ends in `h(τ_π(s̄))` or in an exit value
(SYMPLE-style).

### 7.2 Recurrence classes

Each state variable is classified from its per-path updates. The driver first
removes saturation when a fact makes it exact, e.g. `(pos + 2w).sat_sub(1)`
with `w ≥ 1`, via `sat_sub_def`.

| Class | Update shape | Closed form (in remaining measure `f`, ghost entry values `ḡ`) |
| --- | --- | --- |
| `Const` | unchanged | `g_v` |
| `Affine(k)` | `v + k` | `g_v + k(f₀ − f)` |
| `Geometric(s)` | `v >> s` | `2^(f−1)` (normalized) |
| `BitDigit(w)` | `v − w` if `v ≥ w`, else `v`; `w` geometric, `v < 2w` | `g_v & (2^f − 1)` |
| `Conserved` | Δs cancel another class | `v + u = g_v + g_u` |
| `GuardCount(φ)` | `v + [φ]`, φ a `BitDigit` guard | `g_v + popcnt(g_rem >> f)` |
| `Linear` | Δv a fixed combination of other Δs (Karr) | `Σ cᵢuᵢ + c` |
| `FirstMatch(φ, e)` | `e` when φ ∧ unset, else `v`; disjoint intervals | `pred_passed(f) ? F(ḡ) : v₀` |
| `Reduce(⊕)` | `v ⊕ g(i)` with a proven `Assoc` | `foldl ⊕ v₀ …` |
| `Map` / `Search(p)` | fresh slot / exit on first `p(i)` | `map`, `first_index` |
| `AffineGF2` | `M·v ⊕ b(xᵢ)` (bvnorm xor-set) | transformer composition (CRC folding) |
| `Unknown` | anything else | the variable stays a loop variable |

### 7.3 Traces and profiles

- **Sources of trace inputs**, at most 256 per loop:
  - **(a) profile inputs**: fixture-derived distributions recorded in the
    crate's checked-in `PROFILE.json` (§10.4);
  - **(b) seeded corner samples**: 0 and every power of two of the width
    with its neighbours (`2^k − 1`, `2^k`, `2^k + 1`, every `k ≤ W`), the
    `requires` boundaries (literals and constant expressions such as
    `MAX_LEAVES = 1 << 62`, evaluated) and the literals of the loop's own
    tests, with the seed taken from the hash of the definition. No value is
    picked for a particular program (fairness audit of 2026-10-02, J4; the
    synthesis' constants are likewise harvested from the loop, J3,
    `opt::loopsum::pool`).
- **Evaluation.** The front end's reference evaluator runs the traces; small
  cases go through `Env::eval_closed`. Traces are untrusted and only filter
  candidates.
- **Recorded:** every state variable at every iteration, the exit iteration, and
  the `FirstMatch` payload.

As built (O6, `opt/loopsum/traces.rs`, `opt/cost/profile.rs`):
- `sandblaster profile` evaluates the entry on the declared fixtures and
  records each loop head's argument vectors in `PROFILE.json`: at most 64
  per loop per root, deduplicated, and evenly strided after sorting. The
  file sits next to the DSL root's directory. For QMDB it is
  `qmdb/PROFILE.json`, with the N=1 and N=32 roots: 32 fixtures and 31
  `shape_go` calls, and 490 fixtures and 367 calls.
- The build reads the file and re-runs when it changes. It changes only
  Σ2's trace inputs, never what is admitted.
- A loop gets at most 256 samples: the profile's first, then the seeded
  corners. The corners are 0, 1, powers of two and their neighbours, the
  maximum, the call's `requires` boundaries, related pairs, and
  pseudo-random values seeded by the hash of the loop's name.
- Samples that violate the call's `requires` are dropped (checked by
  kernel evaluation).
- Each trace runs on a native interpreter of the classified one-step paths.
  The kernel also evaluates the loop call closed, and the two final
  results must agree.

### 7.4 Synthesis

The unknowns to synthesize are `FirstMatch` witness indices, trip counts and
`Search` exits.

- **Method.** Bottom-up enumeration with observational-equivalence pruning over
  the sample vector (EUSolver/Brahma style). Grammar:
  - inputs: entry values and the constants of the loop's pool: the width's
    `{0, 1, 2, W−1, W}` and the constants harvested from the loop itself
    (its literals ± 1; its shift amounts `k`, `k − 1`, `2^k`; its literal
    divisors) — never a fixed list of a target's constants (fairness audit
    of 2026-10-02, J3: the list used to carry LEB128's `6` and `7`);
  - operations: `+ − ^ & | min max`, `<<` and `>>` by terms, `/c`, `%c`,
    `mask(E)`, `lz`, `tz`, `popcnt`;
  - guards: `ite(P, E, E)` with comparisons.
- **Bounds.** Size ≤ 7, at most 2·10^5 candidates, at most 3 sent to proof.
- **Guards.** EUSolver decision trees over the loop's own comparisons.
- **Payload fields** are the per-variable closed forms at the witness step,
  simplified by the aegraph using bit facts.
- An offline, generalized **template library** (P1/P2/P4-class shapes, found by
  rulegen, §10.5) can propose candidates directly. Synthesis stays the general
  path.

As built (O6, `opt/loopsum/{synth,guards}.rs`):
- **Constants from the loop** (`loopsum::pool`, J3): leaves as above;
  divisors `2`, the shift amounts and the literal divisors; guard thresholds
  the loop's own comparison literals (and `c + 1`) and the per-iteration
  boundaries `2^(j·k)` of each shift amount `k`. `tests/fairness_pool.rs`
  checks that a literal-free loop gets only the width's constants.
- **Templates first** (`guards::affine_atom`). The shapes are `A + c`,
  `c − A` and `(c − A) / k` for `k` one of the pool's divisors, where `A` is `lz`, `tz` or
  `popcnt` of an input, of the `^` of two inputs, or of `x | 1`. They are
  written by hand; rulegen does not produce them yet.
- **Then enumeration**, bounded by size 7 and 2·10^5 classes. It runs on a
  working set of 48 samples. A candidate that fits them is checked on every
  sample, and a counterexample joins the working set, at most 4 times.
- **Guard trees** have depth one and try at most 8 of the loop's own
  comparisons.
- **A witness is kept only if the bit library can pin it** to a literal at
  each iteration. An enumerated candidate must be an affine function of one
  `lz` or `tz` atom over a variable or the `^` of two variables
  (`guards::solvable`). A template's `(c − A) / k` is pinned by magnitude
  (§7.5).
- **Open:** a guard-tree witness `ite(g, E₁, E₂)` passes synthesis, but the
  pinning code has no case for `ite`. So its lemma chain always fails, and
  the loop drops to the early-exit rung. No QMDB or corpus loop needs one.

### 7.5 Invariant, lemmas and proof

`inv(s̄, ḡ)` is generated as the conjunction of the per-variable closed forms
and the entry facts they need.

**Literal fuel at the call site** (the common case, e.g. `shape_go(63, …)`).
The driver generates **K+1 non-recursive lemmas**:

```
lemma_k : Π s̄ ḡ (.req : Req_h(k, s̄)) (.inv : inv(k, s̄, ḡ) = true). Eq(R, h(k, s̄) .req, Res(ḡ))   (k = 0..K)
```

- `lemma_0` is `Delta` plus the exit.
- `lemma_k` is `Delta` one step, then a case split on the guards, then a proof
  that the invariant transports to `k−1`, then `lemma_{k−1}`.
- Inside `lemma_k` every `2^k`, `>> k` and mask is a **literal**, which is
  exactly bvnorm's and linarith's fragment.
- No measure proofs are needed. Each lemma is small, checked independently and
  cacheable.

**Symbolic fuel.** One recursive lemma with `h`'s measure. Its step enumerates
`f ∈ [1, C]` (C ≤ 64, auto's finite enumeration) through a chain of dependent
`if f == j` arms. The last arm closes by `absurd` via linarith.

As built (O6, `opt/loopsum/{lemmas,enumerate}.rs`):
- **Pinning by magnitude.** A witness that divides a bit count, such as
  P6's `(63 − lz(x|1)) / 7`, is pinned in two steps. linarith first narrows
  the range the atom can take at the iteration; then each case uses the
  bit-library family `lz_range_k`.
- **Emitted form.** The closed form is the helper `<loop>__closed`, always
  inlined, with the summary lemma `<loop>::summary` (a stable name: the
  deferred law `shape_closed_form` can be discharged by
  `crate::merkle::shape_go::summary`) and the link `<helper>::equiv`.
- **Symbolic fuel** is the generic lemma of `loopsum::enumerate`: a chain
  of dependent tests `f < 1`, `f < 2`, …, where in arm `c` the facts give
  `f = c` by linarith and `f` is rewritten to the literal `c` in the goal
  and the hypotheses. The arm's proof then works on literals like a
  per-literal lemma, and its recursive calls are the induction hypothesis.
  The last arm contradicts the bound by linarith. Today only the set-bit
  rung (§7.6) uses it. Must-reject R28 (an arm that claims `f = c + 1`) is
  rejected by the kernel.
- **Symbolic shift amounts** (corpus P13, `k < 63 ? count_ones(n >> (k + 1)) : 0`).
  The recurrence class `MaskedCount` covers "count the set bits above
  position `k`". Its per-literal obligations shift by the variable `k`. The
  obligation prover has a threshold route for them: when the facts pin a
  shift-amount variable to a literal, it rewrites that variable to the
  literal and proves the rest on literals. P13 moved from 12.9× ideal to
  1.00× *(emitted; development set: measured on the program the feature
  was built for)*.
- **Exported facts** (`loopsum::facts`). For a `FirstMatch` loop whose
  payload is a struct of machine integers, the candidates are Houdini-style:
  `fᵢ ≤ c`, `fᵢ < fⱼ`, and `fᵢ + fⱼ ≤ c` (in `Int`), with the constants
  from the static parameters or the traces. They are filtered on the traces
  first. Then a second per-literal chain proves `holds(loop(…)) = true` for
  the conjunction. A conjunct that fails is dropped, and the chain is built
  again once. Callers use the facts as in §6.4.

**Integer reasoning.** linarith is rational, so the bit-slice and quotient steps
use an **integer-cut tactic** added to `auto`: a Bool split on `lt(atom, c)`,
which yields `atom ≤ c−1` in one arm and `atom ≥ c` in the other. Each arm then
closes with its own Farkas certificate.
- One-bit atoms such as `(x >> k) & 1` are enumerated this way.
- Quotient identities such as `t >> k = L >> k` from `s ≤ t < s + 2^(k−1)` come
  out of two strengthened certificates per arm.

**Order of checks.** The call site discharges `inv(init, ḡ)` with linarith
from the entry facts. Candidates are validated on the traces, conjunct by
conjunct at every recorded iteration, before any kernel work starts.

**Step budget.** `steps_per_loop` (5·10^8) bounds the whole summary: the
analysis, the lemma chain, the summary and link lemmas, the exported facts
and the fallback rungs. Every search and kernel check takes its budget from
the loop's meter (`loopsum::meter`) and is charged what it used; a summary
that runs out fails and the loop is kept. The report's
`budgets_used.loopsum_steps` gives the steps per driven function (QMDB's
`shape`: 11,063,271, the same in a cold and a warm build).

**The fact chain reuses the summary chain.** The exported facts are proven by
a second chain of per-literal lemmas (`loopsum::facts`). At each recursive
call it needs the same obligations as the summary chain (the invariant at
the next state, the loop's `requires`). It works on the summary chain's
outlined loop body, so those obligations are the same goals, and it takes
the summary chain's proofs of them: renamed by the names of the context
entries they use, when the goal and those entries' types agree up to that
renaming (otherwise the kernel checks the renamed proof before it is used).
Every fact lemma is still checked by the kernel.

### 7.6 Fallback rungs

Each rung is certified independently.

1. **Early exit.** Condition: once the `FirstMatch` payload is set, the
   invariant makes it final.
   - Emitted code: `if found.is_some() && t < start { return found }`.
   - Proof: an induction showing the remaining run returns `found`.
   - Measured candidate: 2.43 / 13.8 / 2.48 ns.
2. **Idle-run skip.** A run of idle iterations with `Geometric` updates is jumped
   by a bit scan (`f' = 64 − lz(rem)`). Proof: a k-step idle-run lemma.
3. **Set-bit iteration** over the `BitDigit` variable. Measured candidate: 3.76 ns
   at N=1, but 32.5 ns at N=32, which is why selection needs profiles.
4. **Residual loop** (Σ1), or the source loop.

As built (O6, `opt/loopsum/{rungs,setbits}.rs`). The rungs are tried in
the order closed form, early exit, set-bit iteration. The loop is kept when
all of them fail.
- **Early exit.** The stop test `S` is one of the payload's own in-place
  select tests (or its negation) that keeps the payload. It is checked on
  the traces: once it holds, it stays true and the payload stays the same.
  - The emitted helper is `<loop>__early`:
    `if S(s̄) { p } else { <the loop's body, recursing into <loop>__early> }`.
  - It is linked by two measure-recursive lemmas, both checked by the
    kernel. `<loop>::early::final` says that once `S` holds the loop returns
    `p`. Its induction step is where a wrong stop test fails, as in
    must-reject R6. `<loop>::early::equiv` equates the helper and the loop.
  - The call site uses an entry wrapper at the call's static arguments,
    always inlined.
  - Measured with synthesis switched off (a test hook): 2.40–2.54 ns at N=1.
- **Idle skip.** Built only at the entry. When the first iterations are
  idle (only static parameters change) while a dynamic value is below a
  static halving power of two, the entry wrapper jumps to the first
  non-idle iteration with one bit scan. Its lemmas are
  `<loop>::early::idle<j>` and `<entry>::idle_at`. Idle runs after the
  entry are still iterated one at a time.
- **Set-bit iteration.** The helper `<loop>__bits` visits only the set bits
  of the `BitDigit` variable: an idle step jumps to the next set bit with
  `min(f − 1, 63 + s₀ − lz(v))`.
  - Two enumeration lemmas link it to the loop: `<loop>::bits::idle` (an
    idle run changes nothing) and `<loop>::bits::equiv`. Both are
    kernel-checked, end to end on `shape_go`.
  - Must-reject R29 (a wrong set-bit step) is rejected by the kernel.
  - It runs only after the early exit fails, or when a test forces it
    (`LoopConfig::prefer_set_bits`). It takes about 22 s on `shape_go`.
    QMDB never reaches it.
  - Choosing between it and the early exit by cost is left to the cost
    model (plan O8).

### 7.7 Bound invariants

`Affine`/`Linear` classes with inequalities (e.g. `acc ≤ i·(2^32−1)`) prove that
`checked_add` never fails (P10). The residual then drops the `Option` plumbing
and LLVM vectorizes the loop.

---

## 8. Σ3: sequence summaries

### 8.1 Segment normal form

List-, slice- and array-valued terms built from the following operations are
normalized into a segment list `[Piece]`:
- `seq::{take, drop, append, update, replicate, index}`;
- `array::copy_range` (elab/semantics.rs), which is `take(a, lo) ++ s ++ drop(a, hi)`;
- `array::repeat`;
- range slices.

A `Piece` is `Elem(v)`, `Seg { list, lo, hi }` or `Rep { val, n }`, together
with a length that is linear in atoms.

Every rewrite is an instance of a checked lemma in the new file
`sandblaster/front/lemmas/seq.core`.
- **Most rules are unconditional**, because `seq::take` and `seq::drop` take an
  `Int` and clamp (`prelude/list.core:55-64`). Examples:
  - `take(xs ++ ys, n) = take(xs, n) ++ take(ys, n − len xs)` and its `drop` dual;
  - `update` over `append`;
  - `take`/`drop`/`index`/`update` of `replicate`;
  - `append` associativity;
  - `take(xs, len xs) = xs`.
- **Conditional rules** (`index` over `append`) take linarith side conditions
  over the length facts.
- **Rebuilt slices** go through `slice::ext : Eq(Usize, n₁, n₂) → Eq(List T, l₁,
  l₂) → Eq(Slice T, mk n₁ l₁ p₁, mk n₂ l₂ p₂)`. It is proven by J, and it is
  sound because `SliceOk` is an `Irr` Σ component (`prelude/slice.core`). This
  avoids motives over proof-carrying terms.

### 8.2 Driving consumers over segments

- **General case.** When a list-consuming callee receives a segment list, the
  driver makes a polyvariant specialization on the segment shape
  (`StaticArg::Segs`, §6.5) and drives the consumer's body over it.
  - A `[h, t@..]` match splits on emptiness of the first piece:
    - `Seg`: split on the underlying list, or on `lo < hi`;
    - `Elem`: determined;
    - `Rep`: split on `n > 0`.
  - `[init@.., last]` splits from the right.
  - Folding yields **one residual loop per `Seg` piece** over the original slice.
    No fusion law is needed in advance: correctness comes step by step from the
    seq lemmas and from the induction hypotheses at folds. This is
    supercompilation subsuming deforestation, with TT Lite SC's discipline.
- **Fast templates.** For the two most common consumer shapes, Σ3 has
  pre-proven split lemmas that avoid driving:
  - counted accumulator recursion:
    - `SP1: n ≤ |X| → g(n, X ++ Y, acc) = k(foldl step acc (take X n), drop X n ++ Y)`;
    - `SP2: |X| ≤ n → g(n, X ++ Y, acc) = g(n − |X|, Y, foldl step acc X)`;
  - `foldl_append` and `foldr_append` for plain folds.

  They are an optimization of the general case, never a requirement.

**Σ3 as built (O7, `opt/seqsum/`, `lemmas/seq.core`).**

- **Normal form** (`segments.rs`). Lists built from
  `seq::{take, drop, append, update, replicate}`, constructor spines and the
  prelude's slice and array constructors (unfolded definitionally) are
  normalized into pieces joined by right-nested appends:
  `Seg{b, lo, n} = take(drop(b, lo), n)`, `Elem(v)` and `Rep{v, n}`.
  - Every rewrite instantiates a checked lemma of `lemmas/seq.core`. The
    file has 53 lemmas plus `seq::{foldl, foldr, scanl}`, and it loads on
    the first segment site (about 0.1 s), not on every run.
  - Side conditions are linear in the pieces' lengths. They are decided by
    linarith over the path facts plus `slice::ok_len`, by the same
    procedure in the driver and the proof builder.
- **Consumer calls** (`drive.rs`). At a leaf, take a call `f(…, s, …)`
  whose slice's list is not a program slice. With one piece it becomes `f`
  on a sub-slice. With several it becomes the segment specialization of
  `f` at the pieces' shape:
  - a transparent entry `E(x̄, s̄, h̄) := f(x̄, mk(s₁ ++ e₁ :: s₂ …))`, where
    `h̄` bounds each piece's length;
  - printed as the helper `f__seg<k>`, with those bounds as its `requires`.
    `k` is the consumer's next specialization number, fixed when the entry
    is created and never reused, so two shapes of one consumer never share
    a name.
- **Helpers.** The helper is driven from `E` like any function.
  - A recursive call on the same shape is a back-edge: the helper is a loop
    with `decreases Σ|sᵢ|`, and its lemma `Eq(R, H, E)` is measure
    recursive.
  - A call on another shape is another helper, and reads resolve by the
    normal form (forwarding).
  - This is a helper per shape, instead of the `StaticArg::Segs`
    specialization above, so the driver keeps a single hook.
- **Demand splits** (`demand.rs`). A piece the facts do not decide becomes
  the residual's own `usize` length test. It is proven by splitting the
  residual only; the source has no such test.
- **Proofs** (`prove.rs`). Segment leaves are closed by a congruence walk:
  helper lemmas, δ of entries, normal forms plus `slice::ext` for slices,
  and index lemmas for reads.
  - A let-bound element type is resolved through the proof builder's `let`
    table, and `cong` refuses a type that is not closed. This is what makes
    consumers that read `[.., last]` or `xs[n / 2]` provable.
  - Before the helper's lemma is committed, the builder checks each leaf
    proof and each `linarith` claim whose certificate it leaves to the
    kernel. A proof refused there counts as a proof not found. Must-reject
    runs skip this check, so the kernel judges the lemma. On QMDB the check
    adds about 70 ms to each `reconstruct_finish` variant.
- **Failures.** A segment helper that cannot be built (it does not print,
  or its proof is not found) marks its key as failed. The caller is driven
  again with the call kept, as for fold helpers and loops. Only a helper
  lemma the kernel rejects, or a refuted or ill-typed helper, is an
  optimizer fault. If the leaf hook rewrites a kept call for which the
  driver had just recorded a guard specialization (§6.4), that `GuardSpec`
  is dropped.
- **Printing.** Optimizer helpers that no printed function reaches are not
  printed (dead-helper elimination in the print view).
- **No fast templates.** SP1 and SP2 are not built. A segment helper's loop
  runs exactly the consumer's tests: the source's emptiness test becomes
  the helper's demand test, and a call on the last piece is the consumer
  itself. So the templates would only save helper code. `foldl_append`,
  `foldr_append` and `index_scanl` are in `seq.core` for a later template
  or demand pass.
- **Must-reject.** R5 (`take` claimed to stop before the padding) is
  rejected by the kernel's linarith check. R9 (the segment order swapped at
  a back-edge) fails the helper lemma's induction step.
- **QMDB.** `reconstruct_finish` now calls the chain `root__seg0` →
  `bag_prefix__seg0` → `fold_back__seg0` → `fold_back_go__seg0` (and its
  `__sha2` twin, `root__sha2__seg0` and so on). The 62-digest buffer is
  gone. `reconstruct_finish__sha2`
  has a 480-byte frame on aarch64 and calls only `fold__sha2` and
  `root_seal__sha2`. `tools/asmcheck/o1.toml` asserts no `memset`/`memcpy`,
  no large frame and no vector zeroing on aarch64 and on the x86 targets.

### 8.3 Demand and dead initialization

- **Unread pieces disappear.** Example: the `Rep(Z, 61−nb−na)` tail beyond the
  consumed length `m`. `replicate` fills that are never read are never
  materialized.
- **Forwarding.** A read at a known offset becomes the written value.
- **Known-zero propagation.** `x ⊕ 0 = x`, `0·c = 0` and linearity of GF(2)
  operations keep `Rep(0, n)` pieces symbolic through linear passes. This is
  Reed–Solomon's `truncated_size` class, and it is the same shape as QMDB's zero
  tail.
- **Demand** (P8): `index(scanl f z xs, k) = foldl f z (take xs k)`.

  As built (O7): unread pieces are dropped (the normal form takes the
  consumed length), `replicate` fills that are never read are never
  materialized, and reads at known offsets are forwarded. Known-zero
  propagation is not built. Neither is the scan demand: `index_scanl` is in
  `seq.core`, but P8 also needs a summary of the loop that builds the table
  and a synthesized fold helper, so its code is unchanged since O1.
- **No `MaybeUninit`.**
  - It cannot be written in the safe dialect.
  - It would need a trusted template *and* a definedness obligation, because
    reading uninitialized bytes is undefined behaviour even when the result
    does not depend on them.
  - It buys nothing measurable: uninitialized 72.2 ns vs fused 73.1 ns
    *(hand-written candidates)*.
  - Buffers that escape into an unspecializable consumer keep their zeroing.

---

## 9. Σ4: algebraic summaries

### 9.1 Word algebra

bvnorm (DESIGN §9.8) is used as-is.

- **BvRefl islands.** A maximal straight-line word subproof collapses into one
  `BvRefl` (see the `Word` row in §11.2).
- **Entry cap.** The untrusted caller caps every `BvRefl` at 2·10^5 canonical
  entries and splits larger goals into per-round lemmas.
  - Whole-function SHA-class `BvRefl` is never issued.
  - Import-by-`BvRefl` of a whole body is never issued.
  - Both patterns are the >10 GB memory incident class.
- **AC-free canonicalization.** The aegraph uses `bvnorm::classify`
  (bvnorm/mod.rs:738). Its ids are comparable only within one call, so each
  region's word classes go into one batched call.

### 9.2 GF(2)-linear maps (Reed–Solomon, CRC, AES linear layers, GHASH by a constant)

- **Recognition.** A function linear in one argument over GF(2) (bvnorm xor-set
  normal form with a constant multiplier) is summarized as a bit matrix.
- **Lowering, chosen by cost:**
  - NEON `vqtbl1q_u8` nibble tables;
  - AVX2 / AVX-512BW `vpshufb`;
  - **GFNI** `vgf2p8affineqb`: for GF(2^16) with the lo/hi byte-plane layout,
    2 affines + `vshufi64x2` + one xor per 64 B.
  - On SDM-transcribed models the GFNI lowering agrees with Commonware's
    `Neon::mul` for all 65536 multipliers (measured, `$O/rs/run_gfni.txt`).
- **Proof without new trusted code.**
  - The checked prelude lemma `gf2_linear_ext`: two GF(2)-linear maps that agree
    on a basis are equal.
  - Linearity of the source: induction plus bvnorm rule 3.
  - Linearity of the lowered form:
    - syntactic for the affine model, whose parity is transcribed as an xor of
      bit extractions, not `count_ones`;
    - by explicit enumeration over 256 byte values for tables (auto's explicit
      enumeration covers ≤ 256).
  - Agreement on the 16 unit vectors, by evaluation.
  - The Reed–Solomon report's proposed bvnorm rules K3/K5 are **not needed**.
- **Runtime multipliers (staging).** A loop-invariant `mul(x, c)` is staged as
  `let t = lut(c)` outside the loop.
  - `lut(c)` is built from the 16 basis products `c·2^j` by Gray-code XORs,
    about 200 operations, justified by `mul_linear`.
  - So Commonware's 8 MiB `Mul128` table is unnecessary for correctness, and
    RS needs no packed-array evaluator.
  - Memo tables (`#[memo]`, §16) are proven through builder-induction lemmas
    `index(build(), x) = f(x)`, not by exhaustive evaluation.

### 9.3 Rings: reflective RingRefl (curve25519, BLS/VROOM, Barrett, P14)

`sandblaster/front/lemmas/ring.core` defines:
- `ring::Expr`, an AST over `Int` with atoms;
- `ring::norm`, a sparse-polynomial normalizer;
- `ring::sound : eval(e) = eval_poly(norm e)`, proven once and checked.

**Certificates.**
- A ring certificate is `trans(sound e₁, sym(sound e₂))`, where `norm e₁ ≡ norm e₂`
  holds by kernel conversion.
- Congruence mod p uses an explicit witness `k` with `a − b = k·p`.

**TCB cost: zero.** There is no native fallback. If the kernel evaluator is too
slow on the Fp12 identity (about 144 monomials) within 2·10^8 steps, the
response is a TCB-budget design note, not a silent kernel addition (plan
decision point D3).

**Uses:**
- **E1:** fold ×19 onto the narrow operand before the widening multiply.
- **E2:** narrow `u128` carries to `u64` under linarith bounds.
- **Formula selection:** Karatsuba vs flattened sums of products, e.g. BLS Fp12
  at 66t² vs 24t² multiplies.
- **P14:** `2S(n) = n(n+1)`.

### 9.4 Algorithm selection through refinement, and `#[rewrite]` laws

- **Refinement.** Two exec functions `f₁` and `f₂` that `#[refines]` the same
  spec with identity output views are equal: `f₁ x = s(α x) = f₂ x`. The
  optimizer derives `f₁ = f₂` mechanically and may replace one with the other
  per call site. Examples:
  - Reed–Solomon matrix vs FFT decode (1.9–5.2× measured at n ≤ 100
    *(third-party code)*);
  - the direct log-sum locator vs the 65536-point FWHT;
  - Straus vs Pippenger;
  - BLS RNS vs six-limb Montgomery implementations (§9.5).
- **`#[rewrite]` laws.** Each becomes an oriented aegraph rule and a
  `Step::Apply`, with the law instance as its proof. The annotation is parsed
  (`resolve.rs:70,93`) but not yet in HIR, so consuming it waits for the §15
  S0 merge.
- **Scope of automation.** The automatic part is the choice between
  implementations. The implementations themselves are written by the author.
  Automatic invention of a new representation (RNS from Montgomery, say) is out
  of scope.

### 9.5 Representation regions (view-level links, helpers only)

**The problem.** The following change limb representatives, so they are equal
only modulo p through `decode`:
- lazy reduction;
- VROOM's delayed reduction;
- Commonware's NEON (26/25-bit digits) and IFMA field kernels.

**Regions.** The optimizer forms regions between canonicalization points: bytes,
canonical equality, a boolean verdict, or inversion through the canonical
boundary.
- Inside a region it emits **new private helpers** with simulation lemmas:
  `inv(x̂) → inv(e x̂) ∧ decode(e x̂) = spec(decode x̂)`.
- The region's **boundary function**, which replaces a source function, gets a
  **plain** equality. Its proof composes the simulation lemmas and a lemma
  `obs(x) = obs(y) ⇐ decode(x) = decode(y)` at the observation.

**Restrictions.**
- A region never crosses a function whose output depends on the representative,
  such as VROOM's public `Element`. Such functions keep the source
  representation at their boundary.
- No representation-dependent value escapes a region, so nothing is persisted
  or sent between hosts in a dispatch-dependent layout. No process-wide
  "dispatch is constant" assumption is introduced.

This is a DESIGN §15.2 wording note, not a kernel change. Its must-reject test is
`view_leak`.

---

## 10. Selection: aegraph, cost model, profiles

### 10.1 The aegraph (straight-line regions only)

- **Structure.** An acyclic e-graph over let-free residual DAGs, Cranelift style:
  at most 10^4 e-nodes and 8 rounds. **Control flow stays out of the e-graph**:
  it belongs to the driver, so there are no colored e-graphs.
- **Rules** are kernel-checked lemmas:
  - bvnorm classes;
  - prelude and library lemmas;
  - K1-derived bit lemmas; P3's idiom `Σ (x >> i) & 1 = count_ones(x)` is K1's
    defining equation read right to left;
  - `#[rewrite]` laws;
  - GF(2) and ring lemmas;
  - rulegen lemmas (§10.5).
- **Proofs.** Unions carry explanations (Flatt et al. 2022). They are kept in a
  memoized proof DAG, so a shared subterm is proven once. The chosen path
  becomes an `eq::trans`/`eq::cong` chain.
  - Congruence through proof slots uses per-head `cong_irr` lemmas
    (`lemmas/cong.core`): `Π a a' p p' (e : a = a'). Eq(W, H(a; p), H(a'; p'))`.
  - These are proven by transport. The base case is `refl` because conversion
    skips `Irr` positions (conv.rs:10-12).
  - The fresh `p'` is proven by auto in the path context.

### 10.2 Cost model per variant set

- **Static part.** A list-scheduling estimate over the residual DAG, using per-op
  latency, reciprocal throughput and µop tables per target
  (`opt/cost/tables/<target>.json`). It yields latency, throughput, critical path
  and code bytes.
- **Critical-path weighting.** Work on the input → first-hash path of a
  latency-bound chain costs its latency. Work in the shadow of the chain costs
  its throughput.
  - This follows the parallelism report: the SHA chain uses about 75% of the SHA
    unit.
  - It explains why `shape` costs its full ~15 ns while buffer zeroing is partly
    hidden.
- **Dynamic part.**
  - Trip counts come from literal measures, summaries or profiles.
  - A data-dependent branch costs `penalty × min(p, 1−p)`, where `p` comes from
    `PROFILE.json`, else the traces, else 0.5.
  - The x86 H2 `shape` loop mispredicts about half its peaks.
- **Code size.** Charged against a per-loop-body budget (op cache / L1i) and the
  crate growth cap. PR 4811's G2 insertion loop varied about 13% between
  identical-source builds because of code placement alone.
- **Tuning evidence.** `sandblaster/targets/evidence/tuning-<arch>-<uarch>.json`,
  produced by the host kit (x86) or by local calibration (aarch64). It sets
  constants such as b*, k_sat, θ, the 512- vs 256-bit choice and `pext` speed.
  **It changes choices only, never correctness.**

Seed operation costs (x86 values are provisional until the host kit runs):

| op | x86-64 v1 | x86 v3-scalar | x86-64-v4 | aarch64 M5 |
| --- | --- | --- | --- | --- |
| `count_ones(u64)` | ~12 ops (SWAR / `psadbw`) | `popcnt` 1 op (lat 3) | `popcnt`; lanes `vpopcntq` | `fmov;cnt;addv;fmov` (4); `cnt` with CSSC |
| `leading_zeros` | `bsr` + fixup | `lzcnt` 1 | 1; lanes `vplzcntq` | `clz` 1 |
| `trailing_zeros` | `bsf` + fixup | `tzcnt` 1 | 1 | `rbit;clz` 2 (`ctz` with CSSC) |
| `pext` | – | excluded (Zen 1/2 microcode it) | 1 (all AVX-512 AMD parts are Zen 4+) | – |
| 64×64→128 | `mul` | `mulx` | `mulx`; IFMA 52-bit lanes | `mul`+`umulh` |
| SHA-256 block | portable ~150 ns | SHA-NI (hypothesis) | x16 lanes when ≥ b* ≈ 7 | SHA2: 19.7 ns lat / 14.9 ns tput, k_sat = 2 (measured) |

### 10.3 Multi-candidate extraction

- **Candidates** for each (function, variant set): the ladder rungs, the aegraph
  alternatives and the feature-gated lowerings.
- **Winner:** argmin of the objective, which is critical-path latency for
  single-shot sites and throughput for batch sites. Ties go to fewer code bytes.
- **3% profitability gate.** A candidate replaces the next rung, or the source,
  only if its modeled cost is ≤ 0.97× that rung's.
- **Retries.** The top 3 candidates are kept. After a proof failure at most 2
  retries follow, each avoiding the failed step. After that the next rung is
  used.
- Proofs of lowering-specific candidates are built only for the winner.
- Every candidate's cost and the decision go into `sandblaster-report.json`.

### 10.4 Profiles (`PROFILE.json`)

Distribution-dependent choices cannot be ranked from corner-biased traces. The
measured examples:
- set-bit iteration: 3.76 ns at N=1, 32.5 ns at N=32 *(hand-written
  candidate, development set: QMDB's `shape`)*;
- `pext` wins only for 5–9-byte varints;
- SIMD search pays only for scans longer than about 32 B.

**The command.** `sandblaster profile` runs the portable build (reference
evaluator, or native instrumentation) over the crate's declared corpora: its
`#[example]`s, its test vectors and its benchmark fixtures.

**Train ≠ test** (fairness audit of 2026-10-02, J8). A profile is never
recorded on inputs a benchmark times. QMDB's fixtures are split by a rule
fixed before any measurement (`sandblaster/fixtures/qmdb/splits/`: sorted by
name, alternating; frozen by G6); `PROFILE.json` is recorded on the profile
halves (`splits/n1-profile.txt`, `splits/n32-profile.txt`) and a benchmark
times the other halves only. `Profile::check_timed` refuses a timed input
that lies in a profile corpus (`tests/fairness_profile.rs`), results are
reported with and without the profile, and a subject that uses the profile
is compared with a rustc baseline that gets PGO too.

**The file.** It writes a checked-in `PROFILE.json`:
- branch probabilities keyed by the hash of the source location;
- trip-count histograms;
- value-size histograms (varint lengths, scan lengths, peak counts).

It changes choices only. When it is absent, the defaults are 0.5 and the
corner-biased traces. Because the file is checked in and part of the
determinism key, builds stay reproducible.

### 10.5 Offline rule discovery (`sandblaster/rulegen`, not in the build)

**Pipeline.** Ruler/Enumo style with Hydra-style generalization:
1. enumerate terms of size ≤ 6–7 over word, bit-count, comparison and `seq`
   operations;
2. fingerprint them (exhaustive at U8, plus 256 seeded valuations with corners);
3. generalize literal parameters;
4. prove each candidate by `bvrefl`, K1 lemmas, auto or linarith;
5. drop failures.

**Output.** `lemmas/rules/*.core` and `rules.json`, committed to the repository.

**Second mode.** Mine expensive subterms from residual DAGs of the four
workloads (Souper/Minotaur style) and search offline for cheaper equivalents.

**Every build re-checks every rule lemma.**

### 10.6 As built (plan O8)

- **Aegraph** (`opt/egraph/`). It runs on the straight-line residual of a
  function that tier 0 admitted by conversion and the driver did not
  replace. The region is the function's symbolic value rebuilt as a term over
  its parameters (`quote_region`): primitive operations, literals,
  parameters, opaque calls and constructors; any other value refuses the
  region. Proofs are never quoted: a checked operation whose obligation is
  closed gets `refl`, any other uses its wrapping form (the chain starts with
  `bvrefl`, which reads checked operations as wrapping ones). Budgets: 10^4
  e-nodes, 8 rounds; regions whose tree is larger than 2·10^4 nodes, or
  smaller than half of every rule's left side, stop before any work.
- **Matching** is modulo `bvnorm`: a class is compared with a rule's left side
  at up to three instances (the classes of the variable's width that occur
  most often below it), all in one `bvnorm::classify` call. A trigger
  (operation histogram and size of the left side, read from the rule file
  without loading it) gates the call, so QMDB's regions never reach `bvnorm`
  or the library.
- **Link.** `r::equiv : Π x̄. Eq(R, r x̄, f x̄)` is a transport chain from
  `bvrefl(R, C₀, f x̄)` (`f` may be opaque, so conversion alone does not
  unfold it), one transport per rewrite with the motive abstracting the
  rewritten subterm. A rewrite whose subterm is an operand of a checked
  operation whose proof mentions it is lifted to that operation by the
  `cong_irr` lemmas (tested directly: the proof-free regions do not need it
  today). Rule instances are memoized.
- **Rules.** `lemmas/rules/bitsum.core` (the bit-sum idiom for every source
  width summed in `u32` and in its own width, with the helper lemmas
  `bs_bit`, `bs_step`, `bs_bound`) and `lemmas/cong.core` (50 lemmas), both
  written by `sandblaster/rulegen` (template instances filtered on
  corner and random inputs — two wrong controls per width are dropped —
  then proven with certified `linarith` holes and checked by loading).
  The optimizer loads both, checked by the kernel, when a trigger first fires
  (about 38 ms).
- **Cost model** (`opt/cost/{tables,tuning,model}.rs`). Tables per level
  (x86 v1, v3-scalar, v4; aarch64) and microarchitecture (SPR, Zen 4, Zen 5;
  M5), in milli-cycles, each entry `Measured` (from a committed tuning file:
  Zen 5 host round 0, M5 local calibration) or `Hypothesis`. The cost of a
  residual is `(CP + ΣTP)/2`; branches split the probability of the code
  after them (½ without a profile; an arm that returns early takes its share
  out of the rest; a `?` fails with probability 1/16); a set's cost is the
  worst over its microarchitectures. The 3% gate, the top 3 and two retries
  apply to aegraph candidates and to loop rungs. Lane candidates (O10) are
  priced by lifting the scalar DAG to 128-bit operations.
- **Rungs by cost.** The loop summarizer prices the closed form (its `res`
  definition), the early exit (loop body × mean exit iteration over the
  traces) and the set-bit iteration (body plus jump × mean active iterations);
  a weaker rung goes first only if it is ≥ 3% cheaper. For every loop of the
  corpus and QMDB the closed form stays first; the costs are in the report.
- **Determinism.** `Tuning::hash` (FNV-1a over the committed files) and the
  profile samples key the proof cache (`opt::choice_inputs_hash`); a changed
  tuning file changes choices (tested), identical inputs give identical
  output.

---

## 11. Certification

### 11.1 Admission route

1. `resume` elaborates and commits the residual exec definitions (`res` and its
   helpers). The kernel checks them, including their recursion modes, so a
   residual loop cannot diverge.
2. `add_def(res::equiv)` commits the lemma
   `Π x̄ (h̄ :Irr Req_f). Eq(R, res x̄ h̄, f x̄ h̄)`, with `kind = Lemma`,
   `opaque = true`, and its recursion mode copied from the residual.
3. The print view emits `res`'s body under `f`'s name. The round trip compares
   the printed code with `res`.

`add_def` forbids self-reference except through `Rec`, and every definition
refers only to earlier globals. So the emitted call graph is acyclic by
construction.

### 11.2 Step → kernel term

| Step | Kernel term |
| --- | --- |
| `Eval` | none (conversion) |
| `Unfold g ā` | `Delta(g; ā)` |
| `Split` on a variable | dependent-match idiom `(match x as y return Π(.e: Eq(T,x,y)). Eq(R, res[y], src[y]) with arms λ.e. P_k) refl` (`mirror::plain_match`, generalized) |
| `Split` on a non-variable `s` | motive from `Env::abstract_occurrences(ctx, goal, s)` (api.rs:229-258); each arm gets its path equation as an `Irr` binder |
| `Prune c = b` | `transport(Bool, b, c, sym(Linarith{…}), y. Eq(R, res, src[y]), P_arm)` |
| `Refine x = lit` | transport along the linarith equality (two certificates) |
| `Reuse` | transport along the stored path equation |
| `Merge` | case split; both arms reduce to the select (`ct_select` is a checked definition equal to `if`) |
| `Apply` | lemma instance `L ā h̄` (summary, fact, law), side conditions from facts |
| `CaseOfCase` | dependent match on the inner scrutinee, arms `refl` after ι |
| `Specialize` | the specialization's own lemma |
| `Fold` | `Rec(θ; p)` inside the recursive lemma |
| `Generalize` | β/ζ conversion; carried facts proven at entry and at each fold |
| `Word` | `BvRefl(R, l, r)` (capped) |
| congruence | `eq::cong`, `eq::trans`, `eq::sym` (`prelude/base.core:34-38`); `cong_irr` through proof slots |
| bit facts | `Axiom{K1}` instances and K1-derived lemmas (`lemmas/bits.core`) |
| arithmetic | `Linarith{hyps, goal, cert}` with integer cuts as Bool splits |

### 11.3 Proof builder (`opt/proof/`)

The proof builder generalizes `mirror.rs`. Mirror relates two α-equal bodies;
the builder mirrors the **residual** against the source unfolded along the
process graph. Terms are built bottom-up in the residual's binder structure,
exactly like `Mirror::prove` (mirror.rs:157-284). They are committed the way
`prove_clone` commits (mirror.rs:438-483).

The memoized proof DAG shares repeated subproofs through `Irr` lets.

### 11.4 Kernel delta K1: definitional axioms for bit counting

Primitives compute only on literals (DESIGN §5.7). No existing axiom characterizes
`count_ones`, `leading_zeros` or `trailing_zeros` on symbolic data, and the
existing bounds (`axioms.rs:281-293`) cannot prove any closed form. The minimal
statement that fixes this is each primitive's definition, written in summands
the kernel already decides. The definitions below are in `Int`, so linarith
needs no carry atoms: a `wadd_u32` sum would add rational carry atoms that it
cannot eliminate.

```
count_ones_def(w)     : Π (a : W). Eq(Int, to_int(count_ones_w(a)),     Σ_{i<n}      to_int(and_w(wshr_w(a, i), 1)))
leading_zeros_def(w)  : Π (a : W). Eq(Int, to_int(leading_zeros_w(a)),  Σ_{m<n}      [lt_w(a, 2^m)])
trailing_zeros_def(w) : Π (a : W). Eq(Int, to_int(trailing_zeros_w(a)), Σ_{1≤m≤n}    [eq_w(and_w(a, 2^m − 1), 0)])

[b] := match b : Bool return Int with | false => 0int | true => 1int end
Σ   := left-nested iadd;  n = bits(w);  2^n − 1 written as the all-ones literal
```

**Why these statements hold.**
- If `a ∈ [2^p, 2^(p+1))`, exactly the `m ≥ p+1` comparisons hold, so the sum is
  `n−1−p = lz(a)`. For `a = 0` it is `n`.
- If `t` is the lowest set bit, exactly the `m ≤ t` masks are zero. For `a = 0`
  the sum is `n`.

**How automation uses them.**
- Under a range hypothesis, linarith decides every comparison summand. auto
  step 8 rewrites each summand to `true`/`false`, ι computes it, and the sum
  evaluates.
- bvnorm maps `bit_i(x >> k)` and `bit_i(x & m)` onto the classes of
  `bit_{i(+k)}(x)`, so popcount split identities coincide summand by summand.
- The bound `lz(a) ≥ [a < 2^(n−1)]` falls out directly. The `shape` closed form
  needs it to show `h ≤ 62` (§12.1).

**Encoding.** The schemas are per width only, so the `AxiomId` encoding
(schema·8 + width) is unchanged.

**Tests.**
- exhaustive over U8 and U16 against the primitive semantics;
- at U32/U64/Usize: 10^7 random values, plus every single-bit, all-ones-prefix
  and all-ones-suffix value, plus 0 and ~0;
- mutation tests: swapping `lz`/`tz`, or an off-by-one summand range, must fail.

**Retirement.** `count_ones_le`, `leading_zeros_le/lt` and
`trailing_zeros_le/lt` become checked lemmas in `lemmas/bits.core`.
- auto's step 7 instantiates those lemmas instead of the axioms.
- Net kernel growth is about +40 lines, to at most 9,850 of the 10k budget.

**Library.** `lemmas/bits.core` holds checked lemmas, generated per width and
literal k:
- `popcnt_step_k` and `popcnt_split_k`;
- `popcnt_shr_zero_k`: `x < 2^k → popcnt(x >> k) = 0`;
- `lz_range_k`: `2^k ≤ x < 2^(k+1) → lz(x) = w−1−k`;
- `lz_ge_one`: `x < 2^(w−1) → lz(x) ≥ 1`;
- `tz_range_k`;
- `clz_xor_prefix_k`;
- `count_ones_sum`, the P3 idiom.

**Paperwork.** An `AUDIT.md` entry, and an additive note in
`INTERFACE_CHANGES.md`.

### 11.5 Checked arithmetic printing (E0)

Today proven arithmetic prints as plain `a + b`. Under an `overflow-checks =
true` profile, which is Commonware's release profile, rustc re-inserts the
checks. The measured cost on curve25519's F::mul is 13.8 → 7.3 ns (1.9×;
*(third-party code)*: Commonware's F::mul with overflow checks on vs off, not
emitted code; the emitted P18 gain is 1.43–1.57×, bench/opt-corpus/README.md):
229 instructions and 28 branches vs 169 instructions and 4 branches.

**The rule.** Every checked `add/sub/mul/shl/shr` whose proof slot exists in the
optimized core is printed as `crate::__rt::chk::add_u64(a, b)`.
- This is a fixed `#[inline(always)]` template: `wrapping_add` under
  `not(debug_assertions)`, and the checked operator under `debug_assertions`.
  The debug-profile oracle (DESIGN §10.3) therefore keeps its runtime overflow
  checking.
- The round trip, in generated mode, lowers exactly `__rt::chk::<op>_<w>`, with
  its operand order and width, to the checked primitive with an `Erased` slot.
  So the round trip still requires operator, width and operands to match at
  every erased slot.
- Users cannot write the path: `__rt` is reserved.
- **There is no UB surface.** The trusted meaning, "the machine operation when
  the proof slot holds", is satisfied by wrapping. A round-trip correspondence
  bug can at worst produce a wrong value, never undefined behaviour.

`unchecked_*` (which keeps LLVM's `nuw`/`nsw` flags) is **not** used by default.
It is allowed per site only where a measurement shows ≥ 3% gain, through the
same distinguished-helper rule.

### 11.6 What is trusted

| Item | Class | Size | Justification |
| --- | --- | ---: | --- |
| driver, Σ2–Σ5, aegraph, cost model, proof builder, profiles, tuning, cache | untrusted | – | kernel checks every residual and lemma |
| drive/summary lemmas; `seq/bits/cong/ring/gf2/par` library lemmas | checked | – | `def[lemma]` |
| **K1 axiom schemas** | **kernel** | **≈ +40 net** | §11.4 |
| `__rt::chk::*` helpers | canonical-dialect meaning (TCB item 2) | ≈ 30 lines | wrapping satisfies the checked meaning; no UB |
| parallel templates (`__rt::par::*`) | trusted glue (TCB item 4 class) | ≈ 120 lines | §14.4; they validate the executor, which is untrusted |
| `ct_select` template (with barrier) | trusted glue | ≈ 15 lines | constant time only (DESIGN §15.13) |
| `#[memo]` `LazyLock` template | trusted glue | ≈ 20 lines | defining equation kernel-checked |
| feature-only dispatch + known-answer self-test | dispatch glue (TCB item 4) | ≈ 40 lines | §13.2 |
| new intrinsic models | target semantics (TCB item 4) | per model | evidence-gated dispatch |
| `u128` prelude type over `Int`, printed `u128` | prelude + dialect meaning (items 2, 3) | small | differential corpus per construct |
| assumption: worker threads have ≥ 2 MiB stacks (std/rayon default) | DESIGN §1.1 item 7 | – | the DESIGN §3.7 stack bound applies inside tiles |

---

## 12. Worked derivations

### 12.1 `merkle::shape` → clz/popcount closed form

**Source.** `sandblaster/fixtures/qmdb/sandblaster/merkle.rs:119-184`. With `L` = leaves and `t` =
target: `shape(L, t)` returns `None` when `L > 2^62`. Otherwise it calls
`shape_go(63, t, L, 2^62, 0, 0, 0, None)`. The state is
`(fuel, target, rem, width, pos, start, before, found)`.

1. **Driving `shape`.**
   - Split `gt(L, 2^62)`. The true arm is `None`; the false arm gets
     `L ≤ 2^62`.
   - Static unrolling of `shape_go` is refused: the branching estimate is about
     2^peaks × 3 over 63 levels. The head goes to Σ2.
2. **One iteration.** There are four paths:
   - `rem < w`;
   - `rem ≥ w ∧ t < s`;
   - `rem ≥ w ∧ s ≤ t < s + w`;
   - `rem ≥ w ∧ t ≥ s + w`.

   The saturating operation `(pos + 2w).sat_sub(1)` is exact given `w ≥ 1`.
3. **Classes:**
   - `w_f = 2^(f−1)`: Geometric;
   - `rem_f = L & (2^f−1)`: BitDigit;
   - `s_f = L − rem_f`: Conserved;
   - `b_f = popcnt(L >> f)`: GuardCount;
   - `pos_f = 2·s_f − b_f`: Linear;
   - `found_f = (t < s_f ? Some(F(L,t)) : None)`: FirstMatch over disjoint
     intervals.
4. **Synthesis.** Using 256 profile-plus-corner traces:
   - the witness `h = 63 − lz(L ⊕ t)` is found at size 4;
   - the guard is `Some ⟺ t < L`;
   - the payload is `width = 1 << h`, `before = popcnt(L >> (h+1))`,
     `after = popcnt(L & (2^h−1))`, `index = t & (2^h−1)`, and
     `position = 2(s_h + 2^h) − before − 2` with `s_h = (L >> (h+1)) << (h+1)`.

   The candidate agrees with the generated code on 3.2M cases (measured).
5. **Lemmas.** `lemma_0 … lemma_63` (§7.5), non-recursive, with literal masks.
   The obligations for `j ∈ 1..63`, with `k = j − 1` and `β = (L >> k) & 1`:

   | Obligation | Discharged by |
   | --- | --- |
   | `rem = (β << k) ∣ (L & (2^k−1))` and `∣ = +` on disjoint supports | BvRefl, bit-slice rule |
   | `rem < 2^k ⟺ β = 0` | integer cut on `β` (`lt(β,1)`), then linarith |
   | idle: `rem`, `s` unchanged, `b = popcnt(L >> k)` | linarith + `popcnt_step_k` (β = 0) |
   | peak: `rem − w = L & (2^k−1)`, `s + w = L − (L & (2^k−1))`, `b+1 = popcnt(L >> k)`, `pos + 2w − 1 = 2(s+w) − (b+1)` | linarith + `popcnt_step_k` (β = 1) |
   | hit: `t >> j = L >> j` from `s ≤ t < s + 2^k` | integer cut on the quotient atom (two strengthened certificates) |
   | hit: `2^k ≤ L ⊕ t < 2^(k+1)` | BvRefl (`(L⊕t) >> j = (L>>j) ⊕ (t>>j)`) + linarith |
   | hit: `lz(L ⊕ t) = 63 − k`, so `h = k` | `lz_range_k` |
   | hit: every field of `S_j` equals `F(L,t)`'s (`t − s = t & (2^k−1)`, `(pos+2w).sat_sub(2) = 2(s+w) − b − 2`) | Delta + linarith + BvRefl |
   | miss (before/after): `found` invariant at `s + w` | linarith |

   **Entry.** `inv(63, init)` follows from `L ≤ 2^62`: `L & (2^63−1) = L` and
   `popcnt(L >> 63) = popcnt(0) = 0`, by linarith and then evaluation.

   **Residual domain facts.** `t < L ≤ 2^62` gives `L ⊕ t ≠ 0` and
   `L ⊕ t < 2^63`, so `1 ≤ lz(L ⊕ t) ≤ 63` by `lz_ge_one` and the
   `leading_zeros_lt` lemma. Hence `h ∈ [0, 62]`, which justifies the shifts.
   (The `supercomp` draft derived `h ≤ 62` from `leading_zeros_lt`, which only
   bounds `lz` from above; that derivation was wrong.)

   **Confirmation.** These obligations were derived by hand. Plan milestone O3
   runs them through the kernel before Σ2 is built.
6. **Residual.**

   ```rust
   pub fn shape(leaves: u64, index: u64) -> Option<Shape> {
       if leaves > 4611686018427387904u64 { return None; }
       if !(index < leaves) { return None; }
       let h = 63u32.wrapping_sub(<u64>::leading_zeros(leaves ^ index));
       let width = 1u64.wrapping_shl(h);
       let hi = leaves.wrapping_shr(h).wrapping_shr(1u32);
       let before = <u64>::count_ones(hi);
       let start = hi.wrapping_shl(h).wrapping_shl(1u32);
       Some(Shape { height: h, width,
           position: start.wrapping_add(width).wrapping_mul(2u64).wrapping_sub(before as u64).wrapping_sub(2u64),
           index: index & width.wrapping_sub(1u64), before,
           after: <u64>::count_ones(leaves & width.wrapping_sub(1u64)) })
   }
   ```

   **Link.** `Delta(shape)`, then a split on the guard, then
   `Apply(lemma_63)` with the entry invariant. `shape_go` is no longer
   referenced, so dead-helper elimination drops it.

   **Exported facts.** `height ≤ 62`, `before + after ≤ 61`, `index < width`.

   **By-product.** The summary *is* the deferred law `shape_closed_form`
   (`LAWS.rs:49`), which can now be discharged (§18.1).

   **Expected code:**
   - aarch64: about 30 instructions, branch-free, 2 NEON `cnt`;
   - x86 v3-scalar and v4 clones: `lzcnt`, `shlx`/`shrx`, `popcnt`, `bzhi`,
     about 37 lines;
   - x86 v1: `bsr` + `psadbw`, about 57 lines, still far faster than the loop.

   **Measured candidate** *(hand-written candidate, development set: QMDB's `shape`)*: 2.33 / 2.26 / 2.30 ns against 24.8 / 46.0 / 61.5 ns.

   **Generality.** The same machinery handles P4 `find_block` (Fenwick trees,
   buddy allocators, binomial heaps) unchanged.

### 12.2 Peak buffer → segment folds

**Source value.** On `peak = Some(d)` with `nb + na < 62` and
`m = nb + 1 + na`:

```
root(L, I, F, slice(m, take(C₂, m)))
C₀ = replicate(62, Z);  C₁ = copy_range(C₀, 0, nb, B);  C₁' = update(C₁, nb, d);  C₂ = copy_range(C₁', nb+1, m, A)
```

**Σ3 normalization.** Each step is an unconditional clamped-`Int` lemma
instance, except where noted.

1. `C₁ = [Seg B, Rep(Z, 62−nb)]`
2. `C₁' = [Seg B, Elem d, Rep(Z, 61−nb)]`
3. `C₂ = [Seg B, Elem d, Seg A, Rep(Z, 61−nb−na)]`
4. `take(C₂, m) = [Seg B, Elem d, Seg A]`, using a linarith side condition. The
   zero tail is **unread**, so it disappears.

The proof object is `E_seq`, and it reaches the `SliceOk` component through
`slice::ext`.

**Driving `root` over `B ++ d::A`** (general consumer driving, §8.2):
- **Split on `B`.**
  - `B = []` gives `bag_prefix(n, after, d)`, which folds onto the existing
    summary.
  - `B = b₀ :: B'` gives `G₁(n, B', d, A, b₀) := bag_prefix(n, B' ++ d::A, b₀)`.
- **Driving `G₁`.**
  - `n == 0` gives `fold_back_join(acc, G₃(S, d, A))`.
  - `S = []` gives `bag_prefix(n−1, after, fold(acc, d))`. The source's
    `[] ⇒ None` arm is pruned, because the list is non-empty by construction.
  - `S = h::S'` is a renaming of `G₁`, so it folds with measure `len S`.
- **`G₃(S, d, A) := fold_back(S ++ d::A)`** splits on `A`'s last element and
  gives segment right-folds that fold with measure `len A'`.

**Residual.**

```rust
pub fn reconstruct_finish(leaves: u64, inactive: u64, folded: u64,
                          before: &[Digest], after: &[Digest], peak: Option<Digest>) -> Option<Digest> {
    let d = match peak { None => return None, Some(d) => d };
    if before.len() + after.len() >= 62 { return None; }
    let n = (inactive.saturating_sub(folded) as usize + (folded != 0) as usize).saturating_sub(1);
    root_seal(leaves, inactive, match before {
        [] => bag_prefix(n, after, d),
        [b0, rest @ ..] => bag_seg(n, rest, &d, after, *b0),   // residual helper: canonical tail loop
    })
}
```

**What goes away.** No buffer, no `bzero`, no `memcpy`. On x86, the 62 ymm or
31 zmm stores and the 2 `memcpy@GOTPCREL` calls also disappear.

**Specialization under the caller.** Under `reconstruct_checked`'s facts
(§6.5), `nb + na ≥ 62` is dead in that specialization, which covers inventory
item 4 (redundant checks).

**Measured candidates:**
- `finish_fused`: 73.1 ns vs 89.2 ns (H2);
- with a cheap fold: 19.7 → 1.7 ns for 1–5 peaks, 51.8 → 14.6 ns for deep
  proofs.

**Must-reject.** If the source had sliced one element past (`nb+2+na`), the
segment list would contain `Elem Z`. Any rewrite that drops it fails its
linarith side condition.

### 12.3 Varint, `location`, `parse`

1. **`uint64(xs) = uint64_go(10, xs, 0, 0)`.** The measure is static, so Σ1
   unfolds 10 levels.
   - Each level is a `Split` on the slice (`[] | [h, t@..]`) and on `h < 0x80`.
   - `uint64_finish` is inlined.
   - The `ok` expressions constant-fold per level:
     - level 1: `true`;
     - levels 2–9: `h ≠ 0`, a pending disjunctive fact, split on demand (§6.3);
     - level 10: `h < 2 ∧ h ≠ 0`. The split leaves `h ≥ 1` with `h ≤ 1`, and
       Refine gives `h = 1`.
2. **`location` (case-of-case).**
   - `match uint64(xs) { … if v <= 2^62 … }` is pushed into the leaves.
   - Interval facts come from `and_le`, the literal-shift atoms and `or_le_add`:
     `v_k ≤ 2^(7k) − 1` for levels k ≤ 8 (1-based). So `v ≤ 2^62` is pruned
     true.
   - The level-9 leaf keeps the check.
   - The level-10 leaf has `v ≥ 2^63` (`or_ge_right`), so it becomes `None`. Both
     10th-byte arms are now `None` and merge: **the 10th byte is never
     inspected.**
3. **`parse`** inlines `location` ×2, `byte`, `uint64` and `uint`, about 60
   residual nodes per reader. Case-of-case removes the `Option<(u64,&[u8])>`
   round trips.
4. **Proof.** A Delta chain, mirrored splits, linarith prunes and refines, and
   one merge. There is no induction, because the fuel is literal.

**Measured candidates** for `parse`:
- unrolled + inlined: 1.46 ns;
- peeled first byte only: 1.92 ns;
- LLVM force-inlining alone: 2.85 ns;
- SWAR: 8.2 ns, rejected by cost;
- H2: 6.46 ns; pre-H1: 3.94 ns.

On x86 v4, a rulegen-proven `pext` decoder is a candidate. It is chosen only if
`PROFILE.json` shows that 5–9-byte fields dominate.

### 12.4 `sha256::equal` (32-byte `seq::eq`)

- **Unrolling.** Static-structure unrolling over two η-expanded arrays gives a
  short-circuit chain of 32 `eq_u8`.
- **Word form.** The lowering is `((a₀⊕b₀)|(a₁⊕b₁)|(a₂⊕b₂)|(a₃⊕b₃)) == 0` over
  `from_le_bytes` words. It rests on the checked lemma `eq8_word`:
  `eq_u64(from_le(a[0..8]), from_le(b[0..8])) = ∧_{i<8} eq_u8(aᵢ, bᵢ)`.
- **Proof of `eq8_word`.** By case analysis:
  - byte extraction `cast_u8(from_le(a) >> 8i) = aᵢ` is a bvnorm identity;
  - `eq_sound`/`eq_complete` supply the rest.
  - It is **not** proven by linarith: base-256 uniqueness needs integer
    reasoning that rational Farkas lacks.
- **Alternatives.** A NEON `vceqq_u8` or AVX `vpcmpeqb` + mask candidate is
  generated; cost picks between them.
- **As built (plan O10).** On aarch64 the NEON candidate is generated for
  every `[u8; 16m] == [u8; 16m]` in the crate (`opt/par/seqeq.rs`): per
  16-byte block `veorq_u8` of the two loads, the two `u64` lanes or-ed, the
  blocks' words or-ed. One `bvrefl` lemma per length
  (`seqeq::neon_word_<n>`) proves it equal to the word form. The cheaper
  form that or-s the blocks with `vorrq_u8` before one lane reduction is
  priced but not proven: `bvnorm` has no rule that moves `|` through a
  byte concatenation. On the M5 tables the word form wins (16 bytes: NEON
  22.2 vs 12.0 cycles; 32 bytes: 38.0, `vorrq` form 35.7, vs 21.4), so the
  candidate is reported (`Optimized::seq_eq`) and the word form stays.
  There is no x86 candidate (no byte compare-to-mask models in the O10
  set), and no emission path for a chosen candidate.

---

## 13. Hardware-first lowering

### 13.1 Variant sets

**x86_64:**

| Set | Features | Notes |
| --- | --- | --- |
| `portable` | x86-64 baseline | |
| `v3-scalar` | `popcnt, lzcnt, bmi1, bmi2` | **feature-only** |
| `sha` | `sha, sse4.1, ssse3` | combined with v3-scalar |
| `v4` | `avx512f, bw, vl, cd, dq, vpopcntdq, ifma, vbmi, vbmi2, gfni, vaes, vpclmulqdq, sha, bmi1, bmi2, lzcnt, popcnt` | `pext` allowed only here |

- EVEX-256 (VL) twins inside `v4` are chosen by tuning evidence: Zen 4 splits
  512-bit operations into two halves, and Intel parts have frequency licenses.
- At most 4 sets per architecture are generated. The generated sets are the ones
  the residuals can actually use.

**aarch64:**

| Set | Features | Notes |
| --- | --- | --- |
| `neon` | | |
| `sha2` | | static on Apple, so dispatch is free |
| `sha3` | EOR3/BCAX/RAX1/XAR | |
| `sha512` | | |
| `cssc` | scalar `cnt`/`ctz`/min/max | only if rustc 1.98 accepts it in `#[target_feature]`; the M5 has FEAT_CSSC but `target-cpu=native` does not enable it |

### 13.2 Feature-only clones and their self-test

Clones in `v3-scalar` (and `cssc`) use only primitives, such as `u64::leading_zeros`
compiled under `#[target_feature(enable = "lzcnt,popcnt,bmi1,bmi2")]`. rustc
defines their semantics (TCB item 5), so they need **no intrinsic model
evidence**.

That does not make them safe to dispatch on detection alone. On a CPU without
LZCNT/BMI1, `lzcnt` and `tzcnt` decode as `bsr` and `bsf` and silently compute
different values. A feature-detection bug would therefore produce wrong answers,
not faults.

- **Dispatch rule.** The dispatch glue runs a **known-answer self-test** once,
  when a feature-only set is first selected: `lz`/`tz`/`popcnt`/`bzhi`/`shlx`
  on fixed constants, including 0 and single bits. A mismatch pins the process
  to `portable`.
- **Host kit.** These clones are also covered by the host kit's differential
  tests.
- The DESIGN §15.13 hardware self-test generalizes this mechanism.


**As built (plan O8).**
- Feature-only sets on x86_64: `v3_scalar` = `{popcnt, lzcnt, bmi1, bmi2}` and
  `v4` (design §13.1's list, absorbing every variant set whose features it
  includes), plus each variant set combined with `v3_scalar` (QMDB:
  `sha_sse2_ssse3_sse4_1_v3`); dispatch order `v4`, combined, variant sets,
  `v3_scalar`; at most four sets. Their trees grow from the bit-sensitive
  functions (a bit count, a `for` loop that shifts, a call of a loop head)
  up to the boundary. A clone whose equality lemma fails (mirror, then
  `BvRefl` for non-recursive clones) is left out and the tree rebuilt (at
  most three times); a set none of whose clones is ≥ 3% cheaper than its
  original under the set's tables is dropped after specialization.
- **Headroom (host evidence, pricing before cloning).** A feature-only set
  is generated only when the evidence record says a host has run its clones
  (§13.5). A set with evidence is set aside until the originals are
  specialized; it is then priced on the originals' residuals (each tree
  function under the set's tables against the portable tables, callees at
  their printed cost) and is not generated at all when no function of its
  tree is ≥ 3% cheaper, so its clones are never elaborated or specialized.
  A set that passes is cloned, admitted and specialized after the
  originals (dispatch is at the boundary, so nothing specialized earlier
  depends on its clones), and the check on its own clones' residuals above
  still decides at the end. Today no feature-only set has evidence, so the
  x86 emission has the SHA-NI set only (QMDB N = 1: 1.29 MB, as before O8).
- aarch64 `cssc`: decision D2 is **no** (rustc 1.98.1, E0658 "the target
  feature `cssc` is currently unstable").
- The known-answer self-test runs inside the cached detection
  (`has_<set>() = features && kat_<set>()`), once per process: the hot path
  is one relaxed load and a branch, as before. It checks `lzcnt`, `tzcnt`,
  `popcnt`, `bzhi`, `shlx`/`shrx` (and `pext` in `v4`) on fixed constants,
  and each `#[implements]` variant of the set (QMDB: SHA-NI `compress`)
  against its portable function on fixed inputs. The bit-count clones are
  not compared one by one: they use the instructions the constant checks
  cover, and each is kernel-proven equal to its original.
- Every checked result and argument goes through `black_box`. Without it,
  LLVM rewrote each check into a compare of the constant inputs
  (`lzcnt(z) == 64` became `z == 0`), so a release build never executed
  `lzcnt`/`tzcnt`/`pext` and a `bsr` CPU passed. The zero-input
  `lzcnt`/`tzcnt` checks are `asm!` with the destination cleared first,
  because `bsr`/`bsf` leave the destination unchanged for a zero source.
  G7 asserts that the release self-tests contain `lzcnt`, `tzcnt`, `popcnt`,
  `bzhi` and `shlx`/`shrx` (and `pext` in `v4`).
- Statically enabled sets keep their direct call (no portable code exists to
  fall back to).
- R21 simulates the fault in the machine code: the detection is forced,
  the release binary's `lzcnt`/`tzcnt` encodings are patched to `bsr`/`bsf`
  (prefix `F3` → `3E`), and the binary runs under Rosetta 2. The patched
  clone alone returns wrong answers, the self-test fails, and the process
  runs the portable code.

### 13.3 Lane functor (cheap lane-lifting proofs)

**Why not per-lane BvRefl.** Proving an x16 kernel lane by lane with `BvRefl`
repeats the >10 GB incident class.

**What the functor does instead.**
- It proves **one lanewise lemma per intrinsic model**, by conversion or a small
  `BvRefl` on the model with symbolic lanes. Examples:
  - `view_u32(_mm512_add_epi32(a, b))[i] = wadd(view_u32(a)[i], view_u32(b)[i])`;
  - `view_u64(_mm512_madd52lo_epu64(a, b, c))[i] = madd52lo(aᵢ, bᵢ, cᵢ)`.
- A syntax-directed translation Φ produces the lifted kernel from the scalar
  residual DAG.
- The lemma `Π xs. kernel_xL(xs) = map f xs` is a **congruence chain over the
  DAG**: one lanewise-lemma instance per node, plus array η at 16 lanes (well
  under the 256 limit).
- **Proof cost is O(scalar DAG).**

**Cross-lane operations.**
- Shuffles and transposes have literal immediates. They evaluate to concrete
  permutations and are checked by conversion.
- `vpternlogd` immediates come from bvnorm's ≤ 4-atom truth tables: `0x96` xor3,
  `0xCA` Ch, `0xE8` Maj.

**Lifting rules.** Lifting happens before bounds-check elimination. Inactive
lanes use masked or total accesses (DESIGN §9.4). `Secret` code is uniform by
construction.

**As built (plan O10).** `opt/par/{tiles,cquote,lift,sites}.rs`.

- **Sites.** O10's site is syntactic: an exec function whose body is an
  array literal of `N ≥ 2` calls of one exec function (`[g(ā₀), …]`),
  `N` equal to a target's lane count (AVX-512 ×16, AVX2 ×8, NEON ×4). A
  crate without such a function pays nothing (no symbolic execution, no
  lemma, no core text). General site discovery is O11.
- **Lifting.** Transparent symbolic execution of the site gives the scalar
  DAG of each lane; the lanes must be the same DAG over their own leaves.
  Tiles are single word operations or fused bitwise cones of ≤ 3 inputs
  (the truth table becomes `vpternlogd`'s immediate on AVX-512, `vbslq`/
  `veor3q`-free formulas on AVX2 and NEON: Ch `0xCA`, Maj `0xE8`, xor3
  `0x96`). The kernel text is printed through the residual printer (lane
  mode) and elaborated as an ordinary exec function `s__<target>`.
- **Proof** (`<s__target>::lane_equiv : Π p̄. Eq(R, s__target p̄, s p̄)`).
  One word-level lemma per tile shape (`bvrefl` over `Array U32 N` views),
  its vector instance by conversion, and per cone (cut nodes: leaves,
  multi-use nodes, lane exits; ≤ 10 inputs, ≤ 48 nodes, keyed by the
  template's hash) a transported lemma. The chain is split into stage
  definitions of ≤ 48 cut nodes over Σ node bundles (vector, lanes, the
  fact relating them), so the checker's memory stays bounded; the final
  step links the vector lanes to `g__dag`, the callee's DAG as a
  transparent `let` chain proven equal to `g` by one `bvrefl`. SHA-256 x16:
  27.2 M steps, +183 MiB; x8 14.1 M, +96 MiB; x4 3.2 M, +44 MiB; the
  constant-second-block x16 (`hash64_x16`) 51.8 M, +264 MiB
  (docs/opt-o10-reports.md).
- **Libraries.** `lemmas/lanes/{avx512_x16,avx2_x8,neon_x4}.core` are the
  generated lemmas of the SHA-256 sites (regenerated by
  `tests/opt_lanes.rs` with `SANDBLASTER_REGENERATE_LANES=1`); the optimizer
  generates the same text for the cones a build needs, and the kernel checks
  it when loaded.
- **Decision.** The lifted kernel is priced with its target's tables
  against the site's best existing code (portable, or under an ISA variant
  set). It is dispatched only when the cost model picks it, its models are
  validated, and a host has run the kernel itself (§13.5); otherwise it is
  a ghost item (printed, never called, with
  `SANDBLASTER_LANES_COMPILE_ONLY=1`, for G7).
- **Not built.** Masked tails, per-model lanewise lemmas for the models
  SHA-256 does not use, lanes over `u64` words, and cross-lane shuffles in
  lifted code.

**SIMD search (plan O10, P12; `opt/par/search.rs`).** A tail-recursive byte
search `go(xs: &[u8], i: u64)` — `[] => B(i)`, `[h, t @ ..] => if P(*h) {
F(i) } else { go(t, i + 1) }`, `P` one unsigned comparison with a literal,
`F`/`B` expressions of `i` — gets on aarch64 a NEON variant
`go__search_neon`: `split_first_chunk::<16>`, the compare (`vcltq_u8`,
`vcgeq_u8` or `vceqq_u8` against `vdupq_n_u8(C)`), `vshrn_n_u16::<4>` to a
nibble per byte, `trailing_zeros / 4`, else recursion on the rest; slices
shorter than 16 bytes go to `go`. The proof is a lemma library checked once
per crate (1.46 M steps): sixteen unfoldings of the skeleton
(`search::unroll16`), the mask's first set nibble picks the first matching
byte (`search::pick16`, a case per first match closed by
`bits::tz_range_u64_4k` and `bvrefl`), the vector compare as sixteen scalar
tests (`search::mask_<test>`, `bvrefl`), and measure induction on the slice
length (`search::neon_<test>`). Each site's `search_equiv` is one
application of `search::neon_<test>` to both functions and their `delta`
unfoldings, so the kernel's conversion checks that the source is the
skeleton and the variant the NEON step: no recognizer is trusted. The
variant joins the `{neon}` variant set (static dispatch on aarch64, where
NEON is baseline); its per-16-byte cost is compared with sixteen source
steps (P12: 10.6 vs 18.3 cycles). The AVX-512BW form is not built (the O10
x86 set has no byte compare-to-mask models).

### 13.4 Models to add

Models live in `sandblaster/targets/src/{x86_64,aarch64}/*`, with core text
in `core/*.core`.

| Group | Intrinsics | Workloads |
| --- | --- | --- |
| AVX-512F/BW/VL epi8/32/64 | add/sub/and/or/xor/andnot, `slli/srli/ror/rol`, `ternarylogic_epi{32,64}`, `min_epu64`, `set1`, `setzero`, `set_epi64` (lanes e7..e0), `loadu/storeu`, `maskz_loadu_epi8`/`mask_storeu_epi8` (fault-free tails through trusted slice helpers), `mask_blend_epi{32,64}`, `cmp{eq,lt}_epu*_mask`, `movepi8_mask`, `shuffle_i64x2`, `shuffle_epi8`, `permutexvar_epi{32,64}`, `permutex2var_epi32`, `unpack{lo,hi}_epi{32,64}`; the `_mm256` EVEX twins | SHA x16, RS, curve25519, BLS, search |
| IFMA | `madd52lo/hi_epu64`: model over `Int`, product bits [51:0]/[103:52], operand bits 63:52 ignored, accumulator mod 2^64 | curve25519, BLS/VROOM |
| GFNI | `gf2p8affine_epi64_epi8` (all widths), parity written as an xor of bit extractions | Reed–Solomon |
| VBMI/VBMI2 | `permutexvar_epi8`, `permutex2var_epi8`, `maskz_compress_epi8` | RS tables, varint headers |
| VPOPCNTDQ/CD | `popcnt_epi64`, `lzcnt_epi64` (lanewise primitives: the lemma holds by conversion) | batched `shape`, MMR math |
| VAES/VPCLMULQDQ | `aesenc_epi128`, `clmulepi64_epi128` | CRC32C folding, GHASH (Σ4 AffineGF2) |
| BMI2 | `_pext_u64`, `_pdep_u64` | varint decode (v4 only) |
| SHA-NI | existing three models | QMDB x86 (first host-kit item) |
| NEON u8/u64/u32×2 | `vqtbl1q_u8`, `veorq/vandq/vorrq_u8`, `vshrq_n_u8`, `vdupq_n_u8`, `vcltq/vcgeq/vceqq_u8`, `vshrn_n_u16`, `vcntq_u8`, `vaddvq_u8`, `veor3q_u8`, `vbcaxq_u8`, `vrax1q_u64`, `vxarq_u64`; `vmull_u32`, `vmlal_u32`, `vshrn_n_u64`, `vmovn_u64`, `vaddq_u64`, `vsraq_n_u64`, `vbslq_u64`; `vsha512{h,h2,su0,su1}q_u64` | RS, search, curve25519, SHA-512 (all validated locally) |

Detection must be added to `hw/x86_64.rs` (today it stops at `avx512f`) for
`avx512ifma/vbmi/vbmi2/gfni/vpclmulqdq/vaes/vpopcntdq/cd/sha/bmi1/bmi2/lzcnt/popcnt`.

**As built (plan O10).** The NEON row is complete: 27 NEON u8/u64/u32×2
models and 8 SHA3/SHA512 models (`sandblaster/targets/src/aarch64/{neon2,sha3}.rs`,
`core/aarch64.core`, MODELS.md §3.1–3.2), registered in `intrinsics.rs`,
validated natively on the M5 (10⁷ random cases each, corners, every
immediate, 0 mismatches) with a passing kernel cross-check. The x86 rows
come from the AVX-512 rounds (MODELS.md §10: 98 models validated on Zen 5)
plus the O10 word helpers `load/store_u32x8/u32x16` and
`_mm512_slli/srli_epi32` in `intrinsics.rs`. Not built from the table:
`setzero`, `set_epi64`, `min_epu64`, `permutex2var_epi32`,
`maskz_compress_epi8`, `lzcnt_epi64`, VAES/VPCLMULQDQ, BMI2 `pext`/`pdep`,
the byte compare-to-mask group, and the extra `hw/x86_64.rs` detection.

### 13.5 Evidence and dispatch

The rule is unchanged: no intrinsic without `validated` hardware evidence for
its architecture is reachable from a dispatched path.

- **Emulation.** Intel SDE runs may be recorded as `emulated`. They never enable
  dispatch.
- **Current state.** `evidence/x86_64.json` was recorded under Rosetta and has
  `avx512f: false`. So every AVX-512 variant is **generated, proven and compiled
  now** for `x86_64-unknown-linux-gnu` and `x86_64-apple-darwin`, and dispatched
  only after the host kit records evidence.
- **aarch64.** NEON/SHA2/SHA3/SHA512 models are validated on this M5, so
  `aarch64.json` gains native evidence for them.
- **Feature-only sets (headroom).** A feature-only set (`v3_scalar`, `v4`,
  a variant set combined with `v3_scalar`) needs no intrinsic model, but its
  clones run instructions whose failure mode is a wrong answer (`lzcnt` as
  `bsr` on a CPU without LZCNT). So it is gated like an intrinsic: the
  evidence record's `sets` array holds host runs of each set's clones
  (`evidence::SetRecord`: CPU key, executor, set, the hash of its name and
  feature closure, suite, cases, mismatches), and the optimizer generates
  and dispatches a set only when some CPU that **reports every feature of
  the set** has a passing run under a validating executor (`native` or
  `rosetta2`), and no current run failed on any CPU
  (`evidence::set_validation`; fail closed; a set whose feature list
  changed has no evidence). A run on a CPU that does not report the
  features — the detection had to be forced — is recorded as
  `diagnostic` and never counts, like a forced KAT. The runs come from the
  host kit's `sets` stage (§19). Dispatch stays per architecture, as for
  intrinsics; the known-answer self-test (§13.2) stays as the run-time
  check on each CPU.
- **Current state of the sets.** `v3_scalar` ran the QMDB fixtures (N = 1:
  32, N = 32: 490) and a `shape` differential (10^6 + 289 inputs per
  instance) under Rosetta 2 with the dispatch forced, with no mismatch;
  Rosetta 2 does not report LZCNT, BMI1 or BMI2, so these are diagnostics.
  `v4` and the SHA-NI + `v3_scalar` set have never run (Rosetta 2 has no
  AVX-512 or SHA-NI). No feature-only set is generated until a host round
  (the Zen 5 host of round 0 reports every `v4` feature) records a run.
- **Lane kernels (plan O10).** A lane kernel uses validated models only,
  but it is new code: it is dispatched only when a host has run the kernel
  itself against its site. The evidence record's `sets` array holds those
  runs under the set name `lanes:<target>:<first 32 hex digits of the
  SHA-256 of the kernel's emitted text>` and the suite `lane-differential`
  (≥ 10⁶ inputs), with the same verdict rules as a feature-only set
  (`evidence::set_suites`, `set_suite_min_cases`). The emitted text is what
  a host compiles when it runs the kernel: the kernel item's tokens as the
  optimized printer prints it (doc comments and visibility left out), the
  tokens of every load/store and checked-arithmetic helper it calls, the
  target, and `rustc -V` of the compiler that built sandblaster
  (`opt::par::lane_fingerprint`). The round trip checks that every printed
  lane kernel has exactly those tokens, and compares the helpers verbatim
  with the same templates, so the name always describes the emitted code:
  a changed helper template, a printer change that alters the kernel, or
  another compiler renames the set, and old runs stop counting (R26). The
  core text alone would not do: the round trip reads a helper back as its
  core model and never sees its template. The dispatch glue is not in the
  hash: the host run calls the kernel directly, and the glue is the
  multiversioning template every variant set shares (compared verbatim by
  the round trip). The host kit's `lanes` stage (`tests/host_lanes.rs`)
  produces the runs, on x86_64 for the AVX-512 and AVX2 kernels and on
  aarch64 for the NEON kernel (its dispatch forced by a test hook, since
  the M5 cost model rejects it). No x86 host has run the SHA-256
  kernels yet, so the AVX-512 x16 kernel — chosen by the Zen 5 tables
  (1738 vs 2437 cycles for sixteen SHA-NI compressions) — is generated,
  proven and compiled for `x86_64-unknown-linux-gnu` and
  `x86_64-apple-darwin`, and not dispatched. The NEON x4 kernel is proven
  and rejected by the M5 tables (2484 vs 378 cycles for the SHA2 variant).
  The search variants (P12) use only validated models and need no extra
  record: they are ordinary `#[implements]`-style variants.
- **SME / streaming SVE: not planned.** The M5 has no FEAT_SME_FA64, so
  NEON/SHA2 instructions are illegal in streaming mode. SME2 `LUTI4` for RS is a
  one-off experiment with a kill criterion: ≥ 1.5× per lane over NEON,
  including mode switches.

---

## 14. Automatic parallelism

### 14.1 Answers to the user's questions

1. **"Does the optimizer take advantage of concurrency automatically?"**
   - **Today, no.** `opt/` has no fusion, lane or thread pass.
   - **In this design, yes.** Σ5 finds independence. Independence is exact data
     dependence in the residual DAG, because the core is pure and total. The
     decision procedure then maps it to hardware.
   - For a tree:
     - hashes on the same level are *lanes*: x16 AVX-512 SHA-256 when ≥ b* ≈ 7
       same-shape nodes, ISA pairs on the M5;
     - subtrees are *threads*, one fork-join per region, only above θ;
     - the top ~4 levels are ISA pairs.
   - The author never partitions by hand.
2. **"Manage parallelism manually or map to SIMD?"** Both, innermost first,
   decided per site and per target:
   - ILP and SIMD choices are **static per variant set**. Break-even widths and
     interleave factors are stable properties of the target.
   - The thread choice is a **runtime guard** between two proven-equal versions,
     because pool state, core types and contention decide it.
   - A wrong constant costs speed, never correctness.

**Measured on the M5:**
- SHA2 interleave saturates at k = 2 (19.7 → 14.9 ns/block).
- NEON 4-lane software SHA loses at every width (0.28–0.30×), so the cost model
  rejects it. The variant is still generated and proven, because the same lifted
  DAG becomes the AVX-512 x16 kernel.
- Pool entry costs 3.6–36 µs; an in-pool fork about 20 ns.
- A single QMDB proof (0.3–5 µs, one dependent chain) gets **no** threads and
  **no** lanes: at most 1–2% is available, and the out-of-order core already
  overlaps `hash_chunk`.
- Subtree splitting beats per-level forks at every size: 2^16 leaves 7.1×,
  2^20 10.2× *(hand-written candidates)*.

### 14.2 Site discovery (Σ5, bottom-up from summaries)

| Skeleton | Found as | Proof |
| --- | --- | --- |
| Antichain | ≥ 2 same-shape calls with no DAG path between them (hash-cons key: callee + static args) | conversion (fused straight-line body) |
| Map | Σ2 `Map` class, or a loop writing a fresh slot per iteration | map-loop summary + tiling lemma `map f xs = concat(map (map f) (chunks g xs))` |
| Reduce(⊕) | Σ2 `Reduce` | list homomorphism under `Assoc(⊕)`/`Id(e)`, discharged by bvnorm (word ops), reflective RingRefl (ℤ/p, GF(2)[x]) or a view-level law; failure keeps the site sequential |
| Search(p) | Σ2 `Search` | chunked-search lemma + lane functor (NEON `shrn` mask; AVX-512BW `vptestnmb` → `kmov` → `tzcnt`) |
| Tree | ≥ 2 independent recursive calls | fork-join is the recursion itself; level loops need a per-family shape lemma proven once |
| AffineGF2 | Σ2 class | transformer composition (CRC folding, Horner → Estrin) |
| State decoupling | a recursion threading a cursor/iterator whose effect of one subtree is a closed form of shape (Σ2 on the index effect) | cursor lemma by induction; the two recursive calls become independent (range-proof DFS: 1.2× single-threaded measured, then lanes/threads) |
| Equal-input memoization | a batch whose independent sub-computations may share inputs (multi-proof verify: identical `(pos, left, right)` triples) | exact by congruence (equal inputs ⇒ equal outputs; no collision-resistance assumption); implemented in verified code over `Seq` (sort + unique + lookup) after L6, never as a trusted template (≈ 30% fewer hashes at K = 1024, h = 30) |

Each skeleton carries the element summary's cost, its uniformity and its
liftability per target.

### 14.3 Decision procedure (per site, per variant set)

```
decide(σ, t, ctx):
  K ← kernels for σ.elem on t: scalar; fused_k (2 ≤ k ≤ k_sat) if latency-bound; lanes_L and
      2-gang lanes if uniform ∧ liftable on t; ISA-specific (SHA2 / SHA-NI); author-supplied
      horizontal representations (RNS / limb layouts) when W is small and the operand wide
  inner ← argmin_κ cost_t(κ, W)                     (static W)
        | piecewise by W with thresholds b*_κ      (symbolic W: a size dispatch)
  tail  ← masked gang (AVX-512 k-masks) if tail ≥ b*, else ISA/scalar ILP;
          NEON: pad with duplicated lanes (take n (map f (pad xs)) = map f xs)
  if ctx.has_exec ∧ σ ∈ {Map, Reduce(assoc proven), Tree} ∧ maxW(σ)·c_inner ≥ θ_min(t):
      Map/Reduce: tiles contiguous, multiple of gang·k, ≥ θ_grain/c, ≈ 4P tiles (4–16P only ≥ 1 ms)
      Tree:       subtree tasks down to h_c = log2(θ_grain / c_node); lanes on levels ≥ b*; pairs on top
      Nest:       outer → threads, inner → lanes; 2-D tiles when outer W < P (MSM window × range)
      guard:      par::choose(ctx, n ≥ n*, par_version, seq_version) with n* = ⌈θ_enter / c⌉
      T ≤ 4–6 below 200 µs (heterogeneous P/E cores)
  reject variants over the code-size budget or gaining < 3%; record (σ, t, candidates, costs) in the report
```

`θ_min` is a conservative static prefilter, default 10 µs on the M5. A site that
can never pay gets **no** executor call at all.

M5 thresholds, measured with rayon on macOS:
- parked pool: 50 µs (T=4) to 100 µs (T ≥ 8);
- warm pool: 15–20 µs;
- spinning pool: 1–2 µs.

Linux futex thresholds come from the host kit.

### 14.4 Executor model: the executor is untrusted

**Combinators.** These are checked definitions in `lemmas/par.core`, and their
meaning is sequential:

```
par::choose(ctx: Exec, c: Bool, a: T, b: T, .h: Eq(T, a, b)) : T := a
par::map_tiles(ctx: Exec, g: Usize, f: A → B, xs: List A) : List B := seq::map f xs
par::join(ctx: Exec, a: A, b: B) : (A, B) := (a, b)
par::reduce(ctx: Exec, op, e, xs, .assoc: Assoc op, .id: Id op e) : T := seq::foldl op e xs
```

`Exec` has kernel meaning `Unit`. The combinators occur only in optimizer
residuals; users never write them.

**Templates.** They are fixed text in the emitted `__rt::par` module, excluded
from the round trip like the dispatchers. In generated mode, the round trip
lowers each template call to its combinator.

**What the templates rely on: parametricity, not trust.** The templates call
Commonware-shaped entry points on an executor `E: __rt::Exec`. They rely only
on parametricity plus the existing assumption that the process is free of UB
(DESIGN §1.1 item 7):
- `run(len, serial, parallel)` and `join(a, b)` are generic in their result
  types. An implementation can only return values produced by the closures it
  was given, and both closures are proven equal.
- `map_collect_vec` is generic in its element type. The template maps tile `i`
  to `(i, tile(i))`. After the call it **checks** that exactly the indices
  `0..n` came back, in order and once each. Otherwise it recomputes the tiles
  serially.
  - An executor cannot forge or duplicate an element of an opaque type (no
    `Clone` bound).
  - Tiles are pure, so a tile that ran twice produced the same value.
- Reductions combine the partition results **sequentially in index order, in
  the template**. So the executor never needs associativity, and the only
  reassociation is the checked `Assoc`/`Id` lemma instance.
- `try_*` returns the leftmost error in index order. That costs extra only on the
  error path.
- In-place outputs (after L1) are disjoint `chunks_mut` slices written by tiles.
  Safe Rust guarantees disjointness, and the index check guarantees coverage.

So **any** `commonware_parallel::Strategy` is safe. The trait is unsealed
(`parallel/src/lib.rs:178` at `86b7ee8674`) and its `fold` does not promise
index order; neither matters here.

- The template emits `impl<S: commonware_parallel::Strategy> __rt::Exec for S`
  under the crate's `commonware` cfg, plus `__rt::Serial` (no_std) and
  `__rt::Scoped { threads }` (std).
- The whole trusted claim is the template text, about 120 lines.

**Plumbing, opt-in per crate** (`[opt] exec_entry_points = true`, because it adds
public API):
- For each boundary function with a thread-eligible site, the optimizer emits
  `f` (SIMD/ILP only, unchanged signature) **and**
  `f_with<E: __rt::Exec>(exec: &E, …)`.
- Executor-carrying clones `g__par` are threaded down the call tree to the site,
  like a variant set.
- The executor parameter is erased (`Unit`). The twin's link is a clone lemma:
  α-equivalence modulo renaming plus the combinator definitions.
- Generated mode recognizes exactly one bound form (`E: __rt::Exec`, a parameter
  of type `&E`).
- Commonware call sites that are generic over `S: Strategy` pass their strategy
  unchanged.

**Stack.** Tiles run code whose DESIGN §3.7 stack obligation (≤ 1 MiB) is proven. The
worker-stack assumption (≥ 2 MiB; the std and rayon default) is recorded in the
DESIGN §1.1 assumption list. The templates do not configure caller-owned pools, and
they claim nothing about them.

**Determinism.** Pure, total code with index-ordered assembly gives identical
results on any executor, including Commonware's deterministic runtime and
`Sequential`. Commonware's adaptive policy keeps arbitrating serial vs parallel,
and the template passes it `multiplier` = the proven per-item cost.

### 14.5 Zero overhead vs Commonware's hand-parallelized code

- **Same entry points.** The templates call the same executor entry points
  (`run_batches`, `map_collect_vec`, `join`) with statically computed
  partitions. The index check is O(tiles), about 4P.
- **Same constants.** The proven costs reproduce the hand-tuned constants:
  - `MIN_STRIPE_BYTES` = 8 KiB is about 14 µs per stripe;
  - curve25519 `MIN_UNITS_PER_PARTITION` is about 74 µs;
  - BLS `MIN_PARALLEL_POINTS` = 32.
- **Where generated code should be faster:**
  - subtree instead of level-synchronous merkleize: 1.4–2× at 2^12–2^16,
    measured on a *(hand-written candidate)*, not on emitted code;
  - x16 lanes on wide MMR/BMT levels, where the hand code always uses pairs;
  - shape-specialized x16 with a constant second block;
  - 2–4-stream shard hashing on aarch64: 1.25–1.29× measured on a
    *(hand-written candidate)*;
  - thread-parallel VROOM batch maps, which PR 4811 runs sequentially;
  - automatic Straus below the Pippenger threshold (§9.4).

### 14.6 Per-workload decisions

| Workload | M5 (measured calibration) | AVX-512 host (hypothesis) |
| --- | --- | --- |
| QMDB `verify`, N = 1 / 32 | nothing: the critical-path cost model drives closed forms instead | nothing; SHA-NI pairs where the DAG has width 2 |
| QMDB `verify_many` (future) | SHA2 ×2 on long chains; threads above about 32 proofs (warm) | x16 lanes per ≥ 7 proofs; masked tail; threads above θ |
| MMR/BMT build, merkleize | subtree threads (T ≤ 4–6 below 200 µs), SHA2 pairs | subtree threads; x16 on levels ≥ 7 nodes; SHA-NI pairs at the top |
| Reed–Solomon | stripes ≥ 8 KiB → threads; columns → NEON TBL; FFT rows sequential; shard hashing SHA2 ×2–4 | stripes → threads; GFNI; shard hashing x16 |
| Ed25519 batch | NEON 2-lane tiles for fused formulas; MSM tiles → threads at n ≥ 64; T ≤ 6 for n ≤ 1024 | IFMA 8 lanes; SHA-512 8-lane multi-buffer; threads |
| BLS batch verify | per-item `hash_to_g2` (90–365 µs) → threads; scalar Montgomery inside | RNS channels as IFMA lanes; threads per item and per MSM tile |

---

## 15. Validation across four workloads and the corpus

**Workload coverage of the development targets** (● central, ○ secondary).
This was called the "anti-overfitting matrix"; it lists only the target
workloads the features were built for, so it shows coverage, not
generality. Every number measured on these workloads and on the corpus
below is a development-set number. The held-out evaluation is the
generality evidence, and so far it is negative. Held-out v2
(`sandblaster/bench/heldout-v2/REPORT.md`, 2026-10-03): 0 of 30 functions
changed (optimizer-only geomean 1.007 default layout, 1.002 aligned,
placement noise); no loop is summarized (the two loops that reach the
optimizer are kept), so none of the capabilities below fired on it.
Held-out v1 (`sandblaster/bench/heldout/REPORT.md`, first run 2026-10-02:
0 of 31 changed, 1.02 / 1.005, no held-out loop reached the optimizer) is
development data now; after stage finish-A 3 of its 31 are rewritten, none
faster (`read_u32_le`, for which the cost model predicted 0.70, measures
1.07–1.12 against rustc: slower in all three binaries).

| Capability | QMDB | Reed–Solomon | curve25519 | BLS/VROOM |
| --- | :-: | :-: | :-: | :-: |
| Σ1 unroll / prune / case-of-case | ● varints, `parse`, checks | ● fixed-(k, m) encoders, error paths | ● 5×5 limb loops, `cswap` | ● 8-lane loops |
| Σ1 polyvariance | ● `shape_go(63,…)`, segment consumers | ● multiplier staging | ● A24 (E3) | ● `mul_by_014`, Frobenius |
| Σ2 closed forms / bound invariants | ● `shape` | ○ size arithmetic | ○ recoding windows | ○ Booth widths |
| Σ3 fusion / demand / known zeros | ● peak buffer | ● known-zero FFT inputs, work-buffer init | – | ○ accumulator arrays |
| Σ4 algebra | ○ bvnorm (SHA) | ● GF(2)-linear → GFNI/TBL | ● E1/E2 (RingRefl), regions | ● delayed reduction, formula selection |
| Σ4 selection via refinement | – | ● matrix vs FFT decode | ● Straus vs Pippenger | ● RNS vs Montgomery per target |
| Σ5 parallel | ○ `verify_many`, merkleize | ● stripes, column lanes, shard x16 | ● 8 lanes, MSM tiles | ● RNS lanes, item threads |
| E0 checked-arithmetic printing | ○ | ○ | ● (1.9× F::mul, third-party code; emitted P18 1.43–1.57×) | ● |
| AVX-512 models | SHA-NI, VPOPCNT/LZCNT, `pext` | GFNI, BW, VBMI | IFMA, SHA-512 lanes | IFMA, `vpermq` |

**General corpus.** P1–P14 (§2.3) plus these additions:
- P15: threaded-cursor tree DFS (state decoupling);
- P16: batch of equal-shape hashes (fusion / lanes);
- P17: GF(2^16) mul-by-constant;
- P18: u64 carry chain;
- P19: 16-term dot product mod p (after L2);
- P20: sparse line multiplication.

Each program has a named route, a proof route, a target and a must-reject
variant. The acceptance targets:
- every non-control program within 1.25× of `ideal/` on aarch64;
- controls P9 and P14 no more than 2% slower;
- x86 v3/v4 clones of P1, P2, P4, P6, P11 and P13 contain `lzcnt`/`tzcnt`/`popcnt`
  (static assembly check).

The per-milestone numbers are in the plan.

---

## 16. Language-extension prerequisites

These are front-end and elaboration-semantics work, not optimizer TCB.

**S0 constraint.** Files under DESIGN §15 S0 are being changed in an isolated
copy that will be merged back:
- `hir.rs`, `resolve.rs`, `loader.rs`, `validate.rs`, `prover.rs`, `visit.rs`;
- `typeck/**`;
- `elab/{mod,obl,order,loops,ensures}.rs`.

So every extension below that touches those files starts after the **S0
merge**. Optimizer milestones O1–O11 use only the existing public APIs of those
files: `ProverChain`, `hir::*` types and `hir::Recursion`.

| Id | Extension | Model | Needed by |
| --- | --- | --- | --- |
| L1 | `&mut [T]` parameters and outputs as linear values (state passing; in-place emission justified by a linear-use check); `fill`, `copy_from_slice`, `copy_within`, `chunks_exact_mut`, `split_at_mut` | DESIGN §13.2 | RS work buffers, parallel outputs, MSM buckets |
| L2 | `u128` and `mul_wide_u64` as **prelude** operations over `Int` in `[0, 2^128)` (no `Width` change), printed `(a as u128) * (b as u128)`; IFMA models reuse `Int` | TCB items 2/3 | curve25519, BLS, Barrett, P19 |
| L3 | `#[memo] const T: [U; N] = build();`: opaque with defining equation (Delta), emitted as `LazyLock` of the verified builder; used through builder-induction lemmas | no trust added | RS tables, basepoint tables, VROOM constants |
| L4 | whitelist: `next_power_of_two`, `next_multiple_of`, `is_multiple_of`, `.rev()` ranges; signed digits as `(u16, bool)` | small | RS, curve25519 |
| L5 | `Secret<T>` MVP: structural taint over structs of limbs; `ct_select`/`cswap` templates with a barrier; post-optimization core check; DIT glue on aarch64 | DESIGN §15.13 | X25519, signing, BLS scalar multiplication |
| L6 | `Vec`/`Seq` collections | DESIGN §13.2 | batch verify, MSM, RS scheme, memoization |
| L7 | static traits over the coordinate field (G1/G2 twins) | DESIGN §14.3 | BLS |
| L8 | exec-context parameter (optimizer-generated only; canon/roundtrip) | §14.4 | threads; **not S0-gated** |

---

## 17. Budgets, determinism, caching

| Budget | Default | On exhaustion |
| --- | --- | --- |
| driver kernel steps per function | 5·10^7 (2·10^8 for `#[specialize]`) | next rung down |
| process-graph nodes per function | 4096 | generalize / keep the call |
| unrolled nodes per chain | 4096 (within the node budget of 20k) | fold |
| polyvariant specializations | 8 per callee, 64 per crate | generic summary |
| Σ2 traces | 256 inputs × ≤ 64 iterations (≤ 10^7 steps) | no closed form |
| Σ2 enumeration | 2·10^5 terms, size ≤ 7; ≤ 3 candidates proven | fallback rungs |
| per-literal lemma | ≤ 5·10^6 steps; ≤ 5·10^8 per loop summary | next rung |
| `BvRefl` per call | ≤ 2·10^5 canonical entries (untrusted caller splits) | split or reject |
| aegraph | 10^4 e-nodes, 8 rounds | best so far |
| Houdini fixpoint | ≤ 16 rounds, ≤ 64 candidates | drop remaining candidates |
| crate optimizer steps | 2·10^10 | remaining functions fall back in dependency order |
| growth cap | 400k residual nodes (existing) | stop specializing |

**Memory.** Every container is bounded by these counts, so peak memory is a
deterministic function of the budgets. The budgets are calibrated so that the
optimizer's peak RSS delta on the QMDB build is at most **512 MiB**, measured at
every milestone gate. `sandblaster-memguard` (`SANDBLASTER_MEM_LIMIT_GB`) stays
linked as an abort-only safety net. The optimizer runs single-threaded per
crate by default; `SANDBLASTER_OPT_JOBS` allows at most 2.

**Cache.**
- A hints-only, content-addressed cache lives under
  `target/sandblaster/opt-cache/` and is **not checked in**.
- The key is: the core text closure of the function and its callees' summaries,
  the static signature, the variant set, the optimizer version, and the hashes of
  the tuning evidence and `PROFILE.json`.
- The value is: the chosen candidate and the proof-term skeleton.
- The kernel re-checks every hit on every build. A miss recomputes the identical
  result.
- A hit changes neither the output nor the report nor what a budget allows. A
  loop summary's cached lemma records the metered steps of its build and
  kernel check, and a hit is charged those steps in place of its own, so
  `budgets_used.loopsum_steps` and the per-loop step budget are the same in a
  cold and a warm build (gate G1 compares a warm build with two cold ones).

**Compile-time targets** on the QMDB crate. After O6 and O7 the optimizer took
about 6.3–6.6 s cold, against 4.4–4.6 s for the O2 baseline in the same G9
run (1.42–1.43×, with one round of three at 1.54×; peak RSS +184–193 MiB).
After O8 it was 1.45–1.50×. The headroom work (§17.1) brings it to about
5.6–5.8 s at N = 32 and 5.4–5.5 s at N = 1 (see
docs/opt-headroom-reports.md for the G9 rounds). Targets:
- cold build ≤ 1.5× (hard gate 2×);
- warm build ≤ 1.15×;
- three consecutive builds byte-identical (`sandblaster.rs` and the report).

### 17.1 Optimizer time: work that is not repeated (headroom)

Only front-end savings count for G9: its baseline is built with the current
kernel, allocator and other crates, so a speed-up there moves both sides.
Each item below keeps the emitted code byte-identical and every result
kernel-checked.

- **Tier 0 through the callees' residuals** (`symex::symex_via`). Tier 0
  inlines the callees it specialized below the inline threshold. It now
  evaluates each such call through the callee's admitted straight-line
  residual instead of the callee's source: the residual is already
  evaluated (its constant tables are literals, its own inlined callees
  unfolded), so the caller does not evaluate them again. The residual is
  convertible with the callee (that is how it was admitted), so the value is
  the same; the caller's residual is still checked against the caller's
  own source (`check_residual_equal`). The QMDB `__sha2` clones that inline
  `compress_sha2` re-evaluated `K4` and `K` at every `K4[g]` (the optimizer's
  evaluation mode has no definition cache); they drop from 28–58 ms to
  8–17 ms each. A residual is never kept as a call.
- **Derived links of multiversioned clones** (`opt::derive`). A clone of a
  driven function is still driven, printed and elaborated (the emitted code
  is exactly the driver's), but when its residual is its original's up to
  the renaming, the link is proven by transitivity: `mirror` relates the two
  residuals (callees closed by their clone lemmas), then the original's
  driven lemma, then the clone lemma reversed. Segment helpers of a clone
  consumer get their entry lemma the same way (the two entries are related
  by `mirror`), and the pair `h' = h` serves the mirror proofs of their
  callers. The kernel checks a derived lemma by comparing the unfolded
  bodies it mentions, so it is tried only where the original's proof is
  large (≥ 10,000 term nodes) and always for segment helpers, and each
  derived lemma has a budget of 2·10^5 kernel steps; otherwise the proof
  builder runs as before. QMDB: `reconstruct_finish__sha2` 364 → 150 ms
  (its four segment helpers and its residual derived).
- **Family certificates** (`auto::bitlib`). A family member reuses the
  previous member's `linarith` certificates only when it has ≥ 8 holes
  (`lz_range`: 65). The kernel searches a certificate of its own when a
  supplied one fails, so a wrong reused certificate costs more than
  certifying a one- or two-hole item (`clz_xor_prefix`, `mask_split`,
  `popcnt_step`, `shl_exact`, whose multipliers depend on `k`). Families:
  249 → 161 ms at N = 32.
- **Proof-cache writes in the background** (`opt::cache`): the entries'
  file writes run on a writer thread, joined when the cache is dropped (at
  the end of the optimizer run); encoding stays on the optimizer's thread.
  If the thread cannot be started, the entries are written in place.
- **Memos.** `symex::is_recursive` per optimizer run (it walks the whole
  body and is asked for every callee of every candidate);
  `sandblaster_targets::evidence::load` (the parsed record, while the file's
  size and time stay the same), `model_hash` and `core_hash` per process
  (the evidence gate asks for every intrinsic of every printed function).

---

## 18. Interactions

### 18.1 DESIGN §15 specifications

- **Unaffected:** `#[refines]` and determinacy are statements about source
  globals, and emitted code equals the source.
- **Discharging laws.** Summaries can discharge laws. When a law's statement is
  convertible with, or linarith-implied by, a summary lemma, the lemma is offered
  as its proof; the kernel checks it, and the spec sheet records "proof:
  optimizer summary `shape_go::summary`". This closes `shape_closed_form` and
  helps `peak_count_bound`.
- **New opportunities.** §9.4 turns refinements into optimization
  opportunities.
- **`SPEC.lock`** is untouched.

### 18.2 Round trip

- **Canonical printings.** Every new construct has one:
  - residual control flow and loop helpers;
  - `__rt::chk::*`;
  - masked vector helpers;
  - `__rt::par::*` template calls;
  - the `&E: __rt::Exec` parameter.

  Each has a generated-mode lowering in `roundtrip.rs`.
- **Compare target.** For a lemma-admitted function, the compare target is its
  residual global.
- **Exclusions.** Templates are excluded, like dispatchers.

### 18.3 Multiversioning

- **Per set.** Summaries are computed once, and selection happens per set
  (§4). Tier 0 still re-specializes clones whose leaves call variants.
- **Clone work reused (headroom, §17.1).** A driven clone whose residual is
  its original's renamed takes its link by transitivity through the
  original's lemma and the clone lemma, instead of a new proof from its
  process tree; the same for its segment helpers.
- **Variants.** Lane-lifted variants go through the same evidence gate as
  `#[implements]` variants.
- **Missing `clone_equiv`.** A clone without a `clone_equiv` lemma is emitted
  with a warning today (`multiversion.rs`). That becomes an error in O4, as
  DESIGN §15.2 S3 already plans.

### 18.4 `#[specialize]`

- **`#[specialize]`** means the function must end `Specialized` with any link.
- **`#[specialize(loop_free)]`** also requires a residual without loops, so
  losing `shape`'s closed form fails the build.
- **On failure**, the error prints the first failed step of the process graph:
  the stuck term, the failed obligation, or the budget.

### 18.5 Constant time

- **No secret branches.** The driver never splits on `Secret` data. It merges
  through `ct_select` or keeps the source form.
- **Closed forms.** Σ2 refuses loops with secret state.
- **Instruction choice.** Closed forms over secrets may use only instructions
  marked fixed-latency in the per-target table.
- **Final check.** The DESIGN §15.13 optimized-core check runs after summarization and
  printing.

---

## 19. Host-validation kit (AVX-512: Ice Lake, Sapphire Rapids, Zen 4, Zen 5)

`tools/host-kit/run.sh` merges the scratch kits in `$O/par`, `$O/corpus`,
`$O/rs/{rsbench,gfniasm}`, `$O/curve25519/bench` and `$O/bls/harness` into a
single command. It is compile-checked on this Mac, runs with capped parallelism
(`-j 4`, one benchmark process at a time), and needs crates.io access.

1. **Model evidence.** Run first, in this order: SHA-NI, then BMI/LZCNT/POPCNT
   (known-answer tests), then AVX-512 groups.
   - ≥ 10^7 random inputs per model, plus corners:
     - lanes 0, ~0, 0x80…, single bits;
     - IFMA operands 2^52−1, 2^52, 2^63, 2^64−1 with junk in bits 63:52;
     - every shift count 0–255;
     - every immediate exhaustively (`ternarylogic`, `shuffle_i64x2`,
       `gf2p8affine`);
     - permutation indices with junk high bits;
     - `set_epi64` lane order;
     - masked loads at every tail length.
   - Output: `evidence/x86_64.json`, keyed by model hash × CPUID
     vendor/family/model/stepping (+ microcode).
   - **Feature-only sets** (stage `sets`, headroom): the harness
     `sandblaster/front/tests/host_sets.rs` emits the QMDB verifier
     (N = 1, N = 32) with every feature-only set's clones (their evidence
     granted by a test hook), runs each set's clones directly against the
     portable code (every fixture, and a `shape` differential over corner and
     10^6 pseudo-random inputs), and `sandblaster-targets-evidence --record-set`
     records each run under the CPU's key (`diagnostic` when the CPU does not
     report the set's features). A process that stops on an illegal
     instruction is recorded as a failure on a CPU that reports the features
     and not at all on one that does not.
2. **Differential tests.** Every generated variant against its portable
   function:
   - QMDB fixtures N=1/N=32 plus oracle random proofs (`verify__shani`, `__v4`);
   - corpus checks (400k integers, 1M varints, `pext`);
   - the RS grid vs Commonware AVX2, plus GFNI mul for all 65536 multipliers;
   - curve25519 RFC 8032/7748, Wycheproof and ZIP215 vs Commonware avx512 and
     dalek IFMA;
   - BLS lane-exact vs PR 4811's `kernels_match_portable`, and canonical vs blst.
3. **Tuning evidence** (`evidence/tuning-x86_64-<uarch>.json`):
   - per-op latency and throughput;
   - SHA-NI latency/throughput and k_sat;
   - x16 minimum active lanes b*;
   - 512 vs 256 bit;
   - `pext` speed;
   - Linux futex θ_enter and o_fork;
   - level/batch/tree crossovers;
   - memory bandwidth.
4. **Benchmarks:**
   - QMDB whole-`verify` same-binary A/B (portable vs `__shani` vs `__v4`);
   - corpus under `target-cpu=native`, `x86-64-v4` and `x86-64`;
   - RS kernel/engine/scheme tables;
   - curve25519 single-op and batch grids;
   - BLS vs PR 4811 tables.

   Each configuration is built at least 3 times with different codegen-unit and
   link orders, and min/median are reported to expose op-cache sensitivity.
5. **Report.** `results-<host>-<date>.md` with CPU flags, the static
   instruction mix per kernel (e.g. IFMA counts vs the PR budgets), and pass/fail
   per gate.

**Gating.** Evidence enables dispatch and fails closed. Tuning evidence changes
choices only.

**Hypotheses to confirm or refute:**
- the H2 `shape` loop costs more on x86 (a branch per width);
- zeroing the buffer costs 10–20 ns;
- `pext` beats unrolling only for 5–9-byte varints;
- x16 beats SHA-NI at ≥ 7 lanes;
- GFNI ≥ 2× Commonware AVX2;
- IFMA parity with Commonware's avx512 backend and PR 4811.

---

## 20. Soundness must-reject suite (`sandblaster/front/tests/opt_reject.rs`)

Each test injects an unsound candidate, proof or rule through `OptTestHooks`.
It asserts three things:
- the kernel (or round-trip) error kind;
- `Unspecialized { failure: true }` with the fallback emitted;
- a build error under `SANDBLASTER_STRICT_OPT=1`.

| Id | Injected fault | Rejected by |
| --- | --- | --- |
| R1 | prune of a live arm (fact dropped from hypotheses) | Linarith check |
| R2 | varint: 9th-byte range check claimed dead | Linarith |
| R3 | partial read hoisted out of its guard | extraction check; if forced, residual elaboration |
| R4 | residual arm differs from the driven source (`Some`/`None` swapped) | lemma type check |
| R5 | segment rewrite `take(C₂, nb+2+na) = B ++ d::A` | `take_append` side condition |
| R6 | early exit on a find-*last* variant of `shape_go` | invariant preservation |
| R7 | closed form off by one (`h = 64 − lz`) | `lemma_k` for some k |
| R8 | wrong invariant (`before = popcnt(L >> (f−1))`) | step obligation |
| R9 | `foldl f z (X ++ Y) = foldl f (foldl f z Y) X` | induction step |
| R10 | fold with a non-decreasing measure | kernel termination check |
| R11 | two helpers calling each other (mutual recursion) | `add_def` |
| R12 | helper whose `requires` is not implied at a call site | elaboration obligation |
| R13 | fact from arm A used in arm B | motive typing |
| R14 | select-converted arm containing a partial operation | extraction check; if forced, elaboration |
| R15 | wrapping op on a path where the source value overflows | equality lemma unprovable |
| R16 | lane-lifted SHA with lanes 3/4 swapped | lane-functor lemma |
| R17 | `par::reduce` with `wsub` | `Assoc` obligation; site stays sequential |
| R18 | executor that drops, duplicates or permutes tiles | template index check → serial recompute; result identical |
| R19 | E0 helper printed with swapped operands / wrong width | round trip |
| R20 | K1 with `lz`/`tz` swapped or an off-by-one summand | exhaustive U8/U16 axiom tests |
| R21 | feature-only clone on a CPU where `lzcnt` executes as `bsr` (simulated) | dispatch known-answer test → portable |
| R22 | representation-region helper leaking a non-canonical value to a replaced function | no plain equality → fallback |
| R23 | split on a `Secret` scrutinee; merged secret arm printed as `if` | driver refusal; post-optimization constant-time check |
| R24 | `eq8_word` "proven" by linarith | kernel rejects; lemma library build fails |
| R25 | forged cache entry (tampered proof skeleton) | `add_def` |
| R26 | unvalidated intrinsic in a dispatched variant | evidence gate |
| R27 | clone residual reused without `clone_equiv` | emission-chain check |

---

## 21. Risks and open questions

| # | Risk | Mitigation |
| --- | --- | --- |
| 1 | Σ2 step obligations for `shape_go`/P4 do not close with rational linarith | integer-cut tactic; per-literal lemmas keep shifts literal; **O3 prototypes the full obligation set before Σ2 is built**; rungs 2–3 need weaker facts; last resort: a reflective bit-blasting checker (prelude, 0 TCB) |
| 2 | TCB budget (≈ 190 lines of headroom) | K1 only, net ≈ +40; reflective RingRefl; GF lowering via extensionality; `u128` in the prelude; re-audit before landing (AUDIT.md method: non-blank non-comment lines) |
| 3 | Reflective RingRefl too slow (Fp12 ≈ 144 monomials) | budgets; cache; decision point D3 with a TCB design note, never a silent kernel addition |
| 4 | Proof memory (the > 10 GB incident) | lane functor; `BvRefl` entry cap; no whole-function import proofs; memguard |
| 5 | Scope: ≈ 30k untrusted lines | milestones ship value independently; every milestone keeps the fallback; the QMDB gate lands by O7 |
| 6 | Path explosion and code growth (op cache) | unroll only on static measures under budget; merges; code-size term; 3% gate; growth cap |
| 7 | Cost-model error, especially x86 and distribution-dependent choices | profiles; tuning evidence; multi-result extraction; runtime arbiter for threads |
| 8 | Printing details erase candidate gains (e.g. a non-inlined `shape_cf` helper) | acceptance measures emitted code only; `#[inline]` on small helpers; asm checks |
| 9 | LLVM pessimizes emitted intrinsics code (×19 scalarization seen in curve25519) | measure first; trusted asm templates with models and evidence only where measured (a DESIGN §9.2 extension) |
| 10 | Determinism regressions | ordered maps, fixed-point costs, CI builds three times and diffs |
| 11 | Representation regions are a new design surface | staged late (O18); plain equality at every replaced function; red-team before landing |
| 12 | S0 merge conflicts | O1–O11 use only existing public APIs of S0-owned files; language work waits for the merge |
| 13 | Synthesis fails on arbitrary loops | the ladder degrades and each rung is certified; the report names the failing class so a `#[rewrite]` law or better source can be written |

**Not planned:**
- learned or evolutionary autotuning in the build (nondeterministic);
- a global implicit thread pool;
- heartbeat / TPAL scheduling;
- reassociation over non-canonical representations without a view law;
- colored e-graphs;
- SME / streaming SVE (§13.5).

---

## 22. Research summary

### 22.1 Prior art (families, verdicts)

| Family | Contribution adopted | Why not the whole design |
| --- | --- | --- |
| K framework (all-path reachability, "Compiling by Proving", arXiv 2509.21793) | path compression = Σ1 unrolling; branch lifting = case-of-case; circularities = induction hypotheses | abstracts loops with invariants, invents no closed forms; no per-result certificate |
| Partial evaluation (Jones–Gomard–Sestoft; Danvy TDPE; Truffle/AnyDSL filters) | static measures as the unrolling filter; polyvariance | cannot solve loops or remove buffers alone |
| Supercompilation (Turchin; Sørensen–Glück–Jones; Bolingbroke–Peyton Jones; **TT Lite SC** certifying supercompiler for MLTT) | driving, whistle, generalization, fold; process graph read as a proof | whistle/generalization cost; no mutual recursion in the kernel (fold rule §6.6) |
| Deforestation / fusion (Wadler; foldr/build; Strymonas) | first-order segment lemmas inside the driver | foldr/build needs parametricity and closures |
| Equality saturation (egg, egglog, Cranelift aegraph, lean-egg, Isaria; Flatt et al. explanations) | acyclic e-graph for straight-line selection; explanations as proofs; rulegen (Ruler/Enumo/Hydra) | colored e-graph replay over dependent types has no precedent; loops/buffers need other machinery |
| LLVM SCEV / LoopIdiomRecognize / SROA / DSE (Crellvm) | chains-of-recurrences structure extended with bit classes | measured: LLVM recovers none of the regression |
| Superoptimization (STOKE, Souper, Minotaur, CryptOpt) | offline only, feeding checked lemma libraries | nondeterministic and slow in-build |
| Translation validation (CompCert validators, Alive2, Crocus) | is sandblaster's architecture; validate rules once, instantiate often | framework, not an optimizer |
| Recurrence solving / closed-form synthesis / verified lifting (Kincaid et al.; Frohn; EUSolver; Brahma; Tenspiler/MetaLift) | Σ2: synthesize summary + invariant, prove by induction | synthesis may fail → ladder |
| Compositional summaries (Infer, Godefroid, veritesting) | per-function summaries reused at every call site; merging into selects | – |
| fiat-crypto / Rupicola / Lean `csimp` | rewriting engines from proven equations; lemma-database lowering; bounds by linarith | design influence |
| Certified bit-blasting (bv_decide, SMTCoq) | reflective fallback option for SWAR-class identities | not needed for the hot spots once K1 lands |

### 22.2 Parallelism findings (M5 measurements; `$O/par`, `$O/parbench`)

**SHA-256 kernels:**
- SHA2 instructions: latency 18.8–20.0 ns/block, throughput 14.1–14.9, so the
  ILP headroom is 1.33×, saturated at k = 2.
- NEON 4-lane software SHA: 47–61 ns/block.
- portable: 139–165 ns/block.

**Fork-join costs:**
- `rayon::join` in the pool: about 20 ns.
- `install` round trip: 3.6–20.6 µs; after being idle: 19–30 µs.
- spinning pool: 0.15–0.57 µs.

**Workloads:**
- Merkle level: sequential up to 256 pairs; 1.7× at 1024 pairs; 5.7–6.5× at
  65536 *(hand-written candidates)*.
- Batch paths, K independent 20-deep paths: 1.28–1.30× from interleaving alone;
  8.1× at K = 4096 *(hand-written candidates)*.
- Subtree vs level parallelism: 1.75× (2^10) to 10.2× (2^20) for subtree;
  level-synchronous is always worse *(hand-written candidates)*.

**Single-proof QMDB verify.** It is a single dependent chain covering 85–90% of
the time. Fusing the independent `hash_chunk` saves 1.5 ns (0.4%). Never use
threads or lanes for it.

**Commonware's manual parallelism** (`parallel/src/policy.rs`) is an adaptive
per-callsite EWMA. Serial is sampled only below 10 ms of projected serial time,
and jobs under 1 ms are spawned inline. sandblaster reuses it as the runtime
arbiter.

### 22.3 Reed–Solomon findings (`$O/rs`; monorepo `86b7ee86` = pin for these paths)

**Structure.** Two layers:
- the scheme: `coding/src/reed_solomon.rs` (stripes, BMT commitments);
- the vendored Leopard engine: GF(2^16) in a Cantor basis, LCH additive FFT,
  high/low rates, NoSimd/SSSE3/AVX2/NEON engines behind `Box<dyn Engine>`.

There is **no AVX-512/GFNI engine**.

**Measured:**
- `Neon::mul`: 32–33 GiB/s.
- LLVM on portable nibble-table code: 1.8 GiB/s (18× slower); bit-matrix code:
  5.1 GiB/s.
- Shard SHA-256 is 59–76% of sequential encode time. Multi-stream SHA2 gives
  1.25–1.29× *(hand-written candidate)*.
- Spec-shaped matrix decode: 1.9–5.2× faster than Commonware's FFT decode at
  n = 10–100. Small high-rate decodes pay about 250 µs of 65536-point FWHT.
- Rayon(8): 2.6–5.5×.

**Checked facts:**
- twiddles: `skew[x + 2^m − 1] = log(ω_{x>>m})` for all 65534 entries;
- interpolation specs equal both rate encoders (36 configurations);
- GFNI lowering matches for all 65536 multipliers on SDM models;
- the GFNI kernel has 4 vector ALU ops per 64 B, vs 20 for Commonware's AVX2
  shape.

### 22.4 curve25519 findings (`$O/curve25519`; monorepo `6e15fe7c` = `86b7ee86`)

**Where Commonware stands.** It is tuned for batch verification: 8 SoA lanes,
NEON and IFMA backends, Pippenger, threads. Single-shot operations use naive
algorithms:

| Operation | Commonware | Reference |
| --- | ---: | ---: |
| verify | 73.5 µs | ed25519-consensus 23.0 µs |
| sign | 51 µs | ed25519-consensus 9.6 µs |
| X25519 | 33.5 µs | x25519-dalek 24.1 µs |
| batch n=1 | 426 µs | – |

**Overflow checks in release** cost 1.9× on F::mul *(third-party code)*.

**Level E experiment.** Four exact rewrites, bit-identical (2M field cases, 2000
X25519 cases): E0 unchecked printing, E1 ×19 folding, E2 carry narrowing, E3
A24 specialization. Result: X25519 **18.2 µs** vs 33.9 µs, and vs x25519-dalek's
27.5 µs in the same run.

**What the next tier needs.** Lazy reduction, SIMD kernels and group-law
algorithms (Straus, wNAF, Pippenger) need view-level links or group laws. That
is §9.5 regions, with author-supplied algorithms selected through refinement
(§9.4).

**IFMA static budgets** (per 8-lane kernel):
- `mul_field`: 148 instructions, 26/25 IFMA;
- `add_points`: 1604 instructions.

### 22.5 BLS12-381 / VROOM findings (`$O/bls`; PR 4811 at `5a68b8f417`)

**The PR.**
- Shared bounded-RNS arithmetic: 8 lanes × 2 bases, 50/52-bit, bounds carried in
  const-generic types.
- Portable and AVX-512 IFMA kernels. The ARM paths were removed in commit
  `64cf673971`.

**PR results** (AWS C8a, Zen 5, one core):

| Workload | Speedup |
| --- | ---: |
| pairing | 4.13–4.58× |
| MSM, 100k–1M points | 2.26–2.82× |
| batch subgroup check | 10.86–22.18× |
| hash_to_G2 | 1.21× |
| sign | 1.73–1.77× |

**M5 measurements, portable path:**
- Fp mul 70.5 ns vs blst 19.8 ns (3.6×).
- `sum_of_products` is 15.1× faster than closed operations on a 16-term dot
  product.
- Batched reductions are **0.81×** on the portable path; they only win with
  IFMA.
- Plain-Rust six-limb Montgomery: about 1.1× blst latency. So Montgomery is the
  right aarch64 representation and RNS the right IFMA representation. That
  choice is per target, between author-supplied implementations that refine one
  spec.

**IFMA budgets:**
- Fp12 mul: 948 IFMA / 2312 instructions;
- G1 add: 804 / 2775;
- Miller loop: 6924 IFMA.

**Threads.** The crate has none. `hash_to_G2` scales 5.52× at 8 threads;
fork-join with fresh threads costs 20–54 µs.

---

## 23. Judges' scores and how each flaw is resolved

Three judges each scored the three candidate designs. Higher is better on every
axis ("risk" = how well risk is contained). All three picked **summaries** as
the winner.

| Design | Judge | Soundness | Generality | Perf | Risk | Compile cost |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| summaries (Σ1–Σ5) | 1 | 8.5 | 9 | 8.5 | 6.5 | 6 |
| | 2 | 8.5 | 9 | 8.5 | 5 | 6 |
| | 3 | 9 | 9 | 8 | 6.5 | 6 |
| | **mean** | **8.67** | **9.00** | **8.33** | **6.00** | **6.00** |
| eqsat (colored R-graph) | 1 | 8 | 9 | 8 | 5 | 4.5 |
| | 2 | 8 | 7 | 7 | 4 | 4 |
| | 3 | 8 | 9 | 8 | 4 | 4.5 |
| | **mean** | **8.00** | **8.33** | **7.67** | **4.33** | **4.33** |
| supercomp (positive supercompiler) | 1 | 7 | 8 | 8 | 5.5 | 6 |
| | 2 | 8.5 | 8 | 8 | 5.5 | 6 |
| | 3 | 9 | 8 | 8 | 6 | 6.5 |
| | **mean** | **8.17** | **8.00** | **8.00** | **5.67** | **6.17** |

Why summaries won:
- It is the only plan whose full four-workload scope fits the 10k kernel budget.
- It keeps today's specializer as tier 0.
- Its first new code generalizes `mirror.rs`.
- It has the only real mitigation for the lane-proof memory blow-up (the lane
  functor).
- It keeps plain equality at every replaced function.
- It has the most complete fallback ladder and must-reject suite.

| Flaw found | Resolution in this design |
| --- | --- |
| Executor trait unsealed; `Strategy::fold` promises no order; `try_fold` returns any error (all three) | executor untrusted: parametricity + index check + sequential combine in the template; leftmost error (§14.4); R18 |
| Import by whole-body `BvRefl`; per-lane `BvRefl` for x16 (eqsat, supercomp) | unfolding by `Delta`; `BvRefl` capped at 2·10^5 entries; lane functor (§13.3) |
| View-level links for replaced functions; process-wide dispatch constancy (supercomp) | regions produce helpers only; boundary functions plainly equal; nothing representation-dependent escapes (§9.5); R22 |
| `unsafe unchecked_*` extends the UB surface (summaries, supercomp) | E0 via `__rt::chk::*` wrapping helpers with an operand-exact round-trip rule; debug keeps checks; `unchecked_*` only per measured site (§11.5); R19 |
| Native RingRefl and a `U128` `Width` do not fit the budget (eqsat, supercomp) | reflective RingRefl; `u128` over `Int` in the prelude; decision point D3 (§9.3, §16) |
| Feature-only clones declared evidence-free; LZCNT runs as BSR on old CPUs (all three) | known-answer self-test at first dispatch + host-kit differential (§13.2); R21 |
| `h ≤ 62` derived from `leading_zeros_lt`, which bounds `lz` from above (supercomp) | `lz_ge_one` from K1 (`x < 2^63 ⇒ lz ≥ 1`) (§12.1) |
| Templates "configure the pool": false for caller-owned pools (supercomp) | assumption recorded (≥ 2 MiB worker stacks); tiles meet DESIGN §3.7 (§14.4) |
| `bytes_eq_word` "by linarith" (summaries) | `eq8_word` via bvnorm byte extraction + `eq_sound`/`complete` (§12.4); R24 |
| K0 makes prelude text part of the axiom's meaning (summaries) | K1 is self-contained in `axioms.rs`, built only from primitives, stated in `Int` (§11.4) |
| G1 mask at k = w−1 underspecified (supercomp) | K1 has no k parameter; the all-ones literal is explicit; exhaustive tests cover every width edge |
| Merged `Secret` arms rely on LLVM keeping a select (all three) | `ct_select` template with a barrier (§6.3); R23 |
| Per-literal obligations never run through the kernel; linarith rejects `ne…true`/`eq…false` (all three) | O3 prototype gate; fact normalization with on-demand splits (§6.3); integer-cut tactic (§7.5) |
| Candidate numbers quoted as optimizer output (all three) | every gate measures emitted code in a same-binary A/B; `#[inline]` hints; asm checks |
| Distribution-dependent choices from synthetic traces (all three) | `PROFILE.json` from fixtures (§10.4) |
| TCB count needs re-audit (judge 2) | AUDIT.md method: 9,808 of 10k; K1 net ≈ +40; re-audit at O3 |
| No batch memoization or cursor decoupling (all three) | Σ5 state decoupling and equal-input memoization (§14.2); corpus P15/P16 |
| SHA-NI evidence must come first on x86 (judge 2) | host-kit step 1 (§19) |
| Σ3 limited to counted accumulator recursion (summaries) | general consumer driving over segments; SP1/SP2 as fast templates (§8.2) |
| Driving per variant set multiplies compile time (summaries) | drive once on the portable meaning; per-set extraction only (§4) |
| Checked-in `SUMMARY.lock` churns on tuning changes (summaries) | hints-only cache under `target/`, not checked in (§17) |
| 2 GB RSS / +100% cold build is too high for a shared machine (summaries) | ≤ 512 MiB optimizer RSS delta; single-threaded by default; cold ≤ 1.5× (gate 2×) (§17) |
| `f_with` twins generated by default add public API (summaries) | opt-in per crate (§14.4) |
| Colored-e-graph replay is research-grade; color budget contradicts varint depth (eqsat) | no colors: path sensitivity lives in the driver; the aegraph is straight-line only (§10.1) |
| Algebraic tier underdesigned (supercomp) | Σ4 with RingRefl, E1/E2, formula selection, reduction placement (§9) |

---

## 24. DESIGN.md edits this requires (to land with the milestones)

- **§0 item 4 and the §1 diagram:** "residual straight-line code" becomes
  "summaries with residual control flow, loops and closed forms, each linked by
  a kernel-checked lemma".
- **§1.1 TCB:**
  - item 1: K1 in the axiom list;
  - item 2: `__rt::chk::*` and the executor parameter in the canonical dialect;
  - item 3: the `u128` prelude type;
  - item 4: `__rt::par::*` and `ct_select` templates, and the feature-only
    known-answer test;
  - item 7: worker stacks ≥ 2 MiB.
- **§5.10:** add `count_ones_def`, `leading_zeros_def` and `trailing_zeros_def`.
  Move `count_ones_le`, `leading_zeros_le/lt` and `trailing_zeros_le/lt` to
  checked lemmas.
- **§8.2:** replaced by Appendix A.
- **§8.3:**
  - checked-arithmetic helpers and their round-trip rule;
  - residual helpers with `#[inline]`;
  - `__rt::par::*` calls;
  - the executor parameter form;
  - `ct_select`.
- **§9.3:** feature-only variant sets with the known-answer test; the x86 set
  list; `pext` in v4 only.
- **§9.4:** no longer "later milestone"; the lane functor replaces per-lane
  `BvRefl`.
- **§13.4:** the executor model (untrusted executor, templates, `f_with`).
- **§15.2:** `Link::Lemma` for residuals is the lemma for later
  transformations. Representation regions are helpers only.

---

## Appendix A. Proposed DESIGN.md §8.2 (normative)

### 8.2 Optimizer (always runs, untrusted, results kernel-checked)

"Always on" means: every exec function goes through the optimizer on every
build and there is no flag to disable it. Each function gets exactly one
result, `Specialized { link, rung }` or `Unspecialized(reason)`, recorded in
the report. If the untrusted optimizer fails, runs out of budget, or produces a
candidate the kernel rejects, the build **emits a warning** and uses the next
weaker candidate and finally the proven unspecialized definition (soundness
never depends on the optimizer; the test suite runs with
`SANDBLASTER_STRICT_OPT=1`, which turns such warnings into errors).
`#[specialize]` turns a failure to specialize that function into a build error
printing the first failed step; `#[specialize(loop_free)]` also requires a
residual without loops (use them on hot paths).

1. **Summaries, bottom-up.** In callee-first order each function `f` gets one
   summary: a residual `r_f`, its **link** to `f`, exported fact lemmas
   (`Π x̄ h̄. P(x̄, f x̄ h̄)`), an all-path decision tree, a parallel skeleton and
   a cost per variant set. Callers use a callee's summary (keep the call,
   inline `r_f` through its link, or instantiate its tree) and never re-drive
   its body. Driving runs once per function on the portable meaning; only
   selection (item 6) and tier-0 re-specialization of clones run per variant
   set.
2. **Tier 0 (straight-line).** Array parameters `[T; N]` (literal N ≤ 256) are
   spine-expanded (§5.9); summarized callees, builtin exec methods and
   intrinsics (§5.6) are opaque heads unless their residual is below the
   inline threshold. A **stuck-free** value (primitives, constructors,
   literals, lets, `index(fst p, lit)`, opaque calls, neutral intrinsic
   applications) is residualized with sharing, its proof slots re-proven, and
   admitted with `check_residual_equal` (link: conversion).
3. **Tier 1 (driving).** Otherwise a driver (online partial evaluation on
   `eval_opaque`) builds a process graph:
   * Entry: arrays and non-recursive single-constructor parameters are
     η-expanded; `requires` are facts.
   * Unfolding is the driver's choice, justified by `Delta`: a recursive
     application unfolds when its measure evaluates to a literal or its
     structural argument is a closed spine (within the unroll budget), or while
     a homeomorphic-embedding whistle stays silent; otherwise the driver
     generalizes (most specific generalization; candidate invariants are kept
     only if proven at entry and on every back-edge) and folds. A back-edge
     folds only into the nearest unfolding of the **same** global (no mutual
     recursion); the residual keeps the source measure.
   * A stuck match on a neutral scrutinee is **reused** (an earlier split),
     **pruned** (linarith on path facts), **merged** into a select (both arms
     total, cheap and free of partial operations; mandatory, through the
     `ct_select` template, on `Secret` data) or **split** into a residual match
     whose arms carry their path equation. `ne … true` and `eq … false` facts
     are split on demand and never given to linarith.
   * A match on a summarized callee's result is pushed into the callee's
     leaves (case-of-case); leaves the continuation's facts contradict are
     pruned. A call with static arguments or branch-deciding facts gets a
     polyvariant specialization (≤ 8 per callee).
   * At stuck points the driver consults **loops** (one-iteration symbolic
     execution → recurrence classes → closed forms synthesized from traces;
     rungs: closed form > early exit > idle skip > set-bit iteration >
     residual loop), **sequences** (take/drop/append/update/replicate/
     `copy_range` normal form over clamped `Int` lengths; consumers driven over
     segments; unread segments, dead initialization and copies disappear) and
     **algebra** (`bvnorm`; GF(2)-linear maps lowered to table or affine forms;
     reflective RingRefl; implementations refining one spec; `#[rewrite]`
     laws).
4. **Admission by lemma.** A residual with control flow or recursion is
   committed (`add_def`, kernel-checked, recursion mode included) with
   `r_f::equiv : Π x̄ (h̄ :Irr Req_f). Eq(R, r_f x̄ h̄, f x̄ h̄)` (link: lemma),
   built from the process graph: `Delta` per unfolding, dependent matches with
   path equations per split, transport along `Linarith` certificates per prune
   or refinement, lemma instances per summary, fact or law, `Rec` (with the
   source measure's decrease proof) per fold, `BvRefl` for word leaves (≤ 2·10^5
   canonical entries per call) and, for a literal fuel K, K+1 non-recursive
   per-literal lemmas. Bit-count facts come from the definitional axioms of
   §5.10. New helpers carry their own lemmas; every function that replaces a
   source function has a plain equality to it, and representation-changing
   code (lazy reduction, SIMD limb layouts) exists only in helpers inside a
   region whose boundary function is plainly equal. `check_residual_equal` is
   unchanged.
5. **Residual code.** Lets are scoped to arms; a partial operation is placed
   only where the path facts imply its domain (checked at extraction) and its
   proof slot is re-proven by `elab::generated::resume`; arithmetic whose
   overflow freedom is not locally provable is emitted in wrapping form and
   justified by the link. Printing follows §8.3 (checked arithmetic through
   `__rt::chk`).
6. **Selection.** Per variant set, the candidates (ladder rungs, straight-line
   alternatives from an acyclic e-graph over kernel-checked rules and `bvnorm`
   classes, feature-gated lowerings) are ranked by a target cost model
   (latency/throughput tables, critical-path weight, trip counts, branch
   probabilities from the checked-in `PROFILE.json`, code size; x86 constants
   from host-kit tuning evidence, which changes choices only). A candidate
   replaces the next rung only if it is ≥ 3% cheaper; the top three are kept
   and at most two retries follow a proof failure.
7. **Multiversioning** (§9.3): whole call trees are cloned per hardware
   variant set, selected per set and dispatched once at the boundary; a
   residual's clone is linked by `clone_equiv`. Feature-only sets (x86 `popcnt,
   lzcnt, bmi1, bmi2`; aarch64 `cssc`) use primitives only, need no model
   evidence, and are dispatched only after a known-answer self-test.
8. **Proven bounds-check elimination** (unconditional): every index/range
   operation in the optimized core carries a checked proof, so codegen prints
   `get_unchecked` forms (§8.3).
9. **Parallelism** (§9.4, §13.4): independent work (antichains; maps;
   reductions with proven `Assoc`/`Id`; searches; trees; state-decoupled
   recursions) is mapped innermost first to ILP (fusion, k ≤ k_sat), lanes
   (lane functor: one lanewise lemma per intrinsic model) and threads. Threads
   need an execution context: opt-in `f_with(exec, …)` entry points whose
   kernel meaning ignores the context, fixed templates that validate tile
   indices and combine in index order (the executor is untrusted), and a
   guard between two proven-equal versions. Work below the thread threshold
   never gets threads.
10. **Determinism and budgets.** All budgets count steps or nodes; maps are
    ordered; seeds are content hashes; costs are fixed-point. The output is a
    function of the source, the variant set, the options, `PROFILE.json`, the
    tuning evidence and the optimizer version. A content-addressed cache under
    `target/` holds hints only; every hit is re-checked by the kernel.

---

## Appendix B. Evidence and sources

**Repository** (read-only):
- `DESIGN.md` (sections above);
- `sandblaster/front/src/opt/{mod,symex,residual,mirror,multiversion,variant}.rs`;
- `sandblaster/kernel/src/{api.rs:161-270, alpha.rs:200-290, axioms.rs:270-300, eval.rs, bvnorm/mod.rs:738}`;
- `sandblaster/kernel/AUDIT.md` (9,808 non-blank non-comment lines);
- `prelude/{list,slice,base}.core`;
- `elab/semantics.rs`;
- `sandblaster/fixtures/qmdb/sandblaster/{merkle.rs:119-184, 333-414; codec.rs:130-162; LAWS.rs:49}`;
- `qmdb/BENCHMARKS.md`.

**Scratch evidence** (`$O`, ephemeral; imported in plan O1):

| Topic | Files |
| --- | --- |
| stuck reasons | `explore.txt` |
| regression anatomy | `run2_{shape,finish,varint,path,verify,replay}.txt`, `run3_verify.txt`, `run_qmdb2.txt`, `run_corpus1.txt` |
| hand-written candidates | `micro/h2x/src/lib.rs` (`shape_closed`, `finish_fused`, `uint64_unrolled`, …) |
| corpus | `corpus/` (dsl, ideal, cgen, qgen) |
| x86 assembly | `asm/x86/*` |
| parallelism | `par/`, `parbench/` |
| Reed–Solomon | `rs/` |
| curve25519 | `curve25519/` |
| BLS / VROOM | `bls/` |

**Commonware:**
- `~/code/monorepo` at `86b7ee8674`, pin `6e15fe7c`:
  - `parallel/src/lib.rs:178-240, 388, 460, 713`;
  - `parallel/src/policy.rs`;
  - `coding/src/reed_solomon.rs`;
  - `cryptography/src/reed_solomon/`;
  - `cryptography/curve25519/`;
  - `storage/src/{merkle,bmt}/`.
- `~/code/monorepo-blst-vendor-simd` at `5a68b8f417` (PR 4811). Paper: VROOM,
  eprint 2026/393.

**Prior art:**
- *K framework:*
  - Compiling by Proving (arXiv 2509.21793);
  - all-path reachability (LMCS);
  - proof certificates for K's verifier (OOPSLA 2023).
- *Supercompilation:*
  - TT Lite SC (PSI 2014);
  - supercompilation by evaluation (Haskell 2010).
- *Deforestation and fusion:* Stream Fusion to Completeness (POPL 2017).
- *Equality saturation:*
  - egg;
  - Small Proofs from Congruence Closure (FMCAD 2022);
  - aegraphs (EGRAPHS 2023);
  - Isaria (ASPLOS 2024);
  - lean-egg (POPL 2026).
- *LLVM:* LoopIdiomRecognize; Crellvm (PLDI 2018).
- *Superoptimization:* Minotaur (OOPSLA 2024); Hydra (OOPSLA 2024).
- *Loops and closed forms:*
  - closed forms for numerical loops (POPL 2019);
  - modular loop acceleration (TACAS 2020);
  - Tenspiler (ECOOP 2024).
- *Verified crypto and rewriting:*
  - fiat-crypto (S&P 2019);
  - verified rewriting (ITP 2022);
  - Rupicola (PLDI 2022);
  - Lean `csimp`;
  - bv_decide.
- *Parallelism:*
  - HACLxN (CCS 2020);
  - CryptOpt (PLDI 2023);
  - SYMPLE (SOSP 2015);
  - Futhark incremental flattening (PPoPP 2019);
  - oracle scheduling (OOPSLA 2011);
  - rayon 1.11 thief splitting.
