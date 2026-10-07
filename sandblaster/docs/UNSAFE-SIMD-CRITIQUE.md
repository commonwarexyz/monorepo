# Adversarial soundness critique of DESIGN-UNSAFE-SIMD.md

*2026-10-06. Read-only review of `docs/DESIGN-UNSAFE-SIMD.md` (then
outside the repository, `recovery/unsafe-simd/`) against the four engines'
sources, the survey's extracted MIR
(`recovery/prover-simd/mir-survey/*.sbmir.gz`), the current lift
(`sandblaster/front/src/mir`, `sandblaster/mirx`, `sandblaster/front/src/lift.rs`),
the pinned stdarch at `nightly-2026-06-21`, and the target models. No
cargo build was run; the `mono-wt` worktree was not touched.*

The goal was one thing: find a program in the admitted subset where the
literal reading **L gives a value while the real program has undefined
behaviour or a different value**, and find every place the design trusts
more than it admits. Two findings are critical (S1, S2), four are high
(S3–S6), the rest are medium or confirmations. Each ends with a fix:
refuse the construct, add an obligation, narrow the subset, or pin a tool
setting. The accepted fixes are copied into DESIGN-UNSAFE-SIMD.md's new
"Amendments" section, and its "Implementation record" says how each was
carried out.

The design is careful and mostly errs toward refusal. The value-level
reading (byte views, bounds, formation, offsets, loads, stores) is sound
*given* two things it leans on: that the extracted MIR faithfully
reflects the source's aliasing structure, and that the recorded static
feature set is the build's. Both of those are where it is thinnest, and
both are below.

---------------------------------------------------------------------------

## Part A. What holds up (checked, sound as written)

So the reviewer knows these were examined and are not the problem:

* **Bounds are stricter than Rust, in the safe direction.** `add` stuck
  unless `off' ≤ size`, a load stuck unless `off + n ≤ size`, with the
  base being the reference's referent, not the allocation. For a pointer
  formed from `&mut base`, Stacked/Tree Borrows already confine accesses
  to `base`'s range, so L's base-restriction is exactly right for a
  dereference and conservative for a bare `add`. L is stuck in some
  defined programs and never gives a value in an undefined access. Good.
* **Store through a pointer derived from a shared reference** is `Stuck`
  (`PShr` store) and also reported statically (W4). Correct: it is UB in
  Rust even after `cast_mut()`.
* **Provenance across allocations and integer-to-pointer casts.** Within
  the subset there is no way to make a pointer formed from base A reach
  base B: int↔ptr casts are refused (§1.10), `offset` past the base is
  stuck, escapes are refused (W1). Every `PMut`/`PShr` reads only its own
  base's bytes. So L never reads B, and the subset cannot express the UB
  that would be needed to reach it. Sound, *conditional on the refusals
  being airtight* (S6, S7).
* **Out-of-bounds-but-never-dereferenced pointers** are made `Stuck` by
  the `add` rule even though Rust allows them within the allocation. Safe
  direction (refuses a legal program), not a soundness hole.
* **The loads and stores really are unaligned.** I read the pinned
  stdarch. `vld1q_u8`/`vst1q_u8` are `read_unaligned`/`write_unaligned`
  (aarch64 `generated.rs`); `_mm_loadu_si128` is `copy_nonoverlapping` of
  16 bytes and `_mm_storeu_si128` is `write_unaligned` (`sse2.rs`);
  `_mm256_loadu_si256` is `copy_nonoverlapping` of 32 bytes,
  `_mm256_storeu_si256` is `write_unaligned` (`avx.rs`);
  `_mm512_loadu_si512`/`_mm512_storeu_si512` are
  `read_unaligned`/`write_unaligned` (`avx512f.rs`). So "no alignment
  obligations today" is true at this nightly. But it is a property of the
  *implementation*, not the contract — see S5.
* **Endianness and padding.** The admitted base types (`u8`..`u128`,
  vectors, arrays of them) have no padding and no niches, so every byte
  string of the right length is a valid value and a store cannot forge an
  invalid one. `Multiply128lutT` documents `to_ne_bytes`, which on the
  LE-only targets (A8) equals the design's `(v >> 8k) & 0xff`. Consistent.

---------------------------------------------------------------------------

## Part B. Critical and high findings

### S1 (critical). The window rule is checked on *optimized* MIR, but its soundness is argued over *source* aliasing, and the optimization level is unpinned and differs from the shipped build.

**The claim under attack.** §2.6: "Why this is exact … Under Stacked
Borrows the family's raw tag sits above the reborrow … Under Tree
Borrows raw pointers carry the reborrow's tag, and no foreign access
reaches it in the window." §2.7 (A3′) restates it as exactness for
"borrow-checked MIR of the subset." The whole aliasing argument is about
the reference-to-raw reborrow structure of the **source**.

**What the lift actually reads.** mirx takes `tcx.instance_mir(def)` =
rustc's **optimized** MIR (`mirx/src/main.rs` ~line 920;
`docs/mir-lift.md` §20.1 "optimized MIR, constants evaluated"; README
"rustc's optimized MIR"). The window rule's families, ancestors, windows
and the "mentions a local in `A(F)`" test (W2/W3) are computed on those
optimized MIR locals.

**Why this breaks.** rustc's MIR optimization pipeline runs inside
`optimized_mir` regardless of codegen opt-level. At the default the
extraction uses (`cargo check`, so mir-opt-level 1), `ReferencePropagation`,
`CopyProp`, `GVN`/CSE and `DeadStoreElimination` all run; `Inline` runs at
level ≥ 2. These rewrite exactly the reference-flow the ancestor analysis
keys on, and can delete the access the window rule needs to see:

* `ReferencePropagation` folds `_r = &mut base; … (*_r) …` into direct
  `base` accesses and deletes `_r`, removing an ancestor edge.
* `GVN` + `DeadStoreElimination` can elide a read of `chunk[0]` whose
  value is already in a register. The §2.6 canonical UB example — store
  through `p`, **read `chunk[0]`**, store through `p` again — is refused
  *because* the read of `chunk` sits in `p`'s window (W2). If the read is
  optimized away before the rule sees the MIR, W2 passes and L gives a
  value for a program that is UB under Tree Borrows. The window rule's
  entire job is to detect that UB; an optimization that removes the
  witnessing access defeats it.

This is the unsafe direction: L gives a value where the source has UB.
It bites whenever the source actually has a subtle Borrows violation
(the case the trusted rule exists to catch) and an optimization hides the
witness. The current engines are presumably UB-free, so it does not bite
them today, but the window rule is **trusted** and is meant as a general
guard for this and future SIMD (curve25519's AVX-512, later engines).

Worse, nothing pins `-Zmir-opt-level`. The *shipped* crate builds at
`release` (a different MIR pipeline than the extraction's `check`), so the
theorem is proved about one MIR image and a different one ships. Rust's
story that source-level UB-freedom holds at every opt level does **not**
rescue this, because the window rule establishes UB-freedom of the
*extracted image*, not of the source; an aliasing analysis run on
post-`ReferencePropagation` MIR is reasoning about the wrong object.

Risk 3 only addresses helper inlining of the *value* reading ("both read
the same"). It says nothing about the aliasing analysis seeing a faithful
access set. This is the single biggest gap.

**Fix (accepted).**
1. Pin `-Zmir-opt-level=0` for every pointer-bearing extraction, so the
   extracted MIR is the un-optimized image whose access set and
   reference-flow match the source. Record the level in the `.sbmir`
   `(mir-opt-level 0)` and refuse any other level at load, exactly as the
   target and overflow-checks are refused today. (Alternative, if level 0
   regresses the value reading: extract a *second*, un-optimized MIR
   solely for the window analysis, and require the two to name the same
   function and locals.)
2. Make the Miri cross-check under **both** aliasing models a **mandatory
   build gate over the actual engine functions**, not only the fixtures,
   and not only at step 13. Miri checks the source's abstract-machine UB
   directly, independent of the extracted MIR's shape, so it is the right
   backstop for a trusted static rule. Each aliasing twin must be required
   to be reported as UB by at least one model, or the gate fails.
3. Amend A3′ to state explicitly that it assumes the extracted MIR
   preserves the source's aliasing structure, with the opt-level pin named
   as the mitigation.

### S2 (critical). The union-as-struct parse bug is NOT gated by the unsafe-block refusal and already reaches the shipped extractions; the proposed fix also has an unmeasured blast radius.

**What the designer found** (open issue §1.11 item 1): `ir.rs` sets
`is_enum` from `(kind enum)` and reads every other ADT as a struct,
ignoring `(kind union)` and `(union-field ..)`. Reading a union field is a
type pun that needs `unsafe`; read as a struct field it is a wrong value.
Confirmed at `front/src/mir/ir.rs:587` (`d.is_enum = x.tail()[0].atom() ==
Some("enum")`), and mirx does emit a distinguishable `(kind union)` and
`(union-field f)` (`mirx/src/main.rs:809,1159`), so the fix is
implementable.

**Why it is worse than stated.** The designer says it is "harmless only
while the blanket unsafe refusal stands." That is not the reason it is
harmless, and the premise is wrong. The blanket refusal
(`lift.rs:2108`, `first_unsafe`) inspects only the **crate body's source
tokens**; it never sees library MIR. L follows library calls to depth 8
(`mirx` `MAX_DEPTH`), and a union field read inside a *followed library
function* carries no `unsafe` token into the crate body. So a crate
function with no `unsafe` of its own can already reach a union misread
through library MIR, today, before any part of this design lands.

I checked the shipped extractions. `(kind union)` already appears in
**`storage/sandblaster/mmr/mmr.sbmir`** (1:
`std::sync::lazy_lock::Data`) and **`storage/sandblaster/verifier/verifier.sbmir`**
(2: `MaybeUninit`, `lazy_lock::Data`). The reason nothing is mis-valued
*today* is narrower and more fragile than "unsafe is refused": there is
no `union-field` read modeled to a value in those files (the field-reading
paths are unfollowed or refused for other reasons, e.g. raw pointers).
That is an accident of which paths are followed, not a guarantee.

**The fix's blast radius.** "Refuse `(kind union)` in the parse" refuses
the *type*, hence any function whose MIR reaches it. Since
`LazyLock::Data` already appears in both current locks, a blanket type
refusal may turn currently-green MMR/verifier functions red. That is
sound (those functions were relying on the union being parsed as a
struct), but it is not the cheap, local change the design implies.

**Fix (accepted).**
1. Treat this as a latent soundness bug in the **current** lift, fixed
   immediately and independently of the SIMD work, with a negative twin
   (a crate fn that reads a union field via a followed library fn, with no
   `unsafe` of its own, must be refused).
2. Prefer the **surgical** refusal: reject a `Field`/`SetDiscriminant`
   access to a union-typed place and a `(union-field ..)` aggregate, which
   are the operations that actually pun. If only the type-level refusal is
   practical, measure its effect on the accepted MMR and verifier locks
   first; any union type that is *reached but never field-accessed* and
   must stay admitted goes on an explicit, reviewed allow-list (itself a
   trusted surface), never silently parsed as a struct.
3. Re-scan every checked-in `.sbmir` for `(kind union)`/`(union-field ..)`
   as a standing lint.

### S3 (high). The feature-availability guarantee rests on the recorded static feature set being the build's, which `CARGO_CFG_TARGET_FEATURE` does not fully capture and the extraction does not bind.

**The claim under attack.** §4.2: static features are "recorded by mirx
and checked against `CARGO_CFG_TARGET_FEATURE`," and "cpufeatures folds a
statically enabled feature to `true`," which L reads as a constant. §4.5:
"On aarch64 NEON is static … so the NEON engine has no feature
obligations." The soundness of "this intrinsic runs on a CPU that has its
feature" for the *static* case is only as good as "the recorded static
set = the set the shipping binary is built with."

**Two holes.**
1. `CARGO_CFG_TARGET_FEATURE` is derived from the target spec plus
   `-C target-feature`. It does **not** reliably include the features
   implied by `-C target-cpu=native` or `-C target-cpu=<model>` — a
   long-standing rustc/cargo gap. A build with `target-cpu=native` can
   enable features the recorded set omits. Then (a) a `cpu_features::X()`
   that the extraction kept as a runtime detection folds to a constant in
   the real build, so the extracted MIR — and its theorem — is about a
   *different program* than ships; and (b) the only cross-check that would
   catch it, conformance, is "a test, not a proof," so a cold-path
   divergence can ship with a green theorem.
2. The extraction is a **separate** `cargo check` run by `mirx` under the
   pinned nightly, with its own `--target` and whatever `RUSTFLAGS` it
   inherits. Nothing binds its `-C target-feature`/`-C target-cpu` to the
   verifying build's. The design assumes they match and gives no mechanism
   enforcing it. (mirx today records per-function `(target-features ..)`
   from `codegen_fn_attrs` and the `(target ..)` triple, but not a static
   target-feature set at all — §4.2's record is new work.)

Risk 8 says "the static record is checked against the build" but never
engages with `target-cpu`, so the design trusts this more than it says.

**Fix (accepted).**
1. The static-feature record must come from the **same** flags as the
   verifying build. The load check refuses unless it can show
   `CARGO_CFG_TARGET_FEATURE` is the *complete* static set: refuse when
   `-C target-cpu` is anything but the target's default/`generic` (or
   require the build to pass an explicit, reviewed feature allow-list that
   the record is checked against), and record and compare
   `-C target-cpu`/`-C target-feature` themselves, not only the derived
   feature list.
2. State, as a named addition to §1.1 item 7 and risk 8, the trusted
   assumption that the extraction and the shipping build share the target
   and its feature configuration; until the binding in (1) exists, mark
   "static features count" as trusted-more-than-stated.

### S4 (high). The mutable-iterator models (`IterMut`, `Zip` of `IterMut`s) are trusted TCB with the same force as the window rule, but are filed as incidental "prerequisites."

§1.9 lists "the `IterMut` model … a model leaf in both readings, like
`slice::Iter`" and "`Zip` of `IterMut`s" as reader/model gaps, counted
separately and treated as routine. They are not routine, and the analogy
to `slice::Iter` understates them:

* `slice::Iter` (shared) yields **snapshots**; its soundness is just "a
  shared reference is a snapshot."
* `IterMut` must yield **element codes** (`PMut` rooted at the slice with
  a `PIndex(i)` step) and write them back. The soundness of every loop
  that drives it — `mul_neon`, `fft_butterfly_partial`,
  `formal_derivative`'s leaf — rests on a property the window rule does
  **not** supply: that successive `next()` calls yield **disjoint,
  non-overlapping** element codes, so two live `&mut` elements never
  alias. `IterMut` gets this from raw-pointer bookkeeping the design reads
  as a trusted leaf (not by following its MIR). A wrong `IterMut` model is
  a direct way for L to give a value where Rust has aliasing UB, exactly
  the failure mode the window rule exists to prevent — but outside its
  scope.

`mul_neon`'s whole loop, and `fftb_128`'s caller zipping `x.iter_mut()`
with `y.iter_mut()`, depend on this. The AVX-512 fused butterfly nests
`Zip` three deep.

**Fix (accepted).** Promote the mutable-iterator models to first-class
trusted lift surface (TCB item 8), each with: its own conformance test
against rustc; a stated disjointness property (distinct live `next()`
results are non-overlapping codes) that the write-back composition
relies on; and a negative twin (an iterator model that yields overlapping
codes must break a theorem). Count them in the trusted delta, not as
"not counted here" prerequisites.

### S5 (high). "No alignment obligations" is baked into the trusted load/store table as a constant, but it is a property of the pinned stdarch *implementation* that a toolchain bump can flip silently.

§1.5's table has an "alignment rustc requires" column reading "none" for
every intrinsic, and §2.4's load/store rules carry no alignment check.
That is correct **at nightly-2026-06-21** (Part A), but it is encoded as a
fixed fact in trusted code. If a future stdarch implements, say,
`_mm512_loadu_si512` via a path with an alignment precondition, or a later
target adds an intrinsic to the table, the blanket "none" becomes an
unchecked false assumption and a misaligned access reads as a value.

**Fix (accepted).** Make alignment a per-intrinsic field of the trusted
table, set from the intrinsic's documented contract, and keep §2.5's
alignment-obligation machinery wired in even though every current entry
discharges it with `a = 1`. Tie the "unaligned" fact to the model's
validation evidence (already re-checked at every toolchain bump), so that
a stdarch change that alters the memory contract forces re-validation
rather than passing silently.

### S6 (high / confirm-and-enforce). The admitted base types must be *enforced* free of `UnsafeCell` and niches; the niche-free property is also what makes a panic mid-sequence unwind-safe, and the design never says so.

Two sub-points the design relies on without stating:

* **`UnsafeCell`.** `PShr` is a snapshot taken at formation; it is only
  equal to memory at the use if nothing writes the base in the window
  (W3) **and** the base holds no interior mutability. The admitted base
  types (§1.2) are plain, so this holds — but the parse must *enforce*
  that a base type transitively contains no `UnsafeCell`, not merely that
  it is one of the listed names, or a future widening of the type list
  (structs) silently breaks the snapshot model.
* **Niches and unwinding.** The task asks about panics inside `unsafe`.
  In `fft_private` a safe `self.skew[..]` index can panic **between** a
  load and a store, leaving the `&mut` referent partially written. This is
  UB-free only because the admitted base types have **no niches**, so a
  partially-updated byte array is always a valid value; unwinding then
  carries a valid (if partial) `&mut` out. The design uses "no niches" for
  the byte-view round trip but never connects it to unwind safety, so a
  later base type with a niche would be accepted by the byte-view
  reasoning while breaking unwind safety.

**Fix (accepted).** State both properties as explicit admission
conditions on base and pointee types — transitively `UnsafeCell`-free and
niche-free — checked in the trusted parse, and name niche-freedom as the
reason mid-sequence panics are unwind-safe (§2.5 / the memory-safety
statement).

---------------------------------------------------------------------------

## Part C. Trusts-more-than-it-says (medium)

### S7. The "refuse crate → library `unsafe fn`" fix (designer's §1.11 item 3) has carve-outs that are themselves unsafe pointer functions; the allow-list is load-bearing and must be exact.

The fix refuses a crate call into a library `unsafe fn` "outside the
admitted list." But the admitted pointer operations include
`<*const T>::add`, `<*mut T>::add`, `sub` and `offset`, which **are**
`unsafe fn`s. So the allow-list is not an afterthought: it is the set of
unsafe library functions the whole subset is built on, and the entire
memory-safety argument rests on L modelling each of those exactly. A
same-named but different `add` (a crate's own, or a differently-behaved
library item) must not match.

**Fix (accepted).** The allow-list is matched by **exact def-path plus
signature**, never by last segment; it is enumerated in the trusted gate
and printed on the record; each entry has a negative twin (a same-named
non-pointer `add`, a library `unsafe fn` just off the list) that must be
refused. Generalize the rule's intent: the proxy being used is "the
callee has a safety precondition L does not check," and `unsafe fn` is
that proxy — so any future library leaf that is *safe* but carries an
unchecked validity precondition (niche constructors via
`transmute_unchecked`, which L already makes stuck) must be re-confirmed
stuck, not accidentally modeled.

### S8. Aliased `&mut` parameters are still only caught by assumption A3, not by the window rule — and this design leans on A3 harder.

`fftb_128(x, y)` is sound only because callers never pass aliasing
`&mut`s; the window rule does **not** help here (`y ∉ A(x)` and vice
versa, so W2 passes even though two aliasing `PMut` families to one base
would be UB). This is the existing A3/state-passing assumption, so it is
not new — but the pointer design multiplies the number of `&mut`-derived
raw accesses that depend on it, and the memory-safety record should say so
rather than imply the window rule covers inter-parameter aliasing.

**Fix (accepted).** The per-function memory-safety statement (§5.3) names
the A3 non-aliasing precondition of each `&mut` parameter as an explicit
host obligation wherever a raw pointer is formed from it, so the reviewer
sees that inter-parameter disjointness is assumed, not proven.

### S9. The validated model is the real SIMD instruction, but the pinned stdarch *implements* these loads/stores as byte copies; the design should record that the two agree only because the memory semantics is plain reinterpretation.

§1.5 says each row "names a validated model that already exists," i.e. the
transcription of the hardware load/store. But at this nightly the stdarch
*implementation* is `read_unaligned`/`copy_nonoverlapping`, not the SIMD
instruction. L reads the call as "the model applied to the bytes," which
matches only because both the byte copy and the real instruction produce
"the N bytes at the address, reinterpreted as the vector." That is true
for these plain integer loads/stores, but it is an unstated premise: a
future intrinsic whose model has non-trivial memory semantics (a masked or
broadcasting load) would make the byte-copy equivalence false.

**Fix (accepted).** Record in §1.5 that an admitted load/store model must
be pure byte reinterpretation of its `n` bytes (no masking, broadcast,
gather or conversion), and that this is what lets L equate the validated
instruction model with the byte-level `mem::read`/`mem::write`. The
already-refused masked/gather/broadcast forms (§1.10) are the boundary.

---------------------------------------------------------------------------

## Part D. Process

* **Order the independent review and the Miri gate *before* first trust,
  not at step 13.** The window rule and L's pointer constructs are
  trusted the moment the blanket refusal is lifted; a bug admits UB as a
  value. The design puts the independent review last (§7 step 13) "once
  the artifact has its shape." For a trusted change this is backwards:
  the Miri cross-check over the real engine functions (S1 fix 2) must be
  a build gate from step 3, and the human review of `window.rs` and L's
  pointer arms must land with them, not after all four engines.
* **Re-extract and re-run the Miri gate at every toolchain bump**, since
  S1, S5 and S9 all depend on the pinned MIR shape and the pinned stdarch
  implementation.

---------------------------------------------------------------------------

## Summary of accepted fixes

| # | severity | fix |
| --- | --- | --- |
| S1 | critical | Pin `-Zmir-opt-level=0` for pointer extractions, record and refuse otherwise; make the two-model Miri cross-check a mandatory gate over the real engine functions; amend A3′ to assume the extracted MIR preserves source aliasing, with the pin as mitigation |
| S2 | critical | Fix the union parse now, independently (latent today via followed library MIR; `LazyLock::Data`/`MaybeUninit` already in shipped `.sbmir`); prefer refusing union field access over refusing the type; measure the blast radius on current locks; allow-list any reached-but-unread union explicitly |
| S3 | high | Bind the recorded static feature set to the build's flags; refuse non-default `-C target-cpu` or require an explicit feature allow-list; record `target-cpu`/`target-feature`; name the shared-configuration assumption in §1.1 item 7 / risk 8 |
| S4 | high | Promote `IterMut`/`Zip` models to trusted TCB with conformance, a stated disjointness property, and a negative twin; count them in the trusted delta |
| S5 | high | Make alignment a per-intrinsic field of the trusted table from each intrinsic's contract; keep §2.5's alignment machinery wired; tie the unaligned fact to model validation so a toolchain bump re-checks it |
| S6 | high | Enforce admitted base/pointee types transitively `UnsafeCell`-free and niche-free in the parse; name niche-freedom as the reason mid-sequence panics are unwind-safe |
| S7 | medium | Match the library-`unsafe fn` allow-list by exact def-path + signature; enumerate it in the gate and record; negative twins for same-named and just-off-list callees |
| S8 | medium | Name each `&mut` parameter's A3 non-aliasing precondition as a host obligation in the per-function memory-safety statement |
| S9 | medium | Require an admitted load/store model to be pure byte reinterpretation; record it as the reason the instruction model equals the byte-level read/write |
| — | process | Move the Miri gate and the independent review of `window.rs`/L's pointer arms to land *with* the reading (step 3), not step 13; re-run at every toolchain bump |

No change is needed to the core value model (byte views, bounds,
formation, offsets, loads, stores) beyond S5/S6/S9's enforcement of its
stated premises. The two critical findings are both about the reading's
*inputs* — the MIR image the aliasing rule trusts (S1) and the union
parse that already ships (S2) — not about the pointer arithmetic itself.
