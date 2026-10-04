# Checked structuring: taking the structurer out of the trusted base

Status: **accepted (option A, shallow) with the coordinator's amendments
(a)–(g) below; implemented (plan steps 1–9).** Stage "cs-literal" (plan steps 1–3) is
done: the production literal reading, its library, the statement generator,
the pre-commit records, the normative text (`docs/mir-lift.md` §20.4,
§20.5) and the per-construct tests. Stage "cs-walker" (plan step 4) is
done: the walker proves `Subtree::reconstruct_digest` (non-tail
self-recursion) end to end with every lifted function it calls, and a
caller of a loop (`UInt<u32>::read_cfg`). Stage "cs-integrate" (plan step
5 and the varint part of step 6) is done: the gate of amendment (e) runs in
every verified build, the theorems are cached per amendment (g), and every
one of codec's 63 lifted varint functions has its theorem kernel-checked in
the build. Stage "cs-storage" (the rest of step 6, and step 8) is done:
every lifted function of storage's MMR (69; no MMR function is rewritten)
and verifier set 1 (69) has its theorem, and the lifted round trip proves
the shipped code's theorem of every rewritten function (exercised on the
toy fixtures of `tests/lowered_use.rs` and `tests/lift_opt.rs`). The
stage logs below that predate the fairness audit (2026-10-02) count the
MMR at 76, with the 7 functions of the hand-written `opt.rs` alternatives
(since removed), and report `to_nearest_size` rewritten through one of
them: that was user code, never optimizer output (DESIGN.md principle 3). Stage "cs-assurance" (steps 7 and 9, the
review of the trusted generator, the final validation) is done: the
conformance check runs L against rustc, fault injection shows the theorems
catch a mutated construct of each kind and the two historical bugs, and
`read.rs` is demoted to untrusted in DESIGN.md §1.1 item 8, AUDIT.md §21.1
and `docs/mir-lift.md` §5, §6 and §20. Stage "tcb-gate" is done: the
gate's trusted part is one module, `mir/gate.rs` (125 code lines), that
checks what the kernel holds; planning, the walks, the verdict cache
(whose entries the kernel re-checks) and the reports left the trusted
count. Stage "tcb-literal" is done: L's generator is 1,217 code lines
(it was 1,474), and its text is byte-identical on every MIR instance of
the three modules and every fixture. Stage "tcb-checks" is done: two
assumptions of AUDIT.md §21.1 are now checks — the gate's trusted check
compares every module type a theorem's MIR reaches with the subset's
declaration (kernel field names are positional), and the elaborator
checks each precondition of a function read from MIR against the
elaboration of its declared contract's clause (the name rule of
`stmt.rs` is gone). Stage tcb-review is done: an independent review of the
trusted part closed three gaps, each with a test and its negative twin —
the gate checks that a listed function's MIR instance is that function
(the lift finds instances by unqualified lifted names), and that a
statement rests only on its own extraction's literal reading (L's names
restart with each extraction's reading); core's `Index::index` leaf is
recognized by its exact path — and ran the final validation; the trusted
part is ≈ 4.29k code lines (≈ 4.97k when this workflow began). Stage finish-A made the shipped
code's theorems the only check of a rewrite of a module read from MIR (§5.13; the structural
comparison refused correct code) and added L's slice leaves; the trusted part is ≈ 4.55k code
lines, with the stages since tcb-review counted (§7). After stage finish-A the verifier's set 1
was finished as well: its laws grew to 8, its lock was accepted (272 items, root `3e969a79…`), and
`storage/build.rs` now builds both in-place roots with `compile_lifted` (2,642 obligations, 69 of 69
theorems for the verifier); the pending-gates build is deleted (no root used it any more), so the stage logs' mentions
of the verifier's "development build" describe the tree of their day. The implementation log is the next
section; the design follows it, updated where the implementation differs. This note does not change
`SEMANTICS.md`.

## Amendments (binding)

* **(a)** L, one literal reading per MIR instance, is the only trusted
  reading of bodies. `run(fuel, block, Option(St))` is defined by measure
  recursion with kernel-checked decreases; `None` is a panic, undefined
  behaviour, running out of fuel or an unmodeled construct. `read.rs` is an
  untrusted proposer of S.
* **(b)** The theorem is `L::thm::f : Π x̄ (pre). Σ k. Π n (k ≤ len n).
  run n b0 (Some init(x̄)) = Some(erase(S_f x̄))`: total correctness,
  including the final `&mut` referents. Its preconditions come from the
  function's declared contract (skeleton and attachments), never from
  `read.rs`; an `S_f` precondition the contract does not state is an error.
* **(c)** No kernel changes. The pre-commit bodies and measures leave the
  thread-local side table. New prelude or library definitions count as
  trusted.
* **(d)** `ir.rs` and `sexp.rs` feed L and count as trusted. Trusted: L's
  generator, `literal.core`, the statement generator, `mir/mod.rs`'s names
  and load checks, `ir.rs`, `sexp.rs`, `mirx`, the lift glue. Untrusted:
  `cfg.rs`, `read.rs`, `simproof.rs`. Target for the generator: about 1.0k
  code lines, table-driven, each construct's reading local.
* **(e)** The gate: every verified build checks every lifted function's L
  theorem or fails; `sandblaster check` reports the missing ones (the
  pending-gates build that also reported them is deleted).
* **(f)** Conformance runs L against rustc; mutating one MIR construct must
  break a theorem; the two historical `read.rs` bugs, re-injected behind a
  test hook, must make theorems fail.
* **(g)** Theorems are cached in the verdict cache, keyed by the hashes of
  S and its callees, the MIR text, `literal.core` and the generator.

## Implementation log

### Stage cs-literal (plan steps 1–3), 2026-10-01

**Files** (code lines: the docs' convention, no blank lines, comments or
tests; counted with `proto-scripts/loc.py` of the prototype):

| file | role | trust | code lines |
| --- | --- | --- | --- |
| `front/src/mir/literal.rs` | the generator of L | trusted | 1,460 |
| `front/src/mir/literal.core` | L's library (base 106, leaves 35) | trusted | 141 |
| `front/src/mir/stmt.rs` | the statement: telescope, preconditions, `init`, `erase` | trusted | 163 |
| `front/src/mir/mod.rs` | + `kernel_adt`, `is_transparent`, `host_model_method`, `HostModels::enums`, `Current` | trusted (names) | 480 (was 430) |
| `front/src/mir/checked.rs` | driver: names-only elaboration, loading L, proving entries | untrusted | 384 |
| `front/src/mir/simproof.rs` | the walker (ported; its `StmtSpec` moved to `stmt.rs`) | untrusted | 1,711 |
| `front/src/lift.rs` | + `LiftFacts::mir_loaded`, `LiftFacts::mir_contracts` (declared contracts), host enum paths | lift glue | +40 |
| `front/src/elab/{mod,items,generated}.rs` | + `PreCommit`, `Output::pre_commit` | elaborator | +25 |
| `front/examples/cs_proto.rs` | thin debugging driver (`CS_THM`, `CS_FAULT`, `CS_DUMP`, `CS_FAULTS`, `CS_TRACE`) | — | — |
| `front/tests/literal.rs` | per-construct tests, negative twins, acceptance | — | — |

**Acceptance.**

* L is generated and kernel-checked (types and termination) for every MIR
  instance with a body: varint 168/168 (3,071 kernel items, 1.87 MB of core
  text, checked in 0.14 s), the MMR 128/128 (the 4 others have no MIR body:
  `(nobody)`), the verifier 116/116 (5 without a body). No instance is
  refused.
* The prototype's theorems prove on the ported code, with the same proof
  sizes: varint `Decoder::<u32>::new`, `feed`, the loop lemma of
  `read::<u32>` and `read::<u32>` (49,050 nodes, kernel 0.049 s); the MMR's
  `Position::cmp`, `partial_cmp`, the loop lemma of `PeakIterator::next` and
  `next` (139,826 nodes, 0.38 s); the verifier's `leaf_digest` and
  `node_digest` (32,440 nodes, 0.11 s).
* Fault injection (`CS_FAULT`): `feed` 7→6 and `read::<u32>` 128→64 both
  make their theorems fail.
* `tests/literal.rs`: 20 tests, 13 s in release.

**Constructs read as `None`** (besides panics, which are exactly their
meaning: varint 27 panic blocks, the MMR 33, the verifier 19):

* varint: none.
* the MMR (31) and the verifier (30): all in functions no lifted function
  of these modules calls — the host's codec impls of `Position`/`Location`
  (`commonware_codec::Error`, which these crates do not model, and
  `UInt<u64>`'s codec functions, which have no MIR body in these
  extractions), `std::fmt::Arguments::from_str` (raw pointers, panic
  messages).

**Refused**: nothing (a construct L does not model is `None`, recorded).

**Decisions and deviations.**

* *Pre-commit records (amendment (c)).* `DefRecord` crosses threads
  (`driver::Verification` is returned from the elaboration thread) and
  kernel terms (`Rc`) cannot. The pre-commit body and measure therefore sit
  next to the records, in `elab::Output::pre_commit` (keyed by the
  definition's global, filled by `add_definition`, threaded through the
  optimizer's generated mode), not in `DefRecord` itself. No thread-local
  table remains.
* *L is total.* Every instance is generated; a construct L does not model
  is read as `None` for its block and recorded (`LFn::faults`, naming the
  block, the statement or terminator and why). A local of an unmodeled type
  has the slot type `mir::Unmodeled`; every use of it is `None`.
* *Panics.* A block from which every path panics is `None` (recorded in
  `LFn::panics`, not as a fault).
* *`&str`.* A string constant (a panic message, `Option::expect`'s) is the
  token `mir::Str::str`; reading its contents is not modeled. This made
  `Family::location_to_position` and four other MMR functions readable.
* *Drop glue.* A drop with glue of an ADT value is nothing when the value's
  variant is marked `no-glue` (decided on the value), else `None`
  (`Option::ok_or` dropping a no-glue error).
* *Names.* Module types, host enums and host instances are named by
  `ModuleNames::kernel_adt` (trusted names, `mod.rs`); a host enum by where
  its model declares it (`crate::merkle::host::Bagging`, re-exported as
  `crate::merkle::Bagging`), only for an enum of the lifted crate under the
  module its crate path names (another crate's enum of the same name,
  `commonware_codec::Error` in storage, is not that model). Constructors are matched by variant name, a
  struct's one constructor to its one variant. Library types match their
  full `std`/`core` path. The environment is consulted only for the
  constructors' order.
* *Calls.* One protocol for every cell: the caller's code as an
  `Option` (`None`: an absent optional referent), the initial value read
  through it, the final value written back through it (a lost value is
  `None`). `Out` lists every cell, nested ones included. Codes a callee
  returns are translated back (`xout`); this and nested cells read
  `Option::as_deref_mut` and `DerefMut` of `&mut &mut T` (tested on their
  shape, `tests/literal.rs`; the verifier's `reconstruct_digest` theorem
  needs the walker's non-tail self-calls, a later step).
* *Closures* take their parameters spread from the tuple their callers
  pass; a shim with `spread-arg` keeps the tuple (MIR's two conventions).
* *Leaves* live in `literal.core` (`leaf::*`) and are emitted into a
  module's reading where called (they name the lift's models, which exist
  only once elaborated).
* *Structs in `erase`.* A struct with invariant proofs is erased as the
  mirror's constructor applied to S's own projections (as the prototype
  did; the walker relies on these very terms).
* *Successors.* L computes block successors itself (`cfg.rs` is untrusted).
* *Generator size.* 1,460 code lines against the target of about 1.0k.
  By part: the type map and text helpers ≈ 300 (not in the design's
  estimate), places and reference codes ≈ 300, calls with the cell
  protocol, nested cells and code translation ≈ 200, rvalues, operators,
  casts and their tables ≈ 270, terminators, dispatch, fuel, rank ≈ 180,
  emission of `St`, accessors, `Blk`, `run` ≈ 130, leaves ≈ 70. Each
  construct's reading is local and the operator, intrinsic, leaf and
  library-type readings are tables.

**Open for later stages.**

* Plan step 4 (walker hardening: non-tail self-calls for
  `reconstruct_digest`, fuel splits mid-walk, budgets) and step 5 (driver
  integration, the gate of amendment (e), the verdict-cache keys of (g)).
* Amendment (f): conformance of L against rustc; fault injection per
  construct; the two historical `read.rs` bugs behind a test hook. The
  per-construct tests already pin L's value on their shapes (`snap`: the
  value read before an in-place write; `through`, `push2`: two writes
  through returned and shared references both land).
* §20.3's trust list changes when the gate is in place (`docs/mir-lift.md`
  says so).

**Reproducing.** Build `cs_proto` and run it through the scripts kept in
the session scratch directory (`cs2/build.sh`, `cs2/thms.sh`, `cs2/all.sh`):
`cs_proto <root.rs> <items|-> [<mir key>..]` with `CS_THM` as in Appendix A.

### Stage cs-walker (plan step 4), 2026-10-01

Only untrusted code changed: the walker (`front/src/mir/simproof.rs`,
1,711 → 3,005 code lines, with the sharing pass and the proof profile),
its driver (`front/src/mir/checked.rs`, 384 → 523), the debugging driver
(`front/examples/cs_proto.rs`: `CS_SHOW`/`CS_SKEL`, `CS_PROFILE`,
`CS_FULL`, budgets, traces) and a new test file (`front/tests/walker.rs`).
The kernel, L (`literal.rs` 1,460, `literal.core` 141), the statement
(`stmt.rs` 163), `mir/mod.rs`, `ir.rs`, `sexp.rs` and `LAWS.rs` are
unchanged: the trusted count of stage cs-literal stands, and the trusted
theorem of every function is exactly §3's.

**What the walker does now** (§5 has the detail):

* *Non-tail self-calls* (§5.6). A measure-recursive `S_f` gets its function
  lemma by measure recursion with S's measure; the fuel need is
  `mult·μ(x̄)`, `mult` the number of self-call sites, and the premise is a
  hypothesis of the whole walk. At a `let` whose value holds a self-call
  the literal side is moved to the call (callee lemmas, a split of a
  parameter the literal side waits for, a fuel split mid-walk) and the
  induction hypothesis is applied there as a callee lemma, with the lemma's
  own decrease obligation derived by `linarith` from S's decrease proof
  (S's proof is about the parameters as the walk split them).
* *`Option<&mut T>` parameters* (§5.7). The function lemma (untrusted) also
  proves that S keeps such a referent present exactly when it was given
  (the presence conjunct); at a call it decides the presence of the
  result's component, which a `let` of it is split on (the impossible arm
  refuted).
* *Fuel-dependent callees* (§5.8). A callee whose lemma needs fuel (it
  calls a loop) adds its need to the caller's fuel shadow under the `let`
  that calls it (`let x = v; shadow(b, acc + W(v))`); its lemma applies at
  the terminals, from the premise, and its run is kept folded until then.
* *Refutation first* (§5.9). The newest path equation is checked against
  the others at every walk step (a constructor clash, a fact rewritten to
  another constructor); before every split of the literal side, the full
  search (clash, `linarith`, rewriting) runs. Rewriting reaches through
  S's dependent-match idioms with a bound path equation.
* *Sharing* (§5.10). S's body is hash-consed before the walk and every
  lemma before the kernel sees it: `reconstruct_digest`'s proof goes from
  2.02M distinct nodes to 25k, its kernel check from 1.94 s to 0.66 s.
* *Budget and diagnostics* (§5.11). Each walk has a deadline (300 s) and a
  step budget (2M); a failure names the function, the path of S's splits,
  `let`s, variable and fuel splits to the failing point, both sides (the
  literal side evaluated) and the path equations.

**Acceptance.**

* `Subtree::reconstruct_digest` is proven end to end in the kernel, after
  the theorems of the 15 lifted functions it calls: `Position::new`,
  `Location::new`, `Position::deref`, `Position::sub`, `Location::add`,
  `Location::cmp`, `Location::partial_cmp`, `Family::children`,
  `Subtree::leaf_end`, `is_before`, `is_outside`, `Subtree::children`,
  `Standard::hash`, `leaf_digest`, `node_digest`. Its library callees
  (`slice::get` and `copied`, `ok_or`, `Try::branch` and
  `FromResidual::from_residual` of the `?`s, `as_ref`, `as_deref_mut`)
  are unfolded in the literal side, its leaves (`Iterator::next` of the
  byte-string iterator, `Vec::push`) are their models. The walk: 8
  S-splits, 7 L-splits, 4 fuel splits, 4 applications of the induction
  hypothesis (two self-calls, each for both presences of the collected
  digests), 5 callee lemmas, 6 refutations, 8 literal etas.
* Every theorem of stage cs-literal still proves (numbers below).
* A changed constant of `reconstruct_digest`'s MIR (`*cursor += 1` read as
  `+= 2`) breaks its theorem; the failure names the function, the path to
  the tail (`is_outside = true / slice::get = Some / tail`) and both sides.
* `tests/walker.rs`: 4 tests (the chain, the fault, the budget, the
  fuel-dependent callee), 12 s in release; `tests/literal.rs`: 20 tests,
  14 s.

**Numbers** (release, Apple M-series, memguard at 6 GB, the host shared:
walk times vary by ±30%):

| set | theorems | walk | kernel | proof nodes (shared) | before sharing | design (§8) |
| --- | --- | --- | --- | --- | --- | --- |
| varint: `new`, `feed`, `read::<u32>` loop lemma, `read::<u32>` | 4 | 0.084 s | 0.042 s | 7,131 | 49,053 | 0.050 s, 49,050 |
| + `UInt<u32>::read_cfg` (a loop's caller) | 1 | 0.004 s | 0.005 s | 468 | — | — |
| MMR: `cmp`, `partial_cmp`, `next` loop lemma, `next` | 4 | 0.41 s | 0.29 s | 7,686 | 156,022 | 0.387 s, 139,826 |
| verifier: `leaf_digest`, `node_digest` | 2 | 0.066 s | 0.033 s | 1,525 | 31,585 | 0.124 s, 32,440 |
| verifier: `reconstruct_digest` | 1 | 3.3 s | 0.66 s | 25,433 | 2,020,051 | not attempted (estimate for the module: 2–5 s kernel) |
| verifier: its 15 callees | 15 | 0.29 s | 0.08 s | 10,361 | 167,899 | — |

`Subtree::children` alone shrinks from 117,687 nodes to 4,004 (kernel
0.10 s → 0.02 s). The MMR loop lemma's unshared size grew (135,502 →
152,406): it now takes 5 fuel splits where it took 3, the refutation
before each L-split closing arms at another point; shared it is 6,482.

**Decisions and deviations.**

* *The presence conjunct* is new (not in the design): without it the
  induction hypothesis cannot show that S's result keeps an optional
  referent present, which the literal side's write-back needs (it fails on
  a lost referent). It is part of the untrusted lemma only.
* *Fuel need of a recursive function* is `mult·μ` (the design said `μ`):
  each self-call consumes a unit, and a body with two self-calls on one
  path needs two units per level.
* *Splits of the literal side's own tests on parameters* (`collected`) are
  splits of the variable on both sides (`var_split`, with the context's
  proofs about it transported along the path equation, as eta now does
  too); a field-less struct is never split (it converts by eta).
* *Terminal splits abstract the structured value too* when it waits for
  the same test (a transparent callee's comparison); abstraction inside S's
  terms keeps proofs well-typed by repairing dependent-match idioms and
  unit constructors, and is checked (an ill-typed one is not made; a
  literal eta then abstracts only the literal side's own matches).
* *A callee lemma* is tried outermost first (a callee whose S body calls
  another pending callee), applied once per branch, and a callee whose run
  completes under evaluation is kept folded for it.
* *Injectivity repair*: a structured split the literal side did not make
  (`Some(value)` where L has `Some(seq::index ..)`) is closed from its
  path equation rewritten to the same constructor.

**Fixed on the way:** `repair_unit` did not repair the other arguments of a
constructor whose argument it repaired; a literal eta tried only its first
candidate; `eval_opaque` folds exactly the globals given, so a folded
evaluation must name S's opaque definitions too (else the recursive `S_rd`
unfolds without bound).

**Reproducing.** `cargo test --release -p sandblaster-front --test walker`
(and `--test literal`); or the debugging driver with the session scripts
(`cs3/ver.sh` for the verifier chain, `cs3/thms.sh` for stage cs-literal's
theorems, `cs3/varint.sh` with `read_cfg`), which set `CS_THM` as in
Appendix A plus the 16 entries of `tests/walker.rs`'s `verifier_chain`.

**Open for later stages.**

* Plan step 5: driver integration (the gate of amendment (e), the
  verdict-cache keys of (g)), entries computed from the lift (the loop
  helpers' header slots are still given by hand in `CS_THM`).
* Walk time: `reconstruct_digest`'s walk (3.3 s) is dominated by
  evaluation inside the syntactic abstraction of the refutation's
  rewriting and by the callee-lemma abstraction; a cache of evaluated facts
  per branch would cut it.
* Not supported yet: a recursive function with a loop (refused with a
  message), a fuel-dependent callee inside a recursive function (its lemma
  is not applied: the walk fails at the call, named). Mutual recursion is
  not read by L.

### Stage cs-integrate (plan step 5, varint part of step 6), 2026-10-01

**What the build does now.** `driver::gates::theorem_gate` runs in
`build_crate_emitting` after the six §15 gates, so in `compile_module`,
`compile_lifted`, crate mode and `sandblaster check`, and in the
pending-gates development build (reported there, not enforced). It calls
`mir::checked::prove_lifted` on the module's own elaboration: L is
generated and kernel-checked once per extraction, then every planned
theorem is walked and checked in dependency order (callees, a function's
loop lemmas, the function). A lifted function without a kernel-checked
theorem is an `error[mir-theorem]` diagnostic naming it and why, and the
module gets no verdict. The report's `gates.mir_theorems` lists every
theorem and loop lemma. The verdict cache (namespace `theorem`) keys each
theorem by the toolchain, the generator (`literal.rs`, `stmt.rs`, `mod.rs`,
`ir.rs`, `sexp.rs`, `literal.core`), the structured reading of the function
and of every definition it reaches (`Env::refs_closure`: callees and
helpers), the declared contract, the MIR text of the instance and of every
instance its literal reading runs, and the module's names. A hit is not
walked again unless a walk that misses needs its lemma.

**Planning** (`checked::plan`): the lifted functions come from the lift's
declared contracts (`LiftFacts::mir_contracts`); the loop helpers from the
reading's record (`LiftFacts::mir_helpers`: the header block and the
helper's parameters as MIR locals for a tail-recursive helper; for a
`while` loop, the elaborator's `<f>::loop#k` with the reading's names of
the locals). A function whose MIR is mutually recursive with another
lifted function's is reported missing (L does not read mutual recursion).

**`while` loops** (§5.12, new). The elaborator's `while` helper returns the
variables the loop assigns, and the function goes on after it, so its
lemma cannot end at the function's return. It is stated once per helper,
independent of the rest of the function, as a hand-over to a continuation:

```text
L::wlem::<f>_<H> : Π p̄ j̄ (n) (C : Option(Out))
    (hC : Π m (.hm : len n − μ(p̄) ≤ len m) k̄ c̄ (.ez : h p̄ = tuple(c̄)).
          Eq(run m X (Some σ_X(c̄, w̄)), C))
    (.hle : μ(p̄) ≤ len n). Eq(run n H (Some σ(p̄, j̄)), C)
```

`H` the header, `X` the loop's exit, `σ` the helper's parameters in their
slots (matched by the reading's names of the locals) and junk elsewhere,
`σ_X` the loop's variables taken from the result's components `c̄`, the
other parameters as they are, the slots the loop assigns from `k̄`, the
others unchanged. The proof is by measure recursion with the helper's
measure and its own decrease proofs; the walk splits the helper's body
with `eqS : h p̄ = S` in its goals. At an exit the literal side, stepped to
`X` with every run folded, is handed to `hC` at the current fuel with
`eqS`; a recursive call is the induction hypothesis with `hC` moved along
`eqS` (`eqS · ez'`). At the call `let loop = h(ā); rest` in the function,
the lemma is applied with `C` the goal's right side and a continuation
that walks `rest` from `X`: it moves the goal from `loop = h(ā)` to `loop
= tuple(c̄)` along `ez`, with the rest's fact about the loop (`h_loop`, an
irrelevant `let` proven from the helper's `ensures` at `ā`) a hypothesis
of that motive, so that both sides read the loop's results as fresh
variables (the kernel's array eta treats them alike).

**Walker fixes the rollout needed** (all in untrusted code):

* *Arithmetic refutation before repairs*: two values whose path chose arms
  that agree only arithmetically (`x < 2^15` against `x >> 15 == 0`) are
  refuted before a fact repair consumes the deciding fact (zigzag).
* *`min`/`max`* of symbolic words in S (`usize::max`): rewritten by the
  kernel's `max_def_le`/`max_def_gt` axioms at the comparison `linarith`
  decides, keeping the truth value under which the literal side's value
  matches, else split on the comparison (`size`).
* *Word repair by `linarith`* when the word normalizer cannot equate two
  words equal only on the path (`(16 − lz) / 7` against `1`).
* *Callee lemmas in call order*: the runs of the callees whose lemmas are
  still pending stay folded while one callee's lemma is applied, so a
  callee's run is not unfolded on another callee's literal value
  (`size(as_zigzag(v))`, `write(as_zigzag(v), buf)`).
* *Dependent idioms of the literal side*: a library function's `if c as .h`
  (an array bound, a checked sum) on a test the walker decides by a fact or
  splits on is requalified: the test abstracted, its equation's left side
  kept, its proof the fact (a transport over the test and its proof) or the
  split's equation.
* *Erased pairs*: the kernel's quoter reads a pair captured by a proof
  quoted by substitution back without its type (`Erased`); such pairs are
  completed (a slice or an array by its syntax, else from the components'
  types) and a proof holding one is replaced by a proof of its proposition
  (`refl`, `linarith`), so the walker's motives check.
* *Abstraction typed in proofs* when the relevant occurrences alone leave a
  proof about the value ill-typed (a bridge under an `if c(v) as .h`).
* *Array eta*: a list the literal side spelled out element by element
  under the kernel's array eta is matched by rewriting the structured
  side's array with `(λ (y : Array T N). refl(fst y)) a`, checked under the
  fresh variable.
* *Lift-prelude inlining* is limited to helpers that do not case on an
  argument of several constructors (`ord_le` is kept a call: inlined, its
  match scrutinized the caller's own split value inside S's idioms, which
  made the verifier's `is_before` ill-typed).
* `let x = (let y = v; b); c` is walked as `let y = v; let x = b; c`;
  `step_to` and the exit step through a literal side quoted with `let`s;
  the header's slots are quoted at their types.

**Trusted changes** (`literal.core`; the generator, `stmt.rs`, `mod.rs`,
`ir.rs`, `sexp.rs` and the kernel are unchanged):

* `mir::array_get` is the element through the prelude's `array::index`
  under the bound test (`if i < N as .c`), replacing the proof-free
  recursive `mir::nth` (removed): the kernel does not unfold a recursive
  call stuck on its index, so the old element read of every write through
  an index stopped the literal side. The meaning is the same: the `i`-th
  element below `N`, else `None`.
* `leaf::array_index_to_inclusive` (`&a[..=j]`) computes `j + 1` as the
  checked sum under its own test (`j + 1 ≤ usize::MAX`, true below `N`),
  the form S uses, instead of the wrapping sum: the same value.

**Acceptance.**

* `cargo test -p commonware-codec`: the varint build is `VERIFIED + LIFTED
  AS-IS (module mode)`: every §15 gate, `mir-theorems: 63 of 63 lifted
  function(s) read from MIR with a kernel-checked theorem, 4.9s`, lift
  conformance 22,070 inputs on 63 functions with 0 mismatches, SPEC.lock
  matching (116 items); 147 + 16 + 5 tests pass.
* The 63 theorems and 6 loop lemmas (`read__uN__loop0` and `write__uN::loop#0`
  at u16/u32/u64): walk 1.6 s, kernel 2.5 s, 89,867 proof nodes (shared).
* Negative twins (`tests/theorem_gate.rs`): with `lift::test_hook`'s wrong
  rules the gate fails and the module is not verified — `&a[..=j]` read as
  `&a[..j]` fails `write__u16/u32/u64` (and the functions that call them,
  not attempted), and only those; a signed `Shr` read as logical fails
  `SPrim__i16/i32/i64__as_zigzag`. A walk out of budget leaves its theorem
  missing, named.
* Cache: a second run takes all 63 theorems from the cache; a changed
  constant of `Decoder::<u16>::feed`'s MIR misses (and fails) for the
  functions whose literal reading runs it and still hits for the others.

**Numbers.** The ≈ 100 s baseline is `sandblaster check` of varint. The
gate adds 4.4–5.2 s cold (L 0.16 s, walks 1.6 s, kernel 2.5 s, the rest
planning, cache keys and loading) and 0.3 s cached (the keys and L), about
5 % and 0.3 %. The varint build in this session's run (shared host, the
codec suite compiling alongside) logged the gate at 4.9 s. Before the
eta and erased-pair fixes, `write::<uN>` walked in 16–18 s each; a profile
put 85 % in completing erased pairs, now linear and syntactic for slices
and arrays (0.3 s per `write`).

The other two modules, measured but not rolled out (plan step 6 for them
is later): the verifier 66 of 69 lifted functions (4.4 s), the MMR 67 of
76 (5.1 s); the pending-gates builds report the missing ones.

**Tests.** `tests/theorem_gate.rs` (5 tests, 80 s); `tests/walker.rs` (4)
and `tests/literal.rs` (20) still pass; clippy reports nothing in the
changed files.

**Decisions and deviations.**

* The `while` lemma is stated per helper with a continuation, not per call
  with the rest of the function inside it (tried first, abandoned): the
  rest's proofs (`h_loop`) are about the call's own arguments and do not
  survive a motive generic in the loop's result.
* The gate's bookkeeping in `checked.rs` (planning every recorded function,
  accepting a theorem only from `add_def` of `L::thm::<f>` with the
  statement of `stmt.rs`, or from the cache under the full key) is trusted
  plumbing (407 code lines with `theorem_gate` and the report); the rest of
  `checked.rs` (driving the walker, the loop lemmas) is untrusted.
* L's generator still sits at 1,460 code lines (no change this stage).

**Reproducing.** `cargo test --release -p sandblaster-front --test
theorem_gate`; or `cs_proto` with `CS_GATE=1` (every lifted function of
the root, in plan order; `CS_CACHE=<dir>` for the cache, `CS_DIFF` for the
first differing subterms at a tail mismatch, `CS_TRACE_ETA`,
`CS_TRACE_ERASED`, `CS_TRACE_S`, `CS_TRACE_ABS` for the new steps).

**Open for later stages.**

* Plan step 6 for the MMR (9 missing) and the verifier (3 missing).
* The `#[derive]`d impls (`Clone`, `PartialEq`, `Eq`: 21 of varint's 84 MIR
  roots) are generated by the lift, not read from MIR, so the gate does not
  cover them; their MIR could be checked against the generated S the same
  way.
* Amendment (f): conformance of L against rustc, fault injection per
  construct (the varint twins above use the two existing read.rs hooks; the
  two historical read.rs bugs still need their hooks).
* Nested `while` loops are not supported yet, and a `while` loop whose
  rest needs fuel is untested (the shadow adds the rest's need after the
  loop's `μ + 1`).

### Stage cs-storage (rest of plan step 6, step 8), 2026-10-01

**Result.** Every lifted exec function of storage's MMR (76 at this
stage, counting the 7 functions of the hand-written `#[rewrite]`
alternatives of `opt.rs`; **69 now**: those alternatives were user code,
not optimizer output, and are removed, so no MMR function is rewritten)
and of the verifier's first set (69) has its theorem `L::thm::<f>`
kernel-checked in the build, and varint's 63 still do. `sandblaster check` reports `gate mir-theorems: passed` on both
storage roots (the MMR's only §15 finding is its unaccepted lock, the
verifier's are its examples, sections and lock, as before this stage). Step
8 is in: the lifted round trip proves the **shipped code's theorem** of
every rewritten function (§5.13): the MIR rustc compiles for a rewritten
function (the copy delegating to its lowered replacement and helpers)
returns, at sufficient fuel, exactly the source function's structured
value, by the copy's theorem against the replacement and the link
(`rewrite_equiv` for a user alternative, `..::equiv` or conversion for an
optimizer residual). It is exercised on the toy fixtures:
`tests/lowered_use.rs` (`at_most_one_bit` through its user alternative
`at_most_one_bit_fast`, 3 theorems, and the `ShippedMir` negative twin) and
`tests/lift_opt.rs` (optimizer residuals and per-type dispatch instances).
At this stage it also ran on the MMR's `PeakIterator::to_nearest_size`
through the hand-written alternative `opt::to_nearest_size_fast`; that
alternative is removed, and the MMR has no rewritten function.

**Why the counts were lower.** The real build had 8 MMR functions and 1
verifier function without a theorem; `cs_proto`'s gate mode reported 9 and
3, because it elaborated without the prover's bridges (`WORDS.rs`) and so
read `location_to_position` as a stub of an unproven obligation. The gate
mode now elaborates `^words::`, `^stdlib::`, `^sha256::` as the build does
and matches the build exactly.

**Fixes, by function** (trust in brackets):

| function | gap | fix |
| --- | --- | --- |
| verifier `Subtree::is_inside` | the refutation's rewriting of a fact through an idiom whose scrutinee *holds* the test (`Location::cmp`'s match inside `ge`) left the idiom's proof about the old scrutinee: a kernel `TypeMismatch` | `replace_proofs_gen`: an idiom on a term `s(y)` gets the proof of `Eq(D, lhs, s(y))` by a transport of the path equation whose motive is generic in the proof, from the idiom's own proof at `w = x`; a checked primitive whose operands hold `y` gets its obligation proofs transported the same way [untrusted] |
| MMR `Family::position_to_location` | the closure `f` of `let f = \|n\| ..` is a ZST that MIR never assigns (`RemoveZsts`); L read `&_29` from an empty slot as `None` | a read of a place of a data-free type (`()`, a closure without captures, a function item) is its one value [trusted: `literal.rs`, +5 lines; `tests/literal.rs` with its negative twin] |
| MMR `parent_heights`, `chunk_peaks` | S models core's `RangeInclusive<u32>` and `Once<T>` by the prelude's `RangeInclusiveU32` and `Once { v }`, L reads core's own structs: the statement's two sides had different types | `erase` builds L's value from S's projections, each at the MIR field path it models (`stmt::MODELS`, `Once`'s `v` at `inner.inner.opt`) [trusted: `stmt.rs`; `tests/literal.rs`] |
| MMR `PeakIterator::to_nearest_size` (and `Family::to_nearest_size`) | S's `mid = div_ceil(..)` is the prelude's model, inlined only in evaluation; L runs core's `div_ceil` MIR. S's facts about `mid` (the obligation of `2 * mid`, of `- mid.count_ones()`) never decided L's tests | (1) the prelude's `uN::div_ceil` transcribes core's test (`if r > 0 { d + 1 } else { d }`, it was `r == 0` with the arms swapped) [trusted prelude, same meaning; codec's lock still matches]; (2) **model lemmas** (`Entry::Model`, untrusted): core's `div_ceil` MIR against the model, proven once, applied as a callee lemma so both sides hold the model's call; (3) the blocker chain reaches the outer test past a stuck inner one, so a fact decides `2 * mid ≤ MAX` while `mid`'s own test stays stuck [untrusted] |
| MMR `Family::is_valid_size` (and `Position::is_valid_size`) | the loop lemma's fuel arithmetic failed: the decrease fact's evaluated form is a `let` (the quoter's sharing), which `linarith_fuel` skipped as "not a comparison" | sharing `let`s around a comparison are peeled before the check [untrusted] |

Further walker changes made on the way (untrusted): facts rewritten by a
literal split, syntactically (`rewrite_facts_by_last`: the `let`s and
transparent calls unfolded from the terms, the test abstracted, proofs
transported, iota and beta; no round trip through evaluation, which would
drop the transports and change `linarith` statements); `abs_syn` reaches a
`let`'s value; a bridge applies only while its wrapping operation stays one
after evaluation (`(d + 1) - 1` evaluates to `d`, which every `d` would
match: a memory blow-up); `CS_CHECK` checks every refutation; debugging
traces (`CS_TRACE_FACT`, `CS_TRACE_ARITH`, `CS_FIND_BAD`, `CS_ONLY`, ..).
Two dead ends were removed: rewriting S's facts by evaluation (it
produced checked primitives whose proofs were about the old operands) and
"aligning" the literal side to S's stuck match (the kernel's abstraction
reaches into proofs at neutral heads).

**Step 8, the lowered round trip** (§5.13, `docs/mir-lift.md` §20.7). In
`driver::lowered::round_trip`, after the comparisons pass, for a module read
from MIR: `mir::checked::prove_roundtrip` reads L for the copy's new
instances, continuing the gate's reading of the module (kept in
`elab::Output::mir_gate`; an instance both extractions hold must be the
same MIR in both); each helper gets `L::thm::<id>` against the definition
the round trip compared it with (its declared contract), the copy
`L::thm::<id>` against the replacement with the replacement's *call* as its
structured side (the delegation the round trip checked), and
`Prover::compose` gives `L::shipped::<id>`: §20.5's statement of the copy's
instance against the source function, under the source function's
contract, by a transport along `rewrite_equiv` (preconditions promoted with
`eq::promote` where the link binds them as relevant). A function without
its shipped theorem keeps its source text. The gate keeps the lemmas the
copies need even when cached (`GateOptions::keep_keys`). (At this stage
the MMR's `to_nearest_size`, through the since-removed user alternative
`to_nearest_size_fast`, had 8 theorems; the MMR now has no rewritten
function, and `tests/lowered_use.rs`'s toy alternative has 3.) The same runs for an optimizer residual (its
link `..::equiv : Π x̄. Eq(R, g x̄, f x̄)` read in either direction, or
conversion; the source function's contract when the residual has none) and
for a function lowered through a per-type dispatch (per verified instance:
the helper, the dispatch impl method, the copy at the instance type, the
shipped theorem; `tests/lift_opt.rs`). The theorems are cached like the
gate's (`roundtrip_key`), and a lowering without a preceding gate (the
stage tool `driver::stage::lower_lifted`) reads and proves the instances
the copy needs first (`GateOptions::restrict_keys`).
`tests/lowered_use.rs`: 3 theorems, and the negative twin
(`LowerFault::ShippedMir`: one constant of the helper's MIR changed in the
literal reading only) fails the theorem, the round trip rejects the
rewrite, and the build that compiles the copy fails.

**Trusted changes and counts** (code lines, `loc.py`):

| file | before | after | what |
| --- | --- | --- | --- |
| `mir/literal.rs` | 1,460 | 1,465 | data-free reads |
| `mir/stmt.rs` | 163 | 225 | `MODELS` and `build_model`; `model_statement` (the statement without a contract, for an untrusted lemma only) |
| `elab/lift.core` | — | same size | `uN::div_ceil` transcribed test for test |
| `mir/checked.rs` (bookkeeping) | ≈ 338 | ≈ 460 | model lemmas in the plan, `GateMemory`, `keep_keys`, `prove_roundtrip`'s acceptance and `compose`'s statement (the proofs are kernel-checked) |
| `driver/lowered.rs` | — | +70 | the round trip requires the shipped theorems |

`mir/checked.rs` is 1,612 code lines in all, `mir/simproof.rs` 4,565
(both untrusted but for the bookkeeping above).

**Numbers** (release; `sandblaster check`; shared host, ±30%):

| root | lifted | gate | check total | baseline | added |
| --- | --- | --- | --- | --- | --- |
| MMR | 76 of 76 then (+ 6 loop lemmas, 1 model lemma); 69 of 69 since the `opt.rs` alternatives were removed | 9.6 s cold | 244.6 s | ≈ 230 s | ≈ 4 % |
| verifier | 69 of 69 | 4.4 s cold | 9.7 s | ≈ 7 s | ≈ 60 % (`reconstruct_digest`'s walk, 3.5 s) |
| varint | 63 of 63 (+ 6, + `usize::div_ceil`) | 4.2 s cold | — | ≈ 100 s | ≈ 4 % |

The storage build (`compile_lifted_pending_gates`, debug profile of the
build script, two runs): MMR gate 14.0–21.8 s, the lowering with the round
trip and the shipped theorems 2.4–4.4 s; verifier gate 6.4–10.2 s. `cargo test -p
commonware-storage --lib -- merkle::mmr merkle::position merkle::location
merkle::proof merkle::hasher`: 129 passed; both roots build. (At this
stage `to_nearest_size` was rewritten to the hand-written alternative and
rustc compiled that lowered copy; since the alternative's removal no MMR
function is rewritten, and the lowered copy rustc compiles is
`mmr/iterator.rs` itself.)
`cargo test -p commonware-codec`: varint VERIFIED + LIFTED AS-IS, every §15
gate (lock matching), 147 + 16 + 5 tests.

**Tests.** `tests/theorem_gate.rs` +2 (the verifier's 69; the MMR's 76
then, 69 now, with the functions fixed here named, 136 s); `tests/literal.rs` +2 (data-free
reads with a negative twin; the core models' `erase` with a negative twin);
`tests/lowered_use.rs` +1 and one assertion (the shipped theorems; the
`ShippedMir` twin); `tests/lift_opt.rs` one assertion (the dispatch's
shipped theorems per instance).

**Reproducing.** `cargo test --release -p sandblaster-front --test
theorem_gate` (the storage tests), `--test lowered_use`, `--test lift_opt`;
`cargo build -p commonware-storage` (the reports' `mir-theorems` gate and
`lifted_optimizer[..].shipped_theorems`); `sandblaster check
storage/sandblaster/{mmr,verifier}/mod.rs`; `cs_proto` with `CS_GATE=1`
(and `CS_ONLY=<global>`). The session's scripts are in the scratch
directory's `cs6/` (`gate.sh m|v|c`, `one.sh`, `thm.sh`, `sbcheck.sh`,
`storage.sh`, `wide.sh`).

**Open.**

* The shipped theorems' verdict-cache path has no dedicated test (the
  key covers the generator, the structured readings, the link, the
  contracts and the round trip's MIR; a hit skips the proof).
* The verifier's gate costs ≈ 60 % of its small baseline; most of it is
  `reconstruct_digest`'s walk (cached after the first build).
* L's generator is 1,465 code lines against the ≈ 1.0k target.

### Stage cs-assurance (plan steps 7 and 9, review, validation), 2026-10-01

**Step 7a: conformance of L against rustc** (`front/src/conform/literal.rs`,
139 code lines, untrusted: a mitigation). The lift conformance check, in
module mode (`conform::check`) and in place (`conform::check_in_place`),
now runs the literal reading too. For each lifted function read from MIR,
on the first 64 inputs it compares S on (`conform::LITERAL_CASES`, in the
check's deterministic order), the kernel evaluates
`(λ x̄ n. L::<f>::run n b0 (Some init(x̄))) args 2^16` (the closed terms built
from `stmt::statement`'s own `init` and `erase`) and compares it, by the
kernel's conversion, with `Some(erase(r))`, `r` rustc's output read back at
S's result type. L is compared with rustc directly, not through S. The
literal reading is the gate's when it ran on the elaboration (`elab::Output::mir_gate`),
else generated and checked there (the stage tool `sandblaster conform`);
the conformance functions take the elaboration mutably for that
(`driver::stage::with_elaboration_mut`). Arguments with invariant fields
carry erased proofs, which `Env::eval_closed` refuses: those go through
the reference strategy, as S's evaluation does. A difference is a mismatch
("the literal reading of rustc's MIR gives ..") and fails the build. The
report and its cached record carry `literal_cases` per function and in
all; the cache key adds the generator hash, the MIR and the contracts
(`VERSION` is `/4`).

**Step 7b: fault injection** (`front/tests/fault_injection.rs`).

* *Per construct*: 19 mutations of the MIR L reads (S, read from the
  unchanged MIR, stays as it was), grouped into 7 batches whose targets are
  independent (the three instances of `Decoder::<U>::feed`, of
  `un_zigzag`, ..). Each breaks the theorem of the function that runs it,
  for its own reason (not "not attempted"), while `size__u32`,
  `UPrim__u16__as_u8` and `SPrim__i16__as_zigzag` still prove: an integer
  constant, a comparison, a bit operation, a checked operation, an
  assertion's expected value, a switch's targets, an aggregate's variant,
  a `&mut` borrow's place, a call's arguments, a statement, a `goto`, the
  return place (all in `feed`); a unary operator and a cast
  (`un_zigzag`); an unsigned shift (core's `<u32 as Shl<usize>>::shl`), a
  signed shift (`<&i64 as Shr<usize>>::shr`), an intrinsic (core's
  `u8::leading_zeros`: `ctlz` → `cttz`) and a discriminant's switch
  (`Option::<usize>::unwrap`), all in library MIR; a leaf call's argument
  (`write::<u32>`'s `put_u8`). Drops: varint's MIR has no drop terminator;
  `tests/literal.rs` covers them with negative twins.
* *The two historical structuring bugs*, re-injected into `read.rs` behind
  `lift::test_hook`:
  * `WritebackSnapshot` (the `!env.writeback.contains(k)` filter of
    `Reader::invalidate` dropped: a matched field's write-back is
    materialized from a copy before the field changes): the verifier's
    `Subtree::reconstruct_digest` gets no theorem, and only it (its
    structured reading still elaborates and its proofs pass — no law
    speaks of `collected`).
  * `SnapshotOwnValue` (the `own` filter of `invalidate` dropped: before a
    field or element of a variable is written in place, the variable's own
    entry is snapshotted, and later reads restore the old value): varint's
    `write::<uN>` (the element writes of `bytes`) gets no theorem, nor do
    its callers, and nothing else. Here the misreading also breaks S's own
    proofs (the loop helper `write__uN::loop#0` is rejected: 57 unproven
    obligations); the gate fails independently of them. The MMR and the
    verifier have no in-place write it changes: all their theorems hold
    under it (measured with `cs_proto`'s new `CS_HOOK`). Which of the two
    filters was the original bug 1 is not recorded; this is the reading
    whose loss restores a variable's pre-write value.
* *Amendment (b)*: `ExtraRequires` (the structured reading adds
  `requires(true)` to every private free function it reads) gets no
  theorem for `size__u64`, `read__u32`, `write__u16`, `size__u16`
  (`carries the precondition h_req0, which its declared contract ... does
  not state`), while `Decoder__u32::feed` keeps its theorem. To make the
  refusal structural, `lift.rs`'s `mir_body` now takes the signature only
  (`&mut syn::Signature`): the structured reading cannot touch the
  function's attributes, and the contract is taken from the skeleton's
  attributes before the body is read and the attachments' after (a hook's
  attribute in between is excluded).
* In the conformance tests: a misreading of L alone (`put_pair`'s `xor`
  read as `or` in the MIR L reads) is caught by the conformance check,
  with only literal-reading mismatches, and leaves no cache key.

**Step 4 (review of the trusted part against the MIR reference).** Read
construct by construct: `literal.rs`, `literal.core`, `stmt.rs`, `ir.rs`,
`sexp.rs` and `mod.rs`'s names, against rustc's MIR semantics (wrapping
`Add`/`Sub`/`Mul`; `Shl`/`Shr` masking the amount; `Div`/`Rem` and the
unchecked operations undefined on a zero divisor or overflow; casts;
discriminants; moves; drops; references and write-back; little-endian
transmute) and the kernel's primitive semantics (`#wshl` is `x << (y mod
w)`, `#cast` truncates or zero-extends, `ctlz(0)` and `cttz(0)` are the
width). Found and fixed, each with a test and a negative twin
(`tests/literal.rs`):

| finding | effect before | fix |
| --- | --- | --- |
| `int()` mapped every width other than 8–64 to 64 bits: `u128` read as `usize`, `i128` as `u64` | a `u128` value read truncated to 64 bits (a value where rustc differs; no extracted module has one, varint's `u128` instances are `unverified`) | `u128`/`i128` are not modeled (`mir::Unmodeled`, every use `None`) |
| `ShlUnchecked`/`ShrUnchecked` by an amount of another width tested only the amount's low 32 bits (`#cast_u64_u32`) | `x.unchecked_shl(2^32)` (undefined) read as `x << 0` | the amount is compared with the width at its own type first |
| a zero-sized ADT constant was read as variant 0 | for an enum with several variants (`Result<Infallible, ()>`'s `Err(())`) a type error at best, the wrong variant at worst | only a type with one variant |
| `ir.rs` defaulted a malformed variant discriminant to 0 and an assertion's malformed expected value to `false`, and did not check that variants and locals are listed in order (L indexes both by position) | a printer change or a malformed file would have been read as a different program | each is a parse error (`the_parse_refuses_what_it_would_have_guessed`) |

Recorded, not changed (in `docs/mir-lift.md` §20.4 and AUDIT.md §21.1):
`RuntimeChecks(ub)` is read as `false` (where a library precondition check
would fail, the guarded operation is undefined behaviour, which L reads as
`None` for every operation it models); a module type's fields are in
declaration order in both MIR and the subset's declaration (the kernel's
field names are positional, so this is the lift's, not checked); the
extraction must have overflow checks as the build does (A4); `TryGetError`
is read as the prelude's field-less struct (a construction or projection
of its fields would be a kernel type error, so the whole reading is
refused, never a value). No other reading was found to give a value where
rustc's semantics differ.

*Second review pass* (the stage was resumed after an interruption; the
trusted files were read again end to end: every reading of `literal.rs`,
`literal.core`, `stmt.rs`, the parse and `mod.rs`'s names, the call
protocol with nested cells and returned codes, `init`/`erase` and the
contract rule). One more finding, fixed with a test and its negative
twin (`readings_the_review_found_wrong_are_none_where_rust_differs`): a
library type of `LIB_ADTS` and the range of an index leaf were recognized
by a path *suffix*. `rd.path.ends_with("ops::RangeTo")` also matched a
crate's own `myops::RangeTo` (read as `&a[..j]` whatever its `Index`
impl means), and the bare form `option::Option` matched a crate named
`option`. Both now match the exact path under `std::`/`core::`
(`bytes::TryGetError` as written; `literal::lib_path`). Checked and found
right: the switch's bit masks and signed switch values (mirx prints the
discriminant's bits: `Ordering::Less` is `255`), discriminants from
`AdtDef` (not variant indices), the shift amount's truncation to `u32`
before `mod w` (exact, since every width divides `2^32`), signed shifts
and comparisons on the bits, sign extension only from signed types (also
to `usize` through `u64`), `Assert`'s expected value, drops (a value whose
variant has glue is `None`), moves, shared references as snapshots
(interior mutability needs raw pointers, which are `None`), the cell
protocol (aliasing excluded by the borrow checker; codes rooted at a
callee local are `None`; a parameter re-pointed by the callee leaves the
cell alone), closure argument spreading, and the root types that keep
codes of two frames from being confused (a mix-up is a kernel type
error). The precondition rule checks binder *names* (`h_req<k>` with `k`
below the contract's count, `h_depth`); the content is the contract's
because `read.rs` returns only a block and helpers (`mir_body` gives it
the signature, and only `lift.rs` marks parameters `mut`), so the
attributes the elaborator turns into `h_req<k>` are the skeleton's and
the attachments'. `RuntimeChecks(ub)` read as `false`: the extractions
have one such check (core's `u64::checked_shl`, guarding the language-UB
`unchecked_shl`, which L reads as `None` out of range); a library-UB
check guards operations L does not model.

**Step 9: demotion and accounting.** `read.rs`'s and `mod.rs`'s module
docs, `ir.rs`/`sexp.rs` (now trusted), DESIGN.md §1.1 item 8 (the bodies'
part rewritten: the literal reading, its counts, the theorem gate, S
untrusted; the mitigation paragraph adds L's conformance and fault
injection; the "not trusted" list names `read.rs`, `cfg.rs`, the walker),
AUDIT.md §21.1 (new: trusted files with counts, what an auditor checks
construct by construct, the review's findings, the recorded assumptions,
the tests that pin it), `docs/mir-lift.md` §3, §5 (numbers), §6 step 5
(done), §20.3, §20.4 (the review's readings), §20.5 (the contract is
structural), §20.8 (new: L's conformance and fault injection).

**Trusted lines** (code lines, `loc.py`):

| part | before (structurer trusted) | after |
| --- | --- | --- |
| structurer `read.rs` | 2,417 | 2,433, untrusted |
| L's generator `literal.rs` | — | 1,474 |
| `literal.core` (non-comment lines) | — | 139 |
| statement `stmt.rs` | — | 225 |
| names and load checks `mod.rs` | 434 | 480 |
| parse `ir.rs` + `sexp.rs` | 467 + 131, untrusted | 482 + 131, trusted |
| printer `mirx` | 1,131 | 1,131 |
| **subtotal** | **3,982** | **4,062** |
| gate's bookkeeping (`theorem_gate` and report ≈ 80, `checked.rs`'s planning, keys, acceptance, round-trip acceptance ≈ 500, `lowered.rs` ≈ 70) | — | ≈ 650 |
| lift glue (`#[lift(mir)]` path, contracts) | ≈ 200 | ≈ 260 |
| **total** | **≈ 4.2k** | **≈ 5.0k** (≈ 4.4k without the parse, as counted before) |

Untrusted now: `read.rs` 2,433, `cfg.rs` 235, `simproof.rs` 4,565,
`checked.rs` 1,707 (but its ≈ 500 of bookkeeping), `conform/literal.rs`
137. The generator stays above the ≈ 1.0k target (1,474; the reasons are
in stage cs-literal's log).

**Final validation** (2026-10-01, release, memguard 6 GB, shared host;
every theorem cold, since the generator's hash changed with the second
review's fix):

* `cargo check --tests` of the eight sandblaster crates: clean (two
  pre-existing `cfg(sandblaster)` warnings in `redteam_fidelity.rs`).
  Clippy reports nothing in the files this stage touched.
* Front suites, all passing: `mir` 38, `literal` 24, `lift` 18,
  `lift_open` 27, `lift_verifier` 24, `lift_conformance` 13 (1 ignored),
  `lift_opt` 9 (8 ignored), `theorem_gate` 7, `walker` 4,
  `fault_injection` 4 (111 s), `lowered_use` 11, `verdict_cache` 8,
  `mmr_toolchain` 12, `elab_pipeline` 6, `aug_int_toolchain` 11,
  `build_loop` 7, `module_mode` 10, `build_driver` 5; the front's unit
  tests 49; the kernel's tests (26 targets) all pass.
* `cargo test -p commonware-codec`: 147 + 16 + 5 passed; its build
  verified varint: 21,237 obligations, every §15 gate (spec mutants 763
  killed of 985), lift conformance (L compared with rustc too), the 63
  theorems, SPEC.lock matches (116 items).
* `cargo test -p commonware-storage --lib -- merkle::mmr merkle::position
  merkle::location merkle::proof merkle::hasher`: 129 passed; the
  development builds of the MMR (5,598 obligations) and the verifier
  (1,643) report their pending §15 findings as before.
* `sandblaster check`: the MMR, `gate mir-theorems: passed (76 of 76, 0
  from the cache, 9.4 s)`, 5,598 obligations, 10 laws, 230 s in all, the
  only error the missing SPEC.lock (as before this work); the verifier,
  `gate mir-theorems: passed (69 of 69, 4.4 s)`, 1,643 obligations, 5
  laws, 9.7 s, its errors the examples, sections and lock findings that
  predate this work (14 + 56 + 1).
* Extraction reproducibility: not re-run; the printer `mirx` and every
  `.sbmir` file are unchanged by the checked-structuring work.

**Open after this stage.**

* L's generator is 1,474 code lines against the ≈ 1.0k target (type map,
  text helpers, nested cells, code translation, signed operators, leaves).
* Assumptions the theorems do not check (AUDIT.md §21.1): rustc compiles
  the MIR `mirx` printed, with overflow checks; a module type's fields and
  variants are in the same order and named alike in the MIR and in the
  subset's declaration (kernel field names are positional); the host
  models and leaves (and `Deref` of a library byte newtype without MIR)
  mean the host functions; `RuntimeChecks(ub)` is `false`.
* The precondition rule matches binder names; its content argument is
  structural (the reader sees only the signature). An independent check
  that each `h_req<k>`'s type is the elaboration of the contract's k-th
  clause would make it local.
* Conformance compares L with rustc on the first 64 inputs per function
  that S's check generates (inputs satisfying the contract); inputs where
  rustc panics are compared through S only.
* The MMR and the verifier are still development builds: their
  pending §15 findings (MMR: lock; verifier: examples, sections, lock)
  predate this work.
* The shipped theorems' verdict-cache path has no dedicated test.
* The verifier's gate (4.4 s cold) is large against its 9.7 s check;
  cached after the first build.

### Stage tcb-gate (shrinking the trusted gate), 2026-10-01

**Goal.** The trusted count had not gone down (≈ 5.0k against ≈ 4.8k
before, on the same counting), largely because ≈ 650 lines of gate
bookkeeping were trusted: `gates.rs`'s `theorem_gate` and report (77),
about 500 lines of `checked.rs` (planning, the cache keys and outcome
records, accepting `L::thm::<f>` inside the prover, the gate memory, the
round trip's acceptance and `compose`'s statement) and `lowered.rs`'s
requirement of the shipped theorems (73). This stage makes the trusted
part one small module that checks what the kernel holds, and moves the
rest out of the trusted count. No meaning changed: the same statement,
the same theorems, the same functions required.

**The trusted check** (`front/src/mir/gate.rs`, **125 code lines**; its
doc header says what it trusts). `Ledger` is the record of the literal
readings loaded into one kernel environment:

* `Ledger::load` is the only way L enters the kernel: it runs the
  generator (continuing the module's reading when there is one), loads the
  text and its library with `load_core`, and records the range of globals
  and inductives it loaded, where the environment stood before the first
  load (the elaboration), and the MIR text of every instance it read.
* `Ledger::verdicts` gives, for every function the lift lists
  (`LiftFacts::mir_contracts`), `Ok` only when (1) the instance and every
  instance its reading runs were read from the MIR given; (2) the kernel
  holds `L::thm::<id>` whose type is α-equal, up to binder names and
  proofs (`Env::alpha_eq_relevant`, with globals compared by identity), to
  `stmt::statement`'s statement generated afresh and parsed; (3) every
  global the statement reaches (`Env::refs_closure`, not descending into
  the elaboration's globals) was defined by the elaboration or by a load,
  and no inductive was added since the first load except by a load. (3)
  is what keeps a declaration made by untrusted code — a walker's lemma, a
  replayed cache entry, or a redefinition under an existing name, which
  the kernel allows (the newest definition of a name wins) — from
  standing in for `S_f`, L or the prelude.
* `Ledger::accept_shipped` checks the round trip's `L::shipped::<id>` the
  same way: the copy's instance of the round trip's MIR against the source
  function under its declared contract.

**Call sites** (≈ 25 trusted lines outside `gate.rs`): `theorem_gate`
turns each refused verdict into `error[mir-theorem]` (11 lines; the walks'
reports only explain a refusal); `driver::lowered` names the shipped
copy's MIR instance per instance and fails a rewrite whose
`accept_shipped` fails (≈ 15).

**Untrusted now** (all of `checked.rs`, 1,674 code lines): planning, the
dependency order, the walks, the loop and model lemmas, the theorems'
construction (`prove_fn` still builds `L::thm::<id>` from `stmt.rs`'s
text, but a mistake there is refused), `compose`, the cache keys,
`GateMemory` (now the ledger, the callee lemmas per module and the
shipped notes), the reports (`annotate` folds the trusted verdicts into
them) and `theorems_json`.

**The verdict cache is no longer trusted.** An entry used to be a replayed
verdict (a hit was believed under its key). It now holds the declarations
the proof added (the lemma and the theorem, a loop or model lemma; for a
round-trip function its helpers', its copy's and the shipped one), encoded
as term DAGs with globals and inductives by name
(`opt::cache::encode_decls`, the optimizer's proof-cache codec, each term
length-prefixed). A hit is replayed through `add_def`
(`opt::cache::replay_decls`), so the kernel checks every declaration
again, and then the trusted check runs on it like on a fresh proof. A
wrong key can only replay declarations that are refused. An entry the
kernel does not accept is recorded (`ModuleTheorems::rejected`) and the
module is walked again without the cache. The key (format `/2`) adds the
names L gave the instances (`L::f<k>`), so a reading generated in another
order misses instead of being rejected. A hit now costs the kernel check
of the replayed proofs (varint: about the cold kernel time) instead of
nothing; it still saves the walks.

**Other changes.** `checked::load_literal` and `load_into` go through a
ledger (a throwaway one for tests and debugging); the conformance check
loads L through the environment's ledger (`conform/literal.rs`), and the
gate reuses a reading the conformance check already loaded. The round
trip's "same MIR in both extractions" check moved from the prover into the
trusted check (1). `checked::prove_and_check` is `prove_lifted` followed
by the trusted check (the tests and `cs_proto` use it).
`GateOptions::key_ignores_mir` is a test hook (a stale entry is served).

**Tests** (`tests/theorem_gate.rs`, negative twins):

* `the_trusted_check_refuses_a_weaker_theorem_the_kernel_accepted`: with
  `Decoder::<u32>::feed`'s theorem accepted, the kernel accepts three
  declarations of `L::thm::<feed>` that the trusted check refuses — the
  equation on the return value only (the final `&mut self`, a component of
  `erase`, dropped; proven from the original by `eq::cong`), a precondition
  `false = true`, and the original theorem after `S_f` was redefined under
  its name outside the elaboration; the original is accepted again
  between them.
* `the_trusted_check_refuses_a_function_without_its_theorem`: with only
  feed proven, `size::<u32>` is refused (`the kernel holds no
  L::thm::..`), feed accepted.
* `a_stale_cache_entry_for_a_changed_mir_is_not_accepted`: with keys that
  leave out the MIR, the entries stored for varint are replayed and
  accepted for the same MIR (63 of 63 from the cache), and for a changed
  `Decoder::<u16>::feed` the replayed proof is rejected by the kernel and
  feed has no theorem.

The existing tests run through the trusted check now (`prove_and_check`
in `theorem_gate.rs` and `fault_injection.rs`; `theorem_gate` itself in
the gate tests).

**Trusted lines** (code lines, `loc.py`):

| part | before this stage | after |
| --- | --- | --- |
| L's generator `literal.rs` | 1,474 | 1,474 |
| `literal.core` (non-comment lines) | 139 | 139 |
| statement `stmt.rs` | 225 | 225 |
| names and load checks `mod.rs` | 480 | 481 (`pub mod gate`) |
| parse `ir.rs` + `sexp.rs` | 613 | 613 |
| printer `mirx` | 1,131 | 1,131 |
| lift glue | ≈ 260 | ≈ 260 |
| the gate | ≈ 650 (bookkeeping) | **125** (`gate.rs`) + ≈ 25 (call sites) ≈ 150 |
| **total** | **≈ 5.0k** | **≈ 4.5k** (≈ 3.9k without the parse, as counted before checked structuring: 4.2k then) |

**Validation** (2026-10-01, release, memguard 6 GB, the host heavily
shared: load average ≈ 35, so times are noisy):

* `tests/theorem_gate.rs` 10 (the 7 before and the 3 above),
  `tests/fault_injection.rs` 4 (the 19 per-construct mutations, the two
  historical bugs and the extra precondition, now through the trusted
  check), `tests/literal.rs` 24, `tests/walker.rs` 4; also
  `tests/lowered_use.rs` 11 (the shipped theorems and the `ShippedMir`
  twin, through `accept_shipped`), `tests/lift_opt.rs` 9 (8 ignored as
  before; the dispatch's shipped theorems per instance),
  `tests/lift_conformance.rs` 13 (1 ignored; L loaded through the ledger),
  `tests/verdict_cache.rs` 8: all pass. Clippy reports nothing in the
  changed lines.
* `sandblaster check storage/sandblaster/mmr/mod.rs`: `gate mir-theorems:
  passed (76 of 76 ..., 15.0s)`, 5,598 obligations, the only error the
  missing SPEC.lock (as before). `sandblaster check
  storage/sandblaster/verifier/mod.rs`: `passed (69 of 69 ..., 6.4–7.1s,
  the trusted check 0.0s)`, its errors the examples, sections and lock
  findings that predate this work (14 + 56 + 1).
* `cargo test -p commonware-codec`: 147 + 16 + 5 passed; the varint build
  is verified, every §15 gate, `63 of 63 lifted function(s) read from MIR
  with a kernel-checked theorem (0 from the verdict cache), 6.2s, the
  trusted check 0.1s`, SPEC.lock matching (116 items).
* The trusted check costs 0.0–0.1 s per module. The gates' wall times
  above are higher than stage cs-assurance's (MMR 9.4 s, verifier 4.4 s);
  the walks and kernel checks are unchanged and the host ran other
  agents' builds, so this is load, not the change, but it was not
  re-measured on a quiet host.

**Open after this stage.**

* L's generator is still 1,474 code lines against the ≈ 1.0k target (the
  other lever on the trusted count).
* A cached theorem now costs its kernel re-check (varint: about the cold
  kernel time, ≈ 2.5 s, against 0.3 s for the old replayed verdict); the
  walks are still saved. Not measured on a warm build in this stage.
* The lowering stage tool (`driver::stage::lower_lifted`, no gate before
  it) makes its first trusted load after the optimizer ran, so the
  optimizer's definitions count as the elaboration there; in every build
  the gate's load comes first.
* The shipped theorems' cache path has no dedicated test (it now replays
  declarations that `accept_shipped` checks).

### Stage tcb-literal (shrinking L's generator), 2026-10-01

**Goal.** L's generator `literal.rs` was 1,474 code lines against the
≈ 1.0k target. Shrink it without changing what L means, keeping each
construct's reading local, with its one-line MIR reference.

**Result.** `literal.rs` **1,217** code lines (−257, −17%);
`literal.core` **139**, unchanged. L's text is **byte-identical** before
and after, for every MIR instance of the three modules and for every
fixture of `tests/literal.rs`, so no conversion lemma is needed.

**Equivalence evidence.**

* Method: the generator as it stood at the start of this stage (a copy of
  `literal.rs` and `cfg.rs`) and the new one, each run on the same input.
  `cs_proto <root> -` with `CS_DUMP=<dir>` generates L of every instance
  with a body, loads it (the kernel checks it) and writes the text; it
  now writes one file per MIR module (`<module>.core`), where it used to
  overwrite one file.
* varint (168 instances), 1,871,847 bytes, MD5 `3a92e12ccf0d8c832bf2399a852063b5`;
  the MMR (128), 1,463,701 bytes, `41ad604b11fc044ef116084437e96ce9`; the
  verifier (116), 1,222,773 bytes, `2915db572729ac5e6935c19e86e72769`:
  identical (`cmp`) after each of the three passes of this stage.
* The constructs read as `None`, with their messages (`CS_FAULTS`):
  identical (varint 0, the MMR 31, the verifier 30).
* The fixtures of `tests/literal.rs` (8 bodies, 309,707 bytes; they cover
  signed operations, unchecked shifts by another width, closures, nested
  cells and returned codes, which the three modules use little or not at
  all): identical, written through a temporary dump hook in the test,
  removed afterwards.

**What changed.**

* *Out of the trusted count, into `cfg.rs` (untrusted).* `cfg.rs` returns
  only numbers and booleans; the trusted generator still writes every
  piece of text.
  * `dfs_order`: the post-order numbers behind `rank`, and the loop
    headers. They only decide where fuel is consumed. A wrong rank, or a
    missing header, fails the kernel's check of `run` (every decrease is a
    `linarith` proof). An extra header only consumes more fuel; since
    running out of fuel is `None`, a `Some` is still the result of a
    finite run (A2), with the same value.
  * `panic_blocks` (it was `must_diverge`): the blocks from which every
    path panics, read as `None`. A wrong entry only turns a value into
    `None`. A block wrongly left out is read construct by construct, as
    any other.
  * `occurs`: whether a code can reach type `T` inside type `A`. It only
    prunes the `follow`/`update` functions: a wrong `false` makes that
    path `None`; a wrong `true` generates functions whose arms are `None`.
  * `show`: the rendering of fault messages.
  * Literal's copy of the successor function was identical to `cfg.rs`'s
    `succs` and is gone. These functions are 68 lines in the old generator
    and 63 in `cfg.rs` (235 → 298 code lines).
* *Duplication removed.*
  * `field_of` and `with_field` are one `field(.., set)`.
  * `BINOPS` and `SIGNED_BINOPS` are one table with a column for signed
    bits.
  * The integer types are one table, `INTS`.
  * `Gen` holds a `GenState` instead of copying its four fields.
  * The self-call's fuel match was a copy of the jump's; it is now
    `fuel_jump`.
  * `Return` reads the output's components from the function's `outs`.
  * The call protocol's open binds are a list folded around the callee's
    run, instead of a text prefix with a count of closing parentheses.
  * Helpers for repeated text: `binds`, `code`, `code_app`, `word_lit`
    (it replaces `mask` and three copies of the masking), `slot`,
    `FnCx::{get, through, need, live}`, `result`.
* *`@RC@`, the function's code type.* Text inside a function's arms keeps
  `@RC@` and is substituted once, where each definition is emitted (`run`,
  `deref`/`write`, `follow`/`update`). Before, it was also substituted at
  every intermediate step: `ty_rc`, and the `rc` parameters of the field
  functions, are gone. The callee's code type in the call protocol is
  still substituted explicitly, as before.
* *Dead code.* `Gen::new`, `Gen::order` and `LFn::nblocks` had no users.
* *Layout.* 33 helpers whose body is one expression are written on one
  line, which accounts for 66 of the 257 lines.

The −257 lines, by kind: 68 moved out, 66 of layout, 123 from removed
duplication and simplification. A measure that layout cannot move,
non-blank characters outside comments, goes from 57,563 to 52,368 (−9%;
about 1,570 of these moved to `cfg.rs`).

**What remains** (code lines, by part): the type map (words, MIR types,
ADTs, constructors, fields) ≈ 220; places and reference codes ≈ 230;
rvalues, operators and casts with their tables ≈ 180; per function
(cells, emission of `St`, accessors, `Blk`, `rank`, `run`) ≈ 160; calls
with the cell protocol ≈ 140; terminators, dispatch and fuel ≈ 70; leaves
≈ 70; the interface types (`LFn`, `Cell`, `AdtL`, `GenState`) ≈ 65;
statements, operands, constants ≈ 40; text helpers ≈ 30.

**The other levers of §7, and why they were not used.**

* *Combinators in `literal.core`.* The Rust lines go into per-construct
  dispatch: picking the reading by type, threading the state, the cell
  protocol. The template text is already one `format!` per construct. A
  combinator replaces that one line with another, adds library lines, and
  changes L's text, and with it every proof term built over it. No
  candidate saved lines on balance.
* *Generic accessors.* `g<i>`/`s<i>` take 5 Rust lines. A generic
  definition over a slot list would need `St` as nested pairs, changing
  every text and every proof, to save at most those 5 lines.
* The next real reduction would change L's text, so it needs a kernel
  conversion check per instance and re-proving every theorem. One
  candidate: read static projections through the reference-code
  machinery, which would remove `static_get`/`static_set` (≈ 50 lines);
  the walker's proofs would then go through the `follow` functions. Not
  done in this stage.

**Cache key.** `checked::generator_hash` (amendment (g); also the
conformance cache) now includes `cfg.rs`, since the generator's text
depends on its ranks and headers. A stale key could only replay
declarations that the kernel and `gate.rs` check again.

**Validation** (release, memguard 6 GB):

* `tests/literal.rs`: 24 passed.
* `tests/fault_injection.rs`: 4 passed (the 19 per-construct mutations,
  the two historical bugs, the extra precondition).
* `tests/theorem_gate.rs`: 10 passed.
* The gate (`CS_GATE=1 cs_proto <root> -`: every lifted function walked
  and then accepted by `gate.rs`): varint 63 of 63 (8.3 s), the MMR 76 of
  76 (13.8 s), the verifier 69 of 69 (6.6 s), none from the cache.
* Every test target of `sandblaster-front` builds. Clippy reports
  nothing in `literal.rs` or `cfg.rs`.

**Open after this stage.**

* 1,217 against the ≈ 1.0k target: see "the other levers" above.
* Not changed, noted in review: in `place`, after the `Deref` of a `&mut`,
  the place's type stays the reference type. So `(*r)[i]` is refused
  (`None`). A downcast followed by a field is still read right, because a
  field step takes the field's own type. The effect is only ever `None`,
  never a wrong value; fixing it would change L's text.

### Stage tcb-checks (two assumptions made checks), 2026-10-01

**Goal.** AUDIT.md §21.1 recorded two assumptions the theorems do not
check:

1. "A module type's fields and variants have the same order and names in
   the MIR and in the subset declaration (kernel field names are
   positional)."
2. "The precondition rule matches binder names (`h_req<k>`, `h_depth`)":
   the content argument was structural (the reader sees only the
   signature).

Turn both into checks, small and in the trusted count, each with a test
and its negative twin, without changing any theorem.

**(1) Module types declared alike** (`mir/gate.rs`, check 4 of its
header; +33 code lines). For a theorem and for a shipped theorem alike,
`Ledger::accept` now collects every ADT the function's MIR instances
reach: the types of the locals of every instance in its closure, through
tuples, arrays, slices, references, closure captures and function items'
arguments, and transitively through each ADT's arguments and fields.
For each one that is a module type (a path of the extracted crate,
`ModuleNames::local`, with a subset name, `kernel_adt`), it compares the
MIR's adt-def with the lifted crate's declaration: the HIR item the
elaborator declared the inductive from, found by the kernel name. It
compares:

* the kind (struct or enum);
* a struct's fields by name and in order (a tuple field is named by its
  index, as the MIR names it);
* an enum's variants by name and in order, each with its fields by name
  and in order;
* each variant's discriminant: variant `i` must have discriminant `i`,
  because typeck refuses explicit discriminants, so the subset's are
  `0, 1, ..`.

A mismatch, or a module type with no declaration, refuses the function
and names both declarations: "the MIR declares
`commonware_codec::varint::Decoder` as {=0(result, bits_read)} and the
subset `crate::varint::Decoder__u32` as {=0(bits_read, result)}: kernel
fields are positional, so L and the structured reading would name
different fields".

Host enums and host instances are not compared. A host model may name
fewer variants than the MIR, and that is the host models' own assumption
(A5). `Ledger::verdicts`, `Ledger::accept_shipped` and
`checked::prove_and_check` now take the lifted crate (`&hir::Crate`).

The module types compared, as measured on the gate runs: varint 9
(`Decoder`, `UInt`, `SInt`, each at three widths), the MMR 4 (`Position`,
`Location`, `Family`, `PeakIterator`), the verifier 6 (those of the MMR
but `PeakIterator`, plus `Standard`, `Subtree` and the enum
`ReconstructionError`). All agree.

**(2) Preconditions are the declared contract's, by content** (the
elaborator; the name rule of `stmt.rs` is removed).

* *The lift* carries the declared contract as one more attribute of the
  lifted function: `#[mir_contract(requires(..), .., decreases(..))]`.
  The declared contract is the `requires(..)` and `decreases(..)`
  attributes of the skeleton and the attachments, never what the reading
  of the body adds, and the attribute copies them as they are (`lift.rs`,
  in the block that records `MirContract`).
* *typeck* reads it into `hir::FnDef::declared` and types it in the
  function's scope like the `requires`. It is typed after the body, so
  the body's locals keep their ids.
* *The elaborator* (`elab::items`: `fn_requires`, `as_declared`,
  `depth_prop`) elaborates a function that has a declared contract only
  when:
  * it has as many `requires` clauses as declared;
  * the type of each precondition `h_req<k>` is α-equal
    (`Env::alpha_eq_relevant`, globals by identity) to the elaboration of
    the declared k-th clause at the same depth;
  * it has a depth bound exactly when one is declared, and its hypothesis
    is α-equal to the declared one's.

  Otherwise the function is refused (`could not be elaborated: ..`): it
  gets no definition, so no `S_f` and no theorem. Binder names play no
  part. The obligations that the second elaboration raises are dropped,
  since the first elaboration's obligations stand. Measured on the MMR:
  each comparison takes under 1 ms, and the obligation count is
  unchanged (4,449).
* `S_f` must be defined by the elaboration (check 3 of `gate.rs`), so
  every theorem the gate accepts has the elaboration of the declared
  clauses as its preconditions.
* So the name rule in `stmt::statement` is gone, and with it
  `model_statement`, which existed only to skip the rule.
  `stmt::statement` no longer takes a contract. `lift::MirContract` no
  longer records the clauses' text: it lists the functions read from MIR,
  `global` and `key` only. The verdict-cache keys no longer have contract
  lines, because `S_f`'s type, which the key hashes, carries the
  preconditions.
* The check sits in the elaborator because an independent elaboration of
  the declared clause needs the clause typed and elaborated in the
  function's scope, which only typeck and the elaborator do. Both are
  trusted already (DESIGN.md §1.1 items 2 and 6).

**Tests** (each with a negative twin):

* `tests/theorem_gate.rs`
  `a_module_type_declared_with_its_fields_reordered_is_refused`. With
  `Decoder::<u32>::feed`'s theorem proven, the trusted check accepts it.
  The twin is the lifted crate's `Decoder__u32` with its two fields
  reordered: `bits_read` first, the types in place. The kernel
  environment, whose fields are `f0` and `f1`, and the theorem are
  exactly the same, so no theorem can see the change. The check refuses
  the function and names both declarations.
* `tests/literal.rs` `a_precondition_other_than_the_declared_clause_is_refused`.
  It uses the lift fixture `lift_w` with an attachment
  `requires(bits < 1000usize)` on `Counter::chunks` (`Counter` is not
  exported: a boundary function has no precondition). `Counter::chunks`
  is elaborated with that precondition. The twin uses the new hook
  `WrongRule::ChangedRequires`: after the declared contract was carried,
  the function's first `requires` becomes `requires(true)`. That is the
  same number of clauses, so the binder is still `h_req0`, which the old
  name rule accepted. The elaborator refuses it: "`crate::w::Counter::chunks`
  could not be elaborated: its precondition 0 `Eq(Bool, true, true)` is
  not its declared contract's `Eq(Bool, #lt_usize(bits, 1000usize), true)`
  (lift::MirContract)". This test replaces the stmt-level test of the
  name rule.
* `tests/fault_injection.rs` `a_precondition_the_declared_contract_lacks_is_refused`
  (`WrongRule::ExtraRequires`). The elaborator now refuses the four
  functions ("it has 1 `requires` clause(s), its declared contract 0"),
  and the gate reports them without a theorem. Feed keeps its theorem.

**Trusted lines** (code lines, `loc.py`):

| part | before this stage | after |
| --- | --- | --- |
| the gate's trusted check `gate.rs` | 125 | 158 (+33: check 4) |
| the statement `stmt.rs` | 225 | 210 (−15: the name rule and `model_statement`) |
| the elaborator's precondition check | — | 39 (`elab/items.rs` +22, `typeck/mod.rs` +12, `typeck/expr.rs` +4, `hir.rs` +1) |
| the lift glue | ≈ 260 | ≈ 258 (−2: the contract's text is no longer recorded; +5 lines of the test hook, not counted) |
| **total trusted** | **≈ 4.22k** | **≈ 4.27k** (+55) |

The stage adds checks, so the count goes up a little: 15 of the
precondition check's 39 lines are paid back by the rule it replaces.

**Validation** (2026-10-01/02, release, memguard 6 GB; the host was
heavily shared, load average 40–90, so times are noisy):

* The narrow suites: `tests/theorem_gate.rs` 11 (the 10 before and the
  reordered declaration), `tests/fault_injection.rs` 4 (the 19
  per-construct mutations, the two historical bugs, the extra
  precondition), `tests/literal.rs` 24 (the name-rule test replaced by the
  changed-clause test), `tests/walker.rs` 4. Also `tests/lowered_use.rs`
  11 (`accept_shipped` with the crate), `tests/lift_conformance.rs` 13 (1
  ignored; `stmt::statement` without a contract), `tests/verdict_cache.rs`
  8 and `tests/lift_opt.rs` 9 (8 ignored). All pass. A first run of
  `lift_opt` failed once in rustc's build of the conformance harness
  ("failed to map object file: memory map must have a non-zero length",
  the shared host's temporary files); it passed when run again.
* The gate (`CS_GATE=1 cs_proto <root> -`, every lifted function walked
  and then accepted by `gate.rs` with check 4): varint 63 of 63, the MMR
  76 of 76, the verifier 69 of 69, none from the cache. The module types
  compared are the ones listed under (1).
* `sandblaster check storage/sandblaster/mmr/mod.rs`: `gate mir-theorems:
  passed (76 of 76 .., the trusted check 0.0s)`, 5,598 obligations as
  before; the only error is the missing SPEC.lock, as before.
  `sandblaster check storage/sandblaster/verifier/mod.rs`: `passed (69 of
  69 ..)`, 1,643 obligations; its errors are the 14 example and
  spec-dependency findings, the 56 section findings and the one lock
  finding that predate this work.
* `cargo test --release -p commonware-codec`: 147 + 16 + 5 passed. The
  varint build is verified, every §15 gate passes, and SPEC.lock still
  matches (116 items, root `d2b174be..`), so the carried
  `#[mir_contract(..)]` changes nothing the lock sees.
* Clippy reports nothing in the changed lines (a `type_complexity`
  warning on the new `Contracts` field was fixed with the
  `DecreasesAttr` alias).

**Open after this stage.**

* The elaborator's check covers every function the lift reads from MIR,
  the lifted round trip's source functions included. The round trip's
  copies and helpers are elaborated in generated mode, without a declared
  contract. Their lemmas are untrusted steps of the shipped theorem's
  proof, whose statement is the source function's.
* A `requires` over `#[ghost]` parameters (in the ghost bundle) is
  compared by count only. No function read from MIR has ghost parameters.
* Host enums and host instances are not compared with the MIR (see (1)).

### Stage tcb-review (independent review, final validation), 2026-10-02

**Goal.** Read the whole trusted part again, as the stages tcb-gate,
tcb-literal and tcb-checks left it, construct by construct against
rustc's MIR semantics: L's generator and library, the statement, the
trusted gate with its two new checks, `mod.rs`'s names and load checks,
the parse. Look for a reading that gives a value where rustc's semantics
differ, and for a way the gate could pass a module whose theorems do not
cover every lifted function or state less than `stmt.rs` generates. Fix
each with a test and its negative twin; publish the final counts; run the
final validation.

**Read, end to end:** `literal.rs` (every rvalue, operator row with its
signed column, cast, intrinsic, terminator, the call protocol with nested
cells and returned codes, places static and through codes, the
`deref`/`write`/`follow`/`update` functions, fuel and ranks),
`literal.core` (every definition and constant), `stmt.rs`, `gate.rs`,
the elaborator's precondition check (`elab/items.rs`, `typeck`), the
names and load checks of `mod.rs`, `ir.rs`, `sexp.rs`, the call sites in
`driver::gates` and `driver::lowered`, the kernel's `alpha_eq_relevant`
and `refs_closure` (which the trusted check relies on), and, read only,
the printer's statement, operand, cast, borrow, constant, drop and leaf
printing in `mirx` (not changed).

**Findings, fixed** (each with a test and its negative twin):

| finding | effect before | fix |
| --- | --- | --- |
| A listed function's MIR instance was not checked to be that function. The lift finds an instance by its lifted name alone (`Decoder__u32::feed`, `foo`: unqualified), and `load`'s index keeps one instance per name. `mod.rs` called this matching untrusted ("a mismatch is a name or type error"), but two functions of two extracted modules with one lifted name and one signature (a free `foo` in two files; two types `Foo`, each with a `bar`), or a function whose own instance was not extracted next to another module's of that name, are bound without any error | the gate would accept a function whose theorem is about another function's MIR: S, read from the same instance, agrees with it, so the theorem holds, and the laws would be about the other function. None of the three extractions has such a pair (no two roots share a lifted name, and check 0 accepts all 208 listed functions) | `gate.rs` check 0: the instance must be the listed function, its lifted name in the DSL module of its item (`ModuleNames::instance_global`: the function's own path, its self type's, a sealed trait's for its impl on a primitive, the module type argument's for an operator impl on a primitive). `tests/theorem_gate.rs` `a_function_listed_with_another_functions_instance_is_refused`: `Decoder__u32::new` with its theorem is accepted; listed with the instance of `<Decoder<u32> as Default>::default`, which calls `new`, so that the theorem of its reading against `new`'s structured reading holds and the kernel accepts it (both proven by evaluation), it is refused, naming the instance's function |
| A second extraction's reading could stand in for the first's. L's names restart with each extraction's reading (`L::f0`, ..), the kernel lets a later definition take over a name, and check 3 trusted every load alike | in an environment with readings of two extractions (no build has one today: every crate's lifted modules share one extraction), the first's statements would name the second's definitions, so a theorem about the second's instance would be accepted for the first's function; and a later load of the first's reading (the round trip's, after the second's) would bind its callees' names to the second's definitions | the ledger records which extraction each load read, L's library apart, and check 3 counts only the library's load and the function's own extraction's: every global the statement reaches, through L's definitions too, must come from the elaboration, the library or that extraction's reading. `tests/theorem_gate.rs` `a_reading_whose_names_a_later_extraction_took_over_is_refused`: a second reading of varint's MIR under another module name, its feed proven, takes over feed's names; feed is accepted for the second extraction and refused for the first, whose statement reaches the second reading's definitions |
| An index leaf was recognized by a path suffix, `ends_with("ops::Index::index")` (stage cs-assurance made the range types exact, not the trait). The printer makes any `..::index` call on an array through a trait named `..Index` a leaf, and the structured reading reads every such leaf as core's indexing | a crate's own `myops::Index::index` on an array, by a core range, was read as core's `&a[..j]` whatever the crate's impl does; S agrees, so the theorem holds | core's `Index` by its exact path (`lib_path`). `tests/literal.rs` `readings_the_review_found_wrong_are_none_where_rust_differs`: `k::myops::Index::index` is `None` and named; core's is still the slice. Every leaf of the three extractions and of the fixtures is `std::ops::Index::index`, so L's text is unchanged |

**Checked and found right** (no change):

* *The statement.* `init` puts each relevant parameter of `S_f` in its
  MIR slot (parameter `i` is local `i`; `&mut` and `Option<&mut T>`
  parameters through their cells), `erase` maps S's result component by
  component in `Out`'s order (cells in parameter order, then the return
  place; a lifted function whose referent holds a reference is refused),
  and the telescope is pinned by the well-typedness of `S_f x̄ .h̄` inside
  the kernel's declaration: a precondition type that does not convert with
  `S_f`'s makes the declaration ill-typed.
* *The trusted check against the kernel.* `alpha_eq_relevant` compares
  every binder's domain, irrelevant binders included (the preconditions
  and the `.hle` fuel premise), and every relevant application argument;
  `refs_closure` follows binder domains, motives and inductive
  declarations (a global in the premise is reached). A redefinition of a
  name used by the statement (`seq::len`, `S_f`, L's `run`) after the
  first load is refused by check 3. In every build the first load precedes
  any untrusted definition: the elaboration, then the §15 gates on a
  read-only environment (`run_gates(&out, ..)`), then the theorem gate.
* *L's readings.* Aggregates and aggregate constants carry the variant
  index (`VariantIdx`, the printer's `v.to_index()`), discriminants come
  from the adt-def; signed `Div`/`Rem`/checked/unchecked operations are
  not modeled; `Shl`/`Shr` reduce the amount to `u32` (every width divides
  2^32, so the residue modulo the width is kept, signed amounts included,
  as `rem_euclid` does), and unchecked shifts compare the amount at its
  own type; sign extension only from signed types; `RuntimeChecks(ub)` as
  `false`; a self-call and its continuation run on one unit less; a
  callee's cells are written back before its result is written (`x =
  f(&mut x)` ends with the result). The type of a place after the `Deref`
  of a `&mut` stays the reference type (recorded at stage tcb-literal):
  a field step takes its own type, an index is refused, and a second
  `Deref` has a target type that never equals the true one, so `follow`
  finds nothing: `None`, never a value.
* *`literal.core`.* The sign-extension masks, the checked flags, the
  `bswap` masks, the leaves' panics (`&a[..=j]` fails exactly when `j >=
  N`).
* *The printer* (read only): the statements it omits have no runtime
  effect (storage markers, fake reads, place mentions, ascriptions,
  coverage); a drop whose glue it cannot decide is read as glue; casts,
  borrows and terminators it does not know are printed `unsupported`.
* *The round trip's call site.* A rewritten function always has at least
  one instance, so a lowered function always passed `accept_shipped`.

**Recorded, not changed:**

* *Adt-defs across the gate's and the round trip's extractions.* Check 1
  compares the instances' bodies; L reads the adt-defs of the extraction
  the module's reading began with. In the MMR's two extractions 13 of 114
  adt-defs differ, all only in rustc-internal ids printed inside unmodeled
  types (`(unsupported "type Pat(Ty { id: 211, ..")`), which L reads alike,
  as not modeled; comparing the whole text would refuse every shipped
  theorem whose instances reach a `Vec` (through `RawVec` to `NonNull`).
  Module types are compared with the subset's declaration on both
  extractions (check 4), library types come from the same compiler
  release, and the copy changes function bodies only (`lowered::assemble`).
* *A fragility, fail closed.* An instance whose text holds such an id
  differs between the two extractions (the MMR: `Result::<Position,
  Error>::expect`), so a shipped theorem whose instances ran it would be
  refused and the function keep its source text. None does today.
* *Suffix matches that give no value.* `Option<&mut T>` (`opt_mut`) and
  `Vec`'s allocator `Global` are still recognized by path suffix: a type
  wrongly taken for `Option<&mut T>` has no reading (a type holding a
  `&mut` is not modeled, and the statement with it is ill-typed), and a
  `Vec` with another allocator keeps `Vec`'s meaning as a sequence up to an
  allocation failure, which aborts.
* *Unions* parse as structs (`(kind union)`): no union value with more than
  one field can be built (an aggregate has one operand, the constructor
  one argument per field: a kernel type error), and a one-field union is a
  struct. The MMR and the verifier declare `MaybeUninit` and
  `lazy_lock::Data`, used only in functions no lifted function calls.
* *Ghost parameters.* A `requires` over `#[ghost]` parameters is compared
  by count only; no function read from MIR can have one (the lift adds
  none, and the as-is Rust file cannot declare one).
* *`argc`* defaults to 0 when malformed: then the parameters read as
  uninitialized, or a call's argument count is refused; no value follows.
* *Multi-extraction crates.* After the fix, a crate whose lifted modules
  have two extractions gets the first's functions refused (their names
  taken over), as before the fix, but now named; ids unique across
  readings would make such crates verifiable (not needed by the three).

**Trusted lines** (code lines, `loc.py`):

| part | before this workflow (stage cs-assurance) | after stage tcb-checks | after this stage | what it trusts |
| --- | --- | --- | --- | --- |
| L's generator `mir/literal.rs` | 1,474 | 1,217 | 1,217 | the MIR reference, construct by construct; `cfg.rs` only for fuel placement and `None` |
| L's library `mir/literal.core` | 139 | 139 | 139 | the kernel's primitives; the lift's models (A5) in its leaves |
| the statement `mir/stmt.rs` | 225 | 210 | 210 | `S_f`'s telescope (the elaborator's check) |
| names and load checks `mir/mod.rs` | 480 | 481 | 491 (+10: `instance_global`, with the `dsl_module` helper `kernel_adt` now shares) | the lift's names (`ModuleNames`), the source hashes |
| parse `mir/ir.rs` + `mir/sexp.rs` | 482 + 131 | 482 + 131 | 482 + 131 | the printer's format |
| printer `mirx` | 1,131 | 1,131 | 1,131 | rustc (A4) |
| the gate's trusted check `mir/gate.rs` | ≈ 650 of bookkeeping | 158 | 164 (+6: check 0; check 3 per extraction, the library's load recorded apart) | the kernel, the parts above, the lift's list of functions read from MIR |
| its call sites (`driver::gates`, `driver::lowered`) | (in the ≈ 650) | ≈ 25 | ≈ 25 | — |
| the elaborator's precondition check | — | 39 | 39 | typeck and the elaborator (TCB items 2, 6) |
| the lift glue | ≈ 260 | ≈ 260 | ≈ 260 (unchanged) | — |
| **total** | **≈ 4.97k** | **≈ 4.27k** | **≈ 4.29k** (≈ 3.68k without the parse) | |

Against the start of this workflow, the trusted part is 683 code lines
smaller (≈ 4.97k → ≈ 4.29k, −14%); against the trusted structurer before
checked structuring (≈ 4.78k with the parse, ≈ 4.18k without), it is
smaller by ≈ 0.5k on either counting. This stage adds 16 lines for the
two checks the review found missing.

**Validation** (2026-10-02, release unless noted, memguard 6 GB, the host
shared with other agents' builds):

* The negative twins fail without their fixes: with check 0 disabled the
  misbound `Decoder__u32::new` is accepted, with check 3 counting every
  load alike the taken-over reading is accepted, and with the index leaf
  matched by suffix `myidx` reads as core's indexing (no fault).
* `cargo check --tests` of the eight sandblaster crates: clean but the two
  `cfg(sandblaster)` warnings of `redteam_fidelity.rs` that predate this
  work. Clippy reports nothing in the changed files.
* Front suites: `mir` 38, `literal` 24, `walker` 4, `theorem_gate` 13 (the
  11 before and the two above; varint's gate 63 of 63, the verifier 69 of
  69, the MMR 76 of 76, so check 0 refuses none of the 208 functions),
  `fault_injection` 4 (the 19 per-construct mutations, the two historical
  bugs, the extra precondition: all caught), `lift` 18, `lift_open` 27,
  `lift_verifier` 24, `lift_conformance` 13 (1 ignored), `lift_opt` 9 (8
  ignored), `lowered_use` 11, `verdict_cache` 8, `build_loop` 7,
  `module_mode` 10 (`lift_probe` and `lift_varint_diff` are ignored scratch
  tools); the front's unit tests 49; the kernel's tests: 26 targets, 181
  passed, 1 ignored. `lift_opt` failed twice under two test threads in
  rustc's build of the conformance harness (an empty object file, then a
  missing one): its two module-mode tests built the same module `bits`
  into one `OUT_DIR` at once. Each build now gets its own `OUT_DIR`
  (`tests/lift_opt.rs`, the only change to that file), and it passes with
  two threads, as with one.
* `cargo test -p commonware-codec` (dev profile): 147 + 16 + 5 passed; the
  varint build is verified: 21,237 obligations, every §15 gate (spec
  mutants 763 killed of 985), `mir-theorems: 63 of 63 lifted function(s)
  read from MIR with a kernel-checked theorem (0 from the verdict cache),
  6.2s, the trusted check 0.1s`, lift conformance 22,070 inputs on 63
  functions and the literal reading on 3,654 inputs, 0 mismatches,
  SPEC.lock matching (116 items, root `d2b174be..`).
* `cargo test -p commonware-storage --lib -- merkle::mmr merkle::position
  merkle::location merkle::proof merkle::hasher` (dev profile): 129
  passed. Its build: the MMR 5,598 obligations, `76 of 76 .., 13.2s, the
  trusted check 0.0s`, `to_nearest_size` still rewritten with its 8
  shipped theorems (1 against the source function); the verifier 1,643
  obligations, `69 of 69 .., 6.2s, the trusted check 0.0s`; both
  development builds report their pending §15 findings as before.
* `sandblaster check storage/sandblaster/mmr/mod.rs`: `gate mir-theorems:
  passed (76 of 76 .., 12.6s, the trusted check 0.0s)`, 5,598 obligations,
  10 laws, 307 s in all; the only error the missing SPEC.lock, as before.
  `sandblaster check storage/sandblaster/verifier/mod.rs`: `passed (69 of
  69 .., 6.3s, the trusted check 0.0s)`, 1,643 obligations, 5 laws, 15 s;
  its errors the 14 example and spec-dependency findings, the 56 section
  findings and the one lock finding that predate this work.
* Added check time: the trusted check takes 0.0–0.1 s per module; the two
  checks this stage adds are a name computation per function and a
  per-extraction filter of check 3's existing walk, not measurable at that
  resolution. The gate as a whole: 6.2 s of the varint build (whose
  elaboration took 847 s and gates 500 s on this host), 12.6–13.2 s for the
  MMR, 6.2–6.3 s for the verifier, all cold.

**Open after this workflow.**

* L's generator is 1,217 code lines against the ≈ 1.0k target; the next
  real cut changes L's text (stage tcb-literal: static projections read
  through the reference-code functions, ≈ 50 lines, with every theorem
  proven again).
* Crates whose lifted modules have two extractions: ids unique across
  readings (and L's own inductives of library types shared between them)
  would let the second reading leave the first's names alone.
* The printer's `unsupported` renderings carry rustc-internal ids, so an
  instance holding an unmodeled type differs between two extractions; a
  shipped theorem running one would be refused (fail closed). Dropping the
  ids in the printer or the parse would remove this.
* Host enums and host instances are compared with the MIR by variant name
  only; their tuple fields are positional (in module mode rustc checks each
  modeled variant's payload types in the emitted module's tail, `const _:
  fn(T..) -> E = E::V;`; in place the models are listed in the record): the
  host models' assumption (A5).
* A cached theorem costs its kernel re-check; not measured on a warm build.
  The shipped theorems' cache path still has no dedicated test.

### Stage finish-A (the shipped theorems decide), 2026-10-03

**Goal.** The lifted round trip refused correct rewrites. Besides the
kernel theorems of the shipped code, every printed helper's structured
reading had to equal its residual syntactically, and every copy had to be
the delegation `λ x̄. r x̄`; rustc's MIR of a printed residual binds
temporaries by `let`, tests a checked operation's `Option` with `is_none`
and reaches sub-slices through core's `Index`, so its reading differs from
the residual it computes. Make the theorems (`L::shipped::<id>`,
`L::pshipped::<id>`) the deciding check for every module read from MIR,
keep the syntactic comparison only where no MIR theorem can exist, and
write the argument down (DESIGN.md §2.1, §5.13 here).

**Changed.**

| where | what |
| --- | --- |
| `driver/lowered.rs` (untrusted bookkeeping around the trusted call sites, whose requirement is unchanged) | the round trip is two functions: `shipped_theorems`, which decides a module read from MIR by the trusted check of each rewrite's shipped theorems alone (`mir::gate::accept_shipped`, `accept_shipped_panic`), and `compare_read_back`, the structural comparison, run only for a lifted module without MIR (which the lift no longer accepts). The test hook `LowerFault::CompareStructurally` runs the comparison beside the theorems and records what it would refuse (`LoweredModule::structural`). The emitted function and its round-trip copy leave out a by-value parameter's `mut` (`SourceFn::param_muts`): the rewritten body, a call of the replacement, mutates no parameter, and rustc warns `unused_mut` otherwise |
| `driver/gates.rs` | the build note names what decided ("the shipped MIR's theorems") |
| `mir/simproof.rs` (untrusted) | the two walker gaps of §5.13: a `let`-headed side of an S-split's path equation is evaluated, and `abs_syn` abstracts inside `let` bodies |
| `mir/literal.rs` (+10), `mir/literal.core` (+16) (trusted) | a slice's sub-slices by core's `Index` (`&s[..j]`, `&s[i..]`, `&s[i..j]`, `&s[..=j]`), read as the array's are, by four leaves over the slice (`leaf::slice_index_*`, §2.5, §2.6) |

**Tests.** `tests/lift_opt.rs`
`a_rewrite_whose_shipped_mir_differs_only_syntactically_is_accepted`
(fixture `opt_shipped`: three rewrites whose copies' MIR differs from the
residual by `let`-bound temporaries, `is_none` and `Index` sub-slices;
each ships with its kernel-checked `L::shipped::<id>` and agrees with the
source under rustc, while the comparison, run beside the theorems by the
hook, refuses all three) and `a_wrong_shipped_copy_is_refused_by_the_theorem`
(the copy's MIR read with one constant off: the theorem fails and the
source stays). `tests/literal.rs`
`a_slices_index_by_a_range_is_the_subslice_or_a_panic`: the four slice
leaves, their values and their panics, with negative twins (a crate's own
range type, a crate's own `Index`, both `None` and named).

**Development data.** Held-out v1's `next_power_of_two`, `read_u32_le` and
`mix64`, whose cheaper residuals the comparison refused with "relevant
structure differs", now lower, each with its kernel-checked shipped
theorem.

**Not changed: a residual with a loop.** Not printable, and not only a
printing gap: the elaborator's loop helper `<f>::loop#k` has no HIR item
while the printer, the specializer and the lowering name functions by HIR
item; printing one as a helper would still meet a lowering that prints no
loops and a round trip without a loop lemma for a helper's MIR (DESIGN.md
§2.1, "Not built yet"; development data: held-out v1's `gray_decode`,
`parity`).

**Validation** (this stage's development changes complete, before the
held-out v2 sample was drawn): the touched suites (`lift_opt`,
`lowered_use`, `opt_panics`, `opt_summaries`, `literal`, `mir`, `walker`,
`theorem_gate`, `fault_injection`, `reader_widen`, `build_loop`,
`lift_conformance`, `in_place_cache`, `verdict_cache` and the four
`fairness_*`: 18 suites, 187 tests) and the front end's unit tests of the
lowering, the optimizer and the MIR modules (18) pass (`literal` again
after the slice test was added: 31 tests); G6, its self-test
and `fair-baseline.sh` (plain, `--heldout`, `--selftest`) pass.
`cargo test -p commonware-codec`: varint verified, 21,253 obligations,
603 definitions kernel-checked, `mir-theorems` 63 of 63, every §15 gate
passed, `SPEC.lock: matches (116 item(s), root f0021c19…)`, none of the 6
source functions rewritten (the source emitted as-is), 147 + 16 + 5 tests
pass (343 s with the build). `cargo test -p commonware-storage --lib` (the
MMR, position, location, proof and hasher tests): the MMR verified in
place, 5,953 obligations, 740 definitions, `mir-theorems` 69 of 69, every
§15 gate passed (220 of 297 spec mutants killed), `SPEC.lock: matches (208
item(s), root 1d8d5969…)`, no function rewritten; the verifier's
development build as before (1,929 obligations, `mir-theorems` 69 of 69,
its 79 §15 findings pending); 129 tests pass (1,141 s with the build). The
locks and theorem counts are those before the stage.

**Counts.** L's generator 1,297 code lines (+10), `literal.core` 186 (+16);
the trusted part ≈ 4,552 (+26, §7).

**Then, with development frozen** (snapshot `finish-A dev accepted`,
04:05 PDT): held-out v2 (`bench/heldout-v2/REPORT.md`). H2-v2 was sampled
by its frozen rule, unchanged: all 869 candidates probed, none accepted
(`h2/PROBE-LOG.md`), so H2-v2 is empty; the fair harness on H1-v2: 0 of 30
functions changed, geomean 1.007 (default layout) / 1.002 (aligned) /
0.999 (no overflow checks), A/A 0.87–1.19 / 0.84–1.11, 29 of 30 functions
identical machine code (30 of 30 apart from data addresses). Held-out v1,
development data, run again: 3 of 31 changed (the three this stage lets
through), geomean 1.002 / 1.004 against an A/A of 1.016 / 0.996; the model
predicted 0.90, 0.70 and 0.95 for them, and they measure 1.00 (`mix64`, the
same machine code as rustc's), 1.00 (`next_power_of_two`) and 1.08 / 1.12 /
1.07 (`read_u32_le`, slower in all three binaries). The
shipped code (`bench/shipped-harness/REPORT.md`): codec's varint, storage's
MMR and the verifier's first set as the two crates compile them, against the
original Commonware functions: the same instructions in all 33 functions
(28 identical outright, 5 apart from each copy's constant-data addresses,
like the A/A pair), geomean 1.003 / 1.002 / 1.008.

## Summary

Today `front/src/mir/read.rs` (2,397 code lines) turns rustc's MIR into the
structured exec subset (lets, matches, tail-recursive loop helpers, state
passing) that the elaborator proves. It is trusted: if it misreads MIR, the
proofs are about the wrong program.

This design keeps `read.rs`, now untrusted, and adds two things:

* **L, a literal reading of MIR.** A small trusted generator turns each MIR
  function into a kernel definition, one MIR construct at a time.
* **A kernel-checked theorem per function**, saying that L returns what the
  structured reading S returns.

The theorem is a statement of **total correctness**. For every input that
satisfies S's preconditions, there is a fuel bound after which L returns
`Some` of S's value. That value includes the final values of the `&mut`
parameters' referents. Returning `Some` means the MIR run terminates
without a panic or undefined behaviour.

The proofs are terms built by an untrusted walker and checked by the
kernel. They reuse S's own obligation proofs and decrease proofs. No kernel
change is needed.

**Decision: option A, the shallow embedding.** Option B, a deep embedding
(a MIR interpreter in the kernel), is rejected for the reasons in §1.

Prototype results:

| target | status | kernel time | proof size |
| --- | --- | --- | --- |
| varint `read::<u32, &[u8]>` (decoder loop, `map_err` with a closure, `?`) | proven end to end | 0.050 s | 49,050 nodes |
| MMR `<PeakIterator as Iterator>::next` (`&mut self` loop) | proven end to end | 0.387 s | 139,826 nodes |
| verifier `Subtree::reconstruct_digest` (non-tail self-recursion, `Option<&mut Vec>`) | partial: its hashing callees `leaf_digest` and `node_digest` (SHA-256 host model) are proven | 0.124 s (the two callees) | 32,440 nodes |

The varint and MMR figures cover each target together with its callees and
helper lemmas; per-lemma figures are in §8.

For `reconstruct_digest`, the literal reading of the call graph reaches
`Option::as_deref_mut` and stops. That callee returns a reborrowed `&mut`
into the caller's frame, which the prototype generator does not handle.
The walker also lacks non-tail self-calls. Both are designed in §2.4 and
§5.4 and estimated in §9.

---------------------------------------------------------------------------

## 1. Options and decision

**Common ground.** S is the structured reading `read.rs` produces today. It
is elaborated and proven as it is now: obligations, laws, the optimizer.
What changes is the trust. S is no longer believed to mean the MIR; a
theorem relates it to L. L is the only reading that is trusted.

### A. Shallow (chosen)

L is a set of kernel definitions per MIR instance:

* a state type (one `Option` slot per local, plus cells for `&mut`
  referents);
* a block type;
* one `run : fuel → block → Option(state) → Option(out)`, by measure
  recursion, with one arm per basic block.

Each statement is a small expression over the state in the `Option` monad.
The theorem equates `run` with S by symbolic evaluation in the kernel:
running L on symbolic inputs is just evaluation.

The walker steers the evaluation through tests along S's own case splits.
At each split it moves the literal side with S's facts:

* path equations;
* obligation proofs;
* callee lemmas;
* decrease proofs.

### B. Deep (rejected)

L is a single interpreter `exec : Program → Frame → Option(Value)` over a
MIR syntax tree encoded as a kernel inductive. Each function's text is data.

* **Value encoding.** One universal value type needs an `enc` per S type
  and lemmas that `enc` commutes with every operation. That is about 30
  lemmas per type family (lists, structs, `Option`, slices), written once
  but trusted in shape. The shallow reading uses the kernel's own types, so
  it needs none.
* **Collections.** State is a map from locals to universal values. Every
  read or write of a symbolic slot needs a commutation lemma
  (`get(set(m, i, v), j)`) with symbolic indices; the shallow `St` is a
  record, and its accessors reduce by evaluation.
* **Cost.** Interpretation overhead is about 10–30 times the shallow run in
  the kernel's evaluator: dispatch on the instruction tree, environment
  lookups, value boxing. The shallow PeakIterator lemma already takes
  0.38 s.
* **Speculation.** The kernel unfolds a recursive call only if its body's
  weak-head form is not stuck on a neutral (DESIGN.md §5.6). A big-step
  interpreter is stuck on the program counter of a symbolic state at every
  step. It would need a small-step design with an explicit stack, and the
  proof would have to drive every step.
* **References.** A deep reading still needs the same frame-isolated
  reference model, codes and write-back. The trusted part shrinks only by
  the generator, about 0.6k lines, and grows by the interpreter and encodings.

### C. Considered and dropped

* **A checked structurer in the kernel.** Kernel change: refused.
* **Translation validation of `read.rs` on its intermediate steps**
  (CFG → structured term, each step justified). The steps are
  `read.rs`-specific: symbolic values, inlining library calls, loop
  placement. A justification language is about as large as the structurer.
  A semantic theorem against a literal reading is independent of how S was
  built. A better or different structurer, or hand-written S, is checked the
  same way.
* **Charon/LLBC as L.** Charon's structuring is exactly the trust being
  removed (`docs/mir-lift.md` §2).

### Why A

* **Small, regular trusted part.** L is one construct at a time with no
  structuring decision. Its library has 74 code lines.
* **Proofs come from S's own facts.** The walker reuses S's obligation
  proofs, ensures facts and decrease proofs as they are. Nothing is
  re-proven.
* **Cheap checking.** It is fast because the kernel's evaluator does the
  work (measured in §8).
* **No new trust in the kernel.** L uses only existing features: measure
  recursion, dependent matches, `delta`, `linarith`, `bvrefl` bridges.

---------------------------------------------------------------------------

## 2. The literal reading L (trusted), construct by construct

L is generated per MIR instance by `front/src/mir/literal.rs` from the same
`ir.rs` parse that `read.rs` uses, on top of a fixed library
(`front/src/mir/literal.core`). Everything it emits is ordinary kernel
definitions, checked by the kernel (types, termination). Failure is always
`None`: undefined behaviour, a panic, an unmodeled case. **`None` is never
a wrong answer**, so a missing construct can only make a theorem
unprovable, never false.

### 2.1 Per function

For a MIR instance `f` with locals `_0.._k`, blocks `bb0..bbm` and `&mut`
parameters, L emits the items below. `p` is `L::f<id>`, and each function
is preceded by a comment with its MIR key.

**`p::Root`**: one constructor per local `r<i>` and per cell `rc<j>`. These
are the roots of reference codes.

**`p::St`**: one field `l<i> : Option(T_i)` per local, then one field
`c<j>` per cell. `None` means the slot is uninitialized or moved out of.
`T_i` is L's type for the local's MIR type (§2.3).

**Cells.** A cell is the referent of a `&mut` parameter, held in the frame
by state passing. The parameter's slot holds the code `(rc<j>, [])`. A
`&mut` inside an `Option` parameter gets an optional cell. A referent that
itself holds an optional `&mut` gets a nested cell. The design is in §2.4;
the prototype handles the first two.

**`p::g<i>` / `p::s<i>`**: get and set of slot `i` on `St`.

**`p::Blk`**: `b<k>` per block and `d<k>`, the dispatcher of block `k`'s
switch. Every block ends in a tail jump, so a switch first jumps to `d<k>`,
which tests the value and jumps on.

**`p::rank : Blk → Int`**: the DFS post-order number of the block, doubled
plus 2; `d<k>` is one less than `b<k>`. It decreases along every edge that
is not a DFS back edge.

**`p::run`**:

```
run : (fuel : List(Unit)) → (b : Blk) → (os : Option(St)) → Option(Out)
match os with None ⇒ None | Some(s) ⇒ match b as yb using .eb with  b0 ⇒ … | d0 ⇒ … | …
measure (len(fuel) · 65536 + rank(b))
```

`Out` is the tuple of every cell's final value (nested cells included; an
optional cell's as an `Option`), in cell order, then
the return place when it is not `()`.

**Fuel.** Every jump to a **loop header** consumes one unit of fuel
(`match fuel with Nil ⇒ None | Cons(u, f1) ⇒ rec(f1, …)`), and so does
every self-call. A loop header is the target of a DFS back edge. Every
other jump is free: its rank decreases, which proves it.

The decrease proofs are generated `linarith` terms over:

* the block match's path equation `eb`, giving `rank b`;
* for a fuel-consuming jump, the fuel match's equation `ef`, giving
  `len fuel = 1 + len f1`.

The kernel checks them. Fuel only bounds termination, so its placement is
not trusted: a wrong placement makes `run` fail to typecheck. (Since stage
tcb-literal the post-order and the loop headers come from `cfg.rs`, which
is untrusted, as do the blocks from which every path panics, read as
`None`.) Entering a
loop consumes one unit as well. That gives the walker a stuck point at
every loop entry, where the loop lemma applies (§5).

### 2.2 Statements and terminators

A statement is `Option(St) → Option(St)` in the monad
(`mir::bind`, `mir::map`). A block is its statements' bind chain followed by
its terminator.

**Rvalues and statements**

| MIR | L |
| --- | --- |
| `_i = Use(op)` | read the operand, then `s<i>` |
| `copy` / `move p` | read the place (§2.4); a move leaves the slot as it is, since later reads of a moved-out local do not occur in borrow-checked MIR |
| `BinOp(add / sub / mul, …)` on unsigned `w` | `#wadd_w` / `#wsub_w` / `#wmul_w` (wrapping, as MIR's unchecked `Add` is defined only where the checked form was asserted) |
| `CheckedAdd` / `Sub` / `Mul` | `mir::checked_*_w a b = (wrapped, overflow flag)`; the flag is an explicit integer test, so no proof is carried |
| `AddUnchecked`, `Div`, `Rem`, `ShlUnchecked` / `ShrUnchecked` | `Option`-valued; `None` on undefined behaviour or a zero divisor |
| `Shl` / `Shr` | `#wshl` / `#wshr` with the amount reduced to `u32` |
| `BitAnd` / `Or` / `Xor`, comparisons, `Cmp` | the width's primitive; `Cmp` is `mir::cmp_w` (`Ordering`) |
| `isize`, `i8` (discriminants, `Ordering`) | their bits; signed comparisons are `mir::slt` / `sle` (sign bit flipped) |
| `i16` / `i32` / `i64` | the lift's bit models `crate::__lift::I32(u32)` …: bit operations, equality, casts (as today, SEMANTICS.md §19.3) |
| `UnOp(Not / Neg)` | bit primitive; `Neg` only on the signed models |
| `UnOp(PtrMetadata)` of `&[T]` | `slice::len` |
| `Cast(IntToInt)` | `#cast_*`; signed through the bit model; no sign extension (refused) |
| `Cast(Transmute)` of an unsigned word to `[u8; n]` | `w::to_le_bytes` (the targets are little-endian) |
| `Cast(Unsize)` `&[T; N] → &[T]` | `array::as_slice` |
| `Discriminant(p)` | `L::discr__<ADT>`: a match giving each variant's discriminant at the destination's width |
| `Aggregate` (tuple, struct, enum variant, closure, array) | constructor; a variant the host model lacks is `None`; an array is the list with its length proof `refl` |
| `Ref(shared, p)` | the value of `p` (a snapshot) |
| `Ref(mut, p)` | a reference code `(root, path)` (§2.4) |
| `Repeat` | `array::repeat` |
| `Assume(op)` | `mir::guard` (`None` when false) |
| `StorageLive` / `StorageDead`, fake borrows | nothing |

**Terminators**

| MIR | L |
| --- | --- |
| `Goto(t)` | jump |
| `SwitchInt(op, arms, otherwise)` | jump to `d<k>`; there, compare the value with each arm's literal and jump |
| `Return` | `Some((cells…, _0))`; a cell or the return place is read, and `None` if uninitialized |
| `Assert(op, expected, t)` | `mir::guard`, then jump |
| `Call` of a module or library function with MIR | the callee's `run` with the **same fuel**, on its initial state built from the arguments; its cells are read through the caller's codes and written back; the result goes to the destination; then jump |
| self-call | as a call, inside `match fuel with Cons(u, f1) ⇒ …`, with `f1` |
| `Call` of a leaf | its model (§2.5) |
| `Call` of an intrinsic | `ctlz`, `cttz`, `ctpop`, `saturating_*`, `*_with_overflow` as primitives; `bswap` as `mir::bswap_w` (shifts and masks, so the word normalizer sees through it); `cold_path` does nothing |
| `Call` of a diverging function, `Unreachable`, `Resume` | `None` |
| `Drop` without glue | jump; a drop with glue is `None` (refused) |

### 2.3 Types

| MIR type | L type |
| --- | --- |
| `bool`, `u8 … usize`, `()` | `Bool`, `U8 … Usize`, `Unit` |
| `isize`, `i8` | `U64`, `U8` (bits) |
| `i16` / `i32` / `i64` | the lift's bit models |
| tuples | `Tuple<n>`; the 1-tuple is `mir::Tuple1` |
| `[T; N]`, `&[T]` | `Array T N`, `Slice T` |
| `&T` | `T` (snapshot) |
| `&mut T` | the function's reference code type `Tuple2(Root, List(mir::Proj))` |
| ADT of the module without invariant fields | S's inductive (the same constructors, matched by variant name) |
| ADT of the module with invariant fields | L's own mirror inductive (the relevant fields), with `erase` in the statement (§3) |
| `Option`, `Result`, `ControlFlow`, `Ordering`, `Range`, `PhantomData`, `Infallible` | the lift prelude's or the library's |
| host types (`Error`, `Sha256`, …) | the host model's declaration by name; a variant it does not name is `None` |
| model types | `Vec<T>` → `List(T)`; the byte-string iterator → `Slice (Slice U8)`; `Digest` → `Array U8 32` |

The model types are the same models S uses (SEMANTICS.md §19.10).

### 2.4 References

* A **reference code** is data, `(root, path)`. `path` is a list of
  `PField i` / `PDown v` / `PIndex i` projections.
* **Reading and writing through a code.** `deref__T s root path` and
  `write__T s root path v` are generated per referent type `T`. They match
  on the root's slot or cell and follow the path, each step a field match
  or a list update by index. They are total and return `None` on a bad
  path.
* **Deref.** `*r` of a `&mut` switches the place to the code held in `r`.
  `*r` of a shared reference is the identity (the snapshot).
* **Why codes.** Lenses or Σ-typed references would make `St` refer to its
  own type. Codes keep `St` first order.
* **Calls.** The caller's code for each `&mut` argument is followed. The
  referent value becomes the callee's cell `c<j>` (its own root `rc<j>`).
  After the callee returns `Some((c_0', …, r))`, each `c_j'` is written back
  through the caller's code.
  * **Justification.** Rust's exclusivity, checked by rustc's borrow checker
    before MIR is emitted, guarantees no other path to a `&mut` referent
    during the call.
* **Shared references are snapshots.** The subset has no interior
  mutability (`UnsafeCell` and its users are refused).
* **Returned `&mut`** (needed by `Option::as_deref_mut` in the verifier;
  designed, not yet in the prototype).
  * **The case.** A callee returning a reference returns a code of *its*
    frame, `(rc<j>, path)`.
  * **Translation.** The call site translates the code back: `rc<j>` is
    replaced by the caller's code for argument `j`, with `path` appended.
    The generator knows that map at every call: it is the inverse of how
    it built the callee's cells. A code rooted at a callee local, a
    dangling reference, cannot occur in borrow-checked MIR. It is `None`
    anyway.
  * **Nested cells.** A referent holding `Option<&mut T>` gets a nested cell
    for the inner `T`. At the call, the outer cell holds a code to the
    nested one. At return, the nested cell is written back through the
    caller's inner code.

### 2.5 Leaves

A leaf is a library function without MIR whose meaning is a host model.
L reads its `&mut` arguments through their codes, applies the same model
function S uses, and writes back:

* `Buf::try_get_u8` → `crate::__lift_model::buf_try_get_u8` on the buffer
  cell (`List(U8)`);
* `Vec::push` → `crate::__lift_model::vec_push`;
* `Iterator::next` of the byte-string iterator →
  `crate::__lift::bytes_iter_next`;
* `<H as Hasher>::hash` → the host model's function
  (`crate::merkle::host::Sha256::hash`);
* `Deref::deref` of the `Digest` newtype → `array::as_slice`.

Stage reader-widen adds library functions read as **models** instead of
through their MIR, whose raw pointers neither reading models (`mod.rs`'s
`Model`, by the exact path of each definition; S inlines a small MIR body
of the same meaning, `read::model_body`):

* core's slice iterator: `<[T]>::iter`, `<&[T] as IntoIterator>::into_iter`
  and `Iter::new` → `leaf::slice_iter_new` (the slice at index 0), and
  `<Iter as Iterator>::next` → `leaf::slice_iter_next` through the
  iterator's code (the element at the index, the index one further, or
  `None` at the end); the iterator is `Tuple2(Slice T, Usize)`;
* `<Range<usize> as SliceIndex<[T]>>::get` → `leaf::slice_get_range`.

Stage finish-A reads a slice's sub-slices as the array's are read:
`<[T] as Index<RangeTo / RangeFrom / Range / RangeToInclusive>>::index`
(core's `Index`, by its exact path) → `leaf::slice_index_to`, `_from`,
`_range`, `_to_inclusive`, the array leaves' definitions over the slice
itself (its length in place of `N`): the sub-slice, or `None` — rustc's
panic — unless the range lies in the slice. S read them already
(`&s[i..]`); L read them as unmodeled, so a function that sub-slices a
slice had no theorem (the printed residual of held-out v1's `read_u32_le`,
development data: `&l0_data[l1_offset..]`).

### 2.6 The library (`literal.core`, trusted, 186 code lines with the leaves; 170 before stage finish-A, 139 before stage reader-widen)

| definitions | what they are |
| --- | --- |
| `mir::Infallible`, `mir::Tuple1`, `mir::ControlFlow` | types MIR uses that the subset has no counterpart for |
| `mir::Proj` | reference code projections |
| `rc::fst`, `rc::snd` | the parts of a code |
| `mir::slt` / `sle` on `u8` / `u64` | signed comparisons of bits |
| `mir::bind`, `mir::map`, `mir::guard` | the monad |
| per width: `mir::checked_*`, `*_unchecked`, `div`, `rem`, `shl` / `shr_unchecked`, `cmp` | arithmetic |
| `mir::array_get`, `mir::array_set` | indexing: the prelude's `array::index` / `array::set` under the bound test, the test's equation their premise (stage cs-integrate: `array_get` no longer recurses through a proof-free `mir::nth`) |
| `mir::bswap_u16` / `u32` / `u64` / `usize` | the byte swap by shifts and masks |
| `mir::scheck_add_*`, `mir::scheck_sub_*` on `u8`..`u64` (stage reader-widen) | a signed type's `CheckedAdd`/`CheckedSub` on its bits: the wrapped bits and the overflow flag (the sign bit of `(a ^ r) & (b ^ r)`, `(a ^ b) & (a ^ r)`) |
| `leaf::slice_iter_new`, `leaf::slice_iter_next`, `leaf::slice_get_range` (stage reader-widen) | the models of core's slice iterator and of a slice's `get` by a range (§2.5) |
| `leaf::slice_index_to`, `_from`, `_range`, `_to_inclusive` (stage finish-A) | a slice's sub-slices by core's `Index` (§2.5): the array leaves over the slice |

There are no lemmas. The library is total and proof-free except for
`array_set`'s bound premise.

---------------------------------------------------------------------------

## 3. The theorem

For each lifted function `f` with structured reading `S_f` (parameters
`x̄`, preconditions `h̄`), the trusted statement is generated by
`mir::stmt` (the prototype's `simproof::StmtSpec`):

```
L::thm::f : Π x̄ (.h̄ : pre(x̄)).
  Σ (k : Int). Π (n : List(Unit)) (.hle : Eq(Bool, #le_int(k, seq::len Unit n), true)).
    Eq(Option(Out_f), L::f::run n b0 (Some(init(x̄))), Some(erase(S_f x̄ .h̄)))
```

**`init(x̄)`.** Slot `i` holds the `i`-th parameter:

* `Some(erase(x_i))` for a value or shared-reference parameter;
* the code `(rc<j>, [])` for the `j`-th `&mut` parameter, whose cell holds
  `Some(erase(x_i))`;
* `None` for every other local.

**`erase`.**

* It is the identity on types L and S share.
* A module type whose S declaration carries invariant proofs is mapped to
  L's mirror. The mirror's constructor is applied to S's projections of the
  relevant fields, `match x with C(a0, a1, .p2) ⇒ a0`. These are the very
  terms S uses, which the proofs rely on.
* S's result is a tuple `(final &mut referents…, return value)`, which is
  S's state passing. It is erased component by component, in the same
  order as L's `Out`.

**Meaning.** For every input satisfying S's preconditions there is a bound
`k`, such that L, the meaning of rustc's MIR, run with any fuel of at least
`k` units returns `Some` of exactly S's value. The value includes every
`&mut` parameter's final referent. `Some` means:

* every block reached was executed with no assertion failure, panic,
  undefined behaviour or unmodeled case;
* the run finished after finitely many back edges (bounded by `k`).

Some list of length `k` exists, so the MIR run terminates. This is total
correctness relative to S, the same object the laws are about.

**What the statement does not say.** It says nothing about inputs outside
S's preconditions. Callers establish those as today: obligations at every
call site, in S.

---------------------------------------------------------------------------

## 4. Soundness

**Claim.** Assume the kernel accepts `L::thm::f`. Then for every input
satisfying `pre`, the compiled `f` terminates without panic and returns
the value S computes, with S's final `&mut` referents.

**Argument.** rustc compiles the MIR that `mirx` printed (A4). L is that
MIR's meaning (A1–A3, A5, A8). The theorem says L returns S's value at
sufficient fuel. By A2, the MIR run terminates with that value.

### Assumptions (the trusted base after this change)

* **A1. L's generator and library mean MIR.** 1,297 + 186 code lines (§7; 1,287 + 170 before stage finish-A, 1,217 + 139 before stage reader-widen). Each
  construct's reading is local and checkable against the MIR reference by
  a reader.
* **A2. Fuel adequacy.**
  * The claim: if `run n b σ = Some(v)` for some `n`, the MIR execution
    from block `b` in state `σ` terminates with `v`.
  * Why it holds: `run`'s arms are the blocks' effects in order. Fuel only
    gates jumps into headers and self-calls, and its exhaustion is `None`.
    Calls run the callee's `run` on the same fuel. So a `Some` is the result
    of a finite execution.
  * Status: a meta-argument about the generator's output, not a kernel
    fact. It is the same kind of claim as A1.
* **A3. The reference model.**
  * State passing of `&mut` referents, write-back at return, and snapshots
    for shared references are exact for borrow-checked MIR of the subset:
    no interior mutability, no raw pointers, no `unsafe`
    (`#![forbid(unsafe_code)]` on every verified module).
  * The returned-reference translation of §2.4 relies on the same
    exclusivity.
  * This replaces today's trust that `read.rs`'s state passing is right,
    with the same assumption made once, generically.
* **A4. `mirx` prints rustc's MIR** (1,131 lines; unchanged). It is
  extracted at the pinned release (`docs/mir-lift.md` §2).
* **A5. Host models and leaves** mean what the host functions do. This is
  unchanged, and they are the same model functions S uses.
* **A6. The kernel**, unchanged. No new prelude definitions beyond L's
  library, which is counted in A1.
* **A7. The statement generator** (`mir/stmt.rs`, 234 code lines; 210 before the panic statement of DESIGN.md §8.2 item 12). The theorem text, `init` and `erase`,
  about 0.2k lines, decide what the theorem says. They are small and
  regular, and a reader checks them against §3. Its preconditions are
  `S_f`'s; the elaborator makes them the declared contract's (checked,
  below).
* **A8. Targets.** Little-endian, 64-bit `usize`, as today
  (`transmute` to bytes, `isize` as `U64`).

**Checked, not assumed** (stage tcb-checks; both were recorded as
assumptions before):

* *Module types are declared alike.* L reads field `i` of a module type
  as the MIR numbers it, S as the subset's declaration does, and the
  kernel's field names are positional, so a theorem cannot tell two
  differently named fields apart. The gate's trusted check compares, for
  every module type the function's MIR instances reach, the MIR's
  adt-def with the lifted crate's declaration (variants and fields by
  name and in order, discriminants `0, 1, ..`).
* *Preconditions are the declared contract's, by content.* The elaborator
  elaborates a function read from MIR only when each precondition is
  α-equal to the elaboration of the declared clause, which the lift
  carries apart (`#[mir_contract(..)]`, `hir::FnDef::declared`), whatever
  the binders are named.
* *Each listed function's MIR instance is that function* (stage
  tcb-review). The lift finds an instance by its unqualified lifted name;
  the gate requires the instance's lifted name in the DSL module of its
  item to be the listed function (`ModuleNames::instance_global`).
* *A statement rests on its own extraction's reading* (stage tcb-review).
  L's names restart with each extraction's reading, and the kernel lets a
  later definition take over a name; the gate's check 3 counts only the
  load of L's library and the function's own extraction's.

**No longer trusted:**

* `read.rs`, the structurer, kept as an untrusted proposer of S;
* the walker `simproof.rs`;
* every structuring decision (loop placement, inlining, value shapes);
* S's correspondence to MIR (now a theorem).

**`None` cannot hide a bug.** A construct L reads wrongly as `None` only
loses theorems. A construct L reads wrongly as a *value* is an A1 bug, the
same class as a `read.rs` bug today, but in about 1k lines of local
translations instead of 2.4k lines of symbolic structuring.

**Checks of L itself** (defence in depth for A1):

* **Conformance.** The same kernel-vs-rustc runs as today, applied to L as
  well as S.
* **Fault injection.** Changing one constant of the MIR (the prototype's
  `CS_FAULT`) must make the walk fail. Measured: `feed` with 7→6 and
  `read::<u32>` with 128→64 both fail.

---------------------------------------------------------------------------

## 5. Proof generation (untrusted, `simproof.rs`)

### 5.1 Lemmas with explicit fuel

The trusted statement is derived from an intermediate lemma whose fuel is
explicit.

**Function lemma.**
`Π x̄ h̄ (n) (.hle : W(x̄) ≤ len n). Eq(…, run n b0 (Some init), Some(erase(S x̄)))`.

* `W` is the **fuel shadow**: S's body with every tail replaced by the fuel
  it needs. A value needs 0. A call of a loop helper `h` needs `μ_h(ā) + 1`,
  where `μ_h` is S's own measure and the `+1` is the loop entry.
* The shadow keeps S's lets and matches, so it reduces along S's splits.
* A function that calls no loop helper has `W = 0`. Its lemma holds at
  every fuel and is the one callers use as a callee lemma.

**Loop-helper lemma.** For S's tail-recursive helper `h` of the loop with
header `H`:
`Π p̄ (j̄ : dead slots) (n) (.hle : μ_h(p̄) ≤ len n). Eq(…, run n H (Some σ(p̄, j̄)), Some(erase(h p̄)))`.

* It is proven by **measure recursion with `h`'s own measure**.
* Each recursive call of `h` in S is the induction hypothesis
  (`Rec(args, slots at H, n1, pf)`), with **S's decrease proof reused as
  the recursion's decrease proof**. A machine-width measure is cast to
  `Int` in the premise.
* `σ` places `p̄` in the live slots (`l14 = decoder`, `l2 = byte`,
  `c0 = buf`, `l1 = code`).
* Every other slot is a universally quantified junk binder. At each
  recursive call it is instantiated with the slot's actual value at the
  header.

**Trusted theorem.** `pair(W(x̄), λ n .hle. lemma x̄ n .hle)`.

### 5.2 The walk

The walker mirrors S's term.

* **Lets** are bound again with their values. Their checked primitives'
  proofs become facts:
  * the obligation, as a reused proof;
  * for `+ − ×`, a **bridge** `bits::w*_exact_w`, which rewrites a
    wrapping operation of L into S's checked one using S's proof.

  Calls of lifted functions with lemmas become **call facts**. The proofs a
  call passes, the callee's preconditions instantiated, become facts. These
  are collected through let bodies and inside transparent callees' bodies.
* **S's splits.** The first match of the dependent idiom in evaluation
  order whose scrutinee is stuck, in the term or in a let's value or a
  constructor argument.
  * The literal side is abstracted over the scrutinee by evaluation.
  * The structured side becomes `K[M(y) e]`: the match on `y` applied to
    the path equation, in the match's context `K`, the way `f::ensures` is
    written. In each arm it is `K[arm]`. S's own proofs are never
    rewritten.
  * A scrutinee whose value is a constructor is reduced (iota). One the
    literal side does not hold, such as `ord_lt(pc)` while L tests `pc`
    itself, is still split. The literal side is split later, and the arm
    that contradicts the path is refuted by evaluation.
* **`absurd` leaves** reuse S's proof.
* **Eta.** A struct-typed parameter is split into its fields. A field that
  an invariant field's type mentions is not split.

### 5.3 Moving the literal side (`advance`)

Applied before each split and at each tail, to a fixed point:

1. **Callee lemma.** L's folded call `run_g n b0 init_g(ā)` is transported
   to `Some(erase_g(g ā))` along the callee's lemma. This is skipped when
   the call's value already converts with it.
2. **Bridge.** `#wadd(a, b)` → `#add(a, b; p)`, along `bits::wadd_exact`
   with S's obligation `p`.
3. **Fact.** A stuck test is decided by a fact `x = C(…)`: a path equation,
   an obligation proof or a precondition. Every scrutinee in the stuck
   chain is tried, so `proj1(F)` as well as `F`.
4. **Literal eta.** A non-projection match on a neutral struct, such as a
   call's or a leaf's result tuple, is rewritten to its projections. This
   uses a one-arm match proof, `L[F] = L[C(proj F)]`.
5. **Unfold.** A folded run whose body holds the test is unfolded by its
   `delta` equation. A folded recursive call does not convert with its
   unfolding under the speculative policy, so a plain syntactic expansion
   is rejected by the kernel; this was measured.

### 5.4 Tails

* **`refl`** when the two sides convert.
* **Refutation** of an impossible path, three ways:
  * a constructor clash of two facts;
  * `linarith` over comparison, `Int` and list-length facts;
  * evaluation: a fact `t = D` whose left side, rewritten with the path
    equations, evaluates to another constructor, such as
    `ord_lt(pc) = true` with `pc = Some(v)` and `v = Equal`.
* **L-split** on L's own test, past projections and structs, to the first
  match on a value with several constructors.
* **Word repair.** Both sides are values that differ only in machine-word
  subterms, such as `cast(bswap(x) >> 8k)` against S's big-endian
  `cast(x >> (56 − 8k))`. Each pair is equated by `bvrefl`, the kernel's
  word normalizer, and the literal side is rewritten. This closes the
  SHA-256 boundary: `to_be_bytes` in MIR is `bswap` then a little-endian
  `transmute`, and S uses the prelude's big-endian bytes.
* **Fuel split** when L waits for fuel:
  * `Nil` contradicts the premise (`linarith`);
  * under `Cons(u, n1)`, a helper call steps L to the header with runs
    kept folded, decides the header state with the facts, and applies the
    helper lemma (`μ(ā) ≤ len n1` by `linarith`);
  * a recursive call is the induction hypothesis.
* **Non-tail self-calls**: §5.6 (implemented in stage cs-walker).

### 5.5 Caching

Proofs are kernel terms. The verdict cache stores the theorem's acceptance
keyed by:

* the hash of S's definition and those of its transitive callees;
* the hash of the function's MIR text in the `.sbmir`;
* the hash of the library;
* the hash of the generator version.

Like other verdicts, nothing is re-walked or re-checked when those are
unchanged.

### 5.6 Non-tail self-calls (stage cs-walker)

* **The lemma.** For a measure-recursive `S_f` (its pre-commit body and
  measure `μ` are in `elab::Output::pre_commit`):
  `L::lem::f : Π x̄ h̄ (n) (.hle : mult·μ(x̄) ≤ len n). C`, by measure
  recursion with `μ`; `mult` is the number of self-call sites of the MIR
  (each consumes one unit of fuel and calls on a smaller measure, so the
  `j`-th self-call on a path, `j ≤ mult`, has fuel `len n − j ≥ mult·μ(ā)`
  left). The premise does not depend on S's position, so it is a
  hypothesis of the whole walk (`prem_in_ctx`), not part of each goal.
* **At a `let` whose value holds a self-call** (`Rec`), the literal side is
  moved to the call before the `let` is walked: `advance` (callee lemmas,
  unfolds), then a split the literal side waits for: the fuel (a split of
  `n` mid-walk; `Nil` contradicts the premise with the pending call's
  decrease) or a parameter (`collected`, split on both sides). There the
  induction hypothesis `Rec(ā', h̄', n1, fuel)` is a callee lemma: the
  literal `run n1 b0 (Some st(..))` is transported to `Some(erase(S ā'))`;
  the `Rec`'s decrease proof is the lemma's own obligation, derived by
  `linarith` from S's decrease proof and the measure's congruence along the
  eta splits (S's proof is about `height(Subtree(f0, f1, f2))`, the
  obligation about `height(x0)`).
* **Its arguments** are S's own (committed); the literal side's state at the
  call must convert with `init(ā')`, which is why the parameters and the
  results the call is given are split first.

### 5.7 `Option<&mut T>` parameters: the presence conjunct

The literal side writes an optional cell back only when the caller's code
is present, and fails if the callee lost the referent. The induction
hypothesis alone cannot show that S's result keeps it: that is an inductive
property of S. So a function with optional cells proves the conjunct

`Pres := Eq(Bool, is_some(x_j), is_some(proj_j(S x̄)))` (per optional cell)

with the equation (`C := Sigma(_ : Eq(..)). Pres`); at its tails it holds
by evaluation once the parameter and the results are split. At a call, the
callee's (or the hypothesis's) conjunct is a fact; a `let` of the result's
component is split on (`let_split`: the facts leave one constructor; the
literal side is abstracted over the value, the `let`'s variable is that
constructor in S's body, the other arm is refuted). The trusted theorem
takes the equation (`fst`).

### 5.8 Fuel-dependent callees

A callee whose lemma needs fuel (`W_g`, its own need over its telescope)
cannot be used at every fuel. The caller's fuel shadow accumulates the
needs of the calls of the `let`s walked: `shadow(let x = v; b, acc) =
let x = v; shadow(b, acc + W(v))`, a tail `acc + its need` — so the goal
of the `let`'s body has the same premise as the `let`'s and the walk's
`let` step needs no rewriting. The callee's lemma needs `W_g(ā) ≤ len n`:
inside a terminal it follows from the premise by `linarith` (every summand
is a machine-word measure, a length or a literal); at a split before it,
the lemma waits, and the callee's run is kept folded (no unfold, eta or
fact decision inside it) so the lemma still finds the call. Shown on
`UInt<u32>::read_cfg` over `read::<u32>`.

### 5.9 Refutation and splits

* **Refutation first.** At every walk step the newest path equation is
  checked against the others (a constructor clash; a fact rewritten by it
  to another constructor); an equation at a one-constructor type (an eta
  split's, a fuel split's) decides nothing and is skipped. Before every
  split of the literal side the full search runs: clash, `linarith`, and
  every fact rewritten by the others (written, and evaluated: a `let`'s
  variable or a transparent call's body holds the tests).
* **Rewriting through S's idioms.** A fact's side that holds a dependent
  match on the rewritten value, `(match c as z return Π(.h : Eq(D, c, z))..)
  .refl(c)`, is rewritten with the idiom's path equation bound
  (`Π(q : Eq(D, c, y))`; `refl(c)` and `q` agree by proof irrelevance)
  and the fact's own proof given after the transport — the S-split's own
  construction, applied to a fact (an abstraction of `c` everywhere would
  leave the idiom's arms, whose proofs are about `c`, ill-typed).
* **Splits on both sides.** A test of the literal side on a parameter is a
  split of the variable (L, S, the presence inputs, the right side; a
  proof of the context about it transported along the path equation, as
  eta does). Inside a terminal, a split of the literal side's test
  abstracts the structured value too when it waits for the same test (a
  transparent callee's comparison), and with the literal side a value
  the structured side's own test is split on.
* **Abstraction safety.** Abstraction by conversion over-abstracts unit
  constructors and leaves dependent idioms and proofs about the abstracted
  value inconsistent; the walker repairs unit constructors (in typed
  positions too) and idioms on the abstraction variable, checks the result
  where S's terms are involved, and otherwise falls back (a literal eta
  abstracts only the literal side's own matches, by position).

### 5.10 Sharing (proof size)

The walker quotes the literal side afresh at each step, so its proofs are
trees of repeated subterms. Hash-consing (structurally equal subterms one
node) is applied to S's body before the walk (every shift and commit of it
is then linear in its graph) and to every lemma before the kernel checks
it: `reconstruct_digest` 2,020,051 → 25,433 distinct nodes (kernel 1.94 s
→ 0.66 s), the MMR loop lemma 152,406 → 6,482 (0.44 s → 0.28 s),
`node_digest` 28,524 → 997 (0.10 s → 0.03 s). The motives are where the
duplication was (65% of `reconstruct_digest`'s nodes before sharing,
measured by `CS_PROFILE`).

### 5.11 Budget and diagnostics

Each function's walk has a deadline and a step budget (`Prover::budget_secs`,
`Prover::max_steps`; `CS_BUDGET_SECS`, `CS_BUDGET_STEPS`). A failure names
the function and the point: the path of S's splits (`S-split on <scrutinee>
= <constructor>`), `let`s, variable and fuel splits, the tail; both sides
(the literal side evaluated); at a tail mismatch, the path equations. A
walk failure is a toolchain error, like a failed obligation.

### 5.12 `while` loops (stage cs-integrate)

The elaborator's `while` helper `h = <f>::loop#k` returns the variables the
loop assigns; the function continues after it. Its lemma is a hand-over
from the header `H` to the exit `X` (the one successor of the natural loop
outside it):

```text
Π p̄ j̄ (n) (C) (hC : Π m (.hm : len n − μ(p̄) ≤ len m) k̄ c̄ (.ez : h p̄ = tuple(c̄)).
        Eq(run m X (Some σ_X(c̄, w̄)), C)) (.hle : μ(p̄) ≤ len n).
  Eq(run n H (Some σ(p̄, j̄)), C)
```

* `p̄` all of `h`'s parameters; the slots of the relevant ones by the
  reading's names of the MIR locals (`HelperInfo::local_names`); `j̄` every
  other slot. The loop's variables are the parameters a recursive call
  changes (the result's components, in order); `σ_X` puts the components
  `c̄` in their slots, the slots of the other parameters as at `H`, the
  slots the loop's body assigns (statements, call destinations, cells
  written through a code derived from a `&mut` parameter) from `k̄`, and
  the others from `j̄`.
* The walk is `h`'s pre-commit body with `eqS : h p̄ = S` in every goal
  (`Π(.eqS). Eq(l, C)`); S's splits keep it well-typed. A value tail
  (`tuple(ā)`) steps the literal side to `X` (every run folded) and applies
  `hC n hm k̄ ā eqS`; a recursive call `rec(ā')` after the back edge's fuel
  split is the induction hypothesis with `C` and `λ m hm' k̄ c̄ ez'. hC m hm''
  k̄ c̄ (eqS · ez')`, `hm''` by `linarith` from `hm'`, the fuel split and S's
  decrease proof.
* At the function's `let loop = h(ā); rest` (the shadow there: `μ(ā) + 1`
  plus the rest's need), the lemma takes `C` = the goal's right side and
  the continuation that walks `rest` from `X` with `loop = tuple(c̄)` (along
  `ez`; the rest's `h_loop`, its post-state proven at `ā`, a hypothesis of
  that motive).

### 5.12a Loops of the reader widening (stage reader-widen)

* **A `while` of several tests** (`while a > 0 || b > 0`): S joins the tests
  without short circuit (`(a > 0) | (b > 0)`, one test of each); the
  lemma's exit is reached by the literal side's own tests in turn, each
  split (`split_test`, forced) with the arm against S's path refuted.
* **A loop inside another loop** that is not `while`-shaped is a helper
  that returns the parameters it assigns (`HelperInfo::returns`); its
  lemma is §5.12's, with `returned` naming the result's components.
* **Measures** of loops without an attachment are guessed by the reader
  (untrusted); the elaborator proves their decreases.

---------------------------------------------------------------------------

### 5.12b Nested loops: fuel functions (stage reader-widen)

In a function with a loop inside another, a loop's measure no longer
bounds the fuel its lemma needs: the outer loop's body runs the inner loop,
whose fuel varies with each iteration, and an inner loop's exit may jump to
the outer header, which costs a unit of its own. Each loop helper of such a
function gets a **fuel function** (`checked.rs`'s `fuel_fn`, untrusted):

```text
L::fuel::<id>_<h> : Π p̄. Int        (opaque; measure recursion with h's measure)
  := the fuel shadow of h's body: a recursive call 1 + F(ā), an inner loop's
     call its fuel + 1, the loop's exit e (1 when it jumps to an outer
     loop's header), callees' needs accumulated down the lets
L::fuelnn::<id>_<h> : Π p̄. 0 ≤ F(p̄)   (the same recursion: the body's
     matches, leaves by linarith from the recursive calls' and inner loops'
     nonnegativity)
```

`F`'s recursive calls carry S's own decrease proofs (its body keeps every
binder of S's on the way to them). The lemmas then state `F(p̄) ≤ len n` (a
tail helper) or, for §5.12's `while` lemma, a **reserve** `R` the caller
chooses, the fuel the rest of its body needs after the loop:

```text
Π p̄ j̄ (n) (R : Int) (C) (hC : Π m (.hm : R ≤ len m) k̄ c̄ (.ez). Eq(run m X σ_X, C))
    (.hR : 0 ≤ R) (.hle : F(p̄) + R ≤ len n). Eq(run n H σ, C)
```

The walk's premise is the shadow of the rest of the body (`delta(F; p̄)`
at the start): a recursive call needs `F(ā) + R` after the back edge's
unit, the exit `R` after its own (a fuel split when it jumps to a header),
and the induction hypothesis passes `R`, `hR` and `hC` on unchanged, so no
arithmetic relates the exit to the start. A caller's continuation walks the
rest from `X`, which for an inner loop may be the outer header itself: a
loop's call whose literal side is at its header already is its lemma (or
the induction hypothesis) at once. The continuation keeps a recursive call
of the rest as `Rec`, its type is the lemma's instantiated (not evaluated:
the header's code would run), and at the exit the continuation's state
meets the literal side's along `refl` of the two states (a slot the walk
split by eta converts as a state, not once the run is unfolded). Functions
without nested loops keep the measure (their lemmas and proofs unchanged).

---------------------------------------------------------------------------

### 5.13 The shipped code (stage cs-storage, plan step 8)

The emitted file of a rewritten module is the lifted round trip's copy, so
the round trip's MIR (`<stem>.roundtrip__<module>.sbmir`) is the code rustc
compiles. For a rewritten `f` with replacement `g` and the optimizer's link
`equiv : Π x̄ h̄. Eq(R, f x̄ h̄, g x̄ h̄)`:

```text
L::thm::<helper>  : the helper's MIR against the definition the round trip compared it with
L::thm::<copy>    : the copy's MIR against g          (structured side: the call g x̄ h̄)
L::shipped::<copy> : Π x̄ (.h̄ : pre_f). Σ k. Π n (k ≤ len n).
                      Eq(Option(Out), run_copy n b0 (Some init(x̄)), Some(erase(f x̄ h̄)))
```

`L::shipped` is §3's statement (from `mir/stmt.rs`, with `f`'s declared
contract) of the copy's instance against `f`; its proof transports
`L::thm::<copy>` along `sym(equiv x̄ (promote h̄))`. The literal reading of
the copy continues the gate's (`elab::Output::mir_gate`): the instances
both extractions hold are reused, and must be the same MIR. The helpers are
proven callee-first; each one's lemma replaces the gate's callee lemma of
the same definition (`Prover::replace_callees`: the copy calls the helper,
not the original alternative).

**These theorems decide** (stage finish-A). Until then the round trip also
compared the copy's structured reading (`read.rs` on the copy's MIR,
elaborated in generated mode) with the replacement, syntactically, and
proved the theorems only for what passed. Nothing in that comparison is
needed: the structured reading of the copy is an untrusted proposal, while
`L::thm::<helper>` and `L::thm::<copy>` relate the literal reading of the
copy's MIR — what rustc compiles — directly to the definitions the
comparison compared it with, and `L::shipped` composes them with the
optimizer's kernel-checked link into the statement the laws need, which
the trusted check accepts or refuses. So for a module read from MIR the
round trip runs no comparison (`driver::lowered::round_trip`; the front end
still reads the copy with its MIR, whose load checks the copy's text by its
SHA-256). The comparison refused correct code: the reading of a printed
residual binds rustc's temporaries by `let`, tests `checked_add`'s
`Option` with `is_none` and reaches sub-slices through `Index`, so it
differed from the residual it computes (held-out v1, development data:
`next_power_of_two`, `read_u32_le`, `mix64`). Two walker gaps showed on the
way, both fixed in `simproof.rs` (untrusted): an S-split's path equation
states its scrutinee committed with `let`s (the quoter's sharing), so
refutation by evaluation now evaluates a `let`-headed side too, and
abstracts the tested term inside `let` bodies (`abs_syn`), which refuted
`next_power_of_two`'s overflow arm against L's no-overflow path; and L read
a slice's sub-slices as unmodeled (§2.5, now `leaf::slice_index_*`). Tests:
`tests/lift_opt.rs` `a_rewrite_whose_shipped_mir_differs_only_syntactically_is_accepted`
(fixture `opt_shipped`: three rewrites the comparison, run beside the
theorems by the hook `LowerFault::CompareStructurally`, refuses, each
shipped with its `L::shipped::<id>` and agreeing with the source under
rustc) and `a_wrong_shipped_copy_is_refused_by_the_theorem` (the copy's MIR
read with one constant off: the theorem fails, the source stays);
`tests/literal.rs` `a_slices_index_by_a_range_is_the_subslice_or_a_panic`
(the four slice leaves, their values and panics, with a crate's own range
type and a crate's own `Index` as negative twins).

## 6. Fit with the rest of the toolchain

* **Elaborator.** Unchanged for S. Per lifted function, it adds:
  * L's items, loaded once per module from the generator's text through
    `load_core`;
  * the function's lemma and theorem, as `DefKind::Lemma`, after S's
    definition.

  `read.rs`'s measure-recursive helpers need their pre-commit body and
  measure; `replace_rec` drops the decrease proofs at commit. The prototype
  recorded them in a side table at `add_definition` (`items::PRE_COMMIT`);
  production keeps them in `elab::Output::pre_commit`, next to the
  `DefRecord`s (which cross threads and so cannot hold kernel terms).
* **Verdict cache.** New entries per function, keyed as in §5.5
  (namespace `theorem`). Since stage tcb-gate an entry holds the proof's
  declarations, replayed through the kernel and then checked by the
  trusted check like a fresh proof, so neither the entries nor the keys
  are trusted.
* **The gate** (stage cs-integrate): `driver::gates::theorem_gate`, after
  the §15 gates of every verified build (and of the pending-gates build,
  since deleted);
  `docs/mir-lift.md` §20.6. Its verdict is the trusted check `mir/gate.rs`
  (stage tcb-gate).
* **Conformance** (`sandblaster conform`, kernel vs rustc). It stays. It
  checks A1/A4/A5, which the theorem cannot. It becomes cheaper to make
  meaningful: running L in the kernel on the same inputs compares L with
  rustc directly, while S vs rustc becomes a consequence of the theorem.
* **Optimizer.** Unaffected. It replaces S by its kernel-checked residuals
  (and, apart, by user-supplied alternatives under proven `#[rewrite]`
  lemmas: user code, reported separately, DESIGN.md principle 3). The
  theorem is about the source's S, and the optimized code's correctness is
  the optimizer's own theorem, composed by transitivity.
* **Lowered round trip.** The round trip reads back a rewritten file's MIR
  (`<stem>.roundtrip__<module>.sbmir`). The same generator and walker give
  `L_roundtrip = erase(S_lowered)`. With the optimizer's `S_lowered = S`
  lemma, the shipped code's MIR provably computes what the laws describe.
  Today the round trip is trusted structuring of the copy; with this design
  it is a theorem (stage cs-storage, §5.13: `L::shipped::<id>`).
* **Error reporting.** A walk failure names the function and the point:
  the S split or tail, with both sides printed. It is a toolchain error,
  like a failed obligation, not a user proof failure. A theorem must
  exist for every lifted function before the trust claim holds. A gate
  lists functions without one.

---------------------------------------------------------------------------

## 7. Trusted lines, before and after

Code lines are counted with the docs' convention: no blank lines,
comments or tests. The script used reproduces `docs/mir-lift.md` §5 exactly:
`read.rs` 2,397, `mod.rs` 430 (432 with the prototype's two module lines),
`mirx` 1,131.

| | before | after (stage cs-assurance: measured, with the review's fixes) |
| --- | --- | --- |
| structurer `mir/read.rs` | 2,397 | 2,433, **untrusted** (checked by the theorems); 2,975 measured now (stage cleanup, after reader-widen and finish-A) |
| `mir/cfg.rs` | untrusted | 298, untrusted (stage tcb-literal: + the literal reading's ranks, loop headers, panicking blocks and type-occurrence pruning, 63 lines; 235 before) |
| walker `mir/simproof.rs`, driver `mir/checked.rs` | — | 4,565 + 1,674, untrusted (stage tcb-gate: the gate's trusted part moved to `mir/gate.rs`); 5,014 + 1,889 measured now (stage cleanup) |
| `mir/mod.rs`: `load` checks and names (subset type names, host models) | 430 | 491 (L's names: `kernel_adt`, `is_transparent`, `host_model_method`, host enum paths; stage tcb-review: + `instance_global`, 10; the read.rs names stay until `read.rs` leaves); stage reader-widen: 531 measured (498 before it: + the models' selection, `slice_iter_elem`, `Model`, `MODEL_FNS`, `model_of`, and the slice iterator's subset type, 33) |
| L generator `mir/literal.rs` | — | 1,217 (stage tcb-literal, with byte-identical output; 1,474 before it; prototype 1,905; stage cs-storage: + data-free reads; cs-assurance: + the review's fixes); stage reader-widen: 1,287 (+70: the models' calls `model_call` and the shared `state_leaf`, signed `CheckedAdd/Sub`, the rotations, the bytes-to-word `transmute`, the one value of an enum whose other variants are empty); stage finish-A: 1,297 (+10: a slice's sub-slices by `Index`) |
| L library `mir/literal.core` | — | 139 non-comment lines (stage cs-literal: 141; `mir::nth` removed, `array_get` and the inclusive-range leaf changed); stage reader-widen: 170 (+31: `mir::scheck_*`, `leaf::slice_iter_new`/`next`, `leaf::slice_get_range`); stage finish-A: 186 (+16: `leaf::slice_index_to`/`_from`/`_range`/`_to_inclusive`) |
| statement and `erase` `mir/stmt.rs` | — | 210 (stage cs-storage: + core types S models by prelude structs, the model lemmas' statement; stage tcb-checks: − the precondition name rule, 225 before); stage optimizer-generic: 234 (+24: the panic statement of DESIGN.md §8.2 item 12) |
| printer `mirx` | 1,131 | 1,131 (unchanged) |
| lift glue (`lift.rs`'s `#[lift(mir)]` path) | about 0.2k | about 0.26k (+ the declared contracts, the loaded MIR and the helpers' record in the lift's facts) |
| the gate's trusted check `mir/gate.rs` and its call sites in `gates.rs` and `lowered.rs` (stage tcb-gate; before it, ≈ 650 lines of bookkeeping: `theorem_gate` and its report ≈ 80, `checked.rs`'s planning, cache keys, acceptance and round-trip acceptance ≈ 500, `lowered.rs` ≈ 70) | — | 164 + ≈ 25 (stage tcb-review: + check 0, the instance is the function, and check 3 per extraction, 6; stage tcb-checks: + the module types' declarations, 33; 125 before); stage optimizer-generic: 232 (+68: the panic acceptance, checks 5 and 6); stage finish-A: the call sites in `lowered.rs` keep the requirement as it was (moved into `shipped_theorems`), and the structural comparison they no longer run for a module read from MIR was never part of this count |
| the elaborator's precondition check (`elab/items.rs` 22, `typeck` 16, `hir.rs` 1; stage tcb-checks) | — | 39 |
| `ir.rs` + `sexp.rs` (they feed L: trusted, amendment (d)) | untrusted | 482 + 131 = 613 (cs-assurance: no defaults, order checks) |
| **total trusted** (`read.rs` before, L after the gate) | **about 4.2k** (`ir.rs`/`sexp.rs` not counted; ≈ 4.8k with them) | stage finish-A: **about 4.6k** = 531 + 1,297 + 186 + 234 + 1,131 + ≈ 260 + ≈ 261 + 39 + 613 = 4,552 (+26: the slice leaves; stage optimizer-generic's panic statement and acceptance, +92, counted here for the first time); stage reader-widen: **about 4.4k** = 531 + 1,287 + 170 + 210 + 1,131 + ≈ 260 + ≈ 189 + 39 + 613 = 4,430 (+134 in this stage, `stmt.rs`, `ir.rs`, `sexp.rs` and `gate.rs` unchanged; + 7 lines of `mod.rs` since the last count); before it **about 4.3k** = 491 + 1,217 + 139 + 210 + 1,131 + ≈ 260 + ≈ 189 + 39 + 613 = 4,289 (stage tcb-review, two checks the review found missing: +16; stage tcb-checks, two assumptions made checks: +55; ≈ 4.2k after stage tcb-literal, ≈ 4.5k after stage tcb-gate, ≈ 5.0k before it); **≈ 3.7k** counted as before (without `ir.rs`/`sexp.rs`). What changes is also its kind: local, construct-by-construct translations and one check of what the kernel holds replace 2.4k lines of symbolic structuring |

**Why the generator is 1.2k and not 1.0k.** Stage tcb-literal took it from
1,474 to 1,217 with the same output (the log has the breakdown and the
levers it did not use); what follows explains the 1.45k it started from.
The design's estimate (below)
left out the type map (library types, module types, host models, mirrors,
constructors by name: ≈ 0.2k) and the text helpers (≈ 0.1k); the reference
model grew by nested cells and returned-code translation (≈ 0.1k), and the
rvalue tables by signed bits and the leaves (≈ 0.1k). By part, measured at 1,474:
type map and helpers ≈ 300; places and reference codes ≈ 300; calls with
the cell protocol ≈ 200; rvalues, operators, casts and their tables ≈ 270;
terminators, dispatch, fuel, rank ≈ 180; emission ≈ 130; leaves ≈ 70.

The design's estimate, for the record:

| part | lines |
| --- | --- |
| places and reference codes (follow, update, borrow, deref and write functions per type) | about 250 |
| calls with the cell protocol (init, write-back, returned-code translation) | about 250 |
| rvalues (operators, casts, aggregates, discriminants) | about 200 |
| terminators, switch dispatchers, fuel and rank | about 150 |
| emission of `St`, accessors, `Blk`, `run` | about 150 |

Two levers reduce it further:

* moving per-construct templates into library combinators (counted, but
  each a few reviewable lines);
* generating accessors from one generic definition over a slot list.

(Stage tcb-literal looked at both: neither saves lines without changing
L's text, because each template is already one line of Rust. The log
says why.)

**Growth.** L grows only with new MIR constructs and leaves, about 10–30
lines each, never with structuring idioms. A new `read.rs` heuristic costs
nothing in trust.

---------------------------------------------------------------------------

## 8. Measured numbers

Release build (`cs_proto`, one thread, Apple M-series, memory capped by
memguard at 6 GB). The S elaboration is the filtered elaboration of the
named items and their dependencies.

### 8.1 varint: `read::<u32, &[u8]>` (targets 1 and 4)

`read::<u32>`'s MIR calls core's `map_err` with a closure (`|_| EndOfBuffer`),
`Try::branch` and `FromResidual::from_residual` (the `?`), the
`Buf::try_get_u8` leaf, `Decoder::<u32>::new` and `feed` through a `&mut`,
and loops back to `feed` (header bb10).

| item | value |
| --- | --- |
| S elaboration (21 items: `new`, `feed`, `read__u32`, `read__u32__loop0` and deps) | 2.3 s, 99 defs, 1,245 obligations |
| L (17 MIR functions, including core's `map_err`, both closures, `branch`, `from_residual`, `u32::from`, `checked_sub`, `leading_zeros`, `Shl`, `BitOrAssign`) | 388 items, 694 lines, 300,882 bytes; kernel check 0.03 s |
| `Decoder::new` theorem | 104 nodes; check < 1 ms |
| `Decoder::feed` theorem (12 S-splits, 20 transports all reusing S's obligation proofs, 2 `absurd`) | walk 0.046 s; kernel 0.039 s + 0.001 s; 40,546 nodes |
| `read__u32__loop0` loop lemma (measure recursion, S's decrease proof, `feed`'s callee lemma, 2 literal etas, 27 junk slots) | walk 0.010 s; kernel 0.006 s; 5,368 nodes |
| `read::<u32>` theorem (fuel shadow `μ(decoder, byte, buf) + 1`, helper lemma at bb10) | walk 0.004 s; kernel 0.004 s + 0.001 s; 3,032 nodes |
| **total for the four theorems** | walk 0.061 s; **kernel 0.050 s**; 49,050 nodes |
| fault `read::<u32>` 128→64 | walk fails (leaf mismatch) |
| fault `feed` 7→6 | walk fails |

### 8.2 MMR: `<PeakIterator as Iterator>::next` (target 2)

`next(&mut self)`:

* loops with header bb1, back edge from `sub_assign`'s return;
* compares positions through core's default `lt` and `ge`
  (`partial_cmp` → `Ord::cmp` → `u64::cmp`, `BinOp::Cmp`, `i8`
  discriminants);
* writes `self` through `AddAssign` and `SubAssign` with overflow asserts;
* panics on a failed `assert!`.

| item | value |
| --- | --- |
| S elaboration (219 items: `next`, attachments, `words::`, `stdlib::`) | 8.3 s, 277 defs, 1,506 obligations |
| L (9 MIR functions; `PeakIterator` is L's mirror, its S type has an invariant) | 224 items, 374 lines, 170,057 bytes; kernel check 0.01 s |
| `Position::cmp` theorem (S transparent; 2 S-splits, 4 eta splits) | 1,321 nodes; kernel 0.002 s |
| `Position::partial_cmp` theorem (S opaque; `cmp`'s callee lemma) | 1,031 nodes; kernel 0.001 s |
| `next__loop0` loop lemma (the `u64` measure `self.two_h`, S's decrease proofs, 2 callee lemmas, 6 L-splits, 6 refutations, 3 induction steps, 4 literal etas, 12 reused proofs, 26 junk slots) | walk 0.241 s; **kernel 0.380 s**; 135,502 nodes |
| `next` theorem (fuel shadow `two_h + 1`) | 1,972 nodes; kernel 0.004 s |
| **total for the four theorems** | walk 0.245 s; **kernel 0.387 s**; 139,826 nodes |

### 8.3 Verifier: `reconstruct_digest` (target 3; the prototype's partial result)

| step | result |
| --- | --- |
| S elaboration (242 items) | 2.9 s, 303 defs, 1,492 obligations |
| L generation | Generates: slices (`PtrMetadata`, index), `to_be_bytes` (`bswap` and a little-endian `transmute`), array aggregates, the `Digest` newtype's `Deref`, the three leaves (`Vec::push`, `Iterator::next` of the byte-string iterator, `Sha256::hash`), and the hasher's call graph. **Stops at `Option::as_deref_mut`**, which returns a reborrowed `&mut` into the caller's frame (§2.4, not implemented) |
| L of the hasher (`leaf_digest`, `node_digest` and their callees: `Position::deref`, `to_be_bytes`, `Standard::hash`) | 110 items, 192 lines, 48,131 bytes; kernel check 0.01 s |
| `leaf_digest` theorem against S's opaque definition (`Sha256::hash` of `[pos.to_be_bytes(), element]`; 8 word repairs by `bvrefl`) | walk 0.005 s; kernel 0.008 s + 0.001 s; 3,430 nodes |
| `node_digest` theorem (`[pos, left, right]`; 8 word repairs) | walk 0.046 s; kernel 0.115 s + 0.001 s; 29,010 nodes |
| `reconstruct_digest` theorem | Not attempted in the prototype. Proven in stage cs-walker (§8.5): L's returned-code translation and nested cells (stage cs-literal), the walker's non-tail self-calls (§5.6) and presence conjunct (§5.7) |

### 8.4 Added check time against the baselines

Measured per function: L's items check in 0.01–0.03 s per module's call
graph. Theorems check in 0.001–0.12 s for straight-line functions (the
upper end is `node_digest`, three byte strings into SHA-256) and
0.006–0.38 s for loops. The largest proof so far is the MMR loop lemma,
whose 135k nodes come from L-split duplication of the literal side in
motives.

The estimates below for whole modules assume:

* every function is proven;
* proof size scales with branching as measured;
* the walk runs once and the verdict is cached.

| module | baseline `sandblaster check` | functions (MIR) | estimate added kernel time | relative |
| --- | --- | --- | --- | --- |
| varint | about 100 s | 168 (84 roots) | 2–5 s | 2–5% |
| MMR | about 230 s | 132 (92 roots) | 3–8 s | 1–4% |
| verifier | about 7 s | 121 (87 roots) | 2–5 s (`reconstruct_digest` dominates: 37 blocks, non-tail recursion, many tests) | 30–70% |

The walk is untrusted and cached. Cold it costs about the same as the
kernel check: 0.06 s for varint's four, 0.25 s for the MMR's four.

The verifier's relative cost is high only because its baseline is small.
Two measures would roughly halve proof size:

* **Hash-consing** of the repeated literal side, through the kernel's DAG
  sharing.
* **Fact-first refutation**, which cuts L-split arms early.

### 8.5 Stage cs-walker: `reconstruct_digest` and sharing

| item | walk | kernel | proof nodes | before sharing |
| --- | --- | --- | --- | --- |
| the 15 lifted callees of `reconstruct_digest` (S elaboration: 319 defs, 1,532 obligations, 2.9 s; L of 33 MIR functions, 737 items, 0.07 s) | 0.29 s | 0.08 s | 10,361 | 167,899 |
| `Subtree::reconstruct_digest` (8 S-splits, 7 L-splits, 4 fuel splits, 4 induction steps, 5 callee lemmas, 6 refutations, 8 literal etas; fuel need `2·height`) | 3.3 s | 0.66 s | 25,433 | 2,020,051 |
| `UInt<u32>::read_cfg` (the callee `read::<u32>` needs fuel) | 0.004 s | 0.005 s | 468 | — |
| fault: `*cursor += 1` read as `+= 2` | the walk fails at the tail of `is_outside = true / slice::get = Some`, named | | | |

Against §8.4's estimate for the verifier (2–5 s of added kernel time,
`reconstruct_digest` dominating): its whole call chain checks in 0.74 s.

### 8.6 Stage cs-integrate: the gate on varint

| item | value |
| --- | --- |
| lifted functions with a theorem | 63 of 63 (plus 6 loop lemmas: `read__uN__loop0`, `write__uN::loop#0`) |
| literal reading (135 instances the 63 functions run) | 2,654 kernel items, 0.16 s |
| walks / kernel checks | 1.6 s / 2.5 s, 89,867 proof nodes (shared) |
| gate, cold / all cached | 4.4–5.2 s / 0.3 s (baseline `sandblaster check` ≈ 100 s: ≈ 5 % / 0.3 %) |
| largest | `write::<uN>`: 0.3 s walk, 0.24–0.34 s kernel, 5,245 nodes each (16–18 s walks before erased pairs were completed syntactically) |
| verifier, MMR (not rolled out) | 66 of 69 (4.4 s), 67 of 76 (5.1 s; the 76 counted the 7 functions of the since-removed `opt.rs` alternatives) |

### 8.7 Stage cs-storage: the MMR, the verifier, the shipped code

| item | value |
| --- | --- |
| MMR (`sandblaster check`) | 76 of 76 theorems then (6 loop lemmas, the model lemma of `u64::div_ceil`), gate 9.6 s of 244.6 s (baseline ≈ 230 s: ≈ 4 %); **69 of 69 now**, no MMR rewrite (the 7 functions of the hand-written `opt.rs` alternatives are removed) |
| verifier (`sandblaster check`) | 69 of 69, gate 4.4 s of 9.7 s (baseline ≈ 7 s: ≈ 60 %; `reconstruct_digest`'s walk 3.5 s) |
| varint (cs_proto gate) | 63 of 63 (6 loop lemmas, `usize::div_ceil`'s model lemma), 4.2 s |
| shipped code | then, the MMR's `to_nearest_size` through the since-removed user alternative: 8 theorems (helpers, copy, `L::shipped`), inside the 4.4 s lowering of the debug-profile build script; now no MMR function is rewritten, and the mechanism is tested on the toy fixtures (`tests/lowered_use.rs`: 3 theorems) |
| largest new walks | `position_to_location` 2.4 s walk, 0.08 s kernel, 5,069 nodes; `to_nearest_size::loop#0` 0.17 s, 0.12 s, 4,834 nodes; `is_valid_size__loop0` 0.06 s, 0.11 s, 4,035 nodes |

---------------------------------------------------------------------------

## 9. Implementation plan

The steps are in order. Estimates are agent-days of focused work, including
tests.

| # | step | estimate |
| --- | --- | --- |
| 1 | Production generator `mir/literal.rs` (about 1.0k): a table-driven type map with `mod.rs`'s names, reference codes and cells including nested cells and returned-code translation, the leaves of the three crates, fault messages naming the MIR construct | 4 |
| 2 | Library cleanup, leaf models gathered in `literal.core`; normative text in `docs/mir-lift.md` §20 (the reading of §2 of this note) | 1 |
| 3 | Statement generator (`StmtSpec`, `erase`, `init`) as a reviewed module; pre-commit bodies and measures kept in `DefRecord` (replacing the prototype's side table) | 1 |
| 4 | Walker hardening: non-tail self-calls (§5.4); fuel splits mid-walk; hash-consed motives; a `linarith`-first refutation pass; per-function budget and diagnostics (**done**, stage cs-walker: §5.6–§5.11) | 4 |
| 5 | Driver integration: generate L per module, run the walker per lifted function in dependency order (callees, then helpers, then functions), verdict-cache keys, gate "every lifted function has its theorem" (**done**, stage cs-integrate) | 2 |
| 6 | Roll out on varint (168 MIR functions, 84 roots), then the MMR (132), then the verifier (121); fix walker gaps as they appear (expected: more leaves, `Range` iteration, signed casts) (varint **done**: all 63 lifted functions, stage cs-integrate; the other 21 of the 84 roots are the `#[derive]`d `Clone`, `PartialEq` and `Eq` impls, which the lift generates rather than reads from MIR; the MMR's 76 (69 since the `opt.rs` alternatives were removed) and the verifier's 69 **done**, stage cs-storage) | 5 |
| 7 | Conformance on L as well as S; fault-injection test per construct (each MIR construct mutated must break a theorem) (**done**, stage cs-assurance: `conform/literal.rs`, `tests/fault_injection.rs`) | 2 |
| 8 | Lowered round trip through the same theorem (**done**, stage cs-storage: the shipped code's theorem, §5.13) | 2 |
| 9 | Demote `read.rs` to untrusted in `AUDIT.md` and `mir-lift.md` §5; publish the TCB numbers (**done**, stage cs-assurance: DESIGN.md §1.1 item 8, AUDIT.md §21.1, `mir-lift.md` §3, §5, §6, §20) | 0.5 |
| | **total** | **about 21.5 agent-days** |

---------------------------------------------------------------------------

## 10. Risks

1. **Abstraction by conversion over-abstracts field-less constructors.**
   `tt`, `TryGetError` and any unit-like struct convert with every neutral
   by eta. The prototype repairs them after abstraction (`repair_unit`,
   generalized to every one-constructor field-less type). A missed case
   shows up as an ill-typed motive (a kernel rejection), never as
   unsoundness.
2. **The speculative unfolding policy.**
   * A folded recursive call does not convert with its own unfolding.
     Expansions must go through `delta` (§5.3), and the literal side must
     stay folded at loop headers (`at_header`).
   * A change to the kernel's speculation policy could change the walker's
     view: proofs fail, the kernel stays sound.
3. **Lost decrease proofs.** `replace_rec` drops `Rec`'s decrease proofs at
   commit. The loop lemmas need S's pre-commit body. The prototype keeps a
   side table, and production must keep it in `DefRecord`. Without it, the
   walker would have to re-prove decrease, against the "reuse S's proofs"
   requirement.
4. **Invariant-carrying types** need L's mirror and projection-based
   `erase`.
   * Eta splits must not split fields that an invariant's type mentions.
     Both are handled, but every new invariant shape is a potential walk
     failure.
   * Mitigation: keep the mirror rule in the reviewed statement generator.
5. **Host models.** L and S must use the same model functions. A model
   mismatch is a walk failure, not unsoundness. The models remain trusted,
   unchanged from today (A5).
6. **Generator size.** It is above the task's 0.5k target (§7). A reviewer
   must accept about 1.0k lines of local translations. They replace 2.4k
   lines of symbolic structuring.
7. **Fuel-dependent callees.**
   * A callee whose own lemma needs fuel (it contains a loop) cannot be
     used at every fuel. Its shadow must be added to the caller's (by sum,
     sound since callees run on the same fuel).
   * Done in stage cs-walker (§5.8); the callers in the three crates are
     varint's `read_cfg`/`read_signed`/`write_signed` and the MMR's
     `pos_to_height`, `to_nearest_size`, `is_valid_size`, all proven by
     stage cs-storage. The summands must be
     non-negative to `linarith` (word measures, lengths, literals); an
     `Int` measure that is not would stop the callee lemma at the call.
8. **Proof size.**
   * L-splits duplicate the literal side in every motive: 135k nodes for
     one MMR loop, 0.38 s.
   * Deeper branching (the verifier) could grow this quadratically.
   * Mitigation: hash-consing, refutation before splitting, and splitting
     L only on tests S does not decide. Measured in stage cs-walker:
     `reconstruct_digest` is 2.0M nodes unshared and 25k shared (§5.10);
     the walk time (3.3 s, untrusted, cached) is now the larger cost.
9. **Evaluation cost of non-tail recursion.** Conformance already found
   that the kernel's evaluation of `reconstruct_digest` grows exponentially
   with depth on concrete inputs (`docs/mir-lift.md` §5). The symbolic walk
   evaluates one level per lemma application, so the proof is not
   affected, but checking L by evaluation in conformance is.
10. **Scratch space.** The prototype lives under `/private/tmp`, which macOS
    clears of old files. It must be committed before it ages; the task
    forbade git in this worktree.
11. **The quoter's limits** (stage cs-integrate). Pairs captured by proofs
    come back from the kernel's quoter without their type, and fresh array
    variables are eta-expanded; the walker completes such pairs and matches
    spelled-out arrays (§ stage cs-integrate). A shape these repairs miss
    shows up as a kernel rejection of a motive (named), never as
    unsoundness.

---------------------------------------------------------------------------

## Appendix A: prototype files (`mono-cs`, not merged; ported in stage cs-literal, see the implementation log)

**New files**

| file | role | code lines |
| --- | --- | --- |
| `sandblaster/front/src/mir/literal.rs` | L's generator (trusted in the design) | 1,905 |
| `sandblaster/front/src/mir/literal.core` | L's library (trusted) | 74 |
| `sandblaster/front/src/mir/simproof.rs` | the walker (untrusted) plus `StmtSpec` (trusted statement, 54) | 1,767 |
| `sandblaster/front/examples/cs_proto.rs` | driver: filtered elaboration, L load, theorem pipeline (`fn:` / `helper:` entries), host and model names (`ProtoNames`), `erase_text`; `CS_TRACE`, `CS_CHECK`, `CS_FAULT`, `CS_DUMP` | 628 |
| `sandblaster/front/examples/cs_explore.rs` | prints elaborated definitions (`CS_LIST`, `CS_DIAG`) | 68 |
| `sandblaster/docs/checked-structuring.md` | this note | — |

**Changed files**

| file | change |
| --- | --- |
| `sandblaster/front/src/mir/mod.rs` | `pub mod literal;` and `pub mod simproof;` |
| `sandblaster/front/src/elab/items.rs` | `PRE_COMMIT` side table (measure-recursive definitions' pre-commit body and measure) |

### Reproducing

The scripts live in the session scratch directory (`csb.sh`, `csr.sh`,
`csr_mmr.sh`, `csr_ver.sh`). They build and run through `heavy` with
`HEAVY_SLOTS=2`, `-j 4`, `SANDBLASTER_MEM_LIMIT_GB=6` and
`CARGO_TARGET_DIR=…/sbt-cs`.

**varint**, all four theorems:

```
CS_THM='fn:commonware_codec::varint::Decoder::<u32>::new=crate::varint::Decoder__u32::new;fn:commonware_codec::varint::Decoder::<u32>::feed=crate::varint::Decoder__u32::feed;helper:commonware_codec::varint::read::<u32, &[u8]>=crate::varint::read__u32__loop0|10|l14=p0,l2=p1,c0=p2,l1=code;fn:commonware_codec::varint::read::<u32, &[u8]>=crate::varint::read__u32' \
  csr.sh read__u32,read__u32__loop0 'commonware_codec::varint::Decoder::<u32>::new' 'commonware_codec::varint::Decoder::<u32>::feed' 'commonware_codec::varint::read::<u32, &[u8]>'
```

**MMR** (`P` = `commonware_storage::merkle::position::Position<commonware_storage::merkle::mmr::Family>`,
`N` = `<commonware_storage::merkle::mmr::iterator::PeakIterator as std::iter::Iterator>::next`):

```
CS_THM="fn:<$P as std::cmp::Ord>::cmp=crate::merkle::position::Position::cmp;fn:<$P as std::cmp::PartialOrd>::partial_cmp=crate::merkle::position::Position::partial_cmp;helper:$N=crate::merkle::mmr::iterator::PeakIterator::next__loop0|1|c0=p0,l1=code;fn:$N=crate::merkle::mmr::iterator::PeakIterator::next" \
  csr_mmr.sh 'PeakIterator::next,^words::,^stdlib::' "$N"
```

**Verifier**, the hasher callees (`H` =
`<commonware_storage::merkle::hasher::Standard<commonware_cryptography::Sha256> as commonware_storage::merkle::hasher::Hasher<commonware_storage::merkle::mmr::Family>>`):

```
CS_THM="fn:$H::leaf_digest=crate::merkle::hasher::Standard::leaf_digest;fn:$H::node_digest=crate::merkle::hasher::Standard::node_digest" \
  csr_ver.sh 'reconstruct_digest,^words::,^stdlib::,^sha256::' "$H::leaf_digest" "$H::node_digest"
```

## Appendix B: the dumped statement for `read::<u32, &[u8]>`

```
(x0 : List(U8)) -> Sigma (k : Int), ((n : List(Unit)) -> (.hle : Eq(Bool, #le_int(k, seq::len Unit n), true)) ->
  Eq(Option(Tuple2(List(U8), crate::__lift::Result(U32, crate::error::Error))),
     L::f16::run n L::f16::Blk::b0 (Some[L::f16::St](L::f16::St::st(None, Some(code rc0), None, …, None, Some[List(U8)](x0)))),
     Some(match (crate::varint::read__u32 x0) with tuple2(y0, y1) => tuple2(y0, y1) end)))
```

* The buffer, the `&mut &[u8]` parameter's referent, is cell `c0`. The
  parameter's slot `l1` holds its code.
* `Out` is the final buffer and the result, in the order of S's
  state-passing tuple.
