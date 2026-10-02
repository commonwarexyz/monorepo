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
every lifted function of storage's MMR (76) and verifier set 1 (69) has
its theorem, and the lifted round trip proves the shipped code's theorem
of every rewritten function. Stage "cs-assurance" (steps 7 and 9, the
review of the trusted generator, the final validation) is done: the
conformance check runs L against rustc, fault injection shows the theorems
catch a mutated construct of each kind and the two historical bugs, and
`read.rs` is demoted to untrusted in DESIGN.md §1.1 item 8, AUDIT.md §21.1
and `docs/mir-lift.md` §5, §6 and §20. The implementation log is the next section; the design follows
it, updated where the implementation differs. This note does not change
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
  theorem or fails; the pending-gates build and `sandblaster check` report
  the missing ones.
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

**Result.** Every lifted exec function of storage's MMR (76, with the
`#[rewrite]` alternatives of `opt.rs`) and of the verifier's first set (69)
has its theorem `L::thm::<f>` kernel-checked in the build, and varint's 63
still do. `sandblaster check` reports `gate mir-theorems: passed` on both
storage roots (the MMR's only §15 finding is its unaccepted lock, the
verifier's are its examples, sections and lock, as before this stage). Step
8 is in: the lifted round trip proves the **shipped code's theorem** of
every rewritten function (§5.13): the MIR rustc compiles for
`PeakIterator::to_nearest_size` (the copy delegating to the lowered
`to_nearest_size_fast` and its five helpers) returns, at sufficient fuel,
exactly `PeakIterator::to_nearest_size`'s structured value, by the
copy's theorem against the alternative and the optimizer's
`rewrite_equiv`.

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
copies need even when cached (`GateOptions::keep_keys`). The MMR's
`to_nearest_size`: 8 theorems (5 helpers' and `to_nearest_size_fast`'s, the
copy's, the shipped one). The same runs for an optimizer residual (its
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
| MMR | 76 of 76 (+ 6 loop lemmas, 1 model lemma) | 9.6 s cold | 244.6 s | ≈ 230 s | ≈ 4 % |
| verifier | 69 of 69 | 4.4 s cold | 9.7 s | ≈ 7 s | ≈ 60 % (`reconstruct_digest`'s walk, 3.5 s) |
| varint | 63 of 63 (+ 6, + `usize::div_ceil`) | 4.2 s cold | — | ≈ 100 s | ≈ 4 % |

The storage build (`compile_lifted_pending_gates`, debug profile of the
build script, two runs): MMR gate 14.0–21.8 s, the lowering with the round
trip and the shipped theorems 2.4–4.4 s; verifier gate 6.4–10.2 s. `cargo test -p
commonware-storage --lib -- merkle::mmr merkle::position merkle::location
merkle::proof merkle::hasher`: 129 passed; both roots build;
`to_nearest_size` is still rewritten and rustc compiles the lowered copy.
`cargo test -p commonware-codec`: varint VERIFIED + LIFTED AS-IS, every §15
gate (lock matching), 147 + 16 + 5 tests.

**Tests.** `tests/theorem_gate.rs` +2 (the verifier's 69; the MMR's 76
with the functions fixed here named, 136 s); `tests/literal.rs` +2 (data-free
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
not trusted: a wrong placement makes `run` fail to typecheck. Entering a
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

### 2.6 The library (`literal.core`, trusted, 141 code lines with the leaves)

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

* **A1. L's generator and library mean MIR.** About 1.0k lines (§7). Each
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
* **A7. The statement generator** (`mir/stmt.rs`, 163 code lines). The theorem text, `init` and `erase`,
  about 0.2k lines, decide what the theorem says. They are small and
  regular, and a reader checks them against §3.
* **A8. Targets.** Little-endian, 64-bit `usize`, as today
  (`transmute` to bytes, `isize` as `U64`).

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
  (namespace `theorem`; the walk is not part of the key: it is untrusted,
  and a stored theorem was kernel-checked). Invalidation follows from the
  keys.
* **The gate** (stage cs-integrate): `driver::gates::theorem_gate`, after
  the §15 gates of every verified build and the pending-gates build;
  `docs/mir-lift.md` §20.6.
* **Conformance** (`sandblaster conform`, kernel vs rustc). It stays. It
  checks A1/A4/A5, which the theorem cannot. It becomes cheaper to make
  meaningful: running L in the kernel on the same inputs compares L with
  rustc directly, while S vs rustc becomes a consequence of the theorem.
* **Optimizer.** Unaffected. It rewrites S under proven `#[rewrite]`
  lemmas. The theorem is about the source's S, and the optimized code's
  correctness is the optimizer's own theorem, composed by transitivity.
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
| structurer `mir/read.rs` | 2,397 | 2,433, **untrusted** (checked by the theorems) |
| `mir/cfg.rs` | untrusted | 235, untrusted |
| walker `mir/simproof.rs`, driver `mir/checked.rs` | — | 4,565 + 1,707, untrusted but for the gate's bookkeeping (below) |
| `mir/mod.rs`: `load` checks and names (subset type names, host models) | 430 | 480 (L's names: `kernel_adt`, `is_transparent`, `host_model_method`, host enum paths; the read.rs names stay until `read.rs` leaves) |
| L generator `mir/literal.rs` | — | 1,474 (prototype 1,905; stage cs-storage: + data-free reads; cs-assurance: + the review's fixes) |
| L library `mir/literal.core` | — | 139 non-comment lines (stage cs-literal: 141; `mir::nth` removed, `array_get` and the inclusive-range leaf changed) |
| statement and `erase` `mir/stmt.rs` | — | 225 (stage cs-storage: + core types S models by prelude structs, the model lemmas' statement) |
| printer `mirx` | 1,131 | 1,131 (unchanged) |
| lift glue (`lift.rs`'s `#[lift(mir)]` path) | about 0.2k | about 0.26k (+ the declared contracts, the loaded MIR and the helpers' record in the lift's facts) |
| the gate's bookkeeping (`gates.rs`'s `theorem_gate` and its report, ≈ 80; `checked.rs`'s planning, `prove_lifted`, the cache keys and outcome records, the model lemmas' plan, the gate memory, `prove_roundtrip`'s acceptance and `compose`'s statement, ≈ 500; `lowered.rs`'s requirement of the shipped theorems, ≈ 70) | — | ≈ 650 |
| `ir.rs` + `sexp.rs` (they feed L: trusted, amendment (d)) | untrusted | 482 + 131 = 613 (cs-assurance: no defaults, order checks) |
| **total trusted** (`read.rs` before, L after the gate) | **about 4.2k** (`ir.rs`/`sexp.rs` not counted) | **about 5.0k** = 480 + 1,474 + 139 + 225 + 1,131 + ≈ 260 + ≈ 650 + 613; **4.4k** counted as before (without `ir.rs`/`sexp.rs`). The count grows by the gate's plumbing and the shipped theorems' (step 8 replaces the trust in `read.rs`'s reading of the round trip's copy); what changes is its kind: local, construct-by-construct translations replace 2.4k lines of symbolic structuring |

**Why the generator is 1.45k and not 1.0k.** The design's estimate (below)
left out the type map (library types, module types, host models, mirrors,
constructors by name: ≈ 0.2k) and the text helpers (≈ 0.1k); the reference
model grew by nested cells and returned-code translation (≈ 0.1k), and the
rvalue tables by signed bits and the leaves (≈ 0.1k). By part, measured:
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
| verifier, MMR (not rolled out) | 66 of 69 (4.4 s), 67 of 76 (5.1 s) |

### 8.7 Stage cs-storage: the MMR, the verifier, the shipped code

| item | value |
| --- | --- |
| MMR (`sandblaster check`) | 76 of 76 theorems (6 loop lemmas, the model lemma of `u64::div_ceil`), gate 9.6 s of 244.6 s (baseline ≈ 230 s: ≈ 4 %) |
| verifier (`sandblaster check`) | 69 of 69, gate 4.4 s of 9.7 s (baseline ≈ 7 s: ≈ 60 %; `reconstruct_digest`'s walk 3.5 s) |
| varint (cs_proto gate) | 63 of 63 (6 loop lemmas, `usize::div_ceil`'s model lemma), 4.2 s |
| shipped code, MMR | `to_nearest_size`: 8 theorems (helpers, copy, `L::shipped`), inside the 4.4 s lowering of the debug-profile build script |
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
| 6 | Roll out on varint (168 MIR functions, 84 roots), then the MMR (132), then the verifier (121); fix walker gaps as they appear (expected: more leaves, `Range` iteration, signed casts) (varint **done**: all 63 lifted functions, stage cs-integrate; the other 21 of the 84 roots are the `#[derive]`d `Clone`, `PartialEq` and `Eq` impls, which the lift generates rather than reads from MIR; the MMR's 76 and the verifier's 69 **done**, stage cs-storage) | 5 |
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
