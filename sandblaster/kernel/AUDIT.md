# sandblaster kernel — audit guide

This document is for an external auditor of the trusted computing base (TCB)
of sandblaster's kernel (`sandblaster/kernel`, DESIGN.md §1.1 item 1 and
§5). For every typing, conversion and evaluation rule and every trusted
feature (linear-arithmetic certificates, the word normalizer `bvnorm`, the
axiom schemas, the prelude definitions) it gives the code location, the
justification in the set model, the tests that pin it, and known
limitations. Code locations are `file:line` of the function or `match` arm
at the time of writing (phase 3); function names are given too, since line
numbers drift.

Contents: 1 scope and size · 2 model and invariants · 3 the typing rules ·
4 relevance · 5 inductives and matches · 6 definitions, recursion and
unfolding · 7 evaluation · 8 conversion · 9 linear arithmetic · 10 `BvRefl` /
`bvnorm` · 11 axioms · 12 prelude · 13 API-level checks · 14 resource limits ·
15 what is *not* trusted · 16 known limitations and risks · 17 size and
simplification opportunities · 18 running the tests · 19 `Refs*` and section
abstraction (DESIGN §15.1, §15.5) · 20 closed evaluation (DESIGN §15.7) ·
21 the lift, the buffer model and host models (front end; DESIGN §1.1 item 8).

---------------------------------------------------------------------------

## 1. Scope and size

**Trusted** (a bug can make the kernel accept a false statement):

| Module | Lines (total / code) | Role |
| --- | --- | --- |
| `src/term.rs`, `src/value.rs` | 307/169, 115/65 | frozen data types (terms, NbE values) |
| `src/check.rs` | 1016/801 | bidirectional type checking, relevance (resurrection modes, `is_prop`), `Linarith` rule |
| `src/eval.rs` | 1504/1119 | NbE evaluator, §5.6 unfolding policy, §5.7 prelude rules, array eta |
| `src/conv.rs` | 329/249 | definitional equality |
| `src/prim.rs` | 655/516 | primitive signatures, obligations, literal semantics, neutral simplifications |
| `src/linarith.rs` | 651/531 | linearization and exact certificate check |
| `src/bvnorm/{mod,word,tripwire}.rs` | 813/604, 980/762, 303/241 | `BvRefl`: word normalizer and tripwire |
| `src/axioms.rs` | 333/270 | the axiom schemas (K1 bit-count definitions since O3) |
| `src/recursion.rs` | 278/233 | `add_def`, termination, commit |
| `src/inductive.rs` | 136/108 | inductive declarations, positivity, propositional `Irr` fields |
| `src/env.rs`, `src/api.rs`, `src/util.rs` | 112/64, 511/311, 574/435 | environment, entry points, helpers (budget, stack guard, traversals) |
| `src/quote.rs` | 970/785 | read-back; trusted where the checker uses it (`infer` of `λ`, §3), in `eval_closed` (§20) and in `obs_eq` statements (§19); its memo: §7.5 |
| `src/alpha.rs` | 285/231 | `alpha_eq_relevant`, `check_residual_equal` (trusted for the codegen round trip, DESIGN §8.3) |
| `src/prelude.rs` + `prelude/*.core` | 121/92 + 748 | the prelude definitions (TCB item 3) and their loader |
| `src/syntax/*` | 1709/1554 | parser/printer; trusted only as the reader of the embedded prelude text |
| `src/section.rs` | 585/457 | `Refs*` (`Env::refs_closure`) and `complete_p(R)` (`Env::abstract_section`), §19 |
| `src/closed.rs` | 158/125 | `Env::eval_closed` (known-answer examples), §20 |

**Not trusted, but in the crate:** `src/lincert.rs` (211/173, certificate
search whose output is re-checked, §9), diagnostics, the abstraction mode of
the quoter (`abstract_occurrences`, whose result the caller type-checks),
typed quoting for automation.

**Total:** 12,728 lines, 9,932 non-blank non-comment lines (its red-team
fix of 2026-09-25, §7.5: +44 / +31 in `quote.rs`; the read-back
memo of §7.5: +84 / +54 in `quote.rs`; before it: 12,600 / 9,847; the
2026-09-24 `bvnorm` fixes of §10 — `lows` and one width per class: +56 /
+24; O3, the K1 bit-count definitions of the optimizer design §11.4: +21 /
+15 in `axioms.rs`; before O3: 12,523 / 9,808; phase 4:
11,684 / 9,184; the §15 APIs of §19–§20 added 839 / 624: `section.rs`
457, `closed.rs` 125, `api.rs` 40, `lib.rs` 2 — of which 67 / 44 are the
red-team fixes of §19; phase 3: 11,509 / 9,068).
Without the syntax module: 11,019 / 8,378. Tests: 9,058 lines (24
integration test files, `tests/common`, and `tests/unit/quote_memo.rs`, a
unit-test module of `quote.rs` kept out of `src/`); prelude text: 748
lines (`slice.core` 354, `list.core` 226, `base.core` 77, `bytes.core` 46,
`int.core` 45). No `unsafe`
(`#![forbid(unsafe_code)]` in `lib.rs`); dependencies: `num-bigint`,
`num-integer`, `num-traits`, and `sandblaster-memguard` (resource control
only, §14; it contains the crate's only `unsafe`, the forwarding
`GlobalAlloc` impl, and is not part of the soundness argument).

---------------------------------------------------------------------------

## 2. Model and global invariants

**Set model** (DESIGN §5.2). `Type` is interpreted as a universe of sets
(a Grothendieck universe); `Kind` as the collection containing `Type` and
the Π-types landing in `Kind`. `Π(x : A). B` is the set-theoretic dependent
function space, `Σ` the dependent sum, `Eq(A, a, b)` is `{∗}` if `a = b` and
`∅` otherwise (UIP holds), inductive types are least fixed points of their
(strictly positive) constructor signatures, machine integers are `[0,
2^w)`, `Int` is ℤ, `Bool = {false, true}`, `Empty = ∅`. Irrelevance (§4):
an irrelevant Π `(.x : A) -> B` denotes the functions that are *constant*
in `x` (B cannot mention `x` outside irrelevant sub-positions), i.e.
`‖A‖ → B` with `‖A‖` the truncation (`{∗}` if `A` is inhabited, `∅`
otherwise); an irrelevant Σ component and an irrelevant constructor field
must have a *proposition* type (a subsingleton), so `Σ(x : A). .B` is
`Σ(x : A). B` with `B` a subsingleton. An irrelevant position denotes only
the *existence* of an inhabitant of its type (the enclosing term never
reads it). Every accepted closed term denotes an element of the
interpretation of its type; in particular no closed term of type `Empty` is
accepted. (Phase-4 red team R1 falsified this claim for the phase-3 checker,
whose single `irr` flag let binders introduced inside an irrelevant position
be used relevantly there — e.g. a non-constant `fun (.h : Bool) => not h` —
and let `snd` of an `Irr` Σ and `Irr` constructor fields holding data be
projected; the claim is restored by the resurrection discipline and the
proposition requirement of §4, and pinned by the adversarial test
`irrelevant_positions_resurrect_only_outer_variables` and
`tests/redteam.rs` `r1a`–`r1e`.)

**Invariants the code relies on:**

1. *Terms* are de Bruijn indexed (`Idx`), *values* de Bruijn levelled
   (`Lvl`); a value created under `d` binders mentions only levels `< d`.
2. Values are immutable and shared (`Rc`); every memo keyed by an address
   keeps a clone of the keyed object alive for its whole lifetime, so an
   address is never reused while it is a key (conversion memo `conv.rs:114`;
   `bvnorm` node memo `bvnorm/mod.rs:301`; evaluation memo `EvalMemo`,
   `eval.rs:268`; checker inference memo `check.rs:194`; read-back memo
   (`quote.rs`: values and closures, §7.5); term traversal memos in
   `util.rs:413-485`).
3. Evaluation environments (`VEnv`, an `Rc<Vec<_>>`) are extended in place
   only when not shared (`util.rs:131` `venv_push_owned`); memos hold a clone
   of every environment they key on, which makes it shared.
4. Every evaluation or conversion step consumes budget (`util.rs:23`
   `tick`); exhaustion is `EvalError::OutOfFuel`, an error, never success
   (`kernel.rs::budget_exhaustion_is_an_error`, adversarial
   `conversion_skips_exactly_the_irrelevant_positions`).
5. `garbage()` (`eval.rs:115`, an absurd neutral of type `Type`) is produced
   only for ill-typed input, and — deliberately — as the placeholder for an
   argument value that a *non-dependent* codomain never reads
   (`check.rs:388` `dependent_entry`, `check.rs:588` constructor fields,
   `check.rs:831` match scrutinee). Soundness of the latter rests on
   `util::occurs` (syntactic, linear in the term DAG, `util.rs:510`): the
   placeholder is used only when the codomain does not mention the bound
   variable, so the instantiated type is the same set whatever the argument.

---------------------------------------------------------------------------

## 3. The typing rules (`check.rs`)

Checking is bidirectional: `Checker::check` (`check.rs:313`) handles `λ`
against a Π (domain converted with the Π's domain, relevance equal), `let`
and `Erased`; everything else is `infer` followed by conversion with the
expected type. `Checker::infer` (`check.rs:410`) memoizes the inferred type
of shared term nodes per (node, context, mode) (§7.4) and dispatches on the
term in `infer_node` (`check.rs:426`). Sorts: `Type : Kind`, `Kind` has no
type.

| Term | Location | Rule (and justification) | Pinned by |
| --- | --- | --- | --- |
| `Var` | 429 | type from the context; an `Irr` variable only in an irrelevant position entered after it was bound (`usable`, 89; §4) | kernel `relevance_must_accept`, adversarial `relevance_leaks_are_rejected` |
| `Global` | 451 | the committed type; the pending definition itself is rejected (no self-reference, hence no mutual recursion) | adversarial `nontermination_is_rejected` |
| `Sort` | 452-453 | `Type : Kind`; `Kind` untypable | adversarial `universe_paradoxes_are_rejected` |
| `Pi` | 454 | domain and codomain have sorts; the Π has `max` (a codomain `Kind` is impossible since `Kind` has no type) | kernel `sorts_and_formation` |
| `Lam` | 462 (infer), 316 (check) | body inferred under a fresh variable; the body type is **read back** (typed quote, with sharing) to form the Π's codomain closure — the one place the quoter is trusted | kernel `typed_quotes_recheck`, `sorts_and_formation` |
| `App` | 472 | function type is a Π; annotation relevance = Π relevance; argument checked (an `Irr` argument as an irrelevant position); codomain instantiated with the argument's value, or a placeholder when the codomain does not mention it (§2.5) | adversarial `relevance_leaks_are_rejected`, eval_opt `checking_does_not_evaluate_non_dependent_arguments` |
| `Let` | 487, 354 | type has a sort, value checked (an irrelevant position for `Irr` lets), body under the definition (an `Irr` let variable is usable only in irrelevant positions entered later) | kernel tests |
| `Sigma` | 491 | both components `: Type` (Σ lives in `Type`); an `Irr` second component must be a proposition (`is_prop`, 940; §4) | `sorts_and_formation`, adversarial `irrelevant_positions_resurrect_only_outer_variables` |
| `Pair` | 513 | annotated Σ; second component checked against `B[fst]`, irrelevantly for an `Irr` Σ | `eta_rules`, adversarial `array_length_confusion_is_rejected` |
| `Fst` / `Snd` | 525 / 532 | projections; `snd` of an `Irr` Σ only in an irrelevant position, and only of a pair whose free variables are bound outside it (`mentions_inner`, 95) | adversarial relevance tests |
| `Eq` | 553 | `A : Type`, both sides `: A` (no `Eq` at `Kind`) | `universe_paradoxes_are_rejected` |
| `Refl` | 560 | `refl(A, a) : Eq(A, a, a)` | many |
| `Transport` | 567 | `e : Eq(A, a, b)` checked irrelevantly, motive `: Type` under `y : A`, `v : P[a]`, result `P[b]` (Leibniz substitution; evaluation reduces it only when `a ≡ b`) | adversarial `transport_reduces_only_on_convertible_endpoints` |
| `Ind` | 584 | parameters checked against the declaration | inductive tests |
| `Ctor` | 588 | parameters and fields checked in order, field types instantiated with earlier fields (placeholder when unused, §2.5), `Irr` fields irrelevantly | `inductives_matches_and_iota` |
| `Match` | 613, 831 | scrutinee `: D(ps)`; motive has a sort under `y : D(ps)` (large elimination allowed); arm `k` checked against `P[c_k(ps; fields)]` with fields bound as the checker binds every variable (array eta); result `P[scrut]` | `inductives_matches_and_iota`, phase3 `k1_*` |
| `IntTy` / `Lit` | 614 / 615 | machine literals in `[0, 2^w)` | prims tests |
| `Prim` | 623 | argument widths from `prim_sig`; each proof slot checked irrelevantly against `prim_obligations` (the exact domain condition, `prim.rs:100`) | prims, adversarial `false_shift_facts_are_not_derivable` |
| `Rec` | 645, 878 | only in the pending body, full argument list, not in the parameter telescope; measure recursion checks the decrease proof against the §5.6 obligation in the call-site context | adversarial `nontermination_is_rejected`, `inconsistent_measure_precondition_*` |
| `Delta` | 646 | `delta(g; args) : Eq(R, g args, body[args])`, only for `R : Type` (recursive calls in `body` are `g` itself after commit) — a definitional equation | opaque `delta_and_unfold_expose_the_defining_equation`, adversarial `delta_and_unfold_restrictions` |
| `Unfold` | 659 | casts between `g args` and its body for proposition-valued `g` (`R = Type`) | same |
| `Linarith` | 674 → `infer_linarith` 736 | §9 | §9 |
| `BvRefl` | 675 | both sides `: A`, no `Erased`; accepted iff `bvnorm` says equal (§10) | §10 |
| `Absurd` | 689 | proof `: Empty` checked irrelevantly, never `Erased`; any type | adversarial `absurd_needs_a_proof_of_empty` |
| `Axiom` | 698 | telescope from `axioms::telescope`, hypotheses irrelevant; statement instantiated (§11) | axioms tests |
| `Erased` | 712, 339 | rejected everywhere, except in irrelevant positions of `check_residual_equal` candidates, never as `absurd`'s proof | adversarial `erased_is_rejected_everywhere` |

---------------------------------------------------------------------------

## 4. Relevance (DESIGN §5.3)

**Rule (phase 4, red team R1).** The checker carries a mode
`Mode = Option<u32>` (`check.rs:70`): `None` in a relevant position,
`Some(d)` inside an irrelevant position whose innermost entry was at context
depth `d`. An irrelevant position is entered (`irr_at`/`sub_mode`, 77-86)
exactly at: an `Irr` application argument (`check.rs:472`), prim proof slots
(623), `Rec` proofs (878), the second component of an `Irr` Σ (513), an
`Irr` let value (354), `Transport.eq` (567), `Absurd.proof` (689), `Irr`
constructor fields (588), `Irr` telescope arguments of `Rec`/`Delta`/
`Unfold`/axioms (395, 698). Type positions never switch. Then:

* **Resurrection** (Pfenning 2001; Abel–Scherer 2012; Agda): an `Irr`
  context entry at level `l` is usable relevantly iff the mode is `Some(d)`
  with `l < d` (`usable`, 89) — it was bound *outside* the irrelevant
  position. `Irr` λ/Π binders, `Irr` lets and `Irr` match fields introduced
  *inside* the position keep their status: they are usable only in a nested
  irrelevant position (entered at a larger depth, which resurrects them).
  Contexts only grow along a check, so nesting only raises `d`.
* **Irrelevant projections**: `snd` of an `Irr` Σ is rejected in relevant
  positions, and in an irrelevant position unless every free variable of
  the pair is bound outside it (`mentions_inner`, 95) — as if the pair had
  been destructured outside and its component resurrected. `Irr`
  constructor fields are only bound by match arms, as `Irr` variables, so
  the rule above already covers them (no special case).
* **Propositions only** in projectable irrelevant slots: the type of an
  `Irr` Σ component (checked at Σ formation, 491) and of an `Irr`
  constructor field (checked at declaration, `inductive.rs`) must satisfy
  the conservative syntactic test `Checker::is_prop` (940) on its value:
  `Eq`; a Π whose codomain is a proposition; a Σ of propositions; a
  non-recursive inductive with no constructor, or one constructor whose
  fields all have proposition types. Neutral types (type variables), data,
  several constructors and recursive inductives are rejected. Every current
  use qualifies: `SliceOk` (= `And` of two `Eq`s), the `Array` length
  equation, the chunk bounds of `seq::chunks_c`/`chunks_rest_c`; front-end
  structs have no `Irr` fields.
* The linarith assumption search (`assumption`, 784) and the context facts
  of the certificate search (`context_facts`, 799) use exactly the entries
  usable in the current mode (relevant ones, and `Irr` ones below `d`).
* `Erased` (only for `check_residual_equal`) is accepted in any irrelevant
  position (`mode.is_some()`).
* The inference memo is keyed on the full mode (`d` included).

*Justification (set model, §2).* An irrelevant position denotes only that
its type is inhabited; the enclosing term never reads its value (the
evaluator never forces `Arg::Irr` closures of well-typed relevant code, and
`Rec` proofs, `Transport.eq`, `Absurd.proof` and `Linarith` hypotheses are
not even stored in values). So a proof may depend on the actual values of
the irrelevant variables in scope — resurrection. A function *built inside*
the position is still a value of its type, and an irrelevant Π denotes
constant functions, so its own irrelevant binders must stay irrelevant in
its body — the level condition. For `snd`/fields, the proposition
requirement makes `‖B‖ ≅ B`, and the free-variable condition keeps a
projection from being abstracted over inside the position (no
`fun p => snd p` of type `Σ(x:A). .B → B`, which would need choice for a
non-proposition). Conversion (§8) skips irrelevant spine arguments
(justified: a function cannot depend on them), `Irr` pair components and
`Irr` constructor fields (justified by proof irrelevance of their
proposition types), prim proof slots (their types are `Eq`s). The flows
from irrelevant to relevant are `eq::promote` (prelude; a transport along
an irrelevant equation, whose value is its relevant argument) and `absurd`
(an irrelevant proof of `Empty`); both are sound because the irrelevant
proofs they consume are proofs of true propositions.

*The R1 exploit* (docs/review-3-redteam.md): with the phase-3 single flag,
`absurd(Empty, let L : (G : (.h : Bool) -> Bool) -> Eq(Bool, G .true, G
.false) = fun G => refl(Bool, G .true); false_ne_true (L (fun (.h : Bool)
=> not h)))` checked in the empty context: `fun (.h : Bool) => not h` was
accepted inside `absurd`'s proof although it is not constant in `h`, and the
must-accept lemma `L` (conversion skips `.true`/`.false`) then yields
`false = true`. Variants used `snd` of `Sigma (b : Bool), .Bool`, an `Irr`
field `.x : Bool` of an inductive, and an `Irr` let. Now `h` is bound inside
the position (level ≥ `d`) and rejected; `Sigma (b : Bool), .Bool` and
`ibox(.x : Bool)` are ill-formed.

*Phase-3 addition (unchanged):* a `Linarith` hypothesis may be justified by
a context assumption (§9) usable in the current mode, so the rule adds no
irrelevant-to-relevant flow.

*Must-accept cases kept:* `λG. refl(Bool, G true@Irr) : Π(G : (.h : Bool)
-> Bool). Eq(Bool, G .true, G .false)` (irrelevant binders may hold data;
conversion skips irrelevant spine arguments); `slice::ok_len` and friends
(`.fst(snd(snd(s)))` with `s` bound outside the `Irr` argument); outer
`Irr` hypotheses in proof slots and in `absurd`. *Changed must-accept:* the
adversarial relevance probe `inductive IBox { | ibox(.x : Bool) }` is now
rejected at declaration; the probe uses `PBox { | pbox(.x : Eq(Bool, true,
true)) }`, and `snd` is probed on `Sigma (b : Bool), .Eq(Bool, b, true)`.

*Pinned by:* adversarial `irrelevant_positions_resurrect_only_outer_variables`
(r1a–r1e, inner binders/lets/pairs/linarith facts rejected, nested
positions and outer variables accepted, the proposition table),
`relevance_leaks_are_rejected` (the G0 exploit of docs/review-1.md, `snd` of
an `Irr` Σ, `Irr` fields, matches on irrelevant data),
`conversion_skips_exactly_the_irrelevant_positions`,
`linarith_hints_and_assumptions_cannot_prove_false_goals`; `tests/redteam.rs`
`r1a`–`r1e`; kernel `relevance_must_accept`.

---------------------------------------------------------------------------

## 5. Inductives and matches

**Declarations** (`inductive.rs:47`): parameters of any type `T : Type` or
`T : Kind`, relevant; constructor fields are checked in the context of the
parameters and earlier fields and must have sort exactly `Type` (so `Type`
itself and `Π(X : Type). X` are rejected — Hurkens' paradox); an `Irr`
field must have a proposition type (`is_prop`, §4) and so is never a
recursive occurrence; the inductive
itself may occur only as a direct field `D(p₁ .. pₙ)` applied to exactly the
parameter variables (`is_self_occurrence`, `inductive.rs:30`), nowhere else
(`mentions`, 40) — strict positivity by syntax, no nested or indexed
occurrences. *Justification:* such signatures have least fixed points in the
set model (polynomial functors). *Pinned by:* adversarial
`universe_paradoxes_are_rejected` (box fields, `W(Type)`, negative and
nested occurrences), kernel `inductives_matches_and_iota`.

**Match typing** (§3 table). **ι-reduction** (`eval.rs:445` tail position,
720 otherwise): a match on constructor `k` evaluates arm `k` with the
fields. A match on a neutral is a neutral with a `Match` eliminator.
**Arm fields** are introduced by `Ev::arm_fields` (`eval.rs:1385`) wherever
arms are opened (checker 740, conversion 292, quoter, `bvnorm`): relevant
fields through `Ev::fresh`, so an `Array T N` field is eta-expanded as every
other variable (§8; phase 3, issue K1).

**Struct eta** (`conv.rs:200`): for a non-recursive single-constructor
inductive, `c(ps; a₁..aₙ) ≡ s` iff every relevant `aᵢ ≡ match s { c(xs) => xᵢ }`.
*Justification:* such a type is (in the model) the product of its fields; a
value is determined by its projections. Irrelevant fields are skipped
(proof irrelevance: their types are propositions, §4).

---------------------------------------------------------------------------

## 6. Definitions, recursion, termination, unfolding

**`add_def`** (`recursion.rs:214`): the type is a Π telescope of `arity`
syntactic binders whose result type has a sort (`check_type`, 165); the
body is checked against the type with the definition *pending* (`Rec`
evaluates to a neutral whose global id is not yet in the environment, so it
can never unfold during its own checking; `Global(self)` is rejected); then
the termination check; then commit, replacing every `Rec(args)` by `g args`
(`replace_rec`, 65). A body that is a term DAG is flagged `shared` (§7.4).

**Termination:**
* `Recursion::None`: `Rec` is rejected by the checker.
* `Recursion::Structural { param }` (`structural_check`, 75; `walk_node`,
  100): the parameter has a recursive inductive type; every `Rec` — in any
  position, including irrelevant ones — passes at `param` a variable bound as
  a recursive field of a match whose scrutinee is the parameter or
  (transitively) such a field. *Justification:* well-founded recursion on the
  inductive's subterm order.
* `Recursion::Measure { measure }`: the measure (over the telescope) has
  type `Int` or a machine width; every `Rec(args; p)` carries `p :
  Σ(_ : 0 ≤ m[args]). m[args] < m[params]` (`Int`) or `m[args] < m[params]`
  (machine widths), checked in the call-site context (`check.rs:878`,
  `measure_obligation_term`). *Justification:* the measure is a natural number
  strictly decreasing along recursive calls, so the recursion is well
  founded **given** the hypotheses in scope; a definition whose calls are only
  reachable under inconsistent hypotheses may loop when evaluated in an
  inconsistent context — evaluation then exhausts its budget (an error), it
  never produces a value (adversarial
  `inconsistent_measure_precondition_is_accepted_but_does_not_loop`,
  `ground_recursion_refinement_never_turns_nontermination_into_success`).

**Unfolding policy** (`Ev::policy_step`, `eval.rs:987`; DESIGN §5.6). All
unfolding is sound (it is the definitional equation); the policy only
decides *normal forms*, i.e. completeness and cost:
* non-recursive, non-intrinsic, non-opaque globals unfold on demand (their
  closed body value is cached per mode, `def_value`, 913);
* **opaque** definitions never unfold in the checking mode (`is_opaque`,
  362); `Delta`/`Unfold` expose their equation;
* **intrinsics** unfold only when every relevant argument is a closed value
  (`is_closed`, 163) — or always in the `BvRefl` mode;
* a **recursive** global applied to all arguments is unfolded iff a
  speculative evaluation of its body — sub-budget 2^20 steps, only this
  global folded (`speculate`, 1026) — is not stuck at its head on a neutral
  match or partial checked primitive (`stuck_at_head`, 152). Phase-3
  refinements (same function): if the speculation is stuck only because a
  folded recursive call is inspected (`blocked_by_fold`, 193) and the
  recursion argument is ground (`ground_recursion`, 1097: a closed
  constructor spine for structural recursion, a literal measure), the body
  is evaluated with the real policy (its recursive calls are ground again, so
  it terminates); in the optimizer's transparent mode an application to
  closed arguments whose speculation merely exhausts the sub-budget is
  evaluated with the caller's budget. A result that is still stuck keeps the
  application folded.
* **Speculation reuse** (`resume`, 1146, a pure optimization): a successful
  speculation whose folded calls occur only at the top of its value (tail
  call, or direct constructor/pair fields — proven by `Rc` strong counts) is
  completed by unfolding just those calls; otherwise the body is
  re-evaluated.
* **Modes:** checking mode (default); `eval_opaque`/`conv_opaque`
  (optimizer: `DefDecl.opaque` ignored, exactly the caller's set folded);
  `eval_transparent`/`conv_transparent` (empty set); the `BvRefl` mode
  (transparent, and intrinsics unfold on symbolic data; `Ev::bv`, 326).

*Pinned by:* kernel `recursion_policy_and_delta`,
`intrinsics_unfold_only_on_closed_arguments`, `eval_opaque_keeps_heads`;
opaque (6 tests); eval_opt (shortcuts compute what plain unfolding
computes); phase3 `recursion_inspecting_its_result_computes_on_closed_data`;
depth (tail recursion in constant stack).

---------------------------------------------------------------------------

## 7. Evaluation (`eval.rs`)

### 7.1 NbE
Call-by-value for relevant arguments; irrelevant arguments, `Irr` let
values, `Irr` pair components, prim proof slots and `Irr` constructor fields
are kept as unevaluated closures and never forced. Tail positions (let
bodies, match arms, β-redexes, global unfolding) run iteratively (`run`,
426; `tail_step`, 445), so tail recursion uses constant Rust stack.
`transport` reduces to its value iff its endpoints are convertible
(`ev_transport`, 686 — the only place evaluation calls conversion).
`Linarith`, `BvRefl`, `Delta` evaluate to `refl` of their (checked) goal's
left side (`ev_eq`, 656): proofs of equations are all equal (UIP), and the
evaluator only runs on checked terms.

### 7.2 Primitives (`prim.rs`)
Literal semantics (`eval_lits`, 179; `eval_machine`, 248): wrapping ops mod
2^w; shift and rotate amounts mod w; truncating/zero-extending casts; checked
ops stuck outside their domain; checked `Shl/Shr` compute as `WShl/WShr`;
exact `Int` with a 4096-bit limit (`IntOverflow`, never wraparound);
Euclidean `IDiv/IMod` with `x/0 = 0`, `x%0 = x`. *Pinned by:* prims (U8
exhaustive against native Rust, U16 exhaustive in one argument, U64/Usize
boundaries).

Neutral simplifications (`simplify`, 397), each an identity for every op
family it applies to (DESIGN §5.7): `x+0`, `x−0`, `x·1`, `x·0`, literal
operands of commutative ops move right, `(x+c1)+c2 → x+(c1+c2)` (checked
only if `c1+c2 ≤ MAX`), `(x+c)−c → x`, the positive-checked-add comparisons,
widening cast collapse, `to_int(of_int i) → i`, `of_int(to_int x)`.
*Pinned by:* simplify (each rule instantiated over U8 and compared).

### 7.3 Prelude items with kernel meaning
Registered only by `Env::with_prelude` from the embedded text
(`prelude.rs:89` `register_known`): `List`, `seq::len`, `seq::index`,
`seq::take`, `seq::drop`, `u16/u32/u64::from_le_bytes`. Rules
(`index_simp`, 1206; `le_bytes_simp`, 1273; `byte_extract`, 1310):
`index(T, Cons(x0, ..), i)` for a literal `i` is `x_max(i,0)` when the spine
is that long (what the definition computes); `index(take(l, n), i) →
index(l, i)` for literals `0 ≤ i < n`; `index(drop(l, a), i) → index(l,
a+i)`; `from_le_bytes([cast_u8(x), cast_u8(x>>8), ..]) → x`;
`cast_u8(wshr(from_le_bytes(bs), 8k)) → bs[k]`. *Justification:* each is
the definition's value on every well-typed occurrence (the index proofs
guarantee range). *Pinned by:* simplify `byte_rules_and_list_rules`,
eval_opt.

**Array eta** (`fresh`, 1368; `array_shape`, 1407; `eta_array`, 1440;
DESIGN §5.9): every variable the kernel introduces at type `Σ(l : List T).
.Eq(Int, len T l, N)` with literal `N ≤ 256` (the unfolded `Array T N`) is
the value `([index(T, fst x, 0), .., index(T, fst x, N−1)], snd x)` with
certificate-free bound proofs. *Justification:* extensionality of
fixed-length lists: a list of length `N` equals the list of its elements.
*Pinned by:* kernel `array_eta_small`, adversarial
`array_length_confusion_is_rejected`, phase3 `k1_*`.

### 7.4 Term DAGs (phase 3)
Terms reaching the kernel are often DAGs (read back from symbolic values,
produced by substitution). `EvalMemo` (`eval.rs:268`) memoizes the value of
a shared term node (`Rc::strong_count > 1`) evaluated in a *registered*
environment: an API call's root environment, a checking context's
environment, a root closure instantiation by conversion, quoting or
checking (`inst_root`), and their let/arm/β extensions during that
evaluation (`derive`, 838). A definition body that is a DAG is unfolded with
a memo scoped to that unfolding (`unfold`/`eval_scoped`, 946/956).
Speculative evaluators never use an outer memo. *Justification:* evaluation
is a function of (term, environment, mode); keys are kept alive (§2.2) and
registered environments are never mutated in place (§2.3). The checker
memoizes inferred types the same way (`check.rs:410`), and `occurs`,
`contains_erased`, `map_post`, the structural check, `alpha_eq_relevant`,
`straight_line`, linearization and quoting are linear in the DAG. *Pinned
by:* phase3 `shared_term_graphs_*` (a 2000-level shared chain), adversarial
`eval_memo_distinguishes_environments`.

### 7.5 Read-back memo (`quote.rs`)
**What.** When neither sharing, abstraction nor a node limit is active
(`Quoter::memo_active`; those modes' output depends on more than the node),
`Quoter::q` memoizes neutral nodes and constructors with fields by
`Key::Val(address)`, and `Quoter::q_clo` — the read-back of a closure by
substitution: proofs, and closures whose NbE ran out of budget — by
`Key::Clo(address of the environment vector, address of the body,
binders)`, in `memo[d]` for the quoting depth `d`. The keyed values and
closures are kept alive (`memo_keep`, `clo_keep`; §2.2). Without it, a
proof that refers to an earlier proof twice is read back as the tree it
unfolds to: the §15 S1 chunking loops referred to their `hn` twice per
chunk, and a 22-chunk `Option<Seq<[u8; 4]>>` known-answer example
exhausted 4 GB in `eval_closed`'s read-back.

**Claim.** A hit returns exactly the term the unmemoized quoter would
compute at that call: the same indices, names, relevance, `Erased`
placeholders and Σ annotations; and every call from outside the quoter
returns what a fresh unmemoized quoter with the same context returns (up
to the budget, (3)). For any values: the argument does not assume the
level discipline of §2.1.

**Argument.** (1) The read-back of a node is a function of the node, the
depth `d`, for a closure its `binders`, the mode, and — typed quoting only —
the context types it reads. Values and closures are immutable, and a
closure is nothing but its environment vector and its body, so the two
addresses identify it. Levels become indices relative to `d`
(`lvl_to_idx`: `d − l − 1`), and a closure's body keeps its own variables
(`Var(i)`, `i < local`) and reads its environment's values back at
`d + local`: the key fixes the node, `d` and `binders` exactly (the same
value or closure at another depth, or with another number of own binders,
is another entry). The expected type is not an input of the memoized nodes
(neutrals and constructors ignore it; pairs and λs read it and are not
memoized). The mode is fixed per quoter, and the memo is off in the other
modes. Evaluation during read-back (closure instantiation, field, codomain
and motive types) is a function of its inputs (§7.4). (2) Context types:
the type of a level is read only for a variable head applied to a spine
(`type_of`: its Π domains and Σ types annotate the arguments), and **the
type read for a level is a function of the path to the read**. A read at
depth `d` is of a level `< d` (a level `≥ d` has no index there:
`lvl_to_idx` would underflow; such a value cannot be read back at `d`).
For a level below the depth of the call from outside it is the context's:
such a call (`nest == 0`, `enter`) restores the types given to
`Quoter::typed` below its depth, which an earlier call may have bound.
For any other level it is the type set by the binder of that level on the
path: every binder the quoter introduces sets the type of its level before
anything under it is read — `fresh` for Π, λ, Σ, match
motives and transport motives and for match-arm fields (irrelevant ones
too); `None` for a field whose type cannot be evaluated (budget, `Int`
overflow) and for the binders of a closure quoted by substitution, which
have no type at hand (its own binders and those inside its body: `q_clo`
sets them before each free variable it reads back under them) — and a call
at depth `d` sets levels `≥ d` only, so nothing inside a subtree changes a
level bound above it. A read-back at depth `d` is therefore a function of
the node and of the types of the levels `< d` it reads. A memo hit skips
the binders inside the memoized node and so leaves other types in levels
`≥ d` than recomputing it would; no read sees them, since each such level
is set again before it is read. `type_of` records the level
(`read[l]`); `set_type(l, t)` with a `t` that is not the identical object,
after such a read, drops `memo[l + 1..]` — every entry that can have read
level `l` as a free level — and `read[l..]` (every remaining entry is at a
depth `≤ l`, so none reads a level `≥ l` as a free level). A change of a
level nobody read since the last cut affects no entry: by determinism,
recomputing an entry that did not read `l` does not read it either. When
a level `l` is (re)bound, every read-back in progress is at a depth `≤ l`.
*Red team 2026-09-25:* before the `None` binders of `q_clo` and `enter`, a
single typed read-back on a fresh quoter could return other Σ annotations
memoized than unmemoized (e.g. `Σ(U64, U32)` where the reference had
`Σ(U64, U64)`): the binders of a closure quoted by substitution set no
type, so a value read back under one that mentions its level (outside
§2.1: a closure environment mentioning a level its body binds) read the
type an earlier binder of that level had left, and a memo hit on a node
containing that binder had skipped it. §2.1-valid values never read such
levels (the QMDB builds print byte-identical code before and after the
fix), but the memo no longer relies on it.
(3) Budget: the quoter's internal budget (5·10⁷ steps) bounds the NbE of
closures; when it runs out a closure is read back by substitution instead
(a convertible, unnormalized term, §16.1). A hit may return the form
computed while budget remained where recomputation would fall back; both
are correct read-backs, and the memo only ever saves budget.

**Where it is trusted.** `infer(λ)` reads back with sharing (memo off);
`eval_closed` (§20) and the `obs_eq` statements of `section.rs` (§19) read
back typed without sharing (memo on), each on a fresh quoter; `linearize`
(one quoter for all atoms, each call at the context's depth) is
re-checked.

**Pinned by:** `tests/unit/quote_memo.rs` (a unit-test module of
`src/quote.rs`: `cargo test -p sandblaster-kernel --lib`) — memoized vs
unmemoized read-back (a fresh reference quoter per call) on 600 random
value DAGs over sequences of calls on one quoter (sharing across binders at
different depths, closure environments captured at different levels, one
body under several environments, irrelevant arguments, fields, pair
components, proof slots and `let`s, `Erased` in bodies, every neutral head
and eliminator, typed contexts); one closure at interleaved depths and with
and without a binder of its own; sibling λs whose bodies read back one
value under differently typed binders; match-arm fields (relevant,
irrelevant, un-evaluable types: budget and `Int` overflow); the red-team
generator of 2026-09-25 — values outside §2.1 (binder types that annotate,
shared or fresh; values shared across sibling binders of one level and
reused deeper; match arms and closures whose environment mentions the
levels they bind; proofs with binders): 40,000 single read-backs of a value
and of a proof on fresh quoters, 80,000 deeper ones, 4,000 sequences of 25
calls on one quoter, 40,000 calls with address reuse between them; the
red-team case itself, closure binders read as unknown between free
variables, and calls from outside starting from their context (beyond and
below its depth, through `q` and `q_clo`); proof chains (exponential as
trees); chunk certificates through `eval_closed` (linear read-back up to 64
chunks); the memo off in the bounded, sharing and abstracting modes. Each
of 18 mutations — depth, environment, body or binders dropped from the key;
no cut, a cut one level too deep, or reads not recorded; arm fields
(relevant or irrelevant) not setting their type; memoizing pairs and λs;
the memo on while sharing or abstracting; closure binders keeping stale
types, or their `None` levels not reset after a nested read-back; no
restore on entry, a restore of the levels beyond the context only, a
restore in nested calls too, or `q_clo` from outside without it — fails at
least one of these tests, and so does the memo before the red-team fix (7
tests). (Keeping the read flags of deeper levels at a cut is conservative:
only more cuts.) The QMDB builds (N = 32 and N = 1) print byte-identical
code with and without the memo and before and after its red-team fix, and
the same report.

---------------------------------------------------------------------------

## 8. Conversion (`conv.rs`)

Untyped NbE conversion on values (`Conv::conv`, 114; `conv_inner`, 228):

| Rule | Location | Justification |
| --- | --- | --- |
| sorts, `IntTy`, literals by equality; Π, Σ domains and codomains (under a fresh variable of the domain) | 228 | structural |
| λ vs λ; **η for functions** (`λ` vs anything: `body[x] ≡ f x`) | 173 | function extensionality holds in the set model |
| **η for Σ** (pair vs neutral through projections; `Irr` second component skipped, so `(fst p, _) ≡ p` for an `Irr` Σ) | 184 | surjective pairing; proof irrelevance (an `Irr` component has a proposition type, §4) |
| **η for structs** | 200 | §5 |
| array η | via variable introduction (§7.3) | §7.3 |
| `refl` vs `refl`: always equal | 254 | UIP (proofs of an equation are equal) |
| constructors, `Ind` by index, parameters and relevant fields | 256 | structural; irrelevant fields skipped (proposition types, §4) |
| neutrals: equal heads and spines; irrelevant spine arguments skipped | 266, 317 | an irrelevant Π denotes constant functions: no function — including one built inside an irrelevant position — uses its irrelevant argument relevantly (§4 resurrection rule) |
| match eliminators: scrutinee, parameters and arms (arms under the fields' fresh variables, `arm_fields`); **motives not compared** | 292 | the value of a match does not depend on its motive in the set model, and both sides have the same type |
| transport neutrals: every component including the motive | 317 | structural |
| absurd neutrals: by type only | 317 | their context is inconsistent (no value exists) |
| checked `Shl/Shr` ≡ `WShl/WShr` | 67 | they compute identically (§7.2) |
| prim proof slots skipped | 317 | proof irrelevance |

*Memo* (§5.9): scoped to one top-level conversion, records positive results
keyed on both addresses plus the mode, keeps both values alive. Failure is
never memoized (conversion does not backtrack, so a failure propagates
immediately). *Pinned by:* kernel `eta_rules`, adversarial
`memo_address_reuse_churn`, `conversion_skips_exactly_the_irrelevant_positions`.

---------------------------------------------------------------------------

## 9. Linear arithmetic (`linarith.rs`, `check.rs:736`; DESIGN §5.8)

**Linearization** (`build`, 501; `lin_node`, 298) turns stated hypotheses
and the negated goal into constraints `e ≤ 0` / `e = 0` over ℤ with atoms
identified up to conversion. Every encoding is a true fact of the
primitive's semantics: literals; checked `add/sub` (exact on their domain,
which the term's own proof slot guarantees); `mul` and `imul` by a literal;
`iadd/isub/ineg`; `to_int`, `of_int`, widening and equal-width casts
transparent; definitional atoms with their constraints — `div/rem` (checked)
and `idiv/imod` by a literal `k > 0`, `wshr/shr` by a literal, `and` with a
literal mask `2^k−1`, truncating casts: a shared `(q, r)` with `a = k·q + r,
0 ≤ r ≤ k−1` (Euclidean division); `wadd`, `wsub`, `wmul` by a literal and
`wshl/shl` by a literal: a result atom and a carry `c` with `res = e −
2^w·c` and the carry range. Machine-typed atoms get `0 ≤ a ≤ 2^w−1`;
`seq::len` atoms `0 ≤ a`. Constraint order is canonical (hypotheses,
negated goal, implicit constraints in creation order; `Env::linearize`
exposes it). Hypothesis forms: `Eq(Bool, cmp_w(a, b), true|false)` except the
disjunctive `ne … true` / `eq … false`; `Eq(IntTy w, a, b)`. An equality
goal needs two refutations.

**Certificate check** (`check_cert`, 612; `check_problem`, 626 — the
trusted core): exact bignum rationals scaled by the lcm of the (positive)
denominators; `≤` constraints need nonnegative multipliers; accept iff the
combination has all atom coefficients zero and a positive constant (Farkas:
then the constraints are infeasible over ℚ, hence over ℤ).

**Phase-3 robustness** (`infer_linarith`, 646; INTERFACE_CHANGES "Phase 3"):
1. A stated hypothesis is justified by its (well-typed) proof, or — if the
   proof has another type — by a context assumption with the stated type,
   usable in the current relevance mode (`assumption`, 784; §4: relevant entries, and `Irr` entries bound outside the enclosing irrelevant position). This covers
   terms obtained by substitution that carry a proof only valid in another
   branch (e.g. the `refl` a dependent-match path equation was applied to).
2. The certificate is a hint: if it fails the exact check, the kernel
   searches (`lincert::farkas`, phase-I simplex over exact rationals,
   Bland's rule, every pivot charged to the budget) for the same system,
   then for the system extended with the context's hypotheses of §5.8 form
   (`context_facts`, 709; at most 64). Any certificate found goes through
   the same `check_cert`.

*Soundness argument:* acceptance still requires a verified Farkas
refutation, from hypotheses each of which holds in the context (inhabited by
a checked proof or by a context variable). The search is untrusted: a bug
there can only lose certificates. *Pinned by:* linarith (5 tests: forms,
canonical order, definitional atoms, stated props, the exact check and hint
semantics), adversarial `forged_and_overflowing_certificates_are_rejected`
(128-bit wraparound forgery, nonpositive denominators, `Empty` from
nothing), `linarith_hints_and_assumptions_cannot_prove_false_goals`, phase3
`linarith_*`.

*Limitations:* no nonlinear reasoning (products of two atoms are atoms;
`mul_mono` covers bounds, §11); trivial hypotheses after substitution
(`Eq(Bool, true, true)`) carry no information; the search is exponential in
the worst case only through pivot counts (Bland's rule terminates).

---------------------------------------------------------------------------

## 10. `BvRefl` and `bvnorm` (`bvnorm/`; DESIGN §9.8)

`bvrefl(A, a, b) : Eq(A, a, b)` is accepted (`check_bvrefl`,
`bvnorm/mod.rs:798`; `decide_in`, 711) iff
1. `a ≡ b` by conversion (checking mode), or
2. both terms, evaluated in the **`BvRefl` mode** — transparent (opaque
   definitions unfold, phase 3) with intrinsics unfolded on symbolic data;
   folded applications found in context values are unfolded when this mode's
   policy unfolds them (`expand_neutral`, 427) — land in the same class of
   the word normalizer (one bottom-up, hash-consed pass over both value DAGs,
   `Norm::visit`, 319), **and**
3. the **tripwire** (`tripwire.rs:273`) evaluates both *original* value DAGs
   on 36 valuations of their free atoms (4 corner valuations: all 0, all
   ones, 1, the top bit; 32 pseudo-random), independently of the normalizer's
   rewriting, and finds no difference.

The normalizer rules 1–7 (`word.rs` module doc, every rule an exact
identity on w-bit words): constant folding with the kernel's own literal
semantics and amounts mod w; `not x = x ⊕ ~0`; GF(2)-linear xor forms over
(atom, rotation, mask) terms with known-zero supports; sorted idempotent
`and`/`or` sets; truth tables over ≤ 4 variables; canonical sums mod 2^w;
bit-slice concatenation for provably disjoint supports and exact width
views; a class that the distribution of a low chunk *creates* (the sum of
the truncated summands, or an and/or set or truth table of truncated
operands, at a width w' below its base's) is recorded as that chunk of its
wide base B (`Norm::lows`; `word.rs` `view_class` 767, `base_of` 711), so its
bits resolve to B's bits when it is re-widened or re-chunked (the bytes of a
sum regrouped into u16 lanes and back are the sum). Generic nodes are keyed structurally with irrelevant positions skipped
exactly as in conversion, closures under fresh variables, match motives
ignored. Checked `add/sub/mul/shl/shr` are read as their wrapping forms
(they only occur in their domain, where they agree).

**One width per class.** A bound variable's class is its level
(`Gen([T_VAR, l])`) whatever its type, so binders at the same depth (sibling
λs, the arms of a match) share one class, as do classes built from them. The
support masks, rule 7's width views (including `lows`) and the tripwire's atom
masks all read a class's recorded width, so one width per class is a
soundness invariant. `note_width` (`word.rs:378`) sets `Norm::width_clash`
when a class that already has a width is used at another; `decide_in` then
answers `Different` ("not decided: a class is used at two machine widths"),
and `classify`/`tripwire_agrees` return an error, before classes are compared
or the tripwire runs. Before this (found by the 2026-09-24 red team,
`docs/shani-variantequiv-report.md`), the first width won: `(y as u16) >> 8`
for `y : U32` after a `U8` sibling normalized to 0, the tripwire (same masks)
agreed, and closed proofs of `Empty` were accepted.

*Justification:* each rule is an identity of ℤ/2^w (or of the evaluation
semantics); the transparent mode only unfolds definitions (identities); the
tripwire is a sanity net against normalizer bugs, not part of the argument.
The `lows` record is a value identity: the distributed class equals B mod
2^w' on every valuation (truncation is a ring homomorphism and commutes with
bitwise operators), so resolving its bit j to bit j of B is exact. Only
classes created by that very distribution are recorded (no view of them
exists yet), and B is always a base (never a view, never itself recorded), so
every bit keeps one canonical home. Rejecting a width clash is always sound;
with `width_clash` clear, every class has exactly one width, which is the
width of every use.
*Pinned by:* bvnorm (8 tests: every unsound candidate of docs/review-1.md
rejected by normalizer and kernel; exhaustive U8×U8, U16-over-bytes and
one-U16-atom generators with 65,536 valuations cross-checked against native
value tables; u32/u64 every shift amount; random trees), bv_demos (SHA
functions, rotations and byte order, 4-round SHA256H/H2, full ARMv8
compress = FIPS compress, a wrong constant rejected), adversarial
`bvrefl_cannot_prove_false_equations` (incl. through opaque definitions),
`bvnorm_memo_address_reuse_churn`, phase3 `variant_equiv_*` (the elaborated
shapes of `compress_sha2 == compress`, two wrong variants rejected),
bvnorm_lows (4 tests: the SHA-NI byte/u16/u32/u64 round trips of sums, sets
and truth tables land in the wide word's class by `classify` and by the
kernel's `bvrefl`, which fails on the pre-`lows` normalizer; near misses
rejected; exhaustive over two U8 atoms with aliasing low chunks in both
creation orders; random cross-width trees cross-checked natively),
bvnorm_widths (3 tests: four closed `Empty` lemmas — sibling λs, match arms
narrowing and widening, applications of sibling function binders — rejected
with the width message, all accepted before the fix; every entry point
rejects for both arm orders; same-width siblings still proven), front
`variant_shani` (`compress_shani == compress` proven directly in ~55 ms /
~11 MiB; 8 wrong variants rejected with "normal forms differ").

*Limitations* (always sound): rotations/shifts do not distribute over
and/or/truth-table classes; truth tables limited to 4 variables; sums
mixing disjoint and overlapping summands may split by association; no ring
normalization of symbolic products; λ/struct η only through the conversion
prefilter; a narrow class that already existed before a low chunk distributes
into it keeps its own views (order-dependent completeness only); a true
equation whose problem uses one class at two widths is not decided (siblings
at the same depth with different machine types, both used under primitives;
a complete fix would make a variable's class depend on its binder's width).

---------------------------------------------------------------------------

## 11. Axioms (`axioms.rs`; DESIGN §5.10)

`Axiom { ax, args }` is a full application of a schema's telescope (data
relevant, hypotheses irrelevant) and never computes. `AxiomId = schema·8 +
width` (widths U8 U16 U32 U64 Usize Int = 0..5); new schemas are appended.
Every schema is a fact about unsigned integers `0 ≤ a, b < 2^w` and the
exact Rust semantics:

| Schema (at every machine width unless noted) | Statement | Justification |
| --- | --- | --- |
| `and_le_left/right` | `a & b ≤ a`, `≤ b` | bits of `a & b` ⊆ bits of each |
| `or_ge_left/right` | `a ≤ a | b`, `b ≤ a | b` | bits ⊆ |
| `or_le_add` | `a | b ≤ a + b` (in `Int`) | no bit counted twice |
| `xor_le_or` | `a ^ b ≤ a | b` | bitwise ⊆ |
| `shr_le` | `wshr(a, s) ≤ a` | shifting right never increases |
| `min_def_le/gt`, `max_def_le/gt` | `min/max` by cases on `a ≤ b` | definition |
| `sat_sub_def_le/gt`, `sat_add_def_le/gt` | saturating ops by cases | definition |
| `count_ones_le` | `count_ones(a) ≤ w` | a w-bit word has ≤ w ones. **Derivable from `count_ones_def`** (the bits are remainders mod 2, each ≤ 1: one linarith step, `bits::count_ones_le_<w>` in `sandblaster/front/lemmas/bits.core`); `auto` uses the lemma. Kept only because the S0-owned `elab/basic.rs` (`BasicProver`, line 1448) names the schema; its removal (−3 lines) is queued with the O12 post-merge patches |
| `rotr_rotl` | `rotr(rotl(a, s), s) = a` | inverse bit permutations |
| `int_to_sat_def_in/lo/hi` | clamp of an `Int` | definition |
| `mul_mono` (Int only) | `0 ≤ a ≤ A ∧ 0 ≤ b ≤ B → a·b ≤ A·B` | monotonicity of multiplication on ℕ |
| `div_def`, `rem_def` | `b ≠ 0 →` checked `div/rem` = `idiv/imod` | unsigned truncating division is Euclidean on ℕ |
| `rem_lt` | `b ≠ 0 → a % b < b` | Euclidean remainder |
| `count_ones_def` (O3, K1) | `to_int(count_ones(a)) = Σ_{i<w} to_int((a >> i) & 1)` | the definition of population count: bit `i` of `a` is `(a >> i) & 1` (`i < w`, so the shift amount is exact) |
| `leading_zeros_def` (O3, K1) | `to_int(leading_zeros(a)) = Σ_{m<w} [a < 2^m]` | if `2^p ≤ a < 2^(p+1)` exactly the `m ≥ p+1` comparisons hold: `w−1−p` of them, which is `lz(a)`; for `a = 0` all `w` hold |
| `trailing_zeros_def` (O3, K1) | `to_int(trailing_zeros(a)) = Σ_{1≤m≤w} [a & (2^m − 1) = 0]` | if `t` is the lowest set bit exactly the masks with `m ≤ t` are zero: `t` of them; for `a = 0` all `w` (the `m = w` mask is the all-ones literal) |
| *retired* `leading_zeros_le/lt`, `trailing_zeros_le/lt` (phase 3) | — | O3: valid at no width (ids kept, names no longer parse); now the checked lemmas `bits::{leading,trailing}_zeros_{le,lt}_<w>` derived from K1 |

K1 here is the optimizer design's kernel delta (§11.4 of
`docs/optimizer-design.md`), not the phase-3 issue K1 of §5/§8. Notation:
`[b]` is `match b : Bool return Int with | false => 0int |
true => 1int end`, `Σ` is a left-nested `iadd`, `to_int` the cast to
`Int`, all literals are in range at width `w`. The statements are in `Int`
so linarith needs no carry atoms (a sum in `U32` would add carries it
cannot eliminate). K1 adds no new term former and no new evaluation rule:
each schema is one more closed statement whose truth in the set model is a
fact about `w`-bit naturals and the Rust semantics of the primitive
(`prim.rs::eval_machine`: `count_ones`, `leading_zeros − (64 − w)`,
`trailing_zeros` with `w` for 0).

*Pinned by:* axioms (12 tests): each schema's hypotheses and statement are
evaluated by the kernel and compared with an **independent native Rust
computation** — U8 exhaustive over all argument tuples, U16 exhaustive in
each argument (others on a boundary grid), U32/U64/Usize boundaries, Int
schemas on grids; ids round-trip, retired schemas are valid nowhere, every
axiom type is well-formed. K1 additionally: both sides compared with native
`count_ones`/`leading_zeros`/`trailing_zeros` exhaustively over U8/U16 and
at every single-bit, all-ones-prefix and all-ones-suffix value (± 1), 0 and
~0 at every width (`k1_exhaustive_u8_u16`, `k1_patterns_at_every_width`);
10^7 random values per width at U32/U64/Usize (`k1_random_at_u32_u64_usize`,
uniform, sparse and dense words) through a native interpreter of the
kernel's statement *term* (independent of the kernel evaluator), every
1024th value also through the kernel evaluator (asserted equal); the
statements are printed and compared with an independent construction from
the specification (`k1_statements_match_the_specification`); and the R20
mutations — `lz`/`tz` sums swapped, off-by-one summand ranges at either
end, `≤` for `<` — each fail the exhaustive U8 and U16 check
(`k1_mutations_are_rejected_by_the_exhaustive_tests`). `phase3.rs`
`bit_count_definitions_discharge_bit_length_obligations` derives the
retired bounds in core text (`64 − lz(x)`, `63 − tz(x)` for `x ≠ 0`).

---------------------------------------------------------------------------

## 12. Prelude definitions (TCB item 3)

`prelude/*.core`, embedded with `include_str!` (`prelude.rs:25`), expanded
by the `%for W in …` template (`expand_templates`, 37: `$w $W $BITS $BYTES
$MAX` substitution), parsed by the core-text parser and **checked** item by
item by `add_def`/`add_inductive` — so the prelude cannot be ill-typed; what
is trusted is that each definition *means* the Rust method it models.

| File | Items | Content |
| --- | --- | --- |
| `base.core` | 35 (6 lemmas) | Unit, Option, Either, Tuple2..12, Not/And/Or/Iff/Exists, equality lemmas (`eq::promote`), bool ops, option methods |
| `list.core` | 19 (6 lemmas) | List and `seq::*` (len, cons, index, update, take, drop, append, rev, replicate, split_first_chunk, eq) |
| `slice.core` | 40 (3 lemmas) | `SliceOk`, `Slice` (`Σ(n : Usize). Σ(l : List T). .SliceOk`), `Array` (`Σ(l : List T). .Eq(Int, len l, N)`), array and slice methods, chunking (`seq::chunks_c`/`chunks_rest_c` start the loops `seq::chunks_go`/`chunks_rest_go` at `n = len l`; the loops test the carried length `n`, with its equation `hn : Eq(Int, n, len l)` as an irrelevant argument, so chunking a list of length L takes O(L) evaluation steps, not O(L²/N): §15 S1 review, known-answer vectors of several KiB. Each step refers to `hn` once — `p1` (N ≤ len l) and `pn` (the next step's `hn`) are both projected from one proof `q` — so the chunks' length certificates form a chain whose read-back is linear in the number of chunks with the read-back memo (§7.5); the S1 text referred to `hn` twice per step, which doubled the read-back per chunk without the memo. The loops' own result certificates (the `snd` of `chunks_c`/`chunks_rest_c`, and the `SliceOk` proofs of `slice::as_chunks`) mention the previous result twice: their read-back is linear through the memo alone) |
| `int.core` | 26 | integer methods at every width (wrapping, rotate, count/leading/trailing, swap_bytes, min/max, saturating, checked, abs_diff, …) |
| `bytes.core` | 12 (3 intrinsic) | `from_le_bytes` (intrinsic: folded on symbolic data so the §7.3 byte rules apply), `to_le`, `from_be := from_le ∘ rev`, `to_be` |

`def[lemma]` items are checked and untrusted. *Pinned by:* prelude (loads;
slice, array, integer and byte methods computed against native Rust; lemmas
usable), syntax `whole_prelude_round_trips` (the printer/parser agree on
every item — a guard against the parser misreading the trusted text),
prelude_load. *Known:* `SliceOk`'s bound `n ≤ ISIZE_MAX` is only sound for
non-zero-sized element types (the front end rejects zero-sized slice
elements, DESIGN §3.2).

---------------------------------------------------------------------------

## 13. API-level checks (`api.rs`, `alpha.rs`)

* `add_def`, `add_inductive`, `check`, `infer`: §3–§6. Each public entry
  point installs the stack guard (§14).
* `check_residual_equal` (`alpha.rs:270`, codegen): the candidate must be
  straight-line (no relevant `match`, `rec`, `absurd`, no relevant reference
  to the reference or a later global — it is emitted as the reference's
  body), well-typed at the reference's type with `Erased` allowed only in
  irrelevant positions, and convertible with the reference in the
  transparent mode (unfolding is sound). *Pinned by:* kernel
  `residual_candidates`, opaque `residuals_are_compared_transparently`.
* `alpha_eq_relevant` (`alpha.rs:196`, codegen round trip DESIGN §8.3):
  syntactic α-equivalence ignoring names and every irrelevant position
  (never evaluates, except to find the Σ of a pair whose type is not
  syntactically a Σ); shared node pairs found equal are memoized. *Pinned
  by:* adversarial `round_trip_mutations_are_detected` (hoisting a checked
  read, `x*0`, an unused let — all convertible, all rejected), kernel
  `alpha_eq_relevant_ignores_names_and_proofs`.
* `quote`, `quote_typed`, `abstract_occurrences(_ext)`, `linearize`,
  `bvnorm::{decide, classify}`, `linarith::check_certificate`: tools for
  automation; their outputs are checked again by the kernel when used.
* `refs_closure`, `abstract_section` (§19) and `eval_closed` (§20): trusted
  (DESIGN §15): the first two define what "fully specified" claims, the
  third is the kernel's verdict on a known-answer example.

---------------------------------------------------------------------------

## 14. Resource limits

* **Budget:** every evaluation/conversion/checking step ticks
  (`util.rs:23`); exhaustion is an error. Speculation uses a sub-budget whose
  exhaustion keeps an application folded (sound).
* **Stack:** the kernel is recursive over terms and values. The outermost
  API call records the stack position (`StackGuard`, `util.rs:85`, the
  address of a local — no `unsafe`), and `tick` reports `OutOfFuel` when more
  than the thread's allowance (default 1.5 MiB, `set_stack_limit`) is used
  (checked every 16 steps). *Pinned by:* depth
  `deep_non_tail_recursion_is_an_error_not_a_crash`.
* **`Int`:** 4096-bit limit, `IntOverflow` (prims
  `int_implementation_limit_is_an_error`).
* **Heap (phase 4):** the kernel depends on `sandblaster-memguard`, which
  installs a counting global allocator in every binary linking the kernel
  (hard cap: an allocation beyond it fails and Rust aborts the process;
  default 8 GiB, `SANDBLASTER_MEM_LIMIT_GB` via `init_from_env` in the build
  script and CLI). `tick` polls its *soft* limit at the stack-check period
  (`util.rs:31`, two relaxed atomic loads every 16 steps) and reports
  `OutOfFuel` once the process holds more heap than that, so a runaway
  proof search or symbolic execution fails gracefully instead of exhausting
  the host (the phase-4 red team was killed by memory exhaustion). This is
  resource control, **not TCB-relevant**: the probe can only turn a check
  into a failure, never into success (`OutOfFuel` is never success, §2.4),
  and the allocator only forwards to `System`. *Pinned by:*
  `tests/memguard.rs` `soft_memory_limit_makes_large_evaluations_fail_gracefully`
  (a 24 MiB evaluation fails with `OutOfFuel` under a soft limit 1 MiB
  above the current heap, with the hard limit 8 MiB above it as a tripwire;
  with the limits restored it completes).

---------------------------------------------------------------------------

## 15. What is not trusted

The front end, elaborator, automation, optimizer and printer (DESIGN §1.1);
in this crate: `lincert` (search output re-checked), `abstract_occurrences`
and typed quoting for automation (outputs re-checked), diagnostics
(size-bounded rendering), the printer (except as the round-trip guard of
the prelude text), `Env::linearize` (the kernel rebuilds the system itself),
`bvnorm::decide`/`classify` as used by automation (the kernel re-decides).
The `sandblaster-memguard` dependency and the heap probe in `tick` (§14) are
resource control: they can only make a check fail.

---------------------------------------------------------------------------

## 16. Known limitations and residual risks

1. **Quote in `infer(λ)`.** The Π codomain of an inferred λ type is the
   read-back of the body type (`check.rs:462`); a quoter bug could produce a
   wrong type there. Analysis of the placeholders the quoter may emit:
   `Erased` appears only as an irrelevant proof (`absurd`, `transport`
   equations — never evaluated) or as the Σ annotation of a pair whose type
   is unknown, which makes the re-evaluated pair's second component relevant
   and so conversion only *stricter*. Typed quotes are re-checked in
   `kernel.rs::typed_quotes_recheck` and phase3 `k1_*`. Still, this is the
   one place a large component (the quoter) is trusted (simplification in
   §17).
2. **Match motives are not compared in conversion** (§8). Sound in the set
   model because both sides have the same type; relies on the checker having
   typed both.
3. **`refl ≡ refl` and absurd-by-type** (§8): rely on UIP and on the
   inconsistency of contexts containing an absurd neutral.
4. **Address-keyed memos** (§2.2): each keeps its keys alive; reviewed for
   every memo (conversion, `bvnorm`, evaluation, inference, quoting,
   traversals, alpha). A future memo that forgets to keep a key alive would
   be a soundness bug (address reuse). The read-back memo's key must also
   fix everything else the read-back depends on (depth, own binders,
   context types), and every type the quoter reads must be a function of
   the path to the read (red team 2026-09-25): §7.5.
5. **`Rc::strong_count` reasoning** in `resume` (speculation reuse) and in
   the "shared node" tests of the memos: counts only decide *whether an
   optimization applies*; a wrong count leads to re-evaluation or a missed
   memo hit, never to a different value.
6. **Measure recursion under inconsistent hypotheses** may loop at
   evaluation time (budget error), by design (§6).
7. **`bvnorm` is large** (2k lines) and trusted; the tripwire is a sanity
   net, not a proof. Long term: prove the normalizer by reflection (DESIGN
   §9.8), making `BvRefl` ordinary conversion.
8. **Prelude parse:** the prelude is read by the (1.7k-line) parser; a
   parser bug that consistently misreads the text would change the trusted
   definitions. Mitigated by the round-trip test and by the prelude's
   behavioural tests against native Rust.
9. **Linarith assumption justification** trusts the context: the kernel
   API accepts contexts built by the caller (`Ctx`), whose entries are
   assumptions by definition. A caller that builds an inconsistent context
   can prove anything *in that context*; top-level definitions are checked in
   the empty context (`add_def`).
10. **Relevance discipline (phase 4).** Soundness of skipping irrelevant
    positions in conversion rests on the resurrection rule (§4) and on
    `is_prop` being conservative (a type it accepts must be a subsingleton
    in the set model: `Eq` by UIP, Π into / Σ of subsingletons, and
    single-constructor non-recursive inductives of subsingletons). The
    phase-3 single-flag rule was unsound (R1); DESIGN §5.3's sentence "in an
    irrelevant position, all context variables are usable" is superseded by
    "the variables bound outside it are usable".
11. **Completeness gaps** (sound): the §5.6 policy keeps non-ground
    recursion folded; opacity in checking mode; `bvnorm` limitations (§10);
    no nonlinear arithmetic (§9); abstraction inside proofs is best effort
    (`abstract_occurrences_ext`).
12. **§15 statements are relative to caller inputs** (§19): `complete_p(R)`
    is correct for the section, hypotheses, views and stop set it is given;
    choosing them, view adequacy, proving every returned statement and the
    well-foundedness of sections over the returned `deps` are enforced by
    the front end. The kernel does check that the stop set holds only exec
    functions, never inlines a non-spec global, and requires members of a
    split requires to be published with an exact `obs_eq`.

---------------------------------------------------------------------------

## 17. Size and simplification opportunities

The kernel is 9.9k code lines (12.7k total) against the DESIGN §1.1 target
of < 8k. Candidates, in order of TCB reduction per effort:

1. **Take the parser out of the TCB** (−1.5k trusted lines): ship the
   prelude as checked terms produced at build time, or keep the parser but
   verify the prelude by a second, independent reader in the tests (the
   round trip already partly does this).
2. **Take the quoter out of the TCB** (−0.7k): infer λ types without read-back
   (e.g. a Π value whose codomain closure re-infers the body, or require
   annotations — every λ in checked code is checked against a Π anyway, and
   inference of bare λs is rare). Typed quoting, sharing and abstraction then
   become automation-side (they could even move to the front end).
3. **Move `lincert` (0.2k, untrusted) to a clearly separate crate** — it is
   already outside the argument; keeping it here is a convenience for the
   hint semantics.
4. **Performance shortcuts** in `eval.rs` (speculation reuse `resume`,
   direct list indexing, the evaluation memo, ≈ 0.3k lines) are optimizations
   that compute exactly what plain evaluation computes; they could be
   dropped at a cost in speed (measured: phase-2 perf table).
5. **`bvnorm` by reflection** (−2k): the long-term plan (§10).
6. `alpha.rs` (0.23k) is only trusted for the codegen round trip claim; it
   could move next to the round trip if that claim's TCB is accounted there.
7. Smaller: `garbage()` placeholders for non-dependent codomains could be
   replaced by always evaluating arguments (simpler, slower); the typed
   quote's field-type recomputation duplicates `arm_fields`.

Nothing in the crate is dead code; `Env::conv_opaque`, `eval_opaque` and
`check_residual_equal` are used by the optimizer.

---------------------------------------------------------------------------

## 18. Running the tests

```text
CARGO_TARGET_DIR=target/<dir> cargo test -p sandblaster-kernel -- --test-threads=2   # ≈ 20 s (opt-level 3 dev profile; ≈ 55 s while
#   sandblaster-memguard is built at opt-level 0 in the dev profile: its counting allocator is then the hot spot)
CARGO_TARGET_DIR=target/<dir> cargo test -p sandblaster-kernel --lib    # the read-back memo's unit tests (tests/unit/quote_memo.rs, §7.5)
CARGO_TARGET_DIR=target/<dir> cargo test -p sandblaster-kernel --test adversarial --test phase3 --test redteam
CARGO_TARGET_DIR=target/<dir> cargo test -p sandblaster-kernel --test axioms --test prims    # exhaustive semantics checks
CARGO_TARGET_DIR=target/<dir> cargo test --release -p sandblaster-kernel --test perf --test perf_sha --test bv_demos -- --nocapture
```

| Test file | Tests | What it pins |
| --- | --- | --- |
| `adversarial.rs` | 22 | every must-accept/must-reject case of DESIGN §5.3 and docs/review-1.md; phase-3 rules (linarith hints/assumptions, ground recursion, evaluation memo, transparent `BvRefl`); phase-4 resurrection and proposition rules (red team R1) |
| `redteam.rs` | 15 | red-team R1 reproductions r1a–r1e (must reject), prelude integer/byte fidelity against native Rust, false word/arithmetic statements |
| `memguard.rs` | 1 | the heap probe of `tick` (§14) |
| `kernel.rs` | 17 | sorts, relevance must-accept, inductives/ι, η rules, array η, recursion policy, `Delta`/`Unfold`, quote, alpha, abstraction, residuals, intrinsics, budget |
| `phase3.rs` | 11 | K1 (match arms), ground recursion, abstraction (heads, prefixes, proofs), linarith robustness, DAGs, VariantEquiv, bit-length bounds from the K1 bit-count definitions |
| `axioms.rs` | 12 | every axiom schema against native Rust; the K1 bit-count definitions exhaustively (U8/U16), on patterns, at 10^7 random values per width, against the specification, and the R20 mutations |
| `prims.rs`, `simplify.rs` | 4, 6 | primitive semantics and §5.7 rules against native Rust |
| `linarith.rs` | 5 | §5.8 forms, order, atoms, exact check |
| `bvnorm.rs`, `bvnorm_lows.rs`, `bvnorm_widths.rs`, `bv_demos.rs` | 8, 4, 3, 6 | §9.8 soundness generators, distributed low chunks, one width per class, demos |
| `opaque.rs`, `eval_opt.rs`, `depth.rs` | 6, 2, 2 | opacity, evaluator shortcuts, stack safety |
| `prelude.rs`, `prelude_load.rs`, `syntax.rs` | 6, 2, 6 | prelude semantics and round trip; the target intrinsic models check |
| `perf.rs`, `perf_sha.rs`, `smoke.rs` | 1, 1, 1 | performance smoke tests |
| `section.rs` | 16 | §19: `Refs*`; `complete_p(R)` must-accept (proven against the returned term) and must-reject cases |
| `eval_closed.rs` | 4 | §20: agreement with the reference evaluator and native Rust, completion, failure modes |
| `unit/quote_memo.rs` (lib unit tests of `quote.rs`) | 15 | §7.5: memoized = unmemoized read-back (random DAGs, depths, own binders, context types, arm fields; red-team values outside §2.1 on fresh quoters, in sequences and with address reuse; closure binders and un-evaluable fields read as unknown; calls from outside start from their context); linear read-back of proof chains and chunk certificates; the memo off in the other modes |

---------------------------------------------------------------------------

## 19. `Refs*` and section abstraction (`section.rs`; DESIGN §15.1, §15.5)

**Why this is trusted.** `Env::abstract_section` builds the statement
`complete_p(R)` that *defines* the claim "the specification determines
`p`". The front end proves it and the kernel checks that proof against
exactly the returned term, but a wrong statement (a partial substitution,
a hypothesis still pointing at the real function, a forged goal, an extra
unsatisfiable hypothesis) would make the claim vacuous while every proof
checks. So the statement is built here, from kernel data only, and never
accepted from the caller (review 4, R4-A4). `Env::refs_closure` is the
spec-closure relation the front end uses to compute `Deps(R)` and to enforce
§15.1.

**Relevant positions** (`relevant_children`, one table for both functions):
every child of a term except an `Irr` application argument or let value, the
second component of a pair whose Σ is `Irr` (`alpha::pair_snd_rel`), prim
proof slots, the `Rec` proof, `Transport.eq`, `Absurd.proof`, `Irr`
constructor fields and the `Irr` arguments of `Delta`/`Unfold`/axioms.
Binder domains (including those of `Irr` binders), motives and the stated
propositions inside proof terms are relevant. *Justification (set model,
§2):* an irrelevant position denotes only that its type is inhabited, which
type checking establishes; the denotation of a term is a function of its
relevant positions and of the denotations of the globals and inductives
referenced there.

**`Refs*`** (`closure`): the nodes (globals and inductives) referenced from
relevant positions of the roots (`Global`, the `def` of `Delta`/`Unfold`,
the inductive of `Ind`/`Ctor`/`Match`), closed under their declarations —
a global's type and stored body (opaque or not; loop helpers, `::ensures`
lemmas, prelude definitions alike), an inductive's parameter and field types
(`Irr` fields included: an invariant is part of the type's meaning) — not
descending into the stop set, whose members are listed when reached.
Iterative and linear in the term DAGs (each declaration walked once).
`refs_closure` returns the globals, by id.

**Construction** (`abstract_section`):

1. *Inputs* (`api::Section`): members `R` (distinct, known), published
   `P(R) ⊆ R` (distinct), hypotheses (lemma globals, optional restatements),
   views, established functions (known `Exec`/`LoopHelper` globals, disjoint
   from `R`: the stop set). Only an exec function can have been fully
   specified in an earlier section; a spec definition in the stop set would
   hide what its body reaches (red-team A2).
2. *Telescope.* Members sorted by id; `F_j'` gets the type of `r_j` placed
   at depth `j`. A type mentions only globals defined before it (`add_def`
   checks types before commit), so id order is a linear extension of the
   requires-reference DAG; a later member in a type is an error.
3. *Placement* (`Abs::place`): every `Global(r)`, `r ∈ R`, in every
   position becomes the variable of `F_r'`; every `Global(g)` in a relevant
   position with `g` outside `R` and the stop set whose `Refs*` meets `R`
   (`Abs::reaches`) becomes `g`'s body placed the same way (λ-lifting over
   the members, applied to them and inlined; memoized per depth) — **only
   if `g` is a `Spec` definition**. Any other kind that reaches `R` (an exec
   caller, a loop helper, a lemma, an `::ensures`) is an error: establish it
   or merge it into `R` (see "Why only spec definitions are lifted"). A
   recursive spec `g` cannot be inlined (no fixpoint term) and is an error.
   Free variables are renumbered through an explicit level map. Linear in
   the DAG (memo on node, depth and relevance).
4. *Hypotheses.* Hypothesis `i` is the *type of a global of the
   environment*, placed at depth `k + i`. A restatement (the caller's
   re-proven proof slots) replaces it only if `alpha_eq_relevant` with it:
   identical up to binder names and irrelevant positions.
5. *Views* (`api::SectionView`): `ty`, `target : Type` and `map : ty ->
   target` are type-checked in the empty context.
6. *Per published `p`:* `p`'s own parameter telescope (its first `arity`
   Π binders) is placed with the members abstracted. A relevant parameter
   type, or the result type, that mentions an `F'` is an error (the two
   sides of `obs_eq` would have different types). An `Irr` binder whose
   abstracted domain mentions an `F'` is split: `F_p'` receives a proof of
   the abstracted proposition, `p` a proof of its own (real) one; otherwise
   both receive the same proof. Every member whose `F'` occurs in a split
   domain must be published with an exact `obs_eq` (no view applied
   anywhere; checked after all statements are built), else the section is
   rejected (see "The split requires"; red-team A1). The conclusion is
   generated: `obs_eq(Out, F_p' x̄ h̄, p x̄ h̄')` (below).
7. *Typing.* Every binder domain is checked to be a type in the context of
   the previous binders, and the conclusion in the full context — the Π rule
   applied binder by binder, so the returned `Π` telescope is a well-typed
   closed type (`Type`, or `Kind` for generic sections).
8. *Spec closure of the statement.* `Refs*` of all abstracted parts
   (member types, hypotheses as bound, views, `p`'s abstracted parameter and
   result types), with the established functions as stop set, must not
   contain a member; the violation is reported with the part. The parts not
   checked are exactly the kernel-generated real side: `p` itself on the
   right of `obs_eq` and the real-side requires domains of split binders
   (both taken from `p`'s own type; the members these mention are published
   and exact, step 6). `deps` is this `Refs*` together with the λ-lifted
   globals and `Refs*` of their declarations (stop set: established ∪ `R`),
   members removed — DESIGN §15.5 computes `Deps(R)` on the hypotheses
   *before* lifting, so a lifted global must not disappear from it.

**`obs_eq`** (`obs`, DESIGN §15.5): at a type convertible with a view's
`ty`, `Eq(target, map a, map b)`; at a Π type, pointwise `Π(y). obs_eq(a y,
b y)` (there is no funext, so `Eq` at a function type would be unprovable);
at a relevant non-dependent Σ and at a struct-like inductive whose relevant
fields do not depend on each other (tuples), componentwise
(`Σ(_ : c₀). … cₙ`, projections by `match`) when some component is not plain;
otherwise `Eq(Out, a, b)` (by Σ/struct η, componentwise `Eq` of plain
components is equivalent to `Eq`).

**Why the statement cannot be forged.**
* The goal is not an input: `F_p'`, `p`, the arguments and the output type
  come from `p`'s type; only the view maps are caller terms, and they are
  applied by the kernel.
* Every hypothesis is the abstraction of the statement of a checked global,
  hence of a theorem about the real functions (a restatement may change only
  proofs). Interpreting every `F_r'` as `r` and `h_i` as the lemma satisfies
  the whole hypothesis telescope — lifting is sound for this because a
  lifted body with `F' := R` is `g`'s own body (δ) — so the hypotheses are
  jointly satisfiable: no `Empty`, no contradictory or goal-shaped
  hypothesis can be added. Omitting hypotheses only strengthens the
  statement.
* No abstracted part can refer to the real members through any relevant
  position, definition body, type or inductive declaration (step 8, which
  does not rely on the lifting heuristic of step 3: `reaches` only decides
  what is inlined, a miss is caught here). A hypothesis constrains `F'`
  only through the specification: spec functions (inlined by their
  bodies), established exec functions (listed in `deps`), trusted
  primitives. No exec implementation outside `R` is ever inlined (step 3).

**Why only spec definitions are lifted** (red-team A4). The meta-theorem
(DESIGN §15.5) quantifies over interpretations of the *exec* globals: each
exec function is interpreted on its own, independently of its body, while
a spec definition denotes its body under the interpretation. So a spec
occurrence `s ā` means `body_s[F'](ā)` and lifting is exact. An exec caller
`c ∉ R` whose body calls `f ∈ R` means `I(c)`, not `body_c[F'_f]`: inlining
it turns the law `c x == 5` into `F'_f x == 5`, a specification of `f`
taken from `c`'s implementation, and hid `c` from `deps` (attack:
`caller := f5`, law `caller x == 5`, `complete_f5` provable with `deps =
[]`). Rejecting instead forces the correct alternatives: `c` established
(the law is about the real `c` and says nothing about `F'_f`; `c ∈ deps`,
and `c`'s own section, whose hypotheses mention `f`, has `f ∈ deps`, so the
front end's well-foundedness check merges them) or `c ∈ R` (the law is
about `F'_c`). A lemma or `::ensures` in a relevant position is not a
definition either (its body is a proof about the real functions).

**Set-model reading.** Let `S = Π(F̄' : T̄[F'])(h̄ : H̄[F'])(x̄ : Ā)(ē :Irr
Req_p[F'](x̄))(ē' :Irr Req_p(x̄)). obs_eq(F_p' x̄ ē, p x̄ ē')`. By step 8 the
denotation of every abstracted part is a function of `F̄'` and of the
(fixed) denotations of non-member globals only (spec definitions inlined,
established and other non-member exec functions fixed — hence in `deps`).
So `S` holds iff every tuple of functions `F̄'` of the declared types
satisfying the hypotheses agrees with the real `p`, up to `obs_eq`, on
every input satisfying both `Req_p[F']` and `Req_p`; these coincide (next
paragraph), so on every valid input. The real functions satisfy the
hypotheses (above), so the statements of `P(R)` jointly are exactly §15.5's
determinacy of `P(R)` by `H(R)`, relative to `deps`; the meta-theorem
(≺-induction over well-founded sections) is the caller's, and so is proving
*every* returned statement.

**The shared `Irr` argument.** An irrelevant Π denotes functions constant in
the proof argument (§2): `F_p' x̄ h` and `p x̄ h` do not depend on which proof
`h` of `Req_p(x̄)` is supplied. Hence `Π(h). obs_eq(F_p' x̄ h, p x̄ h)` is
equivalent to `Π(h h'). obs_eq(F_p' x̄ h, p x̄ h')`: one shared binder
quantifies over exactly the valid inputs and loses nothing.

**The split requires** (red-team A1). When `Req_p` mentions members `Q ⊆ R`,
`Req_p[F']` and `Req_p` differ, DESIGN's `f_p x̄ h̄` with `h̄ : Req_p[F']` is
ill-typed, and typing needs two binders (step 6). The statement alone then
only claims agreement on inputs valid for *both*, and depends on the real
`q ∈ Q` through the real-side domain (outside step 8's check). Without
more, a merged section `R = {q, p}`, `P(R) = {p}` was accepted with `deps =
[]` although nothing specified `q'`: `p` was certified on a domain defined
by `q`'s implementation (the proof discharged a hypothesis's requires from
the real `q` by δ). So every `q ∈ Q` must be published with an exact
`obs_eq` (plain `Eq`, pointwise or componentwise without any view — in the
set model, equality). Then, for an interpretation satisfying the
hypotheses, `complete_q` gives `F_q' = q` on `q`'s valid inputs, and by
induction on the id order (the members in `q`'s requires have smaller ids
and are, recursively, published and exact) `q`'s two domains coincide, so
`F_q' = q` as functions; hence `Req_p[F'] = Req_p` and the two binders range
over the same valid inputs. The real-side mention of `q` is thus justified
by `complete_q`, which is part of the same claim. A view would only give
`α (F_q' x) = α (q x)`, which does not make the domains coincide; an
unpublished `q` has no statement at all — both are rejected.

**What the caller enforces** (not the kernel): the choice of `R`, `P(R)` and
`H(R)` (with `P(R)` containing every member in a published member's
requires, which the kernel checks); proving every returned statement; that
the stop set holds only exec functions fully specified in earlier sections
(the kernel checks the kind), and the well-foundedness of sections over
`deps` (DESIGN §15.5; e.g. the twin law `f x == g x` with `R = {f}` yields a
statement provable through `g`, and `deps` contains `g`; an established
caller of `f` is in `deps`, and `f` in the caller's); the adequacy of views
(injective or `Abstract(T)`, §15.2; views are locked surface items);
non-vacuity of requires (§15.5 Domain).

*Limitations* (all fail closed): a non-spec global outside `R` and the stop
set that reaches `R` (an exec caller, a loop helper) and a recursive spec
definition that reaches `R` cannot be lifted — establish or merge them; a
member in a published member's requires must itself be published, without
a view; an inductive whose declaration mentions `R` cannot be abstracted;
parameter and result types depending on `R` are rejected; proof slots proven
from facts about the real functions do not re-check after abstraction —
restate them (`SectionHyp::restated`); lifting inlines bodies (size).

*Pinned by:* `tests/section.rs` — `Refs*` through spec, opaque and loop
bodies, `::ensures` types and inductive fields, not through proofs, stop set
(1 test); must-accept, each proven against the returned term: refinement
only, exact characterization of a boolean function (and soundness alone not
provable), `Kind`-sorted generic section, requires telescope with split
(both members published and proven) and shared `Irr` binders,
views/tuples/function outputs (4); the twin law's `deps` (1); must-reject:
reaching `R` through a spec fn body and an opaque spec definition (lifted,
reported in `deps`: the attack proof that proves the unlifted statement
fails), an exec caller (rejected; established it is in `deps` and `f` is in
its section's `deps`; merged the law no longer pins `f'`), a loop helper and
a recursive spec fn, an `::ensures` lemma (relevant occurrence; proof slot,
accepted once restated) and an inductive (rejected), partial substitution,
forged conclusions and hypotheses (goal `f = f`, `Empty`, smuggled goal,
extra binder), malformed inputs including a spec fn in the stop set (9);
red-team regressions A4/A4b (lifted exec caller: rejected, established
reported and unprovable, merged unprovable) and A1 (split requires over an
unpublished or viewed member rejected; published, both statements proven)
(2). Mutations of the lifting, the spec-only lifting, the final `Refs*`
check, the restatement check, the requires split, the exactness check (and
its view flag), the stop-set kind check and the lifted `deps` are each
caught by these tests.

---------------------------------------------------------------------------

## 20. Closed evaluation (`closed.rs`; DESIGN §15.7)

**Why this is trusted.** An `#[example]` on an opaque (loop) function or on
non-tail recursion that checking-mode conversion keeps folded is decided by
`Env::eval_closed`; its result is the kernel's verdict (the front end's
`driver::Unfolder` remains a diagnostic).

**Steps.** (1) `infer` the term in the empty context: closed, well-typed,
no `Erased`. (2) Evaluate it in the fully transparent mode (`Ev::transparent`,
the mode of `check_residual_equal` and `BvRefl`: opaque definitions unfold).
(3) Complete (`Ground::deep`/`force`): a neutral headed by a global applied
to all its arguments is replaced by the global's body evaluated on the
(completed) arguments (`Ev::unfold`), a stuck primitive is recomputed on
completed operands (still stuck is an error), a stuck `transport` reduces to
its value when its completed endpoints are convertible (transparent
conversion; otherwise an error); the head's eliminators are then re-applied
(`apply`, `fst`, `snd`, and a `match` on a constructor selects its arm);
constructor fields and pair components are completed recursively (memo by
value address, keys kept alive). A variable, `absurd` or axiom head is an
error. (4) The result must be first-order data (constructors, literals,
pairs, `refl` in relevant positions). (5) Typed read-back.

**Justification.** Each step is an equation of the set model: β, ι,
projections, δ of a global's body (for any global, opaque or intrinsic), the
§5.7 literal semantics, and `transport` on equal endpoints; so
`eval_closed(t) = n` implies `⟦t⟧ = ⟦n⟧`. Because `t` is closed and
well-typed, every irrelevant argument reached is a closed checked proof of
a true proposition, so measure recursion really decreases and checked
primitives are in their domain; the budget bounds the work regardless, and
exhausting it (or the stack or heap allowance) is `OutOfFuel`, never a
result. The quoter is trusted only on first-order values, where read-back is
structural (irrelevant fields are quoted by substitution and are ignored by
conversion).

*Limitations:* completion recurses on the depth of the data (the stack guard
turns overflow into `OutOfFuel`; run large examples on a big stack); results
are read back without sharing; function-valued results are rejected (apply
them to arguments instead).

*Pinned by:* `tests/eval_closed.rs` — path-like non-tail recursion that
inspects its own result, opaque, for several sizes: equal to the reference
evaluator (the driver's `Unfolder`, reproduced from public operations) and
to native Rust; boolean examples over it; `refl` fails in checking mode
where `eval_closed` computes; an intrinsic applied to a λ (folded by every
evaluation mode) completed at the top, under a primitive and under a match;
budget exhaustion, ill-typed, open and `Erased` terms, and non-data results
are errors.

---------------------------------------------------------------------------

## 21. The lift, the buffer model and host models (DESIGN §1.1 item 8)

Front-end code, listed here so that the whole TCB audit is in one place.
A lifted module (`#[lift] mod m;`) is an existing Rust file the host crate
compiles **as-is**; the proofs are about the lift's translation of it. A
translation bug makes a proven law false of the shipped code without any
kernel error, so the translation is trusted.

**Trusted code.**

| File | Lines (total / code) | Role |
| --- | --- | --- |
| `sandblaster/front/src/lift.rs` | 4072 / 3511 | the reading: preprocessing (`macro_rules!` expansion ≈ 0.3k, inline-module flattening, host-only items dropped), sealed-trait monomorphization (`instances`, `check_sealed`), state passing (`lift_fn_b`, `FnRw::states`), the rewrite table (`FnRw::rewrite*`, `signed_rewrite`), loop helpers (`loop_helper`), attachments (ghost: they add contracts, never code) |
| `sandblaster/front/lift/prelude.rs` | 76 / 38 | `Result`, `TryGetError`, `I16`/`I32`/`I64`, `iN_shr`, `iN_neg` (exec: checked like any code; trusted to *mean* core's) |
| `sandblaster/front/lift/model.rs` | 88 / 54 | the buffer model: `bufmut_put_u8`, `bufmut_put_slice`, `buf_try_get_u8`, and the signed conversions of ghost code |
| `sandblaster/front/src/elab/lift.core` | 29 / 24 | `uN::div_ceil` |
| `#[lift(host)]` modules (per crate) | — | the host items the source names, as the proofs see them |

Budget: 4k code lines. Everything a rule does not cover is an error
(`Ctx::err`), never a guess; a signed operation without a rule does not
type check (the signed types are distinct structs).

**What an auditor checks, rule by rule** (the table at the top of
`lift.rs`, SEMANTICS.md §19): that each rewrite preserves rustc's meaning
*including panics* — a Rust panic must become an obligation (`unreachable!()`
or a checked operation), never a value. Rules whose argument is not local:
monomorphization relies on the trait being sealed (declared in a private
inline module: rustc's coherence and privacy make the impl set closed);
a sealed-trait method named like an inherent integer method must be a pure
delegation in every impl (`check_sealed`), so both resolutions agree;
`T::SIZE` is read as `size_of::<T>()` and the emitted module's tail makes
rustc check each such value against the host (`const _: () =
assert!(..)`); every host-model variant is checked the same way.

**Host assumptions.** The caller's `Buf`/`BufMut` behave as the byte
sequences of `lift/model.rs`; the host traits (`Read`, `Write`,
`EncodeSize`, `FixedSize`, codec's `Buf`) have commonware-codec's
signatures (rustc checks the as-is file against the real ones in the host
build; the lift checks it against the assumed ones).

**Mitigation: the lift conformance check** (`src/conform.rs`, not trusted).
Every module-mode build of a lifted module runs it after the gates and
before emitting. For each lifted exec function (the lift records the
original item and each parameter's passing mode, `lift::ConformEntry`) the
kernel evaluates the lifted function (`Env::eval_closed`; arguments with
invariant fields carry erased proofs, so those go through the reference
strategy of `sandblaster eval`) and a generated harness calls the original,
compiled by the build's `rustc` with overflow checks and debug assertions,
on the same deterministic, coverage-driven inputs (400 kernel evaluations
per function). States and results must be equal. The harness links
`lift/conform_host.rs` (the host traits) and `lift/conform_bytes.rs` (the
buffer model in Rust, compiled as the crate `bytes`), which the pilot's
`vshim` compares with the real `bytes` crate (put/get sequences on
`Vec<u8>`, `BytesMut`, `&[u8]`, `Bytes`, chains). The check can only fail
a build; a wrong shim could hide a misreading but never create one.

*Pinned by:* `sandblaster/front/tests/lift_conformance.rs` (a small
codec passes; the negative twins — `lift::test_hook::WrongRule::SignedShrLogical`
and `InclusiveRangeAsExclusive`, deliberately wrong rules — are caught
with the inputs that show them; cache and failure paths),
`tests/aug_int_toolchain.rs` (signed operations against rustc),
`tests/lift.rs` (`div_ceil` against rustc; each refusal), the varint
pilot (six widths: every lifted function of `varint.rs` agrees with rustc's
build in the pilot's own build).

*Known gaps.* The check is a test: inputs it never generates are not
compared. Not compared: functions with a precondition (the lift's loop
helpers; their callers are), functions inside inline modules the harness
cannot name, `#[lift(unverified = ..)]` instances (`u128`/`i128` for
varint: not lifted, unchecked host code) and dropped items. The harness
runs on the build host, not the target (the lifted widths are fixed; both
are 64-bit). The host-model *meaning* beyond variant names and payload
types (for example that the host's `Error::InvalidVarint(n)` carries what
the model says) is not checked.

### 21.1 Function bodies: the literal reading of rustc's MIR

Function bodies of lifted exec modules are read only from rustc's MIR
(`#[lift(mir = "m.sbmir")]`, `docs/mir-lift.md` §20). Since
`docs/checked-structuring.md`, the **trusted** reading of a body is the
literal reading L, and the structured reading S that the laws and proofs
are about is checked against it by a kernel theorem per lifted function.

**Trusted code** (code lines: no blank lines, comments or tests).

| File | Code lines | Role | Trusts |
| --- | --- | --- | --- |
| `front/src/mir/literal.rs` | 1,217 | L's generator: per MIR instance, `Root`, `St` (one `Option` slot per local, one per `&mut` referent cell), `Blk`, `rank`, `run` by measure recursion (fuel only at loop headers and self-calls); places, reference codes, calls with the cell protocol, operators, casts, intrinsics, leaves — tables, each construct read locally. The post-order, the loop headers, the panicking blocks and type-occurrence pruning come from the untrusted `cfg.rs` as numbers and booleans: they only place fuel (every decrease is kernel-checked) or read a block or path as `None` | the MIR reference (each construct's meaning); `literal.core`; the names of `mod.rs`; the lift's models in the leaves (A5); `cfg.rs` for nothing but fuel placement and `None` |
| `front/src/mir/literal.core` | 139 | L's library: the option monad, checked/unchecked/division operators per width, signed comparisons and sign extension of bits, `bswap`, array get/set under the bound test, the leaves' models | the kernel's primitives and prelude; the lift's models (`crate::__lift_model`, host models) in the leaves |
| `front/src/mir/stmt.rs` | 210 | the statement `L::thm::f`: `S_f`'s telescope, `init`, `erase` (its preconditions are `S_f`'s, which the elaborator's check below makes the declared contract's) | `S_f`'s telescope (the elaborator and its precondition check); L's `LFn` record |
| `front/src/mir/ir.rs`, `sexp.rs` | 482, 131 | the parse L reads; malformed input is an error, never a default | the printer's format |
| `front/src/mir/mod.rs` | 491 | names (`kernel_adt`, `is_transparent`, `host_model_method`, `instance_global`: the lifted function a module instance is) and the load checks (format version, module, compiler release, overflow checks, the sources' SHA-256) | the lift's names (`ModuleNames`: DSL modules, sealed traits, host models) |
| `sandblaster/mirx` | 1,131 | the printer (rustc's data, transcribed) | rustc (A4: the build compiles the MIR it printed) |
| `front/src/mir/gate.rs` and its call sites | 164 + ≈ 25 | the gate's trusted check: the literal reading enters the kernel only through its loader (which records, per extraction, the globals and inductives it loaded and the MIR of each instance it read); a listed function is accepted only when its MIR instance is that function (the lift finds instances by unqualified lifted names), the kernel holds `L::thm::<f>` whose type is α-equal (up to proofs) to `stmt`'s statement generated afresh, read from this MIR, reaching only definitions of the elaboration, of L's library or of its own extraction's literal reading, with no inductive added otherwise, and every module type its MIR instances reach is declared alike by the MIR and the subset (variants and fields by name and in order, discriminants `0, 1, ..`); the same for the round trip's `L::shipped::<f>`. Call sites: the gate's errors (`driver::gates::theorem_gate`), the shipped copy's instance and its requirement (`driver::lowered`) | the kernel (`alpha_eq_relevant`, `refs_closure`); the files above; the lift's list of the functions read from MIR; the elaborator |
| the precondition check: `front/src/elab/items.rs` (`fn_requires`, `as_declared`, `depth_prop`), `typeck` (`#[mir_contract]`), `hir::FnDef::declared` | 22 + 16 + 1 | a function read from MIR is elaborated only when it has as many `requires` clauses as its declared contract, each precondition α-equal to the elaboration of the declared clause at the same depth, and the depth bound exactly when declared, α-equal to the declared one; the lift carries the declared contract apart from the function's own attributes (`#[mir_contract(..)]`, copied from the skeleton's and the attachments' attributes). Otherwise the function has no definition, so no theorem | typeck and the elaborator (TCB items 2, 6) |
| the lift glue | ≈ 260 | loading, signature checks, the declared contracts (the skeleton's attributes before the body is read and the attachments' after, carried as `#[mir_contract(..)]`; the body reader sees the signature only), the list of functions read from MIR (`lift::MirContract`) | the lift's skeleton (TCB item 8) |
| **total** | **≈ 4,289** (≈ 3,676 without the parse) | the literal reading, its statement, parse, names and printer (3,801), the gate's trusted check with its call sites (≈ 189), the precondition check (39), the lift glue (≈ 260); ≈ 4,972 when the structurer's trust was first replaced, ≈ 4,780 with the structurer trusted (`docs/checked-structuring.md`, stage tcb-review) | |

**Untrusted**: `front/src/mir/read.rs` (2,433, the structurer), `cfg.rs`
(298, with the literal reading's shape facts), the walker `simproof.rs` (4,565) and its driver `checked.rs`
(planning, dependency order, loop and model lemmas, the verdict cache —
whose entries are declarations the kernel re-checks on replay — and the
reports). A bug there makes a theorem missing or refused and the build
fail.

**What an auditor checks.** Construct by construct, that L's reading of
each MIR construct (the tables of `docs/mir-lift.md` §20.4) gives a value
only where rustc's semantics gives that value, and `None` for a panic,
undefined behaviour or anything not modeled: wrapping `Add`/`Sub`/`Mul`,
checked operations as (wrapped, flag), `Shl`/`Shr` with the amount masked
(the kernel's `#wshl` is `x << (y mod w)`), unchecked shifts undefined at
or above the width with the amount compared at its own type, sign
extension only from signed types, `Transmute` to little-endian bytes,
discriminants at the destination's type, moves leaving the slot (not read
again in borrow-checked MIR), drops with glue only for variants without
drop code, shared references as snapshots and `&mut` as reference codes
written back after each call (exclusivity, A3 of the design note). The
statement: that `init` places each parameter in its slot and `erase` maps
S's value to L's componentwise. The precondition check: that the lift's
`#[mir_contract(..)]` copies exactly the skeleton's and the attachments'
`requires`/`decreases` attributes, and that the elaborator compares each
precondition with the declared clause elaborated at the same depth. The
gate: that a listed function's MIR instance is that function
(`ModuleNames::instance_global` against the lift's global), that the
statement is generated afresh and compared with the kernel's declaration
in every relevant position and every binder's domain, and that every
global it reaches comes from the elaboration, L's library or the
function's own extraction's reading.

**Review findings of stage cs-assurance, fixed with tests**
(`tests/literal.rs` `readings_the_review_found_wrong_are_none_where_rust_differs`,
`the_parse_refuses_what_it_would_have_guessed`): `u128`/`i128` were read as
64-bit words (now not modeled); `ShlUnchecked`/`ShrUnchecked` by an amount
of another width tested only the amount's low 32 bits (a `u64` amount of
`2^32` read as a shift by 0); a zero-sized constant of an ADT with several
variants was read as its first variant; the parse defaulted a malformed
discriminant to 0, an assertion's malformed expected value to `false`, and
did not check that variants and locals are listed in order; a library
type and an index leaf's range were recognized by a path *suffix*
(`ops::RangeTo` also matched a crate's `myops::RangeTo`, and a crate named
`option` would have had its `Option` read as core's): both now match the
exact path under `std::`/`core::` (`bytes::TryGetError` as written).

**Review findings of stage tcb-review, fixed with tests**
(`tests/theorem_gate.rs` `a_function_listed_with_another_functions_instance_is_refused`,
`a_reading_whose_names_a_later_extraction_took_over_is_refused`;
`tests/literal.rs` `readings_the_review_found_wrong_are_none_where_rust_differs`):
the gate did not check that a listed function's MIR instance is that
function — the lift finds an instance by its unqualified lifted name, so
two functions of two extracted modules with one lifted name and one
signature would bind without error, and the theorem be about the other's
MIR (check 0, `ModuleNames::instance_global`); L's names restart with each
extraction's reading and a later definition takes over a name, so a second
extraction's reading could stand in for the first's (check 3 now counts
only the load of L's library and the function's own extraction's); the index leaf was
recognized by a path suffix (`..ops::Index::index`: a crate's own
`myops::Index::index` on an array was read as core's indexing; now core's
exact path).

**Assumptions recorded, not checked by the theorems**: rustc compiles the
MIR `mirx` printed (the extraction has overflow checks on, so the build
must too); `RuntimeChecks(ub)` is read as `false` (where a library
precondition check would fail, the operation it guards is undefined
behaviour, which L reads as `None`); the host models and leaves mean the
host functions (as for S), host enums and host instances included (a host
model may name fewer variants than the MIR: the check below does not
cover them).

**Checked since stage tcb-checks (they were assumptions)**:

* *Module types are declared alike in the MIR and in the subset.* The
  kernel's field names are positional (`f0`, `f1`, ..): L reads field `i`
  as the MIR numbers it, S as the subset's declaration does, so a theorem
  cannot see two fields named differently. The gate's trusted check
  (`gate.rs`, check 4) compares, for every module type a function's MIR
  instances reach, the MIR's adt-def with the lifted crate's declaration
  (the HIR item the elaborator declared the inductive from): variants by
  name and in order, each variant's fields by name and in order, variant
  `i`'s discriminant `i` (the subset has no explicit discriminants), and
  refuses the function otherwise, naming both declarations.
* *Preconditions are the declared contract's, by content.* The rule used
  to match binder names (`h_req<k>`, `h_depth`), its content argument
  structural. Now the elaborator checks each precondition of a function
  read from MIR against the elaboration of the declared contract's clause
  (above), whatever its binder is named; `stmt.rs` has no rule of its
  own.
* *Each listed function's instance is that function* (stage tcb-review):
  its lifted name in the DSL module of its item (the function's own path,
  its self type's, a sealed trait's for its impl on a primitive, the module
  type argument's for an operator impl on a primitive) is the listed
  function; and its statement rests only on L's library and its own
  extraction's literal reading.

*Pinned by:* `tests/literal.rs` (each construct evaluated by the kernel
with negative twins), `tests/theorem_gate.rs` (the gate on varint, the MMR
and the verifier; wrong rules of the structured reading caught; the
trusted check refusing a weaker theorem the kernel accepted, a missing
theorem, and a stale cache entry for a changed MIR),
`tests/fault_injection.rs` (a mutated MIR construct of each kind breaks a
theorem; the two historical structuring bugs re-injected into `read.rs`
break theorems; a precondition the contract lacks is refused by the
elaborator), `tests/theorem_gate.rs`
`a_module_type_declared_with_its_fields_reordered_is_refused`,
`tests/literal.rs` `a_precondition_other_than_the_declared_clause_is_refused`
(the same number of clauses, the same binder name, another clause),
`tests/theorem_gate.rs`
`a_function_listed_with_another_functions_instance_is_refused` and
`a_reading_whose_names_a_later_extraction_took_over_is_refused`,
`tests/lift_conformance.rs` (L compared with rustc in the conformance
check, module mode and in place), `tests/walker.rs`, `tests/lowered_use.rs`
(the shipped theorems of the lifted round trip).
