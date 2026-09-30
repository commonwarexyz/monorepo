# Kernel interface changes (all additive)

`term.rs` and `value.rs` are unchanged. `api.rs` keeps every frozen item and
signature; its `todo!()` bodies are implemented, `Env`'s private field
`_private: ()` is replaced by the kernel's private state (explicitly allowed),
and the items below are added. No `Term` or `Value` variant was added.

## `api.rs`

| Addition | Rationale |
| --- | --- |
| `impl Display, Error for KernelError`; `impl Default for Env` | ergonomics (`?`, `panic!("{e}")`). |
| `Env::with_prelude()`, `Env::try_with_prelude()` | requested: load and check `prelude/*.core` (DESIGN.md §6). `with_prelude` panics only if the embedded prelude fails to check (a kernel bug, covered by tests). |
| `Env::load_core(src, budget)` | parse and check core text items one at a time (§5.12). |
| `Env::parse_term(names, src)`, `Env::print_term(names, t)`, `Env::print_inductive(ind)`, `Env::print_def_decl(d)` | core text syntax for tests, automation and diagnostics (§5.12). |
| `Env::ctx_venv(ctx)`, `Env::fresh_var(depth, rel, ty)` | the evaluation environment of a context / a fresh variable, **with fixed-length array eta**: array-typed variables are introduced eta-expanded (see "Array eta" below). Values that callers build for `conv` must use these so both sides agree. |
| `Env::quote_typed(ctx, v, ty, share)` | typed read-back: a value `Pair` does not carry its Σ type (frozen `Value`), so untyped `quote` cannot produce a checkable `Term::Pair`. Typed quoting propagates expected types (Σ types, constructor field types, Π domains of neutral spines) and should be used for residuals and motives. |
| `Env::lookup_global/lookup_ind/lookup_ctor`, `global_name/global_type/global_body/global_type_value/global_arity/global_kind/global_param_rels`, `num_globals`, `inductive_decl`, `inductive_is_recursive` | name resolution for the builtins table (§6) and introspection for automation/tests. |

Clarified semantics of frozen entry points (no signature change):

* `quote(depth, v, share)` is untyped: it emits `Erased` for the Σ type of a
  pair it cannot type, and for the proofs of `absurd`/`transport` neutrals
  (not stored in values). With `share = true`, non-leaf nodes with more than
  one parent and an inferable type get a relevant `Let` (named `s0, s1, …`)
  at the root.
* `abstract_occurrences(ctx, goal, t, b)` returns the motive **body** — a term
  in `ctx` extended with one variable `y` (the format of `Transport`/`Match`
  motives) — with `motive[y := t] ≡ goal`.
* `check_residual_equal` additionally rejects candidates that refer (in a
  relevant position) to the reference itself or to any global defined after
  it: the candidate is emitted as the reference's body, so such a call could
  loop at run time. It also rejects relevant `absurd`, and `Erased` is never
  accepted as `absurd`'s proof.
* Every budgeted operation also fails with `EvalError::OutOfFuel` (never a
  crash, never "convertible") when it would use more Rust stack than the
  thread's allowance (below).

## New public modules and items

| Item | Rationale |
| --- | --- |
| `prim::{prim_sig, PrimSig, PrimTy, prim_obligations, is_partial, max_of, eval_prim, LitOut, INT_BITS_LIMIT, prim_name, parse_prim_name, width_suffix, parse_width, prim_arg_rel, prim0}` | the primitive table (§5.7). **`prim_obligations(op, args, bool)` fixes the exact proposition of every proof slot** (front end and automation must build proofs of these types): `Add(w)`: `Eq(Bool, le_int(iadd(to_int a, to_int b), 2^w−1), true)`; `Sub(w)`: `Eq(Bool, le_w(b, a), true)`; `Mul(w)`: `Eq(Bool, le_int(imul(to_int a, to_int b), 2^w−1), true)`; `Div/Rem(w)`: `Eq(Bool, ne_w(b, 0), true)`; `Shl/Shr(w)`: `Eq(Bool, lt_u32(s, w), true)`; `OfInt(w)`: `Eq(Bool, le_int(0, i), true)`, `Eq(Bool, le_int(i, 2^w−1), true)`. `eval_prim` exposes literal evaluation for differential testing. |
| `measure_obligation_term(bool, w)` (crate root) | the exact §5.6 decrease-proof type, as a term over `Var(1) = m[args]`, `Var(0) = m[params]`: `Σ(_ : Eq(Bool, le_int(0, m[args]), true)). Eq(Bool, lt_int(m[args], m[params]), true)` for `Int` measures, `Eq(Bool, lt_w(m[args], m[params]), true)` for machine widths. |
| `axioms::{Schema, SCHEMAS, Params, axiom_id, decode, axiom_name, axiom_by_name, axiom_param_rels, telescope, axiom_type}` | §5.10. `AxiomId(schema_index · 8 + width_index)` with widths `U8 U16 U32 U64 Usize Int` = 0..5; `mul_mono` exists only at `Int`, all other schemas only at machine widths. Data parameters are relevant, hypotheses irrelevant. |
| `syntax::{lexer, parser::{Parser, Item, parse_term, parse_items, parse_kind, is_keyword}, printer::{print_term, print_inductive, print_def, kind_name}}` | §5.12 (see `CORE_SYNTAX.md`). |
| `util::mk::*`, `util::{shift, shift_from, occurs}` | term constructors and de Bruijn helpers shared with the front end and tests. |
| `util::{set_stack_limit, stack_limit, DEFAULT_STACK_LIMIT}` | the kernel is recursive over terms and values; the outermost public entry point records the stack position and `tick` reports `OutOfFuel` once more than the thread-local allowance (default 1.5 MiB, safe on 2 MiB spawned threads) is in use. **Drivers doing large symbolic executions should run the kernel on a thread with a large stack (e.g. 256 MiB–1 GiB) and call `set_stack_limit` with somewhat less than that.** |
| `PRELUDE_FILES`, `expand_templates` (crate root) | the embedded prelude text and its `%for W in … %end` template expansion (auditable TCB text). |

## Conventions the other components must follow

* **Array eta**: variables of type `Array T N` (literal `N ≤ 256`) are
  introduced as `([seq::index T (fst x) 0 …, …], snd x)` by the checker, by
  conversion under binders, by `ctx_venv` and by `fresh_var`.
* **Relevance**: `linarith` hypothesis proofs, transport values and lemma
  bodies are relevant positions; irrelevant facts are usable there through
  `eq::promote A a b .h` (a transport with an irrelevant equation), or by
  placing the proof in an irrelevant position. **Phase 4:** inside an
  irrelevant position only the irrelevant variables bound *outside* it are
  usable relevantly; an `Irr` binder/let/match field introduced inside a
  proof is usable only in a nested irrelevant position (see "Phase 4"
  below).
* **Prelude kernel-known items** (`List`, `seq::len`, `seq::index`,
  `seq::take`, `seq::drop`, `u16/u32/u64::from_le_bytes`) are registered only
  by `with_prelude` from the embedded text; user definitions never get their
  special treatment.

## Phase 2 (kernel follow-up): opaque definitions, `bvnorm`, performance

`term.rs` and `value.rs` are still unchanged (`DefDecl.opaque` was added by
the lead before this phase). All other changes are additive or clarify
semantics that were unimplemented before.

### Opaque definitions (DESIGN.md §5.6)

| Item | Semantics |
| --- | --- |
| `DefDecl.opaque` | honored: an opaque global never unfolds in the default (checking) mode of evaluation and conversion — not even an intrinsic on closed arguments, and not inside `bvrefl`. `Delta`/`Unfold` expose its defining equation (one step; its recursive calls stay folded). Opacity only loses completeness. |
| `Env::eval_opaque(env, depth, t, opaque, b)` | **clarified**: the optimizer's *transparent* mode. `DefDecl.opaque` is ignored and exactly the globals in `opaque` stay folded; an empty set evaluates everything. (Previously it added `opaque` to the default mode, which had no opacity.) |
| `Env::conv_opaque(depth, a, b, opaque, bud)` (new) | conversion whose closure instantiations use the same transparent mode (values already computed keep their folded heads: compare values produced by `eval_opaque`). |
| `Env::eval_transparent(env, depth, t, b)`, `Env::conv_transparent(depth, a, b, bud)` (new) | `eval_opaque`/`conv_opaque` with an empty set, with definition values cached for this mode: the reference semantics for the optimizer, the CLI `eval` and differential tests (opaque functions — e.g. the elaborator's loop functions — compute here, not under `Env::eval`). |
| `Env::check_residual_equal` | the final equivalence is decided in the transparent mode with an empty opaque set (residuals come from `eval_opaque`, which inlines opaque callees). Typing of the candidate is unchanged. |
| `Env::global_opaque(g)` (new) | accessor. |
| core text | `def[<kind>, opaque, arity = n]` attribute list (any order); the printer emits `opaque` (see `CORE_SYNTAX.md`). |

### `BvRefl` / `bvnorm` (DESIGN.md §9.8)

| Item | Semantics |
| --- | --- |
| `Term::BvRefl` | decided by `bvnorm`: conversion first, then the bottom-up word normalizer over both value DAGs evaluated in the `BvRefl` mode (intrinsics unfolded on symbolic data, opaque definitions folded), then the tripwire (36 valuations). Failure is `KernelErrorKind::BvRefl` with both normal forms (or the tripwire valuation) in the message. `lhs`/`rhs` may not contain `Erased`. |
| `bvnorm::decide(env, ctx, lhs, rhs, BvOptions { tripwire }, b) -> Result<BvVerdict, KernelError>` (new public module) | exactly the kernel's test (with `tripwire: true`), without type checking the sides; for automation (`Hint::Bv`, auto step 12) to test before building a term. `BvVerdict::{Equal, Different(msg), TripwireMismatch(msg)}`. |
| `bvnorm::classify(env, ctx, terms, b) -> Result<Vec<u32>, KernelError>` (new) | normalizes several terms in one normalizer; equal ids ⇔ `decide` (without tripwire) says equal. For bucketing candidates and for the exhaustive soundness tests. |
| `bvnorm::tripwire_agrees(env, ctx, lhs, rhs, b) -> Result<bool, KernelError>` (new) | the tripwire alone (tests of the tripwire itself). |
| `prim::eval_machine` (crate-private) | the single implementation of machine-integer literal semantics; `eval_lits` delegates to it (behavior unchanged, covered by `tests/prims.rs`). |

### Diagnostics and performance (no semantic change)

| Item | Change |
| --- | --- |
| `syntax::printer::print_term_bounded(env, names, t, max_len)` (new) | printing that stops after about `max_len` bytes (a quoted value DAG shares subterms and would print as an exponential tree). Kernel error messages use it together with a node-bounded quoter, so an error about a large symbolic value never blows up. |
| `Checker::infer` of `λ` | reads the body type back with sharing (lets at the root) instead of as a tree. |
| `Env::quote` / `quote_typed` | primitive-application nodes are memoized (the result shares `Rc` subterms: linear in the DAG). Extended to closures read back by substitution (proofs) by the read-back memo section below. |
| evaluation | speculation reuse (tail calls and direct constructor fields), direct list indexing by a literal, in-place environment extension, stack check every 16 steps (one thread-local), Fx hashing for internal tables — see `src/eval.rs` and `src/util.rs`. Step counts of the same computation are lower than in phase 1 (budgets sized for phase 1 remain sufficient). |
| type checking | a relevant argument/field/scrutinee is evaluated only if the codomain/later field types/motive mention it. |

## Phase 3 (kernel fixes)

`term.rs` and `value.rs` are unchanged; every change is additive or
refines the semantics of an existing rule (listed per item, with the tests
that pin it; `AUDIT.md` has the full walkthrough).

### Semantics

| Item | Change |
| --- | --- |
| Match arms in conversion (K1) | `conv_arms` (and `bvnorm`'s match nodes) instantiate the fields of arm `k` with the same fresh variables the checker and the quoter use: `Ev::arm_fields` evaluates each field type and goes through `Ev::fresh`, so an `Array T N` field is eta-expanded (§5.9). A stuck match that binds an array field, quoted and re-evaluated, is convertible with the original (`tests/phase3.rs` `k1_*`). The front end's `auto::util::fold_array_eta` workaround is no longer needed for correctness (it still makes quoted terms smaller). |
| §5.6 unfolding policy | **Ground recursion:** when the speculative unfolding of a recursive global is stuck only because a folded recursive call is inspected (`match rec(t) ..`, a partial checked prim on it) and the recursion argument is ground — a closed constructor spine for structural recursion, a literal measure for measure recursion — the body is evaluated with the real policy (the recursion terminates); a result that is still stuck keeps the application folded. **Transparent mode:** in `eval_opaque`/`eval_transparent`, an application to closed arguments with a ground recursion argument whose speculation merely exhausts the 2^20-step sub-budget is evaluated with the caller's budget. Consequence: `driver::eval_in`'s `Unfolder` does 0 manual unfoldings on all 32 QMDB fixtures (it can be removed; `Env::eval_transparent` is the reference evaluator). (`tests/phase3.rs` `recursion_*`, `tests/eval_opt.rs`, adversarial `ground_recursion_refinement_*`.) |
| `Linarith` rule (§5.8) | (1) A stated hypothesis is justified by its proof, or — if the proof is well-typed but of another type (e.g. a `refl` that a dependent-match path equation was applied to, instantiated by substitution into another branch) — by an assumption of the context with the stated type, usable in the current relevance mode (irrelevant assumptions only in irrelevant positions). (2) The certificate is a **hint**: it is checked exactly as before; if it does not verify (substitution removes or merges atoms and shifts the canonical positions), the kernel searches a certificate for the same system, then for the system extended with the context's hypotheses of §5.8 form usable in the current mode (at most 64, most recent first), and verifies it with the same exact check. The search (`src/lincert.rs`, phase-I simplex, Bland's rule, budgeted) is not trusted: its output is re-checked. `linarith(hyps; goal; [])` is therefore a valid proof whenever a certificate exists. Soundness is unchanged: acceptance still requires a verified Farkas refutation from hypotheses that hold in the context. (`tests/phase3.rs` `linarith_*`, `tests/linarith.rs`, adversarial `linarith_hints_and_assumptions_*`.) |
| `BvRefl` (§9.8) | Both sides are evaluated **transparently** for normalization (opaque definitions unfold; intrinsics unfold on symbolic data, as before); folded applications in context values are unfolded when this mode's policy unfolds them. Unfolding is an identity, so this is sound; it makes `BvRefl` prove hardware-variant equivalence (§9.3) against portable functions that are opaque because they contain loops. Conversion (`refl`) still honors opacity. (`tests/phase3.rs` `variant_equiv_*`, `tests/bvnorm.rs`, adversarial `bvrefl_cannot_prove_false_equations`.) |
| Axioms (§5.10) | Four new schemas at every machine width, appended (existing ids unchanged): `leading_zeros_le_w(a) : leading_zeros_w(a) ≤ bits(w)`, `trailing_zeros_le_w(a)` (same), `leading_zeros_lt_w(a, .h : ne_w(a, 0) = true) : leading_zeros_w(a) < bits(w)`, `trailing_zeros_lt_w(a, .h)` (same). Statements are `Eq(Bool, le_u32/lt_u32(.., bits), true)`. (`tests/axioms.rs`, `tests/phase3.rs` `bit_count_axioms_*`.) |

### VariantEquiv (for the optimizer)

`∀ state block. compress_sha2(state, block) == compress(state, block)` is the
term `fun (state : Array U32 8usize) (block : Array U8 64usize) =>
bvrefl(Array U32 8usize, compress_sha2 state block, compress state block)`
checked (`Env::check`) against `(state : ..) -> (block : ..) -> Eq(Array U32
8usize, compress_sha2 state block, compress state block)`, or added as a
lemma with `add_def`. With the elaborated QMDB definitions (portable
`crate::sha256::compress` opaque, its loops opaque measure-recursive helpers)
this checks in about 19 ms (0.54M steps) on this machine; the core-text
shapes are pinned by `tests/phase3.rs` `variant_equiv_compress_sha2_by_bvrefl`
(`tests/variant_equiv.core` + `sandblaster/targets/core/aarch64.core`),
which also rejects two wrong variants. `bvnorm::decide` (the exact kernel
test, without typing) can be used to try the obligation before building the
term. A general obligation `∀ x. requires(x) → variant(x) == portable(x)` is
the same term under the `requires` binders (irrelevant λs).

### New API items

| Item | Semantics |
| --- | --- |
| `Env::abstract_occurrences_ext(ctx, goal, t, in_proofs, b)` | `abstract_occurrences` with a choice for proofs: `in_proofs = true` also abstracts data subterms of irrelevant closures (proof terms), so e.g. the dependent-match idiom's `refl(Bool, c)` becomes `refl(Bool, y)` consistently with the scrutinee. Both modes (and `abstract_occurrences`, = `in_proofs: false`) now abstract **neutral heads and spine prefixes**: a stuck scrutinee (`match c { .. }` with target `c`), a neutral global application under a match, `fst p` under a match (the front end's syntactic completion passes become unnecessary). Which mode keeps a motive well-typed depends on the proofs (a proof whose validity depends on the concrete shape of `t` breaks under abstraction; J-style transport of such proofs, as `auto` does, is the complete method); callers check the motive. |
| `linarith::check_certificate(sys, cert)` | the exact certificate check (the trusted part of the rule), for automation and tests. |
| `axioms::Schema::{LeadingZerosLe, TrailingZerosLe, LeadingZerosLt, TrailingZerosLt}`; `SCHEMAS` has 28 entries | see above. |

### Performance (no semantic change)

| Item | Change |
| --- | --- |
| Term DAGs | Shared term nodes (`Rc::strong_count > 1`) are not treated as trees: the checker memoizes inferred types per (node, context, mode); evaluation memoizes shared nodes in registered environments (API roots, checking contexts, root closure instantiations of conversion/quoting/checking and their let/arm extensions; definition bodies that are DAGs get a memo scoped to each unfolding); `contains_erased`, `occurs`, `map_post` (shifts, `rec` replacement at commit), the structural-recursion check, `alpha_eq_relevant`, `straight_line`, linearization (value DAGs) and quoting (neutral and constructor nodes) are linear in the DAG. A 2000-level shared chain (2^2000-leaf tree) checks, evaluates and converts in about 3 ms (`tests/phase3.rs` `shared_term_graphs_*`; before: exponential, 266 ms at depth 18). |
| Memo soundness | every memo keeps its keys (terms, environment vectors, values) alive, so addresses are never reused while it lives; a registered environment is shared, so it is never extended in place; speculative evaluators (which fold recursive calls) never use an outer memo. |

## Phase 4 (red-team fixes)

`term.rs` and `value.rs` are unchanged; no public signature changed.

### Semantics

| Item | Change |
| --- | --- |
| Relevance (DESIGN §5.3; red team R1, critical) | The checker's boolean irrelevant mode is replaced by Pfenning/Agda-style **resurrection**: on entering an irrelevant position the checker records the context depth `d`; an `Irr` variable is usable relevantly there only if its level is `< d` (bound outside the position). `Irr` λ/Π binders, `Irr` lets and `Irr` match fields introduced inside keep their status (usable only in a nested irrelevant position, which resurrects again). `snd` of an `Irr` Σ is accepted only in an irrelevant position, and only when every free variable of the pair is bound outside it. The linarith assumption search and context facts use exactly the usable entries. This closes a closed proof of `Empty` (`docs/review-3-redteam.md` R1; `tests/redteam.rs` `r1a`–`r1e`, adversarial `irrelevant_positions_resurrect_only_outer_variables`). |
| Irrelevant Σ components and constructor fields | Their types must be **propositions** (conservative syntactic test on the value: `Eq`; Π into a proposition; Σ of propositions; a non-recursive inductive with no constructor or one constructor whose fields are all propositions). Checked at Σ formation and at `add_inductive`; violations are `KernelErrorKind::Relevance`. `Sigma (b : Bool), .Bool` and `inductive IBox { \| ibox(.x : Bool) }` are now rejected. Every prelude/front-end use (`SliceOk`, `Array` length, chunk bounds) qualifies. |
| Must-accept kept | `λG. refl(Bool, G .true) : Π(G : (.h : Bool) -> Bool). Eq(Bool, G .true, G .false)` (irrelevant binders may still hold data). |

**What generators must do** (front end, automation, lemma files): a proof
term placed in an irrelevant position may use the irrelevant hypotheses of
the surrounding context directly, but a hypothesis it introduces itself
(the path equation `.e` of the dependent-match idiom, an `Irr` let, an `Irr`
λ binder, an `Irr` match field) may only be used inside a *nested*
irrelevant position — e.g. as a transport equation, an `Irr` argument
(`eq::promote A a b .e`), a prim proof slot — or the generator binds it
relevantly (inside a proof a relevant binder costs nothing). The same holds
for `snd` of an `Irr` Σ whose pair is bound inside the proof (`.snd(a)` as
an `Irr` argument is fine).

### Resource control (not TCB-relevant)

| Item | Change |
| --- | --- |
| dependency `sandblaster-memguard` | the kernel links the process-wide counting allocator (hard cap; `SANDBLASTER_MEM_LIMIT_GB`). Every binary that links the kernel gets it. |
| budget ticker | `tick` also fails with `EvalError::OutOfFuel` once `sandblaster_memguard::soft_limit_exceeded()` (polled with the stack guard, every 16 steps). Never success. (`tests/memguard.rs`.) |

## DESIGN.md §15 (S0): spec closure, section abstraction, closed evaluation

`term.rs` and `value.rs` are unchanged; every item is additive (AUDIT.md
§19–§20 has the soundness argument).

### New API items (`api.rs`)

| Item | Semantics |
| --- | --- |
| `Env::refs_closure(t, stop) -> Vec<GlobalId>` | `Refs*(t)` (§15.1): globals referenced from relevant positions of `t` (irrelevant positions — proofs — skipped), closed under the types and bodies of globals (opaque ones, loop helpers, `::ensures` lemmas and prelude definitions included) and the parameter and field types of inductives; members of `stop` are listed but not explored. Sorted by id. |
| `Env::abstract_section(&Section, budget) -> Result<SectionStatements, KernelError>` | `complete_p(R)` (§15.5) for each published `p`, built by the kernel: `Π(F_r' : T_r[F'])` for the members by id (a linear extension of the requires-reference DAG), `Π(h_i : H_i[F'])` for the hypotheses in order, `p`'s parameters with the members abstracted (an `Irr` requires that mentions the section gets a second binder `x'` with the real proposition, for `p`), then `obs_eq(Out, F_p' x̄ h̄, p x̄ h̄')`. Every occurrence of a member becomes its `F'`; a non-recursive **spec** definition outside `R` and the stop set that reaches `R`, occurring in a relevant position, is λ-lifted (inlined with the members abstracted); any other global that reaches `R` (an exec caller, a loop helper, a lemma) or a recursive spec definition is an error (establish or merge it). A member occurring in a split requires must be published with an exact `obs_eq` (no view), else the section is rejected: the split statement is relative to the real implementation of that member, which only its own statement pins down. The statement is type-checked (it may be `Kind`-sorted) and rejected if `Refs*` of its abstracted parts contains a member. |
| `Section { members, published, hyps, views, established }` | input: `R`, `P(R) ⊆ R`, `H(R)`, views, and the established functions (the stop set of `Refs*`, disjoint from `R`; `Exec`/`LoopHelper` globals only). |
| `SectionHyp { lemma, restated }` | a hypothesis is the type of the global `lemma` (a law, `ensures` or refinement lemma: a proven statement). `restated` (optional) is the abstracted statement with proof slots re-proven by the front end, a term in the context of the `F'` binders and the earlier hypothesis binders; it must be `alpha_eq_relevant` to the kernel's abstraction (only proofs may differ). |
| `SectionView { ty, target, map }` | `obs_eq` at every type convertible with `ty` is `Eq(target, map a, map b)`; closed terms, `map : ty -> target`, `target : Type` (checked). Otherwise `obs_eq` is `Eq`, pointwise at Π types, componentwise at non-dependent Σ and struct-like inductives (tuples) when a component is not plain. |
| `SectionStatements { statements, members, deps }` | one statement per published function (same order), the members in binder order, and `Refs*` of the abstracted parts and of the λ-lifted spec globals (stop set = `established`; members removed) by id, from which the front end computes `Deps(R)` and checks well-foundedness. |
| `Env::eval_closed(t, budget) -> Result<Tm, KernelError>` | §15.7: `t` must be closed and well-typed (no `Erased`); evaluated in the fully transparent mode, then completed as the driver's `Unfolder` did — folded applications of globals unfolded, stuck primitives/transports recomputed, eliminators re-applied, fields completed — and read back (typed). The result must be first-order data (constructors, literals, pairs, `refl`). An exhausted budget (or stack/heap allowance) is `Eval(OutOfFuel)`, never a result. |

Crate-internal: `Ev::unfold` is `pub(crate)` (used by `closed.rs`).

### What the front end does with them

* **Completeness (agent C).** Call `abstract_section` per computed section;
  prove *each* returned statement as a lemma (e.g. `add_def` with the
  statement as the type, `DefKind::Lemma`, `arity = 0`) — the kernel checks
  the proof against exactly this term; the section is fully specified only
  when all of them are proven. Proof slots of a law that do not re-check
  after abstraction are re-proven in the abstracted context and passed as
  `restated`. Put into `published` every member that occurs in the requires
  of a published member (callers must prove that requires, so it is
  referenced from outside `R`). Pass as `established` only exec functions
  fully specified in earlier sections. Reject the section unless every exec
  global in `deps` is established or a trusted primitive. An error naming
  an exec function outside `R` that "reaches the section" means that
  function's laws or callers tie it to `R`: establish it first if its
  section does not depend on `R`, otherwise merge the two sections (its
  section's `deps` then contain members of `R`). Spec sheet and `SPEC.lock`
  print and hash the returned statements.
* **Spec closure (agent A).** `refs_closure(item, established)` for each spec
  item; an exec global in the result that is not established is
  `error[spec-depends-on-impl]`.
* **Examples (agent A).** An `#[example(e)]` is accepted when `refl` checks
  or when `eval_closed(e)` returns `true`; any error is a failed example.

## O3 (optimizer plan): K1 bit-count definitions

`term.rs`, `value.rs` and every public signature are unchanged; the change
is additive except for the retirement of four phase-3 schemas.

| Item | Change |
| --- | --- |
| `axioms::Schema::{CountOnesDef, LeadingZerosDef, TrailingZerosDef}` (new; `SCHEMAS` has 31 entries, the new ids are `28·8 + w … 30·8 + w`) | At every machine width, one data parameter `a : W`, no hypothesis: `count_ones_def_w(a) : Eq(Int, cast_u32_int(count_ones_w(a)), Σ_{i<w} cast_w_int(and_w(wshr_w(a, i), 1)))`; `leading_zeros_def_w(a) : Eq(Int, cast_u32_int(leading_zeros_w(a)), Σ_{m<w} [lt_w(a, 2^m)])`; `trailing_zeros_def_w(a) : Eq(Int, cast_u32_int(trailing_zeros_w(a)), Σ_{1≤m≤w} [eq_w(and_w(a, 2^m − 1), 0)])`, where `[b]` is `match b : Bool as _ return Int with \| false => 0int \| true => 1int end` and `Σ` a left-nested `iadd` (optimizer design §11.4). Core text: `axiom[count_ones_def_u64](a)`. (`tests/axioms.rs` `k1_*`.) |
| `axioms::Schema::{LeadingZerosLe, TrailingZerosLe, LeadingZerosLt, TrailingZerosLt}` **retired** | `valid_at` is false at every width: `axiom_id` returns `None`, `decode` of their old ids returns `None`, `axiom_by_name("leading_zeros_le_u64")` fails, so `axiom[leading_zeros_le_u64](…)` no longer parses. The variants keep their slots so no other id changes. Replacements (checked lemmas, `sandblaster/front/lemmas/bits.core`): `bits::leading_zeros_le_<w>`, `bits::leading_zeros_lt_<w>`, `bits::trailing_zeros_le_<w>`, `bits::trailing_zeros_lt_<w>`, same statements. No caller outside the kernel tests used them. |
| `axioms::Schema::CountOnesLe` | unchanged and still valid: derivable from `count_ones_def` (lemma `bits::count_ones_le_<w>`, which `auto` now uses), kept only for the S0-owned `elab/basic.rs` (`BasicProver`); to be retired with the O12 post-merge patches. |

**What callers must do.** Nothing, unless they named a retired schema:
use the `bits::*` lemma of the same name instead (they are in every
environment that loads the automation's lemma files).

## §15 S1 review: linear chunking in the prelude (TCB item 3)

`term.rs`, `value.rs`, the API and every signature are unchanged.

| Item | Change |
| --- | --- |
| `prelude/slice.core`: `seq::chunks_go`, `seq::chunks_rest_go` (new, `def[prelude]`, measure `seq::len T l`) | `(T)(N)(.hN)(l)(n : Int)(.hn : Eq(Int, n, seq::len T l))`: the chunking loops of the former `seq::chunks_c`/`chunks_rest_c`, testing the carried length `n < N` instead of `seq::len T l < N` and recursing on `(drop l N, n − N)` (the equation for the rest by `transport` along `hn` and `seq::len_drop`). |
| `seq::chunks_c`, `seq::chunks_rest_c` | **Behaviour-preserving redefinition**: same types, now `seq::chunks_go T N .hN l (seq::len T l) .refl(..)` (non-recursive, transparent). Extensionally equal to the old definitions (the loop bodies are the old bodies with `n = len l`); evaluation takes O(L) steps for a list of length L (reading back the proofs of a result is a separate cost: see the read-back memo section below). The checked lemmas of `sandblaster/front/lemmas/chunks.core` (`seq::chunks_c_small`, `…_step`, `chunks_rest_c_lt`, …) keep their statements; their proofs unfold the loops and use the new `seq::chunks_go_irrel` / `seq::chunks_rest_go_irrel` (a loop started at any `n = len l` equals `chunks_c`). |

**What callers must do.** Nothing: every statement about `chunks_c`,
`chunks_rest_c`, `seq::chunks`, `seq::as_chunks` and `slice::as_chunks` is
unchanged. A proof that unfolded `seq::chunks_c` by `delta` must now unfold
`seq::chunks_go` at `n = len l` (as `lemmas/chunks.core` does). The prelude
hash changes, so a `SPEC.lock` names `prelude:slice.core` as changed.

## Read-back memo and chunk certificates (kernel maintenance)

`term.rs`, `value.rs`, the API and every signature are unchanged. The
memo returns exactly what unmemoized read-back computes; the arm-field
change below alters a typed read-back only where a variable bound by an
irrelevant or un-typable arm field heads an application, and the red-team
fix only for values outside the level discipline (AUDIT.md §2.1) or a
quoter reused at another depth. The QMDB builds print byte-identical code
with the same report (also after the red-team fix).

| Item | Change |
| --- | --- |
| `quote.rs` read-back memo | Closures read back by substitution (proofs, and closures whose NbE runs out of the quoter's budget) are memoized by (environment address, body address, depth, own binders), next to the neutral/constructor memo by (address, depth); the memo is kept per depth and, in typed quoting, drops the entries deeper than a level whose type changes after it was read (AUDIT.md §7.5 gives the exactness argument). Read-back of a proof DAG is now linear in the DAG: a proof that refers to an earlier one twice was read back as its (exponential) tree. |
| typed read-back of match arms | Every arm field sets the type of its level (irrelevant fields too; a field whose type cannot be evaluated sets "unknown"), instead of keeping the type of an earlier binder of the same level. Only a variable head applied to a spine reads it. |
| typed read-back: closure binders, calls from outside (red-team fix, 2026-09-25) | The binders of a closure read back by substitution (its own and those inside its body) set the type of their level to "unknown", like un-typable arm fields, instead of leaving the type of an earlier binder of that level; and each call from outside a quoter starts from the context types it was given below its depth (a reused quoter no longer sees types an earlier call's binders left). The red team found a single typed read-back on a fresh quoter that returned another Σ annotation memoized than unmemoized (a memo hit skips the binders inside the memoized node); now the type read for a level is a function of the path to the read, which the memo's exactness argument needs (AUDIT.md §7.5). Output changes only for values outside the level discipline (a closure environment mentioning a level its body binds) or for a quoter reused at another depth; the kernel does neither (a fresh quoter per read-back; `linarith`'s calls are at the context's depth). |
| `prelude/slice.core`: `seq::chunks_go`, `seq::chunks_rest_go` (TCB item 3) | **Behaviour-preserving**: same types, same relevant code; in the step that drops a chunk, `p1` (`N ≤ len l`) and `pn` (the next step's `hn`) are now both projected from one proof `q` (a `transport` along `hn` of a function of the comparison), so each step refers to `hn` once instead of twice. The chunks' length certificates are then a chain, read back in time linear in the number of chunks (with the memo; quadratic without it), where the S1 text doubled per chunk. The old == new equivalence (against the pre-S1 definitions) was re-proven in the kernel, the chunking lemmas (`sandblaster/front/lemmas/chunks.core`) check unchanged, and a differential of 793 inputs agrees with the pre-S1 definitions and native Rust. |

A 22-chunk `Option<Seq<[u8; 4]>>` known-answer example, which exhausted
4 GB in `sandblaster check`, verifies in 0.1 s (1024 chunks: 0.3 s, 70 MiB).
The loops' own result certificates (the `snd` of `chunks_c` /
`chunks_rest_c`, the `SliceOk` proofs of `slice::as_chunks`) still mention
the previous result twice: their read-back is linear through the memo.

**What callers must do.** Nothing. The prelude hash changes, so a
`SPEC.lock` names `prelude:slice.core` as changed.
