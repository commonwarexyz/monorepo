# Front-end interface changes (all additive)

Frozen or shared front-end interfaces changed by the §15 interface step
(DESIGN.md §15.12 **S0**). Nothing was removed or renamed; every change is an
added variant, field, function or module. The kernel's own additions
(`refs_closure`, `abstract_section`, `eval_closed`) are recorded in
`sandblaster/kernel/INTERFACE_CHANGES.md`.

## `prover.rs` (elaborator ↔ automation contract, DESIGN.md §7.2)

`ObligationKind` gains six variants (names for diagnostics and the report in
`elab::obl::kind_name`):

| Variant | Name | Obligation | Stage |
| --- | --- | --- | --- |
| `Refines` | `refines` | `f::refines`: `f` refines its spec through the views of its types (§15.2) | S1 |
| `TypeInvariant` | `type-invariant` | a struct's invariant at a construction site (literal, tuple-struct call, `..base`, field assignment, pattern rebuild; §15.3) | S2 |
| `InvariantExit` | `invariant-exit` | a loop invariant at the helper's exit, proving `f::loop#k::ensures` (post-loop facts, §7.4) | S0/S1 (agent A) |
| `ViewInjective` | `view-injective` | `view_inj_T` (§15.2, §15.3) | S2 |
| `Example` | `example` | `s::example#k` (§15.7) | S1 |
| `Completeness` | `completeness` | `complete_p(R)` (§15.5) | S3 |

Provers that match on `ObligationKind` must treat unknown kinds like
`WellFormed` (none in this crate matches exhaustively except `kind_name`).
Drift noted by review 4 (R4-H2): `WellFormed` already existed and is now listed
in DESIGN.md §7.2.

## `hir.rs`

| Addition | Meaning |
| --- | --- |
| `Module::spec` | a `#[cfg(sandblaster)] #[spec] mod m;` module or a module inside one; every `fn` in it is a spec fn unless `#[lemma]`/`#[law]`/`#[proof]` |
| `Crate::in_spec_module(id)` | helper |
| `Export::via_use` | the export is a root `pub use` (the §15.8 boundary is exactly the root's `pub use` list of items) |
| `Param::ghost` | `#[ghost] x: T` on an exec function parameter (its bindings are ghost locals; its type may be a ghost type) |
| `FnDef::rewrite`, `FnDef::induction` | `#[rewrite]` and `#[induction(x)]`, previously accepted without a HIR record |
| `FnDef::spec: SpecAnnots` | the §15 annotations of a function: `refines: Option<Refines>` (spec, explicit argument map, `domain`), `proof_of: Option<ProofOf>` (`#[proof(refines = f)]` / `#[proof(complete = f)]`), `refines_proof` / `complete_proof` (the pairing, set by the validator), `examples: Vec<Example>`, `example_files: Vec<ExampleFile>` (path, `FileId`, `ExampleFormat`, `Provenance`), `section_with` / `section_span`, `mirrors_impl` / `trusted_extern: Option<Justified>`, `fuel_sufficient: Option<FuelSufficient>` |
| `FnDef::irr_binders()`, `IrrBinder` | the sources of `Irr` binders of an exec function's kernel type: any `requires`, the `h_depth` of `#[decreases(.., max = C)]`, a ghost parameter |
| `StructDef::{invariant, view, represents}`, `EnumDef::view` | `TypeInvariant` (one ghost binder per field, `self.f` rewritten to it, props typed as propositions), `View::{Struct, Fn}`, `Represents` |
| `SpecAnnots::proof_of_unresolved` | a `#[proof(refines/complete = f)]` whose `f` did not resolve, or a `#[proof(..)]` with malformed arguments (reported): the item is not paired with a law by name either (no cascade) |

Every function-like item keeps the normalized `FnDef` form (§4.2); the §15
records live beside it. `visit::walk_fn` does **not** visit them (they are not
part of the function's meaning; recursion classification is unchanged);
`visit::walk_fn_spec` / `visit::walk_type_spec` do.

## `resolve.rs`

* `Annot` gains `Example, Examples, Invariant, View, Represents, Ghost,
  Section, MirrorsImpl, FuelSufficient, TrustedExtern`; `Annot::ALL`,
  `Annot::name`, `Annot::is_spec15`. `Annot::from_name` is derived from
  `ALL`. The docs of `Annot::Refines` no longer describe §9.6 (types use
  `#[view]`/`#[invariant]`).
* `ModInfo::{spec, data_files}`, `decl_is_spec`.
* `public_names` returns `Vec<PublicName>` (adds `import`: the binding came
  from a `use`).
* `critical_diagnostic`, `is_critical_attr`, `is_critical_path`,
  `mentions_critical`: every form of `sandblaster::critical` is one diagnostic.

## `loader.rs`

`LoadedModule::data_files`: files named by `#[examples(file = "..")]`
(relative to the declaring file's directory) are read through the
`FileProvider` and added to the `SourceMap` (so they are build inputs and
appear in `cargo::rerun-if-changed`).

## `typeck`

* New module `typeck::spec15` (parsing, resolution, typing and placement of
  the §15 annotations; `FnSpecSyn` (with `proof_malformed`), `Site` (with
  `Use` and `Body`), `placement_note`, `InvSelf`).
* `FnSig::{spec, ghost_params}`; `Cx::inv_self` (typing an invariant).
* `#[refines]` on a type is an error (it was accepted and ignored).
* Every attribute nested in a body is rejected (`Checker::check_nested_attrs`:
  statements, expressions, match arms, patterns, closure parameters of
  annotation arguments, `proof!` script statements, constant initializers);
  the rejection of attributes on `let` moved there (same message). Inner
  attributes of function bodies and `impl` blocks are checked (docs and
  whitelisted `#![allow(..)]` only; annotations are outer attributes);
  `impl` attributes are checked once per block, also for blocks without
  functions. Annotations on `use` items are rejected by the resolver.
* §15 attribute arguments that name exec functions accept inherent
  functions, `Type::f` (`#[proof(refines = Mmr::push)]`, `#[section(with =
  [Mmr::size])]`).

## `validate.rs`

* Live boundary rules: a `pub` function reachable from the root must have no
  `Irr` binder (any `requires` — including `true`, which was accepted —, a
  depth bound, a ghost parameter), no `#[refines(.., domain = P)]`, and no
  type parameter inside a slice element type.
* `validate::spec15_gate(&Crate, &mut Diagnostics)`: the §15.8 boundary rules
  (root `pub use` list of items only; monomorphic boundary functions). **Not
  called by `validate`**; S5 adds the call unconditionally in the change that
  makes QMDB fully specified.
* `validate::param_in_slice(&Ty, &Crate)` and `validate::SliceFlow` (per user
  type and parameter index, whether the parameter reaches a slice element:
  a least fixed point, no traversal budget — the first version gave up after
  64 instantiations and answered "no").
* `validate::is_zst` follows rustc's layout and errs on "zero-sized":
  uninhabited enum variants are absent (`Option<Void>`, `enum { A, B(Void) }`
  are zero-sized), `Option<T>` is zero-sized iff `T` is uninhabited, and past
  `validate::LAYOUT_DEPTH` levels (or for an unknown type) the answer is
  "zero-sized".
* `#[proof(refines | complete = f)]` pairing (`pair_spec15_proofs`); such proofs
  are not paired with laws by name.

## `elab`

* `Output::{refinements, examples, sections}` (`refines::RefinesRecord`,
  `examples::ExampleRecord`, `complete::SectionRecord`): always empty in S0.
  The stage that fills one adds its accumulator to `Elab` **and** to
  `elab::generated::rebuild`/`finish` (which construct `Elab` field by field).
* Stage hooks, run after every item (`Elab::spec15_hooks`): `refines.rs`
  (S1: `refines_hook`, `refines_proof_hook`, `view_hook`, `represents_hook`),
  `examples.rs` (S1: `examples_hook`, `mirrors_hook`, `fuel_hook`),
  `invariant.rs` (S2: `invariant_hook`, `ghost_params_hook`), `complete.rs`
  (S3: `sections_hook`, run once). In S0 each reports its annotations with
  `Elab::spec15_not_implemented` — "… is not implemented yet (§15 Sn)", an
  error — so no annotation is silently ignored. `#[trusted_extern]` reports
  "(§13, §15.8)".
* `elab::order` adds §15 edges (a `#[refines(s)]` function after `s`; a
  `#[proof(..= f)]` item after `f`; a type after what its invariants, view and
  representation relation mention).

## Loops (post-loop facts, §7.4)

* `f::loop#k::ensures` states `Squash(Post(..)) = Σ(_ : Unit) ×Irr Post(..)`
  (every conjunct proven irrelevantly); the call site's fact is still
  `Post(J)` (opened with `snd`). Only propositions are stated; a disjunction
  in implication form.
* `a..b` helpers bind the invariants at `i + 1` as facts `h_next` before the
  branch on `i + 1 < b` (a `let` of the next index and irrelevant `let`s in
  the helper body); the recursive call and the lemma's exits use them
  (obligations proven this way are recorded with the prover name `reuse`).
* `elab::obl::INVARIANT_EXIT_NOTE`: the note of a failed `invariant-exit`.
* The `ensures` walk (`Elab::walk_body`) keeps irrelevant `let`s abstract, and
  a failed relevant `ensures` goal built from equations is retried
  irrelevantly and promoted (`Elab::prove_relevant`, `Elab::promote_irr`).

## New modules

`surface.rs` (`SurfaceKind`, `SurfaceItem`) and `lock.rs` (`LOCK_FILE`,
`LockEntry`): S0 stubs for agent D.

## Facade and macros

`sandblaster-macros` defines one erasing macro per `Annot` (a test checks the
three lists agree); function-annotation macros remove `#[ghost]` parameters.
`sandblaster::prelude` exports every annotation but `proof` (the `proof!`
statement macro); `sandblaster::ghost` exports the ghost-item attributes
including `proof`. There is no `critical`.

## §15 S1 (refinement, the specification language, examples, spec closure)

All additive except where noted ("behaviour").

### `hir.rs`

| Addition | Meaning |
| --- | --- |
| `Ty::Nat`, `Ty::Seq(Box<Ty>)` | ghost `Nat` (kernel `Int`, bound established at construction) and `Seq<T>` (kernel `List`); `is_ghost_only`, `walk`, `subst`, `Display` cover them |
| `Coercion::View` | the type-directed view coercion from the operand's type to the node's type (ghost code only); elaborated by `Elab::abstraction` |
| `ExampleFile::text` | the vector file's text (filled by `driver::check` from the source map) |

`Refines::args` are now checked against (coerced to) the spec's parameter
types.

### `builtins.rs`

`GhostFn` gains the `Seq<T>` operations (`SLen, SGet, SIndex, STake, SSkip,
SChunks(N), SFlatten(Option<N>), SToArray(N), SRepeat, SEmpty, SCons,
SAppend, SUpdate, SRev`) and the `Nat`/`Int` methods (`NMin, NMax, NSatSub,
IDivEuclid, IRemEuclid`), with `GhostFn::{seq_method, seq_method_takes_const,
seq_assoc}`.

### `resolve.rs`

`Ext::{NatTy, SeqTy}`; `Nat` and `Seq` are prelude type names (and, like
`Int`, reserved item names); `Seq::repeat | empty | cons` resolve to ghost
functions.

### `typeck`

* `Nat`, `Seq<T>` types (ghost only); unsuffixed literals in ghost code
  default to `Nat`; `Nat` arithmetic (`-` carries an obligation), `as Nat`,
  `Int | Nat as uN`; the ghost numeric join (`uN < Nat < Int`) of operands;
  ghost `==`/comparisons join view-coercible operand types
  (`Cx::{view_coercible, view_target, view_coerce_expr, numeric_join,
  view_join}`); `Seq` methods, `xs[i]`, prefix slice patterns on `Seq`,
  `seq![..]`, `hex!("..")`, `b".."` in ghost code; `Nat` measures and
  `cases` over `Nat`.
* Type annotations (`#[view]`, `#[invariant]`, `#[represents]`) are lowered
  before bodies (bodies use views for the coercion).
* The bare `#[refines(s)]` form is checked: arity, parameter and result
  coercibility, and the `#[represents]` shape (`Cx::check_refines_shape`).

### `diag.rs`

`DiagKind::{SpecDependsOnImpl, SpecMirrorsImpl, Example, FuelSufficient}`
(codes `spec-depends-on-impl`, `spec-mirrors-impl`, `example`,
`fuel-sufficient`).

### `elab`

* `Options::example_budget` (default `examples::EXAMPLE_BUDGET`,
  4·10⁹ kernel steps; exhausting it is an error).
* `Elab::s1: views::S1State` (views, representation relations, refinement /
  example / coverage / closure records, the established set);
  `generated::rebuild` constructs it off (the S1 stages run in the main
  elaboration only).
* `Output::{coverage, spec_closure, established}` (new) and
  `refinements`, `examples` (now filled); `Output::empty`.
* `refines::RefinesRecord` gains `proof`, `form: RefinesForm`, `domain`,
  `up_to`, `statement`; `examples::ExampleRecord` gains `method`, `lemma`,
  `counts`, `detail`; new `examples::{ExampleMethod, CoverageRecord,
  ClosureRecord, ClosureKind, spec15_gate_s1, fuel_param, EXAMPLE_BUDGET}`
  and `views::{ViewInfo, S1State}`.
* **`examples::spec15_gate_s1(&Output, &Crate, &mut Diagnostics)`** — the
  S1 part of the §15.8 gate (coverage gaps, and the spec-closure / fuel /
  mirror findings recorded for legacy spec items become errors). **Not
  called**; S5 calls it next to `validate::spec15_gate`.
* New kernel definitions per crate: `T::view`, `S::represents` (spec),
  `f::refines` (`DefKind::Ensures`), `X::example#k`,
  `X::example#fileJ#k` (lemmas), and the ghost library `ghost::*` loaded by
  `semantics::install` (`elab/ghost.core`).
* Behaviour: ghost `const`s are `DefKind::Spec` (were `Exec`); `Nat`
  parameters of lemmas/laws/proofs add relevant hypotheses after the
  parameters; spec functions guard their body on `Nat` parameters; the
  `ensures` walk mirrors projections with their path equation when the
  goal asks (`WalkGoal::eq_on_projections`, refinement only); the induction
  hypotheses and call-site facts of contract lemmas are re-certified
  (`recert`); `bv()` uses the goal's own sides when the goal is an
  equation and decides it on the spot (a false word equation is an unproven
  obligation, not a kernel rejection); `Int` `/` and `%` need non-negative
  operands.
* Hooks: `refines_hook`, `refines_proof_hook`, `view_hook`,
  `represents_hook`, `examples_hook`, `mirrors_hook`, `fuel_hook` now give
  meaning (see `refines.rs`, `views.rs`, `examples.rs`); `Elab::s1_post_pass`
  (mirrors, fuel, coverage) runs before `sections_hook`;
  `Elab::refines_cycle_check` runs before the first item.
* `elab::order`: a function calling `g` comes after `g`'s `#[proof(refines = g)]` item (where `g::refines` is built), so the refinement is a fact at the call.

### `driver.rs`, `canon.rs`, `validate.rs`, `exhaust.rs`

`driver::check` fills `ExampleFile::text` (one loop); `canon.rs` and
`validate.rs` list `Ty::Nat`/`Ty::Seq` with the other ghost types in one
exhaustive match each; `exhaust.rs` treats `Seq<T>` patterns like slice
patterns.

## §15 S1, agent D (the specification surface and `SPEC.lock`)

All additive except where noted ("behaviour").

### New modules

| Module | Contents |
| --- | --- |
| `surface` | `surface::compute(&Output, &Crate, &SourceMap, &SurfaceOptions) -> Surface` (and `compute_with_terms`, which also returns each item's kernel statement, `Stmt`): the §15.6 surface of a verified elaboration — `SurfaceItem { key, kind, path, item, span, source, statement, kernel, kernel_omitted, canon, src, deps, hash }`, `SurfaceKind` (20 kinds, `tag`/`from_tag`/`heading`; `FuelSufficient`, `SpecType`, `Type`, `Constant` added to the S0 list), `Surface::errors` (`SurfaceError`: an unestablished exec global in a value statement, §15.6 `Hdep`), `Canon` (canon hash and `Refs₁`), `statement_canon`, `Toolchain` (the header hashes and the file of each toolchain global; `Toolchain::current()`), `TCB` (DESIGN.md §1.1 items 1–7), `model_identity` (a target model's source/core hashes, evidence record and verdict), `sha256`, `hex`, `parse_hex`. The S0 stub `SurfaceItem { key, kind, item, span }` is replaced by the full record (behaviour; nothing used the stub). |
| `lock` | `Lock` (`parse`, `render`, `compute_root`, `entries_for`, `empty_for`), `LockEntry` (`LockEntry::of(&SurfaceItem, target)`), `LockDep`, `compare(Option<&str>, &Surface, file) -> LockStatus` (`LockState`, `Mismatch`, `What`; `LockStatus::{summary, json, not_computed, matches}`), `accept(Option<&Lock>, &Surface, &Selection) -> Result<(Lock, Accepted), String>` (only `sandblaster spec --accept` calls it), `enforce(&LockStatus, classes, &mut Diagnostics)` (the §15.8 gate calls it from S5), `FORMAT`, `KERNEL_SOURCES`, `BUILTIN_SOURCES`, `SEMANTICS_MD`, `SEMANTICS_RS`. The S0 stub `LockEntry { key, kind, statement, hash }` gains fields (behaviour; nothing used it). |
| `specdiff` | `Classifier` (`changes`, `classify`, `implies`): bounded kernel attempts at `old ⇒ new` / `new ⇒ old` over the same Merkle dependencies; `Class`, `Change`, `classes`, `equivalent_keys`, `sheet` (the spec sheet), `GREEN_BUILD`, `GOAL_BUDGET`. |
| `deelab` | `DeElab` (fully parenthesized statements with explicit binder types and casts), `constant`, `type_def`, `view`, `represents`, `invariant`, `example`, `flat`. |

### `driver.rs`

* `Checked::{lock_path, spec_lock}`: `SPEC.lock` of the DSL root directory, read through the `FileProvider` by `check`.
* `Built::spec: lock::LockStatus` — computed by `verify_and_optimize` for a verified crate (reported; **not enforced before S5**).
* `spec_run(&Checked, &SpecBaseline, classify) -> SpecRun` (`sandblaster spec`), `SpecBaseline::{None, Lock, Old(entries)}`, `spec15_lock_gate` (= `lock::enforce`; the S5 gate hook, not called by the build).
* `verified_report_json_spec` (the report with the `spec` section); `verified_report_json_audit` is unchanged (no `spec` section).
* Behaviour: the generated crate ends with `pub const SANDBLASTER_SPEC_ROOT: [u8; 32]` (the lock's root when the lock matches, all zero otherwise; `optimize_emit`/`optimize_emit_mode` print zero); `GLUE_NAMES` includes `SANDBLASTER_SPEC_ROOT` (a module-level source name spelled like it is rejected); the verified build's `cargo::warning` summary includes the lock status, and `cargo::rerun-if-changed` names `SPEC.lock` when it exists; the report's `tcb` list adds DESIGN.md §1.1 items 6 and 7; `SANDBLASTER_TRACE_SPEC` traces the surface computation.

### `canon.rs`, `roundtrip.rs`

* `canon::OptPrint::spec_root`, `canon::SPEC_ROOT_NAME`, `canon::spec_root_item(&[u8; 32])` (the fixed template printed last by the phase-3 printer).
* `roundtrip::Stats::spec_root`: the round trip requires the item, compares it token for token with its template, and returns its value; `verify_and_optimize` checks the value against the lock (a mismatch is a round-trip failure).

### `diag.rs`, `elab`

* `DiagKind::SpecLock` (`spec-lock`).
* `elab::examples::ExampleRecord::term`: the closed kernel term of a checked example (the statement the lock hashes).

### CLI

`sandblaster spec <crate> [--accept [ITEM…] [--equivalent-only] | --diff <rev-or-path>] [--target ..]` (`sandblaster/cli/src/main.rs`).

### Tests

`tests/common/api.rs`: `generated_api` leaves out `SANDBLASTER_SPEC_ROOT` (the one item every generated crate adds). The golden files `tests/golden/opt_*.rs` gain the constant (re-blessed; nothing else changed).

## §15 S1 review fixes

All additive except where noted ("behaviour").

### Specification surface and `SPEC.lock`

* `specdiff`: behaviour — every comparison (laws, contracts, definitions)
  abstracts the exec functions and loop helpers it mentions that are not
  established (§15.1) into Π-bound variables of their types, and proves
  `Π F̄'. old[F̄'] ⇒ new[F̄']`; a statement that reaches an implementation
  through another global's definition is *unrelated* unless identical. So
  two statements that are merely both true of the current body are never
  *equivalent* (`--equivalent-only` cannot re-accept a weakened contract).
  Exec constants are still compared by value (their entry hashes it).
  `Classifier::implies` is now private (its statements are over the
  abstraction); `Classifier::implies_closed(a, b)` is the closed form.
* `deelab`: `DeElab::contract_with(word, item, f, Option<&RefinesRecord>)`
  (`contract` = `contract_with(.., None)`): a refinement is printed as the
  `refines s(..)` line, its `meaning:` (the result coercion
  `view::<V>(f(x̄)) == s(..)`, or for `#[represents]` the simulation form
  `for all a: A, (S::represents(self, a) => ..)`, never a view of a type
  without one) and its determinacy (`determines f` or `NOT DETERMINING:
  <up_to>`). The sheet, the lock's `|` lines and the report use it.
  `deelab::KernelShow` prints kernel goals and facts in surface syntax.
* `surface`: the vector-file entry records `N record(s) checked` (hashed).
* `driver`: `Built::spec15: Spec15Report { refinements: Vec<RefinementReport>,
  vector_files: Vec<VectorFileReport> }` (`spec15_report`,
  `refinement_reports`); `verified_report_json_full(.., Option<&Spec15Report>)`
  adds the report's `refinements` (`function, spec, form, proof, status,
  checked, determines, up_to, statement`) and `vector_files` (`records`,
  `checked`) sections; the build and `sandblaster report` use it.
* CLI: `spec --diff <rev>` reads the old revision from git on demand (the
  whole repository at `rev`), so inputs outside the DSL root directory —
  vector files named `../../vectors/..` — come from `rev` too.

### Elaboration and automation

* `diag::DiagKind::RefinesUnproven` (`refines-unproven`): the `[refines]`
  obligation errors of one `f::refines` are folded into one error at the
  attribute — each branch a note with its goal, facts and path conditions
  in surface syntax, and a suggestion chosen by what blocked the branches
  (an opaque callee, word arithmetic, `from_be_bytes`, a failed `bv()`).
  A failed `bv()` on an array or list result names the first element whose
  sides differ modulo word algebra.
* Placeholders (`Elab::placeholder`) are recorded in
  `S1State::placeholders`; an example, a vector file or a refinement goal
  that reaches one is reported "not checked: depends on `X`, which did not
  verify" (`DefStatus::Blocked`), never judged against the default value.
* Examples: behaviour — a false example prints both sides in surface
  syntax (`hex!(..)` for bytes, decimal `Nat`/`Int`) with their first
  difference; the failing records of a vector file are one error at the
  first failing record's line (fields, sides, difference per record).
  CAVP: a key repeated inside one record (case-insensitive) is an error;
  JSON: colliding keys are an error. `fuel_param`: behaviour — a
  `#[decreases]` exempts a function only when its measure does not read the
  detected fuel parameter.
* The body walk (`ensures.rs`): a call-site refinement fact `h_ref : α(f ā)
  = s(α ā)` under a path equation `f ā = C(v̄)` gives the fact `α(C(v̄)) =
  s(α ā)` (`Scope::ref_facts`); a plain or dependent match whose scrutinee
  evaluates to a constructor (the tuple of `split_at`) selects its arm with
  the fields `let`-bound to their values.
* Scripts: after `unfold(f)`, the irrelevant `let`s of the unfolded body
  that depend only on the script's context (a callee's `h_ens`/`h_ref`,
  slice bounds) become facts of the script.
* `auto`: the motive abstraction keeps a side-condition proof whose
  parameter type does not change (an application prefix without the
  abstracted term, the proof not referring to a binder whose type changed),
  transports the dependent-match idiom's equation argument to the kept
  motive's equation, and reads the type of a transport or variable
  application (`abstraction.rs`); linarith enrichment adds atom congruence
  (two atoms of one stuck global with arithmetically equal arguments) and
  links a machine word's and its `Int` value's division by a literal
  (`rem_def`/`div_def` instances); a stuck-term equation whose one side
  occurs in the other is not used as a rewrite rule.

### Known-answer evaluation cost

* The prelude's chunking is linear (`sandblaster/kernel/INTERFACE_CHANGES.md`),
  and coverage evaluates closed calls only of spec functions that need
  outcomes (it re-evaluated every closed spec call, a whole hash per
  vector record). The review's SHA-256 LongMsg layout went from 241 s to
  30 s; `chunks_exact::<64>()` of 64 KiB from 129 s to 1.2 s.
* Not added, by design: a cache of example verdicts. Any cache keyed by
  the lock hash is an input the build would trust to skip an evaluation;
  a forged or stale entry would turn a false known answer into a pass,
  which DESIGN.md §15.8 excludes ("running out of budget: a failed
  obligation, never a pass or a skip"). The native run of vector files
  against the generated code (§15.7) stays with the surface work (agent D
  / S3).

## §15 S2 (agent B: types that carry invariants and meaning)

All additive except where noted ("behaviour"). Semantics: SEMANTICS.md
§13.6.

### `elab`

* **Kernel types (behaviour).** A struct with `#[invariant]` has one
  trailing `Irr` constructor field per conjunct (`Elab::declare_adt` →
  `Elab::invariant_fields`). New per-crate definitions:
  `S::invariant#k` (spec: the conjunct over the fields), `S::holds#k`
  (spec: the conjunct at a value's projections), `S::inv#k` (lemma:
  `Π(T..)(s). holds(S::holds#k T.. s)`), `T::view_inj` (lemma, when
  proven).
* `Elab::proj` takes the constructor's field count from the kernel
  declaration (`Elab::ctor_nfields`); the `nfields` argument is a fallback
  (prelude tuples keep their count). Behaviour: nothing changes for types
  without `Irr` fields.
* New module content `elab::invariant`: `InvPart`, `S2State` (in
  `views::S1State::s2`: `invariants`, `view_inj`), `boolify`,
  `ghost_requires`, `has_irr_fields`, and on `Elab`: `invariant_fields`,
  `invariant_lemmas`, `invariant_closure`, `value_is_prop`, `inv_lemmas`,
  `with_inv_facts`, `param_inv_facts`, `ctor_irr_proofs`,
  `ctor_with_invariants`, `ghost_bundle`, `ghost_bundle_arg`,
  `view_injectivity`, `s2_post_pass`. `invariant_hook` /
  `ghost_params_hook` no longer report "not implemented".
* Construction obligations (`ObligationKind::TypeInvariant`) in
  `exec::adt_value` (literal, tuple-struct call, `..base`), `exec::update`
  (field assignment), `views::view_def` (structural view onto a struct with
  an invariant); `value::Conv` erases the slots and checks the invariant of
  `eval` inputs (`checked_struct`).
* Facts (`FactOrigin::TypeBound`) at parameters (`items::exec_fn`,
  `spec_fn`, `script::ghost_def`, `refines_script`), `exec::bind_local`,
  call results, projections, `pat::compile_ctor` (projected patterns).
  `Scope::inv_seen` (one fact set per value).
* `eqs`: `derive_eq_sound` / `derive_eq_complete` bind the `Irr` fields;
  `Elab::ctor_congruence` (and `tm::ctor_congruence_term`) builds
  `C(x̄, p̄) = C(ȳ, q̄)` from field equations with the `Irr` fields
  generalized.
* `items::default_of`: an inductive with `Irr` fields has a default only
  when each `bool` conjunct evaluates to `true` at the default fields.
* **Ghost parameters (behaviour).** `items::fn_params` no longer pushes
  `#[ghost]` parameters at their positions: the ghost parameters (the last
  ones) and the `requires` that mention them are one binder `ghost : Σ(g̅).
  R̄ × Unit` after the other parameters (`Irr` in the function, relevant in
  its lemmas); `fn_requires` skips the ghost requires. `Scope::ghost_locals`
  (local ↦ projection), `Scope::ghost_facts` (facts over ghost locals, given
  to the prover inside each proof slot: `obl::prove_hinted` wraps the
  proof); `Elab::local_tm` consults `ghost_locals`; `exec::fact_in` keeps a
  fact whose type is not well-formed at the top level (it mentions the
  bundle) virtual; `obl::check_proof_in` checks irrelevant proofs inside an
  extra irrelevant `let` when ghost locals are in scope.
* `exec::apply_tele_args(ty, args: Vec<(Rel, Tm)>, ghost: Option<Vec<Tm>>,
  ..)` (`apply_tele` is `apply_tele_args` with relevant arguments and no
  ghost values): an `Irr` argument for an `Irr` binder, the ghost bundle
  built from `ghost`. `item_call_full` passes the callee's ghost values;
  when a call gives exactly the non-ghost arguments (the round trip's
  lowered code) the bundle is an obligation (`Erased` in generated mode).
* `items::nat_components` and `items::nat_guards(ps: &[Val], ..)`
  (behaviour: the guarded values are terms, the `Nat` parameters and the
  `Nat` components of the other parameters); lemma/law/proof parameters get
  `h_natᵢ_k` hypotheses for their `Nat` components; quantifiers likewise
  (`spec::quant`).
* Determinacy (behaviour): `refines::refines_up_to` accepts a lossy view
  of an `Abstract` type (`views::view_determines`); establishment needs an
  injective view (a proven `view_inj` makes a closure view injective:
  `ViewInfo::injective` is set). `s2_post_pass` (called from
  `Elab::spec15_hooks` before `s1_post_pass`) clears the "up to" of
  simulation-form refinements whose struct is `Abstract` and has a checked
  establishing constructor, and reports a `#[represents]` struct that is not
  `Abstract`.
* `refines`: positional spec arguments of a ghost parameter use its
  projection. `loops::loop_`: a loop reading a ghost local is unsupported
  (reported).

### `auto`

* `congr::irr_ctor_congruence` (called in `search::solve` after
  `arg_congruence`): `K(ā) == K(b̄)` for constructor values with `Irr`
  arguments (here or nested): relevant pairs proven, transports with the
  `Irr` fields generalized. Only fires when `Irr` constructor arguments are
  present.

### `typeck`

* `spec15::{ghost_macro, has_fn_annotation}`, `Cx::call_with_ghosts` (used
  by `fn_call`, `method_fn_call`): the argument of a `#[ghost]` parameter is
  `ghost!(e)` in exec code (typed in ghost mode against the parameter), `e`
  or `ghost!(e)` in ghost code; `ghost!(..)` elsewhere is `error[ghost]`; a
  function passing `ghost!(..)` needs a sandblaster function annotation.
  `#[ghost]` parameters must come last (`error[ghost]`).

### `validate`

* `check_spec15_types` (called by `validate`): a struct with an invariant,
  a representation relation or a view has only private fields
  (`error[invariant]`); a tail-recursive function with ghost parameters is
  unsupported.
* `abstract_reasons(&Crate, ItemId, view_injective) -> Vec<String>`
  (`Abstract(T)`, DESIGN.md §15.3), `exported_functions(&Crate)` (LR1's
  exported functions: the root `pub use` list and the `pub` methods of
  exported types).

### `diag`

`DiagKind::{Invariant, ViewInjective}` (`invariant`, `view-injective`).

### Codegen, round trip, `eval`

* `canon`: `#[ghost]` parameters and the arguments of ghost parameters are
  not printed. The `Irr` slot never appears (structs print from the HIR).
* `roundtrip`: printed inputs map to the non-ghost parameters; argument
  checks of user calls skip ghost parameters; a tail-recursive function with
  ghost parameters is a failure.
* `driver::eval_in`: ghost parameters take no JSON value.

### Facade, macros

* `sandblaster-macros`: every function-annotation macro also removes the
  `ghost!(..)` arguments of the calls in the function's body
  (`strip_ghost_args`), matching the callee's removed `#[ghost]` parameters.
  `sandblaster/src/erase_spec15.rs` compiles such a caller.

### Surface

* `surface`: an invariant entry carries the kernel statement of each
  conjunct (`S::invariant#k`); an invariant that calls a spec function is
  listed as an evidence type (`evidence-type:S`).
* `SurfaceKind::has_kernel_text` includes `Invariant` and `EvidenceType`
  (the lock stores `invariant#k type` / `invariant#k body`); both are value
  kinds (an exec constant they read, e.g. `MAX_LOCATION`, is a `constant:`
  dependency, not a closure error). The generated `S::invariant#k`,
  `S::holds#k`, `S::inv#k` resolve to the invariant/evidence-type entry,
  `view_inj` to the view entry, `eq_sound`/`eq_complete` to the Eq entry.
  `specdiff` still classifies a changed invariant by identity only (S3/S5).

## §15 S2 review fixes

### HIR, `typeck`, `validate`

* `hir::ProofKind::ViewInj` (`#[proof(view_inj = T)]`; `ProofOf::target` is
  then the struct). `typeck::spec15` parses and resolves it (`struct_path`);
  `validate::pair_spec15_proofs` checks it (`check_view_inj_proof`: `T` has a
  closure view, the item takes `(a: T, b: T)` with `T`'s type parameters,
  one per type). Matches on `ProofKind` gain the arm.
* `Cx::call_with_ghosts` takes the callee's `ItemId` (first argument): a
  call that leaves out the (trailing) `#[ghost]` arguments is
  `error[ghost]`, naming the parameters and their `requires`.
* Field reads (`e.f`) and struct patterns in ghost code skip the privacy
  check (DESIGN.md §15.3: ghost code reads private fields anywhere in the
  crate); construction and assignment keep it.
* `check_spec15_types`: a struct with an invariant, a representation
  relation or a view needs at least one field (`error[invariant]`: a
  fieldless struct's constructor is public to host code).
* `abstract_reasons` (behaviour): no boundary function may exchange a user
  type that contains `T` in its fields (transitively, `containing_types`);
  a boundary function over `T` must refine a specification whose signature
  mentions neither `T` nor such a type, with an argument map that reads no
  field of a `T` (`reads_fields_of`).

### `elab`

* `FnState::pure_facts` (a nesting counter) and `Elab::in_pure`: `prop`,
  `pure_expr`, `exec::pure_value` and `loops::pure_loop_value` elaborate in
  a pure context, where `with_inv_facts` adds the invariant facts as hints
  (`Elab::add_inv_hints`) instead of `let`s.
* `Scope::ghost_facts: Vec<(Val, Val)>` is now `Scope::hint_facts:
  Vec<scope::HintFact>` (`ty`, `proof`, binder `name`, `origin`): ghost facts
  and invariant hints alike; `prove_hinted` binds them under their names.
* `Elab::prebind_inv_facts(&[&Expr], &[ScriptStmt], span, k)`: binds the
  facts of the invariant-typed paths projected in place indices (assignment
  statements), loop bounds/invariants/measure/condition (`loops::loop_`,
  now a wrapper of `loop_inner`) and `proof!` steps before the statement.
  Loop helpers add their parameters' facts as hints.
* Invariants: a dependent `&&`-part takes the earlier parts of its attribute
  as `Irr` hypotheses (`InvBody::hyps`); `invariant_fields` returns field
  `k`'s type at depth `generics + fields + k`, and `types::declare_adt` no
  longer shifts it. `S::holds#k` passes `S::inv#m T.. s` for the earlier
  `Irr` fields. `boolify` reads `match` / `if let` with `bool` arms.
* `view_inj`: arm binders are named `a.f` / `b.f`; the promoted `Irr` fields
  are hints; the error names the first undetermined field (or variant
  pair). `Elab::view_inj_proof_item` (from `items`' proof arm) proves
  `T::view_inj_fields` by the item's steps and builds `T::view_inj` from it;
  `view_injectivity` skips the automatic attempt when an item exists
  (`invariant::view_inj_proof_of`). `order`: an exec function mentioning a
  struct comes after that struct's `view_inj` proof item.
* `RefinesRecord::determined_by: Option<String>` (why a refinement
  determines its function); `refines::refines_verdict` (was
  `refines_up_to`) returns `Result<reason, up_to>`; `views::{view_path_types,
  view_determinacy}`. `s2_post_pass` fills it for simulation forms.

### Report, spec sheet, surface

* `driver::RefinementReport::determined_by` (JSON `determined_by`);
  `driver::def_status_str` is public. `deelab`: the verdict line prints the
  reason, and an unproven refinement prints "NOT DETERMINING: the
  refinement is not proven (..)".
* `surface`: every invariant entry is `invariant:S` (evidence types
  included; `evidence-type:` is reserved and no longer produced); its local
  content records the spec functions the invariant calls (`calls`).

## §15 S3, agent C (computed sections, completeness, deterministic budgets)

All additive unless marked **behavior**.

### `elab::complete` (rewritten from the S0 stub)

* `SectionRecord` gains `index` (position in ≺), `hyps: Vec<(kind, name)>`
  (`H(R)` in binder order), `merged`, `statements: Vec<CompleteRecord>`,
  `dep_status: Vec<(ItemId, DepHow)>`, `status: SectionStatus`, `problems`,
  `span`; `members`, `published`, `deps`, `complete` keep their meaning.
  `CompleteRecord { item, name, statement (the kernel's term), text (core
  syntax), surface (de-elaborated), status, proof, lemma, notes }`.
  `SectionStatus::{FullySpecified, Unproven, NotWellFounded, Unstated,
  Blocked}`; `DepHow::{Refines, Section(k), Constant, Unspecified}`.
* `Elab::sections_hook` computes the candidates, the graph, the
  `#[section(with)]` merges and the SCCs (Tarjan, dependencies first),
  `P(R)`, `H(R)`, the views of `Abstract` types, calls
  `Env::abstract_section` with the stop set of fully specified exec
  functions, checks well-foundedness over the returned `deps`, proves each
  `complete_p` (the `#[proof(complete = p)]` script, else
  `auto::complete::prove`) and adds the lemma `p::complete` (`DefKind::Lemma`,
  type = exactly the returned statement, a checked `DefRecord`). A failed
  section adds **no** `DefRecord` or `ObligationRecord` (not enforced before
  S5); a failing proof item, a proof item with nothing to prove and a
  `#[section(with)]` naming a function determined by its refinement are
  errors (`DiagKind::Completeness` / `DiagKind::Section`).
* `complete::spec15_gate_s3(&Output, &Crate, &mut Diagnostics)`: the §15.8
  gate of sections (S5 calls it): one error per section that is not fully
  specified, with the problems, `H(R)`, the unproven statements and what was
  tried.
* `complete::render_statement(&Env, &Tm)`: a statement in surface syntax.
* `Elab::s3: complete::S3State` (also initialized by `generated::rebuild`).
* `FnState::abstracted: HashMap<ItemId, (level, type term)>`: in a
  `#[proof(complete = p)]` script a call of a section member elaborates to
  its `F'` binder (`exec::item_call_full`), without the callee's contract
  facts.
* `elab::Options::complete_budget` (default 1,000,000 steps): the step budget
  of each prover call of a completeness proof. Not user-facing.
* `obl`: a `Completeness` goal of a proof script binds forward-chained
  facts (`auto::complete::forward_hints`) as irrelevant binders of its slot.

### Behavior: callee contract facts in propositions

* `exec::fact_in`: in a pure context (`FnState::pure_facts > 0`: a law, a
  contract, an assertion, a loop invariant) a callee's `h_ens`/`h_ref` is a
  hint of the proof slots (`Scope::hint_facts`) instead of a `let`. A
  statement therefore never embeds a lemma (before, a law mentioning `f`
  with an `ensures` contained `let h_ens = f::ensures x` relevantly, so no
  section could abstract `f`). Statements mentioning such callees change
  their kernel text (lock entries of crates with such laws change once).

### `auto`

* `auto::complete` (new): `prove(env, &mut ProverChain, stmt, &Layout,
  Option<&Induction>, budget, span) -> Result<Proven, AutoFailure>` — the
  refinement / bool-split / induction discharges; `telescope`, `lams`,
  `forward_hints`. Every prover result is re-certified and kernel-checked;
  a proof the kernel rejects falls through to the next prover of the chain.
* `AutoConfig::auto_bvrefl` (default `true`): automatic `BvRefl` attempts
  (step 12). The completeness discharges use `auto` with it off (a `BvRefl`
  on `F' x = f x` unfolds the real function and the kernel's `bvnorm`
  failure message is an unbounded read-back).
* `meter` (**behavior**): a safety-net stop (deadline, memory soft limit,
  per-goal heap cap) is recorded as a `Trip` (`trip_count`, `take_trips`,
  `record_trip`, `is_safety_net`, `memory_soft_limit_reached`); a step
  exhaustion is not.

### Deterministic budgets (DESIGN.md §15.8) — **behavior**

* `elab::obl::prove`: an obligation whose prover tripped a safety net is
  `error[resource]` ("a failure of the build's resources, not a proof
  result"; `Elab::resource_failure`), never `error[obligation]`.
* `driver::resource_gate(&mut Verification)`: any trip on the build thread
  (elaboration, law audit, optimizer), or the memguard soft limit reached
  (`sandblaster_memguard::take_soft_limit_hit`, new), fails the build with
  `error[resource]`; called by `verify_audited` and `verify_and_optimize`
  (after elaboration and again after the optimizer, whose fallbacks would
  otherwise make the emitted code depend on the clock).
* `DiagKind::{Section, Completeness, Resource}` (`section`,
  `completeness`, `resource`).
* `opt::DriveFault::DeadlineTrip` (S3 merge; test hooks only, like every
  `DriveFault`): the driver's run is stopped by a deadline that has passed,
  through the meter, so the function falls back; `verify_and_optimize` must
  then report `error[resource]` and not verify
  (`tests/spec15_opt_interplay.rs`). The optimizer's own 60 s / 600 s
  deadlines stay safety nets (DESIGN.md §8.2 item 10).

### Report, spec sheet, surface, lock

* `driver::Spec15Report::sections: Vec<SectionReport>` and
  `driver::section_reports`; the report JSON has a `sections` array (members,
  published, hypotheses, deps with how each is specified, status,
  `fully_specified`, each `complete_p`'s statement, kernel text, status and
  proof, problems).
* `surface`: a section entry's statement lines are `section R = {..}`,
  `P(R)`, `Deps(R)`, `H(R)`, `[merged ..]`, one `complete_p(R) : ..` line per
  statement; its kernel parts are `complete:<p>` (the statements;
  `SurfaceKind::Section` now has kernel text). `SurfaceItem::notes` (new,
  never hashed or locked): the section's status for this build.
  `surface::section_statement`.
* `lock`: the header has one derived `section <key> R {..} P {..} Deps {..}
  H <hash>…` line per section entry (`Lock::section_lines`); parsing checks
  them against the entries (a hand edit is malformed). `specdiff` classifies
  a changed section as unrelated (it changes with its hypotheses); the sheet
  prints item notes and "== Sections ==" only when there is none.

## §15 S3, law rules (DESIGN.md §15.1 LR1–LR10 but LR8)

All additive unless marked **behavior**. Nothing here fails a crate before
S5: the rules are recorded by every build and enforced by a gate that S5
calls (see "Enforcement").

### Annotations (`resolve`, `hir`, `typeck`, macros, facade)

* `resolve::Annot::{ReducesTo, Assumption, Definitional, Corollary}`
  (`reduces_to`, `assumption`, `definitional`, `corollary`; `is_spec15`),
  with an erasing macro each in `sandblaster-macros` and exports in
  `sandblaster::prelude` and `sandblaster::ghost` (the three lists stay equal).
* `hir::SpecAnnots` gains `mirrors_of: Option<ItemId>` (`#[mirrors_impl(of =
  f, justification = "..")]`, the arguments in any order; the old form is
  unchanged), `reduces_to: Option<(ItemId, Span)>` (a spec function),
  `assumption: Option<hir::Assumption { class: AssumptionClass, cite, span
  }>`, `definitional: Option<Justified>` (the reason) and `corollary:
  Option<Span>`. Placement: `reduces_to`, `definitional`, `corollary` on a
  `#[law]`; `assumption` on a spec function without parameters or result
  (checked by the typechecker; a non-empty body or a `requires` is an
  `error[attribute]` of the law-rule pass). Misuse is an error now: no
  existing crate uses these annotations.

### `elab::law_rules` (new)

* `Elab::law_rules_pass() -> Vec<LawRuleRecord>`, run once by `elaborate`
  after the §15 hooks (main elaboration only, `S1State::on`); the records are
  `Output::law_rules` (new field; `Output::empty` has none).
* `LawRule::{Lr1, Lr2, Lr3, Lr4, Lr5, Lr6Echo, Lr6Resemblance, Lr7, Lr9,
  Lr10}` with `code()` (`LR1` … `LR6a`, `LR6b` …), `hard()` and `kind()`;
  `LawRuleRecord { rule, item, span, msg, notes }` with `diagnostic()` (an
  error for a hard rule, else a warning). The checks are listed in the
  module docs.
* `spec15_gate_laws(&Output, &Crate, &mut Diagnostics)`: the §15.8 gate of
  the law rules.
* The law table (LR9): `law_table(&Crate) -> Vec<LawRow { law, path,
  guarantee, assumes, heading: LawHeading::{Guarantee, Definitional(reason),
  Corollary(laws)} }>`, `table_lines(&[LawRow])`, `guarantee_sentence(docs)`
  (the first sentence of the first paragraph), `states_guarantee(sentence,
  name)` (three words of prose, more than the law's name).
* LR6 (a) uses the restricted view of the closing statements:
  `Elab::echo_attempt(target, keep, prover, budget, span) -> EchoOutcome`
  (new, in `closers.rs`): the view where exactly `keep` unfold, the given
  prover, a kernel check of its proof in the view; nothing recorded. The law
  statement is elaborated again in a fresh context whose obligations,
  diagnostics and definitions are rolled back. Budget: `ECHO_BUDGET`
  (400,000 steps; deterministic).
* `elab::examples`: `inline_helpers` and `independent_evidence` are
  `pub(super)` (used by LR5); an `#[assumption]` needs no example coverage
  (**behavior**, only for the new annotation).

### `auto`

* `AutoConfig::arith` (default `true`): linear arithmetic (every linarith
  use goes through `Engine::linearize`, which returns nothing when it is
  off). Off for the echo prover ("no arithmetic beyond evaluation").

### `diag`

* `DiagKind::{LawMentionsInternal, LawBypassesRefinement, VacuousReduction,
  LawRestatesImpl, LawResemblesImpl, LawCorollary, LawUndocumented,
  OneDirectionalLaws}` (`law-mentions-internal`, `law-bypasses-refinement`,
  `vacuous-reduction`, `law-restates-impl`, `law-resembles-impl`,
  `law-corollary`, `law-undocumented`, `one-directional-laws`). LR2 reuses
  `spec-depends-on-impl`, LR5 `spec-mirrors-impl`.

### Report, spec sheet, surface

* `driver::Spec15Report` gains `law_rules: Vec<LawRuleReport { rule, kind,
  severity, item, message, notes }>` and `laws: Vec<LawRow>`; the report JSON
  has `law_rules` (each with `"enforced": "from §15 S5 …"`) and `laws`
  (law, guarantee, assumes with class and citation, heading, reason or
  `of`).
* `surface::Surface::laws` (the law table, not hashed); `specdiff::sheet`
  prints "== Laws: guarantees and assumptions (DESIGN.md §15.1 LR9) ==" (the
  table, corollaries under their laws, then the definitional laws).
* Lock entries (**behavior**, only where the new annotations are written):
  a law's source text ends with its `#[reduces_to(..)]`,
  `#[definitional(reason = ..)]` and `#[corollary]`; an `#[assumption]` spec
  function's entry covers its class and citation (and prints them); a
  `#[mirrors_impl(of = f)]` entry covers `f` and depends on its contract
  entry.

### Enforcement (no opt-out)

The rules apply to every `#[law]` (and LR4 to every contract) of every
crate, with no marker, attribute, option or environment variable that
exempts a crate or a law. Like `validate::spec15_gate`,
`examples::spec15_gate_s1` and `complete::spec15_gate_s3`, the build records
the findings and the gate `spec15_gate_laws` reports them; S5 calls it
unconditionally in the change that replaces QMDB's legacy `LAWS.rs` (which
today yields LR1, LR2, LR6 and LR10 findings, `tests/spec15_law_rules.rs`),
so no crate fails before then and none can opt out after.

## §15 S3 review fixes (sections and law rules)

All recorded, nothing enforced before S5, unless marked **behavior**.

### What must be determined, the law vocabulary, the boundary gate

* `validate::exported_functions` (**behavior**): the functions of the root's
  `pub use` list and the `pub` methods of every struct or enum reachable
  from it through public signatures (a type an exported function returns
  but the list does not name included: host code calls its methods). The
  law vocabulary (LR1), LR3 and LR10 use it.
* `validate::boundary_functions` (new): `exported_functions` plus every
  other `pub` function of `Crate::reachable` (the public tree of a root
  `pub mod`). The candidates of determinacy (`elab::complete`) are seeded
  with it, so every host-callable exec function is in a section
  (**behavior**: legacy QMDB, with its `pub mod`s, now records a section per
  public function).
* `validate::spec15_gate` (S5): also rejects a struct or enum reachable from
  an exported item through public signatures that is not itself in the
  root's `pub use` list (`error[boundary]`, naming the item it is reached
  through and its `pub` methods).

### `elab::complete`

* `H(R)` (**behavior**): a `#[definitional]` law is no hypothesis (DESIGN.md
  §15.1: never counted as a guarantee), nor an edge of the section graph;
  the functions it mentions are still candidates.
  `SectionRecord::definitional` (new) names such laws; an unspecified
  section reports them.
* `P(R)` (**behavior**): a member mentioned by any contract — also one of
  another member of `R` — is published (`#[section(with)]` merges, never
  unpublishes); only the published members of a fully specified section
  enter the stop set of later sections.
* A law or a member's `#[ensures]`/`#[refines]` that did not verify blocks
  the sections it mentions (`SectionStatus::Blocked`, "`H(R)` is incomplete
  without it"); a failed law's mentions (HIR level, through spec function
  bodies) are candidates.
* Abstractability: when the kernel rejects a law hypothesis in the type
  check (a proof slot that does not re-check), `Elab::restate_law`
  re-elaborates the law with the members abstracted (`FnState::abstracted`)
  and the earlier hypotheses as facts (and instantiated at the law's
  parameters as hints of every slot), and passes the result as
  `SectionHyp::restated` (the kernel checks it against its own
  abstraction). A slot that still fails is located:
  `SectionRecord::problem_spans: Vec<(Span, String)>` (new; the gate prints
  them as located notes) with the proposition it needs in surface syntax.
  `FnState::slot_failures` (new; `obl::fail_obligation` records every
  failed obligation there when set). `fn_params` numbers the `Nat` bounds of
  lemma parameters from the depth at its entry (unchanged for every
  existing caller, which enter at depth 0).
* `CompleteRecord` gains `why` (a reader's account: a claim about the
  specification only when no hypothesis constrains the function, otherwise
  the failed attempt — search failed, step budget ran out, proof rejected),
  `stuck` (the conclusion with the real function unfolded once, surface
  syntax) and `exhausted`. `notes` keep the provers' internals (report
  only). The "constrained only jointly" problem appears only when no member
  of the section is proven.
* `spec15_gate_s3`: the stuck goals first, then the problems (including
  each `why`), the located slots, `H(R)`, the unproven statements; no
  prover internals.
* `auto::complete` (**behavior**, stronger discharges): hypotheses are
  instantiated type-directed (each binder at the first parameter of its
  type, not positionally), and also at the two results `F_p' x̄` and `p x̄`
  when their leading binder has the result type.
* `driver::SectionReport::stuck` (new); the report JSON's sections have a
  `stuck_goals` array.
* `deelab::KernelShow`: core-syntax fallbacks name the binders crossed so
  far (a `let` of an `ensures` statement printed wrong variables before);
  `array::index(T, N, a, i)` prints as `a[i]`.

### `elab::law_rules`

* LR1 (**behavior**): a plain `fn` of a ghost module (`FnKind::Exec`, ghost)
  named by a law is an `error[law-mentions-internal]`; LR2 and the break
  terms of LR4 treat it as exec code.
* LR4 (**behavior**): a well-formed `#[reduces_to]` law is also checked for
  vacuity — a break predicate that ignores its arguments, `requires ⇒
  B(t̄)` proven by bounded `auto` (the law holds of any specification), or
  `requires ⇒ P` proven (the break is dead). `REDUCTION_BUDGET` (1,000,000
  steps, deterministic).
* LR6 (a) (**behavior**, fail closed): a recursive or opaque proposition
  stays unknown in the echo view instead of making the view unbuildable;
  a law whose statement does not re-elaborate or whose view cannot be built
  is an LR6 (a) finding ("could not be decided"), never skipped.
  `EchoOutcome::undecided` (new). The echo note names what the law reduced
  to (no fixed guard sentence) and how to specify a codec whose round trip
  is an echo; LR6 (b) is not reported for a law LR6 (a) caught.
* LR9 (**behavior**): `guarantee_sentence` does not end a sentence at `i.e.`,
  `e.g.`, `cf.`, `vs.`, `resp.`, `viz.` (nor `etc.` before a lower-case
  word); `states_guarantee` counts a code span as one word (at least three
  words, one of them prose); `GUARANTEE_RULE` (new) is printed with the
  finding.

## §15 S4 (the counterexample engine, spec mutation, LR8, `sandblaster coverage`)

All additive; nothing in the build changes (the engine runs from
`sandblaster coverage` and tests; its gate is switched on by S5).

### New module `mutate` (`src/mutate/**`)

* `mutate::ops` — typed-HIR mutation operators (DESIGN.md §15.9 item 1):
  operator replacement (arithmetic, bitwise, comparison, boolean, the dual
  integer methods), constants (`±1`, `0`, a middle-bit flip, `!b`),
  condition negation, guard deletion (`if` condition → `true`/`false`),
  check deletion (`a && b` → one operand), return-value replacement (the
  whole body → each default of the result type: the `λ_. false` mutant),
  loop bounds and indices `±1`, argument and operand swaps. A site is a
  pre-order node index of `ops::walk_mut` (behaviour only: `proof!`
  blocks, loop invariants and measures are skipped) plus an `Op`;
  `ops::source_edits` prints it back as source edits.
* `mutate::clone` — the re-verification set of a mutant (the reverse
  `elab::order::refs` closure; a law and its `#[proof]`, an exec function
  and its `#[proof(refines)]` together; spec mutants propagate through
  ghost items only, implementations of the closure are re-checked as
  leaves), cloning with references redirected (`clone_item`, `remap_fn`;
  clones of laws carry `#[definitional]` so the §15.5 section computation
  ignores them), and the synthesized `bool` checkers of laws
  (`law_checker`: `!(requires) || ensures`) and of `requires`
  (`requires_checker`), with `clone::boolify` (`==` on non-scalars as
  `eqb`; no checker for quantifiers).
* `mutate::eval` — candidate inputs by HIR type (example arguments,
  boundary values, the mutated code's constants ±1, a seeded splitmix64),
  their closed kernel terms (`Nat`, `Seq`, slices, arrays, options, tuples,
  structs without invariants, enums), evaluation (`Env::eval_closed` for
  closed applications; the untrusted reference strategy — a copy of the
  driver's completion — when erased `Irr` arguments are needed) and
  printing.
* `mutate::run(krate, sm, &MutateOptions) -> MutationReport` — the engine:
  a baseline elaboration, enumeration (global cap sampled round-robin over
  the items; optional per-item cap), sequential batches (one fresh `elab::elaborate` of the crate
  extended with the batch's clones and checkers: the "re-elaborate from
  scratch every N mutants" of §15.9; batch size adapted to the heap measured
  against `MutateOptions::mem_fraction` of the memguard soft limit; no batch
  starts above it), classification (`Verdict`), distinguishing inputs and
  LR8. `MutateOptions::from_env` reads `SANDBLASTER_MUTANTS_MAX`,
  `SANDBLASTER_MUTANTS_BATCH`, `SANDBLASTER_MUTANTS_PER_ITEM`,
  `SANDBLASTER_MUTANTS_INPUTS` (caps only; a smaller cap makes the run
  incomplete).
* `mutate::spec15_gate_mutants(&MutationReport, &Crate, &mut Diagnostics)`
  — the S5 gate (not called by the build): `error[spec-incomplete]` (one
  per observed function; the diff, the input, both outputs, the evaluator,
  the unproven `complete_p`), `error[spec-mutant-survived]` (with the
  `#[example(..)]` that kills the survivor), `warning[law-insensitive]`,
  `error[mutation-incomplete]`.
* `mutate::report_json`, `mutate::coverage::{build, coverage, render_text,
  to_json}` — the report and `sandblaster coverage`.

Why not `elab::generated::resume`: `resume` elaborates extra items into a
finished environment but runs no §15 hook (`S1State` is not carried:
`s1.on` is false in `rebuild`), so a clone's refinement lemma, examples and
vector files would silently not be checked — exactly the kills the engine
must see. The clones are therefore ordinary items of the same kind of
extended crate (original items first, same `ItemId`s), elaborated in the
batch's fresh elaboration; nothing in `elab/**` changed.

### `diag::DiagKind` (additive)

`SpecIncomplete` (`spec-incomplete`), `SpecMutantSurvived`
(`spec-mutant-survived`), `LawInsensitive` (`law-insensitive`, a warning),
`MutationIncomplete` (`mutation-incomplete`).

### CLI

`sandblaster coverage <crate> [--json] [--no-sheet] [--mutants-max N]
[--time-budget SECS] [--only ITEM…] [--target ARCH]`
(`sandblaster-cli/src/main.rs`, `coverage_command`).

## §15 S4 review fixes (the counterexample engine)

Still additive and confined to `src/mutate/**`, the tests, and the CLI's
`coverage_command`; nothing in `elab/**`, the kernel, `driver.rs` or
`json.rs` changed.

* **Classification by the underlying failure.** A clone that did not
  verify is a placeholder (an opaque default body). A failure of a clone
  that depends on another failed clone (reverse reachability through
  `elab::order::refs` among the clones; a cycle is not a dependency) is a
  consequence and is never a reason for a verdict, and neither is a
  `Blocked` example, vector record, refinement or law. Evaluation never
  goes through a placeholder: a law checker, a requires checker or a
  compared function is evaluated only when it is checked and its kernel
  `refs_closure` reaches no placeholder global.
* **Specification kills are definite.** Implementation mutants: an
  `ensures`, type invariant or example failure is a specification kill; a
  law or refinement proof failure (budget-limited or not) is one only with
  a definite counterexample — the law's checker evaluates to `false`, or the
  mutant differs from the function its refinement **establishes** (an
  injective view, no domain: `Output::established`). Otherwise the new
  verdict `Verdict::KilledByProofs` (killed by the proofs, not by the
  specification; with a distinguishing input as a note when there is one)
  or `KilledByBudget`. Spec mutants: a spec function that uses the mutated
  one and becomes ill-formed is a safety kill (out of LR8's scope).
  `Verdict::decided` (the kill-rate denominator) leaves out not-run,
  invalid and killed-by-budget mutants.
* **Where differences are looked for.** A published member is observed only
  when its own `complete_p` is not kernel-checked (a counterexample to it,
  `Witness::section`), or when it is proven only relative to a dependency
  that is not fully specified (a section that is not well founded) and the
  mutant changes that dependency: the witness names it
  (`Witness::dependency`) and the gate reports `error[spec-incomplete]` at
  the dependency.
* **Constants at type level.** A constant whose value — or the value of a
  constant computed from it — is also an array length, repeat count or
  intrinsic immediate of the crate is not mutated (the typechecker resolved
  those positions to numbers, so a mutant could not follow it into the
  types): `MutationReport::excluded`, printed by `coverage`.
* **Caps.** `MutateOptions::max_per_item` defaults to no cap; when set and
  it drops mutants the run is incomplete (`MutationReport::capped`), and
  `enumerated` counts every mutant before any cap. The global cap samples
  round-robin over the items (return-value replacements first), and
  `MutationReport::not_sampled` lists items with no mutant in the sample.
  An `only` entry that names no item makes the run incomplete
  (`MutationReport::unknown_only`, `mutate::unknown_only` with the closest
  paths; the CLI rejects it with exit 2).
* **Diffs.** `ops::source_edits` parenthesizes where an operator's binding
  power changes (the new node when its parent binds tighter, operands that
  bind looser; source parentheses sit in the operator gap and are kept), so
  the printed line parses as the evaluated mutant. `Mutant::edit`
  (`SourceEdit`) is the edit structured; `mutate::enumerate_mutants` and
  `mutate::mutated_item` expose the mutants for tools and the re-parse test.
* **Witnesses.** Distinguishing inputs are shrunk (`eval::simpler`, at most
  `MutateOptions::shrink` evaluations); `Witness::differs_at` lists the
  differing positions of a compound output; long byte sequences and word
  arrays print in hex; named-field structs print as `S { f: v }`. The
  suggested `#[example(..)]` uses the bare function name and leaves
  `<expected>` to an independent source; `Outcome::suggestion` is a
  difference at the nearest spec function known answers exist for (a
  refinement target or one with examples).
* **Coverage.** Each counterexample line names the function it was seen at
  (`CexLine::at`, JSON `at`, `mutant_of`); a constant or helper's status
  names the functions its surviving mutants change; a function's status
  counts the mutants seen at it; a function without mutants run says so;
  budget kills are shown apart from the kill rates.
* **Runs.** `MutateOptions::progress` prints a line per batch (the CLI sets
  it); `--time-budget SECS` / `SANDBLASTER_MUTANTS_TIME_BUDGET` stop the run
  cleanly as incomplete.

## Optimizer, post-O6/O7 fixes (fallbacks and printing)

* **`elab/obl.rs`.** A failed obligation passes through
  `opt::refute::annotate` before `fail_obligation`. It does nothing unless
  the optimizer enabled it (`opt::refute::Enable`, around the elaboration of
  its residuals and helpers); then it searches a counterexample to the goal
  (values for the context, hypotheses and goal evaluated by the kernel) and,
  if it finds one, adds the note `refuted: the goal is false at …` first in
  the failure's `tried` list. It never changes a proof result.
* **Classification.** An optimizer residual or helper that does not
  elaborate is an optimizer fault (`rejected_by: "elaboration"`) when a
  counterexample refutes an obligation or any diagnostic other than an
  unproven obligation arises; with only unproven obligations and no
  counterexample it is a proven fallback (`rejected_by: "not re-proven"`,
  `failure: false`, no warning, no strict error). The same holds for the
  straight-line tier.
* **Registries.** `opt::optimize` empties the per-crate thread-local
  registries (loop summaries, exported facts, guard specializations) when it
  returns, not only when it starts: `opt::facts::any()` is false after a run.
* **Invariant facts.** `opt::facts::invariant_facts` and
  `with_decision_facts` give the driver's and the proof builder's decisions
  the `S::inv#k` instances of the values a condition mentions.

## Optimizer, post-O6/O7 fixes (optimizer time, gate coverage)

* **Report.** `opt::BudgetsUsed` gains `loopsum_steps`: the kernel steps of
  the Σ2 loop summaries built while driving the function (reported whether
  or not the driven candidate is admitted). The deterministic report's
  `budgets_used` object gains the field `loopsum_steps` (`driver.rs`, one
  line). A driving whose loop was not summarized says so in its reason
  (`the loop `…` was not summarized, the call kept (…)`).
* **`opt::loopsum::meter`** (new): the step meter of the loop summary being
  built. `LoopConfig::steps_per_loop` now bounds the whole summary (the
  analysis, the lemma chain, the helper's summary and link lemmas, the
  exported facts, the fallback rungs), not only the chain: every search and
  kernel check of a summary takes its budget through `meter::cap` and pays
  with `meter::charge`. A summary that runs out fails (the loop is kept);
  a kernel rejection caused by the meter is not an optimizer fault.
  `LoopHelper::steps` and `LoopFailure::steps` are the metered steps.
* **`opt::loopsum::lemmas`.** `hashcons` keys nodes by their head and their
  children's addresses (no strings; same sharing as before). `add_consed`
  commits an already hash-consed body. The fact chain reuses the summary
  chain's outlined loop body (`shared_body`) and, through
  `Builder::obligation`, the summary chain's proofs of the obligations it
  repeats (same literal, class and occurrence; carried over by the names of
  the context entries they use when the goal and those entries' types agree
  up to that renaming, else checked by the kernel first). `reset_shared`
  empties both per loop summary.
* **`opt::cache`.** `Cache::store_lemma` stores a committed lemma's proof and
  records its content hash from the same encoding.
* **`opt::drive`.** A fact-directed unfolding is a trial
  (`Driver::fact_trial`): kept only when its subtree decides something
  (`Node::decisions`: a prune, reuse, checked call, guard specialization,
  merged split or segment leaf); otherwise the call is kept. Decisions inside
  a trial get an eighth of the usual cap (`Driver::trials`).
* **`auto`.** `util::{FxHasher, FxMap, FxSet}` for the traversal memos;
  `Engine::ground_has_meta` (memoized `has_meta` in e-matching); the opened
  linarith rules are shared by the engines of a thread
  (`ematch::reset_lin_rules`, called with the optimizer's registries);
  `infer_irr` types a `match` by its motive; `lin_term` carries the
  certificate over to the pruned system (checked exactly) before searching
  again; `rat` uses 64-bit and binary gcd paths.
* **`elab/basic.rs`** (one step added): before the contradiction search, the
  basic prover tries linear arithmetic over the facts connected to the goal
  by shared variables; the complete steps follow when it finds nothing.
  **`elab/tm.rs`**: the traversal memos use `FxMap`/`FxSet`.
* **`opt::mirror`.** The clone-lemma proof is hash-consed before the kernel
  checks it; `Mirror::type_of` is memoized.

## Optimizer, post-O6/O7 verification fixes (fixv)

* **`opt::refute`.** The counterexample search takes candidate values from
  the obligation: every integer literal of the hypotheses and the goal (read
  from their terms and from their transparent evaluation), with its
  neighbours, is drawn half the time for a scalar, and the small ones for a
  slice or list length. Relevant facts of the context whose type is an
  equation (the hint facts the elaborator binds in a proof slot) are
  hypotheses (proven by `refl` when they hold), and an irrelevant datum (a
  ghost value) is built like a parameter instead of ending the search. The
  first assignment (every first choice) is unchanged.
* **`auto::abstraction`.** An irrelevant constructor field, a primitive's
  proof and a pair's irrelevant second component are kept as they are when
  the earlier relevant parts of the node did not change and the proof refers
  to no binder whose type changed (`Abs::irr_after`; before, a proof whose
  own type mentioned the target was transported, and the motive was
  ill-typed). `Abstracted::blind` counts the irrelevant proofs kept without a
  readable type. `TransportAll` (test hook R16) restores the old behavior.
* **`opt::proof::steps`.** `abstract_goal` and `abstract_source` return the
  blind count too; `check_motive` takes it, and a typing error of a motive
  with no blind proof starts with `ILL_TYPED`.
* **`opt`.** `PROOF_ILL_TYPED` (`"proof builder: ill-typed term"`) is the
  `rejected_by` of a driven candidate whose proof builder built an
  ill-typed term; it is an optimizer fault (a warning; an error under strict
  options). `DriveFault::TransportKeptProof` (R16).
* **`opt::cache`.** Format 2 (`ROPTC2`): an entry records its `Cost` (the
  metered build and kernel-check steps in the build that stored it).
  `Cache::load_costed` returns it; `Cache::store_lemma` takes it; `load` and
  `store` are unchanged (a zero cost). Format 1 entries are ignored.
* **`opt::loopsum`.** The lemma chain and the fact chain charge a hit its
  recorded cost in place of its own steps (`meter::recharge`, `meter::refund`),
  so the meter, the step budget and `budgets_used.loopsum_steps` do not depend
  on the cache; an entry costing more than the steps left is not used.

## Optimizer O8 (selection, cost model, variant sets)

All additive. No S0/S5-owned file changed (`driver.rs`, `validate.rs`,
`lock.rs`, `elab/**`, `typeck/**` untouched); no kernel change.

* **`opt::cost`** gains `tables` (latency/throughput tables per variant set
  level — `Level::{X86V1, X86V3, X86V4, Aarch64}` — and microarchitecture:
  M5; SPR, Zen 4, Zen 5), `tuning` (`Tuning`: the committed tuning evidence,
  its FNV-1a `hash`, `Tuning::{committed, shared, none, from_texts}`) and
  `model` (`SetModel::{new, portable, fn_cost, expr_cost, term_cost,
  lane_cost, lifted_fn_cost, fn_costs}`, `beats` — the 3% gate — `top`,
  `TOP`, `RETRIES`, `LoopRungCosts`, `fmt_mc`, `prim_op`). Costs are
  fixed-point milli-cycles.
* **`opt::OptOptions::tuning: Arc<Tuning>`** (default: the committed files).
  **`opt::choice_inputs_hash(&OptOptions)`**: the hash of the tuning evidence
  and the profile samples; `opt::cache::Cache::with_inputs` puts it in every
  proof-cache key.
* **`opt::egraph`** (new): `improve` (the aegraph on a tier-0 residual),
  `aeg::EGraph` (≤ `MAX_NODES` = 10^4 e-nodes), `rules` (`FILES`,
  `BITSUM_CORE`, `CONG_CORE`, `index`, `ensure`, `ensure_files`,
  `Signature`, `RuleSig`),
  `explain` (`Rewrite`, `Explanations`, `chain`; `cong_irr` lifting),
  `extract` (`candidates`), `quote_region`, `tree_size_capped`.
* **`opt::Rung::Rewritten`** (between `Driven` and `StraightLine`): a
  straight-line residual rewritten by the aegraph, linked by its lemma
  `f__residual::equiv` (report rung name `"Rewritten"`).
* **`opt::multiversion`.** `VariantSet` gains `hot` (tree seeds that call no
  variant), `kat_fault` (test hooks only; uninhabited in production) and
  `blocked` (functions left out of a tree), and `VariantSet::of_variants`,
  `VariantSet::feature_only`. New: `SCALAR_FEATURES`, `V4_FEATURES`,
  `MAX_SETS`, `bit_sensitive`, `feature_only_sets`. The call tree also grows
  from `hot` and never contains another set's clone (a `#[target_feature]`
  function).
* **`opt::hooks`.** `KatFault::ForceDetect` and `OptTestHooks::kat_faults`
  (R21: the emitted detection reports the set's features; the self-test is
  the production template, and R21 simulates a `bsr` CPU by patching the
  compiled binary). `OptTestHooks::rule_files` replaces the aegraph's rule
  library (a stale or corrupted rule file).
* **`canon::dispatch_module(krate, sets, i)`** takes the print view (the
  known-answer self-test names each variant and its portable function); the
  runtime detection of a set is `features && kat_<set>()`. `roundtrip.rs`
  compares against the same template. The self-test's results and
  arguments go through `core::hint::black_box`, and its zero-input
  `lzcnt`/`tzcnt` checks are `asm!` with the destination cleared (so LLVM
  cannot fold a check away and a `bsr` CPU cannot pass by leaving the
  destination unchanged). A `#[target_feature]` function prints
  `#[inline]` for `Inline::Always` (rustc rejects `#[inline(always)]` there).
* **`opt::loopsum`.** The summarizer prices the rungs (`rung_costs`) and
  tries a weaker rung first only when it is ≥ 3% cheaper than the closed
  form; the helper's `describe` (and so the report reason) ends with
  `rung costs (portable, traces): …`.
* **Lemma files.** `lemmas/rules/bitsum.core` and `lemmas/cong.core`
  (generated by `sandblaster/rulegen`, loaded and kernel-checked by
  `opt::egraph::rules::ensure` the first time a rule trigger fires). The
  result is recorded once per build: a library that fails its check is a
  warning (an error in strict mode) and is not used for the rest of the
  build. `ensure_files` returns `Ok` when every lemma is already loaded and
  an error when only some are.
* **`sandblaster-targets`.** `evidence::tuning::COMMITTED` (the embedded
  committed tuning files); `evidence/tuning-aarch64-m5.json` (local
  calibration) and `evidence/tuning-x86_64-zen5.json` (host round 0).
* **`sandblaster/rulegen`** (new workspace member, not a default
  member): the offline rule generator.
* **`tools/asmcheck`.** Assertions take `require_any` (at least one of the
  listed mnemonics) and `exclude` (a regular expression over labels: the
  matching functions are left out).

## Optimizer headroom (optimizer time, feature-only set evidence)

No S5-owned file changed (`driver.rs`, `validate.rs`, `lock.rs`, `elab/**`,
`typeck/**`, `sandblaster/sandblaster/src/build.rs`, `sandblaster/cli/src/main.rs`
untouched); no kernel change. Every change below is additive except where
marked.

* **`opt::symex::symex_via(env, g, via, opaque, budget)`**: symbolic
  execution with the callees in `via` (callee → its admitted straight-line
  residual) unfolded through their residuals; `symex` is `symex_via` with an
  empty map. Tier 0 passes its inlined callees' residuals.
  **`opt::symex::reset_memo()`**: `is_recursive` is memoized per optimizer
  run (reset at the start and end of `optimize`).
* **`opt::derive`** (new module): the derived links of multiversioned clones
  (`DrivenInfo`; `residual_link` and `seg_helper_link` are crate-private).
  The report's reason and link of a clone are unchanged; its lemma
  `f'__residual::equiv` (and a segment helper's `h'::equiv`) may now be a
  transitivity proof through `f'__residual::mirror_equiv` (resp.
  `h'::mirror_equiv`, `…::entry::clone_equiv`), the original's lemma and the
  clone lemma.
* **`opt::seqsum::drive::Registry::peek(def)`**: the number `reserve` would
  give next, without reserving it.
* **`opt::hooks::OptTestHooks::set_evidence: BTreeSet<String>`** (test hooks
  only): feature-only variant sets generated as if a host had run them.
* **Behaviour (x86): feature-only variant sets need host evidence.** A
  feature-only set (`v3_scalar`, `v4`, a variant set combined with
  `v3_scalar`) is generated only when
  `sandblaster_targets::evidence::set_validation` finds a passing host run of
  its clones on a CPU that reports every feature of the set; otherwise it is
  reported in `Optimized::not_cloned` as `("*", set, "the set is not
  generated: no host evidence …")`. A set with evidence is priced on the
  originals' residuals after they are specialized and is not generated when
  no function of its tree is ≥ 3% cheaper; its clones are then admitted and
  specialized after the originals (their `FnReport`s come last in
  `Optimized::fns`). No committed record has such a run, so the x86 emission
  has no feature-only set today.
* **`auto::bitlib`**: a family member reuses the previous member's
  certificates only when it has at least 8 holes (`REUSE_MIN_HOLES`).
* **`opt::cache::Cache`**: entry files are written by a background thread,
  joined when the cache is dropped (`Cache` implements `Drop`); if the
  thread cannot be started, entries are written in place.
* **`sandblaster-targets`.** `evidence::{SetRecord, SetVerdict, set_hash,
  set_run_status, set_run_json, with_set_run, set_verdict_in,
  set_validation}`; **`EvidenceFile::sets`** (a new field: code that builds
  an `EvidenceFile` literal must add it); the optional top-level `sets`
  array of the evidence records (merged by `merge_files` per CPU, set and
  suite). `evidence::load`, `model_hash` and `coretext::core_hash` are
  memoized per process (`load` while the file's size and modification time
  stay the same). The evidence binary gains `--record-set` and reports the
  recorded sets in `--check-file`; its detected features also cover `sse`,
  `sse3` and `f16c` (implied features of `v4`).
* **Tests.** `tests/host_sets.rs` (ignored by default: the host kit's `sets`
  harness). `tests/opt_x86.rs` checks the production x86 emission without
  feature-only sets and, with their evidence granted by the hook, the four
  sets as before. `tests/opt_reject.rs` R21 grants the sets' evidence.
  `tests/codegen_capture.rs` uses wrapping arithmetic in its input
  generator (it overflowed in the debug profile).
* **`tools/asmcheck/o1.toml`**: the 24 feature-only assertions (the
  `v3_scalar`/`v4` clones and self-tests) check that those functions are
  absent until a host round records the sets; the `shape__portable`
  assertions name `shape` (not multiversioned without a set) and the corpus
  `__portable` assertion checks there is none. **`tools/host-kit/run.sh`**:
  stage `sets`.
* **Headroom fixes (review).**
  * `sandblaster-targets` `evidence::parse` reads set runs strictly: `cases`
    and `mismatches` must be unsigned integers, `features` and
    `unreported_features` arrays of strings, `status` one of `passed`,
    `failed`, `skipped`, `diagnostic`, `set_hash` the `set_hash` of `set`
    and `features`, and each unreported feature one of `features`;
    otherwise the file does not parse (as for a malformed model host
    entry). A set-run JSON object built by hand must now carry `features`.
  * `evidence::set_verdict_in`: any current run with a mismatch, a `failed`
    status or a status its counts contradict (`SetRecord::failure`, new)
    withdraws the set; a CPU counts only with passing runs of every suite of
    `evidence::SET_SUITES` (new: `qmdb-fixtures-n1`, `qmdb-fixtures-n32`,
    `shape-differential-n1`, `shape-differential-n32`), each with at least
    `evidence::set_suite_min_cases(suite)` cases (new; 10^6 for a shape
    differential, `evidence::REQUIRED_SHAPE_CASES`), and only when no other
    record says it lacks one of the set's features (a set run listing it as
    unreported, or its host summary). `SetRecord::counts_as_evidence`
    recomputes the status from the counts.
  * `evidence::HostSummary::detected_features: Vec<(String, bool)>` (a new
    field: code that builds a `HostSummary` literal must add it).
  * `evidence::model_hash` memoizes by the model's items, not its address.
  * `opt`: the pre-pricing of the feature-only sets treats a tree function
    with any aegraph rule match as paying (the check on its clone decides),
    so it never drops a set O8's check would keep.

## Optimizer O10 (target models, the lane functor, SIMD search)

* **New module `opt::par`** (`src/opt/par/**`): `tiles` (lane targets
  `AVX512_X16`, `AVX2_X8`, `NEON_X4`; tiles and their word/vector lemma
  text), `cquote` (a checkable quoter for the few value shapes the lane
  functor copies into kernels), `lift` (the lane functor: `find_site`,
  `plan`, `lift_site`/`lift_site_with`, `prove`, `LaneStats`,
  `LaneFault::SwapLanes` for R16, `LANE_PROOF_STEPS` = 2·10⁹), `sites`
  (syntactic lane sites, `source_cost`), `search` (the SIMD search
  lowering: `candidates`, `lower`, `prove_link`, `library_text`,
  `ensure_library`, `Cmp`), `seqeq` (the SIMD `seq::eq` candidate:
  `comparisons`, `candidate`, `lemma_text`, `SeqEqReport`), and
  `LaneReport`.
* **`opt::Optimized`** gains `lanes: Vec<par::LaneReport>` and `seq_eq:
  Vec<par::seqeq::SeqEqReport>` (code that builds an `Optimized` literal
  must add them). A lane kernel and a search variant appear in `variants`
  as variants of their site (`VariantReport`); the lane kernel's
  `equivalence` names `<kernel>::lane_equiv`, the search variant's
  `<variant>::search_equiv`.
* **Optimizer phases.** 1b: lane kernels (`opts.multiversion` only; a
  lane kernel not dispatched is a ghost item, or public and printed with
  `SANDBLASTER_LANES_COMPILE_ONLY=1`); 1c: search variants (aarch64); the
  `seq::eq` candidates (aarch64, reported only). Lane kernels and search
  variants are not specialized again in phase 3. Phase 2 reads variant
  definitions from the extended crate (the variants the optimizer adds
  are not in the source crate).
* **Evidence gate for lane kernels.** A dispatched lane kernel needs a host
  run of the kernel: `sandblaster_targets::evidence` set records named
  `lanes:<target>:<32 hex of the SHA-256 of the kernel's emitted text>`
  with suite `lane-differential` (`LANE_SET_PREFIX`, `LANE_SUITES`,
  `REQUIRED_LANE_CASES` = 10⁶, `set_suites(name)`). The optimizer's
  evidence check reports "lane kernel `..` is dispatched without host
  evidence of the kernel (..)" as an error (R26).
* **Lane kernel fingerprint (O10 fix).** The set name hashes the code a
  host runs, not the core text: `opt::par::lane_fingerprint(krate, item,
  target) -> Result<LaneFingerprint, String>` (`kernel_tokens`, `emission`,
  `set`) covers the kernel item's printed tokens
  (`roundtrip::lane_item_tokens` / `lane_kernel_tokens`: doc attributes
  and visibility dropped), every load/store and `__rt` helper it calls,
  the target and `sandblaster_targets::evidence::BUILD_RUSTC` (new: `rustc
  -V` of the build). New `canon::lane_kernel_text(krate, id) ->
  LaneKernelText { item, helpers, chk }` prints one function as phase-3
  printing does. `par::LaneReport` gains `kernel_tokens` and `core_hash`
  (the old core-text hash, reports only). The round trip
  (`roundtrip::check`, and `roundtrip::lane_kernel_check(code, o)` alone)
  fails when a printed lane kernel's tokens differ from `kernel_tokens`.
  `intrinsics::helper_template(id)` is what the printer emits for a helper
  (the template, or a test-only replacement:
  `opt::hooks::with_helper_template(arch, name, template, f)`, R26).
  `par::lift::LaneStats` gains `lift_peak_bytes` and `lift_millis` (the
  whole lift, site to `lane_equiv`); `par::search::Lowered` gains
  `instance_steps` (`prove_link_counted`; `opt::proof::commit_counted`).
  `tests/host_lanes.rs` emits for the target's architecture (aarch64: the
  NEON ×4 kernel, forced past the cost model) and checks that `rustc` on
  PATH is `BUILD_RUSTC`.
* **`opt::hooks::OptTestHooks`** gains `lane_faults: BTreeMap<String,
  par::lift::LaneFault>` (R16); `grants_set_evidence` also accepts
  `lanes:<target>` for every kernel of a target.
* **`opt::residual::build_opts(.., bind_calls)`** (new; `build` is
  `build_opts(.., true)`): the lane mode binds a call only when it is used
  more than once and reads nested array parameters element-wise; 256/512-bit
  literal vectors print as `load_u32x16`/`load_u32x8` of `u32` lanes.
* **`opt::mirror`**: array-literal (`Pair`) positions are transported over
  the irrelevant length fact, applied to the clone's own fact.
* **`intrinsics`**: the O10 NEON models (`vcltq/vcgeq/vceqq_u8`, `vcntq_u8`,
  `vaddvq_u8`, `vmaxvq_u8`, `vreinterpretq_u16_u8`, `vshrn_n_u16/u64`,
  `vmovn_u64`, `vsraq_n_u64`, `vbslq_u64`, `vmull/vmlal_u32`, the SHA3 and
  SHA512 group, …), `_mm512_slli/srli_epi32`, and the helpers
  `load_u32x16`/`store_u32x16`/`load_u8x64`.
* **`sandblaster-targets`**: `src/aarch64/{neon2,sha3}.rs` (35 models),
  `Uint16x8`, `Uint64x2`, `Uint32x2`; registry `Source::Neon2`/`Sha3`,
  `ROUND0_AARCH64` (the pre-O10 count); `core/aarch64.core` O10 section;
  `coretext` entries and helpers `load/store_u32x8/u32x16`
  (`core/x86_64_avx.core`, `gen/x86_64_avx.py` `WIDE_HELPERS`); `diff`
  samples for `[u16; 8]`, `[u64; 2]`, `[u32; 2]`, `[u32; 16]`;
  `evidence/aarch64.json` regenerated natively (58 aarch64 models).
* **Tests.** `tests/opt_lanes.rs` (lane functor and phase), `tests/opt_search.rs`
  (search variants, `seq::eq` candidate), `tests/host_lanes.rs` (ignored:
  the host kit's `lanes` harness), `tests/samples/lanes/**`; `opt_reject`
  rows R16 and R26 (lanes, and a NEON variant with withheld model evidence);
  `tests/evidence.rs` uses `vsha512rq_u64`/`vsm3ss1q_u32` as unknown models.
  `tests/opt_corpus/corpus.toml` P12: `crate::first_small__neon` is
  specialized (the `{neon}` clone of the caller).
* **Tools.** `tools/gates/g7.sh` builds the lanes sample (compile-only) for
  both x86 triples and aarch64; `tools/asmcheck/o1.toml` has 6 lane
  assertions; `tools/host-kit/run.sh` has the stage `lanes`.
## §15 S5 gates (the crate path, the stage boundary, gate-mode mutation)

Every §15.8 gate now runs, unconditionally, on every path that states a
crate verdict or writes crate output. No option selects gates.

**The crate path — `driver::gates` (re-exported from `driver`).**
- `build_crate(&Checked, LockUse, root_display) -> CrateBuild`: proofs
  (elaborate, law audit, resource gate), the surface and the lock status
  (with every difference classified), the six gates in order (boundary,
  examples, sections, law-rules, lock, mutation; mutation runs once the
  others passed), then with `LockUse::Enforce` the optimizer, the printer
  with the verdict header, the round trip, the `SANDBLASTER_SPEC_ROOT` check,
  `emission_chain` and the resource gate again. The optimizer options come
  from `OptOptions::from_env` (`SANDBLASTER_STRICT_OPT` only).
- `LockUse::{Enforce, Accepting}`: `Accepting` (`sandblaster spec --accept`)
  skips only the lock comparison and never optimizes or prints.
- `CrateVerdict` (private fields; only `build_crate` constructs it):
  `code()`, `code_sha256()`, `summary()`. `AcceptPermit` (private fields;
  only `build_crate` with `Accepting` constructs it): `target()`,
  `surface_root()`. `GatesPassed`: the printer's seal (never leaves the
  crate path).
- `CrateBuild` fields: `v`, `law_audit`, `spec`, `spec15`, `surface`,
  `changes`, `gates: GateReport`, `emit` (its `code` is always empty: the
  printed file lives only in the verdict), `emit_error`, `report`, `timing`,
  `verdict`, `permit`; methods `status()`, `diagnostics()`, `summary(&Checked)`
  (the CLI `check` summary with one `gate <name>: …` line per gate),
  `render_failure(&Checked, root)`, `optimizer_warnings()`,
  `api_differences()`.
- `GateReport { results: Vec<GateResult>, diags, mutation, chain,
  emitted_sha256, elapsed }`, `GateResult { gate, ran, errors, warnings,
  note }`; `GateReport::json()` is the report's new `gates` section
  (deterministic: no times).
- `emission_chain(&elab::Output, &OptimizedEmit) -> Vec<String>`: the
  read-only cross-check (dispatched clones related and with their equality
  lemma in the kernel env; dispatched variants with their `VariantEquiv`
  lemma; specialized functions with their residual-equality link).
- `build_verified` (the build script's logic) is now a thin wrapper of
  `build_crate(.., LockUse::Enforce, ..)`; it always prints
  `cargo::rerun-if-changed=<lock path>` and writes `sandblaster.rs` only with a
  verdict. Its success warning includes the gates and the emitted file's
  hash.

**Stage APIs moved to `driver::stage`** (never a crate verdict; see the
module docs): `verify`, `verify_with_sources`, `verify_audited`,
`with_elaboration`, `verify_and_optimize -> StageBuild` (was `Built`),
`optimize_emit`, `optimize_emit_mode`, `emit_stage` (was `emit_verified`),
`eval_in`, `eval_json`, `spec_run`/`SpecRun`/`SpecBaseline` (for `spec
--diff`), `emit` and `front_end_report_json` (the phase-1 printer and report,
were `driver::emit`/`driver::report_json`), `summary(&Checked, &Verification)`
(was `verified_summary`) and `report_json(c, v, audit, root, em, spec, s15)`
(replaces `verified_report_json{,_opt,_audit,_spec,_full}`; status is
`status_str`).
- `Verification.verified` → `Verification.proofs_ok` (the proofs checked;
  not a verdict). `status_str` of a stage run whose proofs checked is
  `canon::STAGE_RUN` ("PROOFS CHECKED (stage run, no crate verdict: …)").
- Removed: `driver::build_phase1`, `driver::PHASE1_ENV`
  (`SANDBLASTER_PHASE1_UNVERIFIED`), `driver::spec15_lock_gate` (call
  `lock::enforce`), `canon::VERIFIED` (`VERIFIED (phase 2)` is printed
  nowhere).

**Printer headers (`canon`).** `canon::STAGE` = `STAGE OUTPUT (not a crate
verdict: the §15 gates did not run)`, the second line of every stage print
(optimized, unoptimized, test-only exec-only). `canon::OPTIMIZED`
(`VERIFIED + OPTIMIZED (phase 3)`) is printed only with
`OptPrint.verdict = Some(&GatesPassed)` (new field; `None` everywhere
else). `print_crate_verified` → `print_crate_stage`.
`verdict_header_first_lines(root)` gives the two lines consumers check.

**Lock.** `lock::lock_path(root)`: one lock per root (`SPEC.lock` for
`mod.rs`/`lib.rs`, `SPEC.<stem>.lock` otherwise); `driver::check` uses it.
`lock::accept(&AcceptPermit, old, surface, sel)` (new first parameter; the
permit must be for the surface's target and full-accept root).
`lock::preview_accept(old, surface, sel)`: the same computation without a
permit, writing nothing (tests, review tools). `LockStatus::json` no longer
has an `enforced` field.

**Mutation engine (`mutate`).** `run_gate(krate, sm, &elab::Output)`: the
gate-mode run on the build's own elaboration (call it on the elaboration
thread). `MutateOptions::gate()` (every mutant, no deadline, reads no
environment variable) and the new field `MutateOptions::gate`. Gate mode
elaborates a spec mutant's spec closure and law checkers only (through
`elab::Options::items`), tries its known answers one per elaboration and
stops at the first kill (`#[example]`s nearest first, then the smallest
vector file, then the distinguishing search, then the larger vector files
only for a survivor with a witness), and runs batches on up to four
threads; implementation mutants only when a section is not fully
specified. `elab/examples.rs` (surgical): in a filtered elaboration a
vector file stops at its first definite failing record. Fix (the S4 `words` survivor): a failing
vector record (`detail` "is false") is now a definite kill, like a failing
`#[example]`. `SANDBLASTER_TRACE_MUTATION` prints one line per gate batch
(output only).

**Elaboration (surgical, `elab/mod.rs`).** `Options::items:
Option<Arc<BTreeSet<ItemId>>>` and `Options::elaborates(krate, id)`: only
those items (and every type) are elaborated, the whole-crate passes (§15
post passes, sections, law rules) are skipped, and the output carries an
error diagnostic so `Output::verified()` is false. Only the mutation gate
sets it.

**Report.** New `gates` section (see above) with `emitted.sha256`; the
`sections` and `law_rules` entries lost their `enforced` strings; timing
gains `gates_ms`, `mutation_gate_ms`, `mutation_gate_batches`.

**CLI.** `check`, `emit`, `report`, `spec`, `coverage` run `build_crate`
(exit 0 only with a verdict); `spec --accept` runs `build_crate(Accepting)`
and writes the root's lock only with the permit; `coverage` adds an
exploration run whose caps shape only its report; `eval` and `spec --diff`
are stage tools (no verdict).

**Example.** `cargo run -p sandblaster-front --example stage_emit -- <root>
[--target aarch64|x86_64]`: optimized stage output for the optimizer corpus
(`bench/opt-corpus/run.sh`), accepted only by `bench/opt-corpus/cgen`.

## §15 S5 front-end gaps (role `gaps`)

The features the fully specified QMDB needs (SEMANTICS.md §13.8–§13.11).
All additive except where marked **behavior**.

### Language

- **Recursive spec enums** (`typeck::check_recursive_types`, `elab::types`,
  new `elab::recursive`): an enum of a `#[spec]` module may have fields of
  exactly its own type. New `hir::Crate::is_recursive_adt(id)` and
  `typeck::Checker::is_recursive_adt(id)`. Generated definitions
  `T::size'` (spec, `Recursion::Structural`) and `T::size'_pos` (lemma),
  recorded in `Output::defs` with `item = Some(T)`. Inferred measure
  `size'(p)` for recursion and `#[induction(p)]` on pattern-bound fields,
  also in tuple matches (`elab::recursive::{size_measure, field_bindings,
  expr_field_bindings, script_field_bindings, scrut_locals}`).
  `#[derive(PartialEq)]` on such a type is rejected. Exec types stay
  non-recursive.
- **`?` and `return` in spec functions** (new `typeck::exits`,
  `Cx::desugar_exits`): removed right after typing; `FnBody::Spec` never
  contains `ExprKind::Try`/`Return`. **behavior**: the messages "`return`
  is only allowed in exec functions" and "`?` requires the enclosing exec
  function to return `Option`" now read "exec and spec functions" and
  "the enclosing spec function".
- **Ghost prelude `pow2`, `log2`, `popcount`** (`builtins::GhostFn::{Pow2,
  Log2, Popcount}`, `GhostFn::prelude_fn`, `GhostFn::nat_def`; resolved as
  prelude values in ghost code; signature `(Int) -> Nat`). Definitions in
  `elab/ghost.core` (TCB item 6: the lock's `builtins` hash changes).
  `hir::UnfoldTarget::Ghost(GhostFn)` for `unfold(pow2)` /
  `by_unfolding(log2)`.
- **`#[example]` on ghost constants** (`hir::ConstDef::examples`, new
  field; `hir::Crate::examples_of(id)` for functions and constants; the
  surface entry uses it — surgical edit in `surface.rs`).
- **`Nat` index into arrays** in ghost code: `a[i]` with `i: Nat` is
  `Callee::Ghost(GhostFn::SIndex, [T])` on the array coerced to `Seq<T>`.
- **`#[opaque]` on spec functions** (new `resolve::Annot::Opaque`,
  `hir::SpecAnnots::opaque`; erasing macro `sandblaster_macros::opaque`,
  exported by `sandblaster::prelude` and `sandblaster::ghost` — surgical edits
  in `sandblaster-macros`, `sandblaster/src/{prelude,ghost}.rs`): the kernel
  definition gets `DefDecl.opaque = true`.
- **`#[decreases(e)]` on an induction proof** is now the proof's measure
  (it was ignored, so such proofs failed with "cannot infer a measure").

### Examples (`elab::examples`)

- JSON record values: objects give struct values (fields by name,
  case-insensitively; missing or extra field = error; invariant and `Nat`
  bounds as obligations), arrays give tuples (and `Seq`s), `null` gives
  `None`. **behavior**: a nested object or `null` in a record was an error.
- **behavior** (G8): a vector-file record is decided by `eval_closed`
  first; its `ExampleRecord::method` is `EvalClosed` (was `Conversion`
  when checking-mode conversion decided it). 400 one-block SHA-256 CAVP
  records: 34.7 → 23.8 ms each (the `evalspeed` probe, 14.4 s → 10.1 s).

### Lemmas and `auto`

- New lemma file `lemmas/nat.core` (loaded last; `lemmas::load` first
  loads the ghost library through `elab::semantics::load_ghost_library`,
  which `semantics::install` now also uses): `nat::{pow2_pos, log2_nonneg,
  popcount_nonneg, popcount_le, pow2_succ, popcount_even, popcount_odd,
  log2_bounds}`, also `sandblaster::lemmas::nat::…`. Source:
  `tests/samples/s5_gaps/nat_lemmas/nat.rs`.
- `seq::eq_refl` is a `Backward` rule.
- `auto::arith`: `T::size'` atoms get `T::size'_pos`; `pow2`/`log2`/
  `popcount` atoms get their `nat::` facts.
- `auto::facts`: a boolean fact about a recursive definition applied to a
  constructor of a crate recursive type is unfolded once (`Delta`); a
  path equation `match s { .. } == C(..)` is determined like a boolean one;
  `seq::eq(a, b) == false` with `a = b` (conversion or an equation fact) is
  a contradiction (`seq::eq_refl`, machine-integer elements only);
  `Engine::push_lin_conclusion_pub`.
- `elab::refine`: a script `match` on a tuple of distinct variables refines
  each of them (one matrix column per variable; top-level or-patterns
  expanded into rows), and `Seq` variables are refined (the list's `Nil` /
  `Cons`). `elab::types::{ind_of, ctor_field_tys, ctor_count}` accept
  `Ty::Seq`. Script rest bindings (`r @ ..`) are recognized in tuple
  matches and on `Seq` parameters for `ih`.
- `elab::exec::p0` is `pub(crate)`.

## Prover ergonomics, package P2 (the elaborator; role `pkg1`)

Additive; no kernel change.

- `elab::Elab::nat_ranges: HashMap<GlobalId, (GlobalId, u32)>` (spec
  function ↦ its `f::nat_range` lemma and arity). `f::nat_range` is a
  `DefKind::Ensures` definition added after a spec function whose result has
  `Nat` components (`ensures::nat_range_def`, silently skipped when its proof
  fails); `ensures_def` is now `ensures_def_of(.., Option<&Ensures>)`
  underneath. `obl::prove_hinted` binds the instances for the applications
  in the goal and the facts as irrelevant slot facts (`h_range`, only kept
  in the proof when used); the closers' view adds them as facts.
- `ensures::with_induction_hyps`: recursive calls in the path equations in
  scope (not only in the leaf value) get induction hypotheses when the
  measure is seen to decrease. `walk_match` records each path equation's
  statement in `Scope::fact_tys`.
- `closers::restricted_view`: copied facts, the goal and `let` equations
  refer to the copies of other copied facts (`generalize_remap`); `let`s
  stay definitions (re-bound after the view's variables); proofs about the
  view's functions embedded in statements (`DefKind::{Lemma, Law, Ensures}`
  globals whose type mentions them) become view variables; `by_unfolding`
  adds unfolded copies of the facts that apply a named recursive/opaque
  definition, plus the comparisons its body tests when linear arithmetic
  decides them (`h_guard`). `echo_attempt` keeps the old fact set.
- `apply::by_computation` substitutes the variables that facts fix to
  literals or constructors (`fixed_variables`, `substituted_goal`);
  `calc_chain` lifts an exec-typed prefix through a view link
  (`calc_lift`) and checks the chain against its conclusion.
- `script`: `rewrite` of a variable side generalizes the variable
  (`abstract_level`); a value-path rewrite whose motive or sides contain
  `Erased` is an `Unsupported` error instead of a kernel rejection;
  `branch_script` (script `match`/`if` arms, and `refine.rs`'s refined rows:
  a one-line edit there) hoists the body facts the branch exposes.
- `exec::short_circuit` flattens same-operator chains of at least
  `FLAT_CHAIN = 5` operands (`chain_operands`, `chain_step`) outside exec
  function bodies (spec functions, contracts, proofs); shorter chains and
  exec bodies, which the code generator prints, are unchanged.
- The derived facts (unfolded facts, decided guards, Nat ranges) are used
  only when the goal does not follow without them: `obl::prove_hinted`
  retries with the range facts, `closers::by_reasoning` with the derived
  view, after a silent first attempt.
- `typeck`: `#[induction(n)]` on a `Nat`/`Int` parameter implies
  `FnDef::decreases = n`; header `let`s before `requires`/`ensures` wrap the
  contract statements in blocks (`abbreviated`) and start the script;
  identifier patterns of synthesized prelude lemmas skip the hazard check
  (`Cx::prelude_lemma` is `pub(super)`).
- `resolve::Resolver::resolve_path_defs_ghost` (no privacy check): a lemma
  named in an exec `proof!` block resolves whatever its visibility.
- `elab/generated.rs`: one-line initializer of `nat_ranges`.

## Integration of main (optimizer O6–O10), §15 S5 and the prover fixes

- `driver::Checked::profile: Option<driver::ProfileInput>` (new field;
  `ProfileInput { path, parsed }`, `ProfileInput::loop_samples`): `check`
  reads `PROFILE.json` (optimizer design §10.4) through the file provider,
  like the lock. `gates::build_crate` sets `OptOptions::loops.profile` from
  it (no new option); `build_verified` emits `cargo::rerun-if-changed` for
  it and a `cargo::warning` when it does not parse. `sandblaster profile`
  stays a stage tool (it writes the file, never a verdict); `emit`/`report`
  read the profile through the crate path instead of loading it themselves.
- Lemma files: the elaborator's generic `Seq` library is now
  `lemmas/seq_lib.core` (was `seq.core` on the prover-fix branch);
  `lemmas/seq.core` is the optimizer's Σ3 library. Three optimizer lemmas
  were renamed so no name is defined twice (`seq::index_eq` →
  `seq::index_at_eq`, `seq::index_take` → `seq::index_take_lt`,
  `seq::take_append` → `seq::take_append_split`), and its copy of
  `seq::append_assoc` was dropped (the same statement is in
  `flatten.core`). `opt::seqsum::ensure_lemmas` fails instead of shadowing
  when one of its names is already defined.
- `opt::cost::profile::profile_crate` calls `driver::stage::with_elaboration`;
  `canon::lane_kernel_text` prints with `verdict: None`; main's optimizer
  tests call `driver::stage::optimize_emit*`.

## Module mode (augmentation pilot, role `modmode`; DESIGN.md §2.1)

A verified module inside an ordinary host crate. All additions; crate mode is
unchanged (same gates, same emitted file, same report except the fields
below).

- `relocate` (new module): `relocate(code, note) -> Result<String,
  Vec<String>>` rewrites a crate verdict's file for inclusion as one
  module's body — `crate::` path heads become `self::` / `super::`×depth
  (position independent), `pub(crate)` becomes `pub(self)` /
  `pub(in super::…)` (visible exactly within the file), the guard's
  `compile_error!` becomes `::core::compile_error!`, and every top-level item
  but the guard gets `MODULE_LINTS` first — and refuses `$`, out-of-line
  `mod x;`, macros outside `MACROS`, a `crate` token that is neither a path
  head nor `pub(crate)`, and relative paths that would leave the file. The
  rewrite is computed on token trees, applied to the text by byte range,
  and the result re-tokenized and compared token for token (spacing
  included); any difference is an error. Also `module_note`, `tokens`,
  `flatten`, `Tok`, `MACROS`, `MODULE_LINTS`.
- `driver::gates::Emission { Crate, Module { module_file, out } }` and
  `build_crate_emitting(c, lock, root, &Emission)`; `build_crate` is
  `build_crate_emitting(.., &Emission::Crate)`. Module mode relocates after
  the round trip, the spec-root check and `emission_chain`, as one more
  emission-chain step (a refusal is an `error[emission-chain]` finding: no
  verdict, no code).
- `driver::gates::GateReport::emitted_file` (new field; empty means
  `sandblaster.rs`) and `GateReport::file_name()`: the report's
  `gates.emitted.file`, `CrateBuild::summary`'s `emitted:` line and the
  verdict summary name the emitted file (`<out>.rs` in module mode).
- `CrateBuild::render_failure`: a build whose only findings are
  emission-chain findings now says so ("the emission chain of `root`
  failed"), instead of "failed the §15 gates ()" with an empty gate list
  (both modes).
- `driver::module` (new): `build_module(root, module_file, context, env, fs)
  -> BuildOutcome` (the logic of `sandblaster::build::compile_module`),
  `module_out_name`, `module_include_line`, `module_file_ok`; re-exported
  from `driver`. Checks: the module file (under `src/`, not the crate root)
  is exactly `include!(concat!(env!("OUT_DIR"), "/<out>.rs"));` plus
  comments; no other `.rs` under `src/` mentions `"/<out>.rs"` outside
  comments; the DSL root is not under `src/`. Outputs `OUT_DIR/<out>.rs`,
  `<out>-report.json`, `<out>-timing.json` and, with a `context`,
  `<out>-verdict.key` (verdict reuse for an identical input set; see the
  module docs). Prints `cargo::rerun-if-changed=<manifest>/src`.
- `loader::FileProvider::list_rs(dir)` (new provided method, default
  `Unsupported`): implemented by `RealFs` (recursive, sorted) and `MemFs`.
  `sandblaster-cli`'s `GitRevFs` keeps the default (it never builds a module).
- Facade (`sandblaster` crate, feature `build`): `sandblaster::build::compile_module(root,
  module_file)`; `compile` is unchanged (its tail moved into a private
  `finish`). The verdict-reuse context is the SHA-256 of the build-script
  binary plus every `SANDBLASTER_*` variable but `SANDBLASTER_MEM_LIMIT_GB`.

Tests: `relocate` unit tests (3); `tests/module_mode.rs` (10: the relocated
verdict equals the relocation of the crate-mode verdict; rustc compiles and
runs the module in a host crate next to decoys and agrees with the source;
host access to internals is E0603; a host that denies warnings and uses part
of the boundary compiles; negative twins for the module file, a second
include, failing proofs and gates, no-opt-out variables, the DSL root under
`src/`, file names; verdict reuse and its invalidation). The example host
crate and its cargo-level twins live in the pilot's scratch directory
(`aug/modmode/host-example`, `aug/modmode/twins.sh`).
