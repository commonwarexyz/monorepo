//! Kernel API (FROZEN SIGNATURES — DESIGN.md §5.11). Implementations live in
//! the other kernel modules; these signatures are the contract used by the
//! front end, the automation and the optimizer.
//!
//! Additive extensions (recorded in `INTERFACE_CHANGES.md`): prelude loading
//! ([`Env::with_prelude`]), core text syntax entry points, name lookups,
//! [`Env::ctx_venv`] (the evaluation environment of a context, with array
//! eta), typed quoting ([`Env::quote_typed`]) and small accessors; the §15
//! entry points [`Env::refs_closure`], [`Env::abstract_section`] and
//! [`Env::eval_closed`].

use std::collections::HashMap;

use crate::env::{DefInfo, IndInfo, Known, Pending};
use crate::term::{DefDecl, DefKind, GlobalId, IndId, InductiveDecl, Lvl, Name, Rel, Tm};
use crate::value::{Budget, EnvEntry, EvalError, V, VEnv};

/// Kernel errors carry a human-readable message; the front end maps them to
/// diagnostics with spans.
#[derive(Clone, Debug)]
pub struct KernelError {
    pub kind: KernelErrorKind,
    pub message: String,
}

impl std::fmt::Display for KernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for KernelError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelErrorKind {
    TypeMismatch,
    NotAType,
    IllFormed,
    Relevance,
    Termination,
    Linarith,
    BvRefl,
    Erased,
    Eval(EvalError),
}

/// One typing-context entry.
#[derive(Clone, Debug)]
pub struct CtxEntry {
    pub name: Name,
    pub rel: Rel,
    pub ty: V,
    /// `Some` for let-bound entries (the value is available to conversion).
    pub def: Option<crate::value::Arg>,
}

/// A typing context: a persistent list of entries (level 0 = outermost).
#[derive(Clone, Debug, Default)]
pub struct Ctx {
    pub entries: std::rc::Rc<Vec<CtxEntry>>,
}

impl Ctx {
    pub fn depth(&self) -> Lvl {
        Lvl(self.entries.len() as u32)
    }
    /// Extend with a binder. (Implementation may use a persistent structure.)
    pub fn push(&self, e: CtxEntry) -> Ctx {
        let mut v = (*self.entries).clone();
        v.push(e);
        Ctx { entries: std::rc::Rc::new(v) }
    }
}

/// The global environment: inductives and checked definitions.
pub struct Env {
    pub(crate) inds: Vec<IndInfo>,
    pub(crate) defs: Vec<DefInfo>,
    pub(crate) bool_id: IndId,
    pub(crate) empty_id: IndId,
    pub(crate) global_names: HashMap<Name, GlobalId>,
    pub(crate) ind_names: HashMap<Name, IndId>,
    pub(crate) ctor_names: HashMap<Name, Vec<(IndId, u32)>>,
    pub(crate) known: Known,
    /// The definition whose body `add_def` is checking.
    pub(crate) pending: Option<Pending>,
}

/// The result of `whnf`-style inspection used by automation.
pub struct Inspect;

impl Default for Env {
    fn default() -> Self {
        Env::new()
    }
}

impl Env {
    /// A fresh environment with the builtins `Bool` (ctor 0 = false, 1 = true)
    /// and `Empty` (no constructors).
    pub fn new() -> Env {
        let mut env = Env {
            inds: Vec::new(),
            defs: Vec::new(),
            bool_id: IndId(0),
            empty_id: IndId(1),
            global_names: HashMap::new(),
            ind_names: HashMap::new(),
            ctor_names: HashMap::new(),
            known: Known::default(),
            pending: None,
        };
        let ctor = |n: &str| crate::term::CtorDecl { name: n.into(), fields: vec![] };
        env.bool_id = env
            .add_inductive(InductiveDecl { name: "Bool".into(), params: vec![], ctors: vec![ctor("false"), ctor("true")] })
            .expect("builtin Bool");
        env.empty_id = env.add_inductive(InductiveDecl { name: "Empty".into(), params: vec![], ctors: vec![] }).expect("builtin Empty");
        env
    }
    pub fn bool_ind(&self) -> IndId {
        self.bool_id
    }
    pub fn empty_ind(&self) -> IndId {
        self.empty_id
    }

    /// Check and add an inductive declaration.
    pub fn add_inductive(&mut self, d: InductiveDecl) -> Result<IndId, KernelError> {
        let _guard = crate::util::StackGuard::enter();
        crate::inductive::add_inductive(self, d)
    }
    /// Check (type, body, relevance, termination) and add a definition.
    pub fn add_def(&mut self, d: DefDecl, b: &mut Budget) -> Result<GlobalId, KernelError> {
        let _guard = crate::util::StackGuard::enter();
        crate::recursion::add_def(self, d, b)
    }

    /// Infer the type of a term in a context.
    pub fn infer(&self, ctx: &Ctx, t: &Tm, b: &mut Budget) -> Result<V, KernelError> {
        let _guard = crate::util::StackGuard::enter();
        let cx = crate::check::cx_of_ctx(self, ctx);
        crate::check::Checker::new(self).infer(&cx, t, crate::check::REL, b)
    }
    /// Check a term against a type in a context.
    pub fn check(&self, ctx: &Ctx, t: &Tm, ty: &V, b: &mut Budget) -> Result<(), KernelError> {
        let _guard = crate::util::StackGuard::enter();
        let cx = crate::check::cx_of_ctx(self, ctx);
        crate::check::Checker::new(self).check(&cx, t, ty, crate::check::REL, b)
    }

    /// Evaluate a term (default unfolding policy, DESIGN.md §5.6).
    pub fn eval(&self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> Result<V, EvalError> {
        let _guard = crate::util::StackGuard::enter();
        crate::eval::Ev::new(self).memoized(env).eval(env, depth, t, b)
    }
    /// Evaluate in the optimizer's *transparent* mode: exactly the globals
    /// in `opaque` are kept as folded heads; definitions declared opaque
    /// (`DefDecl.opaque`) are **not** folded unless they are in the set, so
    /// an empty set evaluates everything (DESIGN.md §5.6). Optimizer only;
    /// the checker never calls this.
    pub fn eval_opaque(&self, env: &VEnv, depth: Lvl, t: &Tm, opaque: &dyn Fn(GlobalId) -> bool, b: &mut Budget) -> Result<V, EvalError> {
        let _guard = crate::util::StackGuard::enter();
        crate::eval::Ev::with_opaque(self, opaque).memoized(env).eval(env, depth, t, b)
    }
    /// [`Env::eval_opaque`] with an empty opaque set: every definition
    /// (including opaque ones) unfolds by the §5.6 policy. The reference
    /// semantics for the optimizer, the CLI `eval` and differential tests;
    /// definition values are cached for this mode.
    pub fn eval_transparent(&self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> Result<V, EvalError> {
        let _guard = crate::util::StackGuard::enter();
        crate::eval::Ev::transparent(self).memoized(env).eval(env, depth, t, b)
    }
    /// Quote a value back to a term. With `share = true`, every value node with
    /// more than one parent is bound once with a `Let` (optimizer residuals).
    ///
    /// Untyped: the Σ type of a pair and the proofs of `absurd`/`transport`
    /// neutrals are not stored in values and are emitted as `Erased`; use
    /// [`Env::quote_typed`] for terms that must be checked again.
    pub fn quote(&self, depth: Lvl, v: &V, share: bool) -> Tm {
        let _guard = crate::util::StackGuard::enter();
        crate::quote::Quoter::untyped(self).quote_root(depth, v, None, share)
    }
    /// Definitional equality (memoized, DESIGN.md §5.9).
    pub fn conv(&self, depth: Lvl, a: &V, b: &V, bud: &mut Budget) -> Result<bool, EvalError> {
        let _guard = crate::util::StackGuard::enter();
        crate::conv::Conv::new(self).conv(depth, a, b, bud)
    }

    /// Definitional equality in the optimizer's transparent mode: closures
    /// are instantiated as by [`Env::eval_opaque`] with the same opaque set
    /// (values already computed keep their folded heads; compare values
    /// produced by `eval_opaque`). Sound: unfolding a definition is an
    /// identity.
    pub fn conv_opaque(&self, depth: Lvl, a: &V, b: &V, opaque: &dyn Fn(GlobalId) -> bool, bud: &mut Budget) -> Result<bool, EvalError> {
        let _guard = crate::util::StackGuard::enter();
        crate::conv::Conv::with_opaque(self, opaque).conv(depth, a, b, bud)
    }

    /// [`Env::conv_opaque`] with an empty opaque set (pairs with
    /// [`Env::eval_transparent`]).
    pub fn conv_transparent(&self, depth: Lvl, a: &V, b: &V, bud: &mut Budget) -> Result<bool, EvalError> {
        let _guard = crate::util::StackGuard::enter();
        crate::conv::Conv::transparent(self).conv(depth, a, b, bud)
    }

    /// Codegen-only candidate check (DESIGN.md §8.3): `candidate` may contain
    /// `Erased` in irrelevant positions; it must be straight-line (no `Match`,
    /// no `Rec`), well-typed at `ty` treating `Erased` as inhabiting its
    /// expected type, and convertible with `reference` applied to the same
    /// parameters. The candidate is NOT added to the environment.
    pub fn check_residual_equal(&self, ty: &Tm, candidate: &Tm, reference: GlobalId, b: &mut Budget) -> Result<(), KernelError> {
        let _guard = crate::util::StackGuard::enter();
        crate::alpha::check_residual_equal(self, ty, candidate, reference, b)
    }

    /// α-equivalence of two terms ignoring binder names and every irrelevant
    /// position (used by the codegen round trip, DESIGN.md §8.3).
    pub fn alpha_eq_relevant(&self, a: &Tm, b: &Tm, corresponding: &dyn Fn(GlobalId, GlobalId) -> bool) -> bool {
        let _guard = crate::util::StackGuard::enter();
        crate::alpha::alpha_eq_relevant(self, a, b, corresponding)
    }

    /// Build the motive `λy. goal[t := y]` by abstracting every occurrence of
    /// `t` in `goal` (up to conversion). Used by automation for rewriting.
    ///
    /// The result is the motive **body**: a term in `ctx` extended with one
    /// variable `y` (the format of `Transport`/`Match` motives), such that
    /// `motive[y := t] ≡ goal`.
    pub fn abstract_occurrences(&self, ctx: &Ctx, goal: &V, t: &V, b: &mut Budget) -> Result<Tm, KernelError> {
        let _guard = crate::util::StackGuard::enter();
        self.abstract_occurrences_ext(ctx, goal, t, false, b)
    }

    /// [`Env::abstract_occurrences`] with a choice for proofs: with
    /// `in_proofs = true` occurrences inside irrelevant closures (proof
    /// terms, e.g. the `refl(Bool, c)` path equation of the dependent-match
    /// idiom) are abstracted too, consistently with the relevant positions
    /// (generalization of every occurrence). Either way the result is a
    /// motive body with `motive[y := t] ≡ goal` (conversion ignores
    /// irrelevant positions); which choice keeps the motive well-typed
    /// depends on the proofs, and the caller checks it. Neutral heads and
    /// spine prefixes (stuck scrutinees) are abstracted in both modes.
    pub fn abstract_occurrences_ext(&self, ctx: &Ctx, goal: &V, t: &V, in_proofs: bool, b: &mut Budget) -> Result<Tm, KernelError> {
        let _guard = crate::util::StackGuard::enter();
        let _ = b;
        let depth = ctx.depth();
        let mut types = crate::check::cx_of_ctx(self, ctx).types();
        types.push(None);
        let mut q = crate::quote::Quoter::typed(self, types).abstracting(t.clone(), depth, in_proofs);
        let tm = q.q(Lvl(depth.0 + 1), goal, None);
        if q.failed {
            return Err(crate::check::kerr(
                KernelErrorKind::Eval(EvalError::OutOfFuel),
                "abstract_occurrences: conversion budget exhausted",
            ));
        }
        Ok(tm)
    }

    /// The linear system the kernel would build for a `Linarith` term; used by
    /// the (untrusted) certificate search so both sides agree on atoms and
    /// constraint order.
    pub fn linearize(&self, ctx: &Ctx, hyps: &[(Tm, Tm)], goal: &Tm, b: &mut Budget) -> Result<crate::linarith::LinSystem, KernelError> {
        let _guard = crate::util::StackGuard::enter();
        let cx = crate::check::cx_of_ctx(self, ctx);
        let chk = crate::check::Checker::new(self);
        let stated = hyps.iter().map(|(_, s)| chk.eval(&cx, s, b)).collect::<Result<Vec<_>, _>>()?;
        let gv = chk.eval(&cx, goal, b)?;
        crate::linarith::build(self, &cx, &stated, &gv, b)
    }
}

// ---------------------------------------------------------------------------
// Additive extensions (see INTERFACE_CHANGES.md).
// ---------------------------------------------------------------------------

impl Env {
    /// A fresh environment with the checked prelude (DESIGN.md §6) loaded
    /// from `sandblaster/kernel/prelude/*.core`. Panics only if the
    /// embedded prelude fails to check (a kernel bug; covered by tests).
    pub fn with_prelude() -> Env {
        match Env::try_with_prelude() {
            Ok(e) => e,
            Err(e) => panic!("the embedded sandblaster prelude failed to check: {e}"),
        }
    }

    /// Like [`Env::with_prelude`], returning the error instead of panicking.
    pub fn try_with_prelude() -> Result<Env, KernelError> {
        let _guard = crate::util::StackGuard::enter();
        crate::prelude::load()
    }

    /// Parse and check core text (DESIGN.md §5.12) declarations, adding each
    /// to the environment in order. Returns the names of the added items.
    pub fn load_core(&mut self, src: &str, b: &mut Budget) -> Result<Vec<Name>, KernelError> {
        let _guard = crate::util::StackGuard::enter();
        crate::syntax::load(self, src, b)
    }

    /// Parse a core text term in a context with the given variable names
    /// (level order: the last name is `Idx(0)`).
    pub fn parse_term(&self, names: &[&str], src: &str) -> Result<Tm, KernelError> {
        crate::syntax::parser::parse_term(self, names, src)
    }

    /// Print a term as core text in a context with the given variable names
    /// (level order).
    pub fn print_term(&self, names: &[Name], t: &Tm) -> String {
        crate::syntax::printer::print_term(self, names, t)
    }

    /// Print an inductive declaration as core text.
    pub fn print_inductive(&self, ind: IndId) -> Option<String> {
        crate::syntax::printer::print_inductive(self, ind)
    }

    /// Print a committed definition as core text (its body with `Rec` restored
    /// is not available; the stored body uses the global itself).
    pub fn print_def_decl(&self, d: &DefDecl) -> String {
        crate::syntax::printer::print_def(self, d)
    }

    /// The evaluation environment of a context: let values, and fresh
    /// variables (array-typed variables eta-expanded, DESIGN.md §5.9) for
    /// the other entries. Values built for conversion with the kernel must use
    /// this environment.
    pub fn ctx_venv(&self, ctx: &Ctx) -> VEnv {
        let _guard = crate::util::StackGuard::enter();
        crate::check::cx_of_ctx(self, ctx).venv
    }

    /// A fresh variable at level `depth` of type `ty` (eta-expanded for
    /// fixed-length array types).
    pub fn fresh_var(&self, depth: Lvl, rel: Rel, ty: &V) -> EnvEntry {
        let _guard = crate::util::StackGuard::enter();
        crate::eval::Ev::new(self).fresh(depth, rel, ty)
    }

    /// Quote with the types of the context variables, so pairs get their Σ
    /// types (`ty` is the expected type of `v`, if known).
    pub fn quote_typed(&self, ctx: &Ctx, v: &V, ty: Option<&V>, share: bool) -> Tm {
        let _guard = crate::util::StackGuard::enter();
        let types = crate::check::cx_of_ctx(self, ctx).types();
        crate::quote::Quoter::typed(self, types).quote_root(ctx.depth(), v, ty, share)
    }

    /// Look up a global by name (the most recent definition with that name).
    pub fn lookup_global(&self, name: &str) -> Option<GlobalId> {
        self.global_names.get(name).copied()
    }
    /// Look up an inductive by name.
    pub fn lookup_ind(&self, name: &str) -> Option<IndId> {
        self.ind_names.get(name).copied()
    }
    /// Look up a constructor by name (`None` if absent or ambiguous; use
    /// `Ind::Ctor` names to disambiguate).
    pub fn lookup_ctor(&self, name: &str) -> Option<(IndId, u32)> {
        if let Some((ind, c)) = name.rsplit_once("::")
            && let Some(i) = self.lookup_ind(ind)
        {
            let info = &self.inds[i.0 as usize];
            if let Some(k) = info.ctors.iter().position(|x| &*x.name == c) {
                return Some((i, k as u32));
            }
        }
        match self.ctor_names.get(name) {
            Some(v) if v.len() == 1 => Some(v[0]),
            _ => None,
        }
    }
    /// Name of a global.
    pub fn global_name(&self, g: GlobalId) -> Option<Name> {
        self.defs.get(g.0 as usize).map(|d| d.name.clone())
    }
    /// Type (as written) of a global.
    pub fn global_type(&self, g: GlobalId) -> Option<Tm> {
        self.defs.get(g.0 as usize).map(|d| d.ty.clone())
    }
    /// Body of a global as stored (its `Rec` calls replaced by the global).
    pub fn global_body(&self, g: GlobalId) -> Option<Tm> {
        self.defs.get(g.0 as usize).map(|d| d.body.clone())
    }
    /// Type value of a global.
    pub fn global_type_value(&self, g: GlobalId) -> Option<V> {
        self.defs.get(g.0 as usize).map(|d| d.ty_val.clone())
    }
    /// Arity of a global.
    pub fn global_arity(&self, g: GlobalId) -> Option<u32> {
        self.defs.get(g.0 as usize).map(|d| d.arity)
    }
    /// Kind of a global.
    pub fn global_kind(&self, g: GlobalId) -> Option<DefKind> {
        self.defs.get(g.0 as usize).map(|d| d.kind)
    }
    /// Is a global opaque (DESIGN.md §5.6)?
    pub fn global_opaque(&self, g: GlobalId) -> Option<bool> {
        self.defs.get(g.0 as usize).map(|d| d.opaque)
    }
    /// Relevance of a global's parameters.
    pub fn global_param_rels(&self, g: GlobalId) -> Option<Vec<Rel>> {
        self.defs.get(g.0 as usize).map(|d| d.param_rels.clone())
    }
    /// Number of committed globals.
    pub fn num_globals(&self) -> u32 {
        self.defs.len() as u32
    }
    /// The declaration of an inductive.
    pub fn inductive_decl(&self, ind: IndId) -> Option<InductiveDecl> {
        self.inds.get(ind.0 as usize).map(|i| InductiveDecl { name: i.name.clone(), params: i.params.clone(), ctors: i.ctors.clone() })
    }
    /// Is the inductive recursive (some direct recursive field)?
    pub fn inductive_is_recursive(&self, ind: IndId) -> Option<bool> {
        self.inds.get(ind.0 as usize).map(|i| i.recursive)
    }

    /// Relevance of the fields of a constructor.
    pub(crate) fn ctor_rels(&self, ind: IndId, ctor: u32) -> Option<Vec<Rel>> {
        self.inds.get(ind.0 as usize)?.ctors.get(ctor as usize).map(|c| c.fields.iter().map(|f| f.1).collect())
    }
}

// ---------------------------------------------------------------------------
// DESIGN.md §15 (additive, see INTERFACE_CHANGES.md and AUDIT.md §19–§20).
// ---------------------------------------------------------------------------

/// A hypothesis of a section (DESIGN.md §15.5): the statement (type) of a
/// lemma of the environment — a law, an `ensures` or refinement lemma —
/// with the section abstracted.
#[derive(Clone, Debug)]
pub struct SectionHyp {
    pub lemma: GlobalId,
    /// The abstracted statement with its proofs re-established by the caller
    /// (a term in the context of the members' `F'` binders and the earlier
    /// hypotheses). It must equal the kernel's abstraction of the lemma's
    /// type in every relevant position ([`Env::alpha_eq_relevant`]); only
    /// proofs may differ.
    pub restated: Option<Tm>,
}

/// An abstraction function for an output type (DESIGN.md §15.2):
/// `obs_eq` at every type convertible with `ty` is
/// `Eq(target, map a, map b)`. Closed terms; `map : ty -> target`,
/// `target : Type`.
#[derive(Clone, Debug)]
pub struct SectionView {
    pub ty: Tm,
    pub target: Tm,
    pub map: Tm,
}

/// The input of [`Env::abstract_section`].
#[derive(Clone, Copy, Debug)]
pub struct Section<'a> {
    /// `R`: the functions abstracted by the statements.
    pub members: &'a [GlobalId],
    /// `P(R) ⊆ R`: one statement each. Must include every member occurring
    /// in the requires of a published member (with a view-free `obs_eq`).
    pub published: &'a [GlobalId],
    /// `H(R)`, in binder order.
    pub hyps: &'a [SectionHyp],
    pub views: &'a [SectionView],
    /// The established functions (exec functions fully specified in earlier
    /// sections): `Refs*` does not descend into them.
    pub established: &'a [GlobalId],
}

/// The output of [`Env::abstract_section`].
#[derive(Clone, Debug)]
pub struct SectionStatements {
    /// `complete_p(R)` for each `p` of `published`, in that order: closed
    /// types (possibly `Kind`-sorted) with binders `F'` for `members`, then
    /// one per hypothesis, then `p`'s parameters.
    pub statements: Vec<Tm>,
    /// The members in binder order (by id).
    pub members: Vec<GlobalId>,
    /// `Refs*` of the abstracted parts and of the λ-lifted spec globals, not
    /// descending into `established` (listed when reached), without the
    /// members, by id: the caller computes `Deps(R)` from it and checks that
    /// the sections are well founded.
    pub deps: Vec<GlobalId>,
}

impl Env {
    /// `Refs*(t)` (DESIGN.md §15.1): the globals referenced from relevant
    /// positions of `t`, closed under the types and bodies of the globals
    /// (opaque ones included) and the declarations of the inductives it
    /// reaches, not descending into `stop` (whose members are listed when
    /// reached). Sorted by id.
    pub fn refs_closure(&self, t: &Tm, stop: &[GlobalId]) -> Vec<GlobalId> {
        let stop: crate::util::FxSet<GlobalId> = stop.iter().copied().collect();
        let nodes = crate::section::closure(self, &[t], &|g| stop.contains(&g));
        nodes.into_iter().filter_map(|n| if let crate::section::Node::G(g) = n { Some(g) } else { None }).collect()
    }

    /// The completeness statements `complete_p(R)` of a section (DESIGN.md
    /// §15.5), built entirely by the kernel from the members' types, the
    /// hypothesis lemmas' statements and the views; see AUDIT.md §19.
    pub fn abstract_section(&self, s: &Section<'_>, b: &mut Budget) -> Result<SectionStatements, KernelError> {
        let _guard = crate::util::StackGuard::enter();
        crate::section::abstract_section(self, s, b)
    }

    /// Evaluate a closed, well-typed term to first-order data (DESIGN.md
    /// §15.7), unfolding every definition including folded recursive
    /// applications; see AUDIT.md §20. Exhausting the budget is an error.
    pub fn eval_closed(&self, t: &Tm, b: &mut Budget) -> Result<Tm, KernelError> {
        let _guard = crate::util::StackGuard::enter();
        crate::closed::eval_closed(self, t, b)
    }
}
