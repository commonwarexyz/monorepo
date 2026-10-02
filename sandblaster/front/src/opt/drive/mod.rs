//! Σ1, the driver (optimizer design §6): an online partial evaluator on
//! the kernel's evaluator that turns a function stuck for the straight-line
//! route (tier 0) into a **process tree** ([`tree`]): a residual with
//! control flow, and the log of source-side steps its equality lemma is
//! built from (`opt::proof`).
//!
//! * [`config`]: budgets (steps and nodes only; design §17);
//! * [`step`]: value-level operations (heads, elimination, unfolding);
//! * [`facts`]: the facts of a path (linear facts as `auto` state binders,
//!   the decision cache, fact normalization);
//! * [`process`]: the driving loop (Unfold, Reuse, Prune, Split; merges in
//!   place);
//! * [`tree`]: the process tree;
//! * [`word`]: the `Word` step (static-length byte comparisons in word form).
//!
//! This module holds the entry point [`run`] and the crate's unfolding
//! policy ([`CratePolicy`]): the entry η of design §6.1 (fixed-length
//! arrays eta-expanded by the kernel; struct and tuple parameters are
//! projected by `match` arms that the residual prints as field accesses —
//! struct η is part of conversion, DESIGN.md §5.9), static-measure and
//! static-structure unrolling (§6.2), and inlining of small callees.

pub mod config;
pub mod facts;
pub mod process;
pub mod step;
pub mod tree;
pub mod word;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env};
use sandblaster_kernel::term::{DefKind, GlobalId, IndId, Lvl, Rel, Term};
use sandblaster_kernel::value::{Arg, Budget, EnvEntry, Head, Neutral, VEnv, Value};

use crate::auto::state::St;
use crate::auto::util::entry_arg;
use crate::hir::*;
pub use config::DriveConfig;
pub use process::{Policy, Unfold};
pub use tree::{Node, NodeKind, Step};

/// How a user recursive function's termination measure is found in its
/// arguments (the recursion is static when that argument is known).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Measure {
    /// An unsigned parameter (kernel argument index).
    Param(usize),
    /// The length of a slice parameter (kernel argument index).
    SliceLen(usize),
}

/// What a fold helper is built from (design §6.6, bound invariants): a
/// user recursion with a measure (a parameter or a slice parameter's
/// length), a `requires` conjunct `m <= N` bounding it by a literal, and
/// `u64` parameters (accumulators the invariant may bound).
#[derive(Clone, Debug)]
pub struct FoldShape {
    pub measure: Measure,
    /// The conjunct `m <= N` (a `bool` expression) and `N`.
    pub bound: Expr,
    pub n: u128,
    /// The `u64` parameters (kernel argument indices).
    pub accs: Vec<usize>,
}

/// The [`FoldShape`] of `f` (item `id`), if it has one.
pub fn fold_shape(id: ItemId, f: &FnDef) -> Option<FoldShape> {
    if !f.generics.is_empty() {
        return None;
    }
    let measure = measure_of(id, f)?;
    let m_param = match measure {
        Measure::Param(i) | Measure::SliceLen(i) => i,
    };
    let m_local = match &f.params.get(m_param)?.pat.kind {
        PatKind::Binding { local, sub: None, .. } => *local,
        _ => return None,
    };
    // `m <= N` among the `requires` (split at `&&`)
    fn conjuncts<'e>(e: &'e Expr, out: &mut Vec<&'e Expr>) {
        match &peel(e).kind {
            ExprKind::Binary(BinOp::And, a, b) | ExprKind::PropAnd(a, b) => {
                conjuncts(a, out);
                conjuncts(b, out);
            }
            _ => out.push(peel(e)),
        }
    }
    let mut cs = Vec::new();
    for r in &f.requires {
        conjuncts(r, &mut cs);
    }
    let is_measure = |e: &Expr| match (&measure, &peel(e).kind) {
        (Measure::Param(_), ExprKind::Local(l)) => *l == m_local,
        (Measure::SliceLen(_), ExprKind::Call { callee: Callee::Builtin(crate::builtins::Builtin::Slice(crate::builtins::SliceMethod::Len), _), args }) if args.len() == 1 => matches!(&peel(&args[0]).kind, ExprKind::Local(l) if *l == m_local),
        _ => false,
    };
    let (bound, n) = cs.iter().find_map(|c| match &c.kind {
        ExprKind::Binary(BinOp::Le, a, b) if is_measure(a) => match &peel(b).kind {
            ExprKind::Lit(Lit::Int(n)) => Some(((*c).clone(), *n)),
            _ => None,
        },
        _ => None,
    })?;
    let accs: Vec<usize> = f.params.iter().enumerate().filter(|(j, p)| *j != m_param && matches!(p.ty, Ty::Uint(UintTy::U64)) && matches!(p.pat.kind, PatKind::Binding { sub: None, .. })).map(|(j, _)| j).collect();
    if accs.is_empty() {
        return None;
    }
    Some(FoldShape { measure, bound, n, accs })
}

/// The value of `f`'s `#[decreases(e)]` at `args` when `e` is integer
/// arithmetic (`+ − ·`, literals) over parameters whose arguments are
/// literals.
fn static_measure(f: &FnDef, args: &[Arg]) -> Option<u32> {
    use num_traits::ToPrimitive;
    let d = f.decreases.as_ref()?;
    let ngen = f.generics.len();
    fn go(e: &Expr, f: &FnDef, args: &[Arg], ngen: usize) -> Option<i128> {
        match &peel(e).kind {
            ExprKind::Lit(Lit::Int(n)) => i128::try_from(*n).ok(),
            ExprKind::Local(l) => {
                let j = f.params.iter().position(|p| matches!(p.pat.kind, PatKind::Binding { local, sub: None, .. } if local == *l))?;
                step::as_lit(args.get(ngen + j).and_then(step::rel)?)?.to_i128()
            }
            ExprKind::Cast(x, _) => go(x, f, args, ngen),
            ExprKind::Binary(op, a, b) => {
                let (x, y) = (go(a, f, args, ngen)?, go(b, f, args, ngen)?);
                match op {
                    BinOp::Add => x.checked_add(y),
                    BinOp::Sub => x.checked_sub(y),
                    BinOp::Mul => x.checked_mul(y),
                    _ => None,
                }
            }
            _ => None,
        }
    }
    let v = go(&d.measure, f, args, ngen)?;
    u32::try_from(v).ok()
}

/// Peels coercions, references and dereferences.
fn peel(e: &Expr) -> &Expr {
    match &e.kind {
        ExprKind::Coerce(_, x) | ExprKind::Ref(x) | ExprKind::Deref(x) => peel(x),
        _ => e,
    }
}

/// The measure of a recursive user function: its `#[decreases(e)]` when
/// `e` is a parameter or a slice parameter's length, else the measure the
/// elaborator infers (DESIGN.md §4.2: a parameter decremented by a literal
/// at every recursive call, or a slice parameter recursed on its rest).
pub fn measure_of(id: ItemId, f: &FnDef) -> Option<Measure> {
    let ngen = f.generics.len();
    let param_of = |l: LocalId| f.params.iter().position(|p| matches!(p.pat.kind, PatKind::Binding { local, sub: None, .. } if local == l));
    if let Some(d) = &f.decreases {
        let m = peel(&d.measure);
        return match &m.kind {
            ExprKind::Local(l) => param_of(*l).map(|i| Measure::Param(ngen + i)),
            ExprKind::Call { callee: Callee::Builtin(crate::builtins::Builtin::Slice(crate::builtins::SliceMethod::Len), _), args } if args.len() == 1 => match &peel(&args[0]).kind {
                ExprKind::Local(l) => param_of(*l).map(|i| Measure::SliceLen(ngen + i)),
                _ => None,
            },
            _ => None,
        };
    }
    let FnBody::Exec(body) = &f.body else { return None };
    let mut calls: Vec<Vec<Expr>> = Vec::new();
    struct V<'x>(ItemId, &'x mut Vec<Vec<Expr>>);
    impl crate::visit::Visitor for V<'_> {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Call { callee: Callee::Item(c, _), args } = &e.kind
                && *c == self.0
            {
                self.1.push(args.clone());
            }
            crate::visit::walk_expr(self, e);
        }
    }
    crate::visit::Visitor::expr(&mut V(id, &mut calls), body);
    if calls.is_empty() {
        return None;
    }
    for (j, p) in f.params.iter().enumerate() {
        let PatKind::Binding { local, sub: None, .. } = &p.pat.kind else { continue };
        let uint = matches!(p.ty.peel_refs(), Ty::Uint(_));
        let slice = matches!(p.ty.peel_refs(), Ty::Slice(_));
        let ok = calls.iter().all(|args| match args.get(j).map(peel) {
            Some(a) if uint => matches!(&a.kind, ExprKind::Binary(BinOp::Sub, x, y) if matches!(&peel(x).kind, ExprKind::Local(l) if l == local) && matches!(&y.kind, ExprKind::Lit(Lit::Int(k)) if *k >= 1)),
            Some(a) if slice => matches!(&a.kind, ExprKind::Local(l) if l != local),
            _ => false,
        });
        if ok {
            return Some(if uint { Measure::Param(ngen + j) } else { Measure::SliceLen(ngen + j) });
        }
    }
    None
}

/// Nodes of a term in relevant positions (proofs erased).
pub fn relevant_size(t: &sandblaster_kernel::term::Tm, cap: usize) -> usize {
    crate::elab::tm::size_capped(&crate::roundtrip::strip(t), cap)
}

/// Prelude builtins the driver keeps folded that the residual printer
/// prints (`residual::tree`, `global_node`: `split_first_chunk` and
/// `first_chunk` as the slice methods, `bool::not` as `!b`, `bool::as_uN`
/// as `b as uN`).
pub const KEPT_PRINTED: &[&str] = &["slice::split_first_chunk", "slice::first_chunk", "bool::as_u8", "bool::as_u16", "bool::as_u32", "bool::as_u64", "bool::as_usize", "bool::not"];

/// Prelude builtins the driver keeps folded (their unfolded results have no
/// canonical printing either) that the residual printer has no printing
/// for: a residual keeping one is refused (`a stuck application`), so a
/// function whose driving would keep one is not driven
/// ([`Policy::unprintable_use`]).
pub const KEPT_UNPRINTED: &[&str] = &["slice::split_last_chunk", "slice::as_chunks"];

/// The buffer model of lifted code (`crate::__lift_model`, SEMANTICS.md
/// §19.1), kept folded: a residual keeps the host's buffer operations as
/// calls (`driver::lowered` lowers them back to `Buf`/`BufMut` calls)
/// instead of their sequence meaning, which has no host spelling. Only
/// lifted crates have these definitions.
pub const KEPT_LIFT_MODEL: &[&str] = &["crate::__lift_model::bufmut_put_u8", "crate::__lift_model::bufmut_put_slice", "crate::__lift_model::buf_try_get_u8", "crate::__lift_model::buf_remaining"];

/// Whether the driver unrolls a static user recursion `f` (item `id`) of
/// `trips` trips — into per-level helpers or in place (design §6.2, §6.5) —
/// rather than keep its loop: the **cost model's** decision. (Fairness audit
/// of 2026-10-02, J7: this was a fixed limit of 10 trips, the length of a
/// LEB128 `u64`, chosen on the corpus' varint decoder.)
///
/// Unrolling removes the loop's per-iteration bookkeeping — the measure's
/// test and update and the back edge, priced as the cost model prices a
/// loop iteration's overhead (one branch and one ALU operation, `Walker`'s
/// `Loop` arm) — and changes nothing else in an iteration. It pays on every
/// executed iteration alike, so the trip distribution (the profile's, or
/// the static count) cancels out of the comparison: unrolling pays when the
/// unrolled iterations clear the selection gate against the kept ones
/// (`cost::model::beats`, ≥ 3% cheaper; the body priced by the portable
/// tables of the crate's target, every table). Its price is code size: the
/// unrolled copies — `trips` times the body's HIR nodes — must fit the
/// residual budget of one driven function
/// ([`DriveConfig::max_residual_nodes`], which unrolled nodes count
/// against, design §6.2).
pub fn unroll_pays(krate: &Crate, id: ItemId, f: &FnDef, trips: u32, cfg: &DriveConfig) -> bool {
    let FnBody::Exec(body) = &f.body else { return false };
    if (trips as usize).saturating_mul(crate::opt::hir_nodes(body)) > cfg.max_residual_nodes {
        return false;
    }
    let tuning = crate::opt::cost::tuning::Tuning::shared();
    let model = crate::opt::cost::model::SetModel::portable(krate.target.arch.name(), &tuning);
    // one iteration: the body with its recursive call free (the call is the
    // back edge, which the overhead below prices)
    let per = model.fn_costs(krate, f, &|c| (c == id).then_some(0));
    !per.is_empty()
        && per.iter().zip(&model.tables).all(|((_, b), t)| {
            use crate::opt::cost::tables::Op;
            let overhead = t.op(Op::Branch).tp + t.op(Op::Alu).tp;
            let n = u64::from(trips);
            crate::opt::cost::model::beats(b.saturating_mul(n), (b + overhead).saturating_mul(n))
        })
}

/// The crate's unfolding policy for one driven function.
pub struct CratePolicy<'a> {
    pub env: &'a Env,
    pub krate: &'a Crate,
    pub cfg: &'a DriveConfig,
    /// The driven function.
    pub root: GlobalId,
    /// User exec functions by global.
    pub user: &'a HashMap<GlobalId, ItemId>,
    /// Callees unfolded wherever they occur (specialized callees below the
    /// inline threshold, as for tier 0) and small callees.
    pub inline: &'a HashSet<GlobalId>,
    pub list: Option<IndId>,
    /// The summaries of the functions optimized so far (design §6.4): a
    /// callee admitted through its equality lemma is instantiated or
    /// inlined through that link, or kept.
    pub summaries: Option<&'a crate::opt::summary::Summaries>,
    /// Prelude builtins kept folded (their unfolded results have no
    /// canonical printing, e.g. the array of `split_first_chunk`).
    pub keep: HashSet<GlobalId>,
    /// The kept builtins of [`KEPT_UNPRINTED`].
    unprinted: HashSet<GlobalId>,
    recursive: RefCell<HashMap<GlobalId, bool>>,
    small: RefCell<HashMap<GlobalId, bool>>,
    /// [`unroll_pays`] per user recursion and trip count.
    unroll: RefCell<HashMap<(GlobalId, u32), bool>>,
    /// Driving a polyvariant call-site specialization (design §6.5): a
    /// loop helper entered at a literal index is unrolled under the
    /// unroller's checkpoint (the constants usually decide every trip; a
    /// trip they do not decide outgrows the allowance and the loop is
    /// kept, which fails the specialization).
    pub spec_unroll: bool,
    /// Driving the fold helper of this recursion (design §6.6): its first
    /// application on a path is unfolded, a later tail call is the
    /// helper's back-edge ([`Unfold::FoldBack`]).
    pub fold_root: Option<GlobalId>,
    /// The checked arithmetic calls kept folded (`w::checked_add`,
    /// `w::checked_sub` with their lemmas loaded): a decided one is
    /// rewritten by its lemma (`Step::Checked`), an undecided one unfolded.
    checked: HashSet<GlobalId>,
    /// Fact-directed unfolding and guard specialization (plan O6,
    /// `opt::facts`, `opt::guardspec`) are on (the driven function's own
    /// policy); the callees whose driven residual failed (not unfolded:
    /// their guards are specialized instead).
    facts_on: bool,
    no_fact_unfold: HashSet<GlobalId>,
    /// Driving a Σ3 segment specialization of this function (design §8.2):
    /// its first application on a path is unfolded, later ones kept
    /// ([`Unfold::SegEntry`]).
    pub seg_root: Option<GlobalId>,
}

/// A callee larger than this (relevant body nodes) is not unfolded for its
/// facts.
pub const FACT_UNFOLD_NODES: usize = 4096;

impl<'a> CratePolicy<'a> {
    pub fn new(env: &'a Env, krate: &'a Crate, cfg: &'a DriveConfig, root: GlobalId, user: &'a HashMap<GlobalId, ItemId>, inline: &'a HashSet<GlobalId>) -> CratePolicy<'a> {
        // `bool::as_uN` and `bool::not` stay folded so the residual prints
        // `b as uN` and `!b` (the source's own forms: unfolded, the select
        // would print as an `if` — a dependent match, not convertible with
        // the source's — and a split on `!b` would become a split on `b`
        // with its arms swapped)
        let keep = KEPT_PRINTED.iter().chain(KEPT_UNPRINTED).chain(KEPT_LIFT_MODEL).filter_map(|n| env.lookup_global(n)).collect();
        let unprinted = KEPT_UNPRINTED.iter().filter_map(|n| env.lookup_global(n)).collect();
        let checked = ["u8", "u16", "u32", "u64", "usize"]
            .iter()
            .flat_map(|w| ["checked_add", "checked_sub"].map(|op| format!("{w}::{op}")))
            .filter(|n| env.lookup_global(&format!("{n}_some")).is_some() && env.lookup_global(&format!("{n}_none")).is_some())
            .filter_map(|n| env.lookup_global(&n))
            .collect();
        CratePolicy { env, krate, cfg, root, user, inline, list: env.lookup_ind("List"), summaries: None, keep, unprinted, recursive: RefCell::new(HashMap::new()), small: RefCell::new(HashMap::new()), unroll: RefCell::new(HashMap::new()), spec_unroll: false, fold_root: None, checked, facts_on: false, no_fact_unfold: HashSet::new(), seg_root: None }
    }

    /// The policy with fact-directed unfolding and guard specialization on
    /// (see [`CratePolicy::facts_on`]); `no_unfold`: callees whose driven
    /// residual failed.
    pub fn with_facts(mut self, no_unfold: HashSet<GlobalId>) -> CratePolicy<'a> {
        self.facts_on = true;
        self.no_fact_unfold = no_unfold;
        self
    }

    /// The policy of a Σ3 segment specialization of `f` (see
    /// [`CratePolicy::seg_root`]).
    pub fn with_seg_root(mut self, f: GlobalId) -> CratePolicy<'a> {
        self.seg_root = Some(f);
        self
    }

    /// The policy of a fold helper of the recursion `f` (see
    /// [`CratePolicy::fold_root`]).
    pub fn with_fold_root(mut self, f: GlobalId) -> CratePolicy<'a> {
        self.fold_root = Some(f);
        self
    }

    /// The policy of a polyvariant call-site specialization helper
    /// ([`CratePolicy::spec_unroll`]).
    pub fn with_spec_unroll(mut self, on: bool) -> CratePolicy<'a> {
        self.spec_unroll = on;
        self
    }

    /// The policy using the callee summaries `s` (design §6.4).
    pub fn with_summaries(mut self, s: &'a crate::opt::summary::Summaries) -> CratePolicy<'a> {
        self.summaries = Some(s);
        self
    }

    fn is_recursive(&self, g: GlobalId) -> bool {
        *self.recursive.borrow_mut().entry(g).or_insert_with(|| super::symex::is_recursive(self.env, g))
    }

    /// A callee small enough to unfold (relevant body nodes) and without
    /// loops (a loop helper's recursion is not unrolled by the driver).
    fn is_small(&self, g: GlobalId) -> bool {
        *self.small.borrow_mut().entry(g).or_insert_with(|| {
            let Some(b) = self.env.global_body(g) else { return false };
            if relevant_size(&b, self.cfg.inline_body_nodes + 1) > self.cfg.inline_body_nodes {
                return false;
            }
            let mut loops = false;
            crate::elab::tm::any_node(&b, &mut |n| {
                if let Term::Global(h) = n
                    && self.env.global_kind(*h) == Some(DefKind::LoopHelper)
                {
                    loops = true;
                }
                loops
            });
            !loops
        })
    }

    /// User callees unfolded wherever they occur: the specialized ones
    /// (by either route) below the inline threshold, as for tier 0 (an
    /// unspecialized callee stays a call: its body is stuck for a reason
    /// the caller cannot resolve either, e.g. buffers built from slices).
    fn inlines(&self, g: GlobalId) -> bool {
        self.inline.contains(&g) && !self.has_loop_helper(g)
    }

    /// Whether `g`'s body calls a loop helper (the driver does not unroll a
    /// loop helper, so such a callee stays a call).
    fn has_loop_helper(&self, g: GlobalId) -> bool {
        let Some(b) = self.env.global_body(g) else { return false };
        crate::elab::tm::any_node(&b, &mut |n| matches!(n, Term::Global(h) if self.env.global_kind(*h) == Some(DefKind::LoopHelper)))
    }

    /// Whether the user recursion `def` of `trips` trips is unrolled rather
    /// than kept ([`unroll_pays`]; memoized).
    fn unrolls(&self, def: GlobalId, trips: u32) -> bool {
        if let Some(b) = self.unroll.borrow().get(&(def, trips)) {
            return *b;
        }
        let b = self.user.get(&def).and_then(|id| self.krate.fn_def(*id).map(|f| unroll_pays(self.krate, *id, f, trips, self.cfg))).unwrap_or(false);
        self.unroll.borrow_mut().insert((def, trips), b);
        b
    }

    /// Static measure / structure of a recursive application (§6.2): the
    /// number of unfoldings to expect.
    fn is_static(&self, def: GlobalId, args: &[Arg]) -> Option<u32> {
        use num_traits::ToPrimitive;
        match self.user.get(&def).and_then(|id| self.krate.fn_def(*id).map(|f| (*id, f))) {
            Some((id, f)) => match measure_of(id, f) {
                Some(Measure::Param(i)) => args.get(i).and_then(step::rel).and_then(step::as_lit).and_then(|n| n.to_u32()),
                Some(Measure::SliceLen(i)) => match &**args.get(i).and_then(step::rel)? {
                    Value::Pair { fst, .. } => step::as_lit(fst).and_then(|n| n.to_u32()),
                    _ => None,
                },
                None => None,
            },
            None => {
                // prelude recursion (structural on lists): every list
                // argument is a closed spine
                let list = self.list?;
                let tele = super::symex::telescope(self.env, def)?;
                let mut trips: Option<u32> = None;
                for ((_, _, dom), a) in tele.binders.iter().zip(args) {
                    if matches!(&**dom, Term::Ind { ind, .. } if *ind == list) {
                        let v = step::rel(a)?;
                        let n = step::spine_len(v, list)? as u32;
                        trips = Some(trips.map_or(n, |t: u32| t.min(n)));
                    }
                }
                trips
            }
        }
    }
}

impl CratePolicy<'_> {
    /// The trip count Σ2 sees for a user loop (plan O6): the static measure
    /// ([`Self::is_static`]), or the value of a `#[decreases(e)]` whose
    /// parameters are literals here (`9 - n` at `n = 0`). Only Σ2 uses the
    /// latter: the unrolling and per-level helpers keep [`Self::is_static`].
    fn loop_trips(&self, def: GlobalId, args: &[Arg]) -> Option<u32> {
        // a generated loop helper entered at a literal index: at most
        // `MAX_K` trips (plan O6; its static simulation finds the count)
        if self.is_user_loop_helper(def) {
            return args.iter().find_map(step::rel).and_then(step::as_lit).map(|_| crate::opt::loopsum::classify::MAX_K);
        }
        self.is_static(def, args).or_else(|| {
            let f = self.krate.fn_def(*self.user.get(&def)?)?;
            static_measure(f, args)
        })
    }

    /// A loop helper (`f::loop#k`, DESIGN.md §7.4) of a user function `f`.
    pub fn is_user_loop_helper(&self, def: GlobalId) -> bool {
        crate::opt::loopsum::enclosing_fn(self.env, def).is_some_and(|f| self.user.contains_key(&f))
    }

    /// The specialization key of a static user recursion `def args`: its
    /// literal relevant arguments. Only when every `requires` of `def`
    /// mentions static parameters alone (the helper then has no
    /// precondition: the source's `requires` holds at the literals).
    fn spec_key(&self, def: GlobalId, args: &[Arg]) -> Option<tree::SpecKey> {
        let id = *self.user.get(&def)?;
        let f = self.krate.fn_def(id)?;
        if !f.generics.is_empty() || f.params.iter().any(|p| p.ghost || !matches!(p.pat.kind, PatKind::Binding { sub: None, .. })) {
            return None;
        }
        let mut statics = Vec::new();
        let mut static_locals = Vec::new();
        for (j, p) in f.params.iter().enumerate() {
            if let Some(Arg::Rel(v)) = args.get(j)
                && let Some(n) = step::as_lit(v)
            {
                statics.push((j, n));
                if let PatKind::Binding { local, .. } = &p.pat.kind {
                    static_locals.push(*local);
                }
            }
        }
        if statics.is_empty() || statics.len() == f.params.len() {
            return None;
        }
        // every local of the `requires` is a static parameter
        struct Locals(Vec<LocalId>);
        impl crate::visit::Visitor for Locals {
            fn expr(&mut self, e: &Expr) {
                if let ExprKind::Local(l) = &e.kind {
                    self.0.push(*l);
                }
                crate::visit::walk_expr(self, e);
            }
        }
        let mut ls = Locals(Vec::new());
        for r in &f.requires {
            crate::visit::Visitor::expr(&mut ls, r);
        }
        if f.decreases.as_ref().is_some_and(|d| d.max.is_some()) || ls.0.iter().any(|l| !static_locals.contains(l)) {
            return None;
        }
        Some(tree::SpecKey { def, statics })
    }
}

impl CratePolicy<'_> {
    /// Whether the value DAG `v` applies a user recursion whose measure or
    /// structure is static and that the driver unrolls ([`unroll_pays`],
    /// design §6.2): a straight-line (tier-0) residual that keeps such a
    /// call is driven too.
    pub fn applies_static_recursion(&self, v: &sandblaster_kernel::value::V) -> bool {
        use sandblaster_kernel::value::Elim;
        let mut seen: HashSet<*const Value> = HashSet::new();
        let mut stack = vec![v.clone()];
        while let Some(x) = stack.pop() {
            if !seen.insert(Rc::as_ptr(&x)) || seen.len() > 100_000 {
                continue;
            }
            match &*x {
                Value::Ctor { args, .. } => stack.extend(args.iter().filter_map(|a| step::rel(a).cloned())),
                Value::Pair { fst, snd } => {
                    stack.push(fst.clone());
                    stack.extend(step::rel(snd).cloned());
                }
                Value::Neu(n) => {
                    match &n.head {
                        Head::Global { def, args } => {
                            if self.user.contains_key(def) && self.is_recursive(*def) && self.is_static(*def, args).is_some_and(|t| self.unrolls(*def, t)) {
                                return true;
                            }
                            stack.extend(args.iter().filter_map(|a| step::rel(a).cloned()));
                        }
                        Head::Prim { args, .. } => stack.extend(args.iter().cloned()),
                        _ => {}
                    }
                    for e in &n.spine {
                        if let Elim::App(a) = e {
                            stack.extend(step::rel(a).cloned());
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Whether the value DAG `v` applies a user recursion that Σ2 may
    /// summarize (a literal measure of 2 to 64 trips, dynamic
    /// arguments; `loopsum::candidate`): a straight-line (tier-0) residual
    /// that keeps such a loop call is driven too (plan O6).
    pub fn applies_loop_summary(&self, v: &sandblaster_kernel::value::V) -> bool {
        use sandblaster_kernel::value::Elim;
        let mut seen: HashSet<*const Value> = HashSet::new();
        let mut stack = vec![v.clone()];
        while let Some(x) = stack.pop() {
            if !seen.insert(Rc::as_ptr(&x)) || seen.len() > 100_000 {
                continue;
            }
            match &*x {
                Value::Ctor { args, .. } => stack.extend(args.iter().filter_map(|a| step::rel(a).cloned())),
                Value::Pair { fst, snd } => {
                    stack.push(fst.clone());
                    stack.extend(step::rel(snd).cloned());
                }
                Value::Neu(n) => {
                    match &n.head {
                        Head::Global { def, args } => {
                            if (self.user.contains_key(def) || self.is_user_loop_helper(*def))
                                && self.is_recursive(*def)
                                && crate::opt::loopsum::candidate(self.env, true, self.loop_trips(*def, args), *def, args).is_some()
                            {
                                return true;
                            }
                            stack.extend(args.iter().filter_map(|a| step::rel(a).cloned()));
                        }
                        Head::Prim { args, .. } => stack.extend(args.iter().cloned()),
                        _ => {}
                    }
                    for e in &n.spine {
                        if let Elim::App(a) = e {
                            stack.extend(step::rel(a).cloned());
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// The transparent definitions this policy keeps folded: user functions
    /// neither recursive nor inlined, the kept builtins, and the root (the
    /// proof builder's head normalization leaves them to `Unfold` steps).
    pub fn folded_set(&self) -> HashSet<GlobalId> {
        let mut out: HashSet<GlobalId> = self.user.keys().copied().filter(|g| self.folded(*g)).collect();
        if let Some(m) = self.summaries {
            out.extend(m.helpers.keys().copied());
            out.extend(m.folds.values().map(|f| f.global));
        }
        out.extend(self.keep.iter().copied());
        out.extend(self.checked.iter().copied());
        out.insert(self.root);
        out
    }
}

impl Policy for CratePolicy<'_> {
    fn folded(&self, g: GlobalId) -> bool {
        if g == self.root {
            return true;
        }
        let kind = self.env.global_kind(g);
        if kind == Some(DefKind::Intrinsic) {
            return false;
        }
        if self.env.global_opaque(g) == Some(true) || self.keep.contains(&g) || self.checked.contains(&g) {
            return true;
        }
        // specialization helpers stay calls until the driver decides
        // (design §6.4); fold helpers stay calls
        if self.summaries.is_some_and(|m| m.helpers.contains_key(&g) || m.folds.values().any(|f| f.global == g)) {
            return true;
        }
        self.user.contains_key(&g) && !self.is_recursive(g) && !self.inlines(g)
    }

    /// The bodies the driver's evaluation enters unconditionally: the
    /// root's and, transitively, those of the user callees it inlines
    /// wherever they occur (non-recursive, [`Self::inlines`]). An
    /// application of a builtin of [`KEPT_UNPRINTED`] there stays in the
    /// residual (QMDB `graft__sha2`: its inlined `hash_64__sha2` calls
    /// `compress_sha2`, whose `as_chunks` stayed folded under 1.2M steps of
    /// symbolic SHA-2 rounds before the printer refused it). Syntactic, so
    /// conservative: an application in a branch the driver would prune
    /// also refuses the function.
    fn unprintable_use(&self, root: GlobalId) -> Option<(GlobalId, GlobalId)> {
        if self.unprinted.is_empty() {
            return None;
        }
        let mut seen: HashSet<GlobalId> = HashSet::new();
        let mut stack = vec![root];
        while let Some(f) = stack.pop() {
            if !seen.insert(f) {
                continue;
            }
            let Some(body) = self.env.global_body(f) else { continue };
            let mut found = None;
            crate::elab::tm::any_node(&body, &mut |n| {
                if let Term::Global(h) = n {
                    if self.unprinted.contains(h) {
                        found = Some(*h);
                        return true;
                    }
                    if *h != root && self.user.contains_key(h) && !self.is_recursive(*h) && self.inlines(*h) {
                        stack.push(*h);
                    }
                }
                false
            });
            if let Some(h) = found {
                return Some((f, h));
            }
        }
        None
    }

    fn leaf_specializations(&self, v: &sandblaster_kernel::value::V) -> Vec<(GlobalId, tree::SpecKey)> {
        self.specializable_calls(v, false)
    }

    fn fact_directed(&self, env: &Env, def: GlobalId, args: &[Arg], imported: &[u32]) -> Option<Unfold> {
        if !self.facts_on || !self.user.contains_key(&def) || def == self.root || self.is_recursive(def) || self.no_fact_unfold.contains(&def) {
            return None;
        }
        let rel: Vec<&sandblaster_kernel::value::V> = args.iter().filter_map(step::rel).collect();
        let fact_arg = rel.iter().any(|v| crate::opt::facts::is_fact_call(v));
        let about = rel.iter().any(|v| crate::opt::facts::mentions(v, imported));
        if !fact_arg && !about {
            return None;
        }
        if self.has_loop_helper(def) {
            return None;
        }
        let body = env.global_body(def)?;
        if relevant_size(&body, FACT_UNFOLD_NODES + 1) > FACT_UNFOLD_NODES {
            return None;
        }
        if let Some(s) = self.summaries.and_then(|m| m.get(def))
            && let crate::opt::summary::SumLink::Lemma(lemma) = s.link
        {
            return Some(Unfold::Link { res: s.residual, lemma });
        }
        Some(Unfold::Inline)
    }

    fn guard_candidate(&self, def: GlobalId) -> bool {
        self.facts_on && self.user.contains_key(&def) && def != self.root && !self.is_recursive(def) && self.no_fact_unfold.contains(&def)
    }

    fn seg_registry(&self) -> Option<&crate::opt::seqsum::drive::Registry> {
        self.summaries.map(|m| &m.seg)
    }

    fn seg_consumer(&self, g: GlobalId) -> bool {
        self.user.contains_key(&g) && g != self.root
    }

    fn seg_root(&self) -> Option<GlobalId> {
        self.seg_root
    }

    fn unfold(&self, _env: &Env, def: GlobalId, args: &[Arg], cont: Option<usize>, cont_globals: &[GlobalId]) -> Unfold {
        if self.seg_root == Some(def) {
            return Unfold::SegEntry;
        }
        // a continuation that itself calls a callee with several result
        // leaves (one that would be instantiated or inlined in turn): pushing
        // it into this callee's leaves multiplies the copies (the product of
        // the leaves of every call in the chain), so this call is inlined as
        // a value (a join point) or kept, and only the last call of such a
        // chain is instantiated
        let nested = cont_globals.iter().any(|g| self.expands(*g));
        if self.env.global_kind(def) == Some(DefKind::Intrinsic) || self.keep.contains(&def) {
            return Unfold::Keep;
        }
        if self.is_recursive(def) {
            if self.fold_root == Some(def) {
                return Unfold::FoldBack;
            }
            // a user loop with a literal trip count: its Σ2 summary (design
            // §7; plan O6: a closed form beats both the kept loop and the
            // unrolled chain of tests). A loop Σ2 cannot summarize is
            // recorded and, driven again, is kept (long), gets per-level
            // helpers (design §6.5) or is unrolled
            // (a generated loop helper inside a polyvariant specialization is
            // unrolled there, below: the helpers' trees are not summarized)
            if (self.user.contains_key(&def) || (self.is_user_loop_helper(def) && !self.spec_unroll))
                && self.summaries.is_some()
                && let Some(key) = crate::opt::loopsum::candidate(self.env, true, self.loop_trips(def, args), def, args)
            {
                return Unfold::LoopSum { key };
            }
            return match self.is_static(def, args) {
                // a user recursion whose unrolling does not pay stays a
                // call of its loop (the cost model, `unroll_pays`)
                Some(trips) if self.user.contains_key(&def) && !self.unrolls(def, trips) => Unfold::Keep,
                Some(trips) => match self.spec_key(def, args) {
                    // a user recursion: per-level helpers (design §6.5)
                    Some(key) => Unfold::Specialize { key },
                    None => Unfold::Unroll { trips },
                },
                // a loop entered at a literal index inside a polyvariant
                // specialization: unrolled under the checkpoint
                None if self.spec_unroll && self.env.global_kind(def) == Some(DefKind::LoopHelper) && args.iter().find_map(step::rel).and_then(step::as_lit).is_some() => {
                    Unfold::Unroll { trips: self.cfg.max_spec_trips }
                }
                // a recursion with a dynamic measure: its fold helper
                None if self.fold_candidate(def, args) => Unfold::FoldCall,
                None => Unfold::Keep,
            };
        }
        if self.user.contains_key(&def) {
            if self.inlines(def) {
                return Unfold::Inline;
            }
            // a callee admitted through its equality lemma: its summary at
            // the call site (design §6.4), never its source re-driven
            if let Some(s) = self.summaries.and_then(|m| m.get(def))
                && let crate::opt::summary::SumLink::Lemma(lemma) = s.link
                && def != self.root
            {
                use crate::opt::summary::CallForm;
                return match crate::opt::summary::call_form(&self.cfg.call_costs(), s.nodes, s.result_leaves, s.result_bytes, s.calls_user, cont, nested) {
                    CallForm::Instantiate => Unfold::Link { res: s.residual, lemma },
                    CallForm::Inline => Unfold::Bind { res: s.residual, lemma: Some(lemma) },
                    CallForm::Keep => Unfold::Keep,
                };
            }
            // a kept callee applied to literals: its polyvariant call-site
            // specialization (design §6.5), within the caps
            if let Some(key) = self.polyvariant(def, args) {
                return Unfold::Specialize { key };
            }
            return Unfold::Keep;
        }
        // a specialization helper of this crate (design §6.5): its body is
        // unfolded in place (instantiated), inlined as a value, or kept
        if let Some(h) = self.summaries.and_then(|m| m.helpers.get(&def)) {
            use crate::opt::summary::CallForm;
            return match crate::opt::summary::call_form(&self.cfg.call_costs(), h.nodes, h.result_leaves, h.result_bytes, h.calls_user, cont, nested) {
                CallForm::Instantiate => Unfold::Inline,
                CallForm::Inline => Unfold::Bind { res: def, lemma: None },
                CallForm::Keep => Unfold::Keep,
            };
        }
        // a folded non-recursive prelude definition (opaque): unfold small ones
        if self.is_small(def) { Unfold::Inline } else { Unfold::Keep }
    }
}

impl CratePolicy<'_> {
    /// Whether the call `def args` of a user recursion with a dynamic
    /// measure goes to `def`'s fold helper (design §6.6): `def` has the
    /// shape one is built for ([`fold_shape`]) and the call starts an
    /// accumulator at `0`, where the bound invariant holds; never for a
    /// recursion whose helper failed.
    fn fold_candidate(&self, def: GlobalId, args: &[Arg]) -> bool {
        let Some(m) = self.summaries else { return false };
        if m.fold_failed.contains(&def) || self.fold_root.is_some() {
            return false;
        }
        // (also with the helper built: at another call its bound invariant
        // may not hold, and the call's obligation would fail elaboration)
        let Some(id) = self.user.get(&def) else { return false };
        let Some(f) = self.krate.fn_def(*id) else { return false };
        let Some(shape) = fold_shape(*id, f) else { return false };
        shape.accs.iter().any(|j| args.get(*j).and_then(step::rel).and_then(step::as_lit).is_some_and(|n| n == sandblaster_kernel::term::BigInt::from(0)))
    }

    /// The polyvariant call-site specialization of a kept, non-recursive
    /// user callee `def args` (design §6.5): its literal arguments as the
    /// key ([`CratePolicy::spec_key`]: no `requires` over the others),
    /// unless the key failed before or the callee (8) or the crate (64) is
    /// at its cap.
    pub fn polyvariant(&self, def: GlobalId, args: &[Arg]) -> Option<tree::SpecKey> {
        let m = self.summaries?;
        if self.is_recursive(def) || def == self.root {
            return None;
        }
        let key = self.spec_key(def, args)?;
        if m.spec_failed.contains(&key) {
            return None;
        }
        if !m.spec_keys.contains(&key) && (m.spec_keys.iter().filter(|k| k.def == def).count() >= crate::opt::summary::MAX_SPECS_PER_CALLEE || m.spec_keys.len() >= crate::opt::summary::MAX_SPECS_PER_CRATE) {
            return None;
        }
        Some(key)
    }

    /// Whether the value DAG `v` (a straight-line residual) applies a user
    /// function it keeps to literals that a polyvariant specialization
    /// would take ([`CratePolicy::polyvariant`]): such a residual is driven.
    pub fn applies_specializable_call(&self, v: &sandblaster_kernel::value::V) -> bool {
        !self.specializable_calls(v, true).is_empty()
    }

    /// The polyvariant specializations of the kept user applications in the
    /// value DAG `v` (distinct keys; `first`: stop at the first).
    fn specializable_calls(&self, v: &sandblaster_kernel::value::V, first: bool) -> Vec<(GlobalId, tree::SpecKey)> {
        use sandblaster_kernel::value::Elim;
        let mut out: Vec<(GlobalId, tree::SpecKey)> = Vec::new();
        let mut seen: HashSet<*const Value> = HashSet::new();
        let mut stack = vec![v.clone()];
        while let Some(x) = stack.pop() {
            if !seen.insert(Rc::as_ptr(&x)) || seen.len() > 100_000 {
                continue;
            }
            match &*x {
                Value::Ctor { args, .. } => stack.extend(args.iter().filter_map(|a| step::rel(a).cloned())),
                Value::Pair { fst, snd } => {
                    stack.push(fst.clone());
                    stack.extend(step::rel(snd).cloned());
                }
                Value::Neu(n) => {
                    match &n.head {
                        Head::Global { def, args } => {
                            if self.user.contains_key(def)
                                && !self.inlines(*def)
                                && let Some(key) = self.polyvariant(*def, args)
                            {
                                if !out.iter().any(|(_, k)| *k == key) {
                                    out.push((*def, key));
                                }
                                if first {
                                    return out;
                                }
                            }
                            stack.extend(args.iter().filter_map(|a| step::rel(a).cloned()));
                        }
                        Head::Prim { args, .. } => stack.extend(args.iter().cloned()),
                        _ => {}
                    }
                    for e in &n.spine {
                        if let Elim::App(a) = e {
                            stack.extend(step::rel(a).cloned());
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// Whether a call of `g` would be expanded at a call site into several
    /// result leaves (a summarized user function or a helper small enough
    /// to be instantiated or inlined, with more than one leaf).
    fn expands(&self, g: GlobalId) -> bool {
        let Some(m) = self.summaries else { return false };
        let costs = self.cfg.call_costs();
        if let Some(s) = m.get(g) {
            return matches!(s.link, crate::opt::summary::SumLink::Lemma(_)) && s.expanded_leaves > 1 && s.nodes <= costs.max_inline_nodes && !s.calls_user;
        }
        m.helpers.get(&g).is_some_and(|h| h.result_leaves > 1 && h.nodes <= costs.max_inline_nodes && !h.calls_user)
    }
}

/// The context of a function's telescope (parameters and `requires`
/// binders, fresh; fixed-length arrays eta-expanded by the kernel) and the
/// folded application of the function to it.
pub fn root(env: &Env, g: GlobalId) -> Result<(St, sandblaster_kernel::value::V, u32), String> {
    let tele = super::symex::telescope(env, g).ok_or("not a definition with a parameter telescope")?;
    let mut b = Budget { steps: 10_000_000 };
    let mut entries: Vec<CtxEntry> = Vec::new();
    let mut venv: Vec<EnvEntry> = Vec::new();
    let mut nparams = 0u32;
    for (i, (name, rel, dom)) in tele.binders.iter().enumerate() {
        let env_now = VEnv(Rc::new(venv.clone()));
        let tv = env.eval(&env_now, Lvl(i as u32), dom, &mut b).map_err(|e| format!("the type of parameter `{name}`: {e:?}"))?;
        let entry = env.fresh_var(Lvl(i as u32), *rel, &tv);
        if *rel == Rel::Rel {
            nparams = i as u32 + 1;
        }
        entries.push(CtxEntry { name: name.clone(), rel: *rel, ty: tv, def: None });
        venv.push(entry);
    }
    let ctx = Ctx { entries: Rc::new(entries) };
    let mut st = St::new(env, &ctx, 0);
    facts::register_requires(&mut st, nparams);
    let args: Vec<Arg> = st.venv.0.iter().map(entry_arg).collect();
    let v = Rc::new(Value::Neu(Neutral { head: Head::Global { def: g, args }, spine: vec![] }));
    Ok((st, v, nparams))
}

/// `Err` when driving `g` would keep an application the residual cannot
/// print ([`Policy::unprintable_use`]).
fn refuse_unprintable(env: &Env, policy: &dyn Policy, g: GlobalId) -> Result<(), String> {
    match policy.unprintable_use(g) {
        Some((f, h)) => {
            let name = |x: GlobalId| env.global_name(x).map(|s| s.to_string()).unwrap_or_default();
            let at = if f == g { "its body".to_string() } else { format!("`{}`, which it inlines,", name(f)) };
            Err(format!("{at} applies `{}`, which a residual cannot print", name(h)))
        }
        None => Ok(()),
    }
}

/// The result of driving one function.
pub struct Driven {
    pub tree: Node,
    /// The root state (parameters and `requires` binders).
    pub root: St,
    /// Kernel steps used.
    pub steps: u64,
    /// Process-graph nodes.
    pub nodes: usize,
}

/// Drives `g` (see the module docs).
pub fn run(env: &Env, cfg: &DriveConfig, policy: &dyn Policy, g: GlobalId, fault: Option<crate::opt::DriveFault>) -> Result<Driven, String> {
    refuse_unprintable(env, policy, g)?;
    let (st, v, _) = root(env, g)?;
    let mut d = process::Driver::new(env, cfg, policy, g);
    d.fault = fault;
    if fault == Some(crate::opt::DriveFault::DeadlineTrip) {
        // a simulated safety-net stop (the test hooks only): a deadline
        // that has passed, hit through the meter as in a real run
        let _scope = crate::auto::meter::Scope::enter(Some(std::time::Duration::ZERO), &d.budget);
        let why = crate::auto::meter::check().map(crate::auto::meter::describe).unwrap_or_default();
        return Err(format!("the driver's search was stopped: {why}"));
    }
    let path = process::Path { st: st.clone(), facts: facts::Facts::default(), splits: 0, unrolls: 0, unrolled: Vec::new(), kept: Vec::new() };
    let tree = d.run(path, v)?;
    Ok(Driven { tree, root: st, steps: cfg.steps - d.budget.steps, nodes: d.nodes })
}

/// Drives the recursion `g` itself as a fold helper's probe (design §6.6):
/// its root application is the entry, so every recursive call in tail
/// position is a back-edge (`policy` has `g` as its fold root). The
/// back-edges' arguments show how the recursion's accumulators grow.
pub fn run_fold_probe(env: &Env, cfg: &DriveConfig, policy: &dyn Policy, g: GlobalId) -> Result<Driven, String> {
    refuse_unprintable(env, policy, g)?;
    let (st, v, _) = root(env, g)?;
    let mut d = process::Driver::new(env, cfg, policy, g);
    let path = process::Path { st: st.clone(), facts: facts::Facts::default(), splits: 0, unrolls: 0, unrolled: vec![g], kept: Vec::new() };
    let tree = d.run(path, v)?;
    Ok(Driven { tree, root: st, steps: cfg.steps - d.budget.steps, nodes: d.nodes })
}

/// The root of a specialization helper (design §6.5): the context of the
/// dynamic parameters of `key.def` (the static ones are the key's
/// literals), the folded application of `key.def` to the literals, the
/// dynamic parameters and proofs of its (closed) `requires`, and that
/// application as a term over the helper's telescope (the right side of the
/// helper's lemma).
pub fn spec_root(env: &Env, key: &tree::SpecKey) -> Result<(St, sandblaster_kernel::value::V, sandblaster_kernel::term::Tm), String> {
    use sandblaster_kernel::term::Tm;
    use sandblaster_kernel::util::mk;
    let g = key.def;
    let tele = super::symex::telescope(env, g).ok_or("not a definition with a parameter telescope")?;
    let mut b = Budget { steps: 20_000_000 };
    let mut st = St::new(env, &Ctx::default(), 0);
    let mut vals: Vec<EnvEntry> = Vec::new();
    // argument terms, each at the depth it was built (with that depth)
    let mut terms: Vec<(Tm, u32)> = Vec::new();
    let mut args: Vec<Arg> = Vec::new();
    for (i, (name, rel, dom)) in tele.binders.iter().enumerate() {
        let d = st.depth();
        let tv = env.eval(&VEnv(Rc::new(vals.clone())), Lvl(d), dom, &mut b).map_err(|e| format!("the type of parameter `{name}`: {e:?}"))?;
        match rel {
            Rel::Rel => {
                if let Some((_, n)) = key.statics.iter().find(|(j, _)| *j == i) {
                    let Value::IntTy(w) = &*tv else { return Err("a static argument of a non-integer type".into()) };
                    let lit = crate::auto::arith::lit_v(*w, n.clone());
                    vals.push(EnvEntry::Rel(lit.clone()));
                    args.push(Arg::Rel(lit));
                    terms.push((mk::lit(*w, n.clone()), d));
                } else {
                    let e = st.push_raw(env, name.clone(), Rel::Rel, tv);
                    args.push(entry_arg(&e));
                    vals.push(e);
                    terms.push((mk::var(0), d + 1));
                }
            }
            Rel::Irr => {
                // a `requires` over static parameters only: closed, proven here
                let cfg = crate::auto::AutoConfig { self_check: true, goal_timeout: Some(std::time::Duration::from_secs(60)), ..crate::auto::AutoConfig::default() };
                let mut db = crate::auto::lemmas::LemmaDb::default();
                db.refresh(env);
                let p = {
                    let _scope = crate::auto::meter::Scope::enter(Some(std::time::Duration::from_secs(60)), &b);
                    let mut e = crate::auto::search::Engine::new(env, &mut b, &cfg, &db, vec![], d);
                    match e.solve(&st, tv, true) {
                        Ok(Some(p)) => p,
                        _ => return Err(format!("the `requires` of `{}` at the static arguments is not proven", env.global_name(g).unwrap_or_default())),
                    }
                };
                let c = sandblaster_kernel::value::Closure { env: st.venv.clone(), body: p.clone() };
                vals.push(EnvEntry::Irr(c.clone()));
                args.push(Arg::Irr(c));
                terms.push((p, d));
            }
        }
    }
    let n = st.depth();
    // the application over the helper's telescope: shift each argument term
    // from the depth it was built at
    let app_args: Vec<(Rel, Tm)> = tele.binders.iter().zip(&terms).map(|((_, rel, _), (t, d))| (*rel, crate::auto::util::shift(t, (n - d) as i64))).collect();
    let app = mk::apps(mk::global(g), app_args);
    let v = Rc::new(Value::Neu(Neutral { head: Head::Global { def: g, args }, spine: vec![] }));
    Ok((st, v, app))
}

/// Drives a specialization helper from [`spec_root`].
pub fn run_spec(env: &Env, cfg: &DriveConfig, policy: &dyn Policy, key: &tree::SpecKey) -> Result<(Driven, sandblaster_kernel::term::Tm), String> {
    refuse_unprintable(env, policy, key.def)?;
    let (st, v, app) = spec_root(env, key)?;
    let mut d = process::Driver::new(env, cfg, policy, key.def);
    let path = process::Path { st: st.clone(), facts: facts::Facts::default(), splits: 0, unrolls: 0, unrolled: Vec::new(), kept: Vec::new() };
    let tree = d.run(path, v)?;
    Ok((Driven { tree, root: st, steps: cfg.steps - d.budget.steps, nodes: d.nodes }, app))
}
