//! Bidirectional type checking (DESIGN.md §5.2–§5.6, §5.8, §5.10).
//!
//! * Sorts and formation (§5.2): `Type : Kind`, `Kind` has no type; Π has
//!   sort `max(s1, s2)` (a codomain `Kind` is impossible since `Kind` has no
//!   type); Σ components and `Eq`'s type must be `: Type`; transport motives
//!   must be `: Type`; match motives may have any sort (large elimination).
//! * Relevance (§5.3): the checker carries a [`Mode`] `irr`: relevant, or
//!   irrelevant *with the context depth at which the innermost irrelevant
//!   position was entered* (Pfenning/Agda resurrection; red-team R1). An
//!   irrelevant position is entered exactly at: `Irr` application
//!   arguments, prim proof slots, `Rec.proof`, the second component of a
//!   pair whose Σ is `Irr`, the value of an `Irr` let, `Transport.eq`,
//!   `Absurd.proof`, `Irr` constructor fields (and `Irr` parameters of
//!   `Rec`/`Delta`/`Unfold`/axioms, which are applications). Type positions
//!   never switch mode. An `Irr` variable is usable only in an irrelevant
//!   position entered *after* it was bound (its level is below the entry
//!   depth): `Irr` binders, lets and match fields introduced inside an
//!   irrelevant position stay irrelevant there. `snd` of an `Irr` Σ is
//!   rejected in relevant positions, and in irrelevant ones when the pair
//!   mentions a variable bound inside the position. The type of an `Irr` Σ
//!   component (and of an `Irr` constructor field, `inductive.rs`) must be
//!   a proposition ([`Checker::is_prop`]). An application's annotation must
//!   equal the relevance of the function's Π.
//! * `Rec` is only accepted inside the body of the definition being added
//!   (`in_body`), with a full argument list; measure recursion checks the
//!   decrease proof against the §5.6 obligation in the call-site context.
//! * `BvRefl` is decided by [`crate::bvnorm`] (conversion, then the word
//!   normalizer and its tripwire, §9.8).
//! * The value of a relevant application argument (constructor field, match
//!   scrutinee) is computed only when the Π codomain (later field type,
//!   match motive) mentions it: a non-dependent type never reads it, so
//!   checking a definition does not evaluate the computation it describes.
//! * `Linarith` (§5.8, phase 3, see [`Checker::infer_linarith`]): a stated
//!   hypothesis is justified by its (well-typed) proof or by a context
//!   assumption of that type usable in the current relevance mode; the
//!   certificate is a hint — if it does not verify, the kernel's search
//!   (`lincert`, untrusted) looks for one for the same system and then for
//!   the system extended with the context's hypotheses, and the result goes
//!   through the same exact check.
//! * Term DAGs: inferred types of shared nodes are memoized per context and
//!   mode, and evaluation in checking contexts shares one `EvalMemo` (see
//!   [`Checker`]).
//! * Diagnostics render values with bounded quoting and printing, so an
//!   error about a large value DAG never unfolds it into a tree.
//! * `Erased` is rejected everywhere, except in irrelevant positions when the
//!   checker runs for `check_residual_equal` (`allow_erased`), and never as
//!   `Absurd.proof`.

use std::rc::Rc;

use crate::api::{Ctx, CtxEntry, Env, KernelError, KernelErrorKind as K};
use crate::conv::Conv;
use crate::eval::{Ev, EvalMemo};
use crate::linarith;
use crate::prim::{self, PrimTy};
use crate::term::{GlobalId, Idx, Lvl, Name, Recursion, Rel, Sort, Term, Tm, Width};
use crate::util::{entry_arg, mk, tick, venv_push};
use crate::value::{Budget, Closure, EnvEntry, EvalError, V, VEnv, Value};

pub(crate) type KR<T> = Result<T, KernelError>;

/// Relevance mode of the checker (DESIGN.md §5.3; red-team R1): `None` in a
/// relevant position; `Some(d)` inside an irrelevant position whose innermost
/// entry was at context depth `d`. There, the `Irr` variables bound at levels
/// `< d` — outside the position — are usable (they are *resurrected*, as in
/// Pfenning's and Agda's irrelevance), while `Irr` binders, lets and match
/// fields introduced inside keep their status: they are usable only in a
/// nested irrelevant position, which resurrects again. Contexts only grow
/// along a check, so a nested position always has `d' ≥ d`.
pub(crate) type Mode = Option<u32>;

/// A relevant position.
pub(crate) const REL: Mode = None;

/// The mode of an irrelevant position entered in `cx`.
#[inline]
fn irr_at(cx: &Cx) -> Mode {
    Some(cx.depth().0)
}

/// The mode of a sub-position of relevance `rel` entered in `cx`.
#[inline]
fn sub_mode(cx: &Cx, rel: Rel, irr: Mode) -> Mode {
    if rel == Rel::Irr { irr_at(cx) } else { irr }
}

/// May an `Irr` context entry at level `lvl` be used in mode `irr`?
#[inline]
fn usable(irr: Mode, lvl: usize) -> bool {
    matches!(irr, Some(d) if lvl < d as usize)
}

/// Does `t` (a term in a context of depth `depth`) mention a variable bound
/// at a level `≥ d`, i.e. inside the irrelevant position entered at `d`?
fn mentions_inner(t: &Tm, depth: u32, d: u32) -> bool {
    let inner = depth.saturating_sub(d);
    if inner == 0 {
        return false;
    }
    if let Term::Var(crate::term::Idx(i)) = &**t {
        return *i < inner;
    }
    crate::util::any_sub(t, 0, &mut |n, k| matches!(&**n, Term::Var(crate::term::Idx(i)) if *i >= k && *i - k < inner))
}

/// Nesting bound of [`Checker::is_prop`] (it answers "no" beyond it).
pub(crate) const PROP_DEPTH: u32 = 32;

/// Context hypotheses offered to the `linarith` fallback search.
pub(crate) const MAX_CONTEXT_FACTS: usize = 64;

/// Node budget of a value rendered in a diagnostic.
pub(crate) const DIAG_NODES: u64 = 400;

pub(crate) fn kerr(kind: K, msg: impl Into<String>) -> KernelError {
    KernelError { kind, message: msg.into() }
}

impl From<EvalError> for KernelError {
    fn from(e: EvalError) -> Self {
        let msg = match e {
            EvalError::OutOfFuel => "evaluation budget exhausted",
            EvalError::IntOverflow => "Int arithmetic exceeded the implementation limit",
        };
        kerr(K::Eval(e), msg)
    }
}

/// A checking context: the typing context and the evaluation environment of
/// its variables (fresh variables or let values).
#[derive(Clone, Default)]
pub(crate) struct Cx {
    pub ctx: Ctx,
    pub venv: VEnv,
}

impl Cx {
    pub fn depth(&self) -> Lvl {
        self.ctx.depth()
    }

    /// Types of the context variables by level (for typed quoting).
    pub fn types(&self) -> Vec<Option<V>> {
        self.ctx.entries.iter().map(|e| Some(e.ty.clone())).collect()
    }

    pub fn names(&self) -> Vec<Name> {
        self.ctx.entries.iter().map(|e| e.name.clone()).collect()
    }

    fn push(&self, name: &Name, rel: Rel, ty: V, e: EnvEntry, def: bool) -> Cx {
        let def = if def { Some(entry_arg(&e)) } else { None };
        Cx { ctx: self.ctx.push(CtxEntry { name: name.clone(), rel, ty, def }), venv: venv_push(&self.venv, e) }
    }
}

/// Build a checking context from a public [`Ctx`] (fresh variables for
/// entries without a definition; array-typed variables eta-expanded).
pub(crate) fn cx_of_ctx(env: &Env, ctx: &Ctx) -> Cx {
    let mut ev = Ev::new(env);
    let mut entries = Vec::with_capacity(ctx.entries.len());
    for (l, e) in ctx.entries.iter().enumerate() {
        entries.push(match &e.def {
            Some(a) => crate::util::arg_entry(a),
            None => ev.fresh(Lvl(l as u32), e.rel, &e.ty),
        });
    }
    Cx { ctx: ctx.clone(), venv: VEnv(Rc::new(entries)) }
}

/// The checker. `in_body` enables `Rec` (the body of the pending
/// definition); `allow_erased` is only set by `check_residual_equal`.
///
/// **Shared term graphs.** Terms reaching the kernel are often DAGs (read
/// back from symbolic values, or built by substitution): a node shared by
/// many parents must not be checked or evaluated once per path. The checker
/// memoizes (for its lifetime, one API call) the inferred type of every
/// shared node (`Rc::strong_count > 1`) per checking context and relevance
/// mode, and evaluates terms in a context's environment through one shared
/// [`EvalMemo`]. Keys are addresses of the term, the context entries and
/// the environment; the memo keeps all of them alive (no address reuse).
/// Inference is a function of those three and the mode flags, so a memo hit
/// returns exactly what re-checking would (errors are never memoized: an
/// error aborts the whole check).
pub(crate) struct Checker<'e> {
    pub env: &'e Env,
    pub allow_erased: bool,
    pub in_body: bool,
    infer_memo: std::cell::RefCell<InferMemo>,
    ev_memo: Rc<std::cell::RefCell<EvalMemo>>,
}

#[derive(Default)]
struct InferMemo {
    map: crate::util::FxMap<(usize, usize, usize, u32), V>,
    keep: Vec<(Tm, Cx)>,
}

fn addr_of<T>(r: &Rc<T>) -> usize {
    Rc::as_ptr(r) as *const () as usize
}

impl<'e> Checker<'e> {
    pub fn new(env: &'e Env) -> Self {
        Checker::with_flags(env, false, false)
    }

    pub fn with_flags(env: &'e Env, allow_erased: bool, in_body: bool) -> Self {
        Checker { env, allow_erased, in_body, infer_memo: Default::default(), ev_memo: Default::default() }
    }

    pub fn eval(&self, cx: &Cx, t: &Tm, b: &mut Budget) -> KR<V> {
        Ok(Ev::new(self.env).with_memo(self.ev_memo.clone(), &cx.venv).eval(&cx.venv, cx.depth(), t, b)?)
    }

    fn eval_in(&self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> KR<V> {
        Ok(Ev::new(self.env).eval(env, depth, t, b)?)
    }

    fn inst(&self, c: &Closure, e: EnvEntry, depth: Lvl, b: &mut Budget) -> KR<V> {
        Ok(Ev::new(self.env).sharing(self.ev_memo.clone()).inst_root(c, e, depth, b)?)
    }

    pub fn conv(&self, cx: &Cx, a: &V, v: &V, b: &mut Budget) -> KR<bool> {
        Ok(Conv::new(self.env).conv(cx.depth(), a, v, b)?)
    }

    /// Evaluate an argument of the given relevance into an entry.
    fn entry(&self, cx: &Cx, rel: Rel, t: &Tm, b: &mut Budget) -> KR<EnvEntry> {
        Ok(match rel {
            Rel::Rel => EnvEntry::Rel(self.eval(cx, t, b)?),
            Rel::Irr => EnvEntry::Irr(Closure { env: cx.venv.clone(), body: t.clone() }),
        })
    }

    /// Extend the context with a fresh variable.
    pub fn bind(&self, cx: &Cx, name: &Name, rel: Rel, ty: &V) -> (Cx, EnvEntry) {
        let e = Ev::new(self.env).fresh(cx.depth(), rel, ty);
        (cx.push(name, rel, ty.clone(), e.clone(), false), e)
    }

    /// Extend the context with a let-bound entry.
    fn define(&self, cx: &Cx, name: &Name, rel: Rel, ty: V, e: EnvEntry) -> Cx {
        cx.push(name, rel, ty, e, true)
    }

    /// Render a value for diagnostics (size-bounded: large value DAGs are
    /// elided rather than unfolded into trees).
    pub fn show(&self, cx: &Cx, v: &V) -> String {
        let t = crate::quote::Quoter::bounded(self.env, cx.types(), DIAG_NODES).quote_root(cx.depth(), v, None, false);
        crate::syntax::printer::print_term_bounded(self.env, &cx.names(), &t, 2000)
    }

    /// Render a linear system (atoms and constraints in canonical order).
    pub fn show_system(&self, cx: &Cx, sys: &linarith::LinSystem) -> String {
        let mut out = String::new();
        for (i, a) in sys.atoms.iter().enumerate() {
            out.push_str(&format!("  a{i} = {}\n", truncate(self.show_tm(cx, a))));
        }
        for (pi, p) in sys.problems.iter().enumerate() {
            out.push_str(&format!("  problem {pi}:\n"));
            for (ci, c) in p.iter().enumerate() {
                let mut e = String::new();
                for (a, k) in &c.coeffs {
                    e.push_str(&format!("{k}*a{a} + "));
                }
                let rel = if c.kind == linarith::ConstraintKind::Le0 { "<=" } else { "=" };
                out.push_str(&format!("    [{ci}] {e}{} {rel} 0   ({:?})\n", c.constant, c.origin));
            }
        }
        out
    }

    fn show_tm(&self, cx: &Cx, t: &Tm) -> String {
        crate::syntax::printer::print_term_bounded(self.env, &cx.names(), t, 2000)
    }

    fn mismatch(&self, cx: &Cx, t: &Tm, expected: &V, got: &V) -> KernelError {
        kerr(
            K::TypeMismatch,
            format!(
                "type mismatch for `{}`: expected `{}`, found `{}`",
                truncate(self.show_tm(cx, t)),
                truncate(self.show(cx, expected)),
                truncate(self.show(cx, got))
            ),
        )
    }

    /// Infer the sort of a type.
    pub fn infer_sort(&self, cx: &Cx, t: &Tm, irr: Mode, b: &mut Budget) -> KR<Sort> {
        let ty = self.infer(cx, t, irr, b)?;
        match &*ty {
            Value::Sort(s) => Ok(*s),
            _ => Err(kerr(K::NotAType, format!("`{}` is not a type", truncate(self.show_tm(cx, t))))),
        }
    }

    /// Check that `t` is a type of sort exactly `want`.
    fn sort_is(&self, cx: &Cx, t: &Tm, irr: Mode, want: Sort, what: &str, b: &mut Budget) -> KR<()> {
        let s = self.infer_sort(cx, t, irr, b)?;
        if s != want {
            return Err(kerr(K::IllFormed, format!("{what} must have sort {want:?}, found {s:?}")));
        }
        Ok(())
    }

    fn bool_ty(&self) -> V {
        Rc::new(Value::Ind { ind: self.env.bool_id, params: vec![] })
    }

    /// Check `t : ty`.
    pub fn check(&self, cx: &Cx, t: &Tm, ty: &V, irr: Mode, b: &mut Budget) -> KR<()> {
        tick(b)?;
        match &**t {
            Term::Lam { name, rel, dom, body } => {
                let Value::Pi { rel: prel, dom: pdom, cod, .. } = &**ty else {
                    return Err(kerr(
                        K::TypeMismatch,
                        format!("λ checked against the non-function type `{}`", truncate(self.show(cx, ty))),
                    ));
                };
                if rel != prel {
                    return Err(kerr(K::Relevance, format!("λ binder `{name}` relevance does not match its Π type")));
                }
                self.infer_sort(cx, dom, irr, b)?;
                let dv = self.eval(cx, dom, b)?;
                if !self.conv(cx, &dv, pdom, b)? {
                    return Err(self.mismatch(cx, dom, pdom, &dv));
                }
                let (cx2, x) = self.bind(cx, name, *rel, pdom);
                let ct = self.inst(cod, x, cx2.depth(), b)?;
                self.check(&cx2, body, &ct, irr, b)
            }
            Term::Let { name, rel, ty: lty, val, body } => {
                let cx2 = self.check_let(cx, name, *rel, lty, val, irr, b)?;
                self.check(&cx2, body, ty, irr, b)
            }
            Term::Erased => {
                if self.allow_erased && irr.is_some() {
                    Ok(())
                } else {
                    Err(kerr(K::Erased, "`Erased` placeholder in a checked term"))
                }
            }
            _ => {
                let got = self.infer(cx, t, irr, b)?;
                if self.conv(cx, &got, ty, b)? { Ok(()) } else { Err(self.mismatch(cx, t, ty, &got)) }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn check_let(&self, cx: &Cx, name: &Name, rel: Rel, lty: &Tm, val: &Tm, irr: Mode, b: &mut Budget) -> KR<Cx> {
        self.infer_sort(cx, lty, irr, b)?;
        let tv = self.eval(cx, lty, b)?;
        self.check(cx, val, &tv, sub_mode(cx, rel, irr), b)?;
        let e = self.entry(cx, rel, val, b)?;
        Ok(self.define(cx, name, rel, tv, e))
    }

    /// Check the parameters of an inductive; returns their values.
    fn check_params(&self, cx: &Cx, ind: crate::term::IndId, params: &[Tm], irr: Mode, b: &mut Budget) -> KR<Vec<V>> {
        let info = self.env.inds.get(ind.0 as usize).ok_or_else(|| kerr(K::IllFormed, format!("unknown inductive {ind:?}")))?;
        if params.len() != info.params.len() {
            return Err(kerr(K::IllFormed, format!("`{}` expects {} parameters, got {}", info.name, info.params.len(), params.len())));
        }
        let mut penv: Vec<EnvEntry> = Vec::with_capacity(params.len());
        let mut vals = Vec::with_capacity(params.len());
        for (p, (_, pty)) in params.iter().zip(&info.params) {
            let ptv = self.eval_in(&VEnv(Rc::new(penv.clone())), cx.depth(), pty, b)?;
            self.check(cx, p, &ptv, irr, b)?;
            let pv = self.eval(cx, p, b)?;
            penv.push(EnvEntry::Rel(pv.clone()));
            vals.push(pv);
        }
        Ok(vals)
    }

    /// Check arguments against a Π telescope value; returns the entries and
    /// the remaining type.
    /// The environment entry for the argument of a Π type with codomain
    /// `cod`. A relevant argument is evaluated only if the codomain mentions
    /// the bound variable: type checking an application needs the argument's
    /// value only to instantiate a dependent codomain (a non-dependent one
    /// never reads the entry, so a placeholder is equivalent), which keeps
    /// checking a definition from evaluating the computations it describes.
    fn dependent_entry(&self, cx: &Cx, rel: Rel, arg: &Tm, cod: &Closure, b: &mut Budget) -> KR<EnvEntry> {
        if rel == Rel::Rel && !crate::util::occurs(&cod.body, 0) {
            return Ok(EnvEntry::Rel(crate::eval::garbage()));
        }
        self.entry(cx, rel, arg, b)
    }

    fn check_telescope(&self, cx: &Cx, mut ty: V, args: &[Tm], irr: Mode, what: &str, b: &mut Budget) -> KR<(Vec<EnvEntry>, V)> {
        let mut es = Vec::with_capacity(args.len());
        for a in args {
            let Value::Pi { rel, dom, cod, .. } = &*ty.clone() else {
                return Err(kerr(K::IllFormed, format!("too many arguments for {what}")));
            };
            self.check(cx, a, dom, sub_mode(cx, *rel, irr), b)?;
            let e = self.entry(cx, *rel, a, b)?;
            ty = self.inst(cod, e.clone(), cx.depth(), b)?;
            es.push(e);
        }
        Ok((es, ty))
    }

    /// Infer the type of `t` (memoized for shared nodes, see [`Checker`]).
    pub fn infer(&self, cx: &Cx, t: &Tm, irr: Mode, b: &mut Budget) -> KR<V> {
        if Rc::strong_count(t) > 1 && !matches!(&**t, Term::Var(_) | Term::Global(_) | Term::Sort(_) | Term::IntTy(_) | Term::Lit { .. }) {
            let key = (addr_of(t), addr_of(&cx.ctx.entries), addr_of(&cx.venv.0), irr.unwrap_or(u32::MAX));
            if let Some(v) = self.infer_memo.borrow().map.get(&key) {
                tick(b)?;
                return Ok(v.clone());
            }
            let v = self.infer_node(cx, t, irr, b)?;
            let mut m = self.infer_memo.borrow_mut();
            m.map.insert(key, v.clone());
            m.keep.push((t.clone(), cx.clone()));
            return Ok(v);
        }
        self.infer_node(cx, t, irr, b)
    }

    fn infer_node(&self, cx: &Cx, t: &Tm, irr: Mode, b: &mut Budget) -> KR<V> {
        tick(b)?;
        match &**t {
            Term::Var(Idx(i)) => {
                let n = cx.ctx.entries.len();
                let i = *i as usize;
                if i >= n {
                    return Err(kerr(K::IllFormed, format!("unbound variable index {i}")));
                }
                let e = &cx.ctx.entries[n - 1 - i];
                if e.rel == Rel::Irr && !usable(irr, n - 1 - i) {
                    return Err(kerr(
                        K::Relevance,
                        match irr {
                            None => format!("irrelevant variable `{}` used in a relevant position", e.name),
                            Some(_) => format!(
                                "irrelevant variable `{}` used relevantly inside the irrelevant position that binds it (only variables bound \
                                 outside an irrelevant position are usable there)",
                                e.name
                            ),
                        },
                    ));
                }
                Ok(e.ty.clone())
            }
            Term::Global(g) => self.global_type(*g),
            Term::Sort(Sort::Type) => Ok(Rc::new(Value::Sort(Sort::Kind))),
            Term::Sort(Sort::Kind) => Err(kerr(K::IllFormed, "`Kind` has no type and may only appear as the type of a type")),
            Term::Pi { name, rel, dom, cod } => {
                let s1 = self.infer_sort(cx, dom, irr, b)?;
                let dv = self.eval(cx, dom, b)?;
                let (cx2, _) = self.bind(cx, name, *rel, &dv);
                let s2 = self.infer_sort(&cx2, cod, irr, b)?;
                let s = if s1 == Sort::Kind || s2 == Sort::Kind { Sort::Kind } else { Sort::Type };
                Ok(Rc::new(Value::Sort(s)))
            }
            Term::Lam { name, rel, dom, body } => {
                self.infer_sort(cx, dom, irr, b)?;
                let dv = self.eval(cx, dom, b)?;
                let (cx2, _) = self.bind(cx, name, *rel, &dv);
                let bt = self.infer(&cx2, body, irr, b)?;
                // Shared read-back: the body type may contain a large value
                // DAG (e.g. an equation between symbolic hashes).
                let bt_tm = crate::quote::Quoter::typed(self.env, cx2.types()).quote_root(cx2.depth(), &bt, None, true);
                Ok(Rc::new(Value::Pi { name: name.clone(), rel: *rel, dom: dv, cod: Closure { env: cx.venv.clone(), body: bt_tm } }))
            }
            Term::App { rel, fun, arg } => {
                let ft = self.infer(cx, fun, irr, b)?;
                let Value::Pi { rel: prel, dom, cod, .. } = &*ft else {
                    return Err(kerr(K::TypeMismatch, format!("`{}` is not a function", truncate(self.show_tm(cx, fun)))));
                };
                if rel != prel {
                    return Err(kerr(
                        K::Relevance,
                        format!("application `{}` is annotated {rel:?} but the function's Π is {prel:?}", truncate(self.show_tm(cx, t))),
                    ));
                }
                self.check(cx, arg, dom, sub_mode(cx, *rel, irr), b)?;
                let e = self.dependent_entry(cx, *rel, arg, cod, b)?;
                self.inst(cod, e, cx.depth(), b)
            }
            Term::Let { name, rel, ty, val, body } => {
                let cx2 = self.check_let(cx, name, *rel, ty, val, irr, b)?;
                self.infer(&cx2, body, irr, b)
            }
            Term::Sigma { name, snd_rel, fst, snd } => {
                self.sort_is(cx, fst, irr, Sort::Type, "the first component of a Σ", b)?;
                let fv = self.eval(cx, fst, b)?;
                let (cx2, _) = self.bind(cx, name, Rel::Rel, &fv);
                self.sort_is(&cx2, snd, irr, Sort::Type, "the second component of a Σ", b)?;
                // An irrelevant component must be a proposition (red-team R1):
                // conversion skips it, which proof irrelevance justifies.
                if *snd_rel == Rel::Irr {
                    let sv = self.eval(&cx2, snd, b)?;
                    if !self.is_prop(cx2.depth(), &sv, PROP_DEPTH, b)? {
                        return Err(kerr(
                            K::Relevance,
                            format!(
                                "the irrelevant second component of a Σ must be a proposition (Eq, Empty, a Π into a proposition, a Σ \
                                 of propositions, or a single-constructor type of propositions), found `{}`",
                                truncate(self.show(&cx2, &sv))
                            ),
                        ));
                    }
                }
                Ok(Rc::new(Value::Sort(Sort::Type)))
            }
            Term::Pair { ty, fst, snd } => {
                self.infer_sort(cx, ty, irr, b)?;
                let tv = self.eval(cx, ty, b)?;
                let Value::Sigma { snd_rel, fst: a, snd: bcl, .. } = &*tv else {
                    return Err(kerr(K::TypeMismatch, format!("pair annotated with the non-Σ type `{}`", truncate(self.show(cx, &tv)))));
                };
                self.check(cx, fst, a, irr, b)?;
                let fv = self.eval(cx, fst, b)?;
                let bt = self.inst(bcl, EnvEntry::Rel(fv), cx.depth(), b)?;
                self.check(cx, snd, &bt, sub_mode(cx, *snd_rel, irr), b)?;
                Ok(tv)
            }
            Term::Fst(p) => {
                let pt = self.infer(cx, p, irr, b)?;
                match &*pt {
                    Value::Sigma { fst, .. } => Ok(fst.clone()),
                    _ => Err(kerr(K::TypeMismatch, "`fst` of a non-pair")),
                }
            }
            Term::Snd(p) => {
                let pt = self.infer(cx, p, irr, b)?;
                let Value::Sigma { snd_rel, snd, .. } = &*pt else {
                    return Err(kerr(K::TypeMismatch, "`snd` of a non-pair"));
                };
                if *snd_rel == Rel::Irr {
                    match irr {
                        None => return Err(kerr(K::Relevance, "`snd` of an irrelevant Σ in a relevant position")),
                        Some(d) if mentions_inner(p, cx.depth().0, d) => {
                            return Err(kerr(
                                K::Relevance,
                                "`snd` of an irrelevant Σ whose pair mentions variables bound inside the enclosing irrelevant position",
                            ));
                        }
                        Some(_) => {}
                    }
                }
                let pv = self.eval(cx, p, b)?;
                let fv = Ev::new(self.env).fst(&pv);
                self.inst(snd, EnvEntry::Rel(fv), cx.depth(), b)
            }
            Term::Eq { ty, lhs, rhs } => {
                self.sort_is(cx, ty, irr, Sort::Type, "the type of an equality", b)?;
                let tv = self.eval(cx, ty, b)?;
                self.check(cx, lhs, &tv, irr, b)?;
                self.check(cx, rhs, &tv, irr, b)?;
                Ok(Rc::new(Value::Sort(Sort::Type)))
            }
            Term::Refl { ty, val } => {
                self.sort_is(cx, ty, irr, Sort::Type, "the type of `refl`", b)?;
                let tv = self.eval(cx, ty, b)?;
                self.check(cx, val, &tv, irr, b)?;
                let vv = self.eval(cx, val, b)?;
                Ok(Rc::new(Value::Eq { ty: tv, lhs: vv.clone(), rhs: vv }))
            }
            Term::Transport { ty, lhs, rhs, eq, motive, val } => {
                self.sort_is(cx, ty, irr, Sort::Type, "the type of a transport", b)?;
                let tv = self.eval(cx, ty, b)?;
                self.check(cx, lhs, &tv, irr, b)?;
                self.check(cx, rhs, &tv, irr, b)?;
                let lv = self.eval(cx, lhs, b)?;
                let rv = self.eval(cx, rhs, b)?;
                self.no_erased_proof(eq)?;
                let eq_ty = Rc::new(Value::Eq { ty: tv.clone(), lhs: lv.clone(), rhs: rv.clone() });
                self.check(cx, eq, &eq_ty, irr_at(cx), b)?;
                let (cx2, _) = self.bind(cx, &Rc::from("y"), Rel::Rel, &tv);
                self.sort_is(&cx2, motive, irr, Sort::Type, "a transport motive", b)?;
                let mcl = Closure { env: cx.venv.clone(), body: motive.clone() };
                let vt = self.inst(&mcl, EnvEntry::Rel(lv), cx.depth(), b)?;
                self.check(cx, val, &vt, irr, b)?;
                self.inst(&mcl, EnvEntry::Rel(rv), cx.depth(), b)
            }
            Term::Ind { ind, params } => {
                self.check_params(cx, *ind, params, irr, b)?;
                Ok(Rc::new(Value::Sort(Sort::Type)))
            }
            Term::Ctor { ind, ctor, params, args } => {
                let pvals = self.check_params(cx, *ind, params, irr, b)?;
                let info = &self.env.inds[ind.0 as usize];
                let c = info
                    .ctors
                    .get(*ctor as usize)
                    .ok_or_else(|| kerr(K::IllFormed, format!("`{}` has no constructor {ctor}", info.name)))?;
                if args.len() != c.fields.len() {
                    return Err(kerr(
                        K::IllFormed,
                        format!("constructor `{}` expects {} fields, got {}", c.name, c.fields.len(), args.len()),
                    ));
                }
                let mut fenv: Vec<EnvEntry> = pvals.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
                let nf = c.fields.len();
                for (i, (a, (_, frel, fty))) in args.iter().zip(&c.fields).enumerate() {
                    let ftv = self.eval_in(&VEnv(Rc::new(fenv.clone())), cx.depth(), fty, b)?;
                    self.check(cx, a, &ftv, sub_mode(cx, *frel, irr), b)?;
                    // A field's value is needed only by later field types that
                    // mention it (cf. `dependent_entry`).
                    let used = (i + 1..nf).any(|k| crate::util::occurs(&c.fields[k].2, (k - 1 - i) as u32));
                    fenv.push(if *frel == Rel::Irr || used { self.entry(cx, *frel, a, b)? } else { EnvEntry::Rel(crate::eval::garbage()) });
                }
                Ok(Rc::new(Value::Ind { ind: *ind, params: pvals }))
            }
            Term::Match { ind, params, scrut, motive, arms } => self.infer_match(cx, *ind, params, scrut, motive, arms, irr, b),
            Term::IntTy(_) => Ok(Rc::new(Value::Sort(Sort::Type))),
            Term::Lit { w, n } => {
                if let Some(bits) = w.bits()
                    && (n < &num_bigint::BigInt::from(0) || n.bits() > bits as u64)
                {
                    return Err(kerr(K::IllFormed, format!("literal {n} out of range for {w:?}")));
                }
                Ok(Rc::new(Value::IntTy(*w)))
            }
            Term::Prim { op, args, proofs } => {
                let sig = prim::prim_sig(*op).ok_or_else(|| kerr(K::IllFormed, format!("ill-formed primitive {op:?}")))?;
                if args.len() != sig.args.len() || proofs.len() != sig.proofs {
                    return Err(kerr(
                        K::IllFormed,
                        format!("primitive {} expects {} arguments and {} proofs", prim::prim_name(*op), sig.args.len(), sig.proofs),
                    ));
                }
                for (a, w) in args.iter().zip(&sig.args) {
                    self.check(cx, a, &Rc::new(Value::IntTy(*w)), irr, b)?;
                }
                let obls = prim::prim_obligations(*op, args, self.env.bool_id);
                for (p, o) in proofs.iter().zip(&obls) {
                    self.no_erased_proof(p)?;
                    let ov = self.eval(cx, o, b)?;
                    self.check(cx, p, &ov, irr_at(cx), b)?;
                }
                Ok(match sig.result {
                    PrimTy::Int(w) => Rc::new(Value::IntTy(w)),
                    PrimTy::Bool => self.bool_ty(),
                })
            }
            Term::Rec { args, proof } => self.infer_rec(cx, args, proof.as_ref(), irr, b),
            Term::Delta { def, args } => {
                let d = self.env.defs.get(def.0 as usize).ok_or_else(|| kerr(K::IllFormed, format!("unknown global {def:?}")))?;
                if args.len() != d.arity as usize {
                    return Err(kerr(K::IllFormed, format!("delta({}) needs exactly {} arguments", d.name, d.arity)));
                }
                if d.res_sort != Sort::Type {
                    return Err(kerr(K::IllFormed, format!("delta({}) needs a result type R : Type", d.name)));
                }
                let (es, r) = self.check_telescope(cx, d.ty_val.clone(), args, irr, "delta", b)?;
                let lhs = self.apply_global(cx, *def, &es, b)?;
                let rhs = self.eval_in(&VEnv(Rc::new(es)), cx.depth(), &d.inner, b)?;
                Ok(Rc::new(Value::Eq { ty: r, lhs, rhs }))
            }
            Term::Unfold { def, args, to_body, val } => {
                let d = self.env.defs.get(def.0 as usize).ok_or_else(|| kerr(K::IllFormed, format!("unknown global {def:?}")))?;
                if args.len() != d.arity as usize {
                    return Err(kerr(K::IllFormed, format!("unfold({}) needs exactly {} arguments", d.name, d.arity)));
                }
                let (es, r) = self.check_telescope(cx, d.ty_val.clone(), args, irr, "unfold", b)?;
                if !matches!(&*r, Value::Sort(Sort::Type)) {
                    return Err(kerr(K::IllFormed, format!("unfold({}) needs a proposition-valued definition (R = Type)", d.name)));
                }
                let gv = self.apply_global(cx, *def, &es, b)?;
                let bv = self.eval_in(&VEnv(Rc::new(es)), cx.depth(), &d.inner, b)?;
                let (from, to) = if *to_body { (gv, bv) } else { (bv, gv) };
                self.check(cx, val, &from, irr, b)?;
                Ok(to)
            }
            Term::Linarith { hyps, goal, cert } => self.infer_linarith(cx, hyps, goal, cert, irr, b),
            Term::BvRefl { ty, lhs, rhs } => {
                self.sort_is(cx, ty, irr, Sort::Type, "the type of bvrefl", b)?;
                let tv = self.eval(cx, ty, b)?;
                self.check(cx, lhs, &tv, irr, b)?;
                self.check(cx, rhs, &tv, irr, b)?;
                self.no_erased_proof(lhs)?;
                self.no_erased_proof(rhs)?;
                // Equality modulo word algebra (DESIGN.md §9.8): conversion,
                // then `bvnorm` with the tripwire.
                let lv = self.eval(cx, lhs, b)?;
                let rv = self.eval(cx, rhs, b)?;
                crate::bvnorm::check_bvrefl(self.env, cx, lhs, rhs, &lv, &rv, b)?;
                Ok(Rc::new(Value::Eq { ty: tv, lhs: lv, rhs: rv }))
            }
            Term::Absurd { ty, proof } => {
                self.infer_sort(cx, ty, irr, b)?;
                if contains_erased(proof) {
                    return Err(kerr(K::Erased, "`absurd` proof may not contain `Erased`"));
                }
                let empty = Rc::new(Value::Ind { ind: self.env.empty_id, params: vec![] });
                self.check(cx, proof, &empty, irr_at(cx), b)?;
                self.eval(cx, ty, b)
            }
            Term::Axiom { ax, args } => {
                let (params, stmt) =
                    crate::axioms::telescope(*ax, self.env.bool_id).ok_or_else(|| kerr(K::IllFormed, format!("unknown axiom {ax:?}")))?;
                if args.len() != params.len() {
                    return Err(kerr(K::IllFormed, format!("axiom {} expects {} arguments", crate::axioms::axiom_name(*ax), params.len())));
                }
                let mut es: Vec<EnvEntry> = Vec::with_capacity(args.len());
                for (a, (_, rel, pty)) in args.iter().zip(&params) {
                    let ptv = self.eval_in(&VEnv(Rc::new(es.clone())), cx.depth(), pty, b)?;
                    self.check(cx, a, &ptv, sub_mode(cx, *rel, irr), b)?;
                    es.push(self.entry(cx, *rel, a, b)?);
                }
                self.eval_in(&VEnv(Rc::new(es)), cx.depth(), &stmt, b)
            }
            Term::Erased => Err(kerr(K::Erased, "`Erased` placeholder in a checked term (its type cannot be inferred)")),
        }
    }

    /// The `Linarith` rule (DESIGN.md §5.8; phase-3 robustness):
    ///
    /// 1. Every stated hypothesis `s` must be a proposition and every proof
    ///    `p` must be well-typed. `s` is justified by `p` when `p : s`;
    ///    otherwise by an assumption of the context of type `s` (usable in
    ///    the current relevance mode). A term obtained by substitution may
    ///    carry a proof that was only valid in another branch (e.g. the
    ///    `refl` a dependent-match path equation was applied to); the
    ///    statement is still justified if the context has it.
    /// 2. The certificate is a hint: it is checked exactly against the
    ///    kernel's linear system; if it does not fit (substitution removes or
    ///    merges atoms and shifts the canonical positions), the kernel
    ///    searches a certificate for the same system, then for the system
    ///    extended with the context's hypotheses of §5.8 form (usable in the
    ///    current mode). A found certificate goes through the same exact
    ///    check (the search itself, `lincert`, is untrusted).
    ///
    /// Soundness: the goal is accepted only if a verified Farkas combination
    /// refutes its negation from hypotheses that hold in the context (each
    /// is inhabited by a checked proof or a context variable).
    fn infer_linarith(&self, cx: &Cx, hyps: &[(Tm, Tm)], goal: &Tm, cert: &[crate::term::Rat], irr: Mode, b: &mut Budget) -> KR<V> {
        let mut stated = Vec::with_capacity(hyps.len());
        for (p, s) in hyps {
            self.sort_is(cx, s, irr, Sort::Type, "a linarith hypothesis", b)?;
            let sv = self.eval(cx, s, b)?;
            match self.check(cx, p, &sv, irr, b) {
                Ok(()) => {}
                Err(e) if e.kind == K::TypeMismatch => {
                    // The proof must still be well-typed; the statement
                    // must then hold by an assumption.
                    self.no_erased_proof(p)?;
                    if self.infer(cx, p, irr, b).is_err() || self.assumption(cx, &sv, irr, b)?.is_none() {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
            stated.push(sv);
        }
        self.sort_is(cx, goal, irr, Sort::Type, "a linarith goal", b)?;
        let gv = self.eval(cx, goal, b)?;
        let sys = linarith::build(self.env, cx, &stated, &gv, b)?;
        let Err(e) = linarith::check_cert(&sys, cert) else { return Ok(gv) };
        if let Some(c) = linarith::search_cert(&sys, b)?
            && linarith::check_cert(&sys, &c).is_ok()
        {
            return Ok(gv);
        }
        // The context's hypotheses (§5.8 forms, usable in this mode).
        let facts = self.context_facts(cx, irr);
        if !facts.is_empty() {
            let mut all = stated.clone();
            all.extend(facts);
            let sys2 = linarith::build(self.env, cx, &all, &gv, b)?;
            if let Some(c) = linarith::search_cert(&sys2, b)?
                && linarith::check_cert(&sys2, &c).is_ok()
            {
                return Ok(gv);
            }
        }
        Err(kerr(
            K::Linarith,
            format!("{} (and no certificate exists, also with the context's hypotheses)\n{}", e.message, self.show_system(cx, &sys)),
        ))
    }

    /// A context entry of type `ty` usable in the current relevance mode
    /// (its level), most recent first.
    fn assumption(&self, cx: &Cx, ty: &V, irr: Mode, b: &mut Budget) -> KR<Option<usize>> {
        for (l, e) in cx.ctx.entries.iter().enumerate().rev() {
            if e.rel == Rel::Irr && !usable(irr, l) {
                continue;
            }
            if matches!(&*e.ty, Value::Eq { .. }) && self.conv(cx, &e.ty, ty, b)? {
                return Ok(Some(l));
            }
        }
        Ok(None)
    }

    /// The types of the context entries that are §5.8 hypothesis forms,
    /// usable in the current relevance mode (at most [`MAX_CONTEXT_FACTS`],
    /// most recent first).
    fn context_facts(&self, cx: &Cx, irr: Mode) -> Vec<V> {
        cx.ctx
            .entries
            .iter()
            .enumerate()
            .rev()
            .filter(|(l, e)| (e.rel == Rel::Rel || usable(irr, *l)) && linarith::is_hyp_form(self.env, &e.ty))
            .take(MAX_CONTEXT_FACTS)
            .map(|(_, e)| e.ty.clone())
            .collect()
    }

    fn global_type(&self, g: GlobalId) -> KR<V> {
        if let Some(p) = &self.env.pending
            && p.id == g
        {
            return Err(kerr(K::Termination, "a definition may not refer to itself through `Global`; use `rec`"));
        }
        self.env.defs.get(g.0 as usize).map(|d| d.ty_val.clone()).ok_or_else(|| kerr(K::IllFormed, format!("unknown global {g:?}")))
    }

    /// The value of `g` applied to argument entries.
    fn apply_global(&self, cx: &Cx, g: GlobalId, es: &[EnvEntry], b: &mut Budget) -> KR<V> {
        let mut ev = Ev::new(self.env);
        let mut f = ev.eval(&cx.venv, cx.depth(), &mk::global(g), b)?;
        for e in es {
            f = ev.apply(&f, entry_arg(e), cx.depth(), b)?;
        }
        Ok(f)
    }

    #[allow(clippy::too_many_arguments)]
    fn infer_match(
        &self,
        cx: &Cx,
        ind: crate::term::IndId,
        params: &[Tm],
        scrut: &Tm,
        motive: &Tm,
        arms: &[crate::term::Arm],
        irr: Mode,
        b: &mut Budget,
    ) -> KR<V> {
        let pvals = self.check_params(cx, ind, params, irr, b)?;
        let info = &self.env.inds[ind.0 as usize];
        let ind_ty = Rc::new(Value::Ind { ind, params: pvals.clone() });
        self.check(cx, scrut, &ind_ty, irr, b)?;
        let (cx_y, _) = self.bind(cx, &Rc::from("y"), Rel::Rel, &ind_ty);
        self.infer_sort(&cx_y, motive, irr, b)?;
        if arms.len() != info.ctors.len() {
            return Err(kerr(K::IllFormed, format!("match on `{}` needs {} arms, got {}", info.name, info.ctors.len(), arms.len())));
        }
        let mcl = Closure { env: cx.venv.clone(), body: motive.clone() };
        for (k, (arm, c)) in arms.iter().zip(&info.ctors).enumerate() {
            if arm.names.len() != c.fields.len() {
                return Err(kerr(
                    K::IllFormed,
                    format!("arm `{}` binds {} fields, constructor has {}", c.name, arm.names.len(), c.fields.len()),
                ));
            }
            let mut cxa = cx.clone();
            let mut fenv: Vec<EnvEntry> = pvals.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
            let mut fargs = Vec::with_capacity(c.fields.len());
            for (fname, frel, fty) in &c.fields {
                let ftv = self.eval_in(&VEnv(Rc::new(fenv.clone())), cxa.depth(), fty, b)?;
                let (cx2, e) = self.bind(&cxa, fname, *frel, &ftv);
                cxa = cx2;
                fargs.push(entry_arg(&e));
                fenv.push(e);
            }
            let cval = Rc::new(Value::Ctor { ind, ctor: k as u32, params: pvals.clone(), args: fargs });
            let expected = self.inst(&mcl, EnvEntry::Rel(cval), cxa.depth(), b)?;
            self.check(&cxa, &arm.body, &expected, irr, b)?;
        }
        // The scrutinee's value is needed only by a dependent motive.
        let sv = if crate::util::occurs(motive, 0) { self.eval(cx, scrut, b)? } else { crate::eval::garbage() };
        self.inst(&mcl, EnvEntry::Rel(sv), cx.depth(), b)
    }

    fn infer_rec(&self, cx: &Cx, args: &[Tm], proof: Option<&Tm>, irr: Mode, b: &mut Budget) -> KR<V> {
        if !self.in_body {
            return Err(kerr(K::Termination, "`rec` outside the body of its own definition"));
        }
        let p = self.env.pending.as_ref().ok_or_else(|| kerr(K::Termination, "`rec` outside a definition"))?;
        if matches!(p.recursion, Recursion::None) {
            return Err(kerr(K::Termination, "`rec` in a definition declared non-recursive"));
        }
        if args.len() != p.arity as usize {
            return Err(kerr(K::IllFormed, format!("`rec` needs exactly {} arguments", p.arity)));
        }
        if cx.depth().0 < p.arity {
            return Err(kerr(K::Termination, "`rec` inside the parameter telescope"));
        }
        let (es, ty) = self.check_telescope(cx, p.ty_val.clone(), args, irr, "rec", b)?;
        match &p.recursion {
            Recursion::None => unreachable!(),
            Recursion::Structural { .. } => {
                if proof.is_some() {
                    return Err(kerr(K::IllFormed, "structural `rec` takes no decrease proof"));
                }
            }
            Recursion::Measure { measure } => {
                let pf = proof.ok_or_else(|| kerr(K::Termination, "measure `rec` needs a decrease proof"))?;
                let m_args = self.eval_in(&VEnv(Rc::new(es)), cx.depth(), measure, b)?;
                let params: Vec<EnvEntry> = cx.venv.0[..p.arity as usize].to_vec();
                let m_params = self.eval_in(&VEnv(Rc::new(params)), cx.depth(), measure, b)?;
                let w = p.measure_width.unwrap_or(Width::Int);
                let oblig = self.measure_obligation(cx, w, m_args, m_params, b)?;
                self.check(cx, pf, &oblig, irr_at(cx), b)?;
            }
        }
        Ok(ty)
    }

    /// `Σ(_ : Eq(Bool, le_int(0, m_args), true)). Eq(Bool, lt_int(m_args,
    /// m_params), true)` for an `Int` measure, `Eq(Bool, lt_w(m_args,
    /// m_params), true)` for a machine-width measure (DESIGN.md §5.6).
    pub fn measure_obligation(&self, cx: &Cx, w: Width, m_args: V, m_params: V, b: &mut Budget) -> KR<V> {
        let bi = self.env.bool_id;
        let t = measure_obligation_term(bi, w);
        let env = VEnv(Rc::new(vec![EnvEntry::Rel(m_args), EnvEntry::Rel(m_params)]));
        self.eval_in(&env, cx.depth(), &t, b)
    }

    fn no_erased_proof(&self, p: &Tm) -> KR<()> {
        if !self.allow_erased && contains_erased(p) {
            return Err(kerr(K::Erased, "`Erased` placeholder in a checked term"));
        }
        Ok(())
    }

    /// Is the type value `ty` (under `depth` binders) syntactically a
    /// proposition — a subsingleton in the set model? Conservative (red-team
    /// R1): `Eq`; a Π whose codomain is a proposition; a Σ of propositions;
    /// a non-recursive inductive with no constructor, or with one
    /// constructor whose fields all have proposition types. Anything else
    /// (neutral types, sorts, machine integers, several constructors,
    /// recursive inductives, nesting beyond `fuel`) is not. Required of the
    /// type of every irrelevant Σ component and constructor field, so that
    /// conversion skipping them is justified by proof irrelevance and not
    /// only by the relevance discipline.
    pub(crate) fn is_prop(&self, depth: Lvl, ty: &V, fuel: u32, b: &mut Budget) -> KR<bool> {
        tick(b)?;
        if fuel == 0 {
            return Ok(false);
        }
        let next = Lvl(depth.0 + 1);
        Ok(match &**ty {
            Value::Eq { .. } => true,
            Value::Pi { rel, dom, cod, .. } => {
                let x = Ev::new(self.env).fresh(depth, *rel, dom);
                let c = self.inst(cod, x, next, b)?;
                self.is_prop(next, &c, fuel - 1, b)?
            }
            Value::Sigma { fst, snd, .. } => {
                if !self.is_prop(depth, fst, fuel - 1, b)? {
                    return Ok(false);
                }
                let x = Ev::new(self.env).fresh(depth, Rel::Rel, fst);
                let s = self.inst(snd, x, next, b)?;
                self.is_prop(next, &s, fuel - 1, b)?
            }
            Value::Ind { ind, params } => {
                let Some(info) = self.env.inds.get(ind.0 as usize) else { return Ok(false) };
                if info.recursive || info.ctors.len() > 1 {
                    return Ok(false);
                }
                let Some(c) = info.ctors.first() else { return Ok(true) };
                let mut fenv: Vec<EnvEntry> = params.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
                let mut d = depth;
                for (_, frel, fty) in &c.fields {
                    let ftv = self.eval_in(&VEnv(Rc::new(fenv.clone())), d, fty, b)?;
                    if !self.is_prop(d, &ftv, fuel - 1, b)? {
                        return Ok(false);
                    }
                    fenv.push(Ev::new(self.env).fresh(d, *frel, &ftv));
                    d = Lvl(d.0 + 1);
                }
                true
            }
            _ => false,
        })
    }
}

/// The measure obligation as a term over `Var(1) = m[args]`, `Var(0) =
/// m[params]` (see `Checker::measure_obligation`).
pub fn measure_obligation_term(bool_ind: crate::term::IndId, w: Width) -> Tm {
    use crate::term::PrimOp::{Le, Lt};
    if w == Width::Int {
        mk::sigma(
            "_",
            Rel::Rel,
            mk::eq_bool(bool_ind, prim::prim0(Le(Width::Int), vec![mk::lit(Width::Int, 0u8), mk::var(1)]), true),
            mk::eq_bool(bool_ind, prim::prim0(Lt(Width::Int), vec![mk::var(2), mk::var(1)]), true),
        )
    } else {
        mk::eq_bool(bool_ind, prim::prim0(Lt(w), vec![mk::var(1), mk::var(0)]), true)
    }
}

/// Does `t` contain `Erased` anywhere? (Linear in the term DAG.)
pub(crate) fn contains_erased(t: &Tm) -> bool {
    crate::util::any_node(t, &mut |n| matches!(&**n, Term::Erased))
}

fn truncate(s: String) -> String {
    const MAX: usize = 400;
    if s.len() <= MAX {
        s
    } else {
        let mut cut = MAX;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &s[..cut])
    }
}
