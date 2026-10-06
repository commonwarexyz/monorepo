//! Item-level elaboration (DESIGN.md §7.1, §7.3): types, constants, exec
//! and spec functions, their telescopes, recursion measures (§3.7, §4.2)
//! and the kernel definitions (with placeholders for unproven ones).
//!
//! An exec function `fn f<T..>(x: A..) -> R` with `requires P₁..Pₙ` is the
//! definition `f : Π(T : Type).. Π(x : ⟦A⟧).. Π(h₁ :Irr ⟦P₁⟧)..Π(hₙ :Irr
//! ⟦Pₙ⟧). ⟦R⟧`. A depth-bounded recursive function (`#[decreases(e, max =
//! C)]`, §3.7 b) gets one more irrelevant binder `h_depth : e ≤ C`, so the
//! kernel requires the stack-depth proof at every call site (recursive ones
//! included). A self-recursive function is `Recursion::Measure` with the
//! `decreases` measure, or the inferred one (§4.2): the first parameter that
//! every recursive call passes as `p − k` (literal `k ≥ 1`, measure `p`), as
//! the rest binding of a slice pattern on `p` (measure `p.len()`), or as a
//! recursive field of a recursive spec type bound by a pattern on `p`
//! (measure `size'(p)`, `elab::recursive`).
//! Functions containing loops (and their loop helpers), functions building
//! buffers and codec readers are opaque (§5.6, [`opaque_in_proofs`]): they
//! are used through their obligations/ensures in proofs, never
//! symbolically unrolled while checking callers.

use std::collections::HashMap;
use std::rc::Rc;

use sandblaster_kernel::term::{DefDecl, DefKind, GlobalId, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::{mk, shift};
use sandblaster_kernel::value::Budget;

use super::exec::Answer;
use super::{internal, unsupported, DefRecord, DefStatus, Elab, ElabError, ErrKind, FnState, ItemGlobal, Mode, RecInfo, Val, R};
use crate::diag::{DiagKind, Diagnostic};
use crate::hir::*;
use crate::prover::FactOrigin;
use crate::span::Span;
use crate::visit::{self, Visitor};

/// Facts about an elaborated function used at its call sites.
#[derive(Clone, Debug, Default)]
pub struct FnInfo {
    /// Index (among the irrelevant binders) of the stack-depth requires.
    pub depth_req: Option<usize>,
}

/// A telescope binder being built.
pub struct TBinder {
    pub name: String,
    pub rel: Rel,
    pub ty: Tm,
}

/// Whether an exec function is opaque in proofs (DESIGN.md §5.6: "hashes,
/// CRC, codecs and large step functions are opaque in proofs by default and
/// used through their ensures"; `unfold(f)` reveals the definition):
/// functions with loops, functions
/// that **build buffers** — assign array elements or `copy_from_slice` into
/// a local array (hash preimages, byte encodings, stack buffers) — and
/// **codec readers** ([`is_reader`]). Their symbolic values are large,
/// heavily shared graphs (a reader applied to a variable input unfolds into
/// a tree of length tests, and a chain of readers nests them); unfolding
/// them during proof search, printing them in goals and abstracting over
/// them in rewriting motives is never useful. Proofs about their callers
/// treat `reader(bytes)` as a stuck term (equations about it rewrite).
pub fn opaque_in_proofs(f: &FnDef) -> bool {
    has_loop(f) || builds_buffers(f) || is_reader(f) || f.spec.opaque.is_some()
}

/// Whether a function is a **codec reader** (§5.6 "codecs"): it takes a
/// byte slice and returns the decoded value together with the unconsumed
/// rest, `Option<(T, &[u8])>` (`None` rejects the input).
pub fn is_reader(f: &FnDef) -> bool {
    let bytes = Ty::slice_ref(Ty::u8());
    let takes_bytes = f.params.iter().any(|p| p.ty == bytes);
    let returns_rest = matches!(&f.ret, Ty::Option(t) if matches!(&**t, Ty::Tuple(ts) if ts.len() == 2 && ts[1] == bytes));
    takes_bytes && returns_rest
}

/// Whether a function body writes into a local array (`a[i] = v`,
/// `a[..].copy_from_slice(s)`).
pub fn builds_buffers(f: &FnDef) -> bool {
    struct V(bool);
    impl Visitor for V {
        fn stmt(&mut self, s: &Stmt) {
            match &s.kind {
                StmtKind::CopyFromSlice { .. } => self.0 = true,
                StmtKind::Assign { place, .. } | StmtKind::CompoundAssign { place, .. } if place.projs.iter().any(|p| matches!(p, Proj::Index(_))) => self.0 = true,
                _ => {}
            }
            visit::walk_stmt(self, s);
        }
    }
    let mut v = V(false);
    visit::walk_fn(&mut v, f);
    v.0
}

/// Whether a function body contains a loop.
pub fn has_loop(f: &FnDef) -> bool {
    struct V(bool);
    impl Visitor for V {
        fn loop_(&mut self, _: &Loop) {
            self.0 = true;
        }
    }
    let mut v = V(false);
    visit::walk_fn(&mut v, f);
    v.0
}

impl<'a> Elab<'a> {
    /// Elaborates one item, recording failures.
    pub fn item(&mut self, id: ItemId) {
        let krate = self.krate;
        let it = krate.item(id);
        if std::env::var_os("SANDBLASTER_TRACE_ELAB").is_some() {
            eprintln!("elab: item {}", it.path);
        }
        // `SANDBLASTER_TRACE_ELAB_MS=t`: every item that took at least `t` ms
        let timed = std::env::var("SANDBLASTER_TRACE_ELAB_MS").ok().and_then(|v| v.parse::<u128>().ok()).map(|t| (t, std::time::Instant::now()));
        self.item_inner(id);
        if let Some((t, t0)) = timed {
            let ms = t0.elapsed().as_millis();
            if ms >= t {
                eprintln!("elab-time: {ms} ms {}", it.path);
            }
        }
    }

    fn item_inner(&mut self, id: ItemId) {
        let krate = self.krate;
        let it = krate.item(id);
        let res: R<()> = match &it.kind {
            ItemKind::Struct(s) => self.declare_adt(id).and_then(|_| if s.derives.partial_eq { self.derive_eq(id) } else { Ok(()) }).and_then(|_| self.type_spec_defs(id, s.view.as_ref(), s.represents.as_ref())),
            ItemKind::Enum(e) => self.declare_adt(id).and_then(|_| if e.derives.partial_eq { self.derive_eq(id) } else { Ok(()) }).and_then(|_| self.type_spec_defs(id, e.view.as_ref(), None)),
            ItemKind::TypeAlias(_) => Ok(()),
            ItemKind::Const(c) => self.const_item(id, c),
            ItemKind::Fn(f) => match f.kind {
                FnKind::Exec => {
                    if self.hw_items.contains(&id) && self.sem.intrinsics.is_empty() {
                        let why = "hardware function (intrinsics / target features): the target models (`sandblaster/targets/core/<arch>.core`) are not loaded for this architecture (DESIGN.md §9); deferred, never trusted".to_string();
                        self.deferred.push((id, why.clone()));
                        self.defs.push(DefRecord { name: it.path.to_string(), kind: DefKind::Exec, item: Some(id), global: None, status: DefStatus::Deferred(why), span: it.span });
                        return;
                    }
                    self.exec_fn(id, f)
                }
                FnKind::Spec if !self.opts.exec_only => self.spec_fn(id, f),
                FnKind::Lemma if !self.opts.exec_only => self.lemma_item(id, f),
                FnKind::Law if !self.opts.exec_only => self.law_item(id, f),
                FnKind::Proof if !self.opts.exec_only => {
                    // `#[proof(refines = f)]` (DESIGN.md §15.2)
                    if let Some(p) = f.spec.proof_of.filter(|p| p.kind == ProofKind::Refines) {
                        self.refines_proof_item(id, f, &p);
                    }
                    // `#[proof(view_inj = T)]` (§15.2, S2)
                    if let Some(p) = f.spec.proof_of.filter(|p| p.kind == ProofKind::ViewInj)
                        && self.s1.on
                    {
                        self.view_inj_proof_item(id, f, p.target);
                    }
                    Ok(())
                }
                _ => Ok(()),
            },
        };
        if let Err(e) = res {
            self.item_failed(id, e);
        }
    }

    /// The §15 definitions of a type (S1): `T::view` and
    /// `S::represents` (`elab::views`). A failure is reported on the
    /// annotation; the type itself stays usable.
    fn type_spec_defs(&mut self, id: ItemId, view: Option<&'a View>, rep: Option<&'a Represents>) -> R<()> {
        if !self.s1.on {
            return Ok(());
        }
        if let Some(v) = view {
            match self.view_def(id, v) {
                // `T::view_inj` (§15.2, §15.3, S2)
                Ok(()) => self.view_injectivity(id),
                Err(e) => {
                    let path = self.krate.item(id).path.to_string();
                    self.diag(Diagnostic::error(DiagKind::Elab, v.span(), format!("the `#[view]` of `{path}` could not be elaborated: {}", e.msg)));
                }
            }
        }
        if let Some(r) = rep
            && let Err(e) = self.represents_def(id, r)
        {
            let path = self.krate.item(id).path.to_string();
            self.diag(Diagnostic::error(DiagKind::Elab, r.span, format!("the `#[represents]` of `{path}` could not be elaborated: {}", e.msg)));
        }
        Ok(())
    }

    /// Records an item that could not be elaborated.
    pub fn item_failed(&mut self, id: ItemId, e: ElabError) {
        let it = self.krate.item(id);
        let (status, why) = match e.kind {
            ErrKind::Unsupported => (DefStatus::Unsupported(e.msg.clone()), format!("could not be elaborated: {}", e.msg)),
            ErrKind::Blocked => (DefStatus::Blocked(e.msg.clone()), format!("was not elaborated: {}", e.msg)),
            ErrKind::Deferred => (DefStatus::Deferred(e.msg.clone()), format!("is deferred: {}", e.msg)),
            ErrKind::Internal => (DefStatus::Unsupported(format!("internal error: {}", e.msg)), format!("hit an internal elaborator error: {}", e.msg)),
        };
        if e.kind == ErrKind::Deferred {
            self.deferred.push((id, e.msg.clone()));
        } else {
            let span = if e.span.is_dummy() { it.span } else { e.span };
            self.diags.push(Diagnostic::error(DiagKind::Elab, span, format!("`{}` {why}", it.path)));
        }
        if !self.defs.iter().any(|d| d.item == Some(id) && d.name == it.path.to_string()) {
            self.defs.push(DefRecord { name: it.path.to_string(), kind: DefKind::Exec, item: Some(id), global: None, status, span: it.span });
        }
        self.globals.entry(id).or_insert(ItemGlobal::Failed(why));
    }

    /// Adds a definition to the kernel, or a placeholder if an obligation
    /// failed or the kernel rejects it. Records the definition.
    #[allow(clippy::too_many_arguments)]
    pub fn add_definition(&mut self, name: &str, kind: DefKind, item: Option<ItemId>, ty: Tm, body: Tm, recursion: Recursion, arity: u32, opaque: bool, failed: bool, span: Span) -> R<GlobalId> {
        if failed {
            let g = self.placeholder(name, kind, &ty, arity, span);
            self.defs.push(DefRecord { name: name.to_string(), kind, item, global: g, status: DefStatus::Unproven, span });
            return g.ok_or_else(|| ElabError { span, msg: format!("`{name}` has unproven obligations"), kind: ErrKind::Blocked });
        }
        // a definition that uses a stand-in body (the placeholder of a
        // definition that did not verify, or a definition that uses one)
        // was checked against the stand-in's default value, not against
        // the written code: it is added (its dependents are still
        // elaborated and reported) but is blocked, never checked
        let stand_in = self.stand_in_used(&ty, &body);
        // (the pre-commit body keeps the decrease proofs the commit drops)
        let pre_commit = match &recursion {
            Recursion::Measure { measure } => Some(super::PreCommit { body: body.clone(), measure: measure.clone() }),
            _ => None,
        };
        let d = DefDecl { name: Rc::from(name), kind, ty: ty.clone(), body, recursion, arity, opaque };
        let mut b = Budget { steps: self.opts.def_budget };
        match self.env.add_def(d, &mut b) {
            Ok(g) => {
                if let Some(pc) = pre_commit {
                    self.pre_commit.insert(g, pc);
                }
                let status = match stand_in {
                    Some(p) => {
                        self.s1.stand_in_users.insert(g, p.clone());
                        DefStatus::Blocked(format!("depends on `{p}`, which did not verify (checked only against a stand-in body)"))
                    }
                    None => DefStatus::Checked,
                };
                self.defs.push(DefRecord { name: name.to_string(), kind, item, global: Some(g), status, span });
                Ok(g)
            }
            Err(e) => {
                let msg = e.to_string();
                let short: String = msg.chars().take(2000).collect();
                self.diags.push(Diagnostic::error(DiagKind::Elab, span, format!("the kernel rejected `{name}` (an elaborator or prover bug): {short}")));
                let g = self.placeholder(name, kind, &ty, arity, span);
                self.defs.push(DefRecord { name: name.to_string(), kind, item, global: g, status: DefStatus::Rejected(short), span });
                g.ok_or_else(|| ElabError { span, msg: format!("`{name}` was rejected by the kernel"), kind: ErrKind::Blocked })
            }
        }
    }

    /// The first placeholder (by name) that a definition's type or body
    /// uses, directly or through a definition that uses one
    /// (`S1State::stand_in_users`). `None` when no definition failed.
    fn stand_in_used(&self, ty: &Tm, body: &Tm) -> Option<String> {
        if self.s1.placeholders.is_empty() {
            return None;
        }
        let mut found: Option<String> = None;
        let mut look = |n: &Term| {
            let g = match n {
                Term::Global(g) => *g,
                Term::Delta { def, .. } | Term::Unfold { def, .. } => *def,
                _ => return false,
            };
            match self.s1.placeholders.get(&g).or_else(|| self.s1.stand_in_users.get(&g)) {
                Some(p) => {
                    found = Some(p.clone());
                    true
                }
                None => false,
            }
        };
        if super::tm::any_node(ty, &mut look) || super::tm::any_node(body, &mut look) {
            return found;
        }
        None
    }

    /// An opaque definition of the same type with a default body, so that
    /// dependents can still be elaborated and reported. `None` if the
    /// result type has no default value (type parameters, propositions).
    fn placeholder(&mut self, name: &str, kind: DefKind, ty: &Tm, arity: u32, _span: Span) -> Option<GlobalId> {
        let mut binders = Vec::new();
        let mut t = ty.clone();
        for _ in 0..arity {
            let Term::Pi { name, rel, dom, cod } = &*t else { return None };
            binders.push((name.clone(), *rel, dom.clone()));
            t = cod.clone();
        }
        let mut body = self.default_of(&t)?;
        for (n, r, d) in binders.iter().rev() {
            body = Rc::new(Term::Lam { name: n.clone(), rel: *r, dom: d.clone(), body });
        }
        let d = DefDecl { name: Rc::from(name), kind, ty: ty.clone(), body, recursion: Recursion::None, arity, opaque: true };
        let mut b = Budget { steps: self.opts.def_budget };
        let g = self.env.add_def(d, &mut b).ok();
        if let Some(g) = g {
            self.s1.placeholders.insert(g, name.to_string());
        }
        g
    }

    /// A default value of a core type (closed except for type parameters,
    /// which have none).
    pub fn default_of(&self, t: &Tm) -> Option<Tm> {
        match &**t {
            Term::IntTy(w) => Some(mk::lit(*w, 0u8)),
            Term::Sort(_) => Some(mk::ind(self.p.unit, vec![])),
            Term::Ind { ind, params } => {
                if *ind == self.p.option {
                    return Some(mk::ctor(*ind, 0, params.clone(), vec![]));
                }
                let decl = self.env.inductive_decl(*ind)?;
                // the first constructor without a recursive field (a
                // recursive spec type, SEMANTICS.md §13.9)
                let mentions = |t: &Tm| super::tm::any_node(t, &mut |x| matches!(x, Term::Ind { ind: i, .. } if i == ind));
                let (ci, c) = decl.ctors.iter().enumerate().find(|(_, c)| !c.fields.iter().any(|(_, _, t)| mentions(t)))?;
                let np = params.len() as u32;
                let mut args = Vec::new();
                for (j, (_, frel, fty)) in c.fields.iter().enumerate() {
                    if *frel == Rel::Irr {
                        // an invariant's `Irr` field (§15.3): the default
                        // value must satisfy it — a `bool` conjunct that
                        // evaluates to `true` at the default fields (`refl`)
                        let mut all = params.clone();
                        all.extend(args.iter().cloned());
                        let t = super::tm::subst_closed(fty, &all);
                        let Term::Eq { ty, lhs, .. } = &*t else { return None };
                        let mut b = Budget { steps: 10_000_000 };
                        let v = self.env.eval(&sandblaster_kernel::value::VEnv::default(), sandblaster_kernel::term::Lvl(0), lhs, &mut b).ok()?;
                        if !matches!(&*v, sandblaster_kernel::value::Value::Ctor { ind, ctor: 1, .. } if *ind == self.p.bool_) {
                            return None;
                        }
                        args.push(mk::refl(ty.clone(), lhs.clone()));
                        continue;
                    }
                    // field types of user types depend only on the parameters
                    let depth = np + j as u32;
                    let inst = super::tm::map_post(fty, 0, &mut |n, b| match &*n {
                        Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= b => {
                            let lvl = depth.checked_sub(1 + (*i - b))?;
                            if lvl < np { Some(params[lvl as usize].clone()) } else { None }
                        }
                        _ => Some(n),
                    })?;
                    args.push(self.default_of(&inst)?);
                }
                Some(mk::ctor(*ind, ci as u32, params.clone(), args))
            }
            Term::App { .. } => {
                // `Array T N` or `Slice T`
                let (head, args) = spine(t);
                let Term::Global(g) = &*head else { return None };
                if *g == self.p.g("Array") && args.len() == 2 {
                    let n = match &*args[1] {
                        Term::Lit { n, .. } => n.clone(),
                        _ => return None,
                    };
                    let v = self.default_of(&args[0])?;
                    Some(mk::apps(mk::global(self.p.g("array::repeat")), [(Rel::Rel, args[0].clone()), (Rel::Rel, args[1].clone()), (Rel::Rel, v), (Rel::Irr, mk::refl(mk::int_ty(Width::Int), mk::lit(Width::Int, n)))]))
                } else if *g == self.p.g("Slice") && args.len() == 1 {
                    let et = args[0].clone();
                    let nil = mk::ctor(self.p.list, 0, vec![et.clone()], vec![]);
                    let zero = mk::lit(Width::Usize, 0u8);
                    let ok_ty = mk::apps(mk::global(self.p.g("SliceOk")), [(Rel::Rel, et.clone()), (Rel::Rel, zero.clone()), (Rel::Rel, nil.clone())]);
                    let ok = mk::pair(ok_ty, mk::refl(mk::int_ty(Width::Int), mk::lit(Width::Int, 0u8)), mk::refl(mk::bool_ty(self.p.bool_), mk::bool_lit(self.p.bool_, true)));
                    Some(mk::apps(mk::global(self.p.g("slice::mk")), [(Rel::Rel, et), (Rel::Rel, zero), (Rel::Rel, nil), (Rel::Irr, ok)]))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    // ------------------------------------------------------------------
    // constants
    // ------------------------------------------------------------------

    fn const_item(&mut self, id: ItemId, c: &'a ConstDef) -> R<()> {
        let it = self.krate.item(id);
        if it.ghost && self.opts.exec_only {
            return Ok(());
        }
        let name = it.path.to_string();
        self.f = FnState::new(name.clone(), Some(id), &c.locals, it.span);
        self.f.answer = c.ty.clone();
        self.f.ret = c.ty.clone();
        let ty = self.ty(&c.ty, it.span)?;
        let body = self.expr(&c.init, &mut |s, v| Ok(v.at(s.depth())))?;
        let failed = self.f.failed;
        // a ghost constant is a spec constant (DESIGN.md §15.1)
        let kind = if it.ghost { DefKind::Spec } else { DefKind::Exec };
        let g = self.add_definition(&name, kind, Some(id), ty, body, Recursion::None, 0, false, failed, it.span)?;
        self.globals.insert(id, ItemGlobal::Def(g));
        if it.ghost {
            self.spec_item_closure(id, g);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // functions
    // ------------------------------------------------------------------

    /// Pushes the type parameters and parameters of a function; returns
    /// the binders and the parameters whose patterns still need binding.
    pub fn fn_params(&mut self, f: &'a FnDef, span: Span) -> R<(Vec<TBinder>, Vec<(u32, &'a Pat)>)> {
        let mut binders = Vec::new();
        // the parameters' levels start here (0 for a definition; after the
        // section's binders for a law restated with a section abstracted)
        let base = self.depth();
        for g in &f.generics {
            self.push(&g.name, Rel::Rel, &mk::ty(), None)?;
            binders.push(TBinder { name: g.name.clone(), rel: Rel::Rel, ty: mk::ty() });
        }
        self.f.ngen = f.generics.len() as u32;
        let mut pending = Vec::new();
        for (i, p) in f.params.iter().enumerate() {
            // `#[ghost]` parameters (the last ones) form one bundle binder
            // after the others ([`Elab::ghost_bundle`])
            if p.ghost && f.kind == FnKind::Exec {
                continue;
            }
            let ty = self.ty(&p.ty, span)?;
            let (name, simple) = match &p.pat.kind {
                PatKind::Binding { local, sub: None, .. } => (f.locals[local.0 as usize].name.clone(), Some(*local)),
                _ => (format!("arg{i}"), None),
            };
            let lvl = self.push(&name, Rel::Rel, &ty, None)?;
            binders.push(TBinder { name, rel: Rel::Rel, ty });
            match simple {
                Some(l) => {
                    self.f.scope.locals.insert(l, lvl);
                }
                None => pending.push((lvl, &p.pat)),
            }
        }
        if f.kind == FnKind::Exec && f.params.iter().any(|p| p.ghost) {
            self.ghost_bundle(f, &mut binders, span)?;
        }
        // the type bound of every `Nat` parameter of a lemma, law or proof
        // (§4.1): a relevant hypothesis like their `requires`, so callers
        // prove it and the body has it as a fact. Spec functions guard
        // their body instead ([`Elab::nat_guards`], SEMANTICS.md §13.5).
        //
        // The same for the `Nat` components of a parameter (the fields of a
        // spec struct and the components of a tuple, §15.3 / S2: `Nat`
        // bounds carried through data), one hypothesis per component.
        //
        // A law's (and so its proof's) parameters also get the
        // well-formedness of the `Nat`s inside sequences, arrays, options
        // and enums ([`Elab::nat_bounds`]): the law then claims exactly what
        // its source says, for the values its types allow (a law has no
        // callers). So do a lemma's when its contract quantifies over such
        // a type (the parameter is then a witness or an instance of the
        // quantifier, which needs it). Other lemmas keep the plain bounds
        // (the components outside containers, a few levels deep): without
        // the well-formedness hypothesis the kernel statement is the
        // stronger one (it holds for every `Int` inside a container), so it
        // is sound either way, and their callers need not prove a
        // well-formedness proposition (which the provers cannot promote
        // from the irrelevant Nat range facts of a call's arguments).
        if matches!(f.kind, FnKind::Lemma | FnKind::Law | FnKind::Proof) {
            let rel = Rel::Rel;
            let ngen = f.generics.len() as u32;
            let deep = matches!(f.kind, FnKind::Law | FnKind::Proof) || self.contract_quantifies_over_nat_containers(f);
            for (i, p) in f.params.iter().enumerate() {
                let x = self.f.scope.var(base + ngen + i as u32);
                let bounds = if deep {
                    self.nat_bounds(&p.ty, x, true, span)?
                } else {
                    self.nat_components(&p.ty, x, span, 0)?.into_iter().map(|c| self.holds(mk::prim(PrimOp::Le(Width::Int), vec![mk::lit(Width::Int, 0u8), c], vec![]))).collect()
                };
                let d0 = self.depth();
                for (k, b) in bounds.into_iter().enumerate() {
                    let bound = shift(&b, (self.depth() - d0) as i64);
                    let name = if k == 0 { format!("h_nat{i}") } else { format!("h_nat{i}_{k}") };
                    let lvl = self.push(&name, rel, &bound, None)?;
                    self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lvl), origin: FactOrigin::TypeBound, span });
                    self.f.scope.fact_tys.insert(lvl, bound.clone());
                    binders.push(TBinder { name, rel, ty: bound });
                }
            }
        }
        Ok((binders, pending))
    }

    /// Pushes the `requires` binders (irrelevant facts in exec/spec mode,
    /// relevant hypotheses for lemmas).
    pub fn fn_requires(&mut self, f: &'a FnDef, binders: &mut Vec<TBinder>, rel: Rel) -> R<()> {
        let ghost_req = super::invariant::ghost_requires(f);
        // a function read from MIR: its declared contract's clauses, one for one
        let declared = f.declared.as_ref().map(|d| &d.0);
        if let Some(d) = declared.filter(|d| d.len() != f.requires.len()) {
            return unsupported(f.sig_span, format!("it has {} `requires` clause(s), its declared contract {} (lift::MirContract)", f.requires.len(), d.len()));
        }
        for (i, r) in f.requires.iter().enumerate() {
            // a `requires` over `#[ghost]` parameters is in the ghost bundle
            if ghost_req.contains(&i) {
                continue;
            }
            let p = self.prop(r)?;
            if let Some(d) = declared {
                self.as_declared(Some(&p), |s| s.prop(&d[i]).map(Some), &format!("precondition {i}"), r.span)?;
            }
            let name = format!("h_req{i}");
            let lvl = self.push(&name, rel, &p, None)?;
            self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lvl), origin: if rel == Rel::Irr { FactOrigin::Requires } else { FactOrigin::LemmaHyp }, span: r.span });
            self.f.scope.fact_tys.insert(lvl, p.clone());
            binders.push(TBinder { name, rel, ty: p });
        }
        Ok(())
    }

    /// `#[decreases(e, max = C)]`'s hypothesis `e <= C` (`h_depth`), if any.
    fn depth_prop(&mut self, d: &'a Option<Decreases>) -> R<Option<Tm>> {
        let Some((d, max)) = d.as_ref().and_then(|d| Some((d, d.max?))) else { return Ok(None) };
        let (m, w) = (self.pure_expr(&d.measure)?, self.width_of(&d.measure.ty, d.measure.span)?);
        Ok(Some(self.holds(mk::prim(PrimOp::Le(w), vec![m, mk::lit(w, max)], vec![]))))
    }

    /// TRUSTED (`mir::gate`): `p`, a precondition of a function read from
    /// MIR (or its absence), is α-equal to `declared`, the elaboration of the
    /// same clause of its declared contract at the same depth (the
    /// obligations that second elaboration raises are dropped; `p`'s stay).
    fn as_declared(&mut self, p: Option<&Tm>, declared: impl FnOnce(&mut Self) -> R<Option<Tm>>, what: &str, span: Span) -> R<()> {
        let n = self.obligations.len();
        let q = declared(self);
        self.obligations.truncate(n);
        let q = q?;
        if p.zip(q.as_ref()).map_or(p.is_none() && q.is_none(), |(p, q)| self.env.alpha_eq_relevant(p, q, &|a, b| a == b)) {
            return Ok(());
        }
        let show = |t: Option<&Tm>| t.map_or("none".to_string(), |t| self.show_tm(t));
        unsupported(span, format!("its {what} `{}` is not its declared contract's `{}` (lift::MirContract)", show(p), show(q.as_ref())))
    }

    /// An expression without binders (measures, loop bounds): its value.
    pub fn pure_expr(&mut self, e: &'a Expr) -> R<Tm> {
        let d = self.depth();
        let mut out = None;
        let _ = self.in_pure(|s| {
            s.expr(e, &mut |s, v| {
                out = Some(v.clone());
                Ok(s.unit_val())
            })
        })?;
        match out {
            Some(v) if v.depth == d => Ok(v.at(d)),
            _ => unsupported(e.span, "this expression must not contain blocks or branches"),
        }
    }

    fn exec_fn(&mut self, id: ItemId, f: &'a FnDef) -> R<()> {
        let it = self.krate.item(id);
        let name = it.path.to_string();
        let span = it.span;
        self.f = FnState::new(name.clone(), Some(id), &f.locals, span);
        self.f.fdef = Some(f);
        self.f.opaque = opaque_in_proofs(f);
        let (mut binders, pending) = self.fn_params(f, span)?;
        self.fn_requires(f, &mut binders, Rel::Irr)?;
        let mut info = FnInfo::default();
        let depth = self.depth_prop(&f.decreases)?;
        if let Some((_, d)) = &f.declared {
            self.as_declared(depth.as_ref(), |s| s.depth_prop(d), "depth bound", f.sig_span)?;
        }
        if let (Some(dec), Some(p)) = (&f.decreases, depth) {
            let lvl = self.push("h_depth", Rel::Irr, &p, None)?;
            self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lvl), origin: FactOrigin::Requires, span: dec.measure.span });
            self.f.scope.fact_tys.insert(lvl, p.clone());
            binders.push(TBinder { name: "h_depth".into(), rel: Rel::Irr, ty: p });
            info.depth_req = Some(f.requires.len());
        }
        self.fn_info.insert(id, info);
        let arity = self.depth();
        let rty = self.ty(&f.ret, span)?;
        let fty = pi_tele(&binders, rty);
        let recursion = self.fn_recursion(id, f, &fty, arity)?;
        self.f.answer = f.ret.clone();
        self.f.ret = f.ret.clone();
        let FnBody::Exec(body_e) = &f.body else { return internal(span, "exec function without body") };
        let slice_params = self.slice_params(f);
        let body = self.param_bound_facts(&slice_params, 0, span, &mut |s| s.param_inv_facts(f, 0, span, &mut |s| s.bind_params(&pending, 0, span, &mut |s| s.expr(body_e, &mut |s, v| Ok(v.at(s.depth()))))))?;
        let lam = lam_tele(&binders, body);
        let failed = self.f.failed;
        let opaque = self.f.opaque;
        let g = self.add_definition(&name, DefKind::Exec, Some(id), fty, lam, recursion, arity, opaque, failed, span)?;
        self.globals.insert(id, ItemGlobal::Def(g));
        if f.ensures.is_some() {
            if let Err(e) = self.ensures_def(id, f, g) {
                self.item_failed(id, e);
            }
        }
        // `f::refines` (DESIGN.md §15.2), unless a proof item proves it
        self.refines_after_fn(id, f, g);
        Ok(())
    }

    /// Levels and element types of the slice-typed parameters.
    pub fn slice_params(&self, f: &FnDef) -> Vec<(u32, Ty)> {
        f.params
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.ghost)
            .filter_map(|(i, p)| match p.ty.peel_refs() {
                Ty::Slice(e) => Some((f.generics.len() as u32 + i as u32, (**e).clone())),
                _ => None,
            })
            .collect()
    }

    /// `ISIZE_MAX` bound facts for slice parameters (§3.2).
    pub fn param_bound_facts(&mut self, ps: &[(u32, Ty)], i: usize, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let Some((lvl, e)) = ps.get(i).cloned() else { return k(self) };
        self.slice_bound_fact(&e, lvl, span, &mut |s| s.param_bound_facts(ps, i + 1, span, k))
    }

    /// Binds parameters with non-trivial patterns.
    pub fn bind_params(&mut self, pending: &[(u32, &'a Pat)], i: usize, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let Some((lvl, pat)) = pending.get(i) else { return k(self) };
        let v = Val::new(self.f.scope.var(*lvl), self.depth());
        self.bind_irrefutable(pat, v, span, &mut |s| s.bind_params(pending, i + 1, span, k))
    }

    /// The recursion mode of a function (and its `RecInfo`).
    fn fn_recursion(&mut self, id: ItemId, f: &'a FnDef, fty: &Tm, arity: u32) -> R<Recursion> {
        if f.recursion == crate::hir::Recursion::None {
            return Ok(Recursion::None);
        }
        let (m, w) = match &f.decreases {
            Some(dec) => {
                let m = self.pure_expr(&dec.measure)?;
                (m, self.width_of(&dec.measure.ty, dec.measure.span)?)
            }
            None => match self.infer_measure(id, f) {
                Some(x) => x,
                None => return unsupported(f.sig_span, "cannot infer a termination measure; add `#[decreases(e)]` (§4.2)"),
            },
        };
        self.f.rec = Some(RecInfo { item: Some(id), ty: fty.clone(), arity, measure: Some((m.clone(), w)) });
        Ok(Recursion::Measure { measure: m })
    }

    /// [`Self::infer_measure`] for other modules (the `ensures` proof of a
    /// recursive function recurses with the function's measure).
    pub fn infer_measure_pub(&self, id: ItemId, f: &'a FnDef) -> Option<(Tm, Width)> {
        self.infer_measure(id, f)
    }

    /// The inferred measure (§4.2), as a term at the telescope depth.
    fn infer_measure(&self, id: ItemId, f: &'a FnDef) -> Option<(Tm, Width)> {
        let body = match &f.body {
            FnBody::Exec(e) | FnBody::Spec(e) => e,
            _ => return None,
        };
        // recursive calls
        struct Calls<'x> {
            id: ItemId,
            out: Vec<&'x [Expr]>,
        }
        impl<'x> Calls<'x> {
            fn go(&mut self, e: &'x Expr) {
                if let ExprKind::Call { callee: Callee::Item(c, _), args } = &e.kind
                    && *c == self.id
                {
                    self.out.push(args);
                }
                walk_children(e, &mut |x| self.go(x));
            }
        }
        let mut calls = Calls { id, out: vec![] };
        calls.go(body);
        // slice rest bindings: local → scrutinee local
        let mut rest_of: HashMap<LocalId, LocalId> = HashMap::new();
        collect_rest(body, &mut rest_of);
        // recursion on the fields of a recursive spec type (SEMANTICS.md §13.9)
        if let Some(m) = self.size_measure(&f.params, f.generics.len(), &calls.out, &super::recursive::expr_field_bindings(self.krate, body)) {
            return Some(m);
        }
        for (j, p) in f.params.iter().enumerate() {
            let PatKind::Binding { local, sub: None, .. } = &p.pat.kind else { continue };
            if p.ghost {
                continue;
            }
            let lvl = f.generics.len() as u32 + j as u32;
            let var = self.f.scope.var(lvl);
            let ok = !calls.out.is_empty()
                && calls.out.iter().all(|args| {
                    let Some(a) = args.get(j) else { return false };
                    let a = Elab::peel(a);
                    match (&p.ty.peel_refs(), &a.kind) {
                        (Ty::Uint(_) | Ty::Nat, ExprKind::Binary(BinOp::Sub, x, y)) => matches!(&Elab::peel(x).kind, ExprKind::Local(l) if l == local) && matches!(&y.kind, ExprKind::Lit(Lit::Int(k)) if *k >= 1),
                        (Ty::Slice(_) | Ty::Seq(_), ExprKind::Local(t)) => rest_of.get(t) == Some(local),
                        _ => false,
                    }
                });
            if ok {
                return match p.ty.peel_refs() {
                    Ty::Uint(u) => Some((var, u.width())),
                    Ty::Nat => Some((var, Width::Int)),
                    Ty::Slice(_) => Some((mk::fst(var), Width::Usize)),
                    Ty::Seq(e) => {
                        let et = self.ty(e, p.span).ok()?;
                        Some((mk::apps(mk::global(self.p.g("seq::len")), [(Rel::Rel, et), (Rel::Rel, var)]), Width::Int))
                    }
                    _ => None,
                };
            }
        }
        None
    }

    fn spec_fn(&mut self, id: ItemId, f: &'a FnDef) -> R<()> {
        let it = self.krate.item(id);
        let name = it.path.to_string();
        let span = it.span;
        self.f = FnState::new(name.clone(), Some(id), &f.locals, span);
        self.f.fdef = Some(f);
        let (mut binders, pending) = self.fn_params(f, span)?;
        self.fn_requires(f, &mut binders, Rel::Irr)?;
        let arity = self.depth();
        let rty = if f.ret == Ty::Prop { mk::ty() } else { self.ty(&f.ret, span)? };
        let fty = pi_tele(&binders, rty);
        let recursion = self.fn_recursion(id, f, &fty, arity)?;
        self.f.answer = f.ret.clone();
        self.f.ret = f.ret.clone();
        let FnBody::Spec(body_e) = &f.body else { return internal(span, "spec function without body") };
        let prop = f.ret == Ty::Prop;
        // the `Nat` parameters and the `Nat` components of the others
        // (fields of spec structs, tuple components; S2)
        let mut nat_params: Vec<Val> = Vec::new();
        for (i, p) in f.params.iter().enumerate() {
            let x = self.f.scope.var(f.generics.len() as u32 + i as u32);
            for c in self.nat_components(&p.ty, x, span, 0)? {
                nat_params.push(Val::new(c, self.depth()));
            }
        }
        let body = self.nat_guards(&nat_params, 0, &f.ret, span, &mut |s| s.param_inv_facts(f, 0, span, &mut |s| s.bind_params(&pending, 0, span, &mut |s| if prop { s.prop(body_e) } else { s.expr(body_e, &mut |s, v| Ok(v.at(s.depth()))) })))?;
        let lam = lam_tele(&binders, body);
        let failed = self.f.failed;
        // a model function (layered proofs) is opaque in proofs, like
        // `#[opaque]`: the lockstep steps it, a proof unfolds it by name —
        // evaluation never unfolds the code's shape into a goal
        let opaque = f.spec.opaque.is_some() || self.krate.in_model_module(id);
        let g = self.add_definition(&name, DefKind::Spec, Some(id), fty, lam, recursion, arity, opaque, failed, span)?;
        self.globals.insert(id, ItemGlobal::Def(g));
        // spec closure (DESIGN.md §15.1)
        self.spec_item_closure(id, g);
        // the implicit `0 <= result` facts of a `Nat`-valued result
        if !failed && !prop {
            self.nat_range_def(id, f, g);
        }
        Ok(())
    }

    /// The `Nat` parameters of a spec function (levels `ps`) guard its
    /// body (§4.1, SEMANTICS.md §13.5): `if 0 ≤ n { body } else { d }` per
    /// parameter, with the default `d` of the result type. Every `Nat`
    /// argument is non-negative by construction (the partial `Nat`
    /// constructions carry obligations), so the guard never changes the
    /// meaning; inside, `0 ≤ n` is a fact (for `n - 1` under `n != 0`, for
    /// measures) while callers prove nothing — no proof sits in a call's
    /// arguments, so rewriting and case splits over the argument keep their
    /// motives well typed. Without a default (a type parameter) there is no
    /// guard and no fact.
    ///
    /// `ps` are the guarded `Nat` values: the parameters, and the `Nat`
    /// components of the other parameters ([`Elab::nat_components`]).
    pub fn nat_guards(&mut self, ps: &[Val], i: usize, ret: &Ty, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let Some(xv) = ps.get(i) else { return k(self) };
        let rty = if *ret == Ty::Prop { mk::ty() } else { self.ty(ret, span)? };
        let Some(default) = self.default_of(&rty) else { return k(self) };
        let answer = if *ret == Ty::Prop { Answer::Prop } else { Answer::Ty(ret.clone()) };
        let x = xv.at(self.depth());
        let c = mk::prim(PrimOp::Le(Width::Int), vec![mk::lit(Width::Int, 0u8), x], vec![]);
        let d0 = self.depth();
        self.if_then_else(c, &answer, span, &mut |s, b| {
            if b {
                s.nat_guards(ps, i + 1, ret, span, k)
            } else {
                Ok(shift(&default, (s.depth() - d0) as i64))
            }
        })
    }

    /// The `Nat` components of a value `t : ty` (a term at the current
    /// depth): `t` itself for `Nat`, and recursively the components of a
    /// tuple and the fields of a struct (a few levels deep). Their bound
    /// `0 ≤ c` is the type bound of `Nat` (§4.1) carried through data (S1's
    /// "For S2" note): a guard of spec functions, a hypothesis of lemmas,
    /// laws and proofs and of quantifiers — like S1's `Nat` parameters, and
    /// unlike an explicit invariant not part of the kernel type (a spec
    /// value carries no proof, so the provers' case analysis can generalize
    /// over its fields).
    pub fn nat_components(&self, ty: &Ty, t: Tm, span: Span, depth: u32) -> R<Vec<Tm>> {
        if depth > 3 {
            return Ok(vec![]);
        }
        match ty.peel_refs() {
            Ty::Nat => Ok(vec![t]),
            Ty::Tuple(ts) if !ts.is_empty() => {
                let (ind, params) = self.ind_of(ty, span)?;
                let mut out = Vec::new();
                for (i, c) in ts.iter().enumerate() {
                    if !c.is_ghost_only() {
                        continue;
                    }
                    let fty = self.ty(c, span)?;
                    let comp = self.proj(ind, params.clone(), t.clone(), i, ts.len(), fty);
                    out.extend(self.nat_components(c, comp, span, depth + 1)?);
                }
                Ok(out)
            }
            Ty::Adt(id, args) => {
                let ItemKind::Struct(sd) = &self.krate.item(*id).kind else { return Ok(vec![]) };
                if !sd.fields.iter().any(|f| f.ty.is_ghost_only()) {
                    return Ok(vec![]);
                }
                let (ind, params) = self.ind_of(ty, span)?;
                let mut out = Vec::new();
                for (j, f) in sd.fields.iter().enumerate() {
                    let fh = f.ty.subst(args);
                    if !fh.is_ghost_only() {
                        continue;
                    }
                    let fty = self.ty(&fh, span)?;
                    let comp = self.proj(ind, params.clone(), t.clone(), j, sd.fields.len(), fty);
                    out.extend(self.nat_components(&fh, comp, span, depth + 1)?);
                }
                Ok(out)
            }
            _ => Ok(vec![]),
        }
    }

    /// Whether a `requires`/`ensures` of `f` has a quantifier whose binder
    /// type holds a `Nat` inside a container ([`Elab::nat_in_container`]).
    fn contract_quantifies_over_nat_containers(&self, f: &FnDef) -> bool {
        struct V<'e, 'a> {
            el: &'e Elab<'a>,
            f: &'e FnDef,
            found: bool,
        }
        impl Visitor for V<'_, '_> {
            fn expr(&mut self, e: &Expr) {
                if let ExprKind::Quant { binders, .. } = &e.kind
                    && binders.iter().any(|b| self.f.locals.get(b.0 as usize).is_some_and(|d| self.el.nat_in_container(&d.ty)))
                {
                    self.found = true;
                }
                visit::walk_expr(self, e);
            }
        }
        let mut v = V { el: self, f, found: false };
        for r in &f.requires {
            v.expr(r);
        }
        if let Some(en) = &f.ensures {
            v.expr(&en.prop);
        }
        v.found
    }

    /// Whether a value of type `ty` holds a `Nat` inside a sequence, array,
    /// slice, `Option` or enum (possibly under tuple components and struct
    /// fields).
    pub fn nat_in_container(&self, ty: &Ty) -> bool {
        fn go(el: &Elab, ty: &Ty, depth: u32) -> bool {
            if depth > 16 {
                return false;
            }
            match ty.peel_refs() {
                Ty::Tuple(ts) => ts.iter().any(|t| go(el, t, depth + 1)),
                Ty::Array(t, _) | Ty::Slice(t) | Ty::Option(t) | Ty::Seq(t) => el.holds_nat(t),
                Ty::Adt(id, args) => match &el.krate.item(*id).kind {
                    ItemKind::Struct(sd) => sd.fields.iter().any(|f| go(el, &f.ty.subst(args), depth + 1)),
                    ItemKind::Enum(_) => el.holds_nat(ty),
                    _ => false,
                },
                _ => false,
            }
        }
        go(self, ty, 0)
    }

    /// Whether a value of type `ty` holds a `Nat` anywhere: the value, a
    /// tuple component, a struct field, a sequence or array element, an
    /// `Option` or enum payload, recursively (each ADT visited once per
    /// path: a recursive type is decided by its other fields).
    pub fn holds_nat(&self, ty: &Ty) -> bool {
        fn go(el: &Elab, ty: &Ty, seen: &mut Vec<ItemId>) -> bool {
            match ty.peel_refs() {
                Ty::Nat => true,
                Ty::Tuple(ts) => ts.iter().any(|t| go(el, t, seen)),
                Ty::Array(t, _) | Ty::Slice(t) | Ty::Option(t) | Ty::Seq(t) => go(el, t, seen),
                Ty::Adt(id, args) => {
                    if seen.contains(id) {
                        return false;
                    }
                    seen.push(*id);
                    let r = match &el.krate.item(*id).kind {
                        ItemKind::Struct(sd) => sd.fields.iter().any(|f| go(el, &f.ty.subst(args), seen)),
                        ItemKind::Enum(ed) => ed.variants.iter().any(|v| v.fields.iter().any(|f| go(el, &f.ty.subst(args), seen))),
                        _ => false,
                    };
                    seen.pop();
                    r
                }
                _ => false,
            }
        }
        go(self, ty, &mut Vec::new())
    }

    /// The type bounds of the `Nat`s held by a value `t : ty` (a term at
    /// the current depth), as propositions at the current depth
    /// (SEMANTICS.md §13.5): `0 ≤ c` for each `Nat` component `c` outside
    /// containers (the value itself, tuple components, struct fields,
    /// recursively), and — with `deep` — one well-formedness proposition
    /// for each component that holds `Nat`s inside a container:
    ///
    /// * `Seq<T>`, `[T; N]`, `&[T]`: `ghost::seq_all ⟦T⟧ (λv. wf_T v) l`
    ///   for the list `l` (every element well formed);
    /// * `Option<T>`: `match t { None => Unit, Some(v) => wf_T v }`;
    /// * an enum: `match t { C_i(x̄) => wf(x̄) }` (each payload);
    ///
    /// where `wf_T v` is the conjunction (`Σ`) of `v`'s own bounds. These
    /// are the hypotheses of quantified variables (a `Π` for `forall`, a
    /// `Σ` conjunct for `exists`) and of law and proof parameters, so the
    /// kernel statement quantifies over exactly the values the source's
    /// types allow. A `Nat` inside a recursive type has no finite
    /// well-formedness term: an error (write `Int` and state the bound).
    pub fn nat_bounds(&mut self, ty: &Ty, t: Tm, deep: bool, span: Span) -> R<Vec<Tm>> {
        let mut seen = Vec::new();
        self.nat_bounds_d(ty, t, deep, span, &mut seen)
    }

    fn nat_bounds_d(&mut self, ty: &Ty, t: Tm, deep: bool, span: Span, seen: &mut Vec<ItemId>) -> R<Vec<Tm>> {
        let ty = ty.peel_refs().clone();
        if !self.holds_nat(&ty) {
            return Ok(vec![]);
        }
        let recursive = |me: &Self, id: ItemId| -> R<Vec<Tm>> {
            unsupported(
                span,
                format!(
                    "`{}` holds a `Nat` inside a recursive type: a quantified variable or a law parameter of this type has no well-formedness hypothesis for it; use `Int` in the type and state the bound (`requires(..)`, or inside the quantifier)",
                    me.krate.item(id).path
                ),
            )
        };
        match &ty {
            Ty::Nat => Ok(vec![self.holds(mk::prim(PrimOp::Le(Width::Int), vec![mk::lit(Width::Int, 0u8), t], vec![]))]),
            Ty::Tuple(ts) => {
                let (ind, params) = self.ind_of(&ty, span)?;
                let mut out = Vec::new();
                for (i, c) in ts.iter().enumerate() {
                    if !self.holds_nat(c) {
                        continue;
                    }
                    let fty = self.ty(c, span)?;
                    let comp = self.proj(ind, params.clone(), t.clone(), i, ts.len(), fty);
                    out.extend(self.nat_bounds_d(c, comp, deep, span, seen)?);
                }
                Ok(out)
            }
            Ty::Adt(id, args) if matches!(&self.krate.item(*id).kind, ItemKind::Struct(_)) => {
                if seen.contains(id) {
                    return recursive(self, *id);
                }
                let ItemKind::Struct(sd) = &self.krate.item(*id).kind else { return Ok(vec![]) };
                let fields: Vec<Ty> = sd.fields.iter().map(|f| f.ty.subst(args)).collect();
                let (ind, params) = self.ind_of(&ty, span)?;
                seen.push(*id);
                let mut out = Vec::new();
                for (j, fh) in fields.iter().enumerate() {
                    if !self.holds_nat(fh) {
                        continue;
                    }
                    let fty = self.ty(fh, span)?;
                    let comp = self.proj(ind, params.clone(), t.clone(), j, fields.len(), fty);
                    match self.nat_bounds_d(fh, comp, deep, span, seen) {
                        Ok(b) => out.extend(b),
                        Err(e) => {
                            seen.pop();
                            return Err(e);
                        }
                    }
                }
                seen.pop();
                Ok(out)
            }
            _ if !deep => Ok(vec![]),
            Ty::Seq(e) => Ok(vec![self.seq_all_bound(e, t, span, seen)?]),
            Ty::Array(e, _) => Ok(vec![self.seq_all_bound(e, mk::fst(t), span, seen)?]),
            Ty::Slice(e) => Ok(vec![self.seq_all_bound(e, mk::fst(mk::snd(t)), span, seen)?]),
            Ty::Option(a) => {
                let at = self.ty(a, span)?;
                let atv = self.eval(&at)?;
                let saved = self.f.scope.clone();
                self.push_v("v", Rel::Rel, atv);
                let inner = self.nat_bounds_d(a, mk::var(0), true, span, seen);
                self.f.scope = saved;
                let some = self.conj(inner?);
                let none = mk::ind(self.p.unit, vec![]);
                let arms = vec![sandblaster_kernel::term::Arm { names: vec![], body: none }, sandblaster_kernel::term::Arm { names: vec![Rc::from("v")], body: some }];
                Ok(vec![Rc::new(Term::Match { ind: self.p.option, params: vec![at], scrut: t, motive: mk::ty(), arms })])
            }
            Ty::Adt(id, args) => {
                let ItemKind::Enum(ed) = &self.krate.item(*id).kind else { return Ok(vec![]) };
                if seen.contains(id) {
                    return recursive(self, *id);
                }
                let variants: Vec<Vec<(String, Ty)>> = ed.variants.iter().map(|v| v.fields.iter().enumerate().map(|(j, f)| (f.name.clone().unwrap_or_else(|| format!("x{j}")), f.ty.subst(args))).collect()).collect();
                let (ind, params) = self.ind_of(&ty, span)?;
                seen.push(*id);
                let mut arms = Vec::new();
                for (ci, fs) in variants.iter().enumerate() {
                    if self.ctor_nfields(ind, ci) != Some(fs.len()) {
                        seen.pop();
                        return internal(span, format!("the payload of a variant of `{}` does not match its kernel constructor", self.krate.item(*id).path));
                    }
                    let saved = self.f.scope.clone();
                    let d0 = self.depth();
                    let mut res: R<Vec<Tm>> = Ok(vec![]);
                    for (name, fh) in fs {
                        match self.ty(fh, span).and_then(|ft| self.eval(&ft)) {
                            Ok(fv) => {
                                self.push_v(name, Rel::Rel, fv);
                            }
                            Err(e) => {
                                res = Err(e);
                                break;
                            }
                        }
                    }
                    if res.is_ok() {
                        let nf = fs.len() as u32;
                        let mut all = Vec::new();
                        for (j, (_, fh)) in fs.iter().enumerate() {
                            // field `j` at level `d0 + j`
                            match self.nat_bounds_d(fh, mk::var(nf - 1 - j as u32), true, span, seen) {
                                Ok(b) => all.extend(b),
                                Err(e) => {
                                    res = Err(e);
                                    break;
                                }
                            }
                        }
                        if res.is_ok() {
                            res = Ok(all);
                        }
                    }
                    self.f.scope = saved;
                    debug_assert_eq!(self.depth(), d0);
                    let bounds = match res {
                        Ok(b) => b,
                        Err(e) => {
                            seen.pop();
                            return Err(e);
                        }
                    };
                    let body = self.conj(bounds);
                    arms.push(sandblaster_kernel::term::Arm { names: fs.iter().map(|(n, _)| Rc::from(n.as_str())).collect(), body });
                }
                seen.pop();
                Ok(vec![Rc::new(Term::Match { ind, params, scrut: t, motive: mk::ty(), arms })])
            }
            _ => Ok(vec![]),
        }
    }

    /// `ghost::seq_all ⟦e⟧ (λv. wf_e v) l` for a list `l` of `e`s (a term at
    /// the current depth).
    fn seq_all_bound(&mut self, e: &Ty, l: Tm, span: Span, seen: &mut Vec<ItemId>) -> R<Tm> {
        let et = self.ty(e, span)?;
        let etv = self.eval(&et)?;
        let saved = self.f.scope.clone();
        self.push_v("v", Rel::Rel, etv);
        let inner = self.nat_bounds_d(e, mk::var(0), true, span, seen);
        self.f.scope = saved;
        let body = self.conj(inner?);
        let all = self.env.lookup_global("ghost::seq_all").ok_or_else(|| ElabError { span, msg: "ghost library `ghost::seq_all` is missing".into(), kind: ErrKind::Internal })?;
        Ok(mk::apps(mk::global(all), [(Rel::Rel, et.clone()), (Rel::Rel, mk::lam("v", Rel::Rel, et, body)), (Rel::Rel, l)]))
    }

    /// The conjunction of propositions at the current depth: `Σ(_ : b₀).
    /// Σ(_ : b₁). … bₙ` (`Unit` for none).
    fn conj(&self, bs: Vec<Tm>) -> Tm {
        let mut it = bs.into_iter().rev();
        let Some(last) = it.next() else { return mk::ind(self.p.unit, vec![]) };
        it.fold(last, |acc, b| mk::sigma("h", Rel::Rel, b, shift(&acc, 1)))
    }

    /// Answer helper for callers that need a HIR answer type.
    pub fn answer_ty(&self) -> Answer {
        Answer::Ty(self.f.answer.clone())
    }

    /// Switches to relevant-proof mode for lemma bodies.
    pub fn proof_mode(&mut self) {
        self.f.mode = Mode::Proof;
    }
}

/// `Π binders. r`.
pub fn pi_tele(binders: &[TBinder], r: Tm) -> Tm {
    binders.iter().rev().fold(r, |acc, b| mk::pi(&b.name, b.rel, b.ty.clone(), acc))
}

/// `λ binders. body`.
pub fn lam_tele(binders: &[TBinder], body: Tm) -> Tm {
    binders.iter().rev().fold(body, |acc, b| mk::lam(&b.name, b.rel, b.ty.clone(), acc))
}

/// Head and arguments of an application spine.
pub fn spine(t: &Tm) -> (Tm, Vec<Tm>) {
    let mut args = Vec::new();
    let mut h = t.clone();
    while let Term::App { fun, arg, .. } = &*h.clone() {
        args.push(arg.clone());
        h = fun.clone();
    }
    args.reverse();
    (h, args)
}

/// [`walk_children`] for other modules.
pub fn walk_children_pub<'x>(e: &'x Expr, f: &mut dyn FnMut(&'x Expr)) {
    walk_children(e, f)
}

/// Calls `f` on the direct subexpressions of `e`.
fn walk_children<'x>(e: &'x Expr, f: &mut dyn FnMut(&'x Expr)) {
    match &e.kind {
        ExprKind::Lit(_) | ExprKind::Local(_) | ExprKind::Const(_) | ExprKind::BuiltinConst(_) | ExprKind::Unreachable => {}
        ExprKind::Call { args, .. } => args.iter().for_each(f),
        ExprKind::Adt { fields, base, .. } => {
            fields.iter().for_each(|(_, x)| f(x));
            if let Some(b) = base {
                f(b);
            }
        }
        ExprKind::Tuple(es) | ExprKind::Array(es) => es.iter().for_each(f),
        ExprKind::Repeat { elem, .. } => f(elem),
        ExprKind::Field { base, .. } => f(base),
        ExprKind::Index { base, index } => {
            f(base);
            f(index);
        }
        ExprKind::SliceRange { base, lo, hi } => {
            f(base);
            if let Some(x) = lo {
                f(x);
            }
            if let Some(x) = hi {
                f(x);
            }
        }
        ExprKind::Unary(_, x) | ExprKind::Cast(x, _) | ExprKind::Ref(x) | ExprKind::Deref(x) | ExprKind::Coerce(_, x) | ExprKind::Try(x) | ExprKind::PropNot(x) => f(x),
        ExprKind::Binary(_, a, b) | ExprKind::PropEq(a, b) | ExprKind::PropNe(a, b) | ExprKind::PropAnd(a, b) | ExprKind::PropOr(a, b) | ExprKind::Implies(a, b) | ExprKind::Iff(a, b) => {
            f(a);
            f(b);
        }
        ExprKind::If { cond, then, els } => {
            f(cond);
            f(then);
            if let Some(x) = els {
                f(x);
            }
        }
        ExprKind::Match { scrut, arms, .. } => {
            f(scrut);
            for a in arms {
                if let Some(g) = &a.guard {
                    f(g);
                }
                f(&a.body);
            }
        }
        ExprKind::Block(b) => {
            for s in &b.stmts {
                match &s.kind {
                    StmtKind::Let { init, els, .. } => {
                        f(init);
                        if let Some(bl) = els {
                            for s2 in &bl.stmts {
                                if let StmtKind::Expr(x) = &s2.kind {
                                    f(x);
                                }
                            }
                            if let Some(t) = &bl.tail {
                                f(t);
                            }
                        }
                    }
                    StmtKind::Expr(x) => f(x),
                    StmtKind::Assign { value, .. } | StmtKind::CompoundAssign { value, .. } => f(value),
                    StmtKind::CopyFromSlice { src, .. } => f(src),
                    StmtKind::Proof(_) => {}
                }
            }
            if let Some(t) = &b.tail {
                f(t);
            }
        }
        ExprKind::Return(x) => {
            if let Some(x) = x {
                f(x);
            }
        }
        ExprKind::Loop(l) => {
            for s in &l.body.stmts {
                if let StmtKind::Expr(x) = &s.kind {
                    f(x);
                }
            }
        }
        ExprKind::Quant { body, .. } | ExprKind::Lambda { body, .. } => f(body),
        ExprKind::Apply { fun, args } => {
            f(fun);
            args.iter().for_each(f);
        }
    }
}

/// Records `rest @ ..` bindings of slice patterns (with ≥ 1 fixed element)
/// whose scrutinee is a local.
fn collect_rest(e: &Expr, out: &mut HashMap<LocalId, LocalId>) {
    fn pat_rest(p: &Pat, scrut: LocalId, out: &mut HashMap<LocalId, LocalId>) {
        match &p.kind {
            PatKind::Deref { pat, .. } => pat_rest(pat, scrut, out),
            PatKind::Or(ps) => ps.iter().for_each(|x| pat_rest(x, scrut, out)),
            PatKind::Slice { prefix, rest: Some(Some(r)), suffix } if prefix.len() + suffix.len() >= 1 => {
                if let PatKind::Binding { local, .. } = &r.kind {
                    out.insert(*local, scrut);
                }
            }
            _ => {}
        }
    }
    struct V<'o>(&'o mut HashMap<LocalId, LocalId>);
    impl Visitor for V<'_> {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Match { scrut, arms, .. } = &e.kind
                && let ExprKind::Local(x) = &Elab::peel(scrut).kind
            {
                for a in arms {
                    pat_rest(&a.pat, *x, self.0);
                }
            }
            visit::walk_expr(self, e);
        }
        fn stmt(&mut self, s: &Stmt) {
            if let StmtKind::Let { pat, init, .. } = &s.kind
                && let ExprKind::Local(x) = &Elab::peel(init).kind
            {
                pat_rest(pat, *x, self.0);
            }
            visit::walk_stmt(self, s);
        }
    }
    V(out).expr(e);
}
