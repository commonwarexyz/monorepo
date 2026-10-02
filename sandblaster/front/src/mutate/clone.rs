//! Incremental re-verification sets (DESIGN.md §15.9 item 2): which items
//! a mutant must re-check, and the extended crate that re-checks them.
//!
//! A mutant of item `x` re-elaborates `x` and every item whose meaning or
//! proof depends on it — its **closure**: the reverse `Refs` closure of
//! `x` ([`crate::elab::order::refs`], §15 edges included), with a law and
//! its `#[proof]` item, and an exec function and its `#[proof(refines)]`
//! item, always together. For a mutant of **code** (an exec function or
//! constant) every dependent re-checks: callers (their safety obligations
//! and contracts), laws, lemmas, proofs, spec functions (legacy ones that
//! call code) and examples. For a mutant of a **spec** item only ghost
//! items propagate (spec functions, lemmas, laws, proofs); an exec function
//! whose `#[refines]` target, contract or examples mention the closure is
//! re-checked as a leaf (does the implementation still agree?), and its
//! callers are not (their code did not change).
//!
//! Each item of the closure is **cloned** under a fresh path
//! (`name__mutK`) with every reference into the closure redirected to the
//! clone, and appended to the crate after the original items (the same
//! extension `elab::generated::resume` uses: the first items keep their
//! [`ItemId`]s). The clones are ordinary items, so the elaborator gives
//! them exactly the meaning and checks of the originals — obligations,
//! `ensures`, refinement lemmas, examples and vector files — in one
//! elaboration per batch whose other items are the unchanged crate.
//! Cloned laws carry `#[definitional]` (a marker that keeps them out of the
//! §15.5 section computation, which is about the original crate; nothing
//! else about a law changes).
//!
//! Synthesized **checkers** make statements decidable by evaluation: for a
//! cloned law `fn l(x̄) { requires(r̄); ensures(e); }` the spec function
//! `l__mutK__chk(x̄) -> bool { !(r₁ && …) || e }`, and for a function with
//! `requires` the spec function `f__req(x̄) -> bool { r₁ && … }` (every
//! proposition read as a `bool`, `==` on non-scalar types as `eqb`; a
//! statement with a quantifier has no checker).

use std::collections::{BTreeSet, HashMap};

use crate::hir::*;
use crate::span::Span;

/// Whether a mutant changes code or a specification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// An exec function or exec constant (implementation mutant).
    Impl,
    /// A spec function or spec constant (spec mutant, §15.7, §15.1 LR8).
    Spec,
}

/// Who refers to whom: `rev[x]` are the items whose `Refs` contain `x`.
pub fn reverse_refs(krate: &Crate) -> HashMap<ItemId, BTreeSet<ItemId>> {
    let mut rev: HashMap<ItemId, BTreeSet<ItemId>> = HashMap::new();
    for it in &krate.items {
        if !matches!(it.kind, ItemKind::Fn(_) | ItemKind::Const(_)) {
            continue;
        }
        for r in crate::elab::order::refs(krate, it.id) {
            rev.entry(r).or_default().insert(it.id);
        }
    }
    rev
}

fn is_exec(krate: &Crate, id: ItemId) -> bool {
    match &krate.item(id).kind {
        ItemKind::Fn(f) => f.kind == FnKind::Exec,
        ItemKind::Const(_) => !krate.item(id).ghost,
        _ => false,
    }
}

/// Proof items that are about the original crate only (never cloned):
/// `#[proof(complete = f)]` (sections are not re-computed for clones) and
/// `#[proof(view_inj = T)]` (types are not cloned).
fn never_cloned(krate: &Crate, id: ItemId) -> bool {
    match &krate.item(id).kind {
        ItemKind::Fn(f) => f.kind == FnKind::Proof && f.spec.proof_of.is_some_and(|p| matches!(p.kind, ProofKind::Complete | ProofKind::ViewInj)),
        ItemKind::Const(_) => false,
        _ => true,
    }
}

/// The items a mutant of `root` must re-check (see the module docs),
/// `root` included, sorted by id. `None` when more than `cap` items.
pub fn closure(krate: &Crate, rev: &HashMap<ItemId, BTreeSet<ItemId>>, root: ItemId, target: Target, cap: usize) -> Option<BTreeSet<ItemId>> {
    let mut set: BTreeSet<ItemId> = BTreeSet::new();
    // (item, propagate to its referrers)
    let mut work: Vec<(ItemId, bool)> = vec![(root, true)];
    while let Some((x, prop)) = work.pop() {
        if set.contains(&x) || never_cloned(krate, x) {
            continue;
        }
        set.insert(x);
        if set.len() > cap {
            return None;
        }
        // the pairs that are proven together
        if let ItemKind::Fn(f) = &krate.item(x).kind {
            if let Some(LawProof::Item(p)) = f.law_proof {
                work.push((p, prop));
            }
            if let Some(l) = f.proves {
                work.push((l, prop));
            }
            if let Some(p) = f.spec.refines_proof {
                work.push((p, prop));
            }
            if let Some(po) = f.spec.proof_of
                && po.kind == ProofKind::Refines
            {
                // the refinement it proves is re-proven for the clone
                work.push((po.target, target == Target::Impl));
            }
        }
        if !prop {
            continue;
        }
        let x_spec = !is_exec(krate, x);
        for &r in rev.get(&x).into_iter().flatten() {
            if set.contains(&r) {
                continue;
            }
            match target {
                Target::Impl => work.push((r, true)),
                Target::Spec => {
                    if is_exec(krate, r) {
                        // an implementation's contract / refinement over the
                        // spec closure: re-checked, not propagated (its code
                        // is unchanged); an ordering edge to a proof item is
                        // not a reference
                        let via_proof = matches!(&krate.item(x).kind, ItemKind::Fn(f) if f.kind == FnKind::Proof);
                        if x_spec && !via_proof {
                            work.push((r, false));
                        }
                    } else {
                        work.push((r, true));
                    }
                }
            }
        }
    }
    Some(set)
}

// ---------------------------------------------------------------------------
// Redirection of references
// ---------------------------------------------------------------------------

fn remap_id(map: &HashMap<ItemId, ItemId>, id: &mut ItemId) {
    if let Some(n) = map.get(id) {
        *id = *n;
    }
}

/// Redirects every item reference of an expression (everywhere: ghost
/// code, loop invariants and `proof!` blocks included).
pub fn remap_expr(e: &mut Expr, map: &HashMap<ItemId, ItemId>) {
    match &mut e.kind {
        ExprKind::Lit(_) | ExprKind::Local(_) | ExprKind::BuiltinConst(_) | ExprKind::Unreachable => {}
        ExprKind::Const(id) => remap_id(map, id),
        ExprKind::Call { callee, args } => {
            if let Callee::Item(id, _) = callee {
                remap_id(map, id);
            }
            args.iter_mut().for_each(|a| remap_expr(a, map));
        }
        ExprKind::Adt { fields, base, .. } => {
            fields.iter_mut().for_each(|(_, x)| remap_expr(x, map));
            if let Some(b) = base {
                remap_expr(b, map);
            }
        }
        ExprKind::Tuple(es) | ExprKind::Array(es) => es.iter_mut().for_each(|x| remap_expr(x, map)),
        ExprKind::Repeat { elem, .. } => remap_expr(elem, map),
        ExprKind::Field { base, .. } => remap_expr(base, map),
        ExprKind::Index { base, index } => {
            remap_expr(base, map);
            remap_expr(index, map);
        }
        ExprKind::SliceRange { base, lo, hi } => {
            remap_expr(base, map);
            if let Some(l) = lo {
                remap_expr(l, map);
            }
            if let Some(h) = hi {
                remap_expr(h, map);
            }
        }
        ExprKind::Unary(_, x) | ExprKind::Cast(x, _) | ExprKind::Ref(x) | ExprKind::Deref(x) | ExprKind::Coerce(_, x) | ExprKind::Try(x) | ExprKind::PropNot(x) => remap_expr(x, map),
        ExprKind::Binary(_, a, b) | ExprKind::PropEq(a, b) | ExprKind::PropNe(a, b) | ExprKind::PropAnd(a, b) | ExprKind::PropOr(a, b) | ExprKind::Implies(a, b) | ExprKind::Iff(a, b) => {
            remap_expr(a, map);
            remap_expr(b, map);
        }
        ExprKind::If { cond, then, els } => {
            remap_expr(cond, map);
            remap_expr(then, map);
            if let Some(x) = els {
                remap_expr(x, map);
            }
        }
        ExprKind::Match { scrut, arms, .. } => {
            remap_expr(scrut, map);
            for a in arms {
                if let Some(g) = &mut a.guard {
                    remap_expr(g, map);
                }
                remap_expr(&mut a.body, map);
            }
        }
        ExprKind::Block(b) => remap_block(b, map),
        ExprKind::Return(x) => {
            if let Some(x) = x {
                remap_expr(x, map);
            }
        }
        ExprKind::Loop(l) => {
            match &mut l.kind {
                LoopKind::ForRange { lo, hi, .. } => {
                    remap_expr(lo, map);
                    remap_expr(hi, map);
                }
                LoopKind::While { cond } => remap_expr(cond, map),
            }
            l.info.invariants.iter_mut().for_each(|x| remap_expr(x, map));
            if let Some(d) = &mut l.info.decreases {
                remap_expr(d, map);
            }
            remap_block(&mut l.body, map);
        }
        ExprKind::Quant { body, .. } | ExprKind::Lambda { body, .. } => remap_expr(body, map),
        ExprKind::Apply { fun, args } => {
            remap_expr(fun, map);
            args.iter_mut().for_each(|a| remap_expr(a, map));
        }
    }
}

fn remap_block(b: &mut Block, map: &HashMap<ItemId, ItemId>) {
    for s in &mut b.stmts {
        match &mut s.kind {
            StmtKind::Let { init, els, .. } => {
                remap_expr(init, map);
                if let Some(b) = els {
                    remap_block(b, map);
                }
            }
            StmtKind::Expr(e) => remap_expr(e, map),
            StmtKind::Assign { place, value } | StmtKind::CompoundAssign { place, value, .. } => {
                remap_expr(value, map);
                for p in &mut place.projs {
                    if let Proj::Index(x) = p {
                        remap_expr(x, map);
                    }
                }
            }
            StmtKind::CopyFromSlice { range, src, .. } => {
                if let Some((a, b)) = range {
                    if let Some(a) = a {
                        remap_expr(a, map);
                    }
                    if let Some(b) = b {
                        remap_expr(b, map);
                    }
                }
                remap_expr(src, map);
            }
            StmtKind::Proof(ss) => ss.iter_mut().for_each(|x| remap_script(x, map)),
        }
    }
    if let Some(t) = &mut b.tail {
        remap_expr(t, map);
    }
}

fn remap_script(s: &mut ScriptStmt, map: &HashMap<ItemId, ItemId>) {
    let steps = |ss: &mut Vec<ScriptStmt>| ss.iter_mut().for_each(|x| remap_script(x, map));
    match &mut s.kind {
        ScriptKind::Assert { prop, steps: st } => {
            remap_expr(prop, map);
            if let Some(ss) = st {
                steps(ss);
            }
        }
        ScriptKind::Apply { app, .. } => remap_expr(app, map),
        ScriptKind::Match { scrut, arms } => {
            remap_expr(scrut, map);
            for a in arms {
                steps(&mut a.steps);
            }
        }
        ScriptKind::If { cond, then, els } => {
            remap_expr(cond, map);
            steps(then);
            steps(els);
        }
        ScriptKind::Cases { lo, hi, steps: st, .. } => {
            remap_expr(lo, map);
            remap_expr(hi, map);
            steps(st);
        }
        ScriptKind::Witness(es) => es.iter_mut().for_each(|x| remap_expr(x, map)),
        ScriptKind::UseHyp { args, .. } => args.iter_mut().for_each(|x| remap_expr(x, map)),
        ScriptKind::Unfold(UnfoldTarget::Item(id)) => remap_id(map, id),
        ScriptKind::Unfolding(ts) => {
            for t in ts {
                if let UnfoldTarget::Item(id) = t {
                    remap_id(map, id);
                }
            }
        }
        ScriptKind::Rewrite { eq, motive, .. } => {
            remap_expr(eq, map);
            if let Some((_, m)) = motive {
                remap_expr(m, map);
            }
        }
        ScriptKind::Exact(e) | ScriptKind::Step { call: e } => remap_expr(e, map),
        ScriptKind::Let { value, .. } => remap_expr(value, map),
        ScriptKind::Calc { links, concl, .. } => {
            for l in links {
                remap_expr(&mut l.prop, map);
                if let Some(ss) = &mut l.steps {
                    steps(ss);
                }
            }
            remap_expr(concl, map);
        }
        ScriptKind::Using(ids) => ids.iter_mut().for_each(|id| remap_id(map, id)),
        ScriptKind::Unfold(_) | ScriptKind::Bv | ScriptKind::Follows | ScriptKind::Compute | ScriptKind::Lockstep | ScriptKind::Arithmetic | ScriptKind::Contradiction | ScriptKind::Show | ScriptKind::Todo => {}
    }
}

/// Redirects every reference of a function definition (contracts, body and
/// §15 annotations).
pub fn remap_fn(f: &mut FnDef, map: &HashMap<ItemId, ItemId>) {
    f.requires.iter_mut().for_each(|r| remap_expr(r, map));
    if let Some(en) = &mut f.ensures {
        remap_expr(&mut en.prop, map);
    }
    if let Some(d) = &mut f.decreases {
        remap_expr(&mut d.measure, map);
    }
    // the declared contract the elaborator compares the preconditions with
    if let Some((rs, d)) = &mut f.declared {
        rs.iter_mut().for_each(|r| remap_expr(r, map));
        if let Some(d) = d {
            remap_expr(&mut d.measure, map);
        }
    }
    match &mut f.body {
        FnBody::Exec(e) | FnBody::Spec(e) => remap_expr(e, map),
        FnBody::Script(ss) => ss.iter_mut().for_each(|s| remap_script(s, map)),
        FnBody::Claim => {}
    }
    if let Some(LawProof::Item(p)) = &mut f.law_proof {
        remap_id(map, p);
    }
    if let Some(l) = &mut f.proves {
        remap_id(map, l);
    }
    let a = &mut f.spec;
    if let Some(r) = &mut a.refines {
        remap_id(map, &mut r.spec);
        if let Some(args) = &mut r.args {
            args.iter_mut().for_each(|x| remap_expr(x, map));
        }
        if let Some(d) = &mut r.domain {
            remap_expr(d, map);
        }
    }
    if let Some(p) = &mut a.proof_of {
        remap_id(map, &mut p.target);
    }
    if let Some(p) = &mut a.refines_proof {
        remap_id(map, p);
    }
    for ex in &mut a.examples {
        remap_expr(&mut ex.expr, map);
    }
    if let Some(Some(en)) = &mut a.contract_ensures {
        remap_expr(&mut en.prop, map);
    }
    if let Some(m) = &mut a.mirrors_of {
        remap_id(map, m);
    }
    if let Some((r, _)) = &mut a.reduces_to {
        remap_id(map, r);
    }
    if let Some(fs) = &mut a.fuel_sufficient
        && let Some(s) = &mut fs.spec
    {
        remap_id(map, s);
    }
}

/// The path of a clone: the last segment suffixed.
pub fn clone_path(p: &DefPath, suffix: &str) -> DefPath {
    let mut v = p.0.clone();
    if let Some(l) = v.last_mut() {
        l.push_str(suffix);
    }
    DefPath(v)
}

/// A clone of item `orig` with id `id`, path suffixed, references
/// redirected through `map` (see the module docs).
pub fn clone_item(krate: &Crate, orig: ItemId, id: ItemId, suffix: &str, map: &HashMap<ItemId, ItemId>) -> Item {
    let mut it = krate.item(orig).clone();
    it.id = id;
    it.name.push_str(suffix);
    it.path = clone_path(&it.path, suffix);
    match &mut it.kind {
        ItemKind::Fn(f) => {
            remap_fn(f, map);
            // sections are about the original crate
            f.spec.section_with.clear();
            f.spec.section_span = None;
            f.spec.complete_proof = None;
            if f.kind == FnKind::Law && f.spec.definitional.is_none() {
                f.spec.definitional = Some(Justified { justification: "a mutant's re-check of a law (§15.9); not a hypothesis of any section".into(), span: Span::DUMMY });
            }
        }
        ItemKind::Const(c) => remap_expr(&mut c.init, map),
        _ => {}
    }
    it
}

// ---------------------------------------------------------------------------
// Checkers
// ---------------------------------------------------------------------------

fn scalar(t: &Ty) -> bool {
    matches!(t.peel_refs(), Ty::Bool | Ty::Uint(_) | Ty::Int | Ty::Nat)
}

/// The `bool` reading of a proposition (as `elab::invariant::boolify`, and
/// `==`/`!=` on other types as `eqb`); `None` for quantifiers and
/// propositions without one.
pub fn boolify(e: &Expr) -> Option<Expr> {
    let span = e.span;
    let b = |k: ExprKind| Expr::new(k, Ty::Bool, span);
    Some(match &e.kind {
        ExprKind::Coerce(Coercion::BoolToProp, x) => (**x).clone(),
        ExprKind::PropEq(x, y) | ExprKind::PropNe(x, y) => {
            let eq = matches!(e.kind, ExprKind::PropEq(..));
            if scalar(&x.ty) && scalar(&y.ty) && x.ty.peel_refs() == y.ty.peel_refs() {
                b(ExprKind::Binary(if eq { BinOp::Eq } else { BinOp::Ne }, x.clone(), y.clone()))
            } else if x.ty.peel_refs() == y.ty.peel_refs() && !x.ty.is_ghost_only() || matches!(x.ty.peel_refs(), Ty::Seq(_)) && x.ty.peel_refs() == y.ty.peel_refs() {
                let t = x.ty.peel_refs().clone();
                let call = b(ExprKind::Call { callee: Callee::Ghost(crate::builtins::GhostFn::Eqb, vec![t]), args: vec![(**x).clone(), (**y).clone()] });
                if eq { call } else { b(ExprKind::Unary(UnOp::Not, Box::new(call))) }
            } else {
                return None;
            }
        }
        ExprKind::PropAnd(p, q) => b(ExprKind::Binary(BinOp::And, Box::new(boolify(p)?), Box::new(boolify(q)?))),
        ExprKind::PropOr(p, q) => b(ExprKind::Binary(BinOp::Or, Box::new(boolify(p)?), Box::new(boolify(q)?))),
        ExprKind::PropNot(p) => b(ExprKind::Unary(UnOp::Not, Box::new(boolify(p)?))),
        ExprKind::Implies(p, q) => {
            let np = b(ExprKind::Unary(UnOp::Not, Box::new(boolify(p)?)));
            b(ExprKind::Binary(BinOp::Or, Box::new(np), Box::new(boolify(q)?)))
        }
        ExprKind::Iff(p, q) => b(ExprKind::Binary(BinOp::Eq, Box::new(boolify(p)?), Box::new(boolify(q)?))),
        ExprKind::If { cond, then, els: Some(x) } => b(ExprKind::If { cond: cond.clone(), then: Box::new(boolify(then)?), els: Some(Box::new(boolify(x)?)) }),
        ExprKind::Match { scrut, arms, source } => {
            let arms = arms.iter().map(|a| Some(Arm { pat: a.pat.clone(), guard: a.guard.clone(), body: boolify(&a.body)?, span: a.span })).collect::<Option<Vec<_>>>()?;
            b(ExprKind::Match { scrut: scrut.clone(), arms, source: *source })
        }
        ExprKind::Block(bl) if bl.stmts.is_empty() && bl.tail.is_some() => return boolify(bl.tail.as_ref().unwrap()),
        _ if e.ty == Ty::Bool => e.clone(),
        _ => return None,
    })
}

fn and_all(es: Vec<Expr>, span: Span) -> Expr {
    let mut it = es.into_iter();
    let Some(first) = it.next() else { return Expr::new(ExprKind::Lit(Lit::Bool(true)), Ty::Bool, span) };
    it.fold(first, |a, b| Expr::new(ExprKind::Binary(BinOp::And, Box::new(a), Box::new(b)), Ty::Bool, span))
}

/// A ghost spec function `-> bool` with `f`'s parameters and locals and
/// body `body`.
fn checker_fn(f: &FnDef, body: Expr) -> FnDef {
    let span = body.span;
    FnDef {
        kind: FnKind::Spec,
        owner: None,
        receiver: None,
        generics: vec![],
        lifetimes: vec![],
        impl_block: None,
        impl_lifetimes: vec![],
        impl_self_lts: vec![],
        params: f.params.iter().map(|p| Param { ghost: false, ..p.clone() }).collect(),
        ret: Ty::Bool,
        ret_lts: Lifetimes::default(),
        requires: vec![],
        ensures: None,
        decreases: None,
        declared: None,
        body: FnBody::Spec(Expr::new(ExprKind::Block(Block { stmts: vec![], tail: Some(Box::new(body)), span }), Ty::Bool, span)),
        target_features: vec![],
        feature_set: vec![],
        implements: None,
        specialize: false,
        inline: None,
        must_use: false,
        recursion: Recursion::None,
        law_proof: None,
        proves: None,
        rewrite: false,
        induction: None,
        spec: SpecAnnots::default(),
        locals: f.locals.clone(),
        sig_span: f.sig_span,
        sig_text: f.sig_text.clone(),
    }
}

fn simple_params(f: &FnDef) -> bool {
    f.generics.is_empty() && f.params.iter().all(|p| matches!(p.pat.kind, PatKind::Binding { sub: None, .. }) && !p.ghost)
}

/// The checker of a law (`!(requires) || ensures`), or `None`.
pub fn law_checker(law: &FnDef) -> Option<FnDef> {
    if !simple_params(law) {
        return None;
    }
    let span = law.sig_span;
    let req: Vec<Expr> = law.requires.iter().map(boolify).collect::<Option<_>>()?;
    let ens = match &law.ensures {
        Some(e) => boolify(&e.prop)?,
        None => Expr::new(ExprKind::Lit(Lit::Bool(true)), Ty::Bool, span),
    };
    let hyp = and_all(req, span);
    let not_hyp = Expr::new(ExprKind::Unary(UnOp::Not, Box::new(hyp)), Ty::Bool, span);
    Some(checker_fn(law, Expr::new(ExprKind::Binary(BinOp::Or, Box::new(not_hyp), Box::new(ens)), Ty::Bool, span)))
}

/// The checker of a function's `requires` (`r₁ && …`), or `None`.
pub fn requires_checker(f: &FnDef) -> Option<FnDef> {
    if !simple_params(f) {
        return None;
    }
    let req: Vec<Expr> = f.requires.iter().map(boolify).collect::<Option<_>>()?;
    Some(checker_fn(f, and_all(req, f.sig_span)))
}
