//! Read-only HIR traversal.
//!
//! [`Visitor`] has one hook per node kind; the default implementations call
//! the `walk_*` functions, which visit every child in source order
//! (including ghost code: contracts, proof blocks, loop invariants).
//! Override a hook and call the matching `walk_*` to continue into children.
//!
//! [`walk_fn`] does **not** visit the §15 annotations of a function
//! ([`SpecAnnots`]: refinement arguments, domains, examples): they are not
//! part of the function's own meaning (its body, contracts, recursion).
//! [`walk_fn_spec`] and [`walk_type_spec`] visit them for the passes that
//! need them (dependency order, subset checks).

use crate::hir::*;

pub trait Visitor {
    fn expr(&mut self, e: &Expr) {
        walk_expr(self, e);
    }
    fn stmt(&mut self, s: &Stmt) {
        walk_stmt(self, s);
    }
    fn pat(&mut self, p: &Pat) {
        walk_pat(self, p);
    }
    fn place(&mut self, p: &Place) {
        walk_place(self, p);
    }
    fn script(&mut self, s: &ScriptStmt) {
        walk_script(self, s);
    }
    fn block(&mut self, b: &Block) {
        walk_block(self, b);
    }
    fn loop_(&mut self, l: &Loop) {
        walk_loop(self, l);
    }
}

pub fn walk_block<V: Visitor + ?Sized>(v: &mut V, b: &Block) {
    for s in &b.stmts {
        v.stmt(s);
    }
    if let Some(t) = &b.tail {
        v.expr(t);
    }
}

pub fn walk_stmt<V: Visitor + ?Sized>(v: &mut V, s: &Stmt) {
    match &s.kind {
        StmtKind::Let { pat, init, els } => {
            v.expr(init);
            v.pat(pat);
            if let Some(b) = els {
                v.block(b);
            }
        }
        StmtKind::Expr(e) => v.expr(e),
        StmtKind::Assign { place, value } | StmtKind::CompoundAssign { place, value, .. } => {
            v.expr(value);
            v.place(place);
        }
        StmtKind::CopyFromSlice { range, src, .. } => {
            if let Some((a, b)) = range {
                if let Some(a) = a {
                    v.expr(a);
                }
                if let Some(b) = b {
                    v.expr(b);
                }
            }
            v.expr(src);
        }
        StmtKind::Proof(ss) => ss.iter().for_each(|s| v.script(s)),
    }
}

pub fn walk_place<V: Visitor + ?Sized>(v: &mut V, p: &Place) {
    for pr in &p.projs {
        if let Proj::Index(e) = pr {
            v.expr(e);
        }
    }
}

pub fn walk_loop<V: Visitor + ?Sized>(v: &mut V, l: &Loop) {
    match &l.kind {
        LoopKind::ForRange { lo, hi, .. } => {
            v.expr(lo);
            v.expr(hi);
        }
        LoopKind::While { cond } => v.expr(cond),
    }
    for i in &l.info.invariants {
        v.expr(i);
    }
    if let Some(d) = &l.info.decreases {
        v.expr(d);
    }
    v.block(&l.body);
}

pub fn walk_expr<V: Visitor + ?Sized>(v: &mut V, e: &Expr) {
    match &e.kind {
        ExprKind::Lit(_) | ExprKind::Local(_) | ExprKind::Const(_) | ExprKind::BuiltinConst(_) | ExprKind::Unreachable => {}
        ExprKind::Call { args, .. } => args.iter().for_each(|a| v.expr(a)),
        ExprKind::Adt { fields, base, .. } => {
            fields.iter().for_each(|(_, f)| v.expr(f));
            if let Some(b) = base {
                v.expr(b);
            }
        }
        ExprKind::Tuple(es) | ExprKind::Array(es) => es.iter().for_each(|x| v.expr(x)),
        ExprKind::Repeat { elem, .. } => v.expr(elem),
        ExprKind::Field { base, .. } => v.expr(base),
        ExprKind::Index { base, index } => {
            v.expr(base);
            v.expr(index);
        }
        ExprKind::SliceRange { base, lo, hi } => {
            v.expr(base);
            if let Some(l) = lo {
                v.expr(l);
            }
            if let Some(h) = hi {
                v.expr(h);
            }
        }
        ExprKind::Unary(_, x) | ExprKind::Cast(x, _) | ExprKind::Ref(x) | ExprKind::Deref(x) | ExprKind::Coerce(_, x) | ExprKind::Try(x) | ExprKind::PropNot(x) => v.expr(x),
        ExprKind::Binary(_, a, b) | ExprKind::PropEq(a, b) | ExprKind::PropNe(a, b) | ExprKind::PropAnd(a, b) | ExprKind::PropOr(a, b) | ExprKind::Implies(a, b) | ExprKind::Iff(a, b) => {
            v.expr(a);
            v.expr(b);
        }
        ExprKind::If { cond, then, els } => {
            v.expr(cond);
            v.expr(then);
            if let Some(x) = els {
                v.expr(x);
            }
        }
        ExprKind::Match { scrut, arms, .. } => {
            v.expr(scrut);
            for a in arms {
                v.pat(&a.pat);
                if let Some(g) = &a.guard {
                    v.expr(g);
                }
                v.expr(&a.body);
            }
        }
        ExprKind::Block(b) => v.block(b),
        ExprKind::Return(x) => {
            if let Some(x) = x {
                v.expr(x);
            }
        }
        ExprKind::Loop(l) => v.loop_(l),
        ExprKind::Quant { body, .. } | ExprKind::Lambda { body, .. } => v.expr(body),
        ExprKind::Apply { fun, args } => {
            v.expr(fun);
            args.iter().for_each(|a| v.expr(a));
        }
    }
}

pub fn walk_pat<V: Visitor + ?Sized>(v: &mut V, p: &Pat) {
    match &p.kind {
        PatKind::Wild | PatKind::Lit(_) | PatKind::Range { .. } => {}
        PatKind::Binding { sub, .. } => {
            if let Some(s) = sub {
                v.pat(s);
            }
        }
        PatKind::Tuple(ps) | PatKind::Or(ps) => ps.iter().for_each(|x| v.pat(x)),
        PatKind::Ctor { fields, .. } => fields.iter().for_each(|(_, x)| v.pat(x)),
        PatKind::Deref { pat, .. } => v.pat(pat),
        PatKind::Slice { prefix, rest, suffix } => {
            prefix.iter().for_each(|x| v.pat(x));
            if let Some(Some(r)) = rest {
                v.pat(r);
            }
            suffix.iter().for_each(|x| v.pat(x));
        }
    }
}

pub fn walk_script<V: Visitor + ?Sized>(v: &mut V, s: &ScriptStmt) {
    match &s.kind {
        ScriptKind::Assert { prop, steps } => {
            v.expr(prop);
            if let Some(ss) = steps {
                ss.iter().for_each(|x| v.script(x));
            }
        }
        ScriptKind::Apply { app, .. } => v.expr(app),
        ScriptKind::Match { scrut, arms } => {
            v.expr(scrut);
            for a in arms {
                v.pat(&a.pat);
                a.steps.iter().for_each(|x| v.script(x));
            }
        }
        ScriptKind::If { cond, then, els } => {
            v.expr(cond);
            then.iter().for_each(|x| v.script(x));
            els.iter().for_each(|x| v.script(x));
        }
        ScriptKind::Cases { lo, hi, steps, .. } => {
            v.expr(lo);
            v.expr(hi);
            steps.iter().for_each(|x| v.script(x));
        }
        ScriptKind::Witness(es) => es.iter().for_each(|x| v.expr(x)),
        ScriptKind::UseHyp { args, .. } => args.iter().for_each(|x| v.expr(x)),
        ScriptKind::Rewrite { eq, motive, .. } => {
            v.expr(eq);
            if let Some((_, m)) = motive {
                v.expr(m);
            }
        }
        ScriptKind::Exact(e) | ScriptKind::Step { call: e } => v.expr(e),
        ScriptKind::Let { pat, value } => {
            v.expr(value);
            v.pat(pat);
        }
        ScriptKind::Calc { links, concl, .. } => {
            for l in links {
                v.expr(&l.prop);
                if let Some(ss) = &l.steps {
                    ss.iter().for_each(|x| v.script(x));
                }
            }
            v.expr(concl);
        }
        ScriptKind::Using(_) | ScriptKind::Unfold(_) | ScriptKind::Bv | ScriptKind::Follows | ScriptKind::Compute | ScriptKind::Lockstep | ScriptKind::Arithmetic | ScriptKind::Unfolding(_) | ScriptKind::Contradiction | ScriptKind::Show | ScriptKind::Todo => {}
    }
}

/// Walks every expression of a function definition (contracts, body).
pub fn walk_fn<V: Visitor + ?Sized>(v: &mut V, f: &FnDef) {
    for p in &f.params {
        v.pat(&p.pat);
    }
    for r in &f.requires {
        v.expr(r);
    }
    if let Some(en) = &f.ensures {
        v.pat(&en.binder);
        v.expr(&en.prop);
    }
    if let Some(d) = &f.decreases {
        v.expr(&d.measure);
    }
    match &f.body {
        FnBody::Exec(e) | FnBody::Spec(e) => v.expr(e),
        FnBody::Script(ss) => ss.iter().for_each(|s| v.script(s)),
        FnBody::Claim => {}
    }
}

/// Walks the expressions of a function's §15 annotations: the explicit
/// argument map and the domain of `#[refines]`, and the `#[example]`s.
pub fn walk_fn_spec<V: Visitor + ?Sized>(v: &mut V, a: &SpecAnnots) {
    if let Some(r) = &a.refines {
        if let Some(args) = &r.args {
            args.iter().for_each(|e| v.expr(e));
        }
        if let Some(d) = &r.domain {
            v.expr(d);
        }
    }
    for ex in &a.examples {
        v.expr(&ex.expr);
    }
}

/// Walks the expressions of a type's §15 annotations (`#[invariant]`,
/// `#[view(|s| e)]`, `#[represents]`).
pub fn walk_type_spec<V: Visitor + ?Sized>(v: &mut V, kind: &ItemKind) {
    let (inv, view, rep) = match kind {
        ItemKind::Struct(s) => (s.invariant.as_ref(), s.view.as_ref(), s.represents.as_ref()),
        ItemKind::Enum(e) => (None, e.view.as_ref(), None),
        _ => return,
    };
    if let Some(i) = inv {
        i.props.iter().for_each(|(p, _)| v.expr(p));
    }
    if let Some(View::Fn { body, .. }) = view {
        v.expr(body);
    }
    if let Some(r) = rep {
        v.expr(&r.prop);
    }
}
