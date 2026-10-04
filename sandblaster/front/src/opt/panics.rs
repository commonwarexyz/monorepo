//! The **panic-explicit reading** of a function that can panic (DESIGN.md
//! §8.2 item 12): how the always-on optimizer handles unverified code
//! whose arithmetic, divisions or indexing no precondition rules out.
//!
//! A verified build has no such function: every obligation is proven, so
//! no operation ever panics. In the exec-only path (the evaluation of
//! unverified code, `elab::Options::exec_only`), a function whose partial
//! operations the prover cannot show safe is `Unproven`: it has no kernel
//! definition, and the optimizer could not touch it. Such code is the norm
//! in unverified Rust (`a / b` with `b` unchecked, `n * 8` that overflows
//! for huge `n`). Its panics are part of its behaviour, and the optimized
//! code must panic on exactly the same inputs.
//!
//! The reading of `f` is a second function `<f>__panics` with `f`'s
//! parameters and preconditions and the result `Option<R>`, where `None`
//! is the panic outcome. It is built from `f`'s own HIR (untrusted, here):
//!
//! * `a + b`, `a - b`, `a * b` on unsigned integers become
//!   `a.checked_add(b)?` and the like: the prelude's checked operations,
//!   whose test is exactly the operation's overflow test (`uN::checked_add`
//!   tests `a as Int + b as Int ≤ MAX`, the very condition rustc's
//!   `CheckedAdd` asserts and the literal reading's `mir::checked_add_*`
//!   flags), the `?` its panic exit;
//! * `a / b`, `a % b` (and `div_ceil`) by a non-literal divisor get the
//!   guard `if b == 0 { return None; }` right before the operation, rustc's
//!   own test (MIR asserts `b == 0` is false before a division); a shift by
//!   a non-literal amount, an index and a sub-slice get the guard `if
//!   out of range { return None; }` likewise (only the operands are bound
//!   first, in their order);
//! * a call of a function that has a reading becomes the call of its
//!   reading under `?` (its panic propagates); a call of a verified
//!   function stays a call;
//! * the function's own early exits keep their meaning: `return v` is
//!   `return Some(v)`, and its own `?` on an `Option` returns `Some(None)`
//!   (a value of `f`, not a panic); the tail is `Some(tail)`.
//!
//! Nothing moves: every guard and checked operation stands where the
//! operation stood, so the reading evaluates the same operations in the
//! same order and panics at the first one `f` panics at. A loop body is
//! not rewritten (its obligations must be proven as written: a panic inside
//! a loop is not read yet), nor are an `unreachable!()` that is not proven
//! unreachable (`assert!`, `unwrap`, `panic!`: in MIR a `debug_assert!` is
//! indistinguishable from an `assert!`, and a release build has no
//! `debug_assert!`, so its panic is not the release program's), a callee's
//! `requires`, or a place written through an index. A reading whose
//! elaboration leaves any obligation unproven is not built (the reason is
//! reported), and one of a function that calls a function neither
//! kernel-checked nor read is not attempted (it would be blocked as the
//! function is: `opt::panic_readings`).
//!
//! The reading is elaborated and kernel-checked like any exec function
//! (`elab::generated::resume`: every proof slot proven). It is then
//! optimized like any function: its residual is linked to it by the usual
//! kernel-checked equality, `Π x̄. Eq(Option(R), r x̄, f__panics x̄)`, which
//! covers the panic outcome: no rewrite can add, remove or move a panic.
//! What ties the reading to the source is not this module: the lowering of
//! a lifted function (`driver::lowered`) ships a reading's residual only
//! with the two panic theorems of the lifted round trip, both against the
//! literal reading of rustc's MIR (`mir::stmt::statement` with `panic`:
//! `run(L_f) = opt_erase(f__panics x̄)` and `run(L_copy) = opt_erase(f__panics
//! x̄)`, accepted by `mir::gate::Ledger::accept_shipped_panic`). A wrong
//! reading here can only fail those theorems, never ship a different
//! program.

use std::collections::HashMap;

use crate::builtins::{Builtin, IntMethod, SliceMethod};
use crate::hir::*;
use crate::span::Span;

/// The suffix of a reading's name (`f` → `f__panics`).
pub const SUFFIX: &str = "__panics";

/// What became of one function the exec-only elaboration left unproven.
#[derive(Clone, Debug)]
pub struct PanicReading {
    /// The source function.
    pub source: ItemId,
    /// The reading's item (`<f>__panics`) when it was built and
    /// kernel-checked.
    pub item: Option<ItemId>,
    /// Why there is no reading (empty when there is one).
    pub note: String,
}

/// The reading of function `id` of `krate` as a function definition (see
/// the module docs): `readings` maps the functions that already have one
/// (callees first) to their readings' items.
pub fn reading(krate: &Crate, id: ItemId, readings: &HashMap<ItemId, ItemId>) -> Result<FnDef, String> {
    let f = krate.fn_def(id).ok_or("not a function")?;
    if f.kind != FnKind::Exec {
        return Err("not an exec function".into());
    }
    if !f.generics.is_empty() {
        return Err("a generic function".into());
    }
    if f.receiver.is_some() {
        return Err("a method with a receiver".into());
    }
    if f.recursion != Recursion::None || f.decreases.is_some() {
        return Err("a recursive function (a panic inside a recursion is not read yet)".into());
    }
    if f.params.iter().any(|p| p.ghost) {
        return Err("a ghost parameter".into());
    }
    let FnBody::Exec(body) = &f.body else { return Err("not an exec body".into()) };
    if matches!(f.ret, Ty::Never | Ty::Error) {
        return Err("a function that never returns".into());
    }
    let mut t = T { readings, locals: f.locals.clone(), ret: f.ret.clone(), changed: 0 };
    let b = t.expr(body)?;
    if t.changed == 0 {
        return Err("no operation it can panic at is read (its unproven obligations are elsewhere: inside a loop, an `unreachable!()`, a callee's `requires` or an indexed place)".into());
    }
    let span = body.span;
    let ret = Ty::option(f.ret.clone());
    let wrapped = some(b, &f.ret, span);
    let mut pf = f.clone();
    pf.ret = ret;
    pf.body = FnBody::Exec(wrapped);
    pf.locals = t.locals;
    pf.ensures = None;
    pf.specialize = false;
    pf.implements = None;
    pf.inline = None;
    pf.target_features = Vec::new();
    pf.feature_set = Vec::new();
    pf.spec = SpecAnnots::default();
    Ok(pf)
}

/// The crate functions the body of function `id` calls.
pub fn callees(krate: &Crate, id: ItemId) -> Vec<ItemId> {
    struct C(Vec<ItemId>);
    impl crate::visit::Visitor for C {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Call { callee: Callee::Item(g, _), .. } = &e.kind
                && !self.0.contains(g)
            {
                self.0.push(*g);
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut c = C(Vec::new());
    if let Some(FnDef { body: FnBody::Exec(b), .. }) = krate.fn_def(id) {
        crate::visit::Visitor::expr(&mut c, b);
    }
    c.0
}

/// `Some(e)` of type `Option<t>`.
fn some(e: Expr, t: &Ty, span: Span) -> Expr {
    Expr::new(ExprKind::Adt { ctor: Ctor::Some, ty_args: vec![t.clone()], fields: vec![(0, e)], base: None }, Ty::option(t.clone()), span)
}

/// `None` of type `Option<t>`.
fn none(t: &Ty, span: Span) -> Expr {
    Expr::new(ExprKind::Adt { ctor: Ctor::None, ty_args: vec![t.clone()], fields: vec![], base: None }, Ty::option(t.clone()), span)
}

fn lit_usize(n: u128, span: Span) -> Expr {
    Expr::new(ExprKind::Lit(Lit::Int(n)), Ty::usize(), span)
}

/// The literal value of `e` (through casts and coercions).
fn lit_of(e: &Expr) -> Option<u128> {
    match &e.kind {
        ExprKind::Lit(Lit::Int(n)) => Some(*n),
        ExprKind::Coerce(_, x) | ExprKind::Cast(x, _) => lit_of(x),
        _ => None,
    }
}

/// A pure place-like expression that may be evaluated twice (a local, a
/// field or a coercion of one): an index base, so the guard can read its
/// length without binding a copy.
fn simple(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Local(_) | ExprKind::Const(_) => true,
        ExprKind::Field { base, .. } | ExprKind::Coerce(_, base) | ExprKind::Deref(base) | ExprKind::Ref(base) => simple(base),
        _ => false,
    }
}

struct T<'a> {
    readings: &'a HashMap<ItemId, ItemId>,
    locals: Vec<LocalDecl>,
    /// `f`'s result type `R` (the reading returns `Option<R>`).
    ret: Ty,
    /// Operations read as panic exits (and calls of readings).
    changed: usize,
}

impl T<'_> {
    fn fresh(&mut self, name: &str, ty: &Ty, span: Span) -> LocalId {
        let l = LocalId(self.locals.len() as u32);
        self.locals.push(LocalDecl { name: format!("{name}_p{}", l.0), ty: ty.clone(), mutable: false, ghost: false, span });
        l
    }

    /// `let x = e;` and the expression `x`.
    fn bind(&mut self, name: &str, e: Expr, stmts: &mut Vec<Stmt>) -> Expr {
        let (ty, span) = (e.ty.clone(), e.span);
        let l = self.fresh(name, &ty, span);
        let pat = Pat { kind: PatKind::Binding { local: l, mode: BindingMode::ByValue, sub: None }, ty: ty.clone(), span };
        stmts.push(Stmt { kind: StmtKind::Let { pat, init: e, els: None }, span });
        Expr::new(ExprKind::Local(l), ty, span)
    }

    /// The panic exit of the reading: `return None`.
    fn exit(&self, span: Span) -> Expr {
        Expr::new(ExprKind::Return(Some(Box::new(none(&self.ret, span)))), Ty::Never, span)
    }

    /// `{ stmts; if fail { return None; } value }`: the guard of a partial
    /// operation by its failure test (as rustc's MIR tests it), in place.
    fn guarded_fail(&self, mut stmts: Vec<Stmt>, fail: Expr, value: Expr) -> Expr {
        let span = value.span;
        let ty = value.ty.clone();
        let then = Expr::new(ExprKind::Block(Block { stmts: vec![], tail: Some(Box::new(self.exit(span))), span }), Ty::Never, span);
        let iff = Expr::new(ExprKind::If { cond: Box::new(fail), then: Box::new(then), els: None }, Ty::unit(), span);
        stmts.push(Stmt { kind: StmtKind::Expr(iff), span });
        Expr::new(ExprKind::Block(Block { stmts, tail: Some(Box::new(value)), span }), ty, span)
    }

    /// `a / b` or `a % b` (both read already) by a non-literal divisor:
    /// guarded by `b == 0`.
    fn division(&mut self, op: BinOp, w: UintTy, a: Expr, b: Expr, span: Span) -> Expr {
        let mut stmts = Vec::new();
        let a = self.bind("x", a, &mut stmts);
        let b = self.bind("d", b, &mut stmts);
        let zero = Expr::new(ExprKind::Lit(Lit::Int(0)), Ty::Uint(w), span);
        let fail = Expr::new(ExprKind::Binary(BinOp::Eq, Box::new(b.clone()), Box::new(zero)), Ty::Bool, span);
        self.changed += 1;
        let v = Expr::new(ExprKind::Binary(op, Box::new(a), Box::new(b)), Ty::Uint(w), span);
        self.guarded_fail(stmts, fail, v)
    }

    /// `e?` for `e : Option<t>` (the panic exit when `None`).
    fn try_(&self, e: Expr, t: &Ty) -> Expr {
        let span = e.span;
        Expr::new(ExprKind::Try(Box::new(e)), t.clone(), span)
    }

    fn exprs(&mut self, es: &[Expr]) -> Result<Vec<Expr>, String> {
        es.iter().map(|e| self.expr(e)).collect()
    }

    fn block(&mut self, b: &Block) -> Result<Block, String> {
        let mut stmts = Vec::new();
        for s in &b.stmts {
            stmts.push(self.stmt(s)?);
        }
        let tail = match &b.tail {
            Some(t) => Some(Box::new(self.expr(t)?)),
            None => None,
        };
        Ok(Block { stmts, tail, span: b.span })
    }

    fn stmt(&mut self, s: &Stmt) -> Result<Stmt, String> {
        let span = s.span;
        let kind = match &s.kind {
            StmtKind::Let { pat, init, els } => {
                let init = self.expr(init)?;
                let els = match els {
                    Some(b) => Some(self.block(b)?),
                    None => None,
                };
                StmtKind::Let { pat: pat.clone(), init, els }
            }
            StmtKind::Expr(e) => StmtKind::Expr(self.expr(e)?),
            StmtKind::Assign { place, value } => StmtKind::Assign { place: place.clone(), value: self.expr(value)? },
            StmtKind::CompoundAssign { op, place, value } => {
                let value = self.expr(value)?;
                // `x op= v` on an unsigned integer local: `x = checked(x op v)`
                // (a projected place keeps its obligations)
                match (place.projs.is_empty(), &place.ty) {
                    (true, Ty::Uint(w)) if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul) => {
                        let read = place_expr(place);
                        let v = self.checked(*op, *w, read, value, span);
                        StmtKind::Assign { place: place.clone(), value: v }
                    }
                    (true, Ty::Uint(w)) if matches!(op, BinOp::Div | BinOp::Rem) && !lit_of(&value).is_some_and(|n| n != 0) => {
                        let read = place_expr(place);
                        let v = self.division(*op, *w, read, value, span);
                        StmtKind::Assign { place: place.clone(), value: v }
                    }
                    (true, Ty::Uint(w)) if matches!(op, BinOp::Shl | BinOp::Shr) && !lit_of(&value).is_some_and(|n| n < u128::from(w.bits())) => {
                        let read = place_expr(place);
                        let v = self.shift(*op, *w, read, value, span);
                        StmtKind::Assign { place: place.clone(), value: v }
                    }
                    _ => StmtKind::CompoundAssign { op: *op, place: place.clone(), value },
                }
            }
            // a copy into an array keeps its obligations (a written place)
            StmtKind::CopyFromSlice { .. } | StmtKind::Proof(_) => s.kind.clone(),
        };
        Ok(Stmt { kind, span })
    }

    /// `a op b` (both read already) as its checked operation under `?`.
    fn checked(&mut self, op: BinOp, w: UintTy, a: Expr, b: Expr, span: Span) -> Expr {
        let m = match op {
            BinOp::Add => IntMethod::CheckedAdd,
            BinOp::Sub => IntMethod::CheckedSub,
            _ => IntMethod::CheckedMul,
        };
        self.changed += 1;
        let t = Ty::Uint(w);
        let call = Expr::new(ExprKind::Call { callee: Callee::Builtin(Builtin::Int(m, w), vec![]), args: vec![a, b] }, Ty::option(t.clone()), span);
        self.try_(call, &t)
    }

    /// `a << s` / `a >> s` by a non-literal amount: guarded by `s < BITS`.
    fn shift(&mut self, op: BinOp, w: UintTy, a: Expr, s: Expr, span: Span) -> Expr {
        let mut stmts = Vec::new();
        let a = self.bind("x", a, &mut stmts);
        let st = s.ty.clone();
        let s = self.bind("s", s, &mut stmts);
        let bits = Expr::new(ExprKind::Lit(Lit::Int(u128::from(w.bits()))), st, span);
        let fail = Expr::new(ExprKind::Binary(BinOp::Ge, Box::new(s.clone()), Box::new(bits)), Ty::Bool, span);
        self.changed += 1;
        let v = Expr::new(ExprKind::Binary(op, Box::new(a), Box::new(s)), Ty::Uint(w), span);
        self.guarded_fail(stmts, fail, v)
    }

    /// The length of an index base `b` of type `[T; N]` or `[T]`.
    fn len_of(&self, b: &Expr, span: Span) -> Option<Expr> {
        match &b.ty {
            Ty::Array(_, n) => Some(lit_usize(u128::from(*n), span)),
            Ty::Slice(t) => {
                let recv = Expr::new(ExprKind::Coerce(Coercion::AutoRef, Box::new(b.clone())), Ty::slice_ref((**t).clone()), span);
                Some(Expr::new(ExprKind::Call { callee: Callee::Builtin(Builtin::Slice(SliceMethod::Len), vec![(**t).clone()]), args: vec![recv] }, Ty::usize(), span))
            }
            _ => None,
        }
    }

    fn expr(&mut self, e: &Expr) -> Result<Expr, String> {
        let span = e.span;
        let ty = e.ty.clone();
        let kind = match &e.kind {
            ExprKind::Lit(_) | ExprKind::Local(_) | ExprKind::Const(_) | ExprKind::BuiltinConst(_) | ExprKind::Unreachable => return Ok(e.clone()),
            ExprKind::Call { callee, args } => {
                let args = self.exprs(args)?;
                match callee {
                    // a callee with a reading: its panic propagates
                    Callee::Item(g, targs) if self.readings.contains_key(g) => {
                        let r = self.readings[g];
                        self.changed += 1;
                        let call = Expr::new(ExprKind::Call { callee: Callee::Item(r, targs.clone()), args }, Ty::option(ty.clone()), span);
                        return Ok(self.try_(call, &ty));
                    }
                    // `a.div_ceil(b)`: guarded by `b != 0`
                    Callee::Builtin(Builtin::Int(IntMethod::DivCeil, w), _) if args.len() == 2 && !lit_of(&args[1]).is_some_and(|n| n != 0) => {
                        let mut stmts = Vec::new();
                        let mut it = args.into_iter();
                        let a = self.bind("x", it.next().unwrap(), &mut stmts);
                        let b = self.bind("d", it.next().unwrap(), &mut stmts);
                        let zero = Expr::new(ExprKind::Lit(Lit::Int(0)), Ty::Uint(*w), span);
                        let fail = Expr::new(ExprKind::Binary(BinOp::Eq, Box::new(b.clone()), Box::new(zero)), Ty::Bool, span);
                        self.changed += 1;
                        let v = Expr::new(ExprKind::Call { callee: callee.clone(), args: vec![a, b] }, ty, span);
                        return Ok(self.guarded_fail(stmts, fail, v));
                    }
                    // `s.split_at(mid)`: guarded by `mid <= s.len()`
                    Callee::Builtin(Builtin::Slice(SliceMethod::SplitAt), targs) if args.len() == 2 => {
                        let mut stmts = Vec::new();
                        let mut it = args.into_iter();
                        let s = self.bind("s", it.next().unwrap(), &mut stmts);
                        let m = self.bind("m", it.next().unwrap(), &mut stmts);
                        let len = Expr::new(ExprKind::Call { callee: Callee::Builtin(Builtin::Slice(SliceMethod::Len), targs.clone()), args: vec![s.clone()] }, Ty::usize(), span);
                        let fail = Expr::new(ExprKind::Binary(BinOp::Gt, Box::new(m.clone()), Box::new(len)), Ty::Bool, span);
                        self.changed += 1;
                        let v = Expr::new(ExprKind::Call { callee: callee.clone(), args: vec![s, m] }, ty, span);
                        return Ok(self.guarded_fail(stmts, fail, v));
                    }
                    _ => ExprKind::Call { callee: callee.clone(), args },
                }
            }
            ExprKind::Adt { ctor, ty_args, fields, base } => {
                let mut fs = Vec::new();
                for (i, x) in fields {
                    fs.push((*i, self.expr(x)?));
                }
                let base = match base {
                    Some(b) => Some(Box::new(self.expr(b)?)),
                    None => None,
                };
                ExprKind::Adt { ctor: ctor.clone(), ty_args: ty_args.clone(), fields: fs, base }
            }
            ExprKind::Tuple(es) => ExprKind::Tuple(self.exprs(es)?),
            ExprKind::Array(es) => ExprKind::Array(self.exprs(es)?),
            ExprKind::Repeat { elem, count } => ExprKind::Repeat { elem: Box::new(self.expr(elem)?), count: *count },
            ExprKind::Field { base, index, name } => ExprKind::Field { base: Box::new(self.expr(base)?), index: *index, name: name.clone() },
            ExprKind::Index { base, index } => {
                let base = self.expr(base)?;
                let index = self.expr(index)?;
                // a literal index within an array's length is safe
                if let (Ty::Array(_, n), Some(i)) = (&base.ty, lit_of(&index))
                    && i < u128::from(*n)
                {
                    ExprKind::Index { base: Box::new(base), index: Box::new(index) }
                } else {
                    let mut stmts = Vec::new();
                    let base = if simple(&base) { base } else { self.bind("b", base, &mut stmts) };
                    let index = self.bind("i", index, &mut stmts);
                    let Some(len) = self.len_of(&base, span) else { return Err(format!("an index into a value of type {:?}", base.ty)) };
                    let fail = Expr::new(ExprKind::Binary(BinOp::Ge, Box::new(index.clone()), Box::new(len)), Ty::Bool, span);
                    self.changed += 1;
                    let v = Expr::new(ExprKind::Index { base: Box::new(base), index: Box::new(index) }, ty, span);
                    return Ok(self.guarded_fail(stmts, fail, v));
                }
            }
            ExprKind::SliceRange { base, lo, hi } => {
                let base = self.expr(base)?;
                let lo = match lo {
                    Some(x) => Some(self.expr(x)?),
                    None => None,
                };
                let hi = match hi {
                    Some(x) => Some(self.expr(x)?),
                    None => None,
                };
                if lo.is_none() && hi.is_none() {
                    ExprKind::SliceRange { base: Box::new(base), lo: None, hi: None }
                } else {
                    let mut stmts = Vec::new();
                    let base = if simple(&base) { base } else { self.bind("b", base, &mut stmts) };
                    let lo = lo.map(|x| self.bind("lo", x, &mut stmts));
                    let hi = hi.map(|x| self.bind("hi", x, &mut stmts));
                    let Some(len) = self.len_of(&base, span) else { return Err(format!("a sub-slice of a value of type {:?}", base.ty)) };
                    let gt = |a: Expr, b: Expr| Expr::new(ExprKind::Binary(BinOp::Gt, Box::new(a), Box::new(b)), Ty::Bool, span);
                    let fail = match (&lo, &hi) {
                        (Some(l), Some(h)) => Expr::new(ExprKind::Binary(BinOp::Or, Box::new(gt(l.clone(), h.clone())), Box::new(gt(h.clone(), len))), Ty::Bool, span),
                        (Some(l), None) => gt(l.clone(), len),
                        (None, Some(h)) => gt(h.clone(), len),
                        (None, None) => unreachable!(),
                    };
                    self.changed += 1;
                    let v = Expr::new(ExprKind::SliceRange { base: Box::new(base), lo: lo.map(Box::new), hi: hi.map(Box::new) }, ty, span);
                    return Ok(self.guarded_fail(stmts, fail, v));
                }
            }
            ExprKind::Unary(op, x) => ExprKind::Unary(*op, Box::new(self.expr(x)?)),
            ExprKind::Binary(op, a, b) => {
                let (a, b) = (self.expr(a)?, self.expr(b)?);
                match (&ty, op) {
                    (Ty::Uint(w), BinOp::Add | BinOp::Sub | BinOp::Mul) => return Ok(self.checked(*op, *w, a, b, span)),
                    (Ty::Uint(w), BinOp::Div | BinOp::Rem) if !lit_of(&b).is_some_and(|n| n != 0) => return Ok(self.division(*op, *w, a, b, span)),
                    (Ty::Uint(w), BinOp::Shl | BinOp::Shr) if !lit_of(&b).is_some_and(|n| n < u128::from(w.bits())) => return Ok(self.shift(*op, *w, a, b, span)),
                    _ => ExprKind::Binary(*op, Box::new(a), Box::new(b)),
                }
            }
            ExprKind::Cast(x, t) => ExprKind::Cast(Box::new(self.expr(x)?), t.clone()),
            ExprKind::Ref(x) => ExprKind::Ref(Box::new(self.expr(x)?)),
            ExprKind::Deref(x) => ExprKind::Deref(Box::new(self.expr(x)?)),
            ExprKind::Coerce(c, x) => ExprKind::Coerce(*c, Box::new(self.expr(x)?)),
            ExprKind::If { cond, then, els } => {
                let els = match els {
                    Some(x) => Some(Box::new(self.expr(x)?)),
                    None => None,
                };
                ExprKind::If { cond: Box::new(self.expr(cond)?), then: Box::new(self.expr(then)?), els }
            }
            ExprKind::Match { scrut, arms, source } => {
                let scrut = Box::new(self.expr(scrut)?);
                let mut out = Vec::new();
                for a in arms {
                    let guard = match &a.guard {
                        Some(g) => Some(self.expr(g)?),
                        None => None,
                    };
                    out.push(Arm { pat: a.pat.clone(), guard, body: self.expr(&a.body)?, span: a.span });
                }
                ExprKind::Match { scrut, arms: out, source: *source }
            }
            ExprKind::Block(b) => ExprKind::Block(self.block(b)?),
            // `f`'s own early exits: values of the reading
            ExprKind::Return(v) => {
                let v = match v {
                    Some(v) => self.expr(v)?,
                    None => Expr::new(ExprKind::Tuple(vec![]), Ty::unit(), span),
                };
                ExprKind::Return(Some(Box::new(some(v, &self.ret, span))))
            }
            ExprKind::Try(x) => {
                // `x?` of `f` (returning `Option<U>`): `match x { Some(v) => v,
                // None => return Some(None) }`
                let x = self.expr(x)?;
                let Ty::Option(t) = x.ty.clone() else { return Err("`?` on a value that is not an `Option`".into()) };
                let Ty::Option(u) = self.ret.clone() else { return Err("`?` in a function that does not return an `Option`".into()) };
                let v = self.fresh("v", &t, span);
                let bind = Pat { kind: PatKind::Binding { local: v, mode: BindingMode::ByValue, sub: None }, ty: (*t).clone(), span };
                let some_p = Pat { kind: PatKind::Ctor { ctor: Ctor::Some, ty_args: vec![(*t).clone()], fields: vec![(0, bind)] }, ty: x.ty.clone(), span };
                let none_p = Pat { kind: PatKind::Ctor { ctor: Ctor::None, ty_args: vec![(*t).clone()], fields: vec![] }, ty: x.ty.clone(), span };
                let ret_none = Expr::new(ExprKind::Return(Some(Box::new(some(none(&u, span), &self.ret, span)))), Ty::Never, span);
                let arms = vec![Arm { pat: some_p, guard: None, body: Expr::new(ExprKind::Local(v), (*t).clone(), span), span }, Arm { pat: none_p, guard: None, body: ret_none, span }];
                ExprKind::Match { scrut: Box::new(x), arms, source: MatchSource::Match }
            }
            // a loop is read as written: its obligations must be proven
            ExprKind::Loop(_) => return Ok(e.clone()),
            ExprKind::PropEq(..) | ExprKind::PropNe(..) | ExprKind::PropAnd(..) | ExprKind::PropOr(..) | ExprKind::PropNot(_) | ExprKind::Implies(..) | ExprKind::Iff(..) | ExprKind::Quant { .. } | ExprKind::Lambda { .. } | ExprKind::Apply { .. } => return Ok(e.clone()),
        };
        Ok(Expr::new(kind, ty, span))
    }
}

/// The value of a place without projections (a local) as an expression.
fn place_expr(p: &Place) -> Expr {
    Expr::new(ExprKind::Local(p.local), p.ty.clone(), p.span)
}
