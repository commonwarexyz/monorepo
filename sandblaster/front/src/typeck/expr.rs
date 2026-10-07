//! Expression and statement type checking (DESIGN.md §3.3, §3.4, §3.6).
//!
//! Typing is **bidirectional**: [`Cx::expr`] takes an expectation ([`Exp`])
//! and returns an [`Expr`] with its natural type; [`Cx::check`] then applies
//! the allowed coercions ([`Cx::coerce`]: unsizing `&[T; N] → &[T]`,
//! `&&T → &T`, `bool → Prop` in proposition positions). Rules that must
//! agree with rustc (§3.6):
//!
//! * An unsuffixed integer literal takes its type from the expectation (or
//!   from the other operand of an arithmetic/bitwise/comparison operator);
//!   otherwise it is rejected ("annotate this literal").
//! * The operand of `as` has **no** expectation, except that a syntactically
//!   bare (possibly parenthesized) literal takes the target type. The right
//!   operand of `<<`/`>>` has no expectation either. An unsuffixed literal
//!   there is rejected unless a typed operand fixes its type, because rustc
//!   would default it to `i32` (`(1 << k) as u64` is an `i32` shift in rustc).
//! * No implicit conversions except auto-ref/deref of receivers, auto-deref
//!   of field-access/index bases, `&T` operands of arithmetic operators (as
//!   rustc's `impl Add<u32> for &u32` etc.), and the coercions above.
//! * Method resolution: the §3.4 whitelist, user inherent methods, target
//!   intrinsics (free functions). Autoderef probes `T, *T, **T, ..`; arrays
//!   reach slice methods through unsizing.
//! * Names: locals shadow items in the value namespace (lexical scopes);
//!   everything else goes through [`crate::resolve`].
//! * Intrinsic calls are allowed only if every required feature is in the
//!   implication closure of the calling function's own `#[target_feature]`
//!   (§9.3; static target features do not count).
//!
//! Loops record [`LoopInfo`] (mutated/read outer locals, invariants and
//! decreases from a leading `proof!` block).

use std::collections::BTreeSet;

use syn::spanned::Spanned;

use super::{Checker, GenScope};
use crate::builtins::{ArrayMethod, Builtin, GhostFn, IntMethod, OptionMethod, SliceMethod};
use crate::diag::{DiagKind, Diagnostic};
use crate::hir::*;
use crate::intrinsics;
use crate::resolve::{Def, Ext, GhostKw, ItemTag, Ns};
use crate::span::Span;
use crate::visit::{self, Visitor};

/// Expectation for an expression.
#[derive(Clone, Debug)]
pub enum Exp {
    None,
    Ty(Ty),
    /// A proposition position (§4.1).
    Prop,
}

impl Exp {
    pub fn ty(&self) -> Option<&Ty> {
        match self {
            Exp::Ty(t) => Some(t),
            _ => None,
        }
    }
}

/// Result of resolving a value path.
#[derive(Clone, Debug)]
pub enum VRes {
    Local(LocalId),
    /// A function with explicit type arguments: impl-level (from a type
    /// path) and own (turbofish).
    Fn(ItemId, Option<Vec<Ty>>, Vec<Ty>),
    Const(ItemId),
    /// A constructor with explicit type arguments.
    Ctor(Ctor, Option<Vec<Ty>>),
    BuiltinConst(BuiltinConst),
    /// `u32::from_be_bytes`, `u32::wrapping_add` (UFCS).
    IntAssoc(UintTy, IntMethod),
    Intrinsic(intrinsics::IntrinsicId, Vec<i64>),
    Ghost(GhostFn, Vec<Ty>),
    GhostKw(GhostKw),
}

/// Fields of a constructor `(name, generic type, visibility)`, the number of
/// type parameters of its type, and its (generic) result type.
pub type CtorFields = (Vec<(Option<String>, Ty, Vis)>, usize, Ty);

/// Per-body checking context.
pub struct Cx<'c, 'a> {
    pub ck: &'c mut Checker<'a>,
    pub m: ModId,
    pub item: Option<ItemId>,
    pub kind: FnKind,
    /// Ghost context (ghost item, contract, proof block).
    pub ghost: bool,
    /// Checking a constant initializer.
    pub in_const: bool,
    pub locals: Vec<LocalDecl>,
    scopes: Vec<Vec<(String, LocalId)>>,
    pub ret: Ty,
    pub g: GenScope,
    pub loop_depth: u32,
    pub loop_count: u32,
    pub features: Vec<String>,
    no_exp_reason: Vec<&'static str>,
    /// Typing a struct's `#[invariant(p)]` (§15.3): `self.f` is the field
    /// binder of `f`; bare `self` and methods of the struct are rejected.
    pub inv_self: Option<super::spec15::InvSelf>,
    /// Checking a lifted module's exec code ([`crate::lift`]): it may name
    /// the ghost buffer model (`Seq<u8>` values, the spec functions of
    /// `crate::__lift_model`), because it is checked, never printed.
    pub lift: bool,
}

/// Whether an expression needs an expected type to be typed (unsuffixed
/// literals and operators over them, `None`, `[]`).
pub fn needs_exp(e: &syn::Expr) -> bool {
    match e {
        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(l), .. }) => l.suffix().is_empty(),
        syn::Expr::Paren(p) => needs_exp(&p.expr),
        syn::Expr::Group(g) => needs_exp(&g.expr),
        syn::Expr::Binary(b) => {
            use syn::BinOp::*;
            match b.op {
                Add(_) | Sub(_) | Mul(_) | Div(_) | Rem(_) | BitAnd(_) | BitOr(_) | BitXor(_) => needs_exp(&b.left) && needs_exp(&b.right),
                Shl(_) | Shr(_) => needs_exp(&b.left),
                _ => false,
            }
        }
        syn::Expr::Unary(u) => matches!(u.op, syn::UnOp::Not(_) | syn::UnOp::Neg(_)) && needs_exp(&u.expr),
        syn::Expr::Path(p) => p.path.is_ident("None"),
        syn::Expr::Array(a) => a.elems.is_empty(),
        // a ghost lambda with an unannotated binder takes its binder types
        // from the expected function type
        syn::Expr::Closure(c) => c.inputs.iter().any(|p| !matches!(p, syn::Pat::Type(_))),
        _ => false,
    }
}

/// Whether typing `e` may declare locals (a block, `match`, `if let`,
/// closure or quantifier): such an index is typed once, as `usize`.
fn binds_locals(e: &syn::Expr) -> bool {
    struct V(bool);
    impl<'ast> syn::visit::Visit<'ast> for V {
        fn visit_expr(&mut self, e: &'ast syn::Expr) {
            if matches!(e, syn::Expr::Block(_) | syn::Expr::Match(_) | syn::Expr::If(_) | syn::Expr::Closure(_) | syn::Expr::Let(_) | syn::Expr::Macro(_)) {
                self.0 = true;
            }
            syn::visit::visit_expr(self, e);
        }
    }
    let mut v = V(false);
    syn::visit::Visit::visit_expr(&mut v, e);
    v.0
}

/// Whether `e` is a (possibly parenthesized) bare literal.
fn bare_lit(e: &syn::Expr) -> bool {
    match e {
        syn::Expr::Lit(_) => true,
        syn::Expr::Paren(p) => bare_lit(&p.expr),
        syn::Expr::Group(g) => bare_lit(&g.expr),
        _ => false,
    }
}

/// A literal with a type suffix (`31u32`), through parentheses.
fn suffixed_lit(e: &syn::Expr) -> bool {
    match e {
        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) => !i.suffix().is_empty(),
        syn::Expr::Paren(p) => suffixed_lit(&p.expr),
        syn::Expr::Group(g) => suffixed_lit(&g.expr),
        _ => false,
    }
}

fn map_binop(op: &syn::BinOp) -> Option<(BinOp, bool)> {
    use syn::BinOp as S;
    Some(match op {
        S::Add(_) => (BinOp::Add, false),
        S::Sub(_) => (BinOp::Sub, false),
        S::Mul(_) => (BinOp::Mul, false),
        S::Div(_) => (BinOp::Div, false),
        S::Rem(_) => (BinOp::Rem, false),
        S::And(_) => (BinOp::And, false),
        S::Or(_) => (BinOp::Or, false),
        S::BitXor(_) => (BinOp::BitXor, false),
        S::BitAnd(_) => (BinOp::BitAnd, false),
        S::BitOr(_) => (BinOp::BitOr, false),
        S::Shl(_) => (BinOp::Shl, false),
        S::Shr(_) => (BinOp::Shr, false),
        S::Eq(_) => (BinOp::Eq, false),
        S::Lt(_) => (BinOp::Lt, false),
        S::Le(_) => (BinOp::Le, false),
        S::Ne(_) => (BinOp::Ne, false),
        S::Ge(_) => (BinOp::Ge, false),
        S::Gt(_) => (BinOp::Gt, false),
        S::AddAssign(_) => (BinOp::Add, true),
        S::SubAssign(_) => (BinOp::Sub, true),
        S::MulAssign(_) => (BinOp::Mul, true),
        S::DivAssign(_) => (BinOp::Div, true),
        S::RemAssign(_) => (BinOp::Rem, true),
        S::BitXorAssign(_) => (BinOp::BitXor, true),
        S::BitAndAssign(_) => (BinOp::BitAnd, true),
        S::BitOrAssign(_) => (BinOp::BitOr, true),
        S::ShlAssign(_) => (BinOp::Shl, true),
        S::ShrAssign(_) => (BinOp::Shr, true),
        _ => return None,
    })
}

/// Type checks a constant initializer.
pub fn check_const(ck: &mut Checker, id: ItemId, e: &syn::Expr, ty: &Ty) -> (Expr, Vec<LocalDecl>) {
    let it = ck.res.items[id.0 as usize].clone();
    let mut cx = Cx::new(ck, it.module, None, FnKind::Exec, it.ghost, Ty::Error, GenScope::default(), vec![]);
    cx.in_const = true;
    let init = cx.check(e, ty);
    let locals = std::mem::take(&mut cx.locals);
    if !it.ghost {
        let mut v = ConstCheck { cx: &mut cx };
        v.expr(&init);
    }
    (init, locals)
}

/// Rejects constructs rustc cannot evaluate in a `const` initializer.
struct ConstCheck<'x, 'c, 'a> {
    cx: &'x mut Cx<'c, 'a>,
}

impl Visitor for ConstCheck<'_, '_, '_> {
    fn expr(&mut self, e: &Expr) {
        match &e.kind {
            ExprKind::Call { callee: Callee::Item(..) | Callee::Intrinsic(..), .. } => {
                self.cx.ck.diags.push(Diagnostic::error(DiagKind::Unsupported, e.span, "function calls are not allowed in constant initializers").note("user functions are not `const fn`; rustc would reject the call"));
            }
            ExprKind::Call { callee: Callee::Builtin(b, _), .. } if !b.is_const_fn() => {
                self.cx.err(DiagKind::Unsupported, e.span, "this method cannot be evaluated in a constant initializer (not a `const fn` in core)");
            }
            ExprKind::Binary(BinOp::Eq | BinOp::Ne, a, _) if !matches!(a.ty, Ty::Uint(_) | Ty::Bool) => {
                self.cx.err(DiagKind::Unsupported, e.span, "structural `==` is not allowed in constant initializers");
            }
            _ => {}
        }
        visit::walk_expr(self, e);
    }
}

/// Type checks a function (signature already lowered).
pub fn check_fn(ck: &mut Checker, id: ItemId, inputs: &[syn::FnArg], block: &syn::Block) -> Option<FnDef> {
    let sig = ck.sigs.get(&id)?.clone();
    let it = ck.res.items[id.0 as usize].clone();
    let ghost = it.ghost || sig.kind.is_ghost();
    let lifted = !ghost && ck.res.mods[it.module.0 as usize].lifted;
    let mut cx = Cx::new(ck, it.module, Some(id), sig.kind, ghost, sig.ret.clone(), sig.gen_scope.clone(), sig.feature_set.clone());
    cx.lift = lifted;
    cx.push_scope();
    let mut params = Vec::new();
    for (i, input) in inputs.iter().enumerate() {
        let ty = sig.params.get(i).cloned().unwrap_or(Ty::Error);
        match input {
            syn::FnArg::Receiver(r) => {
                let span = cx.sp(r.span());
                let l = cx.new_local("self", ty.clone(), r.mutability.is_some() && r.reference.is_none(), false, span);
                params.push(Param { pat: Pat { kind: PatKind::Binding { local: l, mode: BindingMode::ByValue, sub: None }, ty: ty.clone(), span }, ty, lts: Lifetimes::default(), span, ghost: false });
            }
            syn::FnArg::Typed(pt) => {
                let span = cx.sp(pt.span());
                let ghost_param = sig.ghost_params.get(i).copied().unwrap_or(false);
                let saved = cx.ghost;
                cx.ghost |= ghost_param;
                let pat = cx.irrefutable_pat(&pt.pat, &ty, "function parameter");
                cx.ghost = saved;
                let lts = sig.param_lts.get(i).cloned().unwrap_or_default();
                params.push(Param { pat, ty, lts, span, ghost: ghost_param });
            }
        }
    }
    // contracts (ghost context)
    let saved = cx.ghost;
    cx.ghost = true;
    let mut requires: Vec<Expr> = sig.contracts.requires.iter().map(|r| cx.prop(r)).collect();
    let mut ensures = sig.contracts.ensures.as_ref().map(|e| cx.ensures(e, &sig.ret));
    let contract_ensures = sig.contracts.contract_ensures.as_ref().map(|c| c.as_ref().map(|e| cx.ensures(e, &sig.ret)));
    let decreases = sig.contracts.decreases.as_ref().map(|(e, max)| {
        let measure = cx.measure(e);
        Decreases { measure, max: *max }
    });
    // §15 annotations (ghost context, parameters in scope)
    let mut spec = cx.lower_fn_spec(&sig);
    if contract_ensures.is_some() && ensures.is_none() {
        cx.err(DiagKind::Contract, sig.sig_span, "`#[contract_ensures]` without `#[ensures]`");
    }
    spec.contract_ensures = contract_ensures;
    spec.attached = sig.contracts.lift_src.clone();
    let induction = sig.spec.induction.as_ref().and_then(|(x, _)| cx.lookup_local(x));
    // `#[induction(n)]` on a `Nat`/`Int` parameter implies the measure `n`
    // (`#[decreases(n)]`): the elaborator checks it at every `ih(..)`
    let decreases = match (decreases, induction, &sig.spec.induction) {
        (None, Some(l), Some((_, isp))) if matches!(cx.local_ty(l), Ty::Nat | Ty::Int) => Some(Decreases { measure: Expr::new(ExprKind::Local(l), cx.local_ty(l), *isp), max: None }),
        (d, _, _) => d,
    };
    cx.ghost = saved;
    // body
    let mut law_proof = None;
    let body = match sig.kind {
        FnKind::Exec => FnBody::Exec(cx.block_expr(block, &Exp::Ty(sig.ret.clone()), cx.sp(block.span()))),
        FnKind::Spec => {
            let exp = if sig.ret == Ty::Prop { Exp::Prop } else { Exp::Ty(sig.ret.clone()) };
            let body = cx.block_expr(block, &exp, cx.sp(block.span()));
            FnBody::Spec(cx.desugar_exits(body, &sig.ret))
        }
        FnKind::Lemma | FnKind::Law | FnKind::Proof => {
            if !sig.ret.is_unit() {
                cx.err(DiagKind::Contract, sig.sig_span, format!("`#[{}]` functions return `()`; state results with `ensures(..)`", sig.kind.name()));
            }
            let (req, ens, steps, n_header) = cx.fn_script(block, sig.kind);
            requires.extend(req);
            if let Some(e) = ens {
                if ensures.is_some() {
                    cx.err(DiagKind::Contract, e.span, "duplicate `ensures`");
                }
                ensures = Some(Ensures { binder: Pat { kind: PatKind::Wild, ty: Ty::unit(), span: e.span }, prop: e });
            }
            match sig.kind {
                FnKind::Law => {
                    // the replayed header `let`s are not a proof: a law
                    // with nothing else is a claim, proven by its
                    // `#[proof]` item (its contract carries the `let`s)
                    if steps.len() == n_header {
                        law_proof = Some(LawProof::Missing);
                        FnBody::Claim
                    } else {
                        law_proof = Some(LawProof::Inline);
                        FnBody::Script(steps)
                    }
                }
                _ => FnBody::Script(steps),
            }
        }
    };
    // the declared contract carried apart (typed last: the body's locals keep their ids)
    let saved = std::mem::replace(&mut cx.ghost, true);
    let declared = sig.contracts.declared.as_ref().map(|(r, d)| (r.iter().map(|e| cx.prop(e)).collect(), d.as_ref().map(|(e, max)| Decreases { measure: cx.measure(e), max: *max })));
    cx.ghost = saved;
    cx.pop_scope();
    let locals = std::mem::take(&mut cx.locals);
    Some(FnDef {
        kind: sig.kind,
        owner: sig.owner,
        receiver: sig.receiver,
        generics: sig.generics.clone(),
        lifetimes: sig.lifetimes.clone(),
        impl_block: sig.impl_block,
        impl_lifetimes: sig.impl_lifetimes.clone(),
        impl_self_lts: sig.impl_self_lts.clone(),
        params,
        ret: sig.ret.clone(),
        ret_lts: sig.ret_lts.clone(),
        requires,
        panics: sig.contracts.panics_when.is_some(),
        ensures,
        decreases,
        declared,
        body,
        target_features: sig.target_features.clone(),
        feature_set: sig.feature_set.clone(),
        inline: sig.inline,
        must_use: sig.must_use,
        recursion: Recursion::None,
        law_proof,
        proves: None,
        induction,
        spec,
        locals,
        sig_span: sig.sig_span,
        sig_text: sig.sig_text.clone(),
    })
}

impl<'c, 'a> Cx<'c, 'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(ck: &'c mut Checker<'a>, m: ModId, item: Option<ItemId>, kind: FnKind, ghost: bool, ret: Ty, g: GenScope, features: Vec<String>) -> Cx<'c, 'a> {
        Cx { ck, m, item, kind, ghost, in_const: false, locals: vec![], scopes: vec![vec![]], ret, g, loop_depth: 0, loop_count: 0, features, no_exp_reason: vec![], inv_self: None, lift: false }
    }

    pub fn sp(&self, s: proc_macro2::Span) -> Span {
        self.ck.sp(self.m, s)
    }

    pub fn err(&mut self, kind: DiagKind, span: Span, msg: impl Into<String>) {
        self.ck.err(kind, span, msg);
    }

    pub fn push(&mut self, d: Diagnostic) {
        self.ck.diags.push(d);
    }

    pub fn tys(&self, t: &Ty) -> String {
        self.ck.ty_str(t)
    }

    pub fn push_scope(&mut self) {
        self.scopes.push(vec![]);
    }

    pub fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    /// Declares a local in the innermost scope.
    pub fn new_local(&mut self, name: &str, ty: Ty, mutable: bool, ghost: bool, span: Span) -> LocalId {
        let id = LocalId(self.locals.len() as u32);
        self.locals.push(LocalDecl { name: name.to_string(), ty, mutable, ghost: ghost || self.ghost, span });
        self.scopes.last_mut().unwrap().push((name.to_string(), id));
        id
    }

    /// Adds an already-declared local to the innermost scope (or-patterns).
    pub fn bind_existing(&mut self, name: &str, id: LocalId) {
        self.scopes.last_mut().unwrap().push((name.to_string(), id));
    }

    pub fn lookup_local(&self, name: &str) -> Option<LocalId> {
        for s in self.scopes.iter().rev() {
            if let Some((_, id)) = s.iter().rev().find(|(n, _)| n == name) {
                return Some(*id);
            }
        }
        None
    }

    pub fn local_ty(&self, id: LocalId) -> Ty {
        self.locals[id.0 as usize].ty.clone()
    }

    // ------------------------------------------------------------------
    // coercions
    // ------------------------------------------------------------------

    /// `check(e, t)`: type `e` against `t` and coerce.
    pub fn check(&mut self, e: &syn::Expr, t: &Ty) -> Expr {
        self.no_exp_reason.push("");
        let x = self.expr(e, &Exp::Ty(t.clone()));
        self.no_exp_reason.pop();
        self.coerce(x, t)
    }

    /// Synthesizes the type of `e` (no expectation).
    pub fn infer(&mut self, e: &syn::Expr) -> Expr {
        self.expr(e, &Exp::None)
    }

    /// Applies the coercions allowed at a coercion site.
    pub fn coerce(&mut self, e: Expr, t: &Ty) -> Expr {
        if e.ty == *t || e.ty.is_never() || e.ty.is_error() || t.is_error() {
            return e;
        }
        let span = e.span;
        match (&e.ty, t) {
            (Ty::Ref(a), Ty::Ref(b)) => {
                if let (Ty::Array(ea, _), Ty::Slice(eb)) = (&**a, &**b)
                    && ea == eb {
                        return Expr::new(ExprKind::Coerce(Coercion::Unsize, Box::new(e)), t.clone(), span);
                    }
                if let Ty::Ref(inner) = &**a {
                    let inner = (**inner).clone();
                    let d = Expr::new(ExprKind::Coerce(Coercion::AutoDeref, Box::new(e)), Ty::Ref(Box::new(inner)), span);
                    return self.coerce(d, t);
                }
            }
            (Ty::Bool, Ty::Prop) => return Expr::new(ExprKind::Coerce(Coercion::BoolToProp, Box::new(e)), Ty::Prop, span),
            _ => {}
        }
        if self.ghost && self.view_coercible(&e.ty, t) {
            return Expr::new(ExprKind::Coerce(Coercion::View, Box::new(e)), t.clone(), span);
        }
        let (a, b) = (self.tys(t), self.tys(&e.ty));
        self.err(DiagKind::Type, span, format!("mismatched types: expected `{a}`, found `{b}`"));
        Expr { ty: t.clone(), ..e }
    }

    /// Wraps `e` in auto-derefs until its type is not a reference.
    pub fn autoderef(&mut self, mut e: Expr) -> Expr {
        while let Ty::Ref(inner) = e.ty.clone() {
            let span = e.span;
            e = Expr::new(ExprKind::Coerce(Coercion::AutoDeref, Box::new(e)), *inner, span);
        }
        e
    }

    /// Derefs one reference level (operands of arithmetic operators).
    fn deref_once(&mut self, e: Expr) -> Expr {
        if let Ty::Ref(inner) = e.ty.clone() {
            let span = e.span;
            return Expr::new(ExprKind::Coerce(Coercion::AutoDeref, Box::new(e)), *inner, span);
        }
        e
    }

    fn error_expr(span: Span) -> Expr {
        Expr::new(ExprKind::Tuple(vec![]), Ty::Error, span)
    }

    // ------------------------------------------------------------------
    // expressions
    // ------------------------------------------------------------------

    /// Types an expression under an expectation (without the final coercion).
    pub fn expr(&mut self, e: &syn::Expr, exp: &Exp) -> Expr {
        if let Exp::Prop = exp {
            return self.prop_expr(e);
        }
        let span = self.sp(e.span());
        match e {
            syn::Expr::Lit(l) => self.lit(&l.lit, exp, span),
            syn::Expr::Paren(p) => self.expr(&p.expr, exp),
            syn::Expr::Group(g) => self.expr(&g.expr, exp),
            syn::Expr::Path(p) => self.path_expr(p, exp, span),
            syn::Expr::Binary(b) => self.binary(b, exp, span),
            syn::Expr::Unary(u) => self.unary(u, exp, span),
            syn::Expr::Cast(c) => self.cast(c, span),
            syn::Expr::Reference(r) => self.reference(r, exp, span),
            syn::Expr::Index(i) => self.index(i, span),
            syn::Expr::Field(f) => self.field(f, span),
            syn::Expr::Call(c) => self.call(c, exp, span),
            syn::Expr::MethodCall(mc) => self.method_call(mc, exp, span),
            syn::Expr::Struct(s) => self.struct_lit(s, exp, span),
            syn::Expr::Tuple(t) => {
                if t.elems.len() > 12 {
                    self.err(DiagKind::Unsupported, span, "tuples are limited to 12 elements");
                }
                let expected: Option<Vec<Ty>> = match exp.ty() {
                    Some(Ty::Tuple(ts)) if ts.len() == t.elems.len() => Some(ts.clone()),
                    _ => None,
                };
                let es: Vec<Expr> = t.elems.iter().enumerate().map(|(i, x)| match &expected {
                    Some(ts) => self.check(x, &ts[i]),
                    None => self.infer(x),
                }).collect();
                let ty = Ty::Tuple(es.iter().map(|x| x.ty.clone()).collect());
                Expr::new(ExprKind::Tuple(es), ty, span)
            }
            syn::Expr::Array(a) => self.array_lit(a, exp, span),
            syn::Expr::Repeat(r) => {
                let n = match self.ck.ce.eval(self.m, &r.len, Some(UintTy::Usize)) {
                    Ok(n) => n as u64,
                    Err(msg) => {
                        self.err(DiagKind::Type, span, format!("repeat length must be a literal or constant: {msg}"));
                        0
                    }
                };
                let elem = match exp.ty() {
                    Some(Ty::Array(t, _)) => {
                        let t = (**t).clone();
                        self.check(&r.expr, &t)
                    }
                    _ => self.infer(&r.expr),
                };
                let ty = Ty::array(elem.ty.clone(), n);
                Expr::new(ExprKind::Repeat { elem: Box::new(elem), count: n }, ty, span)
            }
            syn::Expr::Block(b) => {
                if b.label.is_some() {
                    self.err(DiagKind::Loop, span, "labeled blocks are not supported");
                }
                self.block_expr(&b.block, exp, span)
            }
            syn::Expr::Unsafe(_) => {
                self.push(Diagnostic::error(DiagKind::Unsupported, span, "`unsafe` blocks are not allowed").note("the DSL crate is `#![forbid(unsafe_code)]` (DESIGN.md §2)"));
                Self::error_expr(span)
            }
            syn::Expr::If(i) => self.if_expr(i, exp, span),
            syn::Expr::Match(m) => self.match_expr(m, exp, span),
            syn::Expr::ForLoop(f) => self.for_loop(f, span),
            syn::Expr::While(w) => self.while_loop(w, span),
            syn::Expr::Loop(_) => {
                self.push(Diagnostic::error(DiagKind::Loop, span, "`loop` is not supported").note("use `for i in a..b` or `while cond` with `decreases` (DESIGN.md §3.3)"));
                Self::error_expr(span)
            }
            syn::Expr::Break(_) => {
                self.err(DiagKind::Loop, span, "`break` is not supported");
                Expr::new(ExprKind::Unreachable, Ty::Never, span)
            }
            syn::Expr::Continue(_) => {
                self.err(DiagKind::Loop, span, "`continue` is not supported");
                Expr::new(ExprKind::Unreachable, Ty::Never, span)
            }
            syn::Expr::Return(r) => self.return_expr(r.expr.as_deref(), span),
            syn::Expr::Try(t) => self.try_expr(&t.expr, span),
            syn::Expr::Macro(m) => self.macro_expr(&m.mac, exp, span),
            syn::Expr::Closure(c) if self.ghost => self.lambda_expr(c, exp, span),
            syn::Expr::Closure(_) => {
                self.push(Diagnostic::error(DiagKind::Closure, span, "closures are not supported in exec code").note("closure syntax is only allowed in ghost code: lambdas `|x: T| e` of type `fn(T) -> U`, `forall`, `exists`, `#[ensures(|ret| ..)]`, `rewrite(h, |x| ..)`"));
                Self::error_expr(span)
            }
            syn::Expr::Assign(_) => {
                self.err(DiagKind::Unsupported, span, "assignment is only allowed as a statement");
                Self::error_expr(span)
            }
            syn::Expr::Range(_) => {
                self.err(DiagKind::Unsupported, span, "ranges are only allowed in `for` loops and slice indexing (`&s[a..b]`)");
                Self::error_expr(span)
            }
            syn::Expr::Let(_) => {
                self.err(DiagKind::Unsupported, span, "`let` expressions are only allowed as the whole condition of `if let`");
                Self::error_expr(span)
            }
            syn::Expr::RawAddr(_) => {
                self.err(DiagKind::RawPointer, span, "raw pointers are not supported");
                Self::error_expr(span)
            }
            _ => {
                self.err(DiagKind::Unsupported, span, "unsupported expression");
                Self::error_expr(span)
            }
        }
    }

    fn lit(&mut self, l: &syn::Lit, exp: &Exp, span: Span) -> Expr {
        match l {
            syn::Lit::Bool(b) => Expr::new(ExprKind::Lit(Lit::Bool(b.value)), Ty::Bool, span),
            syn::Lit::Byte(b) => Expr::new(ExprKind::Lit(Lit::Int(b.value() as u128)), Ty::u8(), span),
            syn::Lit::Int(i) => {
                let v: u128 = match i.base10_parse() {
                    Ok(v) => v,
                    Err(_) => {
                        self.err(DiagKind::Literal, span, "integer literal is too large");
                        return Self::error_expr(span);
                    }
                };
                let suffix = i.suffix();
                let ty = if suffix.is_empty() {
                    match exp.ty() {
                        Some(Ty::Uint(w)) => Ty::Uint(*w),
                        Some(Ty::Int) => Ty::Int,
                        Some(Ty::Nat) => Ty::Nat,
                        Some(Ty::I32) => Ty::I32,
                        Some(Ty::Error) => return Self::error_expr(span),
                        // ghost code: unsuffixed literals default to `Nat` (§4.1)
                        None if self.ghost => Ty::Nat,
                        Some(other) => {
                            let t = self.tys(other);
                            self.err(DiagKind::Type, span, format!("mismatched types: expected `{t}`, found integer literal"));
                            return Self::error_expr(span);
                        }
                        None => {
                            self.literal_needs_type(span);
                            return Self::error_expr(span);
                        }
                    }
                } else if let Some(w) = UintTy::from_name(suffix) {
                    Ty::Uint(w)
                } else if suffix == "i32" && matches!(exp.ty(), Some(Ty::I32)) {
                    Ty::I32
                } else {
                    match suffix {
                        "i8" | "i16" | "i32" | "i64" | "isize" => {
                            self.push(Diagnostic::error(DiagKind::Signed, span, format!("signed literal suffix `{suffix}` is not supported")).note("signed integers are reserved; only literal `i32` immediates of intrinsics are allowed"));
                        }
                        "u128" | "i128" => {
                            self.err(DiagKind::Wide, span, format!("`{suffix}` literals are not supported"));
                        }
                        "f32" | "f64" => self.err(DiagKind::Float, span, "floating point literals are not supported"),
                        _ => self.err(DiagKind::Literal, span, format!("unknown literal suffix `{suffix}`")),
                    }
                    return Self::error_expr(span);
                };
                match &ty {
                    Ty::Uint(w) if v > w.max_value() => {
                        self.push(Diagnostic::error(DiagKind::Literal, span, format!("literal out of range for `{}`", w.name())).note(format!("the literal `{v}` does not fit into `{}` whose range is `0..={}`", w.name(), w.max_value())));
                    }
                    Ty::I32 if v > i32::MAX as u128 => self.err(DiagKind::Literal, span, "literal out of range for `i32`"),
                    _ => {}
                }
                Expr::new(ExprKind::Lit(Lit::Int(v)), ty, span)
            }
            syn::Lit::Float(_) => {
                self.err(DiagKind::Float, span, "floating point literals are not supported");
                Self::error_expr(span)
            }
            syn::Lit::ByteStr(bs) if self.ghost => {
                // ghost `b".."` (§4.1): a `[u8; N]` literal
                let bytes = bs.value();
                let es: Vec<Expr> = bytes.iter().map(|b| Expr::new(ExprKind::Lit(Lit::Int(*b as u128)), Ty::u8(), span)).collect();
                Expr::new(ExprKind::Array(es), Ty::array(Ty::u8(), bytes.len() as u64), span)
            }
            _ => {
                self.err(DiagKind::Unsupported, span, "string, character and byte-string literals are not supported");
                Self::error_expr(span)
            }
        }
    }

    fn literal_needs_type(&mut self, span: Span) {
        let reason = self.no_exp_reason.last().copied().unwrap_or("");
        let d = match reason {
            "cast" => Diagnostic::error(DiagKind::Literal, span, "unsuffixed literal in the operand of `as`")
                .note("rustc would type this literal as `i32` (the cast target is not an expectation for compound operands)")
                .note("write a suffix (e.g. `1u64`) or combine it with a typed operand (DESIGN.md §3.6)"),
            "shift" => Diagnostic::error(DiagKind::Literal, span, "unsuffixed literal as the right operand of a shift")
                .note("rustc would type this literal as `i32`; write a suffix (e.g. `3u32`) (DESIGN.md §3.6)"),
            _ => Diagnostic::error(DiagKind::Literal, span, "cannot infer the type of this literal; annotate it").note("add a suffix (e.g. `0u32`) or a type annotation (DESIGN.md §3.6)"),
        };
        self.push(d);
    }

    fn array_lit(&mut self, a: &syn::ExprArray, exp: &Exp, span: Span) -> Expr {
        let n = a.elems.len() as u64;
        let elem_ty: Option<Ty> = match exp.ty() {
            Some(Ty::Array(t, m)) => {
                if *m != n {
                    self.err(DiagKind::Type, span, format!("mismatched types: expected an array of {m} elements, found {n}"));
                }
                Some((**t).clone())
            }
            _ => None,
        };
        let mut out: Vec<Option<Expr>> = vec![None; a.elems.len()];
        let mut t = elem_ty;
        if t.is_none()
            && let Some((i, e)) = a.elems.iter().enumerate().find(|(_, e)| !needs_exp(e)) {
                let x = self.infer(e);
                t = Some(x.ty.clone());
                out[i] = Some(x);
            }
        let t = match t {
            Some(t) => t,
            None => {
                if a.elems.is_empty() {
                    self.err(DiagKind::Type, span, "cannot infer the element type of an empty array; annotate it");
                } else {
                    let _ = self.infer(&a.elems[0]);
                }
                return Self::error_expr(span);
            }
        };
        let es: Vec<Expr> = a.elems.iter().enumerate().map(|(i, e)| match out[i].take() {
            Some(x) => self.coerce(x, &t),
            None => self.check(e, &t),
        }).collect();
        Expr::new(ExprKind::Array(es), Ty::array(t, n), span)
    }

    // ------------------------------------------------------------------
    // paths
    // ------------------------------------------------------------------

    /// Lowers the generic arguments of a path segment: (types, const ints).
    fn seg_args(&mut self, seg: &syn::PathSegment) -> (Vec<Ty>, Vec<(i128, Span)>) {
        let mut tys = Vec::new();
        let mut consts = Vec::new();
        if let syn::PathArguments::AngleBracketed(a) = &seg.arguments {
            for arg in &a.args {
                match arg {
                    syn::GenericArgument::Type(syn::Type::Path(tp)) if tp.qself.is_none() && tp.path.segments.len() == 1 && self.const_like_ident(&tp.path) => {
                        // a const item used as a const generic argument (`::<N>`)
                        let e: syn::Expr = syn::Expr::Path(syn::ExprPath { attrs: vec![], qself: None, path: tp.path.clone() });
                        let span = self.sp(tp.span());
                        match self.ck.ce.eval(self.m, &e, None) {
                            Ok(v) => consts.push((v as i128, span)),
                            Err(msg) => self.err(DiagKind::Type, span, msg),
                        }
                    }
                    syn::GenericArgument::Type(t) => {
                        let g = self.g.clone();
                        let ghost = self.ghost;
                        tys.push(self.ck.lower_ty(self.m, t, &g, ghost || self.lift));
                    }
                    syn::GenericArgument::Const(e) => {
                        let span = self.sp(e.span());
                        match const_int(e) {
                            Some(v) => consts.push((v, span)),
                            None => match self.ck.ce.eval(self.m, e, None) {
                                Ok(v) => consts.push((v as i128, span)),
                                Err(msg) => self.err(DiagKind::Type, span, format!("const argument must be a literal or constant: {msg}")),
                            },
                        }
                    }
                    syn::GenericArgument::Lifetime(_) => {}
                    other => self.err(DiagKind::Unsupported, self.sp(other.span()), "unsupported generic argument"),
                }
            }
        }
        (tys, consts)
    }

    /// Whether a single-ident path names a const item (so `::<N>` is a const
    /// argument, not a type).
    fn const_like_ident(&self, p: &syn::Path) -> bool {
        let name = p.segments[0].ident.to_string();
        matches!(self.ck.res.lookup(self.m, &name, Ns::Value, self.ghost || self.lift), Some((Def::Item(id), _)) if self.ck.res.items[id.0 as usize].tag == ItemTag::Const) && self.ck.res.lookup(self.m, &name, Ns::Type, self.ghost || self.lift).is_none()
    }

    fn check_ghost_ref(&mut self, id: ItemId, span: Span) {
        let it = &self.ck.res.items[id.0 as usize];
        if it.ghost && !self.ghost && !self.lift {
            let name = it.name.clone();
            self.push(Diagnostic::error(DiagKind::Ghost, span, format!("exec code refers to ghost item `{name}`")).note("ghost items (`#[cfg(sandblaster)]`) are never compiled; exec code cannot use them"));
        }
    }

    /// Resolves a value path.
    pub fn value_path(&mut self, path: &syn::Path, span: Span) -> Option<VRes> {
        let n = path.segments.len();
        let segs: Vec<(String, Span)> = path.segments.iter().map(|s| (s.ident.to_string(), self.sp(s.ident.span()))).collect();
        let last_seg = path.segments.last().unwrap();
        if n == 1 && path.leading_colon.is_none()
            && let Some(l) = self.lookup_local(&segs[0].0) {
                if !matches!(last_seg.arguments, syn::PathArguments::None) {
                    self.err(DiagKind::Type, span, "unexpected generic arguments on a local");
                }
                return Some(VRes::Local(l));
            }
        let (own_tys, own_consts) = self.seg_args(last_seg);
        if n >= 2 && path.leading_colon.is_none() {
            let prefix = &path.segments.iter().take(n - 1).collect::<Vec<_>>();
            let last = segs[n - 1].0.clone();
            // `u32::X`
            if prefix.len() == 1 {
                let pname = prefix[0].ident.to_string();
                if let Some(w) = UintTy::from_name(&pname)
                    && self.ck.res.lookup(self.m, &pname, Ns::Type, self.ghost || self.lift).is_none() {
                        return match last.as_str() {
                            "MAX" => Some(VRes::BuiltinConst(BuiltinConst::Max(w))),
                            "MIN" => Some(VRes::BuiltinConst(BuiltinConst::Min(w))),
                            "BITS" => Some(VRes::BuiltinConst(BuiltinConst::Bits(w))),
                            other => match IntMethod::from_name(other) {
                                Some(m) => Some(VRes::IntAssoc(w, m)),
                                None => {
                                    self.push(Diagnostic::error(DiagKind::Resolve, segs[n - 1].1, format!("`{}::{other}` is not in the method whitelist", w.name())).note("see DESIGN.md §3.4"));
                                    None
                                }
                            },
                        };
                    }
                if pname == "Self" {
                    return match self.g.self_ty.clone() {
                        Some(Ty::Adt(id, args)) => self.type_relative(id, Some(args), &last, own_tys, segs[n - 1].1),
                        _ => {
                            self.err(DiagKind::Resolve, span, "`Self` is only available in inherent impls");
                            None
                        }
                    };
                }
            }
            let psegs = &segs[..n - 1];
            if let Ok(def) = self.ck.res.resolve_path_defs(self.m, psegs, Ns::Type, false, self.ghost || self.lift) {
                let pargs = self.seg_args(prefix[n - 2]).0;
                let pargs = if pargs.is_empty() { None } else { Some(pargs) };
                match def {
                    Def::Item(id) => match self.ck.res.items[id.0 as usize].tag.clone() {
                        ItemTag::Struct { .. } => {
                            self.check_ghost_ref(id, span);
                            return self.type_relative(id, pargs, &last, own_tys, segs[n - 1].1);
                        }
                        ItemTag::Alias => {
                            if let Ty::Adt(aid, args) = self.ck.alias_ty(id) {
                                return self.type_relative(aid, Some(args), &last, own_tys, segs[n - 1].1);
                            }
                        }
                        ItemTag::Enum { variants, .. } => {
                            self.check_ghost_ref(id, span);
                            if !variants.iter().any(|(v, _)| *v == last) {
                                return self.type_relative(id, pargs, &last, own_tys, segs[n - 1].1);
                            }
                            // fall through: variant resolution below (keeps privacy/namespace checks)
                            let idx = variants.iter().position(|(v, _)| *v == last).unwrap();
                            let args = pargs.or(if own_tys.is_empty() { None } else { Some(own_tys.clone()) });
                            return Some(VRes::Ctor(Ctor::Variant(id, idx as u32), args));
                        }
                        _ => {}
                    },
                    Def::Ext(Ext::OptionEnum) => {
                        let args = pargs.or(if own_tys.is_empty() { None } else { Some(own_tys.clone()) });
                        return match last.as_str() {
                            "Some" => Some(VRes::Ctor(Ctor::Some, args)),
                            "None" => Some(VRes::Ctor(Ctor::None, args)),
                            _ => {
                                self.push(Diagnostic::error(DiagKind::Resolve, segs[n - 1].1, format!("`Option::{last}` is not supported")).note("allowed: `is_some`, `is_none`, `unwrap_or` as methods; `Some`, `None`"));
                                None
                            }
                        };
                    }
                    _ => {}
                }
            }
        }
        let def = match self.ck.res.resolve_path_defs(self.m, &segs, Ns::Value, path.leading_colon.is_some(), self.ghost || self.lift) {
            Ok(d) => d,
            Err(d) => {
                // a hint for type-namespace-only names used as values
                self.push(d);
                return None;
            }
        };
        let own_opt = if own_tys.is_empty() { None } else { Some(own_tys.clone()) };
        match def {
            Def::Item(id) => {
                self.check_ghost_ref(id, span);
                match self.ck.res.items[id.0 as usize].tag.clone() {
                    ItemTag::Fn => Some(VRes::Fn(id, None, own_tys)),
                    ItemTag::Const => Some(VRes::Const(id)),
                    ItemTag::Struct { .. } => Some(VRes::Ctor(Ctor::Struct(id), own_opt)),
                    _ => {
                        self.err(DiagKind::Resolve, span, "expected a value");
                        None
                    }
                }
            }
            Def::Variant(id, i) => {
                self.check_ghost_ref(id, span);
                Some(VRes::Ctor(Ctor::Variant(id, i), own_opt))
            }
            Def::Ext(Ext::SomeCtor) => Some(VRes::Ctor(Ctor::Some, own_opt)),
            Def::Ext(Ext::NoneCtor) => Some(VRes::Ctor(Ctor::None, own_opt)),
            Def::Ext(Ext::Intrinsic(i)) => {
                // immediates are literal `i32` const arguments (§9.2)
                if let syn::PathArguments::AngleBracketed(a) = &last_seg.arguments {
                    for arg in &a.args {
                        let lit = matches!(arg, syn::GenericArgument::Const(e) if imm_literal(e).is_some() || matches!(e, syn::Expr::Block(b) if b.block.stmts.len() == 1 && matches!(&b.block.stmts[0], syn::Stmt::Expr(x, None) if imm_literal(x).is_some())));
                        if !lit {
                            let s = self.sp(arg.span());
                            self.push(Diagnostic::error(DiagKind::Type, s, "intrinsic immediates must be integer literals").note("stdarch immediates are `const IMM: i32` generics; constants of unsigned type would not type check in rustc (DESIGN.md §9.2)"));
                        }
                    }
                }
                let imms = own_consts.iter().map(|(v, _)| *v as i64).collect();
                Some(VRes::Intrinsic(i, imms))
            }
            Def::Ext(Ext::GhostFn(g)) => Some(VRes::Ghost(g, own_tys)),
            Def::Ext(Ext::GhostKw(k)) => Some(VRes::GhostKw(k)),
            Def::Ext(Ext::IsizeMax) => Some(VRes::BuiltinConst(BuiltinConst::IsizeMax)),
            _ => {
                self.err(DiagKind::Resolve, span, "expected a value");
                None
            }
        }
    }

    /// `Type::name`: an enum variant or an inherent function.
    fn type_relative(&mut self, id: ItemId, args: Option<Vec<Ty>>, name: &str, own: Vec<Ty>, span: Span) -> Option<VRes> {
        if let ItemTag::Enum { variants, .. } = &self.ck.res.items[id.0 as usize].tag
            && let Some(i) = variants.iter().position(|(v, _)| v == name) {
                return Some(VRes::Ctor(Ctor::Variant(id, i as u32), args));
            }
        let methods: Vec<ItemId> = match &self.ck.hir_items[id.0 as usize] {
            Some(ItemKind::Struct(s)) => s.methods.clone(),
            Some(ItemKind::Enum(e)) => e.methods.clone(),
            _ => vec![],
        };
        for f in methods {
            if self.ck.res.items[f.0 as usize].name == name {
                self.check_ghost_ref(f, span);
                let fit = &self.ck.res.items[f.0 as usize];
                if !self.ck.res.visible(fit.vis, fit.module, self.m) {
                    self.err(DiagKind::Privacy, span, format!("associated function `{name}` is private"));
                }
                return Some(VRes::Fn(f, args, own));
            }
        }
        let tname = self.ck.res.items[id.0 as usize].name.clone();
        self.err(DiagKind::Resolve, span, format!("no associated item named `{name}` found for `{tname}`"));
        None
    }

    fn path_expr(&mut self, p: &syn::ExprPath, exp: &Exp, span: Span) -> Expr {
        if p.qself.is_some() {
            self.err(DiagKind::Trait, span, "qualified paths (`<T>::f`) are not supported in source; use method syntax");
            return Self::error_expr(span);
        }
        if self.inv_self.is_some() && p.path.is_ident("self") {
            self.invariant_bare_self(span);
            return Self::error_expr(span);
        }
        let Some(r) = self.value_path(&p.path, span) else { return Self::error_expr(span) };
        match r {
            VRes::Local(l) => {
                let ty = self.local_ty(l);
                if self.locals[l.0 as usize].ghost && !self.ghost {
                    self.err(DiagKind::Ghost, span, "exec code refers to a ghost variable");
                }
                Expr::new(ExprKind::Local(l), ty, span)
            }
            VRes::Const(id) => {
                let ty = self.ck.const_tys.get(&id).cloned().unwrap_or(Ty::Error);
                if self.in_const {
                    // rustc allows consts in consts
                }
                Expr::new(ExprKind::Const(id), ty, span)
            }
            VRes::BuiltinConst(c) => {
                let ty = match c {
                    BuiltinConst::Max(w) | BuiltinConst::Min(w) => Ty::Uint(w),
                    BuiltinConst::Bits(_) => Ty::u32(),
                    BuiltinConst::IsizeMax => {
                        if !self.ghost {
                            self.err(DiagKind::Ghost, span, "`ISIZE_MAX` is a ghost constant (`Int`)");
                        }
                        Ty::Int
                    }
                };
                Expr::new(ExprKind::BuiltinConst(c), ty, span)
            }
            VRes::Ctor(c, args) => {
                let shape = self.ctor_shape(c);
                if shape == Shape::Tuple && self.ghost && args.is_none() && self.ctor_fields(c).1 == 0 {
                    return self.ctor_value(c, span);
                }
                if shape != Shape::Unit {
                    self.push(Diagnostic::error(DiagKind::Closure, span, "constructors cannot be used as function values").note("call the constructor with its fields (ghost code may pass a tuple constructor of a non-generic type as a function value)"));
                    return Self::error_expr(span);
                }
                self.ctor_app(c, args, &[], exp, span)
            }
            VRes::Fn(id, impl_args, own) if self.ghost => self.fn_value(id, impl_args, own, exp, span),
            VRes::Fn(..) | VRes::IntAssoc(..) | VRes::Intrinsic(..) | VRes::Ghost(..) => {
                self.push(Diagnostic::error(DiagKind::Closure, span, "functions cannot be used as values (no function pointers)").note("call the function instead; ghost code may pass a spec function as a function value"));
                Self::error_expr(span)
            }
            VRes::GhostKw(_) => {
                self.err(DiagKind::Script, span, "quantifiers and connectives must be applied");
                Self::error_expr(span)
            }
        }
    }

    /// Whether `t` mentions a type parameter left open by generic inference
    /// ([`Cx::subst_partial`] names them `?`).
    fn has_open_param(t: &Ty) -> bool {
        let mut open = false;
        t.walk(&mut |x| open |= matches!(x, Ty::Param(_, n) if n == "?"));
        open
    }

    /// A ghost lambda `|x: A, y| e` (DESIGN.md §13.2): an unannotated binder
    /// takes its type from the expected function type; the body is checked
    /// against the expected result when that is known. A `Nat` result is
    /// viewed as `Int` (no bound travels with a function value). The body
    /// may read the enclosing locals but not assign them, and may not
    /// `return`, use `?` or loop: it is a total expression.
    fn lambda_expr(&mut self, c: &syn::ExprClosure, exp: &Exp, span: Span) -> Expr {
        if c.movability.is_some() || c.asyncness.is_some() || c.capture.is_some() || c.constness.is_some() || c.lifetimes.is_some() {
            self.err(DiagKind::Closure, span, "a ghost lambda is written `|x: T, ..| e` (no `move`, `async`, `static`, `const` or `for<..>`)");
        }
        let expected: Option<(Vec<Ty>, Ty)> = match exp.ty() {
            Some(Ty::Fn(ps, r)) => Some((ps.clone(), (**r).clone())),
            _ => None,
        };
        if let Some((ps, _)) = &expected
            && ps.len() != c.inputs.len()
        {
            self.err(DiagKind::Type, span, format!("expected a lambda of {} argument(s), found {}", ps.len(), c.inputs.len()));
        }
        let locals_before = self.locals.len();
        self.push_scope();
        let mut params = Vec::new();
        let mut tys = Vec::new();
        for (i, input) in c.inputs.iter().enumerate() {
            let ispan = self.sp(input.span());
            let exp_i = expected.as_ref().and_then(|(ps, _)| ps.get(i)).filter(|t| !Self::has_open_param(t)).cloned();
            let (pat, ann) = match input {
                syn::Pat::Type(pt) => {
                    let g = self.g.clone();
                    (&*pt.pat, Some(self.ck.lower_ty(self.m, &pt.ty, &g, true)))
                }
                p => (p, None),
            };
            let name = match pat {
                syn::Pat::Ident(pi) if pi.subpat.is_none() && pi.by_ref.is_none() && pi.mutability.is_none() => pi.ident.to_string(),
                syn::Pat::Wild(_) => "_".to_string(),
                _ => {
                    self.err(DiagKind::Closure, ispan, "lambda binders must be plain names");
                    "_".to_string()
                }
            };
            let t = match (ann, exp_i) {
                (Some(a), Some(e)) => {
                    if a != e && !a.is_error() && !e.is_error() {
                        let (x, y) = (self.tys(&e), self.tys(&a));
                        self.err(DiagKind::Type, ispan, format!("mismatched types: this lambda's binder is expected to have type `{x}`, found `{y}`"));
                    }
                    a
                }
                (Some(a), None) => a,
                (None, Some(e)) => e,
                (None, None) => {
                    self.err(DiagKind::Type, ispan, "annotate the lambda's binder: `|x: T| ..`");
                    Ty::Error
                }
            };
            if matches!(t, Ty::Nat) || t.is_ghost_only() && { let mut n = false; t.walk(&mut |x| n |= matches!(x, Ty::Nat | Ty::Prop | Ty::Proof)); n } {
                self.err(DiagKind::Type, ispan, "a lambda binder cannot mention `Nat` or `Prop` (write `Int` or `bool`: no bound travels with a function value)");
            }
            params.push(self.new_local(&name, t.clone(), false, true, ispan));
            tys.push(t);
        }
        let ret_ann = match &c.output {
            syn::ReturnType::Default => None,
            syn::ReturnType::Type(_, t) => {
                let g = self.g.clone();
                Some(self.ck.lower_ty(self.m, t, &g, true))
            }
        };
        let ret_exp = ret_ann.clone().or_else(|| expected.as_ref().map(|(_, r)| r.clone()).filter(|r| !Self::has_open_param(r)));
        let body = match &ret_exp {
            Some(r) => self.check(&c.body, r),
            None => self.infer(&c.body),
        };
        self.pop_scope();
        // `Nat` results are `Int`s (the identity view)
        let body = if body.ty == Ty::Nat { self.coerce(body, &Ty::Int) } else { body };
        // a total expression over the enclosing locals
        if crate::elab::exec::has_exit(&body) {
            self.err(DiagKind::Closure, span, "a lambda's body cannot `return` or use `?`: it is an expression");
        }
        let assigned: Vec<LocalId> = crate::elab::exec::assigned_in(&body).into_iter().filter(|l| (l.0 as usize) < locals_before).collect();
        if !assigned.is_empty() {
            self.err(DiagKind::Closure, span, "a lambda cannot assign the variables of its enclosing code");
        }
        {
            struct Loops(bool);
            impl Visitor for Loops {
                fn loop_(&mut self, _: &Loop) {
                    self.0 = true;
                }
            }
            let mut v = Loops(false);
            v.expr(&body);
            if v.0 {
                self.err(DiagKind::Closure, span, "a lambda's body cannot contain a loop");
            }
        }
        let ret = body.ty.clone();
        if matches!(ret, Ty::Prop | Ty::Proof) {
            self.err(DiagKind::Type, span, "a lambda returns a value, not a proposition (write a `bool`)");
        }
        Expr::new(ExprKind::Lambda { params, body: Box::new(body) }, Ty::Fn(tys, Box::new(ret)), span)
    }

    /// A tuple constructor of a non-generic type named as a value in ghost code,
    /// `map(ds, Tree::Pruned)`: the lambda `|x₀, ..| C(x₀, ..)`.
    fn ctor_value(&mut self, c: Ctor, span: Span) -> Expr {
        let (fields, _, ret) = self.ctor_fields(c);
        if let Some(m) = self.adt_module(c)
            && fields.iter().any(|(_, _, v)| !self.ck.res.visible(*v, m, self.m))
        {
            self.err(DiagKind::Privacy, span, "cannot construct a value with private fields here");
        }
        self.push_scope();
        let mut params = Vec::new();
        let mut args = Vec::new();
        let mut tys = Vec::new();
        for (i, (_, t, _)) in fields.iter().enumerate() {
            let mut bad = false;
            t.walk(&mut |x| bad |= matches!(x, Ty::Nat | Ty::Prop | Ty::Proof));
            if bad {
                self.pop_scope();
                self.push(Diagnostic::error(DiagKind::Type, span, "this constructor has a `Nat` field, which a function type cannot take").note("write a lambda over `Int`"));
                return Self::error_expr(span);
            }
            let l = self.new_local(&format!("x{i}"), t.clone(), false, true, span);
            params.push(l);
            args.push((i as u32, Expr::new(ExprKind::Local(l), t.clone(), span)));
            tys.push(t.clone());
        }
        self.pop_scope();
        let body = Expr::new(ExprKind::Adt { ctor: c, ty_args: vec![], fields: args, base: None }, ret.clone(), span);
        Expr::new(ExprKind::Lambda { params, body: Box::new(body) }, Ty::Fn(tys, Box::new(ret)), span)
    }

    /// A spec function named as a value in ghost code, `fold(join, a, xs)`:
    /// the lambda `|x₀, ..| f(x₀, ..)` (type arguments from a turbofish or
    /// the expected function type).
    fn fn_value(&mut self, id: ItemId, impl_args: Option<Vec<Ty>>, own: Vec<Ty>, exp: &Exp, span: Span) -> Expr {
        let Some(sig) = self.ck.sigs.get(&id).cloned() else { return Self::error_expr(span) };
        if sig.kind != FnKind::Spec || sig.owner.is_some() || sig.ghost_params.iter().any(|g| *g) || impl_args.is_some() {
            self.push(Diagnostic::error(DiagKind::Closure, span, "only a free spec function can be passed as a value").note("write a lambda: `|x: T| f(x)`"));
            return Self::error_expr(span);
        }
        let n = sig.generics.len();
        let mut sub: Vec<Option<Ty>> = vec![None; n];
        if !own.is_empty() {
            if own.len() != n {
                self.err(DiagKind::Type, span, format!("expected {n} type argument(s), found {}", own.len()));
            }
            for (i, t) in own.into_iter().enumerate().take(n) {
                sub[i] = Some(t);
            }
        }
        if let Some(Ty::Fn(ps, r)) = exp.ty() {
            for (p, q) in sig.params.iter().zip(ps) {
                if !Self::has_open_param(q) {
                    Self::unify(p, q, &mut sub);
                }
            }
            let ret = if sig.ret == Ty::Nat { Ty::Int } else { sig.ret.clone() };
            if !Self::has_open_param(r) {
                Self::unify(&ret, r, &mut sub);
            }
        }
        if sub.iter().any(|s| s.is_none()) {
            self.push(Diagnostic::error(DiagKind::Type, span, "type annotations needed").note("name the type arguments with a turbofish, or write a lambda"));
            return Self::error_expr(span);
        }
        let targs: Vec<Ty> = sub.into_iter().map(|s| s.unwrap_or(Ty::Error)).collect();
        let targs: Vec<Ty> = targs.iter().map(|t| self.ck.no_fn_in_data(t, span)).collect();
        self.push_scope();
        let mut params = Vec::new();
        let mut args = Vec::new();
        let mut tys = Vec::new();
        for (i, p) in sig.params.iter().enumerate() {
            let t = p.subst(&targs);
            let mut bad = false;
            t.walk(&mut |x| bad |= matches!(x, Ty::Nat | Ty::Prop | Ty::Proof));
            if bad {
                self.push(Diagnostic::error(DiagKind::Type, span, "this spec function takes a `Nat` (or `Prop`) parameter, which a function type cannot").note("write a lambda over `Int`: `|x: Int| ..`"));
                self.pop_scope();
                return Self::error_expr(span);
            }
            let l = self.new_local(&format!("x{i}"), t.clone(), false, true, span);
            params.push(l);
            args.push(Expr::new(ExprKind::Local(l), t.clone(), span));
            tys.push(t);
        }
        self.pop_scope();
        let ret = sig.ret.subst(&targs);
        let call = Expr::new(ExprKind::Call { callee: Callee::Item(id, targs), args }, ret, span);
        let body = if call.ty == Ty::Nat { self.coerce(call, &Ty::Int) } else { call };
        let rt = body.ty.clone();
        Expr::new(ExprKind::Lambda { params, body: Box::new(body) }, Ty::Fn(tys, Box::new(rt)), span)
    }

    pub fn ctor_shape(&self, c: Ctor) -> Shape {
        match c {
            Ctor::Struct(id) => match &self.ck.hir_items[id.0 as usize] {
                Some(ItemKind::Struct(s)) => s.shape,
                _ => Shape::Named,
            },
            Ctor::Variant(id, i) => match &self.ck.hir_items[id.0 as usize] {
                Some(ItemKind::Enum(e)) => e.variants[i as usize].shape,
                _ => Shape::Named,
            },
            Ctor::Some => Shape::Tuple,
            Ctor::None => Shape::Unit,
        }
    }

    /// Field types (generic) and generics count of a constructor.
    pub fn ctor_fields(&self, c: Ctor) -> CtorFields {
        match c {
            Ctor::Struct(id) => match &self.ck.hir_items[id.0 as usize] {
                Some(ItemKind::Struct(s)) => {
                    let n = s.generics.len();
                    let args: Vec<Ty> = s.generics.iter().enumerate().map(|(i, p)| Ty::Param(i as u32, p.name.clone())).collect();
                    (s.fields.iter().map(|f| (f.name.clone(), f.ty.clone(), f.vis)).collect(), n, Ty::Adt(id, args))
                }
                _ => (vec![], 0, Ty::Error),
            },
            Ctor::Variant(id, i) => match &self.ck.hir_items[id.0 as usize] {
                Some(ItemKind::Enum(e)) => {
                    let n = e.generics.len();
                    let args: Vec<Ty> = e.generics.iter().enumerate().map(|(i, p)| Ty::Param(i as u32, p.name.clone())).collect();
                    (e.variants[i as usize].fields.iter().map(|f| (f.name.clone(), f.ty.clone(), Vis::Public)).collect(), n, Ty::Adt(id, args))
                }
                _ => (vec![], 0, Ty::Error),
            },
            Ctor::Some => (vec![(None, Ty::Param(0, "T".into()), Vis::Public)], 1, Ty::option(Ty::Param(0, "T".into()))),
            Ctor::None => (vec![], 1, Ty::option(Ty::Param(0, "T".into()))),
        }
    }

    fn adt_module(&self, c: Ctor) -> Option<ModId> {
        match c {
            Ctor::Struct(id) | Ctor::Variant(id, _) => Some(self.ck.res.items[id.0 as usize].module),
            _ => None,
        }
    }

    /// Applies a tuple-like/unit constructor to positional arguments.
    fn ctor_app(&mut self, c: Ctor, explicit: Option<Vec<Ty>>, args: &[syn::Expr], exp: &Exp, span: Span) -> Expr {
        let (fields, n, ret) = self.ctor_fields(c);
        if fields.len() != args.len() {
            self.err(DiagKind::Type, span, format!("this constructor takes {} field(s) but {} were supplied", fields.len(), args.len()));
        }
        if let Some(m) = self.adt_module(c)
            && fields.iter().any(|(_, _, v)| !self.ck.res.visible(*v, m, self.m)) {
                self.err(DiagKind::Privacy, span, "cannot construct a value with private fields here");
            }
        let params: Vec<Ty> = fields.iter().map(|f| f.1.clone()).collect();
        let explicit: Vec<Option<Ty>> = match explicit {
            Some(v) if v.len() == n => v.into_iter().map(Some).collect(),
            Some(_) => {
                self.err(DiagKind::Type, span, format!("expected {n} type argument(s)"));
                vec![None; n]
            }
            None => vec![None; n],
        };
        let user = matches!(c, Ctor::Struct(_) | Ctor::Variant(..));
        let (es, ty_args, ty) = self.generic_call_zst(n, explicit, &params, &ret, args, exp, span, user);
        let fields = es.into_iter().enumerate().map(|(i, e)| (i as u32, e)).collect();
        Expr::new(ExprKind::Adt { ctor: c, ty_args, fields, base: None }, ty, span)
    }

    // ------------------------------------------------------------------
    // generic inference
    // ------------------------------------------------------------------

    fn unify(pat: &Ty, act: &Ty, sub: &mut [Option<Ty>]) -> bool {
        match (pat, act) {
            (_, Ty::Never) | (_, Ty::Error) | (Ty::Error, _) => true,
            (Ty::Param(i, _), _) => {
                let i = *i as usize;
                if i >= sub.len() {
                    return pat == act;
                }
                match &sub[i] {
                    Some(t) => t == act,
                    None => {
                        sub[i] = Some(act.clone());
                        true
                    }
                }
            }
            (Ty::Tuple(a), Ty::Tuple(b)) | (Ty::Adt(_, a), Ty::Adt(_, b)) => {
                if let (Ty::Adt(x, _), Ty::Adt(y, _)) = (pat, act)
                    && x != y {
                        return false;
                    }
                a.len() == b.len() && a.iter().zip(b).all(|(p, q)| Self::unify(p, q, sub))
            }
            (Ty::Array(a, n), Ty::Array(b, m)) => n == m && Self::unify(a, b, sub),
            (Ty::Ref(a), Ty::Ref(b)) => {
                if let (Ty::Slice(p), Ty::Array(q, _)) = (&**a, &**b) {
                    return Self::unify(p, q, sub);
                }
                Self::unify(a, b, sub)
            }
            (Ty::Slice(a), Ty::Slice(b)) | (Ty::Option(a), Ty::Option(b)) | (Ty::Seq(a), Ty::Seq(b)) => Self::unify(a, b, sub),
            (Ty::Fn(a, r), Ty::Fn(b, s)) => a.len() == b.len() && a.iter().zip(b).all(|(p, q)| Self::unify(p, q, sub)) && Self::unify(r, s, sub),
            _ => pat == act,
        }
    }

    fn resolved(t: &Ty, sub: &[Option<Ty>]) -> bool {
        let mut ok = true;
        t.walk(&mut |x| {
            if let Ty::Param(i, _) = x
                && (*i as usize) < sub.len() && sub[*i as usize].is_none() {
                    ok = false;
                }
        });
        ok
    }

    fn subst_partial(t: &Ty, sub: &[Option<Ty>]) -> Ty {
        let full: Vec<Ty> = sub.iter().enumerate().map(|(i, s)| s.clone().unwrap_or(Ty::Param(i as u32, "?".into()))).collect();
        t.subst(&full)
    }

    /// Checks arguments against generic parameter types, inferring the type
    /// arguments (explicit ones first, then non-literal arguments, then the
    /// expected return type, then the remaining arguments).
    #[allow(clippy::too_many_arguments)]
    pub fn generic_call(&mut self, n: usize, explicit: Vec<Option<Ty>>, params: &[Ty], ret: &Ty, args: &[syn::Expr], exp: &Exp, span: Span) -> (Vec<Expr>, Vec<Ty>, Ty) {
        self.generic_call_zst(n, explicit, params, ret, args, exp, span, false)
    }

    /// [`Cx::generic_call`]; with `user_generics`, the type arguments
    /// instantiate user type parameters and must not be zero-sized in exec
    /// code (a generic `&[T]` would become a ZST slice, §3.2).
    #[allow(clippy::too_many_arguments)]
    pub fn generic_call_zst(&mut self, n: usize, explicit: Vec<Option<Ty>>, params: &[Ty], ret: &Ty, args: &[syn::Expr], exp: &Exp, span: Span, user_generics: bool) -> (Vec<Expr>, Vec<Ty>, Ty) {
        let mut sub = explicit;
        sub.resize(n, None);
        // the expectation first (rustc propagates it into the arguments)
        if let Some(t) = exp.ty()
            && !Self::resolved(ret, &sub) {
                let mut trial = sub.clone();
                if Self::unify(ret, t, &mut trial) {
                    sub = trial;
                }
            }
        let mut out: Vec<Option<Expr>> = vec![None; args.len()];
        let np = params.len();
        for (i, a) in args.iter().enumerate() {
            let Some(p) = params.get(i) else {
                let _ = self.infer(a);
                continue;
            };
            if Self::resolved(p, &sub) {
                let pt = Self::subst_partial(p, &sub);
                out[i] = Some(self.check(a, &pt));
            } else if !needs_exp(a) {
                let e = self.infer(a);
                if !Self::unify(p, &e.ty, &mut sub) {
                    let (pt, at) = (self.tys(&Self::subst_partial(p, &sub)), self.tys(&e.ty));
                    self.err(DiagKind::Type, e.span, format!("mismatched types: expected `{pt}`, found `{at}`"));
                }
                out[i] = Some(e);
            }
        }
        if let Some(t) = exp.ty()
            && !Self::resolved(ret, &sub) {
                let mut trial = sub.clone();
                if Self::unify(ret, t, &mut trial) {
                    sub = trial;
                }
            }
        for (i, a) in args.iter().enumerate() {
            if out[i].is_some() || i >= np {
                continue;
            }
            let p = &params[i];
            if Self::resolved(p, &sub) {
                let pt = Self::subst_partial(p, &sub);
                out[i] = Some(self.check(a, &pt));
            } else if matches!(strip_parens(a), syn::Expr::Closure(_)) {
                // a lambda whose binder types are known but not its result
                // (`map(xs, |x| ..)`): its binders take the known types
                let pt = Self::subst_partial(p, &sub);
                let e = self.expr(a, &Exp::Ty(pt));
                if !Self::unify(p, &e.ty, &mut sub) {
                    let (pt, at) = (self.tys(&Self::subst_partial(p, &sub)), self.tys(&e.ty));
                    self.err(DiagKind::Type, e.span, format!("mismatched types: expected `{pt}`, found `{at}`"));
                }
                out[i] = Some(e);
            } else {
                let e = self.infer(a);
                Self::unify(p, &e.ty, &mut sub);
                out[i] = Some(e);
            }
        }
        let mut ty_args: Vec<Ty> = Vec::new();
        for (i, s) in sub.iter().enumerate() {
            match s {
                Some(t) => ty_args.push(t.clone()),
                None => {
                    self.push(Diagnostic::error(DiagKind::Type, span, "type annotations needed").note(format!("cannot infer type parameter #{}; annotate the expected type or use a turbofish", i + 1)));
                    ty_args.push(Ty::Error);
                }
            }
        }
        let es: Vec<Expr> = out
            .into_iter()
            .enumerate()
            .map(|(i, e)| {
                let e = e.unwrap_or_else(|| Self::error_expr(span));
                match params.get(i) {
                    Some(p) => {
                        let pt = p.subst(&ty_args);
                        self.coerce(e, &pt)
                    }
                    None => e,
                }
            })
            .collect();
        if user_generics && !self.ghost {
            for t in &ty_args {
                self.check_zst_instantiation(t, span);
            }
        }
        for t in ty_args.iter_mut() {
            *t = self.ck.no_fn_in_data(t, span);
        }
        (es, ty_args.clone(), ret.subst(&ty_args))
    }

    /// Type parameters may not be instantiated with zero-sized types (a
    /// generic `&[T]` would become a ZST slice, §3.2).
    fn check_zst_instantiation(&mut self, t: &Ty, span: Span) {
        if crate::validate::is_zst(t, &|id| self.ck.hir_items.get(id.0 as usize).cloned().flatten()) {
            let s = self.tys(t);
            self.push(Diagnostic::error(DiagKind::ZstSlice, span, format!("type parameter instantiated with zero-sized type `{s}`")).note("generic code may form slices of its type parameters; zero-sized element types are rejected (DESIGN.md §3.2)"));
        }
    }

    // ------------------------------------------------------------------
    // operators
    // ------------------------------------------------------------------

    /// Types two operands, propagating the type of a typed operand to an
    /// unsuffixed-literal operand.
    /// Operands of a comparison: the right operand is checked against the
    /// type of the left one (as rustc does for `==`/`<`), or vice versa when
    /// only the right one can be typed on its own.
    fn cmp_operands(&mut self, l: &syn::Expr, r: &syn::Expr) -> (Expr, Expr) {
        if !needs_exp(l) {
            let l2 = self.infer(l);
            let r2 = if l2.ty.is_error() || l2.ty.is_never() { self.infer(r) } else { let t = l2.ty.clone(); let x = self.expr(r, &Exp::Ty(t.clone())); self.coerce_cmp(x, &t) };
            (l2, r2)
        } else if !needs_exp(r) {
            let r2 = self.infer(r);
            let l2 = if r2.ty.is_error() || r2.ty.is_never() { self.infer(l) } else { let t = r2.ty.clone(); let x = self.expr(l, &Exp::Ty(t.clone())); self.coerce_cmp(x, &t) };
            (l2, r2)
        } else {
            (self.infer(l), self.infer(r))
        }
    }

    /// Coerces a comparison operand only where rustc would (unsizing to a
    /// slice, bool to prop); otherwise leaves the type for the operator
    /// check to report.
    fn coerce_cmp(&mut self, e: Expr, t: &Ty) -> Expr {
        match (&e.ty, t) {
            (Ty::Ref(a), Ty::Ref(b)) if matches!((&**a, &**b), (Ty::Array(..), Ty::Slice(_))) => e,
            _ if e.ty == *t => e,
            (Ty::Uint(_), Ty::Uint(_)) | (Ty::Bool, _) | (Ty::Uint(_), _) => e,
            _ if Self::shallow_mismatch(&e.ty, t) => e,
            _ => self.coerce(e, t),
        }
    }

    fn shallow_mismatch(a: &Ty, b: &Ty) -> bool {
        std::mem::discriminant(a) != std::mem::discriminant(b) || a.ref_depth() != b.ref_depth()
    }

    fn operands(&mut self, l: &syn::Expr, r: &syn::Expr, exp: Option<&Ty>) -> (Expr, Expr) {
        let (ll, rl) = (needs_exp(l), needs_exp(r));
        if ll && !rl {
            let r2 = self.infer(r);
            let t = r2.ty.peel_refs().clone();
            let l2 = self.check_operand(l, &t);
            (l2, r2)
        } else if rl && !ll {
            let l2 = self.infer(l);
            let t = l2.ty.peel_refs().clone();
            let r2 = self.check_operand(r, &t);
            (l2, r2)
        } else if ll && rl {
            match exp {
                Some(t) if matches!(t, Ty::Uint(_) | Ty::Int | Ty::Nat) => {
                    let t = t.clone();
                    (self.check(l, &t), self.check(r, &t))
                }
                _ => (self.infer(l), self.infer(r)),
            }
        } else {
            (self.infer(l), self.infer(r))
        }
    }

    fn check_operand(&mut self, e: &syn::Expr, t: &Ty) -> Expr {
        if t.is_error() || t.is_never() {
            return self.infer(e);
        }
        self.check(e, t)
    }

    fn binary(&mut self, b: &syn::ExprBinary, exp: &Exp, span: Span) -> Expr {
        let Some((op, compound)) = map_binop(&b.op) else {
            self.err(DiagKind::Unsupported, span, "unsupported operator");
            return Self::error_expr(span);
        };
        if compound {
            self.err(DiagKind::Unsupported, span, "compound assignment is only allowed as a statement");
            return Self::error_expr(span);
        }
        match op {
            BinOp::And | BinOp::Or => {
                let l = self.check(&b.left, &Ty::Bool);
                let r = self.check(&b.right, &Ty::Bool);
                Expr::new(ExprKind::Binary(op, Box::new(l), Box::new(r)), Ty::Bool, span)
            }
            BinOp::Shl | BinOp::Shr => {
                let l = match exp.ty() {
                    Some(t) if needs_exp(&b.left) && matches!(t, Ty::Uint(_)) => {
                        let t = t.clone();
                        self.check(&b.left, &t)
                    }
                    _ => self.infer(&b.left),
                };
                self.no_exp_reason.push("shift");
                let r = self.infer(&b.right);
                self.no_exp_reason.pop();
                let l = self.deref_once(l);
                let r = self.deref_once(r);
                let lt = match &l.ty {
                    Ty::Uint(w) => Ty::Uint(*w),
                    Ty::Error => Ty::Error,
                    other => {
                        let s = self.tys(other);
                        self.err(DiagKind::Type, l.span, format!("cannot shift a value of type `{s}` (unsigned integers only)"));
                        Ty::Error
                    }
                };
                if !matches!(r.ty, Ty::Uint(_) | Ty::Error) {
                    let s = self.tys(&r.ty);
                    self.err(DiagKind::Type, r.span, format!("shift amount must be an unsigned integer, found `{s}`"));
                }
                Expr::new(ExprKind::Binary(op, Box::new(l), Box::new(r)), lt, span)
            }
            _ if op.is_comparison() => {
                let (l, r) = self.cmp_operands(&b.left, &b.right);
                let (l, r) = if self.ghost { self.numeric_join(l, r) } else { (l, r) };
                let (l, r) = if self.ghost { self.view_join(l, r) } else { (l, r) };
                if l.ty.is_error() || r.ty.is_error() {
                    return Expr::new(ExprKind::Binary(op, Box::new(l), Box::new(r)), Ty::Bool, span);
                }
                if l.ty.ref_depth() != r.ty.ref_depth() || l.ty.peel_refs() != r.ty.peel_refs() {
                    let ok_array_slice = matches!(op, BinOp::Eq | BinOp::Ne) && l.ty.ref_depth() == r.ty.ref_depth() && l.ty.ref_depth() > 0 && array_slice_compatible(l.ty.peel_refs(), r.ty.peel_refs());
                    if !ok_array_slice {
                        let (a, bb) = (self.tys(&l.ty), self.tys(&r.ty));
                        self.err(DiagKind::Type, span, format!("cannot compare `{a}` with `{bb}`"));
                        return Expr::new(ExprKind::Binary(op, Box::new(l), Box::new(r)), Ty::Bool, span);
                    }
                }
                let base = l.ty.peel_refs().clone();
                let ordered = matches!(base, Ty::Uint(_) | Ty::Int | Ty::Nat);
                if matches!(op, BinOp::Eq | BinOp::Ne) {
                    if !self.supports_eq(&base) {
                        let s = self.tys(&base);
                        self.push(Diagnostic::error(DiagKind::Type, span, format!("`==` is not available for `{s}`")).note("equality needs `#[derive(PartialEq)]` on user types; vectors and type parameters have none"));
                    }
                } else if !ordered {
                    let s = self.tys(&base);
                    self.err(DiagKind::Type, span, format!("`{}` is only available for unsigned integers, found `{s}`", op.symbol()));
                }
                // make operands plain values
                let (l, r) = if matches!(base, Ty::Uint(_) | Ty::Bool | Ty::Int | Ty::Nat) { (self.autoderef(l), self.autoderef(r)) } else { (l, r) };
                Expr::new(ExprKind::Binary(op, Box::new(l), Box::new(r)), Ty::Bool, span)
            }
            _ => {
                // arithmetic / bitwise
                let (l, r) = self.operands(&b.left, &b.right, exp.ty());
                let l = self.deref_once(l);
                let r = self.deref_once(r);
                if l.ty.is_error() || r.ty.is_error() {
                    return Expr::new(ExprKind::Binary(op, Box::new(l), Box::new(r)), Ty::Error, span);
                }
                let (l, r) = self.numeric_join(l, r);
                let ok = match (&l.ty, &r.ty) {
                    (Ty::Uint(a), Ty::Uint(b)) => a == b,
                    (Ty::Bool, Ty::Bool) => matches!(op, BinOp::BitAnd | BinOp::BitOr | BinOp::BitXor),
                    (Ty::Int, Ty::Int) | (Ty::Nat, Ty::Nat) => self.ghost && matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Rem),
                    _ => false,
                };
                if !ok {
                    let (a, bb) = (self.tys(&l.ty), self.tys(&r.ty));
                    self.err(DiagKind::Type, span, format!("cannot apply `{}` to `{a}` and `{bb}`", op.symbol()));
                    return Expr::new(ExprKind::Binary(op, Box::new(l), Box::new(r)), Ty::Error, span);
                }
                let ty = l.ty.clone();
                Expr::new(ExprKind::Binary(op, Box::new(l), Box::new(r)), ty, span)
            }
        }
    }

    /// Whether `==` is available at `t` (§3.3: derived `PartialEq`, arrays,
    /// slices, tuples, `Option` of such, integers, bool).
    pub fn supports_eq(&self, t: &Ty) -> bool {
        match t {
            Ty::Bool | Ty::Uint(_) | Ty::Int | Ty::Nat => true,
            Ty::Tuple(ts) => ts.iter().all(|t| self.supports_eq(t)),
            Ty::Array(t, _) | Ty::Slice(t) | Ty::Option(t) | Ty::Ref(t) | Ty::Seq(t) => self.supports_eq(t),
            // in ghost code, the equality of the lanes (no `PartialEq` in Rust)
            Ty::Vector(_) => self.ghost,
            Ty::Adt(id, args) => {
                let d = match &self.ck.hir_items[id.0 as usize] {
                    Some(ItemKind::Struct(s)) => s.derives,
                    Some(ItemKind::Enum(e)) => e.derives,
                    _ => return false,
                };
                d.partial_eq && args.iter().all(|a| self.supports_eq(a))
            }
            _ => false,
        }
    }

    fn unary(&mut self, u: &syn::ExprUnary, exp: &Exp, span: Span) -> Expr {
        match u.op {
            syn::UnOp::Deref(_) => {
                let inner = self.infer(&u.expr);
                match inner.ty.clone() {
                    Ty::Ref(t) => Expr::new(ExprKind::Deref(Box::new(inner)), *t, span),
                    Ty::Error => inner,
                    other => {
                        let s = self.tys(&other);
                        self.err(DiagKind::Type, span, format!("type `{s}` cannot be dereferenced"));
                        Self::error_expr(span)
                    }
                }
            }
            syn::UnOp::Not(_) => {
                let inner = match exp.ty() {
                    Some(t) if needs_exp(&u.expr) => {
                        let t = t.clone();
                        self.check(&u.expr, &t)
                    }
                    _ => self.infer(&u.expr),
                };
                let inner = self.deref_once(inner);
                match &inner.ty {
                    Ty::Bool | Ty::Uint(_) | Ty::Error => {
                        let ty = inner.ty.clone();
                        Expr::new(ExprKind::Unary(UnOp::Not, Box::new(inner)), ty, span)
                    }
                    other => {
                        let s = self.tys(other);
                        self.err(DiagKind::Type, span, format!("cannot apply `!` to `{s}`"));
                        Self::error_expr(span)
                    }
                }
            }
            syn::UnOp::Neg(_) => {
                if !self.ghost {
                    self.push(Diagnostic::error(DiagKind::Signed, span, "negation is not supported").note("unsigned integers have no negation; use `wrapping_neg()` (signed integers are reserved)"));
                    return Self::error_expr(span);
                }
                let inner = self.check(&u.expr, &Ty::Int);
                Expr::new(ExprKind::Unary(UnOp::Neg, Box::new(inner)), Ty::Int, span)
            }
            _ => {
                self.err(DiagKind::Unsupported, span, "unsupported unary operator");
                Self::error_expr(span)
            }
        }
    }

    fn cast(&mut self, c: &syn::ExprCast, span: Span) -> Expr {
        let g = self.g.clone();
        let ghost = self.ghost;
        let target = self.ck.lower_ty(self.m, &c.ty, &g, ghost || self.lift);
        match &target {
            Ty::Uint(_) | Ty::Error => {}
            Ty::Int | Ty::Nat if self.ghost => {}
            other => {
                let s = self.tys(other);
                self.err(DiagKind::Type, span, format!("`as` may only target unsigned integer types, found `{s}`"));
                return Self::error_expr(span);
            }
        }
        // an unsuffixed literal takes the target type (Rust infers it); a
        // suffixed one cast to an unsigned type has its own (`31u32 as
        // usize`, which the MIR reading writes for a signed shift's amount;
        // a ghost cast to `Int`/`Nat` keeps its reading)
        let inner = if bare_lit(&c.expr) && !(suffixed_lit(&c.expr) && matches!(target, Ty::Uint(_))) {
            self.check(&c.expr, &target)
        } else {
            self.no_exp_reason.push("cast");
            let x = self.infer(&c.expr);
            self.no_exp_reason.pop();
            x
        };
        match (&inner.ty, &target) {
            (Ty::Uint(_) | Ty::Bool | Ty::Error, _) => {}
            // ghost `Int`/`Nat` casts (§4.1): `Int as Nat` needs `0 ≤ x`;
            // `as uN` truncates mod 2^N exactly like exec `as`
            (Ty::Int | Ty::Nat, Ty::Int | Ty::Nat | Ty::Uint(_)) if self.ghost => {}
            (other, _) => {
                let (s, t) = (self.tys(other), self.tys(&target));
                self.err(DiagKind::Type, span, format!("invalid cast from `{s}` to `{t}`"));
            }
        }
        Expr::new(ExprKind::Cast(Box::new(inner), target.clone()), target, span)
    }

    fn reference(&mut self, r: &syn::ExprReference, exp: &Exp, span: Span) -> Expr {
        if r.mutability.is_some() {
            self.push(Diagnostic::error(DiagKind::MutRef, span, "`&mut` is not supported").note("the only mutation through a reference is `local.copy_from_slice(src)` (DESIGN.md §3.3)"));
            return Self::error_expr(span);
        }
        if let syn::Expr::Index(ix) = strip_parens(&r.expr)
            && let syn::Expr::Range(rg) = strip_parens(&ix.index) {
                return self.slice_range(&ix.expr, rg, span);
            }
        let inner = match exp.ty() {
            Some(Ty::Ref(t)) if !matches!(**t, Ty::Slice(_)) => {
                let t = (**t).clone();
                self.check(&r.expr, &t)
            }
            Some(Ty::Ref(t)) => {
                // `&[a, b]` / `&[]` where a slice is expected: the array gets
                // its element type from the slice
                let Ty::Slice(elem) = &**t else { unreachable!() };
                match strip_parens(&r.expr) {
                    syn::Expr::Array(a) => {
                        let at = Ty::array((**elem).clone(), a.elems.len() as u64);
                        self.check(&r.expr, &at)
                    }
                    syn::Expr::Repeat(_) => {
                        let e = (**elem).clone();
                        self.expr(&r.expr, &Exp::Ty(Ty::array(e, 0)))
                    }
                    _ => self.infer(&r.expr),
                }
            }
            _ => self.infer(&r.expr),
        };
        let ty = Ty::reference(inner.ty.clone());
        Expr::new(ExprKind::Ref(Box::new(inner)), ty, span)
    }

    fn slice_range(&mut self, base: &syn::Expr, rg: &syn::ExprRange, span: Span) -> Expr {
        if matches!(rg.limits, syn::RangeLimits::Closed(_)) {
            self.err(DiagKind::Unsupported, span, "inclusive range indexing (`a..=b`) is not supported; use `a..b + 1`");
        }
        let b = self.infer(base);
        let b = self.autoderef(b);
        let elem = match &b.ty {
            Ty::Array(t, _) | Ty::Slice(t) => (**t).clone(),
            Ty::Error => Ty::Error,
            other => {
                let s = self.tys(other);
                self.err(DiagKind::Type, span, format!("cannot index into a value of type `{s}`"));
                Ty::Error
            }
        };
        let lo = rg.start.as_ref().map(|e| Box::new(self.check(e, &Ty::usize())));
        let hi = rg.end.as_ref().map(|e| Box::new(self.check(e, &Ty::usize())));
        Expr::new(ExprKind::SliceRange { base: Box::new(b), lo, hi }, Ty::slice_ref(elem), span)
    }

    fn index(&mut self, i: &syn::ExprIndex, span: Span) -> Expr {
        if matches!(strip_parens(&i.index), syn::Expr::Range(_)) {
            self.err(DiagKind::Unsupported, span, "range indexing must be borrowed: write `&s[a..b]`");
            return Self::error_expr(span);
        }
        let b = self.infer(&i.expr);
        let b = self.autoderef(b);
        // ghost `v[i]` on a hardware vector (§9.2): lane `i` of its model's
        // `Array(lane, n)` (lane 0 first), indexed as that array
        let b = match (&b.ty, self.ghost) {
            (Ty::Vector(v), true) => {
                let (lane, n) = v.lanes();
                self.view_coerce_expr(b, &Ty::array(Ty::Uint(lane), n))
            }
            _ => b,
        };
        if let (Ty::Seq(t), true) = (&b.ty, self.ghost) {
            // ghost `xs[i]` on a `Seq<T>`, `i: Nat` (§4.1)
            let t = (**t).clone();
            let idx = self.check(&i.index, &Ty::Nat);
            return Expr::new(ExprKind::Call { callee: Callee::Ghost(GhostFn::SIndex, vec![t.clone()]), args: vec![b, idx] }, t, span);
        }
        let elem = match &b.ty {
            Ty::Array(t, _) | Ty::Slice(t) => (**t).clone(),
            Ty::Error => Ty::Error,
            other => {
                let s = self.tys(other);
                self.err(DiagKind::Type, span, format!("cannot index into a value of type `{s}`"));
                Ty::Error
            }
        };
        if let (Ty::Array(t, _), true, false, false) = (&b.ty, self.ghost, needs_exp(&i.index), binds_locals(&i.index)) {
            // ghost `a[i]` on an array with `i: Nat` (§15 S5): the element of
            // the array's sequence, with the obligation `i < N` (like `Seq`
            // indexing). The index is typed on its own first; anything but
            // `Nat` (and a literal) is typed again as the `usize` index of
            // array indexing, as before.
            let t = (**t).clone();
            let mark = self.ck.diags.list.len();
            let idx = self.infer(&i.index);
            if idx.ty == Ty::Nat && self.ck.diags.list.len() == mark {
                let seq = self.coerce(b, &Ty::Seq(Box::new(t.clone())));
                return Expr::new(ExprKind::Call { callee: Callee::Ghost(GhostFn::SIndex, vec![t.clone()]), args: vec![seq, idx] }, t, span);
            }
            self.ck.diags.list.truncate(mark);
        }
        let idx = self.check(&i.index, &Ty::usize());
        Expr::new(ExprKind::Index { base: Box::new(b), index: Box::new(idx) }, elem, span)
    }

    fn field(&mut self, f: &syn::ExprField, span: Span) -> Expr {
        if self.inv_self.is_some() && super::spec15::is_self_path(&f.base) {
            return self.invariant_field(&f.member, span);
        }
        let b = self.infer(&f.base);
        let b = self.autoderef(b);
        let (index, name, ty) = match (&b.ty, &f.member) {
            (Ty::Tuple(ts), syn::Member::Unnamed(i)) => match ts.get(i.index as usize) {
                Some(t) => (i.index, None, t.clone()),
                None => {
                    self.err(DiagKind::Type, span, format!("no field `{}` on tuple", i.index));
                    return Self::error_expr(span);
                }
            },
            (Ty::Adt(id, args), member) => {
                let (id, args) = (*id, args.clone());
                let Some(ItemKind::Struct(s)) = self.ck.hir_items[id.0 as usize].clone() else {
                    self.err(DiagKind::Type, span, "field access on an enum; use `match`");
                    return Self::error_expr(span);
                };
                let pos = match member {
                    syn::Member::Named(n) => s.fields.iter().position(|fd| fd.name.as_deref() == Some(&n.to_string())),
                    syn::Member::Unnamed(i) => (s.shape == Shape::Tuple && (i.index as usize) < s.fields.len()).then_some(i.index as usize),
                };
                let Some(pos) = pos else {
                    let tn = self.ck.res.items[id.0 as usize].name.clone();
                    self.err(DiagKind::Type, span, format!("no field `{}` on type `{tn}`", member.to_token_stream_string()));
                    return Self::error_expr(span);
                };
                let fd = &s.fields[pos];
                let owner_mod = self.ck.res.items[id.0 as usize].module;
                // ghost code (spec modules, contracts, `proof!`, lemmas, laws,
                // proofs) may read private fields anywhere in the crate
                // (DESIGN.md §15.3): it is erased, so host code never sees it
                if !self.ghost && !self.ck.res.visible(fd.vis, owner_mod, self.m) {
                    self.err(DiagKind::Privacy, span, format!("field `{}` is private", member.to_token_stream_string()));
                }
                (pos as u32, fd.name.clone(), fd.ty.subst(&args))
            }
            (Ty::Error, _) => return Self::error_expr(span),
            (other, _) => {
                let s = self.tys(other);
                self.err(DiagKind::Type, span, format!("no field `{}` on type `{s}`", f.member.to_token_stream_string()));
                return Self::error_expr(span);
            }
        };
        Expr::new(ExprKind::Field { base: Box::new(b), index, name }, ty, span)
    }

    // ------------------------------------------------------------------
    // calls
    // ------------------------------------------------------------------

    fn call(&mut self, c: &syn::ExprCall, exp: &Exp, span: Span) -> Expr {
        let syn::Expr::Path(p) = strip_parens(&c.func) else {
            self.push(Diagnostic::error(DiagKind::Closure, span, "only named functions can be called (no closures or function pointers)"));
            return Self::error_expr(span);
        };
        if p.qself.is_some() {
            self.err(DiagKind::Trait, span, "qualified paths (`<T>::f`) are not supported in source; use method syntax");
            return Self::error_expr(span);
        }
        let args: Vec<syn::Expr> = c.args.iter().cloned().collect();
        let Some(r) = self.value_path(&p.path, span) else {
            for a in &args {
                let _ = self.infer(a);
            }
            return Self::error_expr(span);
        };
        match r {
            VRes::Fn(id, impl_args, own) => self.fn_call(id, impl_args, own, &args, exp, span),
            VRes::Ctor(c, targs) => {
                if self.ctor_shape(c) != Shape::Tuple {
                    self.err(DiagKind::Type, span, "this constructor does not take positional fields");
                    return Self::error_expr(span);
                }
                self.ctor_app(c, targs, &args, exp, span)
            }
            VRes::IntAssoc(w, m) => {
                let b = Builtin::Int(m, w);
                let sig = b.sig(&[]);
                self.fixed_call(Callee::Builtin(b, vec![]), &sig.params, sig.ret, &args, span)
            }
            VRes::Intrinsic(i, imms) => self.intrinsic_call(i, imms, &args, span),
            VRes::Ghost(g, explicit) => {
                if !self.ghost {
                    self.err(DiagKind::Ghost, span, format!("ghost function `{}` in exec code", g.name()));
                }
                let sig = g.sig();
                if g.nat_def().is_some() {
                    // `pow2`, `log2`, `popcount`: `Nat -> Nat`, no type parameter
                    if !explicit.is_empty() {
                        self.err(DiagKind::Type, span, format!("`{}` takes no type arguments", g.name()));
                    }
                    return self.fixed_call(Callee::Ghost(g, vec![]), &sig.params, sig.ret, &args, span);
                }
                let explicit: Vec<Option<Ty>> = explicit.into_iter().map(Some).collect();
                let (es, ty_args, ret) = self.generic_call(1, explicit, &sig.params, &sig.ret, &args, exp, span);
                Expr::new(ExprKind::Call { callee: Callee::Ghost(g, ty_args), args: es }, ret, span)
            }
            VRes::GhostKw(k) => self.ghost_kw(k, &args, span),
            VRes::Local(l) => match self.local_ty(l) {
                Ty::Fn(params, ret) if self.ghost => {
                    if params.len() != args.len() {
                        self.err(DiagKind::Type, span, format!("this function takes {} argument(s) but {} were supplied", params.len(), args.len()));
                    }
                    let fun = Expr::new(ExprKind::Local(l), Ty::Fn(params.clone(), ret.clone()), span);
                    let es: Vec<Expr> = args.iter().enumerate().map(|(i, a)| match params.get(i) {
                        Some(p) => self.check(a, p),
                        None => self.infer(a),
                    }).collect();
                    Expr::new(ExprKind::Apply { fun: Box::new(fun), args: es }, *ret, span)
                }
                _ => {
                    self.push(Diagnostic::error(DiagKind::Closure, span, "cannot call a local variable (no closures or function pointers)").note("ghost code calls a local of function type `fn(..) -> ..`"));
                    Self::error_expr(span)
                }
            },
            VRes::Const(_) | VRes::BuiltinConst(_) => {
                self.err(DiagKind::Type, span, "a constant is not a function");
                Self::error_expr(span)
            }
        }
    }

    /// Calls with a fixed (non-generic) signature.
    fn fixed_call(&mut self, callee: Callee, params: &[Ty], ret: Ty, args: &[syn::Expr], span: Span) -> Expr {
        if params.len() != args.len() {
            self.err(DiagKind::Type, span, format!("this function takes {} argument(s) but {} were supplied", params.len(), args.len()));
        }
        let es: Vec<Expr> = args.iter().enumerate().map(|(i, a)| match params.get(i) {
            Some(p) => self.check(a, p),
            None => self.infer(a),
        }).collect();
        Expr::new(ExprKind::Call { callee, args: es }, ret, span)
    }

    /// The target's statically enabled features, counted for a function
    /// read from rustc's MIR (its structured reading follows the literal
    /// reading's rule, docs/DESIGN-UNSAFE-SIMD.md §4: a CPU running the
    /// binary has them; the literal reading checks the real condition,
    /// bound to the build's), none for user code (DESIGN.md §9.3).
    fn static_features(&self) -> Vec<String> {
        if self.lift && !self.ghost { self.ck.res.target.features.iter().cloned().collect() } else { Vec::new() }
    }

    /// The §9.3 feature rule for the current function.
    fn require_features(&mut self, needed: &[&str], what: &str, span: Span) {
        if self.ghost {
            return;
        }
        let statics = self.static_features();
        let missing: Vec<&str> = needed.iter().copied().filter(|f| !self.features.iter().any(|g| g == f) && !statics.iter().any(|g| g == f)).collect();
        if !missing.is_empty() {
            self.push(
                Diagnostic::error(DiagKind::Feature, span, format!("{what} requires target feature(s) {}", missing.iter().map(|f| format!("`{f}`")).collect::<Vec<_>>().join(", ")))
                    .note(format!("add `#[target_feature(enable = \"{}\")]` to the calling function", missing.join(",")))
                    .note("statically enabled target features do not count (DESIGN.md §9.3)"),
            );
        }
    }

    fn intrinsic_call(&mut self, i: intrinsics::IntrinsicId, mut imms: Vec<i64>, args: &[syn::Expr], span: Span) -> Expr {
        let info = intrinsics::get(i);
        // the structured reading of a load or store through a pointer of
        // crate code (docs/mir-lift.md §20.10; the lift writes these into
        // functions read from MIR only): the intrinsic's validated model on
        // the bytes. A load takes the `n` bytes it reads (its model's memory
        // type, `[u8; n]`) and gives the vector; a store takes the vector
        // and gives the bytes it writes. Ghost code (laws, proofs) speaks of
        // them the same way: it has no pointers.
        if info.pointer_args && (self.lift || self.ghost) && imms.is_empty() {
            let path = format!("core::arch::{}::{}", info.arch.name(), info.name);
            let uint = |b: u32| match b {
                8 => Some(crate::hir::UintTy::U8),
                16 => Some(crate::hir::UintTy::U16),
                32 => Some(crate::hir::UintTy::U32),
                64 => Some(crate::hir::UintTy::U64),
                _ => None,
            };
            let mem = |t: sandblaster_targets::coretext::CoreTy| match t {
                sandblaster_targets::coretext::CoreTy::Vector(l, n) => uint(l.bits()).map(|u| Ty::Array(Box::new(Ty::Uint(u)), n as u64)),
                sandblaster_targets::coretext::CoreTy::Word(_) => None,
            };
            let vec = |t: sandblaster_targets::coretext::CoreTy| match t {
                sandblaster_targets::coretext::CoreTy::Vector(l, n) => intrinsics::VecTy::ALL.into_iter().find(|v| v.arch() == info.arch && uint(l.bits()).is_some_and(|u| v.lanes() == (u, n as u64))).map(Ty::Vector),
                sandblaster_targets::coretext::CoreTy::Word(_) => None,
            };
            let sig = sandblaster_targets::coretext::find_by_path(&path).and_then(|cm| match (cm.params, info.ret == Ty::unit()) {
                ([(_, m)], false) => Some((vec![mem(*m)?], info.ret.clone())),
                ([(_, v)], true) => Some((vec![vec(*v)?], mem(cm.ret)?)),
                _ => None,
            });
            let Some((params, ret)) = sig else {
                self.push(Diagnostic::error(DiagKind::RawPointer, span, format!("`{}`: no model to read its memory through", info.name)));
                return Self::error_expr(span);
            };
            self.require_features(info.features, &format!("intrinsic `{}`", info.name), span);
            return self.fixed_call(Callee::Intrinsic(i, vec![]), &params, ret, args, span);
        }
        if info.pointer_args {
            self.push(Diagnostic::error(DiagKind::RawPointer, span, format!("`{}` takes raw pointers and cannot be called from user code", info.name)).note("take and return vector values, or build them with the modeled intrinsics; a pointer load or store needs `unsafe`, which verified code never contains: it stays in unverified host code (DESIGN.md §2, §16.4)"));
            return Self::error_expr(span);
        }
        self.require_features(info.features, &format!("intrinsic `{}`", info.name), span);
        let np = info.params.len();
        let mut vargs: Vec<syn::Expr> = args.to_vec();
        if imms.is_empty() && !info.imms.is_empty() && args.len() == np + info.imms.len() {
            // legacy const-generic position
            for a in &args[np..] {
                let s = self.sp(a.span());
                match imm_literal(a) {
                    Some(v) => imms.push(v),
                    None => self.push(Diagnostic::error(DiagKind::Type, s, "intrinsic immediates must be integer literals").note("stdarch immediates are `const IMM: i32` generics (DESIGN.md §9.2)")),
                }
            }
            vargs.truncate(np);
        }
        if imms.len() != info.imms.len() {
            self.err(DiagKind::Type, span, format!("intrinsic `{}` takes {} immediate(s), found {}", info.name, info.imms.len(), imms.len()));
        }
        for (v, imm) in imms.iter().zip(&info.imms) {
            if *v < imm.lo || *v > imm.hi {
                self.err(DiagKind::Literal, span, format!("immediate `{}` of `{}` must be in {}..={}, found {v}", imm.name, info.name, imm.lo, imm.hi));
            }
        }
        let (params, ret) = (info.params.clone(), info.ret.clone());
        let mut e = self.fixed_call(Callee::Intrinsic(i, imms.clone()), &params, ret, &vargs, span);
        if let ExprKind::Call { callee, .. } = &mut e.kind {
            *callee = Callee::Intrinsic(i, imms);
        }
        e
    }

    fn fn_call(&mut self, id: ItemId, impl_args: Option<Vec<Ty>>, own: Vec<Ty>, args: &[syn::Expr], exp: &Exp, span: Span) -> Expr {
        let Some(sig) = self.ck.sigs.get(&id).cloned() else { return Self::error_expr(span) };
        if let Some(inv) = &self.inv_self
            && sig.owner == Some(inv.owner)
        {
            let name = self.ck.res.items[id.0 as usize].name.clone();
            self.invariant_self_method(&name, span);
        }
        match sig.kind {
            FnKind::Lemma | FnKind::Law | FnKind::Proof => {
                self.push(Diagnostic::error(DiagKind::Script, span, format!("`#[{}]` functions can only be applied as script statements", sig.kind.name())).note("write `name(args);` or `let h = name(args);` inside a proof"));
                return Self::error_expr(span);
            }
            FnKind::Spec if !self.ghost && !self.lift => {
                self.err(DiagKind::Ghost, span, "spec functions can only be called from ghost code");
            }
            _ => {}
        }
        if !sig.target_features.is_empty() && !self.ghost {
            let statics = self.static_features();
            let missing: Vec<String> = sig.feature_set.iter().filter(|f| !self.features.contains(f) && !statics.contains(f)).cloned().collect();
            if !missing.is_empty() {
                self.push(
                    Diagnostic::error(DiagKind::Feature, span, format!("calling a `#[target_feature]` function requires feature(s) {}", missing.join(", ")))
                        .note("calls from functions without those features are only allowed in generated dispatch glue (DESIGN.md §9.3)"),
                );
            }
        }
        let n = sig.generics.len();
        let n_impl = match sig.owner {
            Some(o) => match &self.ck.hir_items[o.0 as usize] {
                Some(ItemKind::Struct(s)) => s.generics.len(),
                Some(ItemKind::Enum(e)) => e.generics.len(),
                _ => 0,
            },
            None => 0,
        }
        .min(n);
        let mut explicit: Vec<Option<Ty>> = vec![None; n];
        if let Some(a) = impl_args {
            for (i, t) in a.into_iter().enumerate().take(n_impl) {
                explicit[i] = Some(t);
            }
        }
        if !own.is_empty() {
            if own.len() != n - n_impl {
                self.err(DiagKind::Type, span, format!("expected {} type argument(s), found {}", n - n_impl, own.len()));
            }
            for (i, t) in own.into_iter().enumerate() {
                if n_impl + i < n {
                    explicit[n_impl + i] = Some(t);
                }
            }
        }
        // `#[ghost]` parameters take `ghost!(e)` (DESIGN.md §15.3)
        let (es, ty_args, ret) = self.call_with_ghosts(id, &sig, 0, n, explicit, args, exp, span);
        Expr::new(ExprKind::Call { callee: Callee::Item(id, ty_args), args: es }, ret, span)
    }

    fn method_call(&mut self, mc: &syn::ExprMethodCall, exp: &Exp, span: Span) -> Expr {
        let name = mc.method.to_string();
        if name == "copy_from_slice" {
            self.push(Diagnostic::error(DiagKind::MutRef, span, "`copy_from_slice` is only allowed as a statement on a `let mut` array local").note("write `local.copy_from_slice(src);` or `local[a..b].copy_from_slice(src);`"));
            return Self::error_expr(span);
        }
        let (turbo_tys, turbo_consts) = match &mc.turbofish {
            Some(t) => {
                let seg = syn::PathSegment { ident: mc.method.clone(), arguments: syn::PathArguments::AngleBracketed(t.clone()) };
                self.seg_args(&seg)
            }
            None => (vec![], vec![]),
        };
        if self.inv_self.is_some() && super::spec15::is_self_path(&mc.receiver) {
            self.invariant_self_method(&name, span);
            for a in &mc.args {
                let _ = self.infer(a);
            }
            return Self::error_expr(span);
        }
        let recv = self.infer(&mc.receiver);
        let args: Vec<syn::Expr> = mc.args.iter().cloned().collect();
        if recv.ty.is_error() {
            for a in &args {
                let _ = self.infer(a);
            }
            return Self::error_expr(span);
        }
        // autoderef probing
        let mut steps: Vec<Ty> = vec![recv.ty.clone()];
        while let Ty::Ref(t) = steps.last().unwrap().clone() {
            steps.push(*t);
        }
        for (k, st) in steps.iter().enumerate() {
            match st {
                Ty::Adt(id, targs) => {
                    let (id, targs) = (*id, targs.clone());
                    let methods: Vec<ItemId> = match &self.ck.hir_items[id.0 as usize] {
                        Some(ItemKind::Struct(s)) => s.methods.clone(),
                        Some(ItemKind::Enum(e)) => e.methods.clone(),
                        _ => vec![],
                    };
                    if let Some(f) = methods.into_iter().find(|f| self.ck.res.items[f.0 as usize].name == name) {
                        let Some(sig) = self.ck.sigs.get(&f).cloned() else { return Self::error_expr(span) };
                        let Some(rk) = sig.receiver else {
                            self.err(DiagKind::Type, span, format!("`{name}` is an associated function, not a method; call it as `Type::{name}(..)`"));
                            return Self::error_expr(span);
                        };
                        self.check_ghost_ref(f, span);
                        let fit = &self.ck.res.items[f.0 as usize];
                        if !self.ck.res.visible(fit.vis, fit.module, self.m) {
                            self.err(DiagKind::Privacy, span, format!("method `{name}` is private"));
                        }
                        let adj = self.adjust_receiver(recv, k, rk == Receiver::ByRef, false);
                        return self.method_fn_call(f, targs, turbo_tys, adj, &args, exp, span);
                    }
                }
                Ty::Uint(w) => {
                    if let Some(m) = IntMethod::from_name(&name).filter(|m| !m.is_assoc()) {
                        let adj = self.adjust_receiver(recv, k, false, false);
                        let b = Builtin::Int(m, *w);
                        let sig = b.sig(&[]);
                        return self.builtin_method(Callee::Builtin(b, vec![]), &sig.params, sig.ret, adj, &args, span);
                    }
                }
                Ty::Array(t, n) if name == "as_slice" => {
                    let (t, n) = ((**t).clone(), *n);
                    let adj = self.adjust_receiver(recv, k, true, false);
                    let b = Builtin::Array(ArrayMethod::AsSlice(n));
                    let sig = b.sig(std::slice::from_ref(&t));
                    return self.builtin_method(Callee::Builtin(b, vec![t]), &sig.params, sig.ret, adj, &args, span);
                }
                Ty::Array(t, _) | Ty::Slice(t) if SliceMethod::is_slice_method_name(&name) => {
                    let t = (**t).clone();
                    let unsize = matches!(st, Ty::Array(..));
                    let n = if SliceMethod::takes_const(&name) {
                        match turbo_consts.first() {
                            Some((v, _)) if *v >= 0 => Some(*v as u64),
                            _ => {
                                self.push(Diagnostic::error(DiagKind::Type, span, format!("`{name}` needs its length as a turbofish: `{name}::<N>()`")));
                                return Self::error_expr(span);
                            }
                        }
                    } else {
                        None
                    };
                    let Some(m) = SliceMethod::from_name(&name, n) else { break };
                    if let SliceMethod::AsChunks(0) = m {
                        self.err(DiagKind::Type, span, "`as_chunks::<0>` is not allowed (N > 0)");
                    }
                    let adj = self.adjust_receiver(recv, k, true, unsize);
                    let b = Builtin::Slice(m);
                    let sig = b.sig(std::slice::from_ref(&t));
                    return self.builtin_method(Callee::Builtin(b, vec![t]), &sig.params, sig.ret, adj, &args, span);
                }
                Ty::Option(t) => {
                    if let Some(m) = OptionMethod::from_name(&name) {
                        let t = (**t).clone();
                        let by_ref = !matches!(m, OptionMethod::UnwrapOr);
                        let adj = self.adjust_receiver(recv, k, by_ref, false);
                        let b = Builtin::Option(m);
                        let sig = b.sig(std::slice::from_ref(&t));
                        return self.builtin_method(Callee::Builtin(b, vec![t]), &sig.params, sig.ret, adj, &args, span);
                    }
                }
                // ghost `Seq<T>` methods (§4.1)
                Ty::Seq(t) if self.ghost => {
                    let t = (**t).clone();
                    let (g, targ) = if name == "flatten" {
                        match &t {
                            Ty::Array(e, n) => (Some(GhostFn::SFlatten(Some(*n))), (**e).clone()),
                            Ty::Seq(e) => (Some(GhostFn::SFlatten(None)), (**e).clone()),
                            other => {
                                let s2 = self.tys(other);
                                self.err(DiagKind::Type, span, format!("`flatten` needs a `Seq<[T; N]>` or a `Seq<Seq<T>>`, found `Seq<{s2}>`"));
                                return Self::error_expr(span);
                            }
                        }
                    } else {
                        let n = if GhostFn::seq_method_takes_const(&name) {
                            match turbo_consts.first() {
                                Some((v, _)) if *v > 0 => Some(*v as u64),
                                _ => {
                                    self.push(Diagnostic::error(DiagKind::Type, span, format!("`{name}` needs its length as a turbofish: `{name}::<N>()` with N > 0")));
                                    return Self::error_expr(span);
                                }
                            }
                        } else {
                            None
                        };
                        (GhostFn::seq_method(&name, n), t.clone())
                    };
                    if let Some(g) = g {
                        let adj = self.adjust_receiver(recv, k, false, false);
                        let sig = g.sig();
                        let params: Vec<Ty> = sig.params.iter().map(|p| p.subst(std::slice::from_ref(&targ))).collect();
                        let ret = sig.ret.subst(std::slice::from_ref(&targ));
                        return self.builtin_method(Callee::Ghost(g, vec![targ]), &params, ret, adj, &args, span);
                    }
                }
                // ghost `Nat` / `Int` methods (§4.1)
                Ty::Nat | Ty::Int if self.ghost => {
                    let g = match (name.as_str(), st) {
                        ("min", _) => Some(GhostFn::NMin),
                        ("max", _) => Some(GhostFn::NMax),
                        ("saturating_sub", Ty::Nat) => Some(GhostFn::NSatSub),
                        ("div_euclid", Ty::Int) => Some(GhostFn::IDivEuclid),
                        ("rem_euclid", Ty::Int) => Some(GhostFn::IRemEuclid),
                        _ => None,
                    };
                    if let Some(g) = g {
                        let t = st.clone();
                        let adj = self.adjust_receiver(recv, k, false, false);
                        let sig = g.sig();
                        let params: Vec<Ty> = sig.params.iter().map(|p| p.subst(std::slice::from_ref(&t))).collect();
                        let ret = sig.ret.subst(std::slice::from_ref(&t));
                        return self.builtin_method(Callee::Ghost(g, vec![t]), &params, ret, adj, &args, span);
                    }
                }
                _ => {}
            }
        }
        for a in &args {
            let _ = self.infer(a);
        }
        let s = self.tys(&recv.ty);
        let hint = match name.as_str() {
            "unwrap" | "expect" => "`unwrap`/`expect` are not allowed; use `match`, `let .. else` or `?` (DESIGN.md §3.4)",
            "iter" | "map" | "fold" | "into_iter" | "enumerate" | "zip" => "iterators are not supported; use `for i in a..b` loops",
            "clone" => "all values are `Copy`; use the value directly",
            _ => "see the method whitelist in DESIGN.md §3.4",
        };
        self.push(Diagnostic::error(DiagKind::Resolve, span, format!("no method `{name}` found for `{s}`")).note(hint));
        Self::error_expr(span)
    }

    /// Adjusts a receiver of type `&^n T` reached after `k` derefs to the
    /// method's receiver mode (`by_ref`: `&T`, else `T`); `unsize` turns
    /// `&[T; N]` into `&[T]`.
    fn adjust_receiver(&mut self, mut recv: Expr, k: usize, by_ref: bool, unsize: bool) -> Expr {
        let span = recv.span;
        if by_ref {
            if k == 0 {
                let ty = Ty::reference(recv.ty.clone());
                recv = Expr::new(ExprKind::Coerce(Coercion::AutoRef, Box::new(recv)), ty, span);
            } else {
                for _ in 0..k - 1 {
                    recv = self.deref_once(recv);
                }
            }
            if unsize
                && let Ty::Ref(inner) = &recv.ty
                    && let Ty::Array(t, _) = &**inner {
                        let ty = Ty::slice_ref((**t).clone());
                        recv = Expr::new(ExprKind::Coerce(Coercion::Unsize, Box::new(recv)), ty, span);
                    }
        } else {
            for _ in 0..k {
                recv = self.deref_once(recv);
            }
        }
        recv
    }

    fn builtin_method(&mut self, callee: Callee, params: &[Ty], ret: Ty, recv: Expr, args: &[syn::Expr], span: Span) -> Expr {
        if params.len() != args.len() + 1 {
            self.err(DiagKind::Type, span, format!("this method takes {} argument(s) but {} were supplied", params.len() - 1, args.len()));
        }
        let mut es = vec![recv];
        for (i, a) in args.iter().enumerate() {
            match params.get(i + 1) {
                Some(p) => es.push(self.check(a, p)),
                None => es.push(self.infer(a)),
            }
        }
        Expr::new(ExprKind::Call { callee, args: es }, ret, span)
    }

    #[allow(clippy::too_many_arguments)]
    fn method_fn_call(&mut self, f: ItemId, targs: Vec<Ty>, own: Vec<Ty>, recv: Expr, args: &[syn::Expr], exp: &Exp, span: Span) -> Expr {
        let Some(sig) = self.ck.sigs.get(&f).cloned() else { return Self::error_expr(span) };
        if sig.kind == FnKind::Spec && !self.ghost && !self.lift {
            self.err(DiagKind::Ghost, span, "spec functions can only be called from ghost code");
        }
        if !sig.target_features.is_empty() && !self.ghost {
            let missing: Vec<String> = sig.feature_set.iter().filter(|x| !self.features.contains(x)).cloned().collect();
            if !missing.is_empty() {
                self.err(DiagKind::Feature, span, format!("calling a `#[target_feature]` method requires feature(s) {}", missing.join(", ")));
            }
        }
        let n = sig.generics.len();
        let mut explicit: Vec<Option<Ty>> = vec![None; n];
        let n_impl = targs.len().min(n);
        for (i, t) in targs.into_iter().enumerate().take(n) {
            explicit[i] = Some(t);
        }
        for (i, t) in own.into_iter().enumerate() {
            if n_impl + i < n {
                explicit[n_impl + i] = Some(t);
            }
        }
        // receiver already typed: unify its param
        let recv_param = sig.params[0].subst(&explicit.iter().enumerate().map(|(i, t)| t.clone().unwrap_or(Ty::Param(i as u32, "?".into()))).collect::<Vec<_>>());
        let recv = self.coerce(recv, &recv_param);
        let (mut es, ty_args, ret) = self.call_with_ghosts(f, &sig, 1, n, explicit, args, exp, span);
        es.insert(0, recv);
        Expr::new(ExprKind::Call { callee: Callee::Item(f, ty_args), args: es }, ret, span)
    }

    fn struct_lit(&mut self, s: &syn::ExprStruct, exp: &Exp, span: Span) -> Expr {
        if s.qself.is_some() {
            self.err(DiagKind::Unsupported, span, "qualified struct paths are not supported");
            return Self::error_expr(span);
        }
        let path = &s.path;
        let segs: Vec<(String, Span)> = path.segments.iter().map(|x| (x.ident.to_string(), self.sp(x.ident.span()))).collect();
        let mut explicit: Option<Vec<Ty>> = None;
        for seg in &path.segments {
            let (tys, _) = self.seg_args(seg);
            if !tys.is_empty() {
                explicit = Some(tys);
            }
        }
        let ctor = if segs.len() == 1 && segs[0].0 == "Self" {
            match self.g.self_ty.clone() {
                Some(Ty::Adt(id, args)) if matches!(self.ck.res.items[id.0 as usize].tag, ItemTag::Struct { .. }) => {
                    explicit = Some(args);
                    Some(Ctor::Struct(id))
                }
                _ => {
                    self.err(DiagKind::Resolve, span, "`Self { .. }` requires an inherent impl of a struct");
                    None
                }
            }
        } else if segs.len() >= 2 && segs[0].0 == "Self" && segs.len() == 2 {
            match self.g.self_ty.clone() {
                Some(Ty::Adt(id, args)) => match &self.ck.res.items[id.0 as usize].tag {
                    ItemTag::Enum { variants, .. } => {
                        explicit = Some(args);
                        variants.iter().position(|(v, _)| *v == segs[1].0).map(|i| Ctor::Variant(id, i as u32))
                    }
                    _ => None,
                },
                _ => None,
            }
        } else {
            match self.ck.res.resolve_path_defs(self.m, &segs, Ns::Type, path.leading_colon.is_some(), self.ghost || self.lift) {
                Ok(Def::Item(id)) if matches!(self.ck.res.items[id.0 as usize].tag, ItemTag::Struct { .. }) => {
                    self.check_ghost_ref(id, span);
                    Some(Ctor::Struct(id))
                }
                Ok(Def::Item(id)) if self.ck.res.items[id.0 as usize].tag == ItemTag::Alias => match self.ck.alias_ty(id) {
                    Ty::Adt(aid, args) => {
                        explicit = Some(args);
                        Some(Ctor::Struct(aid))
                    }
                    _ => None,
                },
                Ok(Def::Variant(id, i)) => {
                    self.check_ghost_ref(id, span);
                    Some(Ctor::Variant(id, i))
                }
                Ok(_) => None,
                Err(d) => {
                    self.push(d);
                    return Self::error_expr(span);
                }
            }
        };
        let Some(ctor) = ctor else {
            self.err(DiagKind::Type, span, "expected a struct or struct-like variant");
            return Self::error_expr(span);
        };
        if self.ctor_shape(ctor) != Shape::Named {
            self.err(DiagKind::Unsupported, span, "brace syntax is only supported for structs with named fields");
            return Self::error_expr(span);
        }
        let (fields, n, ret) = self.ctor_fields(ctor);
        let owner_mod = self.adt_module(ctor);
        // map written fields to indices
        let mut idx_args: Vec<(u32, syn::Expr, Span)> = Vec::new();
        for fv in &s.fields {
            let fspan = self.sp(fv.span());
            let fname = match &fv.member {
                syn::Member::Named(n) => n.to_string(),
                syn::Member::Unnamed(_) => {
                    self.err(DiagKind::Unsupported, fspan, "numeric field names in struct literals are not supported");
                    continue;
                }
            };
            let Some(pos) = fields.iter().position(|f| f.0.as_deref() == Some(fname.as_str())) else {
                self.err(DiagKind::Type, fspan, format!("struct has no field named `{fname}`"));
                continue;
            };
            if let Some(m) = owner_mod
                && !self.ck.res.visible(fields[pos].2, m, self.m) {
                    self.err(DiagKind::Privacy, fspan, format!("field `{fname}` is private"));
                }
            if idx_args.iter().any(|(i, _, _)| *i == pos as u32) {
                self.err(DiagKind::Type, fspan, format!("field `{fname}` specified more than once"));
                continue;
            }
            idx_args.push((pos as u32, fv.expr.clone(), fspan));
        }
        let explicit_v: Vec<Option<Ty>> = match explicit {
            Some(v) if v.len() == n => v.into_iter().map(Some).collect(),
            _ => vec![None; n],
        };
        let params: Vec<Ty> = idx_args.iter().map(|(i, _, _)| fields[*i as usize].1.clone()).collect();
        let exprs: Vec<syn::Expr> = idx_args.iter().map(|(_, e, _)| e.clone()).collect();
        // `..base` contributes the whole type
        let mut params2 = params.clone();
        let mut exprs2 = exprs.clone();
        if let Some(rest) = &s.rest {
            if matches!(ctor, Ctor::Variant(..)) {
                self.err(DiagKind::Unsupported, span, "functional update syntax is only supported for structs");
            }
            params2.push(ret.clone());
            exprs2.push((**rest).clone());
        } else if idx_args.len() != fields.len() {
            let missing: Vec<String> = fields.iter().enumerate().filter(|(i, _)| !idx_args.iter().any(|(j, _, _)| *j as usize == *i)).map(|(_, f)| f.0.clone().unwrap_or_default()).collect();
            self.err(DiagKind::Type, span, format!("missing field(s) {}", missing.iter().map(|m| format!("`{m}`")).collect::<Vec<_>>().join(", ")));
        }
        let (mut es, ty_args, ty) = self.generic_call_zst(n, explicit_v, &params2, &ret, &exprs2, exp, span, true);
        let base = if s.rest.is_some() { es.pop().map(Box::new) } else { None };
        let fields = idx_args.iter().zip(es).map(|((i, _, _), e)| (*i, e)).collect();
        Expr::new(ExprKind::Adt { ctor, ty_args, fields, base }, ty, span)
    }

    // ------------------------------------------------------------------
    // control flow
    // ------------------------------------------------------------------

    /// Types a block as an expression.
    pub fn block_expr(&mut self, b: &syn::Block, exp: &Exp, span: Span) -> Expr {
        let (blk, ty) = self.block(b, exp, None);
        Expr::new(ExprKind::Block(blk), ty, span)
    }

    /// Types a block. With `loop_head`, a leading `proof!` block may declare
    /// loop invariants and decreases.
    pub fn block(&mut self, b: &syn::Block, exp: &Exp, loop_head: Option<&mut LoopInfo>) -> (Block, Ty) {
        let span = self.sp(b.span());
        self.push_scope();
        let mut stmts = Vec::new();
        let mut tail = None;
        let n = b.stmts.len();
        let mut loop_head = loop_head;
        for (i, s) in b.stmts.iter().enumerate() {
            let last = i + 1 == n;
            match s {
                syn::Stmt::Local(l) => {
                    if let Some(st) = self.local_stmt(l) {
                        stmts.push(st);
                    }
                }
                syn::Stmt::Item(it) => {
                    self.err(DiagKind::Unsupported, self.sp(it.span()), "items inside function bodies are not supported");
                }
                syn::Stmt::Expr(e, semi) => {
                    if last && semi.is_none() {
                        let t = if let Exp::Prop = exp {
                            self.prop(e)
                        } else {
                            let x = self.expr(e, exp);
                            match exp.ty() {
                                Some(t) => self.coerce(x, t),
                                None => x,
                            }
                        };
                        tail = Some(Box::new(t));
                    } else if let Some(st) = self.expr_stmt(e, semi.is_some()) {
                        stmts.push(st);
                    }
                }
                syn::Stmt::Macro(m) => {
                    let mspan = self.sp(m.span());
                    if is_macro(&m.mac.path, "proof") {
                        let head = if i == 0 { loop_head.take() } else { None };
                        let steps = self.proof_block(&m.mac, head, mspan);
                        if !steps.is_empty() {
                            stmts.push(Stmt { kind: StmtKind::Proof(steps), span: mspan });
                        }
                    } else {
                        let e = self.macro_expr(&m.mac, &Exp::None, mspan);
                        if last && m.semi_token.is_none() {
                            tail = Some(Box::new(e));
                        } else {
                            stmts.push(Stmt { kind: StmtKind::Expr(e), span: mspan });
                        }
                    }
                }
            }
        }
        self.pop_scope();
        let ty = match &tail {
            Some(t) => t.ty.clone(),
            None => {
                let diverges = stmts.last().is_some_and(|s| matches!(&s.kind, StmtKind::Expr(e) if e.ty.is_never()));
                if diverges {
                    Ty::Never
                } else {
                    match exp {
                        Exp::Prop => {
                            self.err(DiagKind::Type, span, "expected a proposition, found a block without a final expression");
                            Ty::Prop
                        }
                        Exp::Ty(t) if !t.is_unit() && !t.is_error() => {
                            let s = self.tys(t);
                            self.push(Diagnostic::error(DiagKind::Type, span, format!("mismatched types: expected `{s}`, found `()`")).note("the block has no final expression"));
                            Ty::unit()
                        }
                        _ => Ty::unit(),
                    }
                }
            }
        };
        (Block { stmts, tail, span }, ty)
    }

    fn local_stmt(&mut self, l: &syn::Local) -> Option<Stmt> {
        let span = self.sp(l.span());
        // attributes: rejected with the others nested in the body
        // (`Checker::check_nested_attrs`)
        let (pat, ann) = match &l.pat {
            syn::Pat::Type(pt) => (&*pt.pat, Some(&*pt.ty)),
            p => (p, None),
        };
        let Some(init) = &l.init else {
            self.err(DiagKind::Unsupported, span, "`let` without an initializer is not supported");
            return None;
        };
        let declared = ann.map(|t| {
            let g = self.g.clone();
            let ghost = self.ghost;
            self.ck.lower_ty(self.m, t, &g, ghost || self.lift)
        });
        let value = match &declared {
            Some(t) => self.check(&init.expr, t),
            None => self.infer(&init.expr),
        };
        let ty = declared.unwrap_or_else(|| value.ty.clone());
        let els = match &init.diverge {
            Some((_, e)) => {
                let espan = self.sp(e.span());
                let blk = match &**e {
                    syn::Expr::Block(b) => {
                        let (blk, t) = self.block(&b.block, &Exp::None, None);
                        if !t.is_never() {
                            self.push(Diagnostic::error(DiagKind::Type, espan, "the `else` block of `let .. else` must diverge").note("end it with `return ..;` or `unreachable!()`"));
                        }
                        blk
                    }
                    _ => {
                        self.err(DiagKind::Type, espan, "expected a block after `else`");
                        return None;
                    }
                };
                Some(blk)
            }
            None => None,
        };
        let pat = if els.is_some() { self.refutable_pat(pat, &ty) } else { self.irrefutable_pat(pat, &ty, "`let` binding") };
        Some(Stmt { kind: StmtKind::Let { pat, init: value, els }, span })
    }

    fn expr_stmt(&mut self, e: &syn::Expr, semi: bool) -> Option<Stmt> {
        let span = self.sp(e.span());
        match e {
            syn::Expr::Assign(a) => {
                let place = self.place(&a.left)?;
                let value = self.check(&a.right, &place.ty);
                Some(Stmt { kind: StmtKind::Assign { place, value }, span })
            }
            syn::Expr::Binary(b) if map_binop(&b.op).is_some_and(|(_, c)| c) => {
                let (op, _) = map_binop(&b.op).unwrap();
                let place = self.place(&b.left)?;
                let value = if op.is_shift() {
                    self.no_exp_reason.push("shift");
                    let v = self.infer(&b.right);
                    self.no_exp_reason.pop();
                    let v = self.deref_once(v);
                    if !matches!(v.ty, Ty::Uint(_) | Ty::Error) {
                        self.err(DiagKind::Type, v.span, "shift amount must be an unsigned integer");
                    }
                    v
                } else if needs_exp(&b.right) {
                    self.check(&b.right, &place.ty.clone())
                } else {
                    let v = self.infer(&b.right);
                    let v = self.deref_once(v);
                    self.coerce(v, &place.ty.clone())
                };
                let ok = match &place.ty {
                    Ty::Uint(_) => true,
                    Ty::Bool => matches!(op, BinOp::BitAnd | BinOp::BitOr | BinOp::BitXor),
                    Ty::Error => true,
                    _ => false,
                };
                if !ok {
                    let s = self.tys(&place.ty);
                    self.err(DiagKind::Type, span, format!("`{}=` cannot be applied to `{s}`", op.symbol()));
                }
                Some(Stmt { kind: StmtKind::CompoundAssign { op, place, value }, span })
            }
            syn::Expr::MethodCall(mc) if mc.method == "copy_from_slice" => self.copy_from_slice(mc, span),
            _ => {
                let x = self.infer(e);
                if !semi && !x.ty.is_unit() && !x.ty.is_never() && !x.ty.is_error() {
                    let s = self.tys(&x.ty);
                    self.err(DiagKind::Type, span, format!("mismatched types: expected `()`, found `{s}` (add a `;`?)"));
                }
                Some(Stmt { kind: StmtKind::Expr(x), span })
            }
        }
    }

    /// An assignable place rooted at a `mut` local.
    fn place(&mut self, e: &syn::Expr) -> Option<Place> {
        let span = self.sp(e.span());
        match e {
            syn::Expr::Paren(p) => self.place(&p.expr),
            syn::Expr::Path(p) if p.path.segments.len() == 1 && p.qself.is_none() => {
                let name = p.path.segments[0].ident.to_string();
                let Some(l) = self.lookup_local(&name) else {
                    self.err(DiagKind::Unsupported, span, "only local variables (and their fields/elements) can be assigned");
                    return None;
                };
                if !self.locals[l.0 as usize].mutable {
                    self.push(Diagnostic::error(DiagKind::Type, span, format!("cannot assign twice to immutable variable `{name}`")).note_at(self.locals[l.0 as usize].span, "declare it with `let mut`"));
                }
                if self.locals[l.0 as usize].ghost && !self.ghost {
                    self.err(DiagKind::Ghost, span, "exec code assigns a ghost variable");
                }
                let ty = self.local_ty(l);
                Some(Place { local: l, projs: vec![], ty, span })
            }
            syn::Expr::Field(f) => {
                let mut p = self.place(&f.base)?;
                let (index, name, ty) = match (&p.ty, &f.member) {
                    (Ty::Tuple(ts), syn::Member::Unnamed(i)) if (i.index as usize) < ts.len() => (i.index, None, ts[i.index as usize].clone()),
                    (Ty::Adt(id, args), m) => {
                        let (id, args) = (*id, args.clone());
                        let Some(ItemKind::Struct(s)) = self.ck.hir_items[id.0 as usize].clone() else {
                            self.err(DiagKind::Type, span, "cannot assign a field of an enum");
                            return None;
                        };
                        let pos = match m {
                            syn::Member::Named(n) => s.fields.iter().position(|fd| fd.name.as_deref() == Some(&n.to_string())),
                            syn::Member::Unnamed(i) => ((i.index as usize) < s.fields.len() && s.shape == Shape::Tuple).then_some(i.index as usize),
                        };
                        let Some(pos) = pos else {
                            self.err(DiagKind::Type, span, "no such field");
                            return None;
                        };
                        let owner_mod = self.ck.res.items[id.0 as usize].module;
                        if !self.ck.res.visible(s.fields[pos].vis, owner_mod, self.m) {
                            self.err(DiagKind::Privacy, span, "field is private");
                        }
                        (pos as u32, s.fields[pos].name.clone(), s.fields[pos].ty.subst(&args))
                    }
                    (Ty::Ref(_), _) => {
                        self.err(DiagKind::MutRef, span, "cannot assign through a shared reference");
                        return None;
                    }
                    _ => {
                        self.err(DiagKind::Type, span, "no such field");
                        return None;
                    }
                };
                p.projs.push(Proj::Field { index, name });
                p.ty = ty;
                p.span = span;
                Some(p)
            }
            syn::Expr::Index(ix) => {
                let mut p = self.place(&ix.expr)?;
                let ty = match &p.ty {
                    Ty::Array(t, _) => (**t).clone(),
                    // an element of a slice state of a function read from
                    // MIR (its `&mut [T]` parameter, docs/mir-lift.md §20.10)
                    Ty::Ref(inner) if self.lift && !self.ghost && p.projs.is_empty() && matches!(&**inner, Ty::Slice(_)) => match &**inner {
                        Ty::Slice(t) => (**t).clone(),
                        _ => return None,
                    },
                    Ty::Ref(_) => {
                        self.err(DiagKind::MutRef, span, "cannot assign through a shared reference");
                        return None;
                    }
                    _ => {
                        self.err(DiagKind::Type, span, "only array elements can be assigned");
                        return None;
                    }
                };
                if matches!(strip_parens(&ix.index), syn::Expr::Range(_)) {
                    self.err(DiagKind::Unsupported, span, "cannot assign to a range; use `copy_from_slice`");
                    return None;
                }
                let i = self.check(&ix.index, &Ty::usize());
                p.projs.push(Proj::Index(i));
                p.ty = ty;
                p.span = span;
                Some(p)
            }
            syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
                self.err(DiagKind::MutRef, span, "cannot assign through a reference");
                None
            }
            _ => {
                self.err(DiagKind::Unsupported, span, "invalid assignment target");
                None
            }
        }
    }

    fn copy_from_slice(&mut self, mc: &syn::ExprMethodCall, span: Span) -> Option<Stmt> {
        let (local_expr, range) = match strip_parens(&mc.receiver) {
            syn::Expr::Index(ix) => match strip_parens(&ix.index) {
                syn::Expr::Range(r) => (&*ix.expr, Some(r.clone())),
                _ => {
                    self.err(DiagKind::MutRef, span, "`copy_from_slice` destination must be `local` or `local[a..b]`");
                    return None;
                }
            },
            e => (e, None),
        };
        let syn::Expr::Path(p) = strip_parens(local_expr) else {
            self.err(DiagKind::MutRef, span, "`copy_from_slice` destination must be a `let mut` array local");
            return None;
        };
        let name = p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
        let Some(l) = (p.path.segments.len() == 1).then(|| self.lookup_local(&name)).flatten() else {
            self.err(DiagKind::MutRef, span, "`copy_from_slice` destination must be a `let mut` array local");
            return None;
        };
        let lt = self.local_ty(l);
        let elem = match &lt {
            Ty::Array(t, _) => (**t).clone(),
            _ => {
                self.err(DiagKind::MutRef, span, "`copy_from_slice` destination must be an array");
                return None;
            }
        };
        if !self.locals[l.0 as usize].mutable {
            self.push(Diagnostic::error(DiagKind::MutRef, span, format!("`{name}` must be declared `let mut` to use `copy_from_slice`")));
        }
        let range = range.map(|r| {
            if matches!(r.limits, syn::RangeLimits::Closed(_)) {
                self.err(DiagKind::Unsupported, span, "inclusive ranges are not supported here");
            }
            let a = r.start.as_ref().map(|e| self.check(e, &Ty::usize()));
            let b = r.end.as_ref().map(|e| self.check(e, &Ty::usize()));
            (a, b)
        });
        if mc.args.len() != 1 {
            self.err(DiagKind::Type, span, "`copy_from_slice` takes one argument");
            return None;
        }
        let src = self.check(&mc.args[0], &Ty::slice_ref(elem));
        Some(Stmt { kind: StmtKind::CopyFromSlice { dst: l, range, src }, span })
    }

    fn if_expr(&mut self, i: &syn::ExprIf, exp: &Exp, span: Span) -> Expr {
        if let syn::Expr::Let(l) = strip_parens(&i.cond) {
            // if let P = e { a } else { b }  ≡  match e { P => a, _ => b }
            let scrut = self.infer(&l.expr);
            self.push_scope();
            let pat = self.refutable_pat(&l.pat, &scrut.ty);
            let then = self.block_expr(&i.then_branch, exp, self.sp(i.then_branch.span()));
            self.pop_scope();
            let els = match &i.else_branch {
                Some((_, e)) => self.expr(e, exp),
                None => Expr::new(ExprKind::Block(Block { stmts: vec![], tail: None, span }), Ty::unit(), span),
            };
            let els = self.coerce_branch(els, exp);
            let ty = if i.else_branch.is_none() {
                let t = self.coerce(then.clone(), &Ty::unit());
                let _ = t;
                Ty::unit()
            } else {
                self.join(&then, &els, exp, span)
            };
            let wild = Pat { kind: PatKind::Wild, ty: scrut.ty.clone(), span };
            let arms = vec![Arm { pat, guard: None, body: then, span }, Arm { pat: wild, guard: None, body: els, span }];
            return Expr::new(ExprKind::Match { scrut: Box::new(scrut), arms, source: MatchSource::IfLet }, ty, span);
        }
        if contains_let(&i.cond) {
            self.err(DiagKind::Unsupported, span, "`let` chains are not supported");
            return Self::error_expr(span);
        }
        let cond = self.check(&i.cond, &Ty::Bool);
        if let (Exp::None, Some((_, e))) = (exp, &i.else_branch)
            && block_needs_exp(&i.then_branch) && !branch_needs_exp(e) {
                // type the else-branch first and use it as the expectation
                let els = self.expr(e, &Exp::None);
                let t = els.ty.clone();
                let exp2 = if t.is_never() || t.is_error() { Exp::None } else { Exp::Ty(t) };
                let then = self.block_expr(&i.then_branch, &exp2, self.sp(i.then_branch.span()));
                let then = self.coerce_branch(then, &exp2);
                let ty = self.join(&then, &els, exp, span);
                return Expr::new(ExprKind::If { cond: Box::new(cond), then: Box::new(then), els: Some(Box::new(els)) }, ty, span);
            }
        let then = self.block_expr(&i.then_branch, exp, self.sp(i.then_branch.span()));
        match &i.else_branch {
            None => {
                if !then.ty.is_unit() && !then.ty.is_never() && !then.ty.is_error() {
                    let s = self.tys(&then.ty);
                    self.err(DiagKind::Type, then.span, format!("`if` without `else` must have type `()`, found `{s}`"));
                }
                Expr::new(ExprKind::If { cond: Box::new(cond), then: Box::new(then), els: None }, Ty::unit(), span)
            }
            Some((_, e)) => {
                // without an expectation, the then-branch type (if known)
                // is the expectation of the else-branch
                let exp2 = match (exp, &then.ty) {
                    (Exp::None, t) if !t.is_never() && !t.is_error() => Exp::Ty(t.clone()),
                    _ => exp.clone(),
                };
                let els = self.expr(e, &exp2);
                let els = self.coerce_branch(els, &exp2);
                let ty = self.join(&then, &els, exp, span);
                Expr::new(ExprKind::If { cond: Box::new(cond), then: Box::new(then), els: Some(Box::new(els)) }, ty, span)
            }
        }
    }

    fn coerce_branch(&mut self, e: Expr, exp: &Exp) -> Expr {
        match exp.ty() {
            Some(t) => self.coerce(e, t),
            None => e,
        }
    }

    /// Joins the types of two branches.
    fn join(&mut self, a: &Expr, b: &Expr, exp: &Exp, span: Span) -> Ty {
        if let Exp::Prop = exp {
            return Ty::Prop;
        }
        if a.ty.is_never() {
            return b.ty.clone();
        }
        if b.ty.is_never() {
            return a.ty.clone();
        }
        if a.ty.is_error() || b.ty.is_error() {
            return if a.ty.is_error() { b.ty.clone() } else { a.ty.clone() };
        }
        if a.ty != b.ty {
            let (x, y) = (self.tys(&a.ty), self.tys(&b.ty));
            self.err(DiagKind::Type, span, format!("branches have incompatible types: `{x}` and `{y}`"));
        }
        a.ty.clone()
    }

    fn match_expr(&mut self, m: &syn::ExprMatch, exp: &Exp, span: Span) -> Expr {
        let scrut = self.infer(&m.expr);
        let mut slots: Vec<Option<Arm>> = vec![None; m.arms.len()];
        let mut ty: Option<Ty> = None;
        // without an expectation, arms that can be typed on their own go
        // first; their type is the expectation of the others
        let mut order: Vec<usize> = (0..m.arms.len()).collect();
        if let Exp::None = exp {
            order.sort_by_key(|&k| branch_needs_exp(&m.arms[k].body));
        }
        let mut cur_exp = exp.clone();
        for k in order {
            let a = &m.arms[k];
            let aspan = self.sp(a.span());
            self.push_scope();
            let pat = self.refutable_pat(&a.pat, &scrut.ty);
            let guard = a.guard.as_ref().map(|(_, g)| self.check(g, &Ty::Bool));
            let body = if let Exp::Prop = exp { self.prop(&a.body) } else { self.expr(&a.body, &cur_exp) };
            let body = self.coerce_branch(body, &cur_exp);
            self.pop_scope();
            ty = Some(match ty {
                None => body.ty.clone(),
                Some(t) => {
                    let prev = Expr::new(ExprKind::Tuple(vec![]), t, aspan);
                    self.join(&prev, &body, exp, body.span)
                }
            });
            if let (Exp::None, Some(t)) = (&cur_exp, &ty)
                && !t.is_never() && !t.is_error() {
                    cur_exp = Exp::Ty(t.clone());
                }
            slots[k] = Some(Arm { pat, guard, body, span: aspan });
        }
        let arms: Vec<Arm> = slots.into_iter().flatten().collect();
        let ty = ty.unwrap_or(Ty::Never);
        self.check_exhaustive(&scrut.ty, &arms.iter().filter(|a| a.guard.is_none()).map(|a| &a.pat).collect::<Vec<_>>(), span, "match");
        Expr::new(ExprKind::Match { scrut: Box::new(scrut), arms, source: MatchSource::Match }, ty, span)
    }

    fn return_expr(&mut self, e: Option<&syn::Expr>, span: Span) -> Expr {
        if self.loop_depth > 0 {
            self.push(Diagnostic::error(DiagKind::ControlInLoop, span, "`return` inside a loop is not supported").note("loops are desugared into recursive helpers (DESIGN.md §7.4)"));
        }
        // spec functions: `return` is sugar, removed by `desugar_exits`
        // (SEMANTICS.md §13.11)
        if self.in_const || !(self.kind == FnKind::Exec || (self.kind == FnKind::Spec && self.ret != Ty::Prop)) {
            self.err(DiagKind::Unsupported, span, "`return` is only allowed in exec and spec functions");
        }
        let ret = self.ret.clone();
        let v = match e {
            Some(e) => Some(Box::new(self.check(e, &ret))),
            None => {
                if !ret.is_unit() && !ret.is_error() {
                    let s = self.tys(&ret);
                    self.err(DiagKind::Type, span, format!("`return;` in a function returning `{s}`"));
                }
                None
            }
        };
        Expr::new(ExprKind::Return(v), Ty::Never, span)
    }

    fn try_expr(&mut self, e: &syn::Expr, span: Span) -> Expr {
        if self.loop_depth > 0 {
            self.push(Diagnostic::error(DiagKind::ControlInLoop, span, "`?` inside a loop is not supported").note("loops are desugared into recursive helpers (DESIGN.md §7.4)"));
        }
        if !matches!(self.ret, Ty::Option(_) | Ty::Error) || !matches!(self.kind, FnKind::Exec | FnKind::Spec) {
            let what = if self.kind == FnKind::Spec { "spec" } else { "exec" };
            self.err(DiagKind::Type, span, format!("`?` requires the enclosing {what} function to return `Option`"));
        }
        let inner = self.infer(e);
        let ty = match &inner.ty {
            Ty::Option(t) => (**t).clone(),
            Ty::Error => Ty::Error,
            other => {
                let s = self.tys(other);
                self.err(DiagKind::Type, span, format!("`?` is only allowed on `Option`, found `{s}`"));
                Ty::Error
            }
        };
        Expr::new(ExprKind::Try(Box::new(inner)), ty, span)
    }

    fn macro_expr(&mut self, mac: &syn::Macro, exp: &Exp, span: Span) -> Expr {
        if is_macro(&mac.path, "unreachable") {
            if !mac.tokens.is_empty() {
                self.err(DiagKind::Macro, span, "`unreachable!` takes no arguments here");
            }
            return Expr::new(ExprKind::Unreachable, Ty::Never, span);
        }
        if is_macro(&mac.path, "proof") {
            self.err(DiagKind::Script, span, "`proof! { .. }` is a statement");
            return Self::error_expr(span);
        }
        let name = mac.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
        if name == "ghost" {
            self.push(Diagnostic::error(DiagKind::Ghost, span, "`ghost!(..)` is only the argument of a `#[ghost]` parameter at a call site").note("DESIGN.md §15.3: `f(x, ghost!(e))` for `fn f(x: T, #[ghost] g: G)`"));
            return Self::error_expr(span);
        }
        if self.ghost && mac.path.segments.len() == 1 && (name == "seq" || name == "hex") {
            return if name == "seq" { self.seq_macro(mac, exp, span) } else { self.hex_macro(mac, span) };
        }
        self.push(Diagnostic::error(DiagKind::Macro, span, format!("macro `{name}!` is not supported")).note("only `proof! {{ .. }}` and `unreachable!()` are allowed; ghost code also has `seq![..]` and `hex!(\"..\")` (DESIGN.md §3.1, §4.1)"));
        Self::error_expr(span)
    }

    /// Ghost `seq![a, ..xs, b]` (§4.1): a `Seq<T>` built from elements and
    /// spliced sequences (anything that view-coerces to `Seq<T>`).
    fn seq_macro(&mut self, mac: &syn::Macro, exp: &Exp, span: Span) -> Expr {
        let items = match mac.parse_body_with(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated) {
            Ok(p) => p.into_iter().collect::<Vec<_>>(),
            Err(e) => {
                self.err(DiagKind::Macro, span, format!("malformed `seq![..]`: {e}"));
                return Self::error_expr(span);
            }
        };
        let spread = |e: &syn::Expr| -> Option<syn::Expr> {
            match e {
                syn::Expr::Range(r) if r.start.is_none() && matches!(r.limits, syn::RangeLimits::HalfOpen(_)) => r.end.as_deref().cloned(),
                _ => None,
            }
        };
        // the element type: expected, else from the first plain element or
        // the first spliced sequence
        let mut elem: Option<Ty> = match exp.ty() {
            Some(Ty::Seq(t)) => Some((**t).clone()),
            _ => None,
        };
        let mut typed: Vec<Option<Expr>> = vec![None; items.len()];
        if elem.is_none() {
            if let Some((i, e)) = items.iter().enumerate().find(|(_, e)| spread(e).is_none() && !needs_exp(e)) {
                let x = self.infer(e);
                elem = Some(x.ty.clone());
                typed[i] = Some(x);
            } else if let Some((i, e)) = items.iter().enumerate().find_map(|(i, e)| spread(e).map(|x| (i, x))) {
                let x = self.infer(&e);
                elem = match x.ty.peel_refs() {
                    Ty::Seq(t) | Ty::Slice(t) | Ty::Array(t, _) => Some((**t).clone()),
                    _ => None,
                };
                typed[i] = Some(x);
            } else if let Some(e) = items.first() {
                let x = self.infer(e);
                elem = Some(x.ty.clone());
                typed[0] = Some(x);
            }
        }
        let Some(t) = elem else {
            self.err(DiagKind::Type, span, "cannot infer the element type of `seq![]`; annotate it (`let s: Seq<u8> = seq![];`)");
            return Self::error_expr(span);
        };
        let seq_t = Ty::Seq(Box::new(t.clone()));
        let mut parts: Vec<(bool, Expr)> = Vec::new();
        for (i, e) in items.iter().enumerate() {
            match spread(e) {
                Some(inner) => {
                    let x = match typed[i].take() {
                        Some(x) => self.coerce(x, &seq_t),
                        None => self.check(&inner, &seq_t),
                    };
                    parts.push((true, x));
                }
                None => {
                    let x = match typed[i].take() {
                        Some(x) => self.coerce(x, &t),
                        None => self.check(e, &t),
                    };
                    parts.push((false, x));
                }
            }
        }
        let mut acc: Option<Expr> = None;
        for (is_seq, x) in parts.into_iter().rev() {
            let xs = x.span;
            acc = Some(match (is_seq, acc) {
                (true, None) => x,
                (true, Some(rest)) => Expr::new(ExprKind::Call { callee: Callee::Ghost(GhostFn::SAppend, vec![t.clone()]), args: vec![x, rest] }, seq_t.clone(), xs),
                (false, rest) => {
                    let rest = rest.unwrap_or_else(|| Expr::new(ExprKind::Call { callee: Callee::Ghost(GhostFn::SEmpty, vec![t.clone()]), args: vec![] }, seq_t.clone(), span));
                    Expr::new(ExprKind::Call { callee: Callee::Ghost(GhostFn::SCons, vec![t.clone()]), args: vec![x, rest] }, seq_t.clone(), xs)
                }
            });
        }
        let e = acc.unwrap_or_else(|| Expr::new(ExprKind::Call { callee: Callee::Ghost(GhostFn::SEmpty, vec![t.clone()]), args: vec![] }, seq_t.clone(), span));
        Expr { span, ..e }
    }

    /// Ghost `hex!("..")` (§4.1): a `[u8; N]` literal from hex digits
    /// (whitespace between groups allowed).
    fn hex_macro(&mut self, mac: &syn::Macro, span: Span) -> Expr {
        let lit = match mac.parse_body::<syn::LitStr>() {
            Ok(l) => l.value(),
            Err(_) => {
                self.err(DiagKind::Macro, span, "expected `hex!(\"..\")` with a string of hex digits");
                return Self::error_expr(span);
            }
        };
        let digits: Vec<char> = lit.chars().filter(|c| !c.is_whitespace()).collect();
        if !digits.len().is_multiple_of(2) || !digits.iter().all(|c| c.is_ascii_hexdigit()) {
            self.err(DiagKind::Literal, span, "`hex!` needs an even number of hex digits (whitespace between groups is allowed)");
            return Self::error_expr(span);
        }
        let bytes: Vec<u8> = digits.chunks(2).map(|p| u8::from_str_radix(&p.iter().collect::<String>(), 16).unwrap()).collect();
        let es: Vec<Expr> = bytes.iter().map(|b| Expr::new(ExprKind::Lit(Lit::Int(*b as u128)), Ty::u8(), span)).collect();
        Expr::new(ExprKind::Array(es), Ty::array(Ty::u8(), bytes.len() as u64), span)
    }

    // ------------------------------------------------------------------
    // loops
    // ------------------------------------------------------------------

    fn for_loop(&mut self, f: &syn::ExprForLoop, span: Span) -> Expr {
        if f.label.is_some() {
            self.err(DiagKind::Loop, span, "loop labels are not supported");
        }
        let syn::Expr::Range(r) = strip_parens(&f.expr) else {
            self.push(Diagnostic::error(DiagKind::Unsupported, span, "`for` loops must iterate over an integer range `a..b` or `a..=b`").note("iterators are not supported"));
            return Self::error_expr(span);
        };
        let (Some(lo), Some(hi)) = (&r.start, &r.end) else {
            self.err(DiagKind::Unsupported, span, "`for` ranges need both bounds");
            return Self::error_expr(span);
        };
        let inclusive = matches!(r.limits, syn::RangeLimits::Closed(_));
        let (lo_e, hi_e) = self.operands(lo, hi, None);
        let lo_e = self.autoderef(lo_e);
        let hi_e = self.autoderef(hi_e);
        let elem = match (&lo_e.ty, &hi_e.ty) {
            (Ty::Uint(a), Ty::Uint(b)) if a == b => Ty::Uint(*a),
            (Ty::Error, _) | (_, Ty::Error) => Ty::Error,
            (a, b) => {
                let (x, y) = (self.tys(a), self.tys(b));
                self.err(DiagKind::Type, span, format!("loop range bounds must have the same unsigned type, found `{x}` and `{y}`"));
                Ty::Error
            }
        };
        let index = self.loop_count;
        self.loop_count += 1;
        let start = self.locals.len() as u32;
        self.loop_depth += 1;
        self.push_scope();
        let var = match &f.pat.as_ref() {
            syn::Pat::Ident(pi) if pi.by_ref.is_none() && pi.subpat.is_none() => {
                if pi.mutability.is_some() {
                    self.err(DiagKind::Unsupported, span, "the loop variable is immutable");
                }
                let name = pi.ident.to_string();
                let s = self.sp(pi.span());
                if self.ck.res.pattern_hazard(&name) {
                    self.push(Diagnostic::error(DiagKind::IdentPattern, s, format!("loop variable `{name}` has the name of a constant, unit struct or unit variant")).note("rustc and the checker could disagree on such patterns (DESIGN.md §3.3)"));
                }
                Some(self.new_local(&name, elem.clone(), false, false, s))
            }
            syn::Pat::Wild(_) => None,
            _ => {
                self.err(DiagKind::Unsupported, span, "the loop pattern must be a name or `_`");
                None
            }
        };
        let mut info = LoopInfo { index, ..Default::default() };
        let (body, bty) = self.block(&f.body, &Exp::Ty(Ty::unit()), Some(&mut info));
        let _ = bty;
        self.pop_scope();
        self.loop_depth -= 1;
        let kind = LoopKind::ForRange { var, lo: lo_e, hi: hi_e, inclusive };
        self.finish_loop(kind, body, info, start, var, span)
    }

    fn while_loop(&mut self, w: &syn::ExprWhile, span: Span) -> Expr {
        if w.label.is_some() {
            self.err(DiagKind::Loop, span, "loop labels are not supported");
        }
        if matches!(strip_parens(&w.cond), syn::Expr::Let(_)) {
            self.err(DiagKind::Unsupported, span, "`while let` is not supported");
            return Self::error_expr(span);
        }
        let index = self.loop_count;
        self.loop_count += 1;
        let start = self.locals.len() as u32;
        self.loop_depth += 1;
        let cond = self.check(&w.cond, &Ty::Bool);
        let mut info = LoopInfo { index, ..Default::default() };
        let (body, _) = self.block(&w.body, &Exp::Ty(Ty::unit()), Some(&mut info));
        self.loop_depth -= 1;
        if info.decreases.is_none() {
            self.push(Diagnostic::error(DiagKind::Contract, span, "`while` loops need a measure").note("start the body with `proof! { decreases(e); }` (DESIGN.md §3.3)"));
        }
        self.finish_loop(LoopKind::While { cond }, body, info, start, None, span)
    }

    fn finish_loop(&mut self, kind: LoopKind, body: Block, mut info: LoopInfo, start: u32, var: Option<LocalId>, span: Span) -> Expr {
        let mut c = LoopVars { start, reads: BTreeSet::new(), writes: BTreeSet::new() };
        if let LoopKind::While { cond } = &kind {
            c.expr(cond);
        }
        for i in &info.invariants {
            c.expr(i);
        }
        if let Some(d) = &info.decreases {
            c.expr(d);
        }
        c.block(&body);
        info.mutated = c.writes.iter().copied().collect();
        info.read = c.reads.iter().copied().filter(|l| !c.writes.contains(l) && Some(*l) != var).collect();
        let l = Loop { kind, body, info, span };
        Expr::new(ExprKind::Loop(Box::new(l)), Ty::unit(), span)
    }

    /// Checks exhaustiveness of patterns against a type.
    pub fn check_exhaustive(&mut self, ty: &Ty, pats: &[&Pat], span: Span, what: &str) {
        if ty.is_error() {
            return;
        }
        let items = &self.ck.hir_items;
        let lookup = |id: ItemId| items.get(id.0 as usize).cloned().flatten();
        if let Some(w) = crate::exhaust::missing(ty, pats, &lookup, &|id| self.ck.res.items[id.0 as usize].name.clone()) {
            let d = if what == "match" {
                Diagnostic::error(DiagKind::Exhaustive, span, format!("non-exhaustive patterns: `{w}` not covered"))
            } else {
                Diagnostic::error(DiagKind::Exhaustive, span, format!("refutable pattern in {what}: `{w}` not covered")).note("use `let .. else` or `match`")
            };
            self.push(d);
        }
    }

    /// Parses `#[ensures(|ret| p)]` / `#[ensures(p)]`.
    fn ensures(&mut self, e: &syn::Expr, ret: &Ty) -> Ensures {
        let span = self.sp(e.span());
        if let syn::Expr::Closure(c) = e {
            if c.inputs.len() != 1 {
                self.err(DiagKind::Contract, span, "`ensures` closures take exactly the return value");
            }
            self.push_scope();
            let binder = match c.inputs.first() {
                Some(syn::Pat::Type(pt)) => {
                    let g = self.g.clone();
                    let t = self.ck.lower_ty(self.m, &pt.ty, &g, true);
                    if t != *ret && !t.is_error() {
                        let (a, b) = (self.tys(&t), self.tys(ret));
                        self.err(DiagKind::Contract, span, format!("`ensures` binder has type `{a}` but the function returns `{b}`"));
                    }
                    self.irrefutable_pat(&pt.pat, ret, "`ensures` binder")
                }
                Some(p) => self.irrefutable_pat(p, ret, "`ensures` binder"),
                None => Pat { kind: PatKind::Wild, ty: ret.clone(), span },
            };
            let prop = self.prop(&c.body);
            self.pop_scope();
            Ensures { binder, prop }
        } else {
            if !ret.is_unit() {
                self.err(DiagKind::Contract, span, "use `#[ensures(|ret| ..)]` to talk about the return value");
            }
            let prop = self.prop(e);
            Ensures { binder: Pat { kind: PatKind::Wild, ty: Ty::unit(), span }, prop }
        }
    }

    /// A `decreases` measure: an unsigned integer or `Int`.
    pub fn measure(&mut self, e: &syn::Expr) -> Expr {
        let x = self.infer(e);
        let x = self.autoderef(x);
        if !matches!(x.ty, Ty::Uint(_) | Ty::Int | Ty::Nat | Ty::Error) {
            let s = self.tys(&x.ty);
            self.err(DiagKind::Contract, x.span, format!("a measure must be an unsigned integer or `Int`, found `{s}`"));
        }
        x
    }
}

/// Collects outer locals read/assigned inside a loop.
struct LoopVars {
    start: u32,
    reads: BTreeSet<LocalId>,
    writes: BTreeSet<LocalId>,
}

impl Visitor for LoopVars {
    fn expr(&mut self, e: &Expr) {
        if let ExprKind::Local(l) = &e.kind
            && l.0 < self.start {
                self.reads.insert(*l);
            }
        visit::walk_expr(self, e);
    }
    fn stmt(&mut self, s: &Stmt) {
        match &s.kind {
            StmtKind::CopyFromSlice { dst, .. } if dst.0 < self.start => {
                self.writes.insert(*dst);
            }
            _ => {}
        }
        visit::walk_stmt(self, s);
    }
    fn place(&mut self, p: &Place) {
        if p.local.0 < self.start {
            self.writes.insert(p.local);
        }
        visit::walk_place(self, p);
    }
    fn loop_(&mut self, l: &Loop) {
        for m in &l.info.mutated {
            if m.0 < self.start {
                self.writes.insert(*m);
            }
        }
        visit::walk_loop(self, l);
    }
}

pub fn strip_parens(e: &syn::Expr) -> &syn::Expr {
    match e {
        syn::Expr::Paren(p) => strip_parens(&p.expr),
        syn::Expr::Group(g) => strip_parens(&g.expr),
        _ => e,
    }
}

/// Whether a branch body (block or expression) needs an expectation.
pub fn branch_needs_exp(e: &syn::Expr) -> bool {
    match strip_parens(e) {
        syn::Expr::Block(b) => block_needs_exp(&b.block),
        other => needs_exp(other),
    }
}

fn block_needs_exp(b: &syn::Block) -> bool {
    match b.stmts.last() {
        Some(syn::Stmt::Expr(e, None)) => branch_needs_exp(e),
        _ => false,
    }
}

fn contains_let(e: &syn::Expr) -> bool {
    match strip_parens(e) {
        syn::Expr::Let(_) => true,
        syn::Expr::Binary(b) => contains_let(&b.left) || contains_let(&b.right),
        _ => false,
    }
}

/// Whether a macro path is `name` (or `core::name` / `std::name` /
/// `sandblaster::name` / `sandblaster::prelude::name`).
pub fn is_macro(p: &syn::Path, name: &str) -> bool {
    let segs: Vec<String> = p.segments.iter().map(|s| s.ident.to_string()).collect();
    match segs.as_slice() {
        [n] => n == name,
        [c, n] => n == name && (c == "core" || c == "std" || c == "sandblaster"),
        [r, pr, n] => n == name && r == "sandblaster" && pr == "prelude",
        _ => false,
    }
}

fn const_int(e: &syn::Expr) -> Option<i128> {
    match e {
        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(l), .. }) => l.base10_parse::<i128>().ok(),
        syn::Expr::Block(b) if b.block.stmts.len() == 1 => match &b.block.stmts[0] {
            syn::Stmt::Expr(e, None) => const_int(e),
            _ => None,
        },
        syn::Expr::Paren(p) => const_int(&p.expr),
        _ => None,
    }
}

/// An intrinsic immediate in legacy argument position: an unsuffixed or
/// `i32`-suffixed integer literal.
fn imm_literal(e: &syn::Expr) -> Option<i64> {
    match strip_parens(e) {
        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(l), .. }) if l.suffix().is_empty() || l.suffix() == "i32" => l.base10_parse::<i64>().ok(),
        _ => None,
    }
}

fn array_slice_compatible(a: &Ty, b: &Ty) -> bool {
    match (a, b) {
        (Ty::Array(x, _), Ty::Slice(y)) | (Ty::Slice(x), Ty::Array(y, _)) => x == y,
        _ => false,
    }
}

trait MemberStr {
    fn to_token_stream_string(&self) -> String;
}

impl MemberStr for syn::Member {
    fn to_token_stream_string(&self) -> String {
        match self {
            syn::Member::Named(n) => n.to_string(),
            syn::Member::Unnamed(i) => i.index.to_string(),
        }
    }
}
