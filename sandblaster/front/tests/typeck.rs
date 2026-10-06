//! Surface typing tests (DESIGN.md §3.6), including the rustc divergence
//! examples of `docs/review-1.md` (rust-fidelity lens).

mod common;

use common::*;
use sandblaster_front::diag::DiagKind as K;
use sandblaster_front::hir::*;
use sandblaster_front::visit::{self, Visitor};

fn fn_def(k: &Crate, path: &str) -> FnDef {
    k.fn_def(k.find(path).unwrap_or_else(|| panic!("no {path}"))).unwrap().clone()
}

/// Collects every expression of a function.
fn exprs(f: &FnDef) -> Vec<Expr> {
    struct C(Vec<Expr>);
    impl Visitor for C {
        fn expr(&mut self, e: &Expr) {
            self.0.push(e.clone());
            visit::walk_expr(self, e);
        }
    }
    let mut c = C(vec![]);
    visit::walk_fn(&mut c, f);
    c.0
}

fn pats(f: &FnDef) -> Vec<Pat> {
    struct C(Vec<Pat>);
    impl Visitor for C {
        fn pat(&mut self, p: &Pat) {
            self.0.push(p.clone());
            visit::walk_pat(self, p);
        }
    }
    let mut c = C(vec![]);
    visit::walk_fn(&mut c, f);
    c.0
}

// ------------------------------------------------------------ rustc divergences

#[test]
fn divergence_cast_operand_is_not_a_typing_context() {
    // rustc: `(1 << k) as u64` is an i32 shift (widen(31) = 0xffffffff80000000)
    rejects("fn widen(k: u32) -> u64 { (1 << k) as u64 }", K::Literal, "operand of `as`");
    // a bare literal takes the target type, exactly like rustc
    let c = accepts("fn f() -> u64 { 255 as u64 }");
    let f = fn_def(c.krate.as_ref().unwrap(), "crate::f");
    assert!(exprs(&f).iter().any(|e| matches!(e.kind, ExprKind::Lit(Lit::Int(255))) && e.ty == Ty::Uint(UintTy::U64)));
}

#[test]
fn divergence_typed_context_literal_shift() {
    // `let y: u64 = 1 << k` types `1` as u64 in both rustc and the model
    let c = accepts("fn f(k: u32) -> u64 { let y: u64 = 1 << k; y }");
    let f = fn_def(c.krate.as_ref().unwrap(), "crate::f");
    assert!(exprs(&f).iter().any(|e| matches!(e.kind, ExprKind::Lit(Lit::Int(1))) && e.ty == Ty::Uint(UintTy::U64)));
}

#[test]
fn divergence_shift_rhs() {
    rejects("fn s0(x: u32) -> u32 { (x >> 2) ^ (x >> 13) }", K::Literal, "right operand of a shift");
    accepts("fn s0(x: u32) -> u32 { x.rotate_right(2) ^ x.rotate_right(13) ^ (x >> 10u32) }");
}

#[test]
fn divergence_allow_lints_that_hide_rustc_errors() {
    rejects("#[allow(overflowing_literals)] fn f() -> u8 { 0 }", K::Attribute, "overflowing_literals");
    rejects("#[allow(arithmetic_overflow)] fn f() -> u8 { 0 }", K::Attribute, "arithmetic_overflow");
}

#[test]
fn divergence_unimported_const_pattern() {
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}mod m;\nfn h(x: u32) -> u32 {{ match x {{ LIMIT => 0, _ => 1 }} }}\n")), ("r/m.rs", "pub const LIMIT: u32 = 7;\n")]);
    rejects_checked(&c, K::IdentPattern, "LIMIT");
}

#[test]
fn divergence_ghost_const_pattern() {
    rejects("#[cfg(sandblaster)] const K: u32 = 3;\nfn f(x: u32) -> u32 { match x { K => 0, _ => 1 } }", K::IdentPattern, "`K`");
}

#[test]
fn divergence_user_none_expression_resolves_like_rustc() {
    let c = check_files(&[
        ("r/mod.rs", &format!("{HEADER}mod codec;\nuse codec::Parsed::None;\nfn f() -> codec::Parsed {{ None }}\n")),
        ("r/codec.rs", "#[derive(Clone, Copy)] pub enum Parsed { None, Some(u32) }\n"),
    ]);
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let f = fn_def(k, "crate::f");
    assert!(exprs(&f).iter().any(|e| matches!(e.kind, ExprKind::Adt { ctor: Ctor::Variant(_, 0), .. })), "user import shadows the prelude `None`");
}

#[test]
fn divergence_or_pattern_with_guard_is_kept_for_expansion() {
    let c = accepts("pub fn pick(a: Option<u32>, b: Option<u32>) -> u32 { match (a, b) { (Some(x), _) | (_, Some(x)) if x > 5 => x, _ => 0 } }");
    let f = fn_def(c.krate.as_ref().unwrap(), "crate::pick");
    let m = exprs(&f).into_iter().find(|e| matches!(e.kind, ExprKind::Match { .. })).unwrap();
    let ExprKind::Match { arms, .. } = &m.kind else { unreachable!() };
    assert!(matches!(arms[0].pat.kind, PatKind::Or(_)) && arms[0].guard.is_some());
    let expanded = sandblaster_front::elab::pat::expand_or_arms(arms);
    assert_eq!(expanded.len(), 3);
    assert!(expanded[0].guard.is_some() && expanded[1].guard.is_some());
}

#[test]
fn divergence_zst_slice_exploit() {
    rejects("pub fn f(s: &[()], t: [u8; 4]) -> u8 { let n = s.len() + 1; if n > 3 { 0 } else { t[s.len()] } }", K::ZstSlice, "zero-sized");
}

#[test]
fn divergence_unbounded_non_tail_recursion() {
    rejects("pub fn check(s: &[u8]) -> u8 { match s { [] => 0, [h, t @ ..] => *h ^ check(t) } }", K::Recursion, "depth bound");
}

// ------------------------------------------------------------ literal typing

#[test]
fn literal_takes_type_from_other_operand() {
    let c = accepts("fn f(x: u16) -> bool { 1 + x > 2 }");
    let f = fn_def(c.krate.as_ref().unwrap(), "crate::f");
    for e in exprs(&f) {
        if let ExprKind::Lit(Lit::Int(_)) = e.kind {
            assert_eq!(e.ty, Ty::Uint(UintTy::U16));
        }
    }
    rejects("fn f() -> bool { 1 < 2 }", K::Literal, "cannot infer");
}

#[test]
fn if_and_match_branches() {
    accepts("fn f(c: bool) -> u32 { let x = if c { 1 } else { 2u32 }; let y = match c { true => 3, false => x }; x + y }");
    rejects("fn f(c: bool) -> u32 { if c { 1u32 } }", K::Type, "`if` without `else`");
    rejects("fn f(c: bool) -> u32 { if c { 1u32 } else { 2u8 } }", K::Type, "mismatched types");
}

// ------------------------------------------------------------ coercions

#[test]
fn unsizing_and_autoref_are_explicit() {
    let c = accepts("fn len(s: &[u8]) -> usize { s.len() }\nfn f(a: [u8; 4]) -> usize { len(&a) + a.len() + a.as_slice().len() }");
    let f = fn_def(c.krate.as_ref().unwrap(), "crate::f");
    let es = exprs(&f);
    assert!(es.iter().any(|e| matches!(&e.kind, ExprKind::Coerce(Coercion::Unsize, inner) if matches!(inner.kind, ExprKind::Ref(_)))), "explicit unsize of `&a`");
    assert!(es.iter().any(|e| matches!(&e.kind, ExprKind::Coerce(Coercion::Unsize, inner) if matches!(inner.kind, ExprKind::Coerce(Coercion::AutoRef, _)))), "a.len(): autoref + unsize");
}

#[test]
fn reference_operands() {
    accepts("fn f(s: &[u8]) -> u8 { match s.first() { Some(h) => *h + 1, None => 0 } }");
    accepts("fn f(s: &[u8]) -> u8 { match s.first() { Some(h) => h ^ 1, None => 0 } }");
    rejects("fn f(s: &[u8]) -> bool { match s.first() { Some(h) => h == 0, None => false } }", K::Type, "mismatched types");
    accepts("fn f(a: &u32, b: &u32) -> bool { a == b && *a < *b }");
}

#[test]
fn deref_coercion_of_double_references() {
    accepts("fn g(x: &u32) -> u32 { *x }\nfn f(x: &u32) -> u32 { let y = &x; g(y) }");
}

#[test]
fn methods_whitelist_and_receivers() {
    accepts(
        "fn f(x: u32, y: u64, s: &[u8], o: Option<u8>) -> u64 {\n\
         let a = x.wrapping_add(1).rotate_left(3).count_ones() + x.leading_zeros() + x.min(4).max(1);\n\
         let b = y.saturating_sub(2).abs_diff(9).div_ceil(2);\n\
         let c = (s.len() as u64) + (s.is_empty() as u64) + (o.is_some() as u64) + (o.unwrap_or(0) as u64);\n\
         let (d, e) = s.split_at(0);\n\
         let bytes = y.to_be_bytes();\n\
         (a as u64) + b + c + (d.len() as u64) + (e.len() as u64) + (bytes[0] as u64) + u64::from_le_bytes(bytes)\n}",
    );
    accepts("fn f(s: &[u8]) -> u8 { match s.split_first_chunk::<4>() { Some((h, t)) => h[0] ^ (t.len() as u8), None => 0 } }");
    rejects("fn f(s: &[u8]) -> u8 { match s.split_first_chunk() { Some((h, t)) => h[0], None => 0 } }", K::Type, "turbofish");
    rejects("fn f(s: &[u8]) -> usize { s.as_chunks::<0>().1.len() }", K::Type, "N > 0");
    rejects("fn f(x: u32) -> u32 { x.reverse_bits() }", K::Resolve, "no method `reverse_bits`");
}

// ------------------------------------------------------------ patterns

#[test]
fn default_binding_modes_are_explicit() {
    let c = accepts("fn f(s: &[u8]) -> u8 { match s { [h, t @ ..] => *h ^ (t.len() as u8), [] => 0 } }");
    let f = fn_def(c.krate.as_ref().unwrap(), "crate::f");
    let ps = pats(&f);
    assert!(ps.iter().any(|p| matches!(&p.kind, PatKind::Deref { implicit: true, .. })));
    let h = f.locals.iter().find(|l| l.name == "h").unwrap();
    assert_eq!(h.ty, Ty::reference(Ty::u8()));
    let t = f.locals.iter().find(|l| l.name == "t").unwrap();
    assert_eq!(t.ty, Ty::slice_ref(Ty::u8()));
    assert!(ps.iter().any(|p| matches!(&p.kind, PatKind::Binding { mode: BindingMode::ByRef, .. })));
}

#[test]
fn edition_2024_binding_mode_rules() {
    rejects("fn f(s: &(u8, u8)) -> u8 { let (mut a, b) = s; 0 }", K::Type, "`mut` bindings are not allowed under a by-reference");
    rejects("fn f(s: &(u8, u8)) -> u8 { let (&a, b) = s; a }", K::Type, "reference patterns are not allowed");
    rejects("fn f(s: &(u8, u8)) -> u8 { let &(ref a, b) = s; b }", K::Unsupported, "`ref` bindings");
    accepts("fn f(s: &(u8, u8)) -> u8 { let &(a, b) = s; a ^ b }");
}

#[test]
fn slice_and_array_patterns() {
    accepts("fn f(s: &[u8]) -> u8 { match s { [] => 0, [a] => *a, [a, b] => a ^ b, [first, .., last] => first ^ last } }");
    accepts("fn f(s: &[u8]) -> u8 { match s { [init @ .., last] => *last ^ (init.len() as u8), [] => 0 } }");
    accepts("fn f(a: [u8; 4]) -> u8 { let [x, y, rest @ ..] = a; x ^ y ^ rest[1] }");
    rejects("fn f(a: [u8; 4]) -> u8 { let [x, y] = a; x }", K::Type, "pattern requires 2 element(s) but the array has 4");
}

#[test]
fn or_patterns_bind_consistently() {
    rejects("fn f(x: (u8, u8)) -> u8 { match x { (a, 0) | (0, b) => 1, _ => 0 } }", K::Type, "not bound in all alternatives");
    accepts("fn f(x: (u8, u8)) -> u8 { match x { (a, 0) | (0, a) => a, _ => 0 } }");
}

#[test]
fn let_else_must_diverge() {
    rejects("fn f(o: Option<u8>) -> u8 { let Some(v) = o else { 0 }; v }", K::Type, "must diverge");
    accepts("fn f(o: Option<u8>) -> u8 { let Some(v) = o else { return 0; }; v }");
    accepts("fn f(o: Option<u8>) -> u8 { let Some(v) = o else { unreachable!() }; v }");
}

// ------------------------------------------------------------ structs, generics

#[test]
fn struct_literals_and_update() {
    accepts("#[derive(Clone, Copy, PartialEq)] struct S { a: u32, b: u8 }\nfn f(s: S) -> S { let t = S { a: 1, ..s }; if t == s { S { b: 2, a: 3 } } else { t } }");
    rejects("#[derive(Clone, Copy)] struct S { a: u32, b: u8 }\nfn f() -> S { S { a: 1 } }", K::Type, "missing field(s) `b`");
    rejects("#[derive(Clone, Copy)] struct S { a: u32 }\nfn f(x: S, y: S) -> bool { x == y }", K::Type, "`==` is not available");
}

#[test]
fn generic_inference() {
    let c = accepts("#[derive(Clone, Copy)] struct W<T: Copy> { v: T }\nfn id<T: Copy>(x: T) -> T { x }\nfn f(a: u32) -> u32 { let w = W { v: a }; let x: u8 = id(3); id(w).v + (x as u32) + id::<u32>(1) }");
    let f = fn_def(c.krate.as_ref().unwrap(), "crate::f");
    assert!(exprs(&f).iter().any(|e| matches!(&e.kind, ExprKind::Call { callee: Callee::Item(_, targs), .. } if targs == &vec![Ty::u8()])));
    rejects("fn none<T: Copy>() -> Option<T> { None }\nfn f() -> u32 { let x = none(); 0 }", K::Type, "type annotations needed");
}

#[test]
fn ghost_propositions() {
    let c = accepts(
        "#[cfg(sandblaster)] #[spec] fn ok(s: &[u8]) -> Prop { s.len() >= 1 && s[0] == 3 }\n\
         #[requires(off <= s.len() && s.len() - off >= 4)]\n\
         #[ensures(|r: u8| r == s[off])]\n\
         fn f(s: &[u8], off: usize) -> u8 { s[off] }",
    );
    let f = fn_def(c.krate.as_ref().unwrap(), "crate::f");
    assert!(matches!(f.requires[0].kind, ExprKind::PropAnd(..)));
    assert!(matches!(f.ensures.as_ref().unwrap().prop.kind, ExprKind::PropEq(..)));
    rejects("#[ensures(|r: u16| r == 1)]\nfn f() -> u8 { 1 }", K::Contract, "binder has type `u16`");
}

#[test]
fn scripts() {
    let c = accepts(
        "#[cfg(sandblaster)] #[lemma] fn add_comm(a: u32, b: u32) { requires(a <= 10 && b <= 10); ensures(a + b == b + a); }\n\
         #[cfg(sandblaster)] #[lemma] fn uses(x: u32) {\n\
           requires(x <= 3);\n\
           ensures(x + 1 == 1 + x);\n\
           let h = add_comm(x, 1);\n\
           assert(x + 1 <= 4, { add_comm(1, x); });\n\
           proof! { cases(x in 0..=3) { assert(x <= 3); } }\n\
           cases(x, 0u32..4, { bv(); });\n\
           match x { 0 => { show(); } _ => { rewrite(h); } }\n\
           if x == 0 { witness(x); } else { unfold(add_comm); }\n\
           exact(h);\n\
         }",
    );
    let k = c.krate.as_ref().unwrap();
    let f = fn_def(k, "crate::uses");
    let FnBody::Script(ss) = &f.body else { panic!() };
    assert!(matches!(ss[0].kind, ScriptKind::Apply { binder: Some(_), .. }));
    assert!(matches!(ss[2].kind, ScriptKind::Cases { inclusive: true, .. }));
    assert_eq!(f.requires.len(), 1);
    rejects("#[cfg(sandblaster)] #[lemma] fn l(x: u32) { invariant(x > 0); }", K::Script, "only allowed in a `proof!` block at the start of a loop body");
    rejects("#[cfg(sandblaster)] #[lemma] fn l(x: u32) { frobnicate(x); }", K::Resolve, "cannot find lemma `frobnicate`");
}

#[test]
fn loop_info() {
    let c = accepts("fn f(s: &[u32], k: u32) -> u32 { let mut acc: u32 = 0; let mut unused: u32 = 0; for i in 0..s.len() { proof! { invariant(acc <= u32::MAX); } let t = s[i] ^ k; acc = acc.wrapping_add(t); } acc }");
    let f = fn_def(c.krate.as_ref().unwrap(), "crate::f");
    let l = exprs(&f).into_iter().find_map(|e| match e.kind {
        ExprKind::Loop(l) => Some(l),
        _ => None,
    }).unwrap();
    let names = |v: &[LocalId]| v.iter().map(|l| f.local(*l).name.clone()).collect::<Vec<_>>();
    assert_eq!(names(&l.info.mutated), vec!["acc"]);
    assert_eq!(names(&l.info.read), vec!["s", "k"]);
    assert_eq!(l.info.invariants.len(), 1);
    assert_eq!(l.info.index, 0);
}
