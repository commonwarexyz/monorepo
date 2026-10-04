//! Name resolution tests (DESIGN.md §3.1 `use`, §3.6 name resolution).

mod common;

use common::*;
use sandblaster_front::diag::DiagKind as K;
use sandblaster_front::hir::*;

fn body(k: &Crate, path: &str) -> Expr {
    match &k.fn_def(k.find(path).unwrap_or_else(|| panic!("no {path}"))).unwrap().body {
        FnBody::Exec(e) => e.clone(),
        other => panic!("{other:?}"),
    }
}

fn tail(e: &Expr) -> &Expr {
    match &e.kind {
        ExprKind::Block(b) => b.tail.as_deref().expect("tail"),
        _ => e,
    }
}

#[test]
fn use_renames_groups_self_super() {
    let c = check_files(&[
        ("r/mod.rs", &format!("{HEADER}mod a;\nmod b;\nuse a::{{self, inner::{{deep as d, K}}}};\npub fn f() -> u32 {{ d() + a::g() + K + b::h() }}\n")),
        ("r/a/mod.rs", "pub mod inner;\npub fn g() -> u32 { self::inner::deep() }\n"),
        ("r/a/inner.rs", "pub const K: u32 = 2;\npub fn deep() -> u32 { super::super::b::h() }\n"),
        ("r/b.rs", "pub fn h() -> u32 { crate::a::inner::K }\n"),
    ]);
    assert!(c.ok(), "{}", c.render());
}

#[test]
fn unresolved_and_duplicate_names() {
    rejects("use crate::nope::x;", K::Resolve, "cannot find `nope`");
    rejects("fn f() {}\nfn f() {}", K::Resolve, "defined multiple times");
    rejects("fn f() -> u32 { g() }", K::Resolve, "cannot find `g`");
    rejects("fn f(x: Nope) {}", K::Resolve, "cannot find type `Nope`");
}

#[test]
fn globs_only_from_allowed_modules() {
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}mod m;\nuse m::*;\n")), ("r/m.rs", "pub fn f() {}\n")]);
    rejects_checked(&c, K::Resolve, "glob imports are only allowed");
    accepts("use core::arch::aarch64::*;\n#[target_feature(enable = \"neon\")]\nfn f(a: uint8x16_t) -> uint8x16_t { vrev32q_u8(a) }");
}

#[test]
fn locals_shadow_items_in_value_namespace() {
    let c = accepts("fn g() -> u32 { 1 }\nfn f() -> u32 { let g: u32 = 5; g }");
    let k = c.krate.unwrap();
    assert!(matches!(tail(&body(&k, "crate::f")).kind, ExprKind::Local(_)));
    rejects("fn g() -> u32 { 1 }\nfn f() -> u32 { let g: u32 = 5; g() }", K::Closure, "cannot call a local");
}

#[test]
fn shadowing_in_nested_scopes() {
    let c = accepts("fn f(x: u32) -> u32 { let x = x + 1; let y = { let x = 7u32; x }; x + y }");
    let k = c.krate.unwrap();
    let f = k.fn_def(k.find("crate::f").unwrap()).unwrap();
    assert_eq!(f.locals.iter().filter(|l| l.name == "x").count(), 3);
}

#[test]
fn associated_functions_variants_and_self() {
    let c = accepts(
        "#[derive(Clone, Copy)] pub struct P { x: u32 }\n\
         impl P { pub fn new(x: u32) -> Self { Self { x } } pub fn get(self) -> u32 { self.x } fn twice(&self) -> u32 { Self::new(self.x).get() * 2 } }\n\
         #[derive(Clone, Copy)] pub enum E { A, B(u32) }\n\
         impl E { fn val(&self) -> u32 { match self { Self::A => 0, E::B(v) => *v } } }\n\
         fn f() -> u32 { P::new(3).twice() + E::B(4).val() + E::A.val() }",
    );
    let k = c.krate.unwrap();
    let e = tail(&body(&k, "crate::f")).clone();
    let ExprKind::Binary(BinOp::Add, lhs, _) = &e.kind else { panic!("{e:?}") };
    let ExprKind::Binary(BinOp::Add, a, _) = &lhs.kind else { panic!() };
    let ExprKind::Call { callee: Callee::Item(id, _), args } = &a.kind else { panic!("{a:?}") };
    assert_eq!(k.item(*id).path.to_string(), "crate::P::twice");
    // receiver auto-ref: `P::new(3)` is a value, `twice` takes `&self`
    assert!(matches!(args[0].kind, ExprKind::Coerce(Coercion::AutoRef, _)));
}

#[test]
fn prelude_option_and_primitive_assoc() {
    let c = accepts("fn f(x: Option<u32>) -> u32 { let y: Option<u32> = Option::None; let z = Option::<u32>::Some(u32::MAX); let w = core::option::Option::Some(1u32); x.unwrap_or(u32::from_be_bytes([0, 0, 0, 1])) + u32::BITS }");
    let _ = c;
    rejects("fn f() -> u32 { u32::from_str_radix(1) }", K::Resolve, "not in the method whitelist");
}

#[test]
fn arch_helpers_and_intrinsics_resolve_against_target_table() {
    let c = accepts(
        "use core::arch::aarch64::{uint32x4_t, vaddq_u32, vgetq_lane_u32};\n\
         use sandblaster::arch::aarch64 as arch;\n\
         #[target_feature(enable = \"neon\")]\n\
         fn f(a: &[u32; 4]) -> u32 { let v = arch::load_u32x4(a); vgetq_lane_u32::<2>(vaddq_u32(v, v)) }",
    );
    let k = c.krate.unwrap();
    let f = k.fn_def(k.find("crate::f").unwrap()).unwrap();
    assert_eq!(f.feature_set, vec!["neon".to_string()]);
    // an aarch64 intrinsic outside the library (SM4; the SHA-512 ones such
    // as `vsha512hq_u64` joined it with the SHA3/SHA512 models)
    let c = rejects("use core::arch::aarch64::vsm4eq_u32;", K::Resolve, "unresolved import");
    assert!(c.render().contains("only intrinsics of sandblaster's target library"));
    rejects("use sandblaster::arch::aarch64::load_u8x32;", K::Resolve, "unresolved import");
}

#[test]
fn reexports_and_privacy() {
    let c = check_files(&[
        ("r/mod.rs", &format!("{HEADER}mod a;\npub use a::api;\nfn g() -> u32 {{ a::api() + a::inner_value() }}\n")),
        ("r/a.rs", "pub fn api() -> u32 { 1 }\npub(crate) fn inner_value() -> u32 { 2 }\n"),
    ]);
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.unwrap();
    assert_eq!(k.boundary.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), vec!["api"]);
    // a private `use` is not visible from outside its module
    let c = check_files(&[
        ("r/mod.rs", &format!("{HEADER}mod a;\nmod b;\nfn g() -> u32 {{ b::api() }}\n")),
        ("r/a.rs", "pub fn api() -> u32 { 1 }\n"),
        ("r/b.rs", "use super::a::api;\n"),
    ]);
    rejects_checked(&c, K::Privacy, "`api` is private");
}

#[test]
fn ghost_prelude_names_only_in_ghost_code() {
    accepts("#[cfg(sandblaster)] #[spec] fn p(x: u32) -> Prop { forall(|y: u32| implies(y < x, y + 1 <= x)) }");
    rejects("fn f(x: u32) -> bool { forall(|y: u32| y < x) }", K::Ghost, "only allowed in ghost code");
}

#[test]
fn items_named_like_primitives_rejected() {
    rejects("#[derive(Clone, Copy)] struct u32;", K::Resolve, "shadows a primitive");
}

#[test]
fn cfg_target_predicates() {
    // an aarch64-only function and its x86 twin with the same name
    let body = "#[cfg(target_arch = \"aarch64\")] fn hw() -> u32 { 1 }\n#[cfg(target_arch = \"x86_64\")] fn hw() -> u32 { 2 }\npub fn f() -> u32 { hw() }\n";
    assert!(check(body).ok());
    assert!(check_x86(body).ok());
    rejects("#[cfg(test)] fn t() {}", K::Attribute, "unsupported cfg predicate `test`");
    rejects("#[cfg(not(sandblaster))] fn t() {}", K::Attribute, "`sandblaster` may only appear");
    rejects("#[cfg(feature = \"std\")] fn t() {}", K::Attribute, "unsupported cfg key `feature`");
}
