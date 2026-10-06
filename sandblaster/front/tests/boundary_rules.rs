//! The verified boundary (DESIGN.md §3.1, §15.5, §15.8).
//!
//! Live rules (S0): a `pub` function reachable from the DSL root has no
//! `Irr` binder in its kernel type (no `requires` — not even `true` —, no
//! `#[decreases(.., max = C)]` depth hypothesis, no `#[ghost]` parameter),
//! no `#[refines(.., domain = P)]`, and — when generic — no type parameter
//! inside a slice element type (host code instantiates exported generics,
//! where the zero-sized-type rule of §3.2 is never checked). `#[refines]`
//! on a type and `sandblaster::critical` are errors.
//!
//! The §15.8 gate ([`validate::spec15_gate`]: the boundary is exactly the
//! root's `pub use` list of items, boundary functions are monomorphic) runs
//! in the crate path (`driver::gates`), not in `validate` (which the stage
//! tests also call); it is tested here directly.

mod common;

use common::*;
use sandblaster_front::diag::{DiagKind as K, Diagnostics, Severity};
use sandblaster_front::driver::Checked;
use sandblaster_front::validate;

fn gate(c: &Checked) -> Vec<String> {
    let mut d = Diagnostics::new();
    validate::spec15_gate(c.krate.as_ref().expect("a crate"), &mut d);
    assert!(d.list.iter().all(|x| x.severity == Severity::Error && x.kind == K::Boundary));
    d.list.iter().map(|x| x.msg.clone()).collect()
}

#[track_caller]
fn ok_files(files: &[(&str, &str)]) -> Checked {
    let c = check_files(files);
    assert!(c.ok(), "expected no errors, got:\n{}", c.render());
    c
}

const DEPTH: &str = "#[decreases(n, max = 8)]\npub fn depth(n: u32) -> u32 { if n == 0 { 0 } else { depth(n - 1) + 1 } }\n";

// ---------------------------------------------------------------- must reject (live)

#[test]
fn pub_depth_bounded_fn_reachable_from_root() {
    // R4-C1: the hidden `h_depth` precondition used to pass the boundary
    // check (only `has_requires` was checked) and be emitted as a safe fn
    rejects(DEPTH, K::Boundary, "public function `depth` with a recursion depth bound (`#[decreases(.., max = 8)]`) is reachable");
    // re-exported from a private module
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}mod m;\npub use m::depth;\n")), ("r/m.rs", &format!("use sandblaster::prelude::*;\n{DEPTH}"))]);
    rejects_checked(&c, K::Boundary, "`depth` with a recursion depth bound");
    // through a `pub mod` (reachable today)
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}pub mod m;\n")), ("r/m.rs", &format!("use sandblaster::prelude::*;\n{DEPTH}"))]);
    rejects_checked(&c, K::Boundary, "`depth` with a recursion depth bound");
    // a pub method of a boundary type
    rejects(
        "#[derive(Clone, Copy)] pub struct S;\nimpl S { #[decreases(n, max = 4)] pub fn d(&self, n: u32) -> u32 { if n == 0 { 0 } else { self.d(n - 1) + 1 } } }\npub fn mk() -> S { S }",
        K::Boundary,
        "`d` with a recursion depth bound",
    );
}

#[test]
fn pub_fn_with_requires() {
    rejects("#[requires(x > 0)]\npub fn f(x: u32) -> u32 { x - 1 }", K::Boundary, "public function `f` with `requires` is reachable from the DSL root");
    // any requires is an `Irr` binder, even `true`
    rejects("#[requires(true)]\npub fn g(x: u32) -> u32 { x }", K::Boundary, "public function `g` with `requires`");
}

#[test]
fn pub_fn_with_ghost_params_or_domain() {
    rejects("#[requires(true)]\nfn inner(x: u8, #[ghost] k: u8) -> u8 { x }\n#[ensures(|r: u8| true)]\npub fn f(x: u8, #[ghost] k: u8) -> u8 { x }", K::Boundary, "public function `f` with `#[ghost]` parameters");
    rejects(
        "#[cfg(sandblaster)] #[spec] fn s(x: u8) -> u8 { x }\n#[refines(s, domain = x < 10)]\npub fn f(x: u8) -> u8 { x }",
        K::Boundary,
        "refines its spec only on a `domain`",
    );
    // internal: fine
    accepts("#[cfg(sandblaster)] #[spec] fn s(x: u8) -> u8 { x }\n#[refines(s, domain = x < 10)]\nfn f(x: u8) -> u8 { x }\npub fn g() -> u8 { f(1) }");
}

#[test]
fn pub_generic_fn_with_slice_of_type_parameter() {
    // R4-C2: `len::<()>` on a host slice longer than ISIZE_MAX
    rejects("pub fn len<T: Copy>(s: &[T]) -> usize { s.len() }", K::Boundary, "public generic function `len` reachable from the DSL root has its type parameter `T` inside a slice element type");
    rejects("pub fn f<T: Copy>(x: Option<(T, &[(u8, T)])>) -> usize { 0 }", K::Boundary, "type parameter `T` inside a slice element type");
    rejects("pub fn f<T: Copy>(x: T) -> usize { let a = [x; 3]; let s: &[T] = &a; s.len() }", K::Boundary, "`T` inside a slice element type");
    // through the fields of a generic type: a pub method of a boundary type
    rejects(
        "#[derive(Clone, Copy)] pub struct W<'a, T: Copy> { s: &'a [T] }\nimpl<'a, T: Copy> W<'a, T> { pub fn n(&self) -> usize { self.s.len() } }\npub fn mk<'a>(s: &'a [u8]) -> W<'a, u8> { W { s } }",
        K::Boundary,
        "public generic function `n`",
    );
}

#[test]
fn param_in_slice_has_no_traversal_budget() {
    // review S0 (R4-C2 bypass): the search used to give up — answering "no
    // type parameter" — after 64 distinct instantiations of user types met
    // before the slice-bearing field
    let fields: String = (1..=70).map(|k| format!("pub g{k}: G<[u8; {k}]>, ")).collect();
    let src = format!(
        "#[derive(Clone, Copy)] pub struct G<X: Copy> {{ pub x: X }}\n\
         #[derive(Clone, Copy)] pub struct W<'a, T: Copy> {{ pub s: &'a [T] }}\n\
         #[derive(Clone, Copy)] pub struct Big<'a, T: Copy> {{ {fields}pub w: W<'a, T> }}\n\
         #[ensures(|r: usize| r > 0)]\nfn helper<T: Copy>(b: Big<'_, T>) -> usize {{ b.w.s.len() + 1 }}\n\
         #[ensures(|r: usize| r > 0)]\npub fn api<T: Copy>(b: Big<'_, T>) -> usize {{ helper(b) }}\n"
    );
    rejects(&src, K::Boundary, "public generic function `api` reachable from the DSL root has its type parameter `T` inside a slice element type");
    // through a chain of generic wrappers, the slice several levels down
    rejects(
        "#[derive(Clone, Copy)] pub struct A<'a, T: Copy> { pub s: &'a [(u8, T)] }\n\
         #[derive(Clone, Copy)] pub struct B<'a, U: Copy> { pub a: Option<A<'a, U>> }\n\
         #[derive(Clone, Copy)] pub struct C<'a, V: Copy> { pub b: (u8, B<'a, V>) }\n\
         pub fn f<Z: Copy>(c: C<'_, Z>) -> u8 { c.b.0 }",
        K::Boundary,
        "type parameter `Z` inside a slice element type",
    );
    // a parameter that never reaches a slice is fine
    accepts(
        "#[derive(Clone, Copy)] pub struct P<'a, T: Copy> { pub t: T, pub s: &'a [u8] }\n\
         pub fn f<T: Copy>(p: P<'_, T>) -> usize { p.s.len() }",
    );
}

#[test]
fn zero_sized_slices_follow_rustc_layout() {
    // review S0: `Option<Void>`, an enum whose other variants are
    // uninhabited, and deep nesting are zero-sized in rustc
    const VOID: &str = "#[derive(Clone, Copy)] pub enum Void {}\n";
    rejects(&format!("{VOID}#[ensures(|r: usize| r > 0)]\npub fn count(s: &[Option<Void>]) -> usize {{ s.len() + 1 }}"), K::ZstSlice, "slices of the zero-sized type `Option<Void>`");
    rejects(&format!("{VOID}#[derive(Clone, Copy)] pub enum E {{ A, B(Void) }}\npub fn count(s: &[E]) -> usize {{ s.len() }}"), K::ZstSlice, "slices of the zero-sized type `E`");
    rejects(&format!("{VOID}#[derive(Clone, Copy)] pub enum E {{ A, B(Void), C([Void; 2], ()) }}\npub fn count(s: &[E]) -> usize {{ s.len() }}"), K::ZstSlice, "zero-sized type `E`");
    rejects(&format!("{VOID}pub fn count(s: &[Void]) -> usize {{ s.len() }}"), K::ZstSlice, "zero-sized type `Void`");
    let deep: String = std::iter::once("#[derive(Clone, Copy)] pub struct Z0;\n".to_string()).chain((1..=80).map(|k| format!("#[derive(Clone, Copy)] pub struct Z{k}(pub Z{});\n", k - 1))).collect();
    rejects(&format!("{deep}pub fn count(s: &[Z80]) -> usize {{ s.len() }}"), K::ZstSlice, "zero-sized type `Z80`");
    // generic instantiation (the DSL-side check of type arguments)
    rejects(
        &format!("{VOID}fn len<T: Copy>(s: &[T]) -> usize {{ s.len() }}\npub fn f(s: &[Option<Void>]) -> usize {{ len(s) }}"),
        K::ZstSlice,
        "type parameter instantiated with zero-sized type `Option<Void>`",
    );
    // inhabited or sized: fine
    accepts(&format!("{VOID}#[derive(Clone, Copy)] pub enum E {{ A, B(u8) }}\npub fn count(s: &[E], t: &[Option<u8>], u: &[Option<()>]) -> usize {{ s.len() + t.len() + u.len() }}"));
    accepts(&format!("{VOID}#[derive(Clone, Copy)] pub struct S {{ pub a: u8, pub v: Option<Void> }}\npub fn count(s: &[S]) -> usize {{ s.len() }}"));
    accepts(&format!("{VOID}#[derive(Clone, Copy)] pub enum F {{ A(u8), B(Void) }}\npub fn count(s: &[F]) -> usize {{ s.len() }}"));
}

#[test]
fn refines_on_a_struct() {
    rejects("#[refines(spec::fe)]\n#[derive(Clone, Copy)] pub struct Fe([u64; 5]);", K::Attribute, "`#[refines]` is not allowed on a struct");
}

#[test]
fn sandblaster_critical() {
    let c = check_files(&[("r/mod.rs", "#![forbid(unsafe_code)]\n#![cfg_attr(sandblaster, sandblaster::critical)]\nuse sandblaster::prelude::*;\npub fn f() {}\n")]);
    rejects_checked(&c, K::Attribute, "`sandblaster::critical` does not exist");
    let c = check_files(&[("r/mod.rs", "#![forbid(unsafe_code)]\n#![sandblaster::critical]\npub fn f() {}\n")]);
    rejects_checked(&c, K::Attribute, "all of §15 (correct by construction) is mandatory");
}

// ---------------------------------------------------------------- must accept (live)

#[test]
fn internal_depth_bounded_helper() {
    accepts(&format!("{}\npub fn api(n: u32) -> u32 {{ if n <= 8 {{ depth(n) }} else {{ 0 }} }}", DEPTH.replace("pub fn", "pub(crate) fn")));
    accepts(&format!("{}\npub fn api(n: u32) -> u32 {{ if n <= 8 {{ depth(n) }} else {{ 0 }} }}", DEPTH.replace("pub fn", "fn")));
    // pub in a private module that is not re-exported: not reachable
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}mod m;\npub fn api(n: u32) -> u32 {{ if n <= 8 {{ m::depth(n) }} else {{ 0 }} }}\n")), ("r/m.rs", &format!("use sandblaster::prelude::*;\n{DEPTH}"))]);
    assert!(c.ok(), "{}", c.render());
}

#[test]
fn generic_fns_without_slices_of_their_parameters() {
    accepts("pub fn pick<T: Copy>(s: &[u8], a: T, b: T) -> T { if s.is_empty() { a } else { b } }");
    // (the shape of the former QMDB port's `codec::exact`)
    accepts("pub fn exact<A: Copy>(got: Option<(A, &[u8])>) -> Option<A> { match got { Some((a, rest)) if rest.is_empty() => Some(a), _ => None } }");
    // generic with `&[T]` but not pub, or pub but not reachable
    accepts("fn len<T: Copy>(s: &[T]) -> usize { s.len() }\npub fn api(s: &[u8]) -> usize { len(s) }");
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}mod m;\npub fn api(s: &[u8]) -> usize {{ m::len(s) }}\n")), ("r/m.rs", "pub fn len<T: Copy>(s: &[T]) -> usize { s.len() }\n")]);
    assert!(c.ok(), "{}", c.render());
}

// ---------------------------------------------------------------- the §15.8 boundary gate, tested directly

#[test]
fn gate_is_not_switched_on_yet() {
    // `validate` does not call the gate: today's layouts still build
    let c = ok_files(&[("r/mod.rs", &format!("{HEADER}pub mod m;\npub fn top() -> u8 {{ 1 }}\n")), ("r/m.rs", "pub fn id<T: Copy>(x: T) -> T { x }\n")]);
    assert_eq!(gate(&c).len(), 3, "{:?}", gate(&c));
}

#[test]
fn gate_boundary_is_the_root_pub_use_list() {
    // `pub mod` at the root
    let c = ok_files(&[("r/mod.rs", &format!("{HEADER}pub mod codec;\n")), ("r/codec.rs", "pub fn f() -> u8 { 1 }\n")]);
    let g = gate(&c);
    assert!(g.iter().any(|m| m.contains("`pub mod codec` is not allowed at the DSL root")), "{g:?}");
    // `pub use` of a module
    let c = ok_files(&[("r/mod.rs", &format!("{HEADER}mod a;\npub use a::b;\n")), ("r/a/mod.rs", "pub mod b;\n"), ("r/a/b.rs", "pub fn f() -> u8 { 1 }\n")]);
    let g = gate(&c);
    assert!(g.iter().any(|m| m.contains("`pub use` of the module `crate::a::b`")), "{g:?}");
    // a `pub` item declared at the root
    let c = ok_files(&[("r/mod.rs", &format!("{HEADER}pub fn top() -> u8 {{ 1 }}\npub const K: u8 = 3;\n"))]);
    let g = gate(&c);
    assert!(g.iter().any(|m| m.contains("`pub` item `top` declared at the DSL root")), "{g:?}");
    assert!(g.iter().any(|m| m.contains("`pub` item `K` declared at the DSL root")), "{g:?}");
    // boundary functions are monomorphic
    let c = ok_files(&[("r/mod.rs", &format!("{HEADER}mod m;\npub use m::id;\n")), ("r/m.rs", "pub fn id<T: Copy>(x: T) -> T { x }\n")]);
    let g = gate(&c);
    assert!(g.iter().any(|m| m.contains("boundary function `id` is generic")), "{g:?}");
    // and so are pub methods of boundary types
    let c = ok_files(&[
        ("r/mod.rs", &format!("{HEADER}mod m;\npub use m::{{mk, W}};\n")),
        ("r/m.rs", "#[derive(Clone, Copy)] pub struct W<T: Copy> { x: T }\nimpl<T: Copy> W<T> { pub fn get(self) -> T { self.x } }\npub fn mk(x: u8) -> W<u8> { W { x } }\n"),
    ]);
    let g = gate(&c);
    assert!(g.iter().any(|m| m.contains("boundary function `get` is generic")), "{g:?}");
}

#[test]
fn gate_accepts_a_pub_use_boundary() {
    let c = ok_files(&[
        ("r/mod.rs", &format!("{HEADER}mod index;\nmod verifier;\n#[cfg(sandblaster)] #[path = \"LAWS.rs\"] mod laws;\npub use index::Location;\npub use verifier::{{verify, Digest}};\n")),
        ("r/index.rs", "#[derive(Clone, Copy, PartialEq, Eq)] pub struct Location(u64);\nimpl Location { pub fn get(self) -> u64 { self.0 } }\n"),
        ("r/verifier.rs", "pub type Digest = [u8; 32];\npub fn verify(root: &Digest, loc: super::index::Location) -> bool { loc.get() < 3 && root[0] == 0 }\npub fn helper() -> u8 { 1 }\n"),
        ("r/LAWS.rs", ""),
    ]);
    assert_eq!(gate(&c), Vec::<String>::new());
}

// (the gate on the three verified roots, and a `pub mod` at one of them:
// `tests/verified_roots.rs`)

#[test]
fn gate_types_reaching_the_boundary_are_in_the_pub_use_list() {
    // `Token` is returned by the exported `make` but not exported: host code
    // holds its values and calls `leak`, so the boundary would be more than
    // the `pub use` list
    let files = |root: &str| {
        ok_files(&[
            ("r/mod.rs", &format!("{HEADER}mod m;\n{root}\n")),
            ("r/m.rs", "#[derive(Clone, Copy)] pub struct Token(u32);\nimpl Token { pub fn leak(&self) -> u32 { self.0 ^ 7u32 } }\npub fn make(x: u8) -> Token { Token(x as u32) }\n"),
        ])
    };
    let c = files("pub use m::make;");
    let g = gate(&c);
    assert!(g.iter().any(|m| m.contains("type `crate::m::Token` reaches the boundary through `crate::m::make` but is not in the root's `pub use` list")), "{g:?}");
    // its `pub` methods are exported functions all the same (the law
    // vocabulary, and determinacy)
    let k = c.krate.as_ref().unwrap();
    let ex: Vec<String> = validate::exported_functions(k).into_iter().map(|i| k.item(i).path.to_string()).collect();
    assert!(ex.iter().any(|x| x == "crate::m::Token::leak"), "{ex:?}");
    let all: Vec<String> = validate::boundary_functions(k).into_iter().map(|i| k.item(i).path.to_string()).collect();
    assert!(all.iter().any(|x| x == "crate::m::Token::leak"), "{all:?}");
    // exported: accepted
    let c = files("pub use m::{make, Token};");
    assert_eq!(gate(&c), Vec::<String>::new());
    // a `pub mod`'s functions are boundary functions (host-callable), not
    // the law vocabulary
    let c = ok_files(&[("r/mod.rs", &format!("{HEADER}pub mod m;\n")), ("r/m.rs", "pub fn f(x: u32) -> u32 { x }\n")]);
    let k = c.krate.as_ref().unwrap();
    assert!(validate::boundary_functions(k).iter().any(|i| k.item(*i).path.to_string() == "crate::m::f"));
    assert!(!validate::exported_functions(k).iter().any(|i| k.item(*i).path.to_string() == "crate::m::f"));
}
