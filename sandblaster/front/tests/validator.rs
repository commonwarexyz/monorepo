//! Validator corpus: for every rejection of DESIGN.md §3 (and the global
//! rules of `validate`), a negative case with the expected diagnostic kind
//! and message, and a positive case showing the allowed form.

mod common;

use common::*;
use sandblaster_front::diag::DiagKind as K;

// ---------------------------------------------------------------- traits

#[test]
fn traits_rejected() {
    rejects("trait T { fn f(&self); }", K::Trait, "traits are not supported");
    rejects("#[derive(Clone, Copy)] struct S; impl Default for S { fn default() -> S { S } }", K::Trait, "trait impls are not supported");
    rejects("fn f(x: &dyn Fn()) {}", K::Trait, "`dyn Trait`");
    rejects("fn f(x: impl Copy) {}", K::Trait, "`impl Trait`");
    rejects("fn f<T: Ord + Copy>(x: T) -> T { x }", K::Trait, "trait bound `Ord`");
    rejects("#[derive(Clone, Copy, Hash)] struct S;", K::Trait, "`#[derive(Hash)]`");
}

#[test]
fn derives_and_copy_bounds_accepted() {
    accepts("#[derive(Clone, Copy, PartialEq, Eq, Debug)] pub struct S { pub a: u32 }\nfn id<T: Copy>(x: T) -> T { x }\nfn g<T>(x: T) -> T where T: Copy { x }");
}

#[test]
fn user_types_must_be_copy() {
    rejects("#[derive(Clone)] struct S;", K::Attribute, "must derive `Clone, Copy`");
    rejects("fn id<T>(x: T) -> T { x }", K::Trait, "must be bounded by `Copy`");
}

// ---------------------------------------------------------------- statics

#[test]
fn statics_rejected() {
    rejects("static X: u32 = 1;", K::Static, "`static` items are not supported");
    accepts("const X: u32 = 1;");
}

// ---------------------------------------------------------------- closures

#[test]
fn closures_and_fn_pointers_rejected() {
    rejects("fn f() -> u32 { let g = |x: u32| x; 0 }", K::Closure, "closures are not supported");
    rejects("fn f(g: fn(u32) -> u32) {}", K::Closure, "function pointers");
    rejects("fn g() -> u32 { 1 }\nfn f() -> u32 { let h = g; 0 }", K::Closure, "functions cannot be used as values");
    rejects("fn f(x: u32) -> u32 { x(1) }", K::Closure, "cannot call a local");
}

// ---------------------------------------------------------------- floats

#[test]
fn floats_rejected() {
    rejects("fn f() { let x: f64 = 1.0; }", K::Float, "floating point type `f64`");
    rejects("const X: u32 = 1.5;", K::Float, "floating point literals");
}

// ---------------------------------------------------------------- signed

#[test]
fn signed_rejected() {
    rejects("fn f() { let x: i32 = 1; }", K::Signed, "signed integer type `i32`");
    rejects("fn f() -> u64 { let x = 5i64; 0 }", K::Signed, "signed literal suffix `i64`");
    rejects("fn f() -> u32 { let x: u32 = -1; x }", K::Signed, "negation is not supported");
    rejects("fn f(x: isize) {}", K::Signed, "`isize`");
}

#[test]
fn signed_immediates_of_intrinsics_accepted() {
    accepts(
        "#[cfg(target_arch = \"aarch64\")] use core::arch::aarch64::*;\n\
         #[target_feature(enable = \"neon\")]\n\
         fn f(a: uint32x4_t) -> uint32x4_t { let b = vshlq_n_u32::<3>(a); vshrq_n_u32::<5i32>(b) }\n\
         #[target_feature(enable = \"neon\")]\n\
         fn g(a: uint32x4_t) -> uint32x4_t { vextq_u32(a, a, 2) }",
    );
    rejects(
        "use core::arch::aarch64::*;\n#[target_feature(enable = \"neon\")]\nfn f(a: uint32x4_t) -> uint32x4_t { vshlq_n_u32::<32>(a) }",
        K::Literal,
        "must be in 0..=31",
    );
}

// ---------------------------------------------------------------- u128

#[test]
fn wide_integers_rejected() {
    rejects("fn f(x: u128) {}", K::Wide, "`u128` is not supported");
    rejects("fn f() -> u64 { let x = 1u128; 0 }", K::Wide, "`u128` literals");
    rejects("fn f(x: i128) {}", K::Wide, "`i128`");
}

// ---------------------------------------------------------------- raw pointers

#[test]
fn raw_pointers_rejected() {
    rejects("fn f(p: *const u8) {}", K::RawPointer, "raw pointers");
    rejects(
        "use core::arch::aarch64::*;\n#[target_feature(enable = \"neon\")]\nfn f(a: &[u8; 16]) -> uint8x16_t { vld1q_u8(a) }",
        K::RawPointer,
        "takes raw pointers",
    );
    // the `sandblaster::arch` load/store helpers were native-dialect
    // authoring glue, removed with the optimizer: refused
    refused_hardware(
        "use core::arch::aarch64::*;\nuse sandblaster::arch::aarch64::{load_u8x16, store_u8x16};\n\
         #[target_feature(enable = \"neon\")]\n\
         fn f(a: &[u8; 16]) -> [u8; 16] { store_u8x16(vrev32q_u8(load_u8x16(a))) }",
    );
}

// ---------------------------------------------------------------- &mut

#[test]
fn mut_refs_rejected() {
    rejects("fn f(x: &mut u32) {}", K::MutRef, "`&mut` types");
    rejects("fn f() { let mut x: u32 = 0; let y = &mut x; }", K::MutRef, "`&mut` is not supported");
    rejects("fn f(s: &[u8]) -> u8 { let a: [u8; 4] = [0; 4]; a.copy_from_slice(s); 0 }", K::MutRef, "must be declared `let mut`");
    rejects("fn f(s: &[u8]) -> () { let mut a: [u8; 4] = [0; 4]; let u = a.copy_from_slice(s); }", K::MutRef, "only allowed as a statement");
    rejects("fn f(x: &u32) { *x = 1; }", K::MutRef, "cannot assign through a reference");
}

#[test]
fn copy_from_slice_statement_accepted() {
    accepts("fn f(s: &[u8; 8]) -> [u8; 12] { let mut a = [0u8; 12]; a[0..8].copy_from_slice(s); a[8..].copy_from_slice(&s[4..]); a }");
    accepts("fn f(s: &[u8]) -> [u8; 4] { let mut a = [0u8; 4]; a.copy_from_slice(&s[0..4]); a }");
}

// ---------------------------------------------------------------- loops

#[test]
fn loop_break_continue_rejected() {
    rejects("fn f() { loop {} }", K::Loop, "`loop` is not supported");
    rejects("fn f() { for i in 0u32..4 { break; } }", K::Loop, "`break` is not supported");
    rejects("fn f() { for i in 0u32..4 { continue; } }", K::Loop, "`continue` is not supported");
    rejects("fn f() { 'a: for i in 0u32..4 { } }", K::Loop, "loop labels");
    rejects("fn f() -> u32 { let x = 'b: { 1u32 }; x }", K::Loop, "labeled blocks");
}

#[test]
fn return_and_try_in_loops_rejected() {
    rejects("fn f(s: &[u32]) -> u32 { for i in 0..s.len() { return 1; } 0 }", K::ControlInLoop, "`return` inside a loop");
    rejects("fn f(s: &[u32]) -> Option<u32> { let mut t: u32 = 0; for i in 0..s.len() { t = s.get(i)?.wrapping_add(t); } Some(t) }", K::ControlInLoop, "`?` inside a loop");
    accepts("fn f(s: &[u32]) -> Option<u32> { let x = s.first()?; if *x > 3 { return None; } Some(*x) }");
}

#[test]
fn loops_accepted() {
    accepts("fn f(n: u32) -> u32 { let mut a: u32 = 0; for i in 0..n { a = a.wrapping_add(i); } for j in 0u8..=255 { a ^= j as u32; } a }");
    accepts("fn f(n: u32) -> u32 { let mut i = n; while i > 0 { proof! { invariant(i <= n); decreases(i); } i -= 1; } i }");
    rejects("fn f(n: u32) -> u32 { let mut i = n; while i > 0 { i -= 1; } i }", K::Contract, "`while` loops need a measure");
    rejects("fn f() { for i in 0..4 { } }", K::Literal, "annotate");
}

// ---------------------------------------------------------------- literals (§3.6)

#[test]
fn unsuffixed_literals_in_cast_operands_rejected() {
    rejects("fn widen(k: u32) -> u64 { (1 << k) as u64 }", K::Literal, "unsuffixed literal in the operand of `as`");
    rejects("fn f(k: u32) -> u64 { (0xFFFF_FFFF >> k) as u64 }", K::Literal, "operand of `as`");
    accepts("fn f(x: u32) -> u64 { (x + 1) as u64 }");
    accepts("fn f() -> u8 { 5 as u8 }");
    accepts("fn f(k: u32) -> u64 { (1u64 << k) as u64 }");
    rejects("fn f() -> u8 { 256 as u8 }", K::Literal, "out of range for `u8`");
}

#[test]
fn unsuffixed_shift_rhs_rejected() {
    rejects("fn f(x: u32) -> u32 { x >> 3 }", K::Literal, "right operand of a shift");
    rejects("fn f(mut x: u32) -> u32 { x <<= 2; x }", K::Literal, "right operand of a shift");
    accepts("fn f(x: u32, n: u32) -> u32 { (x >> 3u32) ^ (x << (n + 1)) }");
    accepts("fn f(k: u32) -> u64 { let y: u64 = 1 << k; y }");
}

#[test]
fn literals_need_types() {
    rejects("fn f() -> u32 { let x = 5; 0 }", K::Literal, "cannot infer the type of this literal");
    rejects("fn f() -> u8 { let x: u8 = 256; x }", K::Literal, "out of range");
    accepts("fn f(x: u32) -> u32 { let y: u32 = 5; x + y * 2 + (3 - 1) }");
}

// ---------------------------------------------------------------- attributes

#[test]
fn allow_whitelist() {
    rejects("#[allow(arithmetic_overflow)] fn f() {}", K::Attribute, "`#[allow(arithmetic_overflow)]` is not allowed");
    rejects("#[allow(overflowing_literals)] fn f() {}", K::Attribute, "`#[allow(overflowing_literals)]`");
    rejects("#[deny(warnings)] fn f() {}", K::Attribute, "not allowed");
    accepts("#[allow(dead_code, unused_variables, non_snake_case, clippy::too_many_arguments)] fn f() {}");
    let c = check_files(&[("r/mod.rs", "#![forbid(unsafe_code)]\n#![allow(unused)]\nfn f() {}\n")]);
    assert!(c.ok(), "{}", c.render());
    let c = check_files(&[("r/mod.rs", "#![forbid(unsafe_code)]\n#![allow(unconditional_recursion)]\nfn f() {}\n")]);
    rejects_checked(&c, K::Attribute, "not allowed");
}

#[test]
fn other_attributes() {
    rejects("#[repr(C)] #[derive(Clone, Copy)] struct S;", K::Attribute, "`#[repr]`");
    rejects("#[inline(never)] fn f() {}", K::Attribute, "only `#[inline]` and `#[inline(always)]`");
    rejects("#[target_feature(enable = \"neon\")] #[inline(always)] fn f() {}", K::Attribute, "`#[inline(always)]` cannot be combined with `#[target_feature]`");
    accepts("#[inline] #[must_use] fn f() -> u32 { 1 }\n#[inline(always)] fn g() {}\n#[target_feature(enable = \"neon\")] #[inline] fn h() {}");
    rejects("#[target_feature(enable = \"avx2\")] fn f() {}", K::Feature, "unknown target feature `avx2`");
}

#[test]
fn forbid_unsafe_code_required_at_root() {
    let c = check_files(&[("r/mod.rs", "fn f() {}\n")]);
    rejects_checked(&c, K::ForbidUnsafe, "must start with `#![forbid(unsafe_code)]`");
    let c = check_files(&[("r/mod.rs", "#![forbid(unsafe_code)]\nfn f() {}\n")]);
    assert!(c.ok());
}

#[test]
fn unsafe_blocks_rejected() {
    rejects("fn f() { unsafe { } }", K::Unsupported, "`unsafe` blocks are not allowed");
    rejects("unsafe fn f() {}", K::Unsupported, "`unsafe fn` is not supported");
}

// ---------------------------------------------------------------- macros

#[test]
fn macros_rejected() {
    rejects("fn f() { assert!(true); }", K::Macro, "macro `assert!` is not supported");
    rejects("macro_rules! m { () => {} }", K::Macro, "item macros");
    rejects("fn f() -> u32 { unreachable!(\"no\") }", K::Macro, "takes no arguments");
    accepts("fn f(x: bool) -> u32 { if x { 1 } else { unreachable!() } }");
}

// ---------------------------------------------------------------- ZST slices (§3.2)

#[test]
fn zero_sized_slices_rejected() {
    rejects("pub fn f(s: &[()], t: [u8; 4]) -> u8 { 0 }", K::ZstSlice, "zero-sized type `()`");
    rejects("#[derive(Clone, Copy)] struct U;\nfn f(s: &[U]) {}", K::ZstSlice, "zero-sized type `U`");
    rejects("fn f(s: &[[u8; 0]]) {}", K::ZstSlice, "zero-sized");
    rejects("#[derive(Clone, Copy)] struct P((), [u32; 0]);\nfn f(s: &[P]) {}", K::ZstSlice, "zero-sized");
    rejects("fn len<T: Copy>(s: &[T]) -> usize { s.len() }\nfn f() -> usize { let a: [(); 3] = [(); 3]; len(&a) }", K::ZstSlice, "instantiated with zero-sized type");
    accepts("fn f(s: &[u8], t: &[Option<()>], u: &[(u8, ())]) {}");
}

// ---------------------------------------------------------------- boundary (§3.1)

#[test]
fn pub_requires_reachable_rejected() {
    rejects("#[requires(x > 0)]\npub fn f(x: u32) -> u32 { x - 1 }", K::Boundary, "public function `f` with `requires` is reachable");
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}mod m;\npub use m::f;\n")), ("r/m.rs", "use sandblaster::prelude::*;\n#[requires(x > 0)]\npub fn f(x: u32) -> u32 { x - 1 }\n")]);
    rejects_checked(&c, K::Boundary, "reachable");
    // private module, not re-exported: not reachable
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}mod m;\npub fn g() -> u32 {{ m::h() }}\n")), ("r/m.rs", "use sandblaster::prelude::*;\n#[requires(x > 0)]\npub fn f(x: u32) -> u32 { x - 1 }\npub fn h() -> u32 { f(2) }\n")]);
    assert!(c.ok(), "{}", c.render());
    accepts("#[requires(x > 0)]\nfn f(x: u32) -> u32 { x - 1 }\npub fn g(x: u32) -> u32 { x }");
    // any `requires` is an `Irr` binder of the kernel type, even `true` (§3.1, §15.5)
    rejects("#[requires(true)]\npub fn g(x: u32) -> u32 { x }", K::Boundary, "with `requires`");
}

#[test]
fn pub_methods_of_boundary_types_are_boundary() {
    rejects(
        "#[derive(Clone, Copy)] pub struct S { a: u32 }\nimpl S { #[requires(self.a > 0)] pub fn dec(&self) -> u32 { self.a - 1 } }\npub fn mk() -> S { S { a: 1 } }",
        K::Boundary,
        "`dec`",
    );
}

// ---------------------------------------------------------------- identifier patterns (§3.3)

#[test]
fn identifier_patterns_naming_consts_rejected() {
    // the rustc-fidelity example: LIMIT is not imported
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}mod m;\nfn h(x: u32) -> u32 {{ match x {{ LIMIT => 0, _ => 1 }} }}\n")), ("r/m.rs", "pub const LIMIT: u32 = 7;\n")]);
    rejects_checked(&c, K::IdentPattern, "identifier pattern `LIMIT`");
    rejects("#[derive(Clone, Copy)] struct Unit;\nfn f(x: u32) -> u32 { let Unit = x; 0 }", K::IdentPattern, "`Unit`");
    rejects("#[derive(Clone, Copy)] enum E { A, B }\nuse E::A;\nfn f(e: E) -> u32 { match e { A => 0, _ => 1 } }", K::IdentPattern, "`A`");
    // ghost constants count too
    rejects("#[cfg(sandblaster)] const K: u32 = 3;\nfn f(x: u32) -> u32 { match x { K => 0, _ => 1 } }", K::IdentPattern, "`K`");
    accepts("#[derive(Clone, Copy)] enum E { A, B }\nfn f(e: E, o: Option<u32>) -> u32 { match (e, o) { (E::A, None) => 0, (E::B, Some(k)) => k, _ => 1 } }");
}

#[test]
fn user_none_shadowing_prelude_none() {
    let c = check_files(&[
        ("r/mod.rs", &format!("{HEADER}mod codec;\nuse codec::Parsed::None;\nfn f(p: codec::Parsed) -> u32 {{ match p {{ None => 0, _ => 1 }} }}\n")),
        ("r/codec.rs", "#[derive(Clone, Copy)] pub enum Parsed { None, Some(u32) }\n"),
    ]);
    rejects_checked(&c, K::IdentPattern, "`None`");
}

// ---------------------------------------------------------------- recursion (§3.7, §5.6)

#[test]
fn mutual_recursion_rejected() {
    rejects("fn a(n: u32) -> u32 { if n == 0 { 0 } else { b(n - 1) } }\nfn b(n: u32) -> u32 { if n == 0 { 1 } else { a(n - 1) } }", K::Recursion, "mutual recursion is not supported");
}

#[test]
fn non_tail_recursion_needs_bound() {
    rejects("pub fn check(s: &[u8]) -> u8 { match s { [] => 0, [h, t @ ..] => *h ^ check(t) } }", K::Recursion, "needs a depth bound");
    rejects("#[decreases(n, max = 100000)]\nfn f(n: u32) -> u32 { if n == 0 { 0 } else { 1 + f(n - 1) } }", K::Recursion, "exceeds 4096");
    rejects("#[decreases(n, max = 65536)]\nfn f(n: u32) -> u32 { if n == 0 { 0 } else { 1 + f(n - 1) } }", K::Recursion, "exceeds 4096");
    let c = accepts("#[decreases(n, max = 64)]\nfn f(n: u32) -> u32 { if n == 0 { 0 } else { 1 + f(n - 1) } }\nfn g(s: &[u8], acc: u8) -> u8 { match s { [] => acc, [h, t @ ..] => g(t, acc ^ *h) } }");
    let k = c.krate.as_ref().unwrap();
    assert_eq!(k.fn_def(k.find("crate::f").unwrap()).unwrap().recursion, sandblaster_front::hir::Recursion::NonTail);
    assert_eq!(k.fn_def(k.find("crate::g").unwrap()).unwrap().recursion, sandblaster_front::hir::Recursion::Tail);
}

// ---------------------------------------------------------------- stack budget (§3.7)

/// Depth-bounded recursion must fit the 1 MiB stack budget under the
/// frame model of `validate::check_stack` (red team RG-2 / S1).
#[test]
fn depth_bounded_recursion_must_fit_the_stack_budget() {
    // a large frame (a 1 KiB array live across the recursive call)
    rejects(
        "#[decreases(n, max = 4096)]\nfn helper(n: u32) -> u64 { let buf: [u64; 128] = [7u64; 128]; if n == 0u32 { 0u64 } else { buf[(n as usize) % 128].wrapping_add(helper(n - 1u32)) } }\npub fn deep(n: u32) -> u64 { helper(if n > 4000u32 { 4000u32 } else { n }) }",
        K::Recursion,
        "may overflow the stack",
    );
    // a large by-value parameter
    rejects(
        "#[requires(d <= 1024)]\n#[decreases(d, max = 1024)]\nfn deep(d: u32, pad: [u64; 64]) -> u64 { if d == 0 { pad[0] } else { deep(d - 1, pad) ^ pad[1] } }",
        K::Recursion,
        "may overflow the stack",
    );
    // a small frame at a moderate depth is fine
    accepts("#[decreases(n, max = 256)]\nfn f(n: u32) -> u64 { if n == 0u32 { 0u64 } else { 7u64.wrapping_add(f(n - 1u32)) } }\npub fn g(n: u32) -> u64 { f(if n > 256u32 { 256u32 } else { n }) }");
    // the same frame at depth 4096 is not
    rejects(
        "#[decreases(n, max = 4096)]\nfn f(n: u32) -> u64 { if n == 0u32 { 0u64 } else { 7u64.wrapping_add(f(n - 1u32)) } }",
        K::Recursion,
        "may overflow the stack",
    );
    // a caller whose own large frame breaks the budget of the tree
    rejects(
        "#[decreases(n, max = 64)]\nfn f(n: u32) -> u64 { if n == 0u32 { 0u64 } else { 7u64.wrapping_add(f(n - 1u32)) } }\npub fn g(n: u32) -> u64 { let big: [u64; 131072] = [0u64; 131072]; big[(n as usize) % 131072].wrapping_add(f(if n > 64u32 { 64u32 } else { n })) }",
        K::Recursion,
        "call tree of `g`",
    );
    // a generic by-value frame under recursion cannot be bounded
    rejects(
        "#[decreases(n, max = 8)]\nfn f<T: Copy>(n: u32, t: T) -> T { if n == 0u32 { t } else { let r: T = f(n - 1u32, t); r } }\npub fn g() -> u8 { 0u8 }",
        K::Recursion,
        "cannot bound the stack",
    );
    // tail recursion is a loop: no depth bound, no budget
    accepts("fn g(s: &[u8], acc: [u64; 512]) -> u64 { match s { [] => acc[0], [h, t @ ..] => g(t, acc) } }");
}

// (the three verified roots, with the verifier's depth-bounded non-tail
// recursion: `tests/verified_roots.rs`)

// ---------------------------------------------------------------- features (§9.3)

#[test]
fn intrinsic_feature_rule() {
    // static features do not count
    rejects("use core::arch::aarch64::*;\nfn f(a: uint32x4_t) -> uint32x4_t { vaddq_u32(a, a) }", K::Feature, "requires target feature(s) `neon`");
    rejects("use core::arch::aarch64::*;\n#[target_feature(enable = \"neon\")]\nfn f(a: uint32x4_t) -> uint32x4_t { vsha256su0q_u32(a, a) }", K::Feature, "`sha2`");
    // sha2 implies neon, sha3 implies sha2
    accepts("use core::arch::aarch64::*;\n#[target_feature(enable = \"sha2\")]\nfn f(a: uint32x4_t) -> uint32x4_t { vaddq_u32(vsha256su0q_u32(a, a), a) }");
    accepts("use core::arch::aarch64::*;\n#[target_feature(enable = \"sha3\")]\nfn f(a: uint32x4_t) -> uint32x4_t { vsha256su0q_u32(a, a) }");
    rejects("#[target_feature(enable = \"sha2\")]\nfn g() {}\nfn f() { g() }", K::Feature, "calling a `#[target_feature]` function");
    accepts("#[target_feature(enable = \"sha2\")]\nfn g() {}\n#[target_feature(enable = \"sha3\")]\nfn f() { g() }");
}

#[test]
fn wrong_architecture_rejected() {
    rejects("use core::arch::x86_64::*;\nfn f() {}", K::Feature, "`core::arch::x86_64` is not available");
    accepts("#[cfg(target_arch = \"x86_64\")] use core::arch::x86_64::*;\nfn f() {}");
    let c = check_x86("use core::arch::x86_64::*;\n#[target_feature(enable = \"sha,sse2,ssse3,sse4.1\")]\nfn f(a: __m128i, b: __m128i) -> __m128i { _mm_sha256rnds2_epu32(a, b, _mm_shuffle_epi32::<0x0E>(b)) }");
    assert!(c.ok(), "{}", c.render());
}

// ---------------------------------------------------------------- ghost code

#[test]
fn exec_code_cannot_use_ghost_items() {
    rejects("#[cfg(sandblaster)] #[spec] fn s(x: u32) -> u32 { x }\nfn f(x: u32) -> u32 { s(x) }", K::Ghost, "exec code refers to ghost item `s`");
    rejects("#[cfg(sandblaster)] const G: u32 = 1;\nfn f() -> u32 { G }", K::Ghost, "ghost item `G`");
    rejects("#[spec] fn s(x: u32) -> u32 { x }", K::Ghost, "`#[spec]` functions must be ghost");
    rejects("fn f(x: Int) {}", K::Ghost, "ghost type in exec code");
    accepts("#[cfg(sandblaster)] #[spec] fn s(x: u32) -> Int { x as Int + 1 }\n#[requires(s(x) < 100)]\nfn f(x: u32) -> u32 { x + 1 }");
}

// ---------------------------------------------------------------- misc subset

#[test]
fn heap_text_and_misc_rejected() {
    rejects("fn f(x: Vec<u8>) {}", K::Unsupported, "`Vec` is not supported");
    rejects("fn f(x: &str) {}", K::Unsupported, "`str`");
    rejects("fn f() -> u8 { let s = \"hi\"; 0 }", K::Unsupported, "string");
    rejects("async fn f() {}", K::Unsupported, "`async fn`");
    rejects("const fn f() {}", K::Unsupported, "`const fn`");
    rejects("fn f(s: &[u8]) -> u8 { s.iter().fold(0, |a, b| a ^ b) }", K::Resolve, "no method `iter`");
    rejects("fn f(o: Option<u8>) -> u8 { o.unwrap() }", K::Resolve, "no method `unwrap`");
    rejects("fn f() { let x: (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); }", K::Unsupported, "12 elements");
    rejects("fn f() { fn g() {} }", K::Unsupported, "items inside function bodies");
    rejects("fn f(x: u32) -> u32 { if let 1 = x && x > 0 { 0 } else { 1 } }", K::Unsupported, "`let` chains");
    rejects("fn f<const N: usize>() {}", K::Unsupported, "const generics are reserved");
}

#[test]
fn recursive_types_rejected() {
    rejects("#[derive(Clone, Copy)] struct L<'a> { next: Option<&'a L<'a>> }", K::Type, "recursive type `L`");
}

#[test]
fn exhaustiveness() {
    rejects("fn f(x: Option<u8>) -> u8 { match x { Some(v) => v } }", K::Exhaustive, "`None` not covered");
    rejects("fn f(x: u8) -> u8 { match x { 0..=100 => 0, 102..=255 => 1 } }", K::Exhaustive, "`101` not covered");
    rejects("fn f(s: &[u8]) -> u8 { match s { [] => 0, [a] => *a } }", K::Exhaustive, "not covered");
    rejects("fn f(x: Option<u8>) -> u8 { let Some(v) = x; v }", K::Exhaustive, "refutable pattern");
    rejects("fn f(x: u8) -> u8 { match x { v if v > 3 => 0, 0..=3 => 1 } }", K::Exhaustive, "not covered");
    accepts("fn f(x: u8, b: bool, s: &[u8]) -> u8 { let a = match x { 0..=100 => 0u8, 101..=255 => 1 }; let c = match b { true => 1u8, false => 2 }; let d = match s { [] => 0u8, [h, ..] => *h }; a + c + d }");
}

#[test]
fn laws_and_proofs_pairing() {
    let root = format!("{HEADER}#[cfg(sandblaster)] #[path = \"LAWS.rs\"] mod laws;\n#[cfg(sandblaster)] #[path = \"PROOF.rs\"] mod proof;\n");
    let laws = "#[law] fn l(a: u32) { requires(a > 0); ensures(a >= 1); }\n#[law] fn m(a: u32) { requires(a > 1); ensures(a > 0); }\n";
    let c = check_files(&[("r/mod.rs", &root), ("r/LAWS.rs", laws), ("r/PROOF.rs", "#[proof] fn l(a: u32) { }\n#[proof] fn m(a: u32) { l(a); }\n")]);
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let (l, pl, pm) = (k.find("crate::laws::l").unwrap(), k.find("crate::proof::l").unwrap(), k.find("crate::proof::m").unwrap());
    assert_eq!(k.fn_def(l).unwrap().law_proof, Some(sandblaster_front::hir::LawProof::Item(pl)));
    assert_eq!(k.fn_def(pl).unwrap().proves, Some(l));
    // applying `l` inside PROOF.rs names the proof item, which stands for the law
    match &k.fn_def(pm).unwrap().body {
        sandblaster_front::hir::FnBody::Script(ss) => match &ss[0].kind {
            sandblaster_front::hir::ScriptKind::Apply { app, .. } => match &app.kind {
                sandblaster_front::hir::ExprKind::Call { callee: sandblaster_front::hir::Callee::Item(id, _), .. } => assert_eq!(*id, l),
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
    let c = check_files(&[("r/mod.rs", &root), ("r/LAWS.rs", laws), ("r/PROOF.rs", "#[proof] fn l(b: u32) { }\n")]);
    rejects_checked(&c, K::Law, "same parameters");
    let c = check_files(&[("r/mod.rs", &root), ("r/LAWS.rs", laws), ("r/PROOF.rs", "#[proof] fn nothing(a: u32) { }\n")]);
    rejects_checked(&c, K::Law, "does not prove any `#[law]`");
    let c = check_files(&[("r/mod.rs", &root), ("r/LAWS.rs", laws), ("r/PROOF.rs", "")]);
    assert!(c.ok());
    let k = c.krate.unwrap();
    assert_eq!(k.fn_def(k.find("crate::laws::l").unwrap()).unwrap().law_proof, Some(sandblaster_front::hir::LawProof::Missing));
}

/// Hardware variants (`#[implements]`) were native-dialect authoring for the
/// removed optimizer's dispatch: refused whatever their shape. Negative
/// twin: the same `#[target_feature]` function without `#[implements]` is
/// accepted.
#[test]
fn implements_is_refused() {
    rejects(
        "fn compress(s: [u32; 8]) -> [u32; 8] { s }\n#[target_feature(enable = \"sha2\")]\n#[implements(compress)]\nfn compress_hw(s: [u32; 4]) -> [u32; 8] { [0; 8] }",
        K::Feature,
        "`#[implements]` (a hardware variant) is not supported",
    );
    rejects("fn compress(s: [u32; 8]) -> [u32; 8] { s }\n#[implements(compress)]\nfn c2(s: [u32; 8]) -> [u32; 8] { s }", K::Feature, "`#[implements]` (a hardware variant) is not supported");
    refused_hardware("fn compress(s: [u32; 8]) -> [u32; 8] { s }\n#[target_feature(enable = \"sha2\")]\n#[implements(compress)]\nfn compress_hw(s: [u32; 8]) -> [u32; 8] { s }");
    accepts("fn compress(s: [u32; 8]) -> [u32; 8] { s }\n#[target_feature(enable = \"sha2\")]\nfn compress_hw(s: [u32; 8]) -> [u32; 8] { s }");
}

#[test]
fn privacy() {
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}mod a;\nmod b;\n")), ("r/a.rs", "fn secret() -> u32 { 1 }\n"), ("r/b.rs", "fn f() -> u32 { super::a::secret() }\n")]);
    rejects_checked(&c, K::Privacy, "`secret` is private");
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}mod a;\nfn f(s: a::S) -> u32 {{ s.x }}\n")), ("r/a.rs", "#[derive(Clone, Copy)] pub struct S { x: u32 }\n")]);
    rejects_checked(&c, K::Privacy, "field `x` is private");
}

#[test]
fn module_layout() {
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}#[path = \"x.rs\"] mod m;\n")), ("r/x.rs", "")]);
    rejects_checked(&c, K::Load, "`#[path]` is only allowed");
    rejects("mod m { }", K::Unsupported, "inline modules");
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}mod missing;\n"))]);
    rejects_checked(&c, K::Load, "file not found for module `missing`");
}

#[test]
fn annotations_must_be_in_scope_in_exec_modules() {
    let c = check_files(&[("r/mod.rs", "#![forbid(unsafe_code)]\n#[requires(x > 0)]\nfn f(x: u32) -> u32 { x - 1 }\n")]);
    rejects_checked(&c, K::Resolve, "attribute `requires` is not in scope");
    let c = check_files(&[("r/mod.rs", "#![forbid(unsafe_code)]\n#[sandblaster::requires(x > 0)]\nfn f(x: u32) -> u32 { x - 1 }\n")]);
    assert!(c.ok(), "{}", c.render());
}

#[test]
fn intrinsic_immediates_must_be_literals() {
    rejects(
        "use core::arch::aarch64::*;\nconst S: u32 = 3;\n#[target_feature(enable = \"neon\")]\nfn f(a: uint32x4_t) -> uint32x4_t { vshlq_n_u32::<S>(a) }",
        K::Type,
        "immediates must be integer literals",
    );
    rejects(
        "use core::arch::aarch64::*;\n#[target_feature(enable = \"neon\")]\nfn f(a: uint32x4_t, k: i32) -> uint32x4_t { vshlq_n_u32(a, k) }",
        K::Signed,
        "`i32`",
    );
}

#[test]
fn malformed_generic_impls_do_not_crash() {
    // regression: generic arity mismatches between impls, types and calls
    let c = check("#[derive(Clone, Copy)] struct W<T: Copy>(T);\nimpl W { fn f(self) -> u8 { 0 } fn g() -> u8 { 1 } }\nfn h(w: W<u8>) -> u8 { w.f() + W::g() }");
    assert!(c.diags.has_errors());
    let c = check("#[derive(Clone, Copy)] struct W(u8);\nimpl<T: Copy> W { fn f(self) -> u8 { 0 } }\nfn h(w: W) -> u8 { w.f() + W::f(w) }");
    assert!(c.diags.has_errors());
}

#[test]
fn zst_values_are_fine_outside_slices() {
    accepts("fn f(x: Option<()>) -> Option<()> { match x { Some(()) => Some(()), None => None } }");
    rejects("#[derive(Clone, Copy)] struct W<'a, T: Copy> { s: &'a [T] }\nfn f() -> usize { let a: [(); 2] = [(); 2]; let w = W { s: &a }; w.s.len() }", K::ZstSlice, "zero-sized");
}

#[test]
fn open_claims_and_todo_are_warnings() {
    let c = check("#[cfg(sandblaster)] #[law] fn l(a: u32) { requires(a > 0); ensures(a >= 1); }\n#[cfg(sandblaster)] #[lemma] fn m(a: u32) { ensures(a == a); todo(); }");
    assert!(c.ok(), "{}", c.render());
    let w: Vec<String> = c.diags.list.iter().filter(|d| d.severity == sandblaster_front::diag::Severity::Warning).map(|d| d.msg.clone()).collect();
    assert!(w.iter().any(|m| m.contains("open claim: law `l`")), "{w:?}");
    assert!(w.iter().any(|m| m.contains("`todo()`")), "{w:?}");
}
