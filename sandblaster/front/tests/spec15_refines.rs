//! §15 S1 refinement (DESIGN.md §15.2, §15.3): `f::refines` lemmas —
//! views and view coercion, the explicit argument map, `domain`, state
//! passing, `#[represents]` simulation, proofs by the body walk (loops
//! with post-loop facts, recursion) and by `#[proof(refines = f)]` items,
//! the refinement as a fact at call sites, determinacy reporting, and the
//! ghost language of specs (`Nat`, `Seq<T>`, byte literals, `Int` rules).

#[path = "spec15_util.rs"]
mod util;

use sandblaster_front::elab::refines::RefinesForm;
use util::*;

// ---------------------------------------------------------------------
// the basic form, view coercion
// ---------------------------------------------------------------------

#[test]
fn refines_a_nat_spec_through_the_uint_coercion() {
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn double(x: Nat) -> Nat { 2 * x }

#[refines(double)]
pub fn dbl(x: u32) -> u64 { (x as u64) * 2 }
"#,
    );
    let f = r.refinement("crate::dbl");
    assert!(f.checked, "{}", r.explain());
    assert_eq!(f.form, RefinesForm::Plain);
    assert_eq!(f.up_to, None, "u64 ↦ Nat is injective: the refinement determines `dbl`");
    assert!(r.established.iter().any(|g| g == "crate::dbl"), "{:?}", r.established);
    assert!(r.checked_defs.iter().any(|d| d == "crate::dbl::refines"));
}

#[test]
fn option_result_and_slice_through_the_view_coercion() {
    // `Option<(u8, &[u8])> ↦ Option<(Nat, Seq<u8>)>`, `&[u8] ↦ Seq<u8>`; the
    // spec in the index style of the implementation (`len`, `[i]`, `skip`)
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn first(xs: Seq<u8>) -> Option<(Nat, Seq<u8>)> {
    if xs.len() == 0 { None } else { Some((xs[0] as Nat, xs.skip(1))) }
}

#[refines(first)]
pub fn head(xs: &[u8]) -> Option<(u8, &[u8])> {
    if xs.is_empty() { None } else { Some((xs[0], &xs[1..])) }
}
"#,
    );
    let f = r.refinement("crate::head");
    assert!(f.checked && f.up_to.is_none(), "{}", r.explain());
}

#[test]
fn loop_function_refines_with_post_loop_facts() {
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn times3(n: Nat) -> Nat { 3 * n }

#[refines(times3)]
pub fn thrice(n: u16) -> u64 {
    let mut acc: u64 = 0;
    for i in 0..n {
        proof! { invariant((acc as Int) == 3 * (i as Int)); }
        acc += 3;
    }
    acc
}
"#,
    );
    assert!(r.refinement("crate::thrice").checked, "{}", r.explain());
}

#[test]
fn off_by_one_loop_does_not_refine() {
    let r = fails(
        r#"
#[cfg(sandblaster)] #[spec] fn count(n: Nat) -> Nat { n }

#[refines(count)]
pub fn count_up(n: u32) -> u32 {
    let mut c: u32 = 0;
    for i in 0..n {
        proof! { invariant(c <= i); }
        if i > 0 { c += 1; }
    }
    c
}
"#,
    );
    assert!(r.unproven.iter().any(|(d, k, _)| d == "crate::count_up::refines" && k == "refines"), "{}", r.explain());
    assert!(!r.established.iter().any(|g| g == "crate::count_up"));
}

#[test]
fn explicit_argument_map_and_domain() {
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] #[requires(b <= a)] fn sub_nat(a: Nat, b: Nat) -> Nat { a - b }

// internal helper, refined only where the reference is defined
#[refines(sub_nat(x as Nat, y as Nat), domain = y <= x)]
fn sub_checked(x: u64, y: u64) -> u64 { if y <= x { x - y } else { 0 } }

pub fn use_it(x: u64) -> u64 { sub_checked(x, x / 2) }
"#,
    );
    let f = r.refinement("crate::sub_checked");
    assert!(f.checked, "{}", r.explain());
    assert!(f.up_to.as_deref().is_some_and(|u| u.contains("domain")), "a domain refinement does not determine the function: {:?}", f.up_to);
}

#[test]
fn spec_requires_must_follow_from_the_function() {
    // `Nat - Nat` needs `b ≤ a`: without a domain the spec is not total on
    // the input type, and the refinement statement is ill-formed
    let r = fails(
        r#"
#[cfg(sandblaster)] #[spec] #[requires(b <= a)] fn diff(a: Nat, b: Nat) -> Nat { a - b }

#[refines(diff)]
fn diff_impl(a: u64, b: u64) -> u64 { a.saturating_sub(b) }
"#,
    );
    assert!(!r.refinement("crate::diff_impl").checked, "{}", r.explain());
}

#[test]
fn refinement_is_a_fact_at_call_sites() {
    verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn twice_plus(x: Nat) -> Nat { 2 * x + 1 }

#[refines(twice_plus)]
fn tp(x: u16) -> u32 { (x as u32) + (x as u32) + 1 }

// the caller's ensures follows from `tp::refines` (a fact at the call)
#[ensures(|r: u32| (r as Int) == twice_plus(x as Nat) + 1)]
pub fn tp_plus_one(x: u16) -> u32 {
    let s = tp(x);
    proof! { assert((s as Int) == twice_plus(x as Nat)); }
    s + 1
}
"#,
    );
}

#[test]
fn recursive_function_refines_by_induction() {
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn even(n: Nat) -> bool { if n == 0 { true } else { !even(n - 1) } }

#[refines(even)]
#[decreases(n, max = 100)]
#[requires(n <= 100)]
fn is_even(n: u64) -> bool { if n == 0 { true } else { !is_even(n - 1) } }
"#,
    );
    assert!(r.refinement("crate::is_even").checked, "{}", r.explain());
}

// ---------------------------------------------------------------------
// views, state passing, representation relations
// ---------------------------------------------------------------------

#[test]
fn state_passing_through_a_structural_view() {
    // `fn m(self, ..) -> (Self, R)` refines `(V, ..) -> (V, R')`, post-state
    // first; `#[view(spec::Counter)]` maps every field (injective)
    let r = verifies_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] #[path = "spec/mod.rs"] mod spec;

#[derive(Clone, Copy)]
#[view(spec::Counter)]
pub struct Counter { n: u32, total: u64 }

impl Counter {
    #[refines(spec::bump)]
    pub fn bump(self, by: u16) -> (Counter, u64) {
        let n = if self.n < u32::MAX { self.n + 1 } else { self.n };
        let total = if self.total < 1000000 { self.total + (by as u64) } else { self.total };
        (Counter { n, total }, total)
    }
}
"#,
        ),
        (
            "r/spec/mod.rs",
            r#"
#[derive(Clone, Copy)]
pub struct Counter { pub n: Nat, pub total: Nat }

pub fn bump(c: Counter, by: Nat) -> (Counter, Nat) {
    let n = if c.n < 4294967295 { c.n + 1 } else { c.n };
    let total = if c.total < 1000000 { c.total + by } else { c.total };
    (Counter { n, total }, total)
}
"#,
        ),
    ]);
    let f = r.refinement("crate::Counter::bump");
    assert!(f.checked && f.up_to.is_none(), "{}", r.explain());
}

#[test]
fn a_lossy_view_refines_only_up_to_view() {
    // the view drops `tag`: two implementations differing in `tag` refine the
    // same spec, so the refinement does not determine `step` (§15.2)
    let r = verifies(
        r#"
#[derive(Clone, Copy)]
#[view(|p| p.x as Nat)]
pub struct Point { x: u32, tag: u8 }

#[cfg(sandblaster)] #[spec] fn next(x: Nat) -> Nat { if x < 100 { x + 1 } else { 100 } }

#[refines(next)]
pub fn step(p: Point) -> Point {
    if p.x < 100 { Point { x: p.x + 1, tag: 0 } } else { Point { x: 100, tag: 7 } }
}
"#,
    );
    let f = r.refinement("crate::step");
    assert!(f.checked, "{}", r.explain());
    // S2: `Point` is `Abstract` (private fields, no derived `PartialEq` or
    // `Debug`, every boundary function over it refines), so host code
    // cannot observe `tag`: the refinement determines `step` through the
    // view (§15.3) ...
    assert_eq!(f.up_to, None, "{}", r.explain());
    // ... but a lossy view does not establish it (spec code may read `tag`)
    assert!(!r.established.iter().any(|g| g == "crate::step"), "a refinement up to a lossy view does not establish the function");
}

#[test]
fn a_lossy_view_on_a_non_abstract_internal_type_refines_only_up_to_view() {
    // the same, with a derived `PartialEq` (it compares `tag`): not
    // `Abstract`; the type is internal, so the lossy view is allowed and the
    // refinement does not determine `step` (§15.2)
    let r = verifies(
        r#"
#[derive(Clone, Copy, PartialEq)]
#[view(|p| p.x as Nat)]
struct Point { x: u32, tag: u8 }

#[cfg(sandblaster)] #[spec] fn next(x: Nat) -> Nat { if x < 100 { x + 1 } else { 100 } }

#[refines(next)]
fn step(p: Point) -> Point {
    if p.x < 100 { Point { x: p.x + 1, tag: 0 } } else { Point { x: 100, tag: 7 } }
}

pub fn api(x: u32) -> u32 { step(Point { x, tag: 0 }).x }
"#,
    );
    let f = r.refinement("crate::step");
    assert!(f.checked, "{}", r.explain());
    assert_eq!(f.up_to.as_deref(), Some("refines `crate::next` up to view(Point)"));
    assert!(!r.established.iter().any(|g| g == "crate::step"));
}

#[test]
fn representation_relation_simulation_forms() {
    let r = verifies_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] #[path = "spec/mod.rs"] mod spec;

#[derive(Clone, Copy)]
#[represents(|s: &Ctr, a: Nat| s.count as Nat == a && a <= 1000)]
pub struct Ctr { count: u16 }

impl Ctr {
    // constructor-like: establishes the relation
    #[refines(spec::zero)]
    pub fn new() -> Ctr { Ctr { count: 0 } }
    // `S → S`: preserves it
    #[refines(spec::inc)]
    pub fn inc(self) -> Ctr { if self.count < 1000 { Ctr { count: self.count + 1 } } else { self } }
    // an observer refines through it
    #[refines(spec::get)]
    pub fn get(&self) -> u16 { self.count }
    // state passing: preserves it and refines the result
    #[refines(spec::inc_get)]
    pub fn inc_get(self) -> (Ctr, u16) {
        let c = if self.count < 1000 { self.count + 1 } else { self.count };
        (Ctr { count: c }, c)
    }
}
"#,
        ),
        (
            "r/spec/mod.rs",
            r#"
pub fn zero() -> Nat { 0 }
pub fn inc(a: Nat) -> Nat { if a < 1000 { a + 1 } else { a } }
pub fn get(a: Nat) -> Nat { a }
pub fn inc_get(a: Nat) -> (Nat, Nat) { let b = inc(a); (b, b) }
"#,
        ),
    ]);
    assert_eq!(r.refinement("crate::Ctr::new").form, RefinesForm::RepConstructor);
    assert_eq!(r.refinement("crate::Ctr::inc").form, RefinesForm::RepPreserve);
    assert_eq!(r.refinement("crate::Ctr::get").form, RefinesForm::RepObserver);
    assert_eq!(r.refinement("crate::Ctr::inc_get").form, RefinesForm::RepStatePassing);
    for f in ["crate::Ctr::new", "crate::Ctr::inc", "crate::Ctr::get", "crate::Ctr::inc_get"] {
        let x = r.refinement(f);
        assert!(x.checked, "{f}: {}", r.explain());
        // S2: `Ctr` is `Abstract` and `new` establishes the relation, so the
        // simulation determines every method (§15.3)
        assert_eq!(x.up_to, None, "{f}: {}", r.explain());
    }
}

#[test]
fn a_wrong_simulation_step_fails() {
    let r = fails(
        r#"
#[cfg(sandblaster)] #[spec] fn inc(a: Nat) -> Nat { a + 1 }

#[derive(Clone, Copy)]
#[represents(|s: &Ctr, a: Nat| s.count as Nat == a)]
pub struct Ctr { count: u16 }

impl Ctr {
    #[refines(inc)]
    fn inc(self) -> Ctr { if self.count < 1000 { Ctr { count: self.count + 2 } } else { self } }
}
"#,
    );
    assert!(!r.refinement("crate::Ctr::inc").checked, "{}", r.explain());
}

// ---------------------------------------------------------------------
// proof items
// ---------------------------------------------------------------------

#[test]
fn proof_item_proves_the_refinement_by_word_algebra() {
    // compress-style: the implementation and the reference compute the same
    // word function differently; `bv()` in PROOF.rs closes it
    let r = verifies_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] #[path = "spec.rs"] mod spec;
#[cfg(sandblaster)] #[path = "PROOF.rs"] mod proofs;

#[refines(spec::rotmix)]
pub fn mix(a: u32, b: u32) -> u32 { ((a << 5u32) | (a >> 27u32)) ^ b }
"#,
        ),
        ("r/spec.rs", "pub fn rotmix(a: u32, b: u32) -> u32 { a.rotate_left(5) ^ b }
"),
        ("r/PROOF.rs", "#[proof(refines = super::mix)]
fn mix(a: u32, b: u32) { bv(); }
"),
    ]);
    let f = r.refinement("crate::mix");
    assert!(f.checked, "{}", r.explain());
    assert_eq!(f.proof, "crate::proofs::mix");
}

#[test]
fn a_wrong_proof_item_fails() {
    let r = run_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] #[path = "spec.rs"] mod spec;
#[cfg(sandblaster)] #[path = "PROOF.rs"] mod proofs;

#[refines(spec::rotmix)]
pub fn mix(a: u32, b: u32) -> u32 { ((a << 6u32) | (a >> 26u32)) ^ b }
"#,
        ),
        ("r/spec.rs", "pub fn rotmix(a: u32, b: u32) -> u32 { a.rotate_left(5) ^ b }
"),
        ("r/PROOF.rs", "#[proof(refines = super::mix)]
fn mix(a: u32, b: u32) { bv(); }
"),
    ]);
    assert!(r.front_ok, "{}", r.rendered);
    assert!(!r.verified && !r.refinement("crate::mix").checked, "{}", r.explain());
}

// ---------------------------------------------------------------------
// the ghost language of specifications (§4.1): Nat, Seq<T>, literals,
// Int rules
// ---------------------------------------------------------------------

#[test]
fn nat_and_seq_vocabulary() {
    // closed uses are known answers checked by the kernel (`#[example]`,
    // §15.7): each is `refl` or `eval_closed`
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn sum(xs: Seq<u8>) -> Nat { match xs { [] => 0, [h, t @ ..] => h as Nat + sum(t) } }
#[cfg(sandblaster)] #[spec] fn words(xs: Seq<u8>) -> Seq<[u8; 4]> { xs.chunks_exact::<4>() }
#[cfg(sandblaster)] #[spec] fn pad(xs: Seq<u8>) -> Seq<u8> { seq![..xs, 0x80, ..Seq::repeat(0u8, 3)] }

#[cfg(sandblaster)]
#[spec]
#[example(sum(seq![1u8, 2u8, 3u8]) == 6)]
#[example(seq![1u8, 2u8, 3u8].take(2) == seq![1u8, 2u8] && seq![1u8, 2u8, 3u8].skip(2) == seq![3u8])]
#[example(seq![1u8, 2u8, 3u8].take(9) == seq![1u8, 2u8, 3u8] && seq![1u8, 2u8, 3u8].skip(9) == seq![])]
#[example(seq![5u8, 6u8].get(1) == Some(6u8) && seq![5u8, 6u8].get(2) == None && seq![5u8, 6u8][0] == 5u8)]
#[example(words(seq![1u8, 2u8, 3u8, 4u8, 5u8]).len() == 1 && words(seq![1u8, 2u8, 3u8, 4u8]).flatten() == seq![1u8, 2u8, 3u8, 4u8])]
#[example(pad(seq![7u8]) == seq![7u8, 0x80, 0u8, 0u8, 0u8] && pad(seq![]).len() == 4)]
#[example(seq![1u8, 2u8, 3u8].to_array::<3>() == [1u8, 2u8, 3u8] && seq![1u8, 2u8].rev() == seq![2u8, 1u8])]
#[example(seq![1u8, 2u8].update(0, 9u8) == seq![9u8, 2u8] && seq![seq![1u8], seq![2u8, 3u8]].flatten() == seq![1u8, 2u8, 3u8])]
#[example((7 as Nat).saturating_sub(9) == 0 && (7 as Nat).max(9) == 9 && (7 as Nat).min(9) == 7)]
#[example(b"abc" == [0x61u8, 0x62u8, 0x63u8] && hex!("6162 63") == b"abc")]
#[example((-7 as Int).div_euclid(2) == -4 && (-7 as Int).rem_euclid(2) == 1 && (7 as Nat) / 2 == 3 && (7 as Nat) % 2 == 1)]
#[example((300 as Int) as u8 == 44u8 && (-1 as Int) as u8 == 255u8 && (65536 as Nat) as u16 == 0u16)]
fn vocabulary() -> bool { true }
"#,
    );
    assert_eq!(r.examples.iter().filter(|e| e.item == "crate::vocabulary" && e.checked).count(), 12, "{}", r.explain());
}

#[test]
fn int_division_needs_non_negative_operands() {
    let r = fails(
        r#"
#[cfg(sandblaster)] #[spec] fn half(x: Int) -> Int { x / 2 }
"#,
    );
    assert!(r.unproven.iter().any(|(d, k, _)| d == "crate::half" && k == "well-formed"), "{}", r.explain());
    // Euclidean division is total on `Int` (non-zero divisor); `Nat`
    // operands are non-negative by construction
    verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn half(x: Int) -> Int { x.div_euclid(2) }
#[cfg(sandblaster)] #[spec] fn half_nat(x: Nat) -> Nat { x / 2 }
#[cfg(sandblaster)] #[spec] fn half_pos(x: Int) -> Int { if x >= 0 { x / 2 } else { 0 } }
"#,
    );
}

#[test]
fn int_as_uint_truncates_like_exec_as() {
    verifies(
        r#"
#[cfg(sandblaster)]
#[lemma]
fn truncation(x: u8) {
    ensures(((x as Int) as u8) == x);
    follows();
}
"#,
    );
}

#[test]
fn nat_subtraction_and_casts_carry_obligations() {
    let r = fails(
        r#"
#[cfg(sandblaster)] #[spec] fn dec(n: Nat) -> Nat { n - 1 }
"#,
    );
    assert!(r.unproven.iter().any(|(d, k, _)| d == "crate::dec" && k == "underflow"), "{}", r.explain());
    let r = fails(
        r#"
#[cfg(sandblaster)] #[spec] fn to_nat(i: Int) -> Nat { i as Nat }
"#,
    );
    assert!(r.unproven.iter().any(|(d, k, _)| d == "crate::to_nat" && k == "underflow"), "{}", r.explain());
    // a `Nat` parameter's bound is a fact in the body and an obligation at
    // calls; quantified `Nat`s carry it too
    verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn pred(n: Nat) -> Nat { if n == 0 { 0 } else { n - 1 } }
#[cfg(sandblaster)] #[spec] fn pred_int(i: Int) -> Nat { if i > 0 { pred(i as Nat) } else { 0 } }
#[cfg(sandblaster)] #[lemma] fn nat_nonneg(n: Nat) { ensures(n >= 0); by_arithmetic(); }
#[cfg(sandblaster)] #[lemma] fn one(n: Nat) { requires(n > 0); ensures(n - 1 < n); by_arithmetic(); }
#[cfg(sandblaster)] #[lemma] fn ex() { ensures(exists(|n: Nat| n + 1 == 1)); witness(0); }
"#,
    );
}

#[test]
fn refinement_shape_errors_are_type_errors() {
    let r = run(
        r#"
#[cfg(sandblaster)] #[spec] fn two(a: Nat, b: Nat) -> Nat { a + b }
#[refines(two)]
fn one(a: u8) -> u16 { a as u16 }
"#,
    );
    assert!(!r.front_ok && r.errors.iter().any(|(k, m)| *k == sandblaster_front::diag::DiagKind::Type && m.contains("`crate::two` takes 2 argument(s), the function 1")), "{}", r.rendered);
    let r = run(
        r#"
#[cfg(sandblaster)] #[spec] fn neg(a: Int) -> bool { a < 0 }
#[refines(neg)]
fn f(a: bool) -> bool { a }
"#,
    );
    assert!(r.errors.iter().any(|(_, m)| m.contains("parameter 1 of type `bool` has no view coercion to `Int`")), "{}", r.rendered);
    let r = run(
        r#"
#[cfg(sandblaster)] #[spec] fn id(a: Nat) -> Nat { a }
#[refines(id)]
fn f(a: u8) -> bool { a > 0 }
"#,
    );
    assert!(r.errors.iter().any(|(_, m)| m.contains("the result type `bool` has no view coercion to `Nat`")), "{}", r.rendered);
}

#[test]
fn an_enum_view_through_a_match() {
    let r = verifies(
        r#"
#[derive(Clone, Copy)]
#[view(|c| match c { Color::Red => 0 as Nat, Color::Green => 1 as Nat, Color::Blue => 2 as Nat })]
pub enum Color { Red, Green, Blue }

#[cfg(sandblaster)] #[spec] fn succ3(c: Nat) -> Nat { if c < 2 { c + 1 } else { 0 } }

#[refines(succ3)]
pub fn next(c: Color) -> Color {
    match c { Color::Red => Color::Green, Color::Green => Color::Blue, Color::Blue => Color::Red }
}
"#,
    );
    let f = r.refinement("crate::next");
    assert!(f.checked, "{}", r.explain());
    // S2: `Color::view_inj` is proven (distinct constants per variant), so
    // the view is injective: the refinement determines and establishes
    // `next` (§15.2)
    assert_eq!(f.up_to, None, "{}", r.explain());
    assert!(r.established.iter().any(|g| g == "crate::next"), "{:?}", r.established);
    assert!(r.checked_defs.iter().any(|d| d == "crate::Color::view_inj"), "{:?}", r.checked_defs);
}

#[test]
fn a_refinement_proven_by_a_proof_item_is_a_fact_at_later_calls() {
    verifies_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] #[path = "spec.rs"] mod spec;
#[cfg(sandblaster)] #[path = "PROOF.rs"] mod proofs;

#[refines(spec::rotmix)]
fn mix(a: u32, b: u32) -> u32 { ((a << 5u32) | (a >> 27u32)) ^ b }

// uses the refinement of `mix` (proven in PROOF.rs) as a fact
#[ensures(|r: u32| r == spec::rotmix(a, 0))]
pub fn mix0(a: u32) -> u32 { mix(a, 0) }
"#,
        ),
        ("r/spec.rs", "pub fn rotmix(a: u32, b: u32) -> u32 { a.rotate_left(5) ^ b }\n"),
        ("r/PROOF.rs", "#[proof(refines = super::mix)]\nfn mix(a: u32, b: u32) { bv(); }\n"),
    ]);
}
