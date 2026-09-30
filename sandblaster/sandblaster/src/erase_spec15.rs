//! The §15 annotations erase under `rustc` (baseline builds, DESIGN.md §2,
//! §15): type annotations keep their type, function annotations keep their
//! function and remove its `#[ghost]` parameters (which may have ghost types
//! that do not exist for rustc), and ghost items vanish with their
//! annotations. Compiling this module is the test.

use crate::prelude::*;

/// An invariant type (§15.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[invariant(self.0 < 100)]
struct Small(u8);

/// A view on an enum and a representation relation (§15.3).
#[view(|s| s)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Bit {
    Zero,
    One,
}

#[represents(|s: &Absorbed, m: Seq<u8>| s.0 as Nat == m.len())]
#[derive(Clone, Copy)]
struct Absorbed(u64);

/// A refined exec function with a ghost parameter of a ghost type (removed
/// by the first annotation's macro), examples and a section merge.
#[refines(spec_add(a as Nat, b as Nat), domain = a < 10)]
#[example(add(1, 7, 2) == 3)]
#[section(with = [dec])]
fn add(a: u8, #[ghost] budget: Nat, b: u8) -> u8 {
    a.wrapping_add(b)
}

/// A generic function whose ghost parameter comes after an angle-bracketed
/// type with a comma.
#[requires(x > 0)]
fn dec<T: Copy>(pair: Option<(T, T)>, #[sandblaster::prelude::ghost] k: Int, x: u8) -> (Option<(T, T)>, u8) {
    (pair, x - 1)
}

/// A caller passing ghost arguments: its annotation's macro removes the
/// `ghost!(..)` arguments (at any depth), as `add`'s removes the parameter.
#[ensures(|r: u8| true)]
fn caller(a: u8) -> u8 {
    let x = add(a, ghost!(a as Nat + 1), 2);
    add(add(x, ghost!(0), 1), sandblaster::ghost!(seq![1u8]), (1u8).wrapping_add(0))
}

/// A trusted runtime primitive with a contract (§15.8).
#[trusted_extern(justification = "runtime clock")]
#[ensures(|r: u64| true)]
fn now() -> u64 {
    0
}

/// Ghost items vanish with their §15 annotations (their bodies are not
/// Rust: `Nat`, `Seq`, `requires(..)`).
#[spec]
#[examples(file = "vectors.rsp", format = "cavp", provenance = independent)]
#[mirrors_impl(justification = "a one-line spec")]
fn spec_add(a: Nat, b: Nat) -> Nat {
    a + b
}

/// A named assumption (§15.13) and laws with the law-rule annotations
/// (§15.1 LR4, LR6, LR7).
#[spec]
#[assumption(class = computational, cite = "a hardness assumption")]
fn hard() {}

#[law]
#[reduces_to(hard)]
fn reduced(a: Nat) {
    ensures(a == a || spec_add(a, 0) == a);
}

#[law]
#[definitional(reason = "states the definition")]
#[corollary]
fn defined(a: Nat) {
    ensures(spec_add(a, 0) == a + 0);
}

#[lemma]
#[fuel_sufficient(spec_add)]
#[induction(n)]
fn enough(n: Nat) {
    ensures(spec_add(n, 0) == n);
}

#[test]
fn spec15_annotations_erase() {
    assert_eq!(add(1, 2), 3);
    assert_eq!(caller(1), 5);
    assert_eq!(dec::<u8>(None, 3), (None, 2));
    assert_eq!(Small(3).0, 3);
    assert_eq!(Absorbed(4).0, 4);
    assert_ne!(Bit::Zero, Bit::One);
    assert_eq!(now(), 0);
}
