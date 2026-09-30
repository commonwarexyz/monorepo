//! Constructor congruence for `Option` and pairs (`lemmas/seq_lib.core`, third
//! part), proved at element types `E`, `F` that the generator generalizes
//! to `T`, `U`.

/// The first element type (generalized to `T`).
#[derive(Clone, Copy)]
pub struct E { v: u8 }

/// The second element type (generalized to `U`).
#[derive(Clone, Copy)]
pub struct F { w: u8 }

/// Equal payloads give equal options.
#[lemma]
fn some_eq(x: E, y: E) {
    requires(x == y);
    ensures(Some(x) == Some(y));
    rewrite(x == y);
    follows();
}

/// Componentwise equal pairs are equal.
#[lemma]
fn pair_eq(a: E, b: F, c: E, d: F) {
    requires(a == c);
    requires(b == d);
    ensures((a, b) == (c, d));
    rewrite(a == c);
    rewrite(b == d);
    follows();
}
