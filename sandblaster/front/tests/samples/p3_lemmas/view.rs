//! Slices against their `Seq` views (`lemmas/seq_lib.core`, second part),
//! proved at an element type `E` that the generator generalizes to `T`.

/// The element type (generalized to `T` in the library).
#[derive(Clone, Copy)]
pub struct E { v: u8 }

/// A slice's length is its view's length.
#[lemma]
fn view_len(s: &[E], l: Seq<E>) {
    requires(s == l);
    ensures(l.len() == s.len() as Nat);
    rewrite_rev(s == l);
    follows();
}
