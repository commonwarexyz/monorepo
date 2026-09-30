//! Bridges: the code's machine types against the numbers and sequences proofs are written in.
//! Every lemma here is an equation between an operation on a word, a slice or an `Option` of the
//! code and the matching operation on `Nat` or `Seq`. The module is declared `#[bridges]`, so each
//! checked lemma is also a rule of the prover: a lockstep refinement (an exec function against a
//! model written in the code's shape) meets the model's operations through them, with no proof
//! text. Unconditional equations rewrite; the others are applied backward, their `requires` the
//! subgoals.

use sandblaster::prelude::*;

use crate::stdlib::bits::count_ones_u64;

/// A word's `count_ones` is the `popcount` of its value.
#[lemma]
pub fn count_ones(x: u64) {
    ensures(x.count_ones() as Nat == popcount(x as Nat));
    count_ones_u64(x);
}

/// A word read as a number and back is the word.
#[lemma]
pub fn u64_round_trip(x: u64) {
    ensures((x as Nat) as u64 == x);
    by_arithmetic();
}

/// The first element of a slice is element 0 of the sequence it stands for.
#[lemma]
pub fn slice_first<T: Copy>(s: &[T], xs: Seq<T>) {
    requires(s == xs);
    ensures(s.first() == xs.get(0));
    match xs {
        [x, rest @ ..] => {
            assert(s.len() > 0usize, { by_arithmetic(); });
            follows();
        }
        [] => {
            assert(s.len() == 0usize, { by_arithmetic(); });
            follows();
        }
    }
}

/// `s.get(i)` of a slice is `get(i)` of its sequence.
#[lemma]
pub fn slice_get<T: Copy>(s: &[T], xs: Seq<T>, i: usize) {
    requires(s == xs);
    ensures(s.get(i) == xs.get(i as Nat));
    follows();
}

/// The last element of a slice is the last of its sequence.
#[lemma]
pub fn slice_last<T: Copy>(s: &[T], xs: Seq<T>) {
    requires(s == xs);
    requires(xs.len() > 0);
    ensures(s.last() == xs.get(xs.len() - 1));
    follows();
}

/// `split_at_checked` inside the slice: its two parts are `take` and `skip` of its sequence.
#[lemma]
pub fn slice_split_at<T: Copy>(s: &[T], xs: Seq<T>, n: usize) {
    requires(s == xs);
    requires(n <= s.len());
    ensures(match s.split_at_checked(n) { Some((a, b)) => a == xs.take(n as Nat) && b == xs.skip(n as Nat), None => false });
    match s.split_at_checked(n) {
        Some(v) => {
            sandblaster::lemmas::slice::split_at_checked_some::<T>(s, n, v.0, v.1);
            follows();
        }
        None => {
            sandblaster::lemmas::slice::split_at_checked_none::<T>(s, n);
            by_contradiction();
        }
    }
}

/// A slice split as `first()` and the sequence split as `[h, ..t]`: one first element.
#[lemma]
pub fn first_head<T: Copy>(s: &[T], v: T, h: T, t: Seq<T>) {
    requires(s.first() == Some(&v));
    requires(s == seq![h, ..t]);
    ensures(v == h);
    slice_first::<T>(s, seq![h, ..t]);
    follows();
}

/// `first()` of a slice, as the sequence has it: the element there.
#[lemma]
pub fn first_some<T: Copy>(s: &[T], xs: Seq<T>, v: T) {
    requires(s.first() == Some(&v));
    requires(s == xs);
    ensures(xs.get(0) == Some(v));
    follows();
}

/// `first()` of an empty slice: the sequence has nothing there either.
#[lemma]
pub fn first_none<T: Copy>(s: &[T], xs: Seq<T>) {
    requires(s.first() == None);
    requires(s == xs);
    ensures(xs.get(0) == None);
    follows();
}

/// The rest of a slice after its first element is the rest of the sequence.
#[lemma]
pub fn rest_tail<T: Copy>(s: &[T], h: T, t: Seq<T>) {
    requires(s == seq![h, ..t]);
    requires(s.len() >= 1usize);
    ensures(&s[1..] == t);
    follows();
}
