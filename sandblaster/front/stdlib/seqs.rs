//! Lengths and elements of `take` and `skip`, for any element type.

use sandblaster::prelude::*;

/// The first `a.len()` elements of `a ++ r` are `a`; the rest is `r`.
#[lemma]
#[induction(a)]
pub fn take_skip_append<T: Copy>(a: Seq<T>, r: Seq<T>) {
    ensures(seq![..a, ..r].take(a.len()) == a && seq![..a, ..r].skip(a.len()) == r);
    match a {
        [_, rest @ ..] => {
            take_skip_append::<T>(rest, r);
            follows();
        }
        [] => follows(),
    }
}

/// [`take_skip_append`] at a length `n`.
#[lemma]
pub fn take_skip_at<T: Copy>(a: Seq<T>, r: Seq<T>, n: Nat) {
    requires(a.len() == n);
    ensures(seq![..a, ..r].take(n) == a && seq![..a, ..r].skip(n) == r);
    take_skip_append::<T>(a, r);
    rewrite(n == a.len());
    by_arithmetic();
}

/// The first `n` elements of a sequence of at least `n` are `n` long.
#[lemma]
#[decreases(n)]
pub fn take_len_le<T: Copy>(ys: Seq<T>, n: Int) {
    requires(0 <= n && n <= ys.len());
    ensures(ys.take(n as Nat).len() == n);
    match ys {
        [x, rest @ ..] => {
            if n == 0 {
                follows();
            } else {
                take_len_le::<T>(rest, n - 1);
                follows();
            }
        }
        [] => follows(),
    }
}

/// `skip` of at most the whole sequence leaves the rest of its length.
#[lemma]
#[decreases(j)]
pub fn skip_len<T: Copy>(ys: Seq<T>, j: Nat) {
    requires(j <= ys.len());
    ensures(ys.skip(j).len() + j == ys.len());
    match ys {
        [y, rest @ ..] => {
            if j == 0 {
                follows();
            } else {
                skip_len::<T>(rest, j - 1);
                follows();
            }
        }
        [] => follows(),
    }
}

/// `get(0)` after `skip(j)` is `get(j)`.
#[lemma]
#[decreases(j)]
pub fn skip_get0<T: Copy>(ys: Seq<T>, j: Nat) {
    ensures(ys.skip(j).get(0) == ys.get(j));
    match ys {
        [y, rest @ ..] => {
            if j == 0 {
                follows();
            } else {
                skip_get0::<T>(rest, j - 1);
                follows();
            }
        }
        [] => follows(),
    }
}

/// Inside a sequence, `get` finds something.
#[lemma]
#[decreases(n)]
pub fn get_some_len<T: Copy>(ys: Seq<T>, n: Nat) {
    requires(n < ys.len());
    ensures(ys.get(n).is_some());
    match ys {
        [y, rest @ ..] => {
            if n == 0 {
                follows();
            } else {
                get_some_len::<T>(rest, n - 1);
                follows();
            }
        }
        [] => by_contradiction(),
    }
}

/// A sequence of length 0 is empty.
#[lemma]
pub fn len_zero<T: Copy>(xs: Seq<T>) {
    requires(xs.len() == 0);
    ensures(xs == seq![]);
    match xs {
        [] => follows(),
        [_, _rest @ ..] => by_contradiction(),
    }
}

/// Skipping twice is skipping the sum.
#[lemma]
#[decreases(a)]
pub fn skip_skip<T: Copy>(r: Seq<T>, a: Nat, b: Nat) {
    ensures(r.skip(a).skip(b) == r.skip(a + b));
    match r {
        [_, rest @ ..] => {
            if a == 0 { follows(); } else { skip_skip::<T>(rest, a - 1, b); follows(); }
        }
        [] => follows(),
    }
}

/// … with the sum named.
#[lemma]
pub fn skip_skip_to<T: Copy>(r: Seq<T>, a: Nat, b: Nat, s: Nat) {
    requires(s == a + b);
    ensures(r.skip(a).skip(b) == r.skip(s));
    skip_skip::<T>(r, a, b);
    follows();
}

/// Taking all of a sequence is the sequence.
#[lemma]
pub fn take_all<T: Copy>(r: Seq<T>, n: Nat) {
    requires(n == r.len());
    ensures(r.take(n) == r);
    follows();
}

/// Taking fewer from a prefix is taking fewer.
#[lemma]
#[decreases(a)]
pub fn take_take<T: Copy>(r: Seq<T>, a: Nat, b: Nat) {
    requires(b <= a);
    ensures(r.take(a).take(b) == r.take(b));
    match r {
        [_, rest @ ..] => {
            if b == 0 { rewrite(b == 0); follows(); } else { take_take::<T>(rest, a - 1, b - 1); follows(); }
        }
        [] => follows(),
    }
}

/// The element at `c` of a prefix longer than `c` is the element at `c`.
#[lemma]
#[decreases(c)]
pub fn take_skip_first<T: Copy>(r: Seq<T>, n: Nat, c: Nat) {
    requires(c < n);
    ensures(r.take(n).skip(c).get(0) == r.skip(c).get(0));
    match r {
        [_, rest @ ..] => {
            if c == 0 { rewrite(c == 0); follows(); } else { take_skip_first::<T>(rest, n - 1, c - 1); follows(); }
        }
        [] => follows(),
    }
}

/// Appending after a sequence that ends with `b`.
#[lemma]
#[induction(l)]
pub fn append_snoc<T: Copy>(l: Seq<T>, b: T, q: Seq<T>) {
    ensures(seq![..seq![..l, b], ..q] == seq![..l, b, ..q]);
    match l {
        [_, rest @ ..] => { ih(rest, b, q); follows(); }
        [] => follows(),
    }
}

/// … ending with `b, c`.
#[lemma]
#[induction(l)]
pub fn append_snoc2<T: Copy>(l: Seq<T>, b: T, c: T, q: Seq<T>) {
    ensures(seq![..seq![..l, b, c], ..q] == seq![..l, b, c, ..q]);
    match l {
        [_, rest @ ..] => { ih(rest, b, c, q); follows(); }
        [] => follows(),
    }
}

/// Inside a prefix, a later window is the same window.
#[lemma]
#[decreases(a)]
pub fn take_skip_take<T: Copy>(r: Seq<T>, n: Nat, a: Nat, b: Nat) {
    requires(a + b <= n);
    ensures(r.take(n).skip(a).take(b) == r.skip(a).take(b));
    match r {
        [_, rest @ ..] => {
            if a == 0 {
                rewrite(a == 0);
                take_take::<T>(r, n, b);
                follows();
            } else {
                take_skip_take::<T>(rest, n - 1, a - 1, b);
                follows();
            }
        }
        [] => follows(),
    }
}

/// The first element of a non-empty prefix is the first element.
#[lemma]
pub fn take_first<T: Copy>(r: Seq<T>, n: Nat) {
    requires(1 <= n);
    ensures(r.take(n).get(0) == r.get(0));
    match r {
        [_, _rest @ ..] => follows(),
        [] => follows(),
    }
}

/// A window after a prefix is a prefix of the window.
#[lemma]
#[decreases(a)]
pub fn take_skip_comm<T: Copy>(r: Seq<T>, n: Nat, a: Nat) {
    requires(a <= n);
    ensures(r.take(n).skip(a) == r.skip(a).take(n - a));
    match r {
        [_, rest @ ..] => {
            if a == 0 { rewrite(a == 0); follows(); } else { take_skip_comm::<T>(rest, n - 1, a - 1); follows(); }
        }
        [] => follows(),
    }
}

/// Skipping nothing.
#[lemma]
pub fn skip_zero<T: Copy>(r: Seq<T>) {
    ensures(r.skip(0) == r);
    match r { [_, _rest @ ..] => follows(), [] => follows() }
}

/// A sequence is its first `n` elements, then the rest.
#[lemma]
pub fn take_then_skip<T: Copy>(b: Seq<T>, n: Nat) {
    ensures(seq![..b.take(n), ..b.skip(n)] == b);
    follows();
}

/// Skipping `i ≥ 1` past a first element.
#[lemma]
pub fn skip_cons<T: Copy>(z: T, rest: Seq<T>, i: Nat) {
    requires(i >= 1);
    ensures(seq![z, ..rest].skip(i) == rest.skip(i - 1));
    follows();
}

/// Taking `m ≥ 1` keeps the first element.
#[lemma]
pub fn take_cons<T: Copy>(z: T, rest: Seq<T>, m: Nat) {
    requires(m >= 1);
    ensures(seq![z, ..rest].take(m) == seq![z, ..rest.take(m - 1)]);
    follows();
}

/// Two lists with the same first `j` and the same rest are one list.
#[lemma]
pub fn split_eq<T: Copy>(xs: Seq<T>, ys: Seq<T>, j: Nat) {
    requires(xs.take(j) == ys.take(j) && xs.skip(j) == ys.skip(j));
    ensures(xs == ys);
    take_then_skip::<T>(xs, j);
    take_then_skip::<T>(ys, j);
    assert(seq![..xs.take(j), ..xs.skip(j)] == seq![..ys.take(j), ..ys.skip(j)], {
        rewrite(xs.take(j) == ys.take(j));
        rewrite(xs.skip(j) == ys.skip(j));
        follows();
    });
    rewrite_rev(take_then_skip::<T>(xs, j));
    rewrite_rev(take_then_skip::<T>(ys, j));
    follows();
}

/// The length of two sequences, one after the other.
#[lemma]
#[induction(a)]
pub fn len_app<T: Copy>(a: Seq<T>, b: Seq<T>) {
    ensures(seq![..a, ..b].len() == a.len() + b.len());
    match a {
        [_, r @ ..] => { len_app::<T>(r, b); follows(); }
        [] => follows(),
    }
}

/// An index at which `get` finds an element is below the length.
#[lemma]
#[induction(ys)]
pub fn get_bound<T: Copy>(ys: Seq<T>, n: Nat) {
    requires(0 <= n && ys.get(n).is_some());
    ensures(n < ys.len());
    match ys {
        [y, rest @ ..] => {
            if n == 0 {
                follows();
            } else {
                assert(seq![y, ..rest].get(n) == rest.get(n - 1), { follows(); });
                get_bound::<T>(rest, n - 1);
                follows();
            }
        }
        [] => by_contradiction(),
    }
}


/// Equal concatenations whose first parts have one length have equal parts.
#[lemma]
pub fn append_inj<T: Copy>(a1: Seq<T>, b1: Seq<T>, a2: Seq<T>, b2: Seq<T>) {
    requires(a1.len() == a2.len() && seq![..a1, ..b1] == seq![..a2, ..b2]);
    ensures(a1 == a2 && b1 == b2);
    match (a1, a2) {
        ([_, r1 @ ..], [_, r2 @ ..]) => { append_inj::<T>(r1, b1, r2, b2); follows(); }
        ([], []) => follows(),
        _ => follows(),
    }
}

/// Cutting a concatenation past its first part …
#[lemma]
#[induction(a)]
pub fn cut_after<T: Copy>(a: Seq<T>, r: Seq<T>, n: Nat) {
    requires(a.len() <= n);
    ensures(seq![..a, ..r].take(n) == seq![..a, ..r.take(n - a.len())] && seq![..a, ..r].skip(n) == r.skip(n - a.len()));
    match a {
        [_, rest @ ..] => { cut_after::<T>(rest, r, n - 1); follows(); }
        [] => follows(),
    }
}

/// … and within it.
#[lemma]
#[induction(a)]
pub fn cut_within<T: Copy>(a: Seq<T>, r: Seq<T>, n: Nat) {
    requires(n <= a.len());
    ensures(seq![..a, ..r].take(n) == a.take(n) && seq![..a, ..r].skip(n) == seq![..a.skip(n), ..r]);
    match a {
        [_, rest @ ..] => { if n > 0 { cut_within::<T>(rest, r, n - 1); follows(); } else { follows(); } }
        [] => { skip_zero::<T>(r); take_zero::<T>(r); rewrite(n == 0); follows(); }
    }
}

/// Taking nothing gives nothing.
#[lemma]
pub fn take_zero<T: Copy>(r: Seq<T>) {
    ensures(r.take(0) == seq![]);
    match r { [_, _r @ ..] => follows(), [] => follows() }
}

/// The element after a prefix is at the prefix's length.
#[lemma]
#[induction(a)]
pub fn get_after<T: Copy>(a: Seq<T>, x: T) {
    ensures(seq![..a, x].get(a.len()) == Some(x));
    match a {
        [_, r @ ..] => { get_after::<T>(r, x); follows(); }
        [] => follows(),
    }
}

/// The first element of a nonempty sequence, as a sequence (`d` stands in past the end).
#[lemma]
pub fn take_one<T: Copy>(xs: Seq<T>, d: T) {
    requires(1 <= xs.len());
    ensures(xs.take(1) == seq![xs.get(0).unwrap_or(d)]);
    match xs {
        [x, xr @ ..] => { take_cons::<T>(x, xr, 1); follows(); }
        [] => by_contradiction(),
    }
}

/// The last element of a sequence of `m + 1`, as a sequence.
#[lemma]
pub fn skip_last<T: Copy>(xs: Seq<T>, m: Nat, d: T) {
    requires(xs.len() == m + 1);
    ensures(xs.skip(m) == seq![xs.get(m).unwrap_or(d)]);
    match xs {
        [x, xr @ ..] => {
            if m == 0 { len_zero::<T>(xr); rewrite(m == 0); follows(); } else { skip_last::<T>(xr, m - 1, d); follows(); }
        }
        [] => by_contradiction(),
    }
}

/// Two nonempty sequences with one first element and one rest are one sequence.
#[lemma]
pub fn first_ext<T: Copy>(xs: Seq<T>, ys: Seq<T>, d: T) {
    requires(1 <= xs.len() && 1 <= ys.len());
    requires(xs.get(0).unwrap_or(d) == ys.get(0).unwrap_or(d) && xs.skip(1) == ys.skip(1));
    ensures(xs == ys);
    take_one::<T>(xs, d);
    take_one::<T>(ys, d);
    split_eq::<T>(xs, ys, 1);
}

/// Two sequences of `m + 1` with one first `m` and one last element are one sequence.
#[lemma]
pub fn last_ext<T: Copy>(xs: Seq<T>, ys: Seq<T>, m: Nat, d: T) {
    requires(xs.len() == m + 1 && ys.len() == m + 1);
    requires(xs.take(m) == ys.take(m) && xs.get(m).unwrap_or(d) == ys.get(m).unwrap_or(d));
    ensures(xs == ys);
    skip_last::<T>(xs, m, d);
    skip_last::<T>(ys, m, d);
    split_eq::<T>(xs, ys, m);
}

/// Sequences of one length, cut at one place, have first parts and rests of one length.
#[lemma]
pub fn take_skip_same_len<T: Copy, U: Copy>(xs: Seq<T>, ys: Seq<U>, j: Nat) {
    requires(xs.len() == ys.len());
    ensures(xs.take(j).len() == ys.take(j).len() && xs.skip(j).len() == ys.skip(j).len());
    if j <= xs.len() { follows(); } else { follows(); }
}
