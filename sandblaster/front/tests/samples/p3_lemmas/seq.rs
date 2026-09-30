//! The generic `Seq` library (`lemmas/seq_lib.core`), proved at an element type
//! `E` that the generator generalizes to a type parameter `T`.

/// The element type (generalized to `T` in the library).
#[derive(Clone, Copy)]
pub struct E { v: u8 }

/// `get` of an index in range.
#[lemma]
#[induction(l)]
fn get_index(l: Seq<E>, i: Nat) {
    requires(i < l.len());
    ensures(l.get(i) == Some(l[i]));
    match l {
        [] => follows(),
        [x, t @ ..] => {
            if i == 0 { follows(); } else { ih(t, i - 1); follows(); }
        }
    }
}

/// `get` past the end.
#[lemma]
#[induction(l)]
fn get_past(l: Seq<E>, i: Nat) {
    requires(l.len() <= i);
    ensures(l.get(i) == None);
    match l {
        [] => follows(),
        [x, t @ ..] => { ih(t, i - 1); follows(); }
    }
}

/// `get` of a cons at a positive index.
#[lemma]
fn get_cons_succ(x: E, t: Seq<E>, i: Nat) {
    requires(0 < i);
    ensures(seq![x, ..t].get(i) == t.get(i - 1));
    follows();
}

/// `get` after `skip`.
#[lemma]
#[induction(l)]
fn get_skip(l: Seq<E>, k: Nat, i: Nat) {
    ensures(l.skip(k).get(i) == l.get(i + k));
    match l {
        [] => follows(),
        [x, t @ ..] => {
            if k == 0 { follows(); } else { ih(t, k - 1, i); follows(); }
        }
    }
}

/// `get` after `take`, below the length taken.
#[lemma]
#[induction(l)]
fn get_take(l: Seq<E>, n: Nat, i: Nat) {
    requires(i < n);
    ensures(l.take(n).get(i) == l.get(i));
    match l {
        [] => follows(),
        [x, t @ ..] => {
            if i == 0 { follows(); } else { ih(t, n - 1, i - 1); follows(); }
        }
    }
}

/// `get` after `take`, at or past the length taken.
#[lemma]
#[induction(l)]
fn get_take_past(l: Seq<E>, n: Nat, i: Nat) {
    requires(n <= i);
    ensures(l.take(n).get(i) == None);
    match l {
        [] => follows(),
        [x, t @ ..] => {
            if n == 0 { follows(); } else { ih(t, n - 1, i - 1); follows(); }
        }
    }
}

/// `get` in the first part of an append.
#[lemma]
#[induction(xs)]
fn get_append(xs: Seq<E>, ys: Seq<E>, i: Nat) {
    requires(i < xs.len());
    ensures(seq![..xs, ..ys].get(i) == xs.get(i));
    match xs {
        [] => follows(),
        [x, t @ ..] => {
            if i == 0 { follows(); } else { ih(t, ys, i - 1); follows(); }
        }
    }
}

/// `get` in the second part of an append.
#[lemma]
#[induction(xs)]
fn get_append_past(xs: Seq<E>, ys: Seq<E>, i: Nat) {
    requires(xs.len() <= i);
    ensures(seq![..xs, ..ys].get(i) == ys.get(i - xs.len()));
    match xs {
        [] => follows(),
        [x, t @ ..] => { ih(t, ys, i - 1); follows(); }
    }
}

/// `skip` of `skip`.
#[lemma]
#[induction(l)]
fn skip_skip(l: Seq<E>, a: Nat, b: Nat) {
    ensures(l.skip(a).skip(b) == l.skip(a + b));
    match l {
        [] => follows(),
        [x, t @ ..] => {
            if a == 0 { follows(); } else { ih(t, a - 1, b); follows(); }
        }
    }
}

/// `skip` within the first part of an append.
#[lemma]
#[induction(xs)]
fn skip_append(xs: Seq<E>, ys: Seq<E>, k: Nat) {
    requires(k <= xs.len());
    ensures(seq![..xs, ..ys].skip(k) == seq![..xs.skip(k), ..ys]);
    if k == 0 {
        rewrite(k == 0);
        follows();
    } else {
        match xs {
            [] => follows(),
            [x, t @ ..] => { ih(t, ys, k - 1); follows(); }
        }
    }
}

/// `skip` past the first part of an append.
#[lemma]
#[induction(xs)]
fn skip_append_past(xs: Seq<E>, ys: Seq<E>, k: Nat) {
    requires(xs.len() <= k);
    ensures(seq![..xs, ..ys].skip(k) == ys.skip(k - xs.len()));
    match xs {
        [] => follows(),
        [x, t @ ..] => { ih(t, ys, k - 1); follows(); }
    }
}

/// `take` within the first part of an append.
#[lemma]
#[induction(xs)]
fn take_append(xs: Seq<E>, ys: Seq<E>, k: Nat) {
    requires(k <= xs.len());
    ensures(seq![..xs, ..ys].take(k) == xs.take(k));
    if k == 0 {
        rewrite(k == 0);
        follows();
    } else {
        match xs {
            [] => follows(),
            [x, t @ ..] => { ih(t, ys, k - 1); follows(); }
        }
    }
}

/// `take` past the first part of an append.
#[lemma]
#[induction(xs)]
fn take_append_past(xs: Seq<E>, ys: Seq<E>, k: Nat) {
    requires(xs.len() <= k);
    ensures(seq![..xs, ..ys].take(k) == seq![..xs, ..ys.take(k - xs.len())]);
    match xs {
        [] => follows(),
        [x, t @ ..] => { ih(t, ys, k - 1); follows(); }
    }
}

/// `skip` of a cons by a positive count.
#[lemma]
fn skip_cons(x: E, t: Seq<E>, k: Nat) {
    requires(0 < k);
    ensures(seq![x, ..t].skip(k) == t.skip(k - 1));
    follows();
}

/// `take` of a cons by a positive count.
#[lemma]
fn take_cons(x: E, t: Seq<E>, k: Nat) {
    requires(0 < k);
    ensures(seq![x, ..t].take(k) == seq![x, ..t.take(k - 1)]);
    follows();
}

/// `skip` past the end.
#[lemma]
#[induction(l)]
fn skip_past(l: Seq<E>, k: Nat) {
    requires(l.len() <= k);
    ensures(l.skip(k) == seq![]);
    match l {
        [] => follows(),
        [x, t @ ..] => { ih(t, k - 1); follows(); }
    }
}

/// `take` of at least the length.
#[lemma]
#[induction(l)]
fn take_past(l: Seq<E>, k: Nat) {
    requires(l.len() <= k);
    ensures(l.take(k) == l);
    match l {
        [] => follows(),
        [x, t @ ..] => { ih(t, k - 1); follows(); }
    }
}

/// Element `i` after `skip`.
#[lemma]
fn index_skip(l: Seq<E>, k: Nat, i: Nat) {
    requires(i + k < l.len());
    ensures(l.skip(k)[i] == l[i + k]);
    calc! {
        Some(l.skip(k)[i])
            == l.skip(k).get(i) by { get_index(l.skip(k), i); follows(); };
            == l.get(i + k) by { get_skip(l, k, i); follows(); };
            == Some(l[i + k]) by { get_index(l, i + k); follows(); };
    }
    follows();
}

/// Element `i` after `take`.
#[lemma]
fn index_take(l: Seq<E>, n: Nat, i: Nat) {
    requires(i < n && n <= l.len());
    ensures(l.take(n)[i] == l[i]);
    calc! {
        Some(l.take(n)[i])
            == l.take(n).get(i) by { get_index(l.take(n), i); follows(); };
            == l.get(i) by { get_take(l, n, i); follows(); };
            == Some(l[i]) by { get_index(l, i); follows(); };
    }
    follows();
}

/// Element `i` of an append, in the first part.
#[lemma]
fn index_append(xs: Seq<E>, ys: Seq<E>, i: Nat) {
    requires(i < xs.len());
    ensures(seq![..xs, ..ys][i] == xs[i]);
    calc! {
        Some(seq![..xs, ..ys][i])
            == seq![..xs, ..ys].get(i) by { get_index(seq![..xs, ..ys], i); follows(); };
            == xs.get(i) by { get_append(xs, ys, i); follows(); };
            == Some(xs[i]) by { get_index(xs, i); follows(); };
    }
    follows();
}

/// Element `i` of an append, in the second part.
#[lemma]
fn index_append_past(xs: Seq<E>, ys: Seq<E>, i: Nat) {
    requires(xs.len() <= i && i < xs.len() + ys.len());
    ensures(seq![..xs, ..ys][i] == ys[i - xs.len()]);
    calc! {
        Some(seq![..xs, ..ys][i])
            == seq![..xs, ..ys].get(i) by { get_index(seq![..xs, ..ys], i); follows(); };
            == ys.get(i - xs.len()) by { get_append_past(xs, ys, i); follows(); };
            == Some(ys[i - xs.len()]) by { get_index(ys, i - xs.len()); follows(); };
    }
    follows();
}

/// `update` past the first part of an append.
#[lemma]
#[induction(xs)]
fn update_append_past(xs: Seq<E>, ys: Seq<E>, i: Nat, v: E) {
    requires(xs.len() <= i);
    ensures(seq![..xs, ..ys].update(i, v) == seq![..xs, ..ys.update(i - xs.len(), v)]);
    match xs {
        [] => follows(),
        [x, t @ ..] => { ih(t, ys, i - 1, v); follows(); }
    }
}

/// The first element after updating it (the prefix of a buffer written at
/// its front).
#[lemma]
fn take_update_one(l: Seq<E>, v: E) {
    requires(0 < l.len());
    ensures(l.update(0, v).take(1) == seq![v]);
    match l {
        [] => follows(),
        [x, t @ ..] => follows(),
    }
}

/// Equal indices give equal elements (whatever their bound proofs).
#[lemma]
fn index_eq(l: Seq<E>, i: Nat, j: Nat) {
    requires(i == j);
    requires(j < l.len());
    ensures(l[i] == l[j]);
    follows();
}

/// A sequence of length 0 is empty.
#[lemma]
fn len_zero(l: Seq<E>) {
    requires(l.len() == 0);
    ensures(l == seq![]);
    match l {
        [] => follows(),
        [x, t @ ..] => follows(),
    }
}

/// A sequence of length `n + 1` is its first `n` elements followed by element `n`.
#[lemma]
#[induction(l)]
fn take_snoc(l: Seq<E>, n: Nat) {
    requires(n + 1 == l.len());
    ensures(seq![..l.take(n), l[n]] == l);
    match l {
        [] => follows(),
        [x, t @ ..] => {
            if n <= 0 {
                len_zero(t);
                sandblaster::lemmas::seq::index_cons_zero::<E>(x, t, n);
                follows();
            } else {
                ih(t, n - 1);
                take_cons(x, t, n);
                sandblaster::lemmas::seq::index_cons_succ::<E>(x, t, n);
                follows();
            }
        }
    }
}
