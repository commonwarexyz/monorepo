//! Folds, maps, scans and pairwise relations over sequences, for any element types and any
//! functions: ghost function values `fn(A, T) -> A` (DESIGN.md §13.2). Every law is proven once
//! here and instantiated by naming its function (`fold_left_append(xs, ys, a, f)`). Argument order
//! follows Rust's iterators: the sequence, then the start, then the function.

use sandblaster::prelude::*;

// ---------------------------------------------------------------------------------------------
// Definitions.
// ---------------------------------------------------------------------------------------------

/// `f(..f(f(a, x₀), x₁).., xₙ)`.
#[spec]
#[example(fold_left(seq![1 as Int, 2 as Int], 0 as Int, |a: Int, x: Int| 2 * a + x) == 4)]
pub fn fold_left<T: Copy, A: Copy>(xs: Seq<T>, a: A, f: fn(A, T) -> A) -> A {
    match xs {
        [x, rest @ ..] => fold_left(rest, f(a, x), f),
        [] => a,
    }
}

/// `f(x₀, f(x₁, .. f(xₙ, z)))`.
#[spec]
#[example(fold_right(seq![1 as Int, 2 as Int], 0 as Int, |x: Int, a: Int| 2 * a + x) == 5)]
pub fn fold_right<T: Copy, A: Copy>(xs: Seq<T>, z: A, f: fn(T, A) -> A) -> A {
    match xs {
        [x, rest @ ..] => f(x, fold_right(rest, z, f)),
        [] => z,
    }
}

/// The right fold of the non-empty sequence `a, x₀, .., xₙ`, seeded with its last element:
/// `f(a, f(x₀, .. f(xₙ₋₁, xₙ)))`.
#[spec]
#[example(fold_right1(1 as Int, seq![2 as Int, 3 as Int], |x: Int, a: Int| 10 * x + a) == 33)]
pub fn fold_right1<T: Copy>(a: T, xs: Seq<T>, f: fn(T, T) -> T) -> T {
    match xs {
        [x, rest @ ..] => f(a, fold_right1(x, rest, f)),
        [] => a,
    }
}

/// `f(x₀), .., f(xₙ)`.
#[spec]
#[example(map(seq![1 as Int, 2 as Int], |x: Int| 2 * x) == seq![2 as Int, 4 as Int])]
pub fn map<T: Copy, U: Copy>(xs: Seq<T>, f: fn(T) -> U) -> Seq<U> {
    match xs {
        [x, rest @ ..] => seq![f(x), ..map(rest, f)],
        [] => seq![],
    }
}

/// Every element satisfies `p`.
#[spec]
#[example(all(seq![1 as Int, 2 as Int], |x: Int| x > 0) && !all(seq![1 as Int, 0 as Int], |x: Int| x > 0))]
pub fn all<T: Copy>(xs: Seq<T>, p: fn(T) -> bool) -> bool {
    match xs {
        [x, rest @ ..] => p(x) && all(rest, p),
        [] => true,
    }
}

/// Some element satisfies `p`.
#[spec]
#[example(any(seq![0 as Int, 2 as Int], |x: Int| x > 0) && !any(seq![0 as Int], |x: Int| x > 0))]
pub fn any<T: Copy>(xs: Seq<T>, p: fn(T) -> bool) -> bool {
    match xs {
        [x, rest @ ..] => p(x) || any(rest, p),
        [] => false,
    }
}

/// Two sequences of one length whose elements are related by `r` one by one.
#[spec]
#[example(all2(seq![1 as Int], seq![2 as Int], |x: Int, y: Int| x < y) && !all2(seq![1 as Int], seq![2 as Int, 3 as Int], |x: Int, y: Int| x < y))]
pub fn all2<T: Copy, U: Copy>(xs: Seq<T>, ys: Seq<U>, r: fn(T, U) -> bool) -> bool {
    match xs {
        [x, xr @ ..] => match ys {
            [y, yr @ ..] => r(x, y) && all2(xr, yr, r),
            [] => false,
        },
        [] => ys.len() == 0,
    }
}

/// The pairs `(x₀, y₀), ..` up to the shorter length.
#[spec]
#[example(zip(seq![1 as Int, 2 as Int], seq![true]) == seq![(1 as Int, true)])]
pub fn zip<T: Copy, U: Copy>(xs: Seq<T>, ys: Seq<U>) -> Seq<(T, U)> {
    match xs {
        [x, xr @ ..] => match ys {
            [y, yr @ ..] => seq![(x, y), ..zip(xr, yr)],
            [] => seq![],
        },
        [] => seq![],
    }
}

/// The running left fold: `a, f(a, x₀), f(f(a, x₀), x₁), ..`, one longer than `xs`.
#[spec]
#[example(scan(seq![1 as Int, 2 as Int], 0 as Int, |a: Int, x: Int| a + x) == seq![0 as Int, 1 as Int, 3 as Int])]
pub fn scan<T: Copy, A: Copy>(xs: Seq<T>, a: A, f: fn(A, T) -> A) -> Seq<A> {
    match xs {
        [x, rest @ ..] => seq![a, ..scan(rest, f(a, x), f)],
        [] => seq![a],
    }
}

// ---------------------------------------------------------------------------------------------
// Folds.
// ---------------------------------------------------------------------------------------------

/// Folding from the left in two stretches: the second continues from the first's result.
#[lemma]
pub fn fold_left_append<T: Copy, A: Copy>(xs: Seq<T>, ys: Seq<T>, a: A, f: fn(A, T) -> A) {
    ensures(fold_left(seq![..xs, ..ys], a, f) == fold_left(ys, fold_left(xs, a, f), f));
    match xs {
        [x, rest @ ..] => { fold_left_append(rest, ys, f(a, x), f); follows(); }
        [] => follows(),
    }
}

/// Folding from the right in two stretches: the first folds onto the second's result.
#[lemma]
pub fn fold_right_append<T: Copy, A: Copy>(xs: Seq<T>, ys: Seq<T>, z: A, f: fn(T, A) -> A) {
    ensures(fold_right(seq![..xs, ..ys], z, f) == fold_right(xs, fold_right(ys, z, f), f));
    match xs {
        [x, rest @ ..] => { fold_right_append(rest, ys, z, f); follows(); }
        [] => follows(),
    }
}

/// Folding from the right onto a folded suffix is folding onto the suffix itself.
#[lemma]
pub fn fold_right1_append<T: Copy>(a: T, xs: Seq<T>, y: T, ys: Seq<T>, f: fn(T, T) -> T) {
    ensures(fold_right1(a, seq![..xs, fold_right1(y, ys, f)], f) == fold_right1(a, seq![..xs, y, ..ys], f));
    match xs {
        [x, rest @ ..] => { fold_right1_append(x, rest, y, ys, f); follows(); }
        [] => follows(),
    }
}

/// A left fold over a map is one left fold (fusion).
#[lemma]
pub fn fold_left_map<T: Copy, U: Copy, A: Copy>(xs: Seq<T>, a: A, g: fn(T) -> U, f: fn(A, U) -> A) {
    ensures(fold_left(map(xs, g), a, f) == fold_left(xs, a, |b: A, x: T| f(b, g(x))));
    match xs {
        [x, rest @ ..] => { fold_left_map(rest, f(a, g(x)), g, f); follows(); }
        [] => follows(),
    }
}

/// A right fold over a map is one right fold (fusion).
#[lemma]
pub fn fold_right_map<T: Copy, U: Copy, A: Copy>(xs: Seq<T>, z: A, g: fn(T) -> U, f: fn(U, A) -> A) {
    ensures(fold_right(map(xs, g), z, f) == fold_right(xs, z, |x: T, b: A| f(g(x), b)));
    match xs {
        [x, rest @ ..] => { fold_right_map(rest, z, g, f); follows(); }
        [] => follows(),
    }
}

/// Induction for left folds: an invariant of the start that every step keeps holds of the fold.
#[lemma]
pub fn fold_left_inv<T: Copy, A: Copy>(xs: Seq<T>, a: A, f: fn(A, T) -> A, p: fn(A) -> bool) {
    requires(p(a) && forall(|b: A, x: T| implies(p(b), p(f(b, x)))));
    ensures(p(fold_left(xs, a, f)));
    match xs {
        [x, rest @ ..] => { fold_left_inv(rest, f(a, x), f, p); follows(); }
        [] => follows(),
    }
}

/// [`fold_left_inv`] for steps that keep the invariant only on elements satisfying `q`.
#[lemma]
pub fn fold_left_all_inv<T: Copy, A: Copy>(xs: Seq<T>, a: A, f: fn(A, T) -> A, p: fn(A) -> bool, q: fn(T) -> bool) {
    requires(p(a) && all(xs, q) && forall(|b: A, x: T| implies(p(b) && q(x), p(f(b, x)))));
    ensures(p(fold_left(xs, a, f)));
    match xs {
        [x, rest @ ..] => { fold_left_all_inv(rest, f(a, x), f, p, q); follows(); }
        [] => follows(),
    }
}

/// Induction for [`fold_right1`]: a property of every element that every step keeps.
#[lemma]
pub fn fold_right1_inv<T: Copy>(a: T, xs: Seq<T>, f: fn(T, T) -> T, p: fn(T) -> bool) {
    requires(p(a) && all(xs, p) && forall(|x: T, y: T| implies(p(x) && p(y), p(f(x, y)))));
    ensures(p(fold_right1(a, xs, f)));
    match xs {
        [x, rest @ ..] => { fold_right1_inv(x, rest, f, p); follows(); }
        [] => follows(),
    }
}

/// Left folds of related starts over related elements are related, when each step keeps the
/// relation.
#[lemma]
pub fn fold_left_rel<T: Copy, U: Copy, A: Copy, B: Copy>(xs: Seq<T>, ys: Seq<U>, a: A, b: B, f: fn(A, T) -> A, g: fn(B, U) -> B, r: fn(A, B) -> bool, s: fn(T, U) -> bool) {
    requires(r(a, b) && all2(xs, ys, s));
    requires(forall(|a: A, b: B, x: T, y: U| implies(r(a, b) && s(x, y), r(f(a, x), g(b, y)))));
    ensures(r(fold_left(xs, a, f), fold_left(ys, b, g)));
    match (xs, ys) {
        ([x, xr @ ..], [y, yr @ ..]) => { fold_left_rel(xr, yr, f(a, x), g(b, y), f, g, r, s); follows(); }
        _ => follows(),
    }
}

/// Related left folds over sequences of one length have related starts and elements, when each
/// step's result determines its parts that far.
#[lemma]
pub fn fold_left_rel_back<T: Copy, U: Copy, A: Copy, B: Copy>(xs: Seq<T>, ys: Seq<U>, a: A, b: B, f: fn(A, T) -> A, g: fn(B, U) -> B, r: fn(A, B) -> bool, s: fn(T, U) -> bool) {
    requires(r(fold_left(xs, a, f), fold_left(ys, b, g)) && xs.len() == ys.len());
    requires(forall(|a: A, b: B, x: T, y: U| implies(r(f(a, x), g(b, y)), r(a, b) && s(x, y))));
    ensures(r(a, b) && all2(xs, ys, s));
    match (xs, ys) {
        ([x, xr @ ..], [y, yr @ ..]) => { fold_left_rel_back(xr, yr, f(a, x), g(b, y), f, g, r, s); follows(); }
        ([], []) => follows(),
        _ => by_contradiction(),
    }
}

/// [`fold_left_rel`] for [`fold_right1`].
#[lemma]
pub fn fold_right1_rel<T: Copy, U: Copy>(a: T, xs: Seq<T>, b: U, ys: Seq<U>, f: fn(T, T) -> T, g: fn(U, U) -> U, r: fn(T, U) -> bool) {
    requires(r(a, b) && all2(xs, ys, r));
    requires(forall(|a: T, b: U, x: T, y: U| implies(r(a, b) && r(x, y), r(f(a, x), g(b, y)))));
    ensures(r(fold_right1(a, xs, f), fold_right1(b, ys, g)));
    match (xs, ys) {
        ([x, xr @ ..], [y, yr @ ..]) => { fold_right1_rel(x, xr, y, yr, f, g, r); follows(); }
        _ => follows(),
    }
}

/// [`fold_left_rel_back`] for [`fold_right1`].
#[lemma]
pub fn fold_right1_rel_back<T: Copy, U: Copy>(a: T, xs: Seq<T>, b: U, ys: Seq<U>, f: fn(T, T) -> T, g: fn(U, U) -> U, r: fn(T, U) -> bool) {
    requires(r(fold_right1(a, xs, f), fold_right1(b, ys, g)) && xs.len() == ys.len());
    requires(forall(|a: T, b: U, x: T, y: U| implies(r(f(a, x), g(b, y)), r(a, b) && r(x, y))));
    ensures(r(a, b) && all2(xs, ys, r));
    match (xs, ys) {
        ([x, xr @ ..], [y, yr @ ..]) => { fold_right1_rel_back(x, xr, y, yr, f, g, r); follows(); }
        ([], []) => follows(),
        _ => by_contradiction(),
    }
}

/// Equal left folds over sequences of one length have equal starts and elements, when each
/// step's result determines its parts.
#[lemma]
pub fn fold_left_inj<T: Copy, A: Copy>(xs: Seq<T>, ys: Seq<T>, a: A, b: A, f: fn(A, T) -> A) {
    requires(fold_left(xs, a, f) == fold_left(ys, b, f) && xs.len() == ys.len());
    requires(forall(|a: A, b: A, x: T, y: T| implies(f(a, x) == f(b, y), a == b && x == y)));
    ensures(a == b && xs == ys);
    match (xs, ys) {
        ([x, xr @ ..], [y, yr @ ..]) => { fold_left_inj(xr, yr, f(a, x), f(b, y), f); follows(); }
        ([], []) => follows(),
        _ => by_contradiction(),
    }
}

/// [`fold_left_inj`] for [`fold_right1`].
#[lemma]
pub fn fold_right1_inj<T: Copy>(a: T, xs: Seq<T>, b: T, ys: Seq<T>, f: fn(T, T) -> T) {
    requires(fold_right1(a, xs, f) == fold_right1(b, ys, f) && xs.len() == ys.len());
    requires(forall(|a: T, b: T, x: T, y: T| implies(f(a, x) == f(b, y), a == b && x == y)));
    ensures(a == b && xs == ys);
    match (xs, ys) {
        ([x, xr @ ..], [y, yr @ ..]) => { fold_right1_inj(x, xr, y, yr, f); follows(); }
        ([], []) => follows(),
        _ => by_contradiction(),
    }
}

// ---------------------------------------------------------------------------------------------
// Maps.
// ---------------------------------------------------------------------------------------------

/// A map has the length of its sequence.
#[lemma]
pub fn map_len<T: Copy, U: Copy>(xs: Seq<T>, f: fn(T) -> U) {
    ensures(map(xs, f).len() == xs.len());
    by_induction(xs);
}

/// A map of two stretches is the two maps.
#[lemma]
pub fn map_append<T: Copy, U: Copy>(xs: Seq<T>, ys: Seq<T>, f: fn(T) -> U) {
    ensures(map(seq![..xs, ..ys], f) == seq![..map(xs, f), ..map(ys, f)]);
    by_induction(xs);
}

/// The first `j` elements of a map, and the rest, are the maps of the first `j` and of the rest.
#[lemma]
pub fn map_take_skip<T: Copy, U: Copy>(xs: Seq<T>, j: Nat, f: fn(T) -> U) {
    ensures(map(xs, f).take(j) == map(xs.take(j), f) && map(xs, f).skip(j) == map(xs.skip(j), f));
    match xs {
        [_, rest @ ..] => { if j > 0 { map_take_skip(rest, j - 1, f); follows(); } else { follows(); } }
        [] => follows(),
    }
}

/// A map by an injective function is injective.
#[lemma]
pub fn map_inj<T: Copy, U: Copy>(xs: Seq<T>, ys: Seq<T>, f: fn(T) -> U) {
    requires(map(xs, f) == map(ys, f) && forall(|x: T, y: T| implies(f(x) == f(y), x == y)));
    ensures(xs == ys);
    match (xs, ys) {
        ([_, xr @ ..], [_, yr @ ..]) => { map_inj(xr, yr, f); follows(); }
        ([], []) => follows(),
        _ => by_contradiction(),
    }
}

/// A map of a map is one map (fusion).
#[lemma]
pub fn map_map<T: Copy, U: Copy, V: Copy>(xs: Seq<T>, g: fn(T) -> U, f: fn(U) -> V) {
    ensures(map(map(xs, g), f) == map(xs, |x: T| f(g(x))));
    by_induction(xs);
}

/// Every element of a map satisfies `p` exactly when every element satisfies `p` after `f`.
#[lemma]
pub fn all_map<T: Copy, U: Copy>(xs: Seq<T>, f: fn(T) -> U, p: fn(U) -> bool) {
    ensures(all(map(xs, f), p) == all(xs, |x: T| p(f(x))));
    match xs {
        [x, rest @ ..] => { all_map(rest, f, p); unfold(all); by_cases(p(f(x))); }
        [] => follows(),
    }
}

// ---------------------------------------------------------------------------------------------
// `all` and `any`.
// ---------------------------------------------------------------------------------------------

/// One step of [`all`].
#[lemma]
pub fn all_cons<T: Copy>(x: T, rest: Seq<T>, p: fn(T) -> bool) {
    ensures(all(seq![x, ..rest], p) == (p(x) && all(rest, p)));
    follows();
}

/// The first element, and every later one, of a sequence whose every element satisfies `p`.
#[lemma]
pub fn all_head<T: Copy>(x: T, rest: Seq<T>, p: fn(T) -> bool) {
    requires(all(seq![x, ..rest], p));
    ensures(p(x) && all(rest, p));
    follows();
}

/// Every element of two stretches: every element of each.
#[lemma]
pub fn all_append<T: Copy>(xs: Seq<T>, ys: Seq<T>, p: fn(T) -> bool) {
    ensures(all(seq![..xs, ..ys], p) == (all(xs, p) && all(ys, p)));
    by_induction(xs);
}

/// The first `j` elements, and the rest, of a sequence whose every element satisfies `p`.
#[lemma]
pub fn all_take_skip<T: Copy>(xs: Seq<T>, j: Nat, p: fn(T) -> bool) {
    requires(all(xs, p));
    ensures(all(xs.take(j), p) && all(xs.skip(j), p));
    match xs {
        [_, rest @ ..] => { if j > 0 { all_take_skip(rest, j - 1, p); follows(); } else { follows(); } }
        [] => follows(),
    }
}

/// A property implied by one every element has.
#[lemma]
pub fn all_implies<T: Copy>(xs: Seq<T>, p: fn(T) -> bool, q: fn(T) -> bool) {
    requires(all(xs, p) && forall(|x: T| implies(p(x), q(x))));
    ensures(all(xs, q));
    by_induction(xs);
}

/// Some element of two stretches: some element of either.
#[lemma]
pub fn any_append<T: Copy>(xs: Seq<T>, ys: Seq<T>, p: fn(T) -> bool) {
    ensures(any(seq![..xs, ..ys], p) == (any(xs, p) || any(ys, p)));
    by_induction(xs);
}

/// Every element satisfies `p` exactly when none fails it.
#[lemma]
pub fn all_not_any<T: Copy>(xs: Seq<T>, p: fn(T) -> bool) {
    ensures(all(xs, p) == !any(xs, |x: T| !p(x)));
    by_induction(xs);
}

// ---------------------------------------------------------------------------------------------
// Pairwise relations.
// ---------------------------------------------------------------------------------------------

/// One step of [`all2`].
#[lemma]
pub fn all2_cons<T: Copy, U: Copy>(x: T, xr: Seq<T>, y: U, yr: Seq<U>, r: fn(T, U) -> bool) {
    ensures(all2(seq![x, ..xr], seq![y, ..yr], r) == (r(x, y) && all2(xr, yr, r)));
    follows();
}

/// Related sequences have one length.
#[lemma]
pub fn all2_len<T: Copy, U: Copy>(xs: Seq<T>, ys: Seq<U>, r: fn(T, U) -> bool) {
    requires(all2(xs, ys, r));
    ensures(xs.len() == ys.len());
    match (xs, ys) {
        ([_, xr @ ..], [_, yr @ ..]) => { all2_len(xr, yr, r); follows(); }
        _ => follows(),
    }
}

/// Sequences related in two stretches are related.
#[lemma]
pub fn all2_append<T: Copy, U: Copy>(xs: Seq<T>, ys: Seq<T>, us: Seq<U>, vs: Seq<U>, r: fn(T, U) -> bool) {
    requires(all2(xs, us, r) && all2(ys, vs, r));
    ensures(all2(seq![..xs, ..ys], seq![..us, ..vs], r));
    match (xs, us) {
        ([_, xr @ ..], [_, ur @ ..]) => { all2_append(xr, ys, ur, vs, r); follows(); }
        _ => follows(),
    }
}

/// Related sequences, cut at one place, are related on both sides.
#[lemma]
pub fn all2_take_skip<T: Copy, U: Copy>(xs: Seq<T>, ys: Seq<U>, j: Nat, r: fn(T, U) -> bool) {
    requires(all2(xs, ys, r));
    ensures(all2(xs.take(j), ys.take(j), r) && all2(xs.skip(j), ys.skip(j), r));
    match (xs, ys) {
        ([_, xr @ ..], [_, yr @ ..]) => { if j > 0 { all2_take_skip(xr, yr, j - 1, r); follows(); } else { follows(); } }
        _ => follows(),
    }
}

/// A relation implied by one the elements are in.
#[lemma]
pub fn all2_implies<T: Copy, U: Copy>(xs: Seq<T>, ys: Seq<U>, r: fn(T, U) -> bool, s: fn(T, U) -> bool) {
    requires(all2(xs, ys, r) && forall(|x: T, y: U| implies(r(x, y), s(x, y))));
    ensures(all2(xs, ys, s));
    match (xs, ys) {
        ([_, xr @ ..], [_, yr @ ..]) => { all2_implies(xr, yr, r, s); follows(); }
        _ => follows(),
    }
}

/// A sequence is related to itself by a reflexive relation.
#[lemma]
pub fn all2_refl<T: Copy>(xs: Seq<T>, r: fn(T, T) -> bool) {
    requires(forall(|x: T| r(x, x)));
    ensures(all2(xs, xs, r));
    match xs {
        [x, rest @ ..] => { all2_refl(rest, r); assert(r(x, x), { follows(); }); follows(); }
        [] => follows(),
    }
}

/// A map is related to its sequence when each image is related to its element.
#[lemma]
pub fn all2_map<T: Copy, U: Copy>(xs: Seq<T>, f: fn(T) -> U, r: fn(U, T) -> bool) {
    requires(all(xs, |x: T| r(f(x), x)));
    ensures(all2(map(xs, f), xs, r));
    by_induction(xs);
}

// ---------------------------------------------------------------------------------------------
// Zips.
// ---------------------------------------------------------------------------------------------

/// A zip of sequences of one length has that length.
#[lemma]
pub fn zip_len<T: Copy, U: Copy>(xs: Seq<T>, ys: Seq<U>) {
    requires(xs.len() == ys.len());
    ensures(zip(xs, ys).len() == xs.len());
    match (xs, ys) {
        ([_, xr @ ..], [_, yr @ ..]) => { zip_len(xr, yr); follows(); }
        _ => follows(),
    }
}

/// A zip of two stretches of one length each is the two zips.
#[lemma]
pub fn zip_append<T: Copy, U: Copy>(xs: Seq<T>, ys: Seq<T>, us: Seq<U>, vs: Seq<U>) {
    requires(xs.len() == us.len());
    ensures(zip(seq![..xs, ..ys], seq![..us, ..vs]) == seq![..zip(xs, us), ..zip(ys, vs)]);
    match (xs, us) {
        ([_, xr @ ..], [_, ur @ ..]) => { zip_append(xr, ys, ur, vs); follows(); }
        _ => follows(),
    }
}

/// The first components of a zip of sequences of one length are the first sequence.
#[lemma]
pub fn zip_firsts<T: Copy, U: Copy>(xs: Seq<T>, ys: Seq<U>) {
    requires(xs.len() == ys.len());
    ensures(map(zip(xs, ys), |p: (T, U)| p.0) == xs);
    match (xs, ys) {
        ([_, xr @ ..], [_, yr @ ..]) => { zip_firsts(xr, yr); follows(); }
        _ => follows(),
    }
}

// ---------------------------------------------------------------------------------------------
// Scans.
// ---------------------------------------------------------------------------------------------

/// A scan is one longer than its sequence.
#[lemma]
pub fn scan_len<T: Copy, A: Copy>(xs: Seq<T>, a: A, f: fn(A, T) -> A) {
    ensures(scan(xs, a, f).len() == xs.len() + 1);
    match xs {
        [x, rest @ ..] => { scan_len(rest, f(a, x), f); follows(); }
        [] => follows(),
    }
}

/// A scan ends with the fold.
#[lemma]
pub fn scan_last<T: Copy, A: Copy>(xs: Seq<T>, a: A, f: fn(A, T) -> A) {
    ensures(scan(xs, a, f).get(xs.len()) == Some(fold_left(xs, a, f)));
    match xs {
        [x, rest @ ..] => { scan_last(rest, f(a, x), f); follows(); }
        [] => follows(),
    }
}

/// The scan of a prefix is a prefix of the scan.
#[lemma]
pub fn scan_take<T: Copy, A: Copy>(xs: Seq<T>, j: Nat, a: A, f: fn(A, T) -> A) {
    requires(j <= xs.len());
    ensures(scan(xs, a, f).take(j + 1) == scan(xs.take(j), a, f));
    match xs {
        [x, rest @ ..] => { if j == 0 { rewrite(j == 0); follows(); } else { scan_take(rest, j - 1, f(a, x), f); follows(); } }
        [] => follows(),
    }
}

/// A scan starts with its start.
#[lemma]
pub fn scan_first<T: Copy, A: Copy>(xs: Seq<T>, a: A, f: fn(A, T) -> A) {
    ensures(scan(xs, a, f) == seq![a, ..scan(xs, a, f).skip(1)]);
    match xs {
        [_, _rest @ ..] => follows(),
        [] => follows(),
    }
}

/// The scan of two stretches: the first's scan, then the second's from the first's fold.
#[lemma]
pub fn scan_append<T: Copy, A: Copy>(xs: Seq<T>, ys: Seq<T>, a: A, f: fn(A, T) -> A) {
    ensures(scan(seq![..xs, ..ys], a, f) == seq![..scan(xs, a, f), ..scan(ys, fold_left(xs, a, f), f).skip(1)]);
    match xs {
        [x, rest @ ..] => { scan_append(rest, ys, f(a, x), f); follows(); }
        [] => { scan_first(ys, a, f); follows(); }
    }
}
