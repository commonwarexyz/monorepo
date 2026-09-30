//! More facts of the ghost `pow2` and `popcount` (the second part of
//! `lemmas/nat.core`).

/// `pow2(b) = 2 · pow2(a)` for `b = a + 1`, `0 ≤ a`.
#[lemma]
fn pow2_step(a: Int, b: Int) {
    requires(0 <= a);
    requires(b == a + 1);
    ensures(pow2(b) == 2 * pow2(a));
    rewrite(b == a + 1);
    sandblaster::lemmas::nat::pow2_succ(a);
    follows();
}

/// `pow2` is monotone.
#[lemma]
#[induction(b)]
#[decreases(b - a)]
fn pow2_mono(a: Int, b: Int) {
    requires(a <= b);
    ensures(pow2(a) <= pow2(b));
    if b <= a {
        follows();
    } else if b <= 0 {
        by_unfolding(pow2);
    } else {
        ih(a, b - 1);
        sandblaster::lemmas::nat::pow2_pos(b - 1);
        by_unfolding(pow2);
    }
}

/// `2 · pow2(a) ≤ pow2(b)` for `0 ≤ a < b`.
#[lemma]
fn pow2_lt(a: Int, b: Int) {
    requires(0 <= a && a < b);
    ensures(2 * pow2(a) <= pow2(b));
    pow2_mono(a + 1, b);
    sandblaster::lemmas::nat::pow2_succ(a);
    follows();
}

/// One step of `popcount`: the lowest bit, then the rest.
#[lemma]
fn popcount_step(x: Int) {
    requires(0 <= x);
    ensures(popcount(x) == x % 2 + popcount(x / 2));
    if x <= 0 {
        by_unfolding(popcount);
    } else {
        by_unfolding(popcount);
    }
}
