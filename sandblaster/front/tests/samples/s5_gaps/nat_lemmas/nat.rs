//! The facts of the ghost prelude's `pow2`, `log2` and `popcount`
//! (`lemmas/nat.core` is their kernel form).

/// `1 ≤ pow2(n)`.
#[lemma]
#[induction(n)]
#[decreases(n)]
fn pow2_pos(n: Int) {
    ensures(1 <= pow2(n));
    if n <= 0 {
        by_unfolding(pow2);
    } else {
        ih(n - 1);
        by_unfolding(pow2);
    }
}

/// `pow2(n + 1) = 2 · pow2(n)`.
#[lemma]
fn pow2_succ(n: Int) {
    requires(0 <= n);
    ensures(pow2(n + 1) == 2 * pow2(n));
    by_unfolding(pow2);
}

/// `0 ≤ log2(n)`.
#[lemma]
#[induction(n)]
#[decreases(n)]
fn log2_nonneg(n: Int) {
    ensures(0 <= log2(n));
    if n < 2 {
        by_unfolding(log2);
    } else {
        ih(n / 2);
        by_unfolding(log2);
    }
}

/// `0 ≤ popcount(n)`.
#[lemma]
#[induction(n)]
#[decreases(n)]
fn popcount_nonneg(n: Int) {
    ensures(0 <= popcount(n));
    if n <= 0 {
        by_unfolding(popcount);
    } else {
        ih(n / 2);
        by_unfolding(popcount);
    }
}

/// `popcount(n) ≤ n` for `n ≥ 0`.
#[lemma]
#[induction(n)]
#[decreases(n)]
fn popcount_le(n: Int) {
    requires(0 <= n);
    ensures(popcount(n) <= n);
    if n <= 0 {
        by_unfolding(popcount);
    } else {
        ih(n / 2);
        by_unfolding(popcount);
    }
}

/// `popcount(2n) = popcount(n)` for `n ≥ 1`.
#[lemma]
fn popcount_even(n: Int) {
    requires(1 <= n);
    ensures(popcount(2 * n) == popcount(n));
    calc! {
        popcount(2 * n) == (2 * n) % 2 + popcount((2 * n) / 2) by { by_unfolding(popcount); };
        == popcount(n) by { assert((2 * n) / 2 == n); follows(); };
    }
}

/// `popcount(2n + 1) = popcount(n) + 1` for `n ≥ 0`.
#[lemma]
fn popcount_odd(n: Int) {
    requires(0 <= n);
    ensures(popcount(2 * n + 1) == popcount(n) + 1);
    calc! {
        popcount(2 * n + 1) == (2 * n + 1) % 2 + popcount((2 * n + 1) / 2) by { by_unfolding(popcount); };
        == popcount(n) + 1 by { assert((2 * n + 1) / 2 == n); follows(); };
    }
}

/// `pow2(log2(n)) ≤ n < 2 · pow2(log2(n))` for `n ≥ 1`.
#[lemma]
#[induction(n)]
#[decreases(n)]
fn log2_bounds(n: Int) {
    requires(1 <= n);
    ensures(pow2(log2(n)) <= n && n < 2 * pow2(log2(n)));
    if n < 2 {
        by_unfolding(log2, pow2);
    } else {
        ih(n / 2);
        log2_nonneg(n / 2);
        pow2_succ(log2(n / 2));
        by_unfolding(log2);
    }
}
