//! Exact rationals over arbitrary-precision integers, used by the untrusted
//! linear-arithmetic certificate search ([`super::simplex`], DESIGN.md §5.8,
//! §8.1 step 13). Always normalized: `den > 0` and `gcd(num, den) = 1`, so
//! structural equality is numeric equality.
//!
//! **Representation.** A value whose numerator and denominator fit in `i128`
//! is stored inline ([`Q::S`]) and computed with checked machine arithmetic;
//! anything larger (or an intermediate that overflows) uses `BigInt`
//! ([`Q::B`]), and a result that fits again is stored inline. The choice is
//! canonical (a value is `S` exactly when it fits), so equality, ordering
//! and every result are those of the plain `BigInt` rationals: the simplex
//! pivots and the certificates it finds are unchanged, only faster (plan
//! O6: the per-literal loop lemmas are linear arithmetic over `2^k`-scale
//! coefficients, where the `BigInt` path dominated the search).

use std::cmp::Ordering;

use num_bigint::BigInt;
use num_traits::{One, Signed, ToPrimitive, Zero};
use sandblaster_kernel::term::Rat;

/// `gcd(|a|, |b|)` (Euclid; `gcd(0, 0) = 0`).
pub fn gcd(a: &BigInt, b: &BigInt) -> BigInt {
    let mut a = a.abs();
    let mut b = b.abs();
    while !b.is_zero() {
        let r = &a % &b;
        a = b;
        b = r;
    }
    a
}

/// `gcd(|a|, |b|)` on machine integers (`None` if `|i128::MIN|` occurs):
/// Euclid on `u64` when both fit (hardware division), else binary (Stein;
/// a 128-bit `%` is a software division, which dominated the simplex).
fn gcd_i(a: i128, b: i128) -> Option<i128> {
    let (a, b) = (a.checked_abs()? as u128, b.checked_abs()? as u128);
    if a == 1 || b == 1 {
        return Some(1);
    }
    // one of them fits: a single 128-bit remainder brings both into 64 bits
    let (a, b) = if a >> 64 != 0 && b >> 64 == 0 && b != 0 {
        (b, a % b)
    } else if b >> 64 != 0 && a >> 64 == 0 && a != 0 {
        (a, b % a)
    } else {
        (a, b)
    };
    if (a | b) >> 64 == 0 {
        let (mut x, mut y) = (a as u64, b as u64);
        while y != 0 {
            let r = x % y;
            x = y;
            y = r;
        }
        return Some(x as i128);
    }
    if a == 0 || b == 0 {
        return Some((a | b) as i128);
    }
    let shift = (a | b).trailing_zeros();
    let (mut a, mut b) = (a >> a.trailing_zeros(), b);
    loop {
        b >>= b.trailing_zeros();
        if a > b {
            std::mem::swap(&mut a, &mut b);
        }
        b -= a;
        if b == 0 {
            break;
        }
    }
    Some((a << shift) as i128)
}

/// `n / g` for a divisor `g > 0` of `n` (the hardware path when both fit
/// in 64 bits).
fn div_exact(n: i128, g: i128) -> i128 {
    if g == 1 {
        n
    } else if let (Ok(a), Ok(b)) = (i64::try_from(n), i64::try_from(g)) {
        (a / b) as i128
    } else {
        n / g
    }
}

/// An exact rational number (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Q {
    /// Fits in machine integers: `den > 0`, reduced.
    S(i128, i128),
    /// Does not fit: `den > 0`, reduced.
    B(BigInt, BigInt),
}

impl Q {
    /// `num / den` (`den ≠ 0`), normalized.
    pub fn new(num: BigInt, den: BigInt) -> Q {
        assert!(!den.is_zero(), "rational with zero denominator");
        if let (Some(n), Some(d)) = (num.to_i128(), den.to_i128())
            && let Some(q) = Q::small(n, d)
        {
            return q;
        }
        let (mut num, mut den) = if den.is_negative() { (-num, -den) } else { (num, den) };
        let g = gcd(&num, &den);
        if !g.is_zero() && !g.is_one() {
            num /= &g;
            den /= &g;
        }
        if num.is_zero() {
            den = BigInt::one();
        }
        Q::big(num, den)
    }

    /// A reduced `BigInt` pair, stored inline when it fits.
    fn big(num: BigInt, den: BigInt) -> Q {
        match (num.to_i128(), den.to_i128()) {
            (Some(n), Some(d)) => Q::S(n, d),
            _ => Q::B(num, den),
        }
    }

    /// `n / d` on machine integers, normalized (`None` on overflow).
    fn small(n: i128, d: i128) -> Option<Q> {
        if d == 0 {
            return None;
        }
        let (n, d) = if d < 0 { (n.checked_neg()?, d.checked_neg()?) } else { (n, d) };
        if n == 0 {
            return Some(Q::S(0, 1));
        }
        if d == 1 {
            return Some(Q::S(n, 1));
        }
        let g = gcd_i(n, d)?;
        Some(Q::S(div_exact(n, g), div_exact(d, g)))
    }

    fn parts(&self) -> (BigInt, BigInt) {
        match self {
            Q::S(n, d) => (BigInt::from(*n), BigInt::from(*d)),
            Q::B(n, d) => (n.clone(), d.clone()),
        }
    }

    pub fn int(n: BigInt) -> Q {
        match n.to_i128() {
            Some(x) => Q::S(x, 1),
            None => Q::B(n, BigInt::one()),
        }
    }

    pub fn zero() -> Q {
        Q::S(0, 1)
    }

    pub fn one() -> Q {
        Q::S(1, 1)
    }

    pub fn num(&self) -> BigInt {
        match self {
            Q::S(n, _) => BigInt::from(*n),
            Q::B(n, _) => n.clone(),
        }
    }

    pub fn den(&self) -> BigInt {
        match self {
            Q::S(_, d) => BigInt::from(*d),
            Q::B(_, d) => d.clone(),
        }
    }

    pub fn is_zero(&self) -> bool {
        match self {
            Q::S(n, _) => *n == 0,
            Q::B(n, _) => n.is_zero(),
        }
    }

    pub fn is_pos(&self) -> bool {
        match self {
            Q::S(n, _) => *n > 0,
            Q::B(n, _) => n.is_positive(),
        }
    }

    pub fn is_neg(&self) -> bool {
        match self {
            Q::S(n, _) => *n < 0,
            Q::B(n, _) => n.is_negative(),
        }
    }

    pub fn add(&self, o: &Q) -> Q {
        if let (Q::S(a, b), Q::S(c, d)) = (self, o) {
            let r = if b == d {
                a.checked_add(*c).and_then(|n| Q::small(n, *b))
            } else {
                a.checked_mul(*d).zip(c.checked_mul(*b)).and_then(|(x, y)| x.checked_add(y)).zip(b.checked_mul(*d)).and_then(|(n, den)| Q::small(n, den))
            };
            if let Some(r) = r {
                return r;
            }
        }
        let ((sn, sd), (on, od)) = (self.parts(), o.parts());
        if sd == od {
            return Q::new(sn + on, sd);
        }
        Q::new(&sn * &od + &on * &sd, &sd * &od)
    }

    pub fn sub(&self, o: &Q) -> Q {
        self.add(&o.neg())
    }

    pub fn mul(&self, o: &Q) -> Q {
        if self.is_zero() || o.is_zero() {
            return Q::zero();
        }
        if let (Q::S(a, b), Q::S(c, d)) = (self, o) {
            // cross-reduce first: gcd(a, d), gcd(c, b)
            if let (Some(g1), Some(g2)) = (gcd_i(*a, *d), gcd_i(*c, *b))
                && let Some(r) = div_exact(*a, g1).checked_mul(div_exact(*c, g2)).zip(div_exact(*b, g2).checked_mul(div_exact(*d, g1))).and_then(|(n, den)| Q::small(n, den))
            {
                return r;
            }
        }
        let ((sn, sd), (on, od)) = (self.parts(), o.parts());
        Q::new(&sn * &on, &sd * &od)
    }

    /// `self / o` (`o ≠ 0`).
    pub fn div(&self, o: &Q) -> Q {
        if let (Q::S(a, b), Q::S(c, d)) = (self, o)
            && *c != 0
            && let (Some(g1), Some(g2)) = (gcd_i(*a, *c), gcd_i(*d, *b))
            && g1 != 0
            && g2 != 0
            && let Some(r) = div_exact(*a, g1).checked_mul(div_exact(*d, g2)).zip(div_exact(*b, g2).checked_mul(div_exact(*c, g1))).and_then(|(n, den)| Q::small(n, den))
        {
            return r;
        }
        let ((sn, sd), (on, od)) = (self.parts(), o.parts());
        Q::new(&sn * &od, &sd * &on)
    }

    pub fn neg(&self) -> Q {
        match self {
            Q::S(n, d) => match n.checked_neg() {
                Some(m) => Q::S(m, *d),
                None => Q::B(-BigInt::from(*n), BigInt::from(*d)),
            },
            Q::B(n, d) => Q::big(-n.clone(), d.clone()),
        }
    }

    /// The kernel's certificate rational (`den > 0`).
    pub fn to_rat(&self) -> Rat {
        let (num, den) = self.parts();
        Rat { num, den }
    }
}

impl PartialOrd for Q {
    fn partial_cmp(&self, o: &Q) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

impl Ord for Q {
    fn cmp(&self, o: &Q) -> Ordering {
        if let (Q::S(a, b), Q::S(c, d)) = (self, o)
            && let (Some(x), Some(y)) = (a.checked_mul(*d), c.checked_mul(*b))
        {
            return x.cmp(&y);
        }
        let ((sn, sd), (on, od)) = (self.parts(), o.parts());
        (&sn * &od).cmp(&(&on * &sd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(n: i64, d: i64) -> Q {
        Q::new(BigInt::from(n), BigInt::from(d))
    }

    #[test]
    fn arithmetic_is_normalized() {
        assert_eq!(q(2, 4), q(1, 2));
        assert_eq!(q(1, -2), q(-1, 2));
        assert_eq!(q(1, 3).add(&q(1, 6)), q(1, 2));
        assert_eq!(q(1, 2).mul(&q(2, 3)), q(1, 3));
        assert_eq!(q(1, 2).div(&q(1, 4)), q(2, 1));
        assert_eq!(q(0, 5), Q::zero());
        assert!(q(1, 3) < q(1, 2));
        assert_eq!(q(3, 4).to_rat().den, BigInt::from(4));
    }

    /// The machine path and the `BigInt` path agree, across the boundary
    /// where values stop fitting (the representation is canonical).
    #[test]
    fn small_and_big_paths_agree() {
        let big = |n: &str, d: &str| Q::new(n.parse::<BigInt>().unwrap(), d.parse::<BigInt>().unwrap());
        let vals = [
            q(1, 3),
            q(-7, 2),
            q(0, 1),
            big("18446744073709551615", "1"),
            big("170141183460469231731687303715884105727", "3"),
            big("-170141183460469231731687303715884105728", "1"),
            big("340282366920938463463374607431768211457", "2"),
            big("4611686018427387904", "18446744073709551615"),
        ];
        for a in &vals {
            for b in &vals {
                let (an, ad) = (a.num(), a.den());
                let (bn, bd) = (b.num(), b.den());
                let add = Q::new(&an * &bd + &bn * &ad, &ad * &bd);
                assert_eq!(a.add(b), add, "{a:?} + {b:?}");
                let mul = Q::new(&an * &bn, &ad * &bd);
                assert_eq!(a.mul(b), mul, "{a:?} * {b:?}");
                if !b.is_zero() {
                    assert_eq!(a.div(b), Q::new(&an * &bd, &ad * &bn), "{a:?} / {b:?}");
                }
                assert_eq!(a.cmp(b), (&an * &bd).cmp(&(&bn * &ad)), "{a:?} cmp {b:?}");
                assert_eq!(a.neg(), Q::new(-an.clone(), ad.clone()));
                // canonical: fits ⇔ inline
                let fits = |x: &Q| x.num().to_i128().is_some() && x.den().to_i128().is_some();
                for x in [a.add(b), a.mul(b)] {
                    assert_eq!(matches!(x, Q::S(..)), fits(&x), "{x:?}");
                }
            }
        }
    }
}
