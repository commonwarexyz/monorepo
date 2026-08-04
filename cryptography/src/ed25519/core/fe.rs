//! Variable-time field arithmetic over GF(2^255 - 19) in radix-2^51, used by
//! batch verification, together with width-`W` kernels that interleave `W`
//! independent computations to extract instruction-level parallelism.
//!
//! Signature verification operates only on public data (verification keys,
//! signatures, messages), so none of this code needs to be constant-time.
//!
//! The representation, formulas, and bounds discipline mirror
//! curve25519-dalek's serial u64 backend: a field element is five u64 limbs of
//! 51 bits each, limbs may grow to at most 2^54 - 1 between reductions, and
//! [`Fe::mul`] / [`Fe::square`] require inputs below 2^54. Addition does not
//! reduce, so callers must not chain more than three additions into a
//! multiplication, matching the point formulas in [`super::point`].
//!
//! The motivation for owning this arithmetic (rather than using dalek's) is
//! point decompression: the square root in `sqrt_ratio_i` is a ~251-squaring
//! serial dependency chain that dalek evaluates one element at a time, leaving
//! most of a core's multiplier throughput idle. Interleaving four independent
//! chains runs ~2x faster per element on Apple M-series and comparable
//! out-of-order cores.

use core::ops::{Add, Mul, Neg, Sub};

const MASK: u64 = (1u64 << 51) - 1;

/// Number of independent computations interleaved by the batch kernels. Four
/// chains saturate the multiplier ports on the cores we target while staying
/// within the register budget (eight regresses).
pub(crate) const WIDTH: usize = 4;

/// A field element in GF(2^255 - 19), five unsigned 51-bit limbs.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Fe(pub(crate) [u64; 5]);

/// The Edwards curve constant `d = -121665/121666 mod p`.
pub(crate) const EDWARDS_D: Fe = Fe([
    929955233495203,
    466365720129213,
    1662059464998953,
    2033849074728123,
    1442794654840575,
]);

/// `2d mod p`.
pub(crate) const EDWARDS_D2: Fe = Fe([
    1859910466990425,
    932731440258426,
    1072319116312658,
    1815898335770999,
    633789495995903,
]);

/// `sqrt(-1) mod p`.
pub(crate) const SQRT_M1: Fe = Fe([
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
]);

#[inline(always)]
const fn m(a: u64, b: u64) -> u128 {
    (a as u128) * (b as u128)
}

impl Fe {
    pub(crate) const ZERO: Self = Self([0; 5]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// Load a field element from 32 little-endian bytes, ignoring the high bit
    /// and reducing modulo p implicitly. Non-canonical encodings (values in
    /// `[p, 2^255)`) are accepted, exactly like dalek's `from_bytes`, which is
    /// what ZIP215 verification requires.
    pub(crate) fn from_bytes(b: &[u8; 32]) -> Self {
        let load8 = |i: usize| -> u64 { u64::from_le_bytes(b[i..i + 8].try_into().unwrap()) };
        Self([
            load8(0) & MASK,
            (load8(6) >> 3) & MASK,
            (load8(12) >> 6) & MASK,
            (load8(19) >> 1) & MASK,
            (load8(24) >> 12) & MASK,
        ])
    }

    /// Bring all limbs below 2^52 (weak reduction).
    #[inline(always)]
    const fn reduce_weak(mut self) -> Self {
        let l = &mut self.0;
        let c0 = l[0] >> 51;
        let c1 = l[1] >> 51;
        let c2 = l[2] >> 51;
        let c3 = l[3] >> 51;
        let c4 = l[4] >> 51;
        l[0] &= MASK;
        l[1] &= MASK;
        l[2] &= MASK;
        l[3] &= MASK;
        l[4] &= MASK;
        l[0] += c4 * 19;
        l[1] += c0;
        l[2] += c1;
        l[3] += c2;
        l[4] += c3;
        self
    }

    /// Canonical little-endian encoding, fully reduced modulo p.
    pub(crate) const fn to_bytes(self) -> [u8; 32] {
        // After a weak reduction the value is below 2^255. Adding 19 and
        // shifting through the limbs computes the quotient q in {0, 1} of the
        // value by p, then adding 19q and dropping bit 255 subtracts qp.
        let mut l = self.reduce_weak().0;
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= MASK;
        l[2] += l[1] >> 51;
        l[1] &= MASK;
        l[3] += l[2] >> 51;
        l[2] &= MASK;
        l[4] += l[3] >> 51;
        l[3] &= MASK;
        l[4] &= MASK;
        let mut s = [0u8; 32];
        s[0] = l[0] as u8;
        s[1] = (l[0] >> 8) as u8;
        s[2] = (l[0] >> 16) as u8;
        s[3] = (l[0] >> 24) as u8;
        s[4] = (l[0] >> 32) as u8;
        s[5] = (l[0] >> 40) as u8;
        s[6] = ((l[0] >> 48) | (l[1] << 3)) as u8;
        s[7] = (l[1] >> 5) as u8;
        s[8] = (l[1] >> 13) as u8;
        s[9] = (l[1] >> 21) as u8;
        s[10] = (l[1] >> 29) as u8;
        s[11] = (l[1] >> 37) as u8;
        s[12] = ((l[1] >> 45) | (l[2] << 6)) as u8;
        s[13] = (l[2] >> 2) as u8;
        s[14] = (l[2] >> 10) as u8;
        s[15] = (l[2] >> 18) as u8;
        s[16] = (l[2] >> 26) as u8;
        s[17] = (l[2] >> 34) as u8;
        s[18] = (l[2] >> 42) as u8;
        s[19] = ((l[2] >> 50) | (l[3] << 1)) as u8;
        s[20] = (l[3] >> 7) as u8;
        s[21] = (l[3] >> 15) as u8;
        s[22] = (l[3] >> 23) as u8;
        s[23] = (l[3] >> 31) as u8;
        s[24] = (l[3] >> 39) as u8;
        s[25] = ((l[3] >> 47) | (l[4] << 4)) as u8;
        s[26] = (l[4] >> 4) as u8;
        s[27] = (l[4] >> 12) as u8;
        s[28] = (l[4] >> 20) as u8;
        s[29] = (l[4] >> 28) as u8;
        s[30] = (l[4] >> 36) as u8;
        s[31] = (l[4] >> 44) as u8;
        s
    }

    /// Carry-propagate five wide accumulators into a weakly reduced element.
    #[inline(always)]
    const fn carry(c0: u128, mut c1: u128, mut c2: u128, mut c3: u128, mut c4: u128) -> Self {
        let mut out = [0u64; 5];
        c1 += c0 >> 51;
        out[0] = (c0 as u64) & MASK;
        c2 += c1 >> 51;
        out[1] = (c1 as u64) & MASK;
        c3 += c2 >> 51;
        out[2] = (c2 as u64) & MASK;
        c4 += c3 >> 51;
        out[3] = (c3 as u64) & MASK;
        let carry = (c4 >> 51) as u64;
        out[4] = (c4 as u64) & MASK;
        out[0] += carry * 19;
        out[1] += out[0] >> 51;
        out[0] &= MASK;
        Self(out)
    }

    /// One squaring. Input limbs must be below 2^54.
    #[inline(always)]
    pub(crate) fn square(&self) -> Self {
        let a = &self.0;
        debug_assert!(a.iter().all(|l| *l < 1 << 54));
        let a3_19 = 19 * a[3];
        let a4_19 = 19 * a[4];
        let c0 = m(a[0], a[0]) + 2 * (m(a[1], a4_19) + m(a[2], a3_19));
        let c1 = m(a[3], a3_19) + 2 * (m(a[0], a[1]) + m(a[2], a4_19));
        let c2 = m(a[1], a[1]) + 2 * (m(a[0], a[2]) + m(a[4], a3_19));
        let c3 = m(a[4], a4_19) + 2 * (m(a[0], a[3]) + m(a[1], a[2]));
        let c4 = m(a[2], a[2]) + 2 * (m(a[0], a[4]) + m(a[1], a[3]));
        Self::carry(c0, c1, c2, c3, c4)
    }

    /// `2 * self^2`. Input limbs must be below 2^54.
    #[inline(always)]
    pub(crate) fn square2(&self) -> Self {
        let mut r = self.square();
        for l in &mut r.0 {
            *l *= 2;
        }
        r
    }

    /// `self^(2^k)` by repeated squaring.
    pub(crate) fn pow2k(&self, k: u32) -> Self {
        let mut r = *self;
        for _ in 0..k {
            r = r.square();
        }
        r
    }

    /// `self^-1 = self^(p - 2)`. The zero element maps to zero.
    pub(crate) fn invert(&self) -> Self {
        // p - 2 = (2^250 - 1) * 2^5 + 11.
        let [r] = pow_p22501_w(&[*self]);
        let t3 = self
            .square()
            .mul(&self.square().square().square().mul(self));
        r.pow2k(5).mul(&t3)
    }

    /// True if the canonical encoding is odd (dalek's sign convention for the
    /// x-coordinate).
    pub(crate) const fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    /// Equality of the represented field elements (not the representations).
    #[cfg(test)]
    pub(crate) fn eq_vartime(self, other: Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Add for &Fe {
    type Output = Fe;

    /// Limbwise addition without reduction. Callers must keep the total limb
    /// excess below 2^54 before the next multiplication (at most three
    /// additions of reduced values).
    #[inline(always)]
    fn add(self, rhs: &Fe) -> Fe {
        let a = &self.0;
        let b = &rhs.0;
        Fe([
            a[0] + b[0],
            a[1] + b[1],
            a[2] + b[2],
            a[3] + b[3],
            a[4] + b[4],
        ])
    }
}

impl Sub for &Fe {
    type Output = Fe;

    /// Subtraction, weakly reduced. Adds 16p before subtracting so limbs stay
    /// nonnegative for any subtrahend with limbs below 2^54.
    #[inline(always)]
    fn sub(self, rhs: &Fe) -> Fe {
        let a = &self.0;
        let b = &rhs.0;
        Fe([
            (a[0] + 36028797018963664) - b[0],
            (a[1] + 36028797018963952) - b[1],
            (a[2] + 36028797018963952) - b[2],
            (a[3] + 36028797018963952) - b[3],
            (a[4] + 36028797018963952) - b[4],
        ])
        .reduce_weak()
    }
}

impl Neg for &Fe {
    type Output = Fe;

    #[inline(always)]
    fn neg(self) -> Fe {
        &Fe::ZERO - self
    }
}

impl Mul for &Fe {
    type Output = Fe;

    /// Schoolbook multiplication with the 19-fold wraparound. Input limbs must
    /// be below 2^54.
    #[inline(always)]
    fn mul(self, rhs: &Fe) -> Fe {
        let a = &self.0;
        let b = &rhs.0;
        debug_assert!(a.iter().all(|l| *l < 1 << 54));
        debug_assert!(b.iter().all(|l| *l < 1 << 54));
        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;
        let c0 = m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19) + m(a[1], b4_19);
        let c1 = m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2_19) + m(a[3], b3_19) + m(a[2], b4_19);
        let c2 = m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3_19) + m(a[3], b4_19);
        let c3 = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4_19);
        let c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);
        Fe::carry(c0, c1, c2, c3, c4)
    }
}

impl Fe {
    /// Convenience method form of `Mul` for chained expressions.
    #[inline(always)]
    pub(crate) fn mul(&self, rhs: &Self) -> Self {
        self * rhs
    }
}

// Width-W kernels. Each processes W independent elements per step so the
// (serial) dependency chains of consecutive squarings overlap in the
// processor's out-of-order window.

#[inline(always)]
fn square_w<const W: usize>(x: &[Fe; W]) -> [Fe; W] {
    let mut out = [Fe::ZERO; W];
    for i in 0..W {
        out[i] = x[i].square();
    }
    out
}

#[inline(always)]
fn mul_w<const W: usize>(a: &[Fe; W], b: &[Fe; W]) -> [Fe; W] {
    let mut out = [Fe::ZERO; W];
    for i in 0..W {
        out[i] = a[i].mul(&b[i]);
    }
    out
}

#[inline(always)]
fn pow2k_w<const W: usize>(x: &[Fe; W], k: u32) -> [Fe; W] {
    let mut r = *x;
    for _ in 0..k {
        r = square_w(&r);
    }
    r
}

/// `x^(2^250 - 1)` for W independent elements (dalek's `pow22501` chain).
fn pow_p22501_w<const W: usize>(x: &[Fe; W]) -> [Fe; W] {
    let t0 = square_w(x); // 2^1
    let t1 = square_w(&square_w(&t0)); // 2^3
    let t2 = mul_w(x, &t1); // 2^3 + 2^0
    let t3 = mul_w(&t0, &t2); // 11
    let t4 = square_w(&t3); // 22
    let t5 = mul_w(&t2, &t4); // 2^5 - 1
    let t6 = pow2k_w(&t5, 5);
    let t7 = mul_w(&t6, &t5); // 2^10 - 1
    let t8 = pow2k_w(&t7, 10);
    let t9 = mul_w(&t8, &t7); // 2^20 - 1
    let t10 = pow2k_w(&t9, 20);
    let t11 = mul_w(&t10, &t9); // 2^40 - 1
    let t12 = pow2k_w(&t11, 10);
    let t13 = mul_w(&t12, &t7); // 2^50 - 1
    let t14 = pow2k_w(&t13, 50);
    let t15 = mul_w(&t14, &t13); // 2^100 - 1
    let t16 = pow2k_w(&t15, 100);
    let t17 = mul_w(&t16, &t15); // 2^200 - 1
    let t18 = pow2k_w(&t17, 50);
    mul_w(&t18, &t13) // 2^250 - 1
}

/// `x^((p - 5) / 8) = x^(2^252 - 3)` for W independent elements.
fn pow_p58_w<const W: usize>(x: &[Fe; W]) -> [Fe; W] {
    let t19 = pow_p22501_w(x);
    let t20 = pow2k_w(&t19, 2); // 2^252 - 4
    mul_w(&t20, x) // 2^252 - 3
}

/// Square roots of `u/v` for W independent lanes. Per lane, returns
/// `(was_nonzero_square, r)` with dalek's exact `sqrt_ratio_i` semantics:
/// `(true, +sqrt(u/v))` if `u/v` is square, `(true, 0)` if `u` is zero,
/// `(false, 0)` if `v` is zero and `u` nonzero, and `(false, +sqrt(i*u/v))`
/// if `u/v` is a nonsquare. `r` is always the nonnegative root.
pub(crate) fn sqrt_ratio_i_w<const W: usize>(u: &[Fe; W], v: &[Fe; W]) -> ([bool; W], [Fe; W]) {
    let v3 = mul_w(&square_w(v), v);
    let v7 = mul_w(&square_w(&v3), v);
    let uv3 = mul_w(u, &v3);
    let uv7 = mul_w(u, &v7);
    let mut r = mul_w(&uv3, &pow_p58_w(&uv7));
    let check = mul_w(v, &square_w(&r));

    let mut ok = [false; W];
    for i in 0..W {
        let (lane_ok, lane_r) = sqrt_fixup(&u[i], check[i], r[i]);
        ok[i] = lane_ok;
        r[i] = lane_r;
    }
    (ok, r)
}

/// Resolve one lane of a square-root computation: given the candidate root
/// `r` of `u/v` and `check = v * r^2`, apply dalek's sign corrections and
/// squareness classification, returning `(was_nonzero_square, nonnegative
/// root)`.
pub(crate) fn sqrt_fixup(u: &Fe, check: Fe, mut r: Fe) -> (bool, Fe) {
    let cb = check.to_bytes();
    let neg_u = -u;
    let correct = cb == u.to_bytes();
    let flipped = cb == neg_u.to_bytes();
    let flipped_i = cb == neg_u.mul(&SQRT_M1).to_bytes();
    if flipped || flipped_i {
        r = r.mul(&SQRT_M1);
    }
    if r.is_negative() {
        r = -&r;
    }
    (correct || flipped, r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::test_rng;
    use rand::RngExt as _;

    fn random_fe(rng: &mut impl rand::Rng) -> Fe {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Fe::from_bytes(&bytes)
    }

    #[test]
    fn test_sqrt_m1_squares_to_minus_one() {
        assert!(SQRT_M1.square().eq_vartime(-&Fe::ONE));
    }

    #[test]
    fn test_non_canonical_encodings_reduce() {
        // 2^255 - 19 + 1 encodes the field element 1.
        let mut b = [0xffu8; 32];
        b[0] = 0xee;
        b[31] = 0x7f;
        assert_eq!(Fe::from_bytes(&b).to_bytes(), Fe::ONE.to_bytes());

        // The high bit is ignored.
        let mut b = Fe::ONE.to_bytes();
        b[31] |= 0x80;
        assert!(Fe::from_bytes(&b).eq_vartime(Fe::ONE));
    }

    #[test]
    fn test_mul_square_invert() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let x = random_fe(&mut rng);
            assert!(x.square().eq_vartime(x.mul(&x)));
            assert!(x.square2().eq_vartime(&x.square() + &x.square()));
            assert!(x.mul(&x.invert()).eq_vartime(Fe::ONE));
        }
    }

    #[test]
    fn test_add_sub_neg() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let x = random_fe(&mut rng);
            let y = random_fe(&mut rng);
            assert!((&(&x + &y) - &y).eq_vartime(x));
            assert!((&x + &(-&x)).reduce_weak().eq_vartime(Fe::ZERO));
        }
    }

    #[test]
    fn test_wide_kernels_match_narrow() {
        let mut rng = test_rng();
        for _ in 0..16 {
            let xs: [Fe; 4] = core::array::from_fn(|_| random_fe(&mut rng));
            let vs: [Fe; 4] = core::array::from_fn(|_| random_fe(&mut rng));
            let (ok4, r4) = sqrt_ratio_i_w(&xs, &vs);
            for i in 0..4 {
                let (ok1, r1) = sqrt_ratio_i_w(&[xs[i]], &[vs[i]]);
                assert_eq!(ok4[i], ok1[0]);
                assert!(r4[i].eq_vartime(r1[0]));
            }
            let p4 = pow_p58_w(&xs);
            for i in 0..4 {
                let p1 = pow_p58_w(&[xs[i]]);
                assert!(p4[i].eq_vartime(p1[0]));
            }
        }
    }

    #[test]
    fn test_sqrt_ratio_cases() {
        let mut rng = test_rng();
        // u = 0 is a square with root 0, regardless of v.
        let v = random_fe(&mut rng);
        let (ok, r) = sqrt_ratio_i_w(&[Fe::ZERO], &[v]);
        assert!(ok[0] && r[0].eq_vartime(Fe::ZERO));
        // v = 0 with u nonzero is not a square.
        let (ok, r) = sqrt_ratio_i_w(&[Fe::ONE], &[Fe::ZERO]);
        assert!(!ok[0] && r[0].eq_vartime(Fe::ZERO));
        // A known square and a known nonsquare of it via SQRT_M1.
        for _ in 0..16 {
            let x = random_fe(&mut rng);
            let xx = x.square();
            let (ok, r) = sqrt_ratio_i_w(&[xx], &[Fe::ONE]);
            assert!(ok[0]);
            assert!(r[0].square().eq_vartime(xx));
            // xx * SQRT_M1 is a nonsquare when xx != 0 (i is a nonsquare).
            if !xx.eq_vartime(Fe::ZERO) {
                let (ok, _) = sqrt_ratio_i_w(&[xx.mul(&SQRT_M1)], &[Fe::ONE]);
                assert!(!ok[0]);
            }
        }
    }
}
