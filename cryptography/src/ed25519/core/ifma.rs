//! Four-lane AVX-512 IFMA field kernels for batched point decompression on
//! x86_64, with a portable bit-exact model for testing on other hosts.
//!
//! The multiplication, squaring, and carry schedules are curve25519-dalek's
//! IFMA backend, verbatim: field elements in radix 2^51 whose limb products
//! run through the 52-bit multiply-accumulate instructions
//! (`vpmadd52luq`/`vpmadd52huq`), with the 2^52-vs-2^51 radix mismatch
//! absorbed by doubled accumulator groups.
//!
//! Everything is generic over [`Simd52`], a nine-operation vector backend
//! with two implementations: [`Avx512`] maps one-to-one onto the intrinsics
//! and is reachable only behind the [`supported`] runtime check, and
//! [`Model`] reimplements the same operations in scalar arithmetic. The
//! schedules, carries, and exponentiation chains are exercised against the
//! scalar field implementation through [`Model`] on every platform the tests
//! run on; only the one-to-one intrinsic mapping requires IFMA hardware to
//! execute.

use super::fe::{sqrt_fixup, Fe};

/// The nine vector operations the kernels need, over four u64 lanes.
pub(crate) trait Simd52 {
    type V: Copy;

    fn splat(x: u64) -> Self::V;
    fn from_lanes(lanes: [u64; 4]) -> Self::V;
    fn to_lanes(v: Self::V) -> [u64; 4];
    fn add(a: Self::V, b: Self::V) -> Self::V;
    fn and(a: Self::V, b: Self::V) -> Self::V;
    fn shl<const K: i32>(a: Self::V) -> Self::V;
    fn shr<const K: i32>(a: Self::V) -> Self::V;
    /// `z + low52(low52(a) * low52(b))` per lane.
    fn madd52lo(z: Self::V, a: Self::V, b: Self::V) -> Self::V;
    /// `z + (low52(a) * low52(b) >> 52)` per lane.
    fn madd52hi(z: Self::V, a: Self::V, b: Self::V) -> Self::V;
}

/// Scalar model of [`Simd52`], bit-exact with the IFMA instructions.
pub(crate) struct Model;

impl Simd52 for Model {
    type V = [u64; 4];

    fn splat(x: u64) -> [u64; 4] {
        [x; 4]
    }

    fn from_lanes(lanes: [u64; 4]) -> [u64; 4] {
        lanes
    }

    fn to_lanes(v: [u64; 4]) -> [u64; 4] {
        v
    }

    fn add(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        core::array::from_fn(|i| a[i].wrapping_add(b[i]))
    }

    fn and(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        core::array::from_fn(|i| a[i] & b[i])
    }

    fn shl<const K: i32>(a: [u64; 4]) -> [u64; 4] {
        a.map(|x| x << K)
    }

    fn shr<const K: i32>(a: [u64; 4]) -> [u64; 4] {
        a.map(|x| x >> K)
    }

    fn madd52lo(z: [u64; 4], a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        const M52: u64 = (1 << 52) - 1;
        core::array::from_fn(|i| {
            let p = (a[i] & M52) as u128 * (b[i] & M52) as u128;
            z[i].wrapping_add((p as u64) & M52)
        })
    }

    fn madd52hi(z: [u64; 4], a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        const M52: u64 = (1 << 52) - 1;
        core::array::from_fn(|i| {
            let p = (a[i] & M52) as u128 * (b[i] & M52) as u128;
            z[i].wrapping_add((p >> 52) as u64)
        })
    }
}

/// The IFMA instructions, one-to-one.
///
/// Every operation compiles to instructions that are undefined behavior on
/// CPUs without AVX-512 IFMA and VL, so values of this backend must only
/// flow inside [`sqrt_ratio_i_x4`], which is gated on [`supported`].
#[cfg(target_arch = "x86_64")]
pub(crate) struct Avx512;

#[cfg(target_arch = "x86_64")]
impl Simd52 for Avx512 {
    type V = core::arch::x86_64::__m256i;

    #[inline(always)]
    fn splat(x: u64) -> Self::V {
        // SAFETY: AVX2-class register initialization; reachable only behind
        // the `supported` runtime check (see the type's documentation).
        unsafe { core::arch::x86_64::_mm256_set1_epi64x(x as i64) }
    }

    #[inline(always)]
    fn from_lanes(lanes: [u64; 4]) -> Self::V {
        // SAFETY: as above; the pointer is valid for 32 bytes.
        unsafe { core::arch::x86_64::_mm256_loadu_si256(lanes.as_ptr().cast()) }
    }

    #[inline(always)]
    fn to_lanes(v: Self::V) -> [u64; 4] {
        let mut lanes = [0u64; 4];
        // SAFETY: as above; the pointer is valid for 32 bytes.
        unsafe { core::arch::x86_64::_mm256_storeu_si256(lanes.as_mut_ptr().cast(), v) };
        lanes
    }

    #[inline(always)]
    fn add(a: Self::V, b: Self::V) -> Self::V {
        // SAFETY: as above.
        unsafe { core::arch::x86_64::_mm256_add_epi64(a, b) }
    }

    #[inline(always)]
    fn and(a: Self::V, b: Self::V) -> Self::V {
        // SAFETY: as above.
        unsafe { core::arch::x86_64::_mm256_and_si256(a, b) }
    }

    #[inline(always)]
    fn shl<const K: i32>(a: Self::V) -> Self::V {
        // SAFETY: as above.
        unsafe { core::arch::x86_64::_mm256_slli_epi64::<K>(a) }
    }

    #[inline(always)]
    fn shr<const K: i32>(a: Self::V) -> Self::V {
        // SAFETY: as above.
        unsafe { core::arch::x86_64::_mm256_srli_epi64::<K>(a) }
    }

    #[inline(always)]
    fn madd52lo(z: Self::V, a: Self::V, b: Self::V) -> Self::V {
        // SAFETY: requires avx512ifma+avx512vl, guaranteed by `supported`.
        unsafe { core::arch::x86_64::_mm256_madd52lo_epu64(z, a, b) }
    }

    #[inline(always)]
    fn madd52hi(z: Self::V, a: Self::V, b: Self::V) -> Self::V {
        // SAFETY: requires avx512ifma+avx512vl, guaranteed by `supported`.
        unsafe { core::arch::x86_64::_mm256_madd52hi_epu64(z, a, b) }
    }
}

/// Four field elements in radix 2^51, limb i of every lane in vector i,
/// with reduced (below 2^52) limbs.
pub(crate) struct FeX4<B: Simd52>([B::V; 5]);

impl<B: Simd52> Clone for FeX4<B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<B: Simd52> Copy for FeX4<B> {}

impl<B: Simd52> FeX4<B> {
    /// Pack four elements. Input limbs must be below 2^52 (52-bit multiply
    /// operands are read modulo 2^52).
    #[inline(always)]
    pub(crate) fn pack(lanes: &[Fe; 4]) -> Self {
        Self(core::array::from_fn(|i| {
            B::from_lanes(core::array::from_fn(|l| {
                debug_assert!(lanes[l].0[i] < 1 << 52);
                lanes[l].0[i]
            }))
        }))
    }

    /// Unpack four elements.
    #[inline(always)]
    pub(crate) fn unpack(&self) -> [Fe; 4] {
        let limbs: [[u64; 4]; 5] = core::array::from_fn(|i| B::to_lanes(self.0[i]));
        core::array::from_fn(|l| Fe(core::array::from_fn(|i| limbs[i][l])))
    }

    /// Carry-propagate unreduced coefficients (dalek's IFMA reduce).
    #[inline(always)]
    fn reduce(z: [B::V; 5]) -> Self {
        let mask = B::splat((1 << 51) - 1);
        let r19 = B::splat(19);
        let c0 = B::shr::<51>(z[0]);
        let c1 = B::shr::<51>(z[1]);
        let c2 = B::shr::<51>(z[2]);
        let c3 = B::shr::<51>(z[3]);
        let c4 = B::shr::<51>(z[4]);
        Self([
            B::madd52lo(B::and(z[0], mask), c4, r19),
            B::add(B::and(z[1], mask), c0),
            B::add(B::and(z[2], mask), c1),
            B::add(B::and(z[3], mask), c2),
            B::add(B::and(z[4], mask), c3),
        ])
    }

    /// Lane-wise multiplication (dalek's IFMA schedule).
    #[inline(always)]
    fn mul(&self, rhs: &Self) -> Self {
        let x = &self.0;
        let y = &rhs.0;
        let zero = B::splat(0);

        // Accumulators for terms with coefficients 1 and 2.
        let mut z0_1 = zero;
        let mut z1_1 = zero;
        let mut z2_1 = zero;
        let mut z3_1 = zero;
        let mut z4_1 = zero;
        let mut z5_1 = zero;
        let mut z6_1 = zero;
        let mut z7_1 = zero;
        let mut z8_1 = zero;
        let mut z0_2 = zero;
        let mut z1_2 = zero;
        let mut z2_2 = zero;
        let mut z3_2 = zero;
        let mut z4_2 = zero;
        let mut z5_2 = zero;
        let mut z6_2 = zero;
        let mut z7_2 = zero;
        let mut z8_2 = zero;
        let mut z9_2 = zero;

        z4_1 = B::madd52lo(z4_1, x[2], y[2]);
        z5_2 = B::madd52hi(z5_2, x[2], y[2]);
        z5_1 = B::madd52lo(z5_1, x[4], y[1]);
        z6_2 = B::madd52hi(z6_2, x[4], y[1]);
        z6_1 = B::madd52lo(z6_1, x[4], y[2]);
        z7_2 = B::madd52hi(z7_2, x[4], y[2]);
        z7_1 = B::madd52lo(z7_1, x[4], y[3]);
        z8_2 = B::madd52hi(z8_2, x[4], y[3]);

        z4_1 = B::madd52lo(z4_1, x[3], y[1]);
        z5_2 = B::madd52hi(z5_2, x[3], y[1]);
        z5_1 = B::madd52lo(z5_1, x[3], y[2]);
        z6_2 = B::madd52hi(z6_2, x[3], y[2]);
        z6_1 = B::madd52lo(z6_1, x[3], y[3]);
        z7_2 = B::madd52hi(z7_2, x[3], y[3]);
        z7_1 = B::madd52lo(z7_1, x[3], y[4]);
        z8_2 = B::madd52hi(z8_2, x[3], y[4]);

        z8_1 = B::madd52lo(z8_1, x[4], y[4]);
        z9_2 = B::madd52hi(z9_2, x[4], y[4]);
        z4_1 = B::madd52lo(z4_1, x[4], y[0]);
        z5_2 = B::madd52hi(z5_2, x[4], y[0]);
        z5_1 = B::madd52lo(z5_1, x[2], y[3]);
        z6_2 = B::madd52hi(z6_2, x[2], y[3]);
        z6_1 = B::madd52lo(z6_1, x[2], y[4]);
        z7_2 = B::madd52hi(z7_2, x[2], y[4]);

        let z8 = B::add(z8_1, B::add(z8_2, z8_2));
        let z9 = B::add(z9_2, z9_2);

        z3_1 = B::madd52lo(z3_1, x[3], y[0]);
        z4_2 = B::madd52hi(z4_2, x[3], y[0]);
        z4_1 = B::madd52lo(z4_1, x[1], y[3]);
        z5_2 = B::madd52hi(z5_2, x[1], y[3]);
        z5_1 = B::madd52lo(z5_1, x[1], y[4]);
        z6_2 = B::madd52hi(z6_2, x[1], y[4]);
        z2_1 = B::madd52lo(z2_1, x[2], y[0]);
        z3_2 = B::madd52hi(z3_2, x[2], y[0]);

        let z6 = B::add(z6_1, B::add(z6_2, z6_2));
        let z7 = B::add(z7_1, B::add(z7_2, z7_2));

        z3_1 = B::madd52lo(z3_1, x[2], y[1]);
        z4_2 = B::madd52hi(z4_2, x[2], y[1]);
        z4_1 = B::madd52lo(z4_1, x[0], y[4]);
        z5_2 = B::madd52hi(z5_2, x[0], y[4]);
        z1_1 = B::madd52lo(z1_1, x[1], y[0]);
        z2_2 = B::madd52hi(z2_2, x[1], y[0]);
        z2_1 = B::madd52lo(z2_1, x[1], y[1]);
        z3_2 = B::madd52hi(z3_2, x[1], y[1]);

        let z5 = B::add(z5_1, B::add(z5_2, z5_2));

        z3_1 = B::madd52lo(z3_1, x[1], y[2]);
        z4_2 = B::madd52hi(z4_2, x[1], y[2]);
        z0_1 = B::madd52lo(z0_1, x[0], y[0]);
        z1_2 = B::madd52hi(z1_2, x[0], y[0]);
        z1_1 = B::madd52lo(z1_1, x[0], y[1]);
        z2_1 = B::madd52lo(z2_1, x[0], y[2]);
        z2_2 = B::madd52hi(z2_2, x[0], y[1]);
        z3_2 = B::madd52hi(z3_2, x[0], y[2]);

        let mut t0 = zero;
        let mut t1 = zero;
        let r19 = B::splat(19);

        t0 = B::madd52hi(t0, r19, z9);
        t1 = B::madd52lo(t1, r19, B::shr::<52>(z9));
        z3_1 = B::madd52lo(z3_1, x[0], y[3]);
        z4_2 = B::madd52hi(z4_2, x[0], y[3]);
        z1_2 = B::madd52lo(z1_2, r19, B::shr::<52>(z5));
        z2_2 = B::madd52lo(z2_2, r19, B::shr::<52>(z6));
        z3_2 = B::madd52lo(z3_2, r19, B::shr::<52>(z7));
        z0_1 = B::madd52lo(z0_1, r19, z5);

        z4_1 = B::madd52lo(z4_1, r19, z9);
        z1_1 = B::madd52lo(z1_1, r19, z6);
        z0_2 = B::madd52lo(z0_2, r19, B::add(t0, t1));
        z4_2 = B::madd52hi(z4_2, r19, z8);
        z2_1 = B::madd52lo(z2_1, r19, z7);
        z1_2 = B::madd52hi(z1_2, r19, z5);
        z2_2 = B::madd52hi(z2_2, r19, z6);
        z3_2 = B::madd52hi(z3_2, r19, z7);

        z3_1 = B::madd52lo(z3_1, r19, z8);
        z4_2 = B::madd52lo(z4_2, r19, B::shr::<52>(z8));

        Self::reduce([
            B::add(z0_1, B::add(z0_2, z0_2)),
            B::add(z1_1, B::add(z1_2, z1_2)),
            B::add(z2_1, B::add(z2_2, z2_2)),
            B::add(z3_1, B::add(z3_2, z3_2)),
            B::add(z4_1, B::add(z4_2, z4_2)),
        ])
    }

    /// Lane-wise squaring (dalek's IFMA schedule).
    #[inline(always)]
    fn square(&self) -> Self {
        let x = &self.0;
        let zero = B::splat(0);

        // Accumulators for terms with coefficients 1, 2, and 4.
        let mut z0_2 = zero;
        let mut z1_2 = zero;
        let mut z2_2 = zero;
        let mut z3_2 = zero;
        let mut z4_2 = zero;
        let mut z5_2 = zero;
        let mut z6_2 = zero;
        let mut z7_2 = zero;
        let mut z9_2 = zero;
        let mut z2_4 = zero;
        let mut z3_4 = zero;
        let mut z4_4 = zero;
        let mut z5_4 = zero;
        let mut z6_4 = zero;
        let mut z7_4 = zero;
        let mut z8_4 = zero;

        let mut z0_1 = zero;
        z0_1 = B::madd52lo(z0_1, x[0], x[0]);

        let mut z1_1 = zero;
        z1_2 = B::madd52lo(z1_2, x[0], x[1]);
        z1_2 = B::madd52hi(z1_2, x[0], x[0]);

        z2_4 = B::madd52hi(z2_4, x[0], x[1]);
        let mut z2_1 = B::shl::<2>(z2_4);
        z2_2 = B::madd52lo(z2_2, x[0], x[2]);
        z2_1 = B::madd52lo(z2_1, x[1], x[1]);

        z3_4 = B::madd52hi(z3_4, x[0], x[2]);
        let mut z3_1 = B::shl::<2>(z3_4);
        z3_2 = B::madd52lo(z3_2, x[1], x[2]);
        z3_2 = B::madd52lo(z3_2, x[0], x[3]);
        z3_2 = B::madd52hi(z3_2, x[1], x[1]);

        z4_4 = B::madd52hi(z4_4, x[1], x[2]);
        z4_4 = B::madd52hi(z4_4, x[0], x[3]);
        let mut z4_1 = B::shl::<2>(z4_4);
        z4_2 = B::madd52lo(z4_2, x[1], x[3]);
        z4_2 = B::madd52lo(z4_2, x[0], x[4]);
        z4_1 = B::madd52lo(z4_1, x[2], x[2]);

        z5_4 = B::madd52hi(z5_4, x[1], x[3]);
        z5_4 = B::madd52hi(z5_4, x[0], x[4]);
        let mut z5_1 = B::shl::<2>(z5_4);
        z5_2 = B::madd52lo(z5_2, x[2], x[3]);
        z5_2 = B::madd52lo(z5_2, x[1], x[4]);
        z5_2 = B::madd52hi(z5_2, x[2], x[2]);

        z6_4 = B::madd52hi(z6_4, x[2], x[3]);
        z6_4 = B::madd52hi(z6_4, x[1], x[4]);
        let mut z6_1 = B::shl::<2>(z6_4);
        z6_2 = B::madd52lo(z6_2, x[2], x[4]);
        z6_1 = B::madd52lo(z6_1, x[3], x[3]);

        z7_4 = B::madd52hi(z7_4, x[2], x[4]);
        let mut z7_1 = B::shl::<2>(z7_4);
        z7_2 = B::madd52lo(z7_2, x[3], x[4]);
        z7_2 = B::madd52hi(z7_2, x[3], x[3]);

        z8_4 = B::madd52hi(z8_4, x[3], x[4]);
        let mut z8_1 = B::shl::<2>(z8_4);
        z8_1 = B::madd52lo(z8_1, x[4], x[4]);

        let mut z9_1 = zero;
        z9_2 = B::madd52hi(z9_2, x[4], x[4]);

        z5_1 = B::add(z5_1, B::shl::<1>(z5_2));
        z6_1 = B::add(z6_1, B::shl::<1>(z6_2));
        z7_1 = B::add(z7_1, B::shl::<1>(z7_2));
        z9_1 = B::add(z9_1, B::shl::<1>(z9_2));

        let mut t0 = zero;
        let mut t1 = zero;
        let r19 = B::splat(19);

        t0 = B::madd52hi(t0, r19, z9_1);
        t1 = B::madd52lo(t1, r19, B::shr::<52>(z9_1));

        z4_2 = B::madd52lo(z4_2, r19, B::shr::<52>(z8_1));
        z3_2 = B::madd52lo(z3_2, r19, B::shr::<52>(z7_1));
        z2_2 = B::madd52lo(z2_2, r19, B::shr::<52>(z6_1));
        z1_2 = B::madd52lo(z1_2, r19, B::shr::<52>(z5_1));

        z0_2 = B::madd52lo(z0_2, r19, B::add(t0, t1));
        z1_2 = B::madd52hi(z1_2, r19, z5_1);
        z2_2 = B::madd52hi(z2_2, r19, z6_1);
        z3_2 = B::madd52hi(z3_2, r19, z7_1);
        z4_2 = B::madd52hi(z4_2, r19, z8_1);

        z0_1 = B::madd52lo(z0_1, r19, z5_1);
        z1_1 = B::madd52lo(z1_1, r19, z6_1);
        z2_1 = B::madd52lo(z2_1, r19, z7_1);
        z3_1 = B::madd52lo(z3_1, r19, z8_1);
        z4_1 = B::madd52lo(z4_1, r19, z9_1);

        Self::reduce([
            B::add(z0_1, B::add(z0_2, z0_2)),
            B::add(z1_1, B::add(z1_2, z1_2)),
            B::add(z2_1, B::add(z2_2, z2_2)),
            B::add(z3_1, B::add(z3_2, z3_2)),
            B::add(z4_1, B::add(z4_2, z4_2)),
        ])
    }

    /// `self^(2^k)` by repeated squaring.
    #[inline(always)]
    fn pow2k(&self, k: u32) -> Self {
        let mut r = *self;
        for _ in 0..k {
            r = r.square();
        }
        r
    }
}

/// `x^(2^250 - 1)` for four lanes (dalek's `pow22501` chain).
#[inline(always)]
fn pow_p22501_x4<B: Simd52>(x: &FeX4<B>) -> FeX4<B> {
    let t0 = x.square();
    let t1 = t0.square().square();
    let t2 = x.mul(&t1);
    let t3 = t0.mul(&t2);
    let t4 = t3.square();
    let t5 = t2.mul(&t4);
    let t6 = t5.pow2k(5);
    let t7 = t6.mul(&t5);
    let t8 = t7.pow2k(10);
    let t9 = t8.mul(&t7);
    let t10 = t9.pow2k(20);
    let t11 = t10.mul(&t9);
    let t12 = t11.pow2k(10);
    let t13 = t12.mul(&t7);
    let t14 = t13.pow2k(50);
    let t15 = t14.mul(&t13);
    let t16 = t15.pow2k(100);
    let t17 = t16.mul(&t15);
    let t18 = t17.pow2k(50);
    t18.mul(&t13)
}

/// Square roots of `u/v` for four lanes over backend `B`, with the semantics
/// of [`super::fe::sqrt_ratio_i_w`].
#[inline(always)]
pub(crate) fn sqrt_ratio_generic<B: Simd52>(u: &[Fe; 4], v: &[Fe; 4]) -> ([bool; 4], [Fe; 4]) {
    let uv = (FeX4::<B>::pack(u), FeX4::<B>::pack(v));
    let v3 = uv.1.square().mul(&uv.1);
    let v7 = v3.square().mul(&uv.1);
    let uv3 = uv.0.mul(&v3);
    let uv7 = uv.0.mul(&v7);
    // x^((p - 5) / 8) = x^(2^252 - 3).
    let p58 = pow_p22501_x4(&uv7).pow2k(2).mul(&uv7);
    let r = uv3.mul(&p58);
    let check = uv.1.mul(&r.square());

    let (checks, rs) = (check.unpack(), r.unpack());
    let mut ok = [false; 4];
    let mut out = [Fe::ZERO; 4];
    for i in 0..4 {
        let (lane_ok, lane_r) = sqrt_fixup(&u[i], checks[i], rs[i]);
        ok[i] = lane_ok;
        out[i] = lane_r;
    }
    (ok, out)
}

#[cfg(target_arch = "x86_64")]
cpufeatures::new!(cpuid_ifma, "avx512ifma", "avx512vl");

/// True if this CPU supports the AVX-512 IFMA kernel.
#[cfg(target_arch = "x86_64")]
pub(crate) fn supported() -> bool {
    cpuid_ifma::init().get()
}

/// Square roots of `u/v` for four lanes on the IFMA backend.
///
/// Callers must check [`supported`] first.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512ifma,avx512vl")]
pub(crate) unsafe fn sqrt_ratio_i_x4(u: &[Fe; 4], v: &[Fe; 4]) -> ([bool; 4], [Fe; 4]) {
    sqrt_ratio_generic::<Avx512>(u, v)
}

#[cfg(test)]
mod tests {
    use super::{super::fe::sqrt_ratio_i_w, *};
    use commonware_utils::test_rng;
    use rand::RngExt as _;

    fn random_fe(rng: &mut impl rand::Rng) -> Fe {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Fe::from_bytes(&bytes)
    }

    #[test]
    fn test_model_pack_mul_square_match_scalar() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let a: [Fe; 4] = core::array::from_fn(|_| random_fe(&mut rng));
            let b: [Fe; 4] = core::array::from_fn(|_| random_fe(&mut rng));
            let (av, bv) = (FeX4::<Model>::pack(&a), FeX4::<Model>::pack(&b));
            let prod = av.mul(&bv).unpack();
            let sq = av.square().unpack();
            let chain = av.pow2k(64).unpack();
            for i in 0..4 {
                assert_eq!(prod[i].to_bytes(), a[i].mul(&b[i]).to_bytes());
                assert_eq!(sq[i].to_bytes(), a[i].square().to_bytes());
                assert_eq!(chain[i].to_bytes(), a[i].pow2k(64).to_bytes());
            }
        }
    }

    #[test]
    fn test_model_sqrt_ratio_matches_scalar() {
        let mut rng = test_rng();
        for round in 0..64 {
            let mut us: [Fe; 4] = core::array::from_fn(|_| random_fe(&mut rng));
            let mut vs: [Fe; 4] = core::array::from_fn(|_| random_fe(&mut rng));
            if round % 4 == 0 {
                us[0] = Fe::ZERO;
                vs[1] = Fe::ZERO;
                us[2] = vs[2].square().mul(&vs[2]);
            }
            let (ok_model, r_model) = sqrt_ratio_generic::<Model>(&us, &vs);
            let (ok_scalar, r_scalar) = sqrt_ratio_i_w(&us, &vs);
            for i in 0..4 {
                assert_eq!(ok_model[i], ok_scalar[i], "round={round} lane={i}");
                assert_eq!(
                    r_model[i].to_bytes(),
                    r_scalar[i].to_bytes(),
                    "round={round} lane={i}"
                );
            }
        }
    }

    /// Runs only on hosts with IFMA (continuous integration on newer x86
    /// runners, c8a validation): the intrinsic backend must agree with the
    /// model bit for bit.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_avx512_matches_model() {
        if !supported() {
            return;
        }
        let mut rng = test_rng();
        for _ in 0..64 {
            let us: [Fe; 4] = core::array::from_fn(|_| random_fe(&mut rng));
            let vs: [Fe; 4] = core::array::from_fn(|_| random_fe(&mut rng));
            // SAFETY: `supported` returned true above.
            let (ok_hw, r_hw) = unsafe { sqrt_ratio_i_x4(&us, &vs) };
            let (ok_model, r_model) = sqrt_ratio_generic::<Model>(&us, &vs);
            for i in 0..4 {
                assert_eq!(ok_hw[i], ok_model[i]);
                assert_eq!(r_hw[i].to_bytes(), r_model[i].to_bytes());
            }
        }
    }
}
