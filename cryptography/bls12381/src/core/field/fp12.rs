//! The quadratic extension `Fp12 = Fp6[w] / (w^2 - v)`, which contains the target group of the
//! pairing, over any base field representation.
//!
//! An [`Fp12`] holds two [`Fp6`] coefficients, so it holds as many elements as its base field values
//! hold elements, one per lane. Besides multiplication and squaring, it provides the operations of
//! the pairing: multiplication by sparse Miller loop lines, squaring in the cyclotomic subgroup,
//! conjugation, the Frobenius map, and inversion.
//!
//! # Bounds
//!
//! Every operation accepts elements whose components have positional limb bound `1` and integer
//! bound at most [`BOUND`], as defined by the [base field arithmetic](super::arithmetic), and returns
//! elements that satisfy the same, so elements chain through any number of operations. Loaded
//! elements satisfy it.
//!
//! Each operation forms its products lazily and finishes with one tight reduction of each output
//! component, as for [`Field::reduce_tight`], so outputs are bounded however many products they
//! sum. Karatsuba's products over `Fp6` are [carried](Fp6::carry_product) before they combine, so
//! eager sums stay within their limb limits, and every combination subtracts through signed sums,
//! so subtractions add a bias only in the final reductions. Their negative sums stay below
//! `512p` in the positional representations.
//!
//! Representations with [`Field::SCHOOLBOOK`] multiply instead over the coefficients of
//! `1, w, ..., w^5`, where `w^2 = v` and `w^6 = 1 + i`: each output coefficient is the sum of the
//! products of the pairs of coefficients whose degrees add to its own, or to its own plus six,
//! the latter with one factor first multiplied by `1 + i`. Every product accumulates into its
//! output as it forms, so no sum is ever combined with another.
//!
//! Lines multiply with the same contract for their coefficients, but within [`LINE_BOUND`].

use super::{
    arithmetic::{Field, TIGHT, unroll},
    fp::{BYTES as FP_BYTES, WORDS},
    fp2::{BYTES as FP2_BYTES, Fp2},
    fp6::{self, BYTES as FP6_BYTES, Fp6},
};
use commonware_simd::Simd;

/// Number of bytes in an element's big-endian encoding: `c1` followed by `c0`.
pub const BYTES: usize = 2 * FP6_BYTES;

/// Largest integer bound of a component, in units of `p`.
pub const BOUND: u64 = TIGHT;

/// Largest integer bound of a component of a line coefficient, in units of `p`.
pub const LINE_BOUND: u64 = 64;

/// The encoding of one.
pub const ONE: [u8; BYTES] = {
    let mut one = [0; BYTES];
    one[BYTES - 1] = 1;
    one
};

/// Positional bias of every tight reduction, in units of `p`.
///
/// Covers every negative sum of the operations on elements within [`BOUND`] and lines within
/// [`LINE_BOUND`], and leaves room below the value limit for their positive sums.
const BIAS: u64 = 512;

/// Largest number of elements in a value, the widest representation's lane count.
const MAX_LANES: usize = 16;

/// `gamma_j = (1 + i)^(j (p - 1) / 6)` for `j` from `1` to `5`, as extension encodings.
///
/// The Frobenius map sends `a w^j` to `conj(a) w^(j p) = conj(a) gamma_j w^j`, since
/// `w^(p - 1) = (w^6)^((p - 1) / 6)` and `w^6 = 1 + i`.
const FROBENIUS: [[u8; FP2_BYTES]; 5] = [
    encode(
        [
            0x8d07_75ed_9223_5fb8,
            0xf67e_a53d_63e7_813d,
            0x7b24_43d7_84ba_b9c4,
            0x0fd6_03fd_3cbd_5f4f,
            0xc231_beb4_202c_0d1f,
            0x1904_d3bf_02bb_0667,
        ],
        [
            0x2cf7_8a12_6ddc_4af3,
            0x282d_5ac1_4d6c_7ec2,
            0xec0c_8ec9_71f6_3c5f,
            0x54a1_4787_b6c7_b36f,
            0x88e9_e902_231f_9fb8,
            0x00fc_3e2b_36c4_e032,
        ],
    ),
    encode(
        [0; WORDS],
        [
            0x8bfd_0000_0000_aaac,
            0x4094_27eb_4f49_fffd,
            0x897d_2965_0fb8_5f9b,
            0xaa0d_857d_8975_9ad4,
            0xec02_4086_63d4_de85,
            0x1a01_11ea_397f_e699,
        ],
    ),
    encode(
        [
            0xc810_84fb_ede3_cc09,
            0xee67_992f_72ec_05f4,
            0x77f7_6e17_0092_41c5,
            0x4839_5dab_c2d3_435e,
            0x6831_e36d_6bd1_7ffe,
            0x06af_0e04_37ff_400b,
        ],
        [
            0xc810_84fb_ede3_cc09,
            0xee67_992f_72ec_05f4,
            0x77f7_6e17_0092_41c5,
            0x4839_5dab_c2d3_435e,
            0x6831_e36d_6bd1_7ffe,
            0x06af_0e04_37ff_400b,
        ],
    ),
    encode(
        [
            0x8bfd_0000_0000_aaad,
            0x4094_27eb_4f49_fffd,
            0x897d_2965_0fb8_5f9b,
            0xaa0d_857d_8975_9ad4,
            0xec02_4086_63d4_de85,
            0x1a01_11ea_397f_e699,
        ],
        [0; WORDS],
    ),
    encode(
        [
            0x9b18_fae9_8007_8116,
            0xc63a_3e6e_257f_8732,
            0x8bea_df4d_8e9c_0566,
            0xf398_1624_0c0b_8fee,
            0xdf47_fa6b_48b1_e045,
            0x05b2_cfd9_013a_5fd8,
        ],
        [
            0x1ee6_0516_7ff8_2995,
            0x5871_c190_8bd4_78cd,
            0xdb45_f353_6814_f0bd,
            0x70df_3560_e779_82d0,
            0x6bd3_ad4a_fa99_cc91,
            0x144e_4211_3845_86c1,
        ],
    ),
];

/// Returns the encoding of `c0 + c1 i` for little-endian words.
const fn encode(c0: [u64; WORDS], c1: [u64; WORDS]) -> [u8; FP2_BYTES] {
    let mut bytes = [0; FP2_BYTES];
    let mut i = 0;
    while i < WORDS {
        let (high, low) = (
            c1[WORDS - 1 - i].to_be_bytes(),
            c0[WORDS - 1 - i].to_be_bytes(),
        );
        let mut k = 0;
        while k < 8 {
            bytes[8 * i + k] = high[k];
            bytes[FP2_BYTES / 2 + 8 * i + k] = low[k];
            k += 1;
        }
        i += 1;
    }
    bytes
}

/// Elements `c0 + c1 * w`, one per lane of the coefficients.
///
/// Components are base field values. See the [module documentation](self) for the bounds every
/// operation accepts and returns.
#[derive(Clone, Copy)]
pub struct Fp12<F> {
    /// The coefficients of `1`.
    pub c0: Fp6<F>,
    /// The coefficients of `w`.
    pub c1: Fp6<F>,
}

impl<F> Fp12<F> {
    /// Loads up to one element per lane, filling the remaining lanes with `fill`.
    ///
    /// Interprets each component modulo `p` and returns the base field's initial bounds.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn load<S: Simd>(simd: S, elements: &[[u8; BYTES]], fill: &[u8; BYTES]) -> Self
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut coefficients = [[[0; FP6_BYTES]; MAX_LANES]; 2];
        let lanes = elements.len().min(F::LANES);
        for (lane, element) in elements[..lanes].iter().enumerate() {
            let (c1, c0) = split(element);
            coefficients[0][lane] = *c0;
            coefficients[1][lane] = *c1;
        }
        let (fill1, fill0) = split(fill);
        Self {
            c0: Fp6::load(simd, &coefficients[0][..lanes], fill0),
            c1: Fp6::load(simd, &coefficients[1][..lanes], fill1),
        }
    }

    /// Returns one in every lane.
    ///
    /// Runs as its own kernel, so that callers outside kernels build it with the backend's
    /// instructions.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn one<S: Simd>(simd: S) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let zero = F::load(simd, &[], &[0; FP_BYTES]);
                let mut one = [0; FP_BYTES];
                one[FP_BYTES - 1] = 1;
                let one = F::load(simd, &[], &one);
                let zero2 = Fp2 { c0: zero, c1: zero };
                Self {
                    c0: Fp6 {
                        c0: Fp2 { c0: one, c1: zero },
                        c1: zero2,
                        c2: zero2,
                    },
                    c1: Fp6 {
                        c0: zero2,
                        c1: zero2,
                        c2: zero2,
                    },
                }
            },
        )
    }

    /// Stores the canonical value of each lane, dropping lanes beyond `elements`.
    ///
    /// Requires valid value bounds. Entries beyond [`Field::LANES`] are unchanged.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn store<S: Simd>(self, simd: S, elements: &mut [[u8; BYTES]])
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut coefficients = [[[0; FP6_BYTES]; MAX_LANES]; 2];
        let lanes = elements.len().min(F::LANES);
        self.c0.store(simd, &mut coefficients[0][..lanes]);
        self.c1.store(simd, &mut coefficients[1][..lanes]);
        for (lane, element) in elements[..lanes].iter_mut().enumerate() {
            let (c1, c0) = element.split_at_mut(FP6_BYTES);
            c0.copy_from_slice(&coefficients[0][lane]);
            c1.copy_from_slice(&coefficients[1][lane]);
        }
    }

    /// Returns `self * rhs`, with Karatsuba's three products over `Fp6`, eighteen extension
    /// products in all, or every product of two coefficients for [`Field::SCHOOLBOOK`].
    ///
    /// Runs as its own kernel, so callers share one copy.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn mul<S: Simd>(&self, simd: S, rhs: &Self) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let (a, b) = (self, rhs);
                if F::SCHOOLBOOK {
                    return Self::mul_schoolbook(simd, a, b);
                }
                let t0 = a.c0.product(simd, &b.c0);
                let t1 = a.c1.product(simd, &b.c1);
                let a01 = a.c0.add(simd, a.c1).carry(simd);
                let b01 = b.c0.add(simd, b.c1).carry(simd);
                combine::<S, F>(simd, t0, t1, a01.product(simd, &b01))
            },
        )
    }

    /// Returns `a * b` with the thirty-six products of pairs of coefficients, each accumulated
    /// into its output as it forms.
    #[inline(always)]
    fn mul_schoolbook<S: Simd>(simd: S, a: &Self, b: &Self) -> Self
    where
        F: Field<S>,
    {
        let a = coefficients(a);
        let b = coefficients(b);
        let twisted = twist::<{ BOUND + 1 }, S, F>(simd, &b);
        from_coefficients(Fp2::<F>::reduce_each_tight::<6, 12, BIAS, S>(
            simd,
            #[cfg_attr(not(debug_assertions), inline(always))]
            |k| {
                let k = DEGREE[k];
                // Coefficient k sums a_j b_(k - j), where b_(k - j) for j above k is the twisted
                // coefficient of w^(k + 6 - j).
                let mut sum = a[0].product(simd, b[k]);
                unroll::<5>(
                    #[inline(always)]
                    |j| {
                        let j = j + 1;
                        let factor = if j <= k { b[k - j] } else { twisted[k + 5 - j] };
                        sum = acc(simd, sum, a[j], factor);
                    },
                );
                sum
            },
        ))
    }

    /// Returns `self * self`: `c0^2 + v c1^2 + ((c0 + c1)^2 - c0^2 - c1^2) w`, with three
    /// squarings over `Fp6`, or every product of two coefficients for [`Field::SCHOOLBOOK`].
    ///
    /// Runs as its own kernel, so callers share one copy.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn square<S: Simd>(&self, simd: S) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                if F::SCHOOLBOOK {
                    return Self::square_schoolbook(simd, self);
                }
                let t0 = self.c0.square_product(simd);
                let t1 = self.c1.square_product(simd);
                let sum = self.c0.add(simd, self.c1).carry(simd);
                combine::<S, F>(simd, t0, t1, sum.square_product(simd))
            },
        )
    }

    /// Returns `a * a` with the six squares of coefficients and the fifteen products of pairs,
    /// each taken once with one factor doubled, accumulated into their outputs as they form.
    #[inline(always)]
    fn square_schoolbook<S: Simd>(simd: S, a: &Self) -> Self
    where
        F: Field<S>,
    {
        const K: u64 = BOUND + 1;
        let a = coefficients(a);
        let t = twist::<K, S, F>(simd, &a);
        let mut d = [a[0]; 5];
        unroll::<5>(
            #[inline(always)]
            |j| d[j] = a[j].double(simd).carry(simd),
        );
        from_coefficients(Fp2::<F>::reduce_each_tight::<6, 12, BIAS, S>(
            simd,
            #[cfg_attr(not(debug_assertions), inline(always))]
            |k| {
                // Coefficient k sums a_j a_l over pairs whose degrees add to k, or to k + 6 with
                // the twisted coefficient t[l - 1] of w^(l + 6) in place of a_l.
                let square = |x: Fp2<F>| x.square_product::<K, S>(simd);
                match DEGREE[k] {
                    0 => {
                        let sum = acc(simd, square(a[0]), d[1], t[4]);
                        acc(simd, acc(simd, sum, d[2], t[3]), t[2], a[3])
                    }
                    1 => acc(simd, acc(simd, d[0].product(simd, a[1]), d[2], t[4]), d[3], t[3]),
                    2 => {
                        let sum = acc(simd, square(a[1]), d[0], a[2]);
                        acc(simd, acc(simd, sum, d[3], t[4]), t[3], a[4])
                    }
                    3 => acc(simd, acc(simd, d[0].product(simd, a[3]), d[1], a[2]), d[4], t[4]),
                    4 => {
                        let sum = acc(simd, square(a[2]), d[0], a[4]);
                        acc(simd, acc(simd, sum, d[1], a[3]), t[4], a[5])
                    }
                    _ => acc(simd, acc(simd, d[0].product(simd, a[5]), d[1], a[4]), d[2], a[3]),
                }
            },
        ))
    }

    /// Returns the product of `self` and the line `l0 + l2 w^2 + l3 w^3`, given `[l0, l2, l3]`.
    ///
    /// As an element, the line is `(l0 + l2 v) + l3 v w`, so Karatsuba's products over `Fp6` are
    /// sparse: thirteen extension products in all, or eighteen for [`Field::SCHOOLBOOK`]. Every
    /// line component must have limb bound `1` and integer bound at most [`LINE_BOUND`].
    /// Runs as its own kernel, so callers share one copy.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn mul_by_line<S: Simd>(&self, simd: S, line: &[Fp2<F>; 3]) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let [l0, l2, l3] = *line;
                if F::SCHOOLBOOK {
                    return Self::mul_by_line_schoolbook(simd, self, [l0, l2, l3]);
                }
                let t0 = self.c0.product_by_01(simd, l0, l2);
                let t1 = self.c1.product_by_1(simd, l3);
                let sum = self.c0.add(simd, self.c1).carry(simd);
                let l23 = l2.add(simd, l3).carry(simd);
                combine::<S, F>(simd, t0, t1, sum.product_by_01(simd, l0, l23))
            },
        )
    }

    /// Returns `a` times the line `l0 + l2 w^2 + l3 w^3` with the eighteen products of a
    /// coefficient and a line coefficient, each accumulated into its output as it forms.
    #[inline(always)]
    fn mul_by_line_schoolbook<S: Simd>(simd: S, a: &Self, [l0, l2, l3]: [Fp2<F>; 3]) -> Self
    where
        F: Field<S>,
    {
        const K: u64 = LINE_BOUND + 1;
        let a = coefficients(a);
        let t2 = l2.mul_by_nonresidue::<K, S>(simd).carry(simd);
        let t3 = l3.mul_by_nonresidue::<K, S>(simd).carry(simd);
        from_coefficients(Fp2::<F>::reduce_each_tight::<6, 12, BIAS, S>(
            simd,
            #[cfg_attr(not(debug_assertions), inline(always))]
            |k| {
                // Coefficient k sums a_k l0, a_(k - 2) l2, and a_(k - 3) l3, with the twisted
                // line coefficients against a_(k + 4) and a_(k + 3) where the degree wraps.
                match DEGREE[k] {
                    0 => acc(simd, acc(simd, a[0].product(simd, l0), a[4], t2), a[3], t3),
                    1 => acc(simd, acc(simd, a[1].product(simd, l0), a[5], t2), a[4], t3),
                    2 => acc(simd, acc(simd, a[2].product(simd, l0), a[0], l2), a[5], t3),
                    3 => acc(simd, acc(simd, a[3].product(simd, l0), a[1], l2), a[0], l3),
                    4 => acc(simd, acc(simd, a[4].product(simd, l0), a[2], l2), a[1], l3),
                    _ => acc(simd, acc(simd, a[5].product(simd, l0), a[3], l2), a[2], l3),
                }
            },
        ))
    }

    /// Returns `self^2` for `self` in the cyclotomic subgroup, where `self^(p^6 + 1) = 1`.
    ///
    /// This is the squaring of Granger and Scott, "Faster squaring in the cyclotomic subgroup of
    /// sixth degree extensions" (2010), on the pairs of coefficients of `w^k` and `w^(k + 3)`,
    /// elements `x + y s` of `Fp4 = Fp2[s] / (s^2 - (1 + i))` for `s = w^3`: each output is three
    /// times a part of the square of such a pair, plus or minus twice an input coefficient. That
    /// takes nine extension squarings, or six squarings and six products accumulated as they form
    /// for [`Field::SCHOOLBOOK`]. The result is unspecified outside the subgroup.
    /// Runs as its own kernel, so callers share one copy.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn cyclotomic_square<S: Simd>(&self, simd: S) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                if F::SCHOOLBOOK {
                    return Self::cyclotomic_square_schoolbook(simd, self);
                }
                // The coefficients a0, ..., a5 of 1, w, ..., w^5.
                let (a0, a1, a2) = (self.c0.c0, self.c1.c0, self.c0.c1);
                let (a3, a4, a5) = (self.c1.c1, self.c0.c2, self.c1.c2);
                let (real03, imaginary03) = square_pair::<S, F>(simd, a0, a3);
                let (real14, imaginary14) = square_pair::<S, F>(simd, a1, a4);
                let (real25, imaginary25) = square_pair::<S, F>(simd, a2, a5);
                let imaginary25 = Fp2::<F>::product_mul_by_nonresidue(simd, imaginary25);
                from_coefficients(Fp2::<F>::reduce_each_tight::<6, 12, BIAS, S>(
                    simd,
                    #[inline(always)]
                    |k| match k {
                        0 => three_times::<S, F, false>(simd, real03, a0),
                        1 => three_times::<S, F, false>(simd, real14, a2),
                        2 => three_times::<S, F, false>(simd, real25, a4),
                        3 => three_times::<S, F, true>(simd, imaginary25, a1),
                        4 => three_times::<S, F, true>(simd, imaginary03, a3),
                        _ => three_times::<S, F, true>(simd, imaginary14, a5),
                    },
                ))
            },
        )
    }

    /// Returns the cyclotomic square of `a` with every product accumulated into its output as it
    /// forms.
    ///
    /// For the pair `x + y s`, the real part of the square is `x^2 + (1 + i) y^2`, with the
    /// nonresidue multiplied into one factor of `y^2`, and the imaginary part is `(2 x) y`. Each
    /// output is three times such a part, accumulated three times, plus or minus twice a
    /// coefficient, lifted into the sum.
    #[inline(always)]
    fn cyclotomic_square_schoolbook<S: Simd>(simd: S, a: &Self) -> Self
    where
        F: Field<S>,
    {
        let a = coefficients(a);
        from_coefficients(Fp2::<F>::reduce_each_tight::<6, 12, BIAS, S>(
            simd,
            #[cfg_attr(not(debug_assertions), inline(always))]
            |k| {
                // The pairs are (a0, a3), (a1, a4), and (a2, a5); the imaginary part of the last
                // lands on w^7 = (1 + i) w.
                match DEGREE[k] {
                    0 => cyclotomic_real::<S, F>(simd, a[0], a[3], a[0]),
                    2 => cyclotomic_real::<S, F>(simd, a[1], a[4], a[2]),
                    4 => cyclotomic_real::<S, F>(simd, a[2], a[5], a[4]),
                    1 => {
                        let twisted = nonresidue::<{ BOUND + 1 }, S, F>(simd, a[2]);
                        cyclotomic_imaginary::<S, F>(simd, doubled(simd, twisted), a[5], a[1])
                    }
                    3 => cyclotomic_imaginary::<S, F>(simd, doubled(simd, a[0]), a[3], a[3]),
                    _ => cyclotomic_imaginary::<S, F>(simd, doubled(simd, a[1]), a[4], a[5]),
                }
            },
        ))
    }

    /// Returns the conjugate `c0 - c1 w`, which is `self^(p^6)` and the inverse in the cyclotomic
    /// subgroup.
    ///
    /// Reduces the negated coefficient tightly, so the result stays within [`BOUND`].
    /// Runs as its own kernel, so callers share one copy.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn conjugate<S: Simd>(&self, simd: S) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let negated = self.c1.neg::<{ BOUND + 1 }, S>(simd);
                Self {
                    c0: self.c0,
                    c1: Fp6::<F>::reduce_tight::<1, S>(simd, negated.lift(simd)),
                }
            },
        )
    }

    /// Loads the factors `(1 + i)^(j (p - 1) / 6)` for `j` from `1` to `5` in every lane.
    ///
    /// Components have the base field's initial bounds.
    /// Runs as its own kernel, so that callers outside kernels load them with the backend's
    /// instructions.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn frobenius_coefficients<S: Simd>(simd: S) -> [Fp2<F>; 5]
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| core::array::from_fn(|j| Fp2::load(simd, &[], &FROBENIUS[j])),
        )
    }

    /// Returns the Frobenius image `self^p`.
    ///
    /// Conjugates every coefficient of `w^j` and multiplies it by `(1 + i)^(j (p - 1) / 6)`.
    /// Requires the factors returned by [`Self::frobenius_coefficients`].
    /// Runs as its own kernel, so callers share one copy.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn frobenius<S: Simd>(&self, simd: S, coefficients: &[Fp2<F>; 5]) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                // The coefficients of 1, w, ..., w^5.
                let a = [
                    self.c0.c0, self.c1.c0, self.c0.c1, self.c1.c1, self.c0.c2, self.c1.c2,
                ];
                let mut b = a;
                let conjugate = a[0].conjugate::<{ BOUND + 1 }, S>(simd);
                b[0] = Fp2::<F>::reduce_tight::<1, S>(simd, conjugate.lift(simd));
                for j in 1..6 {
                    let conjugate = a[j].conjugate::<{ BOUND + 1 }, S>(simd).carry(simd);
                    let gamma = coefficients[j - 1];
                    b[j] = Fp2::<F>::reduce_tight::<BIAS, S>(simd, conjugate.product(simd, gamma));
                }
                Self {
                    c0: Fp6 {
                        c0: b[0],
                        c1: b[2],
                        c2: b[4],
                    },
                    c1: Fp6 {
                        c0: b[1],
                        c1: b[3],
                        c2: b[5],
                    },
                }
            },
        )
    }

    /// Returns the inverse `(c0 - c1 w) / (c0^2 - v c1^2)`, or zero for zero.
    ///
    /// Inverts the norm in `Fp6` with [`Fp6::invert`].
    /// Runs as its own kernel, so callers share one copy.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn invert<S: Simd>(&self, simd: S) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let norm = Fp6::<F>::product_sub(
                    simd,
                    self.c0.square_product(simd),
                    Fp6::<F>::product_mul_by_nonresidue(simd, self.c1.square_product(simd)),
                );
                let inverse = Fp6::<F>::reduce_tight::<BIAS, S>(simd, norm).invert(simd);
                let negated = self.c1.neg::<{ BOUND + 1 }, S>(simd).carry(simd);
                Self {
                    c0: Fp6::<F>::reduce_tight::<BIAS, S>(simd, self.c0.product(simd, &inverse)),
                    c1: Fp6::<F>::reduce_tight::<BIAS, S>(simd, negated.product(simd, &inverse)),
                }
            },
        )
    }

    /// Returns the product of every lane's element, in every lane.
    ///
    /// Multiplies halves of the lanes together until one remains, moving elements between lanes
    /// through their encodings. A representation holding one element returns it as is.
    /// Runs as its own kernel, so callers share one copy.
    pub fn product_of_lanes<S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        if F::LANES == 1 {
            return self;
        }
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let mut lanes = [[0; BYTES]; MAX_LANES];
                self.store(simd, &mut lanes);
                let mut count = F::LANES;
                while count > 1 {
                    let half = count.div_ceil(2);
                    let low = Self::load(simd, &lanes[..half], &ONE);
                    let high = Self::load(simd, &lanes[half..count], &ONE);
                    low.mul(simd, &high).store(simd, &mut lanes[..half]);
                    count = half;
                }
                Self::load(simd, &[], &lanes[0])
            },
        )
    }
}

/// Combines Karatsuba's products over `Fp6`, `t0 = a0 b0`, `t1 = a1 b1`, and
/// `sum = (a0 + a1)(b0 + b1)`, into `t0 + v t1 + (sum - t0 - t1) w`, and reduces it tightly.
#[cfg_attr(not(debug_assertions), inline(always))]
fn combine<S: Simd, F: Field<S>>(
    simd: S,
    t0: fp6::Product<F, S>,
    t1: fp6::Product<F, S>,
    sum: fp6::Product<F, S>,
) -> Fp12<F> {
    let t0 = Fp6::<F>::carry_product(simd, t0);
    let t1 = Fp6::<F>::carry_product(simd, t1);
    let sum = Fp6::<F>::carry_product(simd, sum);
    let c0 = Fp6::<F>::accumulate(simd, t0, Fp6::<F>::product_mul_by_nonresidue(simd, t1));
    let c1 = Fp6::<F>::product_sub(simd, Fp6::<F>::product_sub(simd, sum, t0), t1);
    let products = [c0.c0, c0.c1, c0.c2, c1.c0, c1.c1, c1.c2];
    from_coefficients(Fp2::<F>::reduce_each_tight::<6, 12, BIAS, S>(
        simd,
        #[inline(always)]
        |k| products[k],
    ))
}

/// Returns the element with the coefficients of `1`, `v`, and `v^2` in `c0`, then in `c1`.
#[inline(always)]
fn from_coefficients<T>([c00, c01, c02, c10, c11, c12]: [Fp2<T>; 6]) -> Fp12<T> {
    Fp12 {
        c0: Fp6 {
            c0: c00,
            c1: c01,
            c2: c02,
        },
        c1: Fp6 {
            c0: c10,
            c1: c11,
            c2: c12,
        },
    }
}

/// Returns the coefficients of `1, w, ..., w^5`, where `w^2 = v`.
#[inline(always)]
const fn coefficients<T: Copy>(a: &Fp12<T>) -> [Fp2<T>; 6] {
    [a.c0.c0, a.c1.c0, a.c0.c1, a.c1.c1, a.c0.c2, a.c1.c2]
}

/// The degree in `w` of each coefficient in the order of [`from_coefficients`].
const DEGREE: [usize; 6] = [0, 2, 4, 1, 3, 5];

/// Returns the coefficients of `w^7, ..., w^11` of an element with the given coefficients of
/// `1, w, ..., w^5`: those of `w, ..., w^5` times `w^6 = 1 + i`, carried, with the bias `K`
/// covering their imaginary components.
#[inline(always)]
fn twist<const K: u64, S: Simd, F: Field<S>>(simd: S, a: &[Fp2<F>; 6]) -> [Fp2<F>; 5] {
    let mut twisted = [a[1]; 5];
    unroll::<5>(
        #[inline(always)]
        |l| twisted[l] = nonresidue::<K, S, F>(simd, a[l + 1]),
    );
    twisted
}

/// Returns `a (1 + i)`, carried, with the bias `K` covering its imaginary component.
#[inline(always)]
fn nonresidue<const K: u64, S: Simd, F: Field<S>>(simd: S, a: Fp2<F>) -> Fp2<F> {
    a.mul_by_nonresidue::<K, S>(simd).carry(simd)
}

/// Returns `2 a`, carried.
#[inline(always)]
fn doubled<S: Simd, F: Field<S>>(simd: S, a: Fp2<F>) -> Fp2<F> {
    a.double(simd).carry(simd)
}

/// Returns `sum + x * y`, as [`Fp2::accumulate_product`] does.
#[inline(always)]
fn acc<S: Simd, F: Field<S>>(
    simd: S,
    sum: super::fp2::Product<F, S>,
    x: Fp2<F>,
    y: Fp2<F>,
) -> super::fp2::Product<F, S> {
    Fp2::<F>::accumulate_product(simd, sum, x, y)
}

/// Returns `3 part`, accumulated.
#[inline(always)]
fn tripled<S: Simd, F: Field<S>>(
    simd: S,
    part: super::fp2::Product<F, S>,
) -> super::fp2::Product<F, S> {
    Fp2::<F>::accumulate(simd, part, Fp2::<F>::accumulate(simd, part, part))
}

/// Returns `3 (x^2 + (1 + i) y^2) - 2 c`, the real part of the cyclotomic square of the pair
/// `x + y s` tripled less twice the coefficient `c`, with every product accumulated as it forms.
///
/// The nonresidue multiplies into one factor of `y^2`, and `2 c` is negated and lifted into the
/// sum.
#[inline(always)]
fn cyclotomic_real<S: Simd, F: Field<S>>(
    simd: S,
    x: Fp2<F>,
    y: Fp2<F>,
    c: Fp2<F>,
) -> super::fp2::Product<F, S> {
    let square = x.square_product::<{ BOUND + 1 }, S>(simd);
    let sum = acc(simd, square, nonresidue::<{ BOUND + 1 }, S, F>(simd, y), y);
    let negated = doubled(simd, c).neg::<{ 2 * BOUND + 1 }, S>(simd);
    Fp2::<F>::accumulate_lift(simd, tripled::<S, F>(simd, sum), negated)
}

/// Returns `3 x2 y + 2 c`, the imaginary part of the cyclotomic square of the pair `x + y s`
/// tripled plus twice the coefficient `c`, given the doubled factor `x2 = 2 x`.
#[inline(always)]
fn cyclotomic_imaginary<S: Simd, F: Field<S>>(
    simd: S,
    x2: Fp2<F>,
    y: Fp2<F>,
    c: Fp2<F>,
) -> super::fp2::Product<F, S> {
    let product = x2.product(simd, y);
    Fp2::<F>::accumulate_lift(simd, tripled::<S, F>(simd, product), doubled(simd, c))
}

/// Returns the parts of `(x + y s)^2` in `Fp4`, `x^2 + (1 + i) y^2` and `2 x y`, as carried
/// products.
#[cfg_attr(not(debug_assertions), inline(always))]
fn square_pair<S: Simd, F: Field<S>>(
    simd: S,
    x: Fp2<F>,
    y: Fp2<F>,
) -> (super::fp2::Product<F, S>, super::fp2::Product<F, S>) {
    let xx = x.square_product::<{ BOUND + 1 }, S>(simd);
    let yy = y.square_product::<{ BOUND + 1 }, S>(simd);
    let sum = x.add(simd, y).carry(simd);
    let real = Fp2::<F>::accumulate(simd, xx, Fp2::<F>::product_mul_by_nonresidue(simd, yy));
    // (x + y)^2 - x^2 - y^2.
    let imaginary = Fp2::<F>::product_sub(
        simd,
        Fp2::<F>::product_sub(simd, sum.square_product::<{ 2 * BOUND + 1 }, S>(simd), xx),
        yy,
    );
    (
        Fp2::<F>::carry_product(simd, real),
        Fp2::<F>::carry_product(simd, imaginary),
    )
}

/// Returns `3 part + 2 a` when `ADD` is set and `3 part - 2 a` otherwise, as a product to
/// reduce tightly.
#[cfg_attr(not(debug_assertions), inline(always))]
fn three_times<S: Simd, F: Field<S>, const ADD: bool>(
    simd: S,
    part: super::fp2::Product<F, S>,
    a: Fp2<F>,
) -> super::fp2::Product<F, S> {
    let tripled = tripled::<S, F>(simd, part);
    let doubled = a.double(simd).lift(simd);
    if ADD {
        Fp2::<F>::accumulate(simd, tripled, doubled)
    } else {
        Fp2::<F>::product_sub(simd, tripled, doubled)
    }
}

/// Splits an element's encoding into its `c1` and `c0` encodings.
#[inline(always)]
fn split(element: &[u8; BYTES]) -> (&[u8; FP6_BYTES], &[u8; FP6_BYTES]) {
    let (c1, c0) = element
        .split_first_chunk::<FP6_BYTES>()
        .expect("two coefficients");
    (c1, c0.try_into().expect("two coefficients"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::core::field::{
        fp::{
            rns::Rns,
            tests::{self as reference, Element},
            unsat28::Unsat28,
            unsat49::Unsat49,
        },
        fp6::BYTES as FP6_BYTES,
    };
    use arbitrary::Unstructured;
    use commonware_simd::{
        Operation, X86V4C, check_consistent,
        emulated::{EmulatedNeon, EmulatedScalar, EmulatedX86V4C},
        test_dispatch,
    };
    use std::{vec, vec::Vec};

    /// Chained rounds of every operation in [`evaluate`].
    const ROUNDS: usize = 3;

    /// Chained cyclotomic squarings in [`evaluate`].
    const SQUARINGS: usize = 8;

    /// Outputs per lane of [`evaluate`].
    const OUTPUTS: usize = 14;

    /// Returns the components of an encoding, in blst's order: `c0.c0.c0`, `c0.c0.c1`,
    /// `c0.c1.c0`, and so on.
    fn components(bytes: &[u8; BYTES]) -> [[u8; FP_BYTES]; 12] {
        let (chunks, _) = bytes.as_chunks::<FP_BYTES>();
        let mut components = [[0; FP_BYTES]; 12];
        for (k, component) in components.iter_mut().enumerate() {
            // Coefficient k / 2 of Fp6 coefficient k / 6, highest first in each encoding.
            let (fp6, fp2, fp) = (k / 6, (k / 2) % 3, k % 2);
            *component = chunks[(1 - fp6) * 6 + (2 - fp2) * 2 + (1 - fp)];
        }
        components
    }

    /// Returns the encoding of components in blst's order.
    fn from_components(components: &[[u8; FP_BYTES]; 12]) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        let (chunks, _) = bytes.as_chunks_mut::<FP_BYTES>();
        for (k, component) in components.iter().enumerate() {
            let (fp6, fp2, fp) = (k / 6, (k / 2) % 3, k % 2);
            chunks[(1 - fp6) * 6 + (2 - fp2) * 2 + (1 - fp)] = *component;
        }
        bytes
    }

    /// Converts an encoding to blst's representation.
    pub(crate) fn to_blst(bytes: &[u8; BYTES]) -> blst::blst_fp12 {
        let mut value = blst::blst_fp12::default();
        for (k, component) in components(bytes).iter().enumerate() {
            let fp = &mut value.fp6[k / 6].fp2[(k / 2) % 3].fp[k % 2];
            // SAFETY: the pointers reference a valid field element and 48 readable bytes.
            unsafe { blst::blst_fp_from_bendian(fp, component.as_ptr()) };
        }
        value
    }

    /// Converts blst's representation to an encoding.
    pub(crate) fn from_blst(value: &blst::blst_fp12) -> [u8; BYTES] {
        let mut components = [[0; FP_BYTES]; 12];
        for (k, component) in components.iter_mut().enumerate() {
            let fp = &value.fp6[k / 6].fp2[(k / 2) % 3].fp[k % 2];
            // SAFETY: the pointers reference a valid field element and 48 writable bytes.
            unsafe { blst::blst_bendian_from_fp(component.as_mut_ptr(), fp) };
        }
        from_components(&components)
    }

    /// Applies a blst operation to encodings.
    fn blst_mul(a: &[u8; BYTES], b: &[u8; BYTES]) -> [u8; BYTES] {
        let mut out = blst::blst_fp12::default();
        // SAFETY: the pointers reference valid field elements.
        unsafe { blst::blst_fp12_mul(&mut out, &to_blst(a), &to_blst(b)) };
        from_blst(&out)
    }

    fn blst_square(a: &[u8; BYTES]) -> [u8; BYTES] {
        let mut out = blst::blst_fp12::default();
        // SAFETY: the pointers reference valid field elements.
        unsafe { blst::blst_fp12_sqr(&mut out, &to_blst(a)) };
        from_blst(&out)
    }

    fn blst_conjugate(a: &[u8; BYTES]) -> [u8; BYTES] {
        let mut value = to_blst(a);
        // SAFETY: the pointer references a valid field element.
        unsafe { blst::blst_fp12_conjugate(&mut value) };
        from_blst(&value)
    }

    fn blst_frobenius(a: &[u8; BYTES], n: usize) -> [u8; BYTES] {
        let mut out = blst::blst_fp12::default();
        // SAFETY: the pointers reference valid field elements.
        unsafe { blst::blst_fp12_frobenius_map(&mut out, &to_blst(a), n) };
        from_blst(&out)
    }

    pub(crate) fn blst_invert(a: &[u8; BYTES]) -> [u8; BYTES] {
        let mut out = blst::blst_fp12::default();
        // SAFETY: the pointers reference valid field elements.
        unsafe { blst::blst_fp12_inverse(&mut out, &to_blst(a)) };
        from_blst(&out)
    }

    fn blst_cyclotomic_square(a: &[u8; BYTES]) -> [u8; BYTES] {
        let mut out = blst::blst_fp12::default();
        // SAFETY: the pointers reference valid field elements.
        unsafe { blst::blst_fp12_cyclotomic_sqr(&mut out, &to_blst(a)) };
        from_blst(&out)
    }

    /// Returns the element of line coefficients `[l0, l2, l3]`: `(l0 + l2 v) + l3 v w`.
    fn line_element(line: &[[u8; FP2_BYTES]; 3]) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        let (chunks, _) = bytes.as_chunks_mut::<FP2_BYTES>();
        // Coefficients c1.c2, c1.c1, c1.c0, c0.c2, c0.c1, c0.c0.
        chunks[5] = line[0];
        chunks[4] = line[1];
        chunks[1] = line[2];
        bytes
    }

    /// Returns `(t, 0)` for an `Fp6` encoding `t`.
    fn embed(t: &[u8; FP6_BYTES]) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[FP6_BYTES..].copy_from_slice(t);
        bytes
    }

    /// Returns an element with canonical components.
    pub(crate) fn element(u: &mut Unstructured<'_>) -> arbitrary::Result<[u8; BYTES]> {
        let mut components = [[0; FP_BYTES]; 12];
        for component in &mut components {
            *component = reference::to_bytes(reference::canonical(u)?);
        }
        Ok(from_components(&components))
    }

    /// Maps a nonzero element into the cyclotomic subgroup: `a^((p^6 - 1)(p^2 + 1))`.
    pub(crate) fn cyclotomic(a: &[u8; BYTES]) -> [u8; BYTES] {
        let a = blst_mul(&blst_conjugate(a), &blst_invert(a));
        blst_mul(&blst_frobenius(&a, 2), &a)
    }

    /// The inputs of one lane.
    #[derive(Clone, Copy)]
    struct Inputs {
        a: [u8; BYTES],
        b: [u8; BYTES],
        /// An element of the cyclotomic subgroup.
        c: [u8; BYTES],
        /// The coefficients of `1, w^2, w^3` of a line.
        line: [[u8; FP2_BYTES]; 3],
    }

    /// Returns the same extension value with every component at integer bound `2 + K`, given
    /// loaded components with integer bound `2`.
    fn widen<const K: u64, S: Simd, F: Field<S>>(simd: S, value: Fp2<F>) -> Fp2<F> {
        let zero = Fp2::<F>::load(simd, &[], &[0; FP2_BYTES]);
        value.sub::<K, S>(simd, zero).carry(simd)
    }

    /// Loads elements and widens every component to integer bound [`BOUND`].
    fn load_wide<S: Simd, F: Field<S>>(simd: S, elements: &[[u8; BYTES]]) -> Fp12<F> {
        let value = Fp12::<F>::load(simd, elements, &ONE);
        let widen6 = |value: Fp6<F>| Fp6 {
            c0: widen::<{ BOUND - 2 }, S, F>(simd, value.c0),
            c1: widen::<{ BOUND - 2 }, S, F>(simd, value.c1),
            c2: widen::<{ BOUND - 2 }, S, F>(simd, value.c2),
        };
        Fp12 {
            c0: widen6(value.c0),
            c1: widen6(value.c1),
        }
    }

    /// Checks, in debug builds, that every component satisfies the element bounds.
    fn check_bound<S: Simd, F: Field<S>>(simd: S, value: Fp12<F>) -> Fp12<F> {
        for fp6 in [value.c0, value.c1] {
            fp6.neg::<{ BOUND + 1 }, S>(simd);
        }
        value
    }

    /// The inputs of a chunk of lanes, loaded and widened.
    struct Loaded<F> {
        a: Fp12<F>,
        b: Fp12<F>,
        c: Fp12<F>,
        line: [Fp2<F>; 3],
    }

    /// An operation on loaded inputs.
    type Step<S, F> = fn(S, &Loaded<F>) -> Fp12<F>;

    /// Loads the inputs of a chunk of lanes, widening every component to its bound.
    #[inline(never)]
    fn load_chunk<S: Simd, F: Field<S>>(simd: S, chunk: &[Inputs]) -> Loaded<F> {
        let a: Vec<_> = chunk.iter().map(|inputs| inputs.a).collect();
        let b: Vec<_> = chunk.iter().map(|inputs| inputs.b).collect();
        let c: Vec<_> = chunk.iter().map(|inputs| inputs.c).collect();
        let mut line = [Fp2::<F>::load(simd, &[], &[0; FP2_BYTES]); 3];
        for (k, coefficient) in line.iter_mut().enumerate() {
            let lanes: Vec<_> = chunk.iter().map(|inputs| inputs.line[k]).collect();
            let loaded = Fp2::<F>::load(simd, &lanes, &[0; FP2_BYTES]);
            *coefficient = widen::<{ LINE_BOUND - 2 }, S, F>(simd, loaded);
        }
        Loaded {
            a: load_wide(simd, &a),
            b: load_wide(simd, &b),
            c: load_wide(simd, &c),
            line,
        }
    }

    /// Returns `(t, 0)` for a value `t` of `Fp6`.
    fn embed6<S: Simd, F: Field<S>>(simd: S, t: Fp6<F>) -> Fp12<F> {
        Fp12 {
            c0: t,
            c1: Fp6::load(simd, &[], &[0; FP6_BYTES]),
        }
    }

    fn mul<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        x.a.mul(simd, &x.b)
    }

    fn square<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        x.a.square(simd)
    }

    fn mul_by_line<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        x.a.mul_by_line(simd, &x.line)
    }

    fn cyclotomic_square<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        x.c.cyclotomic_square(simd)
    }

    fn conjugate<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        x.a.conjugate(simd)
    }

    fn frobenius<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        let coefficients = Fp12::<F>::frobenius_coefficients(simd);
        x.a.frobenius(simd, &coefficients)
    }

    fn invert<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        x.a.invert(simd)
    }

    /// Every operation on the outputs of others.
    fn chain<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        let coefficients = Fp12::<F>::frobenius_coefficients(simd);
        let mut y = x.a;
        for _ in 0..ROUNDS {
            y = check_bound(simd, y.mul(simd, &x.b));
            y = check_bound(simd, y.square(simd));
            y = check_bound(simd, y.mul_by_line(simd, &x.line));
            y = check_bound(simd, y.conjugate(simd));
            y = check_bound(simd, y.frobenius(simd, &coefficients));
            y = check_bound(simd, y.invert(simd));
        }
        y
    }

    fn cyclotomic_chain<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        let mut y = x.c;
        for _ in 0..SQUARINGS {
            y = check_bound(simd, y.cyclotomic_square(simd).conjugate(simd));
        }
        y
    }

    fn product6<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        let product = x.a.c0.product(simd, &x.b.c0);
        embed6(simd, Fp6::<F>::reduce_tight::<BIAS, S>(simd, product))
    }

    fn square6<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        let product = x.a.c0.square_product(simd);
        embed6(simd, Fp6::<F>::reduce_tight::<BIAS, S>(simd, product))
    }

    fn product6_by_01<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        let product = x.a.c0.product_by_01(simd, x.line[0], x.line[1]);
        embed6(simd, Fp6::<F>::reduce_tight::<BIAS, S>(simd, product))
    }

    fn product6_by_1<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        let product = x.a.c0.product_by_1(simd, x.line[2]);
        embed6(simd, Fp6::<F>::reduce_tight::<BIAS, S>(simd, product))
    }

    fn invert6<S: Simd, F: Field<S>>(simd: S, x: &Loaded<F>) -> Fp12<F> {
        embed6(simd, x.a.c0.invert(simd))
    }

    /// Evaluates every operation on one input per lane.
    ///
    /// Each operation runs in its own function, so debug builds keep every frame small.
    fn evaluate<S: Simd, F: Field<S>>(simd: S, inputs: &[Inputs]) -> Vec<[[u8; BYTES]; OUTPUTS]> {
        let operations: [Step<S, F>; OUTPUTS] = [
            mul,
            square,
            mul_by_line,
            cyclotomic_square,
            conjugate,
            frobenius,
            invert,
            chain,
            cyclotomic_chain,
            product6,
            square6,
            product6_by_01,
            product6_by_1,
            invert6,
        ];
        let mut outputs = vec![[[0; BYTES]; OUTPUTS]; inputs.len()];
        for start in (0..inputs.len()).step_by(F::LANES) {
            let chunk = &inputs[start..inputs.len().min(start + F::LANES)];
            let loaded = load_chunk::<S, F>(simd, chunk);
            for (k, operation) in operations.iter().enumerate() {
                let mut lanes = [[0; BYTES]; MAX_LANES];
                check_bound(simd, operation(simd, &loaded)).store(simd, &mut lanes[..chunk.len()]);
                for (output, lane) in outputs[start..].iter_mut().zip(&lanes[..chunk.len()]) {
                    output[k] = *lane;
                }
            }
        }
        outputs
    }

    /// Returns the expected outputs of [`evaluate`] for one lane.
    fn expected(inputs: &Inputs) -> [[u8; BYTES]; OUTPUTS] {
        let Inputs {
            a,
            b,
            c,
            line: coefficients,
        } = *inputs;
        let line = line_element(&coefficients);
        let mut outputs = [[0; BYTES]; OUTPUTS];
        outputs[0] = blst_mul(&a, &b);
        outputs[1] = blst_square(&a);
        outputs[2] = blst_mul(&a, &line);
        outputs[3] = blst_cyclotomic_square(&c);
        outputs[4] = blst_conjugate(&a);
        outputs[5] = blst_frobenius(&a, 1);
        outputs[6] = blst_invert(&a);
        let mut x = a;
        for _ in 0..ROUNDS {
            x = blst_mul(&x, &b);
            x = blst_square(&x);
            x = blst_mul(&x, &line);
            x = blst_conjugate(&x);
            x = blst_frobenius(&x, 1);
            x = blst_invert(&x);
        }
        outputs[7] = x;
        let mut y = c;
        for _ in 0..SQUARINGS {
            y = blst_conjugate(&blst_cyclotomic_square(&y));
        }
        outputs[8] = y;
        let low = |x: &[u8; BYTES]| -> [u8; FP6_BYTES] { x[FP6_BYTES..].try_into().unwrap() };
        let (a0, b0) = (embed(&low(&a)), embed(&low(&b)));
        outputs[9] = blst_mul(&a0, &b0);
        outputs[10] = blst_square(&a0);
        // (l0 + l2 v, 0) and (l3 v, 0).
        let mut l01 = line;
        l01[..FP6_BYTES].fill(0);
        outputs[11] = blst_mul(&a0, &l01);
        let mut l1 = [0; BYTES];
        l1[FP6_BYTES + FP2_BYTES..FP6_BYTES + 2 * FP2_BYTES].copy_from_slice(&coefficients[2]);
        outputs[12] = blst_mul(&a0, &l1);
        outputs[13] = blst_invert(&a0);
        outputs
    }

    /// Runs [`evaluate`] in every representation, returning the positional ones' outputs.
    struct Evaluate<'a>(&'a [Inputs]);

    impl<S: Simd> Operation<S> for Evaluate<'_> {
        type Output = [Vec<[[u8; BYTES]; OUTPUTS]>; 2];

        fn portable(self, simd: S) -> Self::Output {
            simd.execute(|simd: S| {
                [
                    evaluate::<S, Unsat49<S>>(simd, self.0),
                    evaluate::<S, Unsat28<S>>(simd, self.0),
                ]
            })
        }

        // Residues require x86v4c and must match the other representations.
        fn x86_v4c(self, simd: S) -> Self::Output
        where
            S: X86V4C,
        {
            let inputs = self.0;
            let outputs = self.portable(simd);
            let residues = simd.execute(|simd: S| evaluate::<S, Rns<S>>(simd, inputs));
            assert!(residues == outputs[0], "residues differ");
            outputs
        }
    }

    #[test]
    fn operations_match_blst() {
        let mut inputs = Vec::new();
        for lane in 0..MAX_LANES {
            let seed = [(lane as u8).wrapping_mul(37).wrapping_add(11); 4096];
            let mut u = Unstructured::new(&seed);
            let mut lane_inputs = Inputs {
                a: element(&mut u).unwrap(),
                b: element(&mut u).unwrap(),
                c: [0; BYTES],
                line: [[0; FP2_BYTES]; 3],
            };
            lane_inputs.c = cyclotomic(&element(&mut u).unwrap());
            for coefficient in &mut lane_inputs.line {
                let (c0, c1) = (
                    reference::canonical(&mut u).unwrap(),
                    reference::canonical(&mut u).unwrap(),
                );
                coefficient[..FP_BYTES].copy_from_slice(&reference::to_bytes(c1));
                coefficient[FP_BYTES..].copy_from_slice(&reference::to_bytes(c0));
            }
            inputs.push(lane_inputs);
        }
        // Edge cases in the first lanes: zero, one, and an element of Fp2.
        inputs[0].a = [0; BYTES];
        inputs[1].a = ONE;
        inputs[2].b = ONE;
        let expected: Vec<_> = inputs.iter().map(expected).collect();
        let check = |outputs: [Vec<[[u8; BYTES]; OUTPUTS]>; 2]| {
            for (representation, output) in outputs.iter().enumerate() {
                for (lane, (output, expected)) in output.iter().zip(&expected).enumerate() {
                    for k in 0..OUTPUTS {
                        assert!(
                            output[k] == expected[k],
                            "output {k}, representation {representation}, lane {lane}"
                        );
                    }
                }
            }
        };
        check(test_dispatch(Evaluate(&inputs)));
        // Run every representation and vector width even on hosts without native SIMD.
        check(Evaluate(&inputs).portable(EmulatedScalar));
        check(Evaluate(&inputs).portable(EmulatedNeon));
        check(EmulatedX86V4C.execute(Evaluate(&inputs)));
        check_consistent(|| Evaluate(&inputs[..4]));
    }

    #[test]
    fn frobenius_constants_are_powers_of_the_nonresidue() {
        let mul = |(a0, a1): (Element, Element), (b0, b1): (Element, Element)| {
            (
                reference::sub(reference::mul(a0, b0), reference::mul(a1, b1)),
                reference::add(reference::mul(a0, b1), reference::mul(a1, b0)),
            )
        };
        // (p - 1) / 6, little-endian.
        let mut exponent = crate::core::field::fp::MODULUS;
        exponent[0] -= 1;
        let mut remainder = 0u128;
        for word in exponent.iter_mut().rev() {
            let value = (remainder << 64) | *word as u128;
            *word = (value / 6) as u64;
            remainder = value % 6;
        }
        assert_eq!(remainder, 0);
        let nonresidue = (reference::ONE, reference::ONE);
        let mut gamma = (reference::ONE, reference::ZERO);
        for word in exponent.iter().rev() {
            for bit in (0..64).rev() {
                gamma = mul(gamma, gamma);
                if (word >> bit) & 1 == 1 {
                    gamma = mul(gamma, nonresidue);
                }
            }
        }
        let mut power = gamma;
        for constant in &FROBENIUS {
            let (c0, c1) = power;
            assert_eq!(constant[..FP_BYTES], reference::to_bytes(c1));
            assert_eq!(constant[FP_BYTES..], reference::to_bytes(c0));
            power = mul(power, gamma);
        }
    }
}
