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
    fp2::{BYTES as FP2_BYTES, Fp2, encode},
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
    /// Runs as its own kernel, so that callers outside kernels convert with the backend's
    /// instructions.
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
        simd.execute(
            #[inline(always)]
            move |simd: S| Self {
                c0: Fp6::load(simd, &coefficients[0][..lanes], fill0),
                c1: Fp6::load(simd, &coefficients[1][..lanes], fill1),
            },
        )
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
    /// Runs as its own kernel, as [`Self::load`] does.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn store<S: Simd>(self, simd: S, elements: &mut [[u8; BYTES]])
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let lanes = elements.len().min(F::LANES);
        let coefficients = simd.execute(
            #[inline(always)]
            move |simd: S| {
                let mut coefficients = [[[0; FP6_BYTES]; MAX_LANES]; 2];
                self.c0.store(simd, &mut coefficients[0][..lanes]);
                self.c1.store(simd, &mut coefficients[1][..lanes]);
                coefficients
            },
        );
        for (lane, element) in elements[..lanes].iter_mut().enumerate() {
            let (c1, c0) = element.split_at_mut(FP6_BYTES);
            c0.copy_from_slice(&coefficients[0][lane]);
            c1.copy_from_slice(&coefficients[1][lane]);
        }
    }

    /// Multiplies by `rhs` in place, with Karatsuba's three products over `Fp6`, eighteen
    /// extension products in all, or every product of two coefficients for
    /// [`Field::SCHOOLBOOK`].
    ///
    /// Runs as its own kernel, so callers share one copy, and replaces the value in place, so
    /// that a chain of operations copies nothing.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn mul<S: Simd>(&mut self, simd: S, rhs: &Self)
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let (a, b) = (&*self, rhs);
                let product = if F::SCHOOLBOOK {
                    Self::mul_schoolbook(simd, a, b)
                } else {
                    let t0 = a.c0.product(simd, &b.c0);
                    let t1 = a.c1.product(simd, &b.c1);
                    let a01 = a.c0.add(simd, a.c1).carry(simd);
                    let b01 = b.c0.add(simd, b.c1).carry(simd);
                    combine::<S, F>(simd, t0, t1, a01.product(simd, &b01))
                };
                *self = product;
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

    /// Squares in place: `c0^2 + v c1^2 + ((c0 + c1)^2 - c0^2 - c1^2) w`, with three squarings over
    /// `Fp6`, or every product of two coefficients for [`Field::SCHOOLBOOK`].
    ///
    /// Runs as its own kernel, so callers share one copy, and replaces the value in place.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn square<S: Simd>(&mut self, simd: S)
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let a = &*self;
                let square = if F::SCHOOLBOOK {
                    Self::square_schoolbook(simd, a)
                } else {
                    let t0 = a.c0.square_product(simd);
                    let t1 = a.c1.square_product(simd);
                    let sum = a.c0.add(simd, a.c1).carry(simd);
                    combine::<S, F>(simd, t0, t1, sum.square_product(simd))
                };
                *self = square;
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
                match DEGREE[k] {
                    0 => {
                        let sum = acc(simd, a[0].square_product::<K, S>(simd), d[1], t[4]);
                        acc(simd, acc(simd, sum, d[2], t[3]), t[2], a[3])
                    }
                    1 => acc(
                        simd,
                        acc(simd, d[0].product(simd, a[1]), d[2], t[4]),
                        d[3],
                        t[3],
                    ),
                    2 => {
                        let sum = acc(simd, a[1].square_product::<K, S>(simd), d[0], a[2]);
                        acc(simd, acc(simd, sum, d[3], t[4]), t[3], a[4])
                    }
                    3 => acc(
                        simd,
                        acc(simd, d[0].product(simd, a[3]), d[1], a[2]),
                        d[4],
                        t[4],
                    ),
                    4 => {
                        let sum = acc(simd, a[2].square_product::<K, S>(simd), d[0], a[4]);
                        acc(simd, acc(simd, sum, d[1], a[3]), t[4], a[5])
                    }
                    _ => acc(
                        simd,
                        acc(simd, d[0].product(simd, a[5]), d[1], a[4]),
                        d[2],
                        a[3],
                    ),
                }
            },
        ))
    }

    /// Multiplies in place by the line `l0 + l2 w^2 + l3 w^3`, given `[l0, l2, l3]`.
    ///
    /// As an element, the line is `(l0 + l2 v) + l3 v w`, so Karatsuba's products over `Fp6` are
    /// sparse: thirteen extension products in all, or eighteen for [`Field::SCHOOLBOOK`]. Every
    /// line component must have limb bound `1` and integer bound at most [`LINE_BOUND`].
    /// Runs as its own kernel, so callers share one copy, and replaces the value in place.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn mul_by_line<S: Simd>(&mut self, simd: S, line: &[Fp2<F>; 3])
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let [l0, l2, l3] = *line;
                let a = &*self;
                let product = if F::SCHOOLBOOK {
                    Self::mul_by_line_schoolbook(simd, a, [l0, l2, l3])
                } else {
                    let t0 = a.c0.product_by_01(simd, l0, l2);
                    let t1 = a.c1.product_by_1(simd, l3);
                    let sum = a.c0.add(simd, a.c1).carry(simd);
                    let l23 = l2.add(simd, l3).carry(simd);
                    combine::<S, F>(simd, t0, t1, sum.product_by_01(simd, l0, l23))
                };
                *self = product;
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

    /// Squares in place an element of the cyclotomic subgroup, where `self^(p^6 + 1) = 1`.
    ///
    /// This is the squaring of Granger and Scott, "Faster squaring in the cyclotomic subgroup of
    /// sixth degree extensions" (2010), on the pairs of coefficients of `w^k` and `w^(k + 3)`,
    /// elements `x + y s` of `Fp4 = Fp2[s] / (s^2 - (1 + i))` for `s = w^3`: each output is three
    /// times a part of the square of such a pair, plus or minus twice an input coefficient. That
    /// takes nine extension squarings, or six squarings and six products accumulated as they form
    /// for [`Field::SCHOOLBOOK`]. The result is unspecified outside the subgroup.
    /// Runs as its own kernel, so callers share one copy, and replaces the value in place.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn cyclotomic_square<S: Simd>(&mut self, simd: S)
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let a = &*self;
                let square = if F::SCHOOLBOOK {
                    Self::cyclotomic_square_schoolbook(simd, a)
                } else {
                    Self::cyclotomic_square_pairs(simd, a)
                };
                *self = square;
            },
        )
    }

    /// Returns the cyclotomic square of `a` from the squares of its three pairs.
    #[inline(always)]
    fn cyclotomic_square_pairs<S: Simd>(simd: S, a: &Self) -> Self
    where
        F: Field<S>,
    {
        // The coefficients a0, ..., a5 of 1, w, ..., w^5.
        let (a0, a1, a2) = (a.c0.c0, a.c1.c0, a.c0.c1);
        let (a3, a4, a5) = (a.c1.c1, a.c0.c2, a.c1.c2);
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
            move |simd: S| {
                let mut coefficients = [Fp2::load(simd, &[], &FROBENIUS[0]); 5];
                unroll::<5>(
                    #[inline(always)]
                    |j| coefficients[j] = Fp2::load(simd, &[], &FROBENIUS[j]),
                );
                coefficients
            },
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
                    let mut low = Self::load(simd, &lanes[..half], &ONE);
                    let high = Self::load(simd, &lanes[half..count], &ONE);
                    low.mul(simd, &high);
                    low.store(simd, &mut lanes[..half]);
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

/// Reference arithmetic on elements with canonical components, by definition, for testing.
///
/// An element is the polynomial `c_0 + c_1 w + ... + c_5 w^5` over `Fp2`, where `w^6 = 1 + i`: since
/// `v = w^2`, the coefficient of `v^i w^j` in the tower is that of `w^(2i + j)`.
#[cfg(any(test, feature = "fuzz"))]
pub(crate) mod reference {
    use super::{BYTES, FP2_BYTES};
    use crate::core::field::{fp::MODULUS, fp2::reference as fp2};
    use std::sync::OnceLock;

    /// The coefficients of `1, w, ..., w^5`.
    pub(crate) type Element = [fp2::Element; 6];

    /// Zero.
    pub(crate) const ZERO: Element = [fp2::ZERO; 6];

    /// One.
    pub(crate) const ONE: Element = {
        let mut one = ZERO;
        one[0] = fp2::ONE;
        one
    };

    /// Returns the degree in `w` of the extension coefficient at `index` of an encoding, which holds
    /// `c1` then `c0`, each with the coefficients of `v^2, v, 1`.
    const fn degree(index: usize) -> usize {
        2 * (2 - index % 3) + (1 - index / 3)
    }

    /// Returns the residues of an encoding's components.
    pub(crate) fn decode(bytes: &[u8; BYTES]) -> Element {
        let (chunks, _) = bytes.as_chunks::<FP2_BYTES>();
        let mut a = ZERO;
        for (index, chunk) in chunks.iter().enumerate() {
            a[degree(index)] = fp2::decode(chunk);
        }
        a
    }

    /// Returns the encoding of an element.
    pub(crate) fn encode(a: &Element) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        let (chunks, _) = bytes.as_chunks_mut::<FP2_BYTES>();
        for (index, chunk) in chunks.iter_mut().enumerate() {
            *chunk = fp2::encode(a[degree(index)]);
        }
        bytes
    }

    /// Returns `a * b`, the product of polynomials with `w^6` replaced by `1 + i`.
    pub(crate) fn mul(a: &Element, b: &Element) -> Element {
        let mut product = ZERO;
        for (j, &x) in a.iter().enumerate() {
            for (k, &y) in b.iter().enumerate() {
                let mut term = fp2::mul(x, y);
                if j + k >= 6 {
                    term = fp2::mul(term, fp2::NONRESIDUE);
                }
                product[(j + k) % 6] = fp2::add(product[(j + k) % 6], term);
            }
        }
        product
    }

    /// Returns `base^exponent` for a little-endian exponent, given the product and its unit.
    fn pow<T: Copy>(base: T, one: T, mul: impl Fn(T, T) -> T, exponent: &[u64]) -> T {
        let mut result = one;
        for word in exponent.iter().rev() {
            for bit in (0..64).rev() {
                result = mul(result, result);
                if (word >> bit) & 1 == 1 {
                    result = mul(result, base);
                }
            }
        }
        result
    }

    /// Returns `a^exponent` for a little-endian exponent.
    pub(crate) fn power(a: &Element, exponent: &[u64]) -> Element {
        pow(*a, ONE, |x, y| mul(&x, &y), exponent)
    }

    /// Returns the conjugate `a(-w)`, which is `a^(p^6)`.
    pub(crate) fn conjugate(a: &Element) -> Element {
        let mut conjugate = *a;
        for coefficient in conjugate.iter_mut().skip(1).step_by(2) {
            *coefficient = fp2::neg(*coefficient);
        }
        conjugate
    }

    /// Returns `gamma^k` for `k` from `0` to `5`, where `gamma = (1 + i)^((p - 1) / 6)` is
    /// `w^(p - 1)`.
    pub(crate) fn frobenius_factors() -> &'static [fp2::Element; 6] {
        static FACTORS: OnceLock<[fp2::Element; 6]> = OnceLock::new();
        FACTORS.get_or_init(|| {
            // (p - 1) / 6, little-endian.
            let mut exponent = MODULUS;
            exponent[0] -= 1;
            let mut remainder = 0u128;
            for word in exponent.iter_mut().rev() {
                let value = (remainder << 64) | *word as u128;
                *word = (value / 6) as u64;
                remainder = value % 6;
            }
            assert_eq!(remainder, 0, "6 divides p - 1");
            let gamma = pow(fp2::NONRESIDUE, fp2::ONE, fp2::mul, &exponent);
            let mut factors = [fp2::ONE; 6];
            for k in 1..6 {
                factors[k] = fp2::mul(factors[k - 1], gamma);
            }
            factors
        })
    }

    /// Returns `a^p`: each coefficient `c_k` of `w^k` maps to `conj(c_k) w^(k p)`, which is
    /// `conj(c_k) gamma^k w^k`.
    pub(crate) fn frobenius(a: &Element) -> Element {
        let factors = frobenius_factors();
        let mut image = ZERO;
        for (k, coefficient) in image.iter_mut().enumerate() {
            *coefficient = fp2::mul(fp2::conjugate(a[k]), factors[k]);
        }
        image
    }

    /// Returns the inverse of `a`, or zero for zero, through norms.
    ///
    /// `n = a conj(a)` lies in `Fp6`, whose norm `n n^(p^2) n^(p^4)` lies in `Fp2`, so
    /// `a^(-1) = conj(a) n^(p^2) n^(p^4) / (n n^(p^2) n^(p^4))`.
    pub(crate) fn invert(a: &Element) -> Element {
        let conjugate = conjugate(a);
        let n = mul(a, &conjugate);
        let n2 = frobenius(&frobenius(&n));
        let others = mul(&n2, &frobenius(&frobenius(&n2)));
        let scale = fp2::invert(mul(&n, &others)[0]);
        mul(&conjugate, &others).map(|coefficient| fp2::mul(coefficient, scale))
    }
}

/// Fuzzing of [`Fp12`] and [`Fp6`] against the [reference arithmetic](mod@reference).
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::{reference::Element, *};
    use crate::core::field::{
        fp::{rns::Rns, testing::Backend, unsat28::Unsat28, unsat49::Unsat49},
        fp2::reference as fp2,
    };
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_simd::{Operation, X86V4C};
    use std::{vec, vec::Vec};

    /// Largest number of operations in a chain.
    const STEPS: usize = 8;

    /// A fuzzing operation on `Fp12` and its subfield `Fp6`.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    pub enum Plan {
        /// Check that a chain of multiplications, squarings, line multiplications, conjugations,
        /// Frobenius maps, and inversions of elements at their bounds matches the reference after
        /// every step, with inverses checked by their defining property.
        Chain,
        /// Check that a chain of cyclotomic squarings and conjugations of elements of the
        /// cyclotomic subgroup matches the reference after every step.
        CyclotomicChain,
        /// Check that the products, squares, sparse products, and inverses of `Fp6` match the
        /// reference in the embedding of `Fp6` in `Fp12`.
        Subfield,
        /// Check that the product of lanes is the reference product of every lane's element.
        ProductOfLanes,
    }

    impl Plan {
        /// Runs the operation using the remaining input.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::Chain => chain(u, false),
                Self::CyclotomicChain => chain(u, true),
                Self::Subfield => subfield(u),
                Self::ProductOfLanes => product_of_lanes(u),
            }
        }
    }

    /// A computation on the lanes of values, generic over the backend and representation.
    pub(crate) trait Kernel {
        /// The stored results.
        type Output;

        /// Runs the computation in representation `F`.
        fn run<S: Simd, F: Field<S>>(&self, simd: S) -> Self::Output;
    }

    /// A base field representation.
    #[derive(Clone, Copy, Debug)]
    enum Representation {
        Unsat49,
        Unsat28,
        Rns,
    }

    /// An emulated backend and a representation it supports: residues require x86v4c.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Target {
        backend: Backend,
        representation: Representation,
    }

    /// Runs a kernel in a representation, as an operation of any backend.
    struct Execute<'a, K>(&'a K, Representation);

    impl<S: Simd, K: Kernel> Operation<S> for Execute<'_, K> {
        type Output = K::Output;

        fn portable(self, simd: S) -> K::Output {
            match self.1 {
                Representation::Unsat49 => self.0.run::<S, Unsat49<S>>(simd),
                Representation::Unsat28 => self.0.run::<S, Unsat28<S>>(simd),
                Representation::Rns => unreachable!("residues require x86v4c"),
            }
        }

        fn x86_v4c(self, simd: S) -> K::Output
        where
            S: X86V4C,
        {
            match self.1 {
                Representation::Rns => self.0.run::<S, Rns<S>>(simd),
                _ => self.portable(simd),
            }
        }
    }

    /// Returns the lane count of a representation.
    struct Lanes;

    impl Kernel for Lanes {
        type Output = usize;

        fn run<S: Simd, F: Field<S>>(&self, _: S) -> usize {
            F::LANES
        }
    }

    impl Target {
        /// Draws any emulated backend and representation.
        pub(crate) fn draw(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
            let backend = Backend::draw(u)?;
            let representations = if matches!(backend, Backend::X86V4C) {
                2
            } else {
                1
            };
            let representation = [
                Representation::Unsat28,
                Representation::Unsat49,
                Representation::Rns,
            ][u.int_in_range(0..=representations)?];
            Ok(Self {
                backend,
                representation,
            })
        }

        /// Runs a kernel on this target.
        pub(crate) fn run<K: Kernel>(self, kernel: &K) -> K::Output {
            self.backend.execute(Execute(kernel, self.representation))
        }

        /// Returns the number of elements a value holds on this target.
        pub(crate) fn lanes(self) -> usize {
            self.run(&Lanes)
        }

        /// Draws a lane count from one to [`Self::lanes`], every lane when the input is exhausted.
        pub(crate) fn draw_lanes(self, u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
            let lanes = self.lanes();
            Ok(lanes - u.int_in_range(0..=lanes - 1)?)
        }
    }

    /// Draws an extension element with canonical components, requiring the bytes it reads.
    fn extension(u: &mut Unstructured<'_>) -> arbitrary::Result<fp2::Element> {
        fp2::canonical(&mut Unstructured::new(u.bytes(2 * FP_BYTES)?))
    }

    /// Draws an element with canonical components: mostly any element, otherwise zero, one, or an
    /// element of `Fp2` or `Fp6`.
    pub(crate) fn element(u: &mut Unstructured<'_>) -> arbitrary::Result<Element> {
        let mut a = reference::ZERO;
        match u.int_in_range(0..=7u8)? {
            0..=3 => {
                for coefficient in &mut a {
                    *coefficient = extension(u)?;
                }
            }
            4 => {}
            5 => a = reference::ONE,
            6 => a[0] = extension(u)?,
            _ => {
                for coefficient in a.iter_mut().step_by(2) {
                    *coefficient = extension(u)?;
                }
            }
        }
        Ok(a)
    }

    /// Draws an element of the cyclotomic subgroup: `a^((p^6 - 1)(p^2 + 1))` for a drawn nonzero
    /// `a`.
    pub(crate) fn cyclotomic(u: &mut Unstructured<'_>) -> arbitrary::Result<Element> {
        let mut a = element(u)?;
        if a == reference::ZERO {
            a = reference::ONE;
        }
        let x = reference::mul(&reference::conjugate(&a), &reference::invert(&a));
        let c = reference::mul(&reference::frobenius(&reference::frobenius(&x)), &x);
        assert!(
            reference::mul(&reference::conjugate(&c), &c) == reference::ONE,
            "cyclotomic element"
        );
        Ok(c)
    }

    /// Returns `inverse` after checking that it is the inverse of `a`, or zero for zero.
    fn checked_inverse(a: &Element, inverse: Element, label: &str) -> Element {
        let expected = if *a == reference::ZERO {
            reference::ZERO
        } else {
            reference::ONE
        };
        assert!(reference::mul(a, &inverse) == expected, "inverse, {label}");
        inverse
    }

    /// The inputs of one lane, as encodings.
    #[derive(Clone, Copy)]
    struct Inputs {
        a: [u8; BYTES],
        b: [u8; BYTES],
        /// The coefficients of `1, w^2, w^3` of a line.
        line: [[u8; FP2_BYTES]; 3],
    }

    /// The inputs of one lane, as reference elements.
    struct Values {
        a: Element,
        b: Element,
        line: [fp2::Element; 3],
    }

    impl Values {
        /// Draws inputs; `a` lies in the cyclotomic subgroup when `cyclotomic` is set.
        fn draw(u: &mut Unstructured<'_>, cyclotomic: bool) -> arbitrary::Result<Self> {
            let a = if cyclotomic {
                self::cyclotomic(u)?
            } else {
                element(u)?
            };
            Ok(Self {
                a,
                b: element(u)?,
                line: [extension(u)?, extension(u)?, extension(u)?],
            })
        }

        /// Returns the encodings.
        fn encode(&self) -> Inputs {
            Inputs {
                a: reference::encode(&self.a),
                b: reference::encode(&self.b),
                line: self.line.map(fp2::encode),
            }
        }

        /// Returns the line `l0 + l2 w^2 + l3 w^3` as an element.
        const fn line(&self) -> Element {
            let [l0, l2, l3] = self.line;
            let mut line = reference::ZERO;
            (line[0], line[2], line[3]) = (l0, l2, l3);
            line
        }
    }

    /// Returns the same extension value with every component at integer bound `2 + K`, given
    /// loaded components with integer bound `2`.
    fn widen<const K: u64, S: Simd, F: Field<S>>(simd: S, value: Fp2<F>) -> Fp2<F> {
        let zero = Fp2::<F>::load(simd, &[], &[0; FP2_BYTES]);
        value.sub::<K, S>(simd, zero).carry(simd)
    }

    /// Loads elements and widens every component to integer bound [`BOUND`].
    fn load_wide<S: Simd, F: Field<S>>(
        simd: S,
        elements: &[[u8; BYTES]],
        fill: &[u8; BYTES],
    ) -> Fp12<F> {
        let value = Fp12::<F>::load(simd, elements, fill);
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

    /// Stores the first `lanes` elements of a value.
    fn store<S: Simd, F: Field<S>>(simd: S, value: Fp12<F>, lanes: usize) -> Vec<[u8; BYTES]> {
        let mut elements = vec![[0; BYTES]; lanes];
        value.store(simd, &mut elements);
        elements
    }

    /// The inputs of the lanes of a value, loaded with every component widened to its bound.
    struct Loaded<F> {
        a: Fp12<F>,
        b: Fp12<F>,
        line: [Fp2<F>; 3],
    }

    /// Loads the inputs of up to one value's lanes, widening every component to its bound.
    #[inline(never)]
    fn load<S: Simd, F: Field<S>>(simd: S, inputs: &[Inputs]) -> Loaded<F> {
        let a: Vec<_> = inputs.iter().map(|inputs| inputs.a).collect();
        let b: Vec<_> = inputs.iter().map(|inputs| inputs.b).collect();
        let mut line = [Fp2::<F>::load(simd, &[], &[0; FP2_BYTES]); 3];
        for (k, coefficient) in line.iter_mut().enumerate() {
            let lanes: Vec<_> = inputs.iter().map(|inputs| inputs.line[k]).collect();
            let loaded = Fp2::<F>::load(simd, &lanes, &[0; FP2_BYTES]);
            *coefficient = widen::<{ LINE_BOUND - 2 }, S, F>(simd, loaded);
        }
        Loaded {
            a: load_wide(simd, &a, &ONE),
            b: load_wide(simd, &b, &ONE),
            line,
        }
    }

    /// An operation of a chain.
    #[derive(Clone, Copy, Debug)]
    enum Step {
        /// Multiplies by `b`.
        Mul,
        Square,
        /// Multiplies by the line.
        MulByLine,
        Conjugate,
        Frobenius,
        Invert,
        CyclotomicSquare,
    }

    /// The operations of [`Plan::Chain`].
    const STEPS_ANY: [Step; 6] = [
        Step::Mul,
        Step::Square,
        Step::MulByLine,
        Step::Conjugate,
        Step::Frobenius,
        Step::Invert,
    ];

    /// The operations of [`Plan::CyclotomicChain`].
    const STEPS_CYCLOTOMIC: [Step; 2] = [Step::CyclotomicSquare, Step::Conjugate];

    /// An operation on the current value of a chain.
    type Apply<S, F> = fn(S, Fp12<F>, &Loaded<F>, &[Fp2<F>; 5]) -> Fp12<F>;

    fn mul<S: Simd, F: Field<S>>(
        simd: S,
        mut y: Fp12<F>,
        x: &Loaded<F>,
        _: &[Fp2<F>; 5],
    ) -> Fp12<F> {
        y.mul(simd, &x.b);
        y
    }

    fn square<S: Simd, F: Field<S>>(
        simd: S,
        mut y: Fp12<F>,
        _: &Loaded<F>,
        _: &[Fp2<F>; 5],
    ) -> Fp12<F> {
        y.square(simd);
        y
    }

    fn mul_by_line<S: Simd, F: Field<S>>(
        simd: S,
        mut y: Fp12<F>,
        x: &Loaded<F>,
        _: &[Fp2<F>; 5],
    ) -> Fp12<F> {
        y.mul_by_line(simd, &x.line);
        y
    }

    fn conjugate<S: Simd, F: Field<S>>(
        simd: S,
        y: Fp12<F>,
        _: &Loaded<F>,
        _: &[Fp2<F>; 5],
    ) -> Fp12<F> {
        y.conjugate(simd)
    }

    fn frobenius<S: Simd, F: Field<S>>(
        simd: S,
        y: Fp12<F>,
        _: &Loaded<F>,
        coefficients: &[Fp2<F>; 5],
    ) -> Fp12<F> {
        y.frobenius(simd, coefficients)
    }

    fn invert<S: Simd, F: Field<S>>(
        simd: S,
        y: Fp12<F>,
        _: &Loaded<F>,
        _: &[Fp2<F>; 5],
    ) -> Fp12<F> {
        y.invert(simd)
    }

    fn cyclotomic_square<S: Simd, F: Field<S>>(
        simd: S,
        mut y: Fp12<F>,
        _: &Loaded<F>,
        _: &[Fp2<F>; 5],
    ) -> Fp12<F> {
        y.cyclotomic_square(simd);
        y
    }

    /// Applies operations to `a`, storing the value after each.
    ///
    /// Each operation runs in its own function, so debug builds keep every frame small.
    struct Chain<'a> {
        inputs: &'a [Inputs],
        steps: &'a [Step],
    }

    impl Kernel for Chain<'_> {
        type Output = Vec<Vec<[u8; BYTES]>>;

        fn run<S: Simd, F: Field<S>>(&self, simd: S) -> Self::Output {
            let loaded = load::<S, F>(simd, self.inputs);
            let coefficients = Fp12::<F>::frobenius_coefficients(simd);
            let mut y = loaded.a;
            self.steps
                .iter()
                .map(|step| {
                    let apply: Apply<S, F> = match step {
                        Step::Mul => mul,
                        Step::Square => square,
                        Step::MulByLine => mul_by_line,
                        Step::Conjugate => conjugate,
                        Step::Frobenius => frobenius,
                        Step::Invert => invert,
                        Step::CyclotomicSquare => cyclotomic_square,
                    };
                    y = check_bound(simd, apply(simd, y, &loaded, &coefficients));
                    store(simd, y, self.inputs.len())
                })
                .collect()
        }
    }

    /// Runs [`Plan::Chain`], or [`Plan::CyclotomicChain`] when `cyclotomic` is set.
    fn chain(u: &mut Unstructured<'_>, cyclotomic: bool) -> arbitrary::Result<()> {
        let target = Target::draw(u)?;
        let lanes = target.draw_lanes(u)?;
        let values = (0..lanes)
            .map(|_| Values::draw(u, cyclotomic))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        let choices: &[Step] = if cyclotomic {
            &STEPS_CYCLOTOMIC
        } else {
            &STEPS_ANY
        };
        let steps = (0..STEPS - u.int_in_range(0..=STEPS - 1)?)
            .map(|_| u.choose(choices).copied())
            .collect::<arbitrary::Result<Vec<_>>>()?;
        let inputs: Vec<_> = values.iter().map(Values::encode).collect();
        let outputs = target.run(&Chain {
            inputs: &inputs,
            steps: &steps,
        });
        for (lane, values) in values.iter().enumerate() {
            let line = values.line();
            let mut y = values.a;
            for (k, (step, output)) in steps.iter().zip(&outputs).enumerate() {
                let label = std::format!("{target:?}, lane {lane}, step {k} ({step:?})");
                y = match step {
                    Step::Mul => reference::mul(&y, &values.b),
                    Step::Square | Step::CyclotomicSquare => reference::mul(&y, &y),
                    Step::MulByLine => reference::mul(&y, &line),
                    Step::Conjugate => reference::conjugate(&y),
                    Step::Frobenius => reference::frobenius(&y),
                    Step::Invert => checked_inverse(&y, reference::decode(&output[lane]), &label),
                };
                assert!(output[lane] == reference::encode(&y), "{label}");
            }
        }
        Ok(())
    }

    /// An operation of `Fp6`, on the coefficients `c0` of the inputs.
    #[derive(Clone, Copy, Debug)]
    enum Operation6 {
        /// Multiplies `a` by `b`.
        Product,
        Square,
        /// Multiplies `a` by `l0 + l2 v`.
        ProductBy01,
        /// Multiplies `a` by `l3 v`.
        ProductBy1,
        Invert,
    }

    /// Applies an operation of `Fp6` and stores its embedding `(t, 0)`.
    struct Subfield<'a> {
        inputs: &'a [Inputs],
        operation: Operation6,
    }

    impl Kernel for Subfield<'_> {
        type Output = Vec<[u8; BYTES]>;

        fn run<S: Simd, F: Field<S>>(&self, simd: S) -> Self::Output {
            let x = load::<S, F>(simd, self.inputs);
            let a = x.a.c0;
            let t = match self.operation {
                Operation6::Product => {
                    Fp6::<F>::reduce_tight::<BIAS, S>(simd, a.product(simd, &x.b.c0))
                }
                Operation6::Square => {
                    Fp6::<F>::reduce_tight::<BIAS, S>(simd, a.square_product(simd))
                }
                Operation6::ProductBy01 => Fp6::<F>::reduce_tight::<BIAS, S>(
                    simd,
                    a.product_by_01(simd, x.line[0], x.line[1]),
                ),
                Operation6::ProductBy1 => {
                    Fp6::<F>::reduce_tight::<BIAS, S>(simd, a.product_by_1(simd, x.line[2]))
                }
                Operation6::Invert => a.invert(simd),
            };
            let embedded = Fp12 {
                c0: t,
                c1: Fp6::load(simd, &[], &[0; FP6_BYTES]),
            };
            store(simd, check_bound(simd, embedded), self.inputs.len())
        }
    }

    /// Returns the embedding of the coefficient `c0` of `a`: its coefficients of even degree.
    fn even(a: &Element) -> Element {
        let mut even = *a;
        for coefficient in even.iter_mut().skip(1).step_by(2) {
            *coefficient = fp2::ZERO;
        }
        even
    }

    /// Runs [`Plan::Subfield`].
    fn subfield(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let target = Target::draw(u)?;
        let lanes = target.draw_lanes(u)?;
        let operation = *u.choose(&[
            Operation6::Product,
            Operation6::Square,
            Operation6::ProductBy01,
            Operation6::ProductBy1,
            Operation6::Invert,
        ])?;
        let values = (0..lanes)
            .map(|_| Values::draw(u, false))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        let inputs: Vec<_> = values.iter().map(Values::encode).collect();
        let outputs = target.run(&Subfield {
            inputs: &inputs,
            operation,
        });
        for (lane, (values, output)) in values.iter().zip(&outputs).enumerate() {
            let label = std::format!("{target:?}, lane {lane}, {operation:?}");
            let a = even(&values.a);
            let [l0, l2, l3] = values.line;
            let mut factor = reference::ZERO;
            let expected = match operation {
                Operation6::Product => reference::mul(&a, &even(&values.b)),
                Operation6::Square => reference::mul(&a, &a),
                Operation6::ProductBy01 => {
                    (factor[0], factor[2]) = (l0, l2);
                    reference::mul(&a, &factor)
                }
                Operation6::ProductBy1 => {
                    factor[2] = l3;
                    reference::mul(&a, &factor)
                }
                Operation6::Invert => checked_inverse(&a, reference::decode(output), &label),
            };
            assert!(*output == reference::encode(&expected), "{label}");
        }
        Ok(())
    }

    /// Multiplies the lanes of a value loaded with a fill, storing every lane.
    struct LaneProduct<'a> {
        elements: &'a [[u8; BYTES]],
        fill: [u8; BYTES],
    }

    impl Kernel for LaneProduct<'_> {
        type Output = Vec<[u8; BYTES]>;

        fn run<S: Simd, F: Field<S>>(&self, simd: S) -> Self::Output {
            let value = load_wide::<S, F>(simd, self.elements, &self.fill);
            let product = check_bound(simd, value.product_of_lanes(simd));
            store(simd, product, F::LANES)
        }
    }

    /// Runs [`Plan::ProductOfLanes`].
    fn product_of_lanes(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let target = Target::draw(u)?;
        let lanes = target.lanes();
        // Every lane holds an element when the input is exhausted.
        let count = lanes - u.int_in_range(0..=lanes)?;
        let elements = (0..count)
            .map(|_| element(u))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        let fill = element(u)?;
        let mut expected = reference::ONE;
        for element in elements
            .iter()
            .chain(core::iter::repeat_n(&fill, lanes - count))
        {
            expected = reference::mul(&expected, element);
        }
        let encoded: Vec<_> = elements.iter().map(reference::encode).collect();
        let outputs = target.run(&LaneProduct {
            elements: &encoded,
            fill: reference::encode(&fill),
        });
        for (lane, output) in outputs.iter().enumerate() {
            assert!(
                *output == reference::encode(&expected),
                "{target:?}, {count} elements, lane {lane}"
            );
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use commonware_invariants::minifuzz;

        #[test]
        fn minifuzz_chain() {
            minifuzz::test(|u| Plan::Chain.run(u));
        }

        #[test]
        fn minifuzz_cyclotomic_chain() {
            minifuzz::test(|u| Plan::CyclotomicChain.run(u));
        }

        #[test]
        fn minifuzz_subfield() {
            minifuzz::test(|u| Plan::Subfield.run(u));
        }

        #[test]
        fn minifuzz_product_of_lanes() {
            minifuzz::test(|u| Plan::ProductOfLanes.run(u));
        }

        #[test]
        fn frobenius_constants_are_powers_of_the_nonresidue() {
            let factors = reference::frobenius_factors();
            for (k, constant) in FROBENIUS.iter().enumerate() {
                assert_eq!(*constant, fp2::encode(factors[k + 1]), "gamma^{}", k + 1);
            }
        }
    }
}
