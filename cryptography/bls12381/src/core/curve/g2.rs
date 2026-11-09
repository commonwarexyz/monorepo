//! Arithmetic on points of G2, the curve `y^2 = x^3 + 4 (1 + i)` over the quadratic extension.
//!
//! A [`Point`] holds as many projective points as its extension values hold elements, one per lane,
//! and its formulas run once over every base field representation.
//!
//! # Coordinate bounds
//!
//! Every coordinate component a formula accepts or returns has positional limb bound `1` and integer
//! bound at most [`BOUND`], as defined by the [base field arithmetic](crate::core::field::arithmetic).
//! Loaded coordinates and every formula's outputs satisfy this, so points chain through any number
//! of operations without carrying or canonicalizing between them.
//!
//! Raw coordinates hold each lane of a point in the representation's own form, through
//! [`Field::store_raw`] with bound [`BOUND`], so storing and loading them costs no conversion and
//! loaded raw coordinates satisfy the coordinate bounds.
//!
//! Multiplications by `3b = 12 (1 + i)` scale a factor by `12` before a product and multiply the
//! product by `1 + i`, which only rearranges its [signed sums](crate::core::field::arithmetic::Signed).
//! Scaling before the product keeps positional bounds small, since a positional product divides
//! its factors' bounds by `2048`. Products whose factors are sums or scaled values use
//! [`Fp2::product_schoolbook`], whose positional bounds stay below Karatsuba's for such factors.
//!
//! Each reduction uses the smallest positional bias covering its negative sums for coordinates
//! within [`BOUND`], and each value subtraction the smallest bias covering its subtrahend in every
//! representation. Inside a formula, values reach integer bounds of at most `384` and positional
//! limb bounds of at most `12`, and wide sums of products reach at most `334848`.

use crate::core::{
    curve::Points,
    field::{
        arithmetic::{Field, Signed},
        fp::{self, MINUS_ONE, ONE},
        fp2::{BYTES, Fp2, Product, encode},
    },
};
use commonware_formatting::hex;
use commonware_simd::Simd;

/// Projective coordinates `[X, Y, Z]` as big-endian extension elements.
pub type Coordinates = [[u8; BYTES]; 3];

/// The identity `(0 : 1 : 0)` as projective coordinates.
pub const IDENTITY: Coordinates = {
    let mut identity = [[0; BYTES]; 3];
    identity[1][BYTES - 1] = 1;
    identity
};

/// The generator in projective coordinates, with `Z = 1`. Each coordinate is `c1` followed by
/// `c0`.
pub const GENERATOR: Coordinates = [
    hex!(
        "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
    ),
    hex!(
        "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
        "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
    ),
    {
        let mut one = [0; BYTES];
        one[BYTES - 1] = 1;
        one
    },
];

/// Largest integer bound of a coordinate component, in units of `p`.
///
/// The positional representations return at most `32` from the reduction of [`Point::add`]'s `Y`
/// coordinate, and residues reduce to at most `17`.
pub const BOUND: u64 = 32;

/// Largest number of points in a value, the widest representation's lane count.
const MAX_LANES: usize = 16;

/// `c` such that `c i = (1 + i)^(-(p - 1) / 3)`, the coefficient of the untwisted Frobenius
/// map on `X` (RFC 9380, Appendix G.3), which is purely imaginary.
const PSI_X: [u8; fp::BYTES] = fp::encode([
    0x8bfd_0000_0000_aaad,
    0x4094_27eb_4f49_fffd,
    0x897d_2965_0fb8_5f9b,
    0xaa0d_857d_8975_9ad4,
    0xec02_4086_63d4_de85,
    0x1a01_11ea_397f_e699,
]);

/// `(1 + i)^(-(p - 1) / 2)`, the coefficient of the untwisted Frobenius map on `Y`.
const PSI_Y: [u8; BYTES] = encode(
    [
        0xf1ee_7b04_121b_dea2,
        0x3044_66cf_3e67_fa0a,
        0xef39_6489_f61e_b45e,
        0x1c3d_edd9_30b1_cf60,
        0xe2e9_c448_d77a_2cd9,
        0x1352_03e6_0180_a68e,
    ],
    [
        0xc810_84fb_ede3_cc09,
        0xee67_992f_72ec_05f4,
        0x77f7_6e17_0092_41c5,
        0x4839_5dab_c2d3_435e,
        0x6831_e36d_6bd1_7ffe,
        0x06af_0e04_37ff_400b,
    ],
);

/// Projective points, one per lane of the extension values.
///
/// See the [module documentation](self) for the bounds every coordinate satisfies.
#[derive(Clone, Copy)]
pub struct Point<F> {
    /// The `X` coordinates.
    pub x: Fp2<F>,
    /// The `Y` coordinates.
    pub y: Fp2<F>,
    /// The `Z` coordinates.
    pub z: Fp2<F>,
}

impl<S: Simd, F: Field<S>> Points<S> for Point<F> {
    type Coordinates = Coordinates;
    type Raw = [[F::Raw; 2]; 3];

    /// Loads up to one projective point per lane, filling the remaining lanes with `fill`.
    ///
    /// Runs as its own kernel, so callers share one copy of the conversions.
    #[inline(always)]
    fn load(simd: S, points: &[Coordinates], fill: &Coordinates) -> Self {
        simd.execute(
            #[inline(always)]
            move |simd: S| Self::read(simd, points, fill),
        )
    }

    /// Stores each lane's canonical projective coordinates, dropping lanes beyond `points`.
    ///
    /// Runs as its own kernel, so callers share one copy of the conversions.
    #[inline(always)]
    fn store(self, simd: S, points: &mut [Coordinates]) {
        simd.execute(
            #[inline(always)]
            move |simd: S| self.write(simd, points),
        )
    }

    /// Returns `rhs` in every lane whose bit is set in `lanes`, and `self` in the others.
    ///
    /// Bit `i` of `lanes` selects lane `i`, without branching on `lanes`.
    #[inline(always)]
    fn select(self, simd: S, rhs: Self, lanes: u64) -> Self {
        Self {
            x: self.x.select(simd, rhs.x, lanes),
            y: self.y.select(simd, rhs.y, lanes),
            z: self.z.select(simd, rhs.z, lanes),
        }
    }

    /// Stores each lane's raw coordinates, dropping lanes beyond `points`.
    #[inline(always)]
    fn store_raw(self, simd: S, points: &mut [[[F::Raw; 2]; 3]]) {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut coordinates = [[[F::Raw::default(); 2]; MAX_LANES]; 3];
        let lanes = points.len().min(F::LANES);
        self.x
            .store_raw::<BOUND, S>(simd, &mut coordinates[0][..lanes]);
        self.y
            .store_raw::<BOUND, S>(simd, &mut coordinates[1][..lanes]);
        self.z
            .store_raw::<BOUND, S>(simd, &mut coordinates[2][..lanes]);
        for (lane, point) in points[..lanes].iter_mut().enumerate() {
            *point = [
                coordinates[0][lane],
                coordinates[1][lane],
                coordinates[2][lane],
            ];
        }
    }

    /// Loads lane `i` from the raw coordinates `points[i]`, for at least `F::LANES` entries.
    #[inline(always)]
    fn load_raw(simd: S, points: &[&[[F::Raw; 2]; 3]]) -> Self {
        const { assert!(F::LANES <= MAX_LANES) };
        let coordinate = |i: usize| {
            let mut lanes = [&points[0][i]; MAX_LANES];
            for (lane, point) in lanes.iter_mut().zip(points).take(F::LANES) {
                *lane = &point[i];
            }
            Fp2::load_raw::<BOUND, S>(simd, &lanes)
        };
        Self {
            x: coordinate(0),
            y: coordinate(1),
            z: coordinate(2),
        }
    }

    /// Returns `-self`.
    ///
    /// Multiplies `Y` by `-1` rather than subtracting it, so the coordinates keep their bounds.
    #[inline(always)]
    fn negate(self, simd: S) -> Self {
        let minus_one = F::load(simd, &[], &MINUS_ONE);
        Self {
            y: self.y.ready::<1, S>(simd).mul_base(simd, minus_one),
            ..self
        }
    }

    /// Returns `-self` in every lane whose bit is set in `lanes`, and `self` in the others.
    ///
    /// Multiplies `Y` by `1` or `-1`, selected without branching on `lanes`.
    #[inline(always)]
    fn negate_lanes(self, simd: S, lanes: u64) -> Self {
        let sign = F::load(simd, &[], &ONE).select(simd, F::load(simd, &[], &MINUS_ONE), lanes);
        Self {
            y: self.y.ready::<1, S>(simd).mul_base(simd, sign),
            ..self
        }
    }

    /// Returns the image of every lane under the endomorphism `psi`, the Frobenius map carried
    /// through the twist, which multiplies points of the prime-order subgroup by the curve
    /// parameter `x`.
    ///
    /// Conjugates each coordinate and multiplies `X` by [`PSI_X`]` i` and `Y` by [`PSI_Y`],
    /// forming `conj(y) PSI_Y` from its four base field products so that no conjugate needs a
    /// bias; `Z`'s conjugate multiplies its imaginary component by `-1` instead, as
    /// [`Self::negate`] does, so the coordinates keep their bounds. Seven base field products and
    /// five reductions in all.
    ///
    /// Runs as its own kernel, so callers share one copy.
    #[inline(always)]
    fn endomorphism(self, simd: S) -> Self {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let psi_x = F::load(simd, &[], &PSI_X);
                let psi_y = Fp2::load(simd, &[], &PSI_Y);
                let minus_one = F::load(simd, &[], &MINUS_ONE);
                let (x, y, z) = (
                    self.x.ready::<1, S>(simd),
                    self.y.ready::<1, S>(simd),
                    self.z.ready::<1, S>(simd),
                );
                // conj(x) c i = (x1 c) + (x0 c) i.
                let x = Fp2 {
                    c0: x.c1.mul(simd, psi_x),
                    c1: x.c0.mul(simd, psi_x),
                };
                // conj(y) (p0 + p1 i) = (y0 p0 + y1 p1) + (y0 p1 - y1 p0) i.
                let product = Fp2 {
                    c0: Signed::positive(F::accumulate_product(
                        simd,
                        y.c0.product(simd, psi_y.c0),
                        y.c1,
                        psi_y.c1,
                    )),
                    c1: Signed {
                        pos: y.c0.product(simd, psi_y.c1),
                        neg: Some(y.c1.product(simd, psi_y.c0)),
                    },
                };
                let y = Fp2::reduce::<3, S>(simd, product);
                let z = Fp2 {
                    c0: z.c0,
                    c1: z.c1.mul(simd, minus_one),
                };
                Self { x, y, z }
            },
        )
    }

    /// Returns `self + rhs`.
    ///
    /// This is Algorithm 7 of Renes, Costello, and Batina, "Complete addition formulas for prime
    /// order elliptic curves" (2016), which accepts any pair of points, including the identity and
    /// equal points. Each cross term is a schoolbook product of sums less the two known products,
    /// or the two products accumulated for [`Field::SCHOOLBOOK`], and `3b z1 z2` comes from one
    /// more product, so that `Y1 Y2 + 3b Z1 Z2` and `Y1 Y2 - 3b Z1 Z2` each take one reduction. That
    /// leaves thirteen extension products, reduced in two stages of six and three values.
    ///
    /// Runs as its own kernel, so callers share one copy of the formula.
    #[inline(always)]
    fn add(self, simd: S, rhs: Self) -> Self {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let first = Addition::new(simd, self, rhs);
                let first = Fp2::<F>::reduce_each::<6, 12, S>(
                    simd,
                    #[cfg_attr(not(debug_assertions), inline(always))]
                    |k| first.sum(simd, k),
                );
                let [x, y, z] = Fp2::<F>::reduce_each::<3, 6, S>(
                    simd,
                    #[cfg_attr(not(debug_assertions), inline(always))]
                    |k| Addition::coordinate(simd, &first, k),
                );
                Self { x, y, z }
            },
        )
    }

    /// Returns `2 * self`.
    ///
    /// This is Algorithm 9 of Renes, Costello, and Batina, which accepts any point, including the
    /// identity. It returns the same point as [`Self::add`] of `self` with itself, with seven
    /// extension products and one squaring, reduced in two stages of four and three values.
    ///
    /// Runs as its own kernel, so callers share one copy of the formula.
    #[inline(always)]
    fn double(self, simd: S) -> Self {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let first = Fp2::<F>::reduce_each::<4, 8, S>(
                    simd,
                    #[cfg_attr(not(debug_assertions), inline(always))]
                    |k| self.doubling(simd, k),
                );
                let [x, y, z] = Fp2::<F>::reduce_each::<3, 6, S>(
                    simd,
                    #[cfg_attr(not(debug_assertions), inline(always))]
                    |k| Self::doubled(simd, &first, k),
                );
                Self { x, y, z }
            },
        )
    }
}

impl<F> Point<F> {
    /// Body of [`Self::load`].
    #[inline(always)]
    fn read<S: Simd>(simd: S, points: &[Coordinates], fill: &Coordinates) -> Self
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut coordinates = [[[0; BYTES]; MAX_LANES]; 3];
        let lanes = points.len().min(F::LANES);
        for (i, coordinate) in coordinates.iter_mut().enumerate() {
            for (lane, point) in coordinate.iter_mut().zip(&points[..lanes]) {
                *lane = point[i];
            }
        }
        Self {
            x: Fp2::load(simd, &coordinates[0][..lanes], &fill[0]),
            y: Fp2::load(simd, &coordinates[1][..lanes], &fill[1]),
            z: Fp2::load(simd, &coordinates[2][..lanes], &fill[2]),
        }
    }

    /// Body of [`Self::store`].
    #[inline(always)]
    fn write<S: Simd>(self, simd: S, points: &mut [Coordinates])
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut coordinates = [[[0; BYTES]; MAX_LANES]; 3];
        let lanes = points.len().min(F::LANES);
        self.x.store(simd, &mut coordinates[0][..lanes]);
        self.y.store(simd, &mut coordinates[1][..lanes]);
        self.z.store(simd, &mut coordinates[2][..lanes]);
        for (lane, point) in points[..lanes].iter_mut().enumerate() {
            *point = [
                coordinates[0][lane],
                coordinates[1][lane],
                coordinates[2][lane],
            ];
        }
    }

    /// Returns the `k`th of the four values of the first stage of a doubling, as a sum of
    /// products to reduce: `Y^2`, `X Y`, `Y Z`, and `3b Z^2`.
    ///
    /// Within the coordinate bounds, the reduced values have limb bound `1` and integer bounds at
    /// most `17`, `5`, `5`, and `43` in every representation.
    #[inline(always)]
    pub(crate) fn doubling<S: Simd>(self, simd: S, k: usize) -> Fp2<F::Product>
    where
        F: Field<S>,
    {
        let (x, y, z) = (
            self.x.ready::<1, S>(simd),
            self.y.ready::<1, S>(simd),
            self.z.ready::<1, S>(simd),
        );
        match k {
            0 => Fp2::<F>::difference::<{ BOUND + 1 }, S>(
                simd,
                y.square_product::<{ BOUND + 1 }, S>(simd),
            ),
            1 => Fp2::<F>::difference::<5, S>(simd, x.product(simd, y)),
            2 => Fp2::<F>::difference::<5, S>(simd, y.product(simd, z)),
            // 3b z^2 = (1 + i) (12 z) z.
            _ => {
                let z12 = z.mul_small::<12, S>(simd).carry(simd);
                let product = Fp2::<F>::product_mul_by_nonresidue(simd, z12.product_schoolbook(simd, z));
                Fp2::<F>::difference::<22, S>(simd, product)
            }
        }
    }

    /// Returns the `k`th coordinate of the doubled point, as a sum of products to reduce, given the
    /// reduced values of [`Self::doubling`].
    #[inline(always)]
    pub(crate) fn doubled<S: Simd>(simd: S, [yy, xy, yz, b3zz]: &[Fp2<F>; 4], k: usize) -> Fp2<F::Product>
    where
        F: Field<S>,
    {
        let (yy, xy, yz, b3zz) = (*yy, *xy, *yz, *b3zz);
        // 9b z^2, 8 y^2, and y^2 - 9b z^2 and y^2 + 3b z^2.
        let b9zz = b3zz.mul_small::<3, S>(simd).carry(simd);
        let yy8 = yy.mul_small::<8, S>(simd).carry(simd);
        let difference = yy.sub::<130, S>(simd, b9zz).carry(simd);
        let sum = yy.add(simd, b3zz).carry(simd);
        match k {
            0 => {
                let xy2 = xy.double(simd).carry(simd);
                Fp2::<F>::difference::<6, S>(simd, difference.product(simd, xy2))
            }
            1 => Fp2::<F>::difference::<13, S>(
                simd,
                Fp2::<F>::accumulate_product(simd, difference.product(simd, sum), b3zz, yy8),
            ),
            _ => Fp2::<F>::difference::<5, S>(simd, yy8.product(simd, yz)),
        }
    }
}

/// The first stage of an addition: the ready coordinates of both points and, for Karatsuba's
/// cross terms, the products `X1 X2`, `Y1 Y2`, `Z1 Z2`, and `3b Z1 Z2`.
pub(crate) struct Addition<F, S: Simd>
where
    F: Field<S>,
{
    a: [Fp2<F>; 3],
    b: [Fp2<F>; 3],
    xx: Product<F, S>,
    yy: Product<F, S>,
    zz: Product<F, S>,
    b3zz: Product<F, S>,
}

impl<F, S: Simd> Addition<F, S>
where
    F: Field<S>,
{
    /// Readies the coordinates and forms the shared products.
    ///
    /// Under [`Field::SCHOOLBOOK`] the cross terms take their own products, so the products of
    /// coordinates are left unused and unformed.
    #[inline(always)]
    pub(crate) fn new(simd: S, lhs: Point<F>, rhs: Point<F>) -> Self {
        let a = [
            lhs.x.ready::<1, S>(simd),
            lhs.y.ready::<1, S>(simd),
            lhs.z.ready::<1, S>(simd),
        ];
        let b = [
            rhs.x.ready::<1, S>(simd),
            rhs.y.ready::<1, S>(simd),
            rhs.z.ready::<1, S>(simd),
        ];
        // 3b z1 z2 = (1 + i) (12 z1) z2.
        let z12 = a[2].mul_small::<12, S>(simd).carry(simd);
        Self {
            a,
            b,
            xx: a[0].product(simd, b[0]),
            yy: a[1].product(simd, b[1]),
            zz: a[2].product(simd, b[2]),
            b3zz: Fp2::<F>::product_mul_by_nonresidue(simd, z12.product_schoolbook(simd, b[2])),
        }
    }

    /// Returns the `k`th of the six values of the first stage, as a sum of products to reduce: the
    /// cross terms `X1 Y2 + Y1 X2`, `Y1 Z2 + Z1 Y2`, and `X1 Z2 + Z1 X2`, then
    /// `Y1 Y2 + 3b Z1 Z2`, `Y1 Y2 - 3b Z1 Z2`, and `X1 X2`.
    #[inline(always)]
    pub(crate) fn sum(&self, simd: S, k: usize) -> Fp2<F::Product> {
        match k {
            0 => Fp2::<F>::difference::<8, S>(simd, self.cross(simd, 0, 1, (self.xx, self.yy))),
            1 => Fp2::<F>::difference::<8, S>(simd, self.cross(simd, 1, 2, (self.yy, self.zz))),
            2 => Fp2::<F>::difference::<8, S>(simd, self.cross(simd, 0, 2, (self.xx, self.zz))),
            3 => Fp2::<F>::difference::<24, S>(
                simd,
                Fp2::<F>::accumulate(simd, self.yy, self.b3zz),
            ),
            4 => Fp2::<F>::difference::<26, S>(
                simd,
                Fp2::<F>::product_sub(simd, self.yy, self.b3zz),
            ),
            _ => Fp2::<F>::difference::<5, S>(simd, self.xx),
        }
    }

    /// Returns `a[i] b[j] + a[j] b[i]` as a product, given the products `(a[i] b[i], a[j] b[j])`.
    ///
    /// Karatsuba takes a schoolbook product of the sums less the two known products; under
    /// [`Field::SCHOOLBOOK`] the two products accumulate as they form.
    #[inline(always)]
    fn cross(&self, simd: S, i: usize, j: usize, (pi, pj): (Product<F, S>, Product<F, S>)) -> Product<F, S> {
        let (a, b) = (&self.a, &self.b);
        if F::SCHOOLBOOK {
            return Fp2::<F>::accumulate_product(simd, a[i].product(simd, b[j]), a[j], b[i]);
        }
        let sum_a = a[i].add(simd, a[j]).carry(simd);
        let sum_b = b[i].add(simd, b[j]).carry(simd);
        let product = Fp2::<F>::product_sub(simd, sum_a.product_schoolbook(simd, sum_b), pi);
        Fp2::<F>::product_sub(simd, product, pj)
    }

    /// Returns the `k`th coordinate of the sum, as a sum of products to reduce, given the reduced
    /// values of [`Self::sum`].
    #[inline(always)]
    pub(crate) fn coordinate(simd: S, [xy, yz, xz, sum, difference, xx]: &[Fp2<F>; 6], k: usize) -> Fp2<F::Product> {
        let (xy, yz, xz, sum, difference) = (*xy, *yz, *xz, *sum, *difference);
        let xx3 = xx.mul_small::<3, S>(simd).carry(simd);
        let xz12 = xz.mul_small::<12, S>(simd).carry(simd);
        match k {
            0 => Fp2::<F>::difference::<14, S>(
                simd,
                Fp2::<F>::product_sub(
                    simd,
                    xy.product(simd, difference),
                    Self::by_b3xz(simd, yz, xz12),
                ),
            ),
            1 => Fp2::<F>::difference::<16, S>(
                simd,
                Fp2::<F>::accumulate_product(simd, Self::by_b3xz(simd, xx3, xz12), difference, sum),
            ),
            _ => Fp2::<F>::difference::<9, S>(
                simd,
                Fp2::<F>::accumulate_product(simd, sum.product(simd, yz), xx3, xy),
            ),
        }
    }

    /// Returns `factor * 3b xz` as a product, given `xz12 = 12 xz`: `3b xz = (1 + i) (12 xz)`,
    /// multiplying the product by `1 + i`, or under [`Field::SCHOOLBOOK`] the factor `12 xz`
    /// itself.
    #[inline(always)]
    fn by_b3xz(simd: S, factor: Fp2<F>, xz12: Fp2<F>) -> Product<F, S> {
        if F::SCHOOLBOOK {
            let twisted = xz12.mul_by_nonresidue::<{ 12 * BOUND + 1 }, S>(simd).carry(simd);
            return factor.product(simd, twisted);
        }
        Fp2::<F>::product_mul_by_nonresidue(simd, factor.product_schoolbook(simd, xz12))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::field::fp::{
        BYTES as FP_BYTES,
        rns::Rns,
        reference::{self, Element},
        unsat28::Unsat28,
        unsat49::Unsat49,
    };
    use commonware_simd::{
        Operation, X86V4C, check_consistent,
        emulated::{EmulatedNeon, EmulatedScalar, EmulatedX86V4C},
        test_dispatch,
    };
    use std::{vec, vec::Vec};

    /// Number of points summed into each lane.
    const ROUNDS: usize = 12;

    /// A reference extension element `(c0, c1)` with canonical components.
    type Element2 = (Element, Element);

    /// An affine point, or `None` for the identity.
    type Affine = Option<(Element2, Element2)>;

    const ZERO: Element2 = (reference::ZERO, reference::ZERO);
    const ONE: Element2 = (reference::ONE, reference::ZERO);

    fn add((a0, a1): Element2, (b0, b1): Element2) -> Element2 {
        (reference::add(a0, b0), reference::add(a1, b1))
    }

    fn sub((a0, a1): Element2, (b0, b1): Element2) -> Element2 {
        (reference::sub(a0, b0), reference::sub(a1, b1))
    }

    fn mul((a0, a1): Element2, (b0, b1): Element2) -> Element2 {
        (
            reference::sub(reference::mul(a0, b0), reference::mul(a1, b1)),
            reference::add(reference::mul(a0, b1), reference::mul(a1, b0)),
        )
    }

    fn invert((a0, a1): Element2) -> Element2 {
        let norm = reference::add(reference::mul(a0, a0), reference::mul(a1, a1));
        let inverse = reference::invert(norm);
        (
            reference::mul(a0, inverse),
            reference::mul(reference::neg(a1), inverse),
        )
    }

    fn small(n: u64) -> Element2 {
        ([n, 0, 0, 0, 0, 0], reference::ZERO)
    }

    fn encode((c0, c1): Element2) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..FP_BYTES].copy_from_slice(&reference::to_bytes(c1));
        bytes[FP_BYTES..].copy_from_slice(&reference::to_bytes(c0));
        bytes
    }

    fn decode(bytes: &[u8; BYTES]) -> Element2 {
        let (c1, c0) = bytes.split_at(FP_BYTES);
        (
            reference::reduce(c0.try_into().unwrap()),
            reference::reduce(c1.try_into().unwrap()),
        )
    }

    /// Returns the standard G2 generator in affine coordinates, read from blst.
    fn generator() -> (Element2, Element2) {
        let mut affine = blst::blst_p2_affine::default();
        let mut words = [[0u8; FP_BYTES]; 4];
        // SAFETY: every pointer references a valid value of the expected type, and each output
        // buffer holds a base field element.
        unsafe {
            blst::blst_p2_to_affine(&mut affine, blst::blst_p2_generator());
            blst::blst_bendian_from_fp(words[0].as_mut_ptr(), &affine.x.fp[0]);
            blst::blst_bendian_from_fp(words[1].as_mut_ptr(), &affine.x.fp[1]);
            blst::blst_bendian_from_fp(words[2].as_mut_ptr(), &affine.y.fp[0]);
            blst::blst_bendian_from_fp(words[3].as_mut_ptr(), &affine.y.fp[1]);
        }
        let [x0, x1, y0, y1] = words.map(|bytes| reference::reduce(&bytes));
        ((x0, x1), (y0, y1))
    }

    /// Returns `p + q` with the affine chord-and-tangent formulas.
    fn affine_add(p: Affine, q: Affine) -> Affine {
        let (Some((x1, y1)), Some((x2, y2))) = (p, q) else {
            return p.or(q);
        };
        let slope = if x1 == x2 {
            if add(y1, y2) == ZERO {
                return None;
            }
            mul(mul(small(3), mul(x1, x1)), invert(add(y1, y1)))
        } else {
            mul(sub(y2, y1), invert(sub(x2, x1)))
        };
        let x3 = sub(sub(mul(slope, slope), x1), x2);
        let y3 = sub(mul(slope, sub(x1, x3)), y1);
        Some((x3, y3))
    }

    /// Returns projective coordinates as bytes, scaling affine points by `z`.
    fn coordinates(point: Affine, z: Element2) -> Coordinates {
        match point {
            Some((x, y)) => [mul(x, z), mul(y, z), z].map(encode),
            None => [ZERO, z, ZERO].map(encode),
        }
    }

    /// Returns the affine point of projective coordinates.
    fn affine(coordinates: &Coordinates) -> Affine {
        let [x, y, z] = coordinates.map(|bytes| decode(&bytes));
        if z == ZERO {
            return None;
        }
        let inverse = invert(z);
        Some((mul(x, inverse), mul(y, inverse)))
    }

    /// Returns the same points with every coordinate component at integer bound [`BOUND`].
    ///
    /// Scales loaded coordinates, with integer bound `2`, by `16`.
    fn widen<S: Simd, F: Field<S>>(simd: S, point: Point<F>) -> Point<F> {
        let widen = |value: Fp2<F>| {
            value
                .double(simd)
                .carry(simd)
                .mul_small::<{ BOUND / 4 }, S>(simd)
                .carry(simd)
        };
        Point {
            x: widen(point.x),
            y: widen(point.y),
            z: widen(point.z),
        }
    }

    /// Checks, in debug builds, that every coordinate component satisfies the coordinate bounds.
    fn check_bound<S: Simd, F: Field<S>>(simd: S, point: Point<F>) -> Point<F> {
        for value in [point.x, point.y, point.z] {
            value.neg::<{ BOUND + 1 }, S>(simd);
        }
        point
    }

    /// For each lane, sums `ROUNDS` points and doubles the sum, returning both.
    ///
    /// Every addend and some sums enter at the coordinate bound.
    fn sum_and_double<S: Simd, F: Field<S>>(simd: S, points: &[Coordinates]) -> Vec<Coordinates> {
        let lanes = points.len() / ROUNDS;
        let mut output = vec![IDENTITY; 2 * lanes];
        for start in (0..lanes).step_by(F::LANES) {
            let mut sum = Point::<F>::load(simd, &[], &IDENTITY);
            for round in 0..ROUNDS {
                let addend = &points[round * lanes + start..(round + 1) * lanes];
                let addend = widen(simd, Point::load(simd, addend, &IDENTITY));
                check_bound(simd, addend.add(simd, addend));
                check_bound(simd, addend.double(simd));
                sum = check_bound(simd, sum.add(simd, addend));
                // Chain some sums through doublings and round-trip others through bytes or raw
                // coordinates.
                match round % 3 {
                    0 => {
                        let double = check_bound(simd, sum.double(simd));
                        let quadruple = check_bound(simd, double.double(simd));
                        sum = check_bound(simd, sum.add(simd, sum).add(simd, quadruple));
                    }
                    1 => {
                        let mut stored = [IDENTITY; MAX_LANES];
                        sum.store(simd, &mut stored);
                        sum = widen(simd, Point::load(simd, &stored, &IDENTITY));
                    }
                    // Negate through -s + 2s, and round-trip through raw coordinates.
                    _ => {
                        let negated = check_bound(simd, sum.negate(simd));
                        sum = check_bound(simd, negated.add(simd, sum.double(simd)));
                        let mut raw = [[[F::Raw::default(); 2]; 3]; MAX_LANES];
                        sum.store_raw(simd, &mut raw);
                        let lanes: Vec<_> = raw.iter().collect();
                        sum = Point::load_raw(simd, &lanes);
                    }
                }
            }
            sum.store(simd, &mut output[start..lanes]);
            sum.double(simd).store(simd, &mut output[lanes + start..]);
        }
        output
    }

    #[test]
    fn sums_and_doublings_match_reference() {
        /// Runs [`sum_and_double`] in every representation, returning the positional ones' outputs.
        struct Evaluate<'a>(&'a [Coordinates]);

        impl<S: Simd> Operation<S> for Evaluate<'_> {
            type Output = [Vec<Coordinates>; 2];

            fn portable(self, simd: S) -> [Vec<Coordinates>; 2] {
                simd.execute(
                    #[inline(always)]
                    |simd: S| {
                        [
                            sum_and_double::<S, Unsat49<S>>(simd, self.0),
                            sum_and_double::<S, Unsat28<S>>(simd, self.0),
                        ]
                    },
                )
            }

            // Residues require x86v4c and must match the other representations.
            fn x86_v4c(self, simd: S) -> [Vec<Coordinates>; 2]
            where
                S: X86V4C,
            {
                let points = self.0;
                let outputs = self.portable(simd);
                let residues = simd.execute(
                    #[inline(always)]
                    |simd: S| sum_and_double::<S, Rns<S>>(simd, points),
                );
                assert!(residues == outputs[0], "residues differ");
                outputs
            }
        }

        let (x, y) = generator();
        let b = mul(small(4), (reference::ONE, reference::ONE));
        assert_eq!(
            mul(y, y),
            add(mul(x, mul(x, x)), b),
            "the generator is on the curve"
        );
        // Multiples of the generator, with repeats, negations, and identities to exercise
        // doubling, cancellation, and the identity cases, in varied projective scalings.
        let mut points = Vec::new();
        let mut inputs = Vec::new();
        let mut point = Some((x, y));
        for i in 0..ROUNDS * MAX_LANES {
            let addend = match i % 7 {
                3 => None,
                5 => point.map(|(x, y)| (x, sub(ZERO, y))),
                _ => point,
            };
            points.push(addend);
            let z = ([i as u64 + 1, 0, 0, 0, 0, 0], [i as u64 + 2, 0, 0, 0, 0, 0]);
            inputs.push(coordinates(addend, if i % 2 == 0 { ONE } else { z }));
            if i % 5 != 0 {
                point = affine_add(point, Some((x, y)));
            }
        }
        let mut expected = Vec::new();
        for lane in 0..MAX_LANES {
            let mut sum = None;
            for round in 0..ROUNDS {
                sum = affine_add(sum, points[round * MAX_LANES + lane]);
                if round % 3 == 0 {
                    // sum + sum + 4 sum.
                    let double = affine_add(sum, sum);
                    sum = affine_add(double, affine_add(double, double));
                }
            }
            expected.push(sum);
        }
        let check = |outputs: [Vec<Coordinates>; 2]| {
            for (representation, output) in outputs.iter().enumerate() {
                for lane in 0..MAX_LANES {
                    assert_eq!(
                        affine(&output[lane]),
                        expected[lane],
                        "sum {representation} {lane}"
                    );
                    assert_eq!(
                        affine(&output[MAX_LANES + lane]),
                        affine_add(expected[lane], expected[lane]),
                        "double {representation} {lane}"
                    );
                }
            }
        };
        check(test_dispatch(Evaluate(&inputs)));
        check_consistent(|| Evaluate(&inputs));
        // Run every representation and vector width even on hosts without native SIMD.
        check(Evaluate(&inputs).portable(EmulatedScalar));
        check(Evaluate(&inputs).portable(EmulatedNeon));
        check(EmulatedX86V4C.execute(Evaluate(&inputs)));
    }
}
