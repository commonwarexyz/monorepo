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

use crate::core::field::{
    arithmetic::Field,
    fp::MINUS_ONE,
    fp2::{BYTES, Fp2, Product},
};
use commonware_simd::Simd;

/// Projective coordinates `[X, Y, Z]` as big-endian extension elements.
pub type Coordinates = [[u8; BYTES]; 3];

/// The identity `(0 : 1 : 0)` as projective coordinates.
pub const IDENTITY: Coordinates = {
    let mut identity = [[0; BYTES]; 3];
    identity[1][BYTES - 1] = 1;
    identity
};

/// Largest integer bound of a coordinate component, in units of `p`.
///
/// The positional representations return at most `32` from the reduction of [`Point::add`]'s `Y`
/// coordinate, and residues reduce to at most `17`.
pub const BOUND: u64 = 32;

/// Largest number of points in a value, the widest representation's lane count.
const MAX_LANES: usize = 16;

/// A doubled point, with the values of the doubling that the tangent line at the point reuses.
///
/// Each value has positional limb bound `1`. Within the coordinate bounds, `yy` has integer bound
/// at most `17` and `b3zz` at most `43` in every representation, and `yz` at most `17`.
pub(crate) struct Doubling<F> {
    /// The doubled point.
    pub(crate) point: Point<F>,
    /// `Y^2`.
    pub(crate) yy: Fp2<F>,
    /// `3b Z^2`.
    pub(crate) b3zz: Fp2<F>,
    /// `Y Z`.
    pub(crate) yz: Fp2<F>,
}

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

impl<F> Point<F> {
    /// Loads up to one projective point per lane, filling the remaining lanes with `fill`.
    ///
    /// Runs as its own kernel, so callers share one copy of the conversions.
    #[inline(always)]
    pub fn load<S: Simd>(simd: S, points: &[Coordinates], fill: &Coordinates) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| Self::read(simd, points, fill),
        )
    }

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

    /// Stores each lane's canonical projective coordinates, dropping lanes beyond `points`.
    ///
    /// Runs as its own kernel, so callers share one copy of the conversions.
    #[inline(always)]
    pub fn store<S: Simd>(self, simd: S, points: &mut [Coordinates])
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| self.write(simd, points),
        )
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

    /// Returns `rhs` in every lane whose bit is set in `lanes`, and `self` in the others.
    ///
    /// Bit `i` of `lanes` selects lane `i`, without branching on `lanes`.
    #[inline(always)]
    pub fn select<S: Simd>(self, simd: S, rhs: Self, lanes: u64) -> Self
    where
        F: Field<S>,
    {
        Self {
            x: self.x.select(simd, rhs.x, lanes),
            y: self.y.select(simd, rhs.y, lanes),
            z: self.z.select(simd, rhs.z, lanes),
        }
    }

    /// Stores each lane's raw coordinates, dropping lanes beyond `points`.
    #[inline(always)]
    pub fn store_raw<S: Simd>(self, simd: S, points: &mut [[[F::Raw; 2]; 3]])
    where
        F: Field<S>,
    {
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
    pub fn load_raw<S: Simd>(simd: S, points: &[&[[F::Raw; 2]; 3]]) -> Self
    where
        F: Field<S>,
    {
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
    pub fn neg<S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        let minus_one = F::load(simd, &[], &MINUS_ONE);
        Self {
            y: self.y.ready::<1, S>(simd).mul_base(simd, minus_one),
            ..self
        }
    }

    /// Returns `self + rhs`.
    ///
    /// This is Algorithm 7 of Renes, Costello, and Batina, "Complete addition formulas for prime
    /// order elliptic curves" (2016), which accepts any pair of points, including the identity and
    /// equal points. Each cross term is a schoolbook product of sums less the two known products,
    /// and `3b z1 z2` comes from one more product, so that `Y1 Y2 + 3b Z1 Z2` and
    /// `Y1 Y2 - 3b Z1 Z2` each take one reduction. That leaves thirteen extension products.
    ///
    /// Runs as its own kernel, so callers share one copy of the formula.
    #[inline(always)]
    pub fn add<S: Simd>(self, simd: S, rhs: Self) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| self.sum(simd, rhs),
        )
    }

    /// Body of [`Self::add`].
    #[inline(always)]
    fn sum<S: Simd>(self, simd: S, rhs: Self) -> Self
    where
        F: Field<S>,
    {
        let (x1, y1, z1) = (
            self.x.ready::<1, S>(simd),
            self.y.ready::<1, S>(simd),
            self.z.ready::<1, S>(simd),
        );
        let (x2, y2, z2) = (
            rhs.x.ready::<1, S>(simd),
            rhs.y.ready::<1, S>(simd),
            rhs.z.ready::<1, S>(simd),
        );
        let xx = x1.product(simd, x2);
        let yy = y1.product(simd, y2);
        let zz = z1.product(simd, z2);
        // x1 y2 + y1 x2, y1 z2 + z1 y2, and x1 z2 + z1 x2.
        let xy = cross(simd, [x1, y1], [x2, y2], xx, yy);
        let yz = cross(simd, [y1, z1], [y2, z2], yy, zz);
        let xz = cross(simd, [x1, z1], [x2, z2], xx, zz);
        // 3b z1 z2 = (1 + i) (12 z1) z2.
        let z1 = z1.mul_small::<12, S>(simd).carry(simd);
        let b3zz = Fp2::<F>::product_mul_by_nonresidue(simd, z1.product_schoolbook(simd, z2));
        let sum = Fp2::<F>::reduce::<24, S>(simd, Fp2::<F>::accumulate(simd, yy, b3zz));
        let difference = Fp2::<F>::reduce::<26, S>(simd, Fp2::<F>::product_sub(simd, yy, b3zz));
        let xx3 = Fp2::<F>::reduce::<5, S>(simd, xx)
            .mul_small::<3, S>(simd)
            .carry(simd);
        // 3b xz = (1 + i) (12 xz), multiplying its products by 1 + i.
        let xz12 = xz.mul_small::<12, S>(simd).carry(simd);
        let yz_b3xz = Fp2::<F>::product_mul_by_nonresidue(simd, yz.product_schoolbook(simd, xz12));
        let xx3_b3xz =
            Fp2::<F>::product_mul_by_nonresidue(simd, xz12.product_schoolbook(simd, xx3));
        let x = Fp2::<F>::product_sub(simd, xy.product(simd, difference), yz_b3xz);
        let y = Fp2::<F>::accumulate_product(simd, xx3_b3xz, difference, sum);
        let z = Fp2::<F>::accumulate_product(simd, sum.product(simd, yz), xx3, xy);
        Self {
            x: Fp2::<F>::reduce::<14, S>(simd, x),
            y: Fp2::<F>::reduce::<16, S>(simd, y),
            z: Fp2::<F>::reduce::<9, S>(simd, z),
        }
    }

    /// Returns `2 * self`.
    ///
    /// This is Algorithm 9 of Renes, Costello, and Batina, which accepts any point, including the
    /// identity. It returns the same point as [`Self::add`] of `self` with itself, with seven
    /// extension products and one squaring.
    ///
    /// Runs as its own kernel, so callers share one copy of the formula.
    #[inline(always)]
    pub fn double<S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| self.doubling(simd).point,
        )
    }

    /// Body of [`Self::double`], which also returns the values the tangent line reuses.
    #[inline(always)]
    pub(crate) fn doubling<S: Simd>(self, simd: S) -> Doubling<F>
    where
        F: Field<S>,
    {
        let (x, y, z) = (
            self.x.ready::<1, S>(simd),
            self.y.ready::<1, S>(simd),
            self.z.ready::<1, S>(simd),
        );
        let yy = y.square::<{ BOUND + 1 }, S>(simd);
        let xy = x.mul::<5, S>(simd, y);
        let yz = y.mul::<5, S>(simd, z);
        // 3b z^2 = (1 + i) (12 z) z, and 9b z^2.
        let z12 = z.mul_small::<12, S>(simd).carry(simd);
        let b3zz = Fp2::<F>::reduce::<22, S>(
            simd,
            Fp2::<F>::product_mul_by_nonresidue(simd, z12.product_schoolbook(simd, z)),
        );
        let b9zz = b3zz.mul_small::<3, S>(simd).carry(simd);
        let yy8 = yy.mul_small::<8, S>(simd).carry(simd);
        // y^2 - 9b z^2 and y^2 + 3b z^2.
        let difference = yy.sub::<130, S>(simd, b9zz).carry(simd);
        let sum = yy.add(simd, b3zz).carry(simd);
        let xy2 = xy.double(simd).carry(simd);
        let y = Fp2::<F>::accumulate_product(simd, difference.product(simd, sum), b3zz, yy8);
        Doubling {
            point: Self {
                x: Fp2::<F>::reduce::<6, S>(simd, difference.product(simd, xy2)),
                y: Fp2::<F>::reduce::<13, S>(simd, y),
                z: Fp2::<F>::reduce::<5, S>(simd, yy8.product(simd, yz)),
            },
            yy,
            b3zz,
            yz,
        }
    }
}

/// Returns `a[0] b[1] + a[1] b[0]`, given the products `p0 = a[0] b[0]` and `p1 = a[1] b[1]`
/// of coordinates.
#[cfg_attr(not(debug_assertions), inline(always))]
fn cross<S: Simd, F: Field<S>>(
    simd: S,
    a: [Fp2<F>; 2],
    b: [Fp2<F>; 2],
    p0: Product<F, S>,
    p1: Product<F, S>,
) -> Fp2<F> {
    let a = a[0].add(simd, a[1]).carry(simd);
    let b = b[0].add(simd, b[1]).carry(simd);
    let product = Fp2::<F>::product_sub(simd, a.product_schoolbook(simd, b), p0);
    Fp2::<F>::reduce::<8, S>(simd, Fp2::<F>::product_sub(simd, product, p1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::field::fp::{
        BYTES as FP_BYTES,
        rns::Rns,
        tests::{self as reference, Element},
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
                        let negated = check_bound(simd, sum.neg(simd));
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

    #[test]
    fn sums_and_doublings_match_reference() {
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
