//! The group G1: the prime-order subgroup of `y^2 = x^3 + 4` over the base field.

use crate::{
    curve::{Curve, Projective},
    fp::{
        Fp,
        lanes::{Lanes, MAX_LANES},
    },
    scalar::Scalar,
};
use commonware_simd::{Operation, Simd, dispatch};
use subtle::{Choice, ConstantTimeEq};

/// The curve coefficient `b`.
const B: Fp = Fp::from_u64(4);

/// Returns the curve over one point per lane.
#[inline(always)]
fn lanes<S: Simd>(simd: S) -> Curve<Lanes<S>> {
    Curve::new(Lanes(simd), B)
}

/// An element of G1 in homogeneous projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct G1(Projective<Fp>);


/// A curve operation on one or two points.
#[derive(Clone, Copy)]
enum Unary {
    Double,
    Neg,
}

/// Evaluates a unary operation on a single point.
struct Apply(Unary, G1);

impl<S: Simd> Operation<S> for Apply {
    type Output = G1;

    fn portable(self, simd: S) -> G1 {
        simd.execute(
            #[inline(always)]
            |simd: S| {
                let curve = lanes(simd);
                let p = curve.load([&self.1.0]);
                let result = match self.0 {
                    Unary::Double => curve.double(p),
                    Unary::Neg => curve.neg(p),
                };
                let mut output = [G1::IDENTITY.0; 1];
                curve.store(result, &mut output);
                G1(output[0])
            },
        )
    }
}

/// Multiplies a point by a scalar.
struct Mul(G1, Scalar);

impl<S: Simd> Operation<S> for Mul {
    type Output = G1;

    fn portable(self, simd: S) -> G1 {
        simd.execute(
            #[inline(always)]
            |simd: S| {
                let curve = lanes(simd);
                let product = curve.mul(curve.load([&self.0.0]), &self.1);
                let mut output = [G1::IDENTITY.0; 1];
                curve.store(product, &mut output);
                G1(output[0])
            },
        )
    }
}

/// Sums a sequence of points.
struct Sum<'a>(&'a [G1]);

impl<S: Simd> Operation<S> for Sum<'_> {
    type Output = G1;

    fn portable(self, simd: S) -> G1 {
        simd.execute(
            #[inline(always)]
            |simd: S| {
                // Accumulate one partial sum per lane, then fold the lanes together.
                let curve = lanes(simd);
                let mut partial = curve.identity();
                for chunk in self.0.chunks(S::U64_LANES) {
                    partial = curve.add(partial, curve.load(chunk.iter().map(|p| &p.0)));
                }
                let mut partials = [G1::IDENTITY.0; MAX_LANES];
                curve.store(partial, &mut partials);
                let mut total = curve.identity();
                for partial in &partials[..S::U64_LANES] {
                    total = curve.add(total, curve.load([partial]));
                }
                let mut output = [G1::IDENTITY.0; 1];
                curve.store(total, &mut output);
                G1(output[0])
            },
        )
    }
}

/// Adds two points.
struct Add(G1, G1);

impl<S: Simd> Operation<S> for Add {
    type Output = G1;

    fn portable(self, simd: S) -> G1 {
        simd.execute(
            #[inline(always)]
            |simd: S| {
                let curve = lanes(simd);
                let sum = curve.add(curve.load([&self.0.0]), curve.load([&self.1.0]));
                let mut output = [G1::IDENTITY.0; 1];
                curve.store(sum, &mut output);
                G1(output[0])
            },
        )
    }
}

impl G1 {
    /// The identity element.
    pub const IDENTITY: Self = Self(Projective {
        x: Fp::ZERO,
        y: Fp::ONE,
        z: Fp::ZERO,
    });

    /// The standard generator.
    pub const GENERATOR: Self = match (
        Fp::from_words([
            0xfb3a_f00a_db22_c6bb,
            0x6c55_e83f_f97a_1aef,
            0xa14e_3a3f_171b_ac58,
            0xc368_8c4f_9774_b905,
            0x2695_638c_4fa9_ac0f,
            0x17f1_d3a7_3197_d794,
        ]),
        Fp::from_words([
            0x0caa_2329_46c5_e7e1,
            0xd03c_c744_a288_8ae4,
            0x00db_18cb_2c04_b3ed,
            0xfcf5_e095_d5d0_0af6,
            0xa09e_30ed_741d_8ae4,
            0x08b3_f481_e3aa_a0f1,
        ]),
    ) {
        (Some(x), Some(y)) => Self::from_affine_unchecked(x, y),
        _ => panic!("generator coordinates are canonical"),
    };

    /// Builds a point from affine coordinates without checking the curve equation or subgroup.
    pub(crate) const fn from_affine_unchecked(x: Fp, y: Fp) -> Self {
        Self(Projective { x, y, z: Fp::ONE })
    }

    /// Returns `self + other`.
    pub fn add(&self, other: &Self) -> Self {
        dispatch(Add(*self, *other))
    }

    /// Returns `2 * self`.
    pub fn double(&self) -> Self {
        dispatch(Apply(Unary::Double, *self))
    }

    /// Returns `-self`.
    pub fn neg(&self) -> Self {
        dispatch(Apply(Unary::Neg, *self))
    }

    /// Returns `scalar * self`, in constant time with respect to the scalar.
    pub fn mul(&self, scalar: &Scalar) -> Self {
        dispatch(Mul(*self, *scalar))
    }

    /// Returns the sum of `points`.
    pub fn sum(points: &[Self]) -> Self {
        dispatch(Sum(points))
    }

    /// Returns whether this is the identity.
    pub fn is_identity(&self) -> Choice {
        self.0.z.is_zero()
    }

    /// Returns the affine coordinates, or `None` for the identity.
    pub fn to_affine(&self) -> Option<(Fp, Fp)> {
        if bool::from(self.is_identity()) {
            return None;
        }
        let z = self.0.z.invert();
        Some((self.0.x.mul(z), self.0.y.mul(z)))
    }

    /// Returns whether the coordinates satisfy `Y^2 Z = X^3 + 4 Z^3`.
    pub fn is_on_curve(&self) -> Choice {
        let Projective { x, y, z } = self.0;
        let lhs = y.square().mul(z);
        let rhs = x.square().mul(x).add(B.mul(z.square().mul(z)));
        lhs.ct_eq(&rhs)
    }
}

impl ConstantTimeEq for G1 {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Equal projective points have proportional coordinates. Identities have Z = 0 and
        // nonzero Y, so the cross-multiplications also separate them from finite points.
        let (p, q) = (self.0, other.0);
        p.x.mul(q.z).ct_eq(&q.x.mul(p.z)) & p.y.mul(q.z).ct_eq(&q.y.mul(p.z))
    }
}

impl PartialEq for G1 {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for G1 {}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::fp::{Single, tests as fp};
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;
    use commonware_simd::{check_consistent, test_dispatch};

    pub(crate) fn to_blst(point: &G1) -> blst::blst_p1 {
        let mut out = blst::blst_p1::default();
        if let Some((x, y)) = point.to_affine() {
            let affine = blst::blst_p1_affine {
                x: fp::to_blst(x),
                y: fp::to_blst(y),
            };
            // SAFETY: valid pointers to point structures.
            unsafe { blst::blst_p1_from_affine(&mut out, &affine) };
        }
        out
    }

    pub(crate) fn from_blst(point: &blst::blst_p1) -> G1 {
        let mut affine = blst::blst_p1_affine::default();
        // SAFETY: valid pointers to point structures.
        unsafe {
            if blst::blst_p1_is_inf(point) {
                return G1::IDENTITY;
            }
            blst::blst_p1_to_affine(&mut affine, point);
        }
        G1::from_affine_unchecked(fp::from_blst(&affine.x), fp::from_blst(&affine.y))
    }

    /// Draws a random point of the prime-order subgroup, occasionally the identity.
    pub(crate) fn point(u: &mut Unstructured<'_>) -> arbitrary::Result<G1> {
        if u.ratio(1, 16)? {
            return Ok(G1::IDENTITY);
        }
        let scalar: [u8; 32] = u.arbitrary()?;
        let mut out = blst::blst_p1::default();
        // SAFETY: valid pointers; the scalar buffer holds 256 bits.
        unsafe { blst::blst_p1_mult(&mut out, blst::blst_p1_generator(), scalar.as_ptr(), 256) };
        Ok(from_blst(&out))
    }

    #[test]
    fn generator_matches_blst() {
        // SAFETY: the generator pointer is valid for the program's lifetime.
        let generator = unsafe { *blst::blst_p1_generator() };
        assert_eq!(from_blst(&generator), G1::GENERATOR);
        assert!(bool::from(G1::GENERATOR.is_on_curve()));
        assert!(bool::from(G1::IDENTITY.is_on_curve()));
        assert_eq!(G1::IDENTITY.to_affine(), None);
    }

    #[test]
    fn arithmetic_matches_blst() {
        minifuzz::test(|u| {
            let p = point(u)?;
            let q = point(u)?;
            let (bp, bq) = (to_blst(&p), to_blst(&q));
            let mut out = blst::blst_p1::default();
            // SAFETY: valid pointers to point structures.
            unsafe {
                blst::blst_p1_add_or_double(&mut out, &bp, &bq);
                assert_eq!(from_blst(&out), p.add(&q));
                blst::blst_p1_double(&mut out, &bp);
                assert_eq!(from_blst(&out), p.double());
                blst::blst_p1_cneg(&mut out, true);
                assert_eq!(from_blst(&out), p.double().neg());
            }
            assert_eq!(p.add(&p), p.double());
            assert_eq!(p.add(&p.neg()), G1::IDENTITY);
            assert_eq!(p.add(&G1::IDENTITY), p);
            assert!(bool::from(p.add(&q).is_on_curve()));
            Ok(())
        });
    }

    #[test]
    fn sum_matches_sequential_addition() {
        minifuzz::test(|u| {
            let count = u.int_in_range(0..=40)?;
            let mut points = Vec::with_capacity(count);
            for _ in 0..count {
                points.push(point(u)?);
            }
            let expected = points.iter().fold(G1::IDENTITY, |acc, p| acc.add(p));
            assert_eq!(G1::sum(&points), expected);
            struct SumAll<'a>(&'a [G1]);
            impl<S: Simd> Operation<S> for SumAll<'_> {
                type Output = G1;
                fn portable(self, simd: S) -> G1 {
                    Sum(self.0).portable(simd)
                }
            }
            assert_eq!(test_dispatch(SumAll(&points)), expected);
            check_consistent(|| SumAll(&points));
            Ok(())
        });
    }

    #[test]
    fn scalar_multiplication_matches_blst() {
        minifuzz::test(|u| {
            let p = point(u)?;
            let scalar = match u.int_in_range(0..=3)? {
                0 => Scalar::ZERO,
                1 => Scalar::ONE,
                _ => Scalar::from_bytes(&u.arbitrary()?).unwrap_or(Scalar::ONE),
            };
            let mut out = blst::blst_p1::default();
            let bytes = scalar.to_words().map(u64::to_le_bytes).concat();
            // SAFETY: valid pointers; the scalar buffer holds 256 little-endian bits.
            unsafe { blst::blst_p1_mult(&mut out, &to_blst(&p), bytes.as_ptr(), 256) };
            assert_eq!(from_blst(&out), p.mul(&scalar));
            Ok(())
        });
    }

    /// Adds and doubles one pair of points per lane.
    struct Formulas<'a> {
        p: &'a [Projective<Fp>],
        q: &'a [Projective<Fp>],
    }

    impl<S: Simd> Operation<S> for Formulas<'_> {
        type Output = Vec<(G1, G1)>;

        fn portable(self, simd: S) -> Self::Output {
            let curve = lanes(simd);
            let mut results = Vec::new();
            for start in (0..self.p.len()).step_by(S::U64_LANES) {
                let (p, q) = (curve.load(&self.p[start..]), curve.load(&self.q[start..]));
                let mut sums = [G1::IDENTITY.0; 8];
                let mut doubles = [G1::IDENTITY.0; 8];
                curve.store(curve.add(p, q), &mut sums);
                curve.store(curve.double(p), &mut doubles);
                results.extend(
                    sums.into_iter()
                        .zip(doubles)
                        .take(S::U64_LANES)
                        .map(|(s, d)| (G1(s), G1(d))),
                );
            }
            results
        }
    }

    #[test]
    fn lanes_match_scalar_formulas() {
        let scalar = Curve::new(Single, B);
        minifuzz::test(|u| {
            let mut p = Vec::new();
            let mut q = Vec::new();
            for _ in 0..8 {
                p.push(point(u)?.0);
                q.push(point(u)?.0);
            }
            let results = test_dispatch(Formulas { p: &p, q: &q });
            for ((p, q), (sum, doubled)) in p.iter().zip(&q).zip(results) {
                assert_eq!(sum, G1(scalar.add(*p, *q)));
                assert_eq!(doubled, G1(scalar.double(*p)));
            }
            check_consistent(|| Formulas { p: &p, q: &q });
            Ok(())
        });
    }
}
