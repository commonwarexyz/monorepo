//! The optimal ate pairing on BLS12-381.
//!
//! [`pairing`] maps a point of G1 and a point of G2 to the target group [`Gt`]. Products of pairings
//! share one final exponentiation, which is how signatures are verified: [`pairing_check`]
//! asks whether a product of pairings is one.
//!
//! The Miller loop runs on the twist `y^2 = x^3 + 4 (1 + i)` of G2 in homogeneous projective
//! coordinates, with affine inputs, and evaluates each line as the sparse element
//! `l0 + l2 w^2 + l3 w^3` of Fp12. Lines are scaled by Fp2 factors that the final exponentiation
//! removes. The final exponentiation splits into the easy part `(p^6 - 1) (p^2 + 1)`, which
//! lands in the cyclotomic subgroup, and the hard part, an addition chain over the curve
//! parameter `z = -0xd201000000010000` (see "Faster Squaring in the Cyclotomic Subgroup of Sixth
//! Degree Extensions", Granger and Scott, 2010, and the chain of the zkcrypto `pairing` crate).
//!
//! Several pairs run one pair per vector lane; a single pair, and the final exponentiation,
//! run in the residue number system where the backend has it.
//!
//! # Bounds
//!
//! Every state coordinate of the Miller loop is a sum of at most four base products with one
//! reduction: below `3p` under the bounds of [`crate::fp::lanes`] and below `128p` under those of
//! `crate::fp::rns`. State coordinates are therefore valid subtrahends and multiplicands. The
//! line coefficients `l2` and `l3`, which the sparse multiplication multiplies by the non-residue,
//! are single base products and so valid subtrahends. `l0` is a sum or difference of products,
//! below `2^9 p` more than a product, and is only ever a multiplicand.

use crate::{
    curve::{Affine, Curve, Projective},
    fp::{Arithmetic, Fp, lanes::MAX_LANES},
    fp2::{self, Ext, Fp2, Pair},
    fp12::{BYTES, Ext12, Fp12, Sextic},
    g1::G1,
    g2::G2,
    group::{Run, Workload},
};
use alloc::vec::Vec;
use commonware_simd::dispatch;
use subtle::{Choice, ConstantTimeEq};

/// `|z|`, the absolute value of the curve parameter.
const Z: u64 = 0xd201_0000_0001_0000;

/// `|z| / 2`.
const HALF_Z: u64 = Z / 2;

/// An element of the prime-order target group, the image of a pairing.
///
/// # Examples
///
/// ```
/// use commonware_cryptography_bls12381::{g1::G1, g2::G2, pairing::{Gt, pairing}};
///
/// let e = pairing(&G1::GENERATOR, &G2::GENERATOR);
/// assert_ne!(e, Gt::ONE);
/// assert_eq!(e.mul(&e.invert()), Gt::ONE);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Gt(Fp12);

impl Gt {
    /// The identity element.
    pub const ONE: Self = Self(Fp12::ONE);

    /// Returns the element as an element of Fp12.
    pub const fn as_fp12(&self) -> &Fp12 {
        &self.0
    }

    /// Returns whether this is the identity.
    pub fn is_one(&self) -> Choice {
        self.ct_eq(&Self::ONE)
    }

    /// Returns `self * rhs`.
    pub const fn mul(&self, rhs: &Self) -> Self {
        Self(self.0.mul(rhs.0))
    }

    /// Returns the inverse, which is the conjugate in the target group.
    pub const fn invert(&self) -> Self {
        Self(self.0.conjugate())
    }

    /// Returns the canonical big-endian encoding of the Fp12 element, in the order of blst.
    pub fn to_bytes(&self) -> [u8; BYTES] {
        self.0.to_bytes()
    }
}

impl ConstantTimeEq for Gt {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Gt {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Gt {}

/// Returns the pairing `e(p, q)`.
///
/// The pairing of an identity is one. The points must lie in the prime-order subgroups, as
/// every point obtained through the public API does. Timing may depend on the points.
pub fn pairing(p: &G1, q: &G2) -> Gt {
    multi_pairing(&[(*p, *q)])
}

/// Returns the product of the pairings `e(p, q)` over `pairs`, which is one for no pairs.
///
/// The product shares one final exponentiation. Timing may depend on the points.
pub fn multi_pairing(pairs: &[(G1, G2)]) -> Gt {
    let product = miller_loop(pairs);
    if product == Fp12::ONE {
        return Gt::ONE;
    }
    final_exponentiation(&product).unwrap_or(Gt::ONE)
}

/// Returns whether the product of the pairings `e(p, q)` over `pairs` is one.
///
/// A signature `s` of a message hash `h` under a public key `k` verifies when
/// `e(-G1, s) * e(k, h)` is one, which is `pairing_check(&[(-G1::GENERATOR, s), (k, h)])`.
pub fn pairing_check(pairs: &[(G1, G2)]) -> bool {
    multi_pairing(pairs) == Gt::ONE
}

/// Returns the product of the Miller loops of `pairs`, before the final exponentiation.
///
/// Pairs with an identity contribute one. The result is only defined up to factors that the
/// final exponentiation removes.
pub fn miller_loop(pairs: &[(G1, G2)]) -> Fp12 {
    let prepared = prepare(pairs);
    match prepared.len() {
        0 => Fp12::ONE,
        1 => dispatch(Run::<G1, Miller<'_, false>>::new(Miller(&prepared))),
        _ => dispatch(Run::<G1, Miller<'_, true>>::new(Miller(&prepared))),
    }
}

/// Returns `f^((p^12 - 1) / r)` up to the fixed power the addition chain computes, or `None` for
/// zero.
///
/// This is the second half of a pairing: `final_exponentiation(&miller_loop(&[(p, q)]))` is
/// `pairing(&p, &q)`.
pub fn final_exponentiation(f: &Fp12) -> Option<Gt> {
    dispatch(Run::<G1, FinalExponentiation>::new(FinalExponentiation(*f))).map(Gt)
}

/// A pair of nonidentity points in affine coordinates.
#[derive(Clone, Copy, Debug)]
struct Prepared {
    px: Fp,
    py: Fp,
    qx: Fp2,
    qy: Fp2,
}

/// Returns the pairs without an identity, in affine coordinates.
fn prepare(pairs: &[(G1, G2)]) -> Vec<Prepared> {
    let mut ps = Vec::with_capacity(pairs.len());
    let mut qs = Vec::with_capacity(pairs.len());
    for (p, q) in pairs {
        if bool::from(p.is_identity() | q.is_identity()) {
            continue;
        }
        ps.push(*p);
        qs.push(*q);
    }
    G1::to_affine_many(&ps)
        .into_iter()
        .zip(G2::to_affine_many(&qs))
        .filter_map(|(p, q)| {
            let ((px, py), (qx, qy)) = (p?, q?);
            Some(Prepared { px, py, qx, qy })
        })
        .collect()
}

/// The Miller loop of one pair per lane, on the context of the base field.
///
/// Lanes beyond the pairs repeat the first pair and are discarded.
#[derive(Clone, Copy)]
struct Loop<F: Arithmetic<Scalar = Fp>> {
    field: F,
    tower: Ext12<F>,
    /// The base field constant 12, so that `3b' = 12 (1 + i)` for the twist's `b' = 4 (1 + i)`.
    twelve: F::Element,
    /// The affine coordinate `xp` of the G1 point.
    x: F::Element,
    /// `-yp` for the G1 point.
    negated_y: F::Element,
    /// The G2 point.
    q: Affine<Pair<F::Element>>,
}

/// A line `l0 + l2 w^2 + l3 w^3`.
type Line<E> = [Pair<E>; 3];

impl<F: Arithmetic<Scalar = Fp>> Loop<F> {
    /// Returns the Miller loop for the points held in the lanes.
    #[inline(always)]
    fn new(field: F, x: F::Element, y: F::Element, q: Affine<Pair<F::Element>>) -> Self {
        Self {
            field,
            tower: Ext12::new(field),
            twelve: field.constant(Fp::from_u64(12)),
            x,
            negated_y: field.neg(y),
            q,
        }
    }

    /// Returns `s * x` for a base field `s`.
    #[inline(always)]
    fn scale(self, x: Pair<F::Element>, s: F::Element) -> Pair<F::Element> {
        Pair {
            c0: self.field.mul(x.c0, s),
            c1: self.field.mul(x.c1, s),
        }
    }

    /// Returns `3b' x = 12 (1 + i) x`, below the bound of one base product.
    #[inline(always)]
    fn times_b3(self, x: Pair<F::Element>) -> Pair<F::Element> {
        self.scale(fp2::mul_by_nonresidue(self.field, x), self.twelve)
    }

    /// Doubles `t` and returns the line through it, tangent to the twist.
    ///
    /// With the curve equation, `3 x^3 - 2 y^2 z` becomes `z (y^2 - 3b' z^2)`, and scaling the
    /// tangent by `-2 y z^2 / z` leaves `[3b' z^2 - y^2, 3 x^2 xp, -2 y z yp]`. The point is
    /// the complete doubling of Renes, Costello, and Batina (Algorithm 9).
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn double(
        self,
        t: Projective<Pair<F::Element>>,
    ) -> (Projective<Pair<F::Element>>, Line<F::Element>) {
        let ext = Ext(self.field);
        let Projective { x, y, z } = t;
        let xx = ext.square(x);
        let yy = ext.square(y);
        let zz = ext.square(z);
        let xy = ext.mul(x, y);
        let yz = ext.mul(y, z);
        let b3zz = self.times_b3(zz);
        let three_b3zz = ext.add(ext.double(b3zz), b3zz);
        // Subtrahends are below three products; the difference is a multiplicand.
        let u = ext.sub(yy, three_b3zz);
        let v = ext.add(yy, b3zz);
        let eight_yy = ext.double(ext.double(ext.double(yy)));
        let doubled = Projective {
            x: ext.mul(ext.double(xy), u),
            y: ext.mul_add(u, v, eight_yy, b3zz),
            z: ext.mul(eight_yy, yz),
        };
        let three_xx = ext.add(ext.double(xx), xx);
        let line = [
            ext.sub(b3zz, yy),
            self.scale(three_xx, self.x),
            self.scale(ext.double(yz), self.negated_y),
        ];
        (doubled, line)
    }

    /// Adds the point `q` to `t` and returns the line through them.
    ///
    /// The line is `[qx y - qy x, (qy z - y) xp, -(qx z - x) yp]` and the point is the complete
    /// mixed addition of Renes, Costello, and Batina (Algorithm 8).
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn add(
        self,
        t: Projective<Pair<F::Element>>,
    ) -> (Projective<Pair<F::Element>>, Line<F::Element>) {
        let ext = Ext(self.field);
        let Projective { x, y, z } = t;
        let Affine { x: qx, y: qy } = self.q;
        let qxz = ext.mul(qx, z);
        let qyz = ext.mul(qy, z);
        let t0 = ext.mul(x, qx);
        let t1 = ext.mul(y, qy);
        let t3 = ext.mul_add(x, qy, y, qx);
        let t4 = ext.add(qyz, y);
        let xz = ext.add(qxz, x);
        let t0 = ext.add(ext.double(t0), t0);
        let t2 = self.times_b3(z);
        let z3 = ext.add(t1, t2);
        let t1 = ext.sub(t1, t2);
        let y3 = self.times_b3(xz);
        let sum = Projective {
            x: ext.mul_sub(t3, t1, t4, y3),
            y: ext.mul_add(t1, z3, y3, t0),
            z: ext.mul_add(z3, t4, t0, t3),
        };
        let line = [
            ext.mul_sub(qx, y, qy, x),
            self.scale(ext.sub(qyz, y), self.x),
            self.scale(ext.sub(qxz, x), self.negated_y),
        ];
        (sum, line)
    }

    /// Returns the Miller function of `|z|` at the points, conjugated because `z` is negative.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run(self) -> Sextic<F::Element> {
        let ext = Ext(self.field);
        let tower = self.tower;
        let mut t = Projective {
            x: self.q.x,
            y: self.q.y,
            z: ext.constant(Fp2::ONE),
        };
        let mut f = tower.constant(Fp12::ONE);
        // The bits of |z| below the leading one. The first square of one is skipped.
        for bit in (0..63).rev() {
            if bit != 62 {
                f = tower.square(f);
            }
            let (doubled, line) = self.double(t);
            f = tower.mul_by_line(f, line);
            t = doubled;
            if (Z >> bit) & 1 == 1 {
                let (sum, line) = self.add(t);
                f = tower.mul_by_line(f, line);
                t = sum;
            }
        }
        tower.conjugate(f)
    }
}

/// The product of the Miller loops of prepared pairs.
///
/// Several pairs fill the lanes of a lane context when `PARALLEL` is set; one pair runs in the
/// residue number system.
#[derive(Clone, Copy)]
struct Miller<'a, const PARALLEL: bool>(&'a [Prepared]);

impl<const PARALLEL: bool> Workload<G1> for Miller<'_, PARALLEL> {
    type Output = Fp12;

    const PARALLEL: bool = PARALLEL;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<F: Arithmetic<Scalar = Fp>>(self, curve: &Curve<F>) -> Fp12 {
        let f = curve.field;
        let ext = Ext(f);
        let tower = Ext12::new(f);
        // Full chunks multiply lane-wise; the lanes of the product and of a final partial
        // chunk are folded together at the end.
        let mut lanewise: Option<Sextic<F::Element>> = None;
        let mut product = Fp12::ONE;
        for chunk in self.0.chunks(F::LANES) {
            let first = chunk[0];
            let mut px = [first.px; MAX_LANES];
            let mut py = [first.py; MAX_LANES];
            let mut qx = [first.qx; MAX_LANES];
            let mut qy = [first.qy; MAX_LANES];
            for (lane, pair) in chunk.iter().enumerate() {
                px[lane] = pair.px;
                py[lane] = pair.py;
                qx[lane] = pair.qx;
                qy[lane] = pair.qy;
            }
            let value = Loop::new(
                f,
                f.load(&px, first.px),
                f.load(&py, first.py),
                Affine {
                    x: ext.load(&qx, first.qx),
                    y: ext.load(&qy, first.qy),
                },
            )
            .run();
            if chunk.len() == F::LANES {
                lanewise = Some(match lanewise {
                    Some(acc) => tower.mul(acc, value),
                    None => value,
                });
            } else {
                let mut lanes = [Fp12::ONE; MAX_LANES];
                tower.store(value, &mut lanes);
                for lane in &lanes[..chunk.len()] {
                    product = product.mul(*lane);
                }
            }
        }
        if let Some(acc) = lanewise {
            let mut lanes = [Fp12::ONE; MAX_LANES];
            tower.store(acc, &mut lanes);
            for lane in &lanes[..F::LANES] {
                product = product.mul(*lane);
            }
        }
        product
    }
}

/// Returns `a^(z / 2)` for `a` in the cyclotomic subgroup.
#[cfg_attr(not(debug_assertions), inline(always))]
fn raise_to_half_z<F: Arithmetic<Scalar = Fp>>(
    tower: Ext12<F>,
    a: Sextic<F::Element>,
) -> Sextic<F::Element> {
    // Square and multiply over the bits of |z| / 2 below its leading one, then conjugate for
    // the sign of z.
    let mut result = a;
    for bit in (0..62).rev() {
        result = tower.cyclotomic_square(result);
        if (HALF_Z >> bit) & 1 == 1 {
            result = tower.mul(result, a);
        }
    }
    tower.conjugate(result)
}

/// Returns `a^z` for `a` in the cyclotomic subgroup.
#[cfg_attr(not(debug_assertions), inline(always))]
fn raise_to_z<F: Arithmetic<Scalar = Fp>>(
    tower: Ext12<F>,
    a: Sextic<F::Element>,
) -> Sextic<F::Element> {
    tower.cyclotomic_square(raise_to_half_z(tower, a))
}

/// Returns the Frobenius image `a^(p^n)`.
#[inline(always)]
fn frobenius_power<F: Arithmetic<Scalar = Fp>>(
    tower: Ext12<F>,
    mut a: Sextic<F::Element>,
    n: usize,
) -> Sextic<F::Element> {
    for _ in 0..n {
        a = tower.frobenius(a);
    }
    a
}

/// The final exponentiation of a nonzero element, by the chain of the zkcrypto `pairing` crate.
#[cfg_attr(not(debug_assertions), inline(always))]
fn final_exponentiation_chain<F: Arithmetic<Scalar = Fp>>(
    tower: Ext12<F>,
    f: Sextic<F::Element>,
) -> Sextic<F::Element> {
    // The easy part: f^((p^6 - 1) (p^2 + 1)) lies in the cyclotomic subgroup.
    let easy = tower.mul(tower.conjugate(f), tower.invert(f));
    let easy = tower.mul(frobenius_power(tower, easy, 2), easy);

    let y0 = tower.cyclotomic_square(easy);
    let y1 = raise_to_z(tower, y0);
    let y2 = raise_to_half_z(tower, y1);
    let y1 = tower.conjugate(tower.mul(y1, tower.conjugate(easy)));
    let y1 = tower.mul(y1, y2);
    let y2 = raise_to_z(tower, y1);
    let y3 = raise_to_z(tower, y2);
    let y3 = tower.mul(y3, tower.conjugate(y1));
    let y1 = frobenius_power(tower, y1, 3);
    let y2 = frobenius_power(tower, y2, 2);
    let y1 = tower.mul(y1, y2);
    let y2 = tower.mul(tower.mul(raise_to_z(tower, y3), y0), easy);
    let y1 = tower.mul(y1, y2);
    tower.mul(y1, frobenius_power(tower, y3, 1))
}

/// The final exponentiation of one element.
#[derive(Clone, Copy)]
struct FinalExponentiation(Fp12);

impl Workload<G1> for FinalExponentiation {
    type Output = Option<Fp12>;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<F: Arithmetic<Scalar = Fp>>(self, curve: &Curve<F>) -> Option<Fp12> {
        if bool::from(self.0.is_zero()) {
            return None;
        }
        let tower = Ext12::new(curve.field);
        let result = final_exponentiation_chain(tower, tower.load(&[self.0], Fp12::ONE));
        let mut output = [Fp12::ZERO];
        tower.store(result, &mut output);
        Some(output[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fp12::tests as fp12,
        g1::tests::{point as g1_point, to_blst as g1_to_blst},
        g2::tests::{point as g2_point, to_blst as g2_to_blst},
        group::tests::every_context,
        scalar::Scalar,
    };
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;

    /// Returns pseudo-random bytes derived from a seed.
    fn random_bytes(seed: u64) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
        (0..16384)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    /// Runs a check on a few fuzzer cases and on fixed pseudo-random inputs, which the
    /// fuzzer's early cases do not cover.
    fn check(test: impl Fn(&mut Unstructured<'_>) -> arbitrary::Result<()>) {
        minifuzz::Builder::default()
            .with_search_limit(4)
            .test(&test);
        for seed in 1..=3 {
            test(&mut Unstructured::new(&random_bytes(seed))).unwrap();
        }
    }

    /// Returns blst's pairing of two nonidentity points.
    fn blst_pairing(p: &G1, q: &G2) -> Gt {
        let mut p_affine = blst::blst_p1_affine::default();
        let mut q_affine = blst::blst_p2_affine::default();
        let mut miller = blst::blst_fp12::default();
        let mut out = blst::blst_fp12::default();
        // SAFETY: all pointers reference valid, initialized structures.
        unsafe {
            blst::blst_p1_to_affine(&mut p_affine, &g1_to_blst(p));
            blst::blst_p2_to_affine(&mut q_affine, &g2_to_blst(q));
            blst::blst_miller_loop(&mut miller, &q_affine, &p_affine);
            blst::blst_final_exp(&mut out, &miller);
        }
        Gt(fp12::from_blst(&out))
    }

    fn scalar(u: &mut Unstructured<'_>) -> arbitrary::Result<Scalar> {
        Ok(Scalar::from_bytes(&u.arbitrary()?).unwrap_or(Scalar::ONE))
    }

    #[test]
    fn pairing_matches_blst() {
        check(|u| {
            let (p, q) = (g1_point(u)?, g2_point(u)?);
            let expected = if bool::from(p.is_identity() | q.is_identity()) {
                Gt::ONE
            } else {
                blst_pairing(&p, &q)
            };
            assert_eq!(pairing(&p, &q), expected);
            assert_eq!(
                final_exponentiation(&miller_loop(&[(p, q)])),
                Some(expected)
            );
            Ok(())
        });
        let generators = pairing(&G1::GENERATOR, &G2::GENERATOR);
        assert_ne!(generators, Gt::ONE);
        assert_eq!(generators, blst_pairing(&G1::GENERATOR, &G2::GENERATOR));
    }

    #[test]
    fn final_exponentiation_matches_blst() {
        check(|u| {
            let f = fp12::element(u)?;
            let mut out = blst::blst_fp12::default();
            // SAFETY: both pointers reference valid field elements.
            unsafe { blst::blst_final_exp(&mut out, &fp12::to_blst(f)) };
            let expected = if f == Fp12::ZERO {
                None
            } else {
                Some(Gt(fp12::from_blst(&out)))
            };
            assert_eq!(final_exponentiation(&f), expected);
            Ok(())
        });
        assert_eq!(final_exponentiation(&Fp12::ZERO), None);
        assert_eq!(final_exponentiation(&Fp12::ONE), Some(Gt::ONE));
    }

    #[test]
    fn output_is_in_the_target_group() {
        let e = pairing(&G1::GENERATOR, &G2::GENERATOR);
        let mut inverse = blst::blst_fp12::default();
        let mut bytes = [0u8; BYTES];
        // SAFETY: valid pointers; the buffer holds a full encoding.
        unsafe {
            assert!(blst::blst_fp12_in_group(&fp12::to_blst(*e.as_fp12())));
            blst::blst_fp12_inverse(&mut inverse, &fp12::to_blst(*e.as_fp12()));
            blst::blst_bendian_from_fp12(bytes.as_mut_ptr(), &inverse);
        }
        assert_eq!(e.invert().to_bytes(), bytes);
        assert_eq!(e.mul(&e.invert()), Gt::ONE);
        assert!(bool::from(Gt::ONE.is_one()));
        assert!(!bool::from(e.is_one()));
    }

    #[test]
    fn identities_contribute_one() {
        let (p, q) = (G1::GENERATOR, G2::GENERATOR);
        let e = pairing(&p, &q);
        assert_eq!(pairing(&G1::IDENTITY, &q), Gt::ONE);
        assert_eq!(pairing(&p, &G2::IDENTITY), Gt::ONE);
        assert_eq!(pairing(&G1::IDENTITY, &G2::IDENTITY), Gt::ONE);
        assert_eq!(multi_pairing(&[]), Gt::ONE);
        assert!(pairing_check(&[]));
        assert_eq!(miller_loop(&[(G1::IDENTITY, q)]), Fp12::ONE);
        let mixed = [(G1::IDENTITY, q), (p, q), (p, G2::IDENTITY)];
        assert_eq!(multi_pairing(&mixed), e);
    }

    #[test]
    fn pairing_is_bilinear() {
        check(|u| {
            let (p, q) = (g1_point(u)?, g2_point(u)?);
            let (a, b) = (scalar(u)?, scalar(u)?);
            let e = pairing(&p, &q);
            // e(a p, b q) = e(ab p, q) = e(p, ab q) = e(b p, a q).
            let ab = a.mul(b);
            let expected = pairing(&p.mul(&ab), &q);
            assert_eq!(pairing(&p.mul(&a), &q.mul(&b)), expected);
            assert_eq!(pairing(&p, &q.mul(&ab)), expected);
            assert_eq!(pairing(&p.mul(&b), &q.mul(&a)), expected);
            // Additivity in each argument.
            let (p2, q2) = (g1_point(u)?, g2_point(u)?);
            assert_eq!(pairing(&p.add(&p2), &q), e.mul(&pairing(&p2, &q)));
            assert_eq!(pairing(&p, &q.add(&q2)), e.mul(&pairing(&p, &q2)));
            Ok(())
        });
    }

    #[test]
    fn multi_pairing_is_the_product() {
        check(|u| {
            let count = u.int_in_range(0..=10)?;
            let mut pairs = Vec::new();
            let mut expected = Gt::ONE;
            for _ in 0..count {
                let pair = (g1_point(u)?, g2_point(u)?);
                expected = expected.mul(&pairing(&pair.0, &pair.1));
                pairs.push(pair);
            }
            assert_eq!(multi_pairing(&pairs), expected);
            Ok(())
        });
    }

    #[test]
    fn pairing_check_accepts_exactly_valid_relations() {
        check(|u| {
            let (p, q) = (g1_point(u)?, g2_point(u)?);
            let a = scalar(u)?;
            // e(a p, q) e(-p, a q) = 1.
            assert!(pairing_check(&[(p.mul(&a), q), (p.neg(), q.mul(&a))]));
            let invalid = [(p.mul(&a), q), (p.neg(), q.mul(&a.add(Scalar::ONE)))];
            assert_eq!(
                pairing_check(&invalid),
                bool::from(p.is_identity() | q.is_identity())
            );
            Ok(())
        });
        let (p, q) = (
            G1::GENERATOR.double(),
            G2::GENERATOR.add(&G2::GENERATOR.double()),
        );
        assert!(pairing_check(&[(p, q), (p.neg(), q)]));
        assert!(!pairing_check(&[(p, q)]));
    }

    #[test]
    fn contexts_agree() {
        // Nine pairs fill one eight-lane chunk and leave a partial one.
        let pairs: Vec<(G1, G2)> = (1..=9)
            .map(|i| {
                let (a, b) = (Scalar::from_u64(i), Scalar::from_u64(i * i + 1));
                (G1::GENERATOR.mul(&a), G2::GENERATOR.mul(&b))
            })
            .collect();
        let expected = pairs
            .iter()
            .fold(Gt::ONE, |acc, (p, q)| acc.mul(&pairing(p, q)));
        let prepared = prepare(&pairs);
        assert_eq!(prepared.len(), 9);
        let product = every_context::<G1, _>(Miller::<true>(&prepared));
        assert_eq!(final_exponentiation(&product), Some(expected));
        let single = every_context::<G1, _>(Miller::<false>(&prepared[..1]));
        assert_eq!(
            final_exponentiation(&single),
            Some(pairing(&pairs[0].0, &pairs[0].1))
        );
        let exponentiated = every_context::<G1, _>(FinalExponentiation(product));
        assert_eq!(exponentiated.map(Gt), Some(expected));
    }
}
