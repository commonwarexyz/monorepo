//! Elliptic curve arithmetic on several points at once, one per vector lane.

use commonware_simd::Simd;

pub mod g1;
pub mod g2;

/// Projective points of one group, one per lane of a base field representation.
pub trait Points<S: Simd>: Copy {
    /// Canonical projective coordinates of one point.
    type Coordinates: Copy;

    /// Loads up to one point per lane, filling the remaining lanes with `fill`.
    fn load(simd: S, points: &[Self::Coordinates], fill: &Self::Coordinates) -> Self;

    /// Stores each lane's canonical coordinates, dropping lanes beyond `points`.
    fn store(self, simd: S, points: &mut [Self::Coordinates]);

    /// Returns `self + rhs`.
    fn add(self, simd: S, rhs: Self) -> Self;

    /// Returns `2 * self`.
    fn double(self, simd: S) -> Self;

    /// Returns `rhs` in every lane whose bit is set in `lanes`, and `self` in the others.
    fn select(self, simd: S, rhs: Self, lanes: u64) -> Self;

    /// Returns `-self`.
    fn negate(self, simd: S) -> Self;

    /// Returns `-self` in every lane whose bit is set in `lanes`, and `self` in the others.
    fn negate_lanes(self, simd: S, lanes: u64) -> Self;

    /// Returns the image of every lane under the group's endomorphism, which multiplies elements
    /// by the eigenvalue used to split scalars into components.
    fn endomorphism(self, simd: S) -> Self;

    /// One lane of a point in the representation's own form.
    type Raw: Copy + Default;

    /// Stores each lane in the representation's own form, dropping lanes beyond `points`, without
    /// any conversion.
    fn store_raw(self, simd: S, points: &mut [Self::Raw]);

    /// Loads lane `i` from `points[i]`, as [`Self::store_raw`] stored it, for at least one entry
    /// per lane, without any conversion.
    fn load_raw(simd: S, points: &[&Self::Raw]) -> Self;
}

/// Checks of the curve formulas against affine reference arithmetic over the coordinate field.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use crate::core::field::{
        arithmetic::Field,
        fp::testing::{Check, check_any},
    };
    use arbitrary::{Arbitrary, Unstructured};
    use core::{fmt::Debug, marker::PhantomData};
    use std::{format, vec::Vec};

    /// Largest number of points in a value, the widest representation's lane count.
    const MAX_LANES: usize = 16;

    /// Largest number of points added into each lane in one case.
    const MAX_ROUNDS: usize = 4;

    /// A curve `y^2 = x^3 + b`, with reference arithmetic over its coordinate field and the
    /// formulas under test.
    pub(crate) trait Curve {
        /// Name of the curve in failure messages.
        const NAME: &'static str;

        /// A canonical reference element of the coordinate field.
        type Element: Copy + PartialEq + Debug;

        /// The big-endian encoding of a coordinate.
        type Encoded: Copy;

        /// Zero.
        const ZERO: Self::Element;

        /// One.
        const ONE: Self::Element;

        /// The constant `b` of the curve equation.
        const B: Self::Element;

        /// The generator in projective coordinates, with `Z = 1`.
        const GENERATOR: [Self::Encoded; 3];

        /// The identity in projective coordinates.
        const IDENTITY: [Self::Encoded; 3];

        /// Projective points over the base field representation `F`.
        type Point<S: Simd, F: Field<S>>: Points<S, Coordinates = [Self::Encoded; 3]>;

        /// Returns `a + b`.
        fn add(a: Self::Element, b: Self::Element) -> Self::Element;

        /// Returns `a - b`.
        fn sub(a: Self::Element, b: Self::Element) -> Self::Element;

        /// Returns `a * b`.
        fn mul(a: Self::Element, b: Self::Element) -> Self::Element;

        /// Returns the inverse of a nonzero `a`.
        fn invert(a: Self::Element) -> Self::Element;

        /// Returns the canonical encoding of `a`.
        fn encode(a: Self::Element) -> Self::Encoded;

        /// Returns the element an encoding represents.
        fn decode(bytes: &Self::Encoded) -> Self::Element;

        /// Draws an arbitrary element.
        fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self::Element>;

        /// Returns the same points with every coordinate near the largest integer bound the
        /// formulas accept.
        fn widen<S: Simd, F: Field<S>>(simd: S, point: Self::Point<S, F>) -> Self::Point<S, F>;

        /// Checks, in debug builds, that every coordinate satisfies the coordinate bounds.
        fn check_bound<S: Simd, F: Field<S>>(
            simd: S,
            point: Self::Point<S, F>,
        ) -> Self::Point<S, F>;
    }

    /// An affine point, or `None` for the identity.
    type Affine<C> = Option<(<C as Curve>::Element, <C as Curve>::Element)>;

    /// Returns the generator in affine coordinates.
    fn generator<C: Curve>() -> Affine<C> {
        let [x, y, z] = C::GENERATOR.map(|bytes| C::decode(&bytes));
        assert!(z == C::ONE, "{} generator has Z = 1", C::NAME);
        Some((x, y))
    }

    /// Returns whether an affine point satisfies the curve equation.
    fn on_curve<C: Curve>(point: Affine<C>) -> bool {
        point.is_none_or(|(x, y)| C::mul(y, y) == C::add(C::mul(x, C::mul(x, x)), C::B))
    }

    /// Returns `-p`.
    fn affine_neg<C: Curve>(p: Affine<C>) -> Affine<C> {
        p.map(|(x, y)| (x, C::sub(C::ZERO, y)))
    }

    /// Returns `p + q` with the affine chord-and-tangent formulas.
    fn affine_add<C: Curve>(p: Affine<C>, q: Affine<C>) -> Affine<C> {
        let (Some((x1, y1)), Some((x2, y2))) = (p, q) else {
            return p.or(q);
        };
        let slope = if x1 == x2 {
            if C::add(y1, y2) == C::ZERO {
                return None;
            }
            let xx = C::mul(x1, x1);
            C::mul(C::add(C::add(xx, xx), xx), C::invert(C::add(y1, y1)))
        } else {
            C::mul(C::sub(y2, y1), C::invert(C::sub(x2, x1)))
        };
        let x3 = C::sub(C::sub(C::mul(slope, slope), x1), x2);
        let y3 = C::sub(C::mul(slope, C::sub(x1, x3)), y1);
        Some((x3, y3))
    }

    /// Returns projective coordinates of an affine point, scaled by a nonzero `z`.
    fn coordinates<C: Curve>(point: Affine<C>, z: C::Element) -> [C::Encoded; 3] {
        match point {
            Some((x, y)) => [C::mul(x, z), C::mul(y, z), z].map(C::encode),
            None => [C::ZERO, z, C::ZERO].map(C::encode),
        }
    }

    /// Returns the affine point of projective coordinates, asserting that they are a point of
    /// the curve.
    fn affine<C: Curve>(coordinates: &[C::Encoded; 3], label: &str) -> Affine<C> {
        let [x, y, z] = coordinates.map(|bytes| C::decode(&bytes));
        if z == C::ZERO {
            assert!(
                x == C::ZERO && y != C::ZERO,
                "{} {label}: Z = 0 but not the identity",
                C::NAME
            );
            return None;
        }
        let inverse = C::invert(z);
        let point = Some((C::mul(x, inverse), C::mul(y, inverse)));
        assert!(
            on_curve::<C>(point),
            "{} {label}: not on the curve",
            C::NAME
        );
        point
    }

    /// Asserts that projective coordinates represent an expected affine point.
    fn assert_point<C: Curve>(coordinates: &[C::Encoded; 3], expected: Affine<C>, label: &str) {
        let [x, y, z] = coordinates.map(|bytes| C::decode(&bytes));
        let matches = match expected {
            None => x == C::ZERO && y != C::ZERO && z == C::ZERO,
            Some((ex, ey)) => z != C::ZERO && x == C::mul(ex, z) && y == C::mul(ey, z),
        };
        assert!(matches, "{} {label}: expected {expected:?}", C::NAME);
    }

    /// Draws a projective scaling: an arbitrary nonzero element, or one.
    fn scaling<C: Curve>(u: &mut Unstructured<'_>) -> arbitrary::Result<C::Element> {
        let z = C::arbitrary(u)?;
        Ok(if z == C::ZERO { C::ONE } else { z })
    }

    /// The point added into a lane in one round.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    enum Addend {
        /// The lane's running multiple of the generator.
        Multiple,
        /// The negation of the running multiple.
        NegatedMultiple,
        /// The lane's current sum, so that the addition doubles.
        Sum,
        /// The negation of the lane's current sum, so that the addition cancels.
        NegatedSum,
        /// The identity.
        Identity,
    }

    /// How a lane's running multiple changes after a round.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    enum Advance {
        /// Adds the generator.
        AddGenerator,
        /// Doubles the multiple.
        Double,
        /// Keeps the multiple, so that the next round may repeat it.
        Keep,
    }

    /// The composite operation that follows each addition.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    enum Step {
        /// Replaces `s` with `s + s + 2 (2 s)`, adding equal points and chaining doublings.
        Chain,
        /// Round-trips `s` through canonical coordinates, optionally widening them on load.
        Bytes {
            /// Whether to widen the loaded coordinates.
            widen: bool,
        },
        /// Replaces `s` with `-s + 2 s` and round-trips it through raw coordinates.
        Raw,
        /// Selects the addend in the lanes of `select`, then negates the lanes of `negate`.
        Lanes {
            /// Lanes that take the addend.
            select: u64,
            /// Lanes that are negated.
            negate: u64,
        },
        /// Checks that the endomorphism maps `s`, the addend `a`, and `s + a` onto the curve,
        /// moves every point other than the identity, and maps `s + a` to the sum of the
        /// other two images.
        Endomorphism,
    }

    /// Adds random multiples of the generator into every lane through a chain of formulas,
    /// checking the results against the reference.
    ///
    /// Exhausted input fills every lane and runs the most rounds.
    fn formulas<C: Curve, S: Simd, F: Field<S>>(
        simd: S,
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        const { assert!(F::LANES <= MAX_LANES) };
        let lanes = F::LANES;
        let used = lanes - u.int_in_range(0..=lanes - 1)?;
        let rounds = MAX_ROUNDS - u.int_in_range(0..=MAX_ROUNDS - 1)?;
        let generator = generator::<C>();
        let mut multiples = [generator; MAX_LANES];
        let mut sums: [Affine<C>; MAX_LANES] = [None; MAX_LANES];
        let mut sum = C::Point::<S, F>::load(simd, &[], &C::IDENTITY);
        for round in 0..rounds {
            // Lanes beyond `used` load the identity.
            let mut addends: [Affine<C>; MAX_LANES] = [None; MAX_LANES];
            let mut inputs = Vec::with_capacity(used);
            for lane in 0..used {
                let addend = match u.arbitrary()? {
                    Addend::Multiple => multiples[lane],
                    Addend::NegatedMultiple => affine_neg::<C>(multiples[lane]),
                    Addend::Sum => sums[lane],
                    Addend::NegatedSum => affine_neg::<C>(sums[lane]),
                    Addend::Identity => None,
                };
                inputs.push(coordinates::<C>(addend, scaling::<C>(u)?));
                addends[lane] = addend;
                multiples[lane] = match u.arbitrary()? {
                    Advance::AddGenerator => affine_add::<C>(multiples[lane], generator),
                    Advance::Double => affine_add::<C>(multiples[lane], multiples[lane]),
                    Advance::Keep => multiples[lane],
                };
            }
            let mut addend = C::Point::<S, F>::load(simd, &inputs, &C::IDENTITY);
            if !u.arbitrary::<bool>()? {
                addend = C::widen(simd, addend);
            }
            sum = C::check_bound(simd, sum.add(simd, addend));
            for (sum, addend) in sums.iter_mut().zip(addends) {
                *sum = affine_add::<C>(*sum, addend);
            }
            let mut stored = [C::IDENTITY; MAX_LANES];
            match u.arbitrary()? {
                Step::Chain => {
                    let double = C::check_bound(simd, sum.double(simd));
                    let quadruple = C::check_bound(simd, double.double(simd));
                    let double = C::check_bound(simd, sum.add(simd, sum));
                    sum = C::check_bound(simd, double.add(simd, quadruple));
                    for sum in &mut sums {
                        let double = affine_add::<C>(*sum, *sum);
                        *sum = affine_add::<C>(double, affine_add::<C>(double, double));
                    }
                }
                Step::Bytes { widen } => {
                    sum.store(simd, &mut stored);
                    sum = C::Point::<S, F>::load(simd, &stored, &C::IDENTITY);
                    if widen {
                        sum = C::widen(simd, sum);
                    }
                }
                Step::Raw => {
                    let negated = C::check_bound(simd, sum.negate(simd));
                    sum = C::check_bound(simd, negated.add(simd, sum.double(simd)));
                    let mut raw: [<C::Point<S, F> as Points<S>>::Raw; MAX_LANES] =
                        [Default::default(); MAX_LANES];
                    sum.store_raw(simd, &mut raw);
                    let raw: Vec<_> = raw.iter().collect();
                    sum = C::Point::<S, F>::load_raw(simd, &raw);
                }
                Step::Lanes { select, negate } => {
                    sum = sum.select(simd, addend, select);
                    sum = C::check_bound(simd, sum.negate_lanes(simd, negate));
                    for (lane, sum) in sums.iter_mut().enumerate().take(lanes) {
                        if (select >> lane) & 1 == 1 {
                            *sum = addends[lane];
                        }
                        if (negate >> lane) & 1 == 1 {
                            *sum = affine_neg::<C>(*sum);
                        }
                    }
                }
                Step::Endomorphism => {
                    let total = sum.add(simd, addend);
                    let images = [sum, addend, total]
                        .map(|point| C::check_bound(simd, point.endomorphism(simd)));
                    let combined = C::check_bound(simd, images[0].add(simd, images[1]));
                    combined.store(simd, &mut stored);
                    let images = images.map(|image| {
                        let mut stored = [C::IDENTITY; MAX_LANES];
                        image.store(simd, &mut stored);
                        stored
                    });
                    for lane in 0..lanes {
                        let label = |what: &str| format!("round {round}, lane {lane}: {what}");
                        let points = [
                            sums[lane],
                            addends[lane],
                            affine_add::<C>(sums[lane], addends[lane]),
                        ];
                        let mut mapped = [None; 3];
                        for (k, (image, point)) in images.iter().zip(points).enumerate() {
                            let image = affine::<C>(&image[lane], &label("endomorphism image"));
                            let fixed = match point {
                                None => image.is_none(),
                                Some(_) => {
                                    image.is_some()
                                        && image != point
                                        && image != affine_neg::<C>(point)
                                }
                            };
                            assert!(
                                fixed,
                                "{} {}",
                                C::NAME,
                                label("endomorphism fixes only the identity, up to sign")
                            );
                            mapped[k] = image;
                        }
                        assert_point::<C>(
                            &stored[lane],
                            mapped[2],
                            &label("endomorphism is compatible with addition"),
                        );
                    }
                }
            }
        }
        let mut stored = [C::IDENTITY; MAX_LANES];
        sum.store(simd, &mut stored);
        let mut doubled = [C::IDENTITY; MAX_LANES];
        C::check_bound(simd, sum.double(simd)).store(simd, &mut doubled);
        for lane in 0..lanes {
            assert_point::<C>(
                &stored[lane],
                sums[lane],
                &format!("sum, lane {lane} of {used}"),
            );
            assert_point::<C>(
                &doubled[lane],
                affine_add::<C>(sums[lane], sums[lane]),
                &format!("double, lane {lane} of {used}"),
            );
        }
        Ok(())
    }

    /// Runs [`formulas`] on a curve in any representation.
    struct Formulas<C>(PhantomData<C>);

    impl<C> Clone for Formulas<C> {
        fn clone(&self) -> Self {
            *self
        }
    }

    impl<C> Copy for Formulas<C> {}

    impl<C: Curve> Check for Formulas<C> {
        fn check<S: Simd, F: Field<S>>(
            self,
            simd: S,
            u: &mut Unstructured<'_>,
        ) -> arbitrary::Result<()> {
            simd.execute(
                #[inline(always)]
                |simd: S| formulas::<C, S, F>(simd, u),
            )
        }
    }

    /// Runs [`formulas`] in a representation and on an emulated backend drawn from the input.
    fn run<C: Curve>(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        check_any(u, Formulas::<C>(PhantomData))
    }

    /// A check of one curve's formulas.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    pub enum Plan {
        /// Checks G1 addition, doubling, negation, lane selection, conversions, coordinate
        /// bounds, and the endomorphism against the reference, in a drawn representation and
        /// backend.
        G1,
        /// Checks G2 addition, doubling, negation, lane selection, conversions, coordinate
        /// bounds, and the endomorphism against the reference, in a drawn representation and
        /// backend.
        G2,
    }

    impl Plan {
        /// Runs the operation using the remaining input.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::G1 => run::<g1::fuzz::G1>(u),
                Self::G2 => run::<g2::fuzz::G2>(u),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use commonware_invariants::minifuzz;

        #[test]
        fn minifuzz_g1() {
            minifuzz::test(|u| Plan::G1.run(u));
        }

        #[test]
        fn minifuzz_g2() {
            minifuzz::test(|u| Plan::G2.run(u));
        }

        #[test]
        fn generators_are_on_curve() {
            assert!(on_curve::<g1::fuzz::G1>(generator::<g1::fuzz::G1>()), "G1");
            assert!(on_curve::<g2::fuzz::G2>(generator::<g2::fuzz::G2>()), "G2");
        }
    }
}
