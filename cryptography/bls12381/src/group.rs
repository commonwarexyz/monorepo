//! Groups of BLS12-381 and their scalar field, through the `commonware-math` algebra traits, and
//! the pairing into the target group [`GT`].
//!
//! [`G1`] and [`G2`] hold canonical projective coordinates. Each operation runs as one SIMD
//! kernel on the best available backend. Operations over slices of elements ([`G1::sum`],
//! [`G1::mul_each`], [`Space::msm`](commonware_math::algebra::Space::msm), and
//! [`pairings`]) hold one element per lane, so they fill every lane and amortize the
//! conversions at the kernel boundary that single operations pay every time.
//!
//! Multiplications by scalars run in constant time, except
//! [`Space::msm`](commonware_math::algebra::Space::msm), which runs in variable time because its
//! scalars are public in every intended use (Lagrange coefficients in threshold recovery and
//! random weights in batch verification).
//!
//! Elements arise only from the generators through the group operations, so every element lies
//! in the subgroup of prime order `r`.

mod g1;
mod g2;
mod kernel;
mod pairing;
mod scalar;

use core::num::NonZeroUsize;
pub use g1::G1;
pub use g2::G2;
pub use pairing::{GT, multi_pairing, pairing, pairings};
pub use scalar::Scalar;

/// Fewest elements of [`Space::msm`](commonware_math::algebra::Space::msm) that a parallel
/// strategy gives one kernel. Every kernel pays for its own bucket sums and doublings, which
/// cost about as much as adding a few hundred elements.
const MSM_BATCH: NonZeroUsize = NonZeroUsize::new(256).unwrap();

/// Decodes a hexadecimal string at compile time.
const fn hex<const N: usize>(digits: &str) -> [u8; N] {
    const fn nibble(digit: u8) -> u8 {
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            _ => panic!("invalid hexadecimal digit"),
        }
    }
    let digits = digits.as_bytes();
    assert!(digits.len() == 2 * N);
    let mut bytes = [0; N];
    let mut i = 0;
    while i < N {
        bytes[i] = (nibble(digits[2 * i]) << 4) | nibble(digits[2 * i + 1]);
        i += 1;
    }
    bytes
}

/// Formats bytes as hexadecimal.
struct Hex<'a>(&'a [u8]);

impl ::core::fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.write_str("0x")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Implements the operators and the `commonware-math` group traits for a [`kernel::Group`] whose
/// module defines its `GENERATOR` coordinates.
macro_rules! group_traits {
    ($group:ident) => {
        impl ::core::fmt::Debug for $group {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                let [x, y, z] = &self.0;
                f.debug_struct(stringify!($group))
                    .field("x", &$crate::group::Hex(x.as_slice()))
                    .field("y", &$crate::group::Hex(y.as_slice()))
                    .field("z", &$crate::group::Hex(z.as_slice()))
                    .finish()
            }
        }

        impl PartialEq for $group {
            fn eq(&self, other: &Self) -> bool {
                use $crate::group::kernel::{Add, Group, dispatch};
                dispatch(Add(*self, other.negate())).is_identity()
            }
        }

        impl Eq for $group {}

        impl commonware_math::algebra::Object for $group {}

        impl<'a> ::core::ops::AddAssign<&'a Self> for $group {
            fn add_assign(&mut self, rhs: &'a Self) {
                *self = $crate::group::kernel::dispatch($crate::group::kernel::Add(*self, *rhs));
            }
        }

        impl<'a> ::core::ops::Add<&'a Self> for $group {
            type Output = Self;

            fn add(mut self, rhs: &'a Self) -> Self {
                self += rhs;
                self
            }
        }

        impl<'a> ::core::ops::SubAssign<&'a Self> for $group {
            fn sub_assign(&mut self, rhs: &'a Self) {
                *self += &$crate::group::kernel::Group::negate(rhs);
            }
        }

        impl<'a> ::core::ops::Sub<&'a Self> for $group {
            type Output = Self;

            fn sub(mut self, rhs: &'a Self) -> Self {
                self -= rhs;
                self
            }
        }

        impl ::core::ops::Neg for $group {
            type Output = Self;

            fn neg(self) -> Self {
                $crate::group::kernel::Group::negate(&self)
            }
        }

        impl commonware_math::algebra::Additive for $group {
            fn zero() -> Self {
                Self(<Self as $crate::group::kernel::Group>::IDENTITY)
            }

            fn double(&mut self) {
                *self = $crate::group::kernel::dispatch($crate::group::kernel::Double(*self));
            }

            /// Multiplies by an integer of any length without branching on its value.
            fn scale(&self, bits_le: &[u64]) -> Self {
                $crate::group::kernel::dispatch($crate::group::kernel::Multiply {
                    element: *self,
                    scalar: $crate::group::Scalar::from_words_wide(bits_le),
                })
            }
        }

        impl<'a> ::core::ops::MulAssign<&'a $crate::group::Scalar> for $group {
            fn mul_assign(&mut self, rhs: &'a $crate::group::Scalar) {
                *self = $crate::group::kernel::dispatch($crate::group::kernel::Multiply {
                    element: *self,
                    scalar: *rhs,
                });
            }
        }

        impl<'a> ::core::ops::Mul<&'a $crate::group::Scalar> for $group {
            type Output = Self;

            fn mul(mut self, rhs: &'a $crate::group::Scalar) -> Self {
                self *= rhs;
                self
            }
        }

        impl commonware_math::algebra::Space<$crate::group::Scalar> for $group {
            /// Returns the sum of the points times their scalars, in variable time.
            ///
            /// The scalars must be public, as Lagrange coefficients and batch-verification
            /// weights are: the running time and memory accesses depend on them. A sequential
            /// strategy runs one kernel over all points, and a parallel one splits them into
            /// batches of at least 256 points.
            fn msm(
                points: &[Self],
                scalars: &[$crate::group::Scalar],
                strategy: &impl commonware_parallel::Strategy,
            ) -> Self {
                let count = points.len().min(scalars.len());
                let (points, scalars) = (&points[..count], &scalars[..count]);
                strategy.run_batches(count, $crate::group::MSM_BATCH, 1, |batches| {
                    batches
                        .map_collect_vec(
                            |ranges| ranges,
                            |range| {
                                $crate::group::kernel::dispatch($crate::group::kernel::Msm {
                                    elements: &points[range.clone()],
                                    scalars: &scalars[range],
                                    plan: None,
                                })
                            },
                        )
                        .iter()
                        .fold(
                            <Self as commonware_math::algebra::Additive>::zero(),
                            |sum, batch| sum + batch,
                        )
                })
            }
        }

        impl commonware_math::algebra::CryptoGroup for $group {
            type Scalar = $crate::group::Scalar;

            fn generator() -> Self {
                Self(GENERATOR)
            }
        }

        impl $group {
            /// Returns the sum of the elements, as when aggregating keys or signatures.
            ///
            /// Adds one element per lane, so it costs far less than adding them one at a time.
            pub fn sum(elements: &[Self]) -> Self {
                $crate::group::kernel::dispatch($crate::group::kernel::Sum(elements))
            }

            /// Multiplies each element by the scalar at the same index, in place, without
            /// branching on the scalars.
            ///
            /// Multiplies one element per lane. Elements beyond the scalars are unchanged, and
            /// scalars beyond the elements are ignored.
            pub fn mul_each(elements: &mut [Self], scalars: &[$crate::group::Scalar]) {
                $crate::group::kernel::dispatch($crate::group::kernel::MultiplyEach {
                    elements,
                    scalars,
                });
            }
        }
    };
}

use group_traits;

/// Checks shared by both groups.
#[cfg(test)]
mod tests {
    use super::{
        MSM_BATCH, Scalar,
        kernel::{
            Group, Kernel, MAX_LANES, Msm, Multiply, MultiplyEach, Plan, Points, Sum, dispatch,
        },
    };
    use crate::core::field::{
        arithmetic::Field,
        fp::{rns::Rns, unsat28::Unsat28, unsat49::Unsat49},
    };
    use commonware_math::algebra::{CryptoGroup, Random};
    use commonware_parallel::{
        Sequential,
        mocks::{Explorer, pooled},
    };
    use commonware_simd::{Operation, Simd, X86V4C, check_consistent};
    use commonware_utils::{NZUsize, test_rng};
    use std::{fmt::Debug, vec, vec::Vec};

    /// Elements of a slice operation, more than the lanes of the widest representation.
    const SLICE: usize = 2 * MAX_LANES + 3;

    /// Returns the first `count` positive multiples of the generator and distinct scalars.
    fn multiples<G: CryptoGroup<Scalar = Scalar>>(count: usize) -> (Vec<G>, Vec<Scalar>) {
        let generator = G::generator();
        let mut scalar = Scalar::from_u64(3);
        let mut scalars = Vec::with_capacity(count);
        let mut points = Vec::with_capacity(count);
        let mut point = G::zero();
        for i in 0..count {
            scalar = scalar * &scalar + &Scalar::from_u64(i as u64);
            scalars.push(scalar);
            // The point is (i + 1) times the generator.
            point += &generator;
            points.push(point.clone());
        }
        (points, scalars)
    }

    /// Returns scalars that cover zero, one, `r - 1`, and full-width values.
    fn scalars() -> Vec<Scalar> {
        let mut scalars = vec![
            Scalar::ZERO,
            Scalar::ONE,
            -Scalar::ONE,
            Scalar::from_u64(2),
            Scalar::from_u64(0xdead_beef),
        ];
        let mut value = Scalar::from_u64(7);
        for _ in 0..3 {
            value = value * &value + &Scalar::ONE;
            scalars.push(value);
        }
        scalars
    }

    /// Checks the group operations against `reference`, which returns a multiple of the generator.
    pub fn check_operations<G: CryptoGroup<Scalar = Scalar>>(reference: impl Fn(&Scalar) -> G) {
        let generator = G::generator();
        assert_eq!(generator, reference(&Scalar::ONE));
        assert_eq!(G::zero(), reference(&Scalar::ZERO));
        let scalars = scalars();
        for a in &scalars {
            let p = generator.clone() * a;
            assert_eq!(p, reference(a));
            assert_eq!(generator.scale(&a.to_words()), p);
            assert_eq!(-p.clone(), reference(&-*a));
            let mut doubled = p.clone();
            doubled.double();
            assert_eq!(doubled, reference(&(*a + a)));
            assert_eq!(G::zero() + &p, p);
            assert_eq!(p.clone() - &p, G::zero());
            for b in &scalars[..4] {
                let q = reference(b);
                assert_eq!(p.clone() + &q, reference(&(*a + b)));
                assert_eq!(p.clone() - &q, reference(&(*a - b)));
                assert_eq!(p == q, a == b);
            }
        }
        // Integers of any length, reduced modulo the order.
        let a = scalars[6];
        let mut words = [0; 9];
        words[..4].copy_from_slice(&a.to_words());
        words[8] = 5;
        let expected = reference(&Scalar::from_words_wide(&words));
        assert_eq!(generator.scale(&words), expected);
        assert_eq!(generator.scale(&[]), G::zero());
    }

    /// Applies the endomorphism to an element.
    #[derive(Clone, Copy)]
    struct Endomorphism<G>(G);

    impl<G: Group> Kernel for Endomorphism<G> {
        type Output = G;

        fn run<S: Simd, F: Field<S>>(self, simd: S) -> G {
            let mut output = [G::IDENTITY];
            G::Points::<S, F>::load(simd, &[], self.0.coordinates())
                .endomorphism(simd)
                .store(simd, &mut output);
            G::from_coordinates(output[0])
        }
    }

    /// Checks that the endomorphism multiplies by `eigenvalue` in every representation, and that
    /// the components of a scalar, weighted by the powers of the negated eigenvalue, reconstruct
    /// it.
    pub fn check_endomorphism<G: CryptoGroup<Scalar = Scalar> + Group + Debug>(eigenvalue: Scalar) {
        let generator = G::generator();
        let mut scalars = scalars();
        let mut rng = test_rng();
        scalars.extend((0..16).map(|_| Scalar::random(&mut rng)));
        let bound = 1u128.checked_shl(G::COMPONENT_BITS - 1);
        for scalar in scalars {
            let element = generator * &scalar;
            assert_eq!(dispatch(Endomorphism(element)), element * &eigenvalue);
            check_consistent(|| Representations(Endomorphism(element)));

            let components = G::components(&scalar);
            let mut sum = Scalar::ZERO;
            let mut power = Scalar::ONE;
            for (c, component) in components.into_iter().enumerate() {
                assert!(bound.is_none_or(|bound| component < bound));
                assert!(c < G::COMPONENTS || component == 0);
                let component =
                    Scalar::from_words([component as u64, (component >> 64) as u64, 0, 0]).unwrap();
                sum += &(component * &power);
                power *= &-eigenvalue;
            }
            assert_eq!(sum, scalar);
        }
        assert_eq!(dispatch(Endomorphism(G::zero())), G::zero());
    }

    /// Returns `count` elements of a multi-scalar multiplication with their discrete logarithms:
    /// positive multiples of the generator, with identities and repeated elements.
    fn msm_elements<G: CryptoGroup<Scalar = Scalar>>(count: usize) -> (Vec<G>, Vec<u64>) {
        let (mut elements, _) = multiples::<G>(count);
        let mut logarithms: Vec<u64> = (1..=count as u64).collect();
        for i in (3..count).step_by(10) {
            elements[i] = G::zero();
            logarithms[i] = 0;
        }
        for i in (9..count).step_by(10) {
            elements[i] = elements[i - 5].clone();
            logarithms[i] = logarithms[i - 5];
        }
        (elements, logarithms)
    }

    /// Returns `count` scalars of a multi-scalar multiplication: every third is zero, one, `r - 1`,
    /// or has mostly zero digits or digits that carry through every window, and the rest are
    /// full-width values.
    fn msm_scalars(count: usize) -> Vec<Scalar> {
        let mut patterns = scalars();
        patterns.push(Scalar::from_u64(1 << 40));
        patterns.push(Scalar::from_words([0, 0, 0, 1 << 62]).unwrap());
        patterns.push(Scalar::from_words([0, 0, 0, 1 << 8]).unwrap() - &Scalar::ONE);
        patterns.push(Scalar::from_words([u64::MAX, 0, u64::MAX, 0]).unwrap());
        let mut value = Scalar::from_u64(11);
        (0..count)
            .map(|i| {
                if i % 3 == 0 {
                    patterns[(i / 3) % patterns.len()]
                } else {
                    value = value * &value + &Scalar::from_u64(i as u64);
                    value
                }
            })
            .collect()
    }

    /// Returns the sum of the elements with discrete logarithms `logarithms` times `scalars`.
    fn msm_expected<G: CryptoGroup<Scalar = Scalar>>(logarithms: &[u64], scalars: &[Scalar]) -> G {
        let exponent = logarithms
            .iter()
            .zip(scalars)
            .fold(Scalar::ZERO, |sum, (logarithm, scalar)| {
                sum + &(Scalar::from_u64(*logarithm) * scalar)
            });
        G::generator() * &exponent
    }

    /// Checks [`Space::msm`] against a sum of multiplications, across lane boundaries, the
    /// crossover between methods, every window width, and parallel batches.
    pub fn check_msm<G: CryptoGroup<Scalar = Scalar> + Group>() {
        let count = 2 * MSM_BATCH.get() + 5;
        let (elements, logarithms) = msm_elements::<G>(count);
        let scalars = msm_scalars(count);

        // A sum of individual multiplications.
        let products = elements[..12]
            .iter()
            .zip(&scalars)
            .fold(G::zero(), |sum, (element, scalar)| {
                sum + &(*element * scalar)
            });
        assert_eq!(
            G::msm(&elements[..12], &scalars[..12], &Sequential),
            products
        );

        // Sizes around every lane count and around the crossover from Straus's method to
        // Pippenger's for each lane count.
        let mut sizes = vec![0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 33];
        for lanes in [1, 4, 8, 16] {
            let crossover = (1..count)
                .find(|&n| matches!(Plan::choose::<G>(n, lanes), Plan::Pippenger(_)))
                .unwrap();
            sizes.extend([crossover - 1, crossover]);
        }
        for n in sizes {
            assert_eq!(
                G::msm(&elements[..n], &scalars[..n], &Sequential),
                msm_expected::<G>(&logarithms[..n], &scalars[..n]),
                "n={n}"
            );
        }

        // The window widths of both methods up to eight bits, with and without splitting the
        // scalars; wider ones only add buckets.
        let n = 37;
        let expected = msm_expected::<G>(&logarithms[..n], &scalars[..n]);
        let plans = (2..=8)
            .flat_map(|width| [false, true].map(|split| Plan::Straus { width, split }))
            .chain((2..=8).map(Plan::Pippenger));
        for plan in plans {
            let msm = Msm {
                elements: &elements[..n],
                scalars: &scalars[..n],
                plan: Some(plan),
            };
            assert_eq!(dispatch(msm), expected, "{plan:?}");
        }

        // Batches split across threads.
        let strategy = Explorer::parallel(&pooled(NZUsize!(2), NZUsize!(3)));
        assert_eq!(
            G::msm(&elements, &scalars, &strategy),
            msm_expected::<G>(&logarithms, &scalars)
        );

        // The longer input is truncated.
        assert_eq!(
            G::msm(&elements[..3], &scalars[..5], &Sequential),
            G::msm(&elements[..3], &scalars[..3], &Sequential)
        );
        assert_eq!(
            G::msm(&elements[..5], &scalars[..3], &Sequential),
            G::msm(&elements[..3], &scalars[..3], &Sequential)
        );
    }

    /// Checks a sum of a slice against one addition at a time, across lane boundaries.
    pub fn check_sum<G: CryptoGroup<Scalar = Scalar>>(sum: impl Fn(&[G]) -> G) {
        let (points, _) = multiples::<G>(SLICE);
        for count in [0, 1, 5, SLICE] {
            // The sum of the first count positive multiples.
            let expected = G::generator() * &Scalar::from_u64((count * (count + 1) / 2) as u64);
            assert_eq!(sum(&points[..count]), expected);
        }
        let mut with_identities = points.clone();
        with_identities[1] = G::zero();
        with_identities[SLICE - 1] = G::zero();
        assert_eq!(
            sum(&with_identities),
            sum(&points) - &points[1] - &points[SLICE - 1]
        );
    }

    /// Checks multiplying a slice against one multiplication at a time, across lane boundaries.
    pub fn check_mul_each<G: CryptoGroup<Scalar = Scalar>>(mul_each: impl Fn(&mut [G], &[Scalar])) {
        let (points, scalars) = multiples::<G>(SLICE);
        for count in [0, 1, 5, SLICE] {
            let mut products = points.clone();
            mul_each(&mut products[..count], &scalars);
            for (i, (product, point)) in products.iter().zip(&points).enumerate() {
                let expected = if i < count {
                    point.clone() * &scalars[i]
                } else {
                    point.clone()
                };
                assert_eq!(*product, expected);
            }
        }
        // The longer input is truncated.
        let mut products = points.clone();
        mul_each(&mut products, &scalars[..3]);
        for (i, (product, point)) in products.iter().zip(&points).enumerate() {
            let expected = if i < 3 {
                point.clone() * &scalars[i]
            } else {
                point.clone()
            };
            assert_eq!(*product, expected);
        }
        let mut products = points;
        products[2] = G::zero();
        mul_each(&mut products, &scalars);
        assert_eq!(products[2], G::zero());
    }

    /// Runs a kernel in every representation, checking that they compute the same element.
    ///
    /// Representations with different lane counts may sum in different orders, which changes the
    /// projective coordinates but not the element.
    struct Representations<K>(K);

    impl<S: Simd, G: Group + PartialEq + Debug, K: Kernel<Output = G> + Copy> Operation<S>
        for Representations<K>
    {
        type Output = G;

        fn portable(self, simd: S) -> G {
            simd.execute(|simd: S| {
                let expected = self.0.run::<S, Unsat49<S>>(simd);
                assert_eq!(self.0.run::<S, Unsat28<S>>(simd), expected);
                expected
            })
        }

        // Residues require x86v4c.
        fn x86_v4c(self, simd: S) -> G
        where
            S: X86V4C,
        {
            let kernel = self.0;
            let expected = self.portable(simd);
            simd.execute(|simd: S| assert_eq!(kernel.run::<S, Rns<S>>(simd), expected));
            expected
        }
    }

    /// Checks that every representation and backend computes the same coordinates.
    pub fn check_representations<G: CryptoGroup<Scalar = Scalar> + Group>() {
        let generator = G::generator();
        let scalars = scalars();
        let elements: Vec<G> = scalars.iter().map(|scalar| generator * scalar).collect();
        let plans = [
            Plan::Straus {
                width: 5,
                split: false,
            },
            Plan::Straus {
                width: 4,
                split: true,
            },
            Plan::Pippenger(3),
        ];
        for plan in plans {
            check_consistent(|| {
                Representations(Msm {
                    elements: &elements,
                    scalars: &scalars,
                    plan: Some(plan),
                })
            });
        }
        check_consistent(|| Representations(Sum(&elements)));
        check_consistent(|| {
            Representations(Multiply {
                element: elements[6],
                scalar: scalars[5],
            })
        });
        check_consistent(|| EachRepresentations(&elements, &scalars));
    }

    /// Runs [`MultiplyEach`] in every representation, checking that they compute the same
    /// elements.
    struct EachRepresentations<'a, G>(&'a [G], &'a [Scalar]);

    impl<S: Simd, G: Group + PartialEq + Debug> Operation<S> for EachRepresentations<'_, G> {
        type Output = Vec<G>;

        fn portable(self, simd: S) -> Vec<G> {
            simd.execute(|simd: S| {
                let mut expected = self.0.to_vec();
                MultiplyEach {
                    elements: &mut expected,
                    scalars: self.1,
                }
                .run::<S, Unsat49<S>>(simd);
                let mut unsat28 = self.0.to_vec();
                MultiplyEach {
                    elements: &mut unsat28,
                    scalars: self.1,
                }
                .run::<S, Unsat28<S>>(simd);
                assert_eq!(unsat28, expected);
                expected
            })
        }

        // Residues require x86v4c.
        fn x86_v4c(self, simd: S) -> Vec<G>
        where
            S: X86V4C,
        {
            let (elements, scalars) = (self.0, self.1);
            let expected = self.portable(simd);
            simd.execute(|simd: S| {
                let mut rns = elements.to_vec();
                MultiplyEach {
                    elements: &mut rns,
                    scalars,
                }
                .run::<S, Rns<S>>(simd);
                assert_eq!(rns, expected);
            });
            expected
        }
    }
}
