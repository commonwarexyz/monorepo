//! Groups of BLS12-381 and their scalar field, through the `commonware-math` algebra traits, and
//! the pairing into the target group [`GT`].

mod g1;
mod g2;
mod kernel;
mod pairing;
mod scalar;
#[cfg(test)]
mod vectors;

use core::num::NonZeroUsize;
pub use g1::G1;
pub use g2::G2;
pub use pairing::{GT, multi_pairing, pairing, pairings};
pub use scalar::Scalar;

/// Fewest elements of [`Space::msm`](commonware_math::algebra::Space::msm) that a parallel
/// strategy gives one kernel. Every kernel pays for its own bucket sums and doublings, which
/// cost about as much as adding a few hundred elements.
const MSM_BATCH: NonZeroUsize = NonZeroUsize::new(256).unwrap();

/// Fuzzing operations shared by both groups.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::{
        MSM_BATCH, Scalar,
        kernel::{self, Add, Double, Group, Kernel, MAX_LANES, Msm, Multiply, MultiplyEach, Sum},
    };
    pub use super::{pairing::fuzz as pairing, scalar::fuzz as scalar};
    use crate::core::{
        curve::Points,
        field::{
            arithmetic::Field,
            fp::{rns::Rns, testing::Backend, unsat28::Unsat28, unsat49::Unsat49},
        },
    };
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_math::algebra::{CryptoGroup, test_suites};
    use commonware_parallel::{
        Sequential,
        mocks::{Explorer, pooled},
    };
    use commonware_simd::{Operation, Simd, X86V4C};
    use core::{fmt::Debug, num::NonZeroUsize};
    use std::vec::Vec;

    /// Largest multiple of the generator in [`Element::multiples`].
    const MULTIPLES: usize = 32;

    /// Most elements of a slice operation, more than the lanes of the widest representation.
    const SLICE: usize = 2 * MAX_LANES + 3;

    /// Widest window of a drawn [`kernel::Plan`]; wider ones only add buckets.
    const WIDEST: u32 = 8;

    /// A group under test.
    pub trait Element:
        CryptoGroup<Scalar = Scalar> + Group + for<'a> Arbitrary<'a> + 'static
    {
        /// Returns the eigenvalue of the group's endomorphism.
        fn eigenvalue() -> Scalar;

        /// Returns the multiples of the generator by zero through [`MULTIPLES`], as [`table`]
        /// builds them.
        fn multiples() -> &'static [Self];

        /// Returns the sum of the elements.
        fn sum(elements: &[Self]) -> Self;

        /// Multiplies each element by the scalar at the same index.
        fn mul_each(elements: &mut [Self], scalars: &[Scalar]);
    }

    /// Returns the multiples of the generator by zero through [`MULTIPLES`], one addition at a
    /// time.
    pub fn table<G: CryptoGroup>() -> Vec<G> {
        let generator = G::generator();
        let mut multiple = G::zero();
        (0..=MULTIPLES)
            .map(|_| {
                let current = multiple.clone();
                multiple += &generator;
                current
            })
            .collect()
    }

    /// Draws an element with its discrete logarithm: mostly a small multiple of the generator or
    /// its negation, which cost nothing to draw, and otherwise an arbitrary multiple.
    pub fn element<G: Element>(u: &mut Unstructured<'_>) -> arbitrary::Result<(G, Scalar)> {
        let small = |u: &mut Unstructured<'_>| {
            let k = u.int_in_range(0..=MULTIPLES)?;
            Ok((G::multiples()[k], Scalar::from_u64(k as u64)))
        };
        Ok(match u.int_in_range(0u8..=15)? {
            0 => (G::zero(), Scalar::ZERO),
            1..=6 => small(u)?,
            7..=12 => {
                let (element, logarithm) = small(u)?;
                (-element, -logarithm)
            }
            _ => {
                let logarithm = Scalar::arbitrary(u)?;
                (G::generator() * &logarithm, logarithm)
            }
        })
    }

    /// Draws elements with their discrete logarithms. Past the end of the input, the elements
    /// cycle through the small multiples of the generator.
    pub fn elements<G: Element>(
        u: &mut Unstructured<'_>,
        count: usize,
    ) -> arbitrary::Result<(Vec<G>, Vec<Scalar>)> {
        let mut elements = Vec::with_capacity(count);
        let mut logarithms = Vec::with_capacity(count);
        for i in 0..count {
            let (element, logarithm) = if u.is_empty() {
                let k = (5 * i + 1) % (MULTIPLES + 1);
                (G::multiples()[k], Scalar::from_u64(k as u64))
            } else {
                element(u)?
            };
            elements.push(element);
            logarithms.push(logarithm);
        }
        Ok((elements, logarithms))
    }

    /// Draws scalars. Past the end of the input, each scalar follows from the one before, so the
    /// scalars stay distinct and of full width.
    fn scalars(u: &mut Unstructured<'_>, count: usize) -> arbitrary::Result<Vec<Scalar>> {
        let mut previous = Scalar::from_u64(3);
        (0..count)
            .map(|i| {
                previous = if u.is_empty() {
                    previous * &previous + &Scalar::from_u64(i as u64)
                } else {
                    Scalar::arbitrary(u)?
                };
                Ok(previous)
            })
            .collect()
    }

    /// Draws the length of a slice operation, the longest past the end of the input.
    fn length(u: &mut Unstructured<'_>, longest: usize) -> arbitrary::Result<usize> {
        Ok(longest - u.int_in_range(0..=longest)?)
    }

    /// Draws the method of a multi-scalar multiplication, or `None` for the one chosen by cost.
    fn method(u: &mut Unstructured<'_>) -> arbitrary::Result<Option<kernel::Plan>> {
        Ok(match u.int_in_range(0u8..=2)? {
            0 => None,
            1 => Some(kernel::Plan::Straus {
                width: u.int_in_range(2..=WIDEST)?,
                split: u.arbitrary()?,
            }),
            _ => Some(kernel::Plan::Pippenger(u.int_in_range(2..=WIDEST)?)),
        })
    }

    /// Returns the sum of the products of logarithms and scalars at the same index.
    pub fn dot(logarithms: &[Scalar], scalars: &[Scalar]) -> Scalar {
        logarithms
            .iter()
            .zip(scalars)
            .fold(Scalar::ZERO, |sum, (logarithm, scalar)| {
                sum + &(*logarithm * scalar)
            })
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

    /// Multiplies each element by the scalar at the same index, returning the products.
    #[derive(Clone, Copy)]
    struct Each<'a, G>(&'a [G], &'a [Scalar]);

    impl<G: Group> Kernel for Each<'_, G> {
        type Output = Vec<G>;

        fn run<S: Simd, F: Field<S>>(self, simd: S) -> Vec<G> {
            let mut elements = self.0.to_vec();
            MultiplyEach {
                elements: &mut elements,
                scalars: self.1,
            }
            .run::<S, F>(simd);
            elements
        }
    }

    /// Runs a kernel in every representation of a backend, checking that they compute the same
    /// output.
    ///
    /// Representations with different lane counts may sum in different orders, which changes the
    /// projective coordinates but not the element.
    struct Representations<K>(K);

    impl<S: Simd, K: Kernel<Output: PartialEq + Debug> + Copy> Operation<S> for Representations<K> {
        type Output = K::Output;

        fn portable(self, simd: S) -> K::Output {
            simd.execute(|simd: S| {
                let expected = self.0.run::<S, Unsat49<S>>(simd);
                assert_eq!(self.0.run::<S, Unsat28<S>>(simd), expected);
                expected
            })
        }

        // Residues require x86v4c.
        fn x86_v4c(self, simd: S) -> K::Output
        where
            S: X86V4C,
        {
            let kernel = self.0;
            let expected = self.portable(simd);
            simd.execute(|simd: S| assert_eq!(kernel.run::<S, Rns<S>>(simd), expected));
            expected
        }
    }

    /// Checks that every representation of an emulated backend drawn from the input computes
    /// what the kernel's dispatch does.
    pub fn check_representations<K: Kernel<Output: PartialEq + Debug> + Copy>(
        u: &mut Unstructured<'_>,
        kernel: K,
    ) -> arbitrary::Result<()> {
        let output = Backend::draw(u)?.execute(Representations(kernel));
        assert_eq!(output, kernel.dispatch());
        Ok(())
    }

    /// A group fuzzing operation, run on either group.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    pub enum Plan {
        /// Checks the laws of addition, and that doubling agrees with it.
        Additive,
        /// Checks the laws of multiplication by scalars, including that a short multi-scalar
        /// multiplication is the sum of its products.
        Space,
        /// Checks that multiples of the generator add, compare, and multiply as their discrete
        /// logarithms do, for scalars and for integers of any length.
        Multiples,
        /// Checks a multi-scalar multiplication by each method against the discrete logarithms
        /// of its elements, around the lane counts and the crossover between methods.
        Msm,
        /// Checks a multi-scalar multiplication split into batches by a parallel strategy.
        Batches,
        /// Checks the sum of a slice against the discrete logarithms of its elements.
        Sum,
        /// Checks multiplying a slice against one multiplication at a time.
        MulEach,
        /// Checks that the endomorphism multiplies by its eigenvalue, and that the components of
        /// a scalar reconstruct it.
        Endomorphism,
        /// Checks that every representation and backend computes what each kernel's dispatch
        /// does.
        Representations,
    }

    impl Plan {
        /// Runs the operation on the group `G` using the remaining input.
        pub fn run<G: Element>(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            let generator = G::generator();
            match self {
                Self::Additive => {
                    test_suites::fuzz_additive::<G>(u)?;
                    let a = G::arbitrary(u)?;
                    let mut doubled = a;
                    doubled.double();
                    assert_eq!(doubled, a + &a);
                }
                Self::Space => test_suites::fuzz_space_ring::<Scalar, G>(u)?,
                Self::Multiples => {
                    let (p, a) = element::<G>(u)?;
                    let (q, b) = element::<G>(u)?;
                    assert_eq!(p + &q, generator * &(a + &b));
                    assert_eq!(p == q, a == b);
                    let c = Scalar::arbitrary(u)?;
                    assert_eq!(p * &c, generator * &(a * &c));
                    // More words than a scalar holds.
                    let count = u.int_in_range(0..=9)?;
                    let words = (0..count)
                        .map(|_| u.arbitrary())
                        .collect::<arbitrary::Result<Vec<u64>>>()?;
                    assert_eq!(p.scale(&words), p * &Scalar::from_words_wide(&words));
                }
                Self::Msm => {
                    let plan = method(u)?;
                    let count = match u.int_in_range(0u8..=7)? {
                        0 => {
                            let lanes = *u.choose(&[1, 4, 8, 16])?;
                            let crossover = (1..)
                                .find(|&n| {
                                    let plan = kernel::Plan::choose::<G>(n, lanes);
                                    matches!(plan, kernel::Plan::Pippenger(_))
                                })
                                .expect("Pippenger's method costs less for many elements");
                            crossover - u.int_in_range(0..=1)?
                        }
                        _ => length(u, SLICE)?,
                    };
                    // The longer input is truncated.
                    let (extra_elements, extra_scalars) = match u.int_in_range(0u8..=3)? {
                        0 => (u.int_in_range(1..=2)?, 0),
                        1 => (0, u.int_in_range(1..=2)?),
                        _ => (0, 0),
                    };
                    let (elements, logarithms) = elements::<G>(u, count + extra_elements)?;
                    let scalars = scalars(u, count + extra_scalars)?;
                    let actual = match plan {
                        None => G::msm(&elements, &scalars, &Sequential),
                        plan => Msm {
                            elements: &elements[..count],
                            scalars: &scalars[..count],
                            plan,
                        }
                        .dispatch(),
                    };
                    let expected = generator * &dot(&logarithms[..count], &scalars[..count]);
                    assert_eq!(actual, expected, "{plan:?} for {count} elements");
                }
                Self::Batches => {
                    const WORKERS: NonZeroUsize = NonZeroUsize::new(2).unwrap();
                    const TASKS: NonZeroUsize = NonZeroUsize::new(3).unwrap();
                    let strategy = pooled(WORKERS, TASKS);
                    let strategy = match u.int_in_range(0u8..=1)? {
                        0 => Explorer::parallel(&strategy),
                        _ => Explorer::seeded(&strategy, u.arbitrary()?),
                    };
                    // Enough elements for two batches, and a remainder.
                    let count = 2 * MSM_BATCH.get() + u.int_in_range(0..=5)?;
                    let (elements, logarithms) = elements::<G>(u, count)?;
                    let scalars = scalars(u, count)?;
                    assert_eq!(
                        G::msm(&elements, &scalars, &strategy),
                        generator * &dot(&logarithms, &scalars)
                    );
                }
                Self::Sum => {
                    let count = length(u, SLICE)?;
                    let (elements, logarithms) = elements::<G>(u, count)?;
                    let logarithm = logarithms
                        .iter()
                        .fold(Scalar::ZERO, |sum, logarithm| sum + logarithm);
                    assert_eq!(G::sum(&elements), generator * &logarithm);
                }
                Self::MulEach => {
                    // Elements beyond the scalars are unchanged, and scalars beyond the elements
                    // are ignored.
                    let elements_count = length(u, MAX_LANES + 3)?;
                    let scalars_count = length(u, MAX_LANES + 3)?;
                    let (elements, _) = elements::<G>(u, elements_count)?;
                    let scalars = scalars(u, scalars_count)?;
                    let mut products = elements.clone();
                    G::mul_each(&mut products, &scalars);
                    for (i, (product, element)) in products.iter().zip(&elements).enumerate() {
                        let expected = scalars.get(i).map_or(*element, |scalar| *element * scalar);
                        assert_eq!(*product, expected, "element {i}");
                    }
                }
                Self::Endomorphism => {
                    let eigenvalue = G::eigenvalue();
                    let (p, _) = element::<G>(u)?;
                    assert_eq!(Endomorphism(p).dispatch(), p * &eigenvalue);

                    let scalar = Scalar::arbitrary(u)?;
                    let bound = 1u128.checked_shl(G::COMPONENT_BITS - 1);
                    let mut sum = Scalar::ZERO;
                    let mut power = Scalar::ONE;
                    for (c, component) in G::components(&scalar).into_iter().enumerate() {
                        assert!(bound.is_none_or(|bound| component < bound));
                        assert!(c < G::COMPONENTS || component == 0);
                        let words = [component as u64, (component >> 64) as u64, 0, 0];
                        let component = Scalar::from_words(words).expect("below the order");
                        sum += &(component * &power);
                        power *= &-eigenvalue;
                    }
                    assert_eq!(sum, scalar);
                }
                Self::Representations => {
                    let kind = u.int_in_range(0u8..=6)?;
                    let count = length(u, MAX_LANES + 3)?;
                    let (elements, _) = elements::<G>(u, count.max(2))?;
                    let scalars = scalars(u, count.max(1))?;
                    let plan = method(u)?;
                    match kind {
                        0 => check_representations(
                            u,
                            Msm {
                                elements: &elements[..count],
                                scalars: &scalars[..count],
                                plan,
                            },
                        )?,
                        1 => check_representations(u, Sum(&elements[..count]))?,
                        2 => check_representations(u, Each(&elements[..count], &scalars[..count]))?,
                        3 => check_representations(
                            u,
                            Multiply {
                                element: elements[0],
                                scalar: scalars[0],
                            },
                        )?,
                        4 => check_representations(u, Add(elements[0], elements[1]))?,
                        5 => check_representations(u, Double(elements[0]))?,
                        _ => check_representations(u, Endomorphism(elements[0]))?,
                    }
                }
            }
            Ok(())
        }
    }

    /// Defines a test of each [`Plan`] variant on a group.
    #[cfg(test)]
    macro_rules! tests {
        ($group:ty) => {
            use crate::group::fuzz::Plan;
            use commonware_invariants::minifuzz;

            // Most cases multiply several times, so debug builds run few of them.

            #[test]
            fn minifuzz_additive() {
                minifuzz::Builder::default()
                    .with_min_iterations(16)
                    .test(|u| Plan::Additive.run::<$group>(u));
            }

            #[test]
            fn minifuzz_space() {
                minifuzz::Builder::default()
                    .with_min_iterations(4)
                    .test(|u| Plan::Space.run::<$group>(u));
            }

            #[test]
            fn minifuzz_multiples() {
                minifuzz::Builder::default()
                    .with_min_iterations(8)
                    .test(|u| Plan::Multiples.run::<$group>(u));
            }

            #[test]
            fn minifuzz_msm() {
                minifuzz::Builder::default()
                    .with_min_iterations(8)
                    .test(|u| Plan::Msm.run::<$group>(u));
            }

            #[test]
            fn minifuzz_batches() {
                minifuzz::Builder::default()
                    .with_min_iterations(1)
                    .test(|u| Plan::Batches.run::<$group>(u));
            }

            #[test]
            fn minifuzz_sum() {
                minifuzz::Builder::default()
                    .with_min_iterations(16)
                    .test(|u| Plan::Sum.run::<$group>(u));
            }

            #[test]
            fn minifuzz_mul_each() {
                minifuzz::Builder::default()
                    .with_min_iterations(4)
                    .test(|u| Plan::MulEach.run::<$group>(u));
            }

            #[test]
            fn minifuzz_endomorphism() {
                minifuzz::Builder::default()
                    .with_min_iterations(16)
                    .test(|u| Plan::Endomorphism.run::<$group>(u));
            }

            #[test]
            fn minifuzz_representations() {
                minifuzz::Builder::default()
                    .with_min_iterations(4)
                    .test(|u| Plan::Representations.run::<$group>(u));
            }
        };
    }
    #[cfg(test)]
    pub(crate) use tests;
}
