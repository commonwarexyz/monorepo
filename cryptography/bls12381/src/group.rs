//! Groups of BLS12-381 and their scalar field, through the `commonware-math` algebra traits, and
//! the pairing into the target group [`GT`].

/// Implements, for the group `$group` that wraps its canonical projective coordinates and
/// implements [`kernel::Group`] and `Neg`, the operators, the algebra traits, and the slice
/// operations that G1 and G2 share, with `$generator` as the generator.
///
/// With fuzzing, the module `fuzz` it adds implements `Arbitrary` and `fuzz::Element` with
/// `$eigenvalue` as the eigenvalue of the endomorphism.
macro_rules! impl_group {
    ($group:ident, generator: $generator:expr, eigenvalue: $eigenvalue:expr $(,)?) => {
        impl ::core::fmt::Debug for $group {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                $crate::group::fmt_coordinates(stringify!($group), &self.0, f)
            }
        }

        impl PartialEq for $group {
            fn eq(&self, other: &Self) -> bool {
                $crate::group::kernel::Kernel::dispatch($crate::group::kernel::Add(*self, -*other))
                    .is_identity()
            }
        }

        impl Eq for $group {}

        impl ::commonware_math::algebra::Object for $group {}

        impl<'a> ::core::ops::AddAssign<&'a Self> for $group {
            fn add_assign(&mut self, rhs: &'a Self) {
                *self = $crate::group::kernel::Kernel::dispatch($crate::group::kernel::Add(
                    *self, *rhs,
                ));
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
                *self += &-*rhs;
            }
        }

        impl<'a> ::core::ops::Sub<&'a Self> for $group {
            type Output = Self;

            fn sub(mut self, rhs: &'a Self) -> Self {
                self -= rhs;
                self
            }
        }

        impl ::commonware_math::algebra::Additive for $group {
            fn zero() -> Self {
                Self(<Self as $crate::group::kernel::Group>::IDENTITY)
            }

            fn double(&mut self) {
                *self =
                    $crate::group::kernel::Kernel::dispatch($crate::group::kernel::Double(*self));
            }

            /// Multiplies by the little-endian integer `bits_le` of any length, in time independent
            /// of its value.
            fn scale(&self, bits_le: &[u64]) -> Self {
                $crate::group::kernel::Kernel::dispatch($crate::group::kernel::Multiply {
                    element: *self,
                    scalar: $crate::group::Scalar::from_words_wide(bits_le),
                })
            }
        }

        impl<'a> ::core::ops::MulAssign<&'a $crate::group::Scalar> for $group {
            fn mul_assign(&mut self, rhs: &'a $crate::group::Scalar) {
                *self = $crate::group::kernel::Kernel::dispatch($crate::group::kernel::Multiply {
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

        impl ::commonware_math::algebra::Space<$crate::group::Scalar> for $group {
            /// Returns the sum of the points times their scalars, in variable time.
            ///
            /// The scalars must be public, as Lagrange coefficients and batch-verification weights
            /// are: the running time and memory accesses depend on them. The strategy may split
            /// the points into batches and run them on several threads.
            fn msm(
                points: &[Self],
                scalars: &[$crate::group::Scalar],
                strategy: &impl ::commonware_parallel::Strategy,
            ) -> Self {
                $crate::group::kernel::Batch::dispatch_batches(
                    $crate::group::msm::Msm {
                        elements: points,
                        scalars,
                        method: None,
                    },
                    strategy,
                )
            }
        }

        impl ::commonware_math::algebra::CryptoGroup for $group {
            type Scalar = $crate::group::Scalar;

            fn generator() -> Self {
                Self($generator)
            }
        }

        impl $group {
            /// Returns whether this is the identity.
            pub(crate) fn is_identity(&self) -> bool {
                self.0[2] == [0; _]
            }

            /// Returns the sum of the elements, as when aggregating keys or signatures.
            ///
            /// Costs less per element than adding the elements one at a time with `+`. The
            /// strategy may split the elements into batches and run them on several threads.
            pub fn sum(elements: &[Self], strategy: &impl ::commonware_parallel::Strategy) -> Self {
                $crate::group::kernel::Batch::dispatch_batches(
                    $crate::group::kernel::Sum(elements),
                    strategy,
                )
            }

            /// Multiplies each element by the scalar at the same index, in place, in time
            /// independent of the scalars' values.
            ///
            /// Elements beyond the scalars are unchanged, and scalars beyond the elements are
            /// ignored. Costs less per element than multiplying the elements one at a time with
            /// `*`. The strategy may split the elements into batches and run them on several
            /// threads.
            pub fn mul_each(
                elements: &mut [Self],
                scalars: &[$crate::group::Scalar],
                strategy: &impl ::commonware_parallel::Strategy,
            ) {
                $crate::group::kernel::Batch::dispatch_batches(
                    $crate::group::kernel::MultiplyEach { elements, scalars },
                    strategy,
                );
            }
        }

        /// Fuzzing support for this group.
        #[cfg(any(test, feature = "fuzz"))]
        mod fuzz {
            use super::$group;
            use ::arbitrary::{Arbitrary, Unstructured};
            use ::std::{sync::LazyLock, vec::Vec};
            use $crate::group::{
                Scalar,
                fuzz::{self as shared, Element},
            };

            /// The small multiples of the generator.
            static MULTIPLES: LazyLock<Vec<$group>> = LazyLock::new(shared::table);

            impl<'a> Arbitrary<'a> for $group {
                fn arbitrary(u: &mut Unstructured<'a>) -> ::arbitrary::Result<Self> {
                    Ok(shared::element(u)?.0)
                }
            }

            impl Element for $group {
                fn eigenvalue() -> Scalar {
                    $eigenvalue
                }

                fn multiples() -> &'static [Self] {
                    &MULTIPLES
                }

                fn sum(elements: &[Self], strategy: &impl ::commonware_parallel::Strategy) -> Self {
                    Self::sum(elements, strategy)
                }

                fn mul_each(
                    elements: &mut [Self],
                    scalars: &[Scalar],
                    strategy: &impl ::commonware_parallel::Strategy,
                ) {
                    Self::mul_each(elements, scalars, strategy);
                }
            }
        }
    };
}

mod g1;
mod g2;
mod kernel;
mod msm;
mod pairing;
mod scalar;
#[cfg(test)]
mod vectors;

use commonware_formatting::Hex;
use core::fmt;
pub use g1::G1;
pub use g2::G2;
pub use pairing::{GT, multi_pairing, pairing, pairings};
pub use scalar::Scalar;

/// Formats the projective coordinates of an element of the group `name`.
fn fmt_coordinates<const N: usize>(
    name: &str,
    [x, y, z]: &[[u8; N]; 3],
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    f.debug_struct(name)
        .field("x", &Hex(x))
        .field("y", &Hex(y))
        .field("z", &Hex(z))
        .finish()
}

/// Fuzzing operations shared by both groups.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::{
        Scalar,
        kernel::{Add, Batch, Double, Group, Kernel, Multiply, MultiplyEach, Sum},
        msm::{self, Msm, PIPPENGER_CHUNK},
    };
    #[cfg(feature = "fuzz")]
    pub use super::{pairing::fuzz as pairing, scalar::fuzz as scalar};
    use crate::core::{
        curve::Points,
        field::{
            MAX_LANES,
            arithmetic::Field,
            fp::testing::{self, Target},
        },
    };
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_math::algebra::{CryptoGroup, test_suites};
    use commonware_parallel::{
        Strategy,
        mocks::{Explorer, pooled},
    };
    use commonware_simd::Simd;
    use core::{fmt::Debug, num::NonZeroUsize};
    use std::vec::Vec;

    /// Largest multiple of the generator in [`Element::multiples`].
    const MULTIPLES: usize = 32;

    /// Most elements of a slice operation, more than the lanes of the widest representation.
    const SLICE: usize = 2 * MAX_LANES + 3;

    /// Widest window of a drawn [`msm::Method`]; wider ones only add buckets.
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
        fn sum(elements: &[Self], strategy: &impl Strategy) -> Self;

        /// Multiplies each element by the scalar at the same index.
        fn mul_each(elements: &mut [Self], scalars: &[Scalar], strategy: &impl Strategy);
    }

    /// Draws a strategy that runs each operation whole or in batches, on the calling thread or
    /// on a pool of two workers.
    // The strategy owns its pool, which stops with it: CI runs the plans under Intel SDE, where
    // a pool that outlives its test can keep the process from exiting.
    pub fn strategy(u: &mut Unstructured<'_>) -> arbitrary::Result<Explorer> {
        const WORKERS: NonZeroUsize = NonZeroUsize::new(2).unwrap();
        const TASKS: NonZeroUsize = NonZeroUsize::new(3).unwrap();
        Ok(Explorer::seeded(&pooled(WORKERS, TASKS), u.arbitrary()?))
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

    /// Draws an element with its discrete logarithm: in 13 of 16 cases the identity or `+-k G`
    /// for `k <= MULTIPLES`, read from [`Element::multiples`], and otherwise an arbitrary
    /// multiple.
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
    fn method(u: &mut Unstructured<'_>) -> arbitrary::Result<Option<msm::Method>> {
        Ok(match u.int_in_range(0u8..=2)? {
            0 => None,
            1 => Some(msm::Method::Straus {
                width: u.int_in_range(2..=WIDEST)?,
                split: u.arbitrary()?,
            }),
            // A chunk shorter than the slice splits the elements between several chunks.
            _ => Some(msm::Method::Pippenger {
                width: u.int_in_range(2..=WIDEST)?,
                chunk: NonZeroUsize::new(u.int_in_range(1..=SLICE)?).expect("at least one"),
            }),
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

    /// Runs a group kernel as a kernel of the field testing harness.
    struct Grouped<K>(K);

    impl<K: Kernel + Copy> testing::Kernel for Grouped<K> {
        type Output = K::Output;

        fn run<S: Simd, F: Field<S>>(self, simd: S) -> K::Output {
            simd.execute(|simd: S| self.0.run::<S, F>(simd))
        }
    }

    /// Checks that a representation and emulated backend drawn from the input compute what the
    /// kernel's dispatch does.
    ///
    /// Representations with different lane counts may sum in different orders, which changes the
    /// projective coordinates but not the element.
    pub fn check_representations<K: Kernel<Output: PartialEq + Debug> + Copy>(
        u: &mut Unstructured<'_>,
        kernel: K,
    ) -> arbitrary::Result<()> {
        assert_eq!(Target::draw(u)?.run(Grouped(kernel)), kernel.dispatch());
        Ok(())
    }

    /// A kernel that [`Plan::Representations`] runs on a drawn target.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    enum GroupKernel {
        Msm,
        Sum,
        MulEach,
        Multiply,
        Add,
        Double,
        Endomorphism,
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
        /// of its elements, around the lane counts and the crossover between methods, whole or
        /// in batches.
        Msm,
        /// Checks a multi-scalar multiplication of more elements than Pippenger's method holds
        /// the images of at once, whole or in batches.
        Chunks,
        /// Checks the sum of a slice against the discrete logarithms of its elements.
        Sum,
        /// Checks multiplying a slice against one multiplication at a time.
        MulEach,
        /// Checks that the endomorphism multiplies by its eigenvalue.
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
                    let integer = Scalar::from_words_wide(&words);
                    assert_eq!(p.scale(&words), generator * &(a * &integer));
                }
                Self::Msm => {
                    let method = method(u)?;
                    let count = match u.int_in_range(0u8..=7)? {
                        0 => {
                            let lanes = *u.choose(&[1, 4, 8, 16])?;
                            let crossover = (1..)
                                .find(|&n| {
                                    let method = msm::Method::choose::<G>(n, lanes);
                                    matches!(method, msm::Method::Pippenger { .. })
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
                    let strategy = strategy(u)?;
                    let actual = match method {
                        None => G::msm(&elements, &scalars, &strategy),
                        method => Msm {
                            elements: &elements[..count],
                            scalars: &scalars[..count],
                            method,
                        }
                        .dispatch_batches(&strategy),
                    };
                    let expected = generator * &dot(&logarithms[..count], &scalars[..count]);
                    assert_eq!(actual, expected, "{method:?} for {count} elements");
                }
                Self::Chunks => {
                    // Two chunks and a remainder: the whole crosses a chunk, and so does each of
                    // two batches.
                    let count = 2 * PIPPENGER_CHUNK.get() + u.int_in_range(1..=5)?;
                    let (elements, logarithms) = elements::<G>(u, count)?;
                    let scalars = scalars(u, count)?;
                    assert_eq!(
                        G::msm(&elements, &scalars, &strategy(u)?),
                        generator * &dot(&logarithms, &scalars)
                    );
                }
                Self::Sum => {
                    let count = length(u, SLICE)?;
                    let (elements, logarithms) = elements::<G>(u, count)?;
                    let logarithm = logarithms
                        .iter()
                        .fold(Scalar::ZERO, |sum, logarithm| sum + logarithm);
                    assert_eq!(G::sum(&elements, &strategy(u)?), generator * &logarithm);
                }
                Self::MulEach => {
                    // Elements beyond the scalars are unchanged, and scalars beyond the elements
                    // are ignored.
                    let elements_count = length(u, MAX_LANES + 3)?;
                    let scalars_count = length(u, MAX_LANES + 3)?;
                    let (elements, _) = elements::<G>(u, elements_count)?;
                    let scalars = scalars(u, scalars_count)?;
                    let mut products = elements.clone();
                    G::mul_each(&mut products, &scalars, &strategy(u)?);
                    for (i, (product, element)) in products.iter().zip(&elements).enumerate() {
                        let expected = scalars.get(i).map_or(*element, |scalar| *element * scalar);
                        assert_eq!(*product, expected, "element {i}");
                    }
                }
                Self::Endomorphism => {
                    let (p, _) = element::<G>(u)?;
                    assert_eq!(Endomorphism(p).dispatch(), p * &G::eigenvalue());
                }
                Self::Representations => {
                    let kernel = GroupKernel::arbitrary(u)?;
                    let count = length(u, MAX_LANES + 3)?;
                    let (elements, _) = elements::<G>(u, count.max(2))?;
                    let scalars = scalars(u, count.max(1))?;
                    let method = method(u)?;
                    match kernel {
                        GroupKernel::Msm => check_representations(
                            u,
                            Msm {
                                elements: &elements[..count],
                                scalars: &scalars[..count],
                                method,
                            },
                        )?,
                        GroupKernel::Sum => check_representations(u, Sum(&elements[..count]))?,
                        GroupKernel::MulEach => {
                            check_representations(u, Each(&elements[..count], &scalars[..count]))?
                        }
                        GroupKernel::Multiply => check_representations(
                            u,
                            Multiply {
                                element: elements[0],
                                scalar: scalars[0],
                            },
                        )?,
                        GroupKernel::Add => {
                            check_representations(u, Add(elements[0], elements[1]))?
                        }
                        GroupKernel::Double => check_representations(u, Double(elements[0]))?,
                        GroupKernel::Endomorphism => {
                            check_representations(u, Endomorphism(elements[0]))?
                        }
                    }
                }
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::group::{G1, G2};
        use commonware_invariants::minifuzz;

        // Most cases multiply several times, so debug builds run few of them.

        #[test]
        fn minifuzz_additive() {
            minifuzz::Builder::default()
                .with_min_iterations(16)
                .test(|u| {
                    Plan::Additive.run::<G1>(u)?;
                    Plan::Additive.run::<G2>(u)
                });
        }

        #[test]
        fn minifuzz_space() {
            minifuzz::Builder::default()
                .with_min_iterations(4)
                .test(|u| {
                    Plan::Space.run::<G1>(u)?;
                    Plan::Space.run::<G2>(u)
                });
        }

        #[test]
        fn minifuzz_multiples() {
            minifuzz::Builder::default()
                .with_min_iterations(8)
                .test(|u| {
                    Plan::Multiples.run::<G1>(u)?;
                    Plan::Multiples.run::<G2>(u)
                });
        }

        #[test]
        fn minifuzz_msm() {
            minifuzz::Builder::default()
                .with_min_iterations(8)
                .test(|u| {
                    Plan::Msm.run::<G1>(u)?;
                    Plan::Msm.run::<G2>(u)
                });
        }

        #[test]
        fn minifuzz_chunks() {
            minifuzz::Builder::default()
                .with_min_iterations(1)
                .test(|u| {
                    Plan::Chunks.run::<G1>(u)?;
                    Plan::Chunks.run::<G2>(u)
                });
        }

        #[test]
        fn minifuzz_sum() {
            minifuzz::Builder::default()
                .with_min_iterations(16)
                .test(|u| {
                    Plan::Sum.run::<G1>(u)?;
                    Plan::Sum.run::<G2>(u)
                });
        }

        #[test]
        fn minifuzz_mul_each() {
            minifuzz::Builder::default()
                .with_min_iterations(4)
                .test(|u| {
                    Plan::MulEach.run::<G1>(u)?;
                    Plan::MulEach.run::<G2>(u)
                });
        }

        #[test]
        fn minifuzz_endomorphism() {
            minifuzz::Builder::default()
                .with_min_iterations(16)
                .test(|u| {
                    Plan::Endomorphism.run::<G1>(u)?;
                    Plan::Endomorphism.run::<G2>(u)
                });
        }

        #[test]
        fn minifuzz_representations() {
            minifuzz::Builder::default()
                .with_min_iterations(16)
                .test(|u| {
                    Plan::Representations.run::<G1>(u)?;
                    Plan::Representations.run::<G2>(u)
                });
        }
    }
}
