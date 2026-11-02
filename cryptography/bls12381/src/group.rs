//! Groups of BLS12-381 and their scalar field, through the `commonware-math` algebra traits.
//!
//! [`G1`] and [`G2`] hold canonical projective coordinates. Each operation runs as one SIMD
//! kernel on the best available backend, so batch operations such as
//! [`Space::msm`](commonware_math::algebra::Space::msm) amortize the conversions at the kernel
//! boundary that single operations pay every time.
//!
//! Elements arise only from the generators through the group operations, so every element lies
//! in the subgroup of prime order `r`.

mod g1;
mod g2;
mod kernel;
mod scalar;

pub use g1::G1;
pub use g2::G2;
pub use scalar::Scalar;

/// Most elements of [`Space::msm`](commonware_math::algebra::Space::msm) that one kernel
/// multiplies, so that a parallel strategy can split larger inputs.
const MSM_CHUNK: usize = 64;

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

            /// Multiplies by an integer without branching on its value.
            fn scale(&self, bits_le: &[u64]) -> Self {
                $crate::group::kernel::dispatch($crate::group::kernel::Multiply {
                    element: *self,
                    words: bits_le,
                })
            }
        }

        impl<'a> ::core::ops::MulAssign<&'a $crate::group::Scalar> for $group {
            fn mul_assign(&mut self, rhs: &'a $crate::group::Scalar) {
                *self = $crate::group::kernel::dispatch($crate::group::kernel::Multiply {
                    element: *self,
                    words: &rhs.to_words(),
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
            fn msm(
                points: &[Self],
                scalars: &[$crate::group::Scalar],
                strategy: &impl commonware_parallel::Strategy,
            ) -> Self {
                let count = points.len().min(scalars.len());
                strategy.fold(
                    points[..count]
                        .chunks($crate::group::MSM_CHUNK)
                        .zip(scalars[..count].chunks($crate::group::MSM_CHUNK)),
                    <Self as commonware_math::algebra::Additive>::zero,
                    |sum, (elements, scalars)| {
                        sum + &$crate::group::kernel::dispatch($crate::group::kernel::Msm {
                            elements,
                            scalars,
                        })
                    },
                    |a, b| a + &b,
                )
            }
        }

        impl commonware_math::algebra::CryptoGroup for $group {
            type Scalar = $crate::group::Scalar;

            fn generator() -> Self {
                Self(GENERATOR)
            }
        }
    };
}

use group_traits;

/// Checks shared by both groups.
#[cfg(test)]
mod tests {
    use super::{
        MSM_CHUNK, Scalar,
        kernel::{Group, Kernel, Msm, Multiply},
    };
    use crate::core::field::fp::{rns::Rns, unsat28::Unsat28, unsat49::Unsat49};
    use commonware_math::algebra::CryptoGroup;
    use commonware_parallel::Sequential;
    use commonware_simd::{Operation, Simd, check_consistent};
    use std::{fmt::Debug, vec, vec::Vec};

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
    }

    /// Checks [`Space::msm`] against a sum of multiplications, across chunk boundaries.
    pub fn check_msm<G: CryptoGroup<Scalar = Scalar>>() {
        let generator = G::generator();
        let count = MSM_CHUNK + 3;
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
        for count in [0, 1, 5, count] {
            let exponent = scalars[..count]
                .iter()
                .enumerate()
                .fold(Scalar::ZERO, |sum, (i, scalar)| {
                    sum + &(Scalar::from_u64(i as u64 + 1) * scalar)
                });
            let expected = generator.clone() * &exponent;
            assert_eq!(
                G::msm(&points[..count], &scalars[..count], &Sequential),
                expected
            );
        }
        // The longer input is truncated.
        assert_eq!(
            G::msm(&points[..3], &scalars[..5], &Sequential),
            G::msm(&points[..3], &scalars[..3], &Sequential)
        );
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
                assert_eq!(self.0.run::<S, Rns<S>>(simd), expected);
                expected
            })
        }
    }

    /// Checks that every representation and backend computes the same coordinates.
    pub fn check_representations<G: CryptoGroup<Scalar = Scalar> + Group>() {
        let generator = G::generator();
        let scalars = scalars();
        let elements: Vec<G> = scalars.iter().map(|scalar| generator * scalar).collect();
        check_consistent(|| {
            Representations(Msm {
                elements: &elements,
                scalars: &scalars,
            })
        });
        let words = scalars[5].to_words();
        check_consistent(|| {
            Representations(Multiply {
                element: elements[6],
                words: &words,
            })
        });
    }
}
