//! Provides traits for algebraic operations.
//!
//! These traits are designed to lean on the existing Rust operations in [`std::ops`],
//! so that the familiar `+`, `+=`, etc. operators can be used. The traits are also
//! designed with performant implementations in mind, so implementations try to
//! use methods which don't require copying unnecessarily.
use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// Yield all the bits in a u64, from lowest to highest.
fn yield_bits_le(x: u64) -> impl Iterator<Item = bool> {
    (0..64).map(move |i| (x >> i) & 1 != 0)
}

/// Yield the bits in a u64, until they all become 0.
fn yield_bits_le_until_zeroes(x: u64) -> impl Iterator<Item = bool> {
    (0..64 - x.leading_zeros()).map(move |i| (x >> i) & 1 != 0)
}

/// Yield all of the bits in an array of u64s, in little endian order.
fn yield_bits_le_arr(xs: &[u64]) -> impl Iterator<Item = bool> + use<'_> {
    let (&last, start) = xs.split_last().unwrap_or((&0, &[]));
    start
        .iter()
        .copied()
        .flat_map(yield_bits_le)
        .chain(yield_bits_le_until_zeroes(last))
}

/// Inner utility for [`Additive::scale`] and [`Ring::exp`].
///
/// The "double-and-add" / "square-and-multiply" algorithms work over an arbitrary
/// monoid, i.e. something supporting:
///
/// 1. 1 : T
/// 2. (<>) : T -> T -> T
///
/// We take these two operations, along with a helper for applying the operation
/// to oneself, in order to make the algorithm generic.
fn monoid_exp<T: Clone>(
    zero: T,
    op: impl Fn(&mut T, &T),
    self_op: impl Fn(&mut T),
    x: &T,
    bits_le: &[u64],
) -> T {
    let mut acc = zero;
    let mut w = x.clone();
    for b in yield_bits_le_arr(bits_le) {
        if b {
            op(&mut acc, &w);
        }
        self_op(&mut w)
    }
    acc
}

/// A basic trait we expect algebraic data structures to implement.
///
/// Types implementing this trait need to support:
///
/// 1. `T.clone()`,
/// 2. `format!("{:?}", &T)`
/// 2. `&T == &T`,
/// 3. `&T != &T`.
///
/// In other words, being clonable, and comparable for equality.
pub trait Object: Clone + Debug + PartialEq + Eq + Send + Sync {}

/// A type that supports addition, subtraction, and negation.
///
/// For some type `T` implementing this trait, the following operations must be
/// supported:
///
/// 1. `&mut T += &T`,
/// 2. `T + &T`,
/// 3. `&mut T -= &T`,
/// 4. `T - &T`,
/// 5. `-T`.
///
/// There are other combinations of borrowing that could be chosen, but these
/// should be efficiently implementable, even for a "heavier" struct, e.g.
/// a vector of values.
///
/// # Usage
///
///
/// ```
/// # use commonware_math::algebra::Additive;
///
/// // We use .clone() whenever ownership is needed.
/// fn example<T: Additive>(mut x: T, y: T) {
///     x += &y;
///     x.clone() + &y;
///     x -= &y;
///     x.clone() - &y;
///     -x.clone();
///     T::zero();
/// }
/// ```
pub trait Additive:
    Object
    + for<'a> AddAssign<&'a Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + Neg<Output = Self>
{
    /// The neutral element for addition.
    fn zero() -> Self;

    /// Add an element to itself.
    ///
    /// This has a default implementation involving a clone.
    ///
    /// This can be overriden if a more efficient implementation is available.
    fn double(&mut self) {
        *self += &self.clone();
    }

    /// Scale this number by a positive integer.
    ///
    /// To support arbitrary positive integers, we expect to see 64 bit limbs
    /// in little endian order.
    ///
    /// For example, for a 256 bit integer, we expect a slice of 4 elements,
    /// starting with the lowest 64 bits.
    fn scale(&self, bits_le: &[u64]) -> Self {
        monoid_exp(Self::zero(), |a, b| *a += b, |a| a.double(), self, bits_le)
    }
}

/// A type that supports multiplication.
///
/// For some type `T` implementing this trait, the following operations must be
/// supported:
///
/// 1. `&mut T *= &T`,
/// 2. `T * &T`.
///
/// As with [`Additive`], the borrowing scheme is chosen to keep implementations
/// efficient even for heavier structures.
///
/// # Usage
///
/// ```
/// # use commonware_math::algebra::Multiplicative;
///
/// // We use .clone() whenever ownership is needed.
/// fn example<T: Multiplicative>(mut x: T, y: T) {
///     x *= &y;
///     x.clone() * &y;
/// }
/// ```
pub trait Multiplicative:
    Object + for<'a> MulAssign<&'a Self> + for<'a> Mul<&'a Self, Output = Self>
{
    /// Multiply an element with itself.
    ///
    /// This has a default implementation involving a clone.
    ///
    /// This can be overriden for a specific type that's better.
    fn square(&mut self) {
        *self *= &self.clone();
    }
}

/// A type which implements [`Additive`], and supports scaling by some other type.
///
/// Mathematically, this is a (right) `R`-module.
///
/// The following operations must be supported (in addition to [`Additive`]):
/// 1. `T *= &R`,
/// 2. `T * &R`
///
///
/// # Usage
///
/// ```
/// # use commonware_math::algebra::Space;
///
/// // We use .clone() whenever ownership is needed.
/// fn example<R, T: Space<R>>(mut x: T, y: R) {
///     x *= &y;
///     x.clone() * &y;
/// }
/// ```
pub trait Space<R>:
    Additive + for<'a> MulAssign<&'a R> + for<'a> Mul<&'a R, Output = Self>
{
    /// Calculate `sum_i points[i] * scalars[i]`.
    ///
    /// There's a default implementation, but for many types, a more efficient
    /// algorithm is possible.
    ///
    /// Both slices should be considered as padded with [`Additive::zero`] so
    /// that they have the same length.
    ///
    /// For empty slices, the result should be [`Additive::zero`];
    fn msm(points: &[Self], scalars: &[R]) -> Self {
        msm_naive(points, scalars)
    }
}

/// A naive implementation of [`Space::msm`].
///
/// This is what the trait does by default.
///
/// This is useful when implementing the trait, because for small inputs it
/// might be worth just using the naive implementation, because faster
/// algorithms have some overhead in terms of allocating space.
pub fn msm_naive<R, K: Space<R>>(points: &[K], scalars: &[R]) -> K {
    let mut out = K::zero();
    for (s, p) in scalars.iter().zip(points.iter()) {
        out += &(p.clone() * s);
    }
    out
}

impl<R: Additive + Multiplicative> Space<R> for R {}

/// An instance of a mathematical Ring.
///
/// This combines [`Additive`] and [`Multiplicative`], and introduces a
/// neutral element for multiplication, [`Ring::one`].
pub trait Ring: Additive + Multiplicative {
    /// The neutral element for multiplication.
    ///
    /// Multiplying by this element does nothing.
    fn one() -> Self;

    /// Exponentiate this number by a positive integer.
    ///
    /// To support arbitrary positive integers, we expect to see 64 bit limbs
    /// in little endian order.
    ///
    /// For example, for a 256 bit integer, we expect a slice of 4 elements,
    /// starting with the lowest 64 bits.
    fn exp(&self, bits_le: &[u64]) -> Self {
        monoid_exp(Self::one(), |a, b| *a *= b, |a| a.square(), self, bits_le)
    }
}

/// An instance of a mathematical Field.
///
/// This inherits from [`Ring`], and requires the existence of multiplicative
/// inverses as well.
pub trait Field: Ring {
    /// The multiplicative inverse of an element.
    ///
    /// For [`Additive::zero`], this should return [`Additive::zero`].
    ///
    /// For any other element `x`, this should return an element `y` such that
    /// `x * y` is equal to [`Ring::one`].
    fn inv(&self) -> Self;
}

/// A group suitable for use in cryptography.
///
/// This is a cyclic group, with a specified generator.
///
/// The group is of prime order, and thus has an associated field of scalars.
///
/// This trait requires that this type implements [`Space`] over that field.
pub trait CryptoGroup: Space<Self::Scalar> {
    type Scalar: Field;

    /// Return the generator point of this group.
    fn generator() -> Self;
}

#[cfg(any(feature = "test_strategies", test))]
pub mod test_suites {
    use super::*;
    use proptest::{
        prelude::*,
        test_runner::{Config, TestRunner},
    };

    // This alias exists because I got tired of typing this out so many times.
    type TestResult = Result<(), TestCaseError>;

    fn run_proptest<T: Debug>(
        file: &'static str,
        strat: &impl Strategy<Value = T>,
        test: impl Fn(T) -> TestResult,
    ) {
        let config = Config::default().clone_with_source_file(file);
        TestRunner::new(config).run(strat, test).unwrap()
    }

    fn check_add_assign<T: Additive>((a, b): (T, T)) -> TestResult {
        let mut acc = a.clone();
        acc += &b;
        prop_assert_eq!(acc, a + &b, "+= does not match +");
        Ok(())
    }

    fn check_add_commutes<T: Additive>((a, b): (T, T)) -> TestResult {
        prop_assert_eq!(a.clone() + &b, b + &a, "+ not commutative");
        Ok(())
    }

    fn check_add_associates<T: Additive>((a, b, c): (T, T, T)) -> TestResult {
        prop_assert_eq!(
            (a.clone() + &b) + &c,
            a.clone() + &(b + &c),
            "+ not associative"
        );
        Ok(())
    }

    fn check_add_zero<T: Additive>(a: T) -> TestResult {
        prop_assert_eq!(T::zero() + &a, a, "a + 0 != a");
        Ok(())
    }

    fn check_add_neg_self<T: Additive>(a: T) -> TestResult {
        let neg_a = -a.clone();
        prop_assert_eq!(T::zero(), a + &neg_a, "a - a != 0");
        Ok(())
    }

    fn check_sub_vs_add_neg<T: Additive>((a, b): (T, T)) -> TestResult {
        prop_assert_eq!(a.clone() - &b, a.clone() + &-b, "a - b != a + (-b)");
        Ok(())
    }

    fn check_sub_assign<T: Additive>((a, b): (T, T)) -> TestResult {
        let mut acc = a.clone();
        acc -= &b;
        prop_assert_eq!(acc, a - &b, "-= different from -");
        Ok(())
    }

    /// Run the test suite for the [`Additive`] trait.
    ///
    /// Use `file!()` for the first argument.
    pub fn test_additive<T: Additive>(file: &'static str, strat: &impl Strategy<Value = T>) {
        let strat2 = &(strat, strat);
        let strat3 = &(strat, strat, strat);

        run_proptest(file, strat2, check_add_assign);
        run_proptest(file, strat2, check_add_commutes);
        run_proptest(file, strat3, check_add_associates);
        run_proptest(file, strat, check_add_zero);
        run_proptest(file, strat, check_add_neg_self);
        run_proptest(file, strat2, check_sub_vs_add_neg);
        run_proptest(file, strat2, check_sub_assign);
    }

    fn check_mul_assign<T: Multiplicative>((a, b): (T, T)) -> TestResult {
        let mut acc = a.clone();
        acc *= &b;
        prop_assert_eq!(acc, a * &b, "*= different from *");
        Ok(())
    }

    fn check_mul_commutes<T: Multiplicative>((a, b): (T, T)) -> TestResult {
        prop_assert_eq!(a.clone() * &b, b * &a, "* not commutative");
        Ok(())
    }

    fn check_mul_associative<T: Multiplicative>((a, b, c): (T, T, T)) -> TestResult {
        prop_assert_eq!((a.clone() * &b) * &c, a * &(b * &c), "* not associative");
        Ok(())
    }

    /// Run the test suite for the [`Multiplicative`] trait.
    ///
    /// Use `file!()` for the first argument.
    pub fn test_multiplicative<T: Multiplicative>(
        file: &'static str,
        strat: &impl Strategy<Value = T>,
    ) {
        let strat2 = &(strat, strat);
        let strat3 = &(strat, strat, strat);

        run_proptest(file, strat2, check_mul_assign);
        run_proptest(file, strat2, check_mul_commutes);
        run_proptest(file, strat3, check_mul_associative);
    }

    fn check_mul_one<T: Ring>(a: T) -> TestResult {
        prop_assert_eq!(T::one() * &a, a, "a * 1 != a");
        Ok(())
    }

    fn check_mul_distributes<T: Ring>((a, b, c): (T, T, T)) -> TestResult {
        prop_assert_eq!(
            (a.clone() + &b) * &c,
            a * &c + &(b * &c),
            "(a + b) * c != a * c + b * c"
        );
        Ok(())
    }

    /// Run the test suite for the [`Ring`] trait.
    ///
    /// This will also run [`test_additive`] and [`test_multiplicative`].
    ///
    /// Use `file!()` for the first argument.
    pub fn test_ring<T: Ring>(file: &'static str, strat: &impl Strategy<Value = T>) {
        test_additive(file, strat);
        test_multiplicative(file, strat);

        let strat3 = &(strat, strat, strat);

        run_proptest(file, strat, check_mul_one);
        run_proptest(file, strat3, check_mul_distributes);
    }

    fn check_inv<T: Field>(a: T) -> TestResult {
        if a == T::zero() {
            prop_assert_eq!(T::zero(), a.inv(), "0.inv() != 0");
        } else {
            prop_assert_eq!(a.inv() * &a, T::one(), "a * a.inv() != 1");
        }
        Ok(())
    }

    /// Run the test suite for the [`Field`] trait.
    ///
    /// This will also run [`test_ring`].
    ///
    /// Ue `file!()` for the first argument.
    pub fn test_field<T: Field>(file: &'static str, strat: &impl Strategy<Value = T>) {
        test_ring(file, strat);

        run_proptest(file, strat, check_inv);
    }

    fn check_scale_distributes<R, K: Space<R>>((a, b, x): (K, K, R)) -> TestResult {
        prop_assert_eq!((a.clone() + &b) * &x, a * &x + &(b * &x));
        Ok(())
    }

    fn check_scale_assign<R, K: Space<R>>((a, b): (K, R)) -> TestResult {
        let mut acc = a.clone();
        acc *= &b;
        prop_assert_eq!(acc, a * &b);
        Ok(())
    }

    fn check_msm_eq_naive<R, K: Space<R>>(points: &[K], scalars: &[R]) -> TestResult {
        prop_assert_eq!(msm_naive(points, scalars), K::msm(points, scalars));
        Ok(())
    }

    /// Run tests for [`Space`], assuming nothing about the scalar `R`.
    ///
    /// Use `file!()` for the first argument.
    pub fn test_space<R: Debug, K: Space<R>>(
        file: &'static str,
        r_strat: &impl Strategy<Value = R>,
        k_strat: &impl Strategy<Value = K>,
    ) {
        run_proptest(file, &(k_strat, k_strat, r_strat), check_scale_distributes);
        run_proptest(file, &(k_strat, r_strat), check_scale_assign);
        run_proptest(
            file,
            &(0..Config::default().max_default_size_range).prop_flat_map(|len| {
                (
                    prop::collection::vec(k_strat, len),
                    prop::collection::vec(r_strat, len),
                )
            }),
            |(points, scalars)| check_msm_eq_naive(&points, &scalars),
        );
    }

    fn check_scale_compat<R: Multiplicative, K: Space<R>>((a, b, c): (K, R, R)) -> TestResult {
        prop_assert_eq!((a.clone() * &b) * &c, a * &(b * &c));
        Ok(())
    }

    /// Run tests for [`Space`], assuming `R` is [`Multiplicative`].
    ///
    /// This will also run [`test_space`], but check additional compatibility
    /// properties with `R` having multiplication.
    ///
    /// Use `file!()` for the first argument.
    pub fn test_space_multiplicative<R: Multiplicative, K: Space<R>>(
        file: &'static str,
        r_strat: &impl Strategy<Value = R>,
        k_strat: &impl Strategy<Value = K>,
    ) {
        test_space(file, r_strat, k_strat);
        run_proptest(file, &(k_strat, r_strat, r_strat), check_scale_compat);
    }

    fn check_scale_one<R: Ring, K: Space<R>>(a: K) -> TestResult {
        prop_assert_eq!(a.clone(), a * &R::one());
        Ok(())
    }

    fn check_scale_zero<R: Ring, K: Space<R>>(a: K) -> TestResult {
        prop_assert_eq!(K::zero(), a * &R::zero());
        Ok(())
    }

    /// Run tests for [`Space`] assuming that `R` is a [`Ring`].
    ///
    /// This also runs the tests in [`test_space_multiplicative`].
    ///
    /// This additionally checks compatibility with [`Ring::one()`] and
    /// [`Additive::zero()`].
    ///
    /// Use `file!()` for the first argument.
    pub fn test_space_ring<R: Ring, K: Space<R>>(
        file: &'static str,
        r_strat: &impl Strategy<Value = R>,
        k_strat: &impl Strategy<Value = K>,
    ) {
        test_space_multiplicative(file, r_strat, k_strat);

        run_proptest(file, k_strat, check_scale_one);
        run_proptest(file, k_strat, check_scale_zero);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fields::goldilocks::F;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_exp_one(x: F) {
            assert_eq!(x.exp(&[1]), x);
        }

        #[test]
        fn test_exp_zero(x: F) {
            assert_eq!(x.exp(&[]), F::one());
        }

        #[test]
        fn test_exp(x: F, a: u32, b: u32) {
            let a = u64::from(a);
            let b = u64::from(b);
            assert_eq!(x.exp(&[a + b]), x.exp(&[a]) * x.exp(&[b]));
        }

        #[test]
        fn test_scale_one(x: F) {
            assert_eq!(x.scale(&[1]), x);
        }

        #[test]
        fn test_scale_zero(x: F) {
            assert_eq!(x.scale(&[]), F::zero());
        }

        #[test]
        fn test_scale(x: F, a: u32, b: u32) {
            let a = u64::from(a);
            let b = u64::from(b);
            assert_eq!(x.scale(&[a + b]), x.scale(&[a]) + x.scale(&[b]));
        }

        #[test]
        fn test_msm_2(a: [F; 2], b: [F; 2]) {
            assert_eq!(F::msm(&a, &b), a[0] * b[0] + a[1] * b[1]);
        }
    }
}
