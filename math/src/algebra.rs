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
pub trait Object: Clone + Debug + PartialEq + Eq {}

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
}

impl<R: Additive + Multiplicative> Space<R> for R {}

#[cfg(any(feature = "test_strategies", test))]
pub mod tests {
    use super::*;
    use proptest::{prelude::*, test_runner::Config, test_runner::TestRunner};

    fn run_proptest<T: Debug>(
        file: &'static str,
        strat: &impl Strategy<Value = T>,
        test: impl Fn(T) -> Result<(), TestCaseError>,
    ) {
        let config = Config::default().clone_with_source_file(file);
        TestRunner::new(config).run(strat, test).unwrap()
    }

    fn check_add_assign<T: Additive>((a, b): (T, T)) -> Result<(), TestCaseError> {
        let mut acc = a.clone();
        acc += &b;
        prop_assert_eq!(acc, a + &b, "+= does not match +");
        Ok(())
    }

    fn check_add_commutes<T: Additive>((a, b): (T, T)) -> Result<(), TestCaseError> {
        prop_assert_eq!(a.clone() + &b, b + &a, "+ not commutative");
        Ok(())
    }

    fn check_add_associates<T: Additive>((a, b, c): (T, T, T)) -> Result<(), TestCaseError> {
        prop_assert_eq!(
            (a.clone() + &b) + &c,
            a.clone() + &(b + &c),
            "+ not associative"
        );
        Ok(())
    }

    fn check_add_zero<T: Additive>(a: T) -> Result<(), TestCaseError> {
        prop_assert_eq!(T::zero() + &a, a);
        Ok(())
    }

    fn check_add_neg_self<T: Additive>(a: T) -> Result<(), TestCaseError> {
        let neg_a = -a.clone();
        prop_assert_eq!(T::zero(), a + &neg_a);
        Ok(())
    }

    fn check_sub_vs_add_neg<T: Additive>((a, b): (T, T)) -> Result<(), TestCaseError> {
        prop_assert_eq!(a.clone() - &b, a.clone() + &-b);
        Ok(())
    }

    fn check_sub_assign<T: Additive>((a, b): (T, T)) -> Result<(), TestCaseError> {
        let mut acc = a.clone();
        acc -= &b;
        prop_assert_eq!(acc, a - &b);
        Ok(())
    }

    /// Run the test suite for the [`Additive`] trait.
    ///
    /// Use `file!()` for the first argument. (We can't do this ourselves, because
    /// we want the source file that your test code is in to be there, not the
    /// file where this code is located).
    pub fn test_additive<T: Additive>(file: &'static str, strat: &impl Strategy<Value = T>) {
        let strat2 = (&strat, &strat);
        let strat3 = (&strat, &strat, &strat);

        run_proptest(file, &strat2, check_add_assign);
        run_proptest(file, &strat2, check_add_commutes);
        run_proptest(file, &strat3, check_add_associates);
        run_proptest(file, &strat, check_add_zero);
        run_proptest(file, &strat, check_add_neg_self);
        run_proptest(file, &strat2, check_sub_vs_add_neg);
        run_proptest(file, &strat2, check_sub_assign);
    }
}
