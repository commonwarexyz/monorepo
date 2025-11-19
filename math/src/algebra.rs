//! Provides traits for algebraic operations.
//!
//! These traits are designed to lean on the existing Rust operations in [`std::ops`],
//! so that the familiar `+`, `+=`, etc. operators can be used. The traits are also
//! designed with performant implementations in mind, so implementations try to
//! use methods which don't require copying unnecessarily.
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// A basic trait we expect algebraic data structures to implement.
///
/// Types implementing this trait need to support:
///
/// 1. `T.clone()`,
/// 2. `&T == &T`,
/// 3. `&T != &T`.
///
/// In other words, being clonable, and comparable for equality.
pub trait Object: Clone + PartialEq + Eq {}

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
///     T::ZERO;
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
    const ZERO: Self;
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
