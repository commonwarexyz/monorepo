//! Provides traits for algebraic operations.
//!
//! These traits are designed to lean on the existing Rust operations in [`std::ops`],
//! so that the familiar `+`, `+=`, etc. operators can be used. The traits are also
//! designed with performant implementations in mind, so implementations try to
//! use methods which don't require copying unnecessarily.
use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};

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
/// fn example<T: Clone + Additive>(mut x: T, y: T) {
///     x += &y;
///     x.clone() + &y;
///     x -= &y;
///     x.clone() - &y;
///     -x.clone();
///     T::ZERO;
/// }
/// ```
pub trait Additive:
    for<'a> AddAssign<&'a Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + Neg<Output = Self>
{
    /// The neutral element for addition.
    const ZERO: Self;
}
