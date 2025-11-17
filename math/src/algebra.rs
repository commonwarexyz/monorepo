//! Provides traits for algebraic operations.
//!
//! These traits are designed to lean on the existing Rust operations in [`std::ops`],
//! so that the familiar `+`, `+=`, etc. operators can be used. The traits are also
//! designed with performant implementations in mind, so implementations try to
//! use methods which don't require copying unnecessarily.
use std::ops::{Add, AddAssign};

/// A type that supports addition.
///
/// For some type `T` implementing this trait, the following operations must be
/// supported:
///
/// 1. `&mut T += &T`,
/// 2. `T + &T`.
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
/// fn example<T: Additive>(mut x: T, y: T) -> T {
///     x += &y;
///     let z: T = x + &y;
///     z
/// }
/// ```
pub trait Additive: for<'a> AddAssign<&'a Self> + for<'a> Add<&'a Self, Output = Self> {}
