//! Vec-like utility types.
//!
//! # Overview
//!
//! The types in this module provide Vec-like ergonomics while enforcing
//! additional invariants or using different storage strategies:
//!
//! - [`ArrayVec`] stores elements inline with a fixed compile-time capacity.
//! - [`NonEmptyVec`] guarantees that at least one element is always present.
//!
//! These types target different constraints:
//!
//! - choose [`ArrayVec`] when you want to avoid heap allocation for the
//!   container and your maximum length is small and known at compile time,
//! - choose [`NonEmptyVec`] when the important property is "never empty", while
//!   still using heap-backed storage and growable capacity.
//!
//! Both types aim to stay close to ordinary slice and [`Vec`] ergonomics while
//! making their invariants explicit in the type system.
//!
//! # Examples
//!
//! ```
//! use commonware_utils::{array_vec, non_empty_vec};
//!
//! let inline = array_vec![1u8, 2, 3];
//! assert_eq!(inline.capacity(), 3);
//!
//! let never_empty = non_empty_vec![4u8, 5, 6];
//! assert_eq!(never_empty.first(), &4);
//! ```

mod array;
mod non_empty;
pub use array::ArrayVec;
pub use non_empty::NonEmptyVec;
