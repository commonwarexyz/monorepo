//! Vec-like types with stronger invariants.
//!
//! - [`ArrayVec`]: fixed-capacity, inline storage, no heap allocation.
//!   Best for small buffers where the maximum length is known at compile time.
//! - [`NonEmptyVec`]: guaranteed to always contain at least one element.
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
