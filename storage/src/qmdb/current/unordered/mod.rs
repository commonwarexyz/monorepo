//! _Unordered_ variants of a [crate::qmdb::current] authenticated database.
//!
//! These variants do not maintain key ordering, so they cannot generate exclusion proofs. Use
//! the [super::ordered] variants if exclusion proofs are required.
//!
//! Variants:
//! - [fixed]: Variant optimized for values of fixed size.

pub mod fixed;
#[cfg(any(test, feature = "test-traits"))]
mod test_trait_impls;
