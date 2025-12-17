//! [crate::qmdb::current] variants that do not maintain an ordering over active keys, and hence do
//! not support exclusion proofs. Use the [super::ordered] variants if exclusion proofs are
//! required.

pub mod fixed;
