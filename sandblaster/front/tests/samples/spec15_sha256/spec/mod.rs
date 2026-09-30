//! The specification of the worked example (DESIGN.md §15.1): FIPS 180-4
//! for one-block messages and a big-endian reader. Every `fn` here is a
//! spec function; none refers to the implementation.

pub mod codec;
pub mod sha256;
