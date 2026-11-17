//! The BLS12-381 groups and the variants of the BLS signature scheme over them.
//!
//! # Acknowledgements
//!
//! _The following crates were used as a reference when implementing this crate. If code is very similar
//! to the reference, it is accompanied by a comment and link._
//!
//! * <https://github.com/filecoin-project/blstrs> + <https://github.com/MystenLabs/fastcrypto>: Implementing operations over
//!   the BLS12-381 scalar field with <https://github.com/supranational/blst>.
//! * <https://github.com/supranational/blst/blob/v0.3.13/bindings/rust/src/pippenger.rs>: Parallel MSM using tile-based Pippenger.

pub mod group;
pub mod variant;
