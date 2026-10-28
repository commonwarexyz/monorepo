//! The original prototype: scalar, per-lane, and RNS base fields, the extension towers, G1, G2,
//! and pairings.
//!
//! Compiled only with the `old` feature, so that building the new field arithmetic stays fast.

mod algebra;
mod curve;
pub mod fp;
pub mod fp12;
pub mod fp2;
pub mod fp6;
pub mod g1;
pub mod g2;
mod group;
mod hash;
pub mod pairing;
pub mod scalar;
