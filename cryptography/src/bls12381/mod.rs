//! Distributed Key Generation (DKG), Resharing, Signatures, and Threshold Signatures over the BLS12-381 curve.
//!
//! # Features
//!
//! This crate has the following features:
//!
//! - `portable`: Enables `portable` feature on `blst` (<https://github.com/supranational/blst?tab=readme-ov-file#platform-and-language-compatibility>).

#[cfg(feature = "std")]
pub mod dkg;
#[cfg(feature = "std")]
pub mod dkg2;
pub mod primitives;
mod scheme;
pub mod tle;
pub use scheme::{Batch, PrivateKey, PublicKey, Signature};
