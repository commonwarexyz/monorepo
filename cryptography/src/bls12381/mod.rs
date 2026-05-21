//! Distributed Key Generation (DKG), Resharing, Signatures, and Threshold Signatures over the BLS12-381 curve.
//!
//! # Features
//!
//! This crate has the following features:
//!
//! - `portable`: Enables `portable` feature on `blst` (<https://github.com/supranational/blst?tab=readme-ov-file#platform-and-language-compatibility>).
//!
//! # DKG Protocols
//!
//! This module exports two DKG protocols:
//!
//! - [`dkg`], a two-round synchronous protocol,
//! - [`golden_dkg`], a one-round asynchronous protocol (currently in ALPHA).
//!
//! The tradeoff is that the latter is more complicated, and more computationally
//! expensive. However, it is less reliant on assumptions about the number of corruptions,
//! and the single round can be very useful, operationally. At the moment,
//! the status of our Golden implementation is experimental, so we recommend
//! using [`dkg`] for now.

pub mod certificate;
#[cfg(feature = "std")]
pub mod dkg;
#[cfg(all(
    feature = "std",
    not(any(
        commonware_stability_BETA,
        commonware_stability_GAMMA,
        commonware_stability_DELTA,
        commonware_stability_EPSILON,
        commonware_stability_RESERVED
    ))
))] // ALPHA
pub mod golden_dkg;
pub mod primitives;
mod scheme;
pub mod tle;
pub use scheme::{Batch, PrivateKey, PublicKey, Signature};
