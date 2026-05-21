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
//! - [`golden_dkg`], a one-round asynchronous protocol.
//!
//! The tradeoff is that the latter is more complicated, and more computationally
//! expensive. The one round is very attractive, both to simplify operation of the
//! protocol, and to reduce assumptions about corruption and synchrony.
//! In the two-round protocol, you use the second round to collect complaints about
//! dealer misbehavior in the first round. Because these complaints are critical
//! for security, you need to make sure to wait long enough to collect honest complaints,
//! introducing a synchrony assumption, and the need to consider malicious players.
//! With the one round, you avoid these issues.
//!
//! At the moment, the status of our Golden implementation is experimental, so we recommend
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
