//! BLS12-381 threshold signature implementations for `simplex`.
//!
//! This module provides two variants of threshold signing:
//!
//! - [`standard`]: Standard threshold signatures using the certificate macro.
//!   Certificates contain only a vote signature recovered from partial signatures.
//!
//! - [`vrf`]: Threshold VRF (Verifiable Random Function) implementation that produces
//!   both vote signatures and per-round seed signatures. The seed can be used for
//!   randomness (e.g., leader election, timelock encryption).
//!
//! # Security Warning for VRF Usage
//!
//! When using the [`vrf`] variant, it is **not safe** to use a round's randomness
//! to drive execution in that same round. A malicious leader can selectively
//! distribute blocks to gain early visibility of the randomness output, then
//! choose nullification if the outcome is unfavorable.
//!
//! Applications should employ a "commit-then-reveal" pattern by requesting
//! randomness in advance:
//! - Bind randomness requests in finalized blocks **before** the reveal occurs
//! - Example: `draw(view+100)` means execution uses VRF output 100 views later
//!
//! # Non-Attributable Signatures
//!
//! Both variants are **non-attributable**: individual partial signatures cannot be
//! safely presented to third parties as evidence of liveness or faults. With threshold
//! signatures, any `t` valid partial signatures can forge a partial signature for any
//! other participant. Because peer connections are authenticated, evidence can be used
//! locally but cannot be used by external observers.

pub mod standard;
pub mod vrf;

// Re-export VRF variant items for backward compatibility.
// Code that needs only standard threshold signatures should use `standard::Scheme`.
#[cfg(feature = "mocks")]
pub use vrf::fixture;
pub use vrf::{decrypt, encrypt, Scheme, Seed, Seedable, Signature};
