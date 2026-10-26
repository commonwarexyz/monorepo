//! BLS12-381 cryptography.
//!
//! # Benchmark priorities
//!
//! The benchmarks of interest are the primitives needed for threshold signatures,
//! multisignatures, and batch verification:
//!
//! - Pairing-product checks: a multi-Miller loop followed by one final exponentiation,
//!   especially for two terms (single-signature verification) and `n + 1` terms
//!   (distinct-message aggregate verification).
//! - Single pairings and multiple independent pairings, with Miller loops and final
//!   exponentiation also measured separately.
//! - Multi-scalar multiplication (MSM) in G1 and G2 for threshold reconstruction and
//!   randomized batch verification.
//! - Sums of points in G1 and G2 for signature and public-key aggregation.
//! - Hash-to-G1 and hash-to-G2 for new messages.
//! - Fixed-base and variable-base scalar multiplication in G1 and G2 for signing,
//!   public-key derivation, and batch-verification weights.
//! - Compressed point decoding and subgroup validation for signatures and public keys
//!   received from the network.
//! - Batch conversion to affine coordinates for MSMs, pairings, and serialization.
//! - Lagrange-coefficient computation, including scalar batch inversion, for threshold
//!   reconstruction.
//!
//! Complete workloads should complement these primitive benchmarks:
//!
//! - Verify a reconstructed threshold signature: hash one message and perform a
//!   two-term pairing check. Reconstruction is measured separately as coefficient
//!   computation followed by an MSM over the signature shares.
//! - Verify a same-message multisignature with validated proofs of possession: sum the
//!   selected public keys, hash the message, and perform a two-term pairing check.
//!   Measure both cached and freshly aggregated public keys.
//! - Verify a distinct-message aggregate: hash `n` messages and perform an `n + 1`-term
//!   pairing check.
//! - Verify batches of individual signatures or shares with randomized weights,
//!   covering both shared and distinct messages.
//!
//! Cover both signature/public-key group orientations and sweep input sizes such as
//! `1`, `2`, `8`, `32`, `128`, and `512`. Measure operations on prepared inputs as well
//! as the cost including preparation, especially pairing preparation, affine
//! conversion, reusable MSM tables, and Lagrange coefficients.

#![cfg_attr(not(any(feature = "std", test)), no_std)]

// Higher stability levels compile every ALPHA module out, leaving no user of alloc.
#[cfg(not(any(
    commonware_stability_BETA,
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))]
extern crate alloc;

commonware_macros::stability_mod!(ALPHA, mod algebra);
commonware_macros::stability_mod!(ALPHA, mod curve);
commonware_macros::stability_mod!(ALPHA, mod debug_counter);
commonware_macros::stability_mod!(ALPHA, mod montgomery);
commonware_macros::stability_mod!(ALPHA, pub mod fp);
commonware_macros::stability_mod!(ALPHA, pub mod fp2);
commonware_macros::stability_mod!(ALPHA, pub mod fp6);
commonware_macros::stability_mod!(ALPHA, pub mod fp12);
commonware_macros::stability_mod!(ALPHA, pub mod g1);
commonware_macros::stability_mod!(ALPHA, pub mod g2);
commonware_macros::stability_mod!(ALPHA, mod group);
commonware_macros::stability_mod!(ALPHA, mod hash);
commonware_macros::stability_mod!(ALPHA, pub mod pairing);
commonware_macros::stability_mod!(ALPHA, pub mod scalar);
