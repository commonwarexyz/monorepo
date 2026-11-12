//! Benchmarks of the group operations.
//!
//! The benchmarks compare the public API with blst on the same inputs: addition, doubling,
//! multiplication by a scalar, sums, and multi-scalar multiplications in G1 and G2, and single
//! and multiple pairings.
//!
//! # Roadmap
//!
//! Threshold signatures, multisignatures, and batch verification need pairing-product checks
//! ([`multi_pairing`]), single and independent pairings ([`pairing`]), multi-scalar
//! multiplication ([`msm`]), sums of points ([`sum`]), and variable-base scalar multiplication
//! ([`mul`]), which the benchmarks above measure. Benchmarks to add, many for operations the
//! crate does not implement yet:
//!
//! - Miller loops and final exponentiation measured separately.
//! - Hash-to-G1 and hash-to-G2 for new messages.
//! - Fixed-base scalar multiplication in G1 and G2 for signing, public-key derivation, and
//!   batch-verification weights.
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

use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod add;
mod double;
mod msm;
mod mul;
mod multi_pairing;
mod pairing;
mod sum;
mod utils;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(
    add::benches,
    double::benches,
    msm::benches,
    mul::benches,
    multi_pairing::benches,
    pairing::benches,
    sum::benches
);
