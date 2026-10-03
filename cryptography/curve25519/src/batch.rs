//! Batch verification of Ed25519 signatures over already-framed payloads.
//!
//! Validation follows ZIP215: noncanonical point encodings are accepted when they decode,
//! scalars must be canonical, and the verification equation is cofactored. Keys are grouped
//! by their original encodings, which are also used in the challenge hash.

pub(crate) mod core;

use crate::curve::{Backend, WithBackend, with_backend};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;

/// Returns whether verification uses a SIMD backend on this CPU.
///
/// This uses the same backend selection as [`verify`]. SIMD availability does not guarantee a
/// speedup for every workload.
pub fn is_accelerated() -> bool {
    struct Detect;
    impl WithBackend for Detect {
        type Output = bool;

        fn call<B: Backend>(self, _: B) -> bool {
            B::IS_ACCELERATED
        }
    }
    with_backend(Detect)
}

/// Checks Ed25519 signatures using ZIP215 validation rules.
///
/// Each item is an encoded public key, an encoded signature, and the payload it signs. Payloads
/// are hashed verbatim: callers must apply their protocol's namespace framing first. Each
/// distinct public key is decompressed once per call.
///
/// Empty batches and batches larger than `u32::MAX` are rejected. Every batch of valid
/// signatures within that limit is accepted. An invalid batch can be accepted with negligible
/// probability (about `2^-128`) because the equation is randomized.
///
/// Each call must draw fresh randomness unpredictable to whoever assembled the batch.
#[must_use]
pub fn verify<'a>(
    rng: &mut impl CryptoRng,
    items: impl IntoIterator<Item = ([u8; 32], [u8; 64], &'a [u8])>,
    strategy: &impl Strategy,
) -> bool {
    core::verify_batch_bytes(
        rng,
        items.into_iter().map(|(public_key, signature, payload)| {
            (
                core::VerifyingKeyBytes::new(public_key),
                core::Signature::from_bytes(signature),
                payload,
            )
        }),
        strategy,
    )
}
