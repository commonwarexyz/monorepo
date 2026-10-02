//! Batch verification of Ed25519 signatures over already-framed payloads.
//!
//! Validation follows ZIP215: noncanonical point encodings are accepted when they decode,
//! scalars must be canonical, and the verification equation is cofactored. Keys are grouped
//! by their original encodings, which are also used in the challenge hash.

pub(crate) mod core;

use crate::curve::{Backend, WithBackend, with_backend};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use commonware_parallel::Strategy;
use rand_core::CryptoRng;

/// Returns whether verification uses a SIMD backend on this CPU.
///
/// This uses the same dispatch as verification, including the `portable` feature override.
/// SIMD availability does not guarantee a speedup for every workload.
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

/// A batch of Ed25519 signatures over owned or borrowed payloads.
///
/// Each distinct public key is decompressed once per batch. No decoded-key cache is retained.
/// Payloads are hashed verbatim: callers must apply their protocol's namespace framing before
/// queuing them. Signature and public-key validation is deferred until verification.
pub struct Verifier<P> {
    items: Vec<(core::VerifyingKeyBytes, core::Signature, P)>,
}

impl<P: AsRef<[u8]> + Sync> Verifier<P> {
    /// Creates a verifier with space for `capacity` signatures.
    ///
    /// Bound externally supplied counts before using them as allocation hints.
    pub fn new(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    /// Queues an encoded key and signature over an already-framed payload.
    pub fn queue(&mut self, public_key: [u8; 32], signature: [u8; 64], payload: P) {
        self.items.push((
            core::VerifyingKeyBytes::new(public_key),
            core::Signature::from_bytes(signature),
            payload,
        ));
    }

    /// Checks all queued signatures using ZIP215 validation rules.
    ///
    /// Empty batches and batches larger than `u32::MAX` are rejected. Every batch of valid
    /// signatures within that limit is accepted. An invalid batch can be accepted with
    /// negligible probability (about `2^-128`) because the equation is randomized.
    ///
    /// Each call must draw fresh randomness unpredictable to whoever assembled the batch.
    #[must_use]
    pub fn verify(self, rng: &mut impl CryptoRng, strategy: &impl Strategy) -> bool {
        core::verify_batch_bytes(
            rng,
            self.items
                .iter()
                .map(|(key, sig, payload)| (key, sig, payload.as_ref())),
            strategy,
        )
    }
}
