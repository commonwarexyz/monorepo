//! Codec-specific [`commonware_conformance`] testing utilities.
//!
//! This module provides utilities for verifying that codec implementations
//! maintain backward compatibility by comparing encoded output against
//! known-good hash values stored in TOML files.

use crate::Encode;
use arbitrary::{Arbitrary, Unstructured};
use commonware_conformance::Conformance;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::{fmt::Debug, marker::PhantomData};

/// Initial size of the random buffer used for generating arbitrary values.
const INITIAL_BUFFER_SIZE: usize = 4096;

/// Maximum buffer size to try before giving up (16 MB).
const MAX_BUFFER_SIZE: usize = 16 * 1024 * 1024;

/// Generate a deterministic value of type `T` using the given seed.
///
/// Uses the [`arbitrary`] crate with a seeded ChaCha RNG for reproducible
/// value generation. If the initial buffer is insufficient, the buffer size
/// is doubled until generation succeeds or the maximum size is reached.
/// On `IncorrectFormat` (e.g. `NonZeroU16` rejecting zero bytes), the
/// rejected bytes are already consumed so retrying reads fresh bytes from
/// the same deterministic buffer.
pub fn generate_value<T>(seed: u64) -> T
where
    T: for<'a> Arbitrary<'a>,
{
    let mut buffer_size = INITIAL_BUFFER_SIZE;
    loop {
        // Create a seeded RNG
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        // Generate random bytes for the Unstructured input
        let mut buffer = vec![0u8; buffer_size];
        rng.fill(&mut buffer[..]);

        // Try to generate the arbitrary value
        let mut unstructured = Unstructured::new(&buffer);
        loop {
            match T::arbitrary(&mut unstructured) {
                Ok(value) => return value,
                Err(arbitrary::Error::IncorrectFormat) => continue,
                Err(arbitrary::Error::NotEnoughData) => break,
                Err(e) => panic!("failed to generate arbitrary value: {e}"),
            }
        }

        // Give up if we've already tried the maximum size
        if buffer_size >= MAX_BUFFER_SIZE {
            panic!("failed to generate arbitrary value: NotEnoughData with {buffer_size} bytes");
        }

        // Double the buffer size (capped at MAX) and retry
        buffer_size = (buffer_size * 2).min(MAX_BUFFER_SIZE);
    }
}

/// Marker type for codec conformance testing.
///
/// This wrapper is used to bridge types that implement [`Encode`] and [`Arbitrary`]
/// with the [`Conformance`] trait.
///
/// # Usage
///
/// This type is typically in [`commonware_conformance::conformance_tests!`] macro:
///
/// ```rust,ignore
/// commonware_conformance::conformance_tests! {
///     CodecConformance<MyType>,           // Uses default case count
///     CodecConformance<OtherType> => 100, // Explicit case count
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct CodecConformance<T>(PhantomData<T>);

/// Implement the [`Conformance`] trait for [`CodecConformance<T>`].
///
/// This implementation generates a deterministic value using [`Arbitrary`],
/// then encodes it using the [`Encode`] trait.
impl<T> Conformance for CodecConformance<T>
where
    T: Encode + for<'a> Arbitrary<'a> + Send + Sync,
{
    async fn commit(seed: u64) -> Vec<u8> {
        let value: T = generate_value(seed);
        value.encode().to_vec()
    }
}
