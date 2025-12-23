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

/// Size of the random buffer used for generating arbitrary values.
///
/// This should be large enough to generate complex nested types.
const ARBITRARY_BUFFER_SIZE: usize = 4096;

/// Generate a deterministic value of type `T` using the given seed.
///
/// Uses the [`arbitrary`] crate with a seeded ChaCha RNG for reproducible
/// value generation.
pub fn generate_value<T>(seed: u64) -> T
where
    T: for<'a> Arbitrary<'a>,
{
    // Create a seeded RNG
    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    // Generate random bytes for the Unstructured input
    let mut buffer = vec![0u8; ARBITRARY_BUFFER_SIZE];
    rng.fill(&mut buffer[..]);

    // Generate the arbitrary value
    let mut unstructured = Unstructured::new(&buffer);
    T::arbitrary(&mut unstructured).expect("failed to generate arbitrary value")
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
