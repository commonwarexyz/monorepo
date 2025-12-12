//! Codec-specific [conformance] testing utilities.
//!
//! This module provides utilities for verifying that codec implementations
//! maintain backward compatibility by comparing encoded output against
//! known-good hash values stored in TOML files.
//!
//! # Usage
//!
//! Use the `conformance_tests!` macro to define conformance tests:
//!
//! ```ignore
//! conformance_tests! {
//!     Vec<u8>,            // Uses default (65536 cases)
//!     Vec<u16> => 100,    // Explicit case count
//! }
//! ```
//!
//! # Regeneration Mode
//!
//! When `cfg(generate_conformance_tests)` is set, tests regenerate their
//! expected hashes in the TOML file. Use this to intentionally update
//! the codec format:
//!
//! ```bash
//! RUSTFLAGS="--cfg generate_conformance_tests" cargo test
//! ```
//!
//! [conformance]: commonware_conformance

use crate::Encode;
use arbitrary::{Arbitrary, Unstructured};
use commonware_conformance::Conformance;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::{fmt::Debug, marker::PhantomData, path::Path};

/// Default number of test cases when not explicitly specified.
pub const DEFAULT_N_CASES: usize = 65536;

/// Size of the random buffer used for generating arbitrary values.
///
/// This should be large enough to generate complex nested types.
const ARBITRARY_BUFFER_SIZE: usize = 4096;

/// Generate a deterministic value of type `T` using the given seed.
///
/// Uses the `arbitrary` crate with a seeded ChaCha RNG for reproducible
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
/// This wrapper is used to bridge types that implement `Encode + Arbitrary`
/// with the [`Conformance`] trait.
///
/// # Usage
///
/// This type is typically used internally by the `conformance_tests!` macro:
///
/// ```ignore
/// use commonware_codec::conformance::CodecConformance;
///
/// let conformance = CodecConformance::<Vec<u8>>::default();
/// ```
#[derive(Debug, Clone, Copy)]
pub struct CodecConformance<T>(PhantomData<T>);

impl<T> Default for CodecConformance<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

/// Implement the [`Conformance`] trait for [`CodecConformance<T>`].
///
/// This implementation generates a deterministic value using `Arbitrary`,
/// then encodes it using the `Encode` trait.
impl<T> Conformance for CodecConformance<T>
where
    T: Encode + for<'a> Arbitrary<'a> + Send + Sync,
{
    async fn commit(&self, seed: u64) -> Vec<u8> {
        let value: T = generate_value(seed);
        value.encode().to_vec()
    }
}

/// Run conformance tests for a codec type.
///
/// This function is called by the `conformance_tests!` macro.
///
/// # Behavior
///
/// - If the type is missing from the file, it is automatically added.
/// - If the hash differs, the test fails (format changed).
/// - When `cfg(generate_conformance_tests)` is set, regenerates the hash.
///
/// # Arguments
///
/// * `type_name` - The stringified type name (used as the TOML section key)
/// * `n_cases` - Number of test cases to hash together (seeds 0..n_cases)
/// * `conformance_path` - Path to the conformance TOML file
///
/// # Panics
///
/// Panics if the hash doesn't match (format changed).
pub fn run_conformance_test<T>(type_name: &str, n_cases: usize, conformance_path: &str)
where
    T: Encode + for<'a> Arbitrary<'a> + Debug + Send + Sync,
{
    let conformance = CodecConformance::<T>::default();
    let path = Path::new(conformance_path);
    futures::executor::block_on(commonware_conformance::run_conformance_test(
        &conformance,
        type_name,
        n_cases,
        path,
    ));
}

/// Define conformance tests for codec types.
///
/// This macro generates test functions that verify encodings match expected
/// hash values stored in `codec_conformance.toml`.
///
/// # Usage
///
/// ```ignore
/// conformance_tests! {
///     Vec<u8>,                       // Uses default (65536 cases)
///     Vec<u16> => 100,               // Explicit case count
///     BTreeMap<u32, String> => 100,
/// }
/// ```
///
/// Test names are auto-generated. The type name is used as the key in the TOML file.
///
/// # Regeneration Mode
///
/// When `cfg(generate_conformance_tests)` is set, tests regenerate their
/// expected values in the TOML file (useful for intentional format changes):
///
/// ```bash
/// RUSTFLAGS="--cfg generate_conformance_tests" cargo test -p my_crate conformance
/// ```
#[macro_export]
macro_rules! conformance_tests {
    // Helper to emit a single test
    (@emit [$($counter:tt)*] $type:ty, $n_cases:expr) => {
        $crate::paste::paste! {
            #[commonware_macros::test_group("conformance")]
            #[test]
            fn [<test_conformance_ $($counter)* x>]() {
                $crate::conformance::run_conformance_test::<$type>(
                    concat!(module_path!(), "::", stringify!($type)),
                    $n_cases,
                    concat!(env!("CARGO_MANIFEST_DIR"), "/codec_conformance.toml"),
                );
            }
        }
    };

    // Base case: nothing left
    (@internal [$($counter:tt)*]) => {};

    // Case: Type => n_cases, rest...
    (@internal [$($counter:tt)*] $type:ty => $n_cases:expr, $($rest:tt)*) => {
        $crate::conformance_tests!(@emit [$($counter)*] $type, $n_cases);
        $crate::conformance_tests!(@internal [$($counter)* x] $($rest)*);
    };

    // Case: Type => n_cases (no trailing comma, last item)
    (@internal [$($counter:tt)*] $type:ty => $n_cases:expr) => {
        $crate::conformance_tests!(@emit [$($counter)*] $type, $n_cases);
    };

    // Case: Type, rest...
    (@internal [$($counter:tt)*] $type:ty, $($rest:tt)*) => {
        $crate::conformance_tests!(@emit [$($counter)*] $type, $crate::conformance::DEFAULT_N_CASES);
        $crate::conformance_tests!(@internal [$($counter)* x] $($rest)*);
    };

    // Case: Type (no trailing comma, last item with default)
    (@internal [$($counter:tt)*] $type:ty) => {
        $crate::conformance_tests!(@emit [$($counter)*] $type, $crate::conformance::DEFAULT_N_CASES);
    };

    // Entrypoint
    ($($input:tt)*) => {
        $crate::conformance_tests!(@internal [] $($input)*);
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    #[test]
    fn test_generate_value_deterministic() {
        // Same seed should produce same value
        let v1: u32 = generate_value(42);
        let v2: u32 = generate_value(42);
        assert_eq!(v1, v2);

        // Different seeds should (usually) produce different values
        let v3: u32 = generate_value(43);
        // Note: This could theoretically be equal, but extremely unlikely
        assert_ne!(v1, v3);
    }

    #[test]
    fn test_codec_conformance_impl() {
        // Test that the Conformance impl for CodecConformance works
        let conformance = CodecConformance::<u32>::default();

        // Generate commitment for seed 0
        let commitment1 = block_on(conformance.commit(0));
        let commitment2 = block_on(conformance.commit(0));

        // Same seed should produce same commitment
        assert_eq!(commitment1, commitment2);

        // Different seeds should produce different commitments
        let commitment3 = block_on(conformance.commit(1));
        assert_ne!(commitment1, commitment3);
    }

    #[test]
    fn test_codec_conformance_matches_direct_encode() {
        // Verify that the Conformance impl produces the same output as direct encoding
        let conformance = CodecConformance::<u32>::default();

        for seed in 0..10 {
            let commitment = block_on(conformance.commit(seed));

            // Generate the same value and encode directly
            let value: u32 = generate_value(seed);
            let encoded = value.encode().to_vec();

            assert_eq!(commitment, encoded);
        }
    }
}
