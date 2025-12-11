//! Utilities for testing codec conformance.
//!
//! This module provides utilities for verifying that codec implementations
//! maintain backward compatibility by comparing encoded output against
//! known-good hash values stored in TOML files.
//!
//! # Storage Format
//!
//! Test vectors are stored in a TOML file with a single hash per type:
//!
//! ```toml
//! ["Vec<u8>"]
//! n_cases = 100
//! hash = "abc123..."
//!
//! ["Vec<u16>"]
//! n_cases = 100
//! hash = "def456..."
//! ```
//!
//! The hash is computed by generating `n_cases` arbitrary values (using seeds
//! 0..n_cases), encoding each one, and hashing all the encoded bytes together.
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
//! # Behavior
//!
//! - Missing types are automatically added to `codec_conformance.toml`
//! - Format changes (hash mismatches) cause test failures
//! - File locking prevents concurrent write corruption across processes
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

use crate::Encode;
use arbitrary::{Arbitrary, Unstructured};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt::Debug, fs, path::Path};

/// A conformance test file containing test data for multiple types.
///
/// The file is a TOML document with sections for each type name.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct ConformanceFile {
    /// Test data indexed by stringified type name.
    pub types: BTreeMap<String, TypeEntry>,
}

/// Conformance test data for a single type.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TypeEntry {
    /// Number of test cases that were hashed together.
    pub n_cases: usize,
    /// Hex-encoded SHA-256 hash of all encoded values concatenated together.
    pub hash: String,
}

/// Errors that can occur when loading conformance files.
#[derive(Debug)]
pub enum ConformanceError {
    /// Failed to read the file.
    Io(std::path::PathBuf, std::io::Error),
    /// Failed to parse the TOML.
    Parse(std::path::PathBuf, toml::de::Error),
}

impl std::fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, e) => write!(f, "failed to read {}: {}", path.display(), e),
            Self::Parse(path, e) => write!(f, "failed to parse {}: {}", path.display(), e),
        }
    }
}

impl std::error::Error for ConformanceError {}

impl ConformanceFile {
    /// Load a conformance file from the given path.
    pub fn load(path: &Path) -> Result<Self, ConformanceError> {
        let contents =
            fs::read_to_string(path).map_err(|e| ConformanceError::Io(path.to_path_buf(), e))?;
        toml::from_str(&contents).map_err(|e| ConformanceError::Parse(path.to_path_buf(), e))
    }

    /// Load a conformance file, returning an empty file if it doesn't exist.
    pub fn load_or_default(path: &Path) -> Result<Self, ConformanceError> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self::default())
        }
    }
}

/// Encode bytes as a lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(HEX_CHARS[(byte >> 4) as usize] as char);
        result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    result
}

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

/// Compute the conformance hash for a type.
///
/// Generates `n_cases` arbitrary values, encodes each one, and hashes
/// all the encoded bytes together using SHA-256.
pub fn compute_conformance_hash<T>(n_cases: usize) -> String
where
    T: Encode + for<'a> Arbitrary<'a>,
{
    let mut hasher = Sha256::new();

    for seed in 0..n_cases as u64 {
        let value: T = generate_value(seed);
        let encoded = value.encode();

        // Write length prefix to avoid ambiguity between concatenated values
        hasher.update((encoded.len() as u64).to_le_bytes());
        hasher.update(&encoded);
    }

    hex_encode(&hasher.finalize())
}

/// Run conformance tests for a type.
///
/// This function is called by the `conformance_test!` macro.
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
    T: Encode + for<'a> Arbitrary<'a> + Debug,
{
    let path = Path::new(conformance_path);

    #[cfg(generate_conformance_tests)]
    {
        regenerate_conformance::<T>(type_name, n_cases, path);
    }

    #[cfg(not(generate_conformance_tests))]
    {
        verify_and_update_conformance::<T>(type_name, n_cases, path);
    }
}

/// Acquire an exclusive lock on the conformance file.
///
/// Uses OS-level file locking which is automatically released when the
/// process exits, even if killed.
fn acquire_lock(path: &Path) -> fs::File {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap_or_else(|e| panic!("failed to open conformance file: {e}"));

    file.lock()
        .unwrap_or_else(|e| panic!("failed to lock conformance file: {e}"));

    file
}

#[cfg(not(generate_conformance_tests))]
fn verify_and_update_conformance<T>(type_name: &str, n_cases: usize, path: &Path)
where
    T: Encode + for<'a> Arbitrary<'a> + Debug,
{
    use std::io::{Read, Seek, Write};

    // Compute the hash first WITHOUT holding the lock - this is the expensive part
    // and can run in parallel across all conformance tests
    let actual_hash = compute_conformance_hash::<T>(n_cases);

    // Now acquire the lock only for file I/O
    let mut lock = acquire_lock(path);

    let mut contents = String::new();
    lock.read_to_string(&mut contents)
        .unwrap_or_else(|e| panic!("failed to read conformance file: {e}"));

    let mut file: ConformanceFile = if contents.is_empty() {
        ConformanceFile::default()
    } else {
        toml::from_str(&contents)
            .unwrap_or_else(|e| panic!("failed to parse conformance file: {e}"))
    };

    match file.types.get(type_name) {
        Some(entry) => {
            // Verify the hash matches
            if entry.hash != actual_hash {
                panic!(
                    "Conformance test failed for '{type_name}'.\n\n\
                     Format change detected:\n\
                     - expected: \"{}\"\n\
                     - actual:   \"{actual_hash}\"\n\n\
                     If this change is intentional, regenerate with:\n\
                     RUSTFLAGS=\"--cfg generate_conformance_tests\" cargo test",
                    entry.hash
                );
            }
            // Verify n_cases matches
            if entry.n_cases != n_cases {
                panic!(
                    "Conformance test failed for '{type_name}'.\n\n\
                     n_cases mismatch: expected {}, got {n_cases}\n\n\
                     If this change is intentional, regenerate with:\n\
                     RUSTFLAGS=\"--cfg generate_conformance_tests\" cargo test",
                    entry.n_cases
                );
            }
        }
        None => {
            // Add the missing entry
            file.types.insert(
                type_name.to_string(),
                TypeEntry {
                    n_cases,
                    hash: actual_hash,
                },
            );

            // Write the updated file
            let toml_str =
                toml::to_string_pretty(&file).expect("failed to serialize conformance file");
            lock.set_len(0)
                .expect("failed to truncate conformance file");
            lock.seek(std::io::SeekFrom::Start(0))
                .expect("failed to seek conformance file");
            lock.write_all(toml_str.as_bytes())
                .expect("failed to write conformance file");
        }
    }
}

#[cfg(generate_conformance_tests)]
fn regenerate_conformance<T>(type_name: &str, n_cases: usize, path: &Path)
where
    T: Encode + for<'a> Arbitrary<'a> + Debug,
{
    use std::io::{Read, Seek, Write};

    // Compute the hash first WITHOUT holding the lock - this is the expensive part
    // and can run in parallel across all conformance tests
    let hash = compute_conformance_hash::<T>(n_cases);

    // Now acquire the lock only for file I/O
    let mut lock = acquire_lock(path);

    let mut contents = String::new();
    lock.read_to_string(&mut contents)
        .unwrap_or_else(|e| panic!("failed to read conformance file: {e}"));

    let mut file: ConformanceFile = if contents.is_empty() {
        ConformanceFile::default()
    } else {
        toml::from_str(&contents)
            .unwrap_or_else(|e| panic!("failed to parse conformance file: {e}"))
    };

    // Update or insert the entry for this type
    file.types
        .insert(type_name.to_string(), TypeEntry { n_cases, hash });

    // Write the updated file
    let toml_str = toml::to_string_pretty(&file).expect("failed to serialize conformance file");
    lock.set_len(0)
        .expect("failed to truncate conformance file");
    lock.seek(std::io::SeekFrom::Start(0))
        .expect("failed to seek conformance file");
    lock.write_all(toml_str.as_bytes())
        .expect("failed to write conformance file");
}

/// Default number of test cases when not explicitly specified.
pub const DEFAULT_N_CASES: usize = 65536;

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
            #[commonware_macros::test_group("codec_conformance")]
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

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0x12, 0x34, 0xab, 0xcd]), "1234abcd");
    }

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
    fn test_compute_conformance_hash_deterministic() {
        let hash1 = compute_conformance_hash::<u32>(10);
        let hash2 = compute_conformance_hash::<u32>(10);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_conformance_hash_different_types() {
        let hash_u32 = compute_conformance_hash::<u32>(10);
        let hash_u64 = compute_conformance_hash::<u64>(10);
        assert_ne!(hash_u32, hash_u64);
    }

    #[test]
    fn test_compute_conformance_hash_different_n_cases() {
        let hash_10 = compute_conformance_hash::<u32>(10);
        let hash_20 = compute_conformance_hash::<u32>(20);
        assert_ne!(hash_10, hash_20);
    }

    #[test]
    fn test_conformance_file_parse() {
        let toml = r#"
["u32"]
n_cases = 100
hash = "abc123"

["Vec<u8>"]
n_cases = 50
hash = "def456"
"#;

        let file: ConformanceFile = toml::from_str(toml).unwrap();
        assert_eq!(file.types.len(), 2);
        assert!(file.types.contains_key("u32"));
        assert!(file.types.contains_key("Vec<u8>"));

        let u32_entry = file.types.get("u32").unwrap();
        assert_eq!(u32_entry.n_cases, 100);
        assert_eq!(u32_entry.hash, "abc123");
    }
}
