//! Automatically assert the stability of encoding and mechanisms over time.
//!
//! This crate provides a unified infrastructure for verifying that
//! implementations maintain backward compatibility by comparing output
//! against known-good hash values stored in TOML files.
//!
//! # The `Conformance` Trait
//!
//! The core abstraction is the [`Conformance`] trait, which represents
//! types that can produce deterministic bytes from a seed.
//!
//! This enables conformance testing across different domains, for example:
//! - **Codec**: Verify wire format stability
//! - **Storage**: Verify on-disk format stability
//! - **Network**: Verify message ordering consistency
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
//! The hash is computed by generating `n_cases` commitments (using seeds
//! 0..n_cases), and hashing all the bytes together.
//!
//! # Regeneration Mode
//!
//! When `cfg(generate_conformance_tests)` is set, tests regenerate their
//! expected hashes in the TOML file. Use this to intentionally update
//! the format:
//!
//! ```bash
//! RUSTFLAGS="--cfg generate_conformance_tests" cargo test
//! ```

// Re-export commonware_macros for use in macros
#[doc(hidden)]
pub use commonware_macros;
use core::future::Future;
// Re-export futures for use in macros
#[doc(hidden)]
pub use futures;
// Re-export paste for use in macros
#[doc(hidden)]
pub use paste;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

/// Default number of test cases when not explicitly specified.
pub const DEFAULT_CASES: usize = 65536;

/// Trait for types that can produce deterministic bytes for conformance testing.
///
/// Implementations must be deterministic: the same seed must always produce
/// the same output across runs and platforms.
///
/// # Example
///
/// ```rs
/// use commonware_conformance::Conformance;
///
/// struct MyConformance;
///
/// impl Conformance for MyConformance {
///     async fn commit(seed: u64) -> Vec<u8> {
///         // Generate deterministic bytes from the seed
///         seed.to_le_bytes().to_vec()
///     }
/// }
/// ```
pub trait Conformance: Send + Sync {
    /// Produce deterministic bytes from a seed for conformance testing.
    ///
    /// The implementation should use the seed to generate deterministic
    /// test data and return a byte vector representing the commitment.
    fn commit(seed: u64) -> impl Future<Output = Vec<u8>> + Send;
}

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
    /// Hex-encoded SHA-256 hash of all committed values concatenated together.
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
            Self::Io(path, err) => write!(f, "failed to read {}: {}", path.display(), err),
            Self::Parse(path, err) => write!(f, "failed to parse {}: {}", path.display(), err),
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
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(HEX_CHARS[(byte >> 4) as usize] as char);
        result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    result
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

/// Compute the conformance hash for a type using the [`Conformance`] trait.
///
/// Generates `n_cases` commitments (using seeds 0..n_cases), and hashes
/// all the bytes together using SHA-256.
pub async fn compute_conformance_hash<C: Conformance>(n_cases: usize) -> String {
    let mut hasher = Sha256::new();

    for seed in 0..n_cases as u64 {
        let committed = C::commit(seed).await;

        // Write length prefix to avoid ambiguity between concatenated values
        hasher.update((committed.len() as u64).to_le_bytes());
        hasher.update(&committed);
    }

    hex_encode(&hasher.finalize())
}

/// Run conformance tests using the [`Conformance`] trait.
///
/// This function is the generic version that works with any `Conformance`
/// implementation.
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
pub async fn run_conformance_test<C: Conformance>(
    type_name: &str,
    n_cases: usize,
    conformance_path: &Path,
) {
    #[cfg(generate_conformance_tests)]
    {
        regenerate_conformance::<C>(type_name, n_cases, conformance_path).await;
    }

    #[cfg(not(generate_conformance_tests))]
    {
        verify_and_update_conformance::<C>(type_name, n_cases, conformance_path).await;
    }
}

#[cfg(not(generate_conformance_tests))]
async fn verify_and_update_conformance<C: Conformance>(
    type_name: &str,
    n_cases: usize,
    path: &Path,
) {
    use std::io::{Read, Seek, Write};

    // Compute the hash first WITHOUT holding the lock - this is the expensive part
    // and can run in parallel across all conformance tests
    let actual_hash = compute_conformance_hash::<C>(n_cases).await;

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
async fn regenerate_conformance<C: Conformance>(type_name: &str, n_cases: usize, path: &Path) {
    use std::io::{Read, Seek, Write};

    // Compute the hash first WITHOUT holding the lock - this is the expensive part
    // and can run in parallel across all conformance tests
    let hash = compute_conformance_hash::<C>(n_cases).await;

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

/// Define conformance tests for [`Conformance`] types.
///
/// This macro generates test functions that verify encodings match expected
/// hash values stored in `conformance.toml`.
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
            #[$crate::commonware_macros::test_group("conformance")]
            #[test]
            fn [<test_conformance_ $($counter)* x>]() {
                $crate::futures::executor::block_on($crate::run_conformance_test::<$type>(
                    concat!(module_path!(), "::", stringify!($type)),
                    $n_cases,
                    std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance.toml")),
                ));
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
        $crate::conformance_tests!(@emit [$($counter)*] $type, $crate::DEFAULT_CASES);
        $crate::conformance_tests!(@internal [$($counter)* x] $($rest)*);
    };

    // Case: Type (no trailing comma, last item with default)
    (@internal [$($counter:tt)*] $type:ty) => {
        $crate::conformance_tests!(@emit [$($counter)*] $type, $crate::DEFAULT_CASES);
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

    // Test conformance trait with a simple implementation
    struct SimpleConformance;

    impl Conformance for SimpleConformance {
        async fn commit(seed: u64) -> Vec<u8> {
            seed.to_le_bytes().to_vec()
        }
    }

    #[test]
    fn test_compute_conformance_hash_deterministic() {
        let hash_1 = futures::executor::block_on(compute_conformance_hash::<SimpleConformance>(1));
        let hash_2 = futures::executor::block_on(compute_conformance_hash::<SimpleConformance>(1));
        assert_eq!(hash_1, hash_2);
    }

    #[test]
    fn test_compute_conformance_hash_different_n_cases() {
        let hash_10 =
            futures::executor::block_on(compute_conformance_hash::<SimpleConformance>(10));
        let hash_20 =
            futures::executor::block_on(compute_conformance_hash::<SimpleConformance>(20));
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
