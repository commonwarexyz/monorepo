//! Utilities for testing codec conformance.
//!
//! This module provides utilities for verifying that codec implementations
//! maintain backward compatibility by comparing encoded output against
//! known-good test vectors stored in TOML files.
//!
//! # Storage Format
//!
//! Test vectors are stored in a TOML file using the array of tables syntax:
//!
//! ```toml
//! [["Vec<u8>".cases]]
//! seed = 0
//! expected = "abc123"
//!
//! [["Vec<u8>".cases]]
//! seed = 1
//! expected = "def456"
//! ```
//!
//! # Usage
//!
//! Use the `conformance_tests!` macro to define conformance tests:
//!
//! ```ignore
//! conformance_tests! {
//!     Vec<u8> => 5,
//!     Vec<u16> => 5,
//! }
//! ```
//!
//! # Behavior
//!
//! - Missing test cases are automatically added to `codec_conformance.toml`
//! - Format changes (mismatches) cause test failures
//! - File locking prevents concurrent write corruption across processes
//!
//! # Regeneration Mode
//!
//! When `cfg(generate_conformance_tests)` is set, tests regenerate their
//! expected values in the TOML file. Use this to intentionally update
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
use std::{collections::BTreeMap, fmt::Debug, fs, path::Path};

/// A conformance test file containing test cases for multiple types.
///
/// The file is a TOML document with sections for each type name.
/// Uses `BTreeMap<String, TypeSection>` directly to produce clean TOML output.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct ConformanceFile {
    /// Test cases indexed by stringified type name.
    pub types: BTreeMap<String, TypeSection>,
}

/// Test cases for a single type.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct TypeSection {
    /// Individual test cases.
    pub cases: Vec<TestCase>,
}

/// A single test case.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TestCase {
    /// Seed used to generate the test value via proptest.
    pub seed: u64,
    /// Expected hex-encoded bytes after encoding.
    pub expected: String,
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

/// Decode a hex string into bytes.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    if !s.len().is_multiple_of(2) {
        return Err("hex string has odd length");
    }

    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex character"))
        .collect()
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

/// Result of running conformance tests for a single type.
#[derive(Debug, Default)]
pub struct ConformanceResult {
    /// Test cases that failed (format changed).
    pub failures: Vec<ConformanceFailure>,
    /// Test cases that are missing from the conformance file.
    pub missing: Vec<TestCase>,
}

/// A single conformance test failure.
#[derive(Debug)]
pub struct ConformanceFailure {
    /// The seed that produced the failure.
    pub seed: u64,
    /// The expected hex-encoded bytes.
    pub expected: String,
    /// The actual hex-encoded bytes.
    pub actual: String,
}

impl ConformanceResult {
    /// Returns true if all tests passed and no cases are missing.
    pub const fn is_ok(&self) -> bool {
        self.failures.is_empty() && self.missing.is_empty()
    }
}

/// Run conformance tests for a type.
///
/// This function is called by the `conformance_test!` macro.
///
/// # Behavior
///
/// - If test cases are missing, they are automatically added to the conformance file.
/// - If test cases exist but the encoded output differs, the test fails (format changed).
/// - When `cfg(generate_conformance_tests)` is set, outputs TOML to stdout instead
///   of modifying the file.
///
/// # Arguments
///
/// * `type_name` - The stringified type name (used as the TOML section key)
/// * `n_cases` - Number of test cases to generate (seeds 0..n_cases)
/// * `conformance_path` - Path to the conformance TOML file
///
/// # Panics
///
/// Panics if any existing test case fails (format changed).
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

/// A file-based lock for cross-process synchronization.
///
/// Uses atomic file creation to ensure only one process can hold the lock.
/// The lock file is automatically removed when dropped.
struct FileLock {
    path: std::path::PathBuf,
    _file: std::fs::File,
}

impl FileLock {
    /// Acquire an exclusive lock on the given path.
    ///
    /// Creates a `.lock` file next to the target path. Blocks until the lock
    /// is acquired, polling every 10ms.
    fn acquire(path: &Path) -> Self {
        use std::io::ErrorKind;

        let lock_path = path.with_extension("toml.lock");

        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(file) => {
                    return Self {
                        path: lock_path,
                        _file: file,
                    };
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    // Lock held by another process, wait and retry
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => {
                    panic!("failed to acquire conformance file lock: {e}");
                }
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(not(generate_conformance_tests))]
fn verify_and_update_conformance<T>(type_name: &str, n_cases: usize, path: &Path)
where
    T: Encode + for<'a> Arbitrary<'a> + Debug,
{
    let _lock = FileLock::acquire(path);

    let mut file = ConformanceFile::load_or_default(path)
        .unwrap_or_else(|e| panic!("failed to load conformance file: {e}"));

    let result = check_conformance::<T>(type_name, n_cases, &file);

    // If there are failures (format changes), panic immediately
    if !result.failures.is_empty() {
        let mut msg =
            format!("Conformance test failed for '{type_name}'.\n\nFormat changes detected:\n");
        for f in &result.failures {
            msg.push_str(&format!(
                "  seed {}: expected \"{}\" but got \"{}\"\n",
                f.seed, f.expected, f.actual
            ));
        }
        panic!("{msg}");
    }

    // If there are missing cases, add them to the file
    if !result.missing.is_empty() {
        let section = file.types.entry(type_name.to_string()).or_default();
        for case in result.missing {
            section.cases.push(case);
        }

        // Sort cases by seed for consistency
        section.cases.sort_by_key(|c| c.seed);

        // Write the updated file
        let toml_str = toml::to_string_pretty(&file).expect("failed to serialize conformance file");
        fs::write(path, toml_str).expect("failed to write conformance file");
    }
}

#[cfg(generate_conformance_tests)]
fn regenerate_conformance<T>(type_name: &str, n_cases: usize, path: &Path)
where
    T: Encode + for<'a> Arbitrary<'a> + Debug,
{
    let _lock = FileLock::acquire(path);

    let mut file = ConformanceFile::load_or_default(path)
        .unwrap_or_else(|e| panic!("failed to load conformance file: {e}"));

    // Generate new test cases for this type
    let mut cases = Vec::with_capacity(n_cases);
    for seed in 0..n_cases as u64 {
        let value: T = generate_value(seed);
        let encoded = hex_encode(&value.encode());
        cases.push(TestCase {
            seed,
            expected: encoded,
        });
    }

    // Replace the section for this type
    file.types
        .insert(type_name.to_string(), TypeSection { cases });

    // Write the updated file
    let toml_str = toml::to_string_pretty(&file).expect("failed to serialize conformance file");
    fs::write(path, toml_str).expect("failed to write conformance file");
}

/// Check conformance for a type without panicking.
///
/// Returns a [`ConformanceResult`] with any failures or missing cases.
pub fn check_conformance<T>(
    type_name: &str,
    n_cases: usize,
    file: &ConformanceFile,
) -> ConformanceResult
where
    T: Encode + for<'a> Arbitrary<'a> + Debug,
{
    let section = file.types.get(type_name);

    // Build a map of seed -> expected bytes for quick lookup
    let case_map: BTreeMap<u64, &str> = section
        .map(|s| {
            s.cases
                .iter()
                .map(|c| (c.seed, c.expected.as_str()))
                .collect()
        })
        .unwrap_or_default();

    let mut result = ConformanceResult::default();

    for seed in 0..n_cases as u64 {
        let value: T = generate_value(seed);
        let encoded = hex_encode(&value.encode());

        match case_map.get(&seed) {
            Some(expected) => {
                if *expected != encoded {
                    result.failures.push(ConformanceFailure {
                        seed,
                        expected: (*expected).to_string(),
                        actual: encoded,
                    });
                }
            }
            None => {
                result.missing.push(TestCase {
                    seed,
                    expected: encoded,
                });
            }
        }
    }

    result
}

/// Define conformance tests for codec types.
///
/// This macro generates test functions that verify encodings match expected
/// values stored in `codec_conformance.toml`.
///
/// # Usage
///
/// ```ignore
/// conformance_tests! {
///     Vec<u8> => 5,
///     Vec<u16> => 5,
///     BTreeMap<u32, String> => 5,
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
    // Base case: no more types
    ([$($counter:tt)*]) => {};

    // Recursive case: generate test, add one to counter, recurse
    ([$($counter:tt)*] $type:ty => $n_cases:expr $(, $rest_type:ty => $rest_n:expr)*) => {
        $crate::paste::paste! {
            #[test]
            fn [<test_conformance_ $($counter)* x>]() {
                $crate::conformance::run_conformance_test::<$type>(
                    stringify!($type),
                    $n_cases,
                    concat!(env!("CARGO_MANIFEST_DIR"), "/codec_conformance.toml"),
                );
            }
        }
        $crate::conformance_tests!([$($counter)* x] $($rest_type => $rest_n),*);
    };

    // Entrypoint
    ($($type:ty => $n_cases:expr),+ $(,)?) => {
        $crate::conformance_tests!([] $($type => $n_cases),+);
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
    fn test_hex_decode() {
        assert_eq!(hex_decode("").unwrap(), vec![]);
        assert_eq!(hex_decode("00").unwrap(), vec![0x00]);
        assert_eq!(hex_decode("ff").unwrap(), vec![0xff]);
        assert_eq!(
            hex_decode("1234abcd").unwrap(),
            vec![0x12, 0x34, 0xab, 0xcd]
        );
        assert_eq!(
            hex_decode("1234ABCD").unwrap(),
            vec![0x12, 0x34, 0xab, 0xcd]
        );
        assert!(hex_decode("0").is_err()); // odd length
        assert!(hex_decode("gg").is_err()); // invalid char
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
    fn test_conformance_file_parse() {
        let toml = r#"
["u32"]
cases = [
    { seed = 0, expected = "00000000" },
    { seed = 42, expected = "0000002a" },
]

["Vec<u8>"]
cases = [
    { seed = 0, expected = "00" },
]
"#;

        let file: ConformanceFile = toml::from_str(toml).unwrap();
        assert_eq!(file.types.len(), 2);
        assert!(file.types.contains_key("u32"));
        assert!(file.types.contains_key("Vec<u8>"));

        let u32_section = file.types.get("u32").unwrap();
        assert_eq!(u32_section.cases.len(), 2);
        assert_eq!(u32_section.cases[0].seed, 0);
        assert_eq!(u32_section.cases[0].expected, "00000000");
    }

    #[test]
    fn test_check_conformance_success() {
        // Generate the expected value for seed 0
        let value: u8 = generate_value(0);
        let expected = hex_encode(&crate::Encode::encode(&value));

        // Update the test to use the actual generated value
        let toml_with_actual = format!(
            r#"
["u8"]
cases = [
    {{ seed = 0, expected = "{expected}" }},
]
"#
        );
        let file: ConformanceFile = toml::from_str(&toml_with_actual).unwrap();

        let result = check_conformance::<u8>("u8", 1, &file);
        assert!(result.is_ok(), "Expected success but got: {:?}", result);
    }

    #[test]
    fn test_check_conformance_failure() {
        let toml = r#"
["u8"]
cases = [
    { seed = 0, expected = "ff" },
]
"#;
        let file: ConformanceFile = toml::from_str(toml).unwrap();

        // This should fail because the expected value is wrong
        let result = check_conformance::<u8>("u8", 1, &file);

        // The value generated for seed 0 is unlikely to be 0xff
        // If it happens to be, this test would need adjustment
        let value: u8 = generate_value(0);
        if value != 0xff {
            assert!(!result.is_ok());
            assert_eq!(result.failures.len(), 1);
            assert_eq!(result.failures[0].seed, 0);
            assert_eq!(result.failures[0].expected, "ff");
        }
    }

    #[test]
    fn test_check_conformance_missing() {
        let file = ConformanceFile::default();

        let result = check_conformance::<u8>("u8", 3, &file);

        assert!(!result.is_ok());
        assert!(result.failures.is_empty());
        assert_eq!(result.missing.len(), 3);
    }
}
