//! Shared crash-choreography scaffolding for storage fuzz targets: deterministic-runner
//! construction, crash-cycle splitting, fault-injection presets, and bounded parameter
//! generators. Per-structure init, operation, and verification logic stays in each target.

use arbitrary::Unstructured;
use commonware_runtime::deterministic;
use commonware_utils::FuzzRng;

/// Bytes reserved for deterministic runtime choices.
pub const RNG_BYTES: usize = 32;

/// Construct a deterministic runner whose runtime choices (including crash-byte survival
/// sampling) are driven by fuzzer-controlled bytes.
pub fn fuzz_runner(raw_bytes: &[u8; RNG_BYTES]) -> deterministic::Runner {
    let rng = FuzzRng::new(raw_bytes.to_vec());
    deterministic::Runner::new(deterministic::Config::default().with_rng(Box::new(rng)))
}

/// Split the operation stream into one list per checkpoint cycle, cutting at each operation for
/// which `is_crash` returns true. Always returns at least one list (possibly empty), so a bare
/// recovery is still exercised.
pub fn split_cycles<T>(
    operations: impl IntoIterator<Item = T>,
    is_crash: impl Fn(&T) -> bool,
) -> Vec<Vec<T>> {
    let mut cycles = Vec::new();
    let mut current = Vec::new();
    for operation in operations {
        if is_crash(&operation) {
            cycles.push(std::mem::take(&mut current));
        } else {
            current.push(operation);
        }
    }
    cycles.push(current);
    cycles
}

/// Fault preset for interrupting a multi-step storage operation (destroy, prune) at any of its
/// awaits: writes, syncs, and removals may all fail, and a failed write persists an arbitrary
/// byte subset.
pub fn interrupt_faults() -> deterministic::FaultConfig {
    deterministic::FaultConfig::default()
        .write(0.5)
        .partial_write(1.0)
        .sync(0.5)
        .remove(0.5)
}

/// Fault preset for interrupting blob removals only.
pub fn remove_faults() -> deterministic::FaultConfig {
    deterministic::FaultConfig::default().remove(0.5)
}

/// Page size for the buffer pool (1-256 bytes).
pub fn bounded_page_size(u: &mut Unstructured<'_>) -> arbitrary::Result<u16> {
    u.int_in_range(1..=256)
}

/// Number of pages in the buffer-pool cache (1-16).
pub fn bounded_page_cache_size(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    u.int_in_range(1..=16)
}

/// Items per journal section (or blob, for the structures that name it that way).
pub fn bounded_items_per_section(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    u.int_in_range(1..=64)
}

/// A fault rate in [0.0, 1.0]. Allows 0 so the fuzzer can disable individual fault types.
pub fn bounded_rate(u: &mut Unstructured<'_>) -> arbitrary::Result<f64> {
    let percent: u8 = u.int_in_range(0..=100)?;
    Ok(f64::from(percent) / 100.0)
}
