//! Shared input generators for storage fuzz targets.

use arbitrary::Unstructured;
use commonware_utils::{Probability, probability};

/// Generate a logical page size in `1..=256`.
pub fn bounded_page_size(u: &mut Unstructured<'_>) -> arbitrary::Result<u16> {
    u.int_in_range(1..=256)
}

/// Generate a page-cache size in `1..=16`.
pub fn bounded_page_cache_size(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    u.int_in_range(1..=16)
}

/// Generate an item count in `1..=64`.
pub fn bounded_items(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    u.int_in_range(1..=64)
}

/// Generate a buffer size in `1..=2048`.
pub fn bounded_buffer(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    u.int_in_range(1..=2048)
}

/// Generate a nonzero failure rate in `(0, 1]` at percentage granularity.
pub fn bounded_nonzero_rate(u: &mut Unstructured<'_>) -> arbitrary::Result<Probability> {
    let percent: u8 = u.int_in_range(1..=100)?;
    Ok(probability!(u64::from(percent), 100))
}
