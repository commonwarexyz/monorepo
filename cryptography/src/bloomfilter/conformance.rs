//! BloomFilter conformance tests

use super::{BloomFilter, Sha256};
use commonware_codec::conformance::CodecConformance;
use commonware_conformance::Conformance;
use core::num::NonZeroUsize;

commonware_conformance::conformance_tests! {
    CodecConformance<BloomFilter>,
    FpRateBuckets => 1024,
}

/// Conformance test for FP rate bucket calculations and with_rate constructor.
/// Verifies that optimal_bits, optimal_hashers, and with_rate produce stable
/// outputs across all four FP rate buckets for various expected_items values.
struct FpRateBuckets;

impl Conformance for FpRateBuckets {
    async fn commit(seed: u64) -> Vec<u8> {
        let mut log = Vec::new();

        // Use seed to vary expected_items (1 to 1M range)
        let expected_items = ((seed % 1_000_000) + 1) as usize;

        // Test all four FP rate buckets with representative values
        let fp_rates = [
            0.0001, // FP_1E4 bucket (~0.01%)
            0.001,  // FP_1E3 bucket (~0.1%)
            0.01,   // FP_1E2 bucket (~1%)
            0.1,    // FP_1E1 bucket (~10%)
        ];

        for &fp_rate in &fp_rates {
            // Test individual functions
            let bits = BloomFilter::<Sha256>::optimal_bits(expected_items, fp_rate);
            let hashers = BloomFilter::<Sha256>::optimal_hashers(expected_items, bits);

            log.extend((expected_items as u64).to_le_bytes());
            log.extend(fp_rate.to_le_bytes());
            log.extend((bits as u64).to_le_bytes());
            log.extend(hashers.to_le_bytes());

            // Test with_rate constructor produces same results
            let filter = BloomFilter::<Sha256>::with_rate(
                NonZeroUsize::new(expected_items).unwrap(),
                fp_rate,
            );
            log.extend((filter.bits().get() as u64).to_le_bytes());
            log.extend(filter.hashers().get().to_le_bytes());
        }

        // Also test bucket boundaries to catch rounding changes
        let boundary_rates = [
            0.00014, // Just below FP_1E4/FP_1E3 boundary
            0.00016, // Just above FP_1E4/FP_1E3 boundary
            0.00104, // Just below FP_1E3/FP_1E2 boundary
            0.00106, // Just above FP_1E3/FP_1E2 boundary
            0.01004, // Just below FP_1E2/FP_1E1 boundary
            0.01006, // Just above FP_1E2/FP_1E1 boundary
        ];

        for &fp_rate in &boundary_rates {
            let bits = BloomFilter::<Sha256>::optimal_bits(expected_items, fp_rate);
            log.extend((bits as u64).to_le_bytes());
        }

        log
    }
}
