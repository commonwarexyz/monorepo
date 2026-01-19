//! BloomFilter conformance tests

use super::{BloomFilter, Sha256};
use commonware_codec::conformance::CodecConformance;
use commonware_conformance::Conformance;
use commonware_utils::rational::BigRationalExt;
use core::num::NonZeroUsize;
use num_rational::BigRational;

commonware_conformance::conformance_tests! {
    CodecConformance<BloomFilter>,
    RationalOptimalBits => 1024,
}

/// Conformance test for rational-based optimal_bits and with_rate.
/// Verifies that optimal_bits, optimal_hashers, and with_rate produce stable
/// outputs for various expected_items values and FP rates expressed as rationals.
struct RationalOptimalBits;

impl Conformance for RationalOptimalBits {
    async fn commit(seed: u64) -> Vec<u8> {
        let mut log = Vec::new();

        // Use seed to vary expected_items (1 to 1M range)
        let expected_items = ((seed % 1_000_000) + 1) as usize;

        // Test FP rates as rationals: 1/10000, 1/1000, 1/100, 1/10
        let fp_rates = [
            BigRational::from_frac_u64(1, 10_000), // 0.01%
            BigRational::from_frac_u64(1, 1_000),  // 0.1%
            BigRational::from_frac_u64(1, 100),    // 1%
            BigRational::from_frac_u64(1, 10),     // 10%
        ];
        for fp_rate in &fp_rates {
            // Test individual functions
            let bits = BloomFilter::<Sha256>::optimal_bits(expected_items, fp_rate);
            let hashers = BloomFilter::<Sha256>::optimal_hashers(expected_items, bits);

            log.extend((expected_items as u64).to_be_bytes());
            log.extend((bits as u64).to_be_bytes());
            log.extend(hashers.to_be_bytes());

            // Test with_rate constructor produces same results
            let filter = BloomFilter::<Sha256>::with_rate(
                NonZeroUsize::new(expected_items).unwrap(),
                fp_rate.clone(),
            );
            log.extend((filter.bits().get() as u64).to_be_bytes());
            log.extend(filter.hashers().get().to_be_bytes());
        }

        // Test some boundary values
        let boundary_rates = [
            BigRational::from_frac_u64(1, 7_000), // Between 0.01% and 0.1%
            BigRational::from_frac_u64(1, 500),   // Between 0.1% and 1%
            BigRational::from_frac_u64(1, 50),    // Between 1% and 10%
            BigRational::from_frac_u64(3, 100),   // 3%
        ];

        for fp_rate in &boundary_rates {
            let bits = BloomFilter::<Sha256>::optimal_bits(expected_items, fp_rate);
            log.extend((bits as u64).to_be_bytes());
        }

        log
    }
}
