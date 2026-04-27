#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::rational::BigRationalExt;
use libfuzzer_sys::fuzz_target;
use num_bigint::BigInt;
use num_rational::BigRational;
use num_traits::One;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    FromU64 {
        value: u64,
    },
    FromFracU64 {
        numerator: u64,
        denominator: u64,
    },
    FromU128 {
        value: u128,
    },
    FromFracU128 {
        numerator: u128,
        denominator: u128,
    },
    FromUsize {
        value: usize,
    },
    FromFracUsize {
        numerator: usize,
        denominator: usize,
    },
    CeilToU128 {
        numerator: i64,
        denominator: u64,
    },
    Log2Ceil {
        numerator: u8,
        denominator: u8,
        binary_digits: u8,
    },
    /// Cover `log2_floor` with the same shape as `Log2Ceil` and assert the
    /// floor/ceil bracket plus the precision-1-ulp gap.
    Log2Floor {
        numerator: u8,
        denominator: u8,
        binary_digits: u8,
    },
    /// Precision monotonicity: `floor(x, p_a) <= ceil(x, p_b)` for any pair of
    /// precisions, since both bracket a fixed real value.
    Log2Monotonic {
        numerator: u8,
        denominator: u8,
        precision_a: u8,
        precision_b: u8,
    },
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::FromU64 { value } => {
            // Constructor equivalence: from_u64(v) == new(v, 1).
            assert_eq!(
                BigRational::from_u64(value),
                BigRational::new(BigInt::from(value), BigInt::from(1u32))
            );
        }

        FuzzInput::FromFracU64 {
            numerator,
            denominator,
        } => {
            if denominator == 0 {
                return;
            }
            assert_eq!(
                BigRational::from_frac_u64(numerator, denominator),
                BigRational::new(BigInt::from(numerator), BigInt::from(denominator))
            );
        }

        FuzzInput::FromU128 { value } => {
            assert_eq!(
                BigRational::from_u128(value),
                BigRational::new(BigInt::from(value), BigInt::from(1u32))
            );
        }

        FuzzInput::FromFracU128 {
            numerator,
            denominator,
        } => {
            if denominator == 0 {
                return;
            }
            assert_eq!(
                BigRational::from_frac_u128(numerator, denominator),
                BigRational::new(BigInt::from(numerator), BigInt::from(denominator))
            );
        }

        FuzzInput::FromUsize { value } => {
            assert_eq!(
                BigRational::from_usize(value),
                BigRational::new(BigInt::from(value), BigInt::from(1u32))
            );
        }

        FuzzInput::FromFracUsize {
            numerator,
            denominator,
        } => {
            if denominator == 0 {
                return;
            }
            assert_eq!(
                BigRational::from_frac_usize(numerator, denominator),
                BigRational::new(BigInt::from(numerator), BigInt::from(denominator))
            );
        }

        FuzzInput::CeilToU128 {
            numerator,
            denominator,
        } => {
            if denominator == 0 {
                return;
            }
            let rational = BigRational::new(BigInt::from(numerator), BigInt::from(denominator));
            let result = rational.ceil_to_u128();
            // BigRational always has a non-zero denominator, so result is Some.
            let r = result.expect("non-zero denom => Some");
            // Documented contract: negative values clamp to zero.
            if numerator < 0 {
                assert_eq!(r, 0);
            } else {
                // Oracle: ceil(numerator/denominator) on i128 with saturation.
                let n = numerator as i128;
                let d = denominator as i128;
                let oracle_floor = n / d;
                let oracle = if (n % d) == 0 {
                    oracle_floor as u128
                } else {
                    (oracle_floor as u128).saturating_add(1)
                };
                assert_eq!(r, oracle);
            }
        }

        FuzzInput::Log2Ceil {
            numerator,
            denominator,
            binary_digits,
        } => {
            if denominator == 0 || numerator == 0 {
                return;
            }
            let rational = BigRational::from_frac_u64(numerator as u64, denominator as u64);
            // Limit binary_digits to prevent OOM in BigInt operations
            let binary_digits = (binary_digits as usize) % 16;
            // Floor never exceeds ceil; the gap is at most 1/2^p.
            let floor = rational.log2_floor(binary_digits);
            let ceil = rational.log2_ceil(binary_digits);
            assert!(floor <= ceil);
            let ulp = BigRational::new(BigInt::one(), BigInt::one() << binary_digits);
            assert!(&ceil - &floor <= ulp);
        }

        FuzzInput::Log2Floor {
            numerator,
            denominator,
            binary_digits,
        } => {
            if denominator == 0 || numerator == 0 {
                return;
            }
            let rational = BigRational::from_frac_u64(numerator as u64, denominator as u64);
            let binary_digits = (binary_digits as usize) % 16;
            let floor = rational.log2_floor(binary_digits);
            let ceil = rational.log2_ceil(binary_digits);
            assert!(floor <= ceil);
            // Gap at precision p is at most one ulp = 1/2^p.
            let ulp = BigRational::new(BigInt::one(), BigInt::one() << binary_digits);
            assert!(&ceil - &floor <= ulp);
        }

        FuzzInput::Log2Monotonic {
            numerator,
            denominator,
            precision_a,
            precision_b,
        } => {
            if denominator == 0 || numerator == 0 {
                return;
            }
            let rational = BigRational::from_frac_u64(numerator as u64, denominator as u64);
            let p_a = (precision_a as usize) % 16;
            let p_b = (precision_b as usize) % 16;
            // Both refinements bracket the true real log2(x), so floor at any
            // precision must not exceed ceil at any other precision.
            let floor_a = rational.log2_floor(p_a);
            let ceil_b = rational.log2_ceil(p_b);
            assert!(floor_a <= ceil_b);
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
