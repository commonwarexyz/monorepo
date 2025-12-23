#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::rational::BigRationalExt;
use libfuzzer_sys::fuzz_target;
use num_rational::BigRational;

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
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::FromU64 { value } => {
            let _ = BigRational::from_u64(value);
        }

        FuzzInput::FromFracU64 {
            numerator,
            denominator,
        } => {
            if denominator == 0 {
                return;
            }
            let _ = BigRational::from_frac_u64(numerator, denominator);
        }

        FuzzInput::FromU128 { value } => {
            let _ = BigRational::from_u128(value);
        }

        FuzzInput::FromFracU128 {
            numerator,
            denominator,
        } => {
            if denominator == 0 {
                return;
            }
            let _ = BigRational::from_frac_u128(numerator, denominator);
        }

        FuzzInput::FromUsize { value } => {
            let _ = BigRational::from_usize(value);
        }

        FuzzInput::FromFracUsize {
            numerator,
            denominator,
        } => {
            if denominator == 0 {
                return;
            }
            let _ = BigRational::from_frac_usize(numerator, denominator);
        }

        FuzzInput::CeilToU128 {
            numerator,
            denominator,
        } => {
            if denominator == 0 {
                return;
            }
            use num_bigint::BigInt;
            let rational = BigRational::new(BigInt::from(numerator), BigInt::from(denominator));
            let _ = rational.ceil_to_u128();
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
            let _ = rational.log2_ceil(binary_digits);
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
