#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Decode, Encode, EncodeSize};
use commonware_cryptography::{sha256::Sha256, BloomFilter};
use commonware_utils::rational::BigRationalExt;
use libfuzzer_sys::fuzz_target;
use num_rational::BigRational;
use std::{
    collections::HashSet,
    num::{NonZeroU16, NonZeroU8, NonZeroUsize},
};

#[derive(Arbitrary, Debug)]
enum Op {
    Insert(Vec<u8>),
    Contains(Vec<u8>),
    Encode(Vec<u8>),
    DecodeCfg(Vec<u8>, NonZeroU8, NonZeroU16),
    EncodeSize,
}

#[derive(Debug)]
enum Constructor {
    New {
        hashers: NonZeroU8,
        bits: NonZeroU16,
    },
    WithRate {
        expected_items: NonZeroU16,
        fp_numerator: u64,
        fp_denominator: u64,
    },
}

impl<'a> Arbitrary<'a> for Constructor {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.arbitrary::<bool>()? {
            let hashers = u.arbitrary()?;
            // Fallback to highest power of two in u16 on overflow
            let bits = u
                .arbitrary::<u16>()?
                .checked_next_power_of_two()
                .and_then(NonZeroU16::new)
                .unwrap_or(NonZeroU16::new(1 << 15).unwrap());
            Ok(Constructor::New { hashers, bits })
        } else {
            let expected_items = u.arbitrary::<NonZeroU16>()?;
            // Generate FP rate as rational: numerator in [1, denominator-1] to ensure (0, 1)
            let fp_denominator = u.int_in_range(2u64..=10_000)?;
            let fp_numerator = u.int_in_range(1u64..=fp_denominator - 1)?;
            Ok(Constructor::WithRate {
                expected_items,
                fp_numerator,
                fp_denominator,
            })
        }
    }
}

const MAX_OPERATIONS: usize = 64;

#[derive(Debug)]
struct FuzzInput {
    constructor: Constructor,
    ops: Vec<Op>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let constructor = u.arbitrary()?;
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let ops = (0..num_ops)
            .map(|_| Op::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput { constructor, ops })
    }
}

fn fuzz(input: FuzzInput) {
    let mut bf = match input.constructor {
        Constructor::New { hashers, bits } => BloomFilter::<Sha256>::new(hashers, bits.into()),
        Constructor::WithRate {
            expected_items,
            fp_numerator,
            fp_denominator,
        } => {
            let fp_rate = BigRational::from_frac_u64(fp_numerator, fp_denominator);
            BloomFilter::<Sha256>::with_rate(
                NonZeroUsize::new(expected_items.get() as usize).unwrap(),
                fp_rate,
            )
        }
    };

    let cfg = (bf.hashers(), bf.bits().try_into().unwrap());
    let mut model: HashSet<Vec<u8>> = HashSet::new();

    for op in input.ops {
        match op {
            Op::Insert(item) => {
                bf.insert(&item);
                model.insert(item);
            }
            Op::Contains(item) => {
                let res = bf.contains(&item);
                if model.contains(&item) {
                    assert!(res);
                }
            }
            Op::DecodeCfg(data, hashers, bits) => {
                let cfg = (hashers, bits.into());
                _ = BloomFilter::<Sha256>::decode_cfg(&data[..], &cfg);
            }
            Op::Encode(_item) => {
                let encoded = bf.encode();
                let decoded = BloomFilter::<Sha256>::decode_cfg(encoded.clone(), &cfg).unwrap();
                assert_eq!(bf, decoded);

                let encode_size = bf.encode_size();
                assert_eq!(encode_size, encoded.len());
            }
            Op::EncodeSize => {
                let size1 = bf.encode_size();
                let size2 = bf.encode_size();
                assert_eq!(size1, size2, "encode_size should be deterministic");

                let encoded = bf.encode();
                assert_eq!(
                    size1,
                    encoded.len(),
                    "encode_size should match encode().len()"
                );

                let decoded = BloomFilter::<Sha256>::decode_cfg(encoded, &cfg).unwrap();
                assert_eq!(bf, decoded);

                assert_eq!(decoded.encode_size(), size1);
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
