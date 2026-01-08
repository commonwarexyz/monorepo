#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Decode, Encode, EncodeSize};
use commonware_cryptography::{sha256::Sha256, BloomFilter};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::HashSet,
    num::{NonZeroU16, NonZeroU8},
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
        expected_items: u16,
        fp_rate: f64,
    },
}

impl<'a> Arbitrary<'a> for Constructor {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.arbitrary::<bool>()? {
            let hashers = u.arbitrary()?;
            let bits = NonZeroU16::new(u.arbitrary::<u16>()?.max(1).next_power_of_two()).unwrap();
            Ok(Constructor::New { hashers, bits })
        } else {
            let expected_items = u.arbitrary()?;
            // Generate f64 in range (0.0, 1.0) exclusive
            let fp_rate = u
                .arbitrary::<f64>()?
                .abs()
                .fract()
                .clamp(f64::MIN_POSITIVE, 1.0 - f64::EPSILON);

            Ok(Constructor::WithRate {
                expected_items,
                fp_rate,
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
            fp_rate,
        } => BloomFilter::<Sha256>::with_rate(expected_items as usize, fp_rate),
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
