#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Decode, Encode, EncodeSize};
use commonware_cryptography::BloomFilter;
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
    EncodeSize,
}

const MAX_OPERATIONS: usize = 64;

#[derive(Debug)]
struct FuzzInput {
    hashers: NonZeroU8,
    bits: NonZeroU16,
    ops: Vec<Op>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let hashers = u.arbitrary()?;
        let bits = u.arbitrary()?;
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let ops = (0..num_ops)
            .map(|_| Op::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput { hashers, bits, ops })
    }
}

fn fuzz(input: FuzzInput) {
    let cfg = (input.hashers, input.bits.into());
    let mut bf = BloomFilter::new(input.hashers, input.bits.into());
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
            Op::Encode(_item) => {
                let encoded = bf.encode();
                let decoded = BloomFilter::decode_cfg(encoded.clone(), &cfg).unwrap();
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

                let decoded = BloomFilter::decode_cfg(encoded, &cfg).unwrap();
                assert_eq!(bf, decoded);

                assert_eq!(decoded.encode_size(), size1);
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
