#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Decode, Encode, EncodeSize};
use commonware_cryptography::BloomFilter;
use libfuzzer_sys::fuzz_target;
use std::{
    collections::HashSet,
    num::{NonZeroU8, NonZeroUsize},
};

#[derive(Arbitrary, Debug)]
enum Op {
    Insert(Vec<u8>),
    Contains(Vec<u8>),
    Encode(Vec<u8>),
    EncodeSize,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    hashers: u8,
    bits: u16,
    ops: Vec<Op>,
}

fn fuzz(input: FuzzInput) {
    let hashers = (input.hashers).max(1);
    let bits = (input.bits).max(1);
    let mut bf = BloomFilter::new(
        NonZeroU8::new(hashers).unwrap(),
        NonZeroUsize::new(bits.into()).unwrap(),
    );
    let mut model: HashSet<Vec<u8>> = HashSet::new();

    let hashers_usize = hashers as usize;
    let bits_usize = bits as usize;
    let cfg = (
        (hashers_usize..=hashers_usize).into(),
        (bits_usize..=bits_usize).into(),
    );

    for op in input.ops.into_iter().take(64) {
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
