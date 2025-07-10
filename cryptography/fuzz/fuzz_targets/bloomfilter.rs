#![no_main]

use arbitrary::Arbitrary;
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
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
